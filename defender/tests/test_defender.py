import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from collectors import EvidenceCollector, aggregate, ignored_source
from config import Config
from kimi import validate_result
from policy import block_ip, validate_scenario
from service import Defender
from state_store import StateStore


def test_config(directory):
    return SimpleNamespace(reasoning_interval_sec=10, reasoning_effort="low", ignore_networks=Config.from_env().ignore_networks,
                           allow_networks=(), state_dir=directory, access_log_path=os.path.join(directory, "access.log"),
                           scanner_result_path=os.path.join(directory, "scanner.json"), moonshot_api_key="", moonshot_base_url="", moonshot_model="kimi-k3")


class DefenderTests(unittest.TestCase):
    def test_ignore_cidr_and_aggregation(self):
        config = SimpleNamespace(ignore_networks=Config.from_env().ignore_networks)
        self.assertTrue(ignored_source("10.8.8.42", config.ignore_networks))
        self.assertFalse(ignored_source("203.0.113.7", config.ignore_networks))
        items = [{"fingerprint": "same", "timestamp": "2026-01-01T00:00:00Z"}, {"fingerprint": "same", "timestamp": "2026-01-01T00:00:01Z"}]
        self.assertEqual(aggregate(items)[0]["count"], 2)

    def test_multiple_and_invalid_ignore_cidrs(self):
        with patch.dict(os.environ, {"K3DF_IGNORE_NETWORKS": "10.8.8.0/24,192.168.100.0/24"}, clear=False):
            config = Config.from_env()
            self.assertTrue(ignored_source("192.168.100.2", config.ignore_networks))
        with patch.dict(os.environ, {"K3DF_IGNORE_NETWORKS": "not-a-cidr"}, clear=False):
            with self.assertRaises(ValueError):
                Config.from_env()

    def test_nginx_evidence_and_trusted_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            config = test_config(directory)
            store = StateStore(directory, config)
            state = store.load()
            with open(config.access_log_path, "w", encoding="utf-8") as handle:
                handle.write('203.0.113.7 - - [01/Jan/2026:00:00:00 +0000] "GET /customer?id=1 HTTP/1.1" 200 10 "-" "test"\n')
                handle.write('10.8.8.9 - - [01/Jan/2026:00:00:01 +0000] "GET /customer?id=1 HTTP/1.1" 200 10 "-" "test"\n')
            evidence = EvidenceCollector(config, store).collect(state)
            self.assertEqual(len(evidence), 1)
            self.assertEqual(state["metrics"]["ignored_evidence_count"], 1)

    def test_scanner_evidence_once(self):
        with tempfile.TemporaryDirectory() as directory:
            config = test_config(directory)
            store = StateStore(directory, config)
            state = store.load()
            with open(config.scanner_result_path, "w", encoding="utf-8") as handle:
                json.dump({"timestamp": "2026-01-01T00:00:00Z", "findings": [{"type": "SQL Injection", "endpoint": "/customer", "parameter": "id"}]}, handle)
            collector = EvidenceCollector(config, store)
            self.assertEqual(len(collector.collect(state)), 1)
            self.assertEqual(collector.collect(state), [])

    def test_policy_blocks_protected_networks(self):
        with tempfile.TemporaryDirectory() as directory:
            config = test_config(directory)
            protected = {"action": {"type": "block_ip", "ip": "10.8.8.9", "duration_sec": 60}}
            localhost = {"action": {"type": "block_ip", "ip": "127.0.0.1", "duration_sec": 60}}
            public = {"action": {"type": "block_ip", "ip": "203.0.113.7", "duration_sec": 60}}
            self.assertEqual(validate_scenario(protected, config)[0], "BLOCK")
            self.assertEqual(validate_scenario(localhost, config)[0], "BLOCK")
            self.assertEqual(validate_scenario(public, config)[0], "ALLOW")

    def test_state_is_atomic_and_restores(self):
        with tempfile.TemporaryDirectory() as directory:
            config = test_config(directory)
            store = StateStore(directory, config)
            state = store.load()
            block_ip(state, "203.0.113.7", 60, "test")
            store.save(state)
            restored = store.load()
            self.assertEqual(restored["defense"]["blocked_sources"][0]["ip"], "203.0.113.7")
            store.event("TEST", 1, "append only")
            with open(store.events_path, encoding="utf-8") as handle:
                self.assertEqual(len(handle.readlines()), 1)

    def test_malformed_llm_output_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_result({"analysis": {"summary": "x", "threat_level": "INVALID", "confidence": 1}})

    def test_no_evidence_does_not_call_kimi(self):
        with tempfile.TemporaryDirectory() as directory:
            defender = Defender(test_config(directory))
            called = []
            defender.kimi.analyze = lambda _context: called.append(True)
            defender.tick()
            self.assertEqual(called, [])

    def test_evidence_waits_for_batch_window_then_reasons_once(self):
        with tempfile.TemporaryDirectory() as directory:
            defender = Defender(test_config(directory))
            defender.buffer.append({"evidence_id": "EV-1", "fingerprint": "one", "timestamp": "2026-01-01T00:00:00Z", "source": "test", "type": "test", "summary": "test", "confidence": 1, "metadata": {}})
            result = {"analysis": {"summary": "ok", "threat_level": "LOW", "confidence": 1}, "incident_updates": [], "capability_updates": [], "exposure_updates": [], "defense_scenarios": [], "watch_conditions": [], "unresolved_hypotheses": [], "mitre_attack_context": []}
            called = []
            defender.kimi.analyze = lambda _context: called.append(True) or result
            defender.tick()
            self.assertEqual(called, [])
            defender.last_reasoning = time.monotonic() - defender.config.reasoning_interval_sec
            defender.tick()
            self.assertEqual(called, [True])

    def test_capability_exposure_watch_and_scenario_persist(self):
        with tempfile.TemporaryDirectory() as directory:
            defender = Defender(test_config(directory))
            defender.state["cycle"] = 1
            result = {"analysis": {"summary": "SQLi suspected", "threat_level": "HIGH", "confidence": 0.8},
                      "incident_updates": [{"incident_id": "INC-1", "summary": "customer exposure"}],
                      "capability_updates": [{"capability": "application_data_read", "status": "likely", "confidence": 0.8}],
                      "exposure_updates": [{"category": "endpoints", "id": "/customer", "status": "active", "confidence": 0.9}],
                      "defense_scenarios": [{"scenario_id": "S-1", "hypothesis": "block source"}, {"scenario_id": "S-1", "hypothesis": "duplicate"}],
                      "watch_conditions": [{"watch_id": "WATCH-1", "type": "request_pattern", "priority": "HIGH"}],
                      "unresolved_hypotheses": ["scope unknown"], "mitre_attack_context": []}
            defender.apply_analysis(result)
            defender.store.save(defender.state)
            restored = defender.store.load()
            self.assertEqual(restored["attacker_state"]["estimated_capabilities"][0]["capability"], "application_data_read")
            self.assertEqual(restored["exposure"]["endpoints"][0]["id"], "/customer")
            self.assertEqual(restored["defense"]["watch_conditions"][0]["watch_id"], "WATCH-1")
            self.assertEqual(len(restored["defense"]["scenarios"]), 1)

    def test_allowed_block_is_visible_to_nginx_authorizer(self):
        with tempfile.TemporaryDirectory() as directory:
            defender = Defender(test_config(directory))
            scenario = {"hypothesis": "contain public source", "action": {"type": "block_ip", "ip": "203.0.113.7", "duration_sec": 60}}
            defender.execute_scenarios([scenario])
            self.assertFalse(defender.auth("203.0.113.7"))
            self.assertTrue(defender.auth("10.8.8.9"))


if __name__ == "__main__":
    unittest.main()
