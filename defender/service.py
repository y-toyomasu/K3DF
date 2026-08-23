import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from collectors import EvidenceCollector, aggregate
from config import Config
from kimi import KimiClient
from policy import active_block, block_ip, validate_scenario
from state_store import StateStore, now_iso


class Defender:
    def __init__(self, config):
        self.config = config
        self.store = StateStore(config.state_dir, config)
        self.state = self.store.load()
        self.collector = EvidenceCollector(config, self.store)
        self.kimi = KimiClient(config)
        self.buffer = []
        self.lock = threading.RLock()
        self.last_reasoning = time.monotonic()

    def auth(self, source_ip):
        with self.lock:
            return not active_block(self.state, source_ip)

    def context(self, batch):
        return {"cycle": self.state["cycle"], "current_state": {"threat_level": self.state["threat_level"],
                "active_incidents": self.state["active_incidents"][:10], "attacker_capabilities": self.state["attacker_state"]["estimated_capabilities"][:20],
                "exposure_graph": self.state["exposure"], "defender_capabilities": self.state["defender_state"]["authorized_capabilities"]},
                "new_evidence": batch[:50], "batch_summary": {"window_seconds": self.config.reasoning_interval_sec,
                "request_count": sum(item["count"] for item in batch), "suspicious_candidate_count": len(batch),
                "unique_sources": len({item.get("related_source_ip") for item in batch if item.get("related_source_ip")})},
                "scanner_findings": [item for item in batch if item["source"] == "scanner_result"], "recent_events": [],
                "unresolved_hypotheses": self.state["defense"]["unresolved_hypotheses"][:10], "watch_conditions": self.state["defense"]["watch_conditions"][:10]}

    def _upsert(self, collection, item, key):
        value = item.get(key)
        if not value:
            return
        existing = next((entry for entry in collection if entry.get(key) == value), None)
        if existing:
            existing.update(item)
        else:
            collection.append(item)

    def apply_analysis(self, result):
        self.state["threat_level"] = result["analysis"]["threat_level"]
        for incident in result["incident_updates"]:
            self._upsert(self.state["active_incidents"], incident, "incident_id")
            self.store.event("INCIDENT", self.state["cycle"], incident.get("summary", "incident update"), incident, incident.get("incident_id"))
        self.state["metrics"]["incident_count"] = len(self.state["active_incidents"])
        for capability in result["capability_updates"]:
            self._upsert(self.state["attacker_state"]["estimated_capabilities"], capability, "capability")
            self.store.event("CAPABILITY", self.state["cycle"], capability.get("capability", "unknown"), capability, capability.get("related_incident_id"))
        for update in result["exposure_updates"]:
            category = update.get("category")
            if category in self.state["exposure"]:
                self._upsert(self.state["exposure"][category], update, "id")
                self.store.event("EXPOSURE", self.state["cycle"], category, update)
        for watch in result["watch_conditions"]:
            self._upsert(self.state["defense"]["watch_conditions"], watch, "watch_id")
            self.store.event("WATCH", self.state["cycle"], watch.get("reason", "watch condition"), watch)
        self.state["defense"]["unresolved_hypotheses"] = result["unresolved_hypotheses"][:10]
        unique_scenarios = {}
        for scenario in result["defense_scenarios"]:
            scenario_id = scenario.get("scenario_id") or json.dumps(scenario, sort_keys=True)
            unique_scenarios[scenario_id] = scenario
        self.state["defense"]["scenarios"] = list(unique_scenarios.values())[:10]
        for scenario in self.state["defense"]["scenarios"]:
            self.store.event("SCENARIO", self.state["cycle"], scenario.get("hypothesis", "defense scenario"), scenario)
        for context in result["mitre_attack_context"]:
            self.store.event("ATT&CK", self.state["cycle"], "ATT&CK context", context)

    def execute_scenarios(self, scenarios):
        for scenario in scenarios:
            decision, reason = validate_scenario(scenario, self.config)
            self.store.event("POLICY", self.state["cycle"], decision + ": " + reason, {"scenario": scenario, "decision": decision, "reason": reason})
            if decision != "ALLOW":
                self.state["metrics"]["blocked_scenario_count"] += 1
                continue
            action = scenario["action"]
            if action["type"] != "block_ip":
                continue
            record = block_ip(self.state, action["ip"], action.get("duration_sec", 300), scenario.get("hypothesis", "defense containment"))
            self.state["defense"]["current_phase"] = "CONTAIN"
            self.state["defender_state"]["active_actions"] = [record]
            self.state["metrics"]["executed_action_count"] += 1
            self.store.event("ACTION", self.state["cycle"], "temporary Nginx IP block", record)
            verified = active_block(self.state, record["ip"])
            self.state["defense"]["current_phase"] = "VERIFY"
            self.store.event("VERIFY", self.state["cycle"], "Nginx block list verification", {"ip": record["ip"], "verified": verified})
            self.buffer.append({"evidence_id": "EV-ACTION-" + record["ip"], "fingerprint": "action-" + record["ip"],
                                "timestamp": now_iso(), "source": "defender_action", "type": "action_result",
                                "summary": "Nginx temporary block for " + record["ip"], "raw_data": record,
                                "related_endpoint": None, "related_source_ip": record["ip"], "related_incident_id": scenario.get("target_incident_id"),
                                "confidence": 1.0, "metadata": {"verified": verified}})

    def tick(self):
        with self.lock:
            self.buffer.extend(self.collector.collect(self.state))
            active_block(self.state, "0.0.0.0")
            if self.buffer and time.monotonic() - self.last_reasoning >= self.config.reasoning_interval_sec:
                batch = aggregate(self.buffer)
                self.buffer = []
                self.state["cycle"] += 1
                cycle = self.state["cycle"]
                print("K3DF PLAN cycle=%s evidence=%s window=%ss" % (cycle, len(batch), self.config.reasoning_interval_sec), flush=True)
                self.store.event("REASONING_START", cycle, "evidence batch reasoning", {"evidence": len(batch)})
                try:
                    result = self.kimi.analyze(self.context(batch))
                    self.apply_analysis(result)
                    self.execute_scenarios(result["defense_scenarios"])
                    self.store.event("REASONING_END", cycle, result["analysis"]["summary"], result["analysis"])
                    print("K3DF SUMMARY cycle=%s threat=%s" % (cycle, self.state["threat_level"]), flush=True)
                except Exception as error:
                    self.store.event("ERROR", cycle, "reasoning safe failure", {"error": str(error)})
                    print("K3DF ANALYSIS cycle=%s safe_failure=%s" % (cycle, error), flush=True)
                self.state["metrics"]["reasoning_cycle_count"] += 1
                self.last_reasoning = time.monotonic()
            self.state["runtime"]["last_reasoning_at"] = now_iso()
            self.store.save(self.state)


def handler(defender):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/nginx/auth":
                source_ip = self.headers.get("X-Original-Remote-Addr", "")
                allowed = defender.auth(source_ip)
                self.send_response(204 if allowed else 403)
                self.end_headers()
                return
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok"}).encode())
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, _format, *_args):
            return
    return Handler


def main():
    config = Config.from_env()
    defender = Defender(config)
    server = ThreadingHTTPServer(("0.0.0.0", 8090), handler(defender))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("K3DF OBSERVE defender started interval=%ss" % config.reasoning_interval_sec, flush=True)
    while True:
        defender.tick()
        time.sleep(1)


if __name__ == "__main__":
    main()
