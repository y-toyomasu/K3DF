import json
import os
import tempfile
import uuid
from datetime import datetime, timezone

from capability_graph import default_flag_objectives, default_graph, normalize_flags, normalize_graph


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_state(config):
    return {
        "schema_version": "2.0",
        "updated_at": now_iso(),
        "cycle": 0,
        "reasoning_interval_sec": config.reasoning_interval_sec,
        "threat_level": "LOW",
        "attacker_state": {"estimated_capabilities": [], "achieved_attack_tactics": [], "achieved_attack_techniques": []},
        "capability_graph": default_graph(),
        "flag_objectives": default_flag_objectives(),
        "exposure": {"endpoints": [], "parameters": [], "vulnerabilities": [], "exposed_assets": [], "attack_paths": []},
        "defender_state": {
            "available_capabilities": ["observe_http_logs", "inspect_scanner_results", "active_scan", "block_ip", "verify_containment"],
            "authorized_capabilities": ["observe_http_logs", "inspect_scanner_results", "active_scan", "block_ip", "verify_containment"],
            "active_actions": [],
        },
        "active_incidents": [],
        "defense": {"current_phase": "DETECT", "blocked_sources": [], "unresolved_hypotheses": [], "watch_conditions": [], "scenarios": []},
        "configuration": {"ignore_networks": [str(network) for network in config.ignore_networks]},
        "metrics": {"evidence_count": 0, "ignored_evidence_count": 0, "reasoning_cycle_count": 0, "incident_count": 0, "blocked_scenario_count": 0, "executed_action_count": 0},
        "runtime": {"access_log_offset": 0, "access_log_inode": None, "scanner_mtime": 0, "last_reasoning_at": None},
    }


class StateStore:
    def __init__(self, state_dir, config):
        self.state_dir = state_dir
        self.state_path = os.path.join(state_dir, "defender_state.json")
        self.events_path = os.path.join(state_dir, "events.ndjson")
        self.config = config
        os.makedirs(state_dir, exist_ok=True)

    def load(self):
        try:
            with open(self.state_path, encoding="utf-8") as handle:
                state = json.load(handle)
            if state.get("schema_version") not in {"1.0", "2.0"}:
                raise ValueError("unsupported state schema")
            return self._migrate(state)
        except (OSError, ValueError, json.JSONDecodeError):
            state = default_state(self.config)
            self.save(state)
            return state

    def _migrate(self, state):
        """Retain legacy fields while making the versioned graph canonical."""
        state = dict(state)
        state["schema_version"] = "2.0"
        state["capability_graph"] = normalize_graph(state.get("capability_graph"))
        state["flag_objectives"] = normalize_flags(state.get("flag_objectives"))
        state.setdefault("attacker_state", {}).setdefault("estimated_capabilities", [])
        return state

    def save(self, state):
        state["updated_at"] = now_iso()
        fd, temporary_path = tempfile.mkstemp(prefix=".defender-state-", suffix=".json", dir=self.state_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.state_path)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    def event(self, event_type, cycle, summary, data=None, incident_id=None):
        event = {"event_id": str(uuid.uuid4()), "ts": now_iso(), "type": event_type, "cycle": cycle,
                 "incident_id": incident_id, "summary": summary, "data": data or {}}
        with open(self.events_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
            handle.flush()
        return event
