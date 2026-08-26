import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from flask import Flask, jsonify, render_template

app = Flask(__name__)

TARGET_HEALTH_URL = os.getenv("TARGET_HEALTH_URL", "http://web:8080/health")
ACCESS_LOG_PATH = os.getenv("ACCESS_LOG_PATH", "/var/log/nginx/access.log")
DEFENDER_STATE_PATH = os.getenv("DEFENDER_STATE_PATH", "/state/defender_state.json")
DEFENDER_EVENTS_PATH = os.getenv("DEFENDER_EVENTS_PATH", "/state/events.ndjson")
CHECK_TIMEOUT_SECONDS = 2
started_at = time.monotonic()
SUSPICIOUS_REQUEST = re.compile(
    r"(?:\bunion\b\s+(?:all\s+)?\bselect\b|\bselect\b.+\bfrom\b|\bor\b\s+[\w'\"]+\s*=\s*[\w'\"]+|--|/\*|\bsleep\s*\(|\bdrop\b\s+\btable\b)",
    re.IGNORECASE,
)


def _fallback_graph():
    labels = ("Public Endpoint Reached", "Service / Protocol Discovered", "Exploit Attempt Observed", "Exploit Success Confirmed", "Application Data Access", "Credential Acquired", "Challenge Session Established", "Command Execution / Filesystem Read", "Internal Service Reached", "Challenge Database Access")
    return {"nodes": [{"id": "depth_%s" % depth, "label": label, "depth": depth, "status": "not_observed", "confidence": 0.0, "evidence_ids": [], "last_observed_at": None} for depth, label in enumerate(labels, 1)]}


def _fallback_flags():
    return {"flags": [{"id": "flag_%s" % number, "label": "Flag %s" % number, "acquisition_status": "not_observed", "submission_status": "not_submitted", "evidence_ids": [], "updated_at": None, "provenance": "defender_estimate"} for number in (1, 2, 3)]}


def activity_snapshot():
    """Return the latest Nginx observations without modifying its logs."""
    try:
        with open(ACCESS_LOG_PATH, encoding="utf-8", errors="replace") as log_file:
            lines = log_file.readlines()[-200:]
    except OSError:
        lines = []

    events = []
    status_codes = []
    addresses = set()
    paths = Counter()
    suspicious_requests = 0
    pattern = re.compile(r'^(?P<ip>\S+).*?\[(?P<time>[^]]+)] "(?P<request>[^"]*)" (?P<status>\d{3})')
    for line in reversed(lines):
        match = pattern.search(line)
        if not match:
            continue
        item = match.groupdict()
        code = int(item["status"])
        decoded_request = unquote_plus(item["request"])
        suspicious = bool(SUSPICIOUS_REQUEST.search(decoded_request))
        status_codes.append(code)
        addresses.add(item["ip"])
        request_parts = item["request"].split()
        if len(request_parts) >= 2:
            paths[request_parts[1].split("?", 1)[0]] += 1
        suspicious_requests += suspicious
        if len(events) < 8:
            events.append({"time": item["time"], "ip": item["ip"], "request": item["request"], "status": code,
                           "level": "alert" if suspicious or code >= 500 else "warning" if code >= 400 else "normal",
                           "suspicious": suspicious})

    return {"requests_observed": len(status_codes), "client_addresses": len(addresses),
            "client_errors": sum(400 <= code < 500 for code in status_codes),
            "server_errors": sum(code >= 500 for code in status_codes),
            "suspicious_requests": suspicious_requests,
            "top_path": paths.most_common(1)[0][0] if paths else "--",
            "events": events}


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _recent_reasoning_event():
    try:
        with open(DEFENDER_EVENTS_PATH, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()[-100:]
    except OSError:
        return None
    for line in reversed(lines):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") in {"REASONING_END", "REASONING_START", "ERROR"}:
            return event
    return None


def reasoning_snapshot():
    """Expose Kimi's persisted defense assessment, not private chain-of-thought."""
    state = _read_json(DEFENDER_STATE_PATH, {})
    event = _recent_reasoning_event()
    analysis = event.get("data", {}) if event and event.get("type") == "REASONING_END" else {}
    return {
        "available": bool(state),
        "cycle": state.get("cycle", 0),
        "phase": state.get("defense", {}).get("current_phase", "WAITING"),
        "threat_level": state.get("threat_level", "--"),
        "updated_at": state.get("updated_at"),
        "summary": analysis.get("summary") or (event or {}).get("summary") or "まだ防御分析は実行されていません。",
        "confidence": analysis.get("confidence"),
        "evidence_count": state.get("metrics", {}).get("evidence_count", 0),
        "hypotheses": state.get("defense", {}).get("unresolved_hypotheses", [])[:4],
        "watch_conditions": state.get("defense", {}).get("watch_conditions", [])[:4],
        "scenarios": state.get("defense", {}).get("scenarios", [])[:4],
    }


def defender_snapshot():
    """Read the Defender's persisted view without importing or controlling it."""
    unavailable = {
        "available": False, "threat_level": "UNKNOWN", "phase": "--", "updated_at": None,
        "metrics": {}, "incidents": [], "blocked_sources": [], "capabilities": [],
        "exposure_count": 0, "recent_events": [], "capability_graph": _fallback_graph(),
        "depth_summary": {"confirmed_depth": 0, "possible_depth": 0, "confirmed_count": 0, "suspected_count": 0},
        "flag_objectives": _fallback_flags(),
    }
    try:
        with open(DEFENDER_STATE_PATH, encoding="utf-8") as state_file:
            state = json.load(state_file)
        if state.get("schema_version") not in {"1.0", "2.0"}:
            return unavailable
    except (OSError, ValueError, json.JSONDecodeError):
        return unavailable

    try:
        with open(DEFENDER_EVENTS_PATH, encoding="utf-8") as events_file:
            lines = events_file.readlines()[-80:]
        recent_events = [json.loads(line) for line in lines if line.strip()][-6:]
        recent_events.reverse()
    except (OSError, ValueError, json.JSONDecodeError):
        recent_events = []

    exposure = state.get("exposure", {})
    exposure_count = sum(len(exposure.get(key, [])) for key in
                         ("endpoints", "parameters", "vulnerabilities", "exposed_assets", "attack_paths"))
    defense = state.get("defense", {})
    graph = state.get("capability_graph") if isinstance(state.get("capability_graph"), dict) else _fallback_graph()
    nodes = [node for node in graph.get("nodes", []) if isinstance(node, dict)][:20]
    confirmed = [node.get("depth", 0) for node in nodes if node.get("status") == "confirmed"]
    possible = [node.get("depth", 0) for node in nodes if node.get("status") in {"suspected", "confirmed"}]
    flags = state.get("flag_objectives") if isinstance(state.get("flag_objectives"), dict) else _fallback_flags()
    return {
        "available": True,
        "threat_level": state.get("threat_level", "UNKNOWN"),
        "phase": defense.get("current_phase", "DETECT"),
        "updated_at": state.get("updated_at"),
        "metrics": state.get("metrics", {}),
        "incidents": state.get("active_incidents", [])[:5],
        "blocked_sources": defense.get("blocked_sources", [])[:5],
        "capabilities": state.get("attacker_state", {}).get("estimated_capabilities", [])[:6],
        "exposure_count": exposure_count,
        "recent_events": recent_events,
        "capability_graph": {"nodes": nodes},
        "depth_summary": {"confirmed_depth": max(confirmed, default=0), "possible_depth": max(possible, default=0),
                          "confirmed_count": len(confirmed), "suspected_count": sum(node.get("status") == "suspected" for node in nodes)},
        "flag_objectives": {"flags": [item for item in flags.get("flags", []) if isinstance(item, dict)][:3]},
    }


def health_snapshot():
    checked_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(TARGET_HEALTH_URL, timeout=CHECK_TIMEOUT_SECONDS) as response:
            latency_ms = round((time.perf_counter() - started) * 1000)
            healthy = 200 <= response.status < 300
            return {
                "status": "protected" if healthy else "degraded",
                "service_status": "稼働中" if healthy else "要確認",
                "latency_ms": latency_ms,
                "http_status": response.status,
                "checked_at": checked_at,
                "detail": "ヘルスチェックに正常に応答しました。" if healthy else "正常な応答を受信できませんでした。",
            }
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return {
            "status": "offline",
            "service_status": "応答なし",
            "latency_ms": None,
            "http_status": None,
            "checked_at": checked_at,
            "detail": f"ヘルスチェックに接続できませんでした: {error.reason if isinstance(error, urllib.error.URLError) else 'timeout'}",
        }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    snapshot = health_snapshot()
    snapshot["uptime_seconds"] = round(time.monotonic() - started_at)
    snapshot["activity"] = activity_snapshot()
    snapshot["reasoning"] = reasoning_snapshot()
    snapshot["defender"] = defender_snapshot()
    return jsonify(snapshot)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
