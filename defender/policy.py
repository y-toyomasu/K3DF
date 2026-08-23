import ipaddress
from datetime import datetime, timedelta, timezone


PROTECTED_NETWORKS = tuple(ipaddress.ip_network(value) for value in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _is_protected(address, config):
    return any(address in network for network in PROTECTED_NETWORKS + config.ignore_networks + config.allow_networks)


def validate_scenario(scenario, config):
    action = scenario.get("action") if isinstance(scenario, dict) else None
    if not isinstance(action, dict):
        return "BLOCK", "invalid_action"
    action_type = action.get("type")
    if action_type in {"observe_logs", "inspect_scanner_results", "active_scan", "verify_containment"}:
        return "ALLOW", "approved_read_or_scan_action"
    if action_type != "block_ip":
        return "BLOCK", "action_not_authorized"
    try:
        address = ipaddress.ip_address(action.get("ip", ""))
    except ValueError:
        return "BLOCK", "invalid_ip"
    if _is_protected(address, config):
        return "BLOCK", "trusted_or_ignored_network"
    duration = action.get("duration_sec", 300)
    if not isinstance(duration, int) or duration < 1 or duration > 3600:
        return "BLOCK", "unsafe_duration"
    return "ALLOW", "temporary_nginx_block"


def block_ip(state, ip, duration_sec, reason):
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=duration_sec)).isoformat(timespec="seconds")
    blocked = state["defense"]["blocked_sources"]
    existing = next((item for item in blocked if item["ip"] == ip), None)
    record = {"ip": ip, "expires_at": expires_at, "reason": reason, "enforcement": "nginx_auth_request"}
    if existing:
        existing.update(record)
    else:
        blocked.append(record)
    return record


def active_block(state, ip):
    now = datetime.now(timezone.utc)
    state["defense"]["blocked_sources"][:] = [
        item for item in state["defense"]["blocked_sources"]
        if datetime.fromisoformat(item["expires_at"]).astimezone(timezone.utc) > now
    ]
    return any(item["ip"] == ip for item in state["defense"]["blocked_sources"])
