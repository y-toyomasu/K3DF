import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit


ACCESS_PATTERN = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^]]+)] "(?P<method>\S+) (?P<target>\S+) (?P<protocol>[^"]+)" (?P<status>\d{3})')


def _timestamp(value):
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat(timespec="seconds")
    except ValueError:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fingerprint(*parts):
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()[:24]


def ignored_source(source_ip, networks):
    try:
        address = ipaddress.ip_address(source_ip)
        return any(address in network for network in networks)
    except ValueError:
        return False


class EvidenceCollector:
    def __init__(self, config, state_store):
        self.config = config
        self.store = state_store

    def collect(self, state):
        evidence = self._access_log(state) + self._scanner_result(state)
        accepted = []
        for item in evidence:
            source_ip = item.get("related_source_ip")
            if source_ip and ignored_source(source_ip, self.config.ignore_networks):
                state["metrics"]["ignored_evidence_count"] += 1
                self.store.event("EVIDENCE_IGNORED", state["cycle"], "trusted network evidence ignored", {"source": source_ip, "evidence_id": item["evidence_id"]})
                print("K3DF EVIDENCE IGNORED source=%s reason=trusted_network" % source_ip, flush=True)
                continue
            accepted.append(item)
            state["metrics"]["evidence_count"] += 1
            self.store.event("EVIDENCE", state["cycle"], item["summary"], item)
        return accepted

    def _access_log(self, state):
        runtime = state["runtime"]
        try:
            stat = os.stat(self.config.access_log_path)
            if runtime.get("access_log_inode") != stat.st_ino or stat.st_size < runtime.get("access_log_offset", 0):
                runtime["access_log_offset"] = 0
                runtime["access_log_inode"] = stat.st_ino
            with open(self.config.access_log_path, encoding="utf-8", errors="replace") as handle:
                handle.seek(runtime["access_log_offset"])
                lines = handle.readlines()
                runtime["access_log_offset"] = handle.tell()
        except OSError:
            return []
        result = []
        for line in lines:
            match = ACCESS_PATTERN.match(line)
            if not match:
                continue
            entry = match.groupdict()
            parsed = urlsplit(entry["target"])
            parameters = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
            fingerprint = _fingerprint("nginx_access", entry["ip"], entry["method"], parsed.path, ",".join(parameters), entry["status"])
            result.append({
                "evidence_id": "EV-" + _fingerprint(line.strip()), "fingerprint": fingerprint, "timestamp": _timestamp(entry["time"]),
                "source": "nginx_access_log", "type": "http_request", "summary": "%s %s -> %s" % (entry["method"], parsed.path, entry["status"]),
                "raw_reference": self.config.access_log_path, "related_endpoint": parsed.path, "related_source_ip": entry["ip"],
                "related_incident_id": None, "confidence": 0.7,
                "metadata": {"method": entry["method"], "status": int(entry["status"]), "parameter_names": parameters, "target": entry["target"]},
            })
        return result

    def _scanner_result(self, state):
        runtime = state["runtime"]
        try:
            mtime = os.path.getmtime(self.config.scanner_result_path)
            if mtime <= runtime.get("scanner_mtime", 0):
                return []
            with open(self.config.scanner_result_path, encoding="utf-8") as handle:
                result = json.load(handle)
            runtime["scanner_mtime"] = mtime
        except (OSError, ValueError, json.JSONDecodeError):
            return []
        evidence = []
        for finding in result.get("findings", []):
            fingerprint = _fingerprint("scanner", finding.get("type"), finding.get("endpoint"), finding.get("parameter"))
            evidence.append({"evidence_id": "EV-" + fingerprint, "fingerprint": fingerprint,
                             "timestamp": result.get("timestamp") or datetime.now(timezone.utc).isoformat(), "source": "scanner_result",
                             "type": "scanner_finding", "summary": "%s at %s" % (finding.get("type", "finding"), finding.get("endpoint", "unknown")),
                             "raw_reference": self.config.scanner_result_path, "related_endpoint": finding.get("endpoint"), "related_source_ip": None,
                             "related_incident_id": None, "confidence": 0.95, "metadata": finding})
        return evidence


def aggregate(evidence, limit=50):
    grouped = {}
    for item in evidence:
        bucket = grouped.setdefault(item["fingerprint"], {**item, "count": 0, "first_seen": item["timestamp"], "last_seen": item["timestamp"]})
        bucket["count"] += 1
        bucket["last_seen"] = item["timestamp"]
    return list(grouped.values())[:limit]
