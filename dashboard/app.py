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
CHECK_TIMEOUT_SECONDS = 2
started_at = time.monotonic()
SUSPICIOUS_REQUEST = re.compile(
    r"(?:\bunion\b\s+(?:all\s+)?\bselect\b|\bselect\b.+\bfrom\b|\bor\b\s+[\w'\"]+\s*=\s*[\w'\"]+|--|/\*|\bsleep\s*\(|\bdrop\b\s+\btable\b)",
    re.IGNORECASE,
)


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
    return jsonify(snapshot)


@app.route("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
