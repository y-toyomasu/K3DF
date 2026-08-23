#!/usr/bin/env python3

import json
import os
import sys
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime


def request(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, body

    except Exception as e:
        return None, str(e)


def scan_sql_injection(base_url):
    findings = []

    endpoint = "/customer"

    # Normal request
    normal_url = (
        base_url
        + endpoint
        + "?id="
        + urllib.parse.quote("1")
    )

    # SQL Injection test
    attack_value = "1 OR 1=1"

    attack_url = (
        base_url
        + endpoint
        + "?id="
        + urllib.parse.quote(attack_value)
    )

    normal_status, normal_body = request(normal_url)
    attack_status, attack_body = request(attack_url)

    result = {
        "normal_request": {
            "url": normal_url,
            "status": normal_status,
            "response_length": len(normal_body),
        },
        "test_request": {
            "url": attack_url,
            "status": attack_status,
            "response_length": len(attack_body),
        },
    }

    # Very simple detection logic for our lab application.
    if (
        normal_status == 200
        and attack_status == 200
        and len(attack_body) > len(normal_body) * 1.5
        and '"customers"' in attack_body
    ):
        findings.append(
            {
                "type": "SQL Injection",
                "endpoint": endpoint,
                "parameter": "id",
                "severity": "CRITICAL",
                "evidence": {
                    "normal_response_length": len(normal_body),
                    "attack_response_length": len(attack_body),
                    "payload": attack_value,
                },
            }
        )

    result["findings"] = findings

    return result


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")

    result = {
        "scanner": "K3DF Scanner",
        "version": "0.1",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target": base_url,
        "findings": [],
    }

    scan_result = scan_sql_injection(base_url)

    result["checks"] = scan_result
    result["findings"] = scan_result["findings"]

    print(json.dumps(result, indent=2, ensure_ascii=False))

    output_path = os.getenv("K3DF_SCANNER_RESULT_PATH")
    if output_path:
        directory = os.path.dirname(output_path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, temporary_path = tempfile.mkstemp(prefix=".scanner-result-", suffix=".json", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(result, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, output_path)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)


if __name__ == "__main__":
    main()
