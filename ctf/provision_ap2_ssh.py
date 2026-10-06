"""Provision the AP-02 SSH credential into its two intended runtime consumers."""

import json
import secrets
import subprocess
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
USERNAME = "ap02user"


def run_compose(arguments, payload=None):
    command = ["docker", "compose", *arguments]
    try:
        result = subprocess.run(
            command,
            cwd=REPOSITORY,
            input=payload,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        return False
    return result.returncode == 0


def provision() -> bool:
    credential = {
        "username": USERNAME,
        "password": secrets.token_urlsafe(36),
    }
    payload = json.dumps(credential, separators=(",", ":")).encode("utf-8")

    # Keep SSH unavailable while both consumers receive the same new material.
    if not run_compose(["stop", "challenge-ap2-ssh"]):
        return False
    if not run_compose(
        ["--profile", "provisioning", "run", "--rm", "-T", "challenge-ap2-ssh-provision"],
        payload,
    ):
        return False
    if not run_compose(["exec", "-T", "web", "python", "/app/app.py", "provision-ap2"], payload):
        return False
    if not run_compose(["up", "-d", "challenge-ap2-ssh"]):
        return False
    return True


if __name__ == "__main__":
    if not provision():
        print("AP-02 provisioning failed; no credential values were displayed.", file=sys.stderr)
        raise SystemExit(1)
    print("AP-02 SSH credential provisioned in the Web Challenge DB and SSH runtime.")
