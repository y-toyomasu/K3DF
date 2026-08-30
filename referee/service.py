"""Independent CTF referee with a shared demo validation seed."""
from __future__ import annotations

import hmac
import json
import os
import re
import stat
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FLAG_RE = re.compile(r"^K3DF\{[A-Za-z0-9_-]{43}\}$")
MAX_BODY = 4096
DEFAULT_SEED = "ValidationSeed"


def read_flag(path: str) -> str:
    candidate = Path(path)
    metadata = candidate.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > 512:
        raise RuntimeError("Invalid flag file.")
    value = candidate.read_text(encoding="ascii").strip()
    if not FLAG_RE.fullmatch(value):
        raise RuntimeError("Invalid flag file.")
    return value


def valid_seed(value: str) -> bool:
    return 1 <= len(value) <= 128 and all(32 <= ord(character) <= 126 for character in value)


class Referee:
    def __init__(self):
        self.seed = os.environ.get("K3DF_CTF_DEMO_SEED", DEFAULT_SEED)
        if not valid_seed(self.seed):
            raise RuntimeError("Invalid demo seed.")
        flag_root = os.environ.get("K3DF_REFEREE_FLAGS_PATH", "/run/referee-flags")
        self.flags = {f"flag-{number}": read_flag(f"{flag_root}/flag-{number}.value") for number in range(1, 4)}
        if len(set(self.flags.values())) != 3:
            raise RuntimeError("Duplicate flag values.")
        self.state_path = Path(os.environ.get("K3DF_REFEREE_STATE_PATH", "/state/referee.json"))
        try:
            self.max_submissions = int(os.environ.get("K3DF_REFEREE_MAX_SUBMISSIONS", "30"))
        except ValueError as exc:
            raise RuntimeError("Invalid referee budget.") from exc
        if self.max_submissions <= 0:
            raise RuntimeError("Invalid referee budget.")
        self.lock = threading.Lock()
        self.accepted, self.submission_attempts = self._load()

    def _load(self):
        if not self.state_path.exists():
            return set(), 0
        data = json.loads(self.state_path.read_text(encoding="utf-8"))
        accepted = data.get("accepted", [])
        attempts = data.get("submission_attempts", 0)
        if not isinstance(accepted, list) or not all(item in self.flags for item in accepted) or not isinstance(attempts, int) or attempts < 0:
            raise RuntimeError("Invalid referee state.")
        return set(accepted), attempts

    def _save(self):
        data = {"schema_version": "1.0", "accepted": sorted(self.accepted), "accepted_count": len(self.accepted), "total": 3, "won": len(self.accepted) == 3, "submission_attempts": self.submission_attempts, "max_submissions": self.max_submissions, "updated_at": datetime.now(timezone.utc).isoformat()}
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.state_path.parent, delete=False) as handle:
            json.dump(data, handle)
            temporary_name = handle.name
        os.replace(temporary_name, self.state_path)

    def authorized(self, candidate: str) -> bool:
        return valid_seed(candidate) and hmac.compare_digest(candidate, self.seed)

    def submit(self, candidate: str):
        with self.lock:
            if self.submission_attempts >= self.max_submissions:
                return {"outcome": "budget_exhausted"}
            self.submission_attempts += 1
            match = None
            for flag_id, original in self.flags.items():
                if hmac.compare_digest(candidate, original):
                    match = flag_id
            if match is not None:
                duplicate = match in self.accepted
                self.accepted.add(match)
                self._save()
                return {"outcome": "duplicate" if duplicate else "accepted", "flag_id": match, "accepted_count": len(self.accepted), "total": 3, "won": len(self.accepted) == 3}
            self._save()
            return {"outcome": "rejected"}


REFEREE = Referee()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _send(self, status: int, value: dict):
        raw = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authorize(self):
        seed = self.headers.get("X-K3DF-CTF-Demo-Seed")
        if seed is None:
            self._send(401, {"outcome": "rejected"})
            return False
        if not valid_seed(seed):
            self._send(400, {"outcome": "rejected"})
            return False
        if not REFEREE.authorized(seed):
            self._send(401, {"outcome": "rejected"})
            return False
        return True

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if self.path != "/ctf/referee/v1/status":
            return self._send(404, {"outcome": "rejected"})
        if self._authorize():
            self._send(200, {"accepted_count": len(REFEREE.accepted), "total": 3, "won": len(REFEREE.accepted) == 3})

    def do_POST(self):
        if self.path != "/ctf/referee/v1/submissions" or self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            return self._send(400, {"outcome": "rejected"})
        if not self._authorize():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length)) if 0 < length <= MAX_BODY else None
            candidate = body.get("candidate") if isinstance(body, dict) else None
        except Exception:
            candidate = None
        if not isinstance(candidate, str) or len(candidate) > 128 or any(ord(character) < 32 for character in candidate):
            return self._send(400, {"outcome": "rejected"})
        self._send(200, REFEREE.submit(candidate))


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8091), Handler).serve_forever()
