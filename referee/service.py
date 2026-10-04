"""Independent CTF referee with a shared demo validation seed."""
from __future__ import annotations

import hmac
import json
import os
import re
import stat
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

FLAG_RE = re.compile(r"^K3DF\{[A-Za-z0-9_-]{43}\}$")
MAX_BODY = 4096
DEFAULT_SEED = "ValidationSeed"
REFEREE_UID = 10001
REFEREE_GID = 10001
FLAG_READER_GID = 20001


class InitializationError(RuntimeError):
    """Safe initialization diagnostic that never includes mounted paths or values."""


def file_type(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular-file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def initialization_error(category: str, target: str, check: str, expected: str, actual: str) -> InitializationError:
    return InitializationError(
        f"Referee initialization failed: category={category}; target={target}; "
        f"check={check}; expected={expected}; actual={actual}."
    )


def metadata_summary(metadata) -> str:
    return (
        f"type={file_type(metadata.st_mode)},uid={metadata.st_uid},gid={metadata.st_gid},"
        f"mode={stat.S_IMODE(metadata.st_mode):04o}"
    )


def read_flag(flag_id: str, path: str) -> str:
    try:
        candidate = Path(path)
        metadata = candidate.lstat()
    except OSError:
        raise initialization_error("flag-artifact", flag_id, "placement", "regular-file", "missing-or-unreadable") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise initialization_error("flag-artifact", flag_id, "file-type", "regular-file", file_type(metadata.st_mode))
    if metadata.st_size <= 0 or metadata.st_size > 512:
        raise initialization_error("flag-artifact", flag_id, "size", "1-512-bytes", str(metadata.st_size))
    if metadata.st_uid != 0 or metadata.st_gid != FLAG_READER_GID or stat.S_IMODE(metadata.st_mode) != 0o440 or metadata.st_mode & 0o222:
        raise initialization_error("flag-artifact", flag_id, "ownership-and-mode", "uid=0,gid=20001,mode=0440", metadata_summary(metadata))
    try:
        value = candidate.read_text(encoding="ascii").strip()
        if not FLAG_RE.fullmatch(value):
            raise initialization_error("flag-artifact", flag_id, "format", "K3DF{43-safe-characters}", "invalid")
        return value
    except (OSError, UnicodeError):
        raise initialization_error("flag-artifact", flag_id, "content-read", "ascii-readable-flag", "unreadable") from None


def validate_state_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise initialization_error("referee-state", "state-directory", "placement", "directory", "missing-or-unreadable") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise initialization_error("referee-state", "state-directory", "file-type", "directory", file_type(metadata.st_mode))
    if metadata.st_uid != REFEREE_UID or metadata.st_gid != REFEREE_GID or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise initialization_error("referee-state", "state-directory", "ownership-and-mode", "uid=10001,gid=10001,mode=0700", metadata_summary(metadata))


def valid_seed(value: str) -> bool:
    return 1 <= len(value) <= 128 and all(32 <= ord(character) <= 126 for character in value)


class Referee:
    def __init__(self):
        self.seed = os.environ.get("K3DF_CTF_DEMO_SEED", DEFAULT_SEED)
        if not valid_seed(self.seed):
            raise initialization_error("configuration", "K3DF_CTF_DEMO_SEED", "format", "1-128-printable-ascii-characters", "invalid")
        flag_root = os.environ.get("K3DF_REFEREE_FLAGS_PATH", "/run/referee-flags")
        self.flags = {
            f"flag-{number}": read_flag(f"flag-{number}", f"{flag_root}/flag-{number}/flag.value")
            for number in range(1, 4)
        }
        if len(set(self.flags.values())) != 3:
            raise initialization_error("flag-artifact", "flag-set", "uniqueness", "three-distinct-values", "duplicate-values")
        self.state_path = Path(os.environ.get("K3DF_REFEREE_STATE_PATH", "/state/referee.json"))
        validate_state_directory(self.state_path.parent)
        try:
            self.max_submissions = int(os.environ.get("K3DF_REFEREE_MAX_SUBMISSIONS", "30"))
        except ValueError:
            raise initialization_error("configuration", "K3DF_REFEREE_MAX_SUBMISSIONS", "integer", "positive-integer", "invalid") from None
        if self.max_submissions <= 0:
            raise initialization_error("configuration", "K3DF_REFEREE_MAX_SUBMISSIONS", "range", "positive-integer", str(self.max_submissions))
        self.lock = threading.Lock()
        self.accepted, self.submission_attempts = self._load()

    def _load(self):
        if not self.state_path.exists():
            return set(), 0
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            accepted = data.get("accepted", [])
            attempts = data.get("submission_attempts", 0)
            if not isinstance(accepted, list) or not all(item in self.flags for item in accepted) or not isinstance(attempts, int) or attempts < 0:
                raise ValueError
            return set(accepted), attempts
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, AttributeError):
            raise initialization_error("referee-state", "state-file", "content", "valid-state-schema", "invalid-or-unreadable") from None

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


REFEREE: Referee | None = None


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


def main() -> int:
    global REFEREE
    try:
        REFEREE = Referee()
    except InitializationError as error:
        print(error, file=sys.stderr)
        return 1
    ThreadingHTTPServer(("0.0.0.0", 8091), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
