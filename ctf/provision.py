"""Provision untracked CTF runtime artifacts without printing secrets."""
from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

ROOT = Path(os.environ.get("K3DF_CTF_RUNTIME_DIR", "runtime/ctf"))
FLAG_PREFIX = "K3DF{"


def _secret() -> str:
    return FLAG_PREFIX + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=") + "}"


def _write_new(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(value + "\n")


def provision(hint: str) -> None:
    if not hint.strip() or hint.strip().lower() in {"placeholder", "todo"}:
        raise ValueError("A non-placeholder private Flag 1 hint is required.")
    if ROOT.exists() and any(ROOT.iterdir()):
        raise FileExistsError("CTF runtime already exists; refusing to overwrite.")
    for number in range(1, 4):
        _write_new(ROOT / f"flag-{number}" / f"flag-{number}.value", _secret())
    _write_new(ROOT / "flag-1" / "flag-1-hint.txt", hint)
    _write_new(ROOT / "run" / "run-id", "run-" + secrets.token_urlsafe(18))
    _write_new(ROOT / "run" / "run-auth.token", secrets.token_urlsafe(32))


if __name__ == "__main__":
    # Deliberately do not accept a hint or secret on the command line.
    raise SystemExit("Import provision() from trusted operator automation; no secrets are accepted by CLI.")
