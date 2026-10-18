"""Read and validate the private, runtime-only AP-02 credential artifact."""

import hmac
import json
import os
import stat
import sys
import tempfile
from pathlib import Path


CREDENTIAL_PATH = Path("/run/ap2-ssh/credential.json")
USERNAME = "ap02user"
AP2_PASSWORD_ENV = "K3DF_AP2_SSH_PASSWORD"


def configured_password() -> str | None:
    password = os.environ.get(AP2_PASSWORD_ENV)
    if password is not None and (len(password) < 32 or any(char in password for char in "\r\n\0")):
        raise ValueError("invalid AP-02 password configuration")
    return password


def _decode(raw: bytes) -> tuple[str, str]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid credential material") from exc
    if not isinstance(value, dict) or set(value) != {"username", "password"}:
        raise ValueError("invalid credential material")
    username = value["username"]
    password = value["password"]
    if username != USERNAME or not isinstance(password, str) or len(password) < 32:
        raise ValueError("invalid credential material")
    if any(char in password for char in "\r\n\0"):
        raise ValueError("invalid credential material")
    return username, password


def verify_password(username: str, password: str, path: Path = CREDENTIAL_PATH) -> bool:
    """Compare an SSH virtual account to protected runtime material."""
    if username != USERNAME or not isinstance(password, str):
        return False
    try:
        expected_password = configured_password()
        if expected_password is None:
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or (os.name == "posix" and metadata.st_mode & 0o077):
                return False
            expected_user, expected_password = _decode(path.read_bytes())
        else:
            expected_user = USERNAME
    except (OSError, ValueError):
        return False
    return hmac.compare_digest(username, expected_user) and hmac.compare_digest(password, expected_password)


def write_credential(source, path: Path = CREDENTIAL_PATH) -> None:
    """Atomically replace runtime material from stdin without echoing it."""
    if isinstance(source, bytes):
        payload = source
    elif isinstance(source, str):
        payload = source.encode("utf-8")
    else:
        payload = source.buffer.read() if hasattr(source, "buffer") else source.read()
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    username, password = _decode(payload)
    encoded = json.dumps({"username": username, "password": password}, separators=(",", ":")).encode("utf-8")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".credential-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_name, 0o400)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
