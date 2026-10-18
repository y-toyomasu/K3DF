"""Validate the AP-02 password supplied by Compose."""

import hmac
import os


USERNAME = "ap02user"
AP2_PASSWORD_ENV = "K3DF_AP2_SSH_PASSWORD"


def configured_password() -> str:
    password = os.environ.get(AP2_PASSWORD_ENV)
    if password is None or len(password) < 32 or any(char in password for char in "\r\n\0"):
        raise ValueError("invalid AP-02 password configuration")
    return password


def verify_password(username: str, password: str) -> bool:
    """Compare an SSH virtual account to the configured password."""
    if username != USERNAME or not isinstance(password, str):
        return False
    try:
        expected_password = configured_password()
    except ValueError:
        return False
    return hmac.compare_digest(password, expected_password)
