import importlib.util
import os
import secrets
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ap2_ssh_credential", ROOT / "challenge-ap2-ssh" / "credential.py"
)
credential = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(credential)


class AP02SSHCredentialContractTests(unittest.TestCase):
    def test_environment_password_authentication_and_invalid_configuration(self):
        password = secrets.token_urlsafe(36)
        with mock.patch.dict(os.environ, {credential.AP2_PASSWORD_ENV: password}):
            self.assertTrue(credential.verify_password("ap02user", password))
            self.assertFalse(credential.verify_password("ap02user", "wrong-password"))
            self.assertFalse(credential.verify_password("wrong-user", password))
        for invalid in (None, "", "short", "x" * 32 + "\n"):
            environment = {} if invalid is None else {credential.AP2_PASSWORD_ENV: invalid}
            with mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(ValueError, "invalid AP-02 password configuration"):
                    credential.configured_password()

    def test_runtime_is_isolated_and_compose_requires_shared_password(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        dockerfile = (ROOT / "challenge-ap2-ssh" / "Dockerfile").read_text(encoding="utf-8")
        web = compose.split("  web:\n", 1)[1].split("\n  nginx:", 1)[0]
        runtime = compose.split("  challenge-ap2-ssh:\n", 1)[1].split("\nvolumes:", 1)[0]
        required = "K3DF_AP2_SSH_PASSWORD: ${K3DF_AP2_SSH_PASSWORD:?Set K3DF_AP2_SSH_PASSWORD in .env before startup}"

        self.assertIn(required, web)
        self.assertIn(required, runtime)
        self.assertNotIn("challenge-ap2-ssh-provision", compose)
        self.assertNotIn("k3df-ap2-ssh-runtime", compose)
        self.assertIn('user: "10002:10002"', runtime)
        self.assertIn("read_only: true", runtime)
        self.assertIn('"2222:2222"', runtime)
        self.assertIn("internal: true", compose)
        self.assertIn("cap_drop:\n      - ALL", runtime)
        self.assertNotIn("privileged:", runtime)
        self.assertNotIn("NET_ADMIN", runtime)
        self.assertNotIn("/var/run/docker.sock", runtime)
        self.assertNotIn("/host", runtime)
        self.assertIn("USER 10002:10002", dockerfile)


if __name__ == "__main__":
    unittest.main()
