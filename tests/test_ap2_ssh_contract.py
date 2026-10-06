import importlib.util
import hmac
import json
import os
import secrets
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ap2_ssh_credential", ROOT / "challenge-ap2-ssh" / "credential.py"
)
credential = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(credential)


class AP02SSHCredentialContractTests(unittest.TestCase):
    def test_private_credential_is_written_atomically_and_checked(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "run" / "credential.json"
            password = secrets.token_urlsafe(36)
            payload = json.dumps({"username": "ap02user", "password": password}).encode("utf-8")
            try:
                credential.write_credential(payload.decode("utf-8"), path)

                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
                self.assertTrue(credential.verify_password("ap02user", password, path))
                self.assertFalse(credential.verify_password("wrong-user", password, path))
                self.assertFalse(credential.verify_password("ap02user", "wrong-password", path))
            finally:
                if path.exists():
                    path.chmod(0o600)

    def test_rejects_malformed_material_without_replacing_existing_value(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "credential.json"
            original = json.dumps({"username": "ap02user", "password": secrets.token_urlsafe(36)}).encode("utf-8")
            try:
                credential.write_credential(original.decode("utf-8"), path)
                stored = path.read_bytes()

                for payload in ("{}", json.dumps({"username": "root", "password": secrets.token_urlsafe(36)}), "not-json"):
                    with self.subTest(payload_type=type(payload).__name__), self.assertRaises(ValueError):
                        credential.write_credential(payload, path)
                    self.assertTrue(hmac.compare_digest(path.read_bytes(), stored))
            finally:
                if path.exists():
                    path.chmod(0o600)

    def test_runtime_configuration_is_non_root_isolated_and_publishes_only_ssh_port(self):
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        dockerfile = (ROOT / "challenge-ap2-ssh" / "Dockerfile").read_text(encoding="utf-8")
        runtime = compose.split("  challenge-ap2-ssh:\n", 1)[1].split("\n  challenge-ap2-ssh-provision:", 1)[0]

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
