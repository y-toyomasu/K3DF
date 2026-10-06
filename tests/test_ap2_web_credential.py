import importlib.util
import hmac
import io
import json
import secrets
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "web" / "app.py"


class _FlaskStub:
    def __init__(self, *args, **kwargs):
        pass

    def route(self, *args, **kwargs):
        return lambda handler: handler


def load_web_app():
    flask = types.ModuleType("flask")
    flask.Flask = _FlaskStub
    flask.Response = object
    flask.request = object()
    spec = importlib.util.spec_from_file_location("ap2_web_app_test", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    with mock.patch.dict(sys.modules, {"flask": flask}):
        spec.loader.exec_module(module)
    return module


class AP02WebCredentialTests(unittest.TestCase):
    def test_credential_is_separate_from_normal_customer_rows_and_reprovisionable(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            module = load_web_app()
            module.DB_PATH = str(Path(directory) / "crm.db")
            module.init_db()
            first_password = secrets.token_urlsafe(36)
            second_password = secrets.token_urlsafe(36)

            module.provision_ap2_ssh_credential(
                io.StringIO(json.dumps({"username": "ap02user", "password": first_password}))
            )
            module.provision_ap2_ssh_credential(
                io.StringIO(json.dumps({"username": "ap02user", "password": second_password}))
            )

            connection = sqlite3.connect(module.DB_PATH)
            try:
                customer_count = connection.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
                ap2 = connection.execute("SELECT username, password FROM ap2_ssh_credential WHERE id = 1").fetchone()
            finally:
                connection.close()
            self.assertEqual(customer_count, 3)
            self.assertEqual(ap2[0], "ap02user")
            self.assertTrue(hmac.compare_digest(ap2[1], second_password))

    def test_rejects_unscoped_or_malformed_credential(self):
        module = load_web_app()
        for payload in (
            "{}",
            json.dumps({"username": "root", "password": secrets.token_urlsafe(36)}),
            "not-json",
        ):
            with self.subTest(payload_kind=type(payload).__name__), self.assertRaises(ValueError):
                module.provision_ap2_ssh_credential(io.StringIO(payload))


if __name__ == "__main__":
    unittest.main()
