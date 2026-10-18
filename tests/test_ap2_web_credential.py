import importlib.util
import hmac
import os
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
SSH_CREDENTIAL_PATH = ROOT / "challenge-ap2-ssh" / "credential.py"


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
    with mock.patch.dict(sys.modules, {"flask": flask}):
        spec.loader.exec_module(module)
    return module


def load_ssh_credential():
    spec = importlib.util.spec_from_file_location("ap2_ssh_credential_test", SSH_CREDENTIAL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AP02WebCredentialTests(unittest.TestCase):
    def test_password_rotation_updates_only_ap2_record_and_matches_ssh(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            web = load_web_app()
            ssh = load_ssh_credential()
            web.DB_PATH = str(Path(directory) / "crm.db")
            first = secrets.token_urlsafe(36)
            second = secrets.token_urlsafe(36)
            with mock.patch.dict(os.environ, {web.AP2_PASSWORD_ENV: first}):
                web.init_db()
            db = sqlite3.connect(web.DB_PATH)
            try:
                before_users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
                before_customers = db.execute("SELECT * FROM customers ORDER BY id").fetchall()
            finally:
                db.close()
            with mock.patch.dict(os.environ, {web.AP2_PASSWORD_ENV: second}):
                web.init_db()
                self.assertEqual(ssh.AP2_PASSWORD_ENV, web.AP2_PASSWORD_ENV)
                self.assertTrue(ssh.verify_password("ap02user", second))
                self.assertFalse(ssh.verify_password("ap02user", first))
            db = sqlite3.connect(web.DB_PATH)
            try:
                self.assertEqual(db.execute("SELECT * FROM users ORDER BY id").fetchall(), before_users)
                self.assertEqual(db.execute("SELECT * FROM customers ORDER BY id").fetchall(), before_customers)
                row = db.execute("SELECT id, username, password FROM ap2_ssh_credential").fetchone()
                self.assertEqual(db.execute("SELECT COUNT(*) FROM ap2_ssh_credential").fetchone()[0], 1)
            finally:
                db.close()
            self.assertEqual(row[:2], (1, "ap02user"))
            self.assertTrue(hmac.compare_digest(row[2], second))

    def test_invalid_password_is_rejected_without_exposing_value(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            web = load_web_app()
            web.DB_PATH = str(Path(directory) / "crm.db")
            for invalid in ("", "short", "x" * 32 + "\n"):
                with mock.patch.dict(os.environ, {web.AP2_PASSWORD_ENV: invalid}):
                    with self.assertRaisesRegex(ValueError, "invalid AP-02 password configuration"):
                        web.init_db()

    def test_sqli_discovered_password_authenticates_ssh(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            web = load_web_app()
            ssh = load_ssh_credential()
            web.DB_PATH = str(Path(directory) / "crm.db")
            password = secrets.token_urlsafe(36)
            with mock.patch.dict(os.environ, {web.AP2_PASSWORD_ENV: password}):
                web.init_db()
                web.request = types.SimpleNamespace(args={
                    "id": "-1 UNION SELECT 0,username,'','',password FROM ap2_ssh_credential"
                })
                rows = web.customer()["customers"]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["name"], "ap02user")
                self.assertTrue(ssh.verify_password(rows[0]["name"], rows[0]["secret"]))
                self.assertFalse(ssh.verify_password(rows[0]["name"], "wrong-password"))


if __name__ == "__main__":
    unittest.main()
