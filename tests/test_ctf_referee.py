import http.client
import importlib.util
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SERVICE = Path(__file__).resolve().parents[1] / "referee" / "service.py"


def load_service(root: Path, seed: str | None = "DemoSeed"):
    flags = root / "flags"
    flags.mkdir()
    values = [f"K3DF{{{character * 43}}}" for character in ("a", "b", "c")]
    for number, value in enumerate(values, start=1):
        flag_directory = flags / f"flag-{number}"
        flag_directory.mkdir()
        flag_path = flag_directory / "flag.value"
        flag_path.write_text(value, encoding="ascii")
    state_directory = root / "state"
    state_directory.mkdir()
    os.environ["K3DF_REFEREE_FLAGS_PATH"] = str(flags)
    os.environ["K3DF_REFEREE_STATE_PATH"] = str(state_directory / "referee.json")
    os.environ["K3DF_REFEREE_MAX_SUBMISSIONS"] = "30"
    if seed is None:
        os.environ.pop("K3DF_CTF_DEMO_SEED", None)
    else:
        os.environ["K3DF_CTF_DEMO_SEED"] = seed
    name = f"test_referee_service_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, SERVICE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module, values


class RefereeTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.module, self.flags = load_service(self.root)
        self.flag_metadata = {}
        self.state_metadata = (10001, 10001, 0o700)
        self.path_types = {}
        original_lstat = Path.lstat

        def synthetic_lstat(path):
            metadata = original_lstat(path)
            resolved = Path(path)
            kind = self.path_types.get(resolved, stat.S_IFMT(metadata.st_mode))
            if resolved.name == "flag.value":
                uid, gid, mode = self.flag_metadata.get(resolved, (0, 20001, 0o440))
                return SimpleNamespace(st_mode=kind | mode, st_size=metadata.st_size, st_uid=uid, st_gid=gid)
            if resolved == self.root / "state":
                uid, gid, mode = self.state_metadata
                return SimpleNamespace(st_mode=kind | mode, st_size=metadata.st_size, st_uid=uid, st_gid=gid)
            return metadata

        self.lstat_patch = mock.patch.object(self.module.Path, "lstat", synthetic_lstat)
        self.lstat_patch.start()
        self.referee = self.module.Referee()
        self.module.REFEREE = self.referee
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.module.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.lstat_patch.stop()
        self.temporary_directory.cleanup()

    def request(self, method, path, *, headers=None, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        decoded = json.loads(response.read().decode("utf-8"))
        connection.close()
        return response.status, decoded

    def seed_headers(self, value="DemoSeed"):
        return {"X-K3DF-CTF-Demo-Seed": value}

    def submit(self, candidate, seed="DemoSeed"):
        headers = self.seed_headers(seed)
        headers["Content-Type"] = "application/json"
        return self.request("POST", "/ctf/referee/v1/submissions", headers=headers, body=json.dumps({"candidate": candidate}))

    def test_default_seed_and_legacy_run_configuration_are_not_used(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("K3DF_CTF_DEMO_SEED", None)
            self.assertEqual(self.module.Referee().seed, "ValidationSeed")
        self.assertNotIn("K3DF_REFEREE_RUN_ID_PATH", SERVICE.read_text(encoding="utf-8"))
        self.assertNotIn("K3DF_REFEREE_TOKEN_PATH", SERVICE.read_text(encoding="utf-8"))

    def test_health_is_public_and_fixed_status_api_requires_seed(self):
        self.assertEqual(self.request("GET", "/health"), (200, {"status": "ok"}))
        self.assertEqual(self.request("GET", "/ctf/referee/v1/status")[0], 401)
        self.assertEqual(self.request("GET", "/ctf/referee/v1/status", headers=self.seed_headers("wrong"))[0], 401)
        self.assertEqual(self.request("GET", "/ctf/referee/v1/status", headers=self.seed_headers("x" * 129))[0], 400)
        self.assertEqual(self.request("GET", "/ctf/referee/v1/status", headers=self.seed_headers())[0], 200)
        self.assertEqual(self.request("GET", "/ctf/referee/v1/runs/old/status", headers=self.seed_headers())[0], 404)

    def test_submission_is_unordered_duplicate_safe_and_wins_after_three(self):
        self.assertEqual(self.submit(self.flags[2])[1]["outcome"], "accepted")
        self.assertEqual(self.submit(self.flags[2])[1]["outcome"], "duplicate")
        self.assertEqual(self.submit(self.flags[0])[1]["accepted_count"], 2)
        status, result = self.submit(self.flags[1])
        self.assertEqual(status, 200)
        self.assertEqual(result["outcome"], "accepted")
        self.assertTrue(result["won"])

    def test_invalid_requests_and_seed_are_rejected_without_secrets(self):
        self.assertEqual(self.submit("not-a-flag", seed="wrong")[0], 401)
        headers = self.seed_headers()
        headers["Content-Type"] = "application/json"
        self.assertEqual(self.request("POST", "/ctf/referee/v1/submissions", headers=headers, body="[]")[0], 400)
        self.assertEqual(self.request("POST", "/ctf/referee/v1/submissions", headers=self.seed_headers())[0], 400)
        self.assertEqual(self.request("POST", "/ctf/referee/v1/other", headers=headers, body="{}")[0], 400)
        self.submit(self.flags[0])
        saved = self.referee.state_path.read_text(encoding="utf-8")
        self.assertNotIn("DemoSeed", saved)
        self.assertNotIn(self.flags[0], saved)
        self.assertNotIn(str(self.root / "flags"), saved)

    def test_submission_budget_prevents_additional_acceptance(self):
        self.referee.max_submissions = 1
        self.assertEqual(self.submit("not-a-flag")[1]["outcome"], "rejected")
        self.assertEqual(self.submit(self.flags[0])[1]["outcome"], "budget_exhausted")

    def test_invalid_flag_permissions_and_state_directory_fail_closed(self):
        flag_path = self.root / "flags" / "flag-1" / "flag.value"
        self.flag_metadata[flag_path] = (0, 20001, 0o640)
        with self.assertRaisesRegex(RuntimeError, "Invalid flag file"):
            self.module.Referee()
        self.flag_metadata[flag_path] = (0, 20001, 0o440)
        self.state_metadata = (10001, 10001, 0o755)
        with self.assertRaisesRegex(RuntimeError, "Invalid referee state"):
            self.module.Referee()

    def assert_safe_flag_failure(self):
        with self.assertRaises(RuntimeError) as context:
            self.module.Referee()
        self.assertEqual(str(context.exception), "Invalid flag file.")
        self.assertNotIn(str(self.root), str(context.exception))
        self.assertNotIn(self.flags[0], str(context.exception))

    def test_missing_directory_symlink_owner_mode_format_and_non_ascii_flags_are_redacted(self):
        flag_path = self.root / "flags" / "flag-1" / "flag.value"
        flag_path.unlink()
        self.assert_safe_flag_failure()

        flag_path.write_text(self.flags[0], encoding="ascii")
        flag_path.unlink()
        flag_path.mkdir()
        self.assert_safe_flag_failure()

    def test_symlink_owner_mode_format_and_non_ascii_flags_are_redacted(self):
        flag_path = self.root / "flags" / "flag-1" / "flag.value"
        flag_path.unlink()
        self.path_types[flag_path] = stat.S_IFLNK
        self.assert_safe_flag_failure()
        self.path_types.pop(flag_path)

        self.flag_metadata[flag_path] = (0, 0, 0o440)
        self.assert_safe_flag_failure()
        self.flag_metadata[flag_path] = (0, 20001, 0o640)
        self.assert_safe_flag_failure()
        self.flag_metadata[flag_path] = (0, 20001, 0o440)
        flag_path.write_text("K3DF{invalid}", encoding="ascii")
        self.assert_safe_flag_failure()
        flag_path.write_bytes(b"\xff")
        self.assert_safe_flag_failure()

    def test_duplicate_and_corrupt_state_are_redacted(self):
        flag_path = self.root / "flags" / "flag-2" / "flag.value"
        flag_path.write_text(self.flags[0], encoding="ascii")
        with self.assertRaises(RuntimeError) as duplicate:
            self.module.Referee()
        self.assertEqual(str(duplicate.exception), "Duplicate flag values.")
        self.assertNotIn(self.flags[0], str(duplicate.exception))

        flag_path.write_text(self.flags[1], encoding="ascii")
        self.referee.state_path.write_text("{not-json", encoding="utf-8")
        with self.assertRaises(RuntimeError) as state_error:
            self.module.Referee()
        self.assertEqual(str(state_error.exception), "Invalid referee state.")
        self.assertNotIn(str(self.referee.state_path), str(state_error.exception))
        self.assertNotIn("{not-json", str(state_error.exception))
