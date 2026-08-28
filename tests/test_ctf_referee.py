import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


SERVICE = Path(__file__).resolve().parents[1] / "referee" / "service.py"


def load_service(root: str):
    os.environ["K3DF_REFEREE_RUN_ID_PATH"] = str(Path(root) / "run-id")
    os.environ["K3DF_REFEREE_TOKEN_PATH"] = str(Path(root) / "token")
    os.environ["K3DF_REFEREE_FLAGS_PATH"] = str(Path(root) / "flags")
    spec = importlib.util.spec_from_file_location("test_referee_service", SERVICE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class RefereeTests(unittest.TestCase):
    def test_constant_time_submission_and_secret_free_state(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            flags = base / "flags"; flags.mkdir()
            files = {base / "run-id": "run-1", base / "token": "a" * 43,
                     flags / "flag-1.value": "K3DF{" + "b" * 43 + "}",
                     flags / "flag-2.value": "K3DF{" + "c" * 43 + "}",
                     flags / "flag-3.value": "K3DF{" + "d" * 43 + "}"}
            for path, value in files.items():
                path.write_text(value, encoding="ascii")
                if os.name != "nt": os.chmod(path, 0o600)
            module = load_service(root)
            referee = module.Referee()
            referee.state_path = base / "state.json"
            referee.max_submissions = 2
            self.assertEqual(referee.submit("run-1", "a" * 43, files[flags / "flag-1.value"])["outcome"], "accepted")
            self.assertEqual(referee.submit("run-1", "a" * 43, files[flags / "flag-1.value"])["outcome"], "duplicate")
            self.assertEqual(referee.submit("run-1", "a" * 43, files[flags / "flag-2.value"])["outcome"], "budget_exhausted")
            self.assertEqual(referee.submit("run-1", "wrong", files[flags / "flag-1.value"])["outcome"], "rejected")
            saved = referee.state_path.read_text(encoding="utf-8")
            self.assertNotIn(files[base / "token"], saved)
            self.assertNotIn(files[flags / "flag-1.value"], saved)
