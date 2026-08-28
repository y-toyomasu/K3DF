import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


PROVISION = Path(__file__).resolve().parents[1] / "ctf" / "provision.py"


def load_provision(root: str):
    os.environ["K3DF_CTF_RUNTIME_DIR"] = root
    spec = importlib.util.spec_from_file_location("test_ctf_provision", PROVISION)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class ProvisionTests(unittest.TestCase):
    def test_generates_three_unique_flags_and_run_material_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            module = load_provision(directory)
            module.provision("Private hint supplied by trusted operator")
            root = Path(directory)
            flags = [(root / f"flag-{number}" / f"flag-{number}.value").read_text().strip() for number in range(1, 4)]
            self.assertEqual(len(set(flags)), 3)
            self.assertTrue(all(module.FLAG_PREFIX in value and len(value) == 49 for value in flags))
            token = (root / "run" / "run-auth.token").read_text().strip()
            self.assertEqual(len(token), 43)
            with self.assertRaises(FileExistsError):
                module.provision("Other private hint")

    def test_rejects_empty_or_placeholder_hints(self):
        for hint in ("", "  ", "placeholder", "TODO"):
            with self.subTest(hint=hint), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    load_provision(directory).provision(hint)


if __name__ == "__main__":
    unittest.main()
