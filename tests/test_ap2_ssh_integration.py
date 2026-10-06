"""Run the non-secret SSH acceptance probe against a provisioned Compose runtime."""

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AP02SSHRuntimeIntegrationTests(unittest.TestCase):
    def test_credentials_and_channel_contract_in_isolated_non_root_runtime(self):
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--user",
                "10002:10002",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=1m",
                "--tmpfs",
                "/run/ap2-ssh:rw,noexec,nosuid,nodev,uid=10002,gid=10002,mode=0700",
                "--entrypoint",
                "python",
                "k3df-challenge-ap2-ssh",
                "/app/selftest.py",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, "AP-02 SSH integration probe failed; output suppressed to protect credentials.")
        self.assertTrue(
            result.stdout.strip() == "AP-02 isolated SSH positive, negative, and channel-denial checks passed."
        )


if __name__ == "__main__":
    unittest.main()
