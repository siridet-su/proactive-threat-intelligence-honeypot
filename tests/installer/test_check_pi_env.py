"""Contract tests for the value-redacting, read-only Pi env gate."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check_pi_env.py"
spec = importlib.util.spec_from_file_location("check_pi_env", SCRIPT)
assert spec and spec.loader
check_pi_env = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_pi_env)


class CheckPiEnvTests(unittest.TestCase):
    def test_missing_values_and_private_values_are_never_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = root / "honeypot-agent.env"
            env.write_text("REDIS_ADDR=127.0.0.1:6379\nREDIS_DB=0\nMONGO_URI=private-value\n")
            env.chmod(0o600)
            errors = check_pi_env.check_services(root, ["collector"], require_owner=False)
            self.assertTrue(any("COWRIE_LOG_FILE" in item for item in errors))
            self.assertFalse(any("private-value" in item for item in errors))

    def test_symlink_and_loose_mode_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = root / "honeypot-agent.env"
            env.write_text("REDIS_ADDR=127.0.0.1:6379\nREDIS_DB=0\n")
            env.chmod(0o644)
            _, errors = check_pi_env.check_file(env, require_owner=False)
            self.assertIn("mode must be 0600", errors)
            link = root / "linked.env"
            link.symlink_to(env)
            _, errors = check_pi_env.check_file(link, require_owner=False)
            self.assertTrue(any("regular file" in item for item in errors))

    def test_selected_hardware_files_pass_without_other_service_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shared = root / "honeypot-agent.env"
            shared.write_text("REDIS_ADDR=127.0.0.1:6379\nREDIS_DB=0\n")
            shared.chmod(0o600)
            hardware = root / "honeypot/hardware.env"
            hardware.parent.mkdir()
            hardware.write_text("NETWORK_INTERFACES=eth0\nNETWORK_PRIMARY_INTERFACE=eth0\n")
            hardware.chmod(0o600)
            self.assertEqual(
                check_pi_env.check_services(root, ["hardware"], require_owner=False), []
            )


if __name__ == "__main__":
    unittest.main()
