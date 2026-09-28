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
    def test_fresh_core_selection_keeps_backup_file_out_of_gate(self) -> None:
        self.assertNotIn("hardware-backup", check_pi_env.selected_services("all", without_backup=True))
        self.assertIn("hardware-backup", check_pi_env.selected_services("all"))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shared = root / "honeypot-agent.env"
            shared_keys = {"REDIS_ADDR", "REDIS_DB"}
            for service in check_pi_env.selected_services("all", without_backup=True):
                shared_keys |= check_pi_env.SERVICE_SHARED_KEYS[service]
            shared_keys -= {"SENSOR_ZT_IP", "SENSOR_ZT_IFACE"}
            shared.write_text("".join(f"{key}=synthetic\n" for key in sorted(shared_keys)))
            shared.chmod(0o600)
            private = root / "honeypot"
            private.mkdir()
            for name in ("processor.env", "ti-worker.env"):
                path = private / name
                path.write_text("# operator-specific optional values\n")
                path.chmod(0o600)
            hardware = private / "hardware.env"
            hardware.write_text("NETWORK_INTERFACES=wlan0\nNETWORK_PRIMARY_INTERFACE=wlan0\nNETWORK_SAMPLE_SECONDS=1\n")
            hardware.chmod(0o600)
            self.assertEqual(check_pi_env.check_services(root, check_pi_env.selected_services("all", without_backup=True), require_owner=False, profile="fresh-wifi"), [])
            self.assertTrue(any("backup.env" in item for item in check_pi_env.check_services(root, check_pi_env.selected_services("all"), require_owner=False, profile="fresh-wifi")))

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
            hardware.write_text("NETWORK_INTERFACES=eth0\nNETWORK_PRIMARY_INTERFACE=eth0\nNETWORK_SAMPLE_SECONDS=1\n")
            hardware.chmod(0o600)
            self.assertEqual(
                check_pi_env.check_services(root, ["hardware"], require_owner=False), []
            )

    def test_hardware_sample_interval_is_required_and_positive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shared = root / "honeypot-agent.env"
            shared.write_text("REDIS_ADDR=127.0.0.1:6379\nREDIS_DB=0\n")
            shared.chmod(0o600)
            hardware = root / "honeypot/hardware.env"
            hardware.parent.mkdir()
            hardware.write_text("NETWORK_INTERFACES=eth0\nNETWORK_PRIMARY_INTERFACE=eth0\n")
            hardware.chmod(0o600)
            self.assertTrue(any("NETWORK_SAMPLE_SECONDS" in error for error in check_pi_env.check_services(root, ["hardware"], require_owner=False)))
            hardware.write_text("NETWORK_INTERFACES=eth0\nNETWORK_PRIMARY_INTERFACE=eth0\nNETWORK_SAMPLE_SECONDS=0\n")
            self.assertTrue(any("positive integer" in error for error in check_pi_env.check_services(root, ["hardware"], require_owner=False)))

    def test_fresh_wifi_profile_does_not_require_unused_overlay_address(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shared = root / "honeypot-agent.env"
            keys = check_pi_env.SERVICE_SHARED_KEYS["collector"] - {"SENSOR_ZT_IP", "SENSOR_ZT_IFACE"}
            shared.write_text("REDIS_ADDR=127.0.0.1:6379\nREDIS_DB=0\n" + "".join(f"{key}=synthetic\n" for key in sorted(keys)))
            shared.chmod(0o600)
            self.assertEqual(check_pi_env.check_services(root, ["collector"], require_owner=False, profile="fresh-wifi"), [])
            self.assertTrue(any("SENSOR_ZT_IP" in item for item in check_pi_env.check_services(root, ["collector"], require_owner=False)))


if __name__ == "__main__":
    unittest.main()
