"""Safety checks for the resumable Pi installer entry point."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load_script("install_pi_sensor.py")
runtime = load_script("check_pi_runtime.py")


class InstallerEntryTests(unittest.TestCase):
    def test_reviewed_vars_require_exact_package_versions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "vars.json"
            path.write_text(json.dumps({
                "pti_release_id": "r1",
                "pti_release_source": "/tmp/releases/r1",
                "pti_manifest_sha256": "a" * 64,
                "pti_package_versions": {
                    "ca-certificates": "1", "python3": "2",
                    "python3-venv": "3", "redis-server": "REPLACE_WITH_VERSION",
                },
            }))
            with self.assertRaises(installer.InstallError):
                installer.load_vars(path)

    def test_new_bundle_pauses_for_digest_review_before_ansible(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            release = Path(temp) / "r1"
            release.mkdir()
            (release / "manifest.json").write_text("{}")
            with patch.object(installer, "run") as command:
                self.assertFalse(installer.ensure_release("r1", release, None))
                command.assert_not_called()

    def test_inventory_must_select_exactly_one_host(self) -> None:
        with patch.object(installer, "run", return_value=json.dumps({"pi_sensors": {"hosts": ["a", "b"]}})):
            with self.assertRaises(installer.InstallError):
                installer.validate_one_host(Path("/tmp/inventory.ini"))

    def test_redis_config_rejects_public_binding_and_include(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "redis.conf"
            path.write_text("bind 0.0.0.0\nprotected-mode yes\ninclude /tmp/extra.conf\n")
            errors = runtime.check_redis_config(path)
            self.assertTrue(any("loopback" in item for item in errors))
            self.assertTrue(any("include" in item for item in errors))

    def test_redis_config_accepts_loopback_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "redis.conf"
            path.write_text("bind 127.0.0.1 -::1\nprotected-mode yes\nport 6379\n")
            self.assertEqual(runtime.check_redis_config(path), [])


if __name__ == "__main__":
    unittest.main()
