import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_sensor_release import EXPECTED, verify_release


class VerifySensorReleaseTests(unittest.TestCase):
    def make_release(self, root: Path) -> Path:
        release = root / "r1"
        binary_dir = release / "bin"
        binary_dir.mkdir(parents=True)
        modules = []
        lines = []
        for module_id, binary_name in EXPECTED.items():
            payload = f"test-{module_id}".encode()
            (binary_dir / binary_name).write_bytes(payload)
            (binary_dir / binary_name).chmod(0o755)
            digest = hashlib.sha256(payload).hexdigest()
            modules.append({"id": module_id, "binary": f"bin/{binary_name}", "sha256": digest})
            lines.append(f"{digest}  bin/{binary_name}")
        (release / "manifest.json").write_text(json.dumps({
            "schema_version": "pti.sensor-release.v1",
            "release_id": "r1",
            "target": {"goos": "linux", "goarch": "arm64", "cgo_enabled": False},
            "runtime_configuration_included": False,
            "modules": modules,
        }))
        (release / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        return release

    def test_accepts_builder_shape_and_rejects_changed_binary(self):
        with tempfile.TemporaryDirectory() as temp:
            release = self.make_release(Path(temp))
            verify_release(release, "r1")
            (release / "bin/pti-collector").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verify_release(release, "r1")

    def test_rejects_private_or_extra_content(self):
        with tempfile.TemporaryDirectory() as temp:
            release = self.make_release(Path(temp))
            (release / ".env").write_text("placeholder")
            with self.assertRaisesRegex(ValueError, "unexpected release content"):
                verify_release(release, "r1")


if __name__ == "__main__":
    unittest.main()
