import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_sensor_release import EXPECTED, verify_release


class VerifySensorReleaseTests(unittest.TestCase):
    @staticmethod
    def manifest_sha256(release: Path) -> str:
        return hashlib.sha256((release / "manifest.json").read_bytes()).hexdigest()

    def make_release(self, root: Path) -> Path:
        release = root / "r1"
        binary_dir = release / "bin"
        binary_dir.mkdir(parents=True)
        modules = []
        lines = []
        for module_id, (module_path, binary_name) in EXPECTED.items():
            payload = f"test-{module_id}".encode()
            (binary_dir / binary_name).write_bytes(payload)
            (binary_dir / binary_name).chmod(0o755)
            digest = hashlib.sha256(payload).hexdigest()
            modules.append({
                "id": module_id, "module": module_path,
                "binary": f"bin/{binary_name}", "sha256": digest,
                "size_bytes": len(payload), "test_command": "go test ./...",
                "test_result": "passed",
            })
            lines.append(f"{digest}  bin/{binary_name}")
        (release / "manifest.json").write_text(json.dumps({
            "schema_version": "pti.sensor-release.v1",
            "release_id": "r1",
            "source_commit": "a" * 40,
            "built_at_utc": "2026-09-28T00:00:00+00:00",
            "go_version": "go version go1.27.1 linux/amd64",
            "target": {"goos": "linux", "goarch": "arm64", "cgo_enabled": False},
            "module_downloads": "disabled; dependencies must already be cached",
            "runtime_configuration_included": False,
            "modules": modules,
        }))
        (release / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        return release

    def test_accepts_builder_shape_and_rejects_changed_binary(self):
        with tempfile.TemporaryDirectory() as temp:
            release = self.make_release(Path(temp))
            digest = self.manifest_sha256(release)
            verify_release(release, "r1", digest)
            (release / "bin/pti-collector").write_bytes(b"X" * len(b"test-collector"))
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                verify_release(release, "r1", digest)

    def test_rejects_private_or_extra_content(self):
        with tempfile.TemporaryDirectory() as temp:
            release = self.make_release(Path(temp))
            digest = self.manifest_sha256(release)
            (release / ".env").write_text("placeholder")
            with self.assertRaisesRegex(ValueError, "unexpected release content"):
                verify_release(release, "r1", digest)

    def test_rejects_manifest_change_even_when_internal_hashes_match(self):
        with tempfile.TemporaryDirectory() as temp:
            release = self.make_release(Path(temp))
            approved = self.manifest_sha256(release)
            manifest = json.loads((release / "manifest.json").read_text())
            manifest["built_at_utc"] = "changed"
            (release / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "approved digest"):
                verify_release(release, "r1", approved)

    def test_rejects_unexpected_manifest_field_with_matching_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            release = self.make_release(Path(temp))
            manifest = json.loads((release / "manifest.json").read_text())
            manifest["private_config"] = "should never be packaged"
            (release / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "unexpected release manifest fields"):
                verify_release(release, "r1", self.manifest_sha256(release))

    def test_rejects_malformed_manifest_shape(self):
        with tempfile.TemporaryDirectory() as temp:
            release = self.make_release(Path(temp))
            (release / "manifest.json").write_text("[]")
            with self.assertRaisesRegex(ValueError, "must be an object"):
                verify_release(release, "r1", self.manifest_sha256(release))


if __name__ == "__main__":
    unittest.main()
