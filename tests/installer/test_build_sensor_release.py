import unittest

from scripts.build_sensor_release import (
    AGENTS,
    ReleaseBuildError,
    parse_go_version,
    release_plan,
    validate_release_id,
)


class SensorReleaseTests(unittest.TestCase):
    def test_release_plan_is_linux_arm64_and_does_not_install(self):
        plan = release_plan("2026.09.25-test1")

        self.assertEqual(plan["target"], {"goos": "linux", "goarch": "arm64", "cgo_enabled": False})
        self.assertFalse(plan["install_or_service_changes"])
        self.assertEqual(len(plan["agents"]), 6)
        self.assertEqual(tuple(item[0] for item in AGENTS), tuple(item["id"] for item in plan["agents"]))

    def test_release_id_rejects_path_traversal_and_unsafe_characters(self):
        for release_id in ("../escape", "", "bad/name", "..", "-leading"):
            with self.subTest(release_id=release_id), self.assertRaises(ReleaseBuildError):
                validate_release_id(release_id)

    def test_release_id_accepts_simple_version_label(self):
        validate_release_id("v1.2.3-arm64")

    def test_parse_go_version(self):
        self.assertEqual(parse_go_version("go version go1.26.3 linux/arm64"), (1, 26, 3))

    def test_unparseable_go_version_is_rejected(self):
        with self.assertRaises(ReleaseBuildError):
            parse_go_version("unknown compiler")


if __name__ == "__main__":
    unittest.main()
