import json
from contextlib import redirect_stderr
from io import StringIO
import unittest

from scripts.pti_install import (
    DEFAULT_PROFILE,
    ProfileError,
    build_plan,
    build_package_audit,
    build_preflight,
    load_profile,
    main,
    validate_profile,
)


class InstallProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile(DEFAULT_PROFILE)
        cls.full_system_profile = load_profile(
            DEFAULT_PROFILE.with_name("pi-sensor-arm64.json")
        )

    def test_default_profile_is_plan_only_and_does_not_enable_install(self):
        plan = build_plan(
            self.profile,
            {"os_id": "ubuntu", "os_version": "24.04", "architecture": "aarch64"},
        )

        self.assertTrue(plan["plan_only"])
        self.assertFalse(plan["mutations_performed"])
        self.assertFalse(plan["install_enabled"])
        self.assertTrue(plan["target_match"])
        self.assertEqual(plan["target_assessment"], "selected-target-host-match-install-blocked")
        self.assertEqual(plan["profile_id"], "pi-host-foundation-ubuntu-2404-arm64")
        self.assertEqual(
            [module["id"] for module in plan["modules"]],
            ["host-baseline", "base-package-candidates", "private-network", "runtime-layout"],
        )
        self.assertNotIn("redis", [module["id"] for module in plan["modules"]])

    def test_host_dependency_inventory_distinguishes_pi_and_build_host(self):
        dependencies = {entry["id"]: entry for entry in self.profile["host_dependencies"]}

        self.assertEqual(dependencies["go-agent-runtime"]["status"], "not-required-on-pi")
        self.assertIn("python3-venv", dependencies["cowrie-python-runtime"]["items"])
        self.assertEqual(dependencies["data-and-web-later"]["status"], "deferred-by-current-scope")

    def test_package_audit_is_read_only_and_does_not_treat_missing_candidate_as_install(self):
        audit = build_package_audit(
            self.profile,
            {
                "ca-certificates": "installed",
                "curl": "installed",
                "git": "not-installed",
                "python3": "installed",
                "python3-venv": "installed",
            },
        )

        self.assertTrue(audit["read_only"])
        self.assertFalse(audit["mutations_performed"])
        self.assertTrue(audit["audit_completed"])
        self.assertIn("no apt update", audit["package_source"])
        self.assertIn(
            {"name": "git", "status": "not-installed"}, audit["candidate_packages"]
        )

    def test_package_audit_rejects_unsafe_package_names(self):
        profile = json.loads(json.dumps(self.profile))
        profile["package_audit"]["candidate_apt_packages"] = ["curl; reboot"]

        with self.assertRaises(ProfileError):
            validate_profile(profile)

    def test_package_audit_rejects_non_string_package_names(self):
        profile = json.loads(json.dumps(self.profile))
        profile["package_audit"]["candidate_apt_packages"] = [["curl"]]

        with self.assertRaises(ProfileError):
            validate_profile(profile)

    def test_package_audit_marks_unreadable_status_as_unknown(self):
        audit = build_package_audit(self.profile, {})

        self.assertFalse(audit["audit_completed"])
        self.assertTrue(all(row["status"] == "unknown" for row in audit["candidate_packages"]))

    def test_wrong_os_release_is_not_a_target_match(self):
        plan = build_plan(
            self.profile,
            {"os_id": "ubuntu", "os_version": "22.04", "architecture": "aarch64"},
        )

        self.assertFalse(plan["target_match"])
        self.assertEqual(plan["target_assessment"], "host-does-not-match-profile")

    def test_preflight_is_read_only_and_reports_base_prerequisites(self):
        result = build_preflight(
            self.profile,
            {
                "os_id": "ubuntu",
                "os_version": "24.04",
                "architecture": "aarch64",
                "systemd_detected": True,
                "available_tools": {"apt-get": True, "dpkg-query": True},
            },
        )

        self.assertTrue(result["read_only"])
        self.assertFalse(result["mutations_performed"])
        self.assertFalse(result["install_enabled"])
        self.assertTrue(result["preflight_passed"])
        self.assertTrue(all(check["passed"] for check in result["checks"]))

    def test_preflight_fails_for_missing_prerequisite(self):
        result = build_preflight(
            self.profile,
            {
                "os_id": "ubuntu",
                "os_version": "24.04",
                "architecture": "aarch64",
                "systemd_detected": False,
                "available_tools": {"apt-get": True, "dpkg-query": False},
            },
        )

        self.assertFalse(result["preflight_passed"])
        self.assertEqual(
            [check["id"] for check in result["checks"] if not check["passed"]],
            ["systemd", "dpkg-query"],
        )

    def test_modules_are_ordered_with_dependencies_before_consumers(self):
        for profile in (self.profile, self.full_system_profile):
            modules = profile["modules"]
            positions = {module["id"]: index for index, module in enumerate(modules)}

            for module in modules:
                for dependency in module["depends_on"]:
                    self.assertLess(positions[dependency], positions[module["id"]])

    def test_plan_lists_future_services_as_excluded(self):
        excluded = {module["id"] for module in self.profile["excluded_modules"]}

        self.assertTrue(
            {
                "ftp",
                "smtp",
                "odoo",
                "web-corp-direct-https",
                "redis",
                "mongodb-atlas",
                "postgres-deception-core",
                "web-corp-http",
            }.issubset(excluded)
        )

    def test_install_cannot_be_enabled_in_plan_only_profile(self):
        profile = json.loads(json.dumps(self.profile))
        profile["profile"]["install_enabled"] = True

        with self.assertRaises(ProfileError):
            validate_profile(profile)

    def test_unknown_dependency_is_rejected(self):
        profile = json.loads(json.dumps(self.full_system_profile))
        profile["modules"][0]["depends_on"] = ["missing-module"]

        with self.assertRaises(ProfileError):
            validate_profile(profile)

    def test_dependency_that_appears_later_in_order_is_rejected(self):
        profile = json.loads(json.dumps(self.full_system_profile))
        profile["modules"][7]["depends_on"] = ["processor"]

        with self.assertRaises(ProfileError):
            validate_profile(profile)

    def test_apply_command_does_not_exist(self):
        stderr = StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
            main(["apply"])

        self.assertEqual(error.exception.code, 2)
        self.assertIn("invalid choice", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
