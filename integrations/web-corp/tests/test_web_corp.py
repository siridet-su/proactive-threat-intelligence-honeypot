"""In-process tests for the corporate web decoy and its local login spool."""

import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import AsyncMock, patch


INTEGRATION_DIR = Path(__file__).resolve().parents[1]
os.environ.setdefault("WEB_HTML_DIR", str(INTEGRATION_DIR / "html"))
sys.path.insert(0, str(INTEGRATION_DIR))

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


class WebCorpTests(TestCase):
    def setUp(self):
        self.spool = tempfile.TemporaryDirectory()
        self.spool_patch = patch.object(main, "LOGIN_SPOOL_DIR", self.spool.name)
        self.spool_patch.start()
        self.transport = AsyncMock(return_value=None)
        self.transport_patch = patch.object(main, "_post_track", self.transport)
        self.page_track_patch = patch.object(main, "_track")
        self.proxy_patch = patch.object(main, "TRUSTED_PROXY_NETWORKS", ())
        self.transport_patch.start()
        self.page_track_patch.start()
        self.proxy_patch.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        self.proxy_patch.stop()
        self.page_track_patch.stop()
        self.transport_patch.stop()
        self.spool_patch.stop()
        self.spool.cleanup()

    def _last_login_event(self):
        event_files = sorted(Path(self.spool.name).glob("*.jsonl"))
        self.assertTrue(event_files, "login event was not written to the spool")
        return json.loads(event_files[-1].read_text(encoding="utf-8"))

    def test_odoo_login_page_and_structured_attempt(self):
        page = self.client.get("/web/login")
        self.assertEqual(page.status_code, 200)
        self.assertIn("ERP · Odoo", page.text)
        self.assertIn('name="db"', page.text)

        response = self.client.post(
            "/web/login",
            data={
                "db": "odoo_production",
                "login": "analyst@example.invalid",
                "password": "synthetic-test-value",
                "redirect": "/web",
                "remember": "1",
            },
            headers={
                "user-agent": "web-corp-test/1.0",
                "referer": "http://decoy.invalid/web/login",
                "accept-language": "th-TH",
                "x-forwarded-for": "203.0.113.44",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("อีเมลหรือรหัสผ่านไม่ถูกต้อง", response.text)

        event = self._last_login_event()
        self.assertEqual(event["event"], "web_login_attempt")
        self.assertEqual(event["odoo_login"]["database"], "odoo_production")
        self.assertEqual(event["odoo_login"]["login"], "analyst@example.invalid")
        self.assertEqual(event["odoo_login"]["password"], "synthetic-test-value")
        self.assertEqual(event["odoo_login"]["remember"], "1")
        self.assertEqual(event["http"]["user_agent"], "web-corp-test/1.0")
        self.assertEqual(event["http"]["accept_language"], "th-TH")
        self.assertEqual(event["source_ip"], "testclient")
        self.assertEqual(event["result"], "rejected")
        self.assertEqual(event["truncated_fields"], [])
        self.assertEqual(self.transport.await_count, 0, "login values must not go to Core /v1/track")

        event_file = next(Path(self.spool.name).glob("*.jsonl"))
        self.assertEqual(stat.S_IMODE(event_file.stat().st_mode), 0o600)

    def test_legacy_login_field_alias_and_admin_redirect(self):
        response = self.client.post(
            "/login", data={"username": "legacy-user", "password": "synthetic-value"}
        )
        self.assertEqual(response.status_code, 200)
        event = self._last_login_event()
        self.assertEqual(event["odoo_login"]["login"], "legacy-user")
        self.assertEqual(event["odoo_login"]["password"], "synthetic-value")

        redirect = self.client.get("/admin", follow_redirects=False)
        self.assertEqual(redirect.status_code, 302)
        self.assertEqual(redirect.headers["location"], "/login.html")

    def test_login_values_are_bounded_and_truncation_is_explicit(self):
        response = self.client.post(
            "/web/login",
            data={"login": "u" * 300, "password": "p" * 300},
            headers={"user-agent": "a" * 300},
        )
        self.assertEqual(response.status_code, 200)
        event = self._last_login_event()
        self.assertEqual(len(event["odoo_login"]["login"]), 256)
        self.assertEqual(len(event["odoo_login"]["password"]), 256)
        self.assertEqual(len(event["http"]["user_agent"]), 256)
        self.assertEqual(
            event["truncated_fields"],
            ["http.user_agent", "odoo_login.login", "odoo_login.password"],
        )

    def test_sqli_shaped_login_is_rejected_and_tagged_without_core_forwarding(self):
        response = self.client.post(
            "/web/login",
            data={"login": "synthetic-user", "password": "' OR 'a'='a' --"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("อีเมลหรือรหัสผ่านไม่ถูกต้อง", response.text)
        event = self._last_login_event()
        self.assertEqual(event["odoo_login"]["password"], "' OR 'a'='a' --")
        self.assertIn("boolean_tautology", event["sqli_indicators"]["password"])
        self.assertIn("sql_comment", event["sqli_indicators"]["password"])
        self.assertEqual(self.transport.await_count, 0)

    def test_spool_capacity_failure_does_not_accept_the_login(self):
        with patch.object(main, "LOGIN_SPOOL_MAX_BYTES", 64):
            response = self.client.post(
                "/web/login",
                data={"login": "synthetic-user", "password": "p" * 256},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("อีเมลหรือรหัสผ่านไม่ถูกต้อง", response.text)
        self.assertEqual(list(Path(self.spool.name).glob("*.jsonl")), [])


if __name__ == "__main__":
    import unittest

    unittest.main()
