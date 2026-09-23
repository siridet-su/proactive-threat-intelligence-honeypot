"""In-process tests for the corporate web decoy; Core transport is mocked."""

import json
import os
import sys
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

    def _last_login_event(self):
        command = self.transport.await_args.args[1]
        self.assertTrue(command.startswith("web-login "))
        return json.loads(command[len("web-login "):])

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
        self.assertEqual(event["odoo_login"]["remember"], True)
        self.assertEqual(event["http"]["user_agent"], "web-corp-test/1.0")
        self.assertEqual(event["http"]["accept_language"], "th-TH")
        self.assertEqual(event["source_ip"], "testclient")

    def test_legacy_login_field_alias_and_admin_redirect(self):
        response = self.client.post(
            "/login", data={"username": "legacy-user", "password": "synthetic-value"}
        )
        self.assertEqual(response.status_code, 200)
        event = self._last_login_event()
        self.assertEqual(event["odoo_login"]["login"], "legacy-user")

        redirect = self.client.get("/admin", follow_redirects=False)
        self.assertEqual(redirect.status_code, 302)
        self.assertEqual(redirect.headers["location"], "/login.html")


if __name__ == "__main__":
    import unittest

    unittest.main()
