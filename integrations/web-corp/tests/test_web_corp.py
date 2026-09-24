"""In-process tests for the corporate web decoy and its local login spool."""

import ipaddress
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch


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
        self.proxy_patch = patch.object(main, "TRUSTED_PROXY_NETWORKS", ())
        self.proxy_patch.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        self.proxy_patch.stop()
        self.spool_patch.stop()
        self.spool.cleanup()

    def _last_login_event(self):
        events = [json.loads(path.read_text(encoding="utf-8"))
                  for path in Path(self.spool.name).glob("*.jsonl")]
        login_events = [item for item in events if item.get("event") == "web_login_attempt"]
        self.assertTrue(login_events, "login event was not written to the spool")
        return login_events[-1]

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
        self.assertIsInstance(event["source_port"], int)
        self.assertGreaterEqual(event["source_port"], 1)
        self.assertLessEqual(event["source_port"], 65535)
        self.assertEqual(event["result"], "rejected")
        self.assertEqual(event["http"]["scheme"], "http")
        self.assertEqual(event["truncated_fields"], [])
        self.assertNotIn("xss_indicators", event)

        event_file = next(Path(self.spool.name).glob("*.jsonl"))
        self.assertEqual(stat.S_IMODE(event_file.stat().st_mode), 0o600)
        writer_lock = Path(self.spool.name) / ".write.lock"
        self.assertEqual(stat.S_IMODE(writer_lock.stat().st_mode), 0o600)

    def test_direct_source_port_comes_from_the_socket_peer(self):
        request = SimpleNamespace(
            client=SimpleNamespace(host="198.51.100.10", port=49152),
            headers={"x-forwarded-client-port": "22"},
        )
        self.assertEqual(main._client_port(request), 49152)

    def test_trusted_proxy_source_port_requires_a_valid_forwarded_value(self):
        with patch.object(
            main, "TRUSTED_PROXY_NETWORKS", (ipaddress.ip_network("192.0.2.0/24"),)
        ):
            request = SimpleNamespace(
                client=SimpleNamespace(host="192.0.2.10", port=40123),
                headers={"x-forwarded-client-port": "53124"},
            )
            self.assertEqual(main._client_port(request), 53124)

            for forwarded_port in ("", "0", "65536", "53,54", "spoofed"):
                request.headers["x-forwarded-client-port"] = forwarded_port
                self.assertIsNone(main._client_port(request), forwarded_port)

    def test_untrusted_forwarded_port_is_ignored(self):
        request = SimpleNamespace(
            client=SimpleNamespace(host="198.51.100.10", port=49152),
            headers={"x-forwarded-client-port": "22"},
        )
        self.assertEqual(main._client_port(request), 49152)

    def test_uvicorn_rewritten_trusted_proxy_client_uses_forwarded_port(self):
        with patch.object(
            main, "TRUSTED_PROXY_NETWORKS", (ipaddress.ip_network("192.0.2.0/24"),)
        ):
            # Uvicorn's proxy middleware replaces the trusted proxy peer with
            # the forwarded client and uses port 0 when XFF has no port.
            request = SimpleNamespace(
                client=SimpleNamespace(host="198.51.100.10", port=0),
                headers={
                    "x-forwarded-for": "198.51.100.10",
                    "x-forwarded-client-port": "53124",
                },
            )
            self.assertEqual(main._client_port(request), 53124)

    def test_https_login_records_scheme_and_still_rejects(self):
        with TestClient(main.app, base_url="https://testserver") as client:
            response = client.post(
                "/web/login",
                data={"login": "synthetic-https-user", "password": "synthetic-https-value"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("อีเมลหรือรหัสผ่านไม่ถูกต้อง", response.text)
        event = self._last_login_event()
        self.assertEqual(event["http"]["scheme"], "https")
        self.assertEqual(event["result"], "rejected")

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

    def test_only_login_submissions_create_telemetry(self):
        self.assertEqual(self.client.get("/web/login").status_code, 200)
        self.assertEqual(self.client.get("/.env").status_code, 404)
        self.assertEqual(self.client.get("/wp-admin").status_code, 404)
        self.assertEqual(self.client.get("/missing-page").status_code, 404)
        self.assertEqual(self.client.post("/unrelated", data={"x": "y"}).status_code, 404)
        self.assertEqual(self.client.get("/admin", follow_redirects=False).status_code, 302)
        self.assertEqual(list(Path(self.spool.name).glob("*.jsonl")), [])

        response = self.client.post(
            "/web/login", data={"login": "synthetic-user", "password": "synthetic-value"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(list(Path(self.spool.name).glob("*.jsonl"))), 1)

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

    def test_spool_capacity_failure_does_not_accept_the_login(self):
        with patch.object(main, "LOGIN_SPOOL_MAX_BYTES", 64):
            response = self.client.post(
                "/web/login",
                data={"login": "synthetic-user", "password": "p" * 256},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("อีเมลหรือรหัสผ่านไม่ถูกต้อง", response.text)
        self.assertEqual(list(Path(self.spool.name).glob("*.jsonl")), [])

    def test_http_page_and_form_attempt_share_server_issued_session(self):
        page = self.client.get("/login.html")
        self.assertEqual(page.status_code, 200)
        self.assertIn("httponly", page.headers["set-cookie"].lower())
        self.assertIn("samesite=lax", page.headers["set-cookie"].lower())
        self.assertEqual(list(Path(self.spool.name).glob("*.jsonl")), [])
        page_session_id = page.cookies.get("web_corp_visit").split(".")[0]
        login = self.client.post(
            "/web/login",
            data={"login": "synthetic-user", "password": "' OR 'a'='a' --"},
        )
        self.assertEqual(login.status_code, 200)
        events = [json.loads(path.read_text(encoding="utf-8"))
                  for path in Path(self.spool.name).glob("*.jsonl")]
        self.assertEqual(len(events), 1)
        login_event = events[0]
        self.assertEqual(login_event["event"], "web_login_attempt")
        self.assertEqual(login_event["web_session_id"], page_session_id)
        self.assertEqual(len(login_event["web_session_id"]), 32)
        self.assertNotIn("xss_indicators", login_event)
        self.assertIn("boolean_tautology", login_event["sqli_indicators"]["password"])

    def test_forged_and_expired_browser_session_rotate(self):
        first = self.client.get("/login.html")
        cookie = first.cookies.get("web_corp_visit")
        self.assertIsNotNone(cookie)
        original = cookie.split(".")[0]

        with TestClient(main.app, cookies={"web_corp_visit": str(cookie) + "forged"}) as attacker:
            forged_response = attacker.get("/login.html")
        self.assertNotEqual(forged_response.cookies["web_corp_visit"].split(".")[0], original)

        with patch.object(main.time, "time", return_value=main.time.time() + 1801):
            with TestClient(main.app, cookies={"web_corp_visit": str(cookie)}) as stale:
                stale_response = stale.get("/login.html")
        self.assertNotEqual(stale_response.cookies["web_corp_visit"].split(".")[0], original)
        self.assertEqual(list(Path(self.spool.name).glob("*.jsonl")), [])

    def test_page_queries_and_bait_requests_are_not_recorded(self):
        self.assertEqual(
            self.client.get("/login.html?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E").status_code,
            200,
        )
        self.assertEqual(self.client.get("/wp-admin").status_code, 404)
        self.assertEqual(self.client.get("/missing?q=" + "x" * 600).status_code, 404)
        self.assertEqual(list(Path(self.spool.name).glob("*.jsonl")), [])


if __name__ == "__main__":
    import unittest

    unittest.main()
