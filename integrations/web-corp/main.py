"""
web-corp door — FastAPI (เขียนใหม่ 2026-09-20 แทน nginx static เดิม)

เดิม (docs/10_system_concept_3day.md §5): เว็บบริษัท static ล้วน + หน้า login ปลอมที่ล็อกอินไม่ผ่าน
(JS ฝั่ง client ล้วน ไม่มี backend จริง) — จับพฤติกรรม attacker ไม่ได้เลย

ใหม่: เสิร์ฟหน้า/persona บริษัทเดิม (Rattana Trading & Logistics) พร้อม backend ปลอมเพื่อ
  1. เก็บ login attempts ที่ POST /web/login (คง POST /login สำหรับ compatibility)
  2. ดัก path scanning (/.env /wp-admin /phpmyadmin /.git /backup ...) → log เป็น signal "web-scan"
  3. ส่ง login event แบบรอผลจาก /v1/track; page views ปกติยังส่งแบบ fire-and-forget
     → phase tracker + classifier Track B เห็นพฤติกรรม web ต่อ IP (session keyed by IP ข้ามประตู)

คงพฤติกรรมเดิมที่ test_suite/web_corp_behavior_test.py เช็คไว้ทุกข้อ (title, /admin→302 /login.html,
robots Disallow /backup/, /backup/ listing, fake sql.gz 2202009 bytes, 404 baseline).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("web-corp")

HTML_DIR = Path(os.environ.get("WEB_HTML_DIR", "/app/html"))
DECEPTION_CORE_URL = os.environ.get(
    "DECEPTION_CORE_URL", "http://deception-core:9000"
).rstrip("/")
TRACK_URL = DECEPTION_CORE_URL + "/v1/track"

# path ล่อที่สแกนเนอร์/attacker ชอบยิง — เจอ = log เป็น "web-scan" (สัญญาณตั้งใจเจาะ ไม่ใช่ดูเว็บเฉยๆ)
# เก็บแบบ normalize (ตัด trailing slash) เทียบกับ path ที่เข้ามา
BAIT_PATHS = {
    "/.env", "/.git/config", "/.git/HEAD", "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/phpMyAdmin", "/administrator", "/server-status",
    "/.aws/credentials", "/config.php", "/shell.php", "/vendor", "/.ssh/id_rsa",
    "/actuator", "/actuator/env", "/console", "/adminer.php", "/.env.bak",
    "/web/database/manager", "/web/database/selector", "/web/dataset/call_kw",
    "/web/session/authenticate", "/jsonrpc", "/xmlrpc/2/common", "/xmlrpc/2/object",
}
_BAIT_NORM = {p.rstrip("/") or "/" for p in BAIT_PATHS}
_FIELD_LIMIT = 256
_HEADER_LIMIT = 256
_QUERY_LIMIT = 512

# These are triage hints, not a SQL parser or a verdict. No submitted value is
# evaluated or sent to Odoo/PostgreSQL.
_SQLI_RULES = (
    ("sql_comment", re.compile(r"(?:--|/\*|\*/|#)")),
    ("union_select", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)),
    ("boolean_tautology", re.compile(
        r"\b(?:or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
        re.IGNORECASE,
    )),
    ("time_delay", re.compile(
        r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b",
        re.IGNORECASE,
    )),
    ("database_metadata", re.compile(
        r"\b(?:information_schema|pg_catalog|sqlite_master)\b", re.IGNORECASE
    )),
    ("stacked_statement", re.compile(
        r";\s*(?:select|insert|update|delete|drop|alter)\b", re.IGNORECASE
    )),
    ("sql_keyword", re.compile(
        r"\b(?:select|union|sleep|benchmark|information_schema|updatexml|extractvalue)\b",
        re.IGNORECASE,
    )),
)


def _trusted_proxy_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Only honor X-Forwarded-For when the immediate peer is explicitly trusted."""
    networks = []
    for value in os.environ.get("WEB_TRUSTED_PROXY_CIDRS", "").split(","):
        value = value.strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            log.warning("ignoring invalid WEB_TRUSTED_PROXY_CIDRS entry")
    return tuple(networks)


TRUSTED_PROXY_NETWORKS = _trusted_proxy_networks()

app = FastAPI()


def _client_ip(request: Request) -> str:
    # Direct ZeroTier traffic is the normal path. Never trust a caller-supplied
    # X-Forwarded-For unless the immediate peer is configured as a proxy.
    peer = request.client.host if request.client else "0.0.0.0"
    xff = request.headers.get("x-forwarded-for")
    if xff and TRUSTED_PROXY_NETWORKS:
        try:
            peer_ip = ipaddress.ip_address(peer.split("%", 1)[0])
        except ValueError:
            peer_ip = None
        if peer_ip and any(peer_ip in network for network in TRUSTED_PROXY_NETWORKS):
            # Walk from the proxy-facing end. The first non-proxy address is the
            # client asserted by the trusted chain; ignore malformed entries.
            for forwarded in reversed(xff.split(",")[-8:]):
                try:
                    candidate = ipaddress.ip_address(forwarded.strip().split("%", 1)[0])
                except ValueError:
                    continue
                if not any(candidate in network for network in TRUSTED_PROXY_NETWORKS):
                    return str(candidate)
    return peer


def _limited(value: str, limit: int = _FIELD_LIMIT) -> str:
    return str(value or "")[:limit]


def _sqli_indicators(values: dict[str, str]) -> dict[str, list[str]]:
    indicators = {}
    for field, value in values.items():
        matches = [name for name, pattern in _SQLI_RULES if pattern.search(value)]
        if matches:
            indicators[field] = matches
    return indicators


def _login_event(request: Request, ip: str, *, database: str, login: str,
                 password: str, redirect: str, remember: str) -> dict:
    query = _limited(request.url.query, _QUERY_LIMIT)
    values = {
        "database": database,
        "login": login,
        "password": password,
        "redirect": redirect,
        "query": query,
    }
    return {
        "schema_version": 1,
        "event": "web_login_attempt",
        "request_id": uuid.uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "source_ip": ip,
        "http": {
            "method": request.method,
            "path": _limited(request.url.path, _QUERY_LIMIT),
            "query": query,
            "host": _limited(request.headers.get("host", ""), _HEADER_LIMIT),
            "user_agent": _limited(request.headers.get("user-agent", ""), _HEADER_LIMIT),
            "referer": _limited(request.headers.get("referer", ""), _HEADER_LIMIT),
            "origin": _limited(request.headers.get("origin", ""), _HEADER_LIMIT),
            "accept_language": _limited(
                request.headers.get("accept-language", ""), _HEADER_LIMIT
            ),
        },
        "odoo_login": {
            "database": database,
            "login": login,
            "password": password,
            "redirect": redirect,
            "remember": remember.lower() in {"1", "true", "on", "yes"},
        },
        "sqli_indicators": _sqli_indicators(values),
        "result": "rejected",
    }


async def _post_track(ip: str, command: str) -> None:
    """Wait for the core to durably append the event before considering it captured."""
    async with httpx.AsyncClient(timeout=2.0) as c:
        response = await c.post(
            TRACK_URL, json={"ip": ip, "door": "web", "command": command}
        )
        response.raise_for_status()


def _track(ip: str, command: str) -> None:
    """Fire-and-forget for ordinary page views; login attempts use _track_login."""

    async def _call():
        try:
            await _post_track(ip, command)
        except Exception:
            log.exception("track call failed")

    asyncio.create_task(_call())


async def _track_login(ip: str, event: dict) -> bool:
    """Deliver a structured attempt to the persistent shared event stream."""
    command = "web-login " + json.dumps(event, ensure_ascii=False, separators=(",", ":"))
    request_id = event["request_id"]
    try:
        await _post_track(ip, command)
    except Exception:
        # Do not print credential-bearing command/event data into app logs.
        log.exception("login telemetry delivery failed request_id=%s ip=%s", request_id, ip)
        return False
    indicators = event["sqli_indicators"]
    log.info(
        "LOGIN ATTEMPT captured request_id=%s ip=%s sqli_fields=%s",
        request_id,
        ip,
        ",".join(indicators) or "none",
    )
    return True


def _is_sensitive(norm_path: str) -> bool:
    """path ที่ถือเป็น 'สแกน/สอดแนม' — bait list + /backup (robots ประกาศ Disallow ไว้ ใครเปิด =
    ตั้งใจ) + อะไรที่ขึ้นต้นด้วย /.git /.env"""
    return (
        norm_path in _BAIT_NORM
        or norm_path.startswith("/backup")
        or norm_path.startswith("/.git")
        or norm_path.startswith("/.env")
    )


def _safe_file(url_path: str) -> Path | None:
    """map path → ไฟล์ใน HTML_DIR อย่างปลอดภัย (กัน path traversal) คืน None ถ้าไม่มีไฟล์"""
    rel = url_path.lstrip("/")
    if rel == "" or rel.endswith("/"):
        rel = rel + "index.html"
    try:
        candidate = (HTML_DIR / rel).resolve()
        candidate.relative_to(HTML_DIR.resolve())
    except (ValueError, OSError):
        return None  # path traversal / ผิดปกติ
    if candidate.is_dir():
        candidate = candidate / "index.html"
    return candidate if candidate.is_file() else None


def _login_page_with_error() -> str:
    """หน้า login เดิม แต่บังคับโชว์กล่อง error (ล็อกอินไม่ผ่านเสมอตามดีไซน์)"""
    try:
        html = (HTML_DIR / "login.html").read_text(encoding="utf-8")
    except Exception:
        return "<h2>ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง</h2>"
    return html.replace("</head>", "<style>#error{display:block !important;}</style></head>", 1)


@app.post("/login")
@app.post("/web/login")
async def do_login(
    request: Request,
    db: str = Form(default=""),
    database: str = Form(default=""),
    login: str = Form(default=""),
    username: str = Form(default=""),
    password: str = Form(default=""),
    redirect: str = Form(default=""),
    remember: str = Form(default=""),
):
    """Fake Odoo sign-in: record an attempt and always reject it; never authenticate."""
    ip = _client_ip(request)
    # Odoo's login field is named `login`; keep the old `username` alias so any
    # previously bookmarked/tested form continues to be captured.
    values = {
        "database": _limited(db or database),
        "login": _limited(login or username),
        "password": _limited(password),
        "redirect": _limited(redirect),
        "remember": _limited(remember, 32),
    }
    event = _login_event(request, ip, **values)
    await _track_login(ip, event)
    return HTMLResponse(_login_page_with_error(), status_code=200)


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def serve(full_path: str, request: Request):
    path = "/" + full_path
    ip = _client_ip(request)
    norm = path.rstrip("/") or "/"
    target = request.url.path
    if request.url.query:
        target += "?" + _limited(request.url.query, _QUERY_LIMIT)

    # /admin (และ /admin/) → หน้า login ปลอม เหมือน nginx เดิม (SME web ทั่วไปทำแบบนี้)
    if norm == "/admin":
        _track(ip, f"web-scan {request.method} {target}")
        return RedirectResponse(url="/login.html", status_code=302)

    command = f"web-scan {request.method} {target}" if _is_sensitive(norm) else (
        f"{request.method} {target}"
    )
    _track(ip, command)

    if request.method not in {"GET", "HEAD"}:
        return PlainTextResponse("404 Not Found\n", status_code=404)

    # Odoo-style canonical login URL; keep /login.html available for continuity.
    if norm == "/web/login":
        login_page = HTML_DIR / "login.html"
        if login_page.is_file():
            return FileResponse(login_page, media_type="text/html; charset=utf-8")

    f = _safe_file(path)
    if f is None:
        return PlainTextResponse("404 Not Found\n", status_code=404)

    media = None
    if f.suffix == ".html":
        media = "text/html; charset=utf-8"
    elif f.suffix == ".txt":
        media = "text/plain; charset=utf-8"
    return FileResponse(f, media_type=media)
