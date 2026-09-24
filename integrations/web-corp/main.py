"""
web-corp door — FastAPI (เขียนใหม่ 2026-09-20 แทน nginx static เดิม)

เดิม (docs/10_system_concept_3day.md §5): เว็บบริษัท static ล้วน + หน้า login ปลอมที่ล็อกอินไม่ผ่าน
(JS ฝั่ง client ล้วน ไม่มี backend จริง) — จับพฤติกรรม attacker ไม่ได้เลย

ใหม่: เสิร์ฟหน้า/persona บริษัทเดิม (Rattana Trading & Logistics) พร้อม backend ปลอมเพื่อ
  1. เก็บเฉพาะ login attempts ที่ POST /web/login (คง POST /login สำหรับ compatibility)
  2. ปฏิเสธทุก login และไม่ส่งค่าที่กรอกไปยัง Odoo/PostgreSQL
  3. ส่ง login event ผ่าน restricted local spool เข้า Redis/Mongo; page views, scans และ 404
     ไม่ถูกบันทึกเป็น telemetry ของแอป

คงพฤติกรรมเดิมที่ test_suite/web_corp_behavior_test.py เช็คไว้ทุกข้อ (title, /admin→302 /login.html,
robots Disallow /backup/, /backup/ listing, fake sql.gz 2202009 bytes, 404 baseline).
"""
from __future__ import annotations

import asyncio
import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_plus

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
LOGIN_SPOOL_DIR = os.environ.get("WEB_LOGIN_SPOOL_DIR", "").strip()
try:
    LOGIN_SPOOL_MAX_BYTES = max(
        1024, int(os.environ.get("WEB_LOGIN_SPOOL_MAX_BYTES", str(64 * 1024 * 1024)))
    )
except ValueError:
    LOGIN_SPOOL_MAX_BYTES = 64 * 1024 * 1024
_LOGIN_SPOOL_LOCK = threading.Lock()
_WEB_SESSION_KEY = secrets.token_bytes(32)  # Process-local: restart rotates continuity, never persists a credential.
_WEB_SESSION_COOKIE = "web_corp_visit"
_WEB_SESSION_IDLE_SECONDS = 30 * 60
_WEB_SESSION_MAX_SECONDS = 24 * 60 * 60
_SESSION_ID_RE = re.compile(r"^[a-f0-9]{32}$")

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
def _web_session(request: Request) -> tuple[str, str]:
    """Return a sensor-issued continuity ID and refreshed, signed cookie.

    This is browser continuity, *not* an attacker identity. It cannot join SSH
    sessions by IP and does not authorize a finding or action.
    """
    now = int(time.time())
    raw = request.cookies.get(_WEB_SESSION_COOKIE, "")[:160]
    parts = raw.split(".")
    if len(parts) == 4:
        session_id, created_text, last_text, signature = parts
        try:
            created, last = int(created_text), int(last_text)
        except ValueError:
            created, last = 0, 0
        signed = f"{session_id}.{created_text}.{last_text}"
        expected = hmac.new(_WEB_SESSION_KEY, signed.encode(), hashlib.sha256).hexdigest()
        if (_SESSION_ID_RE.fullmatch(session_id) and
                hmac.compare_digest(signature, expected) and
                0 <= now - last <= _WEB_SESSION_IDLE_SECONDS and
                0 <= now - created <= _WEB_SESSION_MAX_SECONDS and
                created <= last):
            refreshed = f"{session_id}.{created}.{now}"
            signature = hmac.new(_WEB_SESSION_KEY, refreshed.encode(), hashlib.sha256).hexdigest()
            return session_id, f"{refreshed}.{signature}"
    session_id = uuid.uuid4().hex
    signed = f"{session_id}.{now}.{now}"
    signature = hmac.new(_WEB_SESSION_KEY, signed.encode(), hashlib.sha256).hexdigest()
    return session_id, f"{signed}.{signature}"


def _with_session_cookie(response, request: Request, token: str):
    response.set_cookie(
        _WEB_SESSION_COOKIE, token, max_age=_WEB_SESSION_IDLE_SECONDS,
        httponly=True, secure=request.url.scheme == "https", samesite="lax", path="/",
    )
    return response


def _pattern_indicators(values: dict[str, str], rules) -> dict[str, list[str]]:
    findings = {}
    for field, raw in values.items():
        # One bounded decoding pass catches ordinary URL encoding; no recursive
        # decoding or attacker-controlled regex is used.
        text = unquote_plus(str(raw or "")[:512])[:512]
        matches = [name for name, pattern in rules if pattern.search(text)]
        if matches:
            findings[field] = matches
    return findings


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


def _bounded_login_value(value: str, field: str, limit: int,
                         truncated_fields: set[str]) -> str:
    raw = str(value or "")
    if len(raw) > limit:
        truncated_fields.add(field)
    return raw[:limit]


def _request_context_headers(request: Request, truncated_fields: set[str]) -> dict[str, str]:
    """Bounded, self-reported context; never treat these headers as browser identity."""
    return {
        key: _bounded_login_value(
            request.headers.get(header, ""), f"http.{key}", _HEADER_LIMIT,
            truncated_fields,
        )
        for key, header in (
            ("host", "host"),
            ("user_agent", "user-agent"),
            ("referer", "referer"),
            ("origin", "origin"),
            ("accept_language", "accept-language"),
        )
    }


def _login_event(request: Request, ip: str, web_session_id: str, *, database: str, login: str,
                 password: str, redirect: str, remember: str) -> dict:
    truncated_fields: set[str] = set()
    query = _bounded_login_value(
        request.url.query, "http.query", _QUERY_LIMIT, truncated_fields
    )
    bounded = {
        "database": _bounded_login_value(
            database, "odoo_login.database", _FIELD_LIMIT, truncated_fields
        ),
        "login": _bounded_login_value(
            login, "odoo_login.login", _FIELD_LIMIT, truncated_fields
        ),
        "password": _bounded_login_value(
            password, "odoo_login.password", _FIELD_LIMIT, truncated_fields
        ),
        "redirect": _bounded_login_value(
            redirect, "odoo_login.redirect", _FIELD_LIMIT, truncated_fields
        ),
        "remember": _bounded_login_value(
            remember, "odoo_login.remember", 32, truncated_fields
        ),
    }
    http_headers = _request_context_headers(request, truncated_fields)
    values = {
        **bounded,
        "query": query,
    }
    return {
        "schema_version": 1,
        "event": "web_login_attempt",
        "request_id": uuid.uuid4().hex,
        "web_session_id": web_session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        ),
        "source_ip": ip,
        "http": {
            "scheme": _bounded_login_value(
                request.url.scheme, "http.scheme", 16, truncated_fields
            ),
            "method": _bounded_login_value(
                request.method, "http.method", 16, truncated_fields
            ),
            "path": _bounded_login_value(
                request.url.path, "http.path", _QUERY_LIMIT, truncated_fields
            ),
            "query": query,
            **http_headers,
        },
        "odoo_login": {
            "database": bounded["database"],
            "login": bounded["login"],
            "password": bounded["password"],
            "redirect": bounded["redirect"],
            "remember": bounded["remember"],
        },
        "sqli_indicators": _pattern_indicators(values, _SQLI_RULES),
        "truncated_fields": sorted(truncated_fields),
        "result": "rejected",
    }


def _spool_login_event(event: dict) -> Path:
    """Atomically persist one credential-bearing JSONL event for the host collector."""
    if not LOGIN_SPOOL_DIR:
        raise RuntimeError("WEB_LOGIN_SPOOL_DIR is not configured")

    request_id = event["request_id"]
    if not re.fullmatch(r"[a-f0-9]{32}", request_id):
        raise ValueError("invalid login event request_id")
    spool_dir = Path(LOGIN_SPOOL_DIR)
    payload = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    final_path = spool_dir / f"{request_id}.jsonl"

    with _LOGIN_SPOOL_LOCK:
        spool_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(spool_dir, 0o700)
        # HTTP and HTTPS containers share this spool. The thread lock alone
        # cannot serialize their capacity checks and writes.
        lock_fd = os.open(spool_dir / ".write.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            pending_bytes = 0
            for path in spool_dir.iterdir():
                if path.suffix != ".jsonl":
                    continue
                try:
                    if path.is_file():
                        pending_bytes += path.stat().st_size
                except FileNotFoundError:
                    continue
            if pending_bytes + len(payload) > LOGIN_SPOOL_MAX_BYTES:
                raise OSError("web login spool capacity reached")
            if final_path.exists():
                return final_path

            temp_path = spool_dir / f".{request_id}.{uuid.uuid4().hex}.tmp"
            fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as spool_file:
                    spool_file.write(payload)
                    spool_file.flush()
                    os.fsync(spool_file.fileno())
                os.replace(temp_path, final_path)
                dir_fd = os.open(spool_dir, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except Exception:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
                raise
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

    return final_path


async def _track_login(event: dict) -> bool:
    """Persist login events locally; never place credential data in Core commands."""
    request_id = event["request_id"]
    ip = event["source_ip"]
    try:
        await asyncio.to_thread(_spool_login_event, event)
    except Exception:
        # Do not print credential-bearing event data into app logs.
        log.exception("login telemetry spool write failed request_id=%s ip=%s", request_id, ip)
        return False
    indicators = event["sqli_indicators"]
    log.info(
        "LOGIN ATTEMPT captured request_id=%s ip=%s sqli_fields=%s",
        request_id,
        ip,
        ",".join(indicators) or "none",
    )
    return True


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
    web_session_id, cookie = _web_session(request)
    # Odoo's login field is named `login`; keep the old `username` alias so any
    # previously bookmarked/tested form continues to be captured.
    values = {
        "database": db or database,
        "login": login or username,
        "password": password,
        "redirect": redirect,
        "remember": remember,
    }
    event = _login_event(request, ip, web_session_id, **values)
    await _track_login(event)
    return _with_session_cookie(HTMLResponse(_login_page_with_error(), status_code=200), request, cookie)


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def serve(full_path: str, request: Request):
    path = "/" + full_path
    web_session_id, cookie = _web_session(request)
    norm = path.rstrip("/") or "/"

    # /admin (และ /admin/) → หน้า login ปลอม เหมือน nginx เดิม (SME web ทั่วไปทำแบบนี้)
    if norm == "/admin":
        return _with_session_cookie(RedirectResponse(url="/login.html", status_code=302), request, cookie)

    if request.method not in {"GET", "HEAD"}:
        return _with_session_cookie(PlainTextResponse("404 Not Found\n", status_code=404), request, cookie)

    # Odoo-style canonical login URL; keep /login.html available for continuity.
    if norm == "/web/login":
        login_page = HTML_DIR / "login.html"
        if login_page.is_file():
            return _with_session_cookie(FileResponse(login_page, media_type="text/html; charset=utf-8"), request, cookie)

    f = _safe_file(path)
    if f is None:
        return _with_session_cookie(PlainTextResponse("404 Not Found\n", status_code=404), request, cookie)

    media = None
    if f.suffix == ".html":
        media = "text/html; charset=utf-8"
    elif f.suffix == ".txt":
        media = "text/plain; charset=utf-8"
    return _with_session_cookie(FileResponse(f, media_type=media), request, cookie)
