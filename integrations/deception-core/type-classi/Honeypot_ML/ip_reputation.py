"""
ip_reputation.py — signal #7 (ip_reputation) จาก **AbuseIPDB ⊕ GreyNoise** + cache + fallback

ทำไมไฟล์นี้: pipeline threat-intel ของเพื่อน (AbuseIPDB→MongoDB) พังอยู่ (Mongo cloud DNS ต่อไม่ติด
2026-09-08) + key เพื่อนอาจหมด → เราถือ key ของเราเอง เรียก AbuseIPDB `/v2/check` ตรงๆ =
self-contained ไม่พึ่ง Mongo/Redis/pipeline เพื่อนเลย (ปรัชญาเดียวกับอ่าน Zeek log เอง).

**เข้ากับ classifier ได้ทันที (CLAUDE.md §5):** คืน bucket ชุดเดียวกับ `signal_extractor.ip_reputation_bucket`
(`known-scanner` / `repeat` / `new-or-clean`) → เสียบช่อง signal `ip_reputation` เดิมได้เลย ไม่ต้องแตะ
LIKELIHOODS. semantic ตรง: AbuseIPDB score สูง = known-scanner (ดันไป Bot), clean = new-or-clean (ดันไป APT).

**ปลอดภัย/ไม่พัง:**
  - key อ่านจาก env `ABUSEIPDB_API_KEY` เท่านั้น (ไม่ hardcode/commit)
  - ไม่มี key / ออฟไลน์ / API error / IP private → คืน None → caller ใช้ local-history fallback
    (`ip_reputation_bucket(seen_count)`) แทน → classifier ยังเดินได้ครบทุกกรณี
  - stdlib ล้วน (`urllib`, `sqlite3`, `ipaddress`) — ไม่เพิ่ม dependency ใน container
  - cache SQLite ต่อ IP (TTL) กันเรียกซ้ำ → ประหยัดโควตาฟรี 1000/วัน (บอทซ้ำ IP เดิม = cache hit)

**เพิ่ม 2026-09-18 (Track B P3 — GreyNoise merge, ดู docs/reports/pi_greynoise_merge_2026-09-18.md):**
รวม GreyNoise (mass-scanner/noise detection) เข้าสัญญาณเดียวกับ AbuseIPDB แบบ **OR-of-evidence** — ฝ่ายใด
ชี้ว่าเป็น scanner → `known-scanner` (จับบอทที่ AbuseIPDB score ต่ำแต่เป็น mass-scanner จริง). 3 buckets เดิม
ไม่เปลี่ยน → ไม่แตะ classifier.py. **budget-aware (ฟรี 50/สัปดาห์):** cache-first + skip ถ้า AbuseIPDB
ตัดสินเป็น known-scanner แล้ว (ไม่เปลือง lookup) + rolling 7-day counter + ไม่มี key/ครบโควตา/error → skip
เงียบ (AbuseIPDB-only เดิม ไม่ regress). GreyNoise ให้ *หลักฐาน scanner ทางบวกเท่านั้น* (noise/malicious);
"benign/unknown" ไม่ override bucket ของ AbuseIPDB.

อ้างอิง: AbuseIPDB `abuseConfidenceScore` (0-100) — patent US11689568 (mass-scanner reputation = bot signal).
GreyNoise Community API `/v3/community/{ip}` (`noise`/`classification`) — internet-wide mass-scan telemetry.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

from signal_extractor import ip_reputation_bucket  # local-history fallback (single source of truth)

# --- config (ทุกตัว override ได้ผ่าน env) ---
_API_URL = "https://api.abuseipdb.com/api/v2/check"
_MAX_AGE_DAYS = int(os.environ.get("ABUSEIPDB_MAX_AGE_DAYS", "90"))
_TIMEOUT_S = float(os.environ.get("ABUSEIPDB_TIMEOUT_S", "3"))
_CACHE_TTL_S = int(os.environ.get("ABUSEIPDB_CACHE_TTL_S", str(24 * 3600)))  # re-check วันละครั้ง/IP
_CACHE_PATH = os.environ.get("ABUSEIPDB_CACHE", "/data/abuseipdb_cache.db")

# --- GreyNoise config (P3 2026-09-18) ---
_GN_API_URL = "https://api.greynoise.io/v3/community"
_GN_TIMEOUT_S = float(os.environ.get("GREYNOISE_TIMEOUT_S", "3"))
_GN_CACHE_PATH = os.environ.get("GREYNOISE_CACHE", "/data/greynoise_cache.db")
_GN_CACHE_TTL_S = int(os.environ.get("GREYNOISE_CACHE_TTL_S", str(7 * 24 * 3600)))  # scanner status นิ่ง → cache ยาว ประหยัดโควตา
_GN_WEEKLY_BUDGET = int(os.environ.get("GREYNOISE_WEEKLY_BUDGET", "50"))  # free tier ~50 lookups/สัปดาห์
_GN_WINDOW_S = 7 * 24 * 3600

# score → bucket (ตรงกับค่าที่ classifier LIKELIHOODS["ip_reputation"] รู้จัก)
#   >=50  known-scanner  (มั่นใจว่าเป็น IP ประสงค์ร้าย/สแกนเนอร์ = สัญญาณบอทแรง)
#   >=10  repeat         (มีรายงานบ้าง)
#   <10   new-or-clean   (สะอาด/ใหม่ = โน้มเอียงคน/APT)
_HIGH, _MID = 50, 10


def _bucket_from_score(score: int) -> str:
    if score >= _HIGH:
        return "known-scanner"
    if score >= _MID:
        return "repeat"
    return "new-or-clean"


def _is_public(ip: str) -> bool:
    """AbuseIPDB ให้ score เฉพาะ public IP — private/loopback/reserved ข้ามไป (คืน None → fallback)"""
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved
                    or a.is_link_local or a.is_multicast or a.is_unspecified)
    except ValueError:
        return False


def _cache_conn() -> sqlite3.Connection | None:
    try:
        con = sqlite3.connect(_CACHE_PATH, timeout=2)
        con.execute("CREATE TABLE IF NOT EXISTS abuseipdb_cache "
                    "(ip TEXT PRIMARY KEY, score INTEGER, ts REAL)")
        return con
    except sqlite3.Error:
        return None  # cache ใช้ไม่ได้ก็ไม่เป็นไร แค่เรียก API ทุกครั้ง (ยัง fallback ได้)


def _cache_get(ip: str) -> int | None:
    con = _cache_conn()
    if con is None:
        return None
    try:
        row = con.execute("SELECT score, ts FROM abuseipdb_cache WHERE ip=?", (ip,)).fetchone()
        if row and (time.time() - row[1]) < _CACHE_TTL_S:
            return int(row[0])
    except sqlite3.Error:
        pass
    finally:
        con.close()
    return None


def _cache_put(ip: str, score: int) -> None:
    con = _cache_conn()
    if con is None:
        return
    try:
        con.execute("INSERT OR REPLACE INTO abuseipdb_cache(ip, score, ts) VALUES (?,?,?)",
                    (ip, int(score), time.time()))
        con.commit()
    except sqlite3.Error:
        pass
    finally:
        con.close()


def _api_score(ip: str, api_key: str) -> int | None:
    """เรียก AbuseIPDB /v2/check → abuseConfidenceScore (0-100) หรือ None ถ้าพลาด (ไม่ throw)"""
    url = f"{_API_URL}?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays={_MAX_AGE_DAYS}"
    req = urllib.request.Request(url, headers={"Key": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return int(data["data"]["abuseConfidenceScore"])
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            KeyError, ValueError, json.JSONDecodeError, OSError):
        return None  # ออฟไลน์/rate-limit/key พัง/รูปแบบเปลี่ยน → fallback


def abuseipdb_bucket(ip: str | None) -> str | None:
    """คืน bucket จาก AbuseIPDB (cache ก่อน แล้วค่อย API) หรือ None ถ้าใช้ไม่ได้ (→ ให้ caller fallback)"""
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key or not ip or not _is_public(ip):
        return None
    cached = _cache_get(ip)
    if cached is not None:
        return _bucket_from_score(cached)
    score = _api_score(ip, api_key)
    if score is None:
        return None
    _cache_put(ip, score)
    return _bucket_from_score(score)


# ------------------------------------------------------------------------------------------
# GreyNoise (P3 2026-09-18) — mass-scanner detection, budget-aware (free ~50/wk)
# ------------------------------------------------------------------------------------------
def _gn_cache_conn() -> sqlite3.Connection | None:
    try:
        con = sqlite3.connect(_GN_CACHE_PATH, timeout=2)
        con.execute("CREATE TABLE IF NOT EXISTS greynoise_cache "
                    "(ip TEXT PRIMARY KEY, scanner INTEGER, ts REAL)")
        con.execute("CREATE TABLE IF NOT EXISTS greynoise_budget (ts REAL)")  # 1 แถว/lookup
        return con
    except sqlite3.Error:
        return None  # ไม่มี cache = ติดตาม budget ไม่ได้ → จะ skip GreyNoise (กัน overrun โควตาฟรี)


def _gn_cache_get(ip: str) -> bool | None:
    """คืน True(scanner)/False(clean) จาก cache ถ้ายังไม่หมดอายุ, None ถ้า miss/หมดอายุ"""
    con = _gn_cache_conn()
    if con is None:
        return None
    try:
        row = con.execute("SELECT scanner, ts FROM greynoise_cache WHERE ip=?", (ip,)).fetchone()
        if row and (time.time() - row[1]) < _GN_CACHE_TTL_S:
            return bool(row[0])
    except sqlite3.Error:
        pass
    finally:
        con.close()
    return None


def _gn_cache_put(ip: str, scanner: bool) -> None:
    con = _gn_cache_conn()
    if con is None:
        return
    try:
        con.execute("INSERT OR REPLACE INTO greynoise_cache(ip, scanner, ts) VALUES (?,?,?)",
                    (ip, 1 if scanner else 0, time.time()))
        con.commit()
    except sqlite3.Error:
        pass
    finally:
        con.close()


def _gn_budget_ok() -> bool:
    """True ถ้ายังยิง GreyNoise ได้ในโควตา rolling 7 วัน (prune แถวเก่าไปด้วย). cache ใช้ไม่ได้ = False
    (กัน overrun เพราะติดตามไม่ได้)"""
    con = _gn_cache_conn()
    if con is None:
        return False
    try:
        con.execute("DELETE FROM greynoise_budget WHERE ts < ?", (time.time() - _GN_WINDOW_S,))
        con.commit()
        n = con.execute("SELECT COUNT(*) FROM greynoise_budget").fetchone()[0]
        return n < _GN_WEEKLY_BUDGET
    except sqlite3.Error:
        return False
    finally:
        con.close()


def _gn_budget_consume() -> None:
    con = _gn_cache_conn()
    if con is None:
        return
    try:
        con.execute("INSERT INTO greynoise_budget(ts) VALUES (?)", (time.time(),))
        con.commit()
    except sqlite3.Error:
        pass
    finally:
        con.close()


def _gn_api(ip: str, api_key: str) -> bool | None:
    """เรียก GreyNoise Community API → True(scanner) / False(clean/ไม่เคยเห็น) / None(ใช้ไม่ได้-ไม่ throw).
    404 = ไม่เคยถูก GreyNoise สังเกต = ไม่ใช่ scanner (คืน False). 401/403/429 = key/โควตาพัง (คืน None)"""
    url = f"{_GN_API_URL}/{urllib.parse.quote(ip)}"
    req = urllib.request.Request(url, headers={"key": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_GN_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False  # not observed → not a known scanner
        return None       # 401/403/429/5xx → unavailable (ไม่นับ budget ไม่ cache)
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError, OSError):
        return None
    noise = bool(data.get("noise"))
    classification = str(data.get("classification", "")).lower()
    return noise or classification == "malicious"


def greynoise_scanner(ip: str | None) -> bool | None:
    """True ถ้า GreyNoise ยืนยันว่าเป็น mass-scanner, False ถ้าสะอาด/ไม่เคยเห็น, None ถ้าใช้ไม่ได้
    (ไม่มี key / private / ครบโควตา / error). cache-first แล้วค่อยยิง (นับ budget เฉพาะที่ยิงจริง)"""
    api_key = os.environ.get("GREYNOISE_API_KEY", "").strip()
    if not api_key or not ip or not _is_public(ip):
        return None
    cached = _gn_cache_get(ip)
    if cached is not None:
        return cached
    if not _gn_budget_ok():
        return None  # โควตา 50/wk หมด → ไม่ยิง (fallback เป็น AbuseIPDB-only)
    result = _gn_api(ip, api_key)
    if result is None:
        return None  # error/rate-limit → ไม่นับ budget ไม่ cache (ลองใหม่รอบหน้าได้)
    _gn_budget_consume()
    _gn_cache_put(ip, result)
    return result


def reputation_bucket(ip: str | None, seen_count: int = 0) -> str:
    """signal #7 ตัวจริงที่ adapter เรียก — merge AbuseIPDB ⊕ GreyNoise (OR-of-evidence) + fallback.
    การันตีคืนค่าเสมอ (ไม่มีวัน None) → classifier มี ip_reputation ครบทุกกรณี.

    ลำดับ (budget-aware — GreyNoise ยิงเฉพาะเคสก้ำกึ่ง):
      1. AbuseIPDB = known-scanner → จบเลย (ไม่เปลือง GreyNoise lookup — ชัดว่า scanner แล้ว)
      2. เคสก้ำกึ่ง (repeat/new-or-clean/None) → ถาม GreyNoise; ยืนยัน scanner → upgrade known-scanner
      3. ไม่มีใครยืนยัน scanner → ใช้ bucket ละเอียดของ AbuseIPDB (repeat/new-or-clean) ถ้ามี
      4. AbuseIPDB ใช้ไม่ได้เลย → local-history fallback"""
    ab = abuseipdb_bucket(ip)  # None ถ้าใช้ไม่ได้
    if ab == "known-scanner":
        return "known-scanner"
    # เคสก้ำกึ่ง — GreyNoise อาจจับ mass-scanner ที่ AbuseIPDB score ต่ำ
    if greynoise_scanner(ip) is True:
        return "known-scanner"
    if ab is not None:
        return ab  # 'repeat' หรือ 'new-or-clean'
    return ip_reputation_bucket(seen_count)
