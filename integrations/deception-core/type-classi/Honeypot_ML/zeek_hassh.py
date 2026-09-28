"""
zeek_hassh.py — เสริมสัญญาณแกน A (bot-vs-คน) ด้วย **HASSH จาก Zeek ssh.log**

ทำไม: client version string ที่ Cowrie ส่งมา ("SSH-2.0-Go") ปลอมได้ง่ายด้วยบรรทัดเดียว.
Zeek คำนวณ **HASSH** = แฮชของรายการ algorithm (KEX/cipher/MAC/compression) ที่ SSH client เสนอจริง
ตอน handshake → สะท้อน library จริง ปลอมยากกว่ามาก + จับกลุ่ม client ตระกูลเดียวกันได้.
ใช้ 2 ทาง: (1) ยืนยัน/แทนที่ client string ด้วยของ Zeek ที่น่าเชื่อกว่า (เห็นระดับ network),
(2) **จับ spoof** — version string บอก "คน" แต่ HASSH ตรง library บอท → ตัดสินเป็น automated.

**self-contained (CLAUDE.md §5, §8):** อ่านไฟล์ ssh.log ที่ Zeek เขียนลง disk อยู่แล้ว (`644` world-readable)
ผ่าน read-only bind-mount — **ไม่แตะ Zeek/config เพื่อน, ไม่พึ่ง Mongo/Redis**. reuse `_client_family`
จาก signal_extractor (ไม่พิมพ์ logic แยกประเภท client ซ้ำ).

**ไม่พัง:** ไม่มีไฟล์ log / อ่านไม่ได้ / ไม่เจอ IP → คืน None/unknown → adapter fallback client string
ของ Cowrie แทน (classifier ยังเดินครบทุกกรณี).

Join: Zeek ผูก entry ด้วย `id.orig_h` (src IP) + `id.resp_p` (port) — จับคู่กับ session ของเราด้วย src IP
(honeypot cowrie = port 22). อ้างอิง: HASSH (Salesforce).
"""

from __future__ import annotations

import json
import os

from signal_extractor import _client_family  # single source of truth (แยกประเภท client)

# --- config (override ได้ผ่าน env) ---
_SSH_LOG = os.environ.get("ZEEK_SSH_LOG", "/zeek-logs/ssh.log")  # จุด bind-mount ใน container
_HONEYPOT_PORT = int(os.environ.get("ZEEK_HONEYPOT_PORT", "22"))  # cowrie ฟังพอร์ตนี้
_MAX_LINES = int(os.environ.get("ZEEK_SSH_LOG_MAX_LINES", "20000"))  # กันไฟล์ใหญ่เกิน (tail)

# HASSH ที่รู้ตระกูลแน่ๆ → hint ('automated' = library/บอท, 'interactive' = client คน)
# seed เท่าที่ "สังเกตจริง" เท่านั้น (ห้ามเดา hash) — เติมจาก self-play/traffic ทีหลัง (งาน C)
#   ec7378c1a92f5a8dde7e8b7a1ddf33d1 = OpenSSH_for_Windows_8.1 (สังเกตจริงบน Pi 2026-09-08)
HASSH_FAMILY: dict[str, str] = {
    "ec7378c1a92f5a8dde7e8b7a1ddf33d1": "interactive",
}


def hassh_family_hint(hassh: str | None) -> str | None:
    """คืน 'automated'/'interactive' ถ้ารู้จัก HASSH นี้ ไม่งั้น None"""
    if not hassh:
        return None
    return HASSH_FAMILY.get(hassh)


def lookup(ip: str | None, log_path: str | None = None) -> dict | None:
    """หา ssh handshake ล่าสุดของ src IP นี้ (พอร์ต honeypot) จาก Zeek ssh.log
    คืน {'hassh','client','ts','resp_p'} หรือ None ถ้าไม่มี/อ่านไม่ได้/ไม่เจอ"""
    if not ip:
        return None
    path = log_path or _SSH_LOG
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None  # ไม่มีไฟล์/อ่านไม่ได้ → ให้ caller fallback
    best = None
    for line in lines[-_MAX_LINES:]:
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("id.orig_h") != ip:
            continue
        if _HONEYPOT_PORT and d.get("id.resp_p") != _HONEYPOT_PORT:
            continue
        ts = d.get("ts", 0)
        if best is None or ts >= best["ts"]:
            best = {"hassh": d.get("hassh"), "client": d.get("client"),
                    "ts": ts, "resp_p": d.get("id.resp_p")}
    return best


def client_family(ip: str | None, cowrie_client_version: str | None,
                  log_path: str | None = None) -> str:
    """สรุป client_family ('automated'/'interactive'/'unknown') โดยใช้ Zeek เสริม:
      1. ถ้ามี entry Zeek → ใช้ client string ของ Zeek (น่าเชื่อกว่า) แยกประเภท
      2. ถ้า HASSH ชี้ว่าเป็น library → override เป็น 'automated' (จับ spoof — HASSH ปลอมยากกว่า)
      3. ไม่มี Zeek → fallback client string ของ Cowrie
    """
    entry = lookup(ip, log_path)
    base_version = (entry["client"] if entry and entry.get("client") else cowrie_client_version)
    fam = _client_family(base_version)
    if entry:
        hint = hassh_family_hint(entry.get("hassh"))
        if hint == "automated":
            return "automated"  # version string อาจโกหกว่าเป็นคน แต่ HASSH ตรง library
    return fam
