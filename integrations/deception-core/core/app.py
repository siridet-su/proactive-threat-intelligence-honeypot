"""
app.py — deception-core FastAPI (:9000, internal network เท่านั้น ไม่ publish ออกนอก)
ประตูทุกบานเรียก /v1/decide ตัวเดียวกัน (docs/10_system_concept_3day.md §5)
"""

import uuid

from fastapi import FastAPI
from pydantic import BaseModel

import brain
import cleanup
import login_decoy
import phase_adaptive
import router
import session_store

app = FastAPI()


@app.on_event("startup")
def _start_cleanup() -> None:
    """เพิ่ม 2026-08-23 — sweep session/cache กลุ่ม B (session-unique) ที่หมดอายุเป็นระยะ
    (ดู cleanup.py, docs/reports/pi_stageB_pregen_2026-08-23.md)"""
    cleanup.start_background()


class DecideRequest(BaseModel):
    ip: str
    door: str
    mode: str = "bash"
    cwd: str = "/"
    files_str: str = ""
    target: str
    command: str
    client: str = ""  # SSH client version (Cowrie -> classifier)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/decide")
def decide(req: DecideRequest):
    return router.decide(
        ip=req.ip,
        door=req.door,
        mode=req.mode,
        cwd=req.cwd,
        files_str=req.files_str,
        target=req.target,
        command=req.command,
        client=req.client,
    )


class TrackRequest(BaseModel):
    ip: str
    door: str
    command: str
    client: str = ""


@app.post("/v1/track")
def track(req: TrackRequest):
    """ประตูเรียกทุกคำสั่ง (แม้ตอบจาก VFS/DB จริงเอง) ให้ session phase อัปเดตตรงกัน
    ไม่ต้องรอ /v1/decide ซึ่งเรียกเฉพาะตอนของไม่มีจริงเท่านั้น"""
    return router.track(ip=req.ip, door=req.door, command=req.command, client=req.client)


class LoginDecoyRequest(BaseModel):
    ip: str
    username: str
    login_time: str


@app.post("/v1/login_decoy/start")
def login_decoy_start(req: LoginDecoyRequest):
    """Part 1 (2026-08-26) — เรียกครั้งเดียวตอน attacker login สำเร็จ (ก่อนคำสั่งแรก) จาก
    cowrie/shell/session.py::SSHSessionForCowrieUser คืนทันที (ไม่รอ generate เสร็จ — เปลี่ยนจาก
    endpoint เดียวที่ค้างรอ เป็น start+poll ดู docstring หัวไฟล์ login_decoy.py)

    **แก้บั๊กจริง 2026-08-28**: เดิมใช้ session.session_id จาก session_store (ผูกกับ ip) เป็น
    session_id ของ Part 1 ตรงๆ — เจอจาก blind audit ว่า 2 การ login จาก ip เดียวกัน (เช่น attacker
    เปิด 2 tab, หรือ IP ใช้ร่วมกันหลังคนหลัง NAT/proxy, หรือ bot reconnect ถี่ๆ) ได้ session_id ตัว
    เดียวกัน ทำให้ session ที่ 2 ไปลบแถว DB ของ session ที่ 1 ทิ้งกลางคัน (ดู
    docs/reports/pi_part1_audit_fixes_2026-08-28.md) — แก้โดยสร้าง id สดใหม่ทุกครั้งที่ login สำเร็จ
    เฉพาะสำหรับ Part 1 (ไม่ผูกกับ ip เลย) แยกออกจาก session_store โดยสิ้นเชิง — session_store ยังใช้
    ต่อได้ปกติสำหรับ Part 2 (phase tracking ที่ต้องการให้ attacker คนเดิม reconnect แล้วนับ phase
    ต่อเนื่องได้ ซึ่งเป็นพฤติกรรมที่ถูกต้องแล้วสำหรับ use case นั้น — Part 1/Part 2 ไม่จำเป็นต้องใช้ id
    ตัวเดียวกัน คนละวัตถุประสงค์กัน)"""
    part1_id = uuid.uuid4().hex[:12]
    login_decoy.start_login_decoy_job(
        username=req.username, ip=req.ip, login_time=req.login_time,
        session_id=part1_id,
    )
    return {"session_id": part1_id, "status": "pending"}


@app.get("/v1/login_decoy/status")
def login_decoy_status(session_id: str):
    """Part 1 — Cowrie ฝั่ง client poll endpoint นี้ทุก 2-3 วิจนกว่า status จะเป็น "done" """
    return login_decoy.get_login_decoy_job(session_id)


class RecordHistoryRequest(BaseModel):
    ip: str
    commands: list[str]


@app.post("/v1/login_decoy/record_history")
def login_decoy_record_history(req: RecordHistoryRequest):
    """เพิ่ม 2026-08-31 (audit batch D, finding #1) — Cowrie เรียกตอน session ปิดจริง
    (`cowrie/shell/session.py::closed()`) ส่งคำสั่งจริงทั้งหมดที่ attacker พิมพ์ระหว่าง connection
    นี้มาต่อท้าย log สะสมของ ip นี้ ให้ reconnect ครั้งถัดไปเห็นใน `.bash_history` จริง (baseline +
    log สะสม — ดู `login_decoy.py::_resolve_static_bash_content()`) เขียนตอน session close เท่านั้น
    (ไม่ live ระหว่าง session) เพราะ bash จริงเองก็ default เขียน `~/.bash_history` ตอน shell exit
    เท่านั้นเหมือนกัน ไม่ใช่ per-command — ตรงกับพฤติกรรมจริงพอดี ไม่ใช่การลดสเปกเพื่อความง่าย
    (session_id ไม่เกี่ยวข้องตรงนี้ — log ผูกกับ ip ตาม single-identity assumption เดิมของทั้งระบบ)"""
    session_store.append_bash_history_log(req.ip, req.commands)
    return {"ok": True}


class PhaseAdaptiveRequest(BaseModel):
    ip: str
    username: str
    phase: str | None = None  # เพิ่ม 2026-08-30 (แก้บั๊กจริง — ดูหัวข้อ "บั๊ก" ใน
    # docs/reports/pi_part2_cowrie_side_implementation_2026-08-30.md) ให้ Cowrie ขอ placements
    # ของ phase ที่ "ยังไม่เสร็จ" ได้ตรงๆ แม้ session จะเลื่อนไป phase ใหม่กว่าแล้วก็ตาม (ไม่งั้น
    # attacker ที่เปลี่ยน phase เร็วกว่าที่ background เตรียมทัน จะพลาดไฟล์ของ phase ก่อนหน้าไปเลย
    # ตลอดกาล เพราะไม่มีใครถามหา phase นั้นซ้ำอีก) ต้อง <= current phase เท่านั้น (กัน client ขอ
    # phase ล่วงหน้าที่ attacker ยังไม่ถึงจริง)
    decoy_session_id: str | None = None  # เพิ่ม 2026-09-01 (ฝั่ง database ของ Part 2) — Cowrie ส่ง
    # fs._decoy_session_id ตรงๆ มาด้วย (ตัวเดียวกับที่ Part 1/psql.py ใช้กรอง SELECT ตาม session)
    # **ไม่ใช่** session.session_id ที่ endpoint นี้ derive จาก req.ip ด้านล่าง (คนละ id space —
    # session.session_id ผูกกับ ip ผ่าน session_store, เจอบั๊กคลาสเดียวกันนี้มาแล้วครั้งหนึ่งตอน
    # 2026-08-28 กับ /v1/login_decoy/cleanup ดู login_decoy.py comment บรรทัด ~183-187) ใช้เฉพาะแท็ก
    # แถว DB ของตาราง phase-adaptive เท่านั้น — ตัว session.session_id เดิมยังใช้เป็นคีย์ sample
    # action เหมือนเดิมทุกประการ ไม่เปลี่ยน ถ้า Cowrie ไม่ส่งมา (None) target ประเภทตารางจะถูกข้าม
    # เหมือนเนื้อหายังไม่พร้อม ไม่ error


@app.post("/v1/phase_adaptive/placements")
def phase_adaptive_placements(req: PhaseAdaptiveRequest):
    """Part 2 (2026-08-30) — เรียกจากฝั่ง Cowrie ตอนเจอว่า phase ของ session เปลี่ยนไปจากที่วาง
    decoy ไว้ล่าสุด (ดู phase_adaptive.py หัวไฟล์ + jaunty-drifting-tome.md ส่วน Part 2 ข้อ 3)
    เร็ว ไม่มี live-call AI ตรงนี้เลย (เนื้อหาต้องเตรียมไว้แล้วจากชั้น background ผ่าน
    warm_next_phase() ที่ track() เรียกทุกคำสั่ง) คืน ready=False ถ้ายังไม่พร้อม — ฝั่ง Cowrie ต้อง
    ไม่ mark ว่าวางแล้วในกรณีนี้ (retry เองตอนคำสั่งถัดไปตามธรรมชาติ ไม่ต้อง poll เพิ่ม)

    อ่าน session ปัจจุบันตรงๆ ไม่เรียก session_store.record_command() ซ้ำ (แค่อ่าน phase ล่าสุดที่
    /v1/track บันทึกไว้แล้ว ไม่เลื่อน phase ซ้ำจากจุดนี้)"""
    session = session_store.get_or_create_session(req.ip)
    # กัน race (แก้ 2026-09-09 — ดู docs/reports/pi_part2_classify_gate_2026-09-09.md): phase เลื่อน
    # ตามคำสั่งที่พิมพ์ ไม่ใช่จำนวนคำสั่ง — ถ้า attacker พิมพ์คำสั่ง Installation (phase แรกที่มีไฟล์
    # Part 2) ตั้งแต่คำสั่งที่ 1-2 phase จะถึงก่อน classifier ครบ CLASSIFY_AT_N คำสั่งแล้วล็อก
    # attacker_type จริง → ถ้าปล่อยวางตอนนั้นจะได้ tier/action ของ default 'Bot' ค้างทั้ง session
    # (ไฟล์ที่ Cowrie วางแล้วไม่ถูกแทน). วางเฉพาะหลังล็อกแล้วเท่านั้น การันตีใช้ attacker_type ที่
    # จำแนกจริงเสมอ. บอทจริง 1-2 คำสั่งไม่เคยถึง phase ที่มีไฟล์ Part 2 อยู่แล้ว จึงไม่เสียอะไร;
    # มือโปรที่กระโดด Installation เร็วแค่รอถึงคำสั่งที่ 3 (get_placements กวาด phase ย้อนหลังให้เอง)
    if not session.attacker_type_locked:
        return {"all_ready": False, "action": None, "extra_delay_ms": 0,
                "placements": [], "phase": session.phase_tracker.current_phase}
    current_phase = session.phase_tracker.current_phase
    phase = current_phase
    if req.phase and req.phase != current_phase:
        order = session.phase_tracker.PHASE_ORDER
        try:
            if req.phase in order and order.index(req.phase) <= order.index(current_phase):
                phase = req.phase  # ขอ phase ก่อนหน้าที่ยังไม่เสร็จได้ ตราบใดที่ไม่ล้ำหน้า current
        except ValueError:
            pass  # phase ที่ขอมาไม่รู้จัก -- ใช้ current_phase เดิมไปเลย ไม่ error
    levers = brain.compute_levers(phase, session.attacker_type)
    result = phase_adaptive.get_placements(
        session_id=session.session_id, phase=phase,
        tier=levers["tier"], attacker_type=levers["attacker_type"],
        decoy_session_id=req.decoy_session_id,
    )
    result["phase"] = phase
    # แทนที่ path home-relative (path_note มี) + owner/group placeholder "$USERNAME" ด้วย
    # username จริง เหมือน login_decoy.py ทำกับ /sysadmin/ (ดู vfs_schema_part2_phase_adaptive.json
    # entry xmrig config.json) -- บั๊กที่เจอจริง 2026-08-30 (verify): เดิมแทนแค่ path ลืม owner/group
    # ทำให้ placement ตอบ owner="$USERNAME" ตรงๆ (ไม่ใช่ username จริง)
    for p in result["placements"]:
        if p.get("path_note"):
            p["path"] = f"/home/{req.username}/{p['path']}"
        if p.get("owner") == "$USERNAME":
            p["owner"] = req.username
        if p.get("group") == "$USERNAME":
            p["group"] = req.username
    return result


class CleanupSessionRequest(BaseModel):
    session_id: str


@app.post("/v1/cleanup_session")
def cleanup_session_endpoint(req: CleanupSessionRequest):
    """Part 1 — เรียกตอนจบ session จริง (cowrie.session.closed) ลบแถว DB ของ session นี้ทิ้ง (ตาม
    มติ 'อยู่แค่ session เดียว') ฝั่งไฟล์ไม่ต้องทำอะไร (honeyfs หายไปเองเมื่อ process/connection จบ
    อยู่แล้ว ไม่ persist)

    **แก้บั๊กจริง 2026-08-28**: เดิมรับแค่ ip แล้ว re-derive session_id จาก session_store (ผูกกับ ip)
    อีกที — พอ /v1/login_decoy/start เปลี่ยนไปสร้าง id สดใหม่ไม่ผูกกับ ip แล้ว จุดนี้ต้องรับ
    session_id ตรงๆ จาก Cowrie แทน (Cowrie เก็บ id ที่ได้จาก start ไว้ที่ fs._decoy_session_id
    อยู่แล้ว ส่งกลับมาตรงนี้ได้เลย ไม่ต้องเดา/คำนวณใหม่)"""
    login_decoy.cleanup_session_decoys(req.session_id)
    return {"ok": True}
