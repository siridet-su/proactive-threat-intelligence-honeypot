"""
router.py — สมองตัดสินว่า "ใครตอบ" ลำดับนี้เท่านั้น ห้ามสลับ
(docs/10_system_concept_3day.md §5④):

  ① cache (เคยแต่งไปแล้วใน session นี้? — กลุ่ม B session-unique เขียนมาจอง cache ล่วงหน้าไว้
     ผ่าน background prefetch ได้ด้วย ไม่ใช่แค่ lazy-on-miss แบบเดิม)
  ② ของจริง — ไม่ใช่หน้าที่ไฟล์นี้ ประตู (Cowrie/FTP) ต้องเช็ค VFS/DB จริงเองก่อนเรียกมาที่นี่
     (deception-core ไม่มีสิทธิ์เข้าถึง VFS ของ Cowrie โดยตรง)
  ③ ไม่มีจริง + gate ปิด (เดิมเรียก "stage A") → refuse ("No such file" แบบ mode-aware)
  ④ ไม่มีจริง + gate เปิด (เดิมเรียก "stage B") → lookup template_content (กลุ่ม A, pre-fetch
     ไว้ล่วงหน้าแบบ background — ดู docs/reports/pi_stageB_pregen_2026-08-23.md) ถ้า miss (worker
     ยังไม่เสร็จ หรือ target นอกชุด bounded) → fallback **ไม่มีการเรียกโมเดลสดอีกต่อไป**
     (เปลี่ยน 2026-08-23 — เดิมข้อ ④ เรียก model_client.generate() สดตรงนี้)

เหตุผลที่ห้ามสลับ ①-④: ให้โมเดลตอบก่อนของจริงเคยทำให้ hallucination พุ่ง 0%→15.8%
ตอนรีเทรน (ดู 09_three_day_plan.md §3)
"""

import threading
import time

import brain
import cache_store
import events
import phase_adaptive
import prefetch_worker
import session_store
import template_store

REFUSE_TEXT = {
    "bash": "cat: {target}: No such file or directory\n",
    "psql": 'ERROR:  relation "{target}" does not exist\n',
}

# แก้ 2026-08-31 (audit รอบ 2, batch E, finding #11): เดิม fallback (stage B แต่ target ไม่อยู่ใน
# ชุด bounded) ตอบ "Input/output error"/"I/O error" ซึ่ง real Linux ไม่มีทางให้ error แบบนี้กับไฟล์
# ที่ไม่มีอยู่จริงเลย (EIO ใช้เฉพาะ disk/hardware corruption จริง) — grey-box audit เจอว่า attacker
# ที่ลอง cat path สุ่มหลายรอบจะได้ error เดียวกันซ้ำๆ เป็น tell ชัดเจน ปรึกษาผู้ใช้แล้วตัดสินใจให้
# ข้อความเหมือน stage A (REFUSE_TEXT) ไปเลย — reuse dict เดียวกัน (ไม่พิมพ์ข้อความซ้ำมือสองที่ ตาม
# CLAUDE.md §5 single source of truth)
FALLBACK_TEXT = REFUSE_TEXT

# door="ftp": ไฟล์เพิ่งโผล่ใน LIST มาแล้ว RETR ตอบ "ไม่มีไฟล์" จะแปลก (ไม่เหมือน cat ที่ยัง
# ไม่เคย ls มาก่อน) — stage A เลยต้องได้ "ของจริงแต่ไม่มีค่า" แทน error string ตรงๆ
# ส่ง mode="bash" ให้โมเดลเสมอสำหรับ FTP (ไม่ใช่ mode ใหม่ "ftp" ที่โมเดลไม่เคยเห็นตอนเทรน
# — session_prompt_builder รองรับแค่ bash/psql สอง mode เท่านั้น เลี่ยง train/inference mismatch)
FTP_STAGE_A_CONTENT = (
    "-- backup truncated: disk quota exceeded during nightly job, "
    "see /var/log/odoo/backup.log for details --\n"
)
FTP_FALLBACK_CONTENT = "-- transfer interrupted: connection reset by peer --\n"


def decide(ip: str, door: str, mode: str, cwd: str, files_str: str, target: str, command: str,
           client: str = "") -> dict:
    t0 = time.monotonic()
    model_mode = mode if mode in REFUSE_TEXT else "bash"

    session = session_store.get_or_create_session(ip, client_version=client)
    was_locked = session.attacker_type_locked  # P5: จับ fresh lock (ก่อน record_command)
    was_type = session.attacker_type           # P8: จับ upgrade (type เปลี่ยนทั้งที่ล็อกแล้ว)
    phase = session_store.record_command(session, command)
    # P5 warm-on-lock: ถ้าคำสั่งนี้คือคำสั่งที่ทำให้ classifier เพิ่งล็อก → warm tier ที่ล็อกทันที
    # (decide() เดิมไม่ warm เลย = ช่องที่ต้องปิด — ดู pi_warm_on_lock_2026-09-18.md)
    # P8 warm-on-upgrade: ถ้า upgrade SK/Bot->APT (type เปลี่ยนทั้งที่ล็อกแล้ว) → warm tier ใหม่ทันที
    # (ไม่งั้น APT ที่เพิ่ง reveal ได้ tier-3 แบบ gen สด ช้า — ดู pi_sigma_upgrade_2026-09-19.md)
    if session.attacker_type_locked and (not was_locked or session.attacker_type != was_type):
        _warm_on_lock(brain.get_lure_tier(session.attacker_type), session.session_id, phase)

    cache_key = f"{door}:{target}"
    cached = cache_store.get(session.session_id, door, cache_key)
    if cached is not None:
        result = {
            "session_id": session.session_id,
            "answered_by": "cache",
            "content": cached,
            "phase": phase,
            "stage": None,
            "action": None,
            "tier": None,
        }
        _log(ip, door, session.session_id, command, phase, result, t0, cache_hit=True)
        return result

    levers = brain.compute_levers(phase, session.attacker_type)
    stage = levers["stage"]

    if stage == "A":
        content = FTP_STAGE_A_CONTENT if door == "ftp" else REFUSE_TEXT[model_mode].format(target=target)
        result = {
            "session_id": session.session_id,
            "answered_by": "refuse",
            "content": content,
            "phase": phase,
            "stage": stage,
            "action": levers["action"],
            "tier": levers["tier"],
        }
        _log(ip, door, session.session_id, command, phase, result, t0, cache_hit=False)
        return result

    # Stage B (gate เปิด) — เป้าหมายไม่มีจริง lookup เนื้อหาที่ pre-fetch ไว้ล่วงหน้าแทนเรียก
    # โมเดลสด (เปลี่ยน 2026-08-23) — content_type map จาก action: deceive=deceive, lure/delay
    # ทั้งคู่ = normal (get_content_mode ใน shared/session_prompt_builder.py ทำ mapping นี้แล้ว
    # แต่ที่นี่ยังไม่ import มาใช้ตรงๆ เพื่อไม่เพิ่ม dependency ใหม่ในไฟล์นี้ — ใช้ inline ตรงไปตรงมา)
    content_type = "deceive" if levers["action"] == "deceive" else "normal"

    if mode == "psql":
        # เปลี่ยน 2026-08-26 (ดู docs/reports/pi_prepared_response_qc_fix_2026-08-26.md): psql
        # เลิกใช้ template_store lookup (text ที่ AI แต่งเลียนแบบผลลัพธ์ psql เอง — เจอบั๊กจริง
        # หลายแบบ: สะท้อน SQL query กลับมา, ตารางคอลัมน์เพี้ยน, พ่นหลายบล็อกซ้อนกัน — ทั้งหมดมาจาก
        # การให้ LLM "เดา" ว่า psql format ผลลัพธ์ยังไง) เปลี่ยนเป็นชี้ให้ psql.py ไปเรียก
        # Postgres จริง (schema `decoy`, seed ไว้ล่วงหน้าครั้งเดียวผ่าน seed_decoy_tables.py —
        # ให้ psql ตัวจริงจัดฟอร์แมตให้ ไม่มี LLM มาปลอมฟอร์แมตอีกต่อไป) ตัว router.py ยังทำหน้าที่
        # เดิม (ตัดสิน gate/tier/content_type) แค่ไม่ lookup text เองอีกต่อไป
        result = {
            "session_id": session.session_id,
            "answered_by": "pregen_real_db",
            "content": None,
            "phase": phase,
            "stage": stage,
            "action": levers["action"],
            "tier": levers["tier"],
        }
        _log(ip, door, session.session_id, command, phase, result, t0, cache_hit=False)
        return result

    templated = template_store.get(door, target, levers["tier"], content_type)
    if templated is not None:
        content = templated
        answered_by = "pregen"
    else:
        # worker ยัง generate ไม่ทัน (attacker เร็วผิดปกติ) หรือ target นอกชุด bounded — fallback
        # เดิม ไม่มี live call ใดๆ หลุดออกไปเลย
        content = FTP_FALLBACK_CONTENT if door == "ftp" else FALLBACK_TEXT[model_mode].format(target=target)
        answered_by = "fallback"

    cache_store.put(session.session_id, door, cache_key, content)
    result = {
        "session_id": session.session_id,
        "answered_by": answered_by,
        "content": content,
        "phase": phase,
        "stage": stage,
        "action": levers["action"],
        "tier": levers["tier"],
    }
    _log(ip, door, session.session_id, command, phase, result, t0, cache_hit=False)
    return result


def _fire_and_forget_warm(tier: int, session_id: str, phase: str) -> None:
    """เพิ่ม 2026-08-23 — background speculative pre-fetch ตามคำแนะนำอาจารย์: "เริ่มสร้างคำตอบ
    จากข้อมูลช่วงแรกที่แฮกเกอร์พยายามพิมพ์" ไม่รู้ mode ล่วงหน้า (payload /v1/track ไม่มี mode)
    เลย trigger ทั้ง bash และ psql พร้อมกัน — idempotent ผ่าน template_store.try_claim() เรียกซ้ำ
    กี่ครั้งก็ไม่เปลือง เรียกใน thread แยกเสมอ กัน track() ช้าลง (ตัว generate เองเป็น sync call
    ใช้เวลาหลายวินาทีต่อ 1 target)

    เพิ่ม 2026-08-30 (Part 2): warm_next_phase() ของ phase_adaptive.py เข้าไปใน thread เดียวกัน —
    เตรียมเนื้อหา decoy ของ phase ถัดไป (+ phase ปัจจุบันเป็น safety net เผื่อกระโดดข้ามหลายขั้น)
    ไว้ล่วงหน้า ไม่มี live-call ตอน attacker โต้ตอบจริงเช่นกัน"""

    def _run():
        # เฉพาะ door="ssh" — track() มาจาก Cowrie เท่านั้น (FTP ไม่เคยเรียก track() เลย ไม่มี
        # trigger ของตัวเอง ต้องพึ่ง warm_all.py bootstrap อย่างเดียว — ดู prefetch_worker.py
        # หัวไฟล์ 2026-08-23)
        for mode in ("bash", "psql"):
            try:
                prefetch_worker.warm_tier("ssh", mode, tier)
            except Exception:
                pass  # ปล่อยผ่าน — ให้ trigger รอบหน้า (คำสั่งถัดไป) retry เอง
            try:
                prefetch_worker.warm_session(session_id, "ssh", mode, tier)
            except Exception:
                pass
        try:
            phase_adaptive.warm_next_phase(session_id, phase, tier)
        except Exception:
            pass  # ปล่อยผ่าน — ให้ trigger รอบหน้า (คำสั่งถัดไป) retry เอง เหมือนของเดิม

    threading.Thread(target=_run, daemon=True).start()


def _warm_on_lock(tier: int, session_id: str, phase: str) -> None:
    """P5 warm-on-lock (ดู docs/reports/pi_warm_on_lock_2026-09-18.md) — ยิงครั้งเดียว *ตอนที่
    classifier เพิ่งล็อก attacker_type* (fresh lock) จากทั้ง decide() และ track(). ต่างจาก
    _fire_and_forget_warm (ทุกคำสั่ง, แค่ next+current phase): อันนี้ front-load **ทั้ง tier ที่ล็อก
    ตั้งแต่ phase ปัจจุบันไปจนจบ kill-chain** ทันทีที่รู้ tier จริง — กัน gen tier ใหม่ (SK/APT) ไม่ทัน
    ตอน attacker กระโดดเข้า phase ที่มีไฟล์ลึก. thread แยกเสมอ (serial hailo หนัก). idempotent."""

    def _run():
        for mode in ("bash", "psql"):
            try:
                prefetch_worker.warm_tier("ssh", mode, tier)
            except Exception:
                pass
            try:
                prefetch_worker.warm_session(session_id, "ssh", mode, tier)
            except Exception:
                pass
        try:
            phase_adaptive.warm_from_phase(session_id, phase, tier)
        except Exception:
            pass  # ปล่อยผ่าน — per-command _fire_and_forget_warm ยัง retry ให้รอบถัดไป

    threading.Thread(target=_run, daemon=True).start()


def track(ip: str, door: str, command: str, client: str = "") -> dict:
    """ประตูเรียกทุกคำสั่ง แม้คำสั่งนั้นตอบจาก VFS/DB จริงเอง (ไม่ผ่าน decide() เลย)
    เพื่ออัปเดต phase ของ session ที่นี่ที่เดียว — ไม่งั้นคำสั่งที่เป็นตัวเลื่อน phase จริง
    (เช่น sudo cat odoo.conf ซึ่งมีไฟล์จริงใน VFS) จะไม่เคยไปถึง deception-core เลย
    gate ก็จะไม่มีวันปลด (ดู work_log_2026-07-27.md งาน 2.2 — เจอจุดนี้ตอน implement จริง)

    แก้ 2026-09-12 (grilling session, Work Item 1 — ทำให้ Part 2 "delay" action หน่วงเวลาจริง ดู
    ~/.claude/plans/attacker-polished-seahorse.md): เพิ่ม `action`/`extra_delay_ms` ของ phase
    ปัจจุบันเข้า response — ผ่าน `phase_adaptive.get_action_and_delay()` (cache เดียวกับที่
    `/v1/phase_adaptive/placements` ใช้ การันตี phase เดียวกัน = action เดียวกันเสมอ, มติ grilling
    2026-09-12: delay ผูกกับ action ของ phase ล้วนๆ ไม่ผูกกับ placement pending/all_ready เพราะไฟล์
    ถูก pre-warm ไว้ล่วงหน้าอยู่แล้ว) gate ด้วย `attacker_type_locked` เหมือน
    `app.py::phase_adaptive_placements()` ทำอยู่แล้ว (กัน race เดียวกัน — ไม่ sample action ด้วย
    attacker_type='Bot' default ค้างก่อนจำแนกจริง) `/v1/track` ถูกเรียกทุกคำสั่งอยู่แล้ว (ไม่ใช่แค่
    คำสั่งที่แตะ Part 2) — ผลคือ delay จะรู้สึกได้กับทุกคำสั่งที่ report ระหว่าง phase นั้น ไม่ใช่แค่
    คำสั่งที่ไปโดน decoy content ตรงๆ ตรงตามที่ตั้งใจ (ทั้ง phase รู้สึกช้าเท่ากัน ไม่ใช่แค่บางคำสั่ง)"""
    t0 = time.monotonic()
    session = session_store.get_or_create_session(ip, client_version=client)
    was_locked = session.attacker_type_locked  # P5: จับ fresh lock (ก่อน record_command)
    was_type = session.attacker_type           # P8: จับ upgrade (type เปลี่ยนทั้งที่ล็อกแล้ว)
    phase = session_store.record_command(session, command)

    levers = brain.compute_levers(phase, session.attacker_type)
    _fire_and_forget_warm(levers["tier"], session.session_id, phase)
    # P5 warm-on-lock (fresh lock) + P8 warm-on-upgrade (SK/Bot->APT type เปลี่ยนทั้งที่ล็อกแล้ว) →
    # front-load ทุก phase ของ tier ใหม่ทันที (นอกเหนือ _fire_and_forget_warm ที่ warm แค่ next+current)
    # levers["tier"] คำนวณหลัง record_command = สะท้อน tier ที่ upgrade แล้ว — ดู pi_sigma_upgrade_2026-09-19.md
    if session.attacker_type_locked and (not was_locked or session.attacker_type != was_type):
        _warm_on_lock(levers["tier"], session.session_id, phase)

    action = None
    extra_delay_ms = 0
    if session.attacker_type_locked:
        action, extra_delay_ms = phase_adaptive.get_action_and_delay(
            session.session_id, phase, session.attacker_type
        )

    events.log_event(
        ip=ip,
        door=door,
        session_id=session.session_id,
        cmd=command,
        phase=phase,
        stage=None,
        action=None,
        tier=None,
        answered_by="local",
        cache_hit=False,
        latency_ms=int((time.monotonic() - t0) * 1000),
        bytes_out=0,
    )
    return {
        "session_id": session.session_id,
        "phase": phase,
        "action": action,
        "extra_delay_ms": extra_delay_ms,
    }


def _log(ip, door, session_id, command, phase, result, t0, cache_hit) -> None:
    events.log_event(
        ip=ip,
        door=door,
        session_id=session_id,
        cmd=command,
        phase=phase,
        stage=result.get("stage"),
        action=result.get("action"),
        tier=result.get("tier"),
        answered_by=result["answered_by"],
        cache_hit=cache_hit,
        latency_ms=int((time.monotonic() - t0) * 1000),
        # เพิ่ม 2026-08-26: content เป็น None ได้แล้วสำหรับ mode="psql" answered_by=
        # "pregen_real_db" (psql.py ไปคิวรี Postgres เองแทน ไม่มี text ให้ log ตรงนี้) —
        # ป้องกัน AttributeError ('NoneType' object has no attribute 'encode')
        bytes_out=len((result["content"] or "").encode("utf-8")),
    )
