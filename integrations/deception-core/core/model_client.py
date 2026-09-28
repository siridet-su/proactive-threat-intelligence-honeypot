"""
model_client.py — เรียก Qwen ผ่าน Colab + cloudflared tunnel
(colab_upload/3_serve/serve_endpoint.py เปิด /generate endpoint ที่รับ payload หน้าตานี้
พอดีอยู่แล้ว — payload ที่ส่งไปต้องตรงกับ GenerateRequest ของฝั่งนั้นเป๊ะ)
timeout 8 วิ (มติ 5 ของ 09_three_day_plan.md — fallback 2 ชั้น cache→static กัน Colab หลุด
ทำให้ระบบค้างตอนเดโม) ถ้าเรียกไม่ทัน/ล้ม ให้ router.py ใช้ fallback text แทน

ทดลอง 2026-08-18: mode="bash" route ไป Hailo-10H บน Pi แทน Colab ถ้าตั้ง
MODEL_ENDPOINT_URL_BASH_HAILO ไว้ (ว่าง = ปิด ใช้ Colab เหมือนเดิมทุก mode) — mode="psql"
ยังไป Colab เสมอ เพราะ Hailo psql พัง 0% ตาม docs/reports/lora_hef_quality_recheck_2026-08-16.md
ดู docs/reports/pi_hailo_bash_route_2026-08-18.md สำหรับเหตุผลเต็ม/ผล verify
"""

import httpx

from config import (
    MODEL_ENDPOINT,
    MODEL_ENDPOINT_BASH_HAILO,
    MODEL_TIMEOUT_S,
    MODEL_TIMEOUT_S_HAILO,
)


class ModelUnavailable(Exception):
    pass


def generate(
    cwd: str,
    files_str: str,
    attacker_type: str,
    kill_chain_phase: str,
    mode: str,
    action: str,
    stage: str,
    tier: int,
    user_command: str,
) -> str:
    if mode == "bash" and MODEL_ENDPOINT_BASH_HAILO:
        endpoint = MODEL_ENDPOINT_BASH_HAILO
        timeout = MODEL_TIMEOUT_S_HAILO
    else:
        endpoint = MODEL_ENDPOINT
        timeout = MODEL_TIMEOUT_S

    if not endpoint:
        raise ModelUnavailable("model endpoint ยังไม่ได้ตั้งค่า (mode=%r)" % mode)

    payload = {
        "cwd": cwd,
        "files_str": files_str,
        "attacker_type": attacker_type,
        "kill_chain_phase": kill_chain_phase,
        "mode": mode,
        "action": action,
        "stage": stage,
        "tier": tier,
        "user_command": user_command,
    }
    try:
        resp = httpx.post(
            f"{endpoint.rstrip('/')}/generate", json=payload, timeout=timeout
        )
        resp.raise_for_status()
        return resp.json()["response"]
    except (httpx.HTTPError, KeyError, ValueError) as e:
        raise ModelUnavailable(str(e)) from e
