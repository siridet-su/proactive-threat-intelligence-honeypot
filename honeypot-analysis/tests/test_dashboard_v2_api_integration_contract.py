from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboard-v2"


def _source() -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in DASHBOARD.joinpath("src").rglob("*.ts")
    ) + "\n" + "\n".join(
        path.read_text(encoding="utf-8")
        for path in DASHBOARD.joinpath("src").rglob("*.tsx")
    )


def test_dashboard_v2_uses_allowlisted_same_origin_api_and_no_demo_telemetry() -> None:
    source = _source()
    assert "fetchDashboardJson" in source
    assert "DASHBOARD_API_READ_TOKEN" in source
    assert "DASHBOARD_API_ORIGIN" in source
    assert "mockData" not in source
    assert "Math.random" not in source
    assert "password098" not in source
    assert "OP_4725" not in source
    assert "192.168.44.122" not in source


def test_dashboard_v2_keeps_threat_intelligence_evidence_lanes_separate() -> None:
    detail = (DASHBOARD / "src/app/(main)/threat-intel/[id]/page.tsx").read_text(encoding="utf-8")
    assert "Trusted ATT&CK observations" in detail
    assert "Model advisory predictions" in detail
    assert "Correlation hypotheses" in detail
    assert "not calibrated probabilities" in detail
    assert "actor attribution" in detail


def test_dashboard_v2_proxy_does_not_expose_sensitive_command_route() -> None:
    proxy = (DASHBOARD / "src/app/api/[...path]/route.ts").read_text(encoding="utf-8")
    assert 'export async function GET' in proxy
    assert 'redirect: "error"' in proxy
    assert 'cache: "no-store"' in proxy
    assert "internal/session-commands" not in proxy
    assert "Authorization" in proxy
    assert "monitor_generic_table_routes" in proxy
    assert "shouldPreferCompatibilityRoute" in proxy
    assert 'origin.hostname === "127.0.0.1"' in proxy
    assert 'origin.port === "8090"' in proxy
    assert 'origin.pathname === "/"' in proxy
    assert '"/sessions"' in proxy
    assert '"/events"' in proxy


def test_dashboard_v2_response_guidance_is_fail_closed_and_manual_only() -> None:
    detail = (DASHBOARD / "src/app/(main)/threat-intel/[id]/page.tsx").read_text(encoding="utf-8")
    assert "requires_manual_approval" in detail
    assert "safe_to_auto_execute" in detail
    assert "fail-closed" in detail
    assert "execution authorization" in detail
