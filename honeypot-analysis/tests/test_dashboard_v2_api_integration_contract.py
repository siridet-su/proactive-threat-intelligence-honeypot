from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboard-v2"


def _active_source() -> str:
    excluded = {DASHBOARD / "src/lib/mockData.ts", DASHBOARD / "src/data/honeypotMockData.ts"}
    paths = [path for path in DASHBOARD.joinpath("src").rglob("*.ts") if path not in excluded]
    paths += [path for path in DASHBOARD.joinpath("src").rglob("*.tsx") if path not in excluded]
    return "\n".join(path.read_text(encoding="utf-8") for path in paths) + "\n"


def test_dashboard_v2_uses_explicit_runtime_api_routes_without_demo_fixtures() -> None:
    source = _active_source()
    assert 'fetch("/api/threats")' in source
    assert 'fetch("/api/hardware")' in source
    assert 'fetch("/api/auth/login"' in source
    assert "mockData" not in source
    assert "password098" not in source
    assert "OP_4725" not in source
    assert "192.168.44.122" not in source


def test_dashboard_v2_session_detail_uses_typed_evidence_and_no_action_executor() -> None:
    detail = (DASHBOARD / "src/app/(main)/threat-intel/[id]/page.tsx").read_text(encoding="utf-8")
    assert "isDashboardThreatEvent" in detail
    assert 'fetch("/api/threats")' in detail
    assert "ERROR: SESSION ARCHIVED OR NOT FOUND" in detail
    assert "safe_to_auto_execute" not in detail
    assert "execute authorization" not in detail.lower()


def test_dashboard_v2_exposes_only_explicit_direct_api_route_handlers() -> None:
    api_root = DASHBOARD / "src/app/api"
    assert not (api_root / "[...path]/route.ts").exists()
    for relative in (
        "threats/route.ts",
        "hardware/route.ts",
        "hardware/stream/route.ts",
        "malware/route.ts",
        "users/route.ts",
    ):
        route = (api_root / relative).read_text(encoding="utf-8")
        assert "export const dynamic" in route or relative == "users/route.ts"
        assert "export async function GET" in route
        assert "clientPromise" in route


def test_dashboard_v2_does_not_embed_automatic_response_execution() -> None:
    source = _active_source()
    assert "safe_to_auto_execute" not in source
    assert "exec(" not in source
    assert "child_process" not in source
