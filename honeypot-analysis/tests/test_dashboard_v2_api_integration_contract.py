from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboard-v2"


def _active_source() -> str:
    excluded = {DASHBOARD / "src/lib/mockData.ts", DASHBOARD / "src/data/honeypotMockData.ts"}
    paths = [path for path in DASHBOARD.joinpath("src").rglob("*.ts") if path not in excluded]
    paths += [path for path in DASHBOARD.joinpath("src").rglob("*.tsx") if path not in excluded]
    return "\n".join(path.read_text(encoding="utf-8") for path in paths) + "\n"


def test_dashboard_v2_uses_explicit_runtime_api_routes_without_demo_fixtures() -> None:
    source = _active_source()
    # The current runtime calls pass explicit cache/options objects, so assert
    # the route prefix rather than an obsolete zero-argument call spelling.
    assert 'fetch("/api/threats"' in source
    assert 'fetch("/api/hardware"' in source
    assert 'fetch("/api/auth/login"' in source
    assert "mockData" not in source
    assert "password098" not in source
    assert "OP_4725" not in source
    assert "192.168.44.122" not in source


def test_dashboard_v2_session_detail_uses_typed_evidence_and_no_action_executor() -> None:
    detail = (DASHBOARD / "src/app/(main)/threat-intel/[id]/page.tsx").read_text(encoding="utf-8")
    assert "SessionAnalysisPanels" in detail
    assert "session-analysis-semantics" in detail
    assert "session-intelligence" in detail
    assert "observed_tactic_path" in detail
    assert "handleNextDistinct" in detail
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
        assert "getSessionFromRequest" in route

    session_analysis = (api_root / "session-analysis/[capability]/route.ts").read_text(encoding="utf-8")
    assert "export const dynamic" in session_analysis
    assert "export async function GET" in session_analysis
    assert "getSessionFromRequest" in session_analysis
    assert "safe_to_auto_execute: false" in session_analysis
    assert "automatic_response_execution: false" in session_analysis


def test_dashboard_v2_does_not_embed_automatic_response_execution() -> None:
    source = _active_source()
    assert "child_process" not in source
    assert "execFile" not in source
    assert "execSync" not in source
    assert "spawn(" not in source
    assert not re.search(r"\bexec\s*\(", source)

    session_analysis = (DASHBOARD / "src/app/api/session-analysis/[capability]/route.ts").read_text(encoding="utf-8")
    assert "requires_manual_approval: true" in session_analysis
    assert "safe_to_auto_execute: false" in session_analysis
