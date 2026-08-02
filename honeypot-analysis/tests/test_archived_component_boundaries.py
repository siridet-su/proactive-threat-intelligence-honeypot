from __future__ import annotations

import copy
import importlib
import inspect
from pathlib import Path
import tomllib

import pytest

from production.api import monitor_web
from production.reporting.canonical_pipeline import CanonicalAssessmentCoordinator
from production.reporting.response_guidance_v3 import (
    read_legacy_response_guidance,
)
from production.reporting.session_assessment_v4 import (
    read_legacy_session_assessment,
)
from production.storage import DatabaseConfigurationError, DatabaseSettings


ROOT = Path(__file__).resolve().parents[1]


def test_packaged_entrypoints_all_resolve_to_callable_targets() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = project["project"]["scripts"]
    assert "honeypot-prediction-retention" not in scripts
    for target in scripts.values():
        module_name, attribute = target.split(":", 1)
        module = importlib.import_module(module_name)
        assert callable(getattr(module, attribute))


def test_only_canonical_coordinator_is_wired_for_new_analysis() -> None:
    from production.workers import analysis_worker, session_monitor

    assert analysis_worker.CanonicalAssessmentCoordinator is (
        CanonicalAssessmentCoordinator
    )
    assert "CanonicalAssessmentCoordinator" in inspect.getsource(
        session_monitor.build_pipeline_trigger
    )
    for legacy_attribute in (
        "_build_deterministic_hypothesis",
        "infer_analytical",
        "generate_recommendations",
    ):
        assert not hasattr(CanonicalAssessmentCoordinator, legacy_attribute)


def test_archived_backends_fail_closed_and_source_is_absent() -> None:
    for backend in ("mongodb", "postgresql", "postgres"):
        with pytest.raises(DatabaseConfigurationError):
            DatabaseSettings.from_values(database_backend=backend)
    for path in (
        "production/storage/mongodb.py",
        "production/storage/postgres_schema.sql",
        "production/tools/migrate_sqlite_to_mongodb.py",
    ):
        assert not (ROOT / path).exists()


def test_historical_adapters_are_read_only_and_do_not_authorize_actions() -> None:
    assessment = {
        "schema_version": "session_assessment.v3",
        "assessment_id": "historic",
        "possible_objectives": [{"objective": "stored-only"}],
    }
    guidance = {
        "schema_version": "response_guidance.v2",
        "guidance_id": "historic",
        "actions": [{"action": "stored-only"}],
    }
    assessment_before = copy.deepcopy(assessment)
    guidance_before = copy.deepcopy(guidance)

    assessment_view = read_legacy_session_assessment(assessment)
    guidance_view = read_legacy_response_guidance(guidance)

    assert assessment == assessment_before
    assert guidance == guidance_before
    assert assessment_view["record"] == assessment_before
    assert assessment_view["recomputed"] is False
    assert assessment_view["authoritative_for_new_records"] is False
    assert guidance_view["record"] == guidance_before
    assert guidance_view["recomputed"] is False
    assert guidance_view["advisory_actions"] == []


def test_monitor_has_one_static_document_and_no_legacy_renderer() -> None:
    source = inspect.getsource(monitor_web.MonitorHandler._do_GET)
    assert monitor_web.STATIC_MONITOR_HTML.is_file()
    assert not hasattr(monitor_web, "render_html")
    assert '"/legacy"' not in source
    assert "canonical monitor asset unavailable" in source
