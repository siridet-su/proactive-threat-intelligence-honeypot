from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import production.reporting.session_assessment_v4 as assessment_v4
from production.reporting.session_assessment_v4 import (
    SessionAssessmentV4Error,
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.utils.validation_diagnostics import (
    build_validation_diagnostic,
)


REVISION = "d" * 40
BEHAVIOR_POLICY = Path(
    "configs/threat_hypothesis_behavior.trusted.json"
).resolve()
CLASSIFICATION_POLICY = Path(
    "configs/classification_rules.trusted.json"
).resolve()


def _payload() -> dict[str, Any]:
    command = "id"
    event = {
        "session": "manifest-provenance-regression",
        "timestamp": "2026-07-31T02:00:00Z",
        "eventid": "cowrie.command.input",
        "input": command,
        "success": 1,
    }
    return {
        "session_id": "manifest-provenance-regression",
        "commands": [command],
        "raw_events": [event],
        "classification_events": [],
    }


def _stage_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    manifest_overrides: dict[str, Any] | None = None,
) -> Path:
    root = tmp_path / "release"
    source = root / "production/reporting/session_assessment_v4.py"
    source.parent.mkdir(parents=True)
    source_bytes = Path(assessment_v4.__file__).read_bytes()
    source.write_bytes(source_bytes)
    manifest = {
        "schema_version": "honeypot_release_manifest.v7",
        "git_revision": REVISION,
        "release_path": str(root.resolve()),
        "release_identity": {
            "policy_id": "immutable_source_release.v2",
        },
        "release_files": {
            "production/reporting/session_assessment_v4.py": {
                "type": "file",
                "bytes": len(source_bytes),
                "sha256": hashlib.sha256(source_bytes).hexdigest(),
            },
        },
    }
    for key, value in (manifest_overrides or {}).items():
        manifest[key] = value
    manifest_path = root / "DEPLOYMENT_MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True),
        encoding="utf-8",
    )
    os.chmod(manifest_path, 0o644)
    monkeypatch.setattr(assessment_v4, "__file__", str(source))
    monkeypatch.delenv("DEPLOYED_COMMIT", raising=False)

    def no_git(*_args: Any, **_kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired("git", 2)

    monkeypatch.setattr(assessment_v4.subprocess, "run", no_git)
    return root


def _build() -> dict[str, Any]:
    payload = _payload()
    return build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )


def test_manifest_bound_staged_release_builds_valid_canonical_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _stage_source(tmp_path, monkeypatch)

    report = _build()
    replay = _build()

    assert not (root / "DEPLOYED_COMMIT").exists()
    assert report["provenance"]["evaluator_git_revision"] == REVISION
    assert validate_session_assessment_v4(report) == []
    assert replay["assessment_id"] == report["assessment_id"]
    assert replay["canonical_evidence"] == report["canonical_evidence"]


def test_archive_without_any_bound_revision_fails_at_whole_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _stage_source(tmp_path, monkeypatch)
    (root / "DEPLOYMENT_MANIFEST.json").unlink()

    with pytest.raises(
        SessionAssessmentV4Error,
        match="evaluator_git_revision is required",
    ) as captured:
        _build()

    diagnostic = build_validation_diagnostic(captured.value)
    assert diagnostic is not None
    assert diagnostic["errors"] == [
        {
            "error_category": "missing",
            "field_path": "provenance.evaluator_git_revision",
            "constraint": "required_field",
            "received_type": "not_recorded",
            "state": "missing",
        },
    ]


def test_manifest_with_mismatched_evaluator_hash_remains_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stage_source(
        tmp_path,
        monkeypatch,
        manifest_overrides={
            "release_files": {
                "production/reporting/session_assessment_v4.py": {
                    "type": "file",
                    "bytes": 1,
                    "sha256": "0" * 64,
                },
            },
        },
    )

    with pytest.raises(
        SessionAssessmentV4Error,
        match="evaluator_git_revision is required",
    ):
        _build()
