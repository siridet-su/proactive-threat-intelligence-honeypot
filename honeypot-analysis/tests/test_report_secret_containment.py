from __future__ import annotations

import builtins
import copy
import json
import stat
from pathlib import Path

import pytest

import production.reporting.artifacts as artifact_module
from production.policies.validate_stix_bundle import validate_stix_bundle_document
from production.reporting.artifacts import (
    attach_report_artifacts,
    build_stix_bundle,
    write_json_report,
    write_markdown_report,
    write_stix_bundle,
)
from production.utils.config import ProductionConfig
from production.utils.sensitive_data import REDACTION_MARKER
from production.workers import analysis_worker as analysis_worker_module
from production.workers import session_monitor as session_monitor_module
from production.workers.session_monitor import CowrieLogReplayer


SECRET = "report-command-secret-20260717"
DIGEST = "hmac-sha256-v1:active-key:" + ("a" * 64)


def _inputs() -> tuple[dict, dict]:
    command = f"sshpass -p '{SECRET}' ssh root@example.invalid"
    credential_metadata = {
        "credential_observed": True,
        "raw_password_stored": False,
        "password_hash_present": True,
        "raw_events_sanitized": True,
        "hashing_enabled": True,
        "password_hash_alias_count": 0,
        "hash_algorithm": "hmac-sha256-v1",
        "active_key_id": "active-key",
        "correlation_key_ids": [],
        "password": SECRET,
        "login_password_hash": DIGEST,
        "unknown": SECRET,
    }
    report = {
        "session_id": "containment-session",
        "summary": f"Observed command: {command}",
        "commands": [command],
        "login_password_hash": DIGEST,
        "data_provenance": {"credential_metadata": credential_metadata},
    }
    session = {
        "session_id": "containment-session",
        "src_ip": "198.51.100.20",
        "sensor": "unit-sensor",
        "start_time": "2026-07-17T00:00:00Z",
        "commands": [command],
        "raw_events": [
            {
                "eventid": "cowrie.login.success",
                "username": "root",
                "password": SECRET,
                "password_hash": DIGEST,
            }
        ],
        "credential_metadata": credential_metadata,
    }
    return report, session


def _config(reports_dir: Path, *, enabled: bool) -> ProductionConfig:
    config = ProductionConfig()
    config.reports_dir = str(reports_dir)
    config.enable_artifacts = enabled
    config.enable_stix_export = False
    config.enable_pdf_export = False
    return config


def _encoded(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def test_artifact_boundaries_redact_without_mutating_inputs(
    tmp_path: Path,
) -> None:
    report, session = _inputs()
    original_report = copy.deepcopy(report)
    original_session = copy.deepcopy(session)
    reports_dir = tmp_path / "disabled-reports"

    returned = attach_report_artifacts(
        report,
        session,
        _config(reports_dir, enabled=False),
    )

    assert report == original_report
    assert session == original_session
    assert not reports_dir.exists()
    assert SECRET not in _encoded(returned)
    assert DIGEST not in _encoded(returned)
    metadata = returned["data_provenance"]["credential_metadata"]
    assert metadata["schema_version"] == "credential_metadata.v1"
    assert metadata["active_key_id"] == "active-key"
    assert "unknown" not in metadata

    json_path = Path(write_json_report(report, "containment-session", tmp_path))
    stix_path = Path(write_stix_bundle(report, session, tmp_path))
    markdown_path = Path(write_markdown_report(report, session, tmp_path))
    bundle = build_stix_bundle(report, session)

    assert validate_stix_bundle_document(bundle) == []
    rendered = "\n".join(
        (
            json_path.read_text(encoding="utf-8"),
            stix_path.read_text(encoding="utf-8"),
            markdown_path.read_text(encoding="utf-8"),
            _encoded(bundle),
        )
    )
    assert SECRET not in rendered
    assert DIGEST not in rendered
    for path in (json_path, stix_path, markdown_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_disabled_artifacts_do_not_inspect_unused_session_payload(
    tmp_path: Path,
) -> None:
    class UnsupportedSessionValue:
        pass

    returned = attach_report_artifacts(
        {"summary": f"password={SECRET}"},
        {"unused": UnsupportedSessionValue()},
        _config(tmp_path / "disabled", enabled=False),
    )
    assert returned["summary"] == f"password={REDACTION_MARKER}"
    assert not (tmp_path / "disabled").exists()


def test_artifact_redaction_failure_precedes_filesystem_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, session = _inputs()
    reports_dir = tmp_path / "must-not-exist"

    def fail_redaction(_value):
        raise RuntimeError(f"Authorization: Bearer {SECRET}")

    monkeypatch.setattr(artifact_module, "redact_for_artifact", fail_redaction)
    with pytest.raises(ValueError, match="report redaction failed") as error:
        attach_report_artifacts(
            report,
            session,
            _config(reports_dir, enabled=True),
        )

    assert SECRET not in str(error.value)
    assert not reports_dir.exists()


def test_blank_reports_directory_fails_without_changing_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, session = _inputs()
    monkeypatch.chdir(tmp_path)
    original_mode = stat.S_IMODE(tmp_path.stat().st_mode)
    config = _config(tmp_path / "unused", enabled=True)
    config.reports_dir = "   "

    with pytest.raises(ValueError, match="reports directory preparation failed"):
        attach_report_artifacts(report, session, config)

    assert stat.S_IMODE(tmp_path.stat().st_mode) == original_mode
    assert list(tmp_path.iterdir()) == []


def test_reports_directory_rejects_root_cwd_symlink_and_broad_modes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, session = _inputs()
    monkeypatch.chdir(tmp_path)
    targets = [Path("/"), tmp_path]
    broad = tmp_path / "broad"
    broad.mkdir(mode=0o755)
    targets.append(broad)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    symlink = tmp_path / "reports-link"
    symlink.symlink_to(private, target_is_directory=True)
    targets.append(symlink)

    root_mode = stat.S_IMODE(Path("/").stat().st_mode)
    for target in targets:
        config = _config(target, enabled=True)
        with pytest.raises(ValueError, match="reports directory preparation failed"):
            attach_report_artifacts(report, session, config)

    assert stat.S_IMODE(Path("/").stat().st_mode) == root_mode
    assert stat.S_IMODE(broad.stat().st_mode) == 0o755


def test_reports_directory_rejects_symlinked_ancestor_without_writing(
    tmp_path: Path,
) -> None:
    report, session = _inputs()
    actual_parent = tmp_path / "actual-parent"
    actual_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(actual_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="reports directory preparation failed"):
        attach_report_artifacts(
            report,
            session,
            _config(linked_parent / "reports", enabled=True),
        )

    assert not (actual_parent / "reports").exists()


def test_artifact_writer_errors_and_paths_are_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, session = _inputs()
    reports_parent = tmp_path / f"password={SECRET}"
    reports_parent.mkdir(mode=0o700)
    reports_dir = reports_parent / "reports"

    def fail_writer(*_args, **_kwargs):
        raise RuntimeError(f"Authorization: Bearer {SECRET}")

    monkeypatch.setattr(artifact_module, "write_json_report", fail_writer)
    returned = attach_report_artifacts(
        report,
        session,
        _config(reports_dir, enabled=True),
    )

    encoded = _encoded(returned)
    assert SECRET not in encoded
    assert returned["artifacts"]["json_error"] == "RuntimeError: operation_failed"
    assert stat.S_IMODE(reports_dir.stat().st_mode) == 0o700


def test_exception_boundaries_never_render_unlabelled_attacker_text() -> None:
    exception = RuntimeError(SECRET)
    helpers = (
        analysis_worker_module._safe_exception_text,
        artifact_module._safe_artifact_error,
        session_monitor_module._safe_exception_text,
    )

    for helper in helpers:
        assert helper(exception) == "RuntimeError: operation_failed"

    rendered = analysis_worker_module._safe_log_json(
        {"service": "analysis_worker", "error": SECRET}
    )
    baseline = analysis_worker_module.deterministic_baseline_report(
        {"session_id": "safe-error-boundary", "commands": [], "raw_events": []},
        SECRET,
    )

    assert SECRET not in rendered
    assert json.loads(rendered)["error"] == "operation_failed"
    assert baseline["schema_version"] == "session_assessment.v5"
    assert baseline["status"] == "observation_only_abstention"
    assert baseline["non_authoritative_context"]["analysis_processing"]["error"] == (
        "operation_failed"
    )


def test_artifact_write_fails_when_configured_directory_identity_changes(
    tmp_path: Path,
) -> None:
    report, _session = _inputs()
    reports_dir = tmp_path / "reports"
    held_dir = tmp_path / "held-reports"
    attacker_dir = tmp_path / "attacker-reports"
    attacker_dir.mkdir(mode=0o700)

    with artifact_module._prepare_reports_directory(reports_dir) as directory:
        reports_dir.rename(held_dir)
        reports_dir.symlink_to(attacker_dir, target_is_directory=True)
        with pytest.raises(ValueError, match="reports directory identity changed"):
            write_json_report(
                report,
                "fd-bound-session",
                directory,
            )

    assert list(held_dir.iterdir()) == []
    assert list(attacker_dir.iterdir()) == []
    reports_dir.unlink()
    held_dir.rename(reports_dir)


def test_artifact_commit_fails_closed_on_mid_write_directory_replacement(
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "reports"
    held_dir = tmp_path / "held-reports"
    attacker_dir = tmp_path / "attacker-reports"
    attacker_dir.mkdir(mode=0o700)

    with artifact_module._prepare_reports_directory(reports_dir) as directory:
        with pytest.raises(ValueError, match="reports directory identity changed"):
            with artifact_module._private_artifact_path(
                directory,
                "mid-write.json",
            ) as temporary_path:
                temporary_path.write_text("{}", encoding="utf-8")
                reports_dir.rename(held_dir)
                reports_dir.symlink_to(attacker_dir, target_is_directory=True)

    assert list(held_dir.iterdir()) == []
    assert list(attacker_dir.iterdir()) == []
    reports_dir.unlink()
    held_dir.rename(reports_dir)


def test_artifact_attachment_rechecks_identity_before_persisting_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, session = _inputs()
    reports_dir = tmp_path / "reports"
    held_dir = tmp_path / "held-reports"
    attacker_dir = tmp_path / "attacker-reports"
    attacker_dir.mkdir(mode=0o700)
    original_writer = artifact_module.write_json_report

    def replace_after_write(*args, **kwargs):
        returned_path = original_writer(*args, **kwargs)
        reports_dir.rename(held_dir)
        reports_dir.symlink_to(attacker_dir, target_is_directory=True)
        return returned_path

    monkeypatch.setattr(
        artifact_module,
        "write_json_report",
        replace_after_write,
    )
    with pytest.raises(ValueError, match="reports directory identity changed"):
        attach_report_artifacts(
            report,
            session,
            _config(reports_dir, enabled=True),
        )

    assert len(list(held_dir.glob("*_report.json"))) == 1
    assert list(attacker_dir.iterdir()) == []
    reports_dir.unlink()
    held_dir.rename(reports_dir)


def test_artifact_versions_are_retry_stable_and_preserve_history(
    tmp_path: Path,
) -> None:
    report, session = _inputs()
    report["confidence"] = "first"
    config = _config(tmp_path / "reports", enabled=True)

    first = attach_report_artifacts(report, session, config)
    retry = attach_report_artifacts(report, session, config)
    revised_report = copy.deepcopy(report)
    revised_report["confidence"] = "revised"
    revised = attach_report_artifacts(revised_report, session, config)

    first_path = Path(first["artifacts"]["json"])
    retry_path = Path(retry["artifacts"]["json"])
    revised_path = Path(revised["artifacts"]["json"])
    assert first_path == retry_path
    assert revised_path != first_path
    assert first_path.exists()
    assert revised_path.exists()
    assert json.loads(first_path.read_text(encoding="utf-8"))["confidence"] == "first"
    assert json.loads(revised_path.read_text(encoding="utf-8"))["confidence"] == "revised"
    assert len(list((tmp_path / "reports").glob("*_report.json"))) == 2


def test_missing_pdf_renderer_is_recorded_as_markdown_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, session = _inputs()
    config = _config(tmp_path / "reports", enabled=True)
    config.enable_pdf_export = True
    original_import = builtins.__import__

    def without_reportlab(name, *args, **kwargs):
        if name == "reportlab" or name.startswith("reportlab."):
            raise ImportError("renderer unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_reportlab)
    returned = attach_report_artifacts(report, session, config)

    artifacts = returned["artifacts"]
    assert "pdf" not in artifacts
    fallback = Path(artifacts["pdf_fallback_markdown"])
    assert fallback.suffix == ".md"
    assert fallback.exists()
    assert SECRET not in fallback.read_text(encoding="utf-8")


def test_worker_json_and_replayer_path_diagnostics_are_redacted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rendered = analysis_worker_module._safe_log_json(
        {
            "service": "analysis_worker",
            "job_id": f"password={SECRET}",
            "error": f"Authorization: Bearer {SECRET}",
        }
    )
    CowrieLogReplayer(str(tmp_path / f"password={SECRET}"))
    output = capsys.readouterr().out

    assert SECRET not in rendered
    assert SECRET not in output
    assert REDACTION_MARKER in rendered
    assert REDACTION_MARKER in output
