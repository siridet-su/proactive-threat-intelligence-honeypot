"""Production report artifacts: JSON, STIX 2.1, and PDF/Markdown fallback."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from production.utils.config import ProductionConfig
from production.utils.sensitive_data import (
    redact_exception_for_log,
    redact_for_artifact,
)
from production.utils.serialization import stable_id, stable_json
from production.reporting.response_guidance_v3 import validate_response_guidance_v3
from production.reporting.response_guidance_v4 import validate_response_guidance_v4
from production.reporting.session_assessment_v6 import (
    trusted_behavioral_findings_for_presentation,
    validate_session_assessment,
)
from production.reporting.artifact_privacy import sanitize_artifact_boundary


TI_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "my-ti-pipeline.local")


class _PDFExportUnavailable(RuntimeError):
    """Raised when the optional PDF renderer is not installed."""


class _ReportsDirectoryIdentityChanged(ValueError):
    """Raised when the configured path no longer names the trusted directory."""


def _safe_artifact_mapping(value: Any, label: str) -> Dict[str, Any]:
    """Return a redacted mapping or fail without exposing the input."""

    if (
        label == "report"
        and isinstance(value, dict)
        and value.get("schema_version") in {
            "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
        }
    ):
        # V4 has already been redacted before its evidence digest and content
        # IDs are computed. Re-redacting at each consumer can alter an
        # otherwise valid canonical snapshot and invalidate its guidance hash.
        validate_session_assessment(value, raise_on_error=True)
        # Canonical evidence and its content IDs are already safe.  The
        # non-authoritative compatibility/audit context is still an artifact
        # input and must pass the shared command-text boundary sanitizer.
        return sanitize_artifact_boundary(value)
    try:
        redacted = redact_for_artifact(value)
    except Exception:
        raise ValueError(f"{label} redaction failed") from None
    redacted = sanitize_artifact_boundary(redacted)
    if not isinstance(redacted, dict):
        raise TypeError(f"{label} must redact to an object")
    return redacted


def _canonical_behavioral_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    if report.get("schema_version") not in {
        "session_assessment.v4",
        "session_assessment.v5", "session_assessment.v6",
    }:
        return []
    return trusted_behavioral_findings_for_presentation(
        report,
        raise_on_error=True,
    )


def _safe_artifact_text(value: Any, label: str) -> str:
    try:
        redacted = redact_for_artifact(str(value))
    except Exception:
        raise ValueError(f"{label} redaction failed") from None
    if not isinstance(redacted, str):
        raise TypeError(f"{label} must redact to text")
    return redacted


def _safe_artifact_error(exc: BaseException) -> str:
    return redact_exception_for_log(exc)


@dataclass(frozen=True)
class _ReportsDirectory:
    path: Path
    descriptor: int


def _directory_open_flags() -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _open_reports_directory(
    configured_path: Any,
    *,
    create_leaf: bool,
) -> _ReportsDirectory:
    """Open a private directory by component and keep the trusted fd alive."""

    directory_descriptor = -1
    try:
        configured = str(configured_path or "").strip()
        if not configured:
            raise ValueError
        output_dir = Path(os.path.abspath(configured))
        working_directory = Path(os.path.abspath(os.getcwd()))
        if output_dir == Path("/") or output_dir == working_directory:
            raise ValueError
        components = output_dir.parts[1:]
        if not components:
            raise ValueError
        flags = _directory_open_flags()
        directory_descriptor = os.open(os.sep, flags)
        for index, component in enumerate(components):
            is_leaf = index == len(components) - 1
            try:
                next_descriptor = os.open(
                    component,
                    flags,
                    dir_fd=directory_descriptor,
                )
            except FileNotFoundError:
                if not (create_leaf and is_leaf):
                    raise
                os.mkdir(component, mode=0o700, dir_fd=directory_descriptor)
                next_descriptor = os.open(
                    component,
                    flags,
                    dir_fd=directory_descriptor,
                )
                os.fchmod(next_descriptor, 0o700)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        metadata = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise PermissionError
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PermissionError
        return _ReportsDirectory(output_dir, directory_descriptor)
    except Exception:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        raise ValueError("reports directory preparation failed") from None


def _assert_reports_directory_identity(directory: _ReportsDirectory) -> None:
    """Verify that the configured path still resolves to the held directory."""

    reopened: Optional[_ReportsDirectory] = None
    try:
        reopened = _open_reports_directory(directory.path, create_leaf=False)
        trusted_metadata = os.fstat(directory.descriptor)
        current_metadata = os.fstat(reopened.descriptor)
        if (
            trusted_metadata.st_dev,
            trusted_metadata.st_ino,
        ) != (
            current_metadata.st_dev,
            current_metadata.st_ino,
        ):
            raise _ReportsDirectoryIdentityChanged
    except _ReportsDirectoryIdentityChanged:
        raise _ReportsDirectoryIdentityChanged(
            "reports directory identity changed"
        ) from None
    except Exception:
        raise _ReportsDirectoryIdentityChanged(
            "reports directory identity changed"
        ) from None
    finally:
        if reopened is not None:
            os.close(reopened.descriptor)


@contextmanager
def _prepare_reports_directory(
    configured_path: Any,
) -> Iterator[_ReportsDirectory]:
    directory = _open_reports_directory(configured_path, create_leaf=True)
    try:
        yield directory
    finally:
        os.close(directory.descriptor)


@contextmanager
def _reports_directory_handle(
    output_dir: Any,
) -> Iterator[_ReportsDirectory]:
    if isinstance(output_dir, _ReportsDirectory):
        yield output_dir
        return
    directory = _open_reports_directory(output_dir, create_leaf=False)
    try:
        yield directory
    finally:
        os.close(directory.descriptor)


def _safe_name(value: Any) -> str:
    text = str(value)
    return "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in text
    )[:120] or "unknown"


_ARTIFACT_VERSION_PATTERN = re.compile(r"^artifact_[0-9a-f]{32}$")
_INTEGRITY_MANIFEST_PATTERN = re.compile(
    r"^artifact_[0-9a-f]{32}_artifact_manifest_([0-9a-f]{64})\.json$"
)


def _artifact_version_id(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
) -> str:
    """Derive a retry-stable version before artifact paths are attached."""

    if report.get("schema_version") in {
        "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
    }:
        provenance = report.get("provenance") or {}
        evidence_sha256 = str(provenance.get("evidence_sha256") or "").strip()
        assessment_id = str(report.get("assessment_id") or "").strip()
        if assessment_id and evidence_sha256:
            return stable_id(
                "artifact",
                {
                    "contract": "canonical_report_artifacts.v2",
                    "schema_version": report.get("schema_version"),
                    "assessment_id": assessment_id,
                    "evidence_sha256": evidence_sha256,
                    "session_id": (
                        session_payload.get("session_id")
                        or report.get("session_id")
                        or "unknown"
                    ),
                },
            )

    report_basis = dict(report)
    report_basis.pop("artifacts", None)
    session_basis = dict(session_payload)
    session_basis.pop("artifacts", None)
    return stable_id(
        "artifact",
        {
            "report": report_basis,
            "session": session_basis,
        },
    )


def _resolve_artifact_version(
    artifact_version: str,
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
) -> str:
    if artifact_version:
        if not _ARTIFACT_VERSION_PATTERN.fullmatch(artifact_version):
            raise ValueError("artifact version is invalid")
        return artifact_version
    return _artifact_version_id(report, session_payload)


def _verified_artifact_path(
    directory: _ReportsDirectory,
    filename: str,
) -> str:
    _assert_reports_directory_identity(directory)
    return str(directory.path / filename)


@contextmanager
def _private_artifact_path(
    directory: _ReportsDirectory,
    filename: str,
) -> Iterator[Path]:
    """Build and replace an artifact relative to a trusted directory fd."""

    if Path(filename).name != filename:
        raise ValueError("artifact filename must not contain path components")
    temporary_name = ""
    file_descriptor = -1
    create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    create_flags |= getattr(os, "O_CLOEXEC", 0)
    create_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        _assert_reports_directory_identity(directory)
        for _attempt in range(10):
            temporary_name = f".{filename}.{uuid.uuid4().hex}.tmp"
            try:
                file_descriptor = os.open(
                    temporary_name,
                    create_flags,
                    0o600,
                    dir_fd=directory.descriptor,
                )
                break
            except FileExistsError:
                continue
        if file_descriptor < 0:
            raise FileExistsError("could not allocate private artifact temporary file")
        os.fchmod(file_descriptor, 0o600)
        os.close(file_descriptor)
        file_descriptor = -1
        temporary_path = (
            Path("/proc/self/fd")
            / str(directory.descriptor)
            / temporary_name
        )
        yield temporary_path
        _assert_reports_directory_identity(directory)
        verify_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        verify_flags |= getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(
            temporary_name,
            verify_flags,
            dir_fd=directory.descriptor,
        )
        try:
            os.fsync(file_descriptor)
            os.fchmod(file_descriptor, 0o600)
        finally:
            os.close(file_descriptor)
            file_descriptor = -1
        os.replace(
            temporary_name,
            filename,
            src_dir_fd=directory.descriptor,
            dst_dir_fd=directory.descriptor,
        )
        os.fsync(directory.descriptor)
        _assert_reports_directory_identity(directory)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=directory.descriptor)
            except FileNotFoundError:
                pass


def _stix_timestamp(
    value: str,
    fallback: str = "1970-01-01T00:00:00Z",
) -> str:
    if not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    return fallback


def _artifact_timestamp(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
) -> str:
    """Choose a source-bound timestamp without consulting the wall clock."""

    if report.get("schema_version") in {
        "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
    }:
        evidence = report.get("canonical_evidence") or {}
        source_timestamps = [
            _stix_timestamp(str(item.get("timestamp") or ""), fallback="")
            for collection in (
                "observations",
                "transfer_observations",
                "direct_cowrie_events",
                "trusted_attck_candidates",
            )
            for item in evidence.get(collection) or []
            if isinstance(item, dict) and item.get("timestamp")
        ]
        source_timestamps = [
            value for value in source_timestamps if value
        ]
        if source_timestamps:
            return max(source_timestamps)
        for value in (
            session_payload.get("end_time"),
            session_payload.get("updated_at"),
            session_payload.get("start_time"),
        ):
            if str(value or "").strip():
                return _stix_timestamp(str(value))
        return "1970-01-01T00:00:00Z"

    for value in (
        report.get("generated_at"),
        session_payload.get("end_time"),
        session_payload.get("updated_at"),
        session_payload.get("start_time"),
    ):
        if str(value or "").strip():
            return _stix_timestamp(str(value))
    return "1970-01-01T00:00:00Z"


def _stix_source_report_sha256(report: Dict[str, Any]) -> str:
    """Hash the retry-stable report projection represented in STIX."""

    basis = deepcopy(report)
    if basis.get("schema_version") in {
        "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
    }:
        for key in (
            "artifacts",
            "generated_at",
            "non_authoritative_context",
        ):
            basis.pop(key, None)
        guidance = basis.get("response_guidance_v3")
        if isinstance(guidance, dict):
            guidance = deepcopy(guidance)
            guidance.pop("generated_at", None)
            guidance.pop("non_authoritative_context", None)
            basis["response_guidance_v3"] = guidance
        guidance_v4 = basis.get("response_guidance_v4")
        if isinstance(guidance_v4, dict):
            guidance_v4 = deepcopy(guidance_v4)
            guidance_v4.pop("generated_at", None)
            basis["response_guidance_v4"] = guidance_v4
    return hashlib.sha256(
        stable_json(basis).encode("utf-8")
    ).hexdigest()


def _ioc_items(ioc_summary: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for key in ("ips", "urls", "domains", "hashes", "ports"):
        for item in ioc_summary.get(key, []) or []:
            yield item


def _layer_items(report: Dict[str, Any], layer_name: str) -> List[Dict[str, Any]]:
    layers = report.get("threat_evidence_layers") or {}
    layer = layers.get(layer_name) if isinstance(layers, dict) else {}
    items = layer.get("items") if isinstance(layer, dict) else []
    return [item for item in items or [] if isinstance(item, dict)]


def _evidence_layer_summary_lines(report: Dict[str, Any]) -> List[str]:
    layers = report.get("threat_evidence_layers") or {}
    if not isinstance(layers, dict):
        return []
    summary = layers.get("summary") or {}
    if not isinstance(summary, dict):
        summary = {}
    return [
        f"Direct command TTPs: {summary.get('direct_command_ttp_count', 0)}",
        f"Session-correlated TTPs: {summary.get('session_correlated_ttp_count', 0)}",
        f"Prediction-only hypotheses: {summary.get('prediction_hypothesis_count', 0)}",
    ]


def _trusted_ttp_ids(report: Dict[str, Any], session_payload: Dict[str, Any]) -> List[str]:
    if report.get("schema_version") in {
        "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
    }:
        evidence = report.get("canonical_evidence") or {}
        return list(dict.fromkeys(
            str(item.get("technique_id") or "").strip()
            for item in evidence.get("trusted_attck_candidates") or []
            if isinstance(item, dict) and str(item.get("technique_id") or "").strip()
        ))
    observed = report.get("observed_behavior") or {}
    candidates = observed.get("trusted_attck_candidates") if isinstance(observed, dict) else []
    if report.get("schema_version") == "threat_hypothesis.v2":
        return list(dict.fromkeys(
            str(item.get("technique_id") or "").strip()
            for item in candidates or []
            if isinstance(item, dict) and str(item.get("technique_id") or "").strip()
        ))
    return list(dict.fromkeys(
        str(value).strip()
        for value in (session_payload.get("ttps", []) or report.get("ttps", []) or [])
        if str(value).strip()
    ))


def write_json_report(
    report: Dict[str, Any],
    session_id: str,
    output_dir: Path,
    *,
    artifact_version: str = "",
) -> str:
    safe_report = _safe_artifact_mapping(report, "report")
    safe_session_id = _safe_artifact_text(session_id, "session_id")
    version = _resolve_artifact_version(
        artifact_version,
        safe_report,
        {"session_id": safe_session_id},
    )
    filename = f"{_safe_name(safe_session_id)}_{version}_report.json"
    rendered = json.dumps(
        safe_report,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
    with _reports_directory_handle(output_dir) as directory:
        with _private_artifact_path(directory, filename) as temporary_path:
            temporary_path.write_text(rendered, encoding="utf-8")
        return _verified_artifact_path(directory, filename)


def _stix_id(object_type: str, key: str) -> str:
    return f"{object_type}--{uuid.uuid5(TI_NAMESPACE, object_type + ':' + key)}"


def _append_stix_object(
    objects: List[Dict[str, Any]],
    report_obj: Dict[str, Any],
    obj: Dict[str, Any],
    seen_ids: set[str],
    *,
    reference_from_report: bool = True,
) -> None:
    object_id = str(obj.get("id") or "")
    if not object_id or object_id in seen_ids:
        return
    seen_ids.add(object_id)
    objects.append(obj)
    if reference_from_report and object_id not in report_obj["object_refs"]:
        report_obj["object_refs"].append(object_id)


def _trusted_recommendation_actions(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    guidance = report.get("response_guidance_v4") or report.get("response_guidance_v3")
    if not isinstance(guidance, dict):
        return []
    if guidance.get("schema_version") == "response_guidance.v4":
        graph = (report.get("canonical_evidence") or {}).get("semantic_graph") or {}
        errors = validate_response_guidance_v4(guidance, parent_graph=graph)
    elif guidance.get("schema_version") == "response_guidance.v3":
        errors = validate_response_guidance_v3(guidance)
    else:
        return []
    if errors:
        return []
    return [
        item for item in guidance.get("advisory_actions") or []
        if isinstance(item, dict)
        and item.get("requires_manual_approval") is True
        and item.get("safe_to_auto_execute") is False
        and item.get("execution_integration") == "not_implemented"
    ]


def _external_references(raw_refs: Any) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    for ref in raw_refs or []:
        if not isinstance(ref, dict):
            continue
        name = str(ref.get("name") or ref.get("source_name") or ref.get("title") or "reference").strip()
        url = str(ref.get("url") or "").strip()
        external_id = str(ref.get("external_id") or ref.get("id") or "").strip()
        out = {"source_name": name}
        if url:
            out["url"] = url
        if external_id:
            out["external_id"] = external_id
        refs.append(out)
    return refs


def _extract_ttp_ids_from_action(action: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    for key in ("ttp", "ttps", "technique", "techniques", "mitre_techniques"):
        raw = action.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
        elif raw:
            values.append(str(raw))
    for ref in action.get("references") or []:
        if not isinstance(ref, dict):
            continue
        values.extend(str(ref.get(key) or "") for key in ("external_id", "id", "name", "url"))
    values.extend(str(item) for item in action.get("evidence") or [])
    joined = "\n".join(values)
    ttps = []
    for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", joined, flags=re.IGNORECASE):
        main = match.upper().split(".", 1)[0]
        if main not in ttps:
            ttps.append(main)
    return ttps


def _sco_for_ioc(ioc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ioc_type = str(ioc.get("type") or "").strip().lower()
    value = str(ioc.get("value") or "").strip()
    if not value:
        return None
    if ioc_type in {"ipv4", "ipv6"}:
        object_type = "ipv6-addr" if ioc_type == "ipv6" else "ipv4-addr"
        return {
            "type": object_type,
            "spec_version": "2.1",
            "id": _stix_id(object_type, value),
            "value": value,
        }
    if ioc_type == "domain":
        return {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": _stix_id("domain-name", value),
            "value": value,
        }
    if ioc_type == "url":
        return {
            "type": "url",
            "spec_version": "2.1",
            "id": _stix_id("url", value),
            "value": value,
        }
    if ioc_type in {"sha256", "sha1", "md5"}:
        return {
            "type": "file",
            "spec_version": "2.1",
            "id": _stix_id("file", ioc_type + ":" + value),
            "hashes": {ioc_type.upper(): value},
        }
    return None


def _build_identity(now: str, session_payload: Dict[str, Any]) -> Dict[str, Any]:
    sensor = str(session_payload.get("sensor") or session_payload.get("sensor_id") or "honeypot").strip()
    identity_id = _stix_id("identity", "honeypot-sensor:" + sensor)
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": f"Honeypot sensor {sensor}",
        "identity_class": "system",
    }


def build_stix_bundle(report: Dict[str, Any], session_payload: Dict[str, Any]) -> Dict[str, Any]:
    report = _safe_artifact_mapping(report, "report")
    session_payload = _safe_artifact_mapping(session_payload, "session")
    now = _artifact_timestamp(report, session_payload)
    session_id = session_payload.get("session_id", "unknown")
    artifact_version = _artifact_version_id(report, session_payload)
    objects: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    report_obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": _stix_id("report", artifact_version),
        "created": now,
        "modified": now,
        "name": f"Automated Threat Intelligence Report - {session_id}",
        "published": now,
        "report_types": ["threat-actor-activity"],
        "object_refs": [],
        "x_honeypot_artifact_version": artifact_version,
        "x_honeypot_source_report_sha256": (
            _stix_source_report_sha256(report)
        ),
    }

    if report.get("schema_version") in {
        "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
    }:
        provenance = report.get("provenance") or {}
        for finding in _canonical_behavioral_findings(report):
            if not isinstance(finding, dict):
                continue
            finding_id = _stix_id(
                "x-honeypot-behavioral-finding",
                str(finding.get("finding_id") or stable_json(finding)),
            )
            _append_stix_object(objects, report_obj, {
                "type": "x-honeypot-behavioral-finding",
                "spec_version": "2.1",
                "id": finding_id,
                "created": now,
                "modified": now,
                "x_honeypot_finding_id": finding.get("finding_id") or "",
                "x_honeypot_finding_type": finding.get("finding_type") or "",
                "x_honeypot_statement": finding.get("statement") or "",
                "x_honeypot_status": finding.get("status") or "",
                "x_honeypot_evidence_refs": finding.get("evidence_refs") or [],
                "x_honeypot_relationship_refs": finding.get("relationship_refs") or [],
                "x_honeypot_evidence_sha256": provenance.get("evidence_sha256") or "",
            }, seen_ids)
        for hypothesis_set in report.get("hypothesis_sets") or []:
            if not isinstance(hypothesis_set, dict):
                continue
            set_id = _stix_id(
                "x-honeypot-hypothesis-set",
                str(hypothesis_set.get("hypothesis_set_id") or stable_json(hypothesis_set)),
            )
            _append_stix_object(objects, report_obj, {
                "type": "x-honeypot-hypothesis-set",
                "spec_version": "2.1",
                "id": set_id,
                "created": now,
                "modified": now,
                "x_honeypot_hypothesis_set_id": hypothesis_set.get("hypothesis_set_id") or "",
                "x_honeypot_question": hypothesis_set.get("question") or "",
                "x_honeypot_hypotheses": hypothesis_set.get("hypotheses") or [],
                "x_honeypot_evidence_sha256": provenance.get("evidence_sha256") or "",
            }, seen_ids)

    ttp_obj_map = {}
    for tid in sorted(set(_trusted_ttp_ids(report, session_payload))):
        ap_id = f"attack-pattern--{uuid.uuid5(TI_NAMESPACE, 'attack-pattern:' + tid)}"
        attack_pattern = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": now,
            "modified": now,
            "name": tid,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tid,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
            }],
        }
        ttp_obj_map[tid] = attack_pattern
        _append_stix_object(objects, report_obj, attack_pattern, seen_ids)

    legacy_actor_matches = [] if report.get("schema_version") == "threat_hypothesis.v2" else report.get("actor_matches", []) or []
    for actor in legacy_actor_matches:
        actor_name = actor.get("actor", "Unknown")
        actor_id = f"threat-actor--{uuid.uuid5(TI_NAMESPACE, 'actor:' + actor_name)}"
        actor_obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": now,
            "modified": now,
            "name": actor_name,
            "confidence": int(actor.get("score", 0)),
            "labels": ["apt"],
            "description": f"Matched: {', '.join(actor.get('matched_ttps', []))}",
            "x_honeypot_attribution_warning": "TTP overlap only; not confirmed named-actor attribution.",
        }
        _append_stix_object(objects, report_obj, actor_obj, seen_ids)
        for tid in actor.get("matched_ttps", []):
            if tid in ttp_obj_map:
                relationship_id = f"relationship--{uuid.uuid5(TI_NAMESPACE, 'rel:' + actor_id + ':' + ttp_obj_map[tid]['id'])}"
                _append_stix_object(objects, report_obj, {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": relationship_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "uses",
                    "source_ref": actor_id,
                    "target_ref": ttp_obj_map[tid]["id"],
                }, seen_ids, reference_from_report=False)

    ioc_summary = report.get("ioc_summary") or session_payload.get("ioc_summary") or {}
    indicator_ids: Dict[str, str] = {}
    sco_refs: List[str] = []
    for ioc in _ioc_items(ioc_summary):
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        if not value:
            continue
        if ioc_type in {"ipv4", "ipv6"}:
            pattern = f"[ipv4-addr:value = '{value}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{value}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{value}']"
        elif ioc_type in {"sha256", "sha1", "md5"}:
            pattern = f"[file:hashes.'{ioc_type.upper()}' = '{value}']"
        else:
            continue
        indicator_id = f"indicator--{uuid.uuid5(TI_NAMESPACE, 'indicator:' + ioc_type + ':' + value)}"
        indicator_ids[f"{ioc_type}:{value}"] = indicator_id
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": value,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _stix_timestamp(ioc.get("first_seen", "")),
            "indicator_types": ["malicious-activity"],
        }
        _append_stix_object(objects, report_obj, indicator, seen_ids)
        sco = _sco_for_ioc(ioc)
        if sco:
            _append_stix_object(objects, report_obj, sco, seen_ids, reference_from_report=False)
            if sco["id"] not in sco_refs:
                sco_refs.append(sco["id"])

    src_ip = str(session_payload.get("src_ip") or "").strip()
    if src_ip and src_ip not in {"unknown", "-"}:
        src_ioc = {"type": "ipv6" if ":" in src_ip else "ipv4", "value": src_ip}
        sco = _sco_for_ioc(src_ioc)
        if sco:
            _append_stix_object(objects, report_obj, sco, seen_ids, reference_from_report=False)
            if sco["id"] not in sco_refs:
                sco_refs.append(sco["id"])

    identity = _build_identity(now, session_payload)
    has_sightings = bool(indicator_ids)
    has_campaign = bool((session_payload.get("campaign_summary") or report.get("campaign_context") or {}).get("campaign_id"))
    if has_sightings or has_campaign:
        _append_stix_object(objects, report_obj, identity, seen_ids)

    commands = [str(command) for command in session_payload.get("commands") or [] if str(command).strip()]
    if commands:
        command_sequence = {
            "type": "x-honeypot-command-sequence",
            "spec_version": "2.1",
            "id": _stix_id("x-honeypot-command-sequence", "session-commands:" + str(session_id)),
            "created": now,
            "modified": now,
            "x_honeypot_session_id": session_id,
            "x_honeypot_commands": commands[:50],
            "x_honeypot_command_count": len(commands),
        }
        _append_stix_object(objects, report_obj, command_sequence, seen_ids, reference_from_report=False)
        if command_sequence["id"] not in sco_refs:
            sco_refs.append(command_sequence["id"])
    if sco_refs or commands:
        observed_id = _stix_id("observed-data", "session-observed-data:" + str(session_id))
        first_observed = _stix_timestamp(str(session_payload.get("start_time") or report.get("created_at") or ""))
        last_observed = _stix_timestamp(str(session_payload.get("end_time") or session_payload.get("updated_at") or report.get("created_at") or ""))
        observed = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now,
            "modified": now,
            "first_observed": first_observed,
            "last_observed": last_observed,
            "number_observed": 1,
            "object_refs": sco_refs,
            "x_honeypot_session_id": session_id,
            "x_honeypot_commands": commands[:50],
            "x_honeypot_event_count": len(session_payload.get("raw_events") or []),
        }
        _append_stix_object(objects, report_obj, observed, seen_ids)

    for marker, indicator_id in sorted(indicator_ids.items()):
        sighting_id = _stix_id("sighting", "session-sighting:" + str(session_id) + ":" + marker)
        sighting = {
            "type": "sighting",
            "spec_version": "2.1",
            "id": sighting_id,
            "created": now,
            "modified": now,
            "sighting_of_ref": indicator_id,
            "where_sighted_refs": [identity["id"]],
            "count": 1,
            "first_seen": _stix_timestamp(str(session_payload.get("start_time") or "")),
            "last_seen": _stix_timestamp(str(session_payload.get("end_time") or session_payload.get("updated_at") or "")),
            "x_honeypot_session_id": session_id,
        }
        _append_stix_object(objects, report_obj, sighting, seen_ids)

    campaign_summary = session_payload.get("campaign_summary") or report.get("campaign_context") or {}
    if isinstance(campaign_summary, dict) and campaign_summary.get("campaign_id"):
        campaign_id_value = str(campaign_summary.get("campaign_id"))
        campaign_id = _stix_id("campaign", "honeypot-campaign:" + campaign_id_value)
        campaign = {
            "type": "campaign",
            "spec_version": "2.1",
            "id": campaign_id,
            "created": now,
            "modified": now,
            "name": f"Honeypot behavioral cluster {campaign_id_value}",
            "description": (
                "Local honeypot behavioral cluster based on observable and command-pattern "
                "similarity. This is not confirmed named-actor attribution."
            ),
            "first_seen": _stix_timestamp(str(campaign_summary.get("first_seen") or session_payload.get("start_time") or "")),
            "last_seen": _stix_timestamp(str(campaign_summary.get("last_seen") or session_payload.get("updated_at") or "")),
            "x_honeypot_campaign_id": campaign_id_value,
            "x_honeypot_matched_existing_campaign": bool(campaign_summary.get("matched_existing_campaign")),
            "x_honeypot_session_count": campaign_summary.get("campaign_session_count") or campaign_summary.get("session_count") or 0,
            "x_honeypot_max_confirmed_severity": campaign_summary.get("max_confirmed_severity") or "",
        }
        _append_stix_object(objects, report_obj, campaign, seen_ids)
        for tid, attack_pattern in ttp_obj_map.items():
            rel_id = _stix_id("relationship", "campaign-uses:" + campaign_id + ":" + attack_pattern["id"])
            _append_stix_object(objects, report_obj, {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "relationship_type": "uses",
                "source_ref": campaign_id,
                "target_ref": attack_pattern["id"],
            }, seen_ids, reference_from_report=False)

    for action in _trusted_recommendation_actions(report):
        guidance_authority = str(
            (
                report.get("response_guidance_v4")
                or report.get("response_guidance_v3")
                or {}
            ).get("authority")
            or ""
        )
        action_id_value = str(action.get("action_id") or action.get("rule_id") or action.get("description") or stable_json(action))
        coa_id = _stix_id("course-of-action", "policy-action:" + action_id_value)
        coa = {
            "type": "course-of-action",
            "spec_version": "2.1",
            "id": coa_id,
            "created": now,
            "modified": now,
            "name": str(action.get("description") or action_id_value),
            "description": str(action.get("rationale") or ""),
            "external_references": _external_references(action.get("references")),
            "x_honeypot_action_id": action.get("action_id") or "",
            "x_honeypot_rule_id": action.get("rule_id") or "",
            "x_honeypot_authority": guidance_authority,
            "x_honeypot_evidence_refs": action.get("evidence_refs") or [],
            "x_honeypot_evidence_scope": action.get("evidence_scope") or [],
            "x_honeypot_requires_manual_approval": True,
            "x_honeypot_safe_to_auto_execute": False,
        }
        _append_stix_object(objects, report_obj, coa, seen_ids)
        for tid in _extract_ttp_ids_from_action(action):
            attack_pattern = ttp_obj_map.get(tid)
            if not attack_pattern:
                continue
            rel_id = _stix_id("relationship", "coa-mitigates:" + coa_id + ":" + attack_pattern["id"])
            _append_stix_object(objects, report_obj, {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now,
                "modified": now,
                "relationship_type": "mitigates",
                "source_ref": coa_id,
                "target_ref": attack_pattern["id"],
            }, seen_ids, reference_from_report=False)

    summary_text = report.get("executive_summary") or report.get("summary") or ""
    if summary_text:
        note_id = _stix_id("note", f"{artifact_version}:{summary_text}")
        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": now,
            "modified": now,
            "abstract": "Threat Hypothesis",
            "content": summary_text,
            "object_refs": report_obj["object_refs"][:1] or [report_obj["id"]],
            "authors": ["Honeypot Threat Hypothesis Engine"],
        }
        _append_stix_object(objects, report_obj, note, seen_ids)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", artifact_version),
        "objects": [report_obj] + objects,
    }


def write_stix_bundle(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
    output_dir: Path,
    *,
    artifact_version: str = "",
) -> str:
    report = _safe_artifact_mapping(report, "report")
    session_payload = _safe_artifact_mapping(session_payload, "session")
    session_id = session_payload.get("session_id", report.get("session_id", "unknown"))
    version = _resolve_artifact_version(
        artifact_version,
        report,
        session_payload,
    )
    filename = f"{_safe_name(session_id)}_{version}_threat_bundle.json"
    rendered = json.dumps(
        build_stix_bundle(report, session_payload),
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )
    with _reports_directory_handle(output_dir) as directory:
        with _private_artifact_path(directory, filename) as temporary_path:
            temporary_path.write_text(rendered, encoding="utf-8")
        return _verified_artifact_path(directory, filename)


def write_markdown_report(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
    output_dir: Path,
    *,
    artifact_version: str = "",
) -> str:
    report = _safe_artifact_mapping(report, "report")
    session_payload = _safe_artifact_mapping(session_payload, "session")
    session_id = session_payload.get("session_id", report.get("session_id", "unknown"))
    version = _resolve_artifact_version(
        artifact_version,
        report,
        session_payload,
    )
    ioc_summary = report.get("ioc_summary") or session_payload.get("ioc_summary") or {}
    lines = [
        "# Threat Intelligence Report",
        "",
        f"Generated: {_artifact_timestamp(report, session_payload)}",
        f"Session: {session_id}",
        f"Source IP: {session_payload.get('src_ip', 'unknown')}",
        "",
        "## Summary",
        str(
            "Canonical behavioral findings and falsifiable alternatives are listed below."
            if report.get("schema_version") in {
                "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
            }
            else (report.get("presentation") or {}).get("summary")
            or report.get("executive_summary") or report.get("summary") or "No summary available."
        ),
        "",
        "## TTPs",
    ]
    for tid in _trusted_ttp_ids(report, session_payload):
        lines.append(f"- {tid}")
    if report.get("schema_version") in {
        "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
    }:
        canonical_findings = _canonical_behavioral_findings(report)
        lines.extend(["", "## Behavioral Findings"])
        for finding in canonical_findings:
            lines.append(
                f"- [{finding.get('status', '')}] {finding.get('statement', '')} "
                f"(finding `{finding.get('finding_id', '')}`; evidence: "
                f"{', '.join(finding.get('evidence_refs') or [])})"
            )
        if not canonical_findings:
            lines.append("- No policy-supported behavioral finding.")
        lines.extend(["", "## Falsifiable Hypothesis Alternatives"])
        for hypothesis_set in report.get("hypothesis_sets") or []:
            lines.append(f"- {hypothesis_set.get('question', '')} (`{hypothesis_set.get('hypothesis_set_id', '')}`)")
            for hypothesis in hypothesis_set.get("hypotheses") or []:
                lines.append(
                    f"  - {hypothesis.get('statement', '')} "
                    f"(`{hypothesis.get('hypothesis_id', '')}`)"
                )
        if not report.get("hypothesis_sets"):
            lines.append("- No evidence-bounded alternative set was warranted.")
        provenance = report.get("provenance") or {}
        lines.extend([
            "",
            "## Canonical Provenance",
            f"- Evidence SHA-256: {provenance.get('evidence_sha256', '')}",
            f"- Behavior policy SHA-256: {(provenance.get('behavior_policy') or {}).get('sha256', '')}",
            f"- Classification policy SHA-256: {(provenance.get('classification_policy') or {}).get('sha256', '')}",
            f"- Evaluator Git revision: {provenance.get('evaluator_git_revision', '')}",
        ])
    assessment = report.get("supported_assessment") or {}
    follow_on = report.get("follow_on_hypothesis") or {}
    if report.get("schema_version") == "threat_hypothesis.v2":
        lines.extend(["", "## Evidence-Grounded Assessment"])
        lines.append(str(assessment.get("behavior_summary") or "No trusted behavioral evidence."))
        objectives = assessment.get("possible_objectives") or []
        if objectives:
            for claim in objectives:
                lines.append(
                    f"- [{claim.get('evidence_status', 'insufficient_evidence')}] "
                    f"{claim.get('text', '')} (claim `{claim.get('claim_id', '')}`)"
                )
        else:
            lines.append("- No attacker objective inferred from the observed evidence.")
        lines.extend(["", "## Post-Session Follow-On Hypothesis"])
        if follow_on.get("abstained"):
            lines.append(f"- Abstained: {follow_on.get('abstention_reason', '')}")
        else:
            for claim in follow_on.get("claims") or []:
                lines.append(f"- [{claim.get('evidence_status', '')}] {claim.get('text', '')}")
    evidence_lines = _evidence_layer_summary_lines(report)
    if evidence_lines:
        lines.extend(["", "## Evidence Layers"])
        lines.append("Direct observations, session correlations, and predictions are separated to avoid mixing facts with hypotheses.")
        for line in evidence_lines:
            lines.append(f"- {line}")
        direct_items = _layer_items(report, "direct_command_ttps")
        if direct_items:
            lines.append("")
            lines.append("### Direct Command TTPs")
            for item in direct_items[:20]:
                confidence = item.get("confidence") or {}
                lines.append(
                    f"- {item.get('main_ttp', '')} | {item.get('tactic', '')} | "
                    f"sources={', '.join(item.get('sources') or [])} | "
                    f"avg_confidence={confidence.get('average', '-')}"
                )
        correlated_items = _layer_items(report, "session_correlated_ttps")
        if correlated_items:
            lines.append("")
            lines.append("### Session-Correlated TTPs")
            for item in correlated_items[:20]:
                lines.append(
                    f"- {item.get('main_ttp', '')} | {item.get('predicted_technique', {}).get('tactic', item.get('tactic', ''))} | "
                    f"source_type={item.get('source_type', '')} | confidence={item.get('confidence', '-')}"
                )
        prediction_items = _layer_items(report, "prediction_only_hypotheses")
        if prediction_items:
            lines.append("")
            lines.append("### Prediction-Only Hypotheses")
            for item in prediction_items[:10]:
                lines.append(
                    f"- {item.get('predicted_tactic', '')} | confidence={item.get('confidence', '-')} | "
                    f"source_types={', '.join(item.get('source_types') or [])}"
                )
    actions = _trusted_recommendation_actions(report)
    lines.extend(["", "## Policy-Approved Operator Actions"])
    if actions:
        for action in actions:
            lines.append(
                f"- P{action.get('policy_order', 50)} {action.get('description', '')} "
                f"(rule `{action.get('rule_id', '')}`; manual approval required)"
            )
            lines.append(f"  - Canonical evidence: {', '.join(action.get('evidence_refs') or [])}")
    else:
        lines.append("- No policy-approved operator action matched the available evidence.")
    lines.extend(["", "## IoCs"])
    for item in _ioc_items(ioc_summary):
        lines.append(f"- {item.get('type')}: {item.get('value')} ({item.get('confidence', 'unknown')})")
    filename = f"{_safe_name(session_id)}_{version}_threat_report.md"
    with _reports_directory_handle(output_dir) as directory:
        with _private_artifact_path(directory, filename) as temporary_path:
            temporary_path.write_text("\n".join(lines), encoding="utf-8")
        return _verified_artifact_path(directory, filename)


def write_pdf_report(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
    output_dir: Path,
    *,
    artifact_version: str = "",
) -> str:
    report = _safe_artifact_mapping(report, "report")
    session_payload = _safe_artifact_mapping(session_payload, "session")
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise _PDFExportUnavailable("PDF renderer is unavailable") from exc

    session_id = session_payload.get("session_id", report.get("session_id", "unknown"))
    version = _resolve_artifact_version(
        artifact_version,
        report,
        session_payload,
    )
    filename = f"{_safe_name(session_id)}_{version}_threat_report.pdf"
    styles = getSampleStyleSheet()
    title = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#C0392B"), spaceAfter=4)
    h2 = ParagraphStyle("HeadingCustom", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#2C3E50"), spaceBefore=14, spaceAfter=4)
    body = ParagraphStyle("BodyCustom", parent=styles["Normal"], fontSize=10, leading=15, spaceAfter=3)
    meta = ParagraphStyle("MetaCustom", parent=styles["Normal"], fontSize=8, textColor=colors.grey)
    story = [
        Paragraph("Threat Intelligence Report", title),
        Paragraph(
            f"Generated: {_artifact_timestamp(report, session_payload)}",
            meta,
        ),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#C0392B"), spaceAfter=12),
        Paragraph("Executive Summary", h2),
        Paragraph(
            escape(
                str(
                    "Canonical behavioral findings and falsifiable alternatives are listed below."
                    if report.get("schema_version") in {
                        "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
                    }
                    else (report.get("presentation") or {}).get("summary")
                    or report.get("executive_summary")
                    or report.get("summary")
                    or "No summary available."
                )
            ),
            body,
        ),
        Spacer(1, 8),
    ]

    if report.get("schema_version") in {
        "session_assessment.v4", "session_assessment.v5", "session_assessment.v6"
    }:
        canonical_findings = _canonical_behavioral_findings(report)
        story.append(Paragraph("Behavioral Findings", h2))
        if canonical_findings:
            for finding in canonical_findings:
                story.append(Paragraph(escape(
                    f"[{finding.get('status', '')}] {finding.get('statement', '')} "
                    f"(finding {finding.get('finding_id', '')}; evidence "
                    f"{', '.join(finding.get('evidence_refs') or [])})"
                ), body))
        else:
            story.append(Paragraph("No policy-supported behavioral finding.", body))
        story.append(Paragraph("Falsifiable Hypothesis Alternatives", h2))
        if report.get("hypothesis_sets"):
            for hypothesis_set in report.get("hypothesis_sets") or []:
                story.append(Paragraph(escape(str(hypothesis_set.get("question") or "")), body))
                for hypothesis in hypothesis_set.get("hypotheses") or []:
                    story.append(Paragraph(escape(
                        f"{hypothesis.get('statement', '')} ({hypothesis.get('hypothesis_id', '')})"
                    ), body))
        else:
            story.append(Paragraph("No evidence-bounded alternative set was warranted.", body))
        provenance = report.get("provenance") or {}
        story.extend([
            Paragraph("Canonical Provenance", h2),
            Paragraph(escape(
                f"Evidence SHA-256: {provenance.get('evidence_sha256', '')}<br/>"
                f"Behavior policy SHA-256: {(provenance.get('behavior_policy') or {}).get('sha256', '')}<br/>"
                f"Classification policy SHA-256: {(provenance.get('classification_policy') or {}).get('sha256', '')}<br/>"
                f"Evaluator Git revision: {provenance.get('evaluator_git_revision', '')}"
            ), body),
        ])

    ttp_rows = [["TTP ID", "Source"]]
    sources = session_payload.get("ttp_sources", {})
    for tid in _trusted_ttp_ids(report, session_payload):
        ttp_rows.append([tid, ", ".join(sources.get(tid, []))])
    if len(ttp_rows) > 1:
        table = Table(ttp_rows, colWidths=[4 * cm, 12 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2E6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.extend([Paragraph("Detected Techniques", h2), table, Spacer(1, 8)])

    evidence_lines = _evidence_layer_summary_lines(report)
    if evidence_lines:
        story.extend([
            Paragraph("Evidence Layers", h2),
            Paragraph("Direct command TTPs, session-correlated TTPs, and prediction-only hypotheses are separated so facts, correlations, and forecasts are not mixed.", body),
        ])
        layer_rows = [["Layer", "Count"]]
        for line in evidence_lines:
            label, _, value = line.partition(":")
            layer_rows.append([label, value.strip()])
        table = Table(layer_rows, colWidths=[8 * cm, 8 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2E6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.extend([table, Spacer(1, 8)])

    actions = _trusted_recommendation_actions(report)
    story.append(Paragraph("Policy-Approved Operator Actions", h2))
    if actions:
        for action in actions[:8]:
            story.append(Paragraph(
                escape(
                    f"P{action.get('policy_order', 50)} {action.get('description', '')} "
                    "(manual approval required)"
                ),
                body,
            ))
    else:
        story.append(Paragraph("No policy-approved operator action matched the available evidence.", body))

    ioc_rows = [["Type", "Value", "Confidence"]]
    for item in _ioc_items(report.get("ioc_summary") or session_payload.get("ioc_summary") or {}):
        ioc_rows.append([item.get("type", ""), item.get("value", "")[:60], item.get("confidence", "")])
    if len(ioc_rows) > 1:
        table = Table(ioc_rows, colWidths=[3 * cm, 10 * cm, 3 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2E6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.extend([Paragraph("Indicators of Compromise", h2), table, Spacer(1, 8)])

    story.extend([
        Spacer(1, 20),
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#95A5A6")),
        Paragraph("CONFIDENTIAL - For authorised recipients only. Do not redistribute.", meta),
    ])
    with _reports_directory_handle(output_dir) as directory:
        with _private_artifact_path(directory, filename) as temporary_path:
            doc = SimpleDocTemplate(
                str(temporary_path),
                pagesize=A4,
                leftMargin=2 * cm,
                rightMargin=2 * cm,
                topMargin=2 * cm,
                bottomMargin=2 * cm,
                invariant=1,
            )
            doc.build(story)
        return _verified_artifact_path(directory, filename)


def _artifact_file_record(
    directory: _ReportsDirectory,
    kind: str,
    path_text: str,
) -> Dict[str, Any]:
    path = Path(path_text)
    if path.parent != directory.path:
        raise ValueError("artifact path escaped the reports directory")
    _assert_reports_directory_identity(directory)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.name, flags, dir_fd=directory.descriptor)
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(descriptor)
    media_types = {
        "json": "application/json",
        "stix": "application/stix+json",
        "markdown": "text/markdown",
        "pdf": "application/pdf",
        "pdf_fallback_markdown": "text/markdown",
    }
    return {
        "kind": kind,
        "filename": path.name,
        "media_type": media_types.get(kind, "application/octet-stream"),
        "sha256": digest.hexdigest(),
        "size_bytes": metadata.st_size,
    }


def _write_artifact_integrity_manifest(
    directory: _ReportsDirectory,
    artifacts: Dict[str, Any],
    *,
    artifact_version: str,
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
) -> str:
    entries = [
        _artifact_file_record(directory, kind, path_text)
        for kind, path_text in sorted(artifacts.items())
        if kind in {
            "json",
            "stix",
            "markdown",
            "pdf",
            "pdf_fallback_markdown",
        }
        and isinstance(path_text, str)
    ]
    manifest = {
        "schema_version": "report_artifact_manifest.v1",
        "artifact_version": artifact_version,
        "source_report_sha256": hashlib.sha256(
            stable_json(report).encode("utf-8")
        ).hexdigest(),
        "source_session_sha256": hashlib.sha256(
            stable_json(session_payload).encode("utf-8")
        ).hexdigest(),
        "generated_at": _artifact_timestamp(report, session_payload),
        "artifacts": entries,
    }
    rendered = (
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    manifest_sha256 = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    filename = (
        f"{artifact_version}_artifact_manifest_{manifest_sha256}.json"
    )
    with _private_artifact_path(directory, filename) as temporary_path:
        temporary_path.write_text(rendered, encoding="utf-8")
    return _verified_artifact_path(directory, filename)


def validate_report_artifact_manifest(path_text: str | Path) -> List[str]:
    """Verify a manifest filename digest and every bound artifact file."""

    path = Path(path_text).resolve()
    match = _INTEGRITY_MANIFEST_PATTERN.fullmatch(path.name)
    if not match:
        return ["artifact manifest filename is invalid"]
    errors: List[str] = []
    try:
        with _reports_directory_handle(path.parent) as directory:
            manifest_record = _artifact_file_record(
                directory, "integrity_manifest", str(path)
            )
            if manifest_record["sha256"] != match.group(1):
                errors.append("artifact manifest SHA-256 mismatch")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path.name, flags, dir_fd=directory.descriptor)
            try:
                blocks = []
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    blocks.append(block)
            finally:
                os.close(descriptor)
            manifest = json.loads(b"".join(blocks).decode("utf-8"))
            if (
                not isinstance(manifest, dict)
                or manifest.get("schema_version")
                != "report_artifact_manifest.v1"
            ):
                return errors + ["artifact manifest schema is invalid"]
            if not _ARTIFACT_VERSION_PATTERN.fullmatch(
                str(manifest.get("artifact_version") or "")
            ):
                errors.append("artifact manifest version is invalid")
            entries = manifest.get("artifacts")
            if not isinstance(entries, list):
                return errors + ["artifact manifest entries are invalid"]
            seen_kinds: set[str] = set()
            seen_filenames: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    errors.append("artifact manifest entry is invalid")
                    continue
                kind = str(entry.get("kind") or "")
                filename = str(entry.get("filename") or "")
                if (
                    not kind
                    or kind in seen_kinds
                    or not filename
                    or Path(filename).name != filename
                ):
                    errors.append("artifact manifest entry identity is invalid")
                    continue
                seen_kinds.add(kind)
                if filename in seen_filenames:
                    # A PDF fallback may intentionally point at the canonical
                    # Markdown file; both records must still hash identically.
                    if kind != "pdf_fallback_markdown":
                        errors.append("artifact manifest filename is duplicated")
                seen_filenames.add(filename)
                actual = _artifact_file_record(
                    directory,
                    kind,
                    str(directory.path / filename),
                )
                if actual["sha256"] != str(entry.get("sha256") or ""):
                    errors.append(f"artifact SHA-256 mismatch: {kind}")
                if actual["size_bytes"] != entry.get("size_bytes"):
                    errors.append(f"artifact size mismatch: {kind}")
    except (
        OSError,
        UnicodeError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ):
        errors.append("artifact manifest verification failed")
    return errors


def attach_report_artifacts(report: Dict[str, Any], session_payload: Dict[str, Any], config: ProductionConfig) -> Dict[str, Any]:
    safe_report = _safe_artifact_mapping(report, "report")
    if not config.enable_artifacts:
        return safe_report
    safe_report.pop("artifacts", None)
    safe_session = _safe_artifact_mapping(session_payload, "session")
    artifact_version = _artifact_version_id(safe_report, safe_session)
    artifacts: Dict[str, Any] = {}
    with _prepare_reports_directory(config.reports_dir) as output_dir:
        try:
            artifacts["json"] = write_json_report(
                safe_report,
                safe_session.get(
                    "session_id",
                    safe_report.get("session_id", "unknown"),
                ),
                output_dir,
                artifact_version=artifact_version,
            )
        except _ReportsDirectoryIdentityChanged:
            raise
        except Exception as exc:
            artifacts["json_error"] = _safe_artifact_error(exc)
        if config.enable_stix_export:
            try:
                artifacts["stix"] = write_stix_bundle(
                    safe_report,
                    safe_session,
                    output_dir,
                    artifact_version=artifact_version,
                )
            except _ReportsDirectoryIdentityChanged:
                raise
            except Exception as exc:
                artifacts["stix_error"] = _safe_artifact_error(exc)
        try:
            artifacts["markdown"] = write_markdown_report(
                safe_report,
                safe_session,
                output_dir,
                artifact_version=artifact_version,
            )
        except _ReportsDirectoryIdentityChanged:
            raise
        except Exception as exc:
            artifacts["markdown_error"] = _safe_artifact_error(exc)
        if config.enable_pdf_export:
            try:
                artifacts["pdf"] = write_pdf_report(
                    safe_report,
                    safe_session,
                    output_dir,
                    artifact_version=artifact_version,
                )
            except _PDFExportUnavailable:
                if artifacts.get("markdown"):
                    artifacts["pdf_fallback_markdown"] = artifacts["markdown"]
                else:
                    artifacts["pdf_error"] = artifacts.get(
                        "markdown_error",
                        "markdown fallback unavailable",
                    )
            except _ReportsDirectoryIdentityChanged:
                raise
            except Exception as exc:
                artifacts["pdf_error"] = _safe_artifact_error(exc)
        try:
            artifacts["integrity_manifest"] = (
                _write_artifact_integrity_manifest(
                    output_dir,
                    artifacts,
                    artifact_version=artifact_version,
                    report=safe_report,
                    session_payload=safe_session,
                )
            )
        except _ReportsDirectoryIdentityChanged:
            raise
        except Exception as exc:
            artifacts["integrity_manifest_error"] = _safe_artifact_error(exc)
        _assert_reports_directory_identity(output_dir)
    safe_report["artifacts"] = artifacts
    return _safe_artifact_mapping(safe_report, "report")
