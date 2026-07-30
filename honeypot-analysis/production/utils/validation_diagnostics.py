"""Bounded structural diagnostics for canonical validation failures.

Diagnostics intentionally contain no exception message, object serialization,
evidence value, command, credential, address, or stack-frame local. Only
allowlisted contract metadata and normalized validator error categories leave
the validation boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, Mapping, Optional


SCHEMA_VERSION = "analysis_validation_diagnostic.v1"
MAX_ERRORS = 24
MAX_TEXT = 160
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,160}$")

_CONTRACTS = {
    "session_assessment.v4",
    "response_guidance.v3",
    "typed_semantic_fact_set.v2",
    "report_artifact_manifest.v1",
    "canonical_analysis",
}
_VALIDATORS = {
    "validate_session_assessment_v4",
    "validate_response_guidance_v3",
    "validate_typed_semantic_fact_set",
    "validate_report_artifact_manifest",
    "canonical_analysis_pipeline",
}
_PRODUCERS = {
    "build_session_assessment_v4",
    "build_response_guidance_v3_from_paths",
    "attach_report_artifacts",
    "CanonicalAssessmentCoordinator.analyze",
    "analysis_worker.deterministic_baseline_report",
}

_EXACT_PATHS = {
    "schema_version must be session_assessment.v4": "schema_version",
    "canonical_evidence must be an object": "canonical_evidence",
    "canonical_evidence.evidence_sha256 mismatch": (
        "canonical_evidence.evidence_sha256"
    ),
    "provenance evidence hash mismatch": "provenance.evidence_sha256",
    "provenance.evaluator_git_revision is required": (
        "provenance.evaluator_git_revision"
    ),
    "provenance.typed_semantics is required": "provenance.typed_semantics",
    "provenance.typed_semantics shape is invalid": (
        "provenance.typed_semantics"
    ),
    "typed semantic schema is invalid": (
        "provenance.typed_semantics.schema_version"
    ),
    "typed semantic mode is invalid": "provenance.typed_semantics.mode",
    "typed semantic activated families are invalid": (
        "provenance.typed_semantics.activated_families"
    ),
    "typed semantic families cannot be both activated and non-activated": (
        "provenance.typed_semantics.activated_families"
    ),
    "typed semantic persistence semantics are invalid": (
        "provenance.typed_semantics.persistence"
    ),
    "typed semantic status is invalid": "provenance.typed_semantics.status",
    "observed evidence must be authoritative": (
        "authority.observed_evidence_authoritative"
    ),
    "non-authoritative context separation semantics are invalid": (
        "non_authoritative_context.separation_semantics"
    ),
    "response_guidance_v3 must be an object": "response_guidance_v3",
    "assessment_id mismatch": "assessment_id",
    "hypothesis set must contain identified alternatives": (
        "hypothesis_sets[].hypotheses"
    ),
    "hypothesis IDs must be unique within a set": (
        "hypothesis_sets[].hypotheses[].hypothesis_id"
    ),
    "hypothesis has unknown evidence refs": (
        "hypothesis_sets[].hypotheses[].supporting_evidence_refs"
    ),
    "typed semantic finding requires typed provenance": (
        "behavioral_findings[].semantic_family"
    ),
    "finding uses a non-activated semantic family": (
        "behavioral_findings[].semantic_family"
    ),
    "finding semantic trace schema is invalid": (
        "behavioral_findings[].semantic_trace.schema_version"
    ),
    "finding semantic trace fact-set hash mismatch": (
        "behavioral_findings[].semantic_trace.fact_set_sha256"
    ),
    "finding semantic trace vocabulary hash mismatch": (
        "behavioral_findings[].semantic_trace.semantic_vocabulary_sha256"
    ),
    "finding semantic trace evidence refs are unresolved": (
        "behavioral_findings[].semantic_trace.matches[].supporting_evidence_refs"
    ),
}

_PREFIX_PATHS = (
    ("provenance.behavior_policy.sha256", "provenance.behavior_policy.sha256"),
    (
        "provenance.classification_policy.sha256",
        "provenance.classification_policy.sha256",
    ),
    ("authority.", "authority"),
    ("behavioral_findings ", "behavioral_findings"),
    ("finding ID mismatch:", "behavioral_findings[].finding_id"),
    ("finding status is invalid:", "behavioral_findings[].status"),
    (
        "finding has unknown evidence refs:",
        "behavioral_findings[].evidence_refs",
    ),
    ("finding semantic trace ", "behavioral_findings[].semantic_trace"),
    ("hypothesis ID mismatch:", "hypothesis_sets[].hypotheses[].hypothesis_id"),
    ("hypothesis set ID mismatch:", "hypothesis_sets[].hypothesis_set_id"),
    ("typed semantic ", "provenance.typed_semantics"),
    ("verified model artifact", "provenance.model_artifacts[]"),
    ("model artifact ", "provenance.model_artifacts[]"),
    ("verified MITRE ATT&CK", "provenance.mitre_attack.sha256"),
    ("configured MITRE ATT&CK", "provenance.mitre_attack.status"),
    ("observation-only abstention", "abstention"),
    ("response_guidance_v3:", "response_guidance_v3"),
)


def _bounded(value: Any, *, default: str = "unknown") -> str:
    text = str(value or "").strip()
    if not text:
        return default
    return text[:MAX_TEXT]


def _allow(value: Any, allowed: set[str], default: str) -> str:
    text = _bounded(value, default=default)
    return text if text in allowed else default


def _field_path(error: str) -> str:
    if error in _EXACT_PATHS:
        return _EXACT_PATHS[error]
    if error.startswith("prohibited canonical field:"):
        candidate = error.partition(":")[2].strip()
        if SAFE_PATH_RE.fullmatch(candidate):
            return candidate
        return "canonical_record"
    for prefix, path in _PREFIX_PATHS:
        if error.startswith(prefix):
            return path
    return "canonical_record"


def _category(error: str) -> tuple[str, str]:
    lowered = error.lower()
    if "missing" in lowered or "required" in lowered:
        return "missing", "required_field"
    if "duplicate" in lowered or "unique" in lowered:
        return "duplicated", "unique_identity"
    if "unknown" in lowered or "unresolved" in lowered:
        return "unresolved", "reference_resolution"
    if "mismatch" in lowered or "inconsistent" in lowered:
        return "inconsistent", "canonical_integrity"
    if "must be an object" in lowered or "must be a list" in lowered:
        return "malformed", "expected_container_type"
    if "prohibited" in lowered:
        return "malformed", "prohibited_authority_field"
    if "invalid" in lowered or "malformed" in lowered:
        return "malformed", "contract_constraint"
    return "malformed", "contract_constraint"


def _normalized_errors(errors: Iterable[Any]) -> list[Dict[str, str]]:
    normalized: list[Dict[str, str]] = []
    for raw in list(errors)[:MAX_ERRORS]:
        # The message is used only for local classification and is never
        # retained in the returned diagnostic.
        message = str(raw or "")
        category, constraint = _category(message)
        normalized.append(
            {
                "error_category": category,
                "field_path": _field_path(message),
                "constraint": constraint,
                "received_type": "not_recorded",
                "state": category,
            }
        )
    return normalized


def build_validation_diagnostic(
    exc: BaseException,
    *,
    contract_name: str = "canonical_analysis",
    validator_name: str = "canonical_analysis_pipeline",
    producer: str = "CanonicalAssessmentCoordinator.analyze",
) -> Optional[Dict[str, Any]]:
    """Return an allowlisted structural diagnostic or ``None``.

    Only exceptions that explicitly carry a sequence of validation errors are
    eligible. Arbitrary exception text and generic exception ``repr`` are
    never inspected or emitted.
    """

    raw_errors = getattr(exc, "validation_errors", None)
    if not isinstance(raw_errors, (list, tuple)) or not raw_errors:
        return None
    errors = _normalized_errors(raw_errors)
    if not errors:
        return None
    contract = _allow(
        getattr(exc, "contract_name", contract_name),
        _CONTRACTS,
        "canonical_analysis",
    )
    validator = _allow(
        getattr(exc, "validator_name", validator_name),
        _VALIDATORS,
        "canonical_analysis_pipeline",
    )
    selected_producer = _allow(
        getattr(exc, "producer", producer),
        _PRODUCERS,
        "CanonicalAssessmentCoordinator.analyze",
    )
    revision = _bounded(getattr(exc, "source_revision", ""))
    if not REVISION_RE.fullmatch(revision):
        revision = "unknown"
    identity_input = {
        "contract_name": contract,
        "validator_name": validator,
        "errors": errors,
        "producer": selected_producer,
        "source_revision": revision,
    }
    digest = hashlib.sha256(
        json.dumps(
            identity_input,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": SCHEMA_VERSION,
        "contract_name": contract,
        "validator_name": validator,
        "errors": errors,
        "safe_object_id": f"validation_{digest[:32]}",
        "producer": selected_producer,
        "source_revision": revision,
    }


def attach_job_context(
    diagnostic: Mapping[str, Any],
    *,
    job_id: Any,
    retry_attempt: Any,
) -> Dict[str, Any]:
    """Copy an already-safe diagnostic and add bounded durable-job context."""

    output = {
        key: diagnostic[key]
        for key in (
            "schema_version",
            "contract_name",
            "validator_name",
            "errors",
            "safe_object_id",
            "producer",
            "source_revision",
        )
        if key in diagnostic
    }
    safe_job = _bounded(job_id)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", safe_job):
        safe_job = "unknown"
    try:
        attempt = max(1, min(int(retry_attempt), 100))
    except (TypeError, ValueError):
        attempt = 1
    output["job_id"] = safe_job
    output["retry_attempt"] = attempt
    return output


def diagnostic_from_exception(
    exc: BaseException,
    *,
    job_id: Any,
    retry_attempt: Any,
) -> Optional[Dict[str, Any]]:
    diagnostic = getattr(exc, "validation_diagnostic", None)
    if not isinstance(diagnostic, Mapping):
        diagnostic = build_validation_diagnostic(exc)
    if not isinstance(diagnostic, Mapping):
        return None
    return attach_job_context(
        diagnostic,
        job_id=job_id,
        retry_attempt=retry_attempt,
    )
