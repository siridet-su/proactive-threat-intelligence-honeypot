"""Canonical deterministic session assessment v4.

New records are built directly from one content-addressed evidence snapshot.
Legacy threat_hypothesis.v2 and session_assessment.v3 are intentionally not
inputs to this evaluator.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from production.policies.threat_hypothesis_behavior_policy import (
    policy_summary,
    resolve_behavior_policy,
)
from production.reporting.response_guidance_v3 import (
    build_response_guidance_v3_from_paths,
    canonical_evidence_snapshot as guidance_evidence_snapshot,
    validate_response_guidance_v3,
)
from production.reporting.threat_hypothesis import (
    build_follow_on_hypothesis,
    build_observed_behavior,
    build_supported_assessment,
)
from production.reporting.typed_semantic_facts import run_typed_semantic_shadow
from production.utils.serialization import stable_id, stable_json, utc_now
from production.utils.sensitive_data import redact_for_artifact


SCHEMA_VERSION = "session_assessment.v4"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
PROHIBITED_AUTHORITY_KEYS = {
    "intent",
    "objective",
    "objectives",
    "possible_objectives",
    "predicted_next_action",
    "score",
    "global_score",
    "confidence_score",
    "recommended_actions",
    "recommended_mitigations",
    "recommendations",
    "mitigations",
    "response_actions",
    "alerts",
}


class SessionAssessmentV4Error(ValueError):
    """Raised when a v4 record violates the whole-contract validator."""


def canonical_assessment_id(value: Dict[str, Any]) -> str:
    """Derive the v4 ID from the current canonical findings and provenance."""

    provenance = value.get("provenance") or {}
    evidence = value.get("canonical_evidence") or {}
    return stable_id(
        "session_assessment",
        {
            "evidence_sha256": evidence.get("evidence_sha256"),
            "behavior_policy_sha256": (
                provenance.get("behavior_policy") or {}
            ).get("sha256"),
            "classification_policy_sha256": (
                provenance.get("classification_policy") or {}
            ).get("sha256"),
            "evaluator_git_revision": provenance.get("evaluator_git_revision"),
            "finding_ids": [
                item.get("finding_id")
                for item in value.get("behavioral_findings") or []
            ],
            "hypothesis_set_ids": [
                item.get("hypothesis_set_id")
                for item in value.get("hypothesis_sets") or []
            ],
        },
    )


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes(stable_json(value).encode("utf-8"))


def _source_payload(session: Any, raw_events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    def get(name: str, default: Any) -> Any:
        return session.get(name, default) if isinstance(session, dict) else getattr(session, name, default)

    return {
        "schema_version": "canonical_cowrie_evidence_snapshot.v1",
        "session_id": _clean(get("session_id", "unknown")) or "unknown",
        "src_ip": _clean(get("src_ip", "")),
        "commands": list(get("commands", []) or []),
        "commands_success": list(get("commands_success", []) or []),
        "commands_failed": list(get("commands_failed", []) or []),
        "classification_events": [
            deepcopy(item) for item in get("classification_events", []) or [] if isinstance(item, dict)
        ],
        "raw_events": [
            deepcopy(item) for item in raw_events or get("raw_events", []) or [] if isinstance(item, dict)
        ],
        "canonical_event_manifest": deepcopy(
            get("canonical_event_manifest", {}) or {}
        ),
        "login_success": bool(get("login_success", False)),
    }


def build_canonical_evidence_snapshot(
    session: Any,
    raw_events: Optional[Iterable[Dict[str, Any]]] = None,
    *,
    behavior_policy_document: Optional[Dict[str, Any]] = None,
    behavior_policy_path: str = "",
) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """Build the one immutable evidence snapshot used by v4 and guidance v3."""

    source = redact_for_artifact(_source_payload(session, raw_events or []))
    if not isinstance(source, dict):
        raise SessionAssessmentV4Error(
            "canonical evidence redaction did not return an object"
        )
    behavior_document = resolve_behavior_policy(
        behavior_policy_document, behavior_policy_path
    )
    observed = build_observed_behavior(
        [deepcopy(source)],
        raw_events=source["raw_events"],
        behavior_policy_document=behavior_document,
        behavior_policy_path=behavior_policy_path,
    )
    authoritative = guidance_evidence_snapshot(observed)
    source_evidence = {
        key: deepcopy(source[key])
        for key in (
            "schema_version",
            "session_id",
            "src_ip",
            "commands",
            "commands_success",
            "commands_failed",
            "raw_events",
            "canonical_event_manifest",
            "login_success",
        )
    }
    snapshot = {
        "schema_version": "canonical_evidence_snapshot.v1",
        # Classifier scores and model-only candidates are deliberately excluded
        # from this sensor-evidence digest and the authoritative snapshot.
        "source_evidence_sha256": _sha256_json(source_evidence),
        "session_id": source["session_id"],
        "src_ip": source["src_ip"],
        "durable_event_manifest": deepcopy(
            source.get("canonical_event_manifest") or {}
        ),
        "observations": deepcopy(
            authoritative.get("ordered_command_observations") or []
        ),
        "transfer_observations": deepcopy(
            authoritative.get("transfer_event_observations") or []
        ),
        "direct_cowrie_events": deepcopy(
            authoritative.get("cowrie_event_evidence") or []
        ),
        "entities": deepcopy(observed.get("normalized_entities") or []),
        "relationships": deepcopy(
            authoritative.get("behavior_relationships") or []
        ),
        "connected_behavior_chains": deepcopy(
            authoritative.get("connected_behavior_chains") or []
        ),
        "trusted_attck_candidates": deepcopy(
            authoritative.get("trusted_attck_candidates") or []
        ),
    }
    snapshot = redact_for_artifact(snapshot)
    if not isinstance(snapshot, dict):
        raise SessionAssessmentV4Error(
            "canonical evidence snapshot redaction did not return an object"
        )
    snapshot["evidence_sha256"] = _sha256_json(snapshot)
    return snapshot, observed, source, behavior_document


def _file_policy(path_text: str, default_relative: str, provided: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    requested = _clean(path_text)
    path = Path(requested) if requested else Path(__file__).resolve().parents[2] / default_relative
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError("policy root is not an object")
        _validate_classification_policy(document)
        return {
            "status": "loaded",
            "path": str(path.resolve()),
            "sha256": _sha256_bytes(raw),
            "policy_id": _clean(document.get("policy_id")),
            "version": _clean(document.get("version")),
        }
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        # An explicitly configured file is never replaced with a bundled file.
        if requested:
            return {
                "status": "invalid",
                "path": requested,
                "sha256": "",
                "policy_id": "",
                "version": "",
                "error": exc.__class__.__name__,
            }
        if isinstance(provided, dict) and provided:
            return {
                "status": "provided",
                "path": "in_memory",
                "sha256": _sha256_json(provided),
                "policy_id": _clean(provided.get("policy_id")),
                "version": _clean(provided.get("version")),
            }
        return {
            "status": "invalid",
            "path": str(path),
            "sha256": "",
            "policy_id": "",
            "version": "",
            "error": exc.__class__.__name__,
        }


def _validate_classification_policy(document: Dict[str, Any]) -> None:
    if document.get("schema_version") != "classification_rule_policy.v1":
        raise ValueError("classification policy schema is invalid")
    if not _clean(document.get("policy_id")) or not _clean(document.get("version")):
        raise ValueError("classification policy identity is incomplete")
    body = document.get("policy")
    if not isinstance(body, dict) or body.get("enabled") is not True:
        raise ValueError("classification policy is disabled or missing")
    rules = body.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("classification policy has no rules")
    reviewed_only = _clean(body.get("rule_review_mode")).lower() != "include_unreviewed"
    reviewed_runtime_rules = 0
    rule_ids = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("classification rule is not an object")
        if rule.get("enabled") is False:
            continue
        rule_id = _clean(rule.get("rule_id"))
        if not rule_id or rule_id in rule_ids:
            raise ValueError("classification rule identity is missing or duplicated")
        rule_ids.add(rule_id)
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", _clean(rule.get("ttp")).upper()):
            raise ValueError("classification rule ATT&CK identifier is invalid")
        try:
            re.compile(_clean(rule.get("pattern")), re.IGNORECASE)
        except re.error as exc:
            raise ValueError("classification rule regex is invalid") from exc
        if not reviewed_only or (rule.get("provenance") or {}).get("reviewed") is True:
            reviewed_runtime_rules += 1
    if reviewed_runtime_rules == 0:
        raise ValueError("classification policy selects no reviewed runtime rules")


def _git_revision() -> str:
    configured = _clean(os.getenv("DEPLOYED_COMMIT"))
    if GIT_REVISION_RE.fullmatch(configured):
        return configured
    root = Path(__file__).resolve().parents[2]
    for marker in (root / "DEPLOYED_COMMIT", root.parent / "DEPLOYED_COMMIT"):
        try:
            value = marker.read_text(encoding="utf-8").strip()
            if GIT_REVISION_RE.fullmatch(value):
                return value
        except OSError:
            pass
    try:
        value = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
        return value if GIT_REVISION_RE.fullmatch(value) else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _artifact_hashes(*values: Any) -> List[Dict[str, str]]:
    found: Dict[str, str] = {}

    def visit(value: Any, path: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                child = f"{path}.{key}" if path else str(key)
                if str(key).lower().endswith("sha256") and SHA256_RE.fullmatch(_clean(item).lower()):
                    found[child] = _clean(item).lower()
                else:
                    visit(item, child)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")

    for value in values:
        visit(value)
    return [{"name": key, "sha256": found[key]} for key in sorted(found)]


def _resolved_artifact_path(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else Path(__file__).resolve().parents[2] / path


def _file_artifact_provenance(
    name: str,
    path_text: Any,
    expected_sha256: Any = "",
) -> Dict[str, Any]:
    configured = _clean(path_text)
    expected = _clean(expected_sha256).lower()
    if not configured:
        return {
            "name": name,
            "path": "",
            "status": "not_configured",
            "sha256": "",
            "expected_sha256": expected,
        }
    path = _resolved_artifact_path(configured)
    result = {
        "name": name,
        "path": str(path.resolve()),
        "status": "missing",
        "sha256": "",
        "expected_sha256": expected,
    }
    try:
        actual = _sha256_bytes(path.read_bytes())
    except OSError:
        return result
    result["sha256"] = actual
    if expected and not SHA256_RE.fullmatch(expected):
        result["status"] = "invalid_expected_sha256"
    elif expected and actual != expected:
        result["status"] = "sha256_mismatch"
    else:
        result["status"] = "verified"
    return result


def _verified_model_artifacts(policy_value: Any) -> List[Dict[str, Any]]:
    document = policy_value if isinstance(policy_value, dict) else {}
    policy = document.get("policy") if isinstance(document.get("policy"), dict) else document
    pairs = (
        ("transformer_checkpoint", "transformer_checkpoint_path", "transformer_checkpoint_sha256"),
        ("transformer_model_spec", "transformer_model_spec_path", "transformer_model_spec_file_sha256"),
        ("transformer_vocabulary", "transformer_vocabulary_path", "transformer_vocabulary_file_sha256"),
        ("transformer_preprocessing", "transformer_preprocessing_path", "transformer_preprocessing_sha256"),
        ("transformer_calibration", "transformer_calibration_path", "transformer_calibration_file_sha256"),
        ("runtime_rule_policy", "runtime_rule_policy_path", "runtime_rule_policy_sha256"),
        ("runtime_trust_policy", "runtime_trust_policy_path", "runtime_trust_policy_sha256"),
        (
            "runtime_classifier_checkpoint",
            "runtime_classifier_checkpoint_path",
            "runtime_classifier_checkpoint_sha256",
        ),
    )
    artifacts = [
        _file_artifact_provenance(name, policy.get(path_key), policy.get(hash_key))
        for name, path_key, hash_key in pairs
        if _clean(policy.get(path_key)) or _clean(policy.get(hash_key))
    ]
    return sorted(artifacts, key=lambda item: item["name"])


def _finding(claim: Dict[str, Any], connected: bool) -> Dict[str, Any]:
    refs = sorted({_clean(ref) for ref in claim.get("evidence_refs") or [] if _clean(ref)})
    content = {
        "finding_type": _clean(claim.get("claim_type")) or "observed_behavior_relationship",
        "statement": _clean(claim.get("text")),
        "status": _clean(claim.get("evidence_status")) or "insufficient_evidence",
        "evidence_refs": refs,
        "relationship_refs": sorted({
            _clean(claim.get("connected_chain_id")) if connected else ""
        } - {""}),
        "behavior_policy_rule_id": _clean(claim.get("behavior_policy_rule_id")),
    }
    return {
        "finding_id": stable_id("finding", content),
        **content,
        "limitations": [
            _clean(item.get("text") if isinstance(item, dict) else item)
            for item in claim.get("limitations") or []
            if _clean(item.get("text") if isinstance(item, dict) else item)
        ],
    }


def _deduplicated_findings(assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
    connected_claims = [
        item for item in assessment.get("connected_behavior_claims") or [] if isinstance(item, dict)
    ]
    connected = [_finding(item, True) for item in connected_claims]
    connected_refs = [set(item["evidence_refs"]) for item in connected]
    output = list(connected)
    for claim in assessment.get("possible_objectives") or []:
        if not isinstance(claim, dict) or claim in connected_claims:
            continue
        item = _finding(claim, False)
        refs = set(item["evidence_refs"])
        if refs and any(refs <= covered for covered in connected_refs):
            continue
        if item["finding_id"] not in {existing["finding_id"] for existing in output}:
            output.append(item)
    return sorted(output, key=lambda item: item["finding_id"])


def _hypothesis_sets(follow_on: Dict[str, Any]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for claim in follow_on.get("claims") or []:
        if not isinstance(claim, dict):
            continue
        refs = sorted({_clean(ref) for ref in claim.get("evidence_refs") or [] if _clean(ref)})
        chain_id = _clean(claim.get("connected_chain_id"))
        alternatives = [
            {
                "statement": _clean(claim.get("text")),
                "status": "active",
                "supporting_evidence_refs": refs,
                "falsification_conditions": [
                    "A linked Cowrie-reported failed prerequisite weakens this alternative.",
                    "Evidence that the referenced artifact was unavailable weakens this alternative.",
                ],
            },
            {
                "statement": (
                    "No linked follow-on execution is observable in this evidence snapshot; "
                    "the activity may have failed, stopped, or continued outside Cowrie visibility."
                ),
                "status": "active",
                "supporting_evidence_refs": [],
                "falsification_conditions": [
                    "A linked execution observation in the same evidence scope disconfirms this alternative."
                ],
            },
        ]
        hypotheses = []
        for alternative in alternatives:
            hypotheses.append({
                "hypothesis_id": stable_id("hypothesis", {
                    "chain_id": chain_id,
                    "statement": alternative["statement"],
                    "evidence_refs": alternative["supporting_evidence_refs"],
                }),
                **alternative,
            })
        set_content = {"chain_id": chain_id, "hypothesis_ids": [item["hypothesis_id"] for item in hypotheses]}
        output.append({
            "hypothesis_set_id": stable_id("hypothesis_set", set_content),
            "question": "What explains the incomplete artifact-related behavior visible in this session?",
            "scope": "bounded_cowrie_observable_behavior",
            "relationship_refs": [chain_id] if chain_id else [],
            "alternatives_are_exhaustive": False,
            "alternatives_are_mutually_exclusive": False,
            "hypotheses": hypotheses,
        })
    return sorted(output, key=lambda item: item["hypothesis_set_id"])


def _strip_context(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_context(item)
            for key, item in value.items()
            if key not in PROHIBITED_AUTHORITY_KEYS and key != "recommendations"
        }
    if isinstance(value, list):
        return [_strip_context(item) for item in value]
    return deepcopy(value)


def build_session_assessment_v4(
    sessions: Iterable[Any],
    raw_events: Optional[List[Dict[str, Any]]] = None,
    *,
    behavior_policy_document: Optional[Dict[str, Any]] = None,
    behavior_policy_path: str = "",
    classification_policy: Optional[Dict[str, Any]] = None,
    classification_policy_path: str = "",
    model_artifact_provenance: Optional[Dict[str, Any]] = None,
    prediction_context: Optional[Dict[str, Any]] = None,
    enrichment_context: Optional[Dict[str, Any]] = None,
    correlation_context: Optional[List[Dict[str, Any]]] = None,
    llm_context: Optional[Dict[str, Any]] = None,
    mitre_cache_path: str = "",
    response_guidance_policy_path: str = "",
    response_guidance_asset_profile_path: str = "",
) -> Dict[str, Any]:
    session_list = list(sessions or [])
    session = session_list[0] if session_list else {}
    snapshot, observed, source, behavior_document = (
        build_canonical_evidence_snapshot(
            session,
            raw_events or [],
            behavior_policy_document=behavior_policy_document,
            behavior_policy_path=behavior_policy_path,
        )
    )
    behavior = policy_summary(behavior_document, include_integrity=True)
    classification = _file_policy(
        classification_policy_path,
        "configs/classification_rules.trusted.json",
        classification_policy,
    )
    mitre_attack = _file_artifact_provenance(
        "mitre_attack_cache",
        mitre_cache_path,
    )
    policy_valid = (
        behavior.get("enabled") is True
        and behavior.get("load_status") in {"loaded", "provided"}
        and SHA256_RE.fullmatch(_clean(behavior.get("sha256")).lower()) is not None
        and classification.get("status") in {"loaded", "provided"}
        and SHA256_RE.fullmatch(_clean(classification.get("sha256")).lower()) is not None
        and (
            mitre_attack.get("status") in {"not_configured", "verified"}
        )
    )
    findings: List[Dict[str, Any]] = []
    hypothesis_sets: List[Dict[str, Any]] = []
    if policy_valid:
        supported = build_supported_assessment(
            observed,
            behavior_policy_document=behavior_document,
            behavior_policy_path=behavior_policy_path,
        )
        follow_on = build_follow_on_hypothesis(
            observed,
            behavior_policy_document=behavior_document,
            behavior_policy_path=behavior_policy_path,
        )
        findings = _deduplicated_findings(supported)
        hypothesis_sets = _hypothesis_sets(follow_on)
    evaluator_revision = _git_revision()
    # Shadow facts receive the exact effective provenance but are still
    # discarded. They cannot affect policy validity, canonical output,
    # persistence, consumers, or identity inputs.
    try:
        run_typed_semantic_shadow(
            observed,
            canonical_evidence=snapshot,
            behavior_policy_sha256=_clean(behavior.get("sha256")),
            classification_policy_sha256=_clean(
                classification.get("sha256")
            ),
            evaluator_git_revision=evaluator_revision,
        )
    except Exception:
        pass
    provenance = {
        "evidence_sha256": snapshot["evidence_sha256"],
        "behavior_policy": behavior,
        "classification_policy": classification,
        "model_artifacts": _verified_model_artifacts(
            model_artifact_provenance or {}
        ),
        "declared_context_hashes": _artifact_hashes(
            source.get("classification_events"),
            prediction_context or {},
        ),
        "mitre_attack": mitre_attack,
        "evaluator_git_revision": evaluator_revision,
        "cached_graph": {
            "accepted": False,
            "disposition": "deterministically_rebuilt_from_canonical_snapshot",
            "bound_evidence_sha256": snapshot["evidence_sha256"],
            "bound_behavior_policy_sha256": _clean(behavior.get("sha256")),
            "bound_classification_policy_sha256": _clean(classification.get("sha256")),
        },
        "durable_event_manifest": deepcopy(
            snapshot.get("durable_event_manifest") or {}
        ),
    }
    authority = {
        "observed_evidence_authoritative": True,
        "predictions_authoritative": False,
        "enrichment_authoritative": False,
        "correlations_authoritative": False,
        "llm_authoritative": False,
        "automatic_response_authorized": False,
        "automatic_alerts_authorized": False,
    }
    record = {
        "schema_version": SCHEMA_VERSION,
        "assessment_id": "",
        "generated_at": utc_now(),
        "status": (
            "observation_only_abstention"
            if not policy_valid
            else ("assessed" if findings or hypothesis_sets else "observed_behavior_only")
        ),
        "abstention": {
            "abstained": not policy_valid,
            "reason": "" if policy_valid else "required_policy_missing_or_invalid",
        },
        "canonical_evidence": snapshot,
        "behavioral_findings": findings,
        "hypothesis_sets": hypothesis_sets,
        "provenance": provenance,
        "authority": authority,
        "non_authoritative_context": {
            "separation_semantics": "context_cannot_change_findings_hypotheses_statuses_or_ids",
            "prediction": _strip_context(prediction_context or {}),
            "enrichment": _strip_context(enrichment_context or {}),
            "cross_session_correlations": _strip_context(correlation_context or []),
            "llm_prose": _strip_context(llm_context or {}),
        },
        "compatibility": {
            "legacy_v2_v3_records": "read_only_not_recomputed",
            "new_record_authority": SCHEMA_VERSION,
        },
    }
    guidance = build_response_guidance_v3_from_paths(
        snapshot,
        policy_path=response_guidance_policy_path,
        asset_profile_path=response_guidance_asset_profile_path,
        session_context=source,
        forecast_context=prediction_context or {},
        enrichment_context=enrichment_context or {},
    )
    record["response_guidance_v3"] = guidance
    record["assessment_id"] = canonical_assessment_id(record)
    validate_session_assessment_v4(record, raise_on_error=True)
    return record


def validate_session_assessment_v4(
    value: Dict[str, Any],
    *,
    raise_on_error: bool = False,
) -> List[str]:
    errors: List[str] = []
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    evidence = value.get("canonical_evidence") if isinstance(value, dict) else {}
    if not isinstance(evidence, dict):
        errors.append("canonical_evidence must be an object")
        evidence = {}
    recorded_hash = _clean(evidence.get("evidence_sha256")).lower()
    hash_input = deepcopy(evidence)
    hash_input.pop("evidence_sha256", None)
    if not SHA256_RE.fullmatch(recorded_hash) or recorded_hash != _sha256_json(hash_input):
        errors.append("canonical_evidence.evidence_sha256 mismatch")
    provenance = value.get("provenance") or {}
    if provenance.get("evidence_sha256") != recorded_hash:
        errors.append("provenance evidence hash mismatch")
    if not GIT_REVISION_RE.fullmatch(_clean(provenance.get("evaluator_git_revision")).lower()):
        errors.append("provenance.evaluator_git_revision is required")
    for name in ("behavior_policy", "classification_policy"):
        policy = provenance.get(name) or {}
        digest = _clean(policy.get("sha256")).lower()
        if value.get("status") != "observation_only_abstention" and not SHA256_RE.fullmatch(digest):
            errors.append(f"provenance.{name}.sha256 is required")
    for artifact in provenance.get("model_artifacts") or []:
        if not isinstance(artifact, dict) or not _clean(artifact.get("name")):
            errors.append("provenance.model_artifacts entries require a name")
            continue
        status = _clean(artifact.get("status"))
        actual = _clean(artifact.get("sha256")).lower()
        expected = _clean(artifact.get("expected_sha256")).lower()
        if status == "verified" and not SHA256_RE.fullmatch(actual):
            errors.append("verified model artifacts require an actual SHA-256")
        if expected and not SHA256_RE.fullmatch(expected):
            errors.append("model artifact expected SHA-256 is malformed")
        if status == "verified" and expected and actual != expected:
            errors.append("verified model artifact does not match expected SHA-256")
    mitre_attack = provenance.get("mitre_attack") or {}
    mitre_status = _clean(mitre_attack.get("status"))
    mitre_sha = _clean(mitre_attack.get("sha256")).lower()
    if mitre_status == "verified" and not SHA256_RE.fullmatch(mitre_sha):
        errors.append("verified MITRE ATT&CK cache requires a SHA-256")
    if (
        value.get("status") != "observation_only_abstention"
        and mitre_status not in {"not_configured", "verified"}
    ):
        errors.append("configured MITRE ATT&CK cache must verify")
    authority = value.get("authority") or {}
    required_false = (
        "predictions_authoritative",
        "enrichment_authoritative",
        "correlations_authoritative",
        "llm_authoritative",
        "automatic_response_authorized",
        "automatic_alerts_authorized",
    )
    if authority.get("observed_evidence_authoritative") is not True:
        errors.append("observed evidence must be authoritative")
    for key in required_false:
        if authority.get(key) is not False:
            errors.append(f"authority.{key} must be false")
    if value.get("status") == "observation_only_abstention":
        if value.get("behavioral_findings") or value.get("hypothesis_sets"):
            errors.append("observation-only abstention cannot contain findings or hypotheses")
        if (value.get("abstention") or {}).get("abstained") is not True:
            errors.append("observation-only abstention must declare abstained=true")
    context = value.get("non_authoritative_context") or {}
    if context.get("separation_semantics") != (
        "context_cannot_change_findings_hypotheses_statuses_or_ids"
    ):
        errors.append("non-authoritative context separation semantics are invalid")
    for collection, id_key in (("behavioral_findings", "finding_id"), ("hypothesis_sets", "hypothesis_set_id")):
        values = value.get(collection)
        if not isinstance(values, list):
            errors.append(f"{collection} must be a list")
            continue
        ids = [_clean(item.get(id_key)) for item in values if isinstance(item, dict)]
        if len(ids) != len(values) or len(ids) != len(set(ids)) or any(not item for item in ids):
            errors.append(f"{collection} IDs must be present and unique")
    guidance = value.get("response_guidance_v3")
    if not isinstance(guidance, dict):
        errors.append("response_guidance_v3 must be an object")
    else:
        guidance_errors = validate_response_guidance_v3(guidance)
        errors.extend(
            f"response_guidance_v3: {error}" for error in guidance_errors
        )
    evidence_refs = {
        _clean(item.get("evidence_id"))
        for key in (
            "observations",
            "transfer_observations",
            "direct_cowrie_events",
            "trusted_attck_candidates",
            "audit_only_candidates",
        )
        for item in evidence.get(key) or []
        if isinstance(item, dict) and _clean(item.get("evidence_id"))
    }
    for finding in value.get("behavioral_findings") or []:
        if not isinstance(finding, dict):
            continue
        content = {
            "finding_type": _clean(finding.get("finding_type")),
            "statement": _clean(finding.get("statement")),
            "status": _clean(finding.get("status")),
            "evidence_refs": sorted({_clean(ref) for ref in finding.get("evidence_refs") or [] if _clean(ref)}),
            "relationship_refs": sorted({_clean(ref) for ref in finding.get("relationship_refs") or [] if _clean(ref)}),
            "behavior_policy_rule_id": _clean(finding.get("behavior_policy_rule_id")),
        }
        if finding.get("finding_id") != stable_id("finding", content):
            errors.append(f"finding ID mismatch: {_clean(finding.get('finding_id'))}")
        if content["status"] not in {"supported", "partially_supported", "insufficient_evidence"}:
            errors.append(f"finding status is invalid: {content['status']}")
        unknown_refs = set(content["evidence_refs"]) - evidence_refs
        if unknown_refs:
            errors.append(f"finding has unknown evidence refs: {sorted(unknown_refs)}")
    for hypothesis_set in value.get("hypothesis_sets") or []:
        if not isinstance(hypothesis_set, dict):
            continue
        hypothesis_ids: List[str] = []
        for hypothesis in hypothesis_set.get("hypotheses") or []:
            if not isinstance(hypothesis, dict):
                errors.append("hypothesis must be an object")
                continue
            refs = sorted({
                _clean(ref) for ref in hypothesis.get("supporting_evidence_refs") or [] if _clean(ref)
            })
            expected = stable_id("hypothesis", {
                "chain_id": next(iter({
                    _clean(ref) for ref in hypothesis_set.get("relationship_refs") or [] if _clean(ref)
                }), ""),
                "statement": _clean(hypothesis.get("statement")),
                "evidence_refs": refs,
            })
            # Older v4 builders carry the chain only in the set ID input.  Use
            # the actual ID as the authoritative integrity check below when no
            # explicit relationship reference is present.
            if hypothesis_set.get("relationship_refs") and hypothesis.get("hypothesis_id") != expected:
                errors.append(f"hypothesis ID mismatch: {_clean(hypothesis.get('hypothesis_id'))}")
            hypothesis_ids.append(_clean(hypothesis.get("hypothesis_id")))
            if set(refs) - evidence_refs:
                errors.append("hypothesis has unknown evidence refs")
        if not hypothesis_ids or any(not item for item in hypothesis_ids):
            errors.append("hypothesis set must contain identified alternatives")
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            errors.append("hypothesis IDs must be unique within a set")
        chain_id = next(iter([
            _clean(ref) for ref in hypothesis_set.get("relationship_refs") or [] if _clean(ref)
        ]), "")
        if hypothesis_set.get("hypothesis_set_id") != stable_id("hypothesis_set", {
            "chain_id": chain_id,
            "hypothesis_ids": hypothesis_ids,
        }):
            errors.append(f"hypothesis set ID mismatch: {_clean(hypothesis_set.get('hypothesis_set_id'))}")
    expected_assessment_id = canonical_assessment_id(value)
    if value.get("assessment_id") != expected_assessment_id:
        errors.append("assessment_id mismatch")
    canonical = {
        key: item for key, item in value.items()
        if key not in {"non_authoritative_context", "response_guidance_v3", "generated_at"}
    }

    def prohibited(item: Any, path: str = "") -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                child_path = f"{path}.{key}" if path else key
                if key in PROHIBITED_AUTHORITY_KEYS:
                    errors.append(f"prohibited canonical field: {child_path}")
                prohibited(child, child_path)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                prohibited(child, f"{path}[{index}]")

    prohibited(canonical)
    if raise_on_error and errors:
        raise SessionAssessmentV4Error("; ".join(errors))
    return errors


def read_legacy_session_assessment(value: Dict[str, Any]) -> Dict[str, Any]:
    """Return a display-only copy of historical v2/v3 data."""

    return {
        "schema_version": "session_assessment_legacy_adapter.v1",
        "status": "legacy_read_only",
        "source_schema_version": _clean(value.get("schema_version")) or "unknown",
        "record": deepcopy(value),
        "recomputed": False,
        "authoritative_for_new_records": False,
    }
