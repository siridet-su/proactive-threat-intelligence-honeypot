"""Knowledge-pack helpers for session-level TTP correlation.

The active correlation engine consumes normalized rules. This module lets those
rules come from multiple versioned documents: the current trusted policy,
generated/imported knowledge packs, or both. It keeps provenance and source
status visible instead of hiding scaling logic in Python code.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from production.correlation.semantics import (
    declared_confidence_semantics,
    LEGACY_CORRELATION_CONFIDENCE_SEMANTICS,
)


POLICY_SCHEMA_VERSION = "session_ttp_correlation_policy.v1"
KNOWLEDGE_PACK_SCHEMA_VERSION = "session_ttp_knowledge_pack.v1"
SUMMARY_SCHEMA_VERSION = "session_ttp_knowledge_summary.v1"
TTP_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
PROJECT_LOCAL_HEURISTIC = "PROJECT_LOCAL_HEURISTIC"
DEFAULT_TEMPORAL_SEMANTICS = "session_scoped_no_elapsed_window"
FROZEN_ATTACK_ONTOLOGY_VERSION = "14.1"
FROZEN_ATTACK_CACHE_RELATIVE_PATH = "data/feeds/mitre_attack_cache.json"

_FROZEN_ATTACK_ONTOLOGY_CACHE: Dict[str, Any] | None = None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def main_ttp_id(value: Any) -> str:
    """Return the parent ATT&CK technique ID used by the active pipeline.

    The system intentionally keeps sub-techniques out of the active TTP field
    to control scope. A source label such as T1565.001 is therefore represented
    as active TTP T1565, with the original label preserved separately.
    """

    text = _clean_text(value).upper()
    if not TTP_ID_RE.match(text):
        return text
    return text.split(".", 1)[0]


def is_subtechnique_id(value: Any) -> bool:
    text = _clean_text(value).upper()
    return bool(TTP_ID_RE.match(text) and "." in text)


def _unique(values: Iterable[Any]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        text = _clean_text(value)
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_path_list(value: Any) -> List[str]:
    if isinstance(value, (list, tuple, set)):
        return [_clean_text(item) for item in value if _clean_text(item)]
    text = _clean_text(value)
    if not text:
        return []
    separators = [",", ";"]
    parts = [text]
    for separator in separators:
        if separator in text:
            parts = text.split(separator)
            break
    return [_clean_text(item) for item in parts if _clean_text(item)]


def load_json_document(path: str | Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, dict):
        raise ValueError(f"knowledge document must contain a JSON object: {path}")
    return loaded


def _body(document: Dict[str, Any]) -> Dict[str, Any]:
    body = document.get("policy", document)
    return body if isinstance(body, dict) else {}


def _rules_from_document(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    if isinstance(document.get("rules"), list):
        return [dict(rule) for rule in document.get("rules") or [] if isinstance(rule, dict)]
    body = _body(document)
    return [dict(rule) for rule in body.get("rules") or [] if isinstance(rule, dict)]


def _normalize_condition_ttp_fields(condition: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(condition)
    if "ttp" in normalized:
        source_ttp = _clean_text(normalized.get("ttp")).upper()
        active_ttp = main_ttp_id(source_ttp)
        if source_ttp and active_ttp != source_ttp:
            normalized.setdefault("source_ttp", source_ttp)
            normalized.setdefault("source_subtechnique", source_ttp)
        normalized["ttp"] = active_ttp
    if "sequence" in normalized:
        sequence = []
        source_sequence = []
        changed = False
        for item in _as_list(normalized.get("sequence")):
            source_ttp = _clean_text(item).upper()
            active_ttp = main_ttp_id(source_ttp)
            sequence.append(active_ttp)
            source_sequence.append(source_ttp)
            changed = changed or bool(source_ttp and active_ttp != source_ttp)
        normalized["sequence"] = sequence
        if changed:
            normalized.setdefault("source_sequence", source_sequence)
    return normalized


def _normalize_conditions(conditions: Any) -> Any:
    if not isinstance(conditions, dict):
        return conditions
    normalized: Dict[str, Any] = {}
    for group, values in conditions.items():
        if group in {"all", "any", "none"}:
            normalized[group] = [
                _normalize_condition_ttp_fields(item) if isinstance(item, dict) else item
                for item in _as_list(values)
            ]
        else:
            normalized[group] = values
    return normalized


def normalize_rule_ttp(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a rule so active `ttp` is always parent/main technique ID."""

    normalized = dict(rule)
    source_ttp = _clean_text(
        normalized.get("source_ttp")
        or normalized.get("source_subtechnique")
        or normalized.get("source_technique_id")
        or normalized.get("ttp")
    ).upper()
    active_ttp = main_ttp_id(source_ttp)
    if active_ttp:
        normalized["ttp"] = active_ttp
    if source_ttp and active_ttp and source_ttp != active_ttp:
        normalized.setdefault("source_ttp", source_ttp)
        normalized.setdefault("source_subtechnique", source_ttp)
        normalized.setdefault("technique_granularity", "subtechnique_collapsed")
    elif active_ttp:
        normalized.setdefault("technique_granularity", "parent")

    metadata = normalized.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    if source_ttp and source_ttp != active_ttp:
        metadata.setdefault("source_ttp", source_ttp)
        metadata.setdefault("source_subtechnique", source_ttp)
        metadata.setdefault("active_ttp", active_ttp)
        metadata.setdefault("active_ttp_granularity", "parent")
    elif active_ttp:
        metadata.setdefault("active_ttp", active_ttp)
        metadata.setdefault("active_ttp_granularity", "parent")
    if metadata:
        normalized["metadata"] = metadata

    if "conditions" in normalized:
        normalized["conditions"] = _normalize_conditions(normalized.get("conditions"))
    return normalized


def _frozen_attack_cache_candidates() -> List[Path]:
    """Return repository-local frozen ontology paths without global assumptions."""

    return [
        Path.cwd() / FROZEN_ATTACK_CACHE_RELATIVE_PATH,
        Path(__file__).resolve().parents[2] / FROZEN_ATTACK_CACHE_RELATIVE_PATH,
    ]


def _load_frozen_attack_ontology() -> Dict[str, Any]:
    """Load the retained ATT&CK v14.1 cache for optional-pack status checks.

    The cache is only used to annotate generated/optional rules.  It never
    promotes a rule or changes the trusted command-level authority path.
    Missing or malformed cache data is represented as ``unresolved`` so a
    generated rule cannot silently appear ontology-verified.
    """

    global _FROZEN_ATTACK_ONTOLOGY_CACHE
    if _FROZEN_ATTACK_ONTOLOGY_CACHE is not None:
        return _FROZEN_ATTACK_ONTOLOGY_CACHE
    for candidate in _frozen_attack_cache_candidates():
        try:
            document = load_json_document(candidate)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        techniques = document.get("techniques")
        if not isinstance(techniques, dict):
            continue
        _FROZEN_ATTACK_ONTOLOGY_CACHE = {
            "status": "available",
            "version": _clean_text(document.get("_version")),
            "path": FROZEN_ATTACK_CACHE_RELATIVE_PATH,
            "sha256": file_sha256(candidate),
            "ids": {str(value).strip().upper() for value in techniques},
        }
        return _FROZEN_ATTACK_ONTOLOGY_CACHE
    _FROZEN_ATTACK_ONTOLOGY_CACHE = {
        "status": "unavailable",
        "version": "",
        "path": FROZEN_ATTACK_CACHE_RELATIVE_PATH,
        "sha256": "",
        "ids": set(),
    }
    return _FROZEN_ATTACK_ONTOLOGY_CACHE


def _optional_rule_ontology_binding(
    rule: Dict[str, Any],
    document_type: str,
) -> Dict[str, Any]:
    """Annotate optional generated rules against the frozen ontology.

    Policy rules are already governed by the reviewed local policy and do not
    need this optional-pack status marker.  Generated rules are always
    contextual/non-authoritative; an unknown ID remains visible for audit but
    is explicitly marked as an ontology mismatch or unresolved.
    """

    if document_type != "knowledge_pack":
        return {}
    source_ttp = _clean_text(
        rule.get("source_ttp")
        or rule.get("source_subtechnique")
        or rule.get("source_technique_id")
        or rule.get("ttp")
    ).upper()
    active_ttp = main_ttp_id(source_ttp)
    ontology = _load_frozen_attack_ontology()
    status = "unresolved"
    if not source_ttp or not TTP_ID_RE.fullmatch(source_ttp):
        status = "invalid_identifier"
    elif ontology.get("status") != "available":
        status = "unresolved"
    elif _clean_text(ontology.get("version")) != FROZEN_ATTACK_ONTOLOGY_VERSION:
        status = "ontology_version_mismatch"
    elif source_ttp in ontology.get("ids", set()):
        status = "verified_frozen_v14_1"
    else:
        status = "ontology_mismatch"
    return {
        "ontology": "MITRE ATT&CK",
        "expected_version": FROZEN_ATTACK_ONTOLOGY_VERSION,
        "observed_version": _clean_text(ontology.get("version")),
        "cache_path": FROZEN_ATTACK_CACHE_RELATIVE_PATH,
        "cache_sha256": _clean_text(ontology.get("sha256")),
        "source_ttp": source_ttp,
        "active_ttp": active_ttp,
        "status": status,
        "authority_effect": "contextual_only_non_authoritative",
    }


def _document_identity(document: Dict[str, Any], source_path: str = "") -> Dict[str, Any]:
    schema = _clean_text(document.get("schema_version"))
    if schema == KNOWLEDGE_PACK_SCHEMA_VERSION:
        return {
            "document_type": "knowledge_pack",
            "document_id": _clean_text(document.get("pack_id") or document.get("policy_id") or source_path),
            "version": _clean_text(document.get("version")),
            "source_path": source_path,
        }
    return {
        "document_type": "policy",
        "document_id": _clean_text(document.get("policy_id") or source_path),
        "version": _clean_text(document.get("version")),
        "source_path": source_path,
    }


def normalize_correlation_document(document: Dict[str, Any], source_path: str = "") -> Dict[str, Any]:
    """Return a policy-shaped document with rule source metadata preserved."""

    identity = _document_identity(document, source_path)
    schema = _clean_text(document.get("schema_version")) or POLICY_SCHEMA_VERSION
    body = _body(document)
    enabled = bool(body.get("enabled", True))
    confidence_semantics = declared_confidence_semantics(
        body.get("confidence_semantics")
    )
    numeric_provenance = _clean_text(
        body.get("numeric_provenance") or PROJECT_LOCAL_HEURISTIC
    )
    temporal_semantics = _clean_text(
        body.get("temporal_semantics") or DEFAULT_TEMPORAL_SEMANTICS
    )
    output_contract = body.get("correlation_output_contract")
    if not isinstance(output_contract, dict):
        output_contract = {
            "observed_namespace": "observed_trusted_ttps",
            "context_namespace": "correlated_ttp_hypotheses",
            "authority": "non_authoritative",
            "can_override_observed": False,
            "can_remove_observed": False,
            "can_promote_trusted": False,
            "may_drive_prediction": False,
            "may_authorize_response": False,
            "canonical_write_allowed": False,
        }
    rules: List[Dict[str, Any]] = []
    for rule in _rules_from_document(document):
        normalized = normalize_rule_ttp(rule)
        normalized.setdefault("enabled", True)
        normalized.setdefault("source_document_type", identity["document_type"])
        normalized.setdefault("source_document_id", identity["document_id"])
        normalized.setdefault("source_document_version", identity["version"])
        normalized.setdefault("source_document_path", source_path)
        normalized.setdefault("numeric_provenance", numeric_provenance)
        ontology_binding = _optional_rule_ontology_binding(
            normalized,
            identity["document_type"],
        )
        if ontology_binding:
            normalized.setdefault("ontology_binding", ontology_binding)
            normalized.setdefault("ontology_status", ontology_binding["status"])
            normalized.setdefault("optional_pack_status", "UNREVIEWED_OPTIONAL_PACK")
            normalized.setdefault("authority_eligibility", "CONTEXTUAL_ONLY")
        if identity["document_type"] == "knowledge_pack":
            normalized.setdefault("knowledge_pack_id", identity["document_id"])
        else:
            normalized.setdefault("source_policy_id", identity["document_id"])
        rules.append(normalized)

    import_status = document.get("import_status") or body.get("import_status") or {}
    if not isinstance(import_status, dict):
        import_status = {}
    source_artifacts = document.get("source_artifacts") or body.get("source_artifacts") or []
    if not isinstance(source_artifacts, list):
        source_artifacts = []

    normalized_document = {
        "schema_version": POLICY_SCHEMA_VERSION,
        "source_schema_version": schema,
        "policy_id": identity["document_id"],
        "version": identity["version"],
        "updated_at": document.get("updated_at") or document.get("generated_at") or "",
        "owner": document.get("owner") or body.get("owner") or "",
        "policy": {
            "enabled": enabled,
            "confidence_semantics": confidence_semantics,
            "numeric_provenance": numeric_provenance,
            "temporal_semantics": temporal_semantics,
            "correlation_output_contract": dict(output_contract),
            "rules": rules,
        },
        "knowledge_summary": {
            "schema_version": SUMMARY_SCHEMA_VERSION,
            "document_type": identity["document_type"],
            "document_id": identity["document_id"],
            "document_version": identity["version"],
            "source_path": source_path,
            "rule_count": len(rules),
            "enabled_rule_count": sum(1 for rule in rules if bool(rule.get("enabled", True))),
            "knowledge_pack_ids": [identity["document_id"]] if identity["document_type"] == "knowledge_pack" else [],
            "policy_ids": [identity["document_id"]] if identity["document_type"] == "policy" else [],
            "import_status": import_status,
            "source_artifacts": source_artifacts,
            "confidence_semantics": confidence_semantics,
            "numeric_provenance": numeric_provenance,
            "temporal_semantics": temporal_semantics,
            "correlation_output_contract": dict(output_contract),
            **summarize_rules(rules),
        },
    }
    return normalized_document


def summarize_rules(rules: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    source_type_counts: Dict[str, int] = {}
    evidence_type_counts: Dict[str, int] = {}
    manual_rule_count = 0
    generated_rule_count = 0
    generated_prediction_rule_count = 0
    unreviewed_generated_rule_count = 0
    prediction_influence_rule_count = 0
    source_document_counts: Dict[str, int] = {}
    ontology_status_counts: Dict[str, int] = {}
    for rule in rules:
        source_type = _clean_text(rule.get("source_type") or "unknown")
        evidence_type = _clean_text(rule.get("evidence_type") or "unknown")
        source_type_counts[source_type] = source_type_counts.get(source_type, 0) + 1
        evidence_type_counts[evidence_type] = evidence_type_counts.get(evidence_type, 0) + 1
        if bool(rule.get("apply_to_prediction")):
            prediction_influence_rule_count += 1
        provenance = rule.get("provenance") or {}
        if isinstance(provenance, dict) and provenance.get("generated"):
            generated_rule_count += 1
            if bool(rule.get("apply_to_prediction")):
                generated_prediction_rule_count += 1
            if not provenance.get("reviewed"):
                unreviewed_generated_rule_count += 1
        else:
            manual_rule_count += 1
        doc_type = _clean_text(rule.get("source_document_type") or "policy")
        source_document_counts[doc_type] = source_document_counts.get(doc_type, 0) + 1
        ontology_status = _clean_text(rule.get("ontology_status"))
        if ontology_status:
            ontology_status_counts[ontology_status] = ontology_status_counts.get(ontology_status, 0) + 1
    return {
        "manual_rule_count": manual_rule_count,
        "generated_rule_count": generated_rule_count,
        "unreviewed_generated_rule_count": unreviewed_generated_rule_count,
        "prediction_influence_rule_count": prediction_influence_rule_count,
        "generated_prediction_rule_count": generated_prediction_rule_count,
        "source_type_counts": source_type_counts,
        "evidence_type_counts": evidence_type_counts,
        "source_document_counts": source_document_counts,
        "ontology_status_counts": ontology_status_counts,
    }


def combine_correlation_documents(documents: Iterable[Tuple[Dict[str, Any], str]]) -> Dict[str, Any]:
    normalized_docs = [normalize_correlation_document(document, source_path) for document, source_path in documents]
    if not normalized_docs:
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "policy_id": "disabled",
            "version": "0",
            "policy": {
                "enabled": False,
                "confidence_semantics": LEGACY_CORRELATION_CONFIDENCE_SEMANTICS,
                "numeric_provenance": PROJECT_LOCAL_HEURISTIC,
                "temporal_semantics": DEFAULT_TEMPORAL_SEMANTICS,
                "rules": [],
            },
            "knowledge_summary": {
                "schema_version": SUMMARY_SCHEMA_VERSION,
                "status": "disabled",
                "rule_count": 0,
                "enabled_rule_count": 0,
                "manual_rule_count": 0,
                "generated_rule_count": 0,
                "unreviewed_generated_rule_count": 0,
                "prediction_influence_rule_count": 0,
                "generated_prediction_rule_count": 0,
                "source_type_counts": {},
                "evidence_type_counts": {},
                "knowledge_pack_ids": [],
                "policy_ids": [],
                "import_status": {},
                "source_artifacts": [],
                "confidence_semantics": LEGACY_CORRELATION_CONFIDENCE_SEMANTICS,
                "numeric_provenance": PROJECT_LOCAL_HEURISTIC,
                "temporal_semantics": DEFAULT_TEMPORAL_SEMANTICS,
            },
        }

    combined_rules: List[Dict[str, Any]] = []
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    policy_ids: List[str] = []
    pack_ids: List[str] = []
    import_status: Dict[str, Any] = {}
    source_artifacts: List[Any] = []
    versions: List[str] = []
    semantics_values: List[str] = []
    numeric_provenance_values: List[str] = []
    output_contracts: List[Dict[str, Any]] = []
    enabled = False
    for document in normalized_docs:
        body = _body(document)
        rules = [dict(rule) for rule in body.get("rules") or [] if isinstance(rule, dict)]
        for rule in rules:
            rule_id = _clean_text(rule.get("rule_id"))
            dedupe_key = rule_id or json.dumps(
                {
                    "ttp": rule.get("ttp"),
                    "tactic": rule.get("tactic"),
                    "conditions": rule.get("conditions"),
                },
                sort_keys=True,
            )
            existing = rules_by_id.get(dedupe_key)
            if not existing:
                rules_by_id[dedupe_key] = rule
                continue
            existing_is_pack = existing.get("source_document_type") == "knowledge_pack"
            new_is_pack = rule.get("source_document_type") == "knowledge_pack"
            if new_is_pack and not existing_is_pack:
                rules_by_id[dedupe_key] = rule
        enabled = enabled or bool(body.get("enabled", True))
        summary = document.get("knowledge_summary") or {}
        policy_ids.extend(summary.get("policy_ids") or [])
        pack_ids.extend(summary.get("knowledge_pack_ids") or [])
        versions.append(_clean_text(document.get("version")))
        semantics_values.append(
            declared_confidence_semantics(
                (body.get("confidence_semantics") if isinstance(body, dict) else None)
            )
        )
        numeric_provenance_values.append(
            _clean_text(
                body.get("numeric_provenance") or PROJECT_LOCAL_HEURISTIC
            )
        )
        contract = body.get("correlation_output_contract")
        if isinstance(contract, dict):
            output_contracts.append(dict(contract))
        source_artifacts.extend(summary.get("source_artifacts") or [])
        for key, value in (summary.get("import_status") or {}).items():
            import_status[key] = value

    combined_rules = list(rules_by_id.values())
    combined_semantics = (
        semantics_values[0]
        if semantics_values and all(value == semantics_values[0] for value in semantics_values)
        else LEGACY_CORRELATION_CONFIDENCE_SEMANTICS
    )
    combined_numeric_provenance = (
        numeric_provenance_values[0]
        if numeric_provenance_values
        and all(value == numeric_provenance_values[0] for value in numeric_provenance_values)
        else PROJECT_LOCAL_HEURISTIC
    )
    combined_output_contract = (
        dict(output_contracts[0])
        if output_contracts and all(value == output_contracts[0] for value in output_contracts)
        else {
            "observed_namespace": "observed_trusted_ttps",
            "context_namespace": "correlated_ttp_hypotheses",
            "authority": "non_authoritative",
            "can_override_observed": False,
            "can_remove_observed": False,
            "can_promote_trusted": False,
            "may_drive_prediction": False,
            "may_authorize_response": False,
            "canonical_write_allowed": False,
        }
    )
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_id": "combined-session-ttp-knowledge",
        "version": "+".join(_unique(versions)) or "combined",
        "policy": {
            "enabled": enabled,
            "confidence_semantics": combined_semantics,
            "numeric_provenance": combined_numeric_provenance,
            "temporal_semantics": DEFAULT_TEMPORAL_SEMANTICS,
            "correlation_output_contract": combined_output_contract,
            "rules": combined_rules,
        },
        "knowledge_summary": {
            "schema_version": SUMMARY_SCHEMA_VERSION,
            "status": "combined",
            "source_document_count": len(normalized_docs),
            "rule_count": len(combined_rules),
            "enabled_rule_count": sum(1 for rule in combined_rules if bool(rule.get("enabled", True))),
            "policy_ids": _unique(policy_ids),
            "knowledge_pack_ids": _unique(pack_ids),
            "import_status": import_status,
            "source_artifacts": source_artifacts,
            "confidence_semantics": combined_semantics,
            "numeric_provenance": combined_numeric_provenance,
            "temporal_semantics": DEFAULT_TEMPORAL_SEMANTICS,
            "correlation_output_contract": combined_output_contract,
            **summarize_rules(combined_rules),
        },
    }


def load_correlation_knowledge(
    policy_path: str = "",
    knowledge_pack_paths: Any = None,
) -> Dict[str, Any]:
    documents: List[Tuple[Dict[str, Any], str]] = []
    if _clean_text(policy_path):
        documents.append((load_json_document(policy_path), _clean_text(policy_path)))
    for path in parse_path_list(knowledge_pack_paths):
        documents.append((load_json_document(path), path))
    return combine_correlation_documents(documents)


def source_artifact_status(path_text: str, source_type: str) -> Dict[str, Any]:
    path = Path(path_text) if path_text else Path()
    status: Dict[str, Any] = {
        "source_type": source_type,
        "path": path_text,
        "exists": bool(path_text and path.exists()),
    }
    if path_text and path.exists() and path.is_file():
        status["artifact_sha256"] = file_sha256(path)
        status["bytes"] = path.stat().st_size
    return status


def env_path_list(name: str, default: Any = None) -> List[str]:
    raw = os.getenv(name)
    if raw is None:
        return parse_path_list(default)
    return parse_path_list(raw)
