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


POLICY_SCHEMA_VERSION = "session_ttp_correlation_policy.v1"
KNOWLEDGE_PACK_SCHEMA_VERSION = "session_ttp_knowledge_pack.v1"
SUMMARY_SCHEMA_VERSION = "session_ttp_knowledge_summary.v1"
TTP_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


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
    rules: List[Dict[str, Any]] = []
    for rule in _rules_from_document(document):
        normalized = normalize_rule_ttp(rule)
        normalized.setdefault("enabled", True)
        normalized.setdefault("source_document_type", identity["document_type"])
        normalized.setdefault("source_document_id", identity["document_id"])
        normalized.setdefault("source_document_version", identity["version"])
        normalized.setdefault("source_document_path", source_path)
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
    return {
        "manual_rule_count": manual_rule_count,
        "generated_rule_count": generated_rule_count,
        "unreviewed_generated_rule_count": unreviewed_generated_rule_count,
        "prediction_influence_rule_count": prediction_influence_rule_count,
        "generated_prediction_rule_count": generated_prediction_rule_count,
        "source_type_counts": source_type_counts,
        "evidence_type_counts": evidence_type_counts,
        "source_document_counts": source_document_counts,
    }


def combine_correlation_documents(documents: Iterable[Tuple[Dict[str, Any], str]]) -> Dict[str, Any]:
    normalized_docs = [normalize_correlation_document(document, source_path) for document, source_path in documents]
    if not normalized_docs:
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "policy_id": "disabled",
            "version": "0",
            "policy": {"enabled": False, "rules": []},
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
            },
        }

    combined_rules: List[Dict[str, Any]] = []
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    policy_ids: List[str] = []
    pack_ids: List[str] = []
    import_status: Dict[str, Any] = {}
    source_artifacts: List[Any] = []
    versions: List[str] = []
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
        source_artifacts.extend(summary.get("source_artifacts") or [])
        for key, value in (summary.get("import_status") or {}).items():
            import_status[key] = value

    combined_rules = list(rules_by_id.values())
    return {
        "schema_version": POLICY_SCHEMA_VERSION,
        "policy_id": "combined-session-ttp-knowledge",
        "version": "+".join(_unique(versions)) or "combined",
        "policy": {
            "enabled": enabled,
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
