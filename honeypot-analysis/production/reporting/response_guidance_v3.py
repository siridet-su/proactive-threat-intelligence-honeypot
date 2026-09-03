"""Deterministic, evidence-bounded advisory response guidance v3.

This module is intentionally independent of ``smb_decision``.  Only the
immutable canonical observed-behaviour snapshot and a content-addressed,
reviewed policy may select a finding, triage value, or advisory task.  Model
forecasts and enrichment are copied into a clearly non-authoritative context
section and are excluded from selection and identity calculation.
"""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from production.policies.validate_response_guidance_policy import (
    SCHEMA_VERSION as POLICY_SCHEMA_VERSION,
    validate_response_guidance_asset_profile,
    validate_response_guidance_policy,
)
from production.reporting.canonical_semantic_graph import (
    validate_canonical_semantic_graph,
)
from production.reporting.typed_semantic_family_selection import (
    policy_output_trace,
    select_activated_semantic_family,
    validate_policy_output_trace,
)
from production.utils.serialization import stable_id, stable_json, utc_now


SCHEMA_VERSION = "response_guidance.v3"
CANONICAL_EVIDENCE_SCHEMA_VERSION = "response_guidance_evidence.v1"
LEGACY_ADAPTER_SCHEMA_VERSION = "response_guidance_legacy_adapter.v1"
BINDING_SCHEMA_VERSION = "response_guidance_binding.v1"
DURABLE_PREFIX_SCHEMA_VERSION = "response_guidance_durable_prefix.v1"
REFERENCE_RESOLUTION_SCHEMA_VERSION = "response_guidance_reference_resolution.v1"
CANONICAL_EVIDENCE_SCOPE = "observed_behavior"
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "configs" / "response_guidance_policy.v3.json"
CURRENT_ACTIVATED_SEMANTIC_FAMILIES = (
    "sensitive_read",
    "transfer",
    "transfer_attempt",
    "inspection",
    "filesystem",
    "execution",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _texts(values: Iterable[Any]) -> List[str]:
    output: List[str] = []
    for value in values or []:
        text = _clean(value)
        if text and text not in output:
            output.append(text)
    return output


def _canonical_text_list(values: Any) -> List[str]:
    """Deduplicate text while retaining its observed order."""

    return _texts(values if isinstance(values, (list, tuple, set)) else [values])


def _normalized_entity_values(values: Any) -> List[str]:
    """Cross the sole entity-to-display boundary without rendering mappings."""

    output: List[str] = []
    candidates = values if isinstance(values, (list, tuple, set)) else [values]
    for value in candidates:
        if isinstance(value, str):
            normalized = _clean(value)
        elif isinstance(value, dict):
            if (
                not _clean(value.get("entity_type"))
                or value.get("uncertain") is True
                or value.get("linkable") is not True
            ):
                continue
            normalized = _clean(value.get("normalized_value"))
        else:
            continue
        if normalized and normalized not in output:
            output.append(normalized)
    return output


def _canonical_mapping(mapping: Any) -> Dict[str, Any]:
    """Keep the observed fields v3 may display, hash, or evaluate.

    In particular this intentionally discards classifier confidence, scores,
    source reputation, forecast fields, generated prose, and mutable metadata.
    Those values cannot change a v3 guidance ID merely by being attached to a
    session's broader reporting object.
    """

    if not isinstance(mapping, dict):
        return {}
    output: Dict[str, Any] = {}
    for key in (
        "evidence_id",
        "evidence_ref",
        "tactic",
        "ttp",
        "technique_id",
        "eventid",
        "timestamp",
        "command_outcome",
        "sha256",
    ):
        value = _clean(mapping.get(key))
        if value:
            output[key] = value
    if isinstance(mapping.get("sequence_index"), int) and not isinstance(mapping.get("sequence_index"), bool):
        output["sequence_index"] = mapping["sequence_index"]
    if mapping.get("transfer_observed") is True:
        output["transfer_observed"] = True
    for key in ("evidence_refs", "source_evidence_refs", "action_types"):
        values = _canonical_text_list(mapping.get(key))
        if values:
            output[key] = values
    entities = mapping.get("entities")
    if isinstance(entities, dict):
        canonical_entities = {
            _clean(entity_type): _normalized_entity_values(entity_values)
            for entity_type, entity_values in entities.items()
            if _clean(entity_type) and _normalized_entity_values(entity_values)
        }
        if canonical_entities:
            output["entities"] = canonical_entities
    mappings = []
    for item in mapping.get("trusted_attck_mappings") or []:
        canonical_item = _canonical_mapping(item)
        if canonical_item:
            mappings.append(canonical_item)
    if mappings:
        output["trusted_attck_mappings"] = mappings
    return output


def _canonical_mapping_list(values: Any) -> List[Dict[str, Any]]:
    output = []
    for item in values or []:
        canonical_item = _canonical_mapping(item)
        if canonical_item:
            output.append(canonical_item)
    return output


def _sha256_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _document_sha256(document: Mapping[str, Any]) -> str:
    return _sha256_bytes(stable_json(document).encode("utf-8"))


def _valid_sha256(value: Any) -> bool:
    return SHA256_RE.fullmatch(_clean(value).lower()) is not None


def _hash_without_key(value: Mapping[str, Any], key: str) -> str:
    copied = deepcopy(dict(value))
    copied.pop(key, None)
    return _document_sha256(copied)


def _path_label(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return path.name


def _configured_path(path_text: str, default: Path) -> Path:
    """Resolve configured relative paths from the repository package root."""

    if not _clean(path_text):
        return default
    candidate = Path(path_text)
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


def _evidence_refs_from_item(item: Mapping[str, Any]) -> Set[str]:
    refs: Set[str] = set()
    for key in ("evidence_id", "evidence_ref"):
        if _clean(item.get(key)):
            refs.add(_clean(item.get(key)))
    for key in (
        "evidence_refs",
        "source_evidence_refs",
        "classification_event_refs",
        "command_evidence_refs",
    ):
        refs.update(_texts(item.get(key) or []))
    for mapping in item.get("trusted_attck_mappings") or []:
        if isinstance(mapping, dict) and _clean(mapping.get("evidence_ref")):
            refs.add(_clean(mapping.get("evidence_ref")))
    return refs


def canonical_evidence_snapshot(observed_behavior: Any) -> Dict[str, Any]:
    """Copy only canonical observed-behaviour fields into a stable snapshot.

    The returned data is the v3 evaluator's entire selection input.  It
    deliberately omits model forecasts, enrichment, report recommendations,
    asset context, and mutable runtime policy metadata.
    """

    observed = observed_behavior if isinstance(observed_behavior, dict) else {}
    if observed.get("schema_version") == "canonical_evidence_snapshot.v3":
        snapshot = json.loads(stable_json(observed))
        recorded = _clean(snapshot.get("evidence_sha256")).lower()
        copied = deepcopy(snapshot)
        copied.pop("evidence_sha256", None)
        if len(recorded) != 64 or recorded != _document_sha256(copied):
            raise ValueError("canonical evidence v3 digest is inconsistent")
        graph_errors = validate_canonical_semantic_graph(
            snapshot.get("semantic_graph")
        )
        if graph_errors:
            raise ValueError(
                "canonical evidence v3 semantic graph is invalid: "
                + "; ".join(graph_errors)
            )
        return snapshot
    if observed.get("schema_version") in {
        "canonical_evidence_snapshot.v1",
        "canonical_evidence_snapshot.v2",
    }:
        snapshot = json.loads(stable_json(observed))
        recorded = _clean(snapshot.get("evidence_sha256")).lower()
        hash_input = deepcopy(snapshot)
        hash_input.pop("evidence_sha256", None)
        if (
            len(recorded) != 64
            or any(character not in "0123456789abcdef" for character in recorded)
            or recorded != _document_sha256(hash_input)
        ):
            raise ValueError("canonical evidence snapshot digest is inconsistent")
        return snapshot
    snapshot = {
        "schema_version": CANONICAL_EVIDENCE_SCHEMA_VERSION,
        "session_id": _clean(observed.get("session_id")) or "unknown",
        "src_ip": _clean(observed.get("src_ip")),
        "ordered_behavior_chain": _canonical_mapping_list(observed.get("ordered_behavior_chain")),
        "ordered_command_observations": _canonical_mapping_list(observed.get("ordered_command_observations")),
        "cowrie_event_evidence": _canonical_mapping_list(observed.get("cowrie_event_evidence")),
        "transfer_event_observations": _canonical_mapping_list(observed.get("transfer_event_observations")),
        "trusted_attck_candidates": _canonical_mapping_list(observed.get("trusted_attck_candidates")),
        "observed_trusted_ttps": _canonical_mapping_list(
            observed.get("observed_trusted_ttps")
        ),
        "connected_behavior_chains": _canonical_mapping_list(observed.get("connected_behavior_chains")),
        "behavior_relationships": _canonical_mapping_list(observed.get("behavior_relationships")),
    }
    return json.loads(stable_json(snapshot))


def canonical_evidence_sha256(observed_behavior: Any) -> str:
    snapshot = canonical_evidence_snapshot(observed_behavior)
    if snapshot.get("schema_version") == "canonical_evidence_snapshot.v3":
        return _clean(snapshot.get("evidence_sha256")).lower()
    if snapshot.get("schema_version") in {
        "canonical_evidence_snapshot.v1",
        "canonical_evidence_snapshot.v2",
    }:
        return _clean(snapshot.get("evidence_sha256")).lower()
    return _document_sha256(snapshot)


def _snapshot_values(
    snapshot: Mapping[str, Any],
    legacy_name: str,
    canonical_name: str,
) -> Any:
    if snapshot.get("schema_version") in {
        "canonical_evidence_snapshot.v1",
        "canonical_evidence_snapshot.v2",
        "canonical_evidence_snapshot.v3",
    }:
        return snapshot.get(canonical_name) or []
    return snapshot.get(legacy_name) or []


def canonical_behavioral_evidence_refs(observed_behavior: Any) -> Set[str]:
    """Return evidence IDs from the immutable v3 observed-evidence snapshot."""

    snapshot = canonical_evidence_snapshot(observed_behavior)
    refs: Set[str] = set()
    for legacy_name, canonical_name in (
        ("ordered_behavior_chain", "connected_behavior_chains"),
        ("ordered_command_observations", "observations"),
        ("cowrie_event_evidence", "direct_cowrie_events"),
        ("transfer_event_observations", "transfer_observations"),
        ("trusted_attck_candidates", "trusted_attck_candidates"),
        ("observed_trusted_ttps", "observed_trusted_ttps"),
        ("connected_behavior_chains", "connected_behavior_chains"),
        ("behavior_relationships", "relationships"),
    ):
        for item in _snapshot_values(snapshot, legacy_name, canonical_name):
            if isinstance(item, dict):
                refs.update(_evidence_refs_from_item(item))
    return refs


def canonical_transfer_evidence_refs(
    observed_behavior: Any,
) -> Set[str]:
    """Return only direct Cowrie transfer-observation evidence IDs."""

    snapshot = canonical_evidence_snapshot(observed_behavior)
    return {
        _clean(item.get("evidence_id"))
        for item in _snapshot_values(
            snapshot,
            "transfer_event_observations",
            "transfer_observations",
        )
        if isinstance(item, dict) and _clean(item.get("evidence_id"))
    }


def _selection_set_sha256(
    *,
    fact_set_sha256: str,
    semantic_vocabulary_sha256: str,
    family_selection_sha256s: Mapping[str, str],
) -> str:
    if (
        not _clean(fact_set_sha256)
        or not _clean(semantic_vocabulary_sha256)
        or not family_selection_sha256s
    ):
        return ""
    return _document_sha256({
        "schema_version": "typed_semantic_selection_set.v1",
        "fact_set_sha256": _clean(fact_set_sha256),
        "semantic_vocabulary_sha256": _clean(
            semantic_vocabulary_sha256
        ),
        "family_selection_sha256s": {
            family: _clean(family_selection_sha256s[family])
            for family in sorted(family_selection_sha256s)
        },
    })


def _mapping_values(snapshot: Dict[str, Any]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    tactics: Dict[str, Set[str]] = {}
    ttps: Dict[str, Set[str]] = {}

    def add(tactic: Any, ttp: Any, refs: Set[str]) -> None:
        tactic_text = _clean(tactic).lower()
        ttp_text = _clean(ttp).upper()
        if tactic_text:
            tactics.setdefault(tactic_text, set()).update(refs)
        if ttp_text:
            ttps.setdefault(ttp_text, set()).update(refs)

    for item in _snapshot_values(
        snapshot, "trusted_attck_candidates", "trusted_attck_candidates"
    ):
        if isinstance(item, dict):
            add(item.get("tactic"), item.get("technique_id") or item.get("ttp"), _evidence_refs_from_item(item))
    for item in _snapshot_values(
        snapshot, "ordered_behavior_chain", "connected_behavior_chains"
    ):
        if isinstance(item, dict):
            add(item.get("tactic"), item.get("ttp"), _evidence_refs_from_item(item))
    for observation in _snapshot_values(
        snapshot, "ordered_command_observations", "observations"
    ):
        if not isinstance(observation, dict):
            continue
        refs = _evidence_refs_from_item(observation)
        for mapping in observation.get("trusted_attck_mappings") or []:
            if isinstance(mapping, dict):
                add(mapping.get("tactic"), mapping.get("ttp"), refs | _evidence_refs_from_item(mapping))
    return tactics, ttps


def _observed_facts(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    all_refs = canonical_behavioral_evidence_refs(snapshot)
    tactics, ttps = _mapping_values(snapshot)
    command_observations = _snapshot_values(
        snapshot, "ordered_command_observations", "observations"
    )
    command_refs: Set[str] = set()
    entities: Dict[str, Set[str]] = {
        "account_names": set(),
        "artifact_hashes": set(),
        "credential_paths": set(),
        "deleted_paths": set(),
        "destination_paths": set(),
        "executed_paths": set(),
        "modified_paths": set(),
        "source_paths": set(),
        "urls": set(),
    }
    action_types: Dict[str, Set[str]] = {}
    for observation in command_observations:
        if not isinstance(observation, dict):
            continue
        refs = _evidence_refs_from_item(observation)
        command_refs.update(refs)
        for action_type in _texts(observation.get("action_types") or []):
            action_types.setdefault(action_type.lower(), set()).update(refs)
        for entity_type, values in (observation.get("entities") or {}).items():
            if entity_type not in entities:
                continue
            entities[entity_type].update(_normalized_entity_values(values or []))
    transfer_refs: Set[str] = set()
    for observation in _snapshot_values(
        snapshot, "transfer_event_observations", "transfer_observations"
    ):
        if isinstance(observation, dict):
            transfer_refs.update(_evidence_refs_from_item(observation))
    return {
        "evidence_refs": all_refs,
        "tactics": tactics,
        "ttps": ttps,
        "action_types": action_types,
        "command_count": len(command_observations),
        "command_refs": command_refs,
        "flags": {
            "has_commands": bool(command_observations),
            "has_cowrie_transfer_event": bool(transfer_refs),
        },
        "flag_refs": {
            "has_commands": command_refs,
            "has_cowrie_transfer_event": transfer_refs,
        },
        "entities": {key: sorted(values) for key, values in entities.items()},
    }


def _condition_match(condition: Any, facts: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]], List[str]]:
    if not isinstance(condition, dict) or not condition:
        return False, [], []
    traces: List[Dict[str, Any]] = []
    evidence_refs: Set[str] = set()

    def values_match(key: str, source: Dict[str, Set[str]], *, all_required: bool) -> bool:
        requested = [_clean(value) for value in condition.get(key) or []]
        requested = [value.lower() if key.endswith("tactics") or key == "any_action_types" else value.upper() if key.endswith("ttps") else value for value in requested]
        available = set(source)
        matched = [value for value in requested if value in available]
        result = len(matched) == len(requested) if all_required else bool(matched)
        refs = sorted({ref for value in matched for ref in source.get(value, set())})
        traces.append({"predicate": key, "expected": requested, "matched": matched, "result": result, "evidence_refs": refs})
        evidence_refs.update(refs)
        return result

    for key, source, all_required in (
        ("all_tactics", facts["tactics"], True),
        ("any_tactics", facts["tactics"], False),
        ("all_ttps", facts["ttps"], True),
        ("any_ttps", facts["ttps"], False),
        ("all_claim_types", {}, True),
        ("any_claim_types", {}, False),
        ("any_action_types", facts["action_types"], False),
    ):
        if key in condition and not values_match(key, source, all_required=all_required):
            return False, traces, sorted(evidence_refs)

    for key, expected in (("required_flags", True), ("absent_flags", False)):
        if key not in condition:
            continue
        requested = _texts(condition.get(key) or [])
        matched = [flag for flag in requested if facts["flags"].get(flag) is expected]
        result = len(matched) == len(requested)
        refs = sorted({ref for flag in matched for ref in facts["flag_refs"].get(flag, set())})
        traces.append({"predicate": key, "expected": requested, "matched": matched, "result": result, "evidence_refs": refs})
        evidence_refs.update(refs)
        if not result:
            return False, traces, sorted(evidence_refs)

    if "min_command_count" in condition:
        expected = int(condition["min_command_count"])
        result = facts["command_count"] >= expected
        refs = sorted(facts["command_refs"])
        traces.append({"predicate": "min_command_count", "expected": expected, "actual": facts["command_count"], "result": result, "evidence_refs": refs})
        evidence_refs.update(refs)
        if not result:
            return False, traces, sorted(evidence_refs)
    return bool(evidence_refs), traces, sorted(evidence_refs)


def _safe_template(template: Any, values: Mapping[str, str]) -> str:
    class _SafeValues(dict[str, str]):
        def __missing__(self, key: str) -> str:
            return "not observed"

    try:
        return _clean(template).format_map(_SafeValues(values))
    except (KeyError, ValueError):
        return _clean(template)


def _context_values(snapshot: Dict[str, Any], facts: Dict[str, Any]) -> Dict[str, str]:
    """Return template values only from the canonical evidence snapshot."""

    values = {key: ", ".join(item) if item else "not observed" for key, item in facts["entities"].items()}
    values.update({
        "src_ip": _clean(snapshot.get("src_ip")) or "not observed",
        "session_id": _clean(snapshot.get("session_id")) or "unknown",
    })
    return values


def _policy_metadata(
    document: Dict[str, Any],
    digest: str,
    source: str,
    status: str,
    errors: List[str],
    *,
    path: str = "",
    document_sha256: str = "",
) -> Dict[str, Any]:
    return {
        "schema_version": _clean(document.get("schema_version")),
        "policy_id": _clean(document.get("policy_id")),
        "version": _clean(document.get("version")),
        "updated_at": _clean(document.get("updated_at")),
        "review_expires_at": _clean(document.get("review_expires_at")),
        "sha256": digest,
        "source": source,
        "path": path,
        "document_sha256": document_sha256 or (_document_sha256(document) if document else ""),
        "status": status,
        "validation_errors": list(errors),
    }


def _profile_metadata(document: Dict[str, Any], digest: str, source: str, status: str, errors: List[str]) -> Dict[str, Any]:
    return {
        "schema_version": _clean(document.get("schema_version")),
        "sha256": digest,
        "source": source,
        "status": status,
        "validation_errors": list(errors),
        "selection_influence": "none",
    }


def load_response_guidance_policy(path_text: str = "") -> Dict[str, Any]:
    """Load and content-address a v3 policy, failing closed on any error."""

    path = _configured_path(path_text, DEFAULT_POLICY_PATH)
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError("policy root must be an object")
        errors = validate_response_guidance_policy(document)
        return {
            "document": document,
            "sha256": _sha256_bytes(raw),
            "source": _path_label(path),
            "path": str(path.resolve()),
            "document_sha256": _document_sha256(document),
            "status": "valid" if not errors else "invalid",
            "validation_errors": errors,
        }
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "document": {},
            "sha256": "",
            "source": _path_label(path),
            "path": str(path.resolve()),
            "document_sha256": "",
            "status": "unavailable",
            "validation_errors": [f"policy load failed: {exc.__class__.__name__}"],
        }


def load_response_guidance_asset_profile(path_text: str = "") -> Dict[str, Any]:
    """Load an optional explicitly configured asset profile without using it to select actions."""

    if not _clean(path_text):
        return {"document": {}, "sha256": "", "source": "", "status": "not_configured", "validation_errors": []}
    path = _configured_path(path_text, PROJECT_ROOT)
    try:
        if ".example." in path.name:
            return {
                "document": {},
                "sha256": "",
                "source": _path_label(path),
                "status": "invalid",
                "validation_errors": ["example asset profiles are prohibited for response guidance"],
            }
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
        if not isinstance(document, dict):
            raise ValueError("asset profile root must be an object")
        errors = validate_response_guidance_asset_profile(document)
        return {
            "document": document,
            "sha256": _sha256_bytes(raw),
            "source": _path_label(path),
            "status": "valid" if not errors else "invalid",
            "validation_errors": errors,
        }
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "document": {},
            "sha256": "",
            "source": _path_label(path),
            "status": "unavailable",
            "validation_errors": [f"asset profile load failed: {exc.__class__.__name__}"],
        }


def _durable_prefix_binding(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """Describe the exact durable manifest carried by canonical evidence.

    The manifest is intentionally hashed as the object that is actually
    carried in the report.  We do not synthesize a received timestamp or an
    event entry that the producer did not persist.  A complete runtime
    manifest is ``verified``; an absent/legacy compact manifest is explicit
    ``partial`` rather than being presented as a full replay proof.
    """

    manifest = snapshot.get("durable_event_manifest")
    if not isinstance(manifest, dict):
        manifest = {}
    content_sha = _document_sha256(manifest)
    session_id = _clean(snapshot.get("session_id"))
    manifest_session = _clean(manifest.get("session_id"))
    through_event_id = _clean(manifest.get("through_event_id"))
    through_received_at = _clean(manifest.get("through_received_at"))
    event_entries = manifest.get("event_entries")
    # Runtime analysis jobs currently carry a compact manifest summary while
    # storage snapshots may carry the complete ordered entries.  A compact
    # summary is deliberately only ``partial``: a digest-shaped watermark is
    # not itself proof that the underlying prefix content was resolved.
    event_count = manifest.get("event_count")
    if not isinstance(event_count, int) or isinstance(event_count, bool):
        event_count = snapshot.get("event_count")
    manifest_basis = {
        "schema_version": _clean(manifest.get("schema_version")),
        "session_id": manifest_session,
        "through_event_id": through_event_id,
        "through_received_at": through_received_at,
        "event_entries": event_entries,
    }
    manifest_hash_matches = (
        _valid_sha256(manifest.get("manifest_sha256"))
        and _document_sha256(manifest_basis)
        == _clean(manifest.get("manifest_sha256")).lower()
    )
    entries_valid = (
        isinstance(event_entries, list)
        and all(
            isinstance(entry, dict)
            and bool(_clean(entry.get("event_id")))
            and bool(_clean(entry.get("received_at")))
            and _valid_sha256(entry.get("payload_sha256"))
            for entry in event_entries
        )
    )
    complete = (
        _clean(manifest.get("schema_version")) == "durable_session_event_manifest.v1"
        and bool(manifest_session)
        and manifest_session == session_id
        and bool(through_event_id)
        and bool(through_received_at)
        and entries_valid
        and isinstance(event_count, int)
        and not isinstance(event_count, bool)
        and event_count == len(event_entries)
        and manifest_hash_matches
    )
    partial = bool(manifest) and bool(session_id) and bool(content_sha)
    return {
        "schema_version": DURABLE_PREFIX_SCHEMA_VERSION,
        "status": "verified" if complete else ("partial" if partial else "unverified"),
        "session_id": session_id,
        "manifest_sha256": _clean(manifest.get("manifest_sha256")).lower(),
        "content_sha256": content_sha,
        "manifest_hash_matches": manifest_hash_matches,
        "through_event_id": through_event_id,
        "through_received_at": through_received_at,
        "event_count": event_count if isinstance(event_count, int) and not isinstance(event_count, bool) else None,
        "source_schema_version": _clean(manifest.get("schema_version")),
    }


def _snapshot_reference_candidates(
    snapshot: Mapping[str, Any],
) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
    """Index canonical evidence IDs without trusting hash-shaped references."""

    collections = (
        ("observations", "observations"),
        ("ordered_command_observations", "ordered_command_observations"),
        ("transfer_observations", "transfer_observations"),
        ("transfer_event_observations", "transfer_event_observations"),
        ("direct_cowrie_events", "direct_cowrie_events"),
        ("cowrie_event_evidence", "cowrie_event_evidence"),
        ("trusted_attck_candidates", "trusted_attck_candidates"),
        ("classification_events", "classification_events"),
    )
    indexed: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    for collection, source in collections:
        for item in snapshot.get(collection) or []:
            if not isinstance(item, dict):
                continue
            ids = {
                _clean(item.get("evidence_id")),
                _clean(item.get("evidence_ref")),
            }
            for evidence_id in sorted(item for item in ids if item):
                indexed.setdefault(evidence_id, []).append((source, deepcopy(item)))
    return indexed


_REFERENCE_SOURCE_PRIORITY = (
    "direct_cowrie_events",
    "observations",
    "ordered_command_observations",
    "transfer_event_observations",
    "transfer_observations",
    "cowrie_event_evidence",
    "trusted_attck_candidates",
    "classification_events",
)


def _preferred_reference_candidates(
    candidates: Iterable[Tuple[str, Dict[str, Any]]],
) -> Tuple[str, List[Dict[str, Any]]]:
    """Select one canonical projection without hiding same-source conflicts.

    The evidence snapshot intentionally carries raw Cowrie events alongside
    derived command/transfer projections that reuse the same evidence ID.  A
    deterministic source precedence keeps that normal representation from
    becoming an artificial ambiguity, while two different contents in the
    same projection remain an explicit fail-closed conflict.
    """

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for source, item in candidates:
        grouped.setdefault(source, []).append(item)
    for source in _REFERENCE_SOURCE_PRIORITY:
        values = grouped.get(source) or []
        if not values:
            continue
        unique = {
            _document_sha256(item): item
            for item in values
        }
        if len(unique) != 1:
            return source, []
        return source, [next(iter(unique.values()))]
    return "", []


def _reference_resolution(
    snapshot: Mapping[str, Any],
    *,
    findings: Iterable[Mapping[str, Any]],
    actions: Iterable[Mapping[str, Any]],
    semantic_traces: Mapping[str, Mapping[str, Any]],
    typed_semantic_fact_set: Optional[Mapping[str, Any]],
    graph: Any,
) -> Dict[str, Any]:
    """Resolve each response reference to bounded content and a recomputable hash."""

    evidence_ids: Set[str] = set()
    for item in list(findings) + list(actions):
        if isinstance(item, Mapping):
            evidence_ids.update(_texts(item.get("supporting_evidence_refs") or []))
            evidence_ids.update(_texts(item.get("evidence_refs") or []))
    for trace in semantic_traces.values():
        for match in (trace or {}).get("matches") or []:
            if isinstance(match, Mapping):
                evidence_ids.update(_texts(match.get("supporting_evidence_refs") or []))

    indexed = _snapshot_reference_candidates(snapshot)
    required: List[Dict[str, str]] = [
        {"reference_type": "evidence", "reference_id": value}
        for value in sorted(evidence_ids)
    ]
    resolved: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, str]] = []
    for evidence_id in sorted(evidence_ids):
        candidates = indexed.get(evidence_id) or []
        source, preferred = _preferred_reference_candidates(candidates)
        if len(preferred) != 1:
            unresolved.append({
                "reference_type": "evidence",
                "reference_id": evidence_id,
                "reason": "missing" if not candidates else "ambiguous_content",
            })
            continue
        content = preferred[0]
        content_sha = _document_sha256(content)
        resolved.append({
            "reference_type": "evidence",
            "reference_id": evidence_id,
            "content_sha256": content_sha,
            "source": source,
            "content": content,
        })

    typed = typed_semantic_fact_set if isinstance(typed_semantic_fact_set, Mapping) else {}
    facts = [item for item in typed.get("facts") or [] if isinstance(item, dict)]
    typed_validation_errors: List[str] = []
    if typed:
        try:
            # Resolve/validate the supplied fact set independently of the
            # response-policy selector.  This catches a hash-shaped
            # ``fact_set_sha256`` whose aggregate content was never actually
            # validated, while preserving the Phase 4B fact-set contract.
            from production.reporting.typed_semantic_facts import (
                validate_typed_semantic_fact_set,
            )

            typed_validation_errors = list(validate_typed_semantic_fact_set(typed))
        except Exception as exc:  # pragma: no cover - defensive import boundary
            typed_validation_errors = [f"typed fact set validation unavailable: {exc.__class__.__name__}"]
    for fact in sorted(facts, key=lambda item: _clean(item.get("fact_id"))):
        fact_id = _clean(fact.get("fact_id"))
        if not fact_id:
            unresolved.append({
                "reference_type": "typed_fact",
                "reference_id": "",
                "reason": "missing_id",
            })
            continue
        required.append({"reference_type": "typed_fact", "reference_id": fact_id})
        content = deepcopy(fact)
        content.pop("fact_id", None)
        expected_id = stable_id("typed_semantic_fact", content)
        if expected_id != fact_id:
            unresolved.append({
                "reference_type": "typed_fact",
                "reference_id": fact_id,
                "reason": "content_id_mismatch",
            })
            continue
        resolved.append({
            "reference_type": "typed_fact",
            "reference_id": fact_id,
            "fact_set_sha256": _clean(typed.get("fact_set_sha256")),
            "content_sha256": _document_sha256(content),
            "source": "typed_semantic_fact_set.v2",
            "content": content,
        })

    typed_fact_projection = {
        "schema_version": _clean(typed.get("schema_version")),
        "session_id": _clean(typed.get("session_id")),
        "facts": [
            {
                "fact_id": _clean(item.get("reference_id")),
                **deepcopy(item.get("content") or {}),
            }
            for item in sorted(
                (
                    item
                    for item in resolved
                    if item.get("reference_type") == "typed_fact"
                ),
                key=lambda item: _clean(item.get("reference_id")),
            )
        ],
    }
    typed_context = {
        "status": (
            "verified"
            if typed and not typed_validation_errors
            else ("unverified" if typed else "not_supplied")
        ),
        "schema_version": _clean(typed.get("schema_version")),
        "session_id": _clean(typed.get("session_id")),
        "fact_set_sha256": _clean(typed.get("fact_set_sha256")).lower(),
        "fact_count": len(facts),
        "fact_projection_sha256": _document_sha256(typed_fact_projection),
        "canonical_evidence_sha256": _clean(
            (typed.get("provenance") or {}).get("canonical_evidence_sha256")
        ).lower(),
        "source_evidence_sha256": _clean(
            (typed.get("provenance") or {}).get("source_evidence_sha256")
        ).lower(),
        "validation_errors": typed_validation_errors,
    }
    typed_prefix_hashes = {
        _clean(snapshot.get("evidence_sha256")).lower(),
        _clean(snapshot.get("observed_evidence_sha256")).lower(),
    }
    typed_canonical_hash = typed_context.get("canonical_evidence_sha256")
    if (
        typed_context.get("status") == "verified"
        and typed_canonical_hash
        and typed_canonical_hash not in typed_prefix_hashes
    ):
        # A fact set can be valid in isolation yet originate from a different
        # evidence representation (for example, a legacy observed-behaviour
        # caller rather than a v3 canonical snapshot).  Keep it available for
        # compatibility, but never present it as verified for this output.
        typed_context["status"] = "unverified"
        typed_context["validation_errors"] = [
            "typed fact-set canonical evidence prefix does not match output"
        ]
        unresolved.append({
            "reference_type": "typed_fact_set",
            "reference_id": _clean(typed.get("fact_set_sha256")),
            "reason": "cross_evidence_prefix",
        })
    if typed_validation_errors:
        unresolved.append({
            "reference_type": "typed_fact_set",
            "reference_id": _clean(typed.get("fact_set_sha256")),
            "reason": "fact_set_validation_failed",
        })

    graph_value = graph if isinstance(graph, dict) else None
    if graph_value is not None:
        graph_id = _clean(graph_value.get("graph_sha256"))
        required.append({"reference_type": "semantic_graph", "reference_id": graph_id})
        graph_content_sha = _document_sha256(graph_value)
        if not _valid_sha256(graph_id) or _hash_without_key(graph_value, "graph_sha256") != graph_id:
            unresolved.append({
                "reference_type": "semantic_graph",
                "reference_id": graph_id,
                "reason": "content_hash_mismatch",
            })
        else:
            resolved.append({
                "reference_type": "semantic_graph",
                "reference_id": graph_id,
                "content_sha256": graph_content_sha,
                "source": "canonical_evidence.semantic_graph",
                "content": deepcopy(graph_value),
            })
    status = "verified" if not unresolved else ("partial" if resolved else "unverified")
    return {
        "schema_version": REFERENCE_RESOLUTION_SCHEMA_VERSION,
        "status": status,
        "required": sorted(required, key=lambda item: (item["reference_type"], item["reference_id"])),
        "resolved": sorted(resolved, key=lambda item: (item["reference_type"], item["reference_id"])),
        "unresolved": sorted(unresolved, key=lambda item: (item["reference_type"], item["reference_id"], item["reason"])),
        "typed_fact_set": typed_context,
    }


def _build_binding(
    snapshot: Mapping[str, Any],
    *,
    assessment_id: str,
    assessment_context: Optional[Mapping[str, Any]],
    policy: Mapping[str, Any],
    policy_sha256: str,
    policy_source: str,
    policy_path: str,
    policy_status: str,
    policy_document_sha256: str,
    findings: Iterable[Mapping[str, Any]],
    actions: Iterable[Mapping[str, Any]],
    semantic_traces: Mapping[str, Mapping[str, Any]],
    typed_semantic_fact_set: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    graph = snapshot.get("semantic_graph")
    graph_errors = validate_canonical_semantic_graph(graph) if isinstance(graph, dict) else []
    graph_binding = {
        "status": "verified" if isinstance(graph, dict) and not graph_errors else ("not_available" if graph is None else "invalid"),
        "graph_sha256": _clean((graph or {}).get("graph_sha256")) if isinstance(graph, dict) else "",
        "content_sha256": _document_sha256(graph) if isinstance(graph, dict) else "",
        "validation_errors": list(graph_errors),
    }
    assessment = deepcopy(dict(assessment_context)) if isinstance(assessment_context, Mapping) else {}
    if assessment_id:
        assessment.setdefault("assessment_id", assessment_id)
    assessment_binding = {
        "status": "verified" if assessment_id and assessment else ("not_supplied" if not assessment_id else "unverified"),
        "assessment_id": _clean(assessment.get("assessment_id") or assessment_id),
        "content_sha256": _document_sha256(assessment) if assessment else "",
        "source": "session_assessment_v4" if assessment else "",
        "content": assessment,
    }
    policy_binding_status = (
        "verified"
        if policy_path and policy_status == "valid" and policy and _valid_sha256(policy_sha256)
        else ("partial" if policy and policy_status == "valid" else "unverified")
    )
    reference_resolution = _reference_resolution(
        snapshot,
        findings=findings,
        actions=actions,
        semantic_traces=semantic_traces,
        typed_semantic_fact_set=typed_semantic_fact_set,
        graph=graph if isinstance(graph, dict) else None,
    )
    components = [
        _durable_prefix_binding(snapshot)["status"],
        assessment_binding["status"],
        graph_binding["status"],
        policy_binding_status,
        reference_resolution["status"],
        (reference_resolution.get("typed_fact_set") or {}).get(
            "status", "not_supplied"
        ),
    ]
    overall = "verified" if all(item == "verified" for item in components) else (
        "partial" if any(item in {"verified", "partial", "not_available", "not_supplied"} for item in components) else "unverified"
    )
    return {
        "schema_version": BINDING_SCHEMA_VERSION,
        "status": overall,
        "session_id": _clean(snapshot.get("session_id")) or "unknown",
        "durable_prefix": _durable_prefix_binding(snapshot),
        "assessment": assessment_binding,
        "graph": graph_binding,
        "policy": {
            "status": policy_binding_status,
            "file_sha256": _clean(policy_sha256).lower(),
            "document_sha256": policy_document_sha256 or (_document_sha256(policy) if policy else ""),
            "source": policy_source,
            "path": policy_path,
            "policy_id": _clean(policy.get("policy_id")),
            "version": _clean(policy.get("version")),
            "schema_version": _clean(policy.get("schema_version")),
            "content_resolution": "actual_file_bytes" if policy_path else "in_memory_document",
        },
        "reference_resolution": reference_resolution,
    }


def _guidance_identity(
    *,
    session_id: str,
    evidence_sha256: str,
    policy_sha256: str,
    profile_sha256: str,
    finding_rules: List[Dict[str, Any]],
    actions: List[Dict[str, Any]],
    status: str,
    guidance_state: str,
    triage: Dict[str, Any],
    safety: Dict[str, Any],
    typed_semantics: Dict[str, Any],
    binding: Optional[Mapping[str, Any]] = None,
) -> str:
    return stable_id("response_guidance_v3", {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "canonical_evidence_sha256": evidence_sha256,
        "policy_sha256": policy_sha256,
        "profile_sha256": profile_sha256,
        "findings": deepcopy(finding_rules),
        "actions": deepcopy(actions),
        "status": status,
        "guidance_state": guidance_state,
        "triage": deepcopy(triage),
        "safety": deepcopy(safety),
        "typed_semantics": deepcopy(typed_semantics),
        "binding": deepcopy(dict(binding)) if isinstance(binding, Mapping) else {},
    })


def _legacy_guidance_identity(
    *,
    session_id: str,
    evidence_sha256: str,
    policy_sha256: str,
    profile_sha256: str,
    finding_rules: List[Dict[str, Any]],
    actions: List[Dict[str, Any]],
    status: str,
    guidance_state: str,
) -> str:
    """Reproduce the pre-typed v3 ID for read-only historical validation."""

    return stable_id("response_guidance_v3", {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "canonical_evidence_sha256": evidence_sha256,
        "policy_sha256": policy_sha256,
        "profile_sha256": profile_sha256,
        "findings": [
            {
                "rule_id": item.get("rule_id"),
                "evidence_refs": item.get(
                    "supporting_evidence_refs"
                ),
            }
            for item in finding_rules
        ],
        "actions": [
            {
                "rule_id": item.get("rule_id"),
                "action_id": item.get("action_id"),
                "evidence_refs": item.get("evidence_refs"),
            }
            for item in actions
        ],
        "status": status,
        "guidance_state": guidance_state,
    })


def _validate_binding(
    value: Mapping[str, Any],
    binding: Any,
    *,
    expected_session_id: str = "",
    expected_assessment_id: str = "",
) -> List[str]:
    """Independently validate response-guidance content bindings."""

    errors: List[str] = []
    policy_metadata = ((value.get("provenance") or {}).get("policy") or {})
    policy_version = _clean(policy_metadata.get("version"))
    historical_policy = policy_version.startswith(
        ("3.0.", "3.1.", "3.2.", "3.3.", "3.4.", "3.5.", "3.6.")
    )
    if not isinstance(binding, dict):
        # v1/v2 and pre-binding v3 records remain readable through the
        # historical adapter.  They are never treated as fully verified.
        if historical_policy:
            return []
        return ["response guidance binding metadata is required for current output"]
    if historical_policy:
        # Historical v3 records may carry a binding-shaped field from a later
        # producer, but their pre-binding identity and semantics remain
        # read-only compatibility data.  Do not upgrade or revalidate them as
        # current fully verified outputs.
        return []
    if binding.get("schema_version") != BINDING_SCHEMA_VERSION:
        errors.append("response guidance binding schema is invalid")
    binding_status = _clean(binding.get("status"))
    if binding_status not in {"verified", "partial", "unverified"}:
        errors.append("response guidance binding status is invalid")
    session_id = _clean(value.get("session_id")) or "unknown"
    if _clean(binding.get("session_id")) != session_id:
        errors.append("response guidance binding session mismatch")
    if expected_session_id and session_id != _clean(expected_session_id):
        errors.append("response guidance session does not match requested session")

    evidence = value.get("canonical_evidence") or {}
    expected_prefix = _durable_prefix_binding(evidence)
    prefix = binding.get("durable_prefix")
    if not isinstance(prefix, dict):
        errors.append("durable prefix binding is required")
        prefix = {}
    else:
        if prefix.get("schema_version") != DURABLE_PREFIX_SCHEMA_VERSION:
            errors.append("durable prefix binding schema is invalid")
        for key in (
            "status",
            "session_id",
            "manifest_sha256",
            "content_sha256",
            "manifest_hash_matches",
            "through_event_id",
            "through_received_at",
            "event_count",
            "source_schema_version",
        ):
            if prefix.get(key) != expected_prefix.get(key):
                errors.append(f"durable prefix binding {key} is inconsistent")
        if prefix.get("status") == "verified" and expected_prefix.get("status") != "verified":
            errors.append("durable prefix claims verified without a complete manifest")
        if prefix.get("status") == "verified" and not _valid_sha256(prefix.get("content_sha256")):
            errors.append("verified durable prefix requires resolved content")
        if prefix.get("status") == "verified" and prefix.get("manifest_hash_matches") is not True:
            errors.append("verified durable prefix requires a matching manifest hash")
    if binding_status == "verified" and prefix.get("status") != "verified":
        errors.append("fully verified guidance requires a verified durable prefix")

    assessment = binding.get("assessment")
    if not isinstance(assessment, dict):
        errors.append("assessment binding is required")
        assessment = {}
    assessment_status = _clean(assessment.get("status"))
    if assessment_status == "verified":
        content = assessment.get("content")
        if not isinstance(content, dict) or not _valid_sha256(assessment.get("content_sha256")):
            errors.append("verified assessment requires resolved content")
        else:
            if _document_sha256(content) != _clean(assessment.get("content_sha256")):
                errors.append("assessment content hash mismatch")
            if _clean(content.get("assessment_id")) != _clean(assessment.get("assessment_id")):
                errors.append("assessment content identity mismatch")
    elif assessment_status not in {"not_supplied", "unverified"}:
        errors.append("assessment binding status is invalid")
    if expected_assessment_id and assessment_status == "verified" and _clean(assessment.get("assessment_id")) != _clean(expected_assessment_id):
        errors.append("assessment binding does not match stored assessment")
    if binding_status == "verified" and assessment_status != "verified":
        errors.append("fully verified guidance requires a verified assessment")

    graph = evidence.get("semantic_graph")
    graph_binding = binding.get("graph")
    if not isinstance(graph_binding, dict):
        errors.append("graph binding is required")
        graph_binding = {}
    if isinstance(graph, dict):
        graph_errors = validate_canonical_semantic_graph(graph)
        errors.extend(f"response guidance graph: {error}" for error in graph_errors)
        if graph_binding.get("status") != "verified":
            errors.append("canonical graph must be represented as verified when present")
        if graph_binding.get("graph_sha256") != _clean(graph.get("graph_sha256")):
            errors.append("graph binding identity mismatch")
        if graph_binding.get("content_sha256") != _document_sha256(graph):
            errors.append("graph binding content hash mismatch")
    elif _clean(graph_binding.get("status")) == "verified":
        errors.append("graph binding claims verified without graph content")
    if binding_status == "verified" and _clean(graph_binding.get("status")) != "verified":
        errors.append("fully verified guidance requires a verified graph")

    policy_binding = binding.get("policy")
    if not isinstance(policy_binding, dict):
        errors.append("policy content binding is required")
        policy_binding = {}
    if _clean(policy_binding.get("status")) == "verified":
        policy_path = _clean(policy_binding.get("path"))
        if not policy_path:
            errors.append("verified policy binding requires a source path")
        else:
            path = Path(policy_path)
            try:
                raw = path.read_bytes()
                document = json.loads(raw.decode("utf-8"))
                if not isinstance(document, dict):
                    raise ValueError("policy root must be an object")
                policy_errors = validate_response_guidance_policy(document)
                if policy_errors:
                    errors.extend(f"resolved policy: {error}" for error in policy_errors)
                raw_sha = _sha256_bytes(raw)
                document_sha = _document_sha256(document)
                if raw_sha != _clean(policy_binding.get("file_sha256")):
                    errors.append("resolved policy file hash mismatch")
                if document_sha != _clean(policy_binding.get("document_sha256")):
                    errors.append("resolved policy canonical hash mismatch")
                for key in ("schema_version", "policy_id", "version"):
                    if _clean(document.get(key)) != _clean(policy_binding.get(key)):
                        errors.append(f"resolved policy {key} mismatch")
                if raw_sha != _clean(policy_metadata.get("sha256")):
                    errors.append("resolved policy does not match output policy hash")
                if document_sha != _clean(policy_metadata.get("document_sha256")):
                    errors.append("resolved policy does not match output document hash")
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"resolved policy unavailable: {exc.__class__.__name__}")
    elif _clean(policy_binding.get("status")) not in {"partial", "unverified"}:
        errors.append("policy content binding status is invalid")
    if binding_status == "verified" and _clean(policy_binding.get("status")) != "verified":
        errors.append("fully verified guidance requires resolved policy content")

    resolution = binding.get("reference_resolution")
    if not isinstance(resolution, dict):
        errors.append("reference resolution is required")
        resolution = {}
    if resolution.get("schema_version") != REFERENCE_RESOLUTION_SCHEMA_VERSION:
        errors.append("reference resolution schema is invalid")
    required = resolution.get("required") if isinstance(resolution.get("required"), list) else []
    resolved = resolution.get("resolved") if isinstance(resolution.get("resolved"), list) else []
    unresolved = resolution.get("unresolved") if isinstance(resolution.get("unresolved"), list) else []
    typed_context = resolution.get("typed_fact_set")
    if not isinstance(typed_context, dict):
        errors.append("typed fact-set resolution is required")
        typed_context = {}
    required_keys = {(item.get("reference_type"), item.get("reference_id")) for item in required if isinstance(item, dict)}
    resolved_by_key: Dict[Tuple[Any, Any], Dict[str, Any]] = {}
    for item in resolved:
        if not isinstance(item, dict):
            errors.append("resolved reference must be an object")
            continue
        key = (item.get("reference_type"), item.get("reference_id"))
        if key in resolved_by_key:
            errors.append("duplicate resolved reference")
        resolved_by_key[key] = item
    if len(required_keys) != len(required):
        errors.append("required references are duplicated or malformed")
    if len(resolved_by_key) != len(resolved):
        errors.append("resolved references are duplicated or malformed")
    indexed = _snapshot_reference_candidates(evidence)
    typed = ((value.get("provenance") or {}).get("typed_semantics") or {})
    typed_resolved = sorted(
        (
            item
            for item in resolved
            if isinstance(item, dict)
            and item.get("reference_type") == "typed_fact"
        ),
        key=lambda item: _clean(item.get("reference_id")),
    )
    typed_projection = {
        "schema_version": _clean(typed_context.get("schema_version")),
        "session_id": _clean(typed_context.get("session_id")),
        "facts": [
            {
                "fact_id": _clean(item.get("reference_id")),
                **deepcopy(item.get("content") or {}),
            }
            for item in typed_resolved
        ],
    }
    if _clean(typed_context.get("status")) == "verified":
        if _clean(typed_context.get("schema_version")) != "typed_semantic_fact_set.v2":
            errors.append("verified typed fact-set schema is invalid")
        if _clean(typed_context.get("session_id")) != _clean(evidence.get("session_id")):
            errors.append("verified typed fact-set session mismatch")
        if not _valid_sha256(typed_context.get("fact_set_sha256")):
            errors.append("verified typed fact-set hash is invalid")
        expected_evidence_hashes = {
            _clean(evidence.get("evidence_sha256")).lower(),
            _clean(evidence.get("observed_evidence_sha256")).lower(),
        }
        if _clean(typed_context.get("canonical_evidence_sha256")).lower() not in expected_evidence_hashes:
            errors.append("verified typed fact-set crosses the evidence prefix")
        if typed_context.get("fact_count") != len(typed_resolved):
            errors.append("verified typed fact-set count is inconsistent")
        if _clean(typed_context.get("fact_projection_sha256")) != _document_sha256(typed_projection):
            errors.append("verified typed fact projection hash mismatch")
        if typed_context.get("validation_errors"):
            errors.append("verified typed fact-set contains validation errors")
    elif _clean(typed_context.get("status")) not in {"not_supplied", "unverified"}:
        errors.append("typed fact-set resolution status is invalid")
    for item in required:
        if not isinstance(item, dict):
            errors.append("required reference must be an object")
            continue
        key = (item.get("reference_type"), item.get("reference_id"))
        resolved_item = resolved_by_key.get(key)
        if resolved_item is None:
            errors.append(f"required reference is unresolved: {key[0]}:{key[1]}")
            continue
        ref_type, ref_id = key
        content = resolved_item.get("content")
        if not isinstance(content, dict):
            errors.append(f"resolved reference lacks content: {ref_type}:{ref_id}")
            continue
        if not _valid_sha256(resolved_item.get("content_sha256")):
            errors.append(f"resolved reference hash is invalid: {ref_type}:{ref_id}")
            continue
        if _document_sha256(content) != _clean(resolved_item.get("content_sha256")):
            errors.append(f"resolved reference content hash mismatch: {ref_type}:{ref_id}")
        if ref_type == "evidence":
            candidates = indexed.get(_clean(ref_id), [])
            _source, preferred = _preferred_reference_candidates(candidates)
            candidate_hashes = {
                _document_sha256(candidate)
                for candidate in preferred
            }
            if len(preferred) != 1:
                errors.append(f"evidence reference content is ambiguous: {ref_id}")
            if _clean(resolved_item.get("content_sha256")) not in candidate_hashes:
                errors.append(f"evidence reference content is not canonical: {ref_id}")
        elif ref_type == "typed_fact":
            content_without_id = deepcopy(content)
            content_without_id.pop("fact_id", None)
            if stable_id("typed_semantic_fact", content_without_id) != _clean(ref_id):
                errors.append(f"typed fact reference identity mismatch: {ref_id}")
            if (
                _clean(typed.get("fact_set_sha256"))
                and _clean(resolved_item.get("fact_set_sha256"))
                != _clean(typed.get("fact_set_sha256"))
            ):
                errors.append(f"typed fact set binding mismatch: {ref_id}")
        elif ref_type == "semantic_graph":
            if validate_canonical_semantic_graph(content):
                errors.append(f"semantic graph reference is invalid: {ref_id}")
            if _clean(content.get("graph_sha256")) != _clean(ref_id):
                errors.append(f"semantic graph reference identity mismatch: {ref_id}")
        else:
            errors.append(f"unknown response reference type: {ref_type}")
    if unresolved and binding_status == "verified":
        errors.append("fully verified guidance contains unresolved references")
    if _clean(resolution.get("status")) == "verified" and unresolved:
        errors.append("reference resolution claims verified with unresolved references")
    if binding_status == "verified" and _clean(resolution.get("status")) != "verified":
        errors.append("fully verified guidance requires verified reference resolution")
    if binding_status == "verified" and _clean(typed_context.get("status")) != "verified":
        errors.append("fully verified guidance requires verified typed fact-set resolution")
    return errors


def validate_response_guidance_v3(
    value: Any,
    *,
    expected_session_id: str = "",
    expected_assessment_id: str = "",
) -> List[str]:
    """Validate the immutable-evidence and no-automation v3 output contract."""

    errors: List[str] = []
    if not isinstance(value, dict):
        return ["response guidance must be an object"]
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported response guidance schema")
    if value.get("authority") not in {"deterministic_observed_evidence_policy", "policy_unavailable"}:
        errors.append("unsupported guidance authority")
    evidence = value.get("canonical_evidence")
    if not isinstance(evidence, dict):
        errors.append("canonical_evidence is required")
        evidence = {}
    try:
        expected_evidence_hash = (
            canonical_evidence_sha256(evidence) if evidence else ""
        )
    except ValueError:
        expected_evidence_hash = ""
    recorded_evidence_hash = _clean((value.get("provenance") or {}).get("canonical_evidence_sha256"))
    if not recorded_evidence_hash or recorded_evidence_hash != expected_evidence_hash:
        errors.append("canonical evidence digest is inconsistent")
    policy = (value.get("provenance") or {}).get("policy") or {}
    policy_hash = _clean(policy.get("sha256"))
    if len(policy_hash) != 64 or any(char not in "0123456789abcdef" for char in policy_hash):
        errors.append("policy SHA-256 is required")
    profile = (value.get("provenance") or {}).get("asset_profile") or {}
    profile_hash = _clean(profile.get("sha256"))
    if profile_hash and (len(profile_hash) != 64 or any(char not in "0123456789abcdef" for char in profile_hash)):
        errors.append("asset profile SHA-256 is malformed")
    expected_safety = {
        "automatic_execution": False,
        "manual_approval_required": True,
        "alerting_side_effect": False,
        "response_action_side_effect": False,
        "execution_integration": "not_implemented",
    }
    if value.get("safety") != expected_safety:
        errors.append("guidance safety boundary is invalid")
    if (value.get("safety") or {}).get("automatic_execution") is not False:
        errors.append("automatic execution must be false")
    if (value.get("safety") or {}).get("alerting_side_effect") is not False:
        errors.append("guidance must not create alerts")
    typed_value = (value.get("provenance") or {}).get(
        "typed_semantics"
    )
    policy_version = _clean(policy.get("version"))
    legacy_pre_typed = (
        typed_value is None
        and policy_version.startswith("3.0.")
    )
    legacy_one_family = policy_version.startswith("3.1.")
    legacy_two_families = policy_version.startswith("3.2.")
    legacy_three_families = policy_version.startswith("3.3.")
    legacy_four_families = policy_version.startswith("3.4.")
    legacy_five_families = policy_version.startswith("3.5.")
    typed = typed_value if isinstance(typed_value, dict) else {}
    if not legacy_pre_typed and not isinstance(typed_value, dict):
        errors.append("typed semantic provenance is required")
    typed_legacy_keys = {
        "schema_version",
        "status",
        "fact_set_sha256",
        "semantic_vocabulary_sha256",
        "selection_sha256",
        "activated_families",
        "selection_authority",
    }
    typed_current_keys = typed_legacy_keys | {
        "family_selection_sha256s",
    }
    expected_typed_keys = (
        typed_legacy_keys if legacy_one_family else typed_current_keys
    )
    if (
        not legacy_pre_typed
        and set(typed) != expected_typed_keys
    ):
        errors.append("typed semantic provenance shape is invalid")
    if (
        not legacy_pre_typed
        and typed.get("schema_version") != "typed_semantic_fact_set.v2"
    ):
        errors.append("typed semantic provenance schema is invalid")
    if (
        not legacy_pre_typed
        and typed.get("activated_families")
        != (
            ["sensitive_read"]
            if legacy_one_family
            else (
                ["sensitive_read", "transfer"]
                if legacy_two_families
                else (
                    ["sensitive_read", "transfer", "inspection"]
                    if legacy_three_families
                    else (
                        [
                            "sensitive_read",
                            "transfer",
                            "inspection",
                            "filesystem",
                        ]
                        if legacy_four_families
                        else (
                            [
                                "sensitive_read",
                                "transfer",
                                "inspection",
                                "filesystem",
                                "execution",
                            ]
                            if legacy_five_families
                            else list(
                                CURRENT_ACTIVATED_SEMANTIC_FAMILIES
                            )
                        )
                    )
                )
            )
        )
    ):
        errors.append("typed semantic activated families are invalid")
    if not legacy_pre_typed and typed.get("selection_authority") != (
        "family_scoped_observed_evidence_interpretation"
    ):
        errors.append("typed semantic selection authority is invalid")
    typed_status = _clean(typed.get("status"))
    typed_fact_hash = _clean(typed.get("fact_set_sha256")).lower()
    typed_vocab_hash = _clean(
        typed.get("semantic_vocabulary_sha256")
    ).lower()
    typed_selection_hash = _clean(
        typed.get("selection_sha256")
    ).lower()
    family_selection_hashes = (
        typed.get("family_selection_sha256s") or {}
    )
    if not isinstance(family_selection_hashes, dict):
        errors.append(
            "typed semantic family selection hashes are invalid"
        )
        family_selection_hashes = {}
    if legacy_pre_typed:
        pass
    elif typed_status == "valid":
        if (
            not legacy_one_family
            and set(family_selection_hashes)
            != (
                {"sensitive_read", "transfer"}
                if legacy_two_families
                else (
                    {"sensitive_read", "transfer", "inspection"}
                    if legacy_three_families
                    else (
                        {
                            "sensitive_read",
                            "transfer",
                            "inspection",
                            "filesystem",
                        }
                        if legacy_four_families
                        else (
                            {
                                "sensitive_read",
                                "transfer",
                                "inspection",
                                "filesystem",
                                "execution",
                            }
                            if legacy_five_families
                            else set(
                                CURRENT_ACTIVATED_SEMANTIC_FAMILIES
                            )
                        )
                    )
                )
            )
        ):
            errors.append(
                "typed semantic family selection hashes are invalid"
            )
        for label, digest in (
            ("fact_set_sha256", typed_fact_hash),
            ("semantic_vocabulary_sha256", typed_vocab_hash),
            ("selection_sha256", typed_selection_hash),
        ):
            if len(digest) != 64 or any(
                char not in "0123456789abcdef" for char in digest
            ):
                errors.append(f"typed semantic {label} is invalid")
        if not legacy_one_family:
            for family, digest in family_selection_hashes.items():
                if (
                    family not in (
                        {"sensitive_read", "transfer"}
                        if legacy_two_families
                        else (
                            {"sensitive_read", "transfer", "inspection"}
                            if legacy_three_families
                            else (
                                {
                                    "sensitive_read",
                                    "transfer",
                                    "inspection",
                                    "filesystem",
                                }
                                if legacy_four_families
                                else (
                                    {
                                        "sensitive_read",
                                        "transfer",
                                        "inspection",
                                        "filesystem",
                                        "execution",
                                    }
                                    if legacy_five_families
                                    else set(
                                        CURRENT_ACTIVATED_SEMANTIC_FAMILIES
                                    )
                                )
                            )
                        )
                    )
                    or not SHA256_RE.fullmatch(_clean(digest).lower())
                ):
                    errors.append(
                        "typed semantic family selection hash is invalid: "
                        f"{family}"
                    )
            expected_selection_set_hash = _selection_set_sha256(
                fact_set_sha256=typed_fact_hash,
                semantic_vocabulary_sha256=typed_vocab_hash,
                family_selection_sha256s=family_selection_hashes,
            )
            if typed_selection_hash != expected_selection_set_hash:
                errors.append(
                    "typed semantic selection-set hash is inconsistent"
                )
    elif typed_status == "unavailable":
        if (
            typed_fact_hash
            or typed_vocab_hash
            or typed_selection_hash
            or family_selection_hashes
        ):
            errors.append(
                "unavailable typed semantics cannot retain unverified hashes"
            )
    else:
        errors.append("typed semantic provenance status is invalid")
    try:
        allowed_refs = canonical_behavioral_evidence_refs(evidence)
        transfer_refs = canonical_transfer_evidence_refs(evidence)
    except (TypeError, ValueError, KeyError) as exc:
        # A malformed v3 snapshot must be represented as a validation failure,
        # not escape through dashboard/report consumers as an operational 500.
        errors.append(f"canonical evidence is invalid: {exc}")
        allowed_refs = set()
        transfer_refs = set()
    actions = value.get("advisory_actions")
    if not isinstance(actions, list):
        errors.append("advisory_actions must be an array")
        actions = []
    seen: Set[str] = set()
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            errors.append(f"advisory_actions[{index}] must be an object")
            continue
        action_id = _clean(action.get("action_id"))
        if not action_id or action_id in seen:
            errors.append(f"advisory_actions[{index}] has missing or duplicate action_id")
        seen.add(action_id)
        refs = _texts(action.get("evidence_refs") or [])
        if not refs or not set(refs).issubset(allowed_refs):
            errors.append(f"advisory_actions[{index}] lacks canonical observed-evidence grounding")
        if action.get("evidence_scope") != [CANONICAL_EVIDENCE_SCOPE]:
            errors.append(f"advisory_actions[{index}] has invalid evidence scope")
        if action.get("requires_manual_approval") is not True:
            errors.append(f"advisory_actions[{index}] must require manual approval")
        if action.get("safe_to_auto_execute") is not False:
            errors.append(f"advisory_actions[{index}] must prohibit automatic execution")
        if action.get("execution_integration") != "not_implemented":
            errors.append(f"advisory_actions[{index}] may not have an execution integration")
        traces = action.get("matched_predicates")
        if (
            not isinstance(traces, list)
            or not traces
            or not all(
                isinstance(item, dict) and item.get("result") is True
                for item in traces
            )
        ):
            errors.append(f"advisory_actions[{index}] lacks a complete matched predicate trace")
        semantic_family = _clean(action.get("semantic_family"))
        if semantic_family:
            if semantic_family not in set(
                typed.get("activated_families") or []
            ):
                errors.append(
                    f"advisory_actions[{index}] uses a non-activated family"
                )
            semantic_trace = action.get("semantic_trace") or {}
            if semantic_trace.get("fact_set_sha256") != typed_fact_hash:
                errors.append(
                    f"advisory_actions[{index}] semantic fact hash mismatch"
                )
            if (
                semantic_trace.get("semantic_vocabulary_sha256")
                != typed_vocab_hash
            ):
                errors.append(
                    f"advisory_actions[{index}] semantic policy hash mismatch"
                )
            expected_family_hash = (
                typed_selection_hash
                if legacy_one_family
                else _clean(
                    family_selection_hashes.get(semantic_family)
                )
            )
            if semantic_trace.get("selection_sha256") != expected_family_hash:
                errors.append(
                    f"advisory_actions[{index}] selection hash mismatch"
                )
            errors.extend(
                f"advisory_actions[{index}]: {error}"
                for error in validate_policy_output_trace(
                    semantic_trace,
                    fact_set_sha256=typed_fact_hash,
                    semantic_vocabulary_sha256=typed_vocab_hash,
                    allowed_evidence_refs=(
                        transfer_refs
                        if semantic_family == "transfer"
                        else allowed_refs
                    ),
                )
            )
    findings = value.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be an array")
        findings = []
    for index, finding in enumerate(findings):
        refs = _texts(finding.get("supporting_evidence_refs") if isinstance(finding, dict) else [])
        if not isinstance(finding, dict) or not refs or not set(refs).issubset(allowed_refs):
            errors.append(f"findings[{index}] lacks canonical observed-evidence grounding")
            continue
        semantic_family = _clean(finding.get("semantic_family"))
        if semantic_family:
            if semantic_family not in set(
                typed.get("activated_families") or []
            ):
                errors.append(
                    f"findings[{index}] uses a non-activated family"
                )
            semantic_trace = finding.get("semantic_trace") or {}
            if semantic_trace.get("fact_set_sha256") != typed_fact_hash:
                errors.append(
                    f"findings[{index}] semantic fact hash mismatch"
                )
            if (
                semantic_trace.get("semantic_vocabulary_sha256")
                != typed_vocab_hash
            ):
                errors.append(
                    f"findings[{index}] semantic policy hash mismatch"
                )
            expected_family_hash = (
                typed_selection_hash
                if legacy_one_family
                else _clean(
                    family_selection_hashes.get(semantic_family)
                )
            )
            if semantic_trace.get("selection_sha256") != expected_family_hash:
                errors.append(
                    f"findings[{index}] selection hash mismatch"
                )
            errors.extend(
                f"findings[{index}]: {error}"
                for error in validate_policy_output_trace(
                    semantic_trace,
                    fact_set_sha256=typed_fact_hash,
                    semantic_vocabulary_sha256=typed_vocab_hash,
                    allowed_evidence_refs=(
                        transfer_refs
                        if semantic_family == "transfer"
                        else allowed_refs
                    ),
                )
            )
            finding_content = {
                key: deepcopy(item)
                for key, item in finding.items()
                if key != "finding_id"
            }
            if finding.get("finding_id") != stable_id(
                "response_guidance_finding",
                finding_content,
            ):
                errors.append(
                    f"findings[{index}] finding_id is inconsistent"
                )
    triage = value.get("triage")
    if not isinstance(triage, dict):
        errors.append("triage must be an object")
        triage = {}
    strongest = findings[0] if findings else {}
    severity = _clean(strongest.get("severity")) or "info"
    expected_triage = {
        "review_priority": severity,
        "urgency": (
            "prompt_review"
            if severity in {"high", "critical"}
            else "routine_review"
        ),
        "semantics": (
            "categorical_observed_evidence_policy_not_score_or_forecast"
        ),
        "finding_ids": [
            item.get("finding_id")
            for item in findings
            if isinstance(item, dict)
        ],
    }
    if triage != expected_triage:
        errors.append("triage is inconsistent with grounded findings")
    binding = value.get("binding")
    binding_errors = _validate_binding(
        value,
        binding,
        expected_session_id=expected_session_id,
        expected_assessment_id=expected_assessment_id,
    )
    errors.extend(binding_errors)
    identity_arguments = {
        "session_id": _clean(value.get("session_id")) or "unknown",
        "evidence_sha256": recorded_evidence_hash,
        "policy_sha256": policy_hash,
        "profile_sha256": profile_hash,
        "finding_rules": findings,
        "actions": actions,
        "status": _clean(value.get("status")),
        "guidance_state": _clean(value.get("guidance_state")),
    }
    expected_id = (
        _legacy_guidance_identity(**identity_arguments)
        if legacy_pre_typed
        else _guidance_identity(
            **identity_arguments,
            triage=triage,
            safety=value.get("safety") or {},
            typed_semantics=typed,
            binding=(
                binding
                if isinstance(binding, Mapping)
                and not policy_version.startswith(
                    ("3.0.", "3.1.", "3.2.", "3.3.", "3.4.", "3.5.", "3.6.")
                )
                else None
            ),
        )
    )
    if _clean(value.get("guidance_id")) != expected_id:
        errors.append("guidance_id is inconsistent with immutable inputs")
    return errors


def build_response_guidance_v3(
    observed_behavior: Any,
    *,
    policy: Optional[Dict[str, Any]] = None,
    policy_sha256: str = "",
    policy_source: str = "",
    policy_path: str = "",
    policy_document_sha256: str = "",
    policy_status: str = "valid",
    policy_validation_errors: Optional[List[str]] = None,
    asset_profile: Optional[Dict[str, Any]] = None,
    asset_profile_sha256: str = "",
    asset_profile_source: str = "",
    asset_profile_status: str = "not_configured",
    asset_profile_validation_errors: Optional[List[str]] = None,
    session_context: Optional[Dict[str, Any]] = None,
    forecast_context: Any = None,
    enrichment_context: Any = None,
    typed_semantic_fact_set: Optional[Dict[str, Any]] = None,
    assessment_id: str = "",
    assessment_context: Optional[Dict[str, Any]] = None,
    activated_semantic_families: Iterable[str] = (),
    blocked_policy_rule_ids: Iterable[str] = (),
) -> Dict[str, Any]:
    """Evaluate v3 policy directly against immutable observed Cowrie evidence."""

    snapshot = canonical_evidence_snapshot(observed_behavior)
    evidence_sha256 = canonical_evidence_sha256(snapshot)
    facts = _observed_facts(snapshot)
    document = deepcopy(policy) if isinstance(policy, dict) else {}
    policy_errors = list(policy_validation_errors or validate_response_guidance_policy(document))
    digest = _clean(policy_sha256) or (_document_sha256(document) if document else "")
    profile_document = deepcopy(asset_profile) if isinstance(asset_profile, dict) else {}
    profile_errors = list(
        asset_profile_validation_errors
        or (
            validate_response_guidance_asset_profile(profile_document)
            if profile_document
            else []
        )
    )
    profile_digest = _clean(asset_profile_sha256) or (_document_sha256(profile_document) if profile_document else "")
    policy_ok = policy_status == "valid" and not policy_errors and bool(digest)
    profile_ok = asset_profile_status in {"valid", "not_configured"} and not profile_errors
    status = "available" if policy_ok and profile_ok else "unavailable"
    authority = "deterministic_observed_evidence_policy" if status == "available" else "policy_unavailable"
    context_values = _context_values(snapshot, facts)
    requested_families = {
        _clean(value)
        for value in activated_semantic_families
        if _clean(value)
    }
    blocked_rules = {
        _clean(value) for value in blocked_policy_rule_ids if _clean(value)
    }
    activated_family_order = list(
        CURRENT_ACTIVATED_SEMANTIC_FAMILIES
    )
    semantic_selections: Dict[str, Dict[str, Any]] = {}
    if (
        requested_families == set(activated_family_order)
        and isinstance(typed_semantic_fact_set, dict)
        and typed_semantic_fact_set
    ):
        try:
            semantic_selections = {
                family: select_activated_semantic_family(
                    typed_semantic_fact_set,
                    family=family,
                )
                for family in activated_family_order
            }
        except ValueError:
            semantic_selections = {}
    semantic_traces = {
        family: policy_output_trace(selection)
        for family, selection in semantic_selections.items()
    }
    semantic_refs = {
        family: sorted({
            _clean(ref)
            for match in selection.get("matches") or []
            if isinstance(match, dict)
            for ref in match.get("supporting_evidence_refs") or []
            if _clean(ref)
        })
        for family, selection in semantic_selections.items()
    }
    semantic_context: Dict[str, Set[str]] = {}
    for selection in semantic_selections.values():
        for match in selection.get("matches") or []:
            if not isinstance(match, dict):
                continue
            role = _clean(match.get("entity_role"))
            value = _clean(match.get("entity_value"))
            if role and value:
                semantic_context.setdefault(role, set()).add(value)
    for role, values in semantic_context.items():
        context_values[role] = ", ".join(sorted(values))
    family_selection_hashes = {
        family: _clean(selection.get("selection_sha256"))
        for family, selection in semantic_selections.items()
    }
    fact_set_hash = _clean(
        (
            semantic_selections.get(
                activated_family_order[0]
            )
            or {}
        ).get("fact_set_sha256")
    )
    vocabulary_hash = _clean(
        (
            semantic_selections.get(
                activated_family_order[0]
            )
            or {}
        ).get("semantic_vocabulary_sha256")
    )
    typed_provenance = {
        "schema_version": "typed_semantic_fact_set.v2",
        "status": (
            "valid"
            if set(semantic_selections) == set(activated_family_order)
            else "unavailable"
        ),
        "fact_set_sha256": fact_set_hash,
        "semantic_vocabulary_sha256": vocabulary_hash,
        "selection_sha256": _selection_set_sha256(
            fact_set_sha256=fact_set_hash,
            semantic_vocabulary_sha256=vocabulary_hash,
            family_selection_sha256s=family_selection_hashes,
        ),
        "family_selection_sha256s": family_selection_hashes,
        "activated_families": activated_family_order,
        "selection_authority": (
            "family_scoped_observed_evidence_interpretation"
        ),
    }

    def match_rule(
        rule: Dict[str, Any],
    ) -> Tuple[bool, List[Dict[str, Any]], List[str]]:
        semantic_family = _clean(rule.get("semantic_family"))
        if semantic_family:
            condition = rule.get("applies_when") or {}
            matches = list(
                (semantic_selections.get(semantic_family) or {}).get("matches")
                or []
            )
            trace = [{
                    "predicate": "activated_semantic_families",
                    "expected": [semantic_family],
                    "matched": [semantic_family] if matches else [],
                    "result": bool(matches),
                    "evidence_refs": semantic_refs.get(semantic_family) or [],
            }]
            predicate_fields = {
                "required_operation_types": "operation_types",
                "required_evidence_classes": "evidence_class",
                "required_outcome_statuses": "outcome_status",
                "required_effect_statuses": "effect_status",
            }
            for predicate, field in predicate_fields.items():
                expected = _texts(condition.get(predicate) or [])
                if not expected:
                    continue
                filtered = []
                for match in matches:
                    actual = match.get(field)
                    actual_values = set(
                        _texts(actual if isinstance(actual, list) else [actual])
                    )
                    predicate_matched = (
                        set(expected).issubset(actual_values)
                        if predicate == "required_operation_types"
                        else bool(set(expected).intersection(actual_values))
                    )
                    if predicate_matched:
                        filtered.append(match)
                refs = sorted({
                    _clean(ref)
                    for match in filtered
                    for ref in match.get("supporting_evidence_refs") or []
                    if _clean(ref)
                })
                trace.append({
                    "predicate": predicate,
                    "expected": expected,
                    "matched": sorted({
                        value
                        for match in filtered
                        for value in _texts(
                            match.get(field)
                            if isinstance(match.get(field), list)
                            else [match.get(field)]
                        )
                        if value in expected
                    }),
                    "result": bool(filtered),
                    "evidence_refs": refs,
                })
                matches = filtered
            refs = sorted({
                _clean(ref)
                for match in matches
                for ref in match.get("supporting_evidence_refs") or []
                if _clean(ref)
            })
            return bool(matches and refs), trace, refs
        return _condition_match(rule.get("applies_when"), facts)

    findings: List[Dict[str, Any]] = []
    actions: List[Dict[str, Any]] = []
    if status == "available":
        for rule in document.get("finding_rules") or []:
            if not isinstance(rule, dict):
                continue
            if _clean(rule.get("rule_id")) in blocked_rules:
                continue
            matched, trace, refs = match_rule(rule)
            if not matched or not refs:
                continue
            finding = {
                "rule_id": _clean(rule.get("rule_id")),
                "severity": _clean(rule.get("severity")) or "info",
                "statement": _safe_template(rule.get("statement"), context_values),
                "supporting_evidence_refs": refs,
                "matched_predicates": trace,
                "references": deepcopy(rule.get("references") or []),
                "provenance": deepcopy(rule.get("provenance") or {}),
            }
            if _clean(rule.get("semantic_family")):
                semantic_family = _clean(rule.get("semantic_family"))
                finding.update({
                    "semantic_family": semantic_family,
                    "semantic_trace": deepcopy(
                        semantic_traces.get(semantic_family) or {}
                    ),
                })
                finding["finding_id"] = stable_id(
                    "response_guidance_finding",
                    finding,
                )
            else:
                finding["finding_id"] = stable_id(
                    "response_guidance_finding",
                    {
                        "rule_id": rule.get("rule_id"),
                        "evidence_refs": refs,
                        "evidence_sha256": evidence_sha256,
                    },
                )
            findings.append(finding)
        for rule in document.get("action_playbooks") or []:
            if not isinstance(rule, dict):
                continue
            if _clean(rule.get("rule_id")) in blocked_rules:
                continue
            matched, trace, refs = match_rule(rule)
            if not matched or not refs:
                continue
            for action in rule.get("actions") or []:
                if not isinstance(action, dict):
                    continue
                selected_action = {
                    "action_id": _clean(action.get("action_id")),
                    "rule_id": _clean(rule.get("rule_id")),
                    "description": _safe_template(action.get("action"), context_values),
                    "rationale": _safe_template(action.get("rationale"), context_values),
                    "policy_order": action.get("priority"),
                    "evidence_scope": [CANONICAL_EVIDENCE_SCOPE],
                    "evidence_refs": refs,
                    "matched_predicates": deepcopy(trace),
                    "preconditions": [
                        "Verify each cited Cowrie observation and its visibility limitation.",
                        "Confirm the target system is owned or explicitly authorized before any external change.",
                        "Obtain human approval before performing any external-system action.",
                    ],
                    "verification_steps": [
                        "Record the authorized system and the evidence used for the review.",
                        "Record the observed result without treating absence of evidence as proof of safety.",
                    ],
                    "rollback_guidance": "This system performs no action. Define and approve target-specific rollback before an authorized external change.",
                    "requires_manual_approval": True,
                    "safe_to_auto_execute": False,
                    "execution_integration": "not_implemented",
                    "references": deepcopy(action.get("references") or []),
                    "provenance": {"rule": deepcopy(rule.get("provenance") or {}), "action": deepcopy(action.get("provenance") or {})},
                }
                if _clean(rule.get("semantic_family")):
                    semantic_family = _clean(
                        rule.get("semantic_family")
                    )
                    selected_action.update({
                        "semantic_family": semantic_family,
                        "semantic_trace": deepcopy(
                            semantic_traces.get(semantic_family) or {}
                        ),
                    })
                actions.append(selected_action)
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["rule_id"], item["finding_id"]))
    actions.sort(key=lambda item: (int(item.get("policy_order") or 9999), item["action_id"], item["rule_id"]))
    strongest = findings[0] if findings else None
    guidance_state = "actions_available" if actions else "no_applicable_grounded_action"
    if status != "available":
        guidance_state = "policy_or_profile_unavailable"
    severity = _clean((strongest or {}).get("severity")) or "info"
    triage = {
        "review_priority": severity,
        "urgency": (
            "prompt_review"
            if severity in {"high", "critical"}
            else "routine_review"
        ),
        "semantics": (
            "categorical_observed_evidence_policy_not_score_or_forecast"
        ),
        "finding_ids": [item["finding_id"] for item in findings],
    }
    safety = {
        "automatic_execution": False,
        "manual_approval_required": True,
        "alerting_side_effect": False,
        "response_action_side_effect": False,
        "execution_integration": "not_implemented",
    }
    guidance_id = _guidance_identity(
        session_id=_clean(snapshot.get("session_id")) or "unknown",
        evidence_sha256=evidence_sha256,
        policy_sha256=digest,
        profile_sha256=profile_digest,
        finding_rules=findings,
        actions=actions,
        status=status,
        guidance_state=guidance_state,
        triage=triage,
        safety=safety,
        typed_semantics=typed_provenance,
        binding=(binding := _build_binding(
            snapshot,
            assessment_id=assessment_id,
            assessment_context=assessment_context,
            policy=document,
            policy_sha256=digest,
            policy_source=policy_source,
            policy_path=policy_path,
            policy_status=policy_status,
            policy_document_sha256=policy_document_sha256,
            findings=findings,
            actions=actions,
            semantic_traces=semantic_traces,
            typed_semantic_fact_set=typed_semantic_fact_set,
        )),
    )
    guidance = {
        "schema_version": SCHEMA_VERSION,
        "guidance_id": guidance_id,
        "generated_at": utc_now(),
        "status": status,
        "guidance_state": guidance_state,
        "authority": authority,
        "session_id": _clean(snapshot.get("session_id")) or "unknown",
        "canonical_evidence": snapshot,
        "binding": binding,
        "findings": findings,
        "triage": triage,
        "advisory_actions": actions,
        "non_authoritative_context": {
            "semantics": "Forecast and enrichment are display context only; they do not select findings, triage, actions, or guidance IDs.",
            "forecast": deepcopy(forecast_context) if isinstance(forecast_context, (dict, list)) else {},
            "enrichment": deepcopy(enrichment_context) if isinstance(enrichment_context, (dict, list)) else {},
        },
        "provenance": {
            "canonical_evidence_sha256": evidence_sha256,
            "policy": _policy_metadata(
                document,
                digest,
                policy_source,
                policy_status,
                policy_errors,
                path=policy_path,
                document_sha256=policy_document_sha256,
            ),
            "asset_profile": _profile_metadata(profile_document, profile_digest, asset_profile_source, asset_profile_status, profile_errors),
            "selection_authority": "deterministic_canonical_observed_evidence_only",
            "forecast_authority": "non_authoritative_context_only",
            "enrichment_authority": "non_authoritative_context_only",
            "typed_semantics": typed_provenance,
        },
        "safety": safety,
        "compatibility": {
            "legacy_v1_v2_records_read_only": True,
            "historical_records_recomputed": False,
            "prediction_snapshot_embedding": "prohibited",
            "binding_status": binding.get("status"),
            "historical_unverified_binding": False,
        },
    }
    validation_errors = validate_response_guidance_v3(guidance)
    if validation_errors:
        guidance["status"] = "unavailable"
        guidance["guidance_state"] = "validation_rejected"
        guidance["authority"] = "policy_unavailable"
        guidance["findings"] = []
        guidance["advisory_actions"] = []
        guidance["triage"] = {
            "review_priority": "info",
            "urgency": "routine_review",
            "semantics": "categorical_observed_evidence_policy_not_score_or_forecast",
            "finding_ids": [],
        }
        guidance["guidance_id"] = _guidance_identity(
            session_id=_clean(snapshot.get("session_id")) or "unknown",
            evidence_sha256=evidence_sha256,
            policy_sha256=digest,
            profile_sha256=profile_digest,
            finding_rules=[],
            actions=[],
            status="unavailable",
            guidance_state="validation_rejected",
            triage=guidance["triage"],
            safety=guidance["safety"],
            typed_semantics=typed_provenance,
            binding=binding,
        )
    guidance["validation"] = {"status": "valid" if not validation_errors else "rejected", "errors": validation_errors}
    return guidance


def build_response_guidance_v3_from_paths(
    observed_behavior: Any,
    *,
    policy_path: str = "",
    asset_profile_path: str = "",
    assessment_id: str = "",
    assessment_context: Optional[Dict[str, Any]] = None,
    session_context: Optional[Dict[str, Any]] = None,
    forecast_context: Any = None,
    enrichment_context: Any = None,
    typed_semantic_fact_set: Optional[Dict[str, Any]] = None,
    activated_semantic_families: Iterable[str] = (),
    blocked_policy_rule_ids: Iterable[str] = (),
) -> Dict[str, Any]:
    """Load exact configuration files and evaluate canonical observed evidence."""

    loaded_policy = load_response_guidance_policy(policy_path)
    loaded_profile = load_response_guidance_asset_profile(asset_profile_path)
    return build_response_guidance_v3(
        observed_behavior,
        policy=loaded_policy["document"],
        policy_sha256=loaded_policy["sha256"],
        policy_source=loaded_policy["source"],
        policy_path=loaded_policy.get("path", ""),
        policy_document_sha256=loaded_policy.get("document_sha256", ""),
        policy_status=loaded_policy["status"],
        policy_validation_errors=loaded_policy["validation_errors"],
        asset_profile=loaded_profile["document"],
        asset_profile_sha256=loaded_profile["sha256"],
        asset_profile_source=loaded_profile["source"],
        asset_profile_status=loaded_profile["status"],
        asset_profile_validation_errors=loaded_profile["validation_errors"],
        session_context=session_context,
        forecast_context=forecast_context,
        enrichment_context=enrichment_context,
        typed_semantic_fact_set=typed_semantic_fact_set,
        assessment_id=assessment_id,
        assessment_context=assessment_context,
        activated_semantic_families=activated_semantic_families,
        blocked_policy_rule_ids=blocked_policy_rule_ids,
    )


def build_response_guidance_v3_from_session(
    session_payload: Dict[str, Any],
    *,
    raw_events: Optional[Iterable[Dict[str, Any]]] = None,
    policy_path: str = "",
    asset_profile_path: str = "",
    behavior_policy_document: Optional[Dict[str, Any]] = None,
    behavior_policy_path: str = "",
    classification_policy_path: str = "",
    assessment_id: str = "",
    assessment_context: Optional[Dict[str, Any]] = None,
    forecast_context: Any = None,
    enrichment_context: Any = None,
) -> Dict[str, Any]:
    """Build a current-policy reevaluation without using forecast for selection."""

    from production.reporting.session_assessment_v4 import (
        _file_policy,
        _git_revision,
        build_canonical_evidence_snapshot,
    )
    from production.policies.threat_hypothesis_behavior_policy import (
        policy_summary,
    )
    from production.reporting.typed_semantic_facts import (
        build_typed_semantic_fact_set,
        build_typed_semantic_provenance,
    )

    session = deepcopy(session_payload) if isinstance(session_payload, dict) else {}
    snapshot, observed, _source, behavior = build_canonical_evidence_snapshot(
        session,
        list(raw_events) if raw_events is not None else session.get("raw_events") or [],
        behavior_policy_document=behavior_policy_document,
        behavior_policy_path=behavior_policy_path,
    )
    behavior_summary = policy_summary(behavior, include_integrity=True)
    classification = _file_policy(
        classification_policy_path,
        "configs/classification_rules.trusted.json",
        None,
    )
    typed_fact_set: Dict[str, Any] = {}
    try:
        provenance = build_typed_semantic_provenance(
            snapshot,
            observed_behavior=observed,
            behavior_policy_sha256=_clean(
                behavior_summary.get("sha256")
            ),
            classification_policy_sha256=_clean(
                classification.get("sha256")
            ),
            evaluator_git_revision=_git_revision(),
        )
        typed_fact_set = build_typed_semantic_fact_set(
            observed,
            provenance=provenance,
        )
    except Exception:
        typed_fact_set = {}
    return build_response_guidance_v3_from_paths(
        snapshot,
        policy_path=policy_path,
        asset_profile_path=asset_profile_path,
        session_context=session,
        forecast_context=forecast_context,
        enrichment_context=enrichment_context,
        typed_semantic_fact_set=typed_fact_set,
        assessment_id=assessment_id,
        assessment_context=assessment_context,
        activated_semantic_families=(
            CURRENT_ACTIVATED_SEMANTIC_FAMILIES
        ),
    )


def attach_non_authoritative_guidance_context(
    guidance: Dict[str, Any],
    *,
    forecast_context: Any = None,
    enrichment_context: Any = None,
) -> Dict[str, Any]:
    """Attach display context without changing selection, validation, or ID."""

    updated = deepcopy(guidance) if isinstance(guidance, dict) else {}
    if updated.get("schema_version") != SCHEMA_VERSION:
        return updated
    updated["non_authoritative_context"] = {
        "semantics": "Forecast and enrichment are display context only; they do not select findings, triage, actions, or guidance IDs.",
        "forecast": deepcopy(forecast_context) if isinstance(forecast_context, (dict, list)) else {},
        "enrichment": deepcopy(enrichment_context) if isinstance(enrichment_context, (dict, list)) else {},
    }
    return updated


def read_legacy_response_guidance(record: Any) -> Dict[str, Any]:
    """Expose v1/v2 historical records without promoting legacy actions.

    This is deliberately a display-only adapter.  It never reconstructs or
    authorizes an action, so a historical legacy payload cannot bypass v3.
    """

    value = record if isinstance(record, dict) else {}
    schema = _clean(value.get("schema_version"))
    return {
        "schema_version": LEGACY_ADAPTER_SCHEMA_VERSION,
        "status": "legacy_read_only" if schema in {"smb_decision.v1", "response_guidance.v2"} else "not_available",
        "legacy_schema_version": schema,
        "legacy_guidance_id": _clean(value.get("guidance_id") or value.get("decision_id")),
        "record": deepcopy(value),
        "recomputed": False,
        "advisory_actions": [],
        "semantics": "Historical v1/v2 data is retained without recomputation or action authorization. Reevaluate under response_guidance.v3 for current advisory tasks.",
    }
