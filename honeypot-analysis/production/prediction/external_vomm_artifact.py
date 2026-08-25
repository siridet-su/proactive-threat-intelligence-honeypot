"""Build and validate immutable external hard-backoff VOMM artifacts.

The production artifact intentionally contains aggregate transition counts, not
raw commands, credentials, IP addresses, or source session identifiers.  Its
companion manifest binds the artifact to a privacy-minimized whole-session
split through cryptographic membership digests.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from production.classification.trust import is_trusted_classification_event
from production.correlation.session_ttp_knowledge import main_ttp_id


ARTIFACT_SCHEMA = "external_transition_model.v1"
MANIFEST_SCHEMA = "external_vomm_manifest.v1"
BUILDER_VERSION = "external_hard_backoff_vomm_builder.v1"


def _tactic_sequence(payload: Mapping[str, Any]) -> list[str]:
    events = [
        item
        for item in payload.get("classification_events") or []
        if isinstance(item, dict)
    ]
    sequence = [
        str(item.get("tactic") or "").strip()
        for item in events
        if is_trusted_classification_event(item)
        and str(item.get("tactic") or "").strip() not in {"", "unknown"}
    ]
    if not sequence and not events:
        sequence = [
            str(item or "").strip()
            for item in payload.get("tactics") or []
            if str(item or "").strip() not in {"", "unknown"}
        ]
    return [
        item
        for index, item in enumerate(sequence)
        if index == 0 or sequence[index - 1] != item
    ]


def _technique_sequence(payload: Mapping[str, Any]) -> list[str]:
    events = [
        item
        for item in payload.get("classification_events") or []
        if isinstance(item, dict)
    ]
    sequence = [
        main_ttp_id(item.get("ttp") or item.get("technique"))
        for item in events
        if is_trusted_classification_event(item)
    ]
    if not sequence and not events:
        sequence = [
            main_ttp_id(item)
            for item in payload.get("ttps") or []
            if str(item or "").strip() not in {"", "unknown"}
        ]
    sequence = [item for item in sequence if item and item != "unknown"]
    return [
        item
        for index, item in enumerate(sequence)
        if index == 0 or sequence[index - 1] != item
    ]


def _build_transition_model(
    payloads: Sequence[Mapping[str, Any]],
    *,
    prefix_max_length: int,
) -> Dict[str, Any]:
    """Build the deterministic aggregate counts used by the rollback artifact."""

    transitions: Dict[str, Counter[str]] = defaultdict(Counter)
    prefixes: Dict[str, Counter[str]] = defaultdict(Counter)
    techniques: Dict[str, Counter[str]] = defaultdict(Counter)
    technique_tactics: Dict[str, Counter[str]] = defaultdict(Counter)
    starts: Counter[str] = Counter()
    usable = 0
    completed = 0
    for payload in payloads:
        if not payload.get("is_ended") and str(payload.get("status") or "") != "closed":
            continue
        completed += 1
        tactics = _tactic_sequence(payload)
        if tactics:
            usable += 1
            starts[tactics[0]] += 1
        for current, following in zip(tactics, tactics[1:]):
            transitions[current][following] += 1
        for index in range(1, len(tactics)):
            for start in range(max(0, index - prefix_max_length), index):
                prefix = tactics[start:index]
                if len(prefix) >= 2:
                    prefixes[">".join(prefix)][tactics[index]] += 1

        technique_sequence = _technique_sequence(payload)
        for current, following in zip(technique_sequence, technique_sequence[1:]):
            techniques[current][following] += 1
        for event in payload.get("classification_events") or []:
            if not isinstance(event, dict) or not is_trusted_classification_event(event):
                continue
            technique = main_ttp_id(event.get("ttp") or event.get("technique"))
            tactic = str(event.get("tactic") or "").strip()
            if technique and technique != "unknown" and tactic and tactic != "unknown":
                technique_tactics[technique][tactic] += 1

    serialized_transitions = {
        key: dict(value) for key, value in sorted(transitions.items())
    }
    serialized_prefixes = {
        key: dict(value) for key, value in sorted(prefixes.items())
    }
    serialized_techniques = {
        key: dict(value) for key, value in sorted(techniques.items())
    }
    return {
        "schema_version": "local_transition_model.v2",
        "source_name": "external_seed_transition",
        "source_database": "external_immutable_manifest",
        "completed_sessions": completed,
        "usable_sessions": usable,
        "transition_count": sum(sum(value.values()) for value in transitions.values()),
        "prefix_transition_count": sum(sum(value.values()) for value in prefixes.values()),
        "technique_transition_count": sum(sum(value.values()) for value in techniques.values()),
        "prefix_max_length": prefix_max_length,
        "transitions": serialized_transitions,
        "prefix_transitions": serialized_prefixes,
        "technique_transitions": serialized_techniques,
        "technique_tactics": {
            key: value.most_common(1)[0][0]
            for key, value in sorted(technique_tactics.items())
            if value
        },
        "start_counts": dict(starts),
    }


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _stable_identifier(prefix: str, value: Any) -> str:
    return f"{prefix}_{sha256_bytes(canonical_json_bytes(value))[:32]}"


def _load_payloads(path: str | Path) -> list[Dict[str, Any]]:
    candidate = Path(path)
    payloads: list[Dict[str, Any]] = []
    if candidate.suffix.lower() in {".jsonl", ".ndjson"}:
        with candidate.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSONL at {candidate}:{number}") from exc
                if not isinstance(payload, dict):
                    raise ValueError(f"JSONL item at {candidate}:{number} must be an object")
                payloads.append(dict(payload))
        return payloads
    document = json.loads(candidate.read_text(encoding="utf-8"))
    if isinstance(document, list):
        payloads = document
    elif isinstance(document, dict):
        payloads = document.get("sessions") or document.get("payloads") or []
    if not isinstance(payloads, list):
        raise ValueError("payload input must be a list or contain sessions/payloads")
    return [dict(item) for item in payloads if isinstance(item, dict)]


def _split_payloads(payloads: Sequence[Mapping[str, Any]]) -> Dict[str, list[Dict[str, Any]]]:
    result: Dict[str, list[Dict[str, Any]]] = {name: [] for name in ("train", "validation", "test")}
    aliases = {"calibration": "validation", "validation": "validation"}
    for index, payload in enumerate(payloads):
        raw_split = str(payload.get("split") or "").strip().lower()
        split = aliases.get(raw_split, raw_split)
        if split not in result:
            raise ValueError(
                "every session must use a train, validation/calibration, or test split; "
                f"item {index} has {raw_split!r}"
            )
        session_id = str(payload.get("session_id") or "").strip()
        if not session_id:
            raise ValueError(f"split payload {index} is missing session_id")
        result[split].append(dict(payload))
    if not all(result.values()):
        raise ValueError("train, validation, and test partitions must all contain sessions")
    return result


def _membership(partition: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    identifiers = sorted(str(item.get("session_id") or "").strip() for item in partition)
    if not identifiers or any(not item for item in identifiers):
        raise ValueError("membership contains an empty session identifier")
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("membership contains duplicate session identifiers")
    return {
        "session_count": len(identifiers),
        "membership_hash_algorithm": "sha256(sorted-safe-session-ids-newline-v1)",
        "membership_sha256": sha256_bytes("\n".join(identifiers).encode("utf-8")),
    }


def _split_intersections(split: Mapping[str, Sequence[Mapping[str, Any]]]) -> Dict[str, Any]:
    members = {
        name: {str(item.get("session_id") or "").strip() for item in values}
        for name, values in split.items()
    }
    pairs = {
        "train_validation": members["train"].intersection(members["validation"]),
        "train_test": members["train"].intersection(members["test"]),
        "validation_test": members["validation"].intersection(members["test"]),
    }
    return {
        "all_empty": not any(pairs.values()),
        "counts": {name: len(value) for name, value in sorted(pairs.items())},
        "intersection_hashes": {
            name: sha256_bytes("\n".join(sorted(value)).encode("utf-8"))
            for name, value in sorted(pairs.items())
        },
    }


def _tactic_vocabulary(model: Mapping[str, Any]) -> list[str]:
    tactics = set(str(value) for value in (model.get("start_counts") or {}) if str(value))
    for current, counts in (model.get("transitions") or {}).items():
        if str(current):
            tactics.add(str(current))
        tactics.update(str(value) for value in (counts or {}) if str(value))
    for values in (model.get("technique_tactics") or {}).values():
        if str(values):
            tactics.add(str(values))
    tactics.discard("unknown")
    return sorted(tactics)


def current_git_commit(root: str | Path = ".") -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _date_range(source_start: str, source_end: str) -> Dict[str, Any]:
    start, end = str(source_start or "").strip(), str(source_end or "").strip()
    if not start or not end:
        raise ValueError("source_start and source_end are required temporal provenance")
    return {
        "source_collection": {
            "start": start,
            "end": end,
            "precision": "selected-source-member-date-range",
        },
        "partition_time_semantics": {
            "method": "preassigned_chronological_whole_session_split",
            "order_field": "source first_seen retained by source builder before privacy minimization",
            "per_session_timestamps_in_artifact": False,
            "note": (
                "The public privacy-minimized payload intentionally omits individual timestamps. "
                "Cryptographic membership digests bind the exact partitions; source-level dates bound "
                "the collection window without inventing per-session timestamps."
            ),
        },
    }


def _artifact_model(
    training_payloads: Sequence[Mapping[str, Any]],
    *,
    prefix_max_length: int,
    smoothing: float,
    min_support: int,
    artifact_version: str,
    manifest_id: str,
    source_dataset: Mapping[str, Any],
    model_builder_commit: str,
    classification: Mapping[str, Any],
    trust_policy: Mapping[str, Any],
) -> Dict[str, Any]:
    model = _build_transition_model(
        training_payloads,
        prefix_max_length=prefix_max_length,
    )
    model_id = _stable_identifier(
        "externalvomm",
        {
            "artifact_version": artifact_version,
            "manifest_id": manifest_id,
            "transitions": model.get("transitions"),
            "prefix_transitions": model.get("prefix_transitions"),
            "technique_transitions": model.get("technique_transitions"),
            "prefix_max_length": prefix_max_length,
            "smoothing": smoothing,
            "min_support": min_support,
        },
    )
    model.update(
        {
            "schema_version": ARTIFACT_SCHEMA,
            "artifact_contract": "external_hard_backoff_vomm.v1",
            "artifact_version": artifact_version,
            "model_id": model_id,
            # A deterministic artifact must not embed wall-clock build time.
            "built_at": f"artifact-version:{artifact_version}",
            "source_type": "external_cowrie_seed",
            "source_name": "external_seed_transition",
            "smoothing": float(smoothing),
            "support_thresholds": {
                "min_transition_count": int(min_support),
                "min_prefix_transition_count": int(min_support),
                "min_technique_transition_count": int(min_support),
                "min_tactic_transition_count": int(min_support),
            },
            "tactic_vocabulary": _tactic_vocabulary(model),
            "provenance": {
                "manifest_id": manifest_id,
                "dataset_handle": source_dataset.get("name"),
                "dataset_sha256": source_dataset.get("sha256"),
                "model_builder_version": BUILDER_VERSION,
                "model_builder_commit": model_builder_commit,
                "classification_policy_sha256": classification.get("sha256"),
                "securebert_checkpoint_id": classification.get("securebert_checkpoint_id"),
                "securebert_checkpoint_sha256": classification.get("securebert_checkpoint_sha256"),
                "trust_policy_sha256": trust_policy.get("sha256"),
                "training_source": "manifest-bound train plus validation whole sessions only",
            },
        }
    )
    return model


def build_external_vomm_artifact(
    *,
    payload_path: str | Path,
    artifact_path: str | Path,
    manifest_path: str | Path,
    artifact_version: str,
    source_start: str,
    source_end: str,
    preprocessing: Mapping[str, Any],
    classification: Mapping[str, Any],
    trust_policy: Mapping[str, Any],
    model_builder_commit: str = "",
) -> Dict[str, Any]:
    """Build an immutable external-only artifact from train+validation only."""

    payload_file = Path(payload_path)
    artifact_file = Path(artifact_path)
    manifest_file = Path(manifest_path)
    payloads = _load_payloads(payload_file)
    split = _split_payloads(payloads)
    intersections = _split_intersections(split)
    if not intersections["all_empty"]:
        raise ValueError("train/validation/test membership intersection is non-empty")

    source_names = {
        str(item.get("dataset_source") or "").strip()
        for item in payloads
        if str(item.get("dataset_source") or "").strip()
    }
    if len(source_names) != 1:
        raise ValueError("payloads must declare exactly one source dataset name")
    prefix_max_length = max(int(preprocessing.get("prefix_max_length") or 3), 1)
    smoothing = max(float(preprocessing.get("transition_smoothing") or 0.0), 0.0)
    min_support = max(int(preprocessing.get("min_transition_count") or 1), 1)
    source_dataset = {
        "name": next(iter(source_names)),
        "payload_path": str(payload_file),
        "sha256": sha256_file(payload_file),
        "payload_schema_versions": sorted(
            {str(item.get("schema_version") or "") for item in payloads}
        ),
    }
    memberships = {name: _membership(rows) for name, rows in split.items()}
    manifest_base: Dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA,
        "artifact_contract": "external_hard_backoff_vomm.v1",
        "artifact_version": str(artifact_version),
        "builder": {
            "version": BUILDER_VERSION,
            "code_commit": str(model_builder_commit or current_git_commit()),
        },
        "source_dataset": source_dataset,
        "temporal_provenance": _date_range(source_start, source_end),
        "partitions": memberships,
        "partition_intersections": intersections,
        "preprocessing": deepcopy(dict(preprocessing)),
        "preprocessing_sha256": sha256_bytes(canonical_json_bytes(preprocessing)),
        "classification": deepcopy(dict(classification)),
        "trust_policy": deepcopy(dict(trust_policy)),
        "deduplication": {
            "unit": "adjacent tactic sequence entries",
            "behavior": "adjacent duplicate tactics collapsed before transition construction",
            "whole_session_split_before_case_extraction": True,
        },
        "training_data": {
            "included_partitions": ["train", "validation"],
            "excluded_partitions": ["test"],
            "session_count": len(split["train"]) + len(split["validation"]),
        },
        "test_data": {
            "session_count": len(split["test"]),
            "purpose": "held_out_evaluation_only",
        },
    }
    manifest_id = _stable_identifier("externalvommmanifest", manifest_base)
    artifact = _artifact_model(
        [*split["train"], *split["validation"]],
        prefix_max_length=prefix_max_length,
        smoothing=smoothing,
        min_support=min_support,
        artifact_version=str(artifact_version),
        manifest_id=manifest_id,
        source_dataset=source_dataset,
        model_builder_commit=str(model_builder_commit or current_git_commit()),
        classification=classification,
        trust_policy=trust_policy,
    )
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    artifact_file.write_bytes(canonical_json_bytes(artifact))
    artifact_sha256 = sha256_file(artifact_file)
    manifest = {
        **manifest_base,
        "manifest_id": manifest_id,
        "artifact": {
            "sha256": artifact_sha256,
            "model_id": artifact["model_id"],
            "schema_version": artifact["schema_version"],
            "size_bytes": artifact_file.stat().st_size,
        },
        "tactic_vocabulary": artifact["tactic_vocabulary"],
        "model_parameters": {
            "hard_backoff_order": ["prefix", "technique", "tactic"],
            "prefix_max_length": prefix_max_length,
            "transition_smoothing": smoothing,
            "support_thresholds": artifact["support_thresholds"],
            "model_builder_version": BUILDER_VERSION,
        },
    }
    manifest_file.parent.mkdir(parents=True, exist_ok=True)
    manifest_file.write_bytes(canonical_json_bytes(manifest))
    return {
        "artifact": artifact,
        "manifest": manifest,
        "artifact_sha256": artifact_sha256,
        "manifest_sha256": sha256_file(manifest_file),
    }


def load_external_vomm_artifact(
    artifact_path: str | Path,
    manifest_path: str | Path,
    *,
    expected_artifact_sha256: str = "",
    expected_model_id: str = "",
    expected_manifest_id: str = "",
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Load a manifest-bound model; invalid input is unavailable, never guessed."""

    artifact_file, manifest_file = Path(artifact_path), Path(manifest_path)
    reasons: list[str] = []
    if not artifact_file.is_file():
        reasons.append("artifact_path_missing")
    if not manifest_file.is_file():
        reasons.append("manifest_path_missing")
    if reasons:
        return {}, {"status": "unavailable", "valid": False, "reasons": reasons}
    try:
        artifact = json.loads(artifact_file.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}, {"status": "unavailable", "valid": False, "reasons": ["artifact_or_manifest_json_malformed"]}
    if not isinstance(artifact, dict) or not isinstance(manifest, dict):
        return {}, {"status": "unavailable", "valid": False, "reasons": ["artifact_or_manifest_not_object"]}
    actual_sha256 = sha256_file(artifact_file)
    manifest_artifact = manifest.get("artifact") if isinstance(manifest.get("artifact"), dict) else {}
    intersections = manifest.get("partition_intersections") if isinstance(manifest.get("partition_intersections"), dict) else {}
    if artifact.get("schema_version") != ARTIFACT_SCHEMA:
        reasons.append("unsupported_artifact_schema")
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        reasons.append("unsupported_manifest_schema")
    if manifest_artifact.get("sha256") != actual_sha256:
        reasons.append("manifest_artifact_sha256_mismatch")
    if expected_artifact_sha256 and actual_sha256 != expected_artifact_sha256:
        reasons.append("expected_artifact_sha256_mismatch")
    if expected_model_id and artifact.get("model_id") != expected_model_id:
        reasons.append("expected_model_id_mismatch")
    if expected_manifest_id and manifest.get("manifest_id") != expected_manifest_id:
        reasons.append("expected_manifest_id_mismatch")
    if manifest_artifact.get("model_id") != artifact.get("model_id"):
        reasons.append("manifest_model_id_mismatch")
    if manifest.get("manifest_id") != (artifact.get("provenance") or {}).get("manifest_id"):
        reasons.append("artifact_manifest_id_mismatch")
    if not bool(intersections.get("all_empty")):
        reasons.append("partition_overlap_not_proven_empty")
    for name in ("train", "validation", "test"):
        membership = (manifest.get("partitions") or {}).get(name) or {}
        if not membership.get("membership_sha256") or int(membership.get("session_count") or 0) <= 0:
            reasons.append(f"missing_{name}_membership")
    for section, keys in (
        ("classification", ("sha256", "securebert_checkpoint_id", "securebert_checkpoint_sha256")),
        ("trust_policy", ("sha256",)),
    ):
        values = manifest.get(section) if isinstance(manifest.get(section), dict) else {}
        for key in keys:
            if not str(values.get(key) or "").strip():
                reasons.append(f"missing_{section}_{key}")
    status = "valid" if not reasons else "unavailable"
    return (
        artifact if not reasons else {},
        {
            "status": status,
            "valid": not reasons,
            "reasons": reasons,
            "artifact_path": str(artifact_file),
            "manifest_path": str(manifest_file),
            "actual_artifact_sha256": actual_sha256,
            "manifest_sha256": sha256_file(manifest_file),
            "model_id": str(artifact.get("model_id") or ""),
            "manifest_id": str(manifest.get("manifest_id") or ""),
            "artifact_version": str(artifact.get("artifact_version") or ""),
            "manifest": manifest,
        },
    )
