"""Bounded trusted behavior history for frozen Transformer inference."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping

from production.prediction.evidence_cutoff import validate_evidence_cutoff
from production.utils.serialization import stable_json


SCHEMA_VERSION = "prediction_trusted_history_manifest.v2"
LEGACY_SCHEMA_VERSION = "prediction_trusted_history_manifest.v1"
MAX_TRUSTED_PHASES = 8


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _phase_hash_basis(phase: Mapping[str, Any]) -> dict[str, Any]:
    basis = deepcopy(dict(phase))
    basis.pop("phase_sha256", None)
    return basis


def phase_sha256(phase: Mapping[str, Any]) -> str:
    """Return the content hash for one canonical trusted phase."""

    return _sha(_phase_hash_basis(phase))


def _label_key(label: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        _text(label.get("tactic")),
        _text(label.get("technique")).upper(),
        _text(label.get("classification_evidence_id") or label.get("evidence_id")),
    )


def _phase_labels(phase: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Return exact tactic/technique pairs, accepting the v1 parallel form."""

    raw_labels = phase.get("labels")
    labels: List[Dict[str, Any]] = []
    if isinstance(raw_labels, list):
        for raw in raw_labels:
            if not isinstance(raw, Mapping):
                continue
            tactic = _text(raw.get("tactic"))
            technique = _text(raw.get("technique")).upper()
            if not tactic or tactic.lower() == "unknown":
                continue
            if not technique or technique == "T0000_UNKNOWN":
                continue
            item = {
                "tactic": tactic,
                "technique": technique,
            }
            evidence_id = _text(
                raw.get("classification_evidence_id") or raw.get("evidence_id")
            )
            if evidence_id:
                item["classification_evidence_id"] = evidence_id
            labels.append(item)
    else:
        tactics = [
            _text(item)
            for item in phase.get("tactics") or []
            if _text(item) and _text(item).lower() != "unknown"
        ]
        techniques = [
            _text(item).upper()
            for item in phase.get("techniques") or []
            if _text(item) and _text(item).upper() != "T0000_UNKNOWN"
        ]
        # A v1 phase is safely adaptable only when it has an unambiguous
        # one-to-one label.  Never invent associations for multi-label phases.
        if len(tactics) == 1 and len(techniques) == 1:
            labels.append({"tactic": tactics[0], "technique": techniques[0]})

    unique = {_label_key(item): item for item in labels}
    return [unique[key] for key in sorted(unique)]


def normalize_trusted_phases(
    phases: Iterable[Mapping[str, Any]],
    *,
    cap: int | None = MAX_TRUSTED_PHASES,
) -> List[Dict[str, Any]]:
    """Normalize exact pairs, optionally retaining only the final bounded ring."""

    result: List[Dict[str, Any]] = []
    for phase in phases or []:
        if not isinstance(phase, Mapping):
            continue
        labels = _phase_labels(phase)
        if not labels:
            continue
        tactics = sorted({item["tactic"] for item in labels})
        techniques = sorted({item["technique"] for item in labels})
        result.append({
            "command_index": int(phase.get("command_index") or len(result)),
            "event_id": _text(phase.get("event_id")),
            "tactics": tactics,
            "techniques": techniques,
            "labels": labels,
        })
    return result[-cap:] if cap is not None else result


def _hashed_phases(phases: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {**deepcopy(dict(phase)), "phase_sha256": phase_sha256(phase)}
        for phase in phases
    ]


def validate_prediction_trusted_history_manifest(
    value: Any,
    *,
    expected_phases: Iterable[Mapping[str, Any]] | None = None,
) -> list[str]:
    """Validate every v2 digest and its bound ordering/count metadata.

    v1 records remain readable through the legacy contract.  This strict
    validator is intentionally v2-only: a caller that advertises v2 cannot
    downgrade to shape-only/hash-looking checks.
    """

    errors: list[str] = []
    if not isinstance(value, Mapping):
        return ["prediction trusted history manifest must be an object"]
    if value.get("schema_version") != SCHEMA_VERSION:
        return ["prediction trusted history manifest schema is not v2"]
    errors.extend(validate_evidence_cutoff(value.get("evidence_cutoff")))
    environment_hash = _text(value.get("classifier_environment_sha256")).lower()
    if len(environment_hash) != 64 or any(
        character not in "0123456789abcdef" for character in environment_hash
    ):
        errors.append("classifier_environment_sha256 is invalid")
    if value.get("maximum_trusted_phases") != MAX_TRUSTED_PHASES:
        errors.append("maximum_trusted_phases is invalid")
    phases = value.get("ordered_trusted_phases")
    if not isinstance(phases, list) or len(phases) > MAX_TRUSTED_PHASES:
        errors.append("ordered_trusted_phases exceeds the v2 maximum")
        phases = phases if isinstance(phases, list) else []
    int_fields = (
        "original_trusted_phase_count",
        "selected_trusted_phase_count",
        "omitted_prefix_phase_count",
    )
    counts: dict[str, int] = {}
    for field in int_fields:
        raw = value.get(field)
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            errors.append(f"{field} is invalid")
        else:
            counts[field] = raw
    selected = counts.get("selected_trusted_phase_count")
    original = counts.get("original_trusted_phase_count")
    omitted = counts.get("omitted_prefix_phase_count")
    if selected is not None and selected != len(phases):
        errors.append("selected_trusted_phase_count does not match phases")
    if (
        original is not None
        and selected is not None
        and omitted is not None
        and original != selected + omitted
    ):
        errors.append("trusted history counts do not reconcile")
    if omitted is not None and value.get("truncated") is not (omitted > 0):
        errors.append("truncated does not match omitted_prefix_phase_count")
    previous_command_index: int | None = None
    for index, phase in enumerate(phases):
        path = f"ordered_trusted_phases[{index}]"
        if not isinstance(phase, Mapping):
            errors.append(f"{path} must be an object")
            continue
        command_index = phase.get("command_index")
        if isinstance(command_index, bool) or not isinstance(command_index, int) or command_index < 0:
            errors.append(f"{path}.command_index is invalid")
        elif previous_command_index is not None and command_index <= previous_command_index:
            errors.append(f"{path}.command_index is not strictly ordered")
        else:
            previous_command_index = command_index
        labels = phase.get("labels")
        if not isinstance(labels, list) or not labels:
            errors.append(f"{path}.labels is invalid")
        else:
            label_pairs: list[tuple[str, str]] = []
            for label_index, label in enumerate(labels):
                if not isinstance(label, Mapping):
                    errors.append(f"{path}.labels[{label_index}] is invalid")
                    continue
                tactic = _text(label.get("tactic"))
                technique = _text(label.get("technique")).upper()
                if not tactic or not technique:
                    errors.append(f"{path}.labels[{label_index}] is incomplete")
                pair = (tactic, technique)
                if pair in label_pairs:
                    errors.append(f"{path}.labels contains duplicate pairs")
                label_pairs.append(pair)
            if phase.get("tactics") != sorted({pair[0] for pair in label_pairs}):
                errors.append(f"{path}.tactics do not match labels")
            if phase.get("techniques") != sorted({pair[1] for pair in label_pairs}):
                errors.append(f"{path}.techniques do not match labels")
        supplied_hash = _text(phase.get("phase_sha256")).lower()
        if len(supplied_hash) != 64 or any(
            character not in "0123456789abcdef" for character in supplied_hash
        ):
            errors.append(f"{path}.phase_sha256 is invalid")
        elif phase_sha256(phase) != supplied_hash:
            errors.append(f"{path}.phase_sha256 mismatch")
    if _sha(phases) != _text(value.get("ordered_trusted_phases_sha256")).lower():
        errors.append("ordered_trusted_phases_sha256 mismatch")
    basis = deepcopy(dict(value))
    basis.pop("history_manifest_sha256", None)
    manifest_hash = _text(value.get("history_manifest_sha256")).lower()
    if len(manifest_hash) != 64 or _sha(basis) != manifest_hash:
        errors.append("history_manifest_sha256 mismatch")
    if expected_phases is not None:
        expected = _hashed_phases(
            normalize_trusted_phases(expected_phases, cap=None)[-MAX_TRUSTED_PHASES:]
        )
        if phases != expected:
            errors.append("trusted history phases do not match the manifest")
    return errors


def build_prediction_trusted_history_manifest(
    *,
    phases: Iterable[Mapping[str, Any]],
    evidence_cutoff: Mapping[str, Any],
    classifier_environment: Mapping[str, Any],
    original_trusted_phase_count: int | None = None,
) -> Dict[str, Any]:
    complete = normalize_trusted_phases(phases, cap=None)
    normalized = _hashed_phases(complete[-MAX_TRUSTED_PHASES:])
    ordered_hash = _sha(normalized)
    original_count = (
        len(complete)
        if original_trusted_phase_count is None
        else max(int(original_trusted_phase_count), len(normalized))
    )
    omitted = max(original_count - len(normalized), 0)
    basis = {
        "schema_version": SCHEMA_VERSION,
        "evidence_cutoff": deepcopy(dict(evidence_cutoff or {})),
        "classifier_environment_sha256": _text(
            classifier_environment.get("environment_sha256")
        ),
        "maximum_trusted_phases": MAX_TRUSTED_PHASES,
        "original_trusted_phase_count": original_count,
        "selected_trusted_phase_count": len(normalized),
        "omitted_prefix_phase_count": omitted,
        "truncated": omitted > 0,
        "ordered_trusted_phases": normalized,
        "ordered_trusted_phases_sha256": ordered_hash,
    }
    return {**basis, "history_manifest_sha256": _sha(basis)}
