"""Frozen classifier-output policy for the corrected next-behavior corpus.

The runtime classifier emits rich events whose trust threshold is deliberately
broader than the historical experiment's 0.90 model-only threshold. This
adapter preserves that distinction, uses the central runtime trust predicate
as a lower safety boundary, and converts every defensible candidate into the
strict private label shape consumed by ``next_behavior_corpus``.
"""

from __future__ import annotations

import re
from collections import Counter
from math import isfinite
from typing import Any, Callable, Dict, Mapping, Sequence

from production.classification.trust import (
    is_opaque_securebert_probe,
    is_trusted_classification_event,
)
from production.prediction.next_behavior_contract import TACTIC_VOCABULARY


_TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_RULE_SOURCES = frozenset({"rule"})
_AGREEMENT_SOURCES = frozenset({"both"})
_MODEL_SOURCES = frozenset({"securebert", "securebert_low_confidence"})
_DISAGREEMENT_SOURCES = frozenset({"rule_securebert_disagreement"})
_EMERGENCY_SOURCES = frozenset({"emergency_python_fallback"})


class NextBehaviorLabelPolicyError(ValueError):
    """Raised when the frozen label policy inputs are invalid."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256(value: Any) -> str:
    text = _clean(value).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise NextBehaviorLabelPolicyError("policy hashes must be SHA-256 digests")
    return text


def _score(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    score = float(value)
    return score if isfinite(score) and 0.0 <= score <= 1.0 else None


def _confidence_bucket(score: float | None) -> str:
    if score is None:
        return "not_applicable"
    if score >= 0.90:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def _canonical_tactic(
    technique: str,
    tactic: Any,
    tactic_lookup: Callable[[str], str | None],
) -> str:
    candidate = _clean(tactic).lower()
    if candidate in TACTIC_VOCABULARY:
        return candidate
    looked_up = _clean(tactic_lookup(technique)).lower()
    return looked_up if looked_up in TACTIC_VOCABULARY else ""


def _base_label(
    *,
    tactic: str,
    technique: str,
    source: str,
    policy_sha256: str,
    trust_policy_sha256: str,
    checkpoint_sha256: str,
    confidence: float | None,
    agreement_status: str,
    evidence_ref: str,
    trusted: bool,
    exclusion_reason: str = "",
) -> Dict[str, Any]:
    label: Dict[str, Any] = {
        "tactic": tactic,
        "technique": technique,
        "source": source,
        "trust_tier": (
            "trusted_observation" if trusted else "audit_only_candidate"
        ),
        "policy_sha256": policy_sha256,
        "trust_policy_sha256": trust_policy_sha256,
        "checkpoint_sha256": (
            checkpoint_sha256
            if source in {"securebert", "rule_model_agreement"}
            else ""
        ),
        "confidence": confidence,
        "confidence_bucket": _confidence_bucket(confidence),
        "agreement_status": agreement_status,
        "evidence_ref": evidence_ref,
    }
    if not trusted:
        label["exclusion_reason"] = exclusion_reason
    return label


def normalize_classifier_outputs(
    outputs: Sequence[Mapping[str, Any]],
    *,
    private_evidence_prefix: str,
    policy_sha256: str,
    trust_policy_sha256: str,
    checkpoint_sha256: str,
    tactic_lookup: Callable[[str], str | None],
    trusted_model_only_threshold: float = 0.90,
) -> Dict[str, Any]:
    """Convert classifier events to trusted/audit-only private labels.

    The returned ``unrepresented_by_reason`` counts outputs such as shell noise
    or malformed/unknown labels that cannot safely be represented as ATT&CK
    provenance. It must be included in the aggregate reconciliation receipt;
    it is never converted to a fabricated tactic or technique.
    """

    if not isinstance(outputs, Sequence) or isinstance(outputs, (str, bytes)):
        raise NextBehaviorLabelPolicyError("classifier outputs must be a sequence")
    if not callable(tactic_lookup):
        raise NextBehaviorLabelPolicyError("tactic_lookup must be callable")
    policy_hash = _sha256(policy_sha256)
    trust_hash = _sha256(trust_policy_sha256)
    checkpoint_hash = _sha256(checkpoint_sha256)
    if not _clean(private_evidence_prefix):
        raise NextBehaviorLabelPolicyError("private evidence prefix is required")
    if (
        isinstance(trusted_model_only_threshold, bool)
        or not isinstance(trusted_model_only_threshold, (int, float))
        or not isfinite(float(trusted_model_only_threshold))
        or not 0.55 <= float(trusted_model_only_threshold) <= 1.0
    ):
        raise NextBehaviorLabelPolicyError(
            "trusted model-only threshold must be finite and in [0.55, 1]"
        )

    labels: list[Dict[str, Any]] = []
    unrepresented: Counter[str] = Counter()

    def append_candidate(
        *,
        technique_value: Any,
        tactic_value: Any,
        source: str,
        confidence: float | None,
        agreement_status: str,
        evidence_suffix: str,
        trusted: bool,
        exclusion_reason: str = "",
    ) -> bool:
        technique = _clean(technique_value).upper()
        if not _TECHNIQUE_ID.fullmatch(technique):
            unrepresented["malformed_label"] += 1
            return False
        tactic = _canonical_tactic(technique, tactic_value, tactic_lookup)
        if not tactic:
            unrepresented["malformed_label"] += 1
            return False
        labels.append(
            _base_label(
                tactic=tactic,
                technique=technique,
                source=source,
                policy_sha256=policy_hash,
                trust_policy_sha256=trust_hash,
                checkpoint_sha256=checkpoint_hash,
                confidence=confidence,
                agreement_status=agreement_status,
                evidence_ref=f"{private_evidence_prefix}:{evidence_suffix}",
                trusted=trusted,
                exclusion_reason=exclusion_reason,
            )
        )
        return True

    for output_index, raw_output in enumerate(outputs):
        if not isinstance(raw_output, Mapping):
            unrepresented["malformed_label"] += 1
            continue
        output = dict(raw_output)
        source = _clean(output.get("source")).lower()
        evidence_base = f"output-{output_index}"

        if source in _DISAGREEMENT_SOURCES:
            represented = append_candidate(
                technique_value=output.get("ttp"),
                tactic_value=output.get("tactic"),
                source="reviewed_rule",
                confidence=None,
                agreement_status="disagreed",
                evidence_suffix=f"{evidence_base}:rule",
                trusted=False,
                exclusion_reason="unresolved_conflict",
            )
            represented = (
                append_candidate(
                    technique_value=output.get("bert_ttp"),
                    tactic_value=output.get("bert_tactic"),
                    source="securebert",
                    confidence=_score(output.get("bert_confidence")),
                    agreement_status="disagreed",
                    evidence_suffix=f"{evidence_base}:model",
                    trusted=False,
                    exclusion_reason="unresolved_conflict",
                )
                or represented
            )
            if not represented:
                unrepresented["unresolved_conflict"] += 1
            continue

        if source in _EMERGENCY_SOURCES:
            append_candidate(
                technique_value=output.get("ttp"),
                tactic_value=output.get("tactic"),
                source="reviewed_rule",
                confidence=None,
                agreement_status="emergency",
                evidence_suffix=evidence_base,
                trusted=False,
                exclusion_reason="emergency_rule",
            )
            continue

        if source in _RULE_SOURCES:
            trusted = is_trusted_classification_event(output)
            append_candidate(
                technique_value=output.get("ttp"),
                tactic_value=output.get("tactic"),
                source="reviewed_rule",
                confidence=None,
                agreement_status="rule_only",
                evidence_suffix=evidence_base,
                trusted=trusted,
                exclusion_reason="" if trusted else "unreviewed_rule",
            )
            continue

        if source in _AGREEMENT_SOURCES:
            trusted = is_trusted_classification_event(output)
            append_candidate(
                technique_value=output.get("ttp"),
                tactic_value=output.get("tactic"),
                source="rule_model_agreement",
                confidence=_score(output.get("bert_confidence")),
                agreement_status="agreed",
                evidence_suffix=evidence_base,
                trusted=trusted,
                exclusion_reason="" if trusted else "unresolved_conflict",
            )
            continue

        if source in _MODEL_SOURCES:
            confidence = _score(output.get("confidence"))
            opaque = is_opaque_securebert_probe(output)
            trusted = bool(
                not opaque
                and confidence is not None
                and confidence >= float(trusted_model_only_threshold)
                and is_trusted_classification_event(output)
            )
            append_candidate(
                technique_value=output.get("ttp"),
                tactic_value=output.get("tactic"),
                source="securebert",
                confidence=confidence,
                agreement_status="model_only",
                evidence_suffix=evidence_base,
                trusted=trusted,
                exclusion_reason=(
                    ""
                    if trusted
                    else "opaque_model_probe"
                    if opaque
                    else "below_trusted_threshold"
                ),
            )
            continue

        if source == "shell_noise":
            unrepresented["shell_noise"] += 1
        elif source in {"securebert_error", "securebert_unavailable", "unclassified"}:
            unrepresented["malformed_label"] += 1
        else:
            unrepresented["missing_provenance"] += 1

    return {
        "labels": labels,
        "unrepresented_by_reason": dict(sorted(unrepresented.items())),
    }
