"""Offline mechanics for the preregistered Model1 + gated Model2 RRF design.

This code does not imply that either ranking performance or the candidate
model has been validated. Model2 may support Model1 candidates only.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


K = 60
W1 = 1.0
W2 = 0.25
T1105_VOTE_ENABLED_BY_DEFAULT = False
TECHNIQUE_RE = re.compile(r"^(T[0-9]{4})(?:\.[0-9]{3})?$")
IDENTITY_FIELDS = ("session_id", "run_id", "measurement_id", "episode_id")
SHARED = ("T1105", "T1046", "T1110")


class RRFContractError(ValueError):
    pass


def _technique(value: Any) -> str:
    text = str(value or "").strip().upper()
    match = TECHNIQUE_RE.fullmatch(text)
    if not match:
        raise RRFContractError("invalid_model1_technique")
    return match.group(1)


def _time(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise RRFContractError("model2_timestamp_invalid") from None
    if parsed.tzinfo is None:
        raise RRFContractError("model2_timestamp_naive")
    return parsed.astimezone(timezone.utc)


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _model1_rank_sum(events: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    unique: dict[str, tuple[str, Mapping[str, Any]]] = {}
    for event in events:
        if not isinstance(event, Mapping):
            raise RRFContractError("model1_event_invalid")
        event_id = str(event.get("source_event_key") or "")
        topk = event.get("topk")
        if not event_id or not isinstance(topk, Sequence) or isinstance(topk, (str, bytes)):
            raise RRFContractError("model1_event_key_or_topk_missing")
        digest = _fingerprint(topk)
        if event_id in unique and unique[event_id][0] != digest:
            raise RRFContractError("model1_event_key_collision")
        unique[event_id] = (digest, event)
    if not unique:
        return {}
    scores: dict[str, float] = {}
    n = len(unique)
    for _, event in unique.values():
        collapsed: list[str] = []
        seen: set[str] = set()
        for item in event["topk"]:
            label = _technique(item.get("technique_id") if isinstance(item, Mapping) else item)
            if label not in seen:
                seen.add(label)
                collapsed.append(label)
        for rank, label in enumerate(collapsed, start=1):
            scores[label] = scores.get(label, 0.0) + W1 * (1.0 / n) * (1.0 / (K + rank))
    return scores


def _model2_votes(
    model2: Mapping[str, Any] | None,
    *,
    expected_identity: Mapping[str, Any],
    expected_model_sha256: str,
    expected_feature_contract_sha256: str,
    now: datetime,
    max_age_seconds: int,
    allow_t1105: bool,
) -> set[str]:
    if not isinstance(expected_identity, Mapping):
        return set()
    if not isinstance(model2, Mapping) or model2.get("status") != "VALID_SHADOW":
        return set()
    if model2.get("authority") != "NON_AUTHORITATIVE_SHADOW_ONLY":
        return set()
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds < 0:
        return set()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        return set()
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_model_sha256 or "")) or not re.fullmatch(
        r"[0-9a-f]{64}", str(expected_feature_contract_sha256 or "")
    ):
        return set()
    if any(not str(expected_identity.get(key) or "") for key in IDENTITY_FIELDS):
        return set()
    if model2.get("model_sha256") != expected_model_sha256 or model2.get("feature_contract_sha256") != expected_feature_contract_sha256:
        return set()
    identity = model2.get("identity")
    if not isinstance(identity, Mapping) or any(str(identity.get(key) or "") != str(expected_identity.get(key) or "") for key in IDENTITY_FIELDS):
        return set()
    try:
        age = (now.astimezone(timezone.utc) - _time(model2.get("generated_at"))).total_seconds()
    except (RRFContractError, AttributeError):
        return set()
    if age < 0 or age > max_age_seconds:
        return set()
    outputs = model2.get("outputs")
    gates = model2.get("eligibility")
    if not isinstance(outputs, Mapping) or not isinstance(gates, Mapping):
        return set()
    if any(gates.get(key) != "PASS" for key in ("session_binding", "run_binding", "measurement_binding", "episode_binding", "feature_complete")):
        return set()
    votes: set[str] = set()
    for label in SHARED:
        if label == "T1105" and not allow_t1105:
            continue
        item = outputs.get(label)
        if not isinstance(item, Mapping) or item.get("result") != "PRESENT":
            continue
        if label == "T1046" and any(gates.get(key) != "PASS" for key in ("pcap_binding", "zeek_binding", "network_complete")):
            continue
        if label == "T1110" and gates.get("auth_binding") != "PASS":
            continue
        votes.add(label)
    return votes


def rank_candidates(
    model1_events: Sequence[Mapping[str, Any]],
    model2: Mapping[str, Any] | None,
    *,
    expected_identity: Mapping[str, Any],
    expected_model_sha256: str,
    expected_feature_contract_sha256: str,
    now: datetime,
    max_age_seconds: int = 300,
    allow_t1105: bool = T1105_VOTE_ENABLED_BY_DEFAULT,
) -> dict[str, Any]:
    """Return Model1 candidates sorted by RRF score; never a probability."""
    base = _model1_rank_sum(model1_events)
    if not base:
        return {
            "status": "NO_MODEL1_CANDIDATES",
            "ranking_semantics": "RRF_ADVISORY_RANK_SCORE_NOT_PROBABILITY",
            "candidates": [],
        }
    votes = _model2_votes(
        model2,
        expected_identity=expected_identity,
        expected_model_sha256=expected_model_sha256,
        expected_feature_contract_sha256=expected_feature_contract_sha256,
        now=now,
        max_age_seconds=max_age_seconds,
        allow_t1105=allow_t1105,
    )
    # Model2 is corroboration only; support for a technique absent from Model1
    # cannot enter the returned candidates or the applied-vote ledger.
    votes.intersection_update(base)
    candidates = []
    for label, score in base.items():
        added = label in votes
        combined = score + (W2 / (K + 1) if added else 0.0)
        candidates.append({
            "technique_id": label,
            "advisory_rank_score": combined,
            "model2_support_added": added,
        })
    candidates.sort(key=lambda item: (-item["advisory_rank_score"], item["technique_id"]))
    return {
        "status": "AVAILABLE",
        "ranking_semantics": "RRF_ADVISORY_RANK_SCORE_NOT_PROBABILITY",
        "model2_vote_labels": sorted(votes),
        "candidate_set_source": "MODEL1_ONLY",
        "candidates": candidates,
    }
