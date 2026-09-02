"""Focused, offline regressions for Mongo event head selection.

The reference implementation in this module is intentionally independent of
the proposed aggregation.  It checks the existing correlated predecessor
contract with direct nested iteration, while the optimized reference selects
the earliest unprocessed row per session before applying the same predicate.
"""

from __future__ import annotations

import inspect
from itertools import product
from typing import Any

from production.storage import MongoDBStorageBackend


NOW = "2026-08-28T00:00:00+00:00"
ATTEMPT_LIMIT = 5
_MISSING = object()


def _event(
    event_id: str,
    session_id: str,
    received_at: str,
    state: str = "claimable",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "_id": event_id,
        "event_id": event_id,
        "session_id": session_id,
        "received_at": received_at,
        "processed": False,
        "attempts": 1,
        "next_retry_at": None,
        "claim_token": None,
        "claim_expires_at": None,
    }
    if state == "delayed":
        row["next_retry_at"] = "2026-08-28T01:00:00+00:00"
    elif state == "leased":
        row["claim_token"] = "00000000-0000-4000-8000-000000000001"
        row["claim_expires_at"] = "2026-08-28T01:00:00+00:00"
    elif state == "expired_lease":
        row["claim_token"] = "00000000-0000-4000-8000-000000000001"
        row["claim_expires_at"] = "2026-08-27T23:00:00+00:00"
    elif state == "exhausted":
        row["attempts"] = ATTEMPT_LIMIT
    elif state == "processed":
        row["processed"] = True
    elif state == "missing_optional":
        row.pop("next_retry_at")
        row.pop("claim_token")
        row.pop("claim_expires_at")
    elif state != "claimable":
        raise AssertionError(f"unknown fixture state: {state}")
    return row


def _eligible_time(row: dict[str, Any], field: str) -> bool:
    value = row.get(field, _MISSING)
    return value is _MISSING or value is None or str(value) <= NOW


def _matches(row: dict[str, Any], mode: str) -> bool:
    if row.get("processed") is not False:
        return False
    attempts = row.get("attempts", _MISSING)
    if attempts is _MISSING or not isinstance(attempts, int):
        return False
    if mode == "claimable" and attempts >= ATTEMPT_LIMIT:
        return False
    if mode == "exhausted" and attempts < ATTEMPT_LIMIT:
        return False
    if mode not in {"claimable", "exhausted"}:
        raise AssertionError(mode)
    if not _eligible_time(row, "next_retry_at"):
        return False
    token = row.get("claim_token", _MISSING)
    if token is not _MISSING and token is not None:
        if not _eligible_time(row, "claim_expires_at"):
            return False
    return True


def old_reference(rows: list[dict[str, Any]], mode: str, limit: int | None = None) -> list[str]:
    """Direct nested-loop equivalent of the pre-repair self-$lookup."""

    candidates = [row for row in rows if _matches(row, mode)]
    heads = []
    for candidate in candidates:
        candidate_key = (
            candidate["received_at"],
            candidate["event_id"],
        )
        blocked = any(
            predecessor.get("processed") is False
            and predecessor.get("session_id") == candidate.get("session_id")
            and (
                (predecessor["received_at"], predecessor["event_id"])
                < candidate_key
            )
            for predecessor in rows
        )
        if not blocked:
            heads.append(candidate)
    heads.sort(key=lambda row: (row["received_at"], row["event_id"]))
    result = [str(row["_id"]) for row in heads]
    return result if limit is None else result[: max(0, int(limit))]


def optimized_reference(rows: list[dict[str, Any]], mode: str, limit: int | None = None) -> list[str]:
    """Independent stage-level reference for the required group-first semantics."""

    unprocessed = [row for row in rows if row.get("processed") is False]
    by_session: dict[str, dict[str, Any]] = {}
    for row in sorted(
        unprocessed,
        key=lambda item: (
            item.get("session_id"),
            item["received_at"],
            item["event_id"],
        ),
    ):
        by_session.setdefault(str(row.get("session_id")), row)
    heads = [row for row in by_session.values() if _matches(row, mode)]
    heads.sort(key=lambda row: (row["received_at"], row["event_id"]))
    result = [str(row["_id"]) for row in heads]
    return result if limit is None else result[: max(0, int(limit))]


def _matrix() -> list[tuple[str, list[dict[str, Any]], str, int | None]]:
    cases: list[tuple[str, list[dict[str, Any]], str, int | None]] = [
        ("one_event", [_event("a", "s1", "2026-08-27T00:00:00+00:00")], "claimable", None),
        ("multiple_sessions", [_event("b", "s2", "2026-08-27T00:00:02+00:00"), _event("a", "s1", "2026-08-27T00:00:01+00:00")], "claimable", None),
        ("claimable_predecessor", [_event("a", "s1", "2026-08-27T00:00:00+00:00"), _event("b", "s1", "2026-08-27T00:00:01+00:00")], "claimable", None),
        ("delayed_predecessor_blocks", [_event("a", "s1", "2026-08-27T00:00:00+00:00", "delayed"), _event("b", "s1", "2026-08-27T00:00:01+00:00")], "claimable", None),
        ("leased_predecessor_blocks", [_event("a", "s1", "2026-08-27T00:00:00+00:00", "leased"), _event("b", "s1", "2026-08-27T00:00:01+00:00")], "claimable", None),
        ("expired_lease_head", [_event("a", "s1", "2026-08-27T00:00:00+00:00", "expired_lease"), _event("b", "s1", "2026-08-27T00:00:01+00:00")], "claimable", None),
        ("exhausted_head", [_event("a", "s1", "2026-08-27T00:00:00+00:00", "exhausted"), _event("b", "s1", "2026-08-27T00:00:01+00:00")], "exhausted", None),
        ("exhausted_later_blocked", [_event("a", "s1", "2026-08-27T00:00:00+00:00"), _event("b", "s1", "2026-08-27T00:00:01+00:00", "exhausted")], "exhausted", None),
        ("processed_predecessor_ignored", [_event("a", "s1", "2026-08-27T00:00:00+00:00", "processed"), _event("b", "s1", "2026-08-27T00:00:01+00:00")], "claimable", None),
        ("equal_timestamp_event_id_tie", [_event("z", "s1", "2026-08-27T00:00:00+00:00"), _event("a", "s1", "2026-08-27T00:00:00+00:00")], "claimable", None),
        ("missing_optional_fields", [_event("a", "s1", "2026-08-27T00:00:00+00:00", "missing_optional")], "claimable", None),
        ("empty", [], "claimable", None),
        ("limit_zero", [_event("a", "s1", "2026-08-27T00:00:00+00:00")], "claimable", 0),
        ("limit_one_cross_session", [_event("b", "s2", "2026-08-27T00:00:01+00:00"), _event("a", "s1", "2026-08-27T00:00:00+00:00")], "claimable", 1),
    ]
    state_pairs = [
        ("claimable", "claimable"),
        ("delayed", "claimable"),
        ("leased", "claimable"),
        ("expired_lease", "claimable"),
        ("processed", "claimable"),
        ("claimable", "exhausted"),
        ("exhausted", "exhausted"),
        ("missing_optional", "claimable"),
    ]
    for index, (first_state, second_state) in enumerate(state_pairs):
        cases.append(
            (
                f"generated_{index}",
                [
                    _event(f"g{index}a", "s1", "2026-08-27T00:00:00+00:00", first_state),
                    _event(f"g{index}b", "s1", "2026-08-27T00:00:01+00:00", second_state),
                    _event(f"g{index}c", "s2", "2026-08-27T00:00:00+00:00", "claimable"),
                ],
                "exhausted" if first_state == "exhausted" or second_state == "exhausted" else "claimable",
                index % 3,
            )
        )
    return cases


def test_semantic_differential_matrix_matches_independent_oracle() -> None:
    cases = _matrix()
    assert len(cases) >= 20
    for name, rows, mode, limit in cases:
        assert old_reference(rows, mode, limit) == optimized_reference(rows, mode, limit), name


def test_required_blocking_and_ordering_cases() -> None:
    delayed = [_event("a", "s1", "2026-08-27T00:00:00+00:00", "delayed"), _event("b", "s1", "2026-08-27T00:00:01+00:00")]
    leased = [_event("a", "s1", "2026-08-27T00:00:00+00:00", "leased"), _event("b", "s1", "2026-08-27T00:00:01+00:00")]
    assert old_reference(delayed, "claimable") == optimized_reference(delayed, "claimable") == []
    assert old_reference(leased, "claimable") == optimized_reference(leased, "claimable") == []

    cross = [_event("b", "s2", "2026-08-27T00:00:02+00:00"), _event("a", "s1", "2026-08-27T00:00:01+00:00")]
    assert optimized_reference(cross, "claimable") == ["a", "b"]

    processed = [_event("a", "s1", "2026-08-27T00:00:00+00:00", "processed"), _event("b", "s1", "2026-08-27T00:00:01+00:00")]
    assert optimized_reference(processed, "claimable") == ["b"]

    tied = [_event("z", "s1", "2026-08-27T00:00:00+00:00"), _event("a", "s1", "2026-08-27T00:00:00+00:00")]
    assert optimized_reference(tied, "claimable") == ["a"]


def test_repaired_pipeline_reduces_heads_before_match_and_has_no_self_lookup() -> None:
    seen: list[list[dict[str, Any]]] = []

    class Events:
        def aggregate(self, pipeline: list[dict[str, Any]]):
            seen.append(pipeline)
            return []

    storage = object.__new__(MongoDBStorageBackend)
    storage.database = type("Database", (), {"events": Events()})()
    assert storage._head_event_ids({"processed": False}, limit=1) == []
    pipeline = seen[0]
    stages = [next(iter(stage)) for stage in pipeline]
    assert "$lookup" not in stages
    assert stages.index("$group") < stages.index("$match", 1)
    assert stages[-1] == "$limit"
    assert pipeline[0] == {"$match": {"processed": False}}
    assert pipeline[1]["$sort"] == {"session_id": 1, "received_at": 1, "event_id": 1}
    assert pipeline[2]["$group"]["head"] == {"$first": "$$ROOT"}


def test_claim_events_external_contract_and_head_limit_are_unchanged(monkeypatch) -> None:
    calls: list[tuple[dict[str, Any], int | None]] = []

    class Events:
        def find_one_and_update(self, *_args, **_kwargs):
            raise AssertionError("no candidate should be claimed in empty fixture")

        def update_one(self, *_args, **_kwargs):
            raise AssertionError("no exhausted candidate should be updated in empty fixture")

    storage = object.__new__(MongoDBStorageBackend)
    storage.database = type("Database", (), {"events": Events()})()
    monkeypatch.setattr(storage, "_leader_matches", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        storage,
        "_head_event_ids",
        lambda match, *, limit=None: calls.append((match, limit)) or [],
    )
    assert storage.claim_events("worker", 2, 30, now=NOW) == []
    assert len(inspect.signature(storage.claim_events).parameters) >= 5
    assert calls[0][1] is None
    assert calls[1][1] == 2
