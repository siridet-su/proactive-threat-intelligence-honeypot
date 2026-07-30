"""Shared source chronology for the frozen next-behavior target.

Durable evidence order is never rewritten.  This module derives only the
model-visible order of the causal prefix currently available to the caller.
It follows the frozen corpus contract: valid source timestamps first, durable
order as the tie-break, and explicit abstention for timestamps that cannot be
interpreted without inventing chronology.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


CHRONOLOGY_SCHEMA_VERSION = "next_behavior_model_chronology.v1"


class NextBehaviorChronologyError(ValueError):
    """A bounded, stable chronology-abstention reason."""

    def __init__(self, reason: str) -> None:
        self.reason = str(reason or "chronology_unavailable")
        super().__init__(self.reason)


@dataclass(frozen=True)
class ModelChronology:
    records: tuple[dict[str, Any], ...]
    source_timestamps: tuple[str, ...]
    late_arrival_count: int
    equal_timestamp_count: int

    def receipt(self) -> dict[str, Any]:
        return {
            "schema_version": CHRONOLOGY_SCHEMA_VERSION,
            "record_count": len(self.records),
            "late_arrival_count": self.late_arrival_count,
            "equal_timestamp_count": self.equal_timestamp_count,
            "missing_timestamp_count": 0,
            "invalid_timestamp_count": 0,
            "ordering": (
                "valid_source_timestamp_then_durable_sequence_then_identity"
            ),
        }


def _source_time(value: Any) -> tuple[datetime, str]:
    text = str(value or "").strip()
    if not text:
        raise NextBehaviorChronologyError("missing_source_timestamp")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NextBehaviorChronologyError("invalid_source_timestamp") from exc
    if parsed.tzinfo is None:
        raise NextBehaviorChronologyError("timezone_missing_source_timestamp")
    utc = parsed.astimezone(timezone.utc)
    return utc, utc.isoformat(timespec="microseconds")


def order_model_chronology(
    records: Sequence[Mapping[str, Any]],
    *,
    maximum_records: int = 10_000,
) -> ModelChronology:
    """Order a currently available prefix without changing durable evidence."""

    if isinstance(maximum_records, bool) or maximum_records < 1:
        raise ValueError("maximum_records must be a positive integer")
    if len(records) > maximum_records:
        raise NextBehaviorChronologyError("chronology_record_limit_exceeded")

    prepared: list[
        tuple[datetime, str, int, str, dict[str, Any]]
    ] = []
    durable_seen: set[tuple[int, str]] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise NextBehaviorChronologyError("invalid_chronology_record")
        try:
            durable_sequence = int(record.get("durable_sequence"))
        except (TypeError, ValueError) as exc:
            raise NextBehaviorChronologyError(
                "invalid_durable_evidence_order"
            ) from exc
        durable_id = str(record.get("durable_id") or "").strip()
        if durable_sequence < 0 or not durable_id:
            raise NextBehaviorChronologyError(
                "invalid_durable_evidence_order"
            )
        durable_key = (durable_sequence, durable_id)
        if durable_key in durable_seen:
            raise NextBehaviorChronologyError("ambiguous_durable_evidence_order")
        durable_seen.add(durable_key)
        parsed, canonical = _source_time(record.get("source_timestamp"))
        prepared.append(
            (
                parsed,
                canonical,
                durable_sequence,
                durable_id,
                deepcopy(dict(record)),
            )
        )

    in_durable_order = sorted(prepared, key=lambda item: (item[2], item[3]))
    late_arrivals = sum(
        1
        for previous, current in zip(
            in_durable_order,
            in_durable_order[1:],
        )
        if current[0] < previous[0]
    )
    ordered = sorted(
        prepared,
        key=lambda item: (item[0], item[2], item[3]),
    )
    equal_timestamps = sum(
        1
        for previous, current in zip(ordered, ordered[1:])
        if current[0] == previous[0]
    )
    return ModelChronology(
        records=tuple(item[4] for item in ordered),
        source_timestamps=tuple(item[1] for item in ordered),
        late_arrival_count=late_arrivals,
        equal_timestamp_count=equal_timestamps,
    )


def relative_time_milliseconds(chronology: ModelChronology) -> tuple[int, ...]:
    """Return deterministic source-relative times for an ordered chronology."""

    if not chronology.source_timestamps:
        return ()
    parsed = [
        datetime.fromisoformat(value)
        for value in chronology.source_timestamps
    ]
    start = parsed[0]
    return tuple(
        int((timestamp - start).total_seconds() * 1000)
        for timestamp in parsed
    )
