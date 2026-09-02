"""Shared semantics for non-authoritative correlation scores.

Correlation and similarity values are bounded project-authored heuristic
strengths.  They are deliberately not probabilities and this small module is
kept dependency-free so producers, storage projections, and UI/API consumers
can resolve the same representation without introducing an import cycle.
"""

from __future__ import annotations

from typing import Any


CORRELATION_CONFIDENCE_SEMANTICS = (
    "developer_defined_heuristic_policy_strength_not_probability"
)
LEGACY_CORRELATION_CONFIDENCE_SEMANTICS = (
    "legacy_unresolved_correlation_score_semantics"
)
VALID_CORRELATION_CONFIDENCE_SEMANTICS = frozenset(
    {
        CORRELATION_CONFIDENCE_SEMANTICS,
        LEGACY_CORRELATION_CONFIDENCE_SEMANTICS,
    }
)


def resolve_confidence_semantics(
    value: Any,
    *,
    absent: str = LEGACY_CORRELATION_CONFIDENCE_SEMANTICS,
) -> str:
    """Resolve a representation value without silently asserting calibration.

    Missing metadata is represented explicitly as legacy/unresolved.  A
    malformed value also resolves to that marker; callers that gate stronger
    consumers should use :func:`is_valid_confidence_semantics` first and fail
    closed when a non-empty malformed value is supplied.
    """

    if value is None or (isinstance(value, str) and not value.strip()):
        return absent
    text = str(value).strip()
    if text in VALID_CORRELATION_CONFIDENCE_SEMANTICS:
        return text
    return LEGACY_CORRELATION_CONFIDENCE_SEMANTICS


def declared_confidence_semantics(
    value: Any,
    *,
    absent: str = LEGACY_CORRELATION_CONFIDENCE_SEMANTICS,
) -> str:
    """Preserve malformed non-empty declarations for fail-closed validation.

    ``resolve_confidence_semantics`` is useful for public projections of old
    rows.  Producers and normalizers must retain a malformed declaration long
    enough for validators/authority gates to reject it rather than silently
    converting it into a valid-looking legacy marker.
    """

    if value is None or (isinstance(value, str) and not value.strip()):
        return absent
    return str(value).strip()


def is_valid_confidence_semantics(value: Any, *, allow_absent: bool = True) -> bool:
    """Return whether an explicit semantics marker is recognized."""

    if value is None or (isinstance(value, str) and not value.strip()):
        return allow_absent
    return str(value).strip() in VALID_CORRELATION_CONFIDENCE_SEMANTICS
