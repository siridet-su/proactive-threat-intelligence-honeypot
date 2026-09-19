"""Versioned read-side contract for the variable Cowrie ``message`` field.

Historical event documents are immutable and may contain either a scalar
message or an array of message fragments.  Consumers must use this adapter
instead of coercing arbitrary values with ``str(...)``.  The adapter does not
rewrite or hash the stored payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


EVENTS_MESSAGE_CONTRACT_VERSION = "events_message_contract.v1"


class EventMessageContractError(ValueError):
    """Raised when a stored message has a shape outside the frozen contract."""


@dataclass(frozen=True)
class EventMessageProjection:
    """A bounded, deterministic projection of one event message value."""

    source_message_type: str
    message_items: tuple[str, ...]

    @property
    def message_text(self) -> str:
        return "\n".join(self.message_items)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_message_type": self.source_message_type,
            "message_items": list(self.message_items),
            "message_text": self.message_text,
        }


def project_event_message(event: Mapping[str, Any]) -> EventMessageProjection:
    """Project ``event['message']`` without coercing invalid values.

    Accepted values are a missing key, ``None``, a string, or a JSON array of
    strings.  Missing and null values intentionally have the same empty
    projection but retain distinct source-type metadata.  Numeric, mapping,
    mixed-type, and other values are explicit contract failures so callers can
    quarantine or diagnose them rather than silently inventing text.
    """

    if not isinstance(event, Mapping):
        raise EventMessageContractError("event must be a mapping")
    if "message" not in event:
        return EventMessageProjection("missing", ())
    value = event["message"]
    if value is None:
        return EventMessageProjection("null", ())
    if isinstance(value, str):
        return EventMessageProjection("string", (value,))
    if isinstance(value, list):
        if any(not isinstance(item, str) for item in value):
            raise EventMessageContractError(
                "message array must contain strings only"
            )
        return EventMessageProjection("array", tuple(value))
    raise EventMessageContractError(
        "message must be missing, null, string, or array[string]"
    )


def event_message_text(event: Mapping[str, Any]) -> str:
    """Return the contract-approved message text for a read-side consumer."""

    return project_event_message(event).message_text
