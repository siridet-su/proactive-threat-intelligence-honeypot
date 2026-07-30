from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "alert_authority_policy.v1"
REQUIRED_NON_AUTHORITATIVE_SOURCES = frozenset(
    {
        "session_assessment.v4",
        "response_guidance.v3",
        "typed_semantic_fact_set.v2",
        "prediction",
        "enrichment",
        "correlation",
        "campaign_similarity",
        "threat_hunt",
    }
)


@dataclass(frozen=True)
class LoadedAlertAuthorityPolicy:
    path: str
    sha256: str
    document: Mapping[str, Any]

    @property
    def policy_id(self) -> str:
        return str(self.document["policy_id"])

    @property
    def version(self) -> str:
        return str(self.document["version"])

    @property
    def automatic_alerts_authorized(self) -> bool:
        return bool(self.document["automatic_authority"]["alert_creation_authorized"])

    @property
    def external_delivery_authorized(self) -> bool:
        return bool(self.document["automatic_authority"]["external_delivery_authorized"])


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{context} keys invalid; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def _require_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return value


def validate_alert_authority_policy(document: Any) -> None:
    policy = _require_mapping(document, "alert authority policy")
    _require_exact_keys(
        policy,
        {
            "schema_version",
            "policy_id",
            "version",
            "automatic_authority",
            "non_authoritative_sources",
            "correlation",
            "historical_alerts",
            "webhook",
        },
        "policy",
    )
    if policy["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    for field in ("policy_id", "version"):
        if not isinstance(policy[field], str) or not policy[field].strip():
            raise ValueError(f"{field} must be a non-empty string")

    authority = _require_mapping(policy["automatic_authority"], "automatic_authority")
    _require_exact_keys(
        authority,
        {
            "alert_creation_authorized",
            "external_delivery_authorized",
            "response_execution_authorized",
        },
        "automatic_authority",
    )
    if dict(authority) != {
        "alert_creation_authorized": False,
        "external_delivery_authorized": False,
        "response_execution_authorized": False,
    }:
        raise ValueError(
            "automatic alerts, external delivery, and response execution must remain prohibited"
        )

    sources = policy["non_authoritative_sources"]
    if (
        not isinstance(sources, list)
        or any(not isinstance(item, str) or not item for item in sources)
        or len(sources) != len(set(sources))
        or frozenset(sources) != REQUIRED_NON_AUTHORITATIVE_SOURCES
    ):
        raise ValueError(
            "non_authoritative_sources must exactly enumerate every contextual source"
        )

    correlation = _require_mapping(policy["correlation"], "correlation")
    _require_exact_keys(
        correlation,
        {"output_schema", "actor_identity_claims_authorized"},
        "correlation",
    )
    if correlation["output_schema"] != "correlation_signal.v1":
        raise ValueError("correlation output must use correlation_signal.v1")
    if correlation["actor_identity_claims_authorized"] is not False:
        raise ValueError("correlation must not claim actor identity")

    historical = _require_mapping(policy["historical_alerts"], "historical_alerts")
    _require_exact_keys(
        historical, {"read_only", "display_label"}, "historical_alerts"
    )
    if historical != {
        "read_only": True,
        "display_label": "historical_legacy_alert",
    }:
        raise ValueError("historical alerts must remain read-only and explicitly labeled")

    webhook = _require_mapping(policy["webhook"], "webhook")
    _require_exact_keys(webhook, {"configured_targets_authorized"}, "webhook")
    if webhook["configured_targets_authorized"] is not False:
        raise ValueError("webhook targets are not authorized by this reviewed policy")


def load_alert_authority_policy(path_text: str) -> LoadedAlertAuthorityPolicy:
    path = Path(path_text)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"alert authority policy unavailable: {path}") from exc
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"alert authority policy is invalid JSON: {path}") from exc
    validate_alert_authority_policy(document)
    return LoadedAlertAuthorityPolicy(
        path=str(path.resolve()),
        sha256=hashlib.sha256(raw).hexdigest(),
        document=document,
    )
