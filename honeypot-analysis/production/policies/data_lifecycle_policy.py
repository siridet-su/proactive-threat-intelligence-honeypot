from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "data_lifecycle_policy.v1"
REQUIRED_RETAINED_ENTITIES = frozenset(
    {
        "events",
        "sessions",
        "alerts",
        "reports",
        "analysis_jobs",
        "enrichment_jobs",
        "threat_hunt_jobs",
        "webhook_deliveries",
        "observables",
        "observable_sightings",
        "enrichment_records",
        "campaigns",
        "campaign_sessions",
        "session_links",
        "analyst_feedback",
        "classification_review_labels",
        "prediction_outbox",
    }
)


@dataclass(frozen=True)
class LoadedDataLifecyclePolicy:
    path: str
    sha256: str
    document: Mapping[str, Any]

    @property
    def policy_id(self) -> str:
        return str(self.document["policy_id"])

    @property
    def version(self) -> str:
        return str(self.document["version"])


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(
            f"{context} keys invalid; missing={missing}, extra={extra}"
        )


def validate_data_lifecycle_policy(document: Any) -> None:
    if not isinstance(document, Mapping):
        raise ValueError("data lifecycle policy must be a JSON object")
    _require_exact_keys(
        document,
        {"schema_version", "policy_id", "version", "authority", "privacy", "entities"},
        "policy",
    )
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    for field in ("policy_id", "version"):
        if not isinstance(document[field], str) or not document[field].strip():
            raise ValueError(f"{field} must be a non-empty string")

    authority = document["authority"]
    if not isinstance(authority, Mapping):
        raise ValueError("authority must be an object")
    _require_exact_keys(
        authority,
        {
            "automatic_deletion_authorized",
            "manual_approval_required",
            "verified_backup_required_before_deletion",
            "restore_rehearsal_required_before_deletion",
        },
        "authority",
    )
    required_authority = {
        "automatic_deletion_authorized": False,
        "manual_approval_required": True,
        "verified_backup_required_before_deletion": True,
        "restore_rehearsal_required_before_deletion": True,
    }
    if dict(authority) != required_authority:
        raise ValueError("data deletion authority must remain manual and recoverable")

    privacy = document["privacy"]
    if not isinstance(privacy, Mapping):
        raise ValueError("privacy must be an object")
    _require_exact_keys(
        privacy,
        {
            "credential_plaintext_storage_allowed",
            "source_ip_purpose",
            "source_ip_external_sharing_allowed",
            "artifact_redaction_required",
        },
        "privacy",
    )
    if privacy["credential_plaintext_storage_allowed"] is not False:
        raise ValueError("credential plaintext storage must be prohibited")
    if privacy["source_ip_external_sharing_allowed"] is not False:
        raise ValueError("source IP external sharing must be prohibited")
    if privacy["artifact_redaction_required"] is not True:
        raise ValueError("artifact redaction must be required")
    if privacy["source_ip_purpose"] != "honeypot_security_research":
        raise ValueError("source IP processing purpose must be explicit and bounded")

    entities = document["entities"]
    if not isinstance(entities, Mapping):
        raise ValueError("entities must be an object")
    if set(entities) != REQUIRED_RETAINED_ENTITIES | {"prediction_snapshots"}:
        raise ValueError("entities must enumerate the complete approved lifecycle scope")
    for name in REQUIRED_RETAINED_ENTITIES:
        entry = entities[name]
        if not isinstance(entry, Mapping) or set(entry) != {"mode"}:
            raise ValueError(f"{name} must define only mode")
        allowed_mode = (
            "retain_expired_for_provenance"
            if name == "enrichment_records"
            else "retain"
        )
        if entry["mode"] != allowed_mode:
            raise ValueError(f"{name} must use mode={allowed_mode}")
    predictions = entities["prediction_snapshots"]
    if not isinstance(predictions, Mapping):
        raise ValueError("prediction_snapshots must be an object")
    _require_exact_keys(
        predictions,
        {
            "mode",
            "minimum_age_days",
            "preserve_latest_per_session",
            "preserve_feedback_references",
        },
        "prediction_snapshots",
    )
    if predictions["mode"] != "manual_apply_only":
        raise ValueError("prediction snapshot deletion must require manual apply")
    days = predictions["minimum_age_days"]
    if isinstance(days, bool) or not isinstance(days, int) or days < 1:
        raise ValueError("prediction snapshot minimum_age_days must be positive")
    if predictions["preserve_latest_per_session"] is not True:
        raise ValueError("latest prediction per session must be preserved")
    if predictions["preserve_feedback_references"] is not True:
        raise ValueError("feedback-referenced predictions must be preserved")


def load_data_lifecycle_policy(path_text: str) -> LoadedDataLifecyclePolicy:
    path = Path(path_text)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"data lifecycle policy unavailable: {path}") from exc
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"data lifecycle policy is invalid JSON: {path}") from exc
    validate_data_lifecycle_policy(document)
    return LoadedDataLifecyclePolicy(
        path=str(path.resolve()),
        sha256=hashlib.sha256(raw).hexdigest(),
        document=document,
    )
