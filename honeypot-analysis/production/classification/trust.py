"""Shared trust rules for command-classification evidence.

Raw classifier output is retained for audit, but only trusted events may become
observed ATT&CK facts or drive session sequences, correlations, and reports.
"""

from __future__ import annotations

import re
from typing import Any, Dict


AUDIT_ONLY_CLASSIFICATION_SOURCES = {
    "emergency_python_fallback",
    "rule_securebert_disagreement",
    "shell_noise",
    "securebert_low_confidence",
    "securebert_error",
    "securebert_unavailable",
    "unclassified",
}
AUTHORITY_DECISION_SCHEMA = "command_authority_decision.v1"
CLASSIFICATION_EVENT_SCHEMA = "classification_event.v2"
MIN_TRUSTED_SECUREBERT_CONFIDENCE = 0.55
_SUPPORTED_FRAGMENT_EXECUTION = {"conditional_unproven"}
_OPAQUE_BUSYBOX_APPLET_RE = re.compile(
    r"^(?:/bin/)?busybox\s+[A-Z]{4,12}(?:\s|$)",
)


def _event_command(event: Dict[str, Any]) -> str:
    return str(event.get("subcommand") or event.get("command") or "").strip()


def is_opaque_securebert_probe(event: Dict[str, Any]) -> bool:
    """Whether an NLP-only event is an opaque BusyBox applet probe.

    Bot probes frequently invoke a random, non-existent BusyBox applet to test
    shell behavior. The token itself has no ATT&CK semantics, so model
    confidence alone cannot promote it to an observed technique.
    """

    source = str(event.get("source") or "").strip().lower()
    return source == "securebert" and bool(_OPAQUE_BUSYBOX_APPLET_RE.match(_event_command(event)))


def classification_evidence_tier(event: Dict[str, Any]) -> str:
    """Return ``trusted_observation`` or ``audit_only_candidate`` for an event."""

    source = str(event.get("source") or "").strip().lower()
    agreement_status = str(event.get("agreement_status") or "").strip().lower()
    if source in AUDIT_ONLY_CLASSIFICATION_SOURCES:
        return "audit_only_candidate"
    # New classifier events must carry the domain-separated authority result
    # and the immutable rule-policy provenance.  Historical v1 events remain
    # readable as legacy report input, but are never emitted by the current
    # runtime classifier.
    is_new_event = (
        event.get("classification_event_schema") == CLASSIFICATION_EVENT_SCHEMA
        or "authority_decision" in event
        or "rule_policy_id" in event
    )
    if is_new_event:
        authority = event.get("authority_decision")
        if not isinstance(authority, dict):
            return "audit_only_candidate"
        fragment_execution = event.get("fragment_execution")
        if fragment_execution is not None:
            if not isinstance(fragment_execution, str):
                return "audit_only_candidate"
            if fragment_execution not in _SUPPORTED_FRAGMENT_EXECUTION:
                return "audit_only_candidate"
            # Conditional RHS fragments are retained for audit and replay
            # provenance, but never constitute trusted observed behavior.
            if fragment_execution == "conditional_unproven":
                return "audit_only_candidate"
        if authority.get("schema_version") != AUTHORITY_DECISION_SCHEMA:
            return "audit_only_candidate"
        if authority.get("decision") != "trusted" or authority.get("trusted_eligible") is not True:
            return "audit_only_candidate"
        if source in {"rule", "both", "rule_securebert_disagreement"}:
            if not event.get("rule_policy_id") or not event.get("rule_policy_version"):
                return "audit_only_candidate"
            if not event.get("rule_policy_sha256") or event.get("rule_policy_load_status") != "loaded":
                return "audit_only_candidate"
    if agreement_status in {
        "tactic_only_disagreement",
        "technique_and_tactic_disagreement",
    }:
        return "audit_only_candidate"
    if source == "both":
        rule_ttp = str(event.get("ttp") or "").strip().upper()
        bert_ttp = str(event.get("bert_ttp") or "").strip().upper()
        if rule_ttp and bert_ttp and rule_ttp != bert_ttp:
            return "audit_only_candidate"
    if event.get("high_confidence") is False:
        return "audit_only_candidate"
    if is_opaque_securebert_probe(event):
        return "audit_only_candidate"
    if source == "securebert":
        # SecureBERT is a candidate/audit signal.  It is never a trusted
        # observation by itself, regardless of confidence or model agreement.
        return "audit_only_candidate"
    ttp = str(event.get("ttp") or "").strip().lower()
    if ttp in {"unknown", "t0000_unknown"}:
        return "audit_only_candidate"
    tactic = str(event.get("tactic") or "").strip().lower()
    if not ((ttp and ttp != "unknown") or (tactic and tactic != "unknown")):
        return "audit_only_candidate"
    return "trusted_observation"


def is_trusted_classification_event(event: Dict[str, Any]) -> bool:
    """Whether classifier output may be promoted to observed ATT&CK evidence."""

    return classification_evidence_tier(event) == "trusted_observation"


def classification_audit_reason(event: Dict[str, Any]) -> str:
    """Give a stable analyst-facing reason for keeping an event audit-only."""

    source = str(event.get("source") or "").strip().lower()
    agreement_status = str(event.get("agreement_status") or "").strip().lower()
    if source == "shell_noise":
        return "shell noise is retained for audit and excluded from ATT&CK evidence"
    if source == "emergency_python_fallback":
        return "unreviewed emergency rule match is retained for audit and excluded from trusted evidence"
    if event.get("authority_decision"):
        reasons = event.get("authority_decision", {}).get("reasons") or []
        if reasons:
            return "authority decision is audit-only: " + ", ".join(
                str(item) for item in reasons[:3]
            )
        return "classification lacks a trusted authority decision"
    if source == "rule_securebert_disagreement" or "disagreement" in agreement_status:
        return "rule and SecureBERT disagree; the candidate is retained for audit and excluded from trusted evidence"
    if is_opaque_securebert_probe(event):
        return "opaque BusyBox applet probe has no defensible command-level ATT&CK meaning"
    if source in {"securebert", "securebert_low_confidence"} or event.get("high_confidence") is False:
        return "low-confidence classifier candidate; not an observed ATT&CK fact"
    if source:
        return f"{source} output is retained for audit and excluded from strong evidence"
    return "classification lacks trusted ATT&CK evidence"
