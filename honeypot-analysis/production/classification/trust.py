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
MIN_TRUSTED_SECUREBERT_CONFIDENCE = 0.55
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
        try:
            if float(event.get("confidence")) < MIN_TRUSTED_SECUREBERT_CONFIDENCE:
                return "audit_only_candidate"
        except (TypeError, ValueError):
            return "audit_only_candidate"
    ttp = str(event.get("ttp") or "").strip().lower()
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
    if source == "rule_securebert_disagreement" or "disagreement" in agreement_status:
        return "rule and SecureBERT disagree; the candidate is retained for audit and excluded from trusted evidence"
    if is_opaque_securebert_probe(event):
        return "opaque BusyBox applet probe has no defensible command-level ATT&CK meaning"
    if source in {"securebert", "securebert_low_confidence"} or event.get("high_confidence") is False:
        return "low-confidence classifier candidate; not an observed ATT&CK fact"
    if source:
        return f"{source} output is retained for audit and excluded from strong evidence"
    return "classification lacks trusted ATT&CK evidence"
