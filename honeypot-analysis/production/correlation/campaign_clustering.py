"""Live, non-authoritative similarity clustering from session fingerprints.

Similarity links observations in this deployment. It does not establish that
two sessions share an actor, tooling identity, intent, or real-world campaign.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from production.classification.trust import is_trusted_classification_event
from production.correlation.session_ttp_correlation import correlation_allows_influence
from production.utils.config import ProductionConfig
from production.policies.alert_authority_policy import (
    LoadedAlertAuthorityPolicy,
    load_alert_authority_policy,
)
from production.utils.serialization import stable_id, utc_now
from production.storage import open_storage


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RANK_SEVERITY = {value: key for key, value in SEVERITY_RANK.items()}

TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:-]+")
URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _short_hash(value: str) -> str:
    return _sha256_text(value)[:32]


def _policy(config_or_policy: ProductionConfig | Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(config_or_policy, ProductionConfig):
        raw = config_or_policy.campaign_policy
    else:
        raw = config_or_policy
    policy = dict(raw or {})
    policy.setdefault("enabled", True)
    policy.setdefault("cluster_active_sessions", True)
    policy.setdefault("cluster_closed_sessions", True)
    policy.setdefault("min_commands_active", 1)
    policy.setdefault("min_commands_closed", 1)
    policy.setdefault("min_match_score", 0.35)
    policy.setdefault("min_match_raw_score", 0.25)
    policy.setdefault("min_independent_evidence_classes", 1)
    policy.setdefault("allow_source_ip_only_match", False)
    policy.setdefault("source_ip_only_confidence", 0.2)
    policy.setdefault("max_matches", 10)
    policy.setdefault("command_pattern_command_limit", 6)
    policy.setdefault("command_pattern_token_limit", 3)
    policy.setdefault("emit_observational_signals", True)
    policy.setdefault(
        "field_weights",
        {
            "hassh_fingerprint": 0.45,
            "ja3_fingerprint": 0.35,
            "command_pattern_hash": 0.30,
            "tactic_sequence_hash": 0.25,
            "source_ip": 0.20,
        },
    )
    policy.setdefault(
        "tactic_severity",
        {
            "credential-access": "medium",
            "defense-evasion": "medium",
            "command-and-control": "high",
            "persistence": "high",
            "privilege-escalation": "high",
            "lateral-movement": "critical",
            "exfiltration": "critical",
            "impact": "critical",
        },
    )
    return policy


def _severity_max(*values: str) -> str:
    rank = 0
    for value in values:
        rank = max(rank, SEVERITY_RANK.get(str(value or "").strip().lower(), 0))
    return RANK_SEVERITY.get(rank, "info")


def _parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _commands(session_payload: Dict[str, Any]) -> List[str]:
    values = session_payload.get("commands") or []
    if not isinstance(values, list):
        return []
    return [str(item or "").strip() for item in values if str(item or "").strip()]


def _ordered_tactics(session_payload: Dict[str, Any]) -> List[str]:
    output: List[str] = []
    classification_events = [
        event for event in session_payload.get("classification_events") or []
        if isinstance(event, dict)
    ]
    for event in classification_events:
        if is_trusted_classification_event(event):
            tactic = str(event.get("tactic") or "").strip().lower()
            if tactic and tactic != "unknown":
                output.append(tactic)
    if not output and not classification_events:
        for tactic in session_payload.get("tactics") or session_payload.get("unique_tactics") or []:
            text = str(tactic or "").strip().lower()
            if text and text != "unknown":
                output.append(text)
    compact: List[str] = []
    for tactic in output:
        if not compact or compact[-1] != tactic:
            compact.append(tactic)
    return compact


def _confirmed_tactics(session_payload: Dict[str, Any]) -> List[str]:
    output: List[str] = []
    for tactic in _ordered_tactics(session_payload):
        if tactic not in output:
            output.append(tactic)
    for item in session_payload.get("session_ttp_correlations") or []:
        if isinstance(item, dict) and correlation_allows_influence(item, "campaign"):
            tactic = str(item.get("tactic") or "").strip().lower()
            if tactic and tactic != "unknown" and tactic not in output:
                output.append(tactic)
    return output


def _normalize_command(command: str, token_limit: int) -> str:
    text = URL_RE.sub("URL", command.lower())
    text = IP_RE.sub("IP", text)
    text = HASH_RE.sub("HASH", text)
    tokens = TOKEN_RE.findall(text)
    normalized: List[str] = []
    for token in tokens:
        if token.startswith("/tmp/") or token.startswith("/var/"):
            token = "PATH"
        if token not in normalized:
            normalized.append(token)
        if len(normalized) >= token_limit:
            break
    return " ".join(normalized)


def _command_pattern(commands: List[str], policy: Dict[str, Any]) -> List[str]:
    command_limit = int(policy.get("command_pattern_command_limit") or 6)
    token_limit = int(policy.get("command_pattern_token_limit") or 3)
    return [
        item
        for item in (_normalize_command(command, token_limit) for command in commands[:command_limit])
        if item
    ]


def _timing_bucket(session_payload: Dict[str, Any]) -> str:
    parsed = _parse_time(session_payload.get("start_time") or session_payload.get("updated_at"))
    if not parsed:
        for event in session_payload.get("raw_events") or []:
            if isinstance(event, dict):
                parsed = _parse_time(event.get("timestamp"))
                if parsed:
                    break
    if not parsed:
        return "unknown"
    return f"dow{parsed.weekday()}-hour{parsed.hour:02d}"


def _eligible(session_payload: Dict[str, Any], policy: Dict[str, Any], status: str) -> Tuple[bool, str]:
    if not policy.get("enabled", True):
        return False, "campaign clustering disabled"
    closed = status == "closed" or bool(session_payload.get("is_ended"))
    if closed and not policy.get("cluster_closed_sessions", True):
        return False, "closed-session clustering disabled"
    if not closed and not policy.get("cluster_active_sessions", True):
        return False, "active-session clustering disabled"
    min_commands = int(policy.get("min_commands_closed" if closed else "min_commands_active") or 0)
    if len(_commands(session_payload)) < min_commands and not session_payload.get("hassh") and not session_payload.get("ja3"):
        return False, f"insufficient fingerprint evidence: command_count below {min_commands}"
    return True, ""


def build_session_fingerprint(session_payload: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    policy = _policy(policy or {})
    commands = _commands(session_payload)
    tactics = _ordered_tactics(session_payload)
    command_pattern = _command_pattern(commands, policy)
    hassh = str(session_payload.get("hassh") or "").strip().lower()
    ja3 = str(session_payload.get("ja3") or "").strip().lower()
    tactic_sequence_text = " > ".join(tactics)
    command_pattern_text = " | ".join(command_pattern)
    fingerprint = {
        "session_id": str(session_payload.get("session_id") or "unknown"),
        "src_ip": str(session_payload.get("src_ip") or "unknown"),
        "hassh": hassh,
        "ja3": ja3,
        "hassh_fingerprint": _short_hash(hassh) if hassh else "",
        "ja3_fingerprint": _short_hash(ja3) if ja3 else "",
        "tactic_sequence": tactics,
        "tactic_sequence_hash": _short_hash(tactic_sequence_text) if tactics else "",
        "command_pattern": command_pattern,
        "command_pattern_hash": _short_hash(command_pattern_text) if command_pattern else "",
        "timing_bucket": _timing_bucket(session_payload),
        "command_count": len(commands),
        "confirmed_tactics": _confirmed_tactics(session_payload),
    }
    fingerprint["primary_fingerprint_type"], fingerprint["primary_fingerprint_value"] = _primary_fingerprint(fingerprint)
    fingerprint["fingerprint_id"] = stable_id(
        "sessionfp",
        {
            "hassh_fingerprint": fingerprint["hassh_fingerprint"],
            "ja3_fingerprint": fingerprint["ja3_fingerprint"],
            "tactic_sequence_hash": fingerprint["tactic_sequence_hash"],
            "command_pattern_hash": fingerprint["command_pattern_hash"],
            "src_ip": fingerprint["src_ip"],
        },
    )
    return fingerprint


def _primary_fingerprint(fingerprint: Dict[str, Any]) -> Tuple[str, str]:
    for key in ("hassh_fingerprint", "ja3_fingerprint", "command_pattern_hash", "tactic_sequence_hash", "src_ip"):
        value = str(fingerprint.get(key) or "").strip()
        if value and value.lower() != "unknown":
            return key, value
    return "none", ""


def score_campaign_match(campaign: Dict[str, Any], fingerprint: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    weights = policy.get("field_weights") or {}
    reasons: List[str] = []
    score = 0.0
    total_possible = 0.0
    for key in ("hassh_fingerprint", "ja3_fingerprint", "command_pattern_hash", "tactic_sequence_hash", "source_ip"):
        fp_key = "src_ip" if key == "source_ip" else key
        campaign_value = str(campaign.get(key if key != "source_ip" else "source_ip") or "").strip()
        fingerprint_value = str(fingerprint.get(fp_key) or "").strip()
        weight = float(weights.get(key) or 0.0)
        if not weight:
            continue
        if fingerprint_value and fingerprint_value.lower() != "unknown":
            total_possible += weight
            if campaign_value and campaign_value == fingerprint_value:
                score += weight
                reasons.append(f"matched {key}")
    normalized = score / total_possible if total_possible > 0 else 0.0
    matched_fields = [reason.removeprefix("matched ") for reason in reasons]
    source_ip_only = matched_fields == ["source_ip"]
    if source_ip_only:
        try:
            source_ip_cap = float(policy.get("source_ip_only_confidence", 0.2))
        except (TypeError, ValueError):
            source_ip_cap = 0.2
        normalized = min(normalized, max(0.0, min(source_ip_cap, 1.0)))
    return {
        "campaign_id": campaign.get("campaign_id") or "",
        "score": round(normalized, 4),
        "raw_score": round(score, 4),
        "total_possible": round(total_possible, 4),
        "match_reasons": reasons,
        "matched_evidence_classes": matched_fields,
        "independent_evidence_class_count": len(matched_fields),
        "source_ip_only": source_ip_only,
        "match_category": (
            "source_ip_only_low_confidence"
            if source_ip_only
            else "multi_signal" if len(matched_fields) > 1 else "single_non_ip_signal"
        ),
        "campaign": campaign,
    }


def find_matching_campaigns(storage: Any, fingerprint: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates = storage.find_matching_campaigns(fingerprint, limit=int(policy.get("max_matches") or 10) * 5)
    matches = [score_campaign_match(candidate, fingerprint, policy) for candidate in candidates]
    minimum = float(policy.get("min_match_score") or 0.0)
    minimum_raw = float(policy.get("min_match_raw_score") or 0.0)
    minimum_classes = int(policy.get("min_independent_evidence_classes") or 1)
    allow_source_ip_only = bool(policy.get("allow_source_ip_only_match", False))
    matches = [
        item
        for item in matches
        if item["score"] >= minimum
        and item["raw_score"] >= minimum_raw
        and item["independent_evidence_class_count"] >= minimum_classes
        and (allow_source_ip_only or not item["source_ip_only"])
    ]
    return sorted(matches, key=lambda item: item["score"], reverse=True)[: int(policy.get("max_matches") or 10)]


def _campaign_id_for_fingerprint(
    fingerprint: Dict[str, Any],
    session_id: str = "",
) -> str:
    source_ip_only = fingerprint.get("primary_fingerprint_type") == "src_ip"
    return stable_id(
        "campaign",
        {
            "primary_fingerprint_type": fingerprint.get("primary_fingerprint_type") or "",
            "primary_fingerprint_value": fingerprint.get("primary_fingerprint_value") or "",
            "source_ip_only_session_id": session_id if source_ip_only else "",
        },
    )


def _session_severity(session_payload: Dict[str, Any], policy: Dict[str, Any]) -> str:
    tactic_map = policy.get("tactic_severity") or {}
    severities = [str(tactic_map.get(tactic) or "info") for tactic in _confirmed_tactics(session_payload)]
    return _severity_max(*severities)


def _merge_tactics(existing: Iterable[str], current: Iterable[str]) -> List[str]:
    output: List[str] = []
    for item in list(existing or []) + list(current or []):
        text = str(item or "").strip().lower()
        if text and text not in output:
            output.append(text)
    return output


def _campaign_payload(
    campaign_id: str,
    fingerprint: Dict[str, Any],
    session_payload: Dict[str, Any],
    policy: Dict[str, Any],
    existing: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    existing = existing or {}
    existing_payload = existing.get("payload") or {}
    now = utc_now()
    current_tactics = _confirmed_tactics(session_payload)
    confirmed_tactics = _merge_tactics(existing_payload.get("confirmed_tactics") or existing.get("confirmed_tactics") or [], current_tactics)
    max_severity = _severity_max(existing.get("max_confirmed_severity") or "", _session_severity(session_payload, policy))
    first_seen = existing.get("first_seen") or session_payload.get("start_time") or now
    last_seen = max(str(existing.get("last_seen") or ""), str(session_payload.get("updated_at") or now))
    payload = {
        "campaign_id": campaign_id,
        "primary_fingerprint_type": fingerprint.get("primary_fingerprint_type") or "",
        "primary_fingerprint_value": fingerprint.get("primary_fingerprint_value") or "",
        "hassh_fingerprint": fingerprint.get("hassh_fingerprint") or "",
        "ja3_fingerprint": fingerprint.get("ja3_fingerprint") or "",
        "tactic_sequence_hash": fingerprint.get("tactic_sequence_hash") or "",
        "command_pattern_hash": fingerprint.get("command_pattern_hash") or "",
        "source_ip": fingerprint.get("src_ip") or "",
        "session_count": int(existing.get("session_count") or 0),
        "first_seen": first_seen,
        "last_seen": last_seen or now,
        "confirmed_tactics": confirmed_tactics,
        "max_confirmed_severity": max_severity,
        "fingerprint": fingerprint,
        "updated_from_session": session_payload.get("session_id") or "",
    }
    return payload


def _similar_session_pattern_signal(
    campaign: Dict[str, Any],
    session_payload: Dict[str, Any],
    match: Dict[str, Any],
    status: str,
    policy: Dict[str, Any],
    alert_authority_policy: LoadedAlertAuthorityPolicy,
) -> Optional[Dict[str, Any]]:
    if not policy.get("emit_observational_signals", True):
        return None
    session_id = str(session_payload.get("session_id") or "unknown")
    campaign_id = str(campaign.get("campaign_id") or "")
    policy_sha256 = alert_authority_policy.sha256
    identity = {
        "campaign_id": campaign_id,
        "session_id": session_id,
        "match_score": match.get("score"),
        "match_reasons": match.get("match_reasons") or [],
        "alert_authority_policy_sha256": policy_sha256,
    }
    return {
        "schema_version": "correlation_signal.v1",
        "signal_id": stable_id("correlationsignal", identity),
        "signal_type": "similar_session_pattern_observed",
        "session_id": session_id,
        "campaign_id": campaign_id,
        "session_status": status,
        "match_score": match.get("score"),
        "match_reasons": match.get("match_reasons") or [],
        "campaign_session_count": campaign.get("session_count") or 0,
        "authority": {
            "semantics": "observation_only_non_authoritative",
            "may_claim_actor_identity": False,
            "may_create_alert": False,
            "may_authorize_response": False,
        },
        "limitations": [
            "similarity does not establish actor identity",
            "similarity does not establish shared tooling identity or intent",
            "signal cannot authorize an alert, external delivery, or response",
        ],
        "provenance": {
            "alert_authority_policy_sha256": policy_sha256,
            "alert_authority_policy_id": alert_authority_policy.policy_id,
        },
    }


def create_or_update_campaign(
    storage: Any,
    session_payload: Dict[str, Any],
    policy: Dict[str, Any],
    status: str = "active",
    *,
    alert_authority_policy: LoadedAlertAuthorityPolicy,
) -> Dict[str, Any]:
    policy = _policy(policy)
    session_id = str(session_payload.get("session_id") or "unknown")
    eligible, reason = _eligible(session_payload, policy, status)
    fingerprint = build_session_fingerprint(session_payload, policy)
    if not eligible:
        return {
            "status": "skipped",
            "reason": reason,
            "session_id": session_id,
            "fingerprint": fingerprint,
        }

    matches = find_matching_campaigns(storage, fingerprint, policy)
    best_match = matches[0] if matches else {}
    existing_campaign = best_match.get("campaign") if best_match else None
    matched_existing = bool(existing_campaign)
    campaign_id = str(
        (existing_campaign or {}).get("campaign_id")
        or _campaign_id_for_fingerprint(fingerprint, session_id)
    )
    prior_campaign_sessions = []
    if matched_existing:
        try:
            prior_campaign_sessions = storage.list_campaign_sessions(campaign_id, limit=100)
        except Exception:
            prior_campaign_sessions = []
    prior_other_session_count = len(
        {
            str(row.get("session_id") or "")
            for row in prior_campaign_sessions
            if str(row.get("session_id") or "") and str(row.get("session_id") or "") != session_id
        }
    )
    campaign = _campaign_payload(campaign_id, fingerprint, session_payload, policy, existing_campaign)
    storage.save_campaign(campaign)
    source_ip_only = fingerprint.get("primary_fingerprint_type") == "src_ip"
    if matched_existing:
        link_confidence = float(best_match.get("score") or 0.0)
    elif source_ip_only:
        link_confidence = float(policy.get("source_ip_only_confidence", 0.2))
    else:
        link_confidence = 1.0
    link_id, inserted = storage.link_campaign_session(
        campaign_id,
        session_id,
        match_reasons=best_match.get("match_reasons") or ["new campaign"],
        confidence=link_confidence,
        payload={
            "session_status": status,
            "fingerprint_id": fingerprint.get("fingerprint_id"),
            "matched_existing_campaign": matched_existing,
            "match_score": best_match.get("score") or 0.0,
            "match_reasons": best_match.get("match_reasons") or [],
            "primary_fingerprint_type": fingerprint.get("primary_fingerprint_type"),
            "primary_fingerprint_value": fingerprint.get("primary_fingerprint_value"),
        },
    )
    session_count = storage.count_campaign_sessions(campaign_id)
    campaign["session_count"] = session_count
    storage.save_campaign(campaign)
    correlation_signal = (
        _similar_session_pattern_signal(
            existing_campaign or {},
            session_payload,
            best_match,
            status,
            policy,
            alert_authority_policy,
        )
        if matched_existing and prior_other_session_count > 0
        else None
    )
    return {
        "status": (
            "matched"
            if matched_existing
            else "created_source_ip_only_low_confidence"
            if source_ip_only
            else "created"
        ),
        "session_id": session_id,
        "campaign_id": campaign_id,
        "matched_existing_campaign": matched_existing,
        "prior_other_session_count": prior_other_session_count,
        "link_id": link_id,
        "link_inserted": inserted,
        "campaign_session_count": session_count,
        "fingerprint": fingerprint,
        "matches": [
            {
                "campaign_id": item.get("campaign_id"),
                "score": item.get("score"),
                "match_reasons": item.get("match_reasons") or [],
            }
            for item in matches
        ],
        "correlation_signal": correlation_signal or {},
        "correlation_signal_id": (
            correlation_signal.get("signal_id") if correlation_signal else ""
        ),
        "automatic_alerts": {
            "status": "prohibited",
            "authorized": False,
            "alert_authority_policy_sha256": alert_authority_policy.sha256,
        },
        "max_confirmed_severity": campaign.get("max_confirmed_severity") or "info",
    }


class CampaignClusteringWorker:
    def __init__(self, config: ProductionConfig) -> None:
        self.config = config
        self.storage = open_storage(config.database_url)
        self.policy = _policy(config)
        self.alert_authority_policy = load_alert_authority_policy(
            config.alert_authority_policy_path
        )

    def backfill(self, limit: int = 1000, include_active: bool = False) -> Dict[str, Any]:
        rows = self.storage.list_rows("sessions", limit=max(int(limit), 1))
        processed = 0
        clustered = 0
        skipped = 0
        signals = 0
        for row in rows:
            payload = row.get("payload")
            if not isinstance(payload, dict):
                try:
                    payload = json.loads(str(row.get("payload_json") or "{}"))
                except json.JSONDecodeError:
                    payload = {}
            if not isinstance(payload, dict):
                continue
            payload.setdefault("session_id", row.get("session_id") or "")
            payload.setdefault("src_ip", row.get("src_ip") or "")
            ended = bool(row.get("ended") or payload.get("is_ended"))
            if not ended and not include_active:
                continue
            status = "closed" if ended else "active"
            processed += 1
            summary = create_or_update_campaign(
                self.storage,
                payload,
                self.policy,
                status=status,
                alert_authority_policy=self.alert_authority_policy,
            )
            if summary.get("status") in {"created", "matched"}:
                clustered += 1
            else:
                skipped += 1
            if summary.get("correlation_signal_id"):
                signals += 1
            payload["campaign_summary"] = summary
            self.storage.save_session(payload)
        return {
            "status": "completed",
            "processed": processed,
            "clustered": clustered,
            "skipped": skipped,
            "correlation_signals": signals,
            "automatic_alerts_created": 0,
            "limit": limit,
            "include_active": include_active,
            "alert_authority_policy_sha256": self.alert_authority_policy.sha256,
            "timestamp": utc_now(),
        }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backfill campaign clustering from stored sessions.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--backfill", action="store_true", help="Cluster existing stored sessions.")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--include-active", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    worker = CampaignClusteringWorker(config)
    if args.backfill:
        print(
            json.dumps(
                {
                    "service": "campaign_clustering",
                    "backfill": worker.backfill(args.limit, args.include_active),
                },
                sort_keys=True,
            )
        )
        return 0
    print(json.dumps({"service": "campaign_clustering", "status": "no_action"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
