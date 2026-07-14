"""Live campaign clustering from honeypot session fingerprints.

This module is deliberately separate from known-actor attribution. Attribution
asks "does this session overlap a named actor profile?". Campaign clustering asks
"does this session look like the same actor/tooling cluster we have already
seen in our own telemetry?".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from production.classification.trust import is_trusted_classification_event
from production.utils.config import ProductionConfig
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
    policy.setdefault("max_matches", 10)
    policy.setdefault("command_pattern_command_limit", 6)
    policy.setdefault("command_pattern_token_limit", 3)
    policy.setdefault("known_actor_return_alerts", True)
    policy.setdefault("known_actor_min_prior_severity", "high")
    policy.setdefault("known_actor_alert_on_status", ["active", "closed"])
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
        if isinstance(item, dict):
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
    return {
        "campaign_id": campaign.get("campaign_id") or "",
        "score": round(normalized, 4),
        "raw_score": round(score, 4),
        "total_possible": round(total_possible, 4),
        "match_reasons": reasons,
        "campaign": campaign,
    }


def find_matching_campaigns(storage: Any, fingerprint: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    candidates = storage.find_matching_campaigns(fingerprint, limit=int(policy.get("max_matches") or 10) * 5)
    matches = [score_campaign_match(candidate, fingerprint, policy) for candidate in candidates]
    minimum = float(policy.get("min_match_score") or 0.0)
    matches = [item for item in matches if item["score"] >= minimum]
    return sorted(matches, key=lambda item: item["score"], reverse=True)[: int(policy.get("max_matches") or 10)]


def _campaign_id_for_fingerprint(fingerprint: Dict[str, Any]) -> str:
    return stable_id(
        "campaign",
        {
            "primary_fingerprint_type": fingerprint.get("primary_fingerprint_type") or "",
            "primary_fingerprint_value": fingerprint.get("primary_fingerprint_value") or "",
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


def _known_actor_return_alert(
    campaign: Dict[str, Any],
    session_payload: Dict[str, Any],
    match: Dict[str, Any],
    status: str,
    policy: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if not policy.get("known_actor_return_alerts", True):
        return None
    allowed_status = {str(item).strip().lower() for item in policy.get("known_actor_alert_on_status") or []}
    if allowed_status and status not in allowed_status:
        return None
    prior_severity = str(campaign.get("max_confirmed_severity") or "info").lower()
    minimum = str(policy.get("known_actor_min_prior_severity") or "high").lower()
    if SEVERITY_RANK.get(prior_severity, 0) < SEVERITY_RANK.get(minimum, 3):
        return None
    session_id = str(session_payload.get("session_id") or "unknown")
    campaign_id = str(campaign.get("campaign_id") or "")
    return {
        "alert_id": stable_id("knownactorreturn", {"campaign_id": campaign_id, "session_id": session_id}),
        "session_id": session_id,
        "severity": prior_severity.upper(),
        "reason": f"Known campaign returned: session matched campaign {campaign_id}",
        "created_at": utc_now(),
        "alert_type": "known_actor_return",
        "payload": {
            "alert_type": "known_actor_return",
            "campaign_id": campaign_id,
            "session_id": session_id,
            "session_status": status,
            "prior_campaign_severity": prior_severity,
            "match_score": match.get("score"),
            "match_reasons": match.get("match_reasons") or [],
            "campaign_session_count": campaign.get("session_count") or 0,
        },
    }


def create_or_update_campaign(
    storage: Any,
    session_payload: Dict[str, Any],
    policy: Dict[str, Any],
    status: str = "active",
    emit_alerts: bool = True,
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
    campaign_id = str((existing_campaign or {}).get("campaign_id") or _campaign_id_for_fingerprint(fingerprint))
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
    link_confidence = float(best_match.get("score") or (0.0 if matched_existing else 1.0))
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
    alert_id = ""
    alert = (
        _known_actor_return_alert(existing_campaign or {}, session_payload, best_match, status, policy)
        if emit_alerts and matched_existing and prior_other_session_count > 0
        else None
    )
    if alert:
        alert_id = storage.store_alert(alert)
    return {
        "status": "matched" if matched_existing else "created",
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
        "known_actor_return_alert_id": alert_id,
        "max_confirmed_severity": campaign.get("max_confirmed_severity") or "info",
    }


class CampaignClusteringWorker:
    def __init__(self, config: ProductionConfig) -> None:
        self.config = config
        self.storage = open_storage(config.database_url)
        self.policy = _policy(config)

    def backfill(self, limit: int = 1000, include_active: bool = False, emit_alerts: bool = False) -> Dict[str, Any]:
        rows = self.storage.list_rows("sessions", limit=max(int(limit), 1))
        processed = 0
        clustered = 0
        skipped = 0
        alerts = 0
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
                emit_alerts=emit_alerts,
            )
            if summary.get("status") in {"created", "matched"}:
                clustered += 1
            else:
                skipped += 1
            if summary.get("known_actor_return_alert_id"):
                alerts += 1
            payload["campaign_summary"] = summary
            self.storage.save_session(payload)
        return {
            "status": "completed",
            "processed": processed,
            "clustered": clustered,
            "skipped": skipped,
            "known_actor_return_alerts": alerts,
            "limit": limit,
            "include_active": include_active,
            "emit_alerts": emit_alerts,
            "timestamp": utc_now(),
        }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backfill campaign clustering from stored sessions.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--backfill", action="store_true", help="Cluster existing stored sessions.")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--include-active", action="store_true")
    parser.add_argument("--emit-alerts", action="store_true", help="Allow backfill to create known_actor_return alerts.")
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
                    "backfill": worker.backfill(args.limit, args.include_active, args.emit_alerts),
                },
                sort_keys=True,
            )
        )
        return 0
    print(json.dumps({"service": "campaign_clustering", "status": "no_action"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
