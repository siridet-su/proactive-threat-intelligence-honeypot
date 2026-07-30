"""Cross-session observable relationship worker.

The worker stores evidence-linked relationships and observational signals. A
shared observable does not establish actor identity and has no alert, guidance,
or response authority.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from production.classification.trust import is_trusted_classification_event
from production.correlation.session_ttp_correlation import correlation_allows_influence
from production.utils.config import ProductionConfig
from production.policies.alert_authority_policy import load_alert_authority_policy
from production.correlation.observable_sightings import extract_session_observable_sightings
from production.utils.sensitive_data import redact_exception_for_log
from production.utils.serialization import stable_id, utc_now
from production.utils.service_lifecycle import ServiceLifecycle
from production.storage import open_storage
from production.workers.job_lifecycle import (
    JobLeaseHeartbeat,
    job_failure_identity,
    job_retry_delay,
    new_job_owner,
)


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RANK_SEVERITY = {value: key for key, value in SEVERITY_RANK.items()}


def _policy(config_or_policy: ProductionConfig | Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(config_or_policy, ProductionConfig):
        raw = config_or_policy.threat_hunt_policy
    else:
        raw = config_or_policy
    policy = dict(raw or {})
    policy.setdefault("enabled", True)
    policy.setdefault("enqueue_on_session_close", True)
    policy.setdefault("signal_active_sessions", True)
    policy.setdefault("max_jobs_per_session", 50)
    policy.setdefault("max_related_sessions_per_job", 100)
    policy.setdefault("observable_types", ["ip", "url", "domain", "hash", "hassh", "ja3"])
    policy.setdefault("include_private_ips", True)
    policy.setdefault("include_source_ip_without_activity", False)
    policy.setdefault("min_commands_for_source_ip", 1)
    policy.setdefault(
        "confidence_by_observable_type",
        {"hash": 0.95, "url": 0.90, "domain": 0.80, "hassh": 0.75, "ja3": 0.75, "ip": 0.65},
    )
    policy.setdefault(
        "severity_by_observable_type",
        {"hash": "high", "url": "high", "domain": "medium", "hassh": "medium", "ja3": "medium", "ip": "medium"},
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


def _commands_count(session_payload: Dict[str, Any]) -> int:
    commands = session_payload.get("commands") or []
    return len(commands) if isinstance(commands, list) else 0


def _login_success(session_payload: Dict[str, Any]) -> bool:
    return bool(session_payload.get("login_success") or session_payload.get("successful_login"))


def _tactics(
    session_payload: Dict[str, Any],
    correlation_scope: str = "threat_hunt",
) -> List[str]:
    output: List[str] = []
    classification_events = [
        event for event in session_payload.get("classification_events") or []
        if isinstance(event, dict)
    ]
    if classification_events:
        for event in classification_events:
            if not is_trusted_classification_event(event):
                continue
            text = str(event.get("tactic") or "").strip()
            if text and text not in output:
                output.append(text)
    else:
        for value in session_payload.get("tactics") or session_payload.get("unique_tactics") or []:
            text = str(value or "").strip()
            if text and text not in output:
                output.append(text)
    for item in session_payload.get("session_ttp_correlations") or []:
        if (
            isinstance(item, dict)
            and correlation_allows_influence(item, correlation_scope)
        ):
            text = str(item.get("tactic") or "").strip()
            if text and text not in output:
                output.append(text)
    return output


def _source_severity(policy: Dict[str, Any], observable_type: str, source_payload: Dict[str, Any]) -> str:
    base = str((policy.get("severity_by_observable_type") or {}).get(observable_type) or "medium")
    tactic_map = policy.get("tactic_severity") or {}
    tactic_severities = [
        str(tactic_map.get(tactic) or "")
        for tactic in _tactics(source_payload, "alert")
    ]
    return _severity_max(base, *tactic_severities)


def _confidence(policy: Dict[str, Any], observable_type: str) -> float:
    try:
        value = float((policy.get("confidence_by_observable_type") or {}).get(observable_type, 0.5))
    except (TypeError, ValueError):
        value = 0.5
    return max(0.0, min(value, 1.0))


def _session_observable_candidates(
    session_payload: Dict[str, Any],
    policy: Dict[str, Any],
) -> List[Dict[str, Any]]:
    allowed = {str(item).strip().lower() for item in policy.get("observable_types") or []}
    include_private = bool(policy.get("include_private_ips", True))
    include_source_ip_without_activity = bool(policy.get("include_source_ip_without_activity", False))
    min_commands_for_source_ip = int(policy.get("min_commands_for_source_ip") or 0)
    command_count = _commands_count(session_payload)
    has_login_success = _login_success(session_payload)
    candidates: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str]] = set()
    for sighting in extract_session_observable_sightings(session_payload, source="threat_hunt_enqueue"):
        observable_type = str(sighting.get("observable_type") or "").strip().lower()
        observable_value = str(sighting.get("observable_value") or "").strip()
        if not observable_type or not observable_value or (allowed and observable_type not in allowed):
            continue
        metadata = ((sighting.get("payload") or {}).get("metadata") or {}) if isinstance(sighting.get("payload"), dict) else {}
        role = str(sighting.get("role") or "")
        if observable_type == "ip":
            if metadata.get("is_private") and not include_private:
                continue
            if role == "session_source_ip" and not include_source_ip_without_activity:
                if command_count < min_commands_for_source_ip and not has_login_success:
                    continue
        marker = (observable_type, observable_value)
        if marker in seen:
            continue
        seen.add(marker)
        candidates.append(
            {
                "observable_type": observable_type,
                "observable_value": observable_value,
                "role": role,
                "source": sighting.get("source") or "",
                "metadata": metadata,
            }
        )
    return candidates


def enqueue_threat_hunts_for_session(storage: Any, session_payload: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    policy = _policy(policy)
    session_id = str(session_payload.get("session_id") or "unknown")
    if not policy.get("enabled", True) or not policy.get("enqueue_on_session_close", True):
        return {"status": "disabled", "session_id": session_id, "queued": 0, "candidates": 0}
    candidates = _session_observable_candidates(session_payload, policy)
    max_jobs = int(policy.get("max_jobs_per_session") or 50)
    queued = 0
    job_ids: List[str] = []
    for item in candidates[:max_jobs]:
        job_id, inserted = storage.enqueue_threat_hunt_job(
            session_id,
            item["observable_type"],
            item["observable_value"],
            trigger_reason="session_closed_observable",
            payload={
                "source": "session_worker",
                "source_session_id": session_id,
                "observable": item,
                "source_tactics": _tactics(session_payload),
                "command_count": _commands_count(session_payload),
            },
        )
        job_ids.append(job_id)
        if inserted:
            queued += 1
    return {
        "status": "queued",
        "session_id": session_id,
        "queued": queued,
        "candidates": len(candidates),
        "job_ids": job_ids,
        "truncated": len(candidates) > max_jobs,
    }


class ThreatHuntWorker:
    def __init__(self, config: ProductionConfig) -> None:
        self.config = config
        self.policy = _policy(config)
        self.storage = open_storage(config.database_url)
        self.worker_owner = new_job_owner("threat-hunt")
        self.alert_authority_policy = load_alert_authority_policy(
            config.alert_authority_policy_path
        )

    def _correlation_signal(
        self,
        job: Dict[str, Any],
        related: Dict[str, Any],
        link_id: str,
        confidence: float,
    ) -> Dict[str, Any]:
        observable_type = str(job.get("observable_type") or "")
        observable_value = str(job.get("observable_value") or "")
        related_session_id = str(related.get("session_id") or "unknown")
        source_session_id = str(job.get("session_id") or "unknown")
        return {
            "schema_version": "correlation_signal.v1",
            "signal_id": stable_id(
                "correlationsignal",
                {
                    "source_session_id": source_session_id,
                    "related_session_id": related_session_id,
                    "observable_type": observable_type,
                    "observable_value": observable_value,
                    "link_id": link_id,
                    "alert_authority_policy_sha256": self.alert_authority_policy.sha256,
                },
            ),
            "session_id": related_session_id,
            "signal_type": "shared_observable_relationship_observed",
            "source_session_id": source_session_id,
            "related_session_id": related_session_id,
            "job_id": job.get("job_id") or "",
            "link_id": link_id,
            "observable_type": observable_type,
            "observable_value": observable_value,
            "relationship_confidence": confidence,
            "related_sighting_count": related.get("sighting_count") or 0,
            "related_first_seen": related.get("first_seen") or "",
            "related_last_seen": related.get("last_seen") or "",
            "authority": {
                "semantics": "observation_only_non_authoritative",
                "may_claim_actor_identity": False,
                "may_create_alert": False,
                "may_authorize_response": False,
            },
            "limitations": [
                "a shared observable does not establish actor identity",
                "the relationship may reflect shared infrastructure or common tooling",
                "signal cannot authorize an alert, external delivery, or response",
            ],
            "provenance": {
                "alert_authority_policy_id": self.alert_authority_policy.policy_id,
                "alert_authority_policy_sha256": self.alert_authority_policy.sha256,
            },
        }

    def _process_job(self, job: Dict[str, Any]) -> Dict[str, Any]:
        source_session_id = str(job.get("session_id") or "unknown")
        observable_type = str(job.get("observable_type") or "").strip().lower()
        observable_value = str(job.get("observable_value") or "").strip()
        max_related = int(self.policy.get("max_related_sessions_per_job") or 100)
        related_sessions = self.storage.find_sessions_by_observable(
            observable_type,
            observable_value,
            exclude_session_id=source_session_id,
            limit=max_related,
        )
        confidence = _confidence(self.policy, observable_type)
        links: List[Dict[str, Any]] = []
        signals: List[Dict[str, Any]] = []
        for related in related_sessions:
            related_session_id = str(related.get("session_id") or "")
            if not related_session_id:
                continue
            link_payload = {
                "session_id_a": source_session_id,
                "session_id_b": related_session_id,
                "link_type": "shared_observable",
                "observable_type": observable_type,
                "observable_value": observable_value,
                "confidence": confidence,
                "job_id": job.get("job_id") or "",
                "source_session_id": source_session_id,
                "related_session_id": related_session_id,
                "related_sighting_count": related.get("sighting_count") or 0,
                "related_first_seen": related.get("first_seen") or "",
                "related_last_seen": related.get("last_seen") or "",
                "related_roles": related.get("roles") or [],
                "related_sources": related.get("sources") or [],
                "created_at": utc_now(),
            }
            link_id = self.storage.save_session_link(link_payload)
            links.append({"link_id": link_id, **link_payload})
            if self.policy.get("signal_active_sessions", True) and not bool(
                related.get("ended")
            ):
                signals.append(
                    self._correlation_signal(job, related, link_id, confidence)
                )
        return {
            "status": "succeeded",
            "job_id": job.get("job_id") or "",
            "source_session_id": source_session_id,
            "observable_type": observable_type,
            "observable_value": observable_value,
            "related_session_count": len(related_sessions),
            "links_created": len(links),
            "signals_created": len(signals),
            "link_ids": [item["link_id"] for item in links],
            "signal_ids": [item["signal_id"] for item in signals],
            "correlation_signals": signals,
            "alerts_created": 0,
            "alert_ids": [],
            "automatic_alerts": {
                "status": "prohibited",
                "authorized": False,
                "alert_authority_policy_sha256": self.alert_authority_policy.sha256,
            },
            "confidence": confidence,
            "timestamp": utc_now(),
        }

    def process_once(
        self,
        *,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> int:
        if not self.policy.get("enabled", True):
            return 0
        processed = 0
        for _ in range(self.config.threat_hunt_batch_size):
            if should_stop is not None and should_stop():
                break
            jobs = self.storage.claim_threat_hunt_jobs(
                self.worker_owner,
                1,
                self.config.job_lease_seconds,
                self.config.threat_hunt_max_attempts,
            )
            if not jobs:
                break
            job = jobs[0]
            if should_stop is not None and should_stop():
                self.storage.release_job_claim(
                    "threat_hunt",
                    job["job_id"],
                    job["claim_owner"],
                    job["claim_token"],
                )
                break
            with JobLeaseHeartbeat(self.storage, self.config, "threat_hunt", job) as heartbeat:
                try:
                    result = self._process_job(job)
                    heartbeat.check(renew=True)
                    completed = self.storage.complete_threat_hunt_job(
                        job.get("job_id", ""),
                        job["claim_owner"],
                        job["claim_token"],
                        result,
                    )
                    processed += int(completed)
                    print(
                        json.dumps(
                            {
                                "service": "threat_hunt_worker",
                                "job_id": job.get("job_id", ""),
                                "correlation_id": job.get("job_id", ""),
                                "status": "succeeded" if completed else "stale_claim",
                                "timestamp": utc_now(),
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                except Exception as exc:
                    error_code, error_type, retryable = job_failure_identity(
                        "threat_hunt", exc
                    )
                    status = self.storage.fail_threat_hunt_job(
                        job.get("job_id", ""),
                        job["claim_owner"],
                        job["claim_token"],
                        error_code,
                        error_type,
                        retryable,
                        self.config.threat_hunt_max_attempts,
                        job_retry_delay(self.config, int(job.get("attempts") or 1)),
                    )
                    print(
                        json.dumps(
                            {
                                "service": "threat_hunt_worker",
                                "job_id": job.get("job_id", ""),
                                "correlation_id": job.get("job_id", ""),
                                "status": status,
                                "error": redact_exception_for_log(exc),
                                "timestamp": utc_now(),
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
        return processed

    def enqueue_existing_sessions(self, limit: int = 1000, ended_only: bool = True) -> Dict[str, Any]:
        rows = self.storage.list_rows("sessions", limit=max(int(limit), 1))
        sessions_seen = 0
        sessions_queued = 0
        jobs_queued = 0
        candidates = 0
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
            payload.setdefault("src_ip", row.get("src_ip") or "unknown")
            if ended_only and not bool(row.get("ended") or payload.get("is_ended")):
                continue
            sessions_seen += 1
            summary = enqueue_threat_hunts_for_session(self.storage, payload, self.policy)
            candidates += int(summary.get("candidates") or 0)
            queued = int(summary.get("queued") or 0)
            jobs_queued += queued
            if queued:
                sessions_queued += 1
        return {
            "status": "completed",
            "sessions_seen": sessions_seen,
            "sessions_with_new_jobs": sessions_queued,
            "jobs_queued": jobs_queued,
            "candidates": candidates,
            "limit": limit,
            "ended_only": ended_only,
            "timestamp": utc_now(),
        }

    def run_forever(self, lifecycle: Optional[ServiceLifecycle] = None) -> None:
        control = lifecycle or ServiceLifecycle()
        with control.signal_handlers():
            while not control.stopping:
                processed = self.process_once(should_stop=lambda: control.stopping)
                if processed:
                    print(
                        json.dumps(
                            {
                                "service": "threat_hunt_worker",
                                "processed": processed,
                                "timestamp": utc_now(),
                            },
                            sort_keys=True,
                        ),
                        flush=True,
                    )
                control.wait(self.config.threat_hunt_poll_seconds)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run cross-session threat hunting jobs.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument("--once", action="store_true", help="Process one batch and exit.")
    parser.add_argument("--enqueue-existing-sessions", action="store_true", help="Queue threat-hunt jobs from already stored sessions.")
    parser.add_argument("--backfill-limit", type=int, default=1000, help="Maximum sessions to inspect when --enqueue-existing-sessions is used.")
    parser.add_argument("--include-active-backfill", action="store_true", help="Also queue jobs from active sessions during backfill.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config)
    worker = ThreatHuntWorker(config)
    if args.enqueue_existing_sessions:
        summary = worker.enqueue_existing_sessions(
            limit=args.backfill_limit,
            ended_only=not args.include_active_backfill,
        )
        print(json.dumps({"service": "threat_hunt_worker", "backfill": summary}, sort_keys=True))
        return 0
    if args.once:
        processed = worker.process_once()
        print(json.dumps({"service": "threat_hunt_worker", "processed": processed}, sort_keys=True))
        return 0
    worker.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
