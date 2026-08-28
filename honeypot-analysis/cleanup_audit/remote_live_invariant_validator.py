"""Run the final 00d7 live invariant check on the promotion host.

This is operational validation tooling, not immutable application source.  It
is run as root so it can atomically publish a root-owned receipt, while the
Mongo storage query is executed with the actual ``honeypot`` effective uid.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import grp
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

from live_invariant_receipt_writer import (
    REQUIRED_INVARIANTS,
    validate_complete_receipt,
    write_atomic_json,
)


CANDIDATE = "00d7e9594b11505c167f4e03bb3efffd9a90144b"
RECOVERY = "403c989d9cfe7e7726610018345352e76bfd5d7f"
PACKAGE_SHA256 = "4597c15dfbcc69030097d6fa2a0f55ab8f8df366d15f2a60445842dbe9945fae"
TREE_SHA1 = "d061bb3b0cbb73d348d2748ee98b0404138f5096"
MANIFEST_SHA256 = "e125c19c94dce085f276ae8d903e508b8c8574c89243182e03f62f9b36e0373e"
ENV_SHA256 = "9976d5141c1ab5229aa5cdd81765cf740a0d359a1c2d6caf553cf399790c5cf4"
MIRROR_PATH = "/var/lib/honeypot/mongodb_epoch_retry_49f9b74.db"
MIRROR_ID = "ec6dac4fbd51eff43455382fe4ae6591083869e54c86e0ff0ca6319d67b75442"
OLD_EPOCH_SHA256 = "f155419ffbd43f6910223f0c9a3cd347d0385d475771d37e79174b51b60ad017"


def sha256(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text(path: str | os.PathLike[str]) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def row_payload(row: dict) -> dict:
    """Decode the canonical JSON payload regardless of storage projection shape."""

    payload = row.get("payload")
    if isinstance(payload, dict):
        return payload
    try:
        decoded = json.loads(row.get("payload_json") or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def load_pre_metrics(
    path: str | os.PathLike[str],
) -> tuple[dict | None, str | None, str | None]:
    """Load counts and the measurement boundary, failing closed on either."""

    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return None, None, f"pre-cutover metrics could not be read or parsed: {exc}"
    metrics = value.get("metrics") if isinstance(value, dict) else None
    counts = metrics.get("collection_counts") if isinstance(metrics, dict) else None
    if not isinstance(counts, dict):
        return None, None, "pre-cutover metrics collection_counts object is missing or invalid"
    normalized = {
        str(key): value
        for key, value in counts.items()
        if isinstance(key, str) and isinstance(value, int) and not isinstance(value, bool)
    }
    if len(normalized) != len(counts):
        return None, None, "pre-cutover metrics collection_counts contains invalid entries"
    checked_at = metrics.get("checked_at") if isinstance(metrics, dict) else None
    if not isinstance(checked_at, str) or not checked_at.strip():
        return None, None, "pre-cutover metrics checked_at boundary is missing or invalid"
    return normalized, checked_at.strip(), None


def load_collection_counts(path: str | os.PathLike[str]) -> tuple[dict | None, str | None]:
    """Compatibility wrapper used by focused malformed-input tests."""

    counts, _checked_at, error = load_pre_metrics(path)
    return counts, error


def deterministic_session_link_id(
    session_id_a: str,
    session_id_b: str,
    link_type: str,
    observable_type: str,
    observable_value: str,
) -> str:
    """Reproduce the canonical session-link identity contract independently."""

    payload = {
        "sessions": sorted([str(session_id_a), str(session_id_b)]),
        "link_type": str(link_type),
        "observable_type": str(observable_type).strip().lower(),
        "observable_value": str(observable_value),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sessionlink_" + hashlib.sha256(encoded).hexdigest()[:32]


def derive_expected_session_links(
    storage: Any,
    session_id: str,
    job_documents: list[dict[str, Any]],
    max_related: int,
) -> dict[str, dict[str, Any]]:
    """Derive the exact allowed link identities from the current producer contract."""

    expected: dict[str, dict[str, Any]] = {}
    for job in job_documents:
        observable_type = str(job.get("observable_type") or "").strip().lower()
        observable_value = str(job.get("observable_value") or "")
        job_id = str(job.get("job_id") or job.get("_id") or "")
        if not observable_type or not observable_value or not job_id:
            continue
        related = storage.find_sessions_by_observable(
            observable_type,
            observable_value,
            exclude_session_id=session_id,
            limit=max_related,
        )
        for item in related:
            target = str(item.get("session_id") or "")
            if not target:
                continue
            link_id = deterministic_session_link_id(
                session_id,
                target,
                "shared_observable",
                observable_type,
                observable_value,
            )
            if link_id in expected:
                raise ValueError("duplicate expected session-link identity")
            expected[link_id] = {
                "link_id": link_id,
                "job_id": job_id,
                "source_session_id": session_id,
                "related_session_id": target,
                "link_type": "shared_observable",
                "observable_type": observable_type,
                "observable_value_sha256": hashlib.sha256(
                    observable_value.encode("utf-8")
                ).hexdigest(),
            }
    return expected


def assess_session_link_contract(
    expected: dict[str, dict[str, Any]],
    actual_documents: list[dict[str, Any]],
    window_documents: list[dict[str, Any]],
    job_documents: list[dict[str, Any]],
) -> dict[str, Any]:
    """Attribute link writes without treating historical targets as replay."""

    expected_ids = set(expected)
    actual_ids = {
        str(item.get("link_id") or item.get("_id") or "")
        for item in actual_documents
    } - {""}
    window_ids = {
        str(item.get("link_id") or item.get("_id") or "")
        for item in window_documents
    } - {""}
    job_ids = {
        str(item.get("job_id") or item.get("_id") or "")
        for item in job_documents
    } - {""}
    result_ids: set[str] = set()
    result_shape_valid = True
    for job in job_documents:
        try:
            result = json.loads(job.get("result_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            result = {}
            result_shape_valid = False
        ids = result.get("link_ids")
        if not isinstance(ids, list):
            result_shape_valid = False
            ids = []
        result_ids.update(str(item) for item in ids if item)
        if result.get("links_created") != len(ids):
            result_shape_valid = False

    provenance_errors: list[str] = []
    for item in actual_documents:
        link_id = str(item.get("link_id") or item.get("_id") or "")
        try:
            payload = json.loads(item.get("payload_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            provenance_errors.append(f"{link_id}:payload_json")
            continue
        contract = expected.get(link_id) or {}
        other_session = (
            item.get("session_id_b")
            if item.get("session_id_a") == contract.get("source_session_id")
            else item.get("session_id_a")
        )
        if (
            payload.get("source_session_id") != contract.get("source_session_id")
            or payload.get("related_session_id") != contract.get("related_session_id")
            or payload.get("job_id") != contract.get("job_id")
            or other_session != contract.get("related_session_id")
            or item.get("link_type") != contract.get("link_type")
            or item.get("observable_type") != contract.get("observable_type")
            or hashlib.sha256(
                str(item.get("observable_value") or "").encode("utf-8")
            ).hexdigest()
            != contract.get("observable_value_sha256")
        ):
            provenance_errors.append(f"{link_id}:contract")

    contract_valid = (
        actual_ids == expected_ids
        and result_ids == expected_ids
        and result_shape_valid
        and not provenance_errors
    )
    historical_replay_zero = window_ids == expected_ids
    return {
        "contract_valid": contract_valid,
        "historical_replay_zero": historical_replay_zero,
        "expected_count": len(expected_ids),
        "actual_count": len(actual_ids),
        "window_count": len(window_ids),
        "expected_ids": sorted(expected_ids),
        "actual_ids": sorted(actual_ids),
        "window_ids": sorted(window_ids),
        "job_ids": sorted(job_ids),
        "job_result_ids": sorted(result_ids),
        "missing_ids": sorted(expected_ids - actual_ids),
        "unexpected_ids": sorted(actual_ids - expected_ids),
        "out_of_contract_window_ids": sorted(window_ids - expected_ids),
        "provenance_errors": provenance_errors,
        "expected": [expected[key] for key in sorted(expected)],
    }


def load_service_environment() -> None:
    pid = subprocess.check_output(
        ["systemctl", "show", "-p", "MainPID", "--value", "honeypot-analysis-worker.service"],
        text=True,
    ).strip()
    for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0"):
        if b"=" in item:
            key, value = item.split(b"=", 1)
            os.environ[key.decode()] = value.decode(errors="surrogateescape")


def with_honeypot_storage(
    session_id: str,
    callback,
    *,
    runtime_root: str = "/opt/honeypot",
    epoch_path: str = "/etc/honeypot/canonical_storage_epoch.v2.json",
):
    """Open the exact Mongo epoch adapter under the service effective uid.

    ``runtime_root`` and ``epoch_path`` are process-local overrides used only
    by the no-cutover preflight.  The normal live invocation keeps the active
    symlink and system epoch path unchanged.
    """

    load_service_environment()
    original_cwd = os.getcwd()
    previous_env = {
        name: os.environ.get(name)
        for name in ("DEPLOYED_COMMIT", "DEPLOYED_TREE", "RELEASE_MANIFEST_SHA256", "STORAGE_EPOCH_RECEIPT_PATH")
    }
    runtime_revision = Path(os.path.realpath(runtime_root)).name
    os.environ["DEPLOYED_COMMIT"] = runtime_revision
    os.environ["STORAGE_EPOCH_RECEIPT_PATH"] = epoch_path
    os.chdir(runtime_root)
    sys.path.insert(0, runtime_root)
    service_user = pwd.getpwnam("honeypot")
    service_group = grp.getgrnam("honeypot")
    real_uid, real_gid = os.getuid(), os.getgid()
    original_groups = os.getgroups()
    os.setgroups([service_group.gr_gid])
    os.setegid(service_group.gr_gid)
    os.seteuid(service_user.pw_uid)
    try:
        from production.storage.backend import open_storage
        from production.utils.config import ProductionConfig

        storage = open_storage(ProductionConfig.from_env().database_settings())
        return callback(storage)
    finally:
        os.seteuid(real_uid)
        os.setegid(real_gid)
        os.setgroups(original_groups)
        os.chdir(original_cwd)
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def run(args: argparse.Namespace) -> dict:
    checks: dict[str, bool] = {}
    details: dict[str, object] = {}
    failures: list[str] = []

    def check(name: str, value: bool, detail: object | None = None) -> None:
        checks[name] = bool(value)
        if detail is not None:
            details[name] = detail
        if not value and not (preflight and name == "candidate_active_before_validation"):
            failures.append(name)

    preflight = bool(getattr(args, "preflight", False))
    runtime_root = str(getattr(args, "runtime_root", "/opt/honeypot"))
    epoch_path = str(
        getattr(args, "epoch_path", "/etc/honeypot/canonical_storage_epoch.v2.json")
    )
    active = os.path.realpath("/opt/honeypot")
    runtime_active = os.path.realpath(runtime_root)
    backup_path = args.backup
    epoch = json.loads(Path(epoch_path).read_text(encoding="utf-8"))
    guard = json.loads(Path(args.guard).read_text(encoding="utf-8"))
    services = [
        "honeypot-analysis-worker.service",
        "honeypot-dashboard-api.service",
        "honeypot-enrichment-worker.service",
        "honeypot-ingest-api.service",
        "honeypot-monitor-web.service",
        "honeypot-session-worker.service",
        "honeypot-threat-hunt-worker.service",
        "honeypot-webhook-dispatcher.service",
        "honeypot-next-distinct-shadow.service",
        "honeypot-next-distinct-shadow-feeder.service",
    ]
    service_states = {
        service: subprocess.check_output(["systemctl", "is-active", service], text=True).strip()
        for service in services
    }
    service_restarts = {
        service: int(
            subprocess.check_output(["systemctl", "show", "-p", "NRestarts", "--value", service], text=True).strip()
            or 0
        )
        for service in services
    }
    guard_states = [event.get("state") for event in guard.get("events", [])]
    check("candidate_active_before_validation", active == f"/opt/honeypot-releases/{CANDIDATE}", active)
    check("candidate_marker", read_text(f"{runtime_root}/DEPLOYED_COMMIT") == CANDIDATE)
    check("candidate_tree", read_text(f"{runtime_root}/DEPLOYED_TREE") == TREE_SHA1)
    check("candidate_manifest", read_text(f"{runtime_root}/RELEASE_MANIFEST_SHA256") == MANIFEST_SHA256)
    check("package_hash", sha256(f"/opt/honeypot-packages/{CANDIDATE}.tar.gz") == PACKAGE_SHA256)
    check(
        "guard_candidate_ready",
        ("CANDIDATE_READY" in guard_states) if preflight else guard.get("state") == "CANDIDATE_READY",
        guard.get("state"),
    )
    check("guard_pre_cutover_database_verified", "PRE_CUTOVER_DATABASE_VERIFIED" in guard_states)
    check("guard_candidate_database_verified", "CANDIDATE_DATABASE_VERIFIED" in guard_states)
    check("all_services_active", all(state == "active" for state in service_states.values()), service_states)
    check("no_service_restarts", all(value == 0 for value in service_restarts.values()), service_restarts)
    check("recovery_release_present", os.path.isdir(f"/opt/honeypot-releases/{RECOVERY}"))
    check("recovery_receipt_backup", sha256(backup_path) == OLD_EPOCH_SHA256, sha256(backup_path))
    check("candidate_epoch_binding", epoch.get("reviewed_release_sha") == CANDIDATE)
    check("mirror_path", (epoch.get("rollback_mirror") or {}).get("path") == MIRROR_PATH)
    check("mirror_identity", (epoch.get("rollback_mirror") or {}).get("identity_id") == MIRROR_ID)
    shadow = json.loads(urllib.request.urlopen("http://127.0.0.1:18082/health", timeout=10).read())
    check("shadow_ready", shadow.get("status") == "READY" and shadow.get("model_ready") is True, shadow.get("status"))
    check(
        "shadow_non_authoritative",
        shadow.get("authority") == "non_authoritative",
        {"authority": shadow.get("authority")},
    )
    check("shadow_canonical_write_disabled", shadow.get("canonical_write_allowed") is False)

    def database_checks(storage):
        from production.prediction.evidence_cutoff import validate_evidence_cutoff
        from production.prediction.next_behavior_contract import validate_next_behavior_session
        from production.prediction.next_behavior_runtime import build_live_next_behavior_session
        from production.prediction.prediction_snapshot_contract import validate_prediction_snapshot_integrity
        from production.prediction.trusted_history import validate_prediction_trusted_history_manifest
        from production.utils.config import ProductionConfig
        from production.utils.serialization import stable_json

        session = storage.get_session(args.session_id) or {}
        session_payload = session.get("payload") or {}
        jobs = storage.list_rows_for_session("analysis_jobs", args.session_id, 10)
        reports = storage.list_rows_for_session("reports", args.session_id, 10)
        current_prediction = storage.get_current_prediction_snapshot(args.session_id) or {}
        prediction_payload = current_prediction.get("payload") or {}
        check(
            "session_exists_closed",
            bool(session) and session_payload.get("is_ended") is True and session_payload.get("analysis_status") == "succeeded",
            {"analysis_status": session_payload.get("analysis_status"), "is_ended": session_payload.get("is_ended")},
        )
        check("sensor_session_binding", session_payload.get("sensor_session_id") == args.cowrie_session_id)
        check("approved_endpoint_bound", session_payload.get("dst_ip") == "100.118.43.30" and session_payload.get("dst_port") == 22)
        check("exact_commands", session_payload.get("commands") == ["id", "whoami", "exit"])
        check("analysis_job_succeeded", len(jobs) == 1 and jobs[0].get("status") == "succeeded")
        check("report_succeeded", len(reports) == 1 and bool(reports[0].get("report_id")))
        try:
            job_payload = json.loads(jobs[0].get("payload_json") or "{}") if jobs else {}
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            job_payload = {}
            check("analysis_payload_parse", False, str(exc))
        terminal_event_id = str((job_payload.get("canonical_event_manifest") or {}).get("through_event_id") or "")
        snapshot = storage.load_session_event_snapshot(args.session_id, terminal_event_id, 100000) or {}
        basis_keys = ["schema_version", "session_id", "through_event_id", "through_received_at", "event_entries"]
        missing_snapshot_fields = [key for key in basis_keys if key not in snapshot]
        basis = {key: snapshot.get(key) for key in basis_keys}
        check("durable_snapshot_shape", not missing_snapshot_fields, missing_snapshot_fields)
        check("durable_snapshot_count", snapshot.get("event_count") == 12)
        check("received_at_propagation", bool(snapshot.get("through_received_at")) and all(bool(row.get("received_at")) for row in snapshot.get("event_entries", [])))
        check("durable_manifest_hash", hashlib.sha256(stable_json(basis).encode()).hexdigest() == snapshot.get("manifest_sha256"))
        summary = {key: snapshot.get(key) for key in ["schema_version", "session_id", "through_event_id", "event_count", "manifest_sha256"]}
        check("analysis_manifest_matches_snapshot", job_payload.get("canonical_event_manifest") == summary)
        report_payload = row_payload(reports[0]) if reports else {}
        report_manifest = ((report_payload.get("canonical_evidence") or {}).get("durable_event_manifest") or {})
        check("report_manifest_matches_snapshot", report_manifest == summary)
        cutoff = job_payload.get("evidence_cutoff")
        check("terminal_evidence_cutoff", not validate_evidence_cutoff(cutoff) and cutoff == {"schema_version": "prediction_evidence_cutoff.v1", "received_at": snapshot.get("through_received_at"), "event_id": terminal_event_id})
        history_manifest = job_payload.get("prediction_trusted_history_manifest") or {}
        history = job_payload.get("prediction_trusted_history") or []
        history_errors = validate_prediction_trusted_history_manifest(history_manifest, expected_phases=history)
        check("v3_trusted_history_manifest", not history_errors and history_manifest.get("schema_version") == "prediction_trusted_history_manifest.v3", history_errors)
        phases = history_manifest.get("ordered_trusted_phases") or []
        phase = phases[0] if len(phases) == 1 else {}
        command_events = {}
        for event in storage.mongo.database.events.find({"session_id": args.session_id, "eventid": "cowrie.command.input"}):
            payload = json.loads(event.get("payload_json") or "{}")
            command_events[payload.get("input")] = {"event_id": event.get("event_id") or event.get("_id"), "timestamp": payload.get("timestamp")}
        expected_refs = {command_events.get("id", {}).get("event_id"), command_events.get("whoami", {}).get("event_id")}
        labels = phase.get("labels") or []
        check("semantic_uniqueness", len(phases) == 1 and len(labels) == 1 and labels[0].get("tactic") == "discovery" and labels[0].get("technique") == "T1033", {"phase_count": len(phases), "label_count": len(labels)})
        check("evidence_provenance_preserved", phase.get("observation_count") == 2 and set(phase.get("evidence_refs") or []) == expected_refs and None not in expected_refs)
        trusted = [item for item in job_payload.get("classification_events") or [] if item.get("tactic") == "discovery" and item.get("ttp") == "T1033"]
        trusted_refs = {((item.get("durable_evidence_order") or {}).get("event_id")) for item in trusted}
        check("duplicate_source_evidence_preserved", len(trusted) == 2 and trusted_refs == expected_refs)
        policy = json.loads(
            Path(runtime_root, "configs/prediction_policy.transformer_poc.trusted.json").read_text()
        )["policy"]
        environment_path = str(Path(runtime_root, policy["runtime_classifier_environment_path"]))
        environment_hash = sha256(environment_path)
        check("classifier_environment_binding", environment_hash == policy.get("runtime_classifier_environment_sha256") == ENV_SHA256, {"computed": environment_hash, "bound": policy.get("runtime_classifier_environment_sha256")})
        try:
            safe_session = build_live_next_behavior_session(job_payload, rule_policy_sha256=policy["runtime_rule_policy_sha256"], trust_policy_sha256=policy["runtime_trust_policy_sha256"], classifier_checkpoint_sha256=policy["runtime_classifier_checkpoint_sha256"], trusted_model_only_threshold=float(policy.get("trusted_model_only_threshold", 0.90)))
            next_behavior_errors = validate_next_behavior_session(safe_session) if safe_session is not None else ["builder returned no session"]
        except (KeyError, TypeError, ValueError) as exc:
            safe_session = None
            next_behavior_errors = [str(exc)]
        check("v3_next_behavior_contract", safe_session is not None and not next_behavior_errors, next_behavior_errors)
        prediction_errors = validate_prediction_snapshot_integrity(prediction_payload)
        check("prediction_completion", not prediction_errors and prediction_payload.get("session_id") == args.session_id and prediction_payload.get("session_status") == "closed" and prediction_payload.get("event_id") == terminal_event_id and prediction_payload.get("evidence_cutoff") == cutoff and prediction_payload.get("prediction_status") == "predicted", prediction_errors)
        check("prediction_environment_binding", (prediction_payload.get("active_model") or {}).get("runtime_classifier_environment_sha256") == ENV_SHA256)
        details["controlled_session"] = {"cowrie_session_id": args.cowrie_session_id, "canonical_session_id": args.session_id, "endpoint": "100.118.43.30:22", "event_count": snapshot.get("event_count"), "terminal_event_id": terminal_event_id, "terminal_received_at": snapshot.get("through_received_at"), "analysis_job_id": jobs[0].get("job_id") if jobs else None, "report_id": reports[0].get("report_id") if reports else None, "prediction_snapshot_id": prediction_payload.get("snapshot_id")}

        before, measurement_start, pre_metrics_error = load_pre_metrics(args.pre_metrics)
        check(
            "pre_metrics_input_valid",
            before is not None and measurement_start is not None,
            pre_metrics_error,
        )
        if before is None:
            before = {}
        after = storage.operational_metrics()["collection_counts"]
        deltas = {key: after.get(key, 0) - before.get(key, 0) for key in sorted(set(before) | set(after))}
        threat_hunt_jobs = list(
            storage.mongo.database.threat_hunt_jobs.find(
                {"session_id": args.session_id}
            ).sort([("job_id", 1)])
        )
        threat_hunt_policy = ProductionConfig.from_env().threat_hunt_policy or {}
        max_related = int(threat_hunt_policy.get("max_related_sessions_per_job") or 100)
        expected_links = derive_expected_session_links(
            storage,
            args.session_id,
            threat_hunt_jobs,
            max_related,
        )
        actual_link_documents = list(
            storage.mongo.database.session_links.find(
                {
                    "$or": [
                        {"session_id_a": args.session_id},
                        {"session_id_b": args.session_id},
                    ]
                }
            )
        )
        window_link_documents = (
            list(
                storage.mongo.database.session_links.find(
                    {"created_at": {"$gte": measurement_start}}
                )
            )
            if measurement_start
            else []
        )
        link_contract = assess_session_link_contract(
            expected_links,
            actual_link_documents,
            window_link_documents,
            threat_hunt_jobs,
        )
        check("session_links_current_contract", link_contract["contract_valid"], link_contract)
        expected = {
            "sessions": 1,
            "events": 12,
            "analysis_jobs": 1,
            "reports": 1,
            "canonical_assessments": 1,
            "campaign_sessions": 1,
            "observable_sightings": 18,
            "prediction_snapshots": 6,
            "prediction_outbox": 6,
            "session_links": link_contract["expected_count"],
            "threat_hunt_jobs": 2,
        }
        nonzero_deltas = {key: value for key, value in deltas.items() if value}
        delta_mismatches = {
            key: {"expected": expected.get(key, 0), "actual": nonzero_deltas.get(key, 0)}
            for key in sorted(set(expected) | set(nonzero_deltas))
            if expected.get(key, 0) != nonzero_deltas.get(key, 0)
        }
        check(
            "bounded_canonical_deltas",
            not delta_mismatches,
            {
                "deltas": deltas,
                "expected_deltas": expected,
                "mismatches": delta_mismatches,
            },
        )
        bound = {}
        for collection in expected:
            query = {"$or": [{"_id": args.session_id}, {"session_id": args.session_id}, {"session_id_a": args.session_id}, {"session_id_b": args.session_id}, {"source_session_id": args.session_id}, {"related_session_id": args.session_id}, {"payload_json": {"$regex": args.session_id}}]}
            bound[collection] = storage.mongo.database[collection].count_documents(query)
        core_bound_matches = all(
            bound.get(key) == value
            for key, value in expected.items()
            if key != "session_links"
        )
        check(
            "historical_replay_zero",
            core_bound_matches and link_contract["historical_replay_zero"],
            {
                "measurement_start": measurement_start,
                "bound_new_document_counts": bound,
                "core_bound_matches": core_bound_matches,
                "session_links": link_contract,
            },
        )
        check("alerts_lifecycle_invariants", deltas.get("alerts") == 0 and deltas.get("lifecycle_ledger") == 0)
        check(
            "canonical_write_noninterference",
            not delta_mismatches
            and link_contract["contract_valid"]
            and link_contract["historical_replay_zero"]
            and checks.get("alerts_lifecycle_invariants") is True,
            {
                "unattributed_collection_deltas": delta_mismatches,
                "unexpected_session_link_ids": link_contract["unexpected_ids"],
                "out_of_contract_window_link_ids": link_contract[
                    "out_of_contract_window_ids"
                ],
            },
        )
        details["canonical_counts_before"] = {key: before.get(key) for key in ["sessions", "events", "analysis_jobs", "reports", "prediction_snapshots", "prediction_outbox", "alerts", "lifecycle_ledger"]}
        details["canonical_counts_after"] = {key: after.get(key) for key in ["sessions", "events", "analysis_jobs", "reports", "prediction_snapshots", "prediction_outbox", "alerts", "lifecycle_ledger"]}

    with_honeypot_storage(
        args.session_id,
        database_checks,
        runtime_root=runtime_root,
        epoch_path=epoch_path,
    )
    health_urls = {
        "dashboard": "http://127.0.0.1:8081/health",
        "ingest": "http://100.85.50.74:8080/health",
        "monitor": "http://127.0.0.1:8090/health",
    }
    health_payloads = {
        name: json.loads(urllib.request.urlopen(url, timeout=10).read())
        for name, url in health_urls.items()
    }
    check(
        "service_health",
        all(value == "active" for value in service_states.values())
        and all(payload.get("ok") is True for payload in health_payloads.values()),
        health_payloads,
    )
    check(
        "selector_release_identity",
        (
            runtime_active == f"/opt/honeypot-releases/{CANDIDATE}"
            and read_text(f"{runtime_root}/DEPLOYED_COMMIT") == CANDIDATE
        )
        if preflight
        else (
            active == f"/opt/honeypot-releases/{CANDIDATE}"
            and read_text("/opt/honeypot/DEPLOYED_COMMIT") == CANDIDATE
        ),
        {"active_selector": active, "runtime_root": runtime_active, "no_cutover": preflight},
    )
    check("rollback_readiness", os.path.isdir(f"/opt/honeypot-releases/{RECOVERY}") and sha256(backup_path) == OLD_EPOCH_SHA256 and epoch.get("rollback_mirror", {}).get("path") == MIRROR_PATH)
    checks.setdefault("durable_event_processing", checks.get("session_exists_closed") and checks.get("analysis_job_succeeded") and checks.get("report_succeeded"))
    checks.setdefault("received_at_propagation", checks.get("received_at_propagation"))
    checks.setdefault("terminal_evidence_cutoff", checks.get("terminal_evidence_cutoff"))
    checks.setdefault("v3_trusted_history_manifest", checks.get("v3_trusted_history_manifest"))
    checks.setdefault("semantic_uniqueness", checks.get("semantic_uniqueness"))
    checks.setdefault("evidence_provenance_preserved", checks.get("evidence_provenance_preserved") and checks.get("duplicate_source_evidence_preserved"))
    checks.setdefault("v3_next_behavior_contract", checks.get("v3_next_behavior_contract"))
    checks.setdefault("prediction_completion", checks.get("prediction_completion"))
    checks.setdefault("classifier_environment_binding", checks.get("classifier_environment_binding") and checks.get("prediction_environment_binding"))
    checks.setdefault("shadow_non_authority", checks.get("shadow_non_authoritative"))
    checks.setdefault("shadow_canonical_write_disabled", checks.get("shadow_canonical_write_disabled"))
    checks.setdefault("historical_replay_zero", checks.get("historical_replay_zero"))
    checks.setdefault("bounded_canonical_deltas", checks.get("bounded_canonical_deltas"))
    checks.setdefault("alerts_lifecycle_invariants", checks.get("alerts_lifecycle_invariants"))
    checks.setdefault("service_health", checks.get("service_health"))
    checks.setdefault("selector_release_identity", checks.get("selector_release_identity"))
    checks.setdefault("rollback_readiness", checks.get("rollback_readiness"))
    result = {
        "schema_version": (
            "gcp_final_live_validation_preflight.v1"
            if preflight
            else "gcp_final_live_validation.v1"
        ),
        "status": (
            "PASS_PREFLIGHT"
            if preflight and not failures and all(checks.get(name) is True for name in REQUIRED_INVARIANTS)
            else (
                "FAIL_PREFLIGHT"
                if preflight
                else ("PASS" if not failures and all(checks.get(name) is True for name in REQUIRED_INVARIANTS) else "FAIL")
            )
        ),
        "candidate_release_id": CANDIDATE,
        "recovery_release_id": RECOVERY,
        "authoritative_cowrie_endpoint": "100.118.43.30:22",
        "checks": checks,
        "details": details,
        "errors": failures,
        "no_cutover": preflight,
    }
    if preflight:
        write_atomic_json(
            args.output,
            result,
            uid=os.getuid(),
            gid=grp.getgrnam("honeypot").gr_gid,
            mode=0o640,
        )
        if result["status"] == "PASS_PREFLIGHT":
            return result
        raise RuntimeError("final invariant preflight failed: " + ",".join(failures))
    if result["status"] != "PASS":
        write_atomic_json(
            args.output,
            result,
            uid=os.getuid(),
            gid=grp.getgrnam("honeypot").gr_gid,
            mode=0o640,
        )
        raise RuntimeError("final invariant validation failed: " + ",".join(failures))
    validate_complete_receipt(result)
    write_atomic_json(args.output, result, uid=os.getuid(), gid=grp.getgrnam("honeypot").gr_gid, mode=0o640)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--guard", required=True)
    parser.add_argument("--backup", required=True)
    parser.add_argument("--pre-metrics", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--cowrie-session-id", required=True)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--runtime-root", default="/opt/honeypot")
    parser.add_argument(
        "--epoch-path", default="/etc/honeypot/canonical_storage_epoch.v2.json"
    )
    args = parser.parse_args()
    result = run(args)
    print(json.dumps({"status": result["status"], "output": args.output, "checks": len(result["checks"]), "failed": [key for key, value in result["checks"].items() if value is not True]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
