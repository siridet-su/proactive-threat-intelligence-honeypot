"""Build and evaluate a privacy-minimized seven-day Zenodo tactic corpus.

Raw events, commands, timestamps, and model checkpoints remain in private paths.
Only anonymized tactic/technique sequences and aggregate metrics are written to
the public evaluation directory. This tool never mutates runtime policy or
runtime transition models.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Mapping, Sequence

from production.classification.classification_pipeline import (
    NotebookParityClassifier,
    is_shell_noise,
    split_compound_command,
)
from production.classification.securebert_classifier import SecureBertCommandClassifier
from production.classification.trust import is_trusted_classification_event
from production.enrichment.mitre_attack_loader import load_mitre_attack_db
from production.prediction.realtime_prediction import build_transition_model
from production.tools.build_external_seed_model import _accepted_classifications
from production.tools.evaluate_next_tactic_model_comparison import (
    DEFAULT_SEED,
    _engine_predictor,
    _fallback_predictor,
    _first_order_predictor,
    _majority_predictor,
    build_cases,
    load_policy,
    load_session_payloads,
    split_session_payloads,
    summarize_predictions,
)
from production.tools.evaluate_zenodo_tuned_next_tactic import (
    _attach_configurations,
    _count_predictor,
    build_count_model,
    tune_model,
)


SELECTED_MEMBERS = (
    "2025-07-03.json.gz",
    "2025-07-10.json.gz",
    "2025-07-17.json.gz",
    "2025-07-24.json.gz",
    "2025-07-31.json.gz",
    "2025-08-07.json.gz",
    "2025-08-14.json.gz",
)
PREVIOUSLY_USED_MEMBERS = (
    "2025-06-27.json.gz",
    "2025-06-29.json.gz",
    "2025-08-17.json.gz",
)
EXPECTED_MEMBER_BYTES = {
    "2025-07-03.json.gz": 261678477,
    "2025-07-10.json.gz": 500081541,
    "2025-07-17.json.gz": 332075166,
    "2025-07-24.json.gz": 468400203,
    "2025-07-31.json.gz": 463626236,
    "2025-08-07.json.gz": 414524496,
    "2025-08-14.json.gz": 395803739,
}
EXPECTED_ZIP_COMPRESSED_BYTES = {
    "2025-07-03.json.gz": 255813041,
    "2025-07-10.json.gz": 492883075,
    "2025-07-17.json.gz": 327119238,
    "2025-07-24.json.gz": 461218117,
    "2025-07-31.json.gz": 456695641,
    "2025-08-07.json.gz": 407980179,
    "2025-08-14.json.gz": 389440642,
}
DATASET_SOURCE = "zenodo:21260400:COW160x4:seven_systematic_weekly_members"
MIN_REPORTABLE_SUPPORT = 30
DEFAULT_PAYLOAD = "evaluation/next_tactic_zenodo_7day_session_payload.jsonl"
DEFAULT_OUTPUT_JSON = "evaluation/next_tactic_zenodo_7day_model_comparison.json"
DEFAULT_OUTPUT_CSV = "evaluation/next_tactic_zenodo_7day_model_comparison.csv"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_id(raw_session_id: str) -> str:
    digest = hashlib.sha256(
        f"{DATASET_SOURCE}\0{raw_session_id}".encode("utf-8")
    ).hexdigest()
    return f"external-{digest[:24]}"


def _connection(path: str) -> sqlite3.Connection:
    database = sqlite3.connect(path)
    database.execute("PRAGMA journal_mode=WAL")
    database.execute("PRAGMA synchronous=NORMAL")
    database.execute("PRAGMA temp_store=MEMORY")
    database.execute("PRAGMA cache_size=-131072")
    database.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            raw_session_id TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            protocol TEXT NOT NULL DEFAULT '',
            configuration TEXT NOT NULL DEFAULT '',
            closed INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS command_events (
            event_order INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_session_id TEXT NOT NULL,
            event_time TEXT NOT NULL,
            command TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_command_events_session_time
            ON command_events(raw_session_id, event_time, event_order);
        CREATE TABLE IF NOT EXISTS command_labels (
            command TEXT PRIMARY KEY,
            labels_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS processed_members (
            member TEXT PRIMARY KEY,
            stats_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS labeled_sessions (
            safe_session_id TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            configuration TEXT NOT NULL,
            classification_events_json TEXT NOT NULL,
            trusted_tactics_json TEXT NOT NULL,
            trusted_techniques_json TEXT NOT NULL,
            deduplicated_tactics_json TEXT NOT NULL
        );
        """
    )
    return database


SESSION_UPSERT = """
INSERT INTO sessions (
    raw_session_id, first_seen, last_seen, protocol, configuration, closed
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(raw_session_id) DO UPDATE SET
    first_seen = CASE
        WHEN sessions.first_seen = '' OR excluded.first_seen < sessions.first_seen
        THEN excluded.first_seen ELSE sessions.first_seen END,
    last_seen = CASE
        WHEN excluded.last_seen > sessions.last_seen
        THEN excluded.last_seen ELSE sessions.last_seen END,
    protocol = CASE
        WHEN excluded.protocol != '' THEN excluded.protocol ELSE sessions.protocol END,
    configuration = CASE
        WHEN excluded.configuration != '' THEN excluded.configuration
        ELSE sessions.configuration END,
    closed = MAX(sessions.closed, excluded.closed)
"""


def _flush_ingest(
    database: sqlite3.Connection,
    sessions: list[tuple[Any, ...]],
    commands: list[tuple[Any, ...]],
) -> None:
    if sessions:
        database.executemany(SESSION_UPSERT, sessions)
        sessions.clear()
    if commands:
        database.executemany(
            "INSERT INTO command_events(raw_session_id, event_time, command) VALUES (?, ?, ?)",
            commands,
        )
        commands.clear()
    database.commit()


def ingest_members(
    raw_dir: str,
    database_path: str,
    members: Sequence[str] = SELECTED_MEMBERS,
) -> Dict[str, Any]:
    database = _connection(database_path)
    existing = {
        str(row[0]) for row in database.execute("SELECT member FROM processed_members")
    }
    member_summaries: Dict[str, Any] = {}
    unknown = sorted(set(members) - set(SELECTED_MEMBERS))
    if unknown:
        raise ValueError(f"members are outside the frozen seven-day sample: {unknown}")
    for member in members:
        path = Path(raw_dir) / member
        if not path.exists() or path.stat().st_size != EXPECTED_MEMBER_BYTES[member]:
            raise ValueError(f"missing or size-mismatched selected member: {path}")
        if member in existing:
            stored = database.execute(
                "SELECT stats_json FROM processed_members WHERE member = ?", (member,)
            ).fetchone()
            member_summaries[member] = json.loads(str(stored[0]))
            print(f"ingest already complete: {member}", flush=True)
            continue

        stats: Counter[str] = Counter()
        eventids: Counter[str] = Counter()
        configurations: Counter[str] = Counter()
        protocols: Counter[str] = Counter()
        session_rows: list[tuple[Any, ...]] = []
        command_rows: list[tuple[Any, ...]] = []
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stats["raw_event_records"] += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    stats["malformed_records"] += 1
                    continue
                if not isinstance(event, dict):
                    stats["non_object_records"] += 1
                    continue
                eventid = str(event.get("eventid") or "")
                eventids[eventid or "missing"] += 1
                configuration = str(event.get("group") or "").strip()
                if configuration:
                    configurations[configuration] += 1
                protocol = str(event.get("protocol") or "").strip().lower()
                if protocol:
                    protocols[protocol] += 1
                if eventid not in {
                    "cowrie.session.connect",
                    "cowrie.command.input",
                    "cowrie.session.closed",
                }:
                    continue
                raw_session_id = str(event.get("session") or "").strip()
                timestamp = str(event.get("ts") or "").strip()
                if not raw_session_id or not timestamp:
                    stats["relevant_events_missing_session_or_time"] += 1
                    continue
                session_rows.append(
                    (
                        raw_session_id,
                        timestamp,
                        timestamp,
                        protocol,
                        configuration,
                        int(eventid == "cowrie.session.closed"),
                    )
                )
                if eventid == "cowrie.command.input":
                    stats["raw_command_input_events"] += 1
                    command = str(event.get("input") or "").strip()
                    if command:
                        stats["nonempty_command_events"] += 1
                        command_rows.append((raw_session_id, timestamp, command))
                    else:
                        stats["empty_command_events"] += 1
                if len(session_rows) >= 20000:
                    _flush_ingest(database, session_rows, command_rows)
        _flush_ingest(database, session_rows, command_rows)
        summary = {
            **dict(stats),
            "eventid_counts": dict(sorted(eventids.items())),
            "configuration_event_counts": dict(sorted(configurations.items())),
            "explicit_protocol_event_counts": dict(sorted(protocols.items())),
            "nested_gzip_bytes": EXPECTED_MEMBER_BYTES[member],
            "zip_compressed_bytes": EXPECTED_ZIP_COMPRESSED_BYTES[member],
        }
        database.execute(
            "INSERT INTO processed_members(member, stats_json) VALUES (?, ?)",
            (member, json.dumps(summary, sort_keys=True)),
        )
        database.commit()
        member_summaries[member] = summary
        print(
            f"ingested {member}: {stats['raw_event_records']} events, "
            f"{stats['nonempty_command_events']} commands",
            flush=True,
        )
    database.close()
    return member_summaries


def _batched(values: Sequence[str], size: int) -> Iterator[list[str]]:
    for index in range(0, len(values), size):
        yield list(values[index : index + size])


def classify_commands(
    database_path: str,
    *,
    model_path: str,
    checkpoint_path: str,
    batch_size: int,
) -> Dict[str, Any]:
    database = _connection(database_path)
    commands = [
        str(row[0])
        for row in database.execute(
            "SELECT DISTINCT command FROM command_events ORDER BY command"
        )
    ]
    non_noise_commands = [command for command in commands if not is_shell_noise(command)]
    fragments = sorted(
        {
            fragment.text
            for command in non_noise_commands
            for fragment in split_compound_command(command)
            if fragment.text
        }
    )
    model = SecureBertCommandClassifier(
        model_path=model_path,
        checkpoint_path=checkpoint_path,
        device="cpu",
        max_length=128,
    )
    predictions: Dict[str, tuple[str | None, float]] = {}
    classifiable = sorted(
        (fragment for fragment in fragments if len(fragment.strip()) >= 3),
        key=lambda fragment: (len(fragment), fragment),
    )
    for batch_number, batch in enumerate(_batched(classifiable, batch_size), start=1):
        for fragment, prediction in zip(batch, model.classify_batch(batch)):
            predictions[fragment] = prediction
        if batch_number % 10 == 0:
            print(
                f"SecureBERT classified {min(batch_number * batch_size, len(classifiable))}/"
                f"{len(classifiable)} unique fragments",
                flush=True,
            )
    for fragment in fragments:
        predictions.setdefault(fragment, (None, 0.0))

    mitre_db = load_mitre_attack_db(
        cache_path="data/feeds/mitre_attack_cache.json", silent=True
    )
    classifier = NotebookParityClassifier(
        bert_fn=lambda command: predictions.get(command, (None, 0.0)),
        mitre_db=mitre_db,
        high_confidence=0.55,
        rule_policy_path="configs/classification_rules.trusted.json",
    )
    filter_stats: Dict[str, Any] = {
        "noise_commands_skipped": 0,
        "unknown_commands_skipped": 0,
        "low_confidence_commands_skipped": 0,
        "disagreement_commands_skipped": 0,
        "filtered_known_commands_skipped": 0,
    }
    source_counts: Counter[str] = Counter()
    accepted_source_counts: Counter[str] = Counter()
    labels_rows = []
    accepted_unique_commands = 0
    accepted_events = 0
    for index, command in enumerate(commands, start=1):
        if is_shell_noise(command):
            filter_stats["noise_commands_skipped"] += 1
            accepted = []
        else:
            outputs = classifier.classify(command)
            accepted = _accepted_classifications(
                command,
                outputs,
                filter_stats,
                source_counts,
                [],
                min_label_confidence=0.90,
                drop_disagreements=True,
                review_limit=0,
            )
            accepted = [event for event in accepted if is_trusted_classification_event(event)]
        safe_labels = []
        for event in accepted:
            label = {
                "ttp": str(event.get("ttp") or ""),
                "tactic": str(event.get("tactic") or ""),
                "source": str(event.get("source") or ""),
                "confidence": float(event.get("confidence") or 0.0),
            }
            if label["ttp"] and label["tactic"] and label["tactic"] != "unknown":
                safe_labels.append(label)
                accepted_source_counts[label["source"]] += 1
        if safe_labels:
            accepted_unique_commands += 1
            accepted_events += len(safe_labels)
        labels_rows.append((command, json.dumps(safe_labels, sort_keys=True)))
        if len(labels_rows) >= 5000:
            database.executemany(
                "INSERT OR REPLACE INTO command_labels(command, labels_json) VALUES (?, ?)",
                labels_rows,
            )
            database.commit()
            labels_rows.clear()
        if index % 10000 == 0:
            print(f"hybrid policy merged {index}/{len(commands)} unique commands", flush=True)
    if labels_rows:
        database.executemany(
            "INSERT OR REPLACE INTO command_labels(command, labels_json) VALUES (?, ?)",
            labels_rows,
        )
        database.commit()

    confidence_buckets = Counter()
    for _label, confidence in predictions.values():
        if confidence >= 0.90:
            confidence_buckets["accepted_at_0_90"] += 1
        elif confidence >= 0.55:
            confidence_buckets["candidate_0_55_to_0_90"] += 1
        else:
            confidence_buckets["below_0_55_or_unlabeled"] += 1
    summary = {
        "unique_raw_commands": len(commands),
        "unique_compound_fragments": len(fragments),
        "securebert_classified_fragments": len(classifiable),
        "securebert_confidence_buckets": dict(sorted(confidence_buckets.items())),
        "accepted_unique_commands": accepted_unique_commands,
        "accepted_classification_events": accepted_events,
        "raw_classifier_source_counts": dict(sorted(source_counts.items())),
        "accepted_source_counts": dict(sorted(accepted_source_counts.items())),
        "filter_counts_on_unique_commands": filter_stats,
        "securebert_threshold": 0.55,
        "final_acceptance_threshold": 0.90,
        "drop_rule_securebert_disagreements": True,
        "hybrid_policy": "reviewed deterministic rules take precedence; SecureBERT supplies candidates for unmatched fragments",
        "compound_commands_split": True,
        "securebert_device": "cpu",
        "securebert_checkpoint_published": False,
        "securebert_checkpoint_sha256": _sha256_file(Path(checkpoint_path) / "model.safetensors"),
        "classification_rule_policy_sha256": _sha256_file(
            Path("configs/classification_rules.trusted.json")
        ),
        "mitre_attack_cache_sha256": _sha256_file(
            Path("data/feeds/mitre_attack_cache.json")
        ),
    }
    database.execute(
        "INSERT OR REPLACE INTO processed_members(member, stats_json) VALUES (?, ?)",
        ("__classification__", json.dumps(summary, sort_keys=True)),
    )
    database.commit()
    database.close()
    return summary


def _finalize_labeled_session(
    database: sqlite3.Connection,
    raw_session_id: str,
    first_seen: str,
    configuration: str,
    labels: list[Dict[str, Any]],
) -> tuple[int, int]:
    if not labels:
        return 0, 0
    safe_events = [
        {
            "ttp": str(label["ttp"]),
            "tactic": str(label["tactic"]),
            "source": "derived_trusted_external_weak_label",
            "evidence_tier": "trusted_observation",
            "label_quality": "classifier_derived_weak_label",
        }
        for label in labels
    ]
    tactics = [str(label["tactic"]) for label in labels]
    techniques = [str(label["ttp"]) for label in labels]
    deduplicated: list[str] = []
    for tactic in tactics:
        if not deduplicated or deduplicated[-1] != tactic:
            deduplicated.append(tactic)
    database.execute(
        """
        INSERT OR REPLACE INTO labeled_sessions(
            safe_session_id, first_seen, configuration,
            classification_events_json, trusted_tactics_json,
            trusted_techniques_json, deduplicated_tactics_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _safe_id(raw_session_id),
            first_seen,
            configuration or "unknown",
            json.dumps(safe_events, sort_keys=True),
            json.dumps(tactics),
            json.dumps(techniques),
            json.dumps(deduplicated),
        ),
    )
    return 1, max(len(deduplicated) - 1, 0)


def build_safe_payload(
    database_path: str,
    payload_path: str,
    private_summary_path: str,
) -> Dict[str, Any]:
    database = _connection(database_path)
    database.execute("DELETE FROM labeled_sessions")
    query = """
        SELECT s.raw_session_id, s.first_seen, s.configuration,
               c.event_time, c.event_order, l.labels_json
        FROM sessions AS s
        JOIN command_events AS c ON c.raw_session_id = s.raw_session_id
        JOIN command_labels AS l ON l.command = c.command
        WHERE s.closed = 1 AND s.protocol = 'ssh' AND l.labels_json != '[]'
        ORDER BY s.first_seen, s.raw_session_id, c.event_time, c.event_order
    """
    current_id = ""
    first_seen = ""
    configuration = ""
    labels: list[Dict[str, Any]] = []
    labeled_sessions = 0
    transitions = 0
    for raw_session_id, seen, config, _event_time, _order, labels_json in database.execute(query):
        raw_session_id = str(raw_session_id)
        if current_id and raw_session_id != current_id:
            added, transition_count = _finalize_labeled_session(
                database, current_id, first_seen, configuration, labels
            )
            labeled_sessions += added
            transitions += transition_count
            labels = []
        if raw_session_id != current_id:
            current_id = raw_session_id
            first_seen = str(seen)
            configuration = str(config)
        labels.extend(json.loads(str(labels_json)))
        if labeled_sessions and labeled_sessions % 10000 == 0:
            database.commit()
    if current_id:
        added, transition_count = _finalize_labeled_session(
            database, current_id, first_seen, configuration, labels
        )
        labeled_sessions += added
        transitions += transition_count
    database.commit()

    total = int(database.execute("SELECT COUNT(*) FROM labeled_sessions").fetchone()[0])
    train_end = int(total * 0.70)
    calibration_end = train_end + int(total * 0.15)
    split_names = ("train", "calibration", "test")
    split_sessions = Counter()
    split_transition_sessions = Counter()
    split_transitions = Counter()
    tactic_distribution = Counter()
    target_distribution = Counter()
    configuration_sessions = Counter()
    destination = Path(payload_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        rows = database.execute(
            """
            SELECT safe_session_id, configuration, trusted_tactics_json,
                   deduplicated_tactics_json
            FROM labeled_sessions ORDER BY first_seen, safe_session_id
            """
        )
        for index, row in enumerate(rows):
            split = (
                "train"
                if index < train_end
                else "calibration"
                if index < calibration_end
                else "test"
            )
            safe_id, config, tactics_json, dedup_json = row
            tactics = json.loads(str(tactics_json))
            deduplicated = json.loads(str(dedup_json))
            transition_examples = [
                {
                    "prefix_context": deduplicated[: position + 1],
                    "target_next_tactic": deduplicated[position + 1],
                }
                for position in range(len(deduplicated) - 1)
            ]
            payload = {
                "schema_version": "next_tactic_zenodo_seven_day_payload.v2",
                "session_id": str(safe_id),
                "dataset_source": DATASET_SOURCE,
                "protocol": "ssh",
                "honeypot_configuration": str(config),
                "split": split,
                "status": "closed",
                "is_ended": True,
                "tactics": deduplicated,
                "adjacent_deduplicated_tactic_sequence": deduplicated,
            }
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
            split_sessions[split] += 1
            configuration_sessions[str(config)] += 1
            tactic_distribution.update(tactics)
            if transition_examples:
                split_transition_sessions[split] += 1
                split_transitions[split] += len(transition_examples)
                target_distribution.update(deduplicated[1:])

    member_stats = {}
    classification_summary = {}
    for member, stats_json in database.execute(
        "SELECT member, stats_json FROM processed_members ORDER BY member"
    ):
        if member == "__classification__":
            classification_summary = json.loads(str(stats_json))
        else:
            member_stats[str(member)] = json.loads(str(stats_json))
    totals = Counter()
    for item in member_stats.values():
        for key in (
            "raw_event_records",
            "malformed_records",
            "raw_command_input_events",
            "nonempty_command_events",
            "empty_command_events",
        ):
            totals[key] += int(item.get(key) or 0)
    session_counts = {
        "total_relevant_sessions": int(
            database.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        ),
        "closed_sessions": int(
            database.execute("SELECT COUNT(*) FROM sessions WHERE closed = 1").fetchone()[0]
        ),
        "explicit_ssh_sessions": int(
            database.execute("SELECT COUNT(*) FROM sessions WHERE protocol = 'ssh'").fetchone()[0]
        ),
        "sessions_with_commands": int(
            database.execute(
                "SELECT COUNT(DISTINCT raw_session_id) FROM command_events"
            ).fetchone()[0]
        ),
    }
    summary = {
        "schema_version": "next_tactic_zenodo_seven_day_summary.v1",
        "dataset_source": DATASET_SOURCE,
        "selection_method": "fixed seven-day weekly cadence selected before classification",
        "selected_members": [
            {
                "member": member,
                "nested_gzip_bytes": EXPECTED_MEMBER_BYTES[member],
                "zip_compressed_bytes": EXPECTED_ZIP_COMPRESSED_BYTES[member],
            }
            for member in SELECTED_MEMBERS
        ],
        "previously_used_members_excluded": list(PREVIOUSLY_USED_MEMBERS),
        "selected_member_count": 7,
        "total_nested_gzip_bytes": sum(EXPECTED_MEMBER_BYTES.values()),
        "total_zip_compressed_bytes": sum(EXPECTED_ZIP_COMPRESSED_BYTES.values()),
        **dict(totals),
        **session_counts,
        "sessions_with_trusted_tactic_labels": total,
        "transition_bearing_sessions": sum(split_transition_sessions.values()),
        "adjacent_deduplicated_tactic_transitions": sum(split_transitions.values()),
        "split_method": "chronological_70_15_15_by_whole_closed_labeled_session_first_seen",
        "split_sessions": dict(split_sessions),
        "split_transition_sessions": dict(split_transition_sessions),
        "split_transitions": dict(split_transitions),
        "configuration_session_counts": dict(sorted(configuration_sessions.items())),
        "tactic_distribution": dict(sorted(tactic_distribution.items())),
        "target_tactic_distribution": dict(sorted(target_distribution.items())),
        "classification_policy": classification_summary,
        "per_member_statistics": member_stats,
        "contains_raw_commands": False,
        "contains_original_session_ids": False,
        "contains_network_identifiers": False,
        "contains_credentials": False,
        "contains_urls_or_filenames": False,
        "label_quality": "classifier_derived_weak_labels",
    }
    Path(private_summary_path).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    database.close()
    return summary


def _csv_rows(result: Mapping[str, Any]) -> Iterable[Dict[str, Any]]:
    for row in result["model_comparison"]:
        metrics = row["metrics"]
        yield {
            "row_type": "pooled",
            "model_id": row["model_id"],
            "tactic": "all",
            "support": metrics["evaluated_examples"],
            "top1_accuracy": metrics["top1_accuracy"],
            "top3_accuracy": metrics["top3_accuracy_secondary"],
            "balanced_top1": metrics["balanced_accuracy"],
            "mrr": metrics["mean_reciprocal_rank"],
            "normalized_brier": metrics["normalized_multiclass_brier_score"],
            "coverage": metrics["coverage"],
            "abstention_rate": metrics["abstention_rate"],
        }
        for tactic, tactic_metrics in metrics["per_tactic"].items():
            descriptive = tactic_metrics.get("descriptive_only") or {}
            yield {
                "row_type": "per_tactic",
                "model_id": row["model_id"],
                "tactic": tactic,
                "support": tactic_metrics["support"],
                "top1_accuracy": tactic_metrics.get("top1_accuracy")
                if tactic_metrics.get("top1_accuracy") is not None
                else descriptive.get("top1_accuracy"),
                "mrr": tactic_metrics.get("mean_reciprocal_rank")
                if tactic_metrics.get("mean_reciprocal_rank") is not None
                else descriptive.get("mean_reciprocal_rank"),
                "normalized_brier": tactic_metrics.get(
                    "normalized_multiclass_brier_score"
                )
                if tactic_metrics.get("normalized_multiclass_brier_score") is not None
                else descriptive.get("normalized_multiclass_brier_score"),
            }


def evaluate_models(
    payload_path: str,
    private_database_path: str,
    private_summary_path: str,
    policy_path: str,
    output_json: str,
    output_csv: str,
) -> Dict[str, Any]:
    payloads = load_session_payloads(payload_path)
    private_database = sqlite3.connect(private_database_path)
    private_rows = private_database.execute(
        """
        SELECT safe_session_id, classification_events_json
        FROM labeled_sessions
        ORDER BY first_seen, safe_session_id
        """
    )
    for payload, row in zip(payloads, private_rows, strict=True):
        if str(payload.get("session_id") or "") != str(row[0]):
            raise ValueError("private trusted-label row is not aligned with public payload")
        payload["classification_events"] = json.loads(str(row[1]))
    private_database.close()
    split, split_method = split_session_payloads(payloads)
    train, calibration, test = (
        split["train"],
        split["calibration"],
        split["test"],
    )
    train_cases = build_cases(train)
    calibration_cases = build_cases(calibration)
    test_cases = build_cases(test)
    _attach_configurations(train_cases, train)
    _attach_configurations(calibration_cases, calibration)
    _attach_configurations(test_cases, test)
    policy = load_policy(policy_path)
    policy_fallback = _fallback_predictor(policy)
    train_vocabulary = sorted({case.actual for case in train_cases})
    fit_payloads = list(train) + list(calibration)
    fit_vocabulary = sorted({case.actual for case in train_cases + calibration_cases})

    print("tuning configuration hard-backoff VOMM on calibration", flush=True)
    hard_tuning = tune_model(
        "configuration_hard_backoff_vomm",
        train,
        calibration_cases,
        train_vocabulary,
        policy_fallback,
    )
    print("tuning configuration/global interpolated VOMM on calibration", flush=True)
    interpolated_tuning = tune_model(
        "configuration_aware_vomm",
        train,
        calibration_cases,
        train_vocabulary,
        policy_fallback,
    )

    fit_model = build_count_model(fit_payloads, max_order=4)
    transition_model = build_transition_model(
        fit_payloads,
        prefix_max_length=int(policy.get("prefix_max_length", 3)),
        source_name="external_seed_transition",
    )
    empty_model = build_transition_model([])
    fallback = policy_fallback
    predictors = {
        "majority_class": (
            "Majority Class Classifier",
            _majority_predictor(fit_payloads),
            {},
        ),
        "first_order_markov": (
            "First-order Markov Chain",
            _first_order_predictor(fit_payloads),
            {},
        ),
        "backoff_vomm": (
            "Current support-gated hard-backoff VOMM",
            _engine_predictor(policy, empty_model, transition_model),
            {
                "runtime_policy_unchanged": True,
                "transition_events_loaded_from_private_trusted_label_store": True,
            },
        ),
        "configuration_aware_vomm": (
            "Calibration-tuned configuration-specific hard-backoff VOMM",
            _count_predictor(
                "configuration_hard_backoff_vomm",
                fit_model,
                fit_vocabulary,
                hard_tuning["selected_settings"],
                fallback,
            ),
            {"calibration_selection": hard_tuning},
        ),
        "configuration_global_interpolated_vomm": (
            "Calibration-tuned configuration/global interpolated VOMM",
            _count_predictor(
                "configuration_aware_vomm",
                fit_model,
                fit_vocabulary,
                interpolated_tuning["selected_settings"],
                fallback,
            ),
            {"calibration_selection": interpolated_tuning},
        ),
    }
    rows = []
    for index, (model_id, (name, predictor, metadata)) in enumerate(predictors.items()):
        print(f"held-out test: {model_id}", flush=True)
        metrics = summarize_predictions(
            test_cases,
            predictor,
            bootstrap_iterations=500,
            seed=DEFAULT_SEED + index * 1009,
            min_per_tactic_support=MIN_REPORTABLE_SUPPORT,
            target_vocabulary=fit_vocabulary,
        )
        rows.append(
            {
                "model_id": model_id,
                "model": name,
                "metrics": metrics,
                "model_metadata": metadata,
            }
        )
    best = max(
        rows,
        key=lambda row: (
            float(row["metrics"].get("balanced_accuracy") or -1.0),
            float(row["metrics"].get("top1_accuracy") or -1.0),
        ),
    )
    best_pooled = max(
        rows, key=lambda row: float(row["metrics"].get("top1_accuracy") or -1.0)
    )
    dataset_summary = json.loads(Path(private_summary_path).read_text(encoding="utf-8"))
    result = {
        "schema_version": "next_tactic_zenodo_seven_day_comparison.v1",
        "runtime_behavior_changed": False,
        "previous_evaluation_files_overwritten": False,
        "dataset_summary": dataset_summary,
        "split_method": split_method,
        "selection_policy": {
            "hyperparameters_use_test_labels": False,
            "tuning_partition": "calibration_only",
            "primary_tuning_objective": "balanced_top1",
            "models_refit_on_train_plus_calibration": True,
            "heldout_test_evaluations_per_final_model": 1,
            "model_comparison_primary_metric": "balanced_top1",
        },
        "split_transition_cases": {
            "train": len(train_cases),
            "calibration": len(calibration_cases),
            "test": len(test_cases),
        },
        "model_comparison": rows,
        "best_model_by_predeclared_balanced_top1": best["model_id"],
        "best_model_by_pooled_top1_descriptive": best_pooled["model_id"],
        "best_pooled_top1": best_pooled["metrics"]["top1_accuracy"],
        "reached_70_percent_pooled_top1": bool(
            float(best_pooled["metrics"]["top1_accuracy"] or 0.0) >= 0.70
        ),
        "claim_scope": "next observed tactic in classifier-derived Cowrie SSH weak-label sequences",
    }
    json_destination = Path(output_json)
    json_destination.parent.mkdir(parents=True, exist_ok=True)
    json_destination.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    fields = (
        "row_type",
        "model_id",
        "tactic",
        "support",
        "top1_accuracy",
        "top3_accuracy",
        "balanced_top1",
        "mrr",
        "normalized_brier",
        "coverage",
        "abstention_rate",
    )
    with Path(output_csv).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(_csv_rows(result))
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("ingest", "classify", "payload", "evaluate"))
    parser.add_argument("--raw-dir", default="/tmp/zenodo7_raw")
    parser.add_argument("--member", action="append", choices=SELECTED_MEMBERS)
    parser.add_argument("--private-db", default="/tmp/zenodo7_private/sessions.sqlite")
    parser.add_argument(
        "--private-summary", default="/tmp/zenodo7_private/dataset_summary.json"
    )
    parser.add_argument("--model-path", default="")
    parser.add_argument("--checkpoint-path", default="")
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD)
    parser.add_argument("--policy", default="configs/prediction_policy.trusted.json")
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-csv", default=DEFAULT_OUTPUT_CSV)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    Path(args.private_db).parent.mkdir(parents=True, exist_ok=True)
    if args.stage == "ingest":
        result = ingest_members(
            args.raw_dir,
            args.private_db,
            members=tuple(args.member) if args.member else SELECTED_MEMBERS,
        )
    elif args.stage == "classify":
        if not args.model_path or not args.checkpoint_path:
            raise ValueError("classify requires --model-path and --checkpoint-path")
        result = classify_commands(
            args.private_db,
            model_path=args.model_path,
            checkpoint_path=args.checkpoint_path,
            batch_size=args.batch_size,
        )
    elif args.stage == "payload":
        result = build_safe_payload(
            args.private_db, args.payload, args.private_summary
        )
    else:
        result = evaluate_models(
            args.payload,
            args.private_db,
            args.private_summary,
            args.policy,
            args.output_json,
            args.output_csv,
        )
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
