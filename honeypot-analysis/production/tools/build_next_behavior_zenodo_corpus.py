#!/usr/bin/env python3
"""Build the corrected-target corpus from verified private Zenodo members.

Raw commands and original session identifiers are written only to the private
SQLite path supplied by the operator. Version-controlled outputs contain only
strict manifests, aggregate receipts, and privacy-safe HMAC identifiers.

Stages are resumable and fail closed:

``ingest``
    Verify source receipts, parse selected event logs, retain causal
    session/command/context ordering, and reject cross-member sessions.

Later classification and safe-corpus stages are added separately so a
completed source mapping remains independently auditable.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import secrets
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, Mapping, Sequence

from production.classification.classification_pipeline import (
    NotebookParityClassifier,
    split_compound_command,
)
from production.classification.securebert_classifier import (
    SecureBertCommandClassifier,
)
from production.enrichment.mitre_attack_loader import load_mitre_attack_db
from production.prediction.next_behavior_corpus import (
    build_privacy_safe_session,
    build_source_member_receipt,
    build_streaming_corpus_receipt,
    pseudonymous_id,
)
from production.prediction.next_behavior_label_policy import (
    normalize_classifier_outputs,
)
from production.utils.serialization import stable_json

from production.tools.fetch_next_behavior_zenodo_members import (
    file_sha256,
    load_source_manifest,
)
from production.tools.verify_next_behavior_classifier_assets import (
    load_classifier_manifest,
    verify_classifier_assets,
)


PRIVATE_SCHEMA_VERSION = 1
PRIVATE_STORE_ID = "next_behavior_zenodo_private_store.v1"
CLASSIFICATION_STAGE_ID = "next_behavior_zenodo_classification.v1"
SAFE_BUILD_STAGE_ID = "next_behavior_zenodo_safe_build.v1"
HISTORICAL_DATASET_SOURCE = (
    "zenodo:21260400:COW160x4:seven_systematic_weekly_members"
)
_CONTEXT_EVENT_TYPES = frozenset(
    {
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
    }
)
_SESSION_EVENT_TYPES = frozenset(
    {
        "cowrie.session.connect",
        "cowrie.command.input",
        "cowrie.session.closed",
    }
) | _CONTEXT_EVENT_TYPES


class NextBehaviorCorpusBuildError(ValueError):
    """Raised when private corpus generation cannot be trusted."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_file(path: Path) -> str:
    return file_sha256(path)


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _normalize_source_timestamp(value: Any) -> str:
    """Normalize Zenodo's UTC-valued naive timestamps to explicit UTC."""

    text = _clean(value)
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def open_private_database(path: Path) -> sqlite3.Connection:
    """Open the private SQLite store and enforce its exact schema version."""

    path.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(path)
    database.execute("PRAGMA journal_mode=WAL")
    database.execute("PRAGMA synchronous=NORMAL")
    database.execute("PRAGMA temp_store=MEMORY")
    database.execute("PRAGMA cache_size=-131072")
    database.execute("PRAGMA foreign_keys=ON")
    database.executescript(
        """
        CREATE TABLE IF NOT EXISTS build_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS processed_members (
            source_member TEXT PRIMARY KEY,
            source_sha256 TEXT NOT NULL,
            source_size_bytes INTEGER NOT NULL,
            chronological_order INTEGER NOT NULL,
            collection_start TEXT NOT NULL,
            collection_end TEXT NOT NULL,
            stats_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            raw_session_id TEXT PRIMARY KEY,
            source_member TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            protocol TEXT NOT NULL DEFAULT '',
            configuration TEXT NOT NULL DEFAULT '',
            closed INTEGER NOT NULL DEFAULT 0,
            cross_member INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_source_member
            ON sessions(source_member);
        CREATE TABLE IF NOT EXISTS command_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_member TEXT NOT NULL,
            source_line INTEGER NOT NULL,
            raw_session_id TEXT NOT NULL,
            event_time TEXT NOT NULL,
            command TEXT NOT NULL,
            UNIQUE(source_member, source_line)
        );
        CREATE INDEX IF NOT EXISTS idx_command_events_session_time
            ON command_events(raw_session_id, event_time, source_line);
        CREATE TABLE IF NOT EXISTS context_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_member TEXT NOT NULL,
            source_line INTEGER NOT NULL,
            raw_session_id TEXT NOT NULL,
            event_time TEXT NOT NULL,
            event_type TEXT NOT NULL,
            UNIQUE(source_member, source_line)
        );
        CREATE INDEX IF NOT EXISTS idx_context_events_session_time
            ON context_events(raw_session_id, event_time, source_line);
        CREATE TABLE IF NOT EXISTS command_labels (
            command TEXT PRIMARY KEY,
            labels_json TEXT NOT NULL,
            unrepresented_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS build_stage_receipts (
            stage_id TEXT PRIMARY KEY,
            receipt_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS safe_sessions (
            sort_session_id TEXT PRIMARY KEY,
            safe_json TEXT,
            reconciliation_json TEXT NOT NULL,
            source_member TEXT NOT NULL,
            legacy_historical_session_id TEXT NOT NULL,
            historical_split TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_safe_sessions_source
            ON safe_sessions(source_member);
        CREATE INDEX IF NOT EXISTS idx_safe_sessions_historical_split
            ON safe_sessions(historical_split);
        """
    )
    existing = database.execute(
        "SELECT value FROM build_metadata WHERE key = 'private_store_id'"
    ).fetchone()
    if existing is not None and str(existing[0]) != PRIVATE_STORE_ID:
        database.close()
        raise NextBehaviorCorpusBuildError(
            "private database belongs to another schema"
        )
    database.execute(
        "INSERT OR IGNORE INTO build_metadata(key, value) VALUES (?, ?)",
        ("private_store_id", PRIVATE_STORE_ID),
    )
    database.execute(f"PRAGMA user_version={PRIVATE_SCHEMA_VERSION}")
    database.commit()
    return database


_SESSION_UPSERT = """
INSERT INTO sessions(
    raw_session_id, source_member, first_seen, last_seen,
    protocol, configuration, closed, cross_member
) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
ON CONFLICT(raw_session_id) DO UPDATE SET
    first_seen = CASE
        WHEN sessions.first_seen = '' OR excluded.first_seen < sessions.first_seen
        THEN excluded.first_seen ELSE sessions.first_seen END,
    last_seen = CASE
        WHEN excluded.last_seen > sessions.last_seen
        THEN excluded.last_seen ELSE sessions.last_seen END,
    protocol = CASE
        WHEN excluded.protocol != '' THEN excluded.protocol
        ELSE sessions.protocol END,
    configuration = CASE
        WHEN excluded.configuration != '' THEN excluded.configuration
        ELSE sessions.configuration END,
    closed = MAX(sessions.closed, excluded.closed),
    cross_member = MAX(
        sessions.cross_member,
        CASE WHEN sessions.source_member != excluded.source_member THEN 1 ELSE 0 END
    )
"""


def _flush_ingest(
    database: sqlite3.Connection,
    session_rows: list[tuple[Any, ...]],
    command_rows: list[tuple[Any, ...]],
    context_rows: list[tuple[Any, ...]],
) -> None:
    if session_rows:
        database.executemany(_SESSION_UPSERT, session_rows)
        session_rows.clear()
    if command_rows:
        database.executemany(
            """
            INSERT INTO command_events(
                source_member, source_line, raw_session_id, event_time, command
            ) VALUES (?, ?, ?, ?, ?)
            """,
            command_rows,
        )
        command_rows.clear()
    if context_rows:
        database.executemany(
            """
            INSERT INTO context_events(
                source_member, source_line, raw_session_id, event_time, event_type
            ) VALUES (?, ?, ?, ?, ?)
            """,
            context_rows,
        )
        context_rows.clear()
    database.commit()


def _verify_selected_member(
    source_member: Mapping[str, Any],
    raw_directory: Path,
) -> Path:
    path = raw_directory / source_member["filename"]
    if not path.is_file():
        raise NextBehaviorCorpusBuildError(
            f"missing source member: {source_member['filename']}"
        )
    if path.stat().st_size != source_member["size_bytes"]:
        raise NextBehaviorCorpusBuildError(
            f"source member size mismatch: {source_member['filename']}"
        )
    if _sha256_file(path) != source_member["sha256"]:
        raise NextBehaviorCorpusBuildError(
            f"source member SHA-256 mismatch: {source_member['filename']}"
        )
    return path


def _clear_partial_member(
    database: sqlite3.Connection,
    source_member: str,
) -> None:
    """Remove only an incomplete member before deterministic replay."""

    database.execute(
        "DELETE FROM command_events WHERE source_member = ?",
        (source_member,),
    )
    database.execute(
        "DELETE FROM context_events WHERE source_member = ?",
        (source_member,),
    )
    database.execute(
        """
        DELETE FROM sessions
        WHERE source_member = ?
          AND NOT EXISTS (
              SELECT 1 FROM processed_members
              WHERE processed_members.source_member = sessions.source_member
          )
        """,
        (source_member,),
    )
    database.commit()


def ingest_member(
    database: sqlite3.Connection,
    source_member: Mapping[str, Any],
    raw_directory: Path,
    *,
    flush_size: int = 20000,
) -> Dict[str, Any]:
    """Ingest one verified member without emitting private event content."""

    filename = _clean(source_member.get("filename"))
    path = _verify_selected_member(source_member, raw_directory)
    stored = database.execute(
        """
        SELECT source_sha256, source_size_bytes, chronological_order,
               collection_start, collection_end, stats_json
        FROM processed_members WHERE source_member = ?
        """,
        (filename,),
    ).fetchone()
    if stored is not None:
        if (
            str(stored[0]) != source_member["sha256"]
            or int(stored[1]) != source_member["size_bytes"]
            or int(stored[2]) != source_member["chronological_order"]
        ):
            raise NextBehaviorCorpusBuildError(
                f"stored source receipt mismatch: {filename}"
            )
        return {
            "status": "already_ingested",
            "source_member": filename,
            "collection_start": str(stored[3]),
            "collection_end": str(stored[4]),
            "stats": json.loads(str(stored[5])),
        }

    _clear_partial_member(database, filename)
    stats: Counter[str] = Counter()
    event_ids: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    configurations: Counter[str] = Counter()
    collection_start = ""
    collection_end = ""
    session_rows: list[tuple[Any, ...]] = []
    command_rows: list[tuple[Any, ...]] = []
    context_rows: list[tuple[Any, ...]] = []
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for source_line, line in enumerate(handle, start=1):
                stats["raw_event_records"] += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    stats["malformed_records"] += 1
                    continue
                if not isinstance(event, dict):
                    stats["non_object_records"] += 1
                    continue
                event_id = _clean(event.get("eventid"))
                event_ids[event_id or "missing"] += 1
                timestamp = _normalize_source_timestamp(event.get("ts"))
                if _clean(event.get("ts")) and not timestamp:
                    stats["invalid_timestamps"] += 1
                if timestamp:
                    if not collection_start or timestamp < collection_start:
                        collection_start = timestamp
                    if not collection_end or timestamp > collection_end:
                        collection_end = timestamp
                protocol = _clean(event.get("protocol")).lower()
                configuration = _clean(event.get("group"))
                if protocol:
                    protocols[protocol] += 1
                if configuration:
                    configurations[configuration] += 1
                if event_id not in _SESSION_EVENT_TYPES:
                    continue
                raw_session_id = _clean(event.get("session"))
                if not raw_session_id or not timestamp:
                    stats["relevant_events_missing_session_or_time"] += 1
                    continue
                stats["relevant_session_events"] += 1
                session_rows.append(
                    (
                        raw_session_id,
                        filename,
                        timestamp,
                        timestamp,
                        protocol,
                        configuration,
                        int(event_id == "cowrie.session.closed"),
                    )
                )
                if event_id == "cowrie.command.input":
                    stats["raw_command_input_events"] += 1
                    command = _clean(event.get("input"))
                    if command:
                        stats["nonempty_command_events"] += 1
                        command_rows.append(
                            (
                                filename,
                                source_line,
                                raw_session_id,
                                timestamp,
                                command,
                            )
                        )
                    else:
                        stats["empty_command_events"] += 1
                elif event_id in _CONTEXT_EVENT_TYPES:
                    stats["context_events"] += 1
                    context_rows.append(
                        (
                            filename,
                            source_line,
                            raw_session_id,
                            timestamp,
                            event_id,
                        )
                    )
                if len(session_rows) >= flush_size:
                    _flush_ingest(
                        database,
                        session_rows,
                        command_rows,
                        context_rows,
                    )
        _flush_ingest(database, session_rows, command_rows, context_rows)
    except (OSError, EOFError, sqlite3.Error) as exc:
        raise NextBehaviorCorpusBuildError(
            f"source member ingestion failed: {filename}: {type(exc).__name__}"
        ) from exc
    if not collection_start or not collection_end:
        raise NextBehaviorCorpusBuildError(
            f"source member has no usable event timestamps: {filename}"
        )

    summary = {
        **dict(sorted(stats.items())),
        "event_id_counts": dict(sorted(event_ids.items())),
        "protocol_event_counts": dict(sorted(protocols.items())),
        "configuration_event_counts": dict(sorted(configurations.items())),
        "timestamp_normalization": (
            "source naive timestamps are documented UTC and normalized to "
            "ISO-8601 Z; offset timestamps are converted to UTC"
        ),
    }
    database.execute(
        """
        INSERT INTO processed_members(
            source_member, source_sha256, source_size_bytes,
            chronological_order, collection_start, collection_end, stats_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            filename,
            source_member["sha256"],
            source_member["size_bytes"],
            source_member["chronological_order"],
            collection_start,
            collection_end,
            _stable_json(summary),
        ),
    )
    database.commit()
    return {
        "status": "ingested",
        "source_member": filename,
        "collection_start": collection_start,
        "collection_end": collection_end,
        "stats": summary,
    }


def _member_by_name(manifest: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        _clean(member["filename"]): dict(member)
        for member in manifest["members"]
    }


def ingest_members(
    *,
    source_manifest_path: Path,
    raw_directory: Path,
    private_database_path: Path,
    selected_members: Iterable[str] = (),
) -> Dict[str, Any]:
    manifest = load_source_manifest(source_manifest_path)
    manifest_hash = _sha256_file(source_manifest_path)
    members_by_name = _member_by_name(manifest)
    requested = [
        _clean(member) for member in selected_members if _clean(member)
    ] or [member["filename"] for member in manifest["members"]]
    unknown = sorted(set(requested) - set(members_by_name))
    if unknown:
        raise NextBehaviorCorpusBuildError(
            "selected members are outside the frozen manifest"
        )
    if len(requested) != len(set(requested)):
        raise NextBehaviorCorpusBuildError("selected member list is duplicated")

    database = open_private_database(private_database_path)
    try:
        stored_manifest = database.execute(
            "SELECT value FROM build_metadata WHERE key = 'source_manifest_sha256'"
        ).fetchone()
        if stored_manifest is not None and str(stored_manifest[0]) != manifest_hash:
            raise NextBehaviorCorpusBuildError(
                "private database source manifest hash mismatch"
            )
        database.execute(
            "INSERT OR IGNORE INTO build_metadata(key, value) VALUES (?, ?)",
            ("source_manifest_sha256", manifest_hash),
        )
        database.commit()
        receipts = [
            ingest_member(database, members_by_name[member], raw_directory)
            for member in requested
        ]
        cross_member_count = int(
            database.execute(
                "SELECT COUNT(*) FROM sessions WHERE cross_member = 1"
            ).fetchone()[0]
        )
        if cross_member_count:
            raise NextBehaviorCorpusBuildError(
                "raw session identifiers occur in more than one source member"
            )
        counts = {
            "processed_members": int(
                database.execute(
                    "SELECT COUNT(*) FROM processed_members"
                ).fetchone()[0]
            ),
            "sessions": int(
                database.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            ),
            "command_events": int(
                database.execute(
                    "SELECT COUNT(*) FROM command_events"
                ).fetchone()[0]
            ),
            "context_events": int(
                database.execute(
                    "SELECT COUNT(*) FROM context_events"
                ).fetchone()[0]
            ),
            "cross_member_sessions": cross_member_count,
        }
    finally:
        database.close()
    return {
        "schema_version": PRIVATE_STORE_ID,
        "status": "ingest_complete",
        "source_manifest_sha256": manifest_hash,
        "selected_member_count": len(requested),
        "member_receipts": receipts,
        "counts": counts,
        "raw_content_emitted": False,
    }


def _batched(values: Sequence[str], size: int) -> Iterator[list[str]]:
    for index in range(0, len(values), size):
        yield list(values[index : index + size])


def _mitre_tactic_lookup(mitre_database: Any) -> Callable[[str], str | None]:
    def lookup(technique: str) -> str | None:
        try:
            tactics = mitre_database.get_tactics(technique)
        except Exception:
            return None
        return str(tactics[0]) if tactics else None

    return lookup


def _require_all_source_members(
    database: sqlite3.Connection,
    source_manifest: Mapping[str, Any],
) -> None:
    expected = {
        str(member["filename"]): (
            str(member["sha256"]),
            int(member["size_bytes"]),
            int(member["chronological_order"]),
        )
        for member in source_manifest["members"]
    }
    stored = {
        str(row[0]): (str(row[1]), int(row[2]), int(row[3]))
        for row in database.execute(
            """
            SELECT source_member, source_sha256, source_size_bytes,
                   chronological_order
            FROM processed_members
            """
        )
    }
    if stored != expected:
        raise NextBehaviorCorpusBuildError(
            "all seven exact source members must be ingested before classification"
        )
    cross_member_count = int(
        database.execute(
            "SELECT COUNT(*) FROM sessions WHERE cross_member = 1"
        ).fetchone()[0]
    )
    if cross_member_count:
        raise NextBehaviorCorpusBuildError(
            "cross-member sessions prevent safe classification"
        )


def classify_private_commands(
    *,
    source_manifest_path: Path,
    classifier_manifest_path: Path,
    repository_root: Path,
    model_root: Path,
    private_database_path: Path,
    code_commit: str,
    batch_size: int = 128,
) -> Dict[str, Any]:
    """Classify each unique private command under the frozen hybrid policy."""

    if batch_size < 1:
        raise NextBehaviorCorpusBuildError("classification batch size must be positive")
    if not code_commit or not re.fullmatch(r"[0-9a-f]{40}", code_commit.lower()):
        raise NextBehaviorCorpusBuildError("code_commit must be a full Git hash")
    source_manifest = load_source_manifest(source_manifest_path)
    classifier_manifest = load_classifier_manifest(classifier_manifest_path)
    asset_receipt = verify_classifier_assets(
        classifier_manifest,
        repository_root=repository_root,
        model_root=model_root,
    )
    database = open_private_database(private_database_path)
    try:
        _require_all_source_members(database, source_manifest)
        command_count = int(
            database.execute(
                "SELECT COUNT(DISTINCT command) FROM command_events"
            ).fetchone()[0]
        )
        existing = database.execute(
            "SELECT receipt_json FROM build_stage_receipts WHERE stage_id = ?",
            (CLASSIFICATION_STAGE_ID,),
        ).fetchone()
        if existing is not None:
            receipt = json.loads(str(existing[0]))
            stored_count = int(
                database.execute(
                    "SELECT COUNT(*) FROM command_labels"
                ).fetchone()[0]
            )
            if (
                receipt.get("classifier_manifest_sha256")
                != _sha256_file(classifier_manifest_path)
                or receipt.get("source_manifest_sha256")
                != _sha256_file(source_manifest_path)
                or receipt.get("code_commit") != code_commit.lower()
                or stored_count != command_count
            ):
                raise NextBehaviorCorpusBuildError(
                    "existing classification receipt is inconsistent"
                )
            return {**receipt, "status": "already_classified"}
        if int(
            database.execute("SELECT COUNT(*) FROM command_labels").fetchone()[0]
        ):
            raise NextBehaviorCorpusBuildError(
                "unreceipted command classifications already exist"
            )

        commands = [
            str(row[0])
            for row in database.execute(
                "SELECT DISTINCT command FROM command_events ORDER BY command"
            )
        ]
        fragments = sorted(
            {
                fragment.text
                for command in commands
                for fragment in split_compound_command(command)
                if fragment.text
            }
        )
        classifiable = sorted(
            (
                fragment
                for fragment in fragments
                if len(fragment.strip()) >= 3
            ),
            key=lambda fragment: (len(fragment), fragment),
        )
        model = SecureBertCommandClassifier(
            model_path=str(model_root),
            checkpoint_path=str(model_root / "checkpoint-6765"),
            device=classifier_manifest["classifier"]["device"],
            max_length=classifier_manifest["classifier"]["max_length"],
        )
        model_predictions: Dict[str, tuple[str | None, float]] = {}
        for batch_number, batch in enumerate(
            _batched(classifiable, batch_size),
            start=1,
        ):
            predictions = model.classify_batch(batch)
            if len(predictions) != len(batch):
                raise NextBehaviorCorpusBuildError(
                    "SecureBERT batch output is misaligned"
                )
            model_predictions.update(zip(batch, predictions, strict=True))
            if batch_number % 20 == 0:
                print(
                    "classified fragments: "
                    f"{min(batch_number * batch_size, len(classifiable))}/"
                    f"{len(classifiable)}",
                    flush=True,
                )
        for fragment in fragments:
            model_predictions.setdefault(fragment, (None, 0.0))

        policy = classifier_manifest["classification_policy"]
        mitre_database = load_mitre_attack_db(
            cache_path=str(repository_root / policy["mitre_cache_path"]),
            silent=True,
        )
        classifier = NotebookParityClassifier(
            bert_fn=lambda command: model_predictions.get(command, (None, 0.0)),
            mitre_db=mitre_database,
            high_confidence=policy["securebert_candidate_threshold"],
            rule_policy_path=str(repository_root / policy["rule_policy_path"]),
        )
        tactic_lookup = _mitre_tactic_lookup(mitre_database)
        label_counts: Counter[str] = Counter()
        unrepresented_counts: Counter[str] = Counter()
        label_rows: list[tuple[str, str, str]] = []
        for index, command in enumerate(commands, start=1):
            outputs = classifier.classify(command)
            normalized = normalize_classifier_outputs(
                outputs,
                private_evidence_prefix=hashlib.sha256(
                    command.encode("utf-8")
                ).hexdigest(),
                policy_sha256=policy["rule_policy_sha256"],
                trust_policy_sha256=policy["trust_policy_sha256"],
                checkpoint_sha256=classifier_manifest["classifier"][
                    "checkpoint_sha256"
                ],
                tactic_lookup=tactic_lookup,
                trusted_model_only_threshold=policy[
                    "trusted_model_only_threshold"
                ],
            )
            for label in normalized["labels"]:
                label_counts[
                    f"{label['trust_tier']}:{label['source']}"
                ] += 1
            unrepresented_counts.update(
                normalized["unrepresented_by_reason"]
            )
            label_rows.append(
                (
                    command,
                    stable_json(normalized["labels"]),
                    stable_json(normalized["unrepresented_by_reason"]),
                )
            )
            if len(label_rows) >= 5000:
                database.executemany(
                    """
                    INSERT INTO command_labels(
                        command, labels_json, unrepresented_json
                    ) VALUES (?, ?, ?)
                    """,
                    label_rows,
                )
                database.commit()
                label_rows.clear()
            if index % 10000 == 0:
                print(
                    f"normalized commands: {index}/{len(commands)}",
                    flush=True,
                )
        if label_rows:
            database.executemany(
                """
                INSERT INTO command_labels(
                    command, labels_json, unrepresented_json
                ) VALUES (?, ?, ?)
                """,
                label_rows,
            )
            database.commit()

        receipt = {
            "schema_version": CLASSIFICATION_STAGE_ID,
            "status": "classified",
            "code_commit": code_commit.lower(),
            "source_manifest_sha256": _sha256_file(source_manifest_path),
            "classifier_manifest_sha256": _sha256_file(
                classifier_manifest_path
            ),
            "checkpoint_sha256": classifier_manifest["classifier"][
                "checkpoint_sha256"
            ],
            "rule_policy_sha256": policy["rule_policy_sha256"],
            "trust_policy_sha256": policy["trust_policy_sha256"],
            "mitre_cache_sha256": policy["mitre_cache_sha256"],
            "unique_command_count": len(commands),
            "unique_fragment_count": len(fragments),
            "classifiable_fragment_count": len(classifiable),
            "label_counts": dict(sorted(label_counts.items())),
            "unrepresented_counts": dict(
                sorted(unrepresented_counts.items())
            ),
            "trusted_model_only_threshold": policy[
                "trusted_model_only_threshold"
            ],
            "drop_rule_securebert_disagreements": policy[
                "drop_rule_securebert_disagreements"
            ],
            "label_adapter_sha256": _sha256_file(
                repository_root
                / "production/prediction/next_behavior_label_policy.py"
            ),
            "corpus_builder_sha256": _sha256_file(Path(__file__)),
            "asset_verification_status": asset_receipt["status"],
            "raw_content_emitted": False,
        }
        database.execute(
            """
            INSERT INTO build_stage_receipts(stage_id, receipt_json)
            VALUES (?, ?)
            """,
            (CLASSIFICATION_STAGE_ID, stable_json(receipt)),
        )
        database.commit()
        return receipt
    finally:
        database.close()


def load_or_create_pseudonymization_key(
    path: Path,
    *,
    create: bool,
) -> tuple[bytes, str]:
    """Load a private 32-byte key, optionally creating it with mode 0600."""

    if path.exists():
        if not path.is_file():
            raise NextBehaviorCorpusBuildError(
                "pseudonymization key path is not a regular file"
            )
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise NextBehaviorCorpusBuildError(
                "pseudonymization key permissions are too broad"
            )
        key = path.read_bytes()
    else:
        if not create:
            raise NextBehaviorCorpusBuildError(
                "pseudonymization key is missing; use --create-key once"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            written = os.write(descriptor, key)
            if written != len(key):
                raise NextBehaviorCorpusBuildError(
                    "pseudonymization key write was incomplete"
                )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if len(key) != 32:
        raise NextBehaviorCorpusBuildError(
            "pseudonymization key must contain exactly 32 bytes"
        )
    key_id = "next-behavior-hmac-" + hashlib.sha256(key).hexdigest()[:16]
    return key, key_id


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NextBehaviorCorpusBuildError(
            "private event timestamp is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise NextBehaviorCorpusBuildError(
            "private event timestamp lacks a timezone"
        )
    return parsed.astimezone(timezone.utc)


def _command_count_bucket(count: int) -> str:
    if count < 1:
        return "0"
    if count == 1:
        return "1"
    if count <= 5:
        return "2-5"
    if count <= 20:
        return "6-20"
    return "21+"


def _session_age_bucket(age_seconds: float) -> str:
    if age_seconds < 0:
        return "unknown"
    if age_seconds < 10:
        return "under_10s"
    if age_seconds < 60:
        return "10_to_60s"
    if age_seconds < 300:
        return "1_to_5m"
    return "over_5m"


def _legacy_historical_id(raw_session_id: str) -> str:
    digest = hashlib.sha256(
        f"{HISTORICAL_DATASET_SOURCE}\0{raw_session_id}".encode("utf-8")
    ).hexdigest()
    return f"external-{digest[:24]}"


def _load_historical_membership(path: Path) -> tuple[Dict[str, str], str]:
    membership: Dict[str, str] = {}
    digest = hashlib.sha256()
    with path.open("rb") as raw_handle:
        for raw_line in raw_handle:
            digest.update(raw_line)
            try:
                value = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise NextBehaviorCorpusBuildError(
                    "historical payload contains malformed JSON"
                ) from exc
            if not isinstance(value, dict):
                raise NextBehaviorCorpusBuildError(
                    "historical payload row is not an object"
                )
            session_id = _clean(value.get("session_id"))
            split = _clean(value.get("split"))
            if not session_id or split not in {"train", "calibration", "test"}:
                raise NextBehaviorCorpusBuildError(
                    "historical payload membership is invalid"
                )
            if session_id in membership:
                raise NextBehaviorCorpusBuildError(
                    "historical payload session is duplicated"
                )
            membership[session_id] = split
    if not membership:
        raise NextBehaviorCorpusBuildError("historical payload is empty")
    return membership, digest.hexdigest()


def _source_member_receipts(
    database: sqlite3.Connection,
    *,
    key: bytes,
    key_id: str,
) -> tuple[list[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    receipts: list[Dict[str, Any]] = []
    by_filename: Dict[str, Dict[str, Any]] = {}
    rows = database.execute(
        """
        SELECT source_member, source_sha256, source_size_bytes,
               chronological_order, collection_start, collection_end
        FROM processed_members ORDER BY chronological_order
        """
    )
    for row in rows:
        receipt = build_source_member_receipt(
            private_member_identifier=str(row[0]),
            source_sha256=str(row[1]),
            byte_size=int(row[2]),
            chronological_order=int(row[3]),
            collection_start=str(row[4]),
            collection_end=str(row[5]),
            pseudonymization_key=key,
            pseudonymization_key_id=key_id,
        )
        receipts.append(receipt)
        by_filename[str(row[0])] = receipt
    return receipts, by_filename


def _context_at_commands(
    command_rows: Sequence[Sequence[Any]],
    context_rows: Sequence[Sequence[Any]],
    *,
    session_start: str,
) -> list[Dict[str, Any]]:
    """Construct causal context using only events at or before each command."""

    ordered_context = sorted(
        context_rows,
        key=lambda row: (str(row[1]), int(row[0])),
    )
    context_index = 0
    login_outcome = "unknown"
    transfer_observed = False
    start = _parse_timestamp(session_start)
    contexts: list[Dict[str, Any]] = []
    for command_number, command_row in enumerate(command_rows, start=1):
        command_line = int(command_row[0])
        command_time = str(command_row[1])
        command_key = (command_time, command_line)
        while context_index < len(ordered_context):
            context_row = ordered_context[context_index]
            context_key = (str(context_row[1]), int(context_row[0]))
            if context_key > command_key:
                break
            event_type = str(context_row[2])
            if event_type == "cowrie.login.success":
                login_outcome = "success"
            elif (
                event_type == "cowrie.login.failed"
                and login_outcome == "unknown"
            ):
                login_outcome = "failed"
            elif event_type in {
                "cowrie.session.file_download",
                "cowrie.session.file_upload",
            }:
                transfer_observed = True
            context_index += 1
        age_seconds = (
            _parse_timestamp(command_time) - start
        ).total_seconds()
        contexts.append(
            {
                "login_outcome": login_outcome,
                "command_count_bucket": _command_count_bucket(command_number),
                "session_age_bucket": _session_age_bucket(age_seconds),
                "confirmed_transfer_observed": transfer_observed,
            }
        )
    return contexts


def _build_one_safe_session(
    database: sqlite3.Connection,
    session_row: Sequence[Any],
    *,
    source_receipt: Mapping[str, Any],
    historical_membership: Mapping[str, str],
    key: bytes,
    key_id: str,
) -> tuple[Dict[str, Any], str, str]:
    raw_session_id = str(session_row[0])
    source_member = str(session_row[1])
    first_seen = str(session_row[2])
    protocol = str(session_row[3])
    configuration = str(session_row[4])
    closed = bool(session_row[5])
    command_rows = list(
        database.execute(
            """
            SELECT c.source_line, c.event_time, c.command,
                   l.labels_json, l.unrepresented_json
            FROM command_events AS c
            JOIN command_labels AS l ON l.command = c.command
            WHERE c.raw_session_id = ?
            ORDER BY c.event_time, c.source_line
            """,
            (raw_session_id,),
        )
    )
    context_rows = list(
        database.execute(
            """
            SELECT source_line, event_time, event_type
            FROM context_events
            WHERE raw_session_id = ?
            ORDER BY event_time, source_line
            """,
            (raw_session_id,),
        )
    )
    contexts = _context_at_commands(
        command_rows,
        context_rows,
        session_start=first_seen,
    )
    observation_groups: list[Dict[str, Any]] = []
    for command_number, (command_row, context) in enumerate(
        zip(command_rows, contexts, strict=True),
        start=1,
    ):
        source_line = int(command_row[0])
        labels = json.loads(str(command_row[3]))
        if not labels:
            continue
        occurrence_labels = []
        for label_index, raw_label in enumerate(labels):
            label = dict(raw_label)
            label["evidence_ref"] = (
                f"{source_member}:{source_line}:label:{label_index}"
            )
            occurrence_labels.append(label)
        observation_groups.append(
            {
                "group_id": f"{source_member}:{source_line}",
                "event_order": command_number,
                "observed_at": str(command_row[1]),
                "labels": occurrence_labels,
                "session_context": context,
            }
        )
    if not observation_groups:
        raise NextBehaviorCorpusBuildError(
            "eligible private session has no representable label groups"
        )
    private_session = {
        "session_id": raw_session_id,
        "protocol": protocol,
        "status": "closed" if closed else "active",
        "configuration_id": configuration or "unknown",
        "observation_groups": observation_groups,
    }
    result = build_privacy_safe_session(
        private_session,
        source_receipt,
        pseudonymization_key=key,
        pseudonymization_key_id=key_id,
    )
    legacy_id = _legacy_historical_id(raw_session_id)
    historical_split = historical_membership.get(legacy_id, "not_present")
    sort_session_id = (
        result["safe_session"]["session_id"]
        if result["safe_session"] is not None
        else pseudonymous_id("session", raw_session_id, key=key)
    )
    return result, legacy_id, historical_split


def _pipeline_reconciliation(
    database: sqlite3.Connection,
    *,
    built_session_count: int,
    safe_session_count: int,
) -> Dict[str, Any]:
    source_stats = [
        json.loads(str(row[0]))
        for row in database.execute(
            "SELECT stats_json FROM processed_members"
        )
    ]
    raw_event_records = sum(
        int(stats.get("raw_event_records") or 0) for stats in source_stats
    )
    raw_command_inputs = sum(
        int(stats.get("raw_command_input_events") or 0)
        for stats in source_stats
    )
    nonempty_command_events = sum(
        int(stats.get("nonempty_command_events") or 0)
        for stats in source_stats
    )
    stored_command_events = int(
        database.execute("SELECT COUNT(*) FROM command_events").fetchone()[0]
    )
    if nonempty_command_events != stored_command_events:
        raise NextBehaviorCorpusBuildError(
            "raw and private-store command counts do not reconcile"
        )

    occurrence_counts: Counter[str] = Counter()
    unrepresented_occurrences: Counter[str] = Counter()
    rows = database.execute(
        """
        SELECT l.labels_json, l.unrepresented_json, COUNT(*)
        FROM command_events AS c
        JOIN command_labels AS l ON l.command = c.command
        GROUP BY l.labels_json, l.unrepresented_json
        """
    )
    for labels_json, unrepresented_json, occurrence_count in rows:
        labels = json.loads(str(labels_json))
        unrepresented = json.loads(str(unrepresented_json))
        count = int(occurrence_count)
        if labels:
            if any(
                label.get("trust_tier") == "trusted_observation"
                for label in labels
            ):
                occurrence_counts["groups_with_trusted_label"] += count
            else:
                occurrence_counts["groups_with_audit_only_labels"] += count
        else:
            occurrence_counts["groups_without_representable_labels"] += count
        for reason, reason_count in unrepresented.items():
            unrepresented_occurrences[str(reason)] += (
                int(reason_count) * count
            )
    categorized = sum(occurrence_counts.values())
    if categorized != stored_command_events:
        raise NextBehaviorCorpusBuildError(
            "classified command occurrence counts do not reconcile"
        )
    return {
        "raw_event_records": raw_event_records,
        "raw_command_input_events": raw_command_inputs,
        "empty_command_input_events": raw_command_inputs
        - nonempty_command_events,
        "nonempty_command_events": nonempty_command_events,
        "private_store_command_events": stored_command_events,
        "unique_classified_commands": int(
            database.execute(
                "SELECT COUNT(*) FROM command_labels"
            ).fetchone()[0]
        ),
        **dict(sorted(occurrence_counts.items())),
        "unrepresented_output_occurrences_by_reason": dict(
            sorted(unrepresented_occurrences.items())
        ),
        "private_sessions_entering_safe_adapter": built_session_count,
        "privacy_safe_sessions_emitted": safe_session_count,
        "sessions_dropped_without_trusted_behavior": (
            built_session_count - safe_session_count
        ),
    }


def build_safe_corpus(
    *,
    source_manifest_path: Path,
    classifier_manifest_path: Path,
    preprocessing_manifest_path: Path,
    historical_payload_path: Path,
    private_database_path: Path,
    pseudonymization_key_path: Path,
    safe_payload_path: Path,
    source_receipts_path: Path,
    corpus_receipt_path: Path,
    build_receipt_path: Path,
    code_commit: str,
    create_key: bool = False,
) -> Dict[str, Any]:
    """Build and export the deterministic privacy-safe corrected corpus."""

    if not code_commit or not all(
        character in "0123456789abcdef" for character in code_commit.lower()
    ) or len(code_commit) != 40:
        raise NextBehaviorCorpusBuildError("code_commit must be a full Git hash")
    output_paths = (
        safe_payload_path,
        source_receipts_path,
        corpus_receipt_path,
        build_receipt_path,
    )
    if any(path.exists() for path in output_paths):
        raise NextBehaviorCorpusBuildError(
            "safe build outputs already exist; refusing to overwrite"
        )
    source_manifest = load_source_manifest(source_manifest_path)
    classifier_manifest = load_classifier_manifest(classifier_manifest_path)
    key, key_id = load_or_create_pseudonymization_key(
        pseudonymization_key_path,
        create=create_key,
    )
    historical_membership, historical_payload_sha256 = (
        _load_historical_membership(historical_payload_path)
    )
    database = open_private_database(private_database_path)
    temporary_paths: list[Path] = []
    try:
        _require_all_source_members(database, source_manifest)
        classification_row = database.execute(
            "SELECT receipt_json FROM build_stage_receipts WHERE stage_id = ?",
            (CLASSIFICATION_STAGE_ID,),
        ).fetchone()
        if classification_row is None:
            raise NextBehaviorCorpusBuildError(
                "classification must complete before the safe build"
            )
        classification_receipt = json.loads(str(classification_row[0]))
        if (
            classification_receipt.get("classifier_manifest_sha256")
            != _sha256_file(classifier_manifest_path)
            or classification_receipt.get("code_commit") != code_commit.lower()
        ):
            raise NextBehaviorCorpusBuildError(
                "classification receipt uses another code or classifier manifest"
            )
        label_count = int(
            database.execute("SELECT COUNT(*) FROM command_labels").fetchone()[0]
        )
        command_count = int(
            database.execute(
                "SELECT COUNT(DISTINCT command) FROM command_events"
            ).fetchone()[0]
        )
        if label_count != command_count:
            raise NextBehaviorCorpusBuildError(
                "command classifications are incomplete"
            )
        source_receipts, receipts_by_filename = _source_member_receipts(
            database,
            key=key,
            key_id=key_id,
        )
        database.execute("DELETE FROM safe_sessions")
        database.commit()
        session_rows = database.execute(
            """
            SELECT s.raw_session_id, s.source_member, s.first_seen,
                   s.protocol, s.configuration, s.closed
            FROM sessions AS s
            WHERE s.closed = 1
              AND s.protocol = 'ssh'
              AND EXISTS (
                  SELECT 1
                  FROM command_events AS c
                  JOIN command_labels AS l ON l.command = c.command
                  WHERE c.raw_session_id = s.raw_session_id
                    AND l.labels_json != '[]'
              )
            ORDER BY s.first_seen, s.raw_session_id
            """
        )
        built_count = 0
        safe_count = 0
        historical_splits: Counter[str] = Counter()
        source_build_counts: Counter[str] = Counter()
        for session_row in session_rows:
            source_member = str(session_row[1])
            result, legacy_id, historical_split = _build_one_safe_session(
                database,
                session_row,
                source_receipt=receipts_by_filename[source_member],
                historical_membership=historical_membership,
                key=key,
                key_id=key_id,
            )
            sort_session_id = (
                result["safe_session"]["session_id"]
                if result["safe_session"] is not None
                else pseudonymous_id("session", str(session_row[0]), key=key)
            )
            database.execute(
                """
                INSERT INTO safe_sessions(
                    sort_session_id, safe_json, reconciliation_json,
                    source_member, legacy_historical_session_id,
                    historical_split
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    sort_session_id,
                    (
                        stable_json(result["safe_session"])
                        if result["safe_session"] is not None
                        else None
                    ),
                    stable_json(result["reconciliation"]),
                    source_member,
                    legacy_id,
                    historical_split,
                ),
            )
            built_count += 1
            safe_count += int(result["safe_session"] is not None)
            historical_splits[historical_split] += 1
            source_build_counts[
                receipts_by_filename[source_member]["member_id"]
            ] += 1
            if built_count % 5000 == 0:
                database.commit()
                print(
                    f"privacy-safe sessions staged: {built_count}",
                    flush=True,
                )
        database.commit()

        def build_result_stream() -> Iterator[Dict[str, Any]]:
            rows = database.execute(
                """
                SELECT safe_json, reconciliation_json
                FROM safe_sessions
                ORDER BY CASE WHEN safe_json IS NULL THEN 1 ELSE 0 END,
                         sort_session_id
                """
            )
            for safe_json, reconciliation_json in rows:
                yield {
                    "safe_session": (
                        json.loads(str(safe_json))
                        if safe_json is not None
                        else None
                    ),
                    "reconciliation": json.loads(str(reconciliation_json)),
                }

        classifier_policy = classifier_manifest["classification_policy"]
        corpus_receipt = build_streaming_corpus_receipt(
            build_result_stream(),
            source_receipts,
            code_commit=code_commit,
            preprocessing_sha256=_sha256_file(
                preprocessing_manifest_path
            ),
            label_policy_sha256=classifier_policy["rule_policy_sha256"],
            trust_policy_sha256=classifier_policy["trust_policy_sha256"],
            classification_checkpoint_sha256=classifier_manifest["classifier"][
                "checkpoint_sha256"
            ],
        )
        if corpus_receipt["safe_session_count"] != safe_count:
            raise NextBehaviorCorpusBuildError(
                "safe-session count changed during receipt generation"
            )

        for path in output_paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(
                f".{path.name}.tmp.{os.getpid()}"
            )
            if temporary.exists():
                raise NextBehaviorCorpusBuildError(
                    "safe build temporary output already exists"
                )
            temporary_paths.append(temporary)

        safe_temporary = temporary_paths[0]
        safe_line_count = 0
        with safe_temporary.open("x", encoding="utf-8") as handle:
            for (safe_json,) in database.execute(
                """
                SELECT safe_json FROM safe_sessions
                WHERE safe_json IS NOT NULL
                ORDER BY sort_session_id
                """
            ):
                handle.write(str(safe_json) + "\n")
                safe_line_count += 1
            handle.flush()
            os.fsync(handle.fileno())
        if safe_line_count != safe_count:
            raise NextBehaviorCorpusBuildError(
                "safe payload line count does not reconcile"
            )
        safe_payload_sha256 = _sha256_file(safe_temporary)
        pipeline_reconciliation = _pipeline_reconciliation(
            database,
            built_session_count=built_count,
            safe_session_count=safe_count,
        )
        source_receipts_payload = {
            "schema_version": "next_behavior_source_member_receipts.v1",
            "source_manifest_sha256": _sha256_file(source_manifest_path),
            "members": source_receipts,
        }
        temporary_paths[1].write_text(
            json.dumps(source_receipts_payload, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        temporary_paths[2].write_text(
            json.dumps(corpus_receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        build_receipt = {
            "schema_version": "next_behavior_zenodo_build_receipt.v1",
            "status": "safe_corpus_built",
            "code_commit": code_commit.lower(),
            "source_manifest_sha256": _sha256_file(source_manifest_path),
            "classifier_manifest_sha256": _sha256_file(
                classifier_manifest_path
            ),
            "preprocessing_manifest_sha256": _sha256_file(
                preprocessing_manifest_path
            ),
            "historical_payload_sha256": historical_payload_sha256,
            "pseudonymization_key_id": key_id,
            "safe_payload": {
                "sha256": safe_payload_sha256,
                "size_bytes": safe_temporary.stat().st_size,
                "line_count": safe_line_count,
            },
            "corpus_receipt_id": corpus_receipt["receipt_id"],
            "timestamp_normalization": (
                "source naive timestamps interpreted as UTC and emitted as "
                "timezone-aware ISO-8601 Z"
            ),
            "classification": classification_receipt,
            "pipeline_reconciliation": pipeline_reconciliation,
            "historical_membership": {
                "accepted_payload_session_count": len(historical_membership),
                "overlap_by_historical_split": dict(
                    sorted(historical_splits.items())
                ),
            },
            "source_session_counts": dict(
                sorted(source_build_counts.items())
            ),
            "raw_content_emitted": False,
        }
        temporary_paths[3].write_text(
            json.dumps(build_receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        for temporary, destination in zip(
            temporary_paths,
            output_paths,
            strict=True,
        ):
            if destination.exists():
                raise NextBehaviorCorpusBuildError(
                    "safe build output appeared during generation"
                )
            temporary.replace(destination)
        database.execute(
            """
            INSERT OR REPLACE INTO build_stage_receipts(stage_id, receipt_json)
            VALUES (?, ?)
            """,
            (SAFE_BUILD_STAGE_ID, stable_json(build_receipt)),
        )
        database.commit()
        return build_receipt
    except BaseException:
        for temporary in temporary_paths:
            if temporary.exists():
                temporary.unlink()
        raise
    finally:
        database.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("ingest", "classify", "safe"))
    parser.add_argument(
        "--source-manifest",
        type=Path,
        default=Path("configs/next_behavior_zenodo_source.v1.json"),
    )
    parser.add_argument("--raw-directory", type=Path)
    parser.add_argument("--private-database", type=Path, required=True)
    parser.add_argument("--member", action="append", default=[])
    parser.add_argument(
        "--classifier-manifest",
        type=Path,
        default=Path(
            "configs/next_behavior_classifier_environment.v1.json"
        ),
    )
    parser.add_argument("--repository-root", type=Path, default=Path("."))
    parser.add_argument("--model-root", type=Path)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument(
        "--preprocessing-manifest",
        type=Path,
        default=Path("configs/next_behavior_preprocessing.v1.json"),
    )
    parser.add_argument("--historical-payload", type=Path)
    parser.add_argument("--pseudonymization-key", type=Path)
    parser.add_argument("--create-key", action="store_true")
    parser.add_argument("--safe-payload", type=Path)
    parser.add_argument("--source-receipts", type=Path)
    parser.add_argument("--corpus-receipt", type=Path)
    parser.add_argument("--build-receipt", type=Path)
    parser.add_argument("--code-commit", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.stage == "ingest":
        if args.raw_directory is None:
            raise NextBehaviorCorpusBuildError(
                "ingest requires --raw-directory"
            )
        result = ingest_members(
            source_manifest_path=args.source_manifest,
            raw_directory=args.raw_directory,
            private_database_path=args.private_database,
            selected_members=args.member,
        )
    elif args.stage == "classify":
        if args.model_root is None:
            raise NextBehaviorCorpusBuildError(
                "classify requires --model-root"
            )
        result = classify_private_commands(
            source_manifest_path=args.source_manifest,
            classifier_manifest_path=args.classifier_manifest,
            repository_root=args.repository_root,
            model_root=args.model_root,
            private_database_path=args.private_database,
            code_commit=args.code_commit,
            batch_size=args.batch_size,
        )
    else:
        required = {
            "--historical-payload": args.historical_payload,
            "--pseudonymization-key": args.pseudonymization_key,
            "--safe-payload": args.safe_payload,
            "--source-receipts": args.source_receipts,
            "--corpus-receipt": args.corpus_receipt,
            "--build-receipt": args.build_receipt,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise NextBehaviorCorpusBuildError(
                "safe build is missing required paths: " + ", ".join(missing)
            )
        result = build_safe_corpus(
            source_manifest_path=args.source_manifest,
            classifier_manifest_path=args.classifier_manifest,
            preprocessing_manifest_path=args.preprocessing_manifest,
            historical_payload_path=args.historical_payload,
            private_database_path=args.private_database,
            pseudonymization_key_path=args.pseudonymization_key,
            safe_payload_path=args.safe_payload,
            source_receipts_path=args.source_receipts,
            corpus_receipt_path=args.corpus_receipt,
            build_receipt_path=args.build_receipt,
            code_commit=args.code_commit,
            create_key=args.create_key,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
