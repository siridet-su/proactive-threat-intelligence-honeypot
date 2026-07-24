#!/usr/bin/env python3
"""Classify and export the frozen selected next-behavior corpus safely.

This is the post-ingest stage for
``build_next_behavior_selected_corpus``.  Raw command text and original
session identifiers remain confined to the private SQLite store.  The public
role artifacts contain only HMAC-pseudonymous identifiers, canonical labels,
privacy-safe examples, and aggregate provenance receipts.

Classification is resumable at exact-command batch boundaries.  A verified
cache row is never recomputed; only commands still absent from
``command_labels`` are passed through the frozen classifier.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess
import tempfile
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
    require_valid_corpus_receipt,
    require_valid_source_member_receipt,
)
from production.prediction.next_behavior_contract import (
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_label_policy import (
    normalize_classifier_outputs,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)
from production.tools.build_next_behavior_selected_corpus import (
    FINAL_PREPARATION_SCHEMA_VERSION,
    FINAL_PREPARATION_FIELDS,
    FINAL_PREPARATION_GENERATION_SCHEMA_VERSION,
    FINAL_PREPARATION_GENERATION_FIELDS,
    PURPOSE_TO_ROLE,
    ROLE_TO_COHORT,
    SelectedCorpusBuildError,
    _legacy_preparation_marker,
    _validated_generation_history,
    _require_canonical_cached_row,
    final_member_receipts_sha256,
    open_selected_database,
    record_final_preparation_generation,
    require_final_preparation_generation_marker,
    require_final_preparation_generation_receipt,
)
from production.tools.build_next_behavior_zenodo_corpus import (
    load_or_create_pseudonymization_key,
)
from production.tools.verify_next_behavior_classifier_assets import (
    load_classifier_manifest,
    verify_classifier_assets,
)
from production.utils.serialization import stable_id, stable_json


CLASSIFICATION_RECEIPT_SCHEMA_VERSION = (
    "next_behavior_selected_classification.v1"
)
SAFE_BUILD_RECEIPT_SCHEMA_VERSION = "next_behavior_selected_safe_build.v3"
LEGACY_SAFE_BUILD_RECEIPT_SCHEMA_VERSION = (
    "next_behavior_selected_safe_build.v2"
)
SOURCE_RECEIPTS_SCHEMA_VERSION = (
    "next_behavior_selected_source_member_receipts.v1"
)
HISTORICAL_SPLIT_EVIDENCE_SCHEMA_VERSION = (
    "next_behavior_historical_split_evidence.v1"
)
HISTORICAL_DATASET_SOURCE = (
    "zenodo:21260400:COW160x4:seven_systematic_weekly_members"
)
EXPECTED_MEMBER_COUNTS = {
    "train": 4,
    "selection": 1,
    "calibration": 1,
    "test": 7,
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BLOCK_SIZE = 8 * 1024 * 1024
_FORBIDDEN_PUBLIC_FIELDS = frozenset(
    {
        "command",
        "commands",
        "input",
        "password",
        "passwd",
        "src_ip",
        "source_ip",
        "username",
        "raw_session_id",
        "raw_command",
        "raw_commands",
    }
)
_LEGACY_BUILD_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "purpose",
        "role",
        "source_cohort",
        "code_commit",
        "source_selection_sha256",
        "classifier_manifest_sha256",
        "preprocessing_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "classification_checkpoint_sha256",
        "label_adapter_sha256",
        "safe_builder_sha256",
        "pseudonymization_key_id",
        "max_sequence_length",
        "safe_sessions",
        "examples",
        "source_receipts_artifact_sha256",
        "corpus_receipt_artifact_sha256",
        "membership",
        "historical_membership",
        "pipeline_reconciliation",
        "final_preparation_gate",
        "corpus_receipt_id",
        "raw_content_emitted",
        "build_receipt_id",
    }
)
_HISTORICAL_SPLIT_EVIDENCE_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "artifact_sha256",
        "record_count",
        "session_membership_sha256",
    }
)
_BUILD_RECEIPT_FIELDS = _LEGACY_BUILD_RECEIPT_FIELDS | frozenset(
    {"historical_split_evidence"}
)
_PAYLOAD_RECEIPT_FIELDS = frozenset(
    {"line_count", "size_bytes", "sha256"}
)
_MEMBERSHIP_FIELDS = frozenset(
    {
        "source_member_count",
        "source_member_membership_sha256",
        "session_count",
        "session_membership_sha256",
        "example_count",
        "example_membership_sha256",
        "input_count",
        "input_membership_sha256",
    }
)
_GENERATION_OUTPUT_FIELDS = frozenset(
    {
        "safe_sessions",
        "examples",
        "source_receipts",
        "corpus_receipt",
        "build_receipt",
        "historical_split_evidence",
    }
)


class SelectedSafeCorpusError(ValueError):
    """Raised when classification or privacy-safe export is not trustworthy."""


def _require_repository_commit(
    repository_root: Path,
    expected_commit: str,
) -> str:
    """Bind generated evidence to the exact clean tracked source tree."""

    commit = _clean(expected_commit).lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SelectedSafeCorpusError("code_commit must be a full Git hash")
    try:
        actual = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip().lower()
        tracked_status = subprocess.run(
            [
                "git",
                "-C",
                str(repository_root),
                "status",
                "--porcelain",
                "--untracked-files=no",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SelectedSafeCorpusError(
            "cannot verify repository commit"
        ) from exc
    if actual != commit:
        raise SelectedSafeCorpusError(
            "code_commit does not match repository HEAD"
        )
    if tracked_status:
        raise SelectedSafeCorpusError(
            "tracked repository state must be clean before artifact generation"
        )
    return commit


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(_BLOCK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_sha256(value: Any, label: str) -> str:
    digest = _clean(value).lower()
    if not _SHA256.fullmatch(digest):
        raise SelectedSafeCorpusError(f"{label} must be a SHA-256 digest")
    return digest


def _batched(values: Sequence[str], size: int) -> Iterator[list[str]]:
    for index in range(0, len(values), size):
        yield list(values[index : index + size])


def _mitre_tactic_lookup(database: Any) -> Callable[[str], str | None]:
    def lookup(technique: str) -> str | None:
        try:
            tactics = database.get_tactics(technique)
        except Exception:
            return None
        return str(tactics[0]) if tactics else None

    return lookup


def _classifier_for_missing(
    *,
    classifier_manifest: Mapping[str, Any],
    repository_root: Path,
    model_root: Path,
    fragments: Sequence[str],
) -> tuple[NotebookParityClassifier, Callable[[str], str | None]]:
    """Load the frozen model once and bind predictions to exact fragments."""

    config = classifier_manifest["classifier"]
    model = SecureBertCommandClassifier(
        model_path=str(model_root),
        checkpoint_path=str(model_root / "checkpoint-6765"),
        device=config["device"],
        max_length=config["max_length"],
    )
    classifiable = sorted(
        (fragment for fragment in fragments if len(fragment.strip()) >= 3),
        key=lambda item: (len(item), item),
    )
    predictions: Dict[str, tuple[str | None, float]] = {}
    for batch in _batched(classifiable, 128):
        outputs = model.classify_batch(batch)
        if len(outputs) != len(batch):
            raise SelectedSafeCorpusError(
                "SecureBERT batch output is misaligned"
            )
        predictions.update(zip(batch, outputs, strict=True))
    for fragment in fragments:
        predictions.setdefault(fragment, (None, 0.0))

    policy = classifier_manifest["classification_policy"]
    mitre_path = repository_root / policy["mitre_cache_path"]
    if _sha256_file(mitre_path) != policy["mitre_cache_sha256"]:
        raise SelectedSafeCorpusError(
            "MITRE cache changed before classifier normalization"
        )
    mitre = load_mitre_attack_db(
        cache_path=str(mitre_path),
        silent=True,
        allow_network_refresh=False,
    )
    if _sha256_file(mitre_path) != policy["mitre_cache_sha256"]:
        raise SelectedSafeCorpusError(
            "MITRE cache changed during classifier normalization"
        )
    classifier = NotebookParityClassifier(
        bert_fn=lambda command: predictions.get(command, (None, 0.0)),
        mitre_db=mitre,
        high_confidence=policy["securebert_candidate_threshold"],
        rule_policy_path=str(repository_root / policy["rule_policy_path"]),
    )
    return classifier, _mitre_tactic_lookup(mitre)


def _validate_all_cached_rows(
    database: sqlite3.Connection,
    classifier_manifest: Mapping[str, Any],
) -> int:
    policy = classifier_manifest["classification_policy"]
    count = 0
    for labels_json, unrepresented_json in database.execute(
        "SELECT labels_json, unrepresented_json FROM command_labels "
        "ORDER BY command"
    ):
        _require_canonical_cached_row(
            str(labels_json),
            str(unrepresented_json),
            rule_policy_sha256=policy["rule_policy_sha256"],
            trust_policy_sha256=policy["trust_policy_sha256"],
            checkpoint_sha256=classifier_manifest["classifier"][
                "checkpoint_sha256"
            ],
        )
        count += 1
    return count


def classify_missing_selected_commands(
    *,
    classifier_manifest_path: Path,
    repository_root: Path,
    model_root: Path,
    private_database_path: Path,
    code_commit: str,
    command_batch_size: int = 256,
    classifier_factory: Callable[
        [Sequence[str]], tuple[Any, Callable[[str], str | None]]
    ]
    | None = None,
) -> Dict[str, Any]:
    """Classify only commands absent from the verified exact-command cache.

    Every command batch is committed atomically.  If a later batch fails, a
    subsequent invocation validates and retains the earlier rows, then resumes
    from the first command still missing.
    """

    commit = _require_repository_commit(repository_root, code_commit)
    if command_batch_size < 1:
        raise SelectedSafeCorpusError("command_batch_size must be positive")
    try:
        manifest = load_classifier_manifest(classifier_manifest_path)
        asset_receipt = verify_classifier_assets(
            manifest,
            repository_root=repository_root,
            model_root=model_root,
        )
    except ValueError as exc:
        raise SelectedSafeCorpusError(str(exc)) from exc
    manifest_sha256 = _sha256_file(classifier_manifest_path)
    policy = manifest["classification_policy"]
    static_stage_basis = {
        "schema_version": CLASSIFICATION_RECEIPT_SCHEMA_VERSION,
        "code_commit": commit,
        "classifier_manifest_sha256": manifest_sha256,
        "checkpoint_sha256": manifest["classifier"]["checkpoint_sha256"],
        "rule_policy_sha256": policy["rule_policy_sha256"],
        "trust_policy_sha256": policy["trust_policy_sha256"],
        "label_adapter_sha256": _sha256_file(
            repository_root
            / "production/prediction/next_behavior_label_policy.py"
        ),
        "selected_builder_sha256": _sha256_file(
            repository_root
            / "production/tools/build_next_behavior_selected_corpus.py"
        ),
        "safe_builder_sha256": _sha256_file(Path(__file__)),
    }

    database = open_selected_database(private_database_path)
    try:
        selection = database.execute(
            "SELECT value FROM metadata WHERE key = 'source_selection_sha256'"
        ).fetchone()
        if selection is None:
            raise SelectedSafeCorpusError(
                "private store is not bound to a completed source selection"
            )
        selection_sha256 = _require_sha256(
            selection[0], "source_selection_sha256"
        )
        final_member_count = int(
            database.execute(
                "SELECT COUNT(*) FROM source_members "
                "WHERE experiment_role = 'test'"
            ).fetchone()[0]
        )
        if final_member_count:
            metadata = dict(
                database.execute(
                    "SELECT key, value FROM metadata WHERE key IN "
                    "('final_corpus_prepared_at', "
                    "'final_corpus_preparation_receipt_id', "
                    "'final_corpus_preparation_receipt_id_pending', "
                    "'final_corpus_preparation_receipt_json')"
                )
            )
            if (
                final_member_count != 7
                or "final_corpus_prepared_at" not in metadata
                or "final_corpus_preparation_receipt_id_pending" in metadata
                or "final_corpus_preparation_receipt_id" not in metadata
                or "final_corpus_preparation_receipt_json" not in metadata
            ):
                raise SelectedSafeCorpusError(
                    "final classification requires completed blinded "
                    "preparation"
                )
            try:
                preparation = json.loads(
                    metadata["final_corpus_preparation_receipt_json"]
                )
            except json.JSONDecodeError as exc:
                raise SelectedSafeCorpusError(
                    "stored final preparation receipt is invalid"
                ) from exc
            if (
                not isinstance(preparation, Mapping)
                or set(preparation) != FINAL_PREPARATION_FIELDS
                or preparation.get("receipt_id")
                != metadata["final_corpus_preparation_receipt_id"]
                or preparation.get("status")
                != "frozen_for_blinded_preparation"
                or preparation.get("evaluation_opened") is not False
                or preparation.get("code_commit") != commit
                or preparation.get("source_selection_sha256")
                != selection_sha256
                or preparation.get("classifier_manifest_sha256")
                != manifest_sha256
                or preparation.get("classification_checkpoint_sha256")
                != manifest["classifier"]["checkpoint_sha256"]
            ):
                raise SelectedSafeCorpusError(
                    "stored final preparation provenance is inconsistent"
                )
        cached_before = _validate_all_cached_rows(database, manifest)
        commands = [
            str(row[0])
            for row in database.execute(
                "SELECT DISTINCT command FROM command_events ORDER BY command"
            )
        ]
        command_count = len(commands)
        source_members = [
            {
                "source_sha256": str(row[0]),
                "chronological_order": int(row[1]),
                "experiment_role": str(row[2]),
            }
            for row in database.execute(
                """
                SELECT source_sha256, chronological_order, experiment_role
                FROM source_members ORDER BY chronological_order
                """
            )
        ]
        stage_basis = {
            **static_stage_basis,
            "source_selection_sha256": selection_sha256,
            "ingested_source_members_sha256": hashlib.sha256(
                stable_json(source_members).encode()
            ).hexdigest(),
            "exact_command_membership_sha256": hashlib.sha256(
                stable_json(commands).encode()
            ).hexdigest(),
        }
        receipt_id = stable_id(
            "nextbehaviorselectedclassification", stage_basis
        )
        existing = database.execute(
            "SELECT receipt_json FROM classification_cache_receipts "
            "WHERE cache_receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if existing is not None:
            receipt = json.loads(str(existing[0]))
            if (
                receipt.get("status") != "classification_complete"
                or receipt.get("source_selection_sha256") != selection_sha256
                or receipt.get("unique_command_count") != command_count
                or cached_before != command_count
            ):
                raise SelectedSafeCorpusError(
                    "completed classification receipt is inconsistent"
                )
            return {**receipt, "status": "already_classified"}

        cached_commands = {
            str(row[0])
            for row in database.execute(
                "SELECT command FROM command_labels"
            )
        }
        missing = [
            command for command in commands if command not in cached_commands
        ]
        initially_missing = len(missing)
        classified = 0
        label_counts: Counter[str] = Counter()
        unrepresented_counts: Counter[str] = Counter()
        classifier: Any = None
        tactic_lookup: Callable[[str], str | None] | None = None
        if missing:
            fragments = sorted(
                {
                    fragment.text
                    for command in missing
                    for fragment in split_compound_command(command)
                    if fragment.text
                }
            )
            if classifier_factory is None:
                classifier, tactic_lookup = _classifier_for_missing(
                    classifier_manifest=manifest,
                    repository_root=repository_root,
                    model_root=model_root,
                    fragments=fragments,
                )
            else:
                classifier, tactic_lookup = classifier_factory(fragments)
        for command_batch in _batched(missing, command_batch_size):
            if classifier is None or tactic_lookup is None:
                raise SelectedSafeCorpusError(
                    "classifier was not initialized for missing commands"
                )
            rows: list[tuple[str, str, str, str]] = []
            for command in command_batch:
                normalized = normalize_classifier_outputs(
                    classifier.classify(command),
                    private_evidence_prefix=hashlib.sha256(
                        command.encode("utf-8")
                    ).hexdigest(),
                    policy_sha256=policy["rule_policy_sha256"],
                    trust_policy_sha256=policy["trust_policy_sha256"],
                    checkpoint_sha256=manifest["classifier"][
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
                rows.append(
                    (
                        command,
                        stable_json(normalized["labels"]),
                        stable_json(normalized["unrepresented_by_reason"]),
                        receipt_id,
                    )
                )
            try:
                database.execute("BEGIN IMMEDIATE")
                database.executemany(
                    """
                    INSERT INTO command_labels(
                        command, labels_json, unrepresented_json,
                        cache_receipt_id
                    ) VALUES (?, ?, ?, ?)
                    """,
                    rows,
                )
                database.commit()
            except sqlite3.Error:
                database.rollback()
                raise
            classified += len(rows)

        final_count = _validate_all_cached_rows(database, manifest)
        if final_count != command_count:
            raise SelectedSafeCorpusError(
                "classification completed without exact command coverage"
            )
        receipt: Dict[str, Any] = {
            **stage_basis,
            "status": "classification_complete",
            "cache_receipt_id": receipt_id,
            "unique_command_count": command_count,
            "verified_cached_command_count_before_run": cached_before,
            "missing_command_count_before_run": initially_missing,
            "newly_classified_command_count": classified,
            "label_counts_for_new_commands": dict(sorted(label_counts.items())),
            "unrepresented_counts_for_new_commands": dict(
                sorted(unrepresented_counts.items())
            ),
            "transaction_boundary": "exact_command_batch",
            "resumption_policy": "retain_verified_rows_and_classify_only_missing",
            "asset_verification_status": asset_receipt["status"],
            "raw_content_emitted": False,
        }
        database.execute(
            "INSERT INTO classification_cache_receipts("
            "cache_receipt_id, receipt_json) VALUES (?, ?)",
            (receipt_id, stable_json(receipt)),
        )
        database.commit()
        return receipt
    except (sqlite3.Error, SelectedCorpusBuildError) as exc:
        database.rollback()
        if isinstance(exc, SelectedSafeCorpusError):
            raise
        raise SelectedSafeCorpusError(str(exc)) from exc
    finally:
        database.close()


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SelectedSafeCorpusError("private timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise SelectedSafeCorpusError("private timestamp lacks a timezone")
    return parsed.astimezone(timezone.utc)


def _command_count_bucket(count: int) -> str:
    if count == 1:
        return "1"
    if count <= 5:
        return "2-5"
    if count <= 20:
        return "6-20"
    return "21+"


def _session_age_bucket(seconds: float) -> str:
    if seconds < 0:
        return "unknown"
    if seconds < 10:
        return "under_10s"
    if seconds < 60:
        return "10_to_60s"
    if seconds < 300:
        return "1_to_5m"
    return "over_5m"


def _context_at_commands(
    command_rows: Sequence[Sequence[Any]],
    context_rows: Sequence[Sequence[Any]],
    *,
    session_start: str,
) -> list[Dict[str, Any]]:
    ordered_context = sorted(
        context_rows, key=lambda row: (str(row[1]), int(row[0]))
    )
    context_index = 0
    login_outcome = "unknown"
    transfer_observed = False
    start = _parse_timestamp(session_start)
    contexts: list[Dict[str, Any]] = []
    for command_number, command_row in enumerate(command_rows, start=1):
        command_key = (str(command_row[1]), int(command_row[0]))
        while context_index < len(ordered_context):
            context = ordered_context[context_index]
            if (str(context[1]), int(context[0])) > command_key:
                break
            event_type = str(context[2])
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
        contexts.append(
            {
                "login_outcome": login_outcome,
                "command_count_bucket": _command_count_bucket(command_number),
                "session_age_bucket": _session_age_bucket(
                    (
                        _parse_timestamp(str(command_row[1])) - start
                    ).total_seconds()
                ),
                "confirmed_transfer_observed": transfer_observed,
            }
        )
    return contexts


def _source_receipts_for_role(
    database: sqlite3.Connection,
    *,
    role: str,
    key: bytes,
    key_id: str,
) -> tuple[list[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    rows = list(
        database.execute(
            """
            SELECT filename, source_sha256, source_size_bytes,
                   chronological_order, collection_start, collection_end
            FROM source_members WHERE experiment_role = ?
            ORDER BY chronological_order
            """,
            (role,),
        )
    )
    if len(rows) != EXPECTED_MEMBER_COUNTS[role]:
        raise SelectedSafeCorpusError(
            f"all frozen {role} members must be ingested before safe export"
        )
    receipts: list[Dict[str, Any]] = []
    by_filename: Dict[str, Dict[str, Any]] = {}
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


def _historical_id(raw_session_id: str) -> str:
    digest = hashlib.sha256(
        f"{HISTORICAL_DATASET_SOURCE}\0{raw_session_id}".encode()
    ).hexdigest()
    return f"external-{digest[:24]}"


def _load_historical_membership(path: Path) -> tuple[Dict[str, str], str]:
    membership: Dict[str, str] = {}
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for raw_line in handle:
                digest.update(raw_line)
                value = json.loads(raw_line)
                if not isinstance(value, dict):
                    raise SelectedSafeCorpusError(
                        "historical membership row must be an object"
                    )
                session_id = _clean(value.get("session_id"))
                split = _clean(value.get("split"))
                if (
                    not session_id
                    or split not in {"train", "calibration", "test"}
                    or session_id in membership
                ):
                    raise SelectedSafeCorpusError(
                        "historical membership is invalid or duplicated"
                    )
                membership[session_id] = split
    except (OSError, json.JSONDecodeError) as exc:
        raise SelectedSafeCorpusError(
            "historical membership cannot be verified"
        ) from exc
    if not membership:
        raise SelectedSafeCorpusError("historical membership is empty")
    return membership, digest.hexdigest()


def _private_session_result(
    database: sqlite3.Connection,
    row: Sequence[Any],
    *,
    source_receipt: Mapping[str, Any],
    key: bytes,
    key_id: str,
) -> Dict[str, Any]:
    raw_session_id = str(row[0])
    source_member = str(row[1])
    first_seen = str(row[2])
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
            FROM context_events WHERE raw_session_id = ?
            ORDER BY event_time, source_line
            """,
            (raw_session_id,),
        )
    )
    contexts = _context_at_commands(
        command_rows, context_rows, session_start=first_seen
    )
    groups: list[Dict[str, Any]] = []
    for event_order, (command_row, context) in enumerate(
        zip(command_rows, contexts, strict=True), start=1
    ):
        labels = json.loads(str(command_row[3]))
        if not labels:
            continue
        source_line = int(command_row[0])
        occurrence_labels = []
        for label_index, raw_label in enumerate(labels):
            label = dict(raw_label)
            label["evidence_ref"] = (
                f"{source_member}:{source_line}:label:{label_index}"
            )
            occurrence_labels.append(label)
        groups.append(
            {
                "group_id": f"{source_member}:{source_line}",
                "event_order": event_order,
                "observed_at": str(command_row[1]),
                "labels": occurrence_labels,
                "session_context": context,
            }
        )
    if not groups:
        # The adapter needs a non-empty private group list.  Sessions with no
        # representable classifier output are omitted and counted separately.
        return {
            "safe_session": None,
            "reconciliation": {
                "private_group_count": 0,
                "safe_trusted_group_count": 0,
                "audit_only_group_count": 0,
                "private_label_count": 0,
                "trusted_label_count": 0,
                "audit_only_label_count": 0,
            },
        }
    return build_privacy_safe_session(
        {
            "session_id": raw_session_id,
            "protocol": str(row[4]),
            "status": "closed",
            "configuration_id": str(row[5]) or "unknown",
            "observation_groups": groups,
        },
        source_receipt,
        pseudonymization_key=key,
        pseudonymization_key_id=key_id,
    )


def _role_pipeline_reconciliation(
    database: sqlite3.Connection,
    *,
    role: str,
    built_session_count: int,
    safe_session_count: int,
    example_count: int,
) -> Dict[str, Any]:
    """Reconcile source receipts, stored occurrences, and public outputs."""

    source_stats = [
        json.loads(str(row[0]))
        for row in database.execute(
            "SELECT stats_json FROM source_members "
            "WHERE experiment_role = ?",
            (role,),
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
        database.execute(
            """
            SELECT COUNT(*)
            FROM command_events AS events
            JOIN source_members AS members
              ON members.filename = events.source_member
            WHERE members.experiment_role = ?
            """,
            (role,),
        ).fetchone()[0]
    )
    if nonempty_command_events != stored_command_events:
        raise SelectedSafeCorpusError(
            "source and private-store command occurrences do not reconcile"
        )

    occurrence_counts: Counter[str] = Counter()
    unrepresented_occurrences: Counter[str] = Counter()
    rows = database.execute(
        """
        SELECT labels.labels_json, labels.unrepresented_json, COUNT(*)
        FROM command_events AS events
        JOIN source_members AS members
          ON members.filename = events.source_member
        JOIN command_labels AS labels
          ON labels.command = events.command
        WHERE members.experiment_role = ?
        GROUP BY labels.labels_json, labels.unrepresented_json
        """,
        (role,),
    )
    for labels_json, unrepresented_json, occurrence_count in rows:
        labels = json.loads(str(labels_json))
        unrepresented = json.loads(str(unrepresented_json))
        count = int(occurrence_count)
        if labels and any(
            label.get("trust_tier") == "trusted_observation"
            for label in labels
        ):
            occurrence_counts["groups_with_trusted_label"] += count
        elif labels:
            occurrence_counts["groups_with_audit_only_labels"] += count
        else:
            occurrence_counts["groups_without_representable_labels"] += count
        for reason, reason_count in unrepresented.items():
            unrepresented_occurrences[str(reason)] += int(reason_count) * count
    if sum(occurrence_counts.values()) != stored_command_events:
        raise SelectedSafeCorpusError(
            "classified command occurrences do not reconcile"
        )
    eligible_sessions = int(
        database.execute(
            """
            SELECT COUNT(*) FROM sessions AS sessions
            WHERE sessions.experiment_role = ?
              AND sessions.source_cohort = ?
              AND sessions.protocol = 'ssh'
              AND sessions.connected = 1
              AND sessions.closed = 1
              AND NOT EXISTS (
                  SELECT 1 FROM quarantined_sessions AS quarantine
                  WHERE quarantine.raw_session_id = sessions.raw_session_id
              )
            """,
            (role, ROLE_TO_COHORT[role]),
        ).fetchone()[0]
    )
    if eligible_sessions != built_session_count:
        raise SelectedSafeCorpusError(
            "eligible and processed session counts do not reconcile"
        )
    return {
        "raw_event_records": raw_event_records,
        "raw_command_input_events": raw_command_inputs,
        "empty_command_input_events": (
            raw_command_inputs - nonempty_command_events
        ),
        "nonempty_command_events": nonempty_command_events,
        "private_store_command_events": stored_command_events,
        **dict(sorted(occurrence_counts.items())),
        "unrepresented_output_occurrences_by_reason": dict(
            sorted(unrepresented_occurrences.items())
        ),
        "eligible_complete_nonquarantined_sessions": eligible_sessions,
        "private_sessions_entering_safe_adapter": built_session_count,
        "privacy_safe_sessions_emitted": safe_session_count,
        "sessions_dropped_without_trusted_behavior": (
            built_session_count - safe_session_count
        ),
        "next_behavior_examples_emitted": example_count,
        "partial_or_quarantined_sessions_emitted": 0,
    }


def _scan_public_value(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _clean(key).lower() in _FORBIDDEN_PUBLIC_FIELDS:
                raise SelectedSafeCorpusError(
                    f"public output contains forbidden field at {path}.{key}"
                )
            _scan_public_value(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_public_value(child, path=f"{path}[{index}]")


def _membership_sha256(values: Iterable[str]) -> str:
    normalized = sorted({_clean(value) for value in values if _clean(value)})
    return hashlib.sha256(stable_json(normalized).encode()).hexdigest()


def _load_json_object(path: Path, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SelectedSafeCorpusError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise SelectedSafeCorpusError(f"{label} must be an object")
    return dict(value)


def _require_role_build_receipt_shape(
    value: Any,
    *,
    expected_purpose: str,
    allow_final: bool,
) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SelectedSafeCorpusError(
            "selected role build receipt fields are invalid"
        )
    receipt = dict(value)
    schema_version = receipt.get("schema_version")
    if schema_version == SAFE_BUILD_RECEIPT_SCHEMA_VERSION:
        expected_fields = _BUILD_RECEIPT_FIELDS
    elif schema_version == LEGACY_SAFE_BUILD_RECEIPT_SCHEMA_VERSION:
        expected_fields = _LEGACY_BUILD_RECEIPT_FIELDS
    else:
        raise SelectedSafeCorpusError(
            "selected role build receipt schema is invalid"
        )
    if set(receipt) != expected_fields:
        raise SelectedSafeCorpusError(
            "selected role build receipt fields are invalid"
        )
    if receipt.get("status") != "role_safe_corpus_built":
        raise SelectedSafeCorpusError(
            "selected role safe corpus is incomplete"
        )
    role = PURPOSE_TO_ROLE.get(expected_purpose)
    if role is None or receipt.get("purpose") != expected_purpose or (
        receipt.get("role") != role
    ):
        raise SelectedSafeCorpusError(
            "selected role build receipt purpose is inconsistent"
        )
    if role == "test" and not allow_final:
        raise SelectedSafeCorpusError(
            "training artifact verification cannot accept final-test artifacts"
        )
    if receipt.get("source_cohort") != ROLE_TO_COHORT[role]:
        raise SelectedSafeCorpusError(
            "selected role build receipt cohort is inconsistent"
        )
    preparation_gate = receipt.get("final_preparation_gate")
    if role == "test":
        if (
            schema_version == SAFE_BUILD_RECEIPT_SCHEMA_VERSION
            and isinstance(preparation_gate, Mapping)
            and preparation_gate.get("schema_version")
            == FINAL_PREPARATION_GENERATION_SCHEMA_VERSION
        ):
            try:
                generation = require_final_preparation_generation_receipt(
                    preparation_gate
                )
            except SelectedCorpusBuildError as exc:
                raise SelectedSafeCorpusError(
                    "final v3 role preparation generation is invalid"
                ) from exc
            if generation["code_commit"] != receipt["code_commit"]:
                raise SelectedSafeCorpusError(
                    "final v3 role preparation commit is inconsistent"
                )
        else:
            if (
                not isinstance(preparation_gate, Mapping)
                or set(preparation_gate) != FINAL_PREPARATION_FIELDS
                or preparation_gate.get("schema_version")
                != FINAL_PREPARATION_SCHEMA_VERSION
                or preparation_gate.get("status")
                != "frozen_for_blinded_preparation"
                or preparation_gate.get("purpose") != "prepare_final_corpus"
                or preparation_gate.get("evaluation_opened") is not False
            ):
                raise SelectedSafeCorpusError(
                    "final role preparation evidence is invalid"
                )
            gate_identity = dict(preparation_gate)
            gate_receipt_id = gate_identity.pop("receipt_id", None)
            if gate_receipt_id != stable_id(
                "nextbehaviorfinalpreparation", gate_identity
            ):
                raise SelectedSafeCorpusError(
                    "final role preparation identity is invalid"
                )
    elif preparation_gate != {"status": "not_applicable"}:
        raise SelectedSafeCorpusError(
            "development role cannot contain a final preparation gate"
        )
    for field in (
        "code_commit",
        "source_selection_sha256",
        "classifier_manifest_sha256",
        "preprocessing_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "classification_checkpoint_sha256",
        "label_adapter_sha256",
        "safe_builder_sha256",
        "source_receipts_artifact_sha256",
        "corpus_receipt_artifact_sha256",
    ):
        if field == "code_commit":
            if not re.fullmatch(r"[0-9a-f]{40}", _clean(receipt.get(field))):
                raise SelectedSafeCorpusError(
                    "selected role code_commit is invalid"
                )
        else:
            _require_sha256(receipt.get(field), field)
    for field in ("safe_sessions", "examples"):
        item = receipt.get(field)
        if not isinstance(item, Mapping) or set(item) != (
            _PAYLOAD_RECEIPT_FIELDS
        ):
            raise SelectedSafeCorpusError(
                f"selected role {field} receipt is invalid"
            )
        for count_field in ("line_count", "size_bytes"):
            count = item.get(count_field)
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                raise SelectedSafeCorpusError(
                    f"selected role {field}.{count_field} is invalid"
                )
        _require_sha256(item.get("sha256"), f"{field}.sha256")
    membership = receipt.get("membership")
    if not isinstance(membership, Mapping) or set(membership) != (
        _MEMBERSHIP_FIELDS
    ):
        raise SelectedSafeCorpusError(
            "selected role membership receipt is invalid"
        )
    for field in _MEMBERSHIP_FIELDS:
        if field.endswith("_count"):
            count = membership.get(field)
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                raise SelectedSafeCorpusError(
                    f"selected role membership.{field} is invalid"
                )
        else:
            _require_sha256(
                membership.get(field), f"membership.{field}"
            )
    if schema_version == SAFE_BUILD_RECEIPT_SCHEMA_VERSION:
        evidence = receipt.get("historical_split_evidence")
        if (
            not isinstance(evidence, Mapping)
            or set(evidence) != _HISTORICAL_SPLIT_EVIDENCE_RECEIPT_FIELDS
            or evidence.get("schema_version")
            != HISTORICAL_SPLIT_EVIDENCE_SCHEMA_VERSION
            or evidence.get("status")
            != "historical_split_evidence_complete"
        ):
            raise SelectedSafeCorpusError(
                "selected role historical split evidence receipt is invalid"
            )
        record_count = evidence.get("record_count")
        if (
            isinstance(record_count, bool)
            or not isinstance(record_count, int)
            or record_count < 0
        ):
            raise SelectedSafeCorpusError(
                "selected role historical split evidence count is invalid"
            )
        _require_sha256(
            evidence.get("artifact_sha256"),
            "historical_split_evidence.artifact_sha256",
        )
        _require_sha256(
            evidence.get("session_membership_sha256"),
            "historical_split_evidence.session_membership_sha256",
        )
    identity = dict(receipt)
    identity.pop("build_receipt_id", None)
    if stable_id("nextbehaviorselectedsafebuild", identity) != receipt.get(
        "build_receipt_id"
    ):
        raise SelectedSafeCorpusError(
            "selected role build receipt identity is invalid"
        )
    return receipt


def verify_selected_role_artifacts(
    *,
    build_receipt_path: Path,
    safe_sessions_path: Path,
    examples_path: Path,
    source_receipts_path: Path,
    corpus_receipt_path: Path,
    expected_purpose: str,
    historical_split_evidence_path: Path | None = None,
    allow_final: bool = False,
) -> Dict[str, Any]:
    """Verify one exact role bundle before any training/evaluation load.

    Training callers leave ``allow_final`` false, so a test path or receipt is
    rejected even if every hash is otherwise valid.  The final evaluator may
    opt in only after its separate pre-test gate has succeeded.
    """

    receipt = _require_role_build_receipt_shape(
        _load_json_object(build_receipt_path, "build receipt"),
        expected_purpose=expected_purpose,
        allow_final=allow_final,
    )
    requires_historical_evidence = (
        receipt["schema_version"] == SAFE_BUILD_RECEIPT_SCHEMA_VERSION
    )
    if requires_historical_evidence and historical_split_evidence_path is None:
        raise SelectedSafeCorpusError(
            "selected role historical split evidence is missing"
        )
    if (
        historical_split_evidence_path is not None
        and not requires_historical_evidence
    ):
        raise SelectedSafeCorpusError(
            "legacy selected role receipt cannot bind historical split evidence"
        )
    for path, field in (
        (safe_sessions_path, "safe_sessions"),
        (examples_path, "examples"),
    ):
        if not path.is_file() or path.is_symlink():
            raise SelectedSafeCorpusError(
                f"selected role {field} payload is missing or unsafe"
            )
        if (
            path.stat().st_size != receipt[field]["size_bytes"]
            or _sha256_file(path) != receipt[field]["sha256"]
        ):
            raise SelectedSafeCorpusError(
                f"selected role {field} payload identity mismatch"
            )
    if (
        _sha256_file(source_receipts_path)
        != receipt["source_receipts_artifact_sha256"]
    ):
        raise SelectedSafeCorpusError(
            "selected role source receipts identity mismatch"
        )
    if (
        _sha256_file(corpus_receipt_path)
        != receipt["corpus_receipt_artifact_sha256"]
    ):
        raise SelectedSafeCorpusError(
            "selected role corpus receipt identity mismatch"
        )
    source_receipts = _load_json_object(
        source_receipts_path, "source receipts"
    )
    if (
        source_receipts.get("schema_version")
        != SOURCE_RECEIPTS_SCHEMA_VERSION
        or source_receipts.get("purpose") != expected_purpose
        or source_receipts.get("role") != receipt["role"]
        or source_receipts.get("source_selection_sha256")
        != receipt["source_selection_sha256"]
        or set(source_receipts)
        != {
            "schema_version",
            "source_selection_sha256",
            "purpose",
            "role",
            "members",
        }
    ):
        raise SelectedSafeCorpusError(
            "selected role source receipts are inconsistent"
        )
    raw_members = source_receipts.get("members")
    if not isinstance(raw_members, list):
        raise SelectedSafeCorpusError(
            "selected role source receipt members are invalid"
        )
    members = [
        require_valid_source_member_receipt(member) for member in raw_members
    ]
    member_ids = [str(member["member_id"]) for member in members]
    if len(member_ids) != len(set(member_ids)):
        raise SelectedSafeCorpusError(
            "selected role source member identity is duplicated"
        )

    corpus_receipt = require_valid_corpus_receipt(
        _load_json_object(corpus_receipt_path, "corpus receipt")
    )
    if corpus_receipt["receipt_id"] != receipt["corpus_receipt_id"]:
        raise SelectedSafeCorpusError(
            "selected role corpus receipt ID is inconsistent"
        )
    if (
        corpus_receipt["code_commit"] != receipt["code_commit"]
        or corpus_receipt["preprocessing_sha256"]
        != receipt["preprocessing_sha256"]
        or corpus_receipt["label_policy_sha256"]
        != receipt["label_policy_sha256"]
        or corpus_receipt["trust_policy_sha256"]
        != receipt["trust_policy_sha256"]
        or corpus_receipt["classification_checkpoint_sha256"]
        != receipt["classification_checkpoint_sha256"]
    ):
        raise SelectedSafeCorpusError(
            "selected role corpus policy provenance is inconsistent"
        )

    historical_evidence: Dict[str, Any] | None = None
    if historical_split_evidence_path is not None:
        if (
            not historical_split_evidence_path.is_file()
            or historical_split_evidence_path.is_symlink()
            or _sha256_file(historical_split_evidence_path)
            != receipt["historical_split_evidence"]["artifact_sha256"]
        ):
            raise SelectedSafeCorpusError(
                "selected role historical split evidence identity mismatch"
            )
        historical_evidence = _load_json_object(
            historical_split_evidence_path,
            "historical split evidence",
        )
        if (
            stable_json(historical_evidence) + "\n"
            != historical_split_evidence_path.read_text(encoding="utf-8")
            or set(historical_evidence)
            != {
                "schema_version",
                "status",
                "selected_safe_corpus_receipt_id",
                "source_selection_sha256",
                "records",
            }
            or historical_evidence.get("schema_version")
            != HISTORICAL_SPLIT_EVIDENCE_SCHEMA_VERSION
            or historical_evidence.get("status")
            != "historical_split_evidence_complete"
            or historical_evidence.get("selected_safe_corpus_receipt_id")
            != corpus_receipt["receipt_id"]
            or historical_evidence.get("source_selection_sha256")
            != receipt["source_selection_sha256"]
            or not isinstance(historical_evidence.get("records"), list)
        ):
            raise SelectedSafeCorpusError(
                "selected role historical split evidence is inconsistent"
            )

    session_ids: list[str] = []
    seen_member_ids: set[str] = set()
    example_ids: list[str] = []
    input_hashes: list[str] = []
    example_line_count = 0
    try:
        with (
            safe_sessions_path.open("r", encoding="utf-8") as session_handle,
            examples_path.open("r", encoding="utf-8") as example_handle,
        ):
            for session_line in session_handle:
                session = json.loads(session_line)
                if stable_json(session) + "\n" != session_line:
                    raise SelectedSafeCorpusError(
                        "selected role safe session is not canonical JSONL"
                    )
                session = require_valid_next_behavior_session(session)
                _scan_public_value(session)
                session_ids.append(str(session["session_id"]))
                seen_member_ids.add(str(session["source_member_id"]))
                for expected in build_next_behavior_examples(
                    session,
                    max_sequence_length=receipt["max_sequence_length"],
                ):
                    line = example_handle.readline()
                    if not line:
                        raise SelectedSafeCorpusError(
                            "selected role examples end before reconstruction"
                        )
                    actual = json.loads(line)
                    if stable_json(actual) + "\n" != line or actual != expected:
                        raise SelectedSafeCorpusError(
                            "selected role example differs from reconstruction"
                        )
                    _scan_public_value(actual)
                    example_ids.append(str(actual["example_id"]))
                    input_hashes.append(
                        str(actual["model_input"]["input_hash"])
                    )
                    example_line_count += 1
            if example_handle.readline():
                raise SelectedSafeCorpusError(
                    "selected role examples contain unreconstructed rows"
                )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, SelectedSafeCorpusError):
            raise
        raise SelectedSafeCorpusError(
            "selected role payload validation failed"
        ) from exc
    if len(session_ids) != len(set(session_ids)) or len(example_ids) != len(
        set(example_ids)
    ):
        raise SelectedSafeCorpusError(
            "selected role payload membership is duplicated"
        )
    if seen_member_ids != set(member_ids):
        raise SelectedSafeCorpusError(
            "selected role safe sessions do not cover exact source membership"
        )
    actual_membership = {
        "source_member_count": len(member_ids),
        "source_member_membership_sha256": _membership_sha256(member_ids),
        "session_count": len(session_ids),
        "session_membership_sha256": _membership_sha256(session_ids),
        "example_count": len(example_ids),
        "example_membership_sha256": _membership_sha256(example_ids),
        "input_count": len(input_hashes),
        "input_membership_sha256": _membership_sha256(input_hashes),
    }
    if actual_membership != receipt["membership"]:
        raise SelectedSafeCorpusError(
            "selected role payload membership hashes are inconsistent"
        )
    if (
        len(session_ids) != receipt["safe_sessions"]["line_count"]
        or example_line_count != receipt["examples"]["line_count"]
    ):
        raise SelectedSafeCorpusError(
            "selected role payload line counts are inconsistent"
        )
    if historical_evidence is not None:
        records = historical_evidence["records"]
        # The safe payload is the authority for the public identifiers; keep
        # only the split as sidecar-owned evidence and require every other
        # field to bind exactly to that payload.
        safe_by_session: Dict[str, Dict[str, Any]] = {}
        try:
            with safe_sessions_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    session = json.loads(line)
                    safe_by_session[str(session["session_id"])] = session
        except (OSError, json.JSONDecodeError) as exc:
            raise SelectedSafeCorpusError(
                "selected role safe sessions cannot bind historical evidence"
            ) from exc
        expected_records = []
        for record in records:
            if (
                not isinstance(record, Mapping)
                or set(record)
                != {
                    "session_id",
                    "source_member_id",
                    "source_member_sha256",
                    "historical_split",
                }
                or _clean(record.get("historical_split"))
                not in {"train", "calibration", "test", "not_present"}
            ):
                raise SelectedSafeCorpusError(
                    "selected role historical split evidence record is invalid"
                )
            session_id = _clean(record.get("session_id"))
            session = safe_by_session.get(session_id)
            if (
                session is None
                or _clean(record.get("source_member_id"))
                != session["source_member_id"]
                or _clean(record.get("source_member_sha256")).lower()
                != session["source_member_sha256"]
            ):
                raise SelectedSafeCorpusError(
                    "selected role historical split evidence binding is inconsistent"
                )
            expected_records.append(dict(record))
        if (
            len(expected_records) != len(safe_by_session)
            or [record["session_id"] for record in expected_records]
            != sorted(safe_by_session)
            or len({record["session_id"] for record in expected_records})
            != len(expected_records)
            or _membership_sha256(record["session_id"] for record in expected_records)
            != receipt["historical_split_evidence"]["session_membership_sha256"]
            or len(expected_records)
            != receipt["historical_split_evidence"]["record_count"]
        ):
            raise SelectedSafeCorpusError(
                "selected role historical split evidence coverage is inconsistent"
            )
    return {
        "status": "selected_role_artifacts_verified",
        "purpose": expected_purpose,
        "role": receipt["role"],
        "build_receipt_id": receipt["build_receipt_id"],
        "code_commit": receipt["code_commit"],
        "source_selection_sha256": receipt["source_selection_sha256"],
        "classifier_manifest_sha256": receipt[
            "classifier_manifest_sha256"
        ],
        "preprocessing_sha256": receipt["preprocessing_sha256"],
        "label_policy_sha256": receipt["label_policy_sha256"],
        "trust_policy_sha256": receipt["trust_policy_sha256"],
        "classification_checkpoint_sha256": receipt[
            "classification_checkpoint_sha256"
        ],
        "membership": actual_membership,
    }


def _canonical_generation_output_paths(
    *,
    safe_sessions_path: Path,
    examples_path: Path,
    source_receipts_path: Path,
    corpus_receipt_path: Path,
    build_receipt_path: Path,
    historical_split_evidence_path: Path,
) -> Dict[str, str]:
    paths = {
        "safe_sessions": safe_sessions_path,
        "examples": examples_path,
        "source_receipts": source_receipts_path,
        "corpus_receipt": corpus_receipt_path,
        "build_receipt": build_receipt_path,
        "historical_split_evidence": historical_split_evidence_path,
    }
    canonical = {
        label: str(path.resolve(strict=False))
        for label, path in paths.items()
    }
    if (
        set(canonical) != _GENERATION_OUTPUT_FIELDS
        or len(set(canonical.values())) != len(canonical)
    ):
        raise SelectedSafeCorpusError(
            "v3 output authorization paths are duplicated or incomplete"
        )
    return canonical


def _store_snapshot_hmac_sha256(
    database: sqlite3.Connection,
    *,
    pseudonymization_key: bytes,
    progress: Callable[[str, int], None] | None = None,
) -> str:
    """Authenticate all final source, membership, event, and label state."""

    digest = hmac.new(
        pseudonymization_key,
        b"next-behavior-final-store-snapshot.v1\0",
        hashlib.sha256,
    )
    queries = (
        (
            "metadata",
            """
            SELECT key, value FROM metadata
            WHERE key IN (
                'store_schema_version',
                'source_selection_sha256',
                'final_corpus_prepared_at',
                'final_corpus_preparation_receipt_id',
                'final_corpus_preparation_receipt_json'
            )
            ORDER BY key
            """,
        ),
        (
            "source_members",
            """
            SELECT filename, source_sha256, source_size_bytes, archive_crc32,
                   chronological_order, source_cohort, experiment_role,
                   collection_start, collection_end, stats_json
            FROM source_members WHERE experiment_role = 'test'
            ORDER BY chronological_order
            """,
        ),
        (
            "sessions",
            """
            SELECT raw_session_id, source_member, source_cohort,
                   experiment_role, first_seen, last_seen, protocol,
                   configuration, connected, closed, cross_member, cross_role
            FROM sessions WHERE experiment_role = 'test'
            ORDER BY raw_session_id
            """,
        ),
        (
            "session_sources",
            """
            SELECT raw_session_id, source_member, source_cohort,
                   experiment_role, chronological_order, first_seen,
                   last_seen, protocol, configuration, connected, closed
            FROM session_sources WHERE experiment_role = 'test'
            ORDER BY raw_session_id, source_member
            """,
        ),
        (
            "command_events",
            """
            SELECT events.source_member, events.source_line,
                   events.raw_session_id, events.event_time, events.command
            FROM command_events AS events
            JOIN source_members AS members
              ON members.filename = events.source_member
            WHERE members.experiment_role = 'test'
            ORDER BY events.source_member, events.source_line
            """,
        ),
        (
            "context_events",
            """
            SELECT events.source_member, events.source_line,
                   events.raw_session_id, events.event_time, events.event_type
            FROM context_events AS events
            JOIN source_members AS members
              ON members.filename = events.source_member
            WHERE members.experiment_role = 'test'
            ORDER BY events.source_member, events.source_line
            """,
        ),
        (
            "quarantine",
            """
            SELECT q.raw_session_id, q.reason, q.source_members_json,
                   q.experiment_roles_json
            FROM quarantined_sessions AS q
            ORDER BY q.raw_session_id
            """,
        ),
        (
            "command_labels",
            """
            SELECT labels.command, labels.labels_json,
                   labels.unrepresented_json, labels.cache_receipt_id
            FROM command_labels AS labels
            ORDER BY labels.command
            """,
        ),
    )
    test_session_ids: set[str] = set()
    test_commands: set[str] = set()
    for table, query in queries:
        digest.update(table.encode())
        digest.update(b"\0")
        count = 0
        for row in database.execute(query):
            if table == "quarantine" and str(row[0]) not in test_session_ids:
                continue
            if table == "command_labels" and str(row[0]) not in test_commands:
                continue
            digest.update(stable_json(list(row)).encode())
            digest.update(b"\n")
            count += 1
            if table == "session_sources":
                test_session_ids.add(str(row[0]))
            elif table == "command_events":
                test_commands.add(str(row[4]))
        digest.update(str(count).encode())
        digest.update(b"\0")
        if progress is not None:
            progress(table, count)
    return digest.hexdigest()


def _final_store_membership(
    database: sqlite3.Connection,
    *,
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
    max_sequence_length: int,
) -> Dict[str, Any]:
    """Reconstruct only membership identities for compatibility checking."""

    source_receipts, receipts_by_filename = _source_receipts_for_role(
        database,
        role="test",
        key=pseudonymization_key,
        key_id=pseudonymization_key_id,
    )
    source_member_ids = [
        str(receipt["member_id"]) for receipt in source_receipts
    ]
    session_ids: list[str] = []
    example_ids: list[str] = []
    input_hashes: list[str] = []
    safe_member_ids: set[str] = set()
    rows = database.execute(
        """
        SELECT s.raw_session_id, s.source_member, s.first_seen,
               s.last_seen, s.protocol, s.configuration
        FROM sessions AS s
        WHERE s.experiment_role = 'test'
          AND s.source_cohort = 'final'
          AND s.protocol = 'ssh'
          AND s.connected = 1
          AND s.closed = 1
          AND NOT EXISTS (
              SELECT 1 FROM quarantined_sessions AS q
              WHERE q.raw_session_id = s.raw_session_id
          )
        ORDER BY s.first_seen, s.raw_session_id
        """
    )
    for row in rows:
        result = _private_session_result(
            database,
            row,
            source_receipt=receipts_by_filename[str(row[1])],
            key=pseudonymization_key,
            key_id=pseudonymization_key_id,
        )
        safe = result["safe_session"]
        if safe is None:
            continue
        session_ids.append(str(safe["session_id"]))
        safe_member_ids.add(str(safe["source_member_id"]))
        for example in build_next_behavior_examples(
            safe, max_sequence_length=max_sequence_length
        ):
            example_ids.append(str(example["example_id"]))
            input_hashes.append(str(example["model_input"]["input_hash"]))
    if (
        safe_member_ids != set(source_member_ids)
        or len(session_ids) != len(set(session_ids))
        or len(example_ids) != len(set(example_ids))
    ):
        raise SelectedSafeCorpusError(
            "final store membership is incomplete or duplicated"
        )
    return {
        "source_member_count": len(source_member_ids),
        "source_member_membership_sha256": _membership_sha256(
            source_member_ids
        ),
        "session_count": len(session_ids),
        "session_membership_sha256": _membership_sha256(session_ids),
        "example_count": len(example_ids),
        "example_membership_sha256": _membership_sha256(example_ids),
        "input_count": len(input_hashes),
        "input_membership_sha256": _membership_sha256(input_hashes),
    }


def _generation_compatibility_fields(
    receipt: Mapping[str, Any],
) -> Dict[str, Any]:
    ignored = {
        "generation_id",
        "generation_number",
        "predecessor_generation_id",
    }
    return {
        key: value for key, value in receipt.items() if key not in ignored
    }


def migrate_final_preparation_generation(
    *,
    private_database_path: Path,
    preparation_receipt: Mapping[str, Any],
    predecessor_build_receipt_path: Path,
    predecessor_safe_sessions_path: Path,
    predecessor_examples_path: Path,
    predecessor_source_receipts_path: Path,
    predecessor_corpus_receipt_path: Path,
    classifier_manifest_path: Path,
    preprocessing_manifest_path: Path,
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
    safe_sessions_path: Path,
    examples_path: Path,
    source_receipts_path: Path,
    corpus_receipt_path: Path,
    build_receipt_path: Path,
    historical_split_evidence_path: Path,
    generation_receipt_path: Path,
    code_commit: str,
    repository_root: Path | None = None,
) -> Dict[str, Any]:
    """Authorize a fresh v3 generation from a verified immutable v2 bundle."""

    root = (
        Path(repository_root)
        if repository_root is not None
        else Path(__file__).resolve().parents[2]
    )
    commit = _require_repository_commit(root, code_commit)
    if (
        not isinstance(pseudonymization_key, bytes)
        or len(pseudonymization_key) < 32
    ):
        raise SelectedSafeCorpusError(
            "pseudonymization key must contain at least 32 bytes"
        )
    key_id = _clean(pseudonymization_key_id)
    target_paths = _canonical_generation_output_paths(
        safe_sessions_path=safe_sessions_path,
        examples_path=examples_path,
        source_receipts_path=source_receipts_path,
        corpus_receipt_path=corpus_receipt_path,
        build_receipt_path=build_receipt_path,
        historical_split_evidence_path=historical_split_evidence_path,
    )
    predecessor_paths = (
        predecessor_build_receipt_path,
        predecessor_safe_sessions_path,
        predecessor_examples_path,
        predecessor_source_receipts_path,
        predecessor_corpus_receipt_path,
    )
    if any(
        not path.is_file() or path.is_symlink() for path in predecessor_paths
    ):
        raise SelectedSafeCorpusError(
            "predecessor v2 artifact is missing or unsafe"
        )
    predecessor_canonical = {
        str(path.resolve(strict=True)) for path in predecessor_paths
    }
    if predecessor_canonical & set(target_paths.values()):
        raise SelectedSafeCorpusError(
            "v3 output paths cannot overwrite predecessor v2 artifacts"
        )
    if any(Path(path).exists() for path in target_paths.values()):
        raise SelectedSafeCorpusError(
            "authorized v3 output must be fresh"
        )
    generation_path_canonical = str(
        generation_receipt_path.resolve(strict=False)
    )
    if (
        generation_path_canonical in predecessor_canonical
        or generation_path_canonical in set(target_paths.values())
    ):
        raise SelectedSafeCorpusError(
            "generation receipt path aliases an artifact path"
        )
    try:
        manifest = load_classifier_manifest(classifier_manifest_path)
    except ValueError as exc:
        raise SelectedSafeCorpusError(str(exc)) from exc
    manifest_sha256 = _sha256_file(classifier_manifest_path)
    preprocessing_sha256 = _sha256_file(preprocessing_manifest_path)
    policy = manifest["classification_policy"]
    current_preparation = _require_final_preparation_receipt(
        preparation_receipt,
        code_commit=commit,
        classifier_manifest=manifest,
        classifier_manifest_sha256=manifest_sha256,
        preprocessing_sha256=preprocessing_sha256,
        pseudonymization_key_id=key_id,
    )
    predecessor_receipt = _require_role_build_receipt_shape(
        _load_json_object(
            predecessor_build_receipt_path,
            "predecessor v2 build receipt",
        ),
        expected_purpose="final_evaluation",
        allow_final=True,
    )
    if predecessor_receipt["schema_version"] != (
        LEGACY_SAFE_BUILD_RECEIPT_SCHEMA_VERSION
    ):
        raise SelectedSafeCorpusError(
            "predecessor must be an exact legacy v2 generation"
        )
    predecessor_verification = verify_selected_role_artifacts(
        build_receipt_path=predecessor_build_receipt_path,
        safe_sessions_path=predecessor_safe_sessions_path,
        examples_path=predecessor_examples_path,
        source_receipts_path=predecessor_source_receipts_path,
        corpus_receipt_path=predecessor_corpus_receipt_path,
        expected_purpose="final_evaluation",
        allow_final=True,
    )
    expected_bindings = {
        "classifier_manifest_sha256": manifest_sha256,
        "preprocessing_sha256": preprocessing_sha256,
        "label_policy_sha256": policy["rule_policy_sha256"],
        "trust_policy_sha256": policy["trust_policy_sha256"],
        "classification_checkpoint_sha256": manifest["classifier"][
            "checkpoint_sha256"
        ],
        "pseudonymization_key_id": key_id,
    }
    for field, expected in expected_bindings.items():
        if predecessor_receipt.get(field) != expected:
            raise SelectedSafeCorpusError(
                f"predecessor v2 {field} is incompatible"
            )
    predecessor_gate = predecessor_receipt["final_preparation_gate"]
    immutable_gate_bindings = {
        "classifier_manifest_sha256": manifest_sha256,
        "classifier_adapter_sha256": manifest["classifier"][
            "adapter_sha256"
        ],
        "classification_pipeline_sha256": manifest["classifier"][
            "pipeline_sha256"
        ],
        "preprocessing_sha256": preprocessing_sha256,
        "environment_lock_sha256": manifest["dependency_lock"]["sha256"],
        "label_policy_sha256": policy["rule_policy_sha256"],
        "trust_policy_sha256": policy["trust_policy_sha256"],
        "mitre_cache_sha256": policy["mitre_cache_sha256"],
        "classification_checkpoint_sha256": manifest["classifier"][
            "checkpoint_sha256"
        ],
        "pseudonymization_key_id": key_id,
    }
    for field, expected in immutable_gate_bindings.items():
        if predecessor_gate.get(field) != expected:
            raise SelectedSafeCorpusError(
                f"legacy preparation {field} is incompatible"
            )
    for field in (
        "source_selection_id",
        "source_selection_sha256",
        "final_source_member_count",
        "final_source_member_receipts_sha256",
        "classifier_manifest_sha256",
        "classifier_adapter_sha256",
        "classification_pipeline_sha256",
        "preprocessing_sha256",
        "environment_lock_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "mitre_cache_sha256",
        "classification_checkpoint_sha256",
        "pseudonymization_key_id",
    ):
        if current_preparation.get(field) != predecessor_gate.get(field):
            raise SelectedSafeCorpusError(
                f"current preparation {field} is incompatible with predecessor"
            )

    database = open_selected_database(private_database_path)
    try:
        legacy_marker = _legacy_preparation_marker(database)
        if legacy_marker != predecessor_gate:
            raise SelectedSafeCorpusError(
                "predecessor v2 does not match preserved store marker"
            )
        selection = database.execute(
            "SELECT value FROM metadata WHERE key = 'source_selection_sha256'"
        ).fetchone()
        if (
            selection is None
            or str(selection[0]) != predecessor_receipt[
                "source_selection_sha256"
            ]
            or str(selection[0]) != predecessor_gate[
                "source_selection_sha256"
            ]
        ):
            raise SelectedSafeCorpusError(
                "predecessor source selection is incompatible with store"
            )
        final_members = [
            {
                "filename": str(row[0]),
                "source_sha256": str(row[1]),
                "source_size_bytes": int(row[2]),
                "archive_crc32": str(row[3]),
                "chronological_order": int(row[4]),
                "source_cohort": str(row[5]),
                "experiment_role": str(row[6]),
            }
            for row in database.execute(
                """
                SELECT filename, source_sha256, source_size_bytes,
                       archive_crc32, chronological_order, source_cohort,
                       experiment_role
                FROM source_members WHERE experiment_role = 'test'
                ORDER BY chronological_order
                """
            )
        ]
        member_receipts_sha256 = final_member_receipts_sha256(final_members)
        if member_receipts_sha256 != predecessor_gate[
            "final_source_member_receipts_sha256"
        ]:
            raise SelectedSafeCorpusError(
                "predecessor source membership is incompatible with store"
            )
        classified = _validate_all_cached_rows(database, manifest)
        unique_commands = int(
            database.execute(
                "SELECT COUNT(DISTINCT command) FROM command_events"
            ).fetchone()[0]
        )
        if classified != unique_commands:
            raise SelectedSafeCorpusError(
                "predecessor classification state is incomplete"
            )
        membership = _final_store_membership(
            database,
            pseudonymization_key=pseudonymization_key,
            pseudonymization_key_id=key_id,
            max_sequence_length=predecessor_receipt[
                "max_sequence_length"
            ],
        )
        if membership != predecessor_verification["membership"]:
            raise SelectedSafeCorpusError(
                "predecessor membership is incompatible with store"
            )
        store_snapshot = _store_snapshot_hmac_sha256(
            database,
            pseudonymization_key=pseudonymization_key,
            progress=lambda table, count: print(
                stable_json(
                    {
                        "stage": "final_store_snapshot",
                        "table": table,
                        "row_count": count,
                    }
                ),
                flush=True,
            ),
        )
        history = _validated_generation_history(database)
    except (sqlite3.Error, SelectedCorpusBuildError) as exc:
        if isinstance(exc, SelectedSafeCorpusError):
            raise
        raise SelectedSafeCorpusError(str(exc)) from exc
    finally:
        database.close()

    base: Dict[str, Any] = {
        "schema_version": FINAL_PREPARATION_GENERATION_SCHEMA_VERSION,
        "status": "compatible_generation_recorded",
        "purpose": "authorize_selected_safe_build_v3",
        "target_safe_build_schema_version": SAFE_BUILD_RECEIPT_SCHEMA_VERSION,
        "code_commit": commit,
        "predecessor_build_receipt_id": predecessor_receipt[
            "build_receipt_id"
        ],
        "predecessor_build_receipt_sha256": _sha256_file(
            predecessor_build_receipt_path
        ),
        "predecessor_build_schema_version": (
            LEGACY_SAFE_BUILD_RECEIPT_SCHEMA_VERSION
        ),
        "legacy_preparation_receipt_id": legacy_marker["receipt_id"],
        "legacy_preparation_receipt_sha256": hashlib.sha256(
            stable_json(legacy_marker).encode()
        ).hexdigest(),
        "preparation_receipt_id": current_preparation["receipt_id"],
        "preparation_receipt_sha256": hashlib.sha256(
            stable_json(current_preparation).encode()
        ).hexdigest(),
        "source_selection_sha256": predecessor_receipt[
            "source_selection_sha256"
        ],
        "final_source_member_receipts_sha256": member_receipts_sha256,
        "classifier_manifest_sha256": manifest_sha256,
        "preprocessing_sha256": preprocessing_sha256,
        "label_policy_sha256": policy["rule_policy_sha256"],
        "trust_policy_sha256": policy["trust_policy_sha256"],
        "classification_checkpoint_sha256": manifest["classifier"][
            "checkpoint_sha256"
        ],
        "pseudonymization_key_id": key_id,
        "max_sequence_length": predecessor_receipt[
            "max_sequence_length"
        ],
        "membership": membership,
        "store_snapshot_hmac_sha256": store_snapshot,
        "authorized_output_paths": target_paths,
        "authorized_output_paths_sha256": hashlib.sha256(
            stable_json(target_paths).encode()
        ).hexdigest(),
    }
    receipt: Dict[str, Any] | None = None
    if history and _generation_compatibility_fields(history[-1]) == base:
        receipt = history[-1]
    if receipt is None:
        receipt = {
            **base,
            "generation_number": len(history) + 1,
            "predecessor_generation_id": (
                history[-1]["generation_id"] if history else None
            ),
        }
        receipt["generation_id"] = stable_id(
            "nextbehaviorfinalpreparationgeneration", receipt
        )
    require_final_preparation_generation_receipt(receipt)
    receipt_bytes = (stable_json(receipt) + "\n").encode()
    if generation_receipt_path.exists():
        if (
            not generation_receipt_path.is_file()
            or generation_receipt_path.is_symlink()
            or generation_receipt_path.read_bytes() != receipt_bytes
        ):
            raise SelectedSafeCorpusError(
                "generation receipt output exists with different provenance"
            )
    else:
        temporary = _write_temp(generation_receipt_path, receipt_bytes)
        try:
            _publish_no_overwrite({generation_receipt_path: temporary})
        finally:
            temporary.unlink(missing_ok=True)
    try:
        ledger = record_final_preparation_generation(
            private_database_path=private_database_path,
            generation_receipt=receipt,
        )
    except SelectedCorpusBuildError as exc:
        raise SelectedSafeCorpusError(str(exc)) from exc
    return {
        **receipt,
        "migration_status": ledger["status"],
        "generation_receipt_sha256": ledger["receipt_sha256"],
    }


def _require_final_preparation_generation(
    value: Any,
    *,
    database: sqlite3.Connection,
    code_commit: str,
    classifier_manifest: Mapping[str, Any],
    classifier_manifest_sha256: str,
    preprocessing_sha256: str,
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
    max_sequence_length: int,
    output_paths: Mapping[str, str],
) -> Dict[str, Any]:
    try:
        receipt = require_final_preparation_generation_marker(
            database, value
        )
    except SelectedCorpusBuildError as exc:
        raise SelectedSafeCorpusError(str(exc)) from exc
    policy = classifier_manifest["classification_policy"]
    bindings = {
        "code_commit": code_commit,
        "target_safe_build_schema_version": SAFE_BUILD_RECEIPT_SCHEMA_VERSION,
        "classifier_manifest_sha256": classifier_manifest_sha256,
        "preprocessing_sha256": preprocessing_sha256,
        "label_policy_sha256": policy["rule_policy_sha256"],
        "trust_policy_sha256": policy["trust_policy_sha256"],
        "classification_checkpoint_sha256": classifier_manifest["classifier"][
            "checkpoint_sha256"
        ],
        "pseudonymization_key_id": pseudonymization_key_id,
        "max_sequence_length": max_sequence_length,
        "authorized_output_paths": dict(output_paths),
    }
    for field, expected in bindings.items():
        if receipt.get(field) != expected:
            raise SelectedSafeCorpusError(
                f"final preparation generation {field} is inconsistent"
            )
    if _store_snapshot_hmac_sha256(
        database,
        pseudonymization_key=pseudonymization_key,
    ) != receipt["store_snapshot_hmac_sha256"]:
        raise SelectedSafeCorpusError(
            "final preparation generation store snapshot changed"
        )
    return receipt


def _require_final_preparation_receipt(
    value: Any,
    *,
    code_commit: str,
    classifier_manifest: Mapping[str, Any],
    classifier_manifest_sha256: str,
    preprocessing_sha256: str,
    pseudonymization_key_id: str,
) -> Dict[str, Any]:
    """Verify the blinded-preparation receipt before private-store access."""

    if not isinstance(value, Mapping) or set(value) != (
        FINAL_PREPARATION_FIELDS
    ):
        raise SelectedSafeCorpusError(
            "final corpus preparation receipt fields are invalid"
        )
    receipt = dict(value)
    if (
        receipt.get("schema_version") != FINAL_PREPARATION_SCHEMA_VERSION
        or receipt.get("status") != "frozen_for_blinded_preparation"
        or receipt.get("purpose") != "prepare_final_corpus"
    ):
        raise SelectedSafeCorpusError(
            "final corpus preparation receipt is not frozen"
        )
    if receipt.get("evaluation_opened") is not False:
        raise SelectedSafeCorpusError(
            "final preparation cannot follow evaluation access"
        )
    if _clean(receipt.get("code_commit")).lower() != code_commit:
        raise SelectedSafeCorpusError(
            "final preparation receipt code commit is inconsistent"
        )
    policy = classifier_manifest["classification_policy"]
    bindings = {
        "classifier_manifest_sha256": classifier_manifest_sha256,
        "classifier_adapter_sha256": classifier_manifest["classifier"][
            "adapter_sha256"
        ],
        "classification_pipeline_sha256": classifier_manifest["classifier"][
            "pipeline_sha256"
        ],
        "preprocessing_sha256": preprocessing_sha256,
        "environment_lock_sha256": classifier_manifest["dependency_lock"][
            "sha256"
        ],
        "label_policy_sha256": policy["rule_policy_sha256"],
        "trust_policy_sha256": policy["trust_policy_sha256"],
        "mitre_cache_sha256": policy["mitre_cache_sha256"],
        "classification_checkpoint_sha256": classifier_manifest["classifier"][
            "checkpoint_sha256"
        ],
        "pseudonymization_key_id": pseudonymization_key_id,
    }
    for field, expected in bindings.items():
        if receipt.get(field) != expected:
            raise SelectedSafeCorpusError(
                f"final preparation receipt {field} is inconsistent"
            )
    for field in (
        "source_selection_sha256",
        "final_source_member_receipts_sha256",
        "classifier_manifest_sha256",
        "classifier_adapter_sha256",
        "classification_pipeline_sha256",
        "preprocessing_sha256",
        "environment_lock_sha256",
        "label_policy_sha256",
        "trust_policy_sha256",
        "mitre_cache_sha256",
        "classification_checkpoint_sha256",
    ):
        _require_sha256(receipt.get(field), field)
    if receipt.get("final_source_member_count") != 7:
        raise SelectedSafeCorpusError(
            "final preparation receipt must bind seven members"
        )
    identity = dict(receipt)
    receipt_id = identity.pop("receipt_id", None)
    if receipt_id != stable_id("nextbehaviorfinalpreparation", identity):
        raise SelectedSafeCorpusError(
            "final preparation receipt identity is invalid"
        )
    return receipt


def _write_temp(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return temporary


def _publish_no_overwrite(temporaries: Mapping[Path, Path]) -> None:
    if any(destination.exists() for destination in temporaries):
        raise SelectedSafeCorpusError(
            "safe build output exists; refusing to overwrite"
        )
    published: list[Path] = []
    try:
        for destination, temporary in temporaries.items():
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise SelectedSafeCorpusError(
                    "safe build output appeared during publication"
                ) from exc
            published.append(destination)
    except BaseException:
        for destination in published:
            destination.unlink(missing_ok=True)
        raise
    finally:
        for temporary in temporaries.values():
            temporary.unlink(missing_ok=True)


def build_selected_safe_corpus(
    *,
    purpose: str,
    private_database_path: Path,
    classifier_manifest_path: Path,
    preprocessing_manifest_path: Path,
    historical_payload_path: Path,
    pseudonymization_key: bytes,
    pseudonymization_key_id: str,
    safe_sessions_path: Path,
    examples_path: Path,
    source_receipts_path: Path,
    corpus_receipt_path: Path,
    build_receipt_path: Path,
    code_commit: str,
    max_sequence_length: int = 8,
    historical_split_evidence_path: Path | None = None,
    final_preparation_receipt: Mapping[str, Any] | None = None,
    final_preparation_generation: Mapping[str, Any] | None = None,
    repository_root: Path | None = None,
) -> Dict[str, Any]:
    """Export one role without exposing any other role's private records.

    The final role is checked before the private database is opened. Its
    caller must supply the exact blinded-preparation receipt and the ingestion
    store must already contain the corresponding preparation marker. This
    export does not grant model-evaluation access.
    """

    role = PURPOSE_TO_ROLE.get(_clean(purpose))
    if role is None:
        raise SelectedSafeCorpusError("purpose is not recognized")
    root = (
        Path(repository_root)
        if repository_root is not None
        else Path(__file__).resolve().parents[2]
    )
    commit = _require_repository_commit(root, code_commit)
    if max_sequence_length < 1:
        raise SelectedSafeCorpusError("max_sequence_length must be positive")
    if (
        not isinstance(pseudonymization_key, bytes)
        or len(pseudonymization_key) < 32
    ):
        raise SelectedSafeCorpusError(
            "pseudonymization key must contain at least 32 bytes"
        )
    output_paths = (
        safe_sessions_path,
        examples_path,
        source_receipts_path,
        corpus_receipt_path,
        build_receipt_path,
    ) + (
        (historical_split_evidence_path,)
        if historical_split_evidence_path is not None
        else ()
    )
    if any(path.exists() for path in output_paths):
        raise SelectedSafeCorpusError(
            "safe build output exists; refusing to overwrite"
        )
    for path in output_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
    try:
        classifier_manifest = load_classifier_manifest(
            classifier_manifest_path
        )
    except ValueError as exc:
        raise SelectedSafeCorpusError(str(exc)) from exc
    preprocessing_sha256 = _sha256_file(preprocessing_manifest_path)
    classifier_sha256 = _sha256_file(classifier_manifest_path)
    policy = classifier_manifest["classification_policy"]
    final_preparation_gate: Dict[str, Any] | None = None
    final_preparation_generation_gate: Dict[str, Any] | None = None
    generation_output_paths: Dict[str, str] | None = None
    if role == "test":
        if (
            final_preparation_receipt is not None
            and final_preparation_generation is not None
        ):
            raise SelectedSafeCorpusError(
                "final export cannot combine legacy preparation with a generation"
            )
        if final_preparation_generation is not None:
            if historical_split_evidence_path is None:
                raise SelectedSafeCorpusError(
                    "preparation generation can authorize only v3 output"
                )
            try:
                require_final_preparation_generation_receipt(
                    final_preparation_generation
                )
            except SelectedCorpusBuildError as exc:
                raise SelectedSafeCorpusError(str(exc)) from exc
            generation_output_paths = _canonical_generation_output_paths(
                safe_sessions_path=safe_sessions_path,
                examples_path=examples_path,
                source_receipts_path=source_receipts_path,
                corpus_receipt_path=corpus_receipt_path,
                build_receipt_path=build_receipt_path,
                historical_split_evidence_path=(
                    historical_split_evidence_path
                ),
            )
        elif final_preparation_receipt is None:
            raise SelectedSafeCorpusError(
                "final-test safe export remains sealed for preparation"
            )
        else:
            final_preparation_gate = _require_final_preparation_receipt(
                final_preparation_receipt,
                code_commit=commit,
                classifier_manifest=classifier_manifest,
                classifier_manifest_sha256=classifier_sha256,
                preprocessing_sha256=preprocessing_sha256,
                pseudonymization_key_id=pseudonymization_key_id,
            )
    historical, historical_sha256 = _load_historical_membership(
        historical_payload_path
    )

    database = open_selected_database(private_database_path)
    spool_path: Path | None = None
    spool: sqlite3.Connection | None = None
    temporary_outputs: Dict[Path, Path] = {}
    try:
        selection_row = database.execute(
            "SELECT value FROM metadata WHERE key = 'source_selection_sha256'"
        ).fetchone()
        if selection_row is None:
            raise SelectedSafeCorpusError(
                "private store is not bound to a completed source selection"
            )
        source_selection_sha256 = _require_sha256(
            selection_row[0], "source_selection_sha256"
        )
        expected_final_selection = (
            final_preparation_generation["source_selection_sha256"]
            if final_preparation_generation is not None
            else (
                final_preparation_gate["source_selection_sha256"]
                if final_preparation_gate is not None
                else None
            )
        )
        if role == "test" and (
            source_selection_sha256 != expected_final_selection
        ):
            raise SelectedSafeCorpusError(
                "final private store source selection differs from "
                "preparation freeze"
            )
        if role == "test":
            generation_head = database.execute(
                "SELECT value FROM metadata "
                "WHERE key = 'final_corpus_preparation_generation_id'"
            ).fetchone()
            if (
                generation_head is not None
                and final_preparation_generation is None
                and historical_split_evidence_path is not None
            ):
                raise SelectedSafeCorpusError(
                    "migrated store v3 output requires its preparation "
                    "generation"
                )
            prepared = database.execute(
                "SELECT value FROM metadata "
                "WHERE key = 'final_corpus_prepared_at'"
            ).fetchone()
            preparation_id = database.execute(
                "SELECT value FROM metadata "
                "WHERE key = 'final_corpus_preparation_receipt_id'"
            ).fetchone()
            preparation_json = database.execute(
                "SELECT value FROM metadata "
                "WHERE key = 'final_corpus_preparation_receipt_json'"
            ).fetchone()
            if final_preparation_generation is not None:
                final_preparation_generation_gate = (
                    _require_final_preparation_generation(
                        final_preparation_generation,
                        database=database,
                        code_commit=commit,
                        classifier_manifest=classifier_manifest,
                        classifier_manifest_sha256=classifier_sha256,
                        preprocessing_sha256=preprocessing_sha256,
                        pseudonymization_key=pseudonymization_key,
                        pseudonymization_key_id=pseudonymization_key_id,
                        max_sequence_length=max_sequence_length,
                        output_paths=generation_output_paths,
                    )
                )
                legacy_gate = _legacy_preparation_marker(database)
                expected_preparation_id = legacy_gate["receipt_id"]
                expected_preparation_json = stable_json(legacy_gate)
            else:
                expected_preparation_id = final_preparation_gate["receipt_id"]
                expected_preparation_json = stable_json(
                    final_preparation_gate
                )
            if (
                prepared is None
                or preparation_id is None
                or preparation_json is None
                or str(preparation_id[0])
                != expected_preparation_id
                or str(preparation_json[0])
                != expected_preparation_json
            ):
                raise SelectedSafeCorpusError(
                    "final corpus preparation marker is missing or inconsistent"
                )
            final_member_rows = [
                {
                    "filename": str(row[0]),
                    "source_sha256": str(row[1]),
                    "source_size_bytes": int(row[2]),
                    "archive_crc32": str(row[3]),
                    "chronological_order": int(row[4]),
                    "source_cohort": str(row[5]),
                    "experiment_role": str(row[6]),
                }
                for row in database.execute(
                    """
                    SELECT filename, source_sha256, source_size_bytes,
                           archive_crc32, chronological_order, source_cohort,
                           experiment_role
                    FROM source_members
                    WHERE experiment_role = 'test'
                    ORDER BY chronological_order
                    """
                )
            ]
            if final_member_receipts_sha256(final_member_rows) != (
                (
                    final_preparation_generation_gate
                    if final_preparation_generation_gate is not None
                    else final_preparation_gate
                )[
                    "final_source_member_receipts_sha256"
                ]
            ):
                raise SelectedSafeCorpusError(
                    "final source receipts differ from preparation freeze"
                )
        unique_commands = int(
            database.execute(
                "SELECT COUNT(DISTINCT command) FROM command_events"
            ).fetchone()[0]
        )
        classified_commands = _validate_all_cached_rows(
            database, classifier_manifest
        )
        if classified_commands != unique_commands:
            raise SelectedSafeCorpusError(
                "exact-command classification is incomplete"
            )
        source_receipts, receipts_by_filename = _source_receipts_for_role(
            database,
            role=role,
            key=pseudonymization_key,
            key_id=pseudonymization_key_id,
        )

        spool_descriptor, spool_name = tempfile.mkstemp(
            prefix=".selected-safe-spool.",
            suffix=".sqlite",
            dir=safe_sessions_path.parent,
        )
        os.close(spool_descriptor)
        spool_path = Path(spool_name)
        spool = sqlite3.connect(spool_path)
        spool.execute(
            """
            CREATE TABLE results(
                sort_session_id TEXT PRIMARY KEY,
                safe_json TEXT,
                reconciliation_json TEXT NOT NULL,
                historical_split TEXT NOT NULL
            )
            """
        )
        session_rows = database.execute(
            """
            SELECT s.raw_session_id, s.source_member, s.first_seen,
                   s.last_seen, s.protocol, s.configuration
            FROM sessions AS s
            WHERE s.experiment_role = ?
              AND s.source_cohort = ?
              AND s.protocol = 'ssh'
              AND s.connected = 1
              AND s.closed = 1
              AND NOT EXISTS (
                  SELECT 1 FROM quarantined_sessions AS q
                  WHERE q.raw_session_id = s.raw_session_id
              )
            ORDER BY s.first_seen, s.raw_session_id
            """,
            (role, ROLE_TO_COHORT[role]),
        )
        built = 0
        safe_count = 0
        historical_counts: Counter[str] = Counter()
        for row in session_rows:
            raw_session_id = str(row[0])
            historical_split = historical.get(
                _historical_id(raw_session_id), "not_present"
            )
            if role == "test" and historical_split != "not_present":
                raise SelectedSafeCorpusError(
                    "final role overlaps accepted historical membership"
                )
            if role != "test" and historical_split == "test":
                raise SelectedSafeCorpusError(
                    "development role overlaps accepted historical test"
                )
            result = _private_session_result(
                database,
                row,
                source_receipt=receipts_by_filename[str(row[1])],
                key=pseudonymization_key,
                key_id=pseudonymization_key_id,
            )
            safe = result["safe_session"]
            sort_id = (
                safe["session_id"]
                if safe is not None
                else pseudonymous_id(
                    "session", raw_session_id, key=pseudonymization_key
                )
            )
            spool.execute(
                "INSERT INTO results VALUES (?, ?, ?, ?)",
                (
                    sort_id,
                    stable_json(safe) if safe is not None else None,
                    stable_json(result["reconciliation"]),
                    historical_split,
                ),
            )
            built += 1
            safe_count += int(safe is not None)
            historical_counts[historical_split] += 1
            if built % 5000 == 0:
                spool.commit()
        spool.commit()

        def results() -> Iterator[Dict[str, Any]]:
            cursor = spool.execute(
                """
                SELECT safe_json, reconciliation_json FROM results
                ORDER BY CASE WHEN safe_json IS NULL THEN 1 ELSE 0 END,
                         sort_session_id
                """
            )
            for safe_json, reconciliation_json in cursor:
                yield {
                    "safe_session": (
                        json.loads(str(safe_json))
                        if safe_json is not None
                        else None
                    ),
                    "reconciliation": json.loads(str(reconciliation_json)),
                }

        corpus_receipt = build_streaming_corpus_receipt(
            results(),
            source_receipts,
            code_commit=commit,
            preprocessing_sha256=preprocessing_sha256,
            label_policy_sha256=policy["rule_policy_sha256"],
            trust_policy_sha256=policy["trust_policy_sha256"],
            classification_checkpoint_sha256=classifier_manifest[
                "classifier"
            ]["checkpoint_sha256"],
        )
        if corpus_receipt["private_session_count"] != built or (
            corpus_receipt["safe_session_count"] != safe_count
        ):
            raise SelectedSafeCorpusError(
                "safe-session counts do not reconcile"
            )

        sessions_descriptor, sessions_name = tempfile.mkstemp(
            prefix=f".{safe_sessions_path.name}.",
            suffix=".tmp",
            dir=safe_sessions_path.parent,
        )
        examples_descriptor, examples_name = tempfile.mkstemp(
            prefix=f".{examples_path.name}.",
            suffix=".tmp",
            dir=examples_path.parent,
        )
        temporary_outputs[safe_sessions_path] = Path(sessions_name)
        temporary_outputs[examples_path] = Path(examples_name)
        session_digest = hashlib.sha256()
        example_digest = hashlib.sha256()
        session_size = 0
        example_size = 0
        example_count = 0
        session_ids: list[str] = []
        safe_member_ids: set[str] = set()
        example_ids: list[str] = []
        input_hashes: list[str] = []
        historical_evidence_records: list[Dict[str, str]] = []
        with (
            os.fdopen(sessions_descriptor, "wb") as sessions_handle,
            os.fdopen(examples_descriptor, "wb") as examples_handle,
        ):
            for safe_json, historical_split in spool.execute(
                "SELECT safe_json, historical_split FROM results "
                "WHERE safe_json IS NOT NULL "
                "ORDER BY sort_session_id"
            ):
                safe = json.loads(str(safe_json))
                _scan_public_value(safe)
                session_ids.append(str(safe["session_id"]))
                safe_member_ids.add(str(safe["source_member_id"]))
                session_line = (stable_json(safe) + "\n").encode()
                sessions_handle.write(session_line)
                session_digest.update(session_line)
                session_size += len(session_line)
                historical_evidence_records.append(
                    {
                        "session_id": str(safe["session_id"]),
                        "source_member_id": str(safe["source_member_id"]),
                        "source_member_sha256": str(
                            safe["source_member_sha256"]
                        ),
                        "historical_split": str(historical_split),
                    }
                )
                for example in build_next_behavior_examples(
                    safe, max_sequence_length=max_sequence_length
                ):
                    _scan_public_value(example)
                    example_line = (stable_json(example) + "\n").encode()
                    examples_handle.write(example_line)
                    example_digest.update(example_line)
                    example_size += len(example_line)
                    example_count += 1
                    example_ids.append(str(example["example_id"]))
                    input_hashes.append(
                        str(example["model_input"]["input_hash"])
                    )
            sessions_handle.flush()
            os.fsync(sessions_handle.fileno())
            examples_handle.flush()
            os.fsync(examples_handle.fileno())

        receipts_payload = {
            "schema_version": SOURCE_RECEIPTS_SCHEMA_VERSION,
            "source_selection_sha256": source_selection_sha256,
            "purpose": purpose,
            "role": role,
            "members": source_receipts,
        }
        source_member_ids = [
            str(member["member_id"]) for member in source_receipts
        ]
        if safe_member_ids != set(source_member_ids):
            raise SelectedSafeCorpusError(
                "every frozen source member must contribute a safe session"
            )
        source_receipts_bytes = (
            json.dumps(receipts_payload, indent=2, sort_keys=True) + "\n"
        ).encode()
        corpus_receipt_bytes = (
            json.dumps(corpus_receipt, indent=2, sort_keys=True) + "\n"
        ).encode()
        membership = {
            "source_member_count": len(source_member_ids),
            "source_member_membership_sha256": _membership_sha256(
                source_member_ids
            ),
            "session_count": len(session_ids),
            "session_membership_sha256": _membership_sha256(session_ids),
            "example_count": len(example_ids),
            "example_membership_sha256": _membership_sha256(example_ids),
            "input_count": len(input_hashes),
            "input_membership_sha256": _membership_sha256(input_hashes),
        }
        if (
            final_preparation_generation_gate is not None
            and membership
            != final_preparation_generation_gate["membership"]
        ):
            raise SelectedSafeCorpusError(
                "v3 output membership differs from authorized generation"
            )
        pipeline_reconciliation = _role_pipeline_reconciliation(
            database,
            role=role,
            built_session_count=built,
            safe_session_count=safe_count,
            example_count=example_count,
        )
        historical_split_evidence: Dict[str, Any] | None = None
        historical_split_evidence_bytes: bytes | None = None
        if historical_split_evidence_path is not None:
            historical_split_evidence = {
                "schema_version": HISTORICAL_SPLIT_EVIDENCE_SCHEMA_VERSION,
                "status": "historical_split_evidence_complete",
                "selected_safe_corpus_receipt_id": corpus_receipt[
                    "receipt_id"
                ],
                "source_selection_sha256": source_selection_sha256,
                "records": historical_evidence_records,
            }
            _scan_public_value(historical_split_evidence)
            historical_split_evidence_bytes = (
                stable_json(historical_split_evidence) + "\n"
            ).encode()
        build_receipt: Dict[str, Any] = {
            "schema_version": (
                SAFE_BUILD_RECEIPT_SCHEMA_VERSION
                if historical_split_evidence is not None
                else LEGACY_SAFE_BUILD_RECEIPT_SCHEMA_VERSION
            ),
            "status": "role_safe_corpus_built",
            "purpose": purpose,
            "role": role,
            "source_cohort": ROLE_TO_COHORT[role],
            "code_commit": commit,
            "source_selection_sha256": source_selection_sha256,
            "classifier_manifest_sha256": classifier_sha256,
            "preprocessing_sha256": preprocessing_sha256,
            "label_policy_sha256": policy["rule_policy_sha256"],
            "trust_policy_sha256": policy["trust_policy_sha256"],
            "classification_checkpoint_sha256": classifier_manifest[
                "classifier"
            ]["checkpoint_sha256"],
            "label_adapter_sha256": _sha256_file(
                Path(__file__).parents[1]
                / "prediction/next_behavior_label_policy.py"
            ),
            "safe_builder_sha256": _sha256_file(Path(__file__)),
            "pseudonymization_key_id": pseudonymization_key_id,
            "max_sequence_length": max_sequence_length,
            "safe_sessions": {
                "line_count": safe_count,
                "size_bytes": session_size,
                "sha256": session_digest.hexdigest(),
            },
            "examples": {
                "line_count": example_count,
                "size_bytes": example_size,
                "sha256": example_digest.hexdigest(),
            },
            "source_receipts_artifact_sha256": hashlib.sha256(
                source_receipts_bytes
            ).hexdigest(),
            "corpus_receipt_artifact_sha256": hashlib.sha256(
                corpus_receipt_bytes
            ).hexdigest(),
            "membership": membership,
            "historical_membership": {
                "input_sha256": historical_sha256,
                "overlap_by_split": dict(sorted(historical_counts.items())),
                "development_reuse_disclosed": role != "test",
                "historical_test_overlap": historical_counts["test"],
                "final_any_historical_overlap": (
                    sum(
                        historical_counts[split]
                        for split in ("train", "calibration", "test")
                    )
                    if role == "test"
                    else 0
                ),
            },
            "pipeline_reconciliation": pipeline_reconciliation,
            "final_preparation_gate": (
                final_preparation_generation_gate
                if final_preparation_generation_gate is not None
                else final_preparation_gate
                if final_preparation_gate is not None
                else {"status": "not_applicable"}
            ),
            "corpus_receipt_id": corpus_receipt["receipt_id"],
            "raw_content_emitted": False,
        }
        if historical_split_evidence is not None:
            build_receipt["historical_split_evidence"] = {
                "schema_version": HISTORICAL_SPLIT_EVIDENCE_SCHEMA_VERSION,
                "status": "historical_split_evidence_complete",
                "artifact_sha256": hashlib.sha256(
                    historical_split_evidence_bytes
                ).hexdigest(),
                "record_count": len(historical_evidence_records),
                "session_membership_sha256": _membership_sha256(
                    record["session_id"]
                    for record in historical_evidence_records
                ),
            }
        build_receipt["build_receipt_id"] = stable_id(
            "nextbehaviorselectedsafebuild", build_receipt
        )
        _scan_public_value(receipts_payload)
        _scan_public_value(corpus_receipt)
        _scan_public_value(build_receipt)
        payloads = {
            source_receipts_path: source_receipts_bytes,
            corpus_receipt_path: corpus_receipt_bytes,
            build_receipt_path: (
                json.dumps(build_receipt, indent=2, sort_keys=True) + "\n"
            ).encode(),
        }
        if historical_split_evidence_path is not None:
            payloads[historical_split_evidence_path] = (
                historical_split_evidence_bytes
            )
        for destination, payload in payloads.items():
            temporary_outputs[destination] = _write_temp(
                destination, payload
            )
        _publish_no_overwrite(temporary_outputs)
        temporary_outputs = {}
        return build_receipt
    except (sqlite3.Error, SelectedCorpusBuildError) as exc:
        if isinstance(exc, SelectedSafeCorpusError):
            raise
        raise SelectedSafeCorpusError(str(exc)) from exc
    finally:
        database.close()
        if spool is not None:
            spool.close()
        for temporary in temporary_outputs.values():
            temporary.unlink(missing_ok=True)
        if spool_path is not None:
            spool_path.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="stage", required=True)
    classify = subparsers.add_parser("classify")
    classify.add_argument("--classifier-manifest", type=Path, required=True)
    classify.add_argument("--repository-root", type=Path, default=Path("."))
    classify.add_argument("--model-root", type=Path, required=True)
    classify.add_argument("--private-database", type=Path, required=True)
    classify.add_argument("--code-commit", required=True)
    classify.add_argument("--command-batch-size", type=int, default=256)
    safe = subparsers.add_parser("safe-development-role")
    safe.add_argument(
        "--purpose",
        choices=("fit_model", "select_model", "fit_calibration"),
        required=True,
    )
    final = subparsers.add_parser("safe-final-role")
    final_preparation = final.add_mutually_exclusive_group(required=True)
    final_preparation.add_argument("--preparation-receipt", type=Path)
    final_preparation.add_argument("--preparation-generation", type=Path)
    for role_parser in (safe, final):
        role_parser.add_argument(
            "--private-database", type=Path, required=True
        )
        role_parser.add_argument(
            "--classifier-manifest", type=Path, required=True
        )
        role_parser.add_argument(
            "--preprocessing-manifest", type=Path, required=True
        )
        role_parser.add_argument(
            "--historical-payload", type=Path, required=True
        )
        role_parser.add_argument(
            "--pseudonymization-key", type=Path, required=True
        )
        role_parser.add_argument("--safe-sessions", type=Path, required=True)
        role_parser.add_argument("--examples", type=Path, required=True)
        role_parser.add_argument(
            "--source-receipts", type=Path, required=True
        )
        role_parser.add_argument(
            "--corpus-receipt", type=Path, required=True
        )
        role_parser.add_argument(
            "--build-receipt", type=Path, required=True
        )
        role_parser.add_argument(
            "--historical-split-evidence", type=Path
        )
        role_parser.add_argument("--code-commit", required=True)
        role_parser.add_argument(
            "--max-sequence-length", type=int, default=8
        )
    migrate = subparsers.add_parser("migrate-final-preparation-generation")
    migrate.add_argument("--private-database", type=Path, required=True)
    migrate.add_argument("--preparation-receipt", type=Path, required=True)
    migrate.add_argument("--predecessor-build-receipt", type=Path, required=True)
    migrate.add_argument("--predecessor-safe-sessions", type=Path, required=True)
    migrate.add_argument("--predecessor-examples", type=Path, required=True)
    migrate.add_argument("--predecessor-source-receipts", type=Path, required=True)
    migrate.add_argument("--predecessor-corpus-receipt", type=Path, required=True)
    migrate.add_argument("--classifier-manifest", type=Path, required=True)
    migrate.add_argument("--preprocessing-manifest", type=Path, required=True)
    migrate.add_argument("--pseudonymization-key", type=Path, required=True)
    migrate.add_argument("--safe-sessions", type=Path, required=True)
    migrate.add_argument("--examples", type=Path, required=True)
    migrate.add_argument("--source-receipts", type=Path, required=True)
    migrate.add_argument("--corpus-receipt", type=Path, required=True)
    migrate.add_argument("--build-receipt", type=Path, required=True)
    migrate.add_argument("--historical-split-evidence", type=Path, required=True)
    migrate.add_argument("--generation-receipt", type=Path, required=True)
    migrate.add_argument("--repository-root", type=Path, default=Path("."))
    migrate.add_argument("--code-commit", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.stage == "classify":
        result = classify_missing_selected_commands(
            classifier_manifest_path=args.classifier_manifest,
            repository_root=args.repository_root,
            model_root=args.model_root,
            private_database_path=args.private_database,
            code_commit=args.code_commit,
            command_batch_size=args.command_batch_size,
        )
    elif args.stage == "migrate-final-preparation-generation":
        try:
            key, key_id = load_or_create_pseudonymization_key(
                args.pseudonymization_key,
                create=False,
            )
        except ValueError as exc:
            raise SelectedSafeCorpusError(str(exc)) from exc
        result = migrate_final_preparation_generation(
            private_database_path=args.private_database,
            preparation_receipt=_load_json_object(
                args.preparation_receipt,
                "current final corpus preparation receipt",
            ),
            predecessor_build_receipt_path=args.predecessor_build_receipt,
            predecessor_safe_sessions_path=args.predecessor_safe_sessions,
            predecessor_examples_path=args.predecessor_examples,
            predecessor_source_receipts_path=args.predecessor_source_receipts,
            predecessor_corpus_receipt_path=args.predecessor_corpus_receipt,
            classifier_manifest_path=args.classifier_manifest,
            preprocessing_manifest_path=args.preprocessing_manifest,
            pseudonymization_key=key,
            pseudonymization_key_id=key_id,
            safe_sessions_path=args.safe_sessions,
            examples_path=args.examples,
            source_receipts_path=args.source_receipts,
            corpus_receipt_path=args.corpus_receipt,
            build_receipt_path=args.build_receipt,
            historical_split_evidence_path=args.historical_split_evidence,
            generation_receipt_path=args.generation_receipt,
            code_commit=args.code_commit,
            repository_root=args.repository_root,
        )
    else:
        try:
            key, key_id = load_or_create_pseudonymization_key(
                args.pseudonymization_key,
                create=False,
            )
        except ValueError as exc:
            raise SelectedSafeCorpusError(str(exc)) from exc
        final_preparation_receipt = (
            _load_json_object(
                args.preparation_receipt,
                "final corpus preparation receipt",
            )
            if args.stage == "safe-final-role"
            and args.preparation_receipt is not None
            else None
        )
        final_preparation_generation = (
            _load_json_object(
                args.preparation_generation,
                "final corpus preparation generation",
            )
            if args.stage == "safe-final-role"
            and args.preparation_generation is not None
            else None
        )
        result = build_selected_safe_corpus(
            purpose=(
                "final_evaluation"
                if args.stage == "safe-final-role"
                else args.purpose
            ),
            private_database_path=args.private_database,
            classifier_manifest_path=args.classifier_manifest,
            preprocessing_manifest_path=args.preprocessing_manifest,
            historical_payload_path=args.historical_payload,
            pseudonymization_key=key,
            pseudonymization_key_id=key_id,
            safe_sessions_path=args.safe_sessions,
            examples_path=args.examples,
            source_receipts_path=args.source_receipts,
            corpus_receipt_path=args.corpus_receipt,
            build_receipt_path=args.build_receipt,
            historical_split_evidence_path=args.historical_split_evidence,
            code_commit=args.code_commit,
            max_sequence_length=args.max_sequence_length,
            final_preparation_receipt=final_preparation_receipt,
            final_preparation_generation=final_preparation_generation,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
