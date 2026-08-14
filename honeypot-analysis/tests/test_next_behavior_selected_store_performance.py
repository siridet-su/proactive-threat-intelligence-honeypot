"""Equivalence and bounded-work tests for selected-store reconciliation."""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

import pytest

from production.reproduction.next_behavior import selected_store
from production.reproduction.next_behavior.selected_store import (
    SelectedCorpusBuildError,
    _clear_partial_member,
    _ingest_one_member,
    _rebuild_sessions_reference,
    _refresh_quarantine,
    open_selected_database,
)


def _member(filename: str, order: int, role: str = "train") -> dict[str, Any]:
    return {
        "filename": filename,
        "sha256": f"{order:064x}",
        "size_bytes": order,
        "archive_crc32": f"{order:08x}",
        "chronological_order": order,
        "source_cohort": "development",
        "experiment_role": role,
    }


def _event(
    event_id: str,
    session: str,
    second: int,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "eventid": event_id,
        "session": session,
        "ts": f"2025-07-01T00:00:{second:02d}Z",
        **extra,
    }


def _write_member(
    path: Path,
    events: Iterable[dict[str, Any]],
) -> Path:
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    return path


def _rows(database: sqlite3.Connection, table: str) -> list[tuple[Any, ...]]:
    columns = [
        str(row[1])
        for row in database.execute(f"PRAGMA table_info({table})")
    ]
    order = ", ".join(columns)
    return database.execute(f"SELECT * FROM {table} ORDER BY {order}").fetchall()


def _assert_reference_equivalent(database: sqlite3.Connection) -> None:
    tables = (
        "metadata",
        "source_members",
        "session_sources",
        "sessions",
        "command_events",
        "context_events",
        "quarantined_sessions",
    )

    def fingerprints() -> dict[str, str]:
        return {
            table: hashlib.sha256(
                json.dumps(
                    _rows(database, table),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            for table in tables
        }

    before = fingerprints()
    _rebuild_sessions_reference(database)
    after = fingerprints()
    assert after == before


def test_fresh_store_gets_member_cleanup_index_without_upgrading_existing_store(
    tmp_path: Path,
) -> None:
    fresh_path = tmp_path / "fresh.sqlite"
    fresh = open_selected_database(fresh_path)
    try:
        indexes = {
            str(row[1])
            for row in fresh.execute("PRAGMA index_list(session_sources)")
        }
        assert "idx_selected_session_sources_member" in indexes
        plan = " ".join(
            str(row[3])
            for row in fresh.execute(
                """
                EXPLAIN QUERY PLAN
                SELECT raw_session_id FROM session_sources
                WHERE source_member = 'member.json.gz'
                """
            )
        )
        assert "idx_selected_session_sources_member" in plan
    finally:
        fresh.close()

    existing_path = tmp_path / "existing.sqlite"
    legacy = sqlite3.connect(existing_path)
    legacy.execute("CREATE TABLE sentinel(value INTEGER)")
    legacy.commit()
    legacy.close()
    existing = open_selected_database(existing_path)
    try:
        indexes = {
            str(row[1])
            for row in existing.execute("PRAGMA index_list(session_sources)")
        }
        assert "idx_selected_session_sources_member" not in indexes
    finally:
        existing.close()


def test_scoped_reconciliation_matches_legacy_for_shared_cross_role_split_session(
    tmp_path: Path,
) -> None:
    database = open_selected_database(tmp_path / "shared.sqlite")
    metrics: Counter[str] = Counter()
    first = _write_member(
        tmp_path / "first.json.gz",
        [
            _event(
                "cowrie.session.connect",
                "shared",
                1,
                protocol="ssh",
            ),
            _event("cowrie.command.input", "shared", 2, input="id"),
            _event("cowrie.login.success", "shared", 3),
            _event("cowrie.session.connect", "only-first", 4),
            _event("cowrie.session.closed", "only-first", 5),
        ],
    )
    second = _write_member(
        tmp_path / "second.json.gz",
        [
            _event(
                "cowrie.session.closed",
                "shared",
                6,
                group="cowrie-second",
            ),
            _event("cowrie.command.input", "shared", 7, input="uname -a"),
        ],
    )
    try:
        _ingest_one_member(
            database,
            _member(first.name, 1),
            first,
            flush_size=2,
            instrumentation=metrics,
        )
        _assert_reference_equivalent(database)
        _ingest_one_member(
            database,
            _member(second.name, 2, "selection"),
            second,
            flush_size=1,
            instrumentation=metrics,
        )
        shared = database.execute(
            """
            SELECT source_member, source_cohort, experiment_role,
                   first_seen, last_seen, protocol, configuration,
                   connected, closed, cross_member, cross_role
            FROM sessions WHERE raw_session_id = 'shared'
            """
        ).fetchone()
        assert shared == (
            first.name,
            "development",
            "train",
            "2025-07-01T00:00:01Z",
            "2025-07-01T00:00:07Z",
            "ssh",
            "cowrie-second",
            1,
            1,
            1,
            1,
        )
        _refresh_quarantine(database)
        quarantine_before = _rows(database, "quarantined_sessions")
        _assert_reference_equivalent(database)
        _refresh_quarantine(database)
        assert _rows(database, "quarantined_sessions") == quarantine_before
        assert metrics["scoped_reconciliations"] == 2
        assert metrics["affected_sessions_reconciled"] == 3
    finally:
        database.close()


def test_interrupted_member_cleanup_is_member_scoped_and_preserves_sessions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = open_selected_database(tmp_path / "interrupted.sqlite")
    good = _write_member(
        tmp_path / "good.json.gz",
        [
            _event("cowrie.session.connect", "durable", 1),
            _event("cowrie.session.closed", "durable", 2),
        ],
    )
    metrics: Counter[str] = Counter()
    try:
        _ingest_one_member(
            database,
            _member(good.name, 1),
            good,
            flush_size=1,
            instrumentation=metrics,
        )
        durable_sessions = _rows(database, "sessions")

        real_open = selected_store.gzip.open

        class _InterruptedLines:
            def __enter__(self) -> "_InterruptedLines":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def __iter__(self):
                yield json.dumps(
                    _event("cowrie.session.connect", "partial", 3)
                )
                raise OSError("synthetic bounded interruption")

        def interrupted_open(path: Path, *args: Any, **kwargs: Any):
            if Path(path).name == "interrupted.json.gz":
                return _InterruptedLines()
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(selected_store.gzip, "open", interrupted_open)
        with pytest.raises(SelectedCorpusBuildError, match="OSError"):
            _ingest_one_member(
                database,
                _member("interrupted.json.gz", 2),
                tmp_path / "interrupted.json.gz",
                flush_size=1,
                instrumentation=metrics,
            )
        assert _rows(database, "sessions") == durable_sessions
        for table in ("command_events", "context_events", "session_sources"):
            assert database.execute(
                f"SELECT COUNT(*) FROM {table} WHERE source_member = ?",
                ("interrupted.json.gz",),
            ).fetchone()[0] == 0
        assert database.execute(
            "SELECT 1 FROM source_members WHERE filename = ?",
            ("interrupted.json.gz",),
        ).fetchone() is None
        assert metrics["partial_members_cleared"] == 1
        assert metrics["partial_session_source_rows_deleted"] == 1
        _assert_reference_equivalent(database)

        # Reopening the store models process restart.  The same member can be
        # retried without re-ingesting or changing the completed member.
        database.close()
        database = open_selected_database(tmp_path / "interrupted.sqlite")
        monkeypatch.setattr(selected_store.gzip, "open", real_open)
        recovered = _write_member(
            tmp_path / "interrupted.json.gz",
            [
                _event("cowrie.session.connect", "partial", 3),
                _event("cowrie.session.closed", "partial", 4),
            ],
        )
        result = _ingest_one_member(
            database,
            _member(recovered.name, 2),
            recovered,
            flush_size=1,
            instrumentation=metrics,
        )
        assert result["status"] == "ingested"
        assert database.execute(
            "SELECT COUNT(*) FROM sessions"
        ).fetchone()[0] == 2
        _assert_reference_equivalent(database)
    finally:
        database.close()


def test_sqlite_failure_rolls_back_partial_member_without_global_rebuild(
    tmp_path: Path,
) -> None:
    database = open_selected_database(tmp_path / "sqlite-failure.sqlite")
    member_path = _write_member(
        tmp_path / "failure.json.gz",
        [
            _event("cowrie.session.connect", "failed", 1),
            _event("cowrie.command.input", "failed", 2, input="id"),
        ],
    )
    database.execute(
        """
        CREATE TRIGGER fail_command_insert
        BEFORE INSERT ON command_events
        BEGIN
            SELECT RAISE(ABORT, 'synthetic sqlite failure');
        END
        """
    )
    database.commit()
    try:
        with pytest.raises(SelectedCorpusBuildError, match="IntegrityError"):
            _ingest_one_member(
                database,
                _member(member_path.name, 1),
                member_path,
                flush_size=2,
            )
        assert database.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert database.execute(
            "SELECT COUNT(*) FROM session_sources"
        ).fetchone()[0] == 0
        assert database.execute(
            "SELECT COUNT(*) FROM source_members"
        ).fetchone()[0] == 0
    finally:
        database.close()


def test_completion_reconciliation_and_member_marker_are_atomic(
    tmp_path: Path,
) -> None:
    database = open_selected_database(tmp_path / "atomic.sqlite")
    first = _write_member(
        tmp_path / "atomic-first.json.gz",
        [
            _event("cowrie.session.connect", "shared", 1),
            _event("cowrie.session.closed", "shared", 2),
        ],
    )
    second = _write_member(
        tmp_path / "atomic-second.json.gz",
        [_event("cowrie.command.input", "shared", 3, input="id")],
    )
    try:
        _ingest_one_member(
            database,
            _member(first.name, 1),
            first,
            flush_size=1,
        )
        before = _rows(database, "sessions")
        database.execute(
            """
            CREATE TRIGGER fail_session_reconcile
            BEFORE INSERT ON sessions
            BEGIN
                SELECT RAISE(ABORT, 'synthetic completion failure');
            END
            """
        )
        database.commit()
        with pytest.raises(SelectedCorpusBuildError, match="IntegrityError"):
            _ingest_one_member(
                database,
                _member(second.name, 2),
                second,
                flush_size=1,
            )
        assert _rows(database, "sessions") == before
        assert database.execute(
            "SELECT 1 FROM source_members WHERE filename = ?",
            (second.name,),
        ).fetchone() is None
        assert database.execute(
            "SELECT COUNT(*) FROM session_sources WHERE source_member = ?",
            (second.name,),
        ).fetchone()[0] == 0
        assert database.execute(
            "SELECT COUNT(*) FROM command_events WHERE source_member = ?",
            (second.name,),
        ).fetchone()[0] == 0
        database.execute("DROP TRIGGER fail_session_reconcile")
        _assert_reference_equivalent(database)
    finally:
        database.close()


def test_no_timestamp_failure_removes_partial_rows(tmp_path: Path) -> None:
    database = open_selected_database(tmp_path / "no-time.sqlite")
    member_path = _write_member(
        tmp_path / "no-time.json.gz",
        [{"eventid": "cowrie.session.connect", "session": "partial"}],
    )
    try:
        with pytest.raises(SelectedCorpusBuildError, match="no usable timestamps"):
            _ingest_one_member(
                database,
                _member(member_path.name, 1),
                member_path,
                flush_size=1,
            )
        assert database.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert database.execute(
            "SELECT COUNT(*) FROM session_sources"
        ).fetchone()[0] == 0
    finally:
        database.close()


def test_bounded_medium_fixture_has_linear_scoped_reconciliation_work(
    tmp_path: Path,
) -> None:
    """Deterministic work benchmark; timing is reported but not asserted."""

    member_count = 12
    sessions_per_member = 120
    shared_per_member = 5
    database = open_selected_database(tmp_path / "medium.sqlite")
    metrics: Counter[str] = Counter()
    legacy_full_scan_rows = 0
    started = time.perf_counter()
    try:
        for order in range(1, member_count + 1):
            events: list[dict[str, Any]] = []
            session_ids = [
                *(f"member-{order:02d}-{index:03d}" for index in range(sessions_per_member)),
                *(f"shared-{index:02d}" for index in range(shared_per_member)),
            ]
            for index, session_id in enumerate(session_ids):
                second = index % 50
                events.extend(
                    [
                        _event("cowrie.session.connect", session_id, second),
                        _event("cowrie.session.closed", session_id, second + 1),
                    ]
                )
            path = _write_member(tmp_path / f"member-{order:02d}.json.gz", events)
            _ingest_one_member(
                database,
                _member(path.name, order),
                path,
                flush_size=37,
                instrumentation=metrics,
            )
            source_rows = int(
                database.execute("SELECT COUNT(*) FROM session_sources").fetchone()[0]
            )
            # The removed implementation rebuilt once before and once after
            # every member.  This is a conservative row-visit approximation:
            # the pre-pass is omitted, making the comparison favor the legacy
            # path rather than exaggerating the improvement.
            legacy_full_scan_rows += source_rows
        elapsed = time.perf_counter() - started
        _assert_reference_equivalent(database)
        assert metrics["scoped_reconciliations"] == member_count
        assert metrics["affected_sessions_reconciled"] == (
            member_count * (sessions_per_member + shared_per_member)
        )
        assert legacy_full_scan_rows > (
            metrics["affected_sessions_reconciled"] * 6
        )
        assert elapsed < 30
    finally:
        database.close()


def test_partial_cleanup_without_rows_is_a_noop(tmp_path: Path) -> None:
    database = open_selected_database(tmp_path / "noop.sqlite")
    metrics: Counter[str] = Counter()
    try:
        assert not _clear_partial_member(
            database,
            "missing.json.gz",
            instrumentation=metrics,
        )
        assert metrics == Counter({"partial_cleanup_checks": 1})
    finally:
        database.close()
