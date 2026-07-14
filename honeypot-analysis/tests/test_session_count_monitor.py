from __future__ import annotations

import logging
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from production.workers.session_count_monitor import (  # noqa: E402
    completed_session_count,
    evaluate_thresholds,
    parse_thresholds,
    prepare_state_for_session_source,
)


def test_parse_thresholds_defaults_and_deduplicates() -> None:
    assert parse_thresholds(None) == [1, 30]
    assert parse_thresholds("30,1,30") == [1, 30]


def test_completed_session_count_reads_sqlite_database(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            """
            create table sessions (
                session_id text primary key,
                src_ip text not null,
                ended integer not null,
                session_source text not null default 'unknown_legacy',
                is_external_source integer not null default 0
            )
            """
        )
        conn.executemany(
            "insert into sessions (session_id, src_ip, ended, session_source, is_external_source) values (?, ?, ?, ?, ?)",
            [
                ("active", "192.0.0.9", 0, "production_live", 1),
                ("closed-1", "192.0.0.9", 1, "production_live", 1),
                ("closed-2", "192.0.0.10", 1, "production_live", 1),
                ("closed-private", "100.64.0.42", 1, "production_live", 0),
                ("e2e", "198.51.100.4", 1, "e2e_test", 1),
                ("legacy", "198.51.100.4", 1, "unknown_legacy", 1),
            ],
        )

    assert completed_session_count(f"sqlite:///{db}") == 2
    assert completed_session_count(f"sqlite:///{db}", external_only=False) == 3
    assert completed_session_count(f"sqlite:///{db}", session_source="e2e_test") == 1


def test_evaluate_thresholds_notifies_each_threshold_once(caplog) -> None:
    state = {"notified_thresholds": []}
    logger = logging.getLogger("test-session-count-monitor")

    with caplog.at_level(logging.WARNING):
        assert evaluate_thresholds(30, [1, 30], state, logger) == [1, 30]
        first_run_records = list(caplog.records)
        assert evaluate_thresholds(30, [1, 30], state, logger) == []

    assert state["notified_thresholds"] == [1, 30]
    assert state["last_completed_session_count"] == 30
    assert state["session_source"] == "production_live"
    assert state["external_only"] is True
    assert len(first_run_records) == 2
    assert len(caplog.records) == 2
    assert "threshold reached" in caplog.text


def test_prepare_state_for_session_source_resets_legacy_threshold_state(caplog) -> None:
    state = {
        "session_source": "unknown_legacy",
        "notified_thresholds": [1, 30],
        "last_completed_session_count": 192,
    }
    logger = logging.getLogger("test-session-count-monitor")

    with caplog.at_level(logging.WARNING):
        prepared = prepare_state_for_session_source(state, "production_live", logger)

    assert prepared["notified_thresholds"] == []
    assert prepared["session_source"] == "production_live"
    assert prepared["external_only"] is True
    assert prepared["previous_state"] == state
    assert "source changed" in caplog.text


def test_prepare_state_for_session_source_resets_unlabeled_legacy_state(caplog) -> None:
    state = {
        "notified_thresholds": [1, 30],
        "last_completed_session_count": 192,
    }
    logger = logging.getLogger("test-session-count-monitor")

    with caplog.at_level(logging.WARNING):
        prepared = prepare_state_for_session_source(state, "production_live", logger)

    assert prepared["notified_thresholds"] == []
    assert prepared["session_source"] == "production_live"
    assert prepared["previous_state"] == state
