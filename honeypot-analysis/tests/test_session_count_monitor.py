from __future__ import annotations

import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from production.workers.session_count_monitor import (  # noqa: E402
    LEGACY_SESSION_COUNT_SCAN_LIMIT,
    completed_session_count,
    evaluate_thresholds,
    parse_thresholds,
    prepare_state_for_session_source,
)
from production.storage import open_storage  # noqa: E402


def test_parse_thresholds_defaults_and_deduplicates() -> None:
    assert parse_thresholds(None) == [1, 30]
    assert parse_thresholds("30,1,30") == [1, 30]


def test_completed_session_count_reads_sqlite_database(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    database_url = f"sqlite:///{db}"
    storage = open_storage(database_url)
    for session_id, src_ip, ended, source in [
        ("active", "8.8.8.8", False, "production_live"),
        ("closed-1", "8.8.8.8", True, "production_live"),
        ("closed-2", "1.1.1.1", True, "production_live"),
        ("closed-private", "100.64.0.42", True, "production_live"),
        ("e2e", "9.9.9.9", True, "e2e_test"),
        ("legacy", "4.2.2.2", True, "unknown_legacy"),
    ]:
        storage.save_session(
            {
                "session_id": session_id,
                "src_ip": src_ip,
                "is_ended": ended,
                "session_source": source,
            }
        )

    assert completed_session_count(database_url) == 2
    assert completed_session_count(database_url, external_only=False) == 3
    assert completed_session_count(database_url, session_source="e2e_test") == 1


def test_sqlite_count_sessions_supports_source_external_and_ended_filters(
    tmp_path: Path,
) -> None:
    storage = open_storage(f"sqlite:///{tmp_path / 'counts.db'}")
    for session_id, src_ip, ended, source in [
        ("active-external", "8.8.8.8", False, "production_live"),
        ("closed-external", "1.1.1.1", True, "production_live"),
        ("closed-private", "100.64.0.42", True, "production_live"),
        ("closed-e2e", "9.9.9.9", True, "e2e_test"),
    ]:
        storage.save_session(
            {
                "session_id": session_id,
                "src_ip": src_ip,
                "is_ended": ended,
                "session_source": source,
            }
        )

    assert storage.count_sessions() == 3
    assert storage.count_sessions(session_source=None) == 4
    assert storage.count_sessions(external_only=True) == 2
    assert storage.count_sessions(ended_only=True) == 2
    assert storage.count_sessions(external_only=True, ended_only=True) == 1
    assert storage.count_sessions(session_source="e2e_test", ended_only=True) == 1


def test_completed_session_count_uses_storage_count_method() -> None:
    class FakeStorage:
        def __init__(self) -> None:
            self.calls = []

        def count_sessions(self, session_source, external_only, ended_only):
            self.calls.append((session_source, external_only, ended_only))
            return 37

        def list_session_rows(self, *args, **kwargs):
            raise AssertionError("count-capable storage must not scan session rows")

    storage = FakeStorage()
    assert completed_session_count(
        "mongodb://example.invalid/honeypot",
        storage=storage,
    ) == 37
    assert storage.calls == [("production_live", True, True)]


def test_completed_session_count_has_bounded_legacy_fake_fallback() -> None:
    class FakeStorage:
        def __init__(self) -> None:
            self.calls = []

        def list_session_rows(self, limit, session_source, external_only):
            self.calls.append((limit, session_source, external_only))
            return [
                {
                    "payload": {
                        "session_id": "mongo-closed",
                        "src_ip": "8.8.4.4",
                        "is_ended": True,
                        "is_external_source": True,
                    }
                },
                {
                    "session_id": "mongo-active",
                    "src_ip": "1.1.1.1",
                    "ended": False,
                    "is_external_source": True,
                },
                {
                    "session_id": "mongo-private",
                    "src_ip": "100.64.0.2",
                    "ended": True,
                    "is_external_source": False,
                },
                {
                    "session_id": "legacy-external",
                    "src_ip": "9.9.9.9",
                    "ended": "1",
                },
                {
                    "session_id": "legacy-private",
                    "src_ip": "192.168.1.10",
                    "ended": "true",
                },
            ]

    storage = FakeStorage()
    assert completed_session_count(
        "mongodb://example.invalid/honeypot",
        storage=storage,
    ) == 2
    assert storage.calls == [
        (LEGACY_SESSION_COUNT_SCAN_LIMIT, "production_live", False)
    ]


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
