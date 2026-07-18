from __future__ import annotations

import json
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest

from production.storage import PostgresStorage, SQLiteStorage, StorageBackend


BASE_TIME = datetime(2026, 7, 18, 8, 0, tzinfo=timezone.utc)
LEADER_TOKEN = "00000000-0000-4000-8000-000000000001"
TOKEN_A = "00000000-0000-4000-8000-000000000002"
TOKEN_B = "00000000-0000-4000-8000-000000000003"
TOKEN_NEW = "00000000-0000-4000-8000-000000000004"


def _at(seconds: float) -> datetime:
    return BASE_TIME + timedelta(seconds=seconds)


def _storage(path: Path) -> SQLiteStorage:
    storage = SQLiteStorage(f"sqlite:///{path}")
    storage.initialize()
    return storage


def _store_events(storage: SQLiteStorage, count: int) -> list[str]:
    event_ids = []
    for index in range(count):
        event_id, inserted = storage.store_event(
            "sensor-a",
            {
                "eventid": "cowrie.command.input",
                "session": f"session-{index}",
                "src_ip": "192.0.2.1",
                "timestamp": _at(index).isoformat(),
                "input": f"command-{index}",
            },
        )
        assert inserted is True
        event_ids.append(event_id)
    return event_ids


def test_initialize_migrates_legacy_event_and_session_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy.db"
    with sqlite3.connect(database_path) as conn:
        conn.executescript(
            """
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                sensor_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                eventid TEXT NOT NULL,
                timestamp TEXT,
                payload_json TEXT NOT NULL,
                received_at TEXT NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                src_ip TEXT NOT NULL,
                start_time TEXT,
                ended INTEGER NOT NULL DEFAULT 0,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO events(
                event_id, sensor_id, session_id, src_ip, eventid,
                timestamp, payload_json, received_at, processed
            ) VALUES (
                'legacy-processed', 'sensor-a', 'session-old', '192.0.2.2',
                'cowrie.session.closed', NULL, '{}',
                '2026-07-18T07:00:00+00:00', 1
            );
            INSERT INTO sessions(
                session_id, src_ip, start_time, ended, payload_json, updated_at
            ) VALUES (
                'session-old', '192.0.2.2', NULL, 1, '{}',
                '2026-07-18T07:00:00+00:00'
            );
            """
        )

    storage = _storage(database_path)

    with storage.connection() as conn:
        event_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(events)")
        }
        session_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(sessions)")
        }
        indexes = {
            row["name"] for row in conn.execute("PRAGMA index_list(events)")
        }
        session_indexes = {
            row["name"] for row in conn.execute("PRAGMA index_list(sessions)")
        }
        legacy = conn.execute(
            """
            SELECT processed, attempts, processing_outcome, processed_at
            FROM events WHERE event_id = 'legacy-processed'
            """
        ).fetchone()
        worker_table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='worker_leases'"
        ).fetchone()

    assert {
        "claim_owner",
        "claim_token",
        "claim_leader_scope",
        "claim_leader_token",
        "claim_expires_at",
        "attempts",
        "next_retry_at",
        "last_error_code",
        "last_error_type",
        "last_error_at",
        "processing_outcome",
        "processed_at",
        "effect_summary_json",
    } <= event_columns
    assert {"session_source", "is_external_source"} <= session_columns
    assert {
        "idx_events_claimable",
        "idx_events_failed",
        "idx_events_leader_claims",
        "idx_events_session_queue",
    } <= indexes
    assert "idx_sessions_active_source_updated" in session_indexes
    assert worker_table is not None
    assert dict(legacy) == {
        "processed": 1,
        "attempts": 0,
        "processing_outcome": None,
        "processed_at": None,
    }
    assert storage.claim_events("worker-a", 10, 30, now=BASE_TIME) == []


def test_postgres_lifecycle_contract_and_schema_are_structurally_complete() -> None:
    # Construction is deliberately bypassed so this remains a no-driver,
    # no-connection structural check rather than a claim of PostgreSQL runtime
    # verification.
    postgres = PostgresStorage.__new__(PostgresStorage)
    assert isinstance(postgres, StorageBackend)

    root = Path(__file__).parents[1]
    schema = (root / "production/storage/postgres_schema.sql").read_text(
        encoding="utf-8"
    )
    for column in (
        "claim_owner",
        "claim_token",
        "claim_leader_scope",
        "claim_leader_token",
        "claim_expires_at",
        "attempts",
        "next_retry_at",
        "last_error_code",
        "last_error_type",
        "last_error_at",
        "processing_outcome",
        "processed_at",
        "effect_summary_json",
    ):
        assert f"ADD COLUMN IF NOT EXISTS {column} " in schema
    assert "CREATE TABLE IF NOT EXISTS worker_leases" in schema
    assert "CREATE INDEX IF NOT EXISTS idx_events_claimable" in schema
    assert "CREATE INDEX IF NOT EXISTS idx_events_failed" in schema
    assert "CREATE INDEX IF NOT EXISTS idx_events_leader_claims" in schema
    assert "CREATE INDEX IF NOT EXISTS idx_events_session_queue" in schema
    assert "CREATE INDEX IF NOT EXISTS idx_sessions_active_source_updated" in schema

    backend_source = (root / "production/storage/backend.py").read_text(
        encoding="utf-8"
    ).split("class PostgresStorage", 1)[1]
    assert "FOR UPDATE OF candidate SKIP LOCKED" in backend_source
    assert "RETURNING attempts" in backend_source


def test_postgres_failed_event_timestamps_are_canonical_iso_strings() -> None:
    postgres = PostgresStorage.__new__(PostgresStorage)

    class Cursor:
        def fetchall(self) -> list[dict]:
            return [
                {
                    "event_id": "event-a",
                    "sensor_id": "sensor-a",
                    "payload_json": {},
                    "attempts": 2,
                    "last_error_code": "database_unavailable",
                    "last_error_type": "StorageError",
                    "last_error_at": datetime(
                        2026, 7, 18, 8, 1, tzinfo=timezone(timedelta(hours=2))
                    ),
                    "processing_outcome": "dead_letter",
                    "processed_at": datetime(2026, 7, 18, 8, 2),
                }
            ]

    @contextmanager
    def connection():
        yield object()

    postgres.connection = connection  # type: ignore[method-assign]
    postgres._execute = lambda *_args, **_kwargs: Cursor()  # type: ignore[method-assign]

    failed = postgres.list_failed_events()
    assert failed[0]["last_error_at"] == "2026-07-18T06:01:00+00:00"
    assert failed[0]["processed_at"] == "2026-07-18T08:02:00+00:00"


def test_two_sqlite_claimers_receive_disjoint_events(tmp_path: Path) -> None:
    database_path = tmp_path / "claims.db"
    first = _storage(database_path)
    second = SQLiteStorage(f"sqlite:///{database_path}")
    event_ids = set(_store_events(first, 4))
    barrier = Barrier(2)

    def claim(storage: SQLiteStorage, owner: str) -> list[dict]:
        barrier.wait()
        return storage.claim_events(owner, 2, 30, now=BASE_TIME)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(claim, first, "worker-a")
        second_future = executor.submit(claim, second, "worker-b")
        first_claims = first_future.result()
        second_claims = second_future.result()

    first_ids = {row["event_id"] for row in first_claims}
    second_ids = {row["event_id"] for row in second_claims}
    assert len(first_ids) == 2
    assert len(second_ids) == 2
    assert first_ids.isdisjoint(second_ids)
    assert first_ids | second_ids == event_ids
    for claim in first_claims + second_claims:
        assert claim["claim_owner"] in {"worker-a", "worker-b"}
        assert claim["attempts"] == 1
        assert uuid.UUID(claim["claim_token"]).version == 4
        assert claim["event"] == json.loads(claim["payload_json"])


def test_claims_require_leader_lease_covering_full_event_lease(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path / "leader-fenced-claims.db")
    _store_events(storage, 1)
    assert storage.acquire_worker_lease(
        "session-worker", "worker-a", LEADER_TOKEN, 10, now=BASE_TIME
    )

    assert storage.claim_events(
        "worker-a",
        1,
        20,
        now=BASE_TIME,
        leader_scope="session-worker",
        leader_token=LEADER_TOKEN,
    ) == []
    assert storage.renew_worker_lease(
        "session-worker", "worker-a", LEADER_TOKEN, 30, now=BASE_TIME
    )
    claim = storage.claim_events(
        "worker-a",
        1,
        20,
        now=BASE_TIME,
        leader_scope="session-worker",
        leader_token=LEADER_TOKEN,
    )
    assert len(claim) == 1
    assert claim[0]["claim_leader_scope"] == "session-worker"
    assert claim[0]["claim_leader_token"] == LEADER_TOKEN
    assert not storage.renew_event_claim(
        claim[0]["event_id"],
        "worker-a",
        claim[0]["claim_token"],
        30,
        now=_at(5),
        leader_scope="session-worker",
        leader_token=LEADER_TOKEN,
    )
    assert storage.renew_worker_lease(
        "session-worker", "worker-a", LEADER_TOKEN, 40, now=_at(5)
    )
    assert storage.renew_event_claim(
        claim[0]["event_id"],
        "worker-a",
        claim[0]["claim_token"],
        30,
        now=_at(5),
        leader_scope="session-worker",
        leader_token=LEADER_TOKEN,
    )
    with pytest.raises(ValueError, match="provided together"):
        storage.claim_events(
            "worker-a",
            1,
            20,
            now=BASE_TIME,
            leader_scope="session-worker",
        )


def test_unbound_claim_rejects_supplied_leader_context(tmp_path: Path) -> None:
    storage = _storage(tmp_path / "unbound-claim.db")
    event_id = _store_events(storage, 1)[0]
    claim = storage.claim_events("worker-a", 1, 20, now=BASE_TIME)[0]
    assert claim["claim_leader_scope"] == ""
    assert claim["claim_leader_token"] == ""
    assert storage.acquire_worker_lease(
        "session-worker", "worker-a", TOKEN_A, 30, now=BASE_TIME
    )

    leader_kwargs = {
        "now": _at(1),
        "leader_scope": "session-worker",
        "leader_token": TOKEN_A,
    }
    assert not storage.renew_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        10,
        **leader_kwargs,
    )
    assert not storage.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        **leader_kwargs,
    )
    assert storage.fail_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        "stale_leader",
        "LeadershipLost",
        True,
        5,
        0,
        **leader_kwargs,
    ) == "stale_claim"
    assert not storage.release_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        **leader_kwargs,
    )
    assert storage.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        {"event_applied": True},
        now=_at(1),
    )


def test_later_session_event_cannot_bypass_delayed_predecessor(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path / "head-of-line.db")
    first_id, _ = storage.store_event(
        "sensor-a",
        {
            "eventid": "cowrie.command.input",
            "session": "same-session",
            "src_ip": "192.0.2.1",
            "timestamp": BASE_TIME.isoformat(),
            "input": "first",
        },
    )
    second_id, _ = storage.store_event(
        "sensor-a",
        {
            "eventid": "cowrie.command.input",
            "session": "same-session",
            "src_ip": "192.0.2.1",
            "timestamp": _at(1).isoformat(),
            "input": "second",
        },
    )
    first = storage.claim_events("worker-a", 10, 30, now=BASE_TIME)
    assert [row["event_id"] for row in first] == [first_id]
    assert storage.claim_events("worker-z", 10, 30, now=BASE_TIME) == []
    assert storage.fail_event(
        first_id,
        "worker-a",
        first[0]["claim_token"],
        "temporary_dependency",
        "DependencyUnavailable",
        True,
        5,
        60,
        now=_at(1),
    ) == "retry_scheduled"

    other_id, _ = storage.store_event(
        "sensor-a",
        {
            "eventid": "cowrie.command.input",
            "session": "other-session",
            "src_ip": "192.0.2.1",
            "timestamp": _at(2).isoformat(),
            "input": "independent",
        },
    )

    independent = storage.claim_events("worker-b", 10, 30, now=_at(30))
    assert [row["event_id"] for row in independent] == [other_id]
    retry = storage.claim_events("worker-b", 10, 30, now=_at(61))[0]
    assert retry["event_id"] == first_id
    assert storage.complete_event(
        first_id, "worker-b", retry["claim_token"], now=_at(62)
    )
    following = storage.claim_events("worker-b", 10, 30, now=_at(62))
    assert [row["event_id"] for row in following] == [second_id]


@pytest.mark.parametrize("corrupt_payload", ["not-json", "[]"])
def test_invalid_head_payload_is_dead_lettered_and_unblocks_following_event(
    tmp_path: Path,
    corrupt_payload: str,
) -> None:
    storage = _storage(tmp_path / "corrupt-payload.db")
    invalid_id, _ = storage.store_event(
        "sensor-a",
        {
            "eventid": "cowrie.command.input",
            "session": "same-session",
            "src_ip": "192.0.2.1",
            "timestamp": BASE_TIME.isoformat(),
            "input": "invalid-head",
        },
    )
    following_id, _ = storage.store_event(
        "sensor-a",
        {
            "eventid": "cowrie.command.input",
            "session": "same-session",
            "src_ip": "192.0.2.1",
            "timestamp": _at(1).isoformat(),
            "input": "valid-following",
        },
    )
    with storage.connection() as conn:
        conn.execute(
            "UPDATE events SET payload_json = ?, received_at = ? WHERE event_id = ?",
            (corrupt_payload, BASE_TIME.isoformat(), invalid_id),
        )
        conn.execute(
            "UPDATE events SET received_at = ? WHERE event_id = ?",
            (_at(1).isoformat(), following_id),
        )

    claimed = storage.claim_events("worker-a", 1, 30, now=_at(2))

    assert [row["event_id"] for row in claimed] == [following_id]
    failed = storage.list_failed_events()
    assert len(failed) == 1
    assert failed[0]["event_id"] == invalid_id
    assert failed[0]["event"] == {}
    assert failed[0]["payload_json"] == "{}"
    assert failed[0]["last_error_code"] == "event_processing_invalid"
    assert failed[0]["last_error_type"] == "ValidationError"
    assert failed[0]["last_error_at"] == _at(2).isoformat()


def test_expired_claim_is_reclaimed_and_old_fencing_token_is_stale(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path / "expiry.db")
    _store_events(storage, 1)
    old = storage.claim_events("worker-a", 1, 10, now=BASE_TIME)[0]

    assert storage.claim_events("worker-b", 1, 10, now=_at(9)) == []
    current = storage.claim_events("worker-b", 1, 10, now=_at(10))[0]

    assert current["event_id"] == old["event_id"]
    assert current["attempts"] == 2
    assert current["claim_token"] != old["claim_token"]
    assert not storage.complete_event(
        old["event_id"], "worker-a", old["claim_token"], now=_at(11)
    )
    assert not storage.renew_event_claim(
        old["event_id"], "worker-a", old["claim_token"], 10, now=_at(11)
    )
    assert not storage.release_event_claim(
        old["event_id"], "worker-a", old["claim_token"], now=_at(11)
    )
    assert (
        storage.fail_event(
            old["event_id"],
            "worker-a",
            old["claim_token"],
            "stale_worker",
            "WorkerError",
            True,
            5,
            0,
            now=_at(11),
        )
        == "stale_claim"
    )


def test_retry_delay_blocks_reclaim_until_due(tmp_path: Path) -> None:
    storage = _storage(tmp_path / "retry.db")
    _store_events(storage, 1)
    claim = storage.claim_events("worker-a", 1, 10, now=BASE_TIME)[0]

    result = storage.fail_event(
        claim["event_id"],
        "worker-a",
        claim["claim_token"],
        "temporary_dependency",
        "DependencyUnavailable",
        True,
        3,
        60,
        now=_at(1),
    )

    assert result == "retry_scheduled"
    assert storage.claim_events("worker-b", 1, 10, now=_at(60)) == []
    retried = storage.claim_events("worker-b", 1, 10, now=_at(61))[0]
    assert retried["attempts"] == 2


@pytest.mark.parametrize("invalid_duration", [float("nan"), float("inf")])
def test_lifecycle_durations_must_be_finite(
    tmp_path: Path,
    invalid_duration: float,
) -> None:
    storage = _storage(tmp_path / f"duration-{invalid_duration}.db")
    _store_events(storage, 1)
    with pytest.raises(ValueError, match="positive number"):
        storage.claim_events(
            "worker-a", 1, invalid_duration, now=BASE_TIME
        )

    claim = storage.claim_events("worker-a", 1, 10, now=BASE_TIME)[0]
    with pytest.raises(ValueError, match="non-negative"):
        storage.fail_event(
            claim["event_id"],
            "worker-a",
            claim["claim_token"],
            "temporary_dependency",
            "DependencyUnavailable",
            True,
            5,
            invalid_duration,
            now=_at(1),
        )


def test_attempt_exhaustion_dead_letters_crashed_event_with_stable_error(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path / "exhaustion.db")
    event_id = _store_events(storage, 1)[0]
    first = storage.claim_events(
        "worker-a", 1, 10, max_attempts=2, now=BASE_TIME
    )[0]
    second = storage.claim_events(
        "worker-b", 1, 10, max_attempts=2, now=_at(10)
    )[0]
    assert first["attempts"] == 1
    assert second["attempts"] == 2

    assert storage.claim_events(
        "worker-c", 1, 10, max_attempts=2, now=_at(20)
    ) == []
    failed = storage.list_failed_events()

    assert len(failed) == 1
    assert failed[0]["event_id"] == event_id
    assert failed[0]["attempts"] == 2
    assert failed[0]["processing_outcome"] == "dead_letter"
    assert failed[0]["last_error_code"] == "event_lease_attempts_exhausted"
    assert failed[0]["last_error_type"] == "LeaseExpired"
    assert failed[0]["last_error_at"] == _at(20).isoformat()


def test_attempt_exhaustion_only_dead_letters_current_session_head(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path / "exhaustion-order.db")
    event_ids = []
    for index in range(2):
        event_id, _ = storage.store_event(
            "sensor-a",
            {
                "eventid": "cowrie.command.input",
                "session": "same-session",
                "src_ip": "192.0.2.1",
                "timestamp": _at(index).isoformat(),
                "input": f"ordered-{index}",
            },
        )
        event_ids.append(event_id)
    with storage.connection() as conn:
        conn.execute("UPDATE events SET attempts = 2")
        ordered = [
            row["event_id"]
            for row in conn.execute(
                "SELECT event_id FROM events ORDER BY received_at, event_id"
            )
        ]

    assert storage.claim_events(
        "worker-a", 10, 30, max_attempts=2, now=BASE_TIME
    ) == []
    assert [row["event_id"] for row in storage.list_failed_events()] == [ordered[0]]
    with storage.connection() as conn:
        tail = conn.execute(
            "SELECT processed FROM events WHERE event_id = ?", (ordered[1],)
        ).fetchone()
    assert tail["processed"] == 0

    assert storage.claim_events(
        "worker-a", 10, 30, max_attempts=2, now=_at(1)
    ) == []
    assert {row["event_id"] for row in storage.list_failed_events()} == set(
        event_ids
    )


def test_terminal_failure_is_visible_without_persisting_error_detail(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path / "dead-letter.db")
    _store_events(storage, 1)
    claim = storage.claim_events("worker-a", 1, 30, now=BASE_TIME)[0]

    with pytest.raises(ValueError, match="registered event failure code"):
        storage.fail_event(
            claim["event_id"],
            "worker-a",
            claim["claim_token"],
            "secret detail with spaces",
            "RuntimeError",
            False,
            5,
            0,
            now=_at(1),
        )

    result = storage.fail_event(
        claim["event_id"],
        "worker-a",
        claim["claim_token"],
        "invalid_event",
        "ValidationError",
        False,
        5,
        0,
        now=_at(1),
    )

    assert result == "dead_letter"
    failed = storage.list_failed_events()
    assert len(failed) == 1
    assert failed[0]["last_error_code"] == "invalid_event"
    assert failed[0]["last_error_type"] == "ValidationError"
    assert "secret detail" not in json.dumps(failed[0])
    assert storage.fetch_unprocessed_events(10) == []


def test_success_persists_effect_summary_and_clears_claim(tmp_path: Path) -> None:
    storage = _storage(tmp_path / "success.db")
    event_id = _store_events(storage, 1)[0]
    initial = storage.claim_events("worker-a", 1, 30, now=BASE_TIME)[0]
    assert storage.fail_event(
        event_id,
        "worker-a",
        initial["claim_token"],
        "temporary_dependency",
        "DependencyUnavailable",
        True,
        5,
        0,
        now=_at(1),
    ) == "retry_scheduled"
    claim = storage.claim_events("worker-b", 1, 30, now=_at(1))[0]

    assert storage.complete_event(
        event_id,
        "worker-b",
        claim["claim_token"],
        {"session_saved": True, "alerts_created": 1},
        now=_at(2),
    )
    assert not storage.complete_event(
        event_id, "worker-b", claim["claim_token"], now=_at(3)
    )

    with storage.connection() as conn:
        row = conn.execute(
            """
            SELECT processed, processing_outcome, processed_at,
                   effect_summary_json, claim_owner, claim_token, claim_expires_at,
                   last_error_code, last_error_type, last_error_at
            FROM events WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
    assert row["processed"] == 1
    assert row["processing_outcome"] == "succeeded"
    assert row["processed_at"] == _at(2).isoformat()
    assert json.loads(row["effect_summary_json"]) == {
        "alerts_created": 1,
        "session_saved": True,
    }
    assert row["claim_owner"] is None
    assert row["claim_token"] is None
    assert row["claim_expires_at"] is None
    assert row["last_error_code"] is None
    assert row["last_error_type"] is None
    assert row["last_error_at"] is None


@pytest.mark.parametrize(
    "invalid_summary",
    [
        {"arbitrary_secret": True},
        {"session_saved": "secret-value"},
        {"session_saved": {"nested": True}},
        {"alerts_created": -1},
        {"alerts_created": 1_000_001},
    ],
)
def test_effect_summary_rejects_arbitrary_nested_or_oversized_values(
    tmp_path: Path,
    invalid_summary: dict,
) -> None:
    storage = _storage(tmp_path / "invalid-effect.db")
    event_id = _store_events(storage, 1)[0]
    claim = storage.claim_events("worker-a", 1, 30, now=BASE_TIME)[0]

    with pytest.raises(ValueError, match="effect_summary"):
        storage.complete_event(
            event_id,
            "worker-a",
            claim["claim_token"],
            invalid_summary,
            now=_at(1),
        )

    with storage.connection() as conn:
        stored = conn.execute(
            "SELECT processed, claim_token, effect_summary_json FROM events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
    assert stored["processed"] == 0
    assert stored["claim_token"] == claim["claim_token"]
    assert stored["effect_summary_json"] is None


def test_worker_lease_active_passive_takeover_renew_and_release(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "leader.db"
    active = _storage(database_path)
    passive = SQLiteStorage(f"sqlite:///{database_path}")

    assert active.acquire_worker_lease(
        "session-worker", "worker-a", TOKEN_A, 10, now=BASE_TIME
    )
    assert not passive.acquire_worker_lease(
        "session-worker", "worker-b", TOKEN_B, 10, now=_at(1)
    )
    assert active.renew_worker_lease(
        "session-worker", "worker-a", TOKEN_A, 20, now=_at(5)
    )
    assert not passive.acquire_worker_lease(
        "session-worker", "worker-b", TOKEN_B, 10, now=_at(20)
    )
    assert passive.acquire_worker_lease(
        "session-worker", "worker-b", TOKEN_B, 10, now=_at(25)
    )
    assert not active.renew_worker_lease(
        "session-worker", "worker-a", TOKEN_A, 10, now=_at(26)
    )
    assert not active.release_worker_lease(
        "session-worker", "worker-a", TOKEN_A, now=_at(26)
    )
    assert passive.renew_worker_lease(
        "session-worker", "worker-b", TOKEN_B, 10, now=_at(26)
    )
    assert passive.release_worker_lease(
        "session-worker", "worker-b", TOKEN_B, now=_at(27)
    )
    assert active.acquire_worker_lease(
        "session-worker", "worker-a", TOKEN_NEW, 10, now=_at(28)
    )


def test_live_event_claim_blocks_takeover_and_stale_leader_terminal_actions(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "takeover-grace.db"
    active = _storage(database_path)
    standby = SQLiteStorage(f"sqlite:///{database_path}")
    event_id = _store_events(active, 1)[0]
    assert active.acquire_worker_lease(
        "session-worker", "worker-a", TOKEN_A, 30, now=BASE_TIME
    )
    claim = active.claim_events(
        "worker-a",
        1,
        20,
        now=BASE_TIME,
        leader_scope="session-worker",
        leader_token=TOKEN_A,
    )[0]
    assert not active.complete_event(
        event_id, "worker-a", claim["claim_token"], now=_at(1)
    )
    assert not active.renew_event_claim(
        event_id, "worker-a", claim["claim_token"], 10, now=_at(1)
    )

    assert active.release_worker_lease(
        "session-worker", "worker-a", TOKEN_A, now=_at(1)
    )
    assert not active.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        now=_at(2),
    )
    assert active.fail_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        "stale_leader",
        "LeadershipLost",
        True,
        5,
        0,
        now=_at(2),
    ) == "stale_claim"
    assert not active.release_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        now=_at(2),
    )
    assert not standby.acquire_worker_lease(
        "session-worker", "worker-b", TOKEN_B, 40, now=_at(2)
    )
    assert not active.acquire_worker_lease(
        "session-worker", "worker-a", TOKEN_NEW, 40, now=_at(2)
    )
    assert standby.acquire_worker_lease(
        "other-worker-scope", "worker-b", TOKEN_B, 40, now=_at(2)
    )
    assert not active.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        now=_at(2),
        leader_scope="session-worker",
        leader_token=TOKEN_A,
    )
    assert active.fail_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        "stale_leader",
        "LeadershipLost",
        True,
        5,
        0,
        now=_at(2),
        leader_scope="session-worker",
        leader_token=TOKEN_A,
    ) == "stale_claim"
    assert not active.release_event_claim(
        event_id,
        "worker-a",
        claim["claim_token"],
        now=_at(2),
        leader_scope="session-worker",
        leader_token=TOKEN_A,
    )

    assert standby.acquire_worker_lease(
        "session-worker", "worker-b", TOKEN_B, 40, now=_at(20)
    )
    assert not active.complete_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        now=_at(20),
        leader_scope="session-worker",
        leader_token=TOKEN_A,
    )
    reclaimed = standby.claim_events(
        "worker-b",
        1,
        10,
        now=_at(20),
        leader_scope="session-worker",
        leader_token=TOKEN_B,
    )[0]
    assert reclaimed["attempts"] == 2
    assert standby.complete_event(
        event_id,
        "worker-b",
        reclaimed["claim_token"],
        {"session_saved": True},
        now=_at(21),
        leader_scope="session-worker",
        leader_token=TOKEN_B,
    )
    with standby.connection() as conn:
        stored = conn.execute(
            """
            SELECT claim_owner, claim_token, claim_leader_scope,
                   claim_leader_token, claim_expires_at
            FROM events WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
    assert dict(stored) == {
        "claim_owner": None,
        "claim_token": None,
        "claim_leader_scope": None,
        "claim_leader_token": None,
        "claim_expires_at": None,
    }


def test_release_makes_event_immediately_claimable_but_preserves_attempts(
    tmp_path: Path,
) -> None:
    storage = _storage(tmp_path / "release.db")
    _store_events(storage, 1)
    first = storage.claim_events("worker-a", 1, 30, now=BASE_TIME)[0]

    assert storage.release_event_claim(
        first["event_id"], "worker-a", first["claim_token"], now=_at(1)
    )
    second = storage.claim_events("worker-b", 1, 30, now=_at(1))[0]
    assert second["event_id"] == first["event_id"]
    assert second["attempts"] == 2


def test_legacy_mark_processed_clears_lifecycle_state(tmp_path: Path) -> None:
    storage = _storage(tmp_path / "legacy-mark.db")
    event_id = _store_events(storage, 1)[0]
    claim = storage.claim_events("worker-a", 1, 30, now=BASE_TIME)[0]
    assert storage.fail_event(
        event_id,
        "worker-a",
        claim["claim_token"],
        "temporary_dependency",
        "DependencyUnavailable",
        True,
        5,
        60,
        now=_at(1),
    ) == "retry_scheduled"

    storage.mark_event_processed(event_id)

    with storage.connection() as conn:
        row = conn.execute(
            """
            SELECT processed, processing_outcome, processed_at, next_retry_at,
                   last_error_code, last_error_type, last_error_at,
                   effect_summary_json, claim_owner, claim_token, claim_expires_at
            FROM events WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
    assert row["processed"] == 1
    assert row["processing_outcome"] == "succeeded"
    assert row["processed_at"]
    assert row["next_retry_at"] is None
    assert row["last_error_code"] is None
    assert row["last_error_type"] is None
    assert row["last_error_at"] is None
    assert row["effect_summary_json"] is None
    assert row["claim_owner"] is None
    assert row["claim_token"] is None
    assert row["claim_expires_at"] is None
