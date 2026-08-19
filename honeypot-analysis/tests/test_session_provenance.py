from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from production.storage.session_provenance import (
    CONTROLLED_SYNTHETIC_PROVENANCE_MARKER,
    SESSION_SOURCE_E2E_TEST,
    SESSION_SOURCE_PRODUCTION_LIVE,
    SESSION_SOURCE_UNKNOWN_LEGACY,
    controlled_synthetic_provenance,
    infer_legacy_session_source,
    is_external_source_ip,
)


def test_controlled_synthetic_provenance_requires_authenticated_sensor_and_source() -> None:
    bound = controlled_synthetic_provenance(
        sensor_id="demo-sensor",
        source_ip="100.85.50.74",
        allowed_sensor_ids=["demo-sensor"],
        allowed_source_ips=["100.85.50.74"],
    )
    assert bound == {
        "session_source": SESSION_SOURCE_E2E_TEST,
        "provenance_marker": CONTROLLED_SYNTHETIC_PROVENANCE_MARKER,
    }
    assert controlled_synthetic_provenance(
        sensor_id="demo-sensor",
        source_ip="203.0.113.10",
        allowed_sensor_ids=["demo-sensor"],
        allowed_source_ips=["100.85.50.74"],
    ) == {"session_source": SESSION_SOURCE_PRODUCTION_LIVE, "provenance_marker": ""}
    assert controlled_synthetic_provenance(
        sensor_id="other-sensor",
        source_ip="100.85.50.74",
        allowed_sensor_ids=["demo-sensor"],
        allowed_source_ips=["100.85.50.74"],
    ) == {"session_source": SESSION_SOURCE_PRODUCTION_LIVE, "provenance_marker": ""}
from production.tools.backfill_session_source import classify_rows, apply_backfill


def test_infer_legacy_session_source_is_exclusion_safe() -> None:
    assert (
        infer_legacy_session_source(
            {
                "session_id": "controlled-test-public",
                "src_ip": "198.51.100.152",
                "start_time": "2026-07-06T17:30:00+07:00",
            }
        )
        == SESSION_SOURCE_E2E_TEST
    )
    assert (
        infer_legacy_session_source(
            {
                "session_id": "old-real-looking",
                "src_ip": "198.51.100.45",
                "start_time": "2026-05-09T00:00:00+00:00",
            }
        )
        == SESSION_SOURCE_UNKNOWN_LEGACY
    )
    assert (
        infer_legacy_session_source(
            {
                "session_id": "post-fix-scanner",
                "src_ip": "192.0.0.9",
                "start_time": "2026-07-06T17:41:01+07:00",
            }
        )
        == SESSION_SOURCE_PRODUCTION_LIVE
    )


def test_is_external_source_ip_excludes_private_and_tailscale_ranges() -> None:
    assert is_external_source_ip("192.0.0.9") is True
    assert is_external_source_ip("192.0.0.10") is True
    assert is_external_source_ip("10.0.0.5") is False
    assert is_external_source_ip("192.168.1.9") is False
    assert is_external_source_ip("100.64.0.42") is False
    assert is_external_source_ip("127.0.0.1") is False
    assert is_external_source_ip("unknown") is False


def test_backfill_updates_column_and_payload_json(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            create table sessions (
                session_id text primary key,
                src_ip text not null,
                start_time text,
                ended integer not null,
                session_source text not null default 'unknown_legacy',
                is_external_source integer not null default 0,
                payload_json text not null,
                updated_at text not null
            )
            """
        )
        rows = [
            ("controlled-test-public", "198.51.100.152", "2026-07-06T17:30:00+07:00", 1),
            ("post-fix-scanner", "192.0.0.9", "2026-07-06T17:41:01+07:00", 1),
        ]
        for session_id, src_ip, start_time, ended in rows:
            conn.execute(
                """
                insert into sessions
                    (session_id, src_ip, start_time, ended, payload_json, updated_at)
                values (?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    src_ip,
                    start_time,
                    ended,
                    json.dumps({"session_id": session_id, "src_ip": src_ip}),
                    "2026-07-06T18:00:00+07:00",
                ),
            )
        classified = classify_rows([dict(row) for row in conn.execute("select * from sessions")])
        apply_backfill(conn, classified)

        sources = {
            row["session_id"]: row["session_source"]
            for row in conn.execute("select session_id, session_source from sessions")
        }
        assert sources == {
            "controlled-test-public": SESSION_SOURCE_E2E_TEST,
            "post-fix-scanner": SESSION_SOURCE_PRODUCTION_LIVE,
        }
        external_flags = {
            row["session_id"]: bool(row["is_external_source"])
            for row in conn.execute("select session_id, is_external_source from sessions")
        }
        assert external_flags == {
            "controlled-test-public": False,
            "post-fix-scanner": True,
        }

        payload = json.loads(
            conn.execute(
                "select payload_json from sessions where session_id = ?",
                ("post-fix-scanner",),
            ).fetchone()["payload_json"]
        )
        assert payload["session_source"] == SESSION_SOURCE_PRODUCTION_LIVE
        assert payload["is_external_source"] is True
