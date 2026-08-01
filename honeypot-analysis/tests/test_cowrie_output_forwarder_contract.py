from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from production.cowrie_output import sanitized_jsonlog
from production.utils.cowrie_privacy import DEFAULT_POLICY
from production.workers import sensor_forwarder


class _OpenFeed:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle = path.open("a", encoding="utf-8")

    def write(self, value: str) -> None:
        self.handle.write(value)

    def flush(self) -> None:
        self.handle.flush()
        os.fsync(self.handle.fileno())

    def close(self) -> None:
        self.handle.close()


def _writer(feed: _OpenFeed):
    output = object.__new__(sanitized_jsonlog.Output)
    output.outfile = feed
    output._boundary = SimpleNamespace(policy=DEFAULT_POLICY)
    output.epoch_timestamp = False
    output._observer_sequence = 0
    return output


def _event(index: int, secret: str) -> dict:
    return {
        "eventid": "cowrie.login.success",
        "session": f"session-{index}",
        "timestamp": f"2026-08-01T00:00:0{index}Z",
        "sensor": "isolated-sensor",
        "src_ip": "192.0.2.10",
        "username": f"user-{secret}",
        "password": secret,
        "message": f"credential material {secret}",
    }


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        sensor_id="isolated-sensor",
        api_token="not-used",
        cowrie_log_path=str(tmp_path / "cowrie.json"),
        spool_path=str(tmp_path / "spool.ndjson"),
        ingest_url="http://127.0.0.1:9/events",
        forwarder_batch_size=10,
        forwarder_timeout_seconds=1,
        forwarder_max_spool_bytes=1024 * 1024,
        forwarder_min_free_bytes=0,
        forwarder_max_line_bytes=64 * 1024,
    )


def test_json_writer_forwarder_restart_and_native_rotation_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed_path = tmp_path / "cowrie.json"
    feed_path.touch(mode=0o640)
    feed_path.chmod(0o640)
    config = _config(tmp_path)
    delivered: list[dict] = []
    spool_counts_at_delivery: list[int] = []

    def acknowledge(_config: object, events: list[dict]) -> dict:
        spool = Path(config.spool_path)
        spool_counts_at_delivery.append(
            len([line for line in spool.read_text().splitlines() if line.strip()])
        )
        delivered.extend(events)
        return {"accepted": len(events), "duplicates": 0, "rejected": []}

    monkeypatch.setattr(sensor_forwarder, "post_events", acknowledge)
    secrets = ["first-arbitrary-secret", "restart-arbitrary-secret", "rotation-secret"]

    first_feed = _OpenFeed(feed_path)
    first_writer = _writer(first_feed)
    first_writer.write(_event(1, secrets[0]))
    first = sensor_forwarder.forward_once(config)
    assert first.sent == 1
    assert first.spooled == 1
    assert first.remaining == 0
    assert sensor_forwarder.forward_once(config).sent == 0

    first_feed.close()
    restarted_feed = _OpenFeed(feed_path)
    restarted_writer = _writer(restarted_feed)
    restarted_writer.write(_event(2, secrets[1]))
    restarted = sensor_forwarder.forward_once(config)
    assert restarted.sent == 1

    # Cowrie's JSON writer rotates by rename/reopen. The forwarder identifies
    # the renamed inode and drains it before switching to the new feed.
    restarted_feed.close()
    historical = Path(f"{feed_path}.2026-08-01")
    feed_path.chmod(0o600)
    feed_path.rename(historical)
    feed_path.touch(mode=0o640)
    feed_path.chmod(0o640)
    empty_after_rotation = sensor_forwarder.forward_once(config)
    assert empty_after_rotation.rotation_detected is True
    assert empty_after_rotation.sent == 0

    rotated_feed = _OpenFeed(feed_path)
    _writer(rotated_feed).write(_event(3, secrets[2]))
    after_rotation = sensor_forwarder.forward_once(config)
    rotated_feed.close()

    assert after_rotation.sent == 1
    assert after_rotation.remaining == 0
    assert spool_counts_at_delivery == [1, 1, 1]
    assert [event["session"] for event in delivered] == [
        "session-1",
        "session-2",
        "session-3",
    ]
    assert len(delivered) == 3
    assert all(event["username"] == "[REDACTED]" for event in delivered)
    assert all(event["password"] == "[REDACTED]" for event in delivered)
    encoded = json.dumps(delivered, sort_keys=True)
    assert all(secret not in encoded for secret in secrets)
    assert stat.S_IMODE(feed_path.stat().st_mode) == 0o640
    assert stat.S_IMODE(historical.stat().st_mode) == 0o600
    rotated_text = historical.read_text(encoding="utf-8")
    assert all(secret not in rotated_text for secret in secrets)
    assert not Path(config.spool_path).exists()


def test_native_rotation_gives_forwarder_a_bounded_read_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    feed = tmp_path / "cowrie.json"
    feed.write_text('{"eventid":"cowrie.session.connect"}\n', encoding="utf-8")
    feed.chmod(0o640)
    scheduled: list[tuple[float, object, tuple[object, ...]]] = []

    class _Reactor:
        @staticmethod
        def callLater(delay: float, callback: object, *args: object) -> None:
            scheduled.append((delay, callback, args))

        @staticmethod
        def stop() -> None:
            raise AssertionError("valid rotation must not stop the reactor")

    rotated = Path(f"{feed}.2026-08-01")
    feed.rename(rotated)
    rotated.chmod(0o640)
    metadata = rotated.stat()
    monkeypatch.setattr(sanitized_jsonlog, "reactor", _Reactor())

    sanitized_jsonlog._schedule_rotated_feed_seal(
        str(rotated), metadata.st_dev, metadata.st_ino
    )

    assert stat.S_IMODE(rotated.stat().st_mode) == 0o640
    assert len(scheduled) == 1
    delay, callback, args = scheduled[0]
    assert delay == sanitized_jsonlog.ROTATED_FEED_HANDOFF_SECONDS
    callback(*args)  # type: ignore[operator]
    assert stat.S_IMODE(rotated.stat().st_mode) == 0o600


def test_native_rotation_sealer_rejects_replaced_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rotated = tmp_path / "cowrie.json.2026-08-01"
    rotated.write_text("replacement", encoding="utf-8")
    stopped: list[bool] = []

    class _Reactor:
        @staticmethod
        def callLater(_delay: float, callback: object, *args: object) -> None:
            callback(*args)  # type: ignore[operator]

        @staticmethod
        def stop() -> None:
            stopped.append(True)

    monkeypatch.setattr(sanitized_jsonlog, "reactor", _Reactor())
    sanitized_jsonlog._seal_rotated_feed(
        str(rotated), rotated.stat().st_dev, rotated.stat().st_ino + 1
    )

    assert stopped == [True]
    assert stat.S_IMODE(rotated.stat().st_mode) != 0o600


def test_partial_writer_record_is_not_forwarded_until_newline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    feed = Path(config.cowrie_log_path)
    feed.write_text('{"eventid":"cowrie.session.connect"', encoding="utf-8")
    delivered: list[dict] = []

    def acknowledge(_config: object, events: list[dict]) -> dict:
        delivered.extend(events)
        return {"accepted": len(events), "duplicates": 0, "rejected": []}

    monkeypatch.setattr(sensor_forwarder, "post_events", acknowledge)
    first = sensor_forwarder.forward_once(config)
    assert first.sent == 0
    assert first.source_offset == 0
    with feed.open("a", encoding="utf-8") as handle:
        handle.write(',"session":"complete"}\n')
    second = sensor_forwarder.forward_once(config)
    assert second.sent == 1
    assert delivered == [{"eventid": "cowrie.session.connect", "session": "complete"}]
