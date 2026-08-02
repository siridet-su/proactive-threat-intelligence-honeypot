from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from production.utils.config import ProductionConfig
from production.workers import sensor_forwarder


def _config(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    values = {
        "sensor_id": "phase10-sensor",
        "api_token": "fake-test-token",
        "cowrie_log_path": str(tmp_path / "cowrie.json"),
        "spool_path": str(tmp_path / "spool.ndjson"),
        "ingest_url": "http://127.0.0.1:9/events",
        "forwarder_batch_size": 10,
        "forwarder_timeout_seconds": 1,
        "forwarder_max_spool_bytes": 1024 * 1024,
        "forwarder_min_free_bytes": 0,
        "forwarder_max_line_bytes": 1024,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _write_events(path: str, events: list[dict]) -> None:
    Path(path).write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )


def _accept_all(captured: list[dict] | None = None):
    def post(_config: object, events: list[dict]) -> dict:
        if captured is not None:
            captured.extend(events)
        return {"accepted": len(events), "duplicates": 0, "rejected": []}

    return post


def _checkpoint(config: SimpleNamespace) -> sensor_forwarder.TailCheckpoint:
    return sensor_forwarder.CowrieLogTailer(
        config.cowrie_log_path, f"{config.spool_path}.offset"
    )._load_checkpoint()


def test_spool_fsync_completes_before_offset_commit(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    event = {"eventid": "cowrie.session.connect", "session": "durable-order"}
    _write_events(config.cowrie_log_path, [event])
    original_fsync = sensor_forwarder.os.fsync
    original_commit = sensor_forwarder.CowrieLogTailer.commit
    spool_fsynced = False

    def tracking_fsync(descriptor: int) -> None:
        nonlocal spool_fsynced
        try:
            target = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError:
            target = ""
        if target == config.spool_path:
            spool_fsynced = True
        original_fsync(descriptor)

    def tracking_commit(
        tailer: sensor_forwarder.CowrieLogTailer,
        checkpoint: sensor_forwarder.TailCheckpoint,
    ) -> None:
        assert spool_fsynced is True
        assert json.loads(Path(config.spool_path).read_text(encoding="utf-8")) == event
        original_commit(tailer, checkpoint)

    monkeypatch.setattr(sensor_forwarder.os, "fsync", tracking_fsync)
    monkeypatch.setattr(sensor_forwarder.CowrieLogTailer, "commit", tracking_commit)
    monkeypatch.setattr(sensor_forwarder, "post_events", _accept_all())

    result = sensor_forwarder.forward_once(config)

    assert result.sent == 1
    assert result.remaining == 0
    assert _checkpoint(config).offset == Path(config.cowrie_log_path).stat().st_size
    assert json.loads(Path(f"{config.spool_path}.offset").read_text())["schema"] == (
        sensor_forwarder.OFFSET_SCHEMA
    )


def test_spool_fsync_failure_never_advances_source_offset(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    _write_events(config.cowrie_log_path, [{"eventid": "cowrie.command.input"}])
    original_fsync = sensor_forwarder.os.fsync

    def fail_spool_fsync(descriptor: int) -> None:
        try:
            target = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError:
            target = ""
        if target == config.spool_path:
            raise OSError("simulated spool fsync crash")
        original_fsync(descriptor)

    monkeypatch.setattr(sensor_forwarder.os, "fsync", fail_spool_fsync)

    result = sensor_forwarder.forward_once(config)

    assert result.sent == 0
    assert result.error
    assert _checkpoint(config).offset == 0
    assert not Path(f"{config.spool_path}.offset").exists()


def test_offset_commit_failure_retains_spool_and_retry_cannot_lose_event(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path)
    event = {"eventid": "cowrie.command.input", "input": "id"}
    _write_events(config.cowrie_log_path, [event])
    original_commit = sensor_forwarder.CowrieLogTailer.commit

    def fail_commit(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated offset crash")

    monkeypatch.setattr(sensor_forwarder.CowrieLogTailer, "commit", fail_commit)
    first = sensor_forwarder.forward_once(config)
    assert first.sent == 0
    assert first.remaining == 1
    assert _checkpoint(config).offset == 0
    assert json.loads(Path(config.spool_path).read_text(encoding="utf-8")) == event

    captured: list[dict] = []
    monkeypatch.setattr(sensor_forwarder.CowrieLogTailer, "commit", original_commit)
    monkeypatch.setattr(sensor_forwarder, "post_events", _accept_all(captured))
    retry = sensor_forwarder.forward_once(config)

    # Re-appending after the append/offset crash window is an intentional
    # at-least-once replay. The ingest contract deduplicates stable events.
    assert retry.sent == 2
    assert captured == [event, event]
    assert retry.remaining == 0
    assert _checkpoint(config).offset > 0


def test_acknowledgement_rewrite_failure_preserves_original_spool(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path)
    event = {"eventid": "cowrie.session.closed", "session": "rewrite-crash"}
    _write_events(config.cowrie_log_path, [event])
    monkeypatch.setattr(sensor_forwarder, "post_events", _accept_all())
    original = sensor_forwarder._atomic_replace_bytes

    def fail_spool_replace(path: Path, payload: bytes) -> None:
        if path == Path(config.spool_path):
            raise OSError("simulated rewrite crash")
        original(path, payload)

    monkeypatch.setattr(sensor_forwarder, "_atomic_replace_bytes", fail_spool_replace)

    result = sensor_forwarder.forward_once(config)

    assert result.sent == 1
    assert result.error
    assert result.remaining == 1
    assert json.loads(Path(config.spool_path).read_text(encoding="utf-8")) == event


def test_atomic_spool_rewrite_keeps_only_unacknowledged_suffix(tmp_path) -> None:
    spool = sensor_forwarder.DiskSpool(str(tmp_path / "spool.ndjson"))
    events = [{"index": index} for index in range(3)]
    spool.append_many(events, max_spool_bytes=4096, min_free_bytes=0)
    _, remaining = spool.load_batch(2)

    spool.replace_remaining(remaining)

    assert json.loads(spool.path.read_text(encoding="utf-8")) == events[2]
    assert spool.path.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".spool.ndjson.*.tmp"))


def test_partial_record_is_not_spooled_or_checkpointed_until_complete(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path)
    path = Path(config.cowrie_log_path)
    path.write_text('{"eventid":"cowrie.command.input"', encoding="utf-8")
    monkeypatch.setattr(sensor_forwarder, "post_events", _accept_all())

    incomplete = sensor_forwarder.forward_once(config)
    assert incomplete.sent == 0
    assert incomplete.source_offset == 0
    assert _checkpoint(config).offset == 0

    with path.open("a", encoding="utf-8") as handle:
        handle.write(',"input":"whoami"}\n')
    complete = sensor_forwarder.forward_once(config)

    assert complete.sent == 1
    assert complete.parse_errors == 0
    assert _checkpoint(config).offset == path.stat().st_size


def test_legacy_bare_offset_replays_from_start_then_upgrades_identity_checkpoint(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path)
    first = {"eventid": "cowrie.session.connect", "session": "first"}
    second = {"eventid": "cowrie.session.closed", "session": "second"}
    _write_events(config.cowrie_log_path, [first, second])
    first_line_bytes = len(json.dumps(first, sort_keys=True).encode("utf-8")) + 1
    Path(f"{config.spool_path}.offset").write_text(
        str(first_line_bytes), encoding="utf-8"
    )
    captured: list[dict] = []
    monkeypatch.setattr(sensor_forwarder, "post_events", _accept_all(captured))

    result = sensor_forwarder.forward_once(config)

    assert result.sent == 2
    assert captured == [first, second]
    checkpoint = _checkpoint(config)
    assert checkpoint.offset == Path(config.cowrie_log_path).stat().st_size
    assert checkpoint.device is not None
    assert checkpoint.inode is not None


def test_rotation_and_truncation_restart_from_new_file_without_skipping(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path)
    captured: list[dict] = []
    monkeypatch.setattr(sensor_forwarder, "post_events", _accept_all(captured))
    first = {"eventid": "cowrie.session.connect", "session": "old"}
    rotated = {"eventid": "cowrie.session.connect", "session": "rotated"}
    truncated = {"eventid": "x"}
    _write_events(config.cowrie_log_path, [first])
    assert sensor_forwarder.forward_once(config).sent == 1

    replacement = tmp_path / "replacement.json"
    _write_events(str(replacement), [rotated])
    os.replace(replacement, config.cowrie_log_path)
    rotation_result = sensor_forwarder.forward_once(config)
    assert rotation_result.rotation_detected is True
    assert rotation_result.sent == 1

    # Truncate the same inode to a shorter complete record.
    _write_events(config.cowrie_log_path, [truncated])
    truncation_result = sensor_forwarder.forward_once(config)
    assert truncation_result.truncation_detected is True
    assert truncation_result.sent == 1
    assert captured == [first, rotated, truncated]


def test_rotation_drains_unread_renamed_inode_before_new_log(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path, forwarder_batch_size=1)
    captured: list[dict] = []
    monkeypatch.setattr(sensor_forwarder, "post_events", _accept_all(captured))
    old_first = {"eventid": "cowrie.command.input", "input": "first"}
    old_unread = {"eventid": "cowrie.command.input", "input": "unread"}
    new_event = {"eventid": "cowrie.session.connect", "session": "new-file"}
    _write_events(config.cowrie_log_path, [old_first, old_unread])
    assert sensor_forwarder.forward_once(config).sent == 1

    os.rename(config.cowrie_log_path, f"{config.cowrie_log_path}.1")
    _write_events(config.cowrie_log_path, [new_event])
    recovered = sensor_forwarder.forward_once(config)
    assert recovered.rotation_detected is True
    assert recovered.sent == 1
    # Reaching the renamed inode's EOF durably switches to offset zero on the
    # new identity. The next poll then reads the new file.
    assert _checkpoint(config).offset == 0
    current = sensor_forwarder.forward_once(config)

    assert current.sent == 1
    assert captured == [old_first, old_unread, new_event]


def test_instance_lock_prevents_second_reader_or_network_send(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    _write_events(config.cowrie_log_path, [{"eventid": "cowrie.session.connect"}])
    called = False

    def forbidden_post(*_args: object, **_kwargs: object) -> dict:
        nonlocal called
        called = True
        return {"accepted": 1, "duplicates": 0, "rejected": []}

    monkeypatch.setattr(sensor_forwarder, "post_events", forbidden_post)
    with sensor_forwarder.ForwarderInstanceLock(config.spool_path):
        result = sensor_forwarder.forward_once(config)

    assert result.lock_contended is True
    assert result.error == "forwarder instance lock is held"
    assert called is False
    assert not Path(config.spool_path).exists()
    assert not Path(f"{config.spool_path}.offset").exists()


def test_malformed_and_oversized_lines_are_bounded_and_do_not_retain_raw_data(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path, forwarder_max_line_bytes=32)
    secret = "secret-shaped-value-that-must-not-survive"
    Path(config.cowrie_log_path).write_bytes(
        (f'{{"password":"{secret}" invalid\n').encode("utf-8")
        + (b"x" * 4096)
        + b"\n"
    )
    monkeypatch.setattr(
        sensor_forwarder,
        "post_events",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )

    result = sensor_forwarder.forward_once(config)
    serialized = Path(config.spool_path).read_text(encoding="utf-8")
    records = [json.loads(line) for line in serialized.splitlines()]

    assert result.parse_errors == 2
    assert result.remaining == 2
    assert len(serialized) < 1024
    assert secret not in serialized
    assert {record["error"] for record in records} == {"line_too_large"}
    assert all(len(record["raw_line_sha256"]) == 64 for record in records)


def test_disk_limit_preserves_source_checkpoint_and_existing_backlog(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path, forwarder_max_spool_bytes=2)
    event = {"eventid": "cowrie.command.input", "input": "uptime"}
    _write_events(config.cowrie_log_path, [event])
    monkeypatch.setattr(
        sensor_forwarder,
        "post_events",
        lambda *_args, **_kwargs: pytest.fail("disk-limited event must not be posted"),
    )

    result = sensor_forwarder.forward_once(config)

    assert result.disk_limited is True
    assert result.sent == 0
    assert _checkpoint(config).offset == 0
    assert not Path(f"{config.spool_path}.offset").exists()


def test_forwarder_metrics_report_backlog_parse_and_source_state(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path)
    Path(config.cowrie_log_path).write_text("not-json\n", encoding="utf-8")
    monkeypatch.setattr(
        sensor_forwarder,
        "post_events",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )

    result = sensor_forwarder.forward_once(config)

    assert result.spooled == 1
    assert result.remaining == 1
    assert result.parse_errors == 1
    assert result.spool_bytes == Path(config.spool_path).stat().st_size
    assert result.source_offset == Path(config.cowrie_log_path).stat().st_size
    assert result.spool_parse_errors == 0
    assert result.disk_limited is False
    assert result.lock_contended is False


def test_corrupt_spool_error_is_bounded_stable_and_reported(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    raw = "not-json-with-secret-shaped-material"
    Path(config.spool_path).write_text(raw + "\n", encoding="utf-8")
    captured: list[dict] = []
    monkeypatch.setattr(sensor_forwarder, "post_events", _accept_all(captured))

    result = sensor_forwarder.forward_once(config)

    assert result.sent == 1
    assert result.spool_parse_errors == 1
    assert len(captured) == 1
    assert captured[0]["eventid"] == "forwarder.spool_parse_error"
    assert captured[0]["raw_line_sha256"]
    assert raw not in json.dumps(captured)
    assert "timestamp" not in captured[0]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("forwarder_batch_size", 0, "positive integer"),
        ("forwarder_max_spool_bytes", 0, "positive integer"),
        ("forwarder_min_free_bytes", -1, "non-negative integer"),
        ("forwarder_max_line_bytes", 1024 * 1024 + 1, "must not exceed"),
    ],
)
def test_forwarder_safety_configuration_fails_closed(field, value, message) -> None:
    with pytest.raises(ValueError, match=message):
        ProductionConfig(**{field: value})
