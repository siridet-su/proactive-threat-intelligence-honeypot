from __future__ import annotations

from hashlib import sha256
import stat
from pathlib import Path

import pytest

from cowrie_hardware_fusion.spool import BoundedSegmentSpool, SpoolError, SpoolLimits


def _record(sequence: int, payload_size: int = 20) -> dict:
    return {"time": {"sequence": sequence}, "payload": "x" * payload_size}


def test_spool_rotates_and_publishes_content_addressed_segments(tmp_path: Path) -> None:
    limits = SpoolLimits(
        max_total_bytes=100_000,
        min_free_bytes=0,
        segment_max_bytes=10_000,
        segment_max_records=2,
    )
    spool = BoundedSegmentSpool(
        tmp_path,
        run_id="run-test-0001",
        metric_scope="pi_sensor",
        limits=limits,
    )

    with spool:
        for sequence in range(5):
            spool.append(_record(sequence))

    assert [receipt["record_count"] for receipt in spool.receipts] == [2, 2, 1]
    assert not list(spool.run_dir.glob("*.partial"))
    for receipt in spool.receipts:
        payload = (spool.run_dir / receipt["filename"]).read_bytes()
        assert sha256(payload).hexdigest() == receipt["sha256"]
        assert len(payload) == receipt["serialized_bytes"]
        assert stat.S_IMODE((spool.run_dir / receipt["filename"]).stat().st_mode) == 0o400


def test_spool_refuses_noncontiguous_sequence_and_leaves_partial(tmp_path: Path) -> None:
    limits = SpoolLimits(
        max_total_bytes=100_000,
        min_free_bytes=0,
        segment_max_bytes=10_000,
        segment_max_records=100,
    )
    spool = BoundedSegmentSpool(
        tmp_path,
        run_id="run-test-0002",
        metric_scope="pi_sensor",
        limits=limits,
    )

    with pytest.raises(SpoolError, match="sequence must be contiguous"):
        with spool:
            spool.append(_record(0))
            spool.append(_record(2))

    assert len(list(spool.run_dir.glob("*.partial"))) == 1
    assert not list(spool.run_dir.glob("*.jsonl"))


def test_spool_never_reuses_a_nonempty_run_directory(tmp_path: Path) -> None:
    limits = SpoolLimits(
        max_total_bytes=100_000,
        min_free_bytes=0,
        segment_max_bytes=10_000,
        segment_max_records=100,
    )
    first = BoundedSegmentSpool(
        tmp_path,
        run_id="run-test-0003",
        metric_scope="pi_sensor",
        limits=limits,
    )
    with first:
        first.append(_record(0))

    second = BoundedSegmentSpool(
        tmp_path,
        run_id="run-test-0003",
        metric_scope="pi_sensor",
        limits=limits,
    )
    with pytest.raises(SpoolError, match="refusing overwrite"):
        second.preflight()
