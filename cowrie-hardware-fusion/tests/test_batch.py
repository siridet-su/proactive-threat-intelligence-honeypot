from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from cowrie_hardware_fusion.batch import (
    build_dataset_index,
    generate_grouped_split,
    group_value_is_non_binding,
)
from cowrie_hardware_fusion.collector import (
    CollectorConfig,
    ProbeResult,
    collect_idle_run,
    collector_source_sha256,
    finalize_idle_manifest,
)
from cowrie_hardware_fusion.dataset import DatasetContractError
from cowrie_hardware_fusion.spool import SpoolLimits


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_non_binding_sentinels_are_axis_specific() -> None:
    assert group_value_is_non_binding("command_template_group", "no-command")
    assert group_value_is_non_binding("workload_family_group", "none")
    assert group_value_is_non_binding("workload_implementation_sha256", "0" * 64)
    assert not group_value_is_non_binding("collection_batch", "none")
    assert not group_value_is_non_binding("environment_group", "none")


class FakeClock:
    def __init__(self) -> None:
        self._origin_ns = 1_000_000_000
        self._current_ns = self._origin_ns
        self._origin_wall = datetime(2026, 9, 2, 8, 0, 0, tzinfo=timezone.utc)

    def monotonic_ns(self) -> int:
        return self._current_ns

    def now_utc(self) -> datetime:
        elapsed = (self._current_ns - self._origin_ns) / 1_000_000_000
        return self._origin_wall + timedelta(seconds=elapsed)

    def sleep_until_ns(self, deadline_ns: int) -> None:
        self._current_ns = max(self._current_ns, deadline_ns)


class FakeProbe:
    boot_id_sha256 = "2" * 64

    def __init__(self) -> None:
        self._template = _load_json(
            PROJECT_ROOT / "schemas" / "examples" / "hardware_telemetry_sample.v1.example.json"
        )

    def sample(self) -> ProbeResult:
        sample = deepcopy(self._template)
        return ProbeResult(
            cpu=sample["cpu"],
            memory=sample["memory"],
            disk=sample["disk"],
            network=sample["network"],
            thermal=sample["thermal"],
            process=sample["process"],
        )


def _config(spool_root: Path) -> CollectorConfig:
    document = _load_json(
        PROJECT_ROOT / "configs" / "experimental_collector.pi_sensor.pilot.example.json"
    )
    config = CollectorConfig.from_document(document)
    return replace(
        config,
        spool_directory=spool_root,
        spool_limits=SpoolLimits(
            max_total_bytes=20_000_000,
            min_free_bytes=0,
            segment_max_bytes=1_000_000,
            segment_max_records=30,
        ),
    )


def _make_run(
    spool_root: Path,
    suffix: str,
    *,
    pilot_only: bool,
    shared_group: str | None = None,
) -> Path:
    manifest = _load_json(
        PROJECT_ROOT / "schemas" / "examples" / "experiment_run_manifest.v1.example.json"
    )
    manifest["run_id"] = f"run-batch-test-{suffix}"
    manifest["provenance"]["pilot_only"] = pilot_only
    manifest["collection"]["collector_sha256"] = collector_source_sha256()
    group_value = shared_group or suffix
    manifest["workload"]["implementation_sha256"] = (
        "a" * 62 + f"{int(group_value):02d}"
        if group_value.isdigit()
        else "b" * 64
    )
    manifest["split_groups"]["scenario_variant_group"] = f"variant-{group_value}"
    manifest["split_groups"]["collection_batch"] = f"batch-{group_value}"

    config = _config(spool_root)
    receipt = collect_idle_run(
        manifest,
        config,
        schema_dir=PROJECT_ROOT / "schemas",
        probe=FakeProbe(),
        clock=FakeClock(),
    )
    run_root = spool_root / f"run={manifest['run_id']}"
    completed = finalize_idle_manifest(
        manifest,
        receipt,
        run_dir=run_root / "scope=pi_sensor",
        schema_dir=PROJECT_ROOT / "schemas",
    )
    (run_root / "manifest.json").write_text(
        json.dumps(completed, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return run_root


def test_index_verifies_receipts_and_freezes_exact_raw_membership(tmp_path: Path) -> None:
    pilot = _make_run(tmp_path, "01", pilot_only=True)
    eligible = _make_run(tmp_path, "02", pilot_only=False)

    index = build_dataset_index(
        "dataset-test-v1",
        [eligible, pilot],
        schema_dir=PROJECT_ROOT / "schemas",
    )

    assert [run["run_id"] for run in index["runs"]] == [
        "run-batch-test-01",
        "run-batch-test-02",
    ]
    assert index["summary"] == {
        "run_count": 2,
        "eligible_run_count": 1,
        "pilot_run_count": 1,
        "receipt_count": 2,
        "record_count": 180,
        "serialized_bytes": sum(
            receipt["serialized_bytes"]
            for run in index["runs"]
            for receipt in run["receipts"]
        ),
    }
    assert len(index["index_sha256"]) == 64


def test_index_rejects_segment_tampering(tmp_path: Path) -> None:
    run_root = _make_run(tmp_path, "01", pilot_only=True)
    receipt = _load_json(run_root / "scope=pi_sensor" / "collection-receipt.json")
    segment_path = run_root / "scope=pi_sensor" / receipt["segments"][0]["filename"]
    segment_path.chmod(0o600)
    segment_path.write_bytes(segment_path.read_bytes() + b"{}\n")

    with pytest.raises(DatasetContractError, match="required property"):
        build_dataset_index(
            "dataset-tampered-v1",
            [run_root],
            schema_dir=PROJECT_ROOT / "schemas",
        )


def test_grouped_split_is_deterministic_and_excludes_pilot_runs(tmp_path: Path) -> None:
    run_roots = [
        _make_run(tmp_path, "00", pilot_only=True),
        *[
            _make_run(tmp_path, f"{index:02d}", pilot_only=False)
            for index in range(1, 7)
        ],
    ]
    index = build_dataset_index(
        "dataset-split-test-v1",
        list(reversed(run_roots)),
        schema_dir=PROJECT_ROOT / "schemas",
    )

    first = generate_grouped_split(
        index,
        "split-test-v1",
        schema_dir=PROJECT_ROOT / "schemas",
    )
    second = generate_grouped_split(
        deepcopy(index),
        "split-test-v1",
        schema_dir=PROJECT_ROOT / "schemas",
    )

    assert first == second
    assert first["excluded"] == [
        {"run_id": "run-batch-test-00", "reason": "pilot_only"}
    ]
    assert set(first["partition_run_counts"]) == {
        "development_train",
        "calibration",
        "final_test",
    }
    assert all(value >= 1 for value in first["partition_run_counts"].values())
    assert len(first["assignments"]) == 6

    assignment_by_run = {
        assignment["run_id"]: assignment["partition"]
        for assignment in first["assignments"]
    }
    for axis in first["group_axes"]:
        partitions_by_value: dict[str, set[str]] = {}
        for run in index["runs"]:
            if run["pilot_only"]:
                continue
            value = run["groups"][axis]
            if group_value_is_non_binding(axis, value):
                continue
            partitions_by_value.setdefault(value, set()).add(assignment_by_run[run["run_id"]])
        assert all(len(partitions) == 1 for partitions in partitions_by_value.values())


def test_grouped_split_fails_when_independent_components_are_insufficient(
    tmp_path: Path,
) -> None:
    run_roots = [
        _make_run(tmp_path, f"{index:02d}", pilot_only=False, shared_group="01")
        for index in range(1, 5)
    ]
    index = build_dataset_index(
        "dataset-one-group-v1",
        run_roots,
        schema_dir=PROJECT_ROOT / "schemas",
    )

    with pytest.raises(DatasetContractError, match="fewer than three independent"):
        generate_grouped_split(
            index,
            "split-must-fail-v1",
            schema_dir=PROJECT_ROOT / "schemas",
        )
