from __future__ import annotations

from copy import deepcopy

import pytest

from cowrie_hardware_fusion.batch import canonical_sha256
from cowrie_hardware_fusion.dataset import DatasetContractError
from cowrie_hardware_fusion.smoke import classification_metrics, prepare_smoke_rows


def _fixtures() -> tuple[list[dict], dict]:
    records: list[dict] = []
    indexed: list[dict] = []
    labels = ("NO_TTP", "T1496.001", "T1499.002")
    for repetition in range(1, 4):
        for label_index, label in enumerate(labels):
            run_id = f"run-smoke-{label.lower().replace('.', '-')}-r{repetition:02d}"
            manifest_hash = f"{repetition}{label_index}".ljust(64, "a")
            ttps = [] if label == "NO_TTP" else [label]
            record = {
                "record_id": f"{run_id}:pi_sensor:workload:30s",
                "window": {"run_id": run_id, "phase": "workload"},
                "labels": {"ground_truth_ttps": ttps},
                "split_groups": {"collection_batch": f"batch-r{repetition:02d}"},
                "xgboost": {
                    "feature_schema_version": "xgboost_hardware_features.v1",
                    "features": {
                        "cpu_mean": float(label_index),
                        "cpu_p95": float(label_index + 1),
                    },
                },
                "quality": {
                    "sample_coverage": 1.0,
                    "baseline_coverage": 1.0,
                    "collector_error_count": 0,
                    "late_sample_count": 0,
                },
                "provenance": {"manifest_content_sha256": manifest_hash},
            }
            record["record_sha256"] = canonical_sha256(record)
            records.append(record)
            indexed.append(
                {
                    "run_id": run_id,
                    "manifest_content_sha256": manifest_hash,
                    "labels": {"ground_truth_ttps": ttps},
                }
            )
    source = {"dataset_id": "smoke-test", "runs": indexed}
    source["index_sha256"] = canonical_sha256(source)
    return records, source


def test_prepare_smoke_rows_holds_out_complete_repetitions() -> None:
    records, source = _fixtures()

    prepared = prepare_smoke_rows(list(reversed(records)), source)

    assert prepared["classes"] == ["NO_TTP", "T1496.001", "T1499.002"]
    assert prepared["folds"] == ["batch-r01", "batch-r02", "batch-r03"]
    assert prepared["feature_names"] == ["cpu_mean", "cpu_p95"]
    assert len(prepared["rows"]) == 9
    assert [row["run_id"] for row in prepared["rows"]] == sorted(
        row["run_id"] for row in prepared["rows"]
    )


def test_prepare_smoke_rows_rejects_tampered_window() -> None:
    records, source = _fixtures()
    records[0]["xgboost"]["features"]["cpu_mean"] = 999.0

    with pytest.raises(DatasetContractError, match="record_sha256"):
        prepare_smoke_rows(records, source)


def test_prepare_smoke_rows_rejects_incomplete_fold() -> None:
    records, source = _fixtures()
    removed = records.pop()
    source["runs"] = [
        run
        for run in source["runs"]
        if run["run_id"] != removed["window"]["run_id"]
    ]
    source["index_sha256"] = canonical_sha256(
        {key: value for key, value in source.items() if key != "index_sha256"}
    )

    with pytest.raises(DatasetContractError, match="must contain every class"):
        prepare_smoke_rows(records, source)


def test_classification_metrics_reports_multiclass_confusion() -> None:
    metrics = classification_metrics(
        ["NO_TTP", "T1496.001", "T1499.002"],
        ["NO_TTP", "T1499.002", "T1499.002"],
        ["NO_TTP", "T1496.001", "T1499.002"],
    )

    assert metrics["accuracy"] == pytest.approx(2 / 3)
    assert metrics["per_class"]["T1496.001"]["recall"] == 0.0
    assert metrics["confusion_matrix"]["T1496.001"]["T1499.002"] == 1


def test_prepare_smoke_rows_rejects_source_index_tampering() -> None:
    records, source = _fixtures()
    tampered = deepcopy(source)
    tampered["dataset_id"] = "changed"

    with pytest.raises(DatasetContractError, match="source index content hash"):
        prepare_smoke_rows(records, tampered)
