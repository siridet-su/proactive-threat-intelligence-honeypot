"""Leakage-aware XGBoost smoke evaluation for small controlled Pi datasets.

This module deliberately treats every controlled repetition as an indivisible test
fold.  The resulting metrics answer only whether the fixed PoC behaviors are
separable; they are not a production performance estimate.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from hashlib import sha256
import math
from pathlib import Path
import platform
from typing import Any

from .batch import canonical_sha256, write_json_exclusive
from .dataset import DatasetContractError


SMOKE_SCHEMA_VERSION = "xgboost_smoke_report.v1"
SMOKE_TRAINER_VERSION = "0.1.0"
NO_TTP_LABEL = "NO_TTP"
PURPOSE = "pilot_smoke_only_not_for_deployment"


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _label(record: Mapping[str, Any]) -> str:
    ttps = record.get("labels", {}).get("ground_truth_ttps")
    if not isinstance(ttps, list):
        raise DatasetContractError("derived window has no ground_truth_ttps list")
    if len(ttps) > 1:
        raise DatasetContractError("smoke trainer supports at most one TTP label per run")
    return str(ttps[0]) if ttps else NO_TTP_LABEL


def _verify_record_hash(record: Mapping[str, Any]) -> None:
    claimed = record.get("record_sha256")
    without_hash = dict(record)
    without_hash.pop("record_sha256", None)
    if not isinstance(claimed, str) or canonical_sha256(without_hash) != claimed:
        raise DatasetContractError("derived window record_sha256 does not match content")


def _verify_source_index(source_index: Mapping[str, Any]) -> None:
    claimed = source_index.get("index_sha256")
    without_hash = dict(source_index)
    without_hash.pop("index_sha256", None)
    if not isinstance(claimed, str) or canonical_sha256(without_hash) != claimed:
        raise DatasetContractError("source index content hash does not match")


def prepare_smoke_rows(
    records: Sequence[Mapping[str, Any]],
    source_index: Mapping[str, Any],
    *,
    minimum_coverage: float = 0.99,
) -> dict[str, Any]:
    """Validate and convert derived windows into deterministic model rows."""

    if not 0.0 <= minimum_coverage <= 1.0:
        raise DatasetContractError("minimum_coverage must be between 0 and 1")
    if len(records) < 6:
        raise DatasetContractError("smoke evaluation needs at least six independent runs")
    _verify_source_index(source_index)

    indexed_runs = source_index.get("runs")
    if not isinstance(indexed_runs, list):
        raise DatasetContractError("source index has no runs list")
    indexed_by_id = {run.get("run_id"): run for run in indexed_runs}
    if None in indexed_by_id or len(indexed_by_id) != len(indexed_runs):
        raise DatasetContractError("source index contains invalid or duplicate run IDs")

    ordered = sorted(
        records,
        key=lambda value: value.get("window", {}).get("run_id", ""),
    )
    rows: list[dict[str, Any]] = []
    record_ids: set[str] = set()
    feature_names: tuple[str, ...] | None = None
    feature_schema_version: str | None = None
    for record in ordered:
        _verify_record_hash(record)
        record_id = record.get("record_id")
        if not isinstance(record_id, str) or record_id in record_ids:
            raise DatasetContractError(
                "derived windows contain invalid or duplicate record IDs"
            )
        record_ids.add(record_id)

        window = record.get("window", {})
        run_id = window.get("run_id")
        if not isinstance(run_id, str) or run_id not in indexed_by_id:
            raise DatasetContractError(
                f"derived window run is absent from source index: {run_id}"
            )
        if window.get("phase") != "workload":
            raise DatasetContractError("smoke trainer accepts workload windows only")

        indexed = indexed_by_id[run_id]
        label = _label(record)
        indexed_ttps = indexed.get("labels", {}).get("ground_truth_ttps", [])
        indexed_label = str(indexed_ttps[0]) if indexed_ttps else NO_TTP_LABEL
        if len(indexed_ttps) > 1 or label != indexed_label:
            raise DatasetContractError(f"window label does not match source index: {run_id}")
        if (
            record.get("provenance", {}).get("manifest_content_sha256")
            != indexed.get("manifest_content_sha256")
        ):
            raise DatasetContractError(
                f"window manifest hash does not match index: {run_id}"
            )

        quality = record.get("quality", {})
        coverage = quality.get("sample_coverage")
        baseline_coverage = quality.get("baseline_coverage")
        if not isinstance(coverage, (int, float)) or coverage < minimum_coverage:
            raise DatasetContractError(f"insufficient workload coverage: {run_id}")
        if (
            not isinstance(baseline_coverage, (int, float))
            or baseline_coverage < minimum_coverage
        ):
            raise DatasetContractError(f"insufficient baseline coverage: {run_id}")
        if quality.get("collector_error_count") != 0:
            raise DatasetContractError(f"collector errors are present: {run_id}")

        xgboost_block = record.get("xgboost", {})
        current_schema = xgboost_block.get("feature_schema_version")
        features = xgboost_block.get("features")
        if not isinstance(features, dict) or not features:
            raise DatasetContractError(f"window has no XGBoost features: {run_id}")
        current_names = tuple(sorted(features))
        if feature_names is None:
            feature_names = current_names
            feature_schema_version = str(current_schema)
        if current_names != feature_names or current_schema != feature_schema_version:
            raise DatasetContractError("all windows must use exactly one feature schema")
        values: list[float] = []
        for name in current_names:
            value = features[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise DatasetContractError(f"feature {name} is not numeric: {run_id}")
            numeric = float(value)
            if not math.isfinite(numeric):
                raise DatasetContractError(f"feature {name} is not finite: {run_id}")
            values.append(numeric)

        batch = record.get("split_groups", {}).get("collection_batch")
        if not isinstance(batch, str) or not batch:
            raise DatasetContractError(f"window has no collection_batch: {run_id}")
        rows.append(
            {
                "run_id": run_id,
                "record_id": record_id,
                "record_sha256": record["record_sha256"],
                "fold": batch,
                "label": label,
                "features": values,
                "late_sample_count": int(quality.get("late_sample_count", 0)),
            }
        )

    observed_run_ids = {row["run_id"] for row in rows}
    if observed_run_ids != set(indexed_by_id):
        missing = sorted(set(indexed_by_id) - observed_run_ids)
        extra = sorted(observed_run_ids - set(indexed_by_id))
        raise DatasetContractError(
            f"derived windows must exactly cover source index; missing={missing}, extra={extra}"
        )

    labels = [NO_TTP_LABEL, *sorted({row["label"] for row in rows} - {NO_TTP_LABEL})]
    if len(labels) < 3:
        raise DatasetContractError(
            "smoke evaluation requires NO_TTP and at least two TTP labels"
        )
    folds = sorted({row["fold"] for row in rows})
    if len(folds) < 3:
        raise DatasetContractError("smoke evaluation requires at least three repetition folds")
    label_set = set(labels)
    for fold in folds:
        test_labels = {row["label"] for row in rows if row["fold"] == fold}
        train_labels = {row["label"] for row in rows if row["fold"] != fold}
        if test_labels != label_set or train_labels != label_set:
            raise DatasetContractError(
                f"fold {fold} must contain every class in both train and test partitions"
            )

    assert feature_names is not None
    return {
        "rows": rows,
        "classes": labels,
        "folds": folds,
        "feature_names": list(feature_names),
        "feature_schema_version": feature_schema_version,
    }


def classification_metrics(
    actual: Sequence[str], predicted: Sequence[str], classes: Sequence[str]
) -> dict[str, Any]:
    """Compute deterministic multiclass metrics without a second ML dependency."""

    if not actual or len(actual) != len(predicted):
        raise DatasetContractError("actual and predicted labels must be non-empty and aligned")
    class_set = set(classes)
    if set(actual) - class_set or set(predicted) - class_set:
        raise DatasetContractError("metrics received a label outside the declared classes")

    confusion = {
        truth: {guess: 0 for guess in classes}
        for truth in classes
    }
    for truth, guess in zip(actual, predicted, strict=True):
        confusion[truth][guess] += 1

    per_class: dict[str, dict[str, float | int]] = {}
    for label in classes:
        true_positive = confusion[label][label]
        false_positive = sum(confusion[other][label] for other in classes if other != label)
        false_negative = sum(confusion[label][other] for other in classes if other != label)
        support = sum(confusion[label].values())
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 0.0
        )
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }

    return {
        "accuracy": sum(
            truth == guess
            for truth, guess in zip(actual, predicted, strict=True)
        )
        / len(actual),
        "macro_f1": sum(float(per_class[label]["f1"]) for label in classes) / len(classes),
        "per_class": per_class,
        "confusion_matrix": confusion,
    }


def train_xgboost_smoke(
    records: Sequence[Mapping[str, Any]],
    source_index: Mapping[str, Any],
    *,
    output_dir: Path,
    seed: int = 20260902,
    num_boost_round: int = 40,
    minimum_coverage: float = 0.99,
) -> dict[str, Any]:
    """Run repetition-held-out XGBoost evaluation and save audit-only artifacts."""

    try:
        import numpy as np
        import xgboost as xgb
    except ModuleNotFoundError as exc:
        raise DatasetContractError(
            "XGBoost smoke dependencies are missing; install project extra [poc-ml]"
        ) from exc

    prepared = prepare_smoke_rows(
        records,
        source_index,
        minimum_coverage=minimum_coverage,
    )
    if output_dir.exists():
        raise DatasetContractError(f"output directory already exists: {output_dir}")
    if num_boost_round < 1:
        raise DatasetContractError("num_boost_round must be positive")
    output_dir.mkdir(parents=True, mode=0o700)

    rows = prepared["rows"]
    classes = prepared["classes"]
    feature_names = prepared["feature_names"]
    class_to_index = {label: index for index, label in enumerate(classes)}
    parameters: dict[str, Any] = {
        "objective": "multi:softprob",
        "num_class": len(classes),
        "eval_metric": "mlogloss",
        "eta": 0.1,
        "max_depth": 2,
        "min_child_weight": 1.0,
        "subsample": 1.0,
        "colsample_bytree": 1.0,
        "lambda": 1.0,
        "alpha": 0.0,
        "tree_method": "hist",
        "seed": seed,
        "nthread": 1,
        "verbosity": 0,
    }

    def matrix(selected: Sequence[Mapping[str, Any]]) -> Any:
        values = np.asarray([row["features"] for row in selected], dtype=np.float32)
        labels = np.asarray(
            [class_to_index[row["label"]] for row in selected],
            dtype=np.int32,
        )
        return xgb.DMatrix(values, label=labels, feature_names=feature_names)

    folds: list[dict[str, Any]] = []
    all_predictions: list[dict[str, Any]] = []
    for fold_id in prepared["folds"]:
        train_rows = [row for row in rows if row["fold"] != fold_id]
        test_rows = [row for row in rows if row["fold"] == fold_id]
        booster = xgb.train(parameters, matrix(train_rows), num_boost_round=num_boost_round)
        probabilities = booster.predict(matrix(test_rows))
        predicted_indices = probabilities.argmax(axis=1).tolist()
        predictions: list[dict[str, Any]] = []
        for row, probability, predicted_index in zip(
            test_rows, probabilities.tolist(), predicted_indices, strict=True
        ):
            prediction = {
                "run_id": row["run_id"],
                "actual": row["label"],
                "predicted": classes[predicted_index],
                "confidence": float(probability[predicted_index]),
                "probabilities": {
                    label: float(probability[index])
                    for index, label in enumerate(classes)
                },
            }
            predictions.append(prediction)
            all_predictions.append(prediction)

        model_filename = f"model-fold-{fold_id}.json"
        model_path = output_dir / model_filename
        booster.save_model(model_path)
        folds.append(
            {
                "fold_id": fold_id,
                "train_run_ids": [row["run_id"] for row in train_rows],
                "test_run_ids": [row["run_id"] for row in test_rows],
                "model_artifact": {
                    "filename": model_filename,
                    "sha256": _file_sha256(model_path),
                },
                "metrics": classification_metrics(
                    [prediction["actual"] for prediction in predictions],
                    [prediction["predicted"] for prediction in predictions],
                    classes,
                ),
                "predictions": predictions,
            }
        )

    full_booster = xgb.train(parameters, matrix(rows), num_boost_round=num_boost_round)
    full_model_path = output_dir / "model-full-pilot-only.json"
    full_booster.save_model(full_model_path)
    gain = full_booster.get_score(importance_type="gain")
    gain_total = sum(float(value) for value in gain.values())
    normalized_gain = [
        {
            "rank": rank,
            "feature": name,
            "normalized_gain": float(value) / gain_total if gain_total else 0.0,
        }
        for rank, (name, value) in enumerate(
            sorted(gain.items(), key=lambda item: (-item[1], item[0])),
            start=1,
        )
    ]

    all_predictions.sort(key=lambda value: value["run_id"])
    report: dict[str, Any] = {
        "schema_version": SMOKE_SCHEMA_VERSION,
        "trainer_version": SMOKE_TRAINER_VERSION,
        "purpose": PURPOSE,
        "source": {
            "dataset_id": source_index["dataset_id"],
            "source_index_sha256": source_index["index_sha256"],
            "run_count": len(rows),
            "records": [
                {
                    "run_id": row["run_id"],
                    "record_id": row["record_id"],
                    "record_sha256": row["record_sha256"],
                }
                for row in rows
            ],
        },
        "data": {
            "classes": classes,
            "class_counts": dict(sorted(Counter(row["label"] for row in rows).items())),
            "feature_schema_version": prepared["feature_schema_version"],
            "feature_count": len(feature_names),
            "feature_names": feature_names,
            "fold_axis": "collection_batch",
            "fold_ids": prepared["folds"],
            "minimum_coverage": minimum_coverage,
            "late_sample_count": sum(row["late_sample_count"] for row in rows),
        },
        "training": {
            "algorithm": "xgboost",
            "class_weighting": "none",
            "parameters": parameters,
            "num_boost_round": num_boost_round,
            "library_versions": {
                "numpy": np.__version__,
                "python": platform.python_version(),
                "xgboost": xgb.__version__,
            },
            "full_model_artifact": {
                "filename": full_model_path.name,
                "sha256": _file_sha256(full_model_path),
                "authority": PURPOSE,
            },
            "full_model_normalized_gain": normalized_gain,
        },
        "folds": folds,
        "out_of_fold": {
            "metrics": classification_metrics(
                [prediction["actual"] for prediction in all_predictions],
                [prediction["predicted"] for prediction in all_predictions],
                classes,
            ),
            "predictions": all_predictions,
        },
        "limitations": [
            "Only three controlled repetitions per scenario were observed.",
            "Train and test folds share one Pi, one collector, one workload binary, and one day.",
            "Labels describe fixed simulated behavior, not attacker intent or production traffic.",
            "Hyperparameters were fixed without tuning; confidence values are not calibrated.",
            "The full-data model is retained for inspection only and must not be deployed.",
        ],
    }
    report["report_sha256"] = canonical_sha256(report)
    write_json_exclusive(output_dir / "report.json", report)
    return report
