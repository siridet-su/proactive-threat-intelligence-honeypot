"""Command-line entry point for deterministic dataset construction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from jsonschema import Draft202012Validator

from .dataset import DatasetContractError, build_training_window
from .spool import SpoolError


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA_DIR = PROJECT_ROOT / "schemas"


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise DatasetContractError(f"{path} must contain one JSON object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetContractError(f"{path}:{line_number}: {exc.msg}") from exc
            if not isinstance(value, dict):
                raise DatasetContractError(f"{path}:{line_number}: expected a JSON object")
            documents.append(value)
    return documents


def _validate(document: dict[str, Any], schema_path: Path, source: str) -> None:
    schema = _load_json(schema_path)
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    rendered: list[str] = []
    for error in errors[:10]:
        location = ".".join(str(component) for component in error.absolute_path) or "$"
        rendered.append(f"{source}:{location}: {error.message}")
    if len(errors) > 10:
        rendered.append(f"... {len(errors) - 10} more schema errors")
    raise DatasetContractError("\n".join(rendered))


def _build_window(args: argparse.Namespace) -> int:
    manifest = _load_json(args.manifest)
    _validate(
        manifest,
        args.schema_dir / "experiment_run_manifest.v1.schema.json",
        str(args.manifest),
    )
    telemetry_schema = args.schema_dir / "hardware_telemetry_sample.v1.schema.json"
    samples: list[dict[str, Any]] = []
    for telemetry_path in args.telemetry:
        segment_samples = _load_jsonl(telemetry_path)
        for index, sample in enumerate(segment_samples, start=1):
            _validate(sample, telemetry_schema, f"{telemetry_path}:{index}")
        samples.extend(segment_samples)

    record = build_training_window(
        manifest,
        samples,
        metric_scope=args.metric_scope,
        phase=args.phase,
        horizon_seconds=args.horizon_seconds,
        minimum_coverage=args.minimum_coverage,
    )
    _validate(
        record,
        args.schema_dir / "derived_training_window.v1.schema.json",
        "derived record",
    )
    rendered = json.dumps(record, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)
    if args.output is None:
        print(rendered)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "output": str(args.output),
                    "record_id": record["record_id"],
                    "record_sha256": record["record_sha256"],
                    "sample_coverage": record["quality"]["sample_coverage"],
                },
                sort_keys=True,
            )
        )
    return 0


def _collector_source_hash(args: argparse.Namespace) -> int:
    from .collector import collector_source_sha256, telemetry_schema_sha256

    print(
        json.dumps(
            {
                "collector_source_sha256": collector_source_sha256(),
                "feature_schema_sha256": telemetry_schema_sha256(args.schema_dir),
            },
            sort_keys=True,
        )
    )
    return 0


def _snapshot_experimental_hardware(args: argparse.Namespace) -> int:
    from .batch import write_json_exclusive
    from .collector import CollectorConfig
    from .parity import capture_experimental_snapshot

    config_document = _load_json(args.config)
    _validate(
        config_document,
        args.schema_dir / "experimental_collector_config.v1.schema.json",
        str(args.config),
    )
    snapshot = capture_experimental_snapshot(
        CollectorConfig.from_document(config_document),
        interval_seconds=args.interval_seconds,
    )
    if args.output is None:
        print(
            json.dumps(
                snapshot,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            )
        )
    else:
        write_json_exclusive(args.output, snapshot)
        print(
            json.dumps(
                {
                    "output": str(args.output),
                    "snapshot_sha256": snapshot["snapshot_sha256"],
                    "valid": snapshot["quality"]["valid"],
                    "mode": snapshot["mode"],
                },
                sort_keys=True,
            )
        )
    return 0


def _compare_hardware_snapshots(args: argparse.Namespace) -> int:
    from .batch import write_json_exclusive
    from .parity import compare_hardware_snapshots

    report = compare_hardware_snapshots(
        _load_json(args.go_snapshot),
        _load_json(args.experimental_snapshot),
    )
    write_json_exclusive(args.output, report)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "report_sha256": report["report_sha256"],
                "summary": report["summary"],
                "purpose": report["purpose"],
            },
            sort_keys=True,
        )
    )
    return 0


def _validate_hardware_impact_protocol(args: argparse.Namespace) -> int:
    from .protocol import validate_hardware_impact_protocol

    document = _load_json(args.protocol)
    _validate(
        document,
        args.schema_dir / "hardware_impact_experiment_protocol.v2.schema.json",
        str(args.protocol),
    )
    summary = validate_hardware_impact_protocol(document)
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


def _validated_collector_inputs(args: argparse.Namespace) -> tuple[dict[str, Any], Any]:
    from .collector import CollectorConfig

    manifest = _load_json(args.manifest)
    config_document = _load_json(args.config)
    _validate(
        manifest,
        args.schema_dir / "experiment_run_manifest.v1.schema.json",
        str(args.manifest),
    )
    _validate(
        config_document,
        args.schema_dir / "experimental_collector_config.v1.schema.json",
        str(args.config),
    )
    return manifest, CollectorConfig.from_document(config_document)


def _collector_preflight(args: argparse.Namespace) -> int:
    from .collector import collector_preflight

    manifest, config = _validated_collector_inputs(args)
    report = collector_preflight(manifest, config, schema_dir=args.schema_dir)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


def _collect_idle_run(args: argparse.Namespace) -> int:
    from .collector import collect_idle_run, collector_preflight

    manifest, config = _validated_collector_inputs(args)
    preflight = collector_preflight(manifest, config, schema_dir=args.schema_dir)
    receipt = collect_idle_run(
        manifest,
        config,
        schema_dir=args.schema_dir,
        ntp_synchronized=preflight["ntp_synchronized"],
    )
    _validate(
        receipt,
        args.schema_dir / "experiment_collection_receipt.v1.schema.json",
        "collection receipt",
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


def _finalize_idle_manifest(args: argparse.Namespace) -> int:
    from .collector import finalize_idle_manifest, write_json_exclusive

    manifest = _load_json(args.manifest)
    receipt = _load_json(args.receipt)
    _validate(
        manifest,
        args.schema_dir / "experiment_run_manifest.v1.schema.json",
        str(args.manifest),
    )
    _validate(
        receipt,
        args.schema_dir / "experiment_collection_receipt.v1.schema.json",
        str(args.receipt),
    )
    completed = finalize_idle_manifest(
        manifest,
        receipt,
        run_dir=args.receipt.parent,
        schema_dir=args.schema_dir,
    )
    _validate(
        completed,
        args.schema_dir / "experiment_run_manifest.v1.schema.json",
        "completed manifest",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json_exclusive(args.output, completed)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "run_id": completed["run_id"],
                "state": completed["state"],
                "receipt_id": receipt["receipt_id"],
            },
            sort_keys=True,
        )
    )
    return 0


def _index_dataset(args: argparse.Namespace) -> int:
    from .batch import build_dataset_index, write_json_exclusive

    document = build_dataset_index(
        args.dataset_id,
        args.run_root,
        schema_dir=args.schema_dir,
    )
    write_json_exclusive(args.output, document)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "dataset_id": document["dataset_id"],
                "index_sha256": document["index_sha256"],
                "summary": document["summary"],
            },
            sort_keys=True,
        )
    )
    return 0


def _train_xgboost_smoke(args: argparse.Namespace) -> int:
    from .smoke import train_xgboost_smoke

    source_index = _load_json(args.source_index)
    _validate(
        source_index,
        args.schema_dir / "dataset_source_index.v1.schema.json",
        str(args.source_index),
    )
    window_schema = args.schema_dir / "derived_training_window.v1.schema.json"
    records: list[dict[str, Any]] = []
    for path in args.window:
        record = _load_json(path)
        _validate(record, window_schema, str(path))
        records.append(record)
    report = train_xgboost_smoke(
        records,
        source_index,
        output_dir=args.output_dir,
        seed=args.seed,
        num_boost_round=args.num_boost_round,
        minimum_coverage=args.minimum_coverage,
    )
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "report_sha256": report["report_sha256"],
                "run_count": report["source"]["run_count"],
                "accuracy": report["out_of_fold"]["metrics"]["accuracy"],
                "macro_f1": report["out_of_fold"]["metrics"]["macro_f1"],
                "purpose": report["purpose"],
            },
            sort_keys=True,
        )
    )
    return 0


def _split_dataset(args: argparse.Namespace) -> int:
    from .batch import generate_grouped_split, write_json_exclusive

    index = _load_json(args.index)
    document = generate_grouped_split(
        index,
        args.split_id,
        seed=args.seed,
        group_axes=args.group_axis,
        schema_dir=args.schema_dir,
    )
    write_json_exclusive(args.output, document)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "split_id": document["split_id"],
                "assignment_sha256": document["assignment_sha256"],
                "partition_run_counts": document["partition_run_counts"],
                "excluded_count": len(document["excluded"]),
            },
            sort_keys=True,
        )
    )
    return 0


def _workload_preflight(args: argparse.Namespace) -> int:
    from .batch import write_json_exclusive
    from .workload import validate_bounded_workload

    manifest = _load_json(args.manifest)
    specification = _load_json(args.specification)
    receipt = validate_bounded_workload(
        manifest,
        specification,
        catalog_path=args.scenario_catalog,
        schema_dir=args.schema_dir,
    )
    write_json_exclusive(args.output, receipt)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "receipt_id": receipt["receipt_id"],
                "receipt_sha256": receipt["receipt_sha256"],
                "run_id": receipt["run_id"],
                "contract_valid": receipt["contract_valid"],
                "execution_authorized": receipt["execution_authorized"],
                "execution_started": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _validated_pi_poc_inputs(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], Any, dict[str, Any]]:
    manifest, config = _validated_collector_inputs(args)
    specification = _load_json(args.specification)
    _validate(
        specification,
        args.schema_dir / "pi_poc_workload_spec.v1.schema.json",
        str(args.specification),
    )
    return manifest, config, specification


def _pi_poc_preflight(args: argparse.Namespace) -> int:
    from .collector import controlled_collector_preflight
    from .poc import pi_poc_preflight

    manifest, config, specification = _validated_pi_poc_inputs(args)
    collector_report = controlled_collector_preflight(
        manifest,
        config,
        schema_dir=args.schema_dir,
    )
    runtime_report = pi_poc_preflight(
        manifest,
        specification,
        catalog_path=args.scenario_catalog,
    )
    print(
        json.dumps(
            {"collector": collector_report, "runtime": runtime_report},
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
    )
    return 0


def _collect_pi_poc_run(args: argparse.Namespace) -> int:
    from .collector import (
        collect_controlled_run,
        controlled_collector_preflight,
        write_json_exclusive,
    )
    from .poc import DockerWorkloadLifecycle, pi_poc_preflight

    manifest, config, specification = _validated_pi_poc_inputs(args)
    collector_report = controlled_collector_preflight(
        manifest,
        config,
        schema_dir=args.schema_dir,
    )
    pi_poc_preflight(
        manifest,
        specification,
        catalog_path=args.scenario_catalog,
    )
    lifecycle = DockerWorkloadLifecycle(manifest, specification)
    collection_receipt = collect_controlled_run(
        manifest,
        config,
        schema_dir=args.schema_dir,
        lifecycle=lifecycle,
        ntp_synchronized=collector_report["ntp_synchronized"],
    )
    execution_receipt = lifecycle.execution_receipt()
    _validate(
        collection_receipt,
        args.schema_dir / "experiment_collection_receipt.v1.schema.json",
        "collection receipt",
    )
    _validate(
        execution_receipt,
        args.schema_dir / "pi_poc_execution_receipt.v1.schema.json",
        "execution receipt",
    )
    run_dir = (
        config.spool_directory
        / f"run={manifest['run_id']}"
        / f"scope={config.metric_scope}"
    )
    execution_path = run_dir / "pi-poc-execution-receipt.json"
    write_json_exclusive(execution_path, execution_receipt)
    print(
        json.dumps(
            {
                "run_id": manifest["run_id"],
                "collection_receipt": str(run_dir / "collection-receipt.json"),
                "execution_receipt": str(execution_path),
                "records": collection_receipt["record_count"],
                "workload_summary": execution_receipt["workload_summary"],
                "cleanup_verified": execution_receipt["cleanup_verified"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _finalize_pi_poc_manifest(args: argparse.Namespace) -> int:
    from .batch import canonical_sha256
    from .collector import finalize_idle_manifest, write_json_exclusive
    from .poc import validate_pi_poc_contract

    manifest = _load_json(args.manifest)
    specification = _load_json(args.specification)
    collection_receipt = _load_json(args.collection_receipt)
    execution_receipt = _load_json(args.execution_receipt)
    _validate(
        specification,
        args.schema_dir / "pi_poc_workload_spec.v1.schema.json",
        str(args.specification),
    )
    validate_pi_poc_contract(
        manifest,
        specification,
        catalog_path=args.scenario_catalog,
    )
    _validate(
        execution_receipt,
        args.schema_dir / "pi_poc_execution_receipt.v1.schema.json",
        str(args.execution_receipt),
    )
    claimed_hash = execution_receipt["receipt_sha256"]
    without_hash = dict(execution_receipt)
    without_hash.pop("receipt_sha256")
    if canonical_sha256(without_hash) != claimed_hash:
        raise DatasetContractError("execution receipt content hash does not match")
    if execution_receipt["run_id"] != manifest["run_id"]:
        raise DatasetContractError("execution receipt run_id does not match manifest")
    if execution_receipt["scenario_id"] != manifest["workload"]["scenario_id"]:
        raise DatasetContractError("execution receipt scenario does not match manifest")
    if execution_receipt["manifest_content_sha256"] != canonical_sha256(manifest):
        raise DatasetContractError("execution receipt does not bind the planned manifest")
    if execution_receipt["specification_content_sha256"] != canonical_sha256(
        specification
    ):
        raise DatasetContractError("execution receipt does not bind the specification")
    if execution_receipt["image_id"].removeprefix("sha256:") != manifest[
        "execution_boundary"
    ]["backend_image_sha256"]:
        raise DatasetContractError("execution receipt image does not match manifest")
    completed = finalize_idle_manifest(
        manifest,
        collection_receipt,
        run_dir=args.collection_receipt.parent,
        schema_dir=args.schema_dir,
    )
    execution_id = execution_receipt["receipt_id"]
    if execution_id not in completed["labels"]["evidence_receipt_ids"]:
        completed["labels"]["evidence_receipt_ids"].append(execution_id)
    _validate(
        completed,
        args.schema_dir / "experiment_run_manifest.v1.schema.json",
        "completed manifest",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json_exclusive(args.output, completed)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "run_id": completed["run_id"],
                "state": completed["state"],
                "evidence_receipt_ids": completed["labels"][
                    "evidence_receipt_ids"
                ],
            },
            sort_keys=True,
        )
    )
    return 0


def _prepare_pi_poc_matrix(args: argparse.Namespace) -> int:
    from .batch import write_json_exclusive
    from .poc import build_pi_poc_matrix, validate_pi_poc_contract

    config_document = _load_json(args.config)
    _validate(
        config_document,
        args.schema_dir / "experimental_collector_config.v1.schema.json",
        str(args.config),
    )
    matrix, documents = build_pi_poc_matrix(
        generation=args.generation,
        experiment_id=args.experiment_id,
        repetitions=3,
        image_id=args.image_id,
        implementation_sha256=args.implementation_sha256,
        repo_commit=args.repo_commit,
        environment_signature_sha256=args.environment_signature_sha256,
        sensor_id=config_document["sensor_id"],
        host_id=config_document["subject_id"],
        collector_id=config_document["collector_id"],
        catalog_path=args.scenario_catalog,
    )
    _validate(
        matrix,
        args.schema_dir / "pi_poc_matrix.v1.schema.json",
        "Pi PoC matrix",
    )
    for manifest, specification in documents:
        _validate(
            manifest,
            args.schema_dir / "experiment_run_manifest.v1.schema.json",
            manifest["run_id"],
        )
        if specification is not None:
            _validate(
                specification,
                args.schema_dir / "pi_poc_workload_spec.v1.schema.json",
                specification["spec_id"],
            )
            validate_pi_poc_contract(
                manifest,
                specification,
                catalog_path=args.scenario_catalog,
            )
    write_json_exclusive(args.output_dir / "matrix.json", matrix)
    for manifest, specification in documents:
        control_dir = args.output_dir / "control" / f"run={manifest['run_id']}"
        write_json_exclusive(control_dir / "planned-manifest.json", manifest)
        if specification is not None:
            write_json_exclusive(control_dir / "workload-spec.json", specification)
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "matrix_sha256": matrix["matrix_sha256"],
                "run_count": matrix["run_count"],
                "estimated_total_seconds": matrix["estimated_total_seconds"],
            },
            sort_keys=True,
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cowrie-hardware-dataset",
        description="Build leakage-aware XGBoost/TCN inputs from one controlled run.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-window", help="build one derived training window")
    build.add_argument("--manifest", type=Path, required=True)
    build.add_argument(
        "--telemetry",
        type=Path,
        nargs="+",
        required=True,
        metavar="JSONL",
        help="one or more immutable telemetry JSONL segments in receipt order",
    )
    build.add_argument("--output", type=Path)
    build.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    build.add_argument("--metric-scope", default="pi_sensor")
    build.add_argument("--phase", choices=("workload", "recovery"), default="workload")
    build.add_argument("--horizon-seconds", type=int, choices=(5, 10, 30, 60), default=30)
    build.add_argument("--minimum-coverage", type=float, default=0.99)
    build.set_defaults(handler=_build_window)

    source_hash = subparsers.add_parser(
        "collector-source-hash",
        help="print collector and telemetry-schema hashes for a run manifest",
    )
    source_hash.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    source_hash.set_defaults(handler=_collector_source_hash)

    parity_snapshot = subparsers.add_parser(
        "snapshot-experimental-hardware",
        help="print one warmed read-only experimental collector snapshot",
    )
    parity_snapshot.add_argument("--config", type=Path, required=True)
    parity_snapshot.add_argument("--interval-seconds", type=float, default=1.0)
    parity_snapshot.add_argument("--output", type=Path)
    parity_snapshot.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    parity_snapshot.set_defaults(handler=_snapshot_experimental_hardware)

    parity_compare = subparsers.add_parser(
        "compare-hardware-snapshots",
        help="compare read-only Go Agent and experimental collector snapshots",
    )
    parity_compare.add_argument("--go-snapshot", type=Path, required=True)
    parity_compare.add_argument("--experimental-snapshot", type=Path, required=True)
    parity_compare.add_argument("--output", type=Path, required=True)
    parity_compare.set_defaults(handler=_compare_hardware_snapshots)

    protocol_validate = subparsers.add_parser(
        "validate-hardware-impact-protocol",
        help="verify schema, content hash, leakage, label, and split gates for protocol v2",
    )
    protocol_validate.add_argument("--protocol", type=Path, required=True)
    protocol_validate.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    protocol_validate.set_defaults(handler=_validate_hardware_impact_protocol)

    preflight = subparsers.add_parser(
        "collector-preflight",
        help="run host, contract, and spool safety checks for a neutral-idle pilot",
    )
    preflight.add_argument("--manifest", type=Path, required=True)
    preflight.add_argument("--config", type=Path, required=True)
    preflight.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    preflight.set_defaults(handler=_collector_preflight)

    collect = subparsers.add_parser(
        "collect-idle-run",
        help="collect one bounded neutral-idle run into local immutable segments",
    )
    collect.add_argument("--manifest", type=Path, required=True)
    collect.add_argument("--config", type=Path, required=True)
    collect.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    collect.set_defaults(handler=_collect_idle_run)

    finalize = subparsers.add_parser(
        "finalize-idle-manifest",
        help="verify immutable segments and create a completed manifest copy",
    )
    finalize.add_argument("--manifest", type=Path, required=True)
    finalize.add_argument("--receipt", type=Path, required=True)
    finalize.add_argument("--output", type=Path, required=True)
    finalize.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    finalize.set_defaults(handler=_finalize_idle_manifest)

    index_dataset = subparsers.add_parser(
        "index-dataset",
        help="verify completed run roots and freeze exact raw membership",
    )
    index_dataset.add_argument("--dataset-id", required=True)
    index_dataset.add_argument(
        "--run-root",
        type=Path,
        nargs="+",
        required=True,
        metavar="RUN_ROOT",
        help="run root containing manifest.json and scope=*/collection-receipt.json",
    )
    index_dataset.add_argument("--output", type=Path, required=True)
    index_dataset.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    index_dataset.set_defaults(handler=_index_dataset)

    from .batch import DEFAULT_GROUP_AXES, SUPPORTED_GROUP_AXES

    split_dataset = subparsers.add_parser(
        "split-dataset",
        help="assign verified non-pilot runs using connected leakage groups",
    )
    split_dataset.add_argument("--index", type=Path, required=True)
    split_dataset.add_argument("--split-id", required=True)
    split_dataset.add_argument("--seed", type=int, default=20260901)
    split_dataset.add_argument(
        "--group-axis",
        nargs="+",
        choices=SUPPORTED_GROUP_AXES,
        default=DEFAULT_GROUP_AXES,
    )
    split_dataset.add_argument("--output", type=Path, required=True)
    split_dataset.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    split_dataset.set_defaults(handler=_split_dataset)

    train_smoke = subparsers.add_parser(
        "train-xgboost-smoke",
        help="run repetition-held-out XGBoost evaluation on controlled pilot windows",
    )
    train_smoke.add_argument("--source-index", type=Path, required=True)
    train_smoke.add_argument(
        "--window",
        type=Path,
        nargs="+",
        required=True,
        metavar="WINDOW_JSON",
    )
    train_smoke.add_argument("--output-dir", type=Path, required=True)
    train_smoke.add_argument("--seed", type=int, default=20260902)
    train_smoke.add_argument("--num-boost-round", type=int, default=40)
    train_smoke.add_argument("--minimum-coverage", type=float, default=0.99)
    train_smoke.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    train_smoke.set_defaults(handler=_train_xgboost_smoke)

    workload_preflight = subparsers.add_parser(
        "workload-preflight",
        help="validate an isolated bounded-workload contract without executing it",
    )
    workload_preflight.add_argument("--manifest", type=Path, required=True)
    workload_preflight.add_argument("--specification", type=Path, required=True)
    workload_preflight.add_argument("--scenario-catalog", type=Path, required=True)
    workload_preflight.add_argument("--output", type=Path, required=True)
    workload_preflight.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    workload_preflight.set_defaults(handler=_workload_preflight)

    pi_preflight = subparsers.add_parser(
        "pi-poc-preflight",
        help="validate a fixed safe-container PoC and current Pi safety gates",
    )
    pi_preflight.add_argument("--manifest", type=Path, required=True)
    pi_preflight.add_argument("--config", type=Path, required=True)
    pi_preflight.add_argument("--specification", type=Path, required=True)
    pi_preflight.add_argument("--scenario-catalog", type=Path, required=True)
    pi_preflight.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    pi_preflight.set_defaults(handler=_pi_poc_preflight)

    pi_collect = subparsers.add_parser(
        "collect-pi-poc-run",
        help="collect one bounded Pi run and execute only its fixed container workload",
    )
    pi_collect.add_argument("--manifest", type=Path, required=True)
    pi_collect.add_argument("--config", type=Path, required=True)
    pi_collect.add_argument("--specification", type=Path, required=True)
    pi_collect.add_argument("--scenario-catalog", type=Path, required=True)
    pi_collect.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    pi_collect.set_defaults(handler=_collect_pi_poc_run)

    pi_finalize = subparsers.add_parser(
        "finalize-pi-poc-manifest",
        help="verify collection and execution evidence, then complete a Pi PoC manifest",
    )
    pi_finalize.add_argument("--manifest", type=Path, required=True)
    pi_finalize.add_argument("--specification", type=Path, required=True)
    pi_finalize.add_argument("--scenario-catalog", type=Path, required=True)
    pi_finalize.add_argument("--collection-receipt", type=Path, required=True)
    pi_finalize.add_argument("--execution-receipt", type=Path, required=True)
    pi_finalize.add_argument("--output", type=Path, required=True)
    pi_finalize.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    pi_finalize.set_defaults(handler=_finalize_pi_poc_manifest)

    pi_prepare = subparsers.add_parser(
        "prepare-pi-poc-matrix",
        help="freeze 15 interleaved idle/control/TTP PoC run manifests",
    )
    pi_prepare.add_argument("--experiment-id", required=True)
    pi_prepare.add_argument("--generation", required=True)
    pi_prepare.add_argument("--image-id", required=True)
    pi_prepare.add_argument("--implementation-sha256", required=True)
    pi_prepare.add_argument("--repo-commit", required=True)
    pi_prepare.add_argument("--environment-signature-sha256", required=True)
    pi_prepare.add_argument("--config", type=Path, required=True)
    pi_prepare.add_argument("--scenario-catalog", type=Path, required=True)
    pi_prepare.add_argument("--output-dir", type=Path, required=True)
    pi_prepare.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    pi_prepare.set_defaults(handler=_prepare_pi_poc_matrix)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (DatasetContractError, SpoolError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: collection interrupted; partial segment retained", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
