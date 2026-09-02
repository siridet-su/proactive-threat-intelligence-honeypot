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
        args.schema_dir / "derived_training_window.v2.schema.json",
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


def _capture_pi_environment_receipt(args: argparse.Namespace) -> int:
    from .batch import write_json_exclusive
    from .environment import (
        capture_pi_environment_receipt,
        validate_environment_receipt,
    )

    config = _load_json(args.config)
    _validate(
        config,
        args.schema_dir / "experimental_collector_config.v1.schema.json",
        str(args.config),
    )
    collector_repo_commit = args.collector_repo_commit_file.read_text(
        encoding="ascii"
    ).strip()
    receipt = capture_pi_environment_receipt(
        sensor_id=config["sensor_id"],
        subject_id=config["subject_id"],
        collector_repo_commit=collector_repo_commit,
        collector_source_archive=args.collector_source_archive,
        production_repo=args.production_repo,
        runner_image_id=args.runner_image_id,
        schema_dir=args.schema_dir,
    )
    _validate(
        receipt,
        args.schema_dir / "experiment_environment_receipt.v2.schema.json",
        "environment receipt",
    )
    summary = validate_environment_receipt(receipt)
    write_json_exclusive(args.output, receipt)
    print(json.dumps({"output": str(args.output), **summary}, sort_keys=True))
    return 0


def _validate_pi_environment_receipt(args: argparse.Namespace) -> int:
    from .environment import validate_environment_receipt

    receipt = _load_json(args.receipt)
    _validate(
        receipt,
        args.schema_dir / "experiment_environment_receipt.v2.schema.json",
        str(args.receipt),
    )
    summary = validate_environment_receipt(receipt)
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


def _snapshot_experimental_hardware(args: argparse.Namespace) -> int:
    from .batch import write_json_exclusive
    from .collector import CollectorConfig, LinuxSystemProbe
    from .parity import capture_experimental_snapshot

    config_document = _load_json(args.config)
    _validate(
        config_document,
        args.schema_dir / "experimental_collector_config.v1.schema.json",
        str(args.config),
    )
    config = CollectorConfig.from_document(config_document)
    probe = LinuxSystemProbe(config)
    if args.target_pid is not None:
        probe.set_target_process(args.target_pid)
    snapshot = capture_experimental_snapshot(
        config,
        interval_seconds=args.interval_seconds,
        probe=probe,
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


def _validate_model_feature_contract(args: argparse.Namespace) -> int:
    from .feature_contract import validate_model_feature_contract

    contract = _load_json(args.contract)
    window = _load_json(args.window)
    _validate(
        contract,
        args.schema_dir / "model_feature_contract.v1.schema.json",
        str(args.contract),
    )
    _validate(
        window,
        args.schema_dir / "derived_training_window.v2.schema.json",
        str(args.window),
    )
    summary = validate_model_feature_contract(contract, window)
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
    records: list[dict[str, Any]] = []
    for path in args.window:
        record = _load_json(path)
        schema_version = record.get("schema_version")
        schema_filename = {
            "derived_training_window.v1": "derived_training_window.v1.schema.json",
            "derived_training_window.v2": "derived_training_window.v2.schema.json",
        }.get(schema_version)
        if schema_filename is None:
            raise DatasetContractError(f"unsupported derived window schema: {schema_version}")
        _validate(record, args.schema_dir / schema_filename, str(path))
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
    args.output_dir.mkdir(parents=True, exist_ok=False)
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


def _prepare_service_pressure_pilot(args: argparse.Namespace) -> int:
    from .batch import write_json_exclusive
    from .instrumentation import (
        build_service_pressure_instrumentation_matrix,
        validate_service_pressure_contract,
    )

    config_document = _load_json(args.config)
    _validate(
        config_document,
        args.schema_dir / "experimental_collector_config.v1.schema.json",
        str(args.config),
    )
    matrix, documents = build_service_pressure_instrumentation_matrix(
        generation=args.generation,
        experiment_id=args.experiment_id,
        image_id=args.image_id,
        implementation_sha256=args.implementation_sha256,
        repo_commit=args.repo_commit,
        environment_signature_sha256=args.environment_signature_sha256,
        sensor_id=config_document["sensor_id"],
        host_id=config_document["subject_id"],
        collector_id=config_document["collector_id"],
        protocol_path=args.protocol,
        catalog_path=args.scenario_catalog,
        schema_dir=args.schema_dir,
    )
    _validate(
        matrix,
        args.schema_dir / "service_pressure_instrumentation_matrix.v2.schema.json",
        "service-pressure instrumentation matrix",
    )
    protocol = _load_json(args.protocol)
    catalog = _load_json(args.scenario_catalog)
    from hashlib import sha256

    catalog_hash = sha256(args.scenario_catalog.read_bytes()).hexdigest()
    for manifest, specification in documents:
        _validate(
            manifest,
            args.schema_dir / "experiment_run_manifest.v1.schema.json",
            manifest["run_id"],
        )
        if specification is not None:
            _validate(
                specification,
                args.schema_dir / "service_pressure_workload_spec.v2.schema.json",
                specification["spec_id"],
            )
            validate_service_pressure_contract(
                manifest,
                specification,
                protocol=protocol,
                catalog=catalog,
                catalog_sha256=catalog_hash,
                schema_dir=args.schema_dir,
            )

    write_json_exclusive(args.output_dir / "matrix.json", matrix)
    for manifest, specification in documents:
        control_dir = args.output_dir / "control" / f"run={manifest['run_id']}"
        control_dir.mkdir(parents=True, exist_ok=False)
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
                "pilot_only": matrix["pilot_only"],
                "training_eligible": matrix["training_eligible"],
            },
            sort_keys=True,
        )
    )
    return 0


def _prepare_hardware_impact_development(args: argparse.Namespace) -> int:
    from .batch import write_json_exclusive
    from .development import build_hardware_impact_development_matrix

    config_document = _load_json(args.config)
    _validate(
        config_document,
        args.schema_dir / "experimental_collector_config.v1.schema.json",
        str(args.config),
    )
    protocol = _load_json(args.protocol)
    feature_contract = _load_json(args.feature_contract)
    _validate(
        protocol,
        args.schema_dir / "hardware_impact_experiment_protocol.v2.schema.json",
        str(args.protocol),
    )
    _validate(
        feature_contract,
        args.schema_dir / "model_feature_contract.v1.schema.json",
        str(args.feature_contract),
    )
    matrix, documents = build_hardware_impact_development_matrix(
        experiment_id=args.experiment_id,
        image_id=args.image_id,
        implementation_sha256=args.implementation_sha256,
        repo_commit=args.repo_commit,
        environment_signature_sha256=args.environment_signature_sha256,
        sensor_id=config_document["sensor_id"],
        host_id=config_document["subject_id"],
        collector_id=config_document["collector_id"],
        protocol_path=args.protocol,
        feature_contract_path=args.feature_contract,
        catalog_path=args.scenario_catalog,
        schema_dir=args.schema_dir,
        schedule_seed=args.schedule_seed,
    )
    _validate(
        matrix,
        args.schema_dir / "hardware_impact_development_matrix.v1.schema.json",
        "hardware-impact development matrix",
    )
    manifest_schema = args.schema_dir / "experiment_run_manifest.v1.schema.json"
    specification_schema = (
        args.schema_dir / "hardware_impact_development_workload_spec.v1.schema.json"
    )
    for manifest, specification in documents:
        _validate(manifest, manifest_schema, manifest["run_id"])
        if specification is not None:
            _validate(specification, specification_schema, specification["spec_id"])

    write_json_exclusive(args.output_dir / "matrix.json", matrix)
    for manifest, specification in documents:
        control_dir = args.output_dir / "control" / f"run={manifest['run_id']}"
        control_dir.mkdir(parents=True, exist_ok=False)
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
                "minimum_distinct_days": matrix["minimum_distinct_days"],
                "training_eligible": matrix["training_eligible"],
                "final_test_opened": matrix["final_test_opened"],
            },
            sort_keys=True,
        )
    )
    return 0


def _validated_development_controls(
    args: argparse.Namespace,
) -> tuple[
    dict[str, Any],
    dict[str, tuple[dict[str, Any], dict[str, Any] | None]],
    dict[str, Any],
]:
    from hashlib import sha256

    from .development import validate_development_matrix

    matrix = _load_json(args.matrix)
    protocol = _load_json(args.protocol)
    feature_contract = _load_json(args.feature_contract)
    catalog = _load_json(args.scenario_catalog)
    _validate(
        matrix,
        args.schema_dir / "hardware_impact_development_matrix.v1.schema.json",
        str(args.matrix),
    )
    _validate(
        protocol,
        args.schema_dir / "hardware_impact_experiment_protocol.v2.schema.json",
        str(args.protocol),
    )
    _validate(
        feature_contract,
        args.schema_dir / "model_feature_contract.v1.schema.json",
        str(args.feature_contract),
    )
    manifest_schema = args.schema_dir / "experiment_run_manifest.v1.schema.json"
    specification_schema = (
        args.schema_dir / "hardware_impact_development_workload_spec.v1.schema.json"
    )
    documents: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    by_run: dict[str, tuple[dict[str, Any], dict[str, Any] | None]] = {}
    for entry in matrix["runs"]:
        run_id = entry["run_id"]
        control_dir = args.control_dir / f"run={run_id}"
        manifest_path = control_dir / "planned-manifest.json"
        specification_path = control_dir / "workload-spec.json"
        manifest = _load_json(manifest_path)
        _validate(manifest, manifest_schema, str(manifest_path))
        if entry["controlled_workload"]:
            specification = _load_json(specification_path)
            _validate(specification, specification_schema, str(specification_path))
        else:
            if specification_path.exists():
                raise DatasetContractError(
                    f"idle control unexpectedly has workload spec: {run_id}"
                )
            specification = None
        documents.append((manifest, specification))
        by_run[run_id] = (manifest, specification)
    summary = validate_development_matrix(
        matrix,
        documents,
        protocol=protocol,
        feature_contract=feature_contract,
        catalog=catalog,
        catalog_sha256=sha256(args.scenario_catalog.read_bytes()).hexdigest(),
        schema_dir=args.schema_dir,
    )
    return matrix, by_run, summary


def _validate_hardware_impact_development_controls(args: argparse.Namespace) -> int:
    matrix, _, summary = _validated_development_controls(args)
    print(
        json.dumps(
            {
                "matrix_id": matrix["matrix_id"],
                **summary,
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


def _development_run_inputs(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], Any, dict[str, Any] | None, dict[str, Any]]:
    from .collector import CollectorConfig

    _, by_run, _ = _validated_development_controls(args)
    if args.run_id not in by_run:
        raise DatasetContractError("run_id is absent from the development matrix")
    manifest, specification = by_run[args.run_id]
    config_document = _load_json(args.config)
    _validate(
        config_document,
        args.schema_dir / "experimental_collector_config.v1.schema.json",
        str(args.config),
    )
    return manifest, CollectorConfig.from_document(config_document), specification, by_run


def _hardware_impact_development_preflight(args: argparse.Namespace) -> int:
    from .collector import collector_preflight, controlled_collector_preflight
    from .poc import safe_container_runtime_preflight

    manifest, config, specification, _ = _development_run_inputs(args)
    if specification is None:
        collector_report = collector_preflight(
            manifest, config, schema_dir=args.schema_dir
        )
        runtime_report = {
            "execution_authorized": False,
            "execution_started": False,
            "reason": "neutral_idle_no_execution",
        }
    else:
        collector_report = controlled_collector_preflight(
            manifest, config, schema_dir=args.schema_dir
        )
        runtime_report = safe_container_runtime_preflight(manifest, specification)
    print(
        json.dumps(
            {
                "run_id": manifest["run_id"],
                "partition": "development_train",
                "collector": collector_report,
                "runtime": runtime_report,
                "collection_started": False,
                "final_test_opened": False,
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
    )
    return 0


def _collect_hardware_impact_development_run(args: argparse.Namespace) -> int:
    from .collector import (
        collect_controlled_run,
        collect_idle_run,
        collector_preflight,
        controlled_collector_preflight,
        write_json_exclusive,
    )
    from .poc import DockerWorkloadLifecycle, safe_container_runtime_preflight

    manifest, config, specification, _ = _development_run_inputs(args)
    if specification is None:
        preflight = collector_preflight(manifest, config, schema_dir=args.schema_dir)
        collection_receipt = collect_idle_run(
            manifest,
            config,
            schema_dir=args.schema_dir,
            ntp_synchronized=preflight["ntp_synchronized"],
        )
        execution_receipt = None
    else:
        preflight = controlled_collector_preflight(
            manifest, config, schema_dir=args.schema_dir
        )
        safe_container_runtime_preflight(manifest, specification)
        lifecycle = DockerWorkloadLifecycle(manifest, specification)
        collection_receipt = collect_controlled_run(
            manifest,
            config,
            schema_dir=args.schema_dir,
            lifecycle=lifecycle,
            ntp_synchronized=preflight["ntp_synchronized"],
        )
        execution_receipt = lifecycle.execution_receipt()
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
        write_json_exclusive(
            run_dir / "pi-poc-execution-receipt.json", execution_receipt
        )
    _validate(
        collection_receipt,
        args.schema_dir / "experiment_collection_receipt.v1.schema.json",
        "collection receipt",
    )
    run_dir = (
        config.spool_directory
        / f"run={manifest['run_id']}"
        / f"scope={config.metric_scope}"
    )
    print(
        json.dumps(
            {
                "run_id": manifest["run_id"],
                "partition": "development_train",
                "collection_receipt": str(run_dir / "collection-receipt.json"),
                "execution_receipt": (
                    str(run_dir / "pi-poc-execution-receipt.json")
                    if execution_receipt is not None
                    else None
                ),
                "records": collection_receipt["record_count"],
                "workload_summary": (
                    execution_receipt["workload_summary"]
                    if execution_receipt is not None
                    else None
                ),
                "cleanup_verified": (
                    execution_receipt["cleanup_verified"]
                    if execution_receipt is not None
                    else True
                ),
                "final_test_opened": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


def _finalize_hardware_impact_development_manifest(args: argparse.Namespace) -> int:
    from .batch import canonical_sha256
    from .collector import finalize_idle_manifest, write_json_exclusive
    from .instrumentation import validate_observed_impact_evidence

    manifest, _, specification, _ = _development_run_inputs(args)
    collection_receipt = _load_json(args.collection_receipt)
    _validate(
        collection_receipt,
        args.schema_dir / "experiment_collection_receipt.v1.schema.json",
        str(args.collection_receipt),
    )
    completed = finalize_idle_manifest(
        manifest,
        collection_receipt,
        run_dir=args.collection_receipt.parent,
        schema_dir=args.schema_dir,
    )
    impact_evidence = None
    if specification is None:
        if args.execution_receipt is not None:
            raise DatasetContractError("idle development run cannot have execution receipt")
    else:
        if args.execution_receipt is None:
            raise DatasetContractError(
                "controlled development run requires execution receipt"
            )
        execution_receipt = _load_json(args.execution_receipt)
        _validate(
            execution_receipt,
            args.schema_dir / "pi_poc_execution_receipt.v1.schema.json",
            str(args.execution_receipt),
        )
        payload = dict(execution_receipt)
        claimed_hash = payload.pop("receipt_sha256")
        if canonical_sha256(payload) != claimed_hash:
            raise DatasetContractError("execution receipt content hash does not match")
        if (
            execution_receipt["run_id"] != manifest["run_id"]
            or execution_receipt["scenario_id"]
            != manifest["workload"]["scenario_id"]
            or execution_receipt["manifest_content_sha256"]
            != canonical_sha256(manifest)
            or execution_receipt["specification_content_sha256"]
            != canonical_sha256(specification)
        ):
            raise DatasetContractError(
                "execution receipt does not bind development controls"
            )
        impact_evidence = validate_observed_impact_evidence(
            manifest, specification, execution_receipt
        )
        execution_id = execution_receipt["receipt_id"]
        if execution_id not in completed["labels"]["evidence_receipt_ids"]:
            completed["labels"]["evidence_receipt_ids"].append(execution_id)
    _validate(
        completed,
        args.schema_dir / "experiment_run_manifest.v1.schema.json",
        "completed development manifest",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json_exclusive(args.output, completed)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "run_id": completed["run_id"],
                "state": completed["state"],
                "partition": "development_train",
                "observed_impact_gate": impact_evidence,
                "final_test_opened": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _validated_service_pressure_inputs(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], Any, dict[str, Any]]:
    from hashlib import sha256

    from .instrumentation import validate_service_pressure_contract

    manifest, config = _validated_collector_inputs(args)
    specification = _load_json(args.specification)
    _validate(
        specification,
        args.schema_dir / "service_pressure_workload_spec.v2.schema.json",
        str(args.specification),
    )
    validate_service_pressure_contract(
        manifest,
        specification,
        protocol=_load_json(args.protocol),
        catalog=_load_json(args.scenario_catalog),
        catalog_sha256=sha256(args.scenario_catalog.read_bytes()).hexdigest(),
        schema_dir=args.schema_dir,
    )
    return manifest, config, specification


def _service_pressure_preflight(args: argparse.Namespace) -> int:
    from .collector import controlled_collector_preflight
    from .poc import safe_container_runtime_preflight

    manifest, config, specification = _validated_service_pressure_inputs(args)
    collector_report = controlled_collector_preflight(
        manifest,
        config,
        schema_dir=args.schema_dir,
    )
    runtime_report = safe_container_runtime_preflight(manifest, specification)
    print(
        json.dumps(
            {"collector": collector_report, "runtime": runtime_report},
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
    )
    return 0


def _collect_service_pressure_run(args: argparse.Namespace) -> int:
    from .collector import (
        collect_controlled_run,
        controlled_collector_preflight,
        write_json_exclusive,
    )
    from .poc import DockerWorkloadLifecycle, safe_container_runtime_preflight

    manifest, config, specification = _validated_service_pressure_inputs(args)
    collector_report = controlled_collector_preflight(
        manifest,
        config,
        schema_dir=args.schema_dir,
    )
    safe_container_runtime_preflight(manifest, specification)
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


def _finalize_service_pressure_manifest(args: argparse.Namespace) -> int:
    from hashlib import sha256

    from .batch import canonical_sha256
    from .collector import finalize_idle_manifest, write_json_exclusive
    from .instrumentation import (
        validate_observed_impact_evidence,
        validate_service_pressure_contract,
    )

    manifest = _load_json(args.manifest)
    specification = _load_json(args.specification)
    collection_receipt = _load_json(args.collection_receipt)
    execution_receipt = _load_json(args.execution_receipt)
    _validate(
        manifest,
        args.schema_dir / "experiment_run_manifest.v1.schema.json",
        str(args.manifest),
    )
    _validate(
        specification,
        args.schema_dir / "service_pressure_workload_spec.v2.schema.json",
        str(args.specification),
    )
    validate_service_pressure_contract(
        manifest,
        specification,
        protocol=_load_json(args.protocol),
        catalog=_load_json(args.scenario_catalog),
        catalog_sha256=sha256(args.scenario_catalog.read_bytes()).hexdigest(),
        schema_dir=args.schema_dir,
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
    impact_evidence = validate_observed_impact_evidence(
        manifest,
        specification,
        execution_receipt,
    )
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
                "evidence_receipt_ids": completed["labels"]["evidence_receipt_ids"],
                "observed_impact_gate": impact_evidence,
            },
            sort_keys=True,
        )
    )
    return 0


def _summarize_service_pressure_signals(args: argparse.Namespace) -> int:
    from hashlib import sha256

    from .batch import write_json_exclusive
    from .instrumentation import summarize_service_pressure_signals

    manifest = _load_json(args.manifest)
    _validate(
        manifest,
        args.schema_dir / "experiment_run_manifest.v1.schema.json",
        str(args.manifest),
    )
    telemetry_schema = args.schema_dir / "hardware_telemetry_sample.v1.schema.json"
    collection_receipt = _load_json(args.collection_receipt)
    _validate(
        collection_receipt,
        args.schema_dir / "experiment_collection_receipt.v1.schema.json",
        str(args.collection_receipt),
    )
    from .collector import verify_collection_receipt

    telemetry_validator = Draft202012Validator(
        _load_json(telemetry_schema),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    verify_collection_receipt(
        collection_receipt,
        run_dir=args.collection_receipt.parent,
        telemetry_validator=telemetry_validator,
    )
    if collection_receipt["run_id"] != manifest["run_id"]:
        raise DatasetContractError("collection receipt run_id does not match manifest")
    if collection_receipt["receipt_id"] not in manifest["labels"]["evidence_receipt_ids"]:
        raise DatasetContractError("completed manifest does not cite collection receipt")
    expected_paths = {
        (args.collection_receipt.parent / segment["filename"]).resolve()
        for segment in collection_receipt["segments"]
    }
    provided_paths = {path.resolve() for path in args.telemetry}
    if provided_paths != expected_paths or len(args.telemetry) != len(expected_paths):
        raise DatasetContractError(
            "telemetry arguments must exactly match collection receipt segments"
        )
    samples: list[dict[str, Any]] = []
    source_segments: list[dict[str, str]] = []
    for telemetry_path in args.telemetry:
        segment_samples = _load_jsonl(telemetry_path)
        for index, sample in enumerate(segment_samples, start=1):
            _validate(sample, telemetry_schema, f"{telemetry_path}:{index}")
        samples.extend(segment_samples)
        source_segments.append(
            {
                "filename": telemetry_path.name,
                "sha256": sha256(telemetry_path.read_bytes()).hexdigest(),
            }
        )
    report = summarize_service_pressure_signals(
        manifest,
        samples,
        collection_receipt_sha256=collection_receipt["receipt_sha256"],
        source_segments=source_segments,
    )
    _validate(
        report,
        args.schema_dir / "service_pressure_signal_report.v1.schema.json",
        "service-pressure signal report",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json_exclusive(args.output, report)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "report_sha256": report["report_sha256"],
                "candidate_signal_count": report["quality"]["candidate_signal_count"],
                "feature_freeze_review_eligible_count": report["quality"][
                    "feature_freeze_review_eligible_count"
                ],
                "model_feature_eligible": report["model_feature_eligible"],
            },
            sort_keys=True,
        )
    )
    return 0


def _add_development_control_arguments(
    command: argparse.ArgumentParser,
    *,
    include_run: bool,
    include_config: bool,
) -> None:
    command.add_argument("--matrix", type=Path, required=True)
    command.add_argument("--control-dir", type=Path, required=True)
    command.add_argument("--protocol", type=Path, required=True)
    command.add_argument("--feature-contract", type=Path, required=True)
    command.add_argument("--scenario-catalog", type=Path, required=True)
    if include_run:
        command.add_argument("--run-id", required=True)
    if include_config:
        command.add_argument("--config", type=Path, required=True)
    command.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)


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

    environment_capture = subparsers.add_parser(
        "capture-pi-environment-receipt",
        help="capture a privacy-bounded, hash-bound Pi runtime/environment receipt",
    )
    environment_capture.add_argument("--config", type=Path, required=True)
    environment_capture.add_argument(
        "--collector-repo-commit-file", type=Path, required=True
    )
    environment_capture.add_argument(
        "--collector-source-archive", type=Path, required=True
    )
    environment_capture.add_argument("--production-repo", type=Path, required=True)
    environment_capture.add_argument("--runner-image-id", required=True)
    environment_capture.add_argument("--output", type=Path, required=True)
    environment_capture.add_argument(
        "--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR
    )
    environment_capture.set_defaults(handler=_capture_pi_environment_receipt)

    environment_validate = subparsers.add_parser(
        "validate-pi-environment-receipt",
        help="verify a captured Pi environment receipt and safety gates",
    )
    environment_validate.add_argument("--receipt", type=Path, required=True)
    environment_validate.add_argument(
        "--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR
    )
    environment_validate.set_defaults(handler=_validate_pi_environment_receipt)

    parity_snapshot = subparsers.add_parser(
        "snapshot-experimental-hardware",
        help="print one warmed read-only experimental collector snapshot",
    )
    parity_snapshot.add_argument("--config", type=Path, required=True)
    parity_snapshot.add_argument("--interval-seconds", type=float, default=1.0)
    parity_snapshot.add_argument(
        "--target-pid",
        type=int,
        help="observe one already-authorized target process without persisting its PID",
    )
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

    feature_contract_validate = subparsers.add_parser(
        "validate-model-feature-contract",
        help="bind frozen XGBoost/TCN profiles to a verified builder-v2 window",
    )
    feature_contract_validate.add_argument("--contract", type=Path, required=True)
    feature_contract_validate.add_argument("--window", type=Path, required=True)
    feature_contract_validate.add_argument(
        "--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR
    )
    feature_contract_validate.set_defaults(handler=_validate_model_feature_contract)

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

    instrumentation_prepare = subparsers.add_parser(
        "prepare-service-pressure-pilot",
        help="freeze one excluded 7-scenario instrumentation run per protocol scenario",
    )
    instrumentation_prepare.add_argument("--experiment-id", required=True)
    instrumentation_prepare.add_argument("--generation", default="v2")
    instrumentation_prepare.add_argument("--image-id", required=True)
    instrumentation_prepare.add_argument("--implementation-sha256", required=True)
    instrumentation_prepare.add_argument("--repo-commit", required=True)
    instrumentation_prepare.add_argument("--environment-signature-sha256", required=True)
    instrumentation_prepare.add_argument("--config", type=Path, required=True)
    instrumentation_prepare.add_argument("--protocol", type=Path, required=True)
    instrumentation_prepare.add_argument("--scenario-catalog", type=Path, required=True)
    instrumentation_prepare.add_argument("--output-dir", type=Path, required=True)
    instrumentation_prepare.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    instrumentation_prepare.set_defaults(handler=_prepare_service_pressure_pilot)

    development_prepare = subparsers.add_parser(
        "prepare-hardware-impact-development",
        help="freeze the 70-run development wave while keeping calibration/final absent",
    )
    development_prepare.add_argument("--experiment-id", required=True)
    development_prepare.add_argument("--image-id", required=True)
    development_prepare.add_argument("--implementation-sha256", required=True)
    development_prepare.add_argument("--repo-commit", required=True)
    development_prepare.add_argument("--environment-signature-sha256", required=True)
    development_prepare.add_argument("--config", type=Path, required=True)
    development_prepare.add_argument("--protocol", type=Path, required=True)
    development_prepare.add_argument("--feature-contract", type=Path, required=True)
    development_prepare.add_argument("--scenario-catalog", type=Path, required=True)
    development_prepare.add_argument("--output-dir", type=Path, required=True)
    development_prepare.add_argument("--schedule-seed", type=int, default=20260903)
    development_prepare.add_argument(
        "--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR
    )
    development_prepare.set_defaults(handler=_prepare_hardware_impact_development)

    development_validate = subparsers.add_parser(
        "validate-hardware-impact-development-controls",
        help="verify all 70 development manifests/specs without collecting data",
    )
    _add_development_control_arguments(
        development_validate, include_run=False, include_config=False
    )
    development_validate.set_defaults(
        handler=_validate_hardware_impact_development_controls
    )

    development_preflight = subparsers.add_parser(
        "hardware-impact-development-preflight",
        help="preflight one matrix-bound development run without starting collection",
    )
    _add_development_control_arguments(
        development_preflight, include_run=True, include_config=True
    )
    development_preflight.set_defaults(
        handler=_hardware_impact_development_preflight
    )

    development_collect = subparsers.add_parser(
        "collect-hardware-impact-development-run",
        help="collect one matrix-bound development run using the reviewed safe runtime",
    )
    _add_development_control_arguments(
        development_collect, include_run=True, include_config=True
    )
    development_collect.set_defaults(
        handler=_collect_hardware_impact_development_run
    )

    development_finalize = subparsers.add_parser(
        "finalize-hardware-impact-development-manifest",
        help="verify receipts/evidence and complete one development manifest",
    )
    _add_development_control_arguments(
        development_finalize, include_run=True, include_config=True
    )
    development_finalize.add_argument(
        "--collection-receipt", type=Path, required=True
    )
    development_finalize.add_argument("--execution-receipt", type=Path)
    development_finalize.add_argument("--output", type=Path, required=True)
    development_finalize.set_defaults(
        handler=_finalize_hardware_impact_development_manifest
    )

    instrumentation_preflight = subparsers.add_parser(
        "service-pressure-pilot-preflight",
        help="validate one controlled instrumentation spec and current Pi safety gates",
    )
    instrumentation_preflight.add_argument("--manifest", type=Path, required=True)
    instrumentation_preflight.add_argument("--config", type=Path, required=True)
    instrumentation_preflight.add_argument("--specification", type=Path, required=True)
    instrumentation_preflight.add_argument("--protocol", type=Path, required=True)
    instrumentation_preflight.add_argument("--scenario-catalog", type=Path, required=True)
    instrumentation_preflight.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    instrumentation_preflight.set_defaults(handler=_service_pressure_preflight)

    instrumentation_collect = subparsers.add_parser(
        "collect-service-pressure-pilot-run",
        help="collect one reviewed instrumentation run with a fixed safe-container workload",
    )
    instrumentation_collect.add_argument("--manifest", type=Path, required=True)
    instrumentation_collect.add_argument("--config", type=Path, required=True)
    instrumentation_collect.add_argument("--specification", type=Path, required=True)
    instrumentation_collect.add_argument("--protocol", type=Path, required=True)
    instrumentation_collect.add_argument("--scenario-catalog", type=Path, required=True)
    instrumentation_collect.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    instrumentation_collect.set_defaults(handler=_collect_service_pressure_run)

    instrumentation_finalize = subparsers.add_parser(
        "finalize-service-pressure-pilot-manifest",
        help="bind controlled instrumentation collection/execution evidence to a manifest",
    )
    instrumentation_finalize.add_argument("--manifest", type=Path, required=True)
    instrumentation_finalize.add_argument("--specification", type=Path, required=True)
    instrumentation_finalize.add_argument("--protocol", type=Path, required=True)
    instrumentation_finalize.add_argument("--scenario-catalog", type=Path, required=True)
    instrumentation_finalize.add_argument("--collection-receipt", type=Path, required=True)
    instrumentation_finalize.add_argument("--execution-receipt", type=Path, required=True)
    instrumentation_finalize.add_argument("--output", type=Path, required=True)
    instrumentation_finalize.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    instrumentation_finalize.set_defaults(handler=_finalize_service_pressure_manifest)

    signal_summary = subparsers.add_parser(
        "summarize-service-pressure-signals",
        help="report candidate availability and phase deltas without changing model features",
    )
    signal_summary.add_argument("--manifest", type=Path, required=True)
    signal_summary.add_argument("--collection-receipt", type=Path, required=True)
    signal_summary.add_argument(
        "--telemetry",
        type=Path,
        nargs="+",
        required=True,
        metavar="JSONL",
    )
    signal_summary.add_argument("--output", type=Path, required=True)
    signal_summary.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    signal_summary.set_defaults(handler=_summarize_service_pressure_signals)
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
