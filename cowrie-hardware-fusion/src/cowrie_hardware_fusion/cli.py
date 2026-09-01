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
