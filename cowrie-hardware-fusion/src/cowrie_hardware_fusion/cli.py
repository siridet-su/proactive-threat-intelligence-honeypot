"""Command-line entry point for deterministic dataset construction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from jsonschema import Draft202012Validator

from .dataset import DatasetContractError, build_training_window


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
    samples = _load_jsonl(args.telemetry)
    _validate(
        manifest,
        args.schema_dir / "experiment_run_manifest.v1.schema.json",
        str(args.manifest),
    )
    telemetry_schema = args.schema_dir / "hardware_telemetry_sample.v1.schema.json"
    for index, sample in enumerate(samples, start=1):
        _validate(sample, telemetry_schema, f"{args.telemetry}:{index}")

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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cowrie-hardware-dataset",
        description="Build leakage-aware XGBoost/TCN inputs from one controlled run.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-window", help="build one derived training window")
    build.add_argument("--manifest", type=Path, required=True)
    build.add_argument("--telemetry", type=Path, required=True, help="telemetry JSONL")
    build.add_argument("--output", type=Path)
    build.add_argument("--schema-dir", type=Path, default=DEFAULT_SCHEMA_DIR)
    build.add_argument("--metric-scope", default="pi_sensor")
    build.add_argument("--phase", choices=("workload", "recovery"), default="workload")
    build.add_argument("--horizon-seconds", type=int, choices=(5, 10, 30, 60), default=30)
    build.add_argument("--minimum-coverage", type=float, default=0.99)
    build.set_defaults(handler=_build_window)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (DatasetContractError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

