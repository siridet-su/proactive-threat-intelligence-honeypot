"""CLI for the bounded Mongo hot-storage to Pi cold-archive policy.

The default command is a read-only plan.  Archive and purge execution are
explicit opt-ins; purge additionally requires ``--confirm-purge``.  This CLI
never prints a credential-bearing URI or credential value.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from production.archive.cold_archive import (
    ArchiveError,
    connect_readonly,
    filesystem_capacity,
    load_uri_and_database,
    mongo_capacity_status,
    redacted_uri_metadata,
    write_immutable_json,
)
from production.archive.retention_orchestrator import RetentionOrchestrator
from production.archive.retention_policy import RetentionPolicyError, load_retention_config


def _json_dump(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))


def _add_connection_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--protected-env-file", action="append", default=[])
    parser.add_argument("--uri-file")
    parser.add_argument("--database")
    parser.add_argument("--timeout-ms", type=int, default=10_000)


def _add_config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", required=True)


def _open_runtime(args: argparse.Namespace) -> tuple[Any, Any, dict[str, Any]]:
    config = load_retention_config(args.config)
    uri, database_name = load_uri_and_database(
        uri_file=args.uri_file,
        protected_env_files=args.protected_env_file,
        database=args.database,
    )
    metadata = redacted_uri_metadata(uri)
    if metadata.get("host") != config.target.srv_hostname:
        raise ArchiveError("runtime Mongo host does not match configured retention target")
    if database_name != config.target.database:
        raise ArchiveError("runtime Mongo database does not match configured retention target")
    client = connect_readonly(uri, timeout_ms=args.timeout_ms)
    return client, client[database_name], {
        "scheme": metadata["scheme"],
        "host": metadata["host"],
        "database": database_name,
        "credential_exposed": False,
    }


def _filesystem_snapshot(config: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, root in (
        ("pi", config.pi["archive_root"]),
        ("secondary", config.secondary["root"]),
    ):
        path = Path(str(root))
        if not path.exists():
            result[name] = {"status": "UNAVAILABLE", "path": str(path)}
            continue
        try:
            result[name] = {"status": "READ_ONLY_CAPTURED", **filesystem_capacity(path)}
        except OSError:
            result[name] = {"status": "UNAVAILABLE", "path": str(path)}
    return result


def _write_optional(path: str | None, value: dict[str, Any]) -> None:
    if path:
        write_immutable_json(path, value)


def _run_capacity(args: argparse.Namespace) -> int:
    config = load_retention_config(args.config)
    client, database, runtime = _open_runtime(args)
    try:
        capacity = mongo_capacity_status(
            database,
            tier_limit_bytes=config.capacity.quota_bytes,
            policy_thresholds={
                "warning": config.capacity.warning_ratio,
                "critical": config.capacity.high_ratio,
                "emergency": config.capacity.critical_ratio,
            },
        )
        result = {
            "schema_version": "mongo_pi_retention_capacity_receipt.v1",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "runtime_target": runtime,
            "capacity": capacity,
            "filesystem": _filesystem_snapshot(config),
            "credential_exposure": False,
            "mutations_performed": False,
        }
        _write_optional(args.output, result)
        _json_dump(result)
    finally:
        client.close()
    return 0


def _run_plan(args: argparse.Namespace) -> int:
    config = load_retention_config(args.config)
    client, database, runtime = _open_runtime(args)
    try:
        plan = RetentionOrchestrator(database, config).plan()
        result = {
            **plan.as_dict(),
            "runtime_target": runtime,
            "filesystem": _filesystem_snapshot(config),
            "credential_exposure": False,
            "mutations_performed": False,
        }
        _write_optional(args.output, result)
        _json_dump(result)
    finally:
        client.close()
    return 0


def _run_execute(args: argparse.Namespace) -> int:
    if args.execute_purge and not args.confirm_purge:
        raise ArchiveError("--execute-purge requires --confirm-purge")
    config = load_retention_config(args.config)
    client, database, runtime = _open_runtime(args)
    try:
        orchestrator = RetentionOrchestrator(database, config)
        result = orchestrator.run(
            execute_archive=args.execute_archive or args.execute_purge,
            execute_purge=args.execute_purge,
            confirm_purge=args.confirm_purge,
            automation=args.automation,
        )
        result = {
            **result,
            "runtime_target": runtime,
            "credential_exposure": False,
        }
        _write_optional(args.output, result)
        _json_dump(result)
    finally:
        client.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="honeypot-mongo-retention")
    subparsers = parser.add_subparsers(dest="command", required=True)

    capacity = subparsers.add_parser("capacity", help="read current capacity and filesystem metadata")
    _add_config_argument(capacity)
    _add_connection_arguments(capacity)
    capacity.add_argument("--output")
    capacity.set_defaults(handler=_run_capacity)

    plan = subparsers.add_parser("plan", help="produce a bounded non-destructive retention plan")
    _add_config_argument(plan)
    _add_connection_arguments(plan)
    plan.add_argument("--output")
    plan.set_defaults(handler=_run_plan)

    execute = subparsers.add_parser("run", help="run an explicitly requested archive/purge cycle")
    _add_config_argument(execute)
    _add_connection_arguments(execute)
    execute.add_argument("--execute-archive", action="store_true")
    execute.add_argument("--execute-purge", action="store_true")
    execute.add_argument("--confirm-purge", action="store_true")
    execute.add_argument("--automation", action="store_true", help="honor explicit automatic policy flags")
    execute.add_argument("--output")
    execute.set_defaults(handler=_run_execute)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (ArchiveError, RetentionPolicyError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"retention verification failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
