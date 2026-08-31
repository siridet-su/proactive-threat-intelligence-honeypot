"""Explicit operator tool for the single Target A archive purge pilot.

The command set is deliberately small:

* ``freeze`` verifies both archive copies and writes the immutable exact-ID set;
* ``preflight`` performs the live read-only GO/NO-GO checks;
* ``execute`` repeats the live checks and, only with an explicit flag, runs the
  resumable exact-ID batches;
* ``postverify`` proves exact absence and captures post-purge metadata.

This is not a retention service and has no age-based or automatic mode.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from production.archive.cold_archive import (
    ArchiveError,
    PurgeSafetyError,
    connect_readonly,
    filesystem_capacity,
    load_uri_and_database,
    redacted_uri_metadata,
    read_archive_verified,
    write_immutable_json,
)
from production.archive.purge import (
    DEFAULT_BATCH_SIZE,
    PILOT_AUTHORIZED_MAX,
    _read_json,
    build_predelete_verification,
    capture_out_of_scope_sentinels,
    capture_storage_metrics,
    execute_exact_purge,
    freeze_exact_purge_set,
    verify_postdelete_exact_set,
)


def _json_file(path: str | Path) -> dict[str, Any]:
    try:
        return _read_json(path)
    except (OSError, UnicodeError, ValueError, KeyError) as exc:
        raise ArchiveError(f"JSON receipt is unavailable: {path}") from exc


def _add_credentials(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--protected-env-file", action="append", default=[])
    parser.add_argument("--uri-file")
    parser.add_argument("--database", default="honeypot_db")


def _add_live_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--exact-set", required=True)
    parser.add_argument("--primary-archive", required=True)
    parser.add_argument("--archive-root", required=True)
    parser.add_argument("--tier-limit-bytes", type=int, default=536870912)
    parser.add_argument("--secondary-capacity-json")
    parser.add_argument("--bson-tests-passed", action="store_true")
    parser.add_argument("--recovery-procedure", required=True)


def _open_live(args: argparse.Namespace, source: Mapping[str, Any]) -> tuple[Any, Any, dict[str, Any]]:
    uri, database = load_uri_and_database(
        uri_file=args.uri_file,
        protected_env_files=args.protected_env_file,
        database=args.database,
    )
    metadata = redacted_uri_metadata(uri)
    if metadata.get("host") != source.get("srv_hostname"):
        raise PurgeSafetyError("runtime Mongo host does not match frozen Target A")
    if database != source.get("database"):
        raise PurgeSafetyError("runtime database does not match frozen Target A")
    client = connect_readonly(uri)
    return client, client[database], {
        "scheme": metadata["scheme"],
        "host": metadata["host"],
        "database": database,
        "credential_exposed": False,
    }


def _target(source: Mapping[str, Any]) -> dict[str, Any]:
    return dict(source)


def _secondary_capacity(args: argparse.Namespace) -> dict[str, Any]:
    return _json_file(args.secondary_capacity_json) if args.secondary_capacity_json else {}


def _safe_summary(value: Mapping[str, Any]) -> None:
    summary = {
        key: value.get(key)
        for key in (
            "status",
            "archive_id",
            "exact_document_count",
            "identity_set_sha256",
            "exact_ids_remaining",
            "acknowledged_deleted_total",
            "broad_predicate_used",
            "mutations_performed",
        )
        if key in value
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))


def _run_freeze(args: argparse.Namespace) -> int:
    manifest = _json_file(args.manifest)
    secondary = _json_file(args.secondary_verification)
    result = freeze_exact_purge_set(
        args.primary_archive,
        manifest,
        secondary_archive_path=args.secondary_archive,
        secondary_verification=secondary,
        output_path=args.output,
        primary_recorded_path=args.primary_recorded_path,
        authorized_max=PILOT_AUTHORIZED_MAX,
    )
    _safe_summary(result)
    return 0


def _live_common(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], Any, Any, dict[str, Any]]:
    manifest = _json_file(args.manifest)
    frozen = _json_file(args.exact_set)
    source = manifest["source_target"]
    client, database, metadata = _open_live(args, source)
    return manifest, frozen, client, database, metadata


def _run_preflight(args: argparse.Namespace) -> int:
    manifest, frozen, client, database, metadata = _live_common(args)
    try:
        read_archive_verified(args.primary_archive, manifest=manifest)
        collection = database[manifest["source_target"]["collection"]]
        storage = capture_storage_metrics(database, tier_limit_bytes=args.tier_limit_bytes)
        pi_capacity = filesystem_capacity(args.archive_root)
        secondary_capacity = _secondary_capacity(args)
        sentinels = capture_out_of_scope_sentinels(collection, manifest)
        recovery_written = Path(args.recovery_procedure).is_file()
        predelete = build_predelete_verification(
            collection,
            frozen,
            manifest,
            target=_target(manifest["source_target"]),
            storage_before=storage,
            pi_capacity=pi_capacity,
            secondary_capacity=secondary_capacity,
            sentinels=sentinels,
            bson_tests_passed=args.bson_tests_passed,
            recovery_procedure_written=recovery_written,
            explicit_confirmation=False,
        )
        predelete["live_mongo_metadata"] = metadata
        predelete["preflight_only"] = True
        write_immutable_json(args.predelete_output, predelete)
        write_immutable_json(args.storage_before_output, storage)
        _safe_summary(predelete)
        return 0 if predelete["status"] in {"READY", "GO"} else 2
    finally:
        client.close()


def _run_execute(args: argparse.Namespace) -> int:
    if not args.confirm_purge:
        raise PurgeSafetyError("--confirm-purge is required for the destructive operation")
    manifest, frozen, client, database, metadata = _live_common(args)
    try:
        read_archive_verified(args.primary_archive, manifest=manifest)
        collection = database[manifest["source_target"]["collection"]]
        storage_before = capture_storage_metrics(database, tier_limit_bytes=args.tier_limit_bytes)
        pi_capacity = filesystem_capacity(args.archive_root)
        secondary_capacity = _secondary_capacity(args)
        sentinels = capture_out_of_scope_sentinels(collection, manifest)
        if not Path(args.recovery_procedure).is_file():
            raise PurgeSafetyError("recovery procedure is not present on the authorized runtime")
        write_immutable_json(args.storage_before_output, storage_before)
        execution = execute_exact_purge(
            collection,
            frozen,
            manifest,
            target=_target(manifest["source_target"]),
            predelete_receipt_path=args.predelete_output,
            progress_path=args.progress_output,
            execution_receipt_path=args.execution_output,
            batch_size=args.batch_size,
            authorized_max=PILOT_AUTHORIZED_MAX,
            explicit_confirmation=True,
            storage_before=storage_before,
            pi_capacity=pi_capacity,
            secondary_capacity=secondary_capacity,
            sentinels=sentinels,
            bson_tests_passed=args.bson_tests_passed,
            recovery_procedure_written=True,
        )
        post = verify_postdelete_exact_set(
            collection,
            frozen,
            manifest,
            target=_target(manifest["source_target"]),
            sentinels=sentinels,
        )
        post["execution_receipt"] = {
            "acknowledged_deleted_total": execution["acknowledged_deleted_total"],
            "batch_size": execution["batch_size"],
        }
        storage_after = capture_storage_metrics(database, tier_limit_bytes=args.tier_limit_bytes)
        write_immutable_json(args.postdelete_output, post)
        write_immutable_json(args.storage_after_output, storage_after)
        primary_post = read_archive_verified(args.primary_archive, manifest=manifest)
        write_immutable_json(
            args.primary_reverification_output,
            {
                "schema_version": "mongo_pi_archive_post_purge_reverification.v1",
                "copy": "PI_COLD_ARCHIVE",
                "archive_id": frozen["archive_id"],
                "archive_sha256": primary_post["sha256"],
                "record_count": primary_post["record_count"],
                "restore_read": primary_post["success"],
                "mutations_performed": False,
            },
        )
        _safe_summary({**execution, **post})
        return 0 if post["status"] == "PASS" else 2
    finally:
        client.close()


def _run_postverify(args: argparse.Namespace) -> int:
    manifest, frozen, client, database, metadata = _live_common(args)
    try:
        collection = database[manifest["source_target"]["collection"]]
        sentinels = _json_file(args.sentinels_json) if args.sentinels_json else None
        result = verify_postdelete_exact_set(
            collection,
            frozen,
            manifest,
            target=_target(manifest["source_target"]),
            sentinels=sentinels,
        )
        storage = capture_storage_metrics(database, tier_limit_bytes=args.tier_limit_bytes)
        write_immutable_json(args.postdelete_output, result)
        write_immutable_json(args.storage_after_output, storage)
        _safe_summary(result)
        return 0 if result["status"] == "PASS" else 2
    finally:
        client.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    freeze = sub.add_parser("freeze")
    freeze.add_argument("--manifest", required=True)
    freeze.add_argument("--primary-archive", required=True)
    freeze.add_argument("--secondary-archive", required=True)
    freeze.add_argument("--secondary-verification", required=True)
    freeze.add_argument("--primary-recorded-path")
    freeze.add_argument("--output", required=True)
    freeze.set_defaults(handler=_run_freeze)

    preflight = sub.add_parser("preflight")
    _add_credentials(preflight)
    _add_live_paths(preflight)
    preflight.add_argument("--predelete-output", required=True)
    preflight.add_argument("--storage-before-output", required=True)
    preflight.set_defaults(handler=_run_preflight)

    execute = sub.add_parser("execute")
    _add_credentials(execute)
    _add_live_paths(execute)
    execute.add_argument("--predelete-output", required=True)
    execute.add_argument("--progress-output", required=True)
    execute.add_argument("--execution-output", required=True)
    execute.add_argument("--postdelete-output", required=True)
    execute.add_argument("--storage-before-output", required=True)
    execute.add_argument("--storage-after-output", required=True)
    execute.add_argument("--primary-reverification-output", required=True)
    execute.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    execute.add_argument("--confirm-purge", action="store_true")
    execute.set_defaults(handler=_run_execute)

    post = sub.add_parser("postverify")
    _add_credentials(post)
    _add_live_paths(post)
    post.add_argument("--sentinels-json")
    post.add_argument("--postdelete-output", required=True)
    post.add_argument("--storage-after-output", required=True)
    post.set_defaults(handler=_run_postverify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (ArchiveError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR {type(exc).__name__}", file=sys.stderr)
        return 2
    except Exception as exc:  # Never leak driver/credential-bearing error text.
        print(f"ERROR {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
