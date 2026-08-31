"""CLI for the read-only MongoDB-to-Pi cold-archive pilot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from production.archive.cold_archive import (
    ArchiveError,
    ArchiveSpec,
    TOOL_VERSION,
    canonical_ejson_loads,
    connect_readonly,
    create_purge_candidate,
    ensure_archive_root,
    export_archive,
    filesystem_capacity,
    load_uri_and_database,
    mongo_capacity_status,
    pi_capacity_gate,
    plan_archive,
    read_archive_verified,
    redacted_uri_metadata,
    write_immutable_json,
)


def _json_object(text: str, name: str) -> Mapping[str, Any]:
    try:
        value = canonical_ejson_loads(text)
    except Exception as exc:
        raise ArchiveError(f"{name} is not valid Extended JSON") from exc
    if not isinstance(value, Mapping):
        raise ArchiveError(f"{name} must be an object")
    return value


def _load_text_argument(text: str | None, path: str | None, name: str) -> str:
    if bool(text) == bool(path):
        raise ArchiveError(f"supply exactly one of --{name}-json or --{name}-file")
    if path:
        return Path(path).read_text(encoding="utf-8")
    assert text is not None
    return text


def _sort_value(text: str) -> tuple[tuple[str, int], ...]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ArchiveError("sort JSON is invalid") from exc
    if not isinstance(value, list):
        raise ArchiveError("sort JSON must be a list")
    result: list[tuple[str, int]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise ArchiveError("each sort item must be [field, direction]")
        result.append((str(item[0]), int(item[1])))
    return tuple(result)


def _schema_info(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ArchiveError("schema info JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ArchiveError("schema info must be an object")
    return value


def _spec_from_args(args: argparse.Namespace, database: str, query: Mapping[str, Any]) -> ArchiveSpec:
    try:
        source_epoch = str(args.source_epoch)
        return ArchiveSpec(
            project_id=str(args.project_id),
            cluster_id=str(args.cluster_id),
            cluster_name=str(args.cluster_name),
            srv_hostname=str(args.srv_hostname),
            database=database,
            collection=str(args.collection),
            query=query,
            sort=_sort_value(args.sort_json),
            limit=args.limit,
            provenance=str(args.provenance),
            schema_info=_schema_info(args.schema_info_json),
            source_epoch=source_epoch,
            tool_version=TOOL_VERSION,
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ArchiveError):
            raise
        raise ArchiveError("archive selection configuration is invalid") from exc


def _plan_payload(plan: Any, uri_metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "mongo_pi_archive_plan.v1",
        "plan_status": "READ_ONLY_PLAN",
        "tool_version": TOOL_VERSION,
        "mongo_target": dict(uri_metadata),
        "source_target": plan.spec.source_target(),
        "query_predicate": _canonical(plan.spec.query),
        "query_predicate_canonical_ejson": _canonical(plan.spec.query),
        "sort": plan.spec.sort_list,
        "limit": plan.spec.limit,
        "source_match_count": plan.source_match_count,
        "selected_count": plan.selected_count,
        "first_sort_key": dict(plan.first_sort_key),
        "last_sort_key": dict(plan.last_sort_key),
        "first_document_id": _canonical(plan.first_document_id),
        "last_document_id": _canonical(plan.last_document_id),
        "estimated_uncompressed_bytes": sum(
            len((_canonical_ejson_line(document) + "\n").encode("utf-8"))
            for document in plan.documents
        ),
        "mutations_performed": False,
    }


def _canonical(value: Any) -> Any:
    from production.archive.cold_archive import canonical_ejson_object

    return canonical_ejson_object(value)


def _canonical_ejson_line(value: Any) -> str:
    from production.archive.cold_archive import canonical_ejson_dumps

    return canonical_ejson_dumps(value)


def _write_or_print(value: Mapping[str, Any], output: str | None) -> None:
    if output:
        write_immutable_json(output, value)
    else:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _credential_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--uri-file", help="protected owner-only URI file; never printed")
    parser.add_argument(
        "--protected-env-file",
        action="append",
        default=[],
        help="existing protected env file containing MONGO_URI/MONGO_DATABASE; read through sudo",
    )
    parser.add_argument("--database", help="database override; otherwise MONGO_DATABASE/URI path")


def _source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--cluster-id", required=True)
    parser.add_argument("--cluster-name", required=True)
    parser.add_argument("--srv-hostname", required=True)
    parser.add_argument("--collection", required=True)
    parser.add_argument("--provenance", required=True)
    parser.add_argument("--source-epoch", default="LEGACY_TARGET_A_NO_CANONICAL_EPOCH")
    parser.add_argument("--schema-info-json")
    parser.add_argument("--query-json")
    parser.add_argument("--query-file")
    parser.add_argument("--sort-json", required=True)
    parser.add_argument("--limit", type=int)


def _add_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", help="immutable JSON output path")


def _open_live(args: argparse.Namespace) -> tuple[Any, str, dict[str, Any]]:
    uri, database = load_uri_and_database(
        uri_file=args.uri_file,
        protected_env_files=args.protected_env_file,
        database=args.database,
    )
    metadata = redacted_uri_metadata(uri)
    metadata["selected_database"] = database
    client = connect_readonly(uri)
    return client, database, metadata


def _run_plan(args: argparse.Namespace, *, export: bool) -> dict[str, Any]:
    query_text = _load_text_argument(args.query_json, args.query_file, "query")
    query = _json_object(query_text, "query")
    client, database, uri_metadata = _open_live(args)
    try:
        spec = _spec_from_args(args, database, query)
        plan = plan_archive(client[database][spec.collection], spec)
        payload = _plan_payload(plan, uri_metadata)
        archive_root = ensure_archive_root(args.archive_root)
        capacity = filesystem_capacity(archive_root)
        payload["pi_capacity_before"] = capacity
        estimated_bytes = int(payload["estimated_uncompressed_bytes"])
        # The gate is a conservative pre-transfer check.  Compression may be
        # smaller, but the raw serialized batch must fit inside the reserve.
        payload["pi_capacity_gate"] = pi_capacity_gate(
            capacity,
            estimated_bytes,
            reserve_bytes=args.pi_reserve_bytes,
            max_used_ratio=args.pi_max_used_ratio,
        )
        if export and not args.dry_run:
            result = export_archive(client[database][spec.collection], spec, archive_root, plan=plan)
            payload["archive_result"] = result
            payload["pi_capacity_after"] = filesystem_capacity(archive_root)
        else:
            payload["archive_result"] = {"status": "DRY_RUN_PLAN_ONLY"}
        return payload
    finally:
        client.close()


def _run_capacity(args: argparse.Namespace) -> dict[str, Any]:
    client, database, uri_metadata = _open_live(args)
    try:
        recent_growth = json.loads(args.recent_growth_json) if args.recent_growth_json else {}
        status = mongo_capacity_status(
            client[database],
            tier_limit_bytes=args.tier_limit_bytes,
            recent_growth=recent_growth,
        )
        status["mongo_target"] = uri_metadata
        status["pi_filesystem"] = filesystem_capacity(args.archive_root)
        return status
    finally:
        client.close()


def _run_offline(args: argparse.Namespace, *, restore: bool) -> dict[str, Any]:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    archive_path = args.archive or str(
        Path(manifest["archive_path"])
        if manifest.get("archive_path")
        else Path(args.manifest).parents[1] / "archives" / f"{manifest['archive_id']}.ejsonl.zst"
    )
    if restore:
        return read_archive_verified(archive_path, manifest=manifest)
    from production.archive.cold_archive import verify_archive_file

    source = manifest["source_target"]
    spec = ArchiveSpec(
        project_id=source["project_id"],
        cluster_id=source["cluster_id"],
        cluster_name=source["cluster_name"],
        srv_hostname=source["srv_hostname"],
        database=source["database"],
        collection=source["collection"],
        query=canonical_ejson_loads(json.dumps(manifest["query_predicate"])),
        sort=tuple((item[0], item[1]) for item in manifest["sort"]),
        limit=manifest.get("limit"),
        provenance=manifest["provenance"],
        schema_info=manifest.get("schema_info") or {},
        source_epoch=source.get("storage_epoch", ""),
    )
    return verify_archive_file(
        archive_path,
        spec=spec,
        expected_count=manifest["selected_count"],
        expected_sha256=manifest["sha256"],
        expected_records_sha256=manifest["records_sha256"],
        expected_first_sort_key=manifest["first_sort_key"],
        expected_last_sort_key=manifest["last_sort_key"],
        expected_first_document_id=canonical_ejson_loads(json.dumps(manifest["first_document_id"])),
        expected_last_document_id=canonical_ejson_loads(json.dumps(manifest["last_document_id"])),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=TOOL_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command, export in (("plan", False), ("archive", True)):
        child = subparsers.add_parser(command)
        _credential_args(child)
        _source_args(child)
        child.add_argument("--archive-root", required=True)
        child.add_argument("--pi-reserve-bytes", type=int, default=10 * 1024 * 1024 * 1024)
        child.add_argument("--pi-max-used-ratio", type=float, default=0.90)
        child.add_argument("--dry-run", action="store_true")
        _add_output(child)
        child.set_defaults(export=export)

    capacity = subparsers.add_parser("capacity")
    _credential_args(capacity)
    capacity.add_argument("--archive-root", required=True)
    capacity.add_argument("--tier-limit-bytes", type=int)
    capacity.add_argument("--recent-growth-json")
    _add_output(capacity)

    for command, restore in (("verify", False), ("restore-read", True)):
        child = subparsers.add_parser(command)
        child.add_argument("--manifest", required=True)
        child.add_argument("--archive")
        _add_output(child)
        child.set_defaults(restore=restore)

    candidate = subparsers.add_parser("purge-candidate")
    candidate.add_argument("--manifest", required=True)
    candidate.add_argument("--output", required=True)
    candidate.add_argument("--lifecycle-gate-json")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command in {"plan", "archive"}:
            result = _run_plan(args, export=args.command == "archive")
            _write_or_print(result, args.output)
        elif args.command == "capacity":
            _write_or_print(_run_capacity(args), args.output)
        elif args.command in {"verify", "restore-read"}:
            _write_or_print(_run_offline(args, restore=args.restore), args.output)
        elif args.command == "purge-candidate":
            lifecycle = json.loads(args.lifecycle_gate_json) if args.lifecycle_gate_json else {}
            manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            result = create_purge_candidate(manifest, output_path=args.output, lifecycle_gate=lifecycle)
            _write_or_print(result, None)
        return 0
    except ArchiveError as exc:
        # Deliberately do not print exception strings that could include a URI
        # from a third-party driver.  Error class is sufficient for receipts.
        print(f"ERROR {type(exc).__name__}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
