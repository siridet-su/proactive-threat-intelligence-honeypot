"""One-time, exact-ID cleanup of Cowrie loopback TCP watchdog sessions.

Run on the Pi as root, with PyMongo available and the protected processor env
file in place. The default action is read-only. --execute first writes and
verifies a root-only backup, then deletes the frozen document IDs atomically.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bson.json_util import CANONICAL_JSON_OPTIONS, dumps, loads
from pymongo import MongoClient
from pymongo.read_concern import ReadConcern
from pymongo.write_concern import WriteConcern


DATABASE = "honeypot_canonical_v1"
SOURCE_IP = "127.0.0.1"
BACKUP_ROOT = Path("/var/backups/honeypot/loopback-cowrie-cleanup")
RELATED_COLLECTIONS = ("observable_sightings", "prediction_outbox", "prediction_snapshots")
DELETE_ORDER = (*RELATED_COLLECTIONS, "events", "sessions")


def protected_uri(path: Path) -> str:
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError("protected env file missing or accessible to group/others")
    for line in path.read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip().removeprefix("export ") == "MONGO_URI":
            value = value.strip()
            if value[:1] == value[-1:] and value[:1] in ('"', "'"):
                value = value[1:-1]
            if value.startswith(("mongodb://", "mongodb+srv://")):
                return value
    raise RuntimeError("MONGO_URI absent or invalid")


def parsed_time(value: object) -> datetime | None:
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return timestamp.astimezone(timezone.utc) if timestamp.tzinfo else None
    except ValueError:
        return None


def connect_destination(event: dict) -> tuple[str, str]:
    payload = event.get("payload_json")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            return "", ""
    if not isinstance(payload, dict):
        return "", ""
    return str(payload.get("dst_ip") or ""), str(payload.get("dst_port") or "")


def select_documents(database, cutoff: datetime) -> tuple[dict[str, list[dict]], dict[str, int]]:
    rows = list(database.sessions.find(
        {"src_ip": SOURCE_IP},
        {"session_id": 1, "src_ip": 1, "session_source": 1, "start_time": 1, "ended": 1},
    ))
    session_by_id = {row.get("session_id"): row for row in rows}
    session_ids = [value for value in session_by_id if isinstance(value, str) and value]
    if len(session_ids) != len(rows):
        raise RuntimeError("loopback session IDs are missing or duplicated")
    events_by_session: dict[str, list[dict]] = defaultdict(list)
    for event in database.events.find(
        {"session_id": {"$in": session_ids}},
        {"_id": 1, "session_id": 1, "src_ip": 1, "eventid": 1, "processed": 1, "payload_json": 1},
    ):
        events_by_session[event["session_id"]].append(event)

    candidate_ids: list[str] = []
    summary = Counter(loopback_sessions=len(rows))
    for session_id, row in session_by_id.items():
        events = events_by_session.get(session_id, [])
        types = Counter(event.get("eventid") for event in events)
        if types != {"cowrie.session.connect": 1, "cowrie.session.closed": 1}:
            summary["other_or_incomplete_sessions"] += 1
            continue
        connect = next(event for event in events if event.get("eventid") == "cowrie.session.connect")
        started = parsed_time(row.get("start_time"))
        if (
            row.get("session_source") != "production_live"
            or row.get("ended") is not True
            or started is None
            or started > cutoff
            or connect_destination(connect) != (SOURCE_IP, "22")
            or any(event.get("src_ip") != SOURCE_IP or event.get("processed") is not True for event in events)
        ):
            summary["pair_excluded_by_safety_checks"] += 1
            continue
        candidate_ids.append(session_id)

    documents: dict[str, list[dict]] = {}
    documents["sessions"] = list(database.sessions.find({"session_id": {"$in": candidate_ids}}))
    documents["events"] = list(database.events.find({"session_id": {"$in": candidate_ids}}))
    if len(documents["sessions"]) != len(candidate_ids) or len(documents["events"]) != 2 * len(candidate_ids):
        raise RuntimeError("candidate documents changed during selection")
    for name in RELATED_COLLECTIONS:
        documents[name] = list(database[name].find({"session_id": {"$in": candidate_ids}}))
    for name in database.list_collection_names():
        if name not in (*RELATED_COLLECTIONS, "sessions", "events"):
            if database[name].count_documents({"session_id": {"$in": candidate_ids}}, maxTimeMS=20_000):
                raise RuntimeError(f"unexpected related documents in {name}")
    summary["eligible_sessions"] = len(candidate_ids)
    for name in DELETE_ORDER:
        summary[f"{name}_documents"] = len(documents[name])
        ids = [d["_id"] for d in documents[name]]
        if len(ids) != len(set(ids)):
            raise RuntimeError(f"duplicate document IDs in {name}")
    return documents, dict(summary)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_backup(documents: dict[str, list[dict]], summary: dict[str, int]) -> Path:
    parent = BACKUP_ROOT.parent
    if not parent.is_dir() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o077:
        raise RuntimeError("protected backup parent is not root-only")
    os.umask(0o077)
    BACKUP_ROOT.mkdir(mode=0o700, exist_ok=True)
    if BACKUP_ROOT.stat().st_uid != 0 or BACKUP_ROOT.stat().st_mode & 0o077:
        raise RuntimeError("backup root is not root-only")
    estimated_bytes = sum(len(dumps(doc, json_options=CANONICAL_JSON_OPTIONS)) for values in documents.values() for doc in values)
    if shutil.disk_usage(BACKUP_ROOT).free < max(20_000_000, estimated_bytes * 4):
        raise RuntimeError("insufficient protected backup space")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = BACKUP_ROOT / stamp
    directory.mkdir(mode=0o700)
    manifest = {"schema_version": "loopback_cowrie_cleanup_backup.v1", "database": DATABASE, "source_ip": SOURCE_IP,
                "scope": "closed production Cowrie 127.0.0.1:22 connect/closed only", "counts": summary, "files": {}}
    for name in DELETE_ORDER:
        path = directory / f"{name}.ejsonl.gz"
        with path.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
                for doc in documents[name]:
                    zipped.write(dumps(doc, json_options=CANONICAL_JSON_OPTIONS, sort_keys=True).encode("utf-8") + b"\n")
            raw.flush()
            os.fsync(raw.fileno())
        count = 0
        with gzip.open(path, "rb") as zipped:
            for line in zipped:
                if not isinstance(loads(line, json_options=CANONICAL_JSON_OPTIONS), dict):
                    raise RuntimeError(f"invalid backup document in {name}")
                count += 1
        if count != len(documents[name]):
            raise RuntimeError(f"backup verification count mismatch in {name}")
        manifest["files"][name] = {"file": path.name, "count": count, "sha256": sha256_file(path)}
    manifest_path = directory / "manifest.json"
    with manifest_path.open("x") as handle:
        json.dump(manifest, handle, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return directory


def delete_exact(database, client, documents: dict[str, list[dict]]) -> dict[str, int]:
    candidate_ids = [doc["session_id"] for doc in documents["sessions"]]
    expected = {name: len(values) for name, values in documents.items()}
    deleted: dict[str, int] = {}
    with client.start_session() as transaction_session:
        with transaction_session.start_transaction(read_concern=ReadConcern("snapshot"), write_concern=WriteConcern("majority")):
            if database.events.count_documents({"session_id": {"$in": candidate_ids}}, session=transaction_session) != expected["events"]:
                raise RuntimeError("candidate events changed before deletion")
            for name in DELETE_ORDER:
                ids = [doc["_id"] for doc in documents[name]]
                if database[name].count_documents({"_id": {"$in": ids}}, session=transaction_session) != len(ids):
                    raise RuntimeError(f"candidate {name} documents changed before deletion")
                result = database[name].delete_many({"_id": {"$in": ids}}, session=transaction_session)
                if result.deleted_count != len(ids):
                    raise RuntimeError(f"candidate {name} deletion count mismatch")
                deleted[name] = result.deleted_count
    for name in DELETE_ORDER:
        ids = [doc["_id"] for doc in documents[name]]
        if database[name].count_documents({"_id": {"$in": ids}}):
            raise RuntimeError(f"post-delete {name} exact IDs remain")
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protected-env-file", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if args.execute and os.geteuid() != 0:
        raise RuntimeError("execute requires root for protected backup")
    client = MongoClient(protected_uri(args.protected_env_file), serverSelectionTimeoutMS=15_000, connectTimeoutMS=15_000)
    try:
        database = client[DATABASE]
        documents, summary = select_documents(database, datetime.now(timezone.utc) - timedelta(minutes=2))
        print(json.dumps({"action": "preflight", "counts": summary}, sort_keys=True), flush=True)
        if not args.execute:
            return 0
        if not summary["eligible_sessions"]:
            raise RuntimeError("no eligible closed watchdog sessions")
        backup = write_backup(documents, summary)
        print(json.dumps({"action": "backup_verified", "protected_directory": str(backup)}, sort_keys=True), flush=True)
        deleted = delete_exact(database, client, documents)
        print(json.dumps({"action": "deleted_and_verified", "deleted": deleted,
                          "protected_directory": str(backup)}, sort_keys=True), flush=True)
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
