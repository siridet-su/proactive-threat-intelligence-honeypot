"""Normalize historical stored payloads to parent/main ATT&CK technique IDs.

The live pipeline now treats parent technique IDs as the active operational
TTP. This maintenance command safely backfills older JSON payloads where a
sub-technique such as T1565.001 may still be stored as the active `ttp`.

The original sub-technique is preserved in `source_ttp` / `source_subtechnique`;
snapshot IDs and feature hashes are intentionally left unchanged because they
identify the historical prediction event that was originally produced.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, Iterable, List, Tuple

from production.utils.config import ProductionConfig
from production.utils.serialization import stable_json, utc_now
from production.correlation.session_ttp_knowledge import is_subtechnique_id, main_ttp_id
from production.storage import StorageBackend, open_storage, safe_database_descriptor


TABLES: Dict[str, Dict[str, str]] = {
    "sessions": {"key": "session_id", "order": "updated_at"},
    "prediction_snapshots": {"key": "snapshot_id", "order": "created_at"},
}

ACTIVE_TTP_KEYS = {
    "ttp",
    "technique",
    "technique_id",
    "last_ttp",
    "predicted_ttp",
    "reviewed_ttp",
    "active_ttp",
}

ACTIVE_TTP_LIST_KEYS = {
    "ttps",
    "observed_ttps",
    "ttp_sequence",
    "correlated_ttps",
    "required_ttps",
    "any_ttps",
    "correlated_ttps_for_prediction",
}

SOURCE_TTP_KEYS = {
    "source_ttp",
    "source_subtechnique",
    "source_technique_id",
    "source_sequence",
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _unique(values: Iterable[Any]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


def _normalize_ttp_value(value: Any) -> Tuple[Any, bool, str]:
    text = str(value or "").strip()
    if not text:
        return value, False, ""
    active = main_ttp_id(text)
    changed = bool(active and active != text)
    return active if active else value, changed, text.upper()


def normalize_payload_main_ttps(payload: Any) -> Tuple[Any, Dict[str, int]]:
    """Return `(normalized_payload, stats)` for one JSON-like value."""

    stats = {
        "active_ttp_values_normalized": 0,
        "active_ttp_lists_normalized": 0,
        "source_subtechniques_preserved": 0,
    }

    def walk(value: Any, parent_key: str = "") -> Any:
        if isinstance(value, list):
            if parent_key in ACTIVE_TTP_LIST_KEYS:
                normalized_items: List[str] = []
                changed = False
                for item in value:
                    normalized, item_changed, _source = _normalize_ttp_value(item)
                    if item_changed:
                        changed = True
                    normalized_items.append(str(normalized))
                if changed:
                    stats["active_ttp_lists_normalized"] += 1
                return _unique(normalized_items)
            return [walk(item, parent_key) for item in value]

        if isinstance(value, dict):
            normalized = {key: walk(item, str(key)) for key, item in value.items()}

            ttp_value = normalized.get("ttp")
            active_ttp, changed, source_ttp = _normalize_ttp_value(ttp_value)
            if changed:
                normalized["ttp"] = active_ttp
                normalized.setdefault("source_ttp", source_ttp)
                if is_subtechnique_id(source_ttp):
                    normalized.setdefault("source_subtechnique", source_ttp)
                    stats["source_subtechniques_preserved"] += 1
                normalized.setdefault("technique_granularity", "subtechnique_collapsed")
                stats["active_ttp_values_normalized"] += 1

            for key in list(normalized.keys()):
                if key in ACTIVE_TTP_KEYS and key != "ttp":
                    active, item_changed, source = _normalize_ttp_value(normalized.get(key))
                    if item_changed:
                        normalized[key] = active
                        normalized.setdefault(f"source_{key}", source)
                        stats["active_ttp_values_normalized"] += 1
                elif key in ACTIVE_TTP_LIST_KEYS:
                    normalized[key] = walk(normalized.get(key), key)
                elif key in SOURCE_TTP_KEYS:
                    # Source fields must preserve the exact upstream sub-technique.
                    normalized[key] = normalized.get(key)
            return normalized

        return value

    return walk(payload), stats


def _decode_payload(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    try:
        loaded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _payload_from_row(row: Dict[str, Any]) -> Dict[str, Any]:
    payload = row.get("payload")
    if isinstance(payload, dict):
        return dict(payload)
    return _decode_payload(row.get("payload_json"))


def _safe_database_label(descriptor: Dict[str, str]) -> str:
    backend = str(descriptor.get("backend") or "unknown")
    if backend == "sqlite":
        return f"sqlite:///{descriptor.get('database_path', '')}"
    endpoint = str(descriptor.get("endpoint") or "")
    database = str(descriptor.get("database") or "")
    suffix = f"/{database}" if database else ""
    return f"{backend}://{endpoint}{suffix}"


def _select_rows(storage: StorageBackend, table: str, limit: int) -> List[Dict[str, Any]]:
    return [dict(row) for row in storage.list_rows(table, limit=limit)]


def _update_payload(
    storage: StorageBackend,
    table: str,
    key_value: str,
    payload: Dict[str, Any],
    row: Dict[str, Any],
) -> None:
    spec = TABLES[table]
    key = spec["key"]
    updated = dict(payload)
    updated.setdefault(key, key_value)
    if table == "sessions":
        for field in ("src_ip", "start_time", "session_source"):
            if field not in updated and row.get(field) is not None:
                updated[field] = row[field]
        if "is_ended" not in updated and row.get("ended") is not None:
            updated["is_ended"] = bool(row["ended"])
        storage.save_session(updated)
        return
    if table == "prediction_snapshots":
        for field in (
            "session_id",
            "src_ip",
            "session_status",
            "event_id",
            "features_hash",
        ):
            if field not in updated and row.get(field) is not None:
                updated[field] = row[field]
        storage.save_prediction_snapshot(updated)
        return
    raise ValueError(f"unsupported table: {table}")


def normalize_storage(
    *,
    database_url: str,
    tables: Iterable[str] = ("sessions", "prediction_snapshots"),
    limit: int = 5000,
    apply: bool = False,
    storage: StorageBackend | None = None,
) -> Dict[str, Any]:
    selected_storage = storage or open_storage(database_url)
    database_descriptor = safe_database_descriptor(database_url)
    result: Dict[str, Any] = {
        "schema_version": "main_ttp_normalization.v1",
        "database": database_descriptor,
        "database_url": _safe_database_label(database_descriptor),
        "apply": bool(apply),
        "generated_at": utc_now(),
        "tables": {},
        "total_rows_scanned": 0,
        "total_rows_changed": 0,
        "total_active_ttp_values_normalized": 0,
        "total_active_ttp_lists_normalized": 0,
        "total_source_subtechniques_preserved": 0,
    }

    for table in tables:
        table = str(table).strip()
        if table not in TABLES:
            raise ValueError(f"unsupported table: {table}")
        rows = _select_rows(selected_storage, table, limit)
        changed_keys: List[str] = []
        table_stats = {
            "rows_scanned": len(rows),
            "rows_changed": 0,
            "active_ttp_values_normalized": 0,
            "active_ttp_lists_normalized": 0,
            "source_subtechniques_preserved": 0,
            "changed_keys_sample": changed_keys,
        }
        key_name = TABLES[table]["key"]
        for row in rows:
            payload = _payload_from_row(row)
            normalized, stats = normalize_payload_main_ttps(payload)
            actual_ttp_changes = (
                stats["active_ttp_values_normalized"]
                + stats["active_ttp_lists_normalized"]
            )
            if not actual_ttp_changes:
                continue
            if stable_json(normalized) == stable_json(payload):
                continue
            key_value = str(row.get(key_name) or payload.get(key_name) or "")
            table_stats["rows_changed"] += 1
            table_stats["active_ttp_values_normalized"] += stats["active_ttp_values_normalized"]
            table_stats["active_ttp_lists_normalized"] += stats["active_ttp_lists_normalized"]
            table_stats["source_subtechniques_preserved"] += stats["source_subtechniques_preserved"]
            if len(changed_keys) < 20:
                changed_keys.append(key_value)
            if apply:
                marker = normalized.setdefault("normalization_history", [])
                if isinstance(marker, list):
                    marker.append(
                        {
                            "operation": "collapse_subtechniques_to_parent_ttps",
                            "applied_at": utc_now(),
                            "active_fields_only": True,
                            "snapshot_ids_and_feature_hashes_preserved": table == "prediction_snapshots",
                        }
                    )
                _update_payload(selected_storage, table, key_value, normalized, row)

        result["tables"][table] = table_stats
        result["total_rows_scanned"] += table_stats["rows_scanned"]
        result["total_rows_changed"] += table_stats["rows_changed"]
        result["total_active_ttp_values_normalized"] += table_stats["active_ttp_values_normalized"]
        result["total_active_ttp_lists_normalized"] += table_stats["active_ttp_lists_normalized"]
        result["total_source_subtechniques_preserved"] += table_stats["source_subtechniques_preserved"]

    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize historical payloads to parent/main ATT&CK TTP IDs.")
    parser.add_argument("--config", default="", help="Production config JSON path.")
    parser.add_argument("--database-url", default="", help="Override DATABASE_URL.")
    parser.add_argument("--tables", default="sessions,prediction_snapshots")
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--apply", action="store_true", help="Write changes. Omit for dry-run.")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config or None)
    database_url = args.database_url or config.database_settings()
    tables = [item.strip() for item in args.tables.split(",") if item.strip()]
    result = normalize_storage(
        database_url=database_url,
        tables=tables,
        limit=max(int(args.limit or 0), 1),
        apply=bool(args.apply),
    )
    print(json.dumps(result, indent=2 if args.json else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
