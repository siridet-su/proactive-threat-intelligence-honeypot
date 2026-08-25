from __future__ import annotations

import argparse
import json
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Any, Iterable, List

from production.storage import StorageBackend, open_storage
from production.utils.config import ProductionConfig
from production.storage.session_provenance import (
    SESSION_SOURCE_PRODUCTION_LIVE,
    is_external_source_ip,
    normalize_session_source,
)


DEFAULT_STATE_PATH = "./runtime/session_count_monitor_state.json"
DEFAULT_THRESHOLDS = [1, 30]
LEGACY_SESSION_COUNT_SCAN_LIMIT = 10_000


def parse_thresholds(raw: str | None) -> List[int]:
    if not raw:
        return list(DEFAULT_THRESHOLDS)
    thresholds: List[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        value = int(item)
        if value <= 0:
            raise ValueError("session-count thresholds must be positive integers")
        thresholds.append(value)
    return sorted(set(thresholds))


def _session_payload(row: dict[str, Any]) -> dict[str, Any]:
    payload = row.get("payload")
    if isinstance(payload, dict):
        return payload
    raw = row.get("payload_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return loaded if isinstance(loaded, dict) else {}
    return {}


def _row_bool(row: dict[str, Any], payload: dict[str, Any], *keys: str) -> bool:
    def as_bool(value: Any) -> bool:
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"", "0", "false", "no", "off"}:
                return False
            if normalized in {"1", "true", "yes", "on"}:
                return True
        return bool(value)

    for key in keys:
        if key in row and row[key] is not None:
            return as_bool(row[key])
        if key in payload and payload[key] is not None:
            return as_bool(payload[key])
    return False


def completed_session_count(
    database_url: str,
    session_source: str = SESSION_SOURCE_PRODUCTION_LIVE,
    external_only: bool = True,
    *,
    storage: StorageBackend | None = None,
) -> int:
    source = normalize_session_source(session_source, SESSION_SOURCE_PRODUCTION_LIVE)
    selected_storage = storage or open_storage(database_url)
    count_method = getattr(selected_storage, "count_sessions", None)
    if callable(count_method):
        return int(
            count_method(
                session_source=source,
                external_only=external_only,
                ended_only=True,
            )
        )
    if storage is None:
        raise AttributeError("configured storage backend does not implement count_sessions")

    # Compatibility for older injected test fakes only. Runtime adapters use
    # count_sessions() so the monitor never loads the session corpus into memory.
    rows = selected_storage.list_session_rows(
        limit=LEGACY_SESSION_COUNT_SCAN_LIMIT,
        session_source=source,
        external_only=False,
    )
    completed = 0
    for row in rows:
        payload = _session_payload(row)
        if not _row_bool(row, payload, "ended", "is_ended"):
            continue
        if external_only:
            has_external_marker = (
                ("is_external_source" in row and row.get("is_external_source") is not None)
                or ("is_external_source" in payload and payload.get("is_external_source") is not None)
            )
            if has_external_marker:
                if not _row_bool(row, payload, "is_external_source"):
                    continue
            else:
                src_ip = row.get("src_ip") or payload.get("src_ip")
                if not is_external_source_ip(src_ip):
                    continue
        completed += 1
    return completed


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"notified_thresholds": []}
    with path.open("r", encoding="utf-8") as f:
        state = json.load(f)
    if not isinstance(state, dict):
        raise ValueError(f"session-count monitor state must be a JSON object: {path}")
    state.setdefault("notified_thresholds", [])
    return state


def prepare_state_for_session_source(
    state: dict,
    session_source: str,
    logger: logging.Logger,
    external_only: bool = True,
) -> dict:
    """Reset threshold state when an old monitor run used a different data source."""
    previous_source = str(state.get("session_source") or "").strip()
    previous_external_only = bool(state.get("external_only", False))
    if previous_source == session_source and previous_external_only == external_only:
        return state
    if not previous_source and not state.get("notified_thresholds") and "last_completed_session_count" not in state:
        return state
    logger.warning(
        "session-count monitor source changed; resetting threshold notifications: previous_session_source=%s session_source=%s previous_external_only=%s external_only=%s",
        previous_source,
        session_source,
        previous_external_only,
        external_only,
    )
    return {
        "notified_thresholds": [],
        "previous_state": state,
        "session_source": session_source,
        "external_only": external_only,
    }


def write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(state, f, sort_keys=True)
        f.write("\n")
    tmp.replace(path)


def configure_logging(use_syslog: bool = True) -> logging.Logger:
    logger = logging.getLogger("honeypot-session-count-monitor")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("%(levelname)s %(name)s %(message)s")
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    if use_syslog and Path("/dev/log").exists():
        syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)
    return logger


def evaluate_thresholds(
    completed_count: int,
    thresholds: Iterable[int],
    state: dict,
    logger: logging.Logger,
    session_source: str = SESSION_SOURCE_PRODUCTION_LIVE,
    external_only: bool = True,
) -> List[int]:
    notified = {int(value) for value in state.get("notified_thresholds", [])}
    newly_notified: List[int] = []
    for threshold in sorted(set(thresholds)):
        if completed_count >= threshold and threshold not in notified:
            logger.warning(
                "completed-session threshold reached: threshold=%s completed_sessions=%s session_source=%s external_only=%s",
                threshold,
                completed_count,
                session_source,
                external_only,
            )
            notified.add(threshold)
            newly_notified.append(threshold)
    state["notified_thresholds"] = sorted(notified)
    state["last_completed_session_count"] = completed_count
    state["session_source"] = session_source
    state["external_only"] = external_only
    return newly_notified


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Monitor completed honeypot session thresholds.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument(
        "--state-path",
        default=os.getenv("SESSION_COUNT_MONITOR_STATE_PATH", DEFAULT_STATE_PATH),
        help="Path to threshold notification state JSON.",
    )
    parser.add_argument(
        "--thresholds",
        default=os.getenv("SESSION_COUNT_MONITOR_THRESHOLDS", ",".join(str(v) for v in DEFAULT_THRESHOLDS)),
        help="Comma-separated completed-session thresholds. Default: 1,30.",
    )
    parser.add_argument(
        "--session-source",
        default=os.getenv("SESSION_COUNT_MONITOR_SOURCE", SESSION_SOURCE_PRODUCTION_LIVE),
        help="Session provenance to count. Default: production_live.",
    )
    parser.add_argument(
        "--include-non-external-source-ips",
        action="store_true",
        default=os.getenv("SESSION_COUNT_MONITOR_INCLUDE_NON_EXTERNAL_SOURCE_IPS", "").strip().lower()
        in {"1", "true", "yes", "on"},
        help="Audit mode: include non-global source IPs. Default counts external/global source IPs only.",
    )
    parser.add_argument("--no-syslog", action="store_true", help="Log to stdout only.")
    return parser


def main() -> None:
    args = build_arg_parser().parse_args()
    logger = configure_logging(use_syslog=not args.no_syslog)
    config = ProductionConfig.from_env(args.config)
    thresholds = parse_thresholds(args.thresholds)
    session_source = normalize_session_source(args.session_source, SESSION_SOURCE_PRODUCTION_LIVE)
    external_only = not bool(args.include_non_external_source_ips)
    state_path = Path(args.state_path)
    state = load_state(state_path)
    state = prepare_state_for_session_source(state, session_source, logger, external_only=external_only)
    count = completed_session_count(
        config.database_settings(),
        session_source=session_source,
        external_only=external_only,
    )
    newly_notified = evaluate_thresholds(
        count,
        thresholds,
        state,
        logger,
        session_source=session_source,
        external_only=external_only,
    )
    write_state(state_path, state)
    logger.info(
        "session-count monitor complete: completed_sessions=%s session_source=%s external_only=%s thresholds=%s newly_notified=%s state_path=%s",
        count,
        session_source,
        external_only,
        thresholds,
        newly_notified,
        state_path,
    )


if __name__ == "__main__":
    main()
