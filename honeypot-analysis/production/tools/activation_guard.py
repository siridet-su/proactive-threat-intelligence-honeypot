"""Independent release-pointer activation and fallback guard.

This module intentionally uses only the Python standard library.  It is
invoked from the verified recovery release, so it remains independent of the
candidate being activated.  The receipt is an atomic, owner-only state
machine: a delayed recovery endpoint is ``RECOVERY_PENDING`` until the
bounded recovery deadline expires; only then can it become incomplete.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


RECEIPT_SCHEMA = "honeypot_activation_guard_receipt.v3"
SUPPORTED_RECEIPT_SCHEMAS = frozenset(
    {"honeypot_activation_guard_receipt.v2", RECEIPT_SCHEMA}
)
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
DEFAULT_INTEGRITY_DEADLINE_SECONDS = 300
MAX_DEADLINE_SECONDS = 900
STATES = frozenset(
    {
        "GUARD_ARMED",
        "PRE_CUTOVER_DATABASE_VERIFIED",
        "PRE_CUTOVER_DATABASE_FAILED",
        "CANDIDATE_STARTING",
        "CANDIDATE_PENDING",
        "CANDIDATE_SERVICE_READY",
        "CANDIDATE_DATABASE_VERIFIED",
        "CANDIDATE_READY",
        "CANDIDATE_HEALTH_FAILED",
        "CANDIDATE_DATABASE_FAILED",
        "FALLBACK_REQUESTED",
        "RECOVERY_PENDING",
        "FALLBACK_SERVICE_READY",
        "FALLBACK_DATABASE_VERIFIED",
        "FALLBACK_COMPLETED",
        "FALLBACK_INCOMPLETE",
        "ACTIVATION_COMPLETED",
    }
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    data = (json.dumps(dict(payload), sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _run(command: Sequence[str], *, timeout: float = 30.0) -> bool:
    try:
        completed = subprocess.run(
            list(command),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _service_states(services: Sequence[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for service in services:
        try:
            completed = subprocess.run(
                ["systemctl", "is-active", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
                timeout=5,
            )
            state = (completed.stdout or "").strip()
        except (OSError, subprocess.SubprocessError):
            state = "unknown"
        result[service] = state if state in {"active", "inactive", "failed", "activating"} else "unknown"
    return result


def _health(url: str) -> bool:
    try:
        request = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(request, timeout=3) as response:
            if response.status != 200:
                return False
            body = response.read(4096)
        parsed = json.loads(body.decode("utf-8"))
        return isinstance(parsed, dict) and parsed.get("ok") is True
    except (OSError, ValueError, TypeError, urllib.error.URLError, json.JSONDecodeError):
        return False


def _marker(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return ""
    return value if REVISION_RE.fullmatch(value) else ""


def _database_readiness(path: Path) -> Dict[str, bool]:
    if not path.is_file():
        return {"database_verified": False, "queues_verified": False}
    uri = f"file:{path.resolve()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            connection.execute("SELECT 1").fetchone()
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version != 3:
                return {"database_verified": False, "queues_verified": False}
            for table in ("analysis_jobs", "enrichment_jobs", "threat_hunt_jobs", "prediction_outbox"):
                columns = {
                    str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
                }
                if "status" in columns:
                    pending = connection.execute(
                        f"SELECT 1 FROM {table} "
                        "WHERE status IN ('running','pending','queued','retry','in_progress') "
                        "LIMIT 1"
                    ).fetchone()
                    if pending is not None:
                        return {"database_verified": True, "queues_verified": False}
        return {"database_verified": True, "queues_verified": True}
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return {"database_verified": False, "queues_verified": False}


def _database_integrity_ok(path: Path, *, deadline_seconds: int) -> bool:
    """Run the expensive SQLite integrity gate once within a monotonic budget."""

    if not path.is_file():
        return False
    deadline = time.monotonic() + deadline_seconds

    def stop_after_deadline() -> int:
        return 1 if time.monotonic() >= deadline else 0

    uri = f"file:{path.resolve()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            connection.set_progress_handler(stop_after_deadline, 10_000)
            quick = str(connection.execute("PRAGMA quick_check").fetchone()[0]).lower()
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower()
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            connection.set_progress_handler(None, 0)
        return quick == "ok" and integrity == "ok" and version == 3
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return False


def _bounded_deadline(value: int, *, name: str) -> int:
    parsed = int(value)
    if parsed < 1 or parsed > MAX_DEADLINE_SECONDS:
        raise ValueError(f"{name} must be between 1 and {MAX_DEADLINE_SECONDS} seconds")
    return parsed


class ActivationGuard:
    """Perform a bounded candidate activation with independently verified fallback."""

    def __init__(
        self,
        *,
        candidate: str,
        recovery: str,
        active_link: str,
        marker: str,
        services: Sequence[str],
        health: Mapping[str, str],
        database: str,
        receipt: str,
        initial_deadline: int = 210,
        recovery_deadline: int = 180,
        initial_health_deadline: int | None = None,
        recovery_health_deadline: int | None = None,
        integrity_deadline: int = DEFAULT_INTEGRITY_DEADLINE_SECONDS,
        poll_seconds: float = 2.0,
    ) -> None:
        if not REVISION_RE.fullmatch(Path(candidate).name) or not REVISION_RE.fullmatch(Path(recovery).name):
            raise ValueError("release paths must end in full Git revisions")
        if not services or not all(services):
            raise ValueError("service allowlist must not be empty")
        if not health:
            raise ValueError("health endpoints must not be empty")
        self.candidate = str(Path(candidate).resolve())
        self.recovery = str(Path(recovery).resolve())
        # Do not resolve the active symlink or marker at construction time:
        # both must follow the atomic pointer switch during verification.
        self.active_link = Path(os.path.abspath(active_link))
        self.marker = Path(os.path.abspath(marker))
        self.services = tuple(dict.fromkeys(str(item) for item in services))
        self.health = dict(health)
        self.database = Path(database).resolve()
        self.receipt = Path(receipt).resolve()
        self.initial_health_deadline = _bounded_deadline(
            initial_deadline if initial_health_deadline is None else initial_health_deadline,
            name="initial health deadline",
        )
        self.recovery_health_deadline = _bounded_deadline(
            recovery_deadline if recovery_health_deadline is None else recovery_health_deadline,
            name="recovery health deadline",
        )
        self.integrity_deadline = _bounded_deadline(
            integrity_deadline,
            name="integrity deadline",
        )
        # Retain the legacy attributes and receipt fields for callers that inspect them.
        self.initial_deadline = self.initial_health_deadline
        self.recovery_deadline = self.recovery_health_deadline
        self.poll_seconds = max(float(poll_seconds), 0.1)
        self.started_at = _now()
        self.events: List[Dict[str, Any]] = []
        self.state = "GUARD_ARMED"
        self._write_event("GUARD_ARMED")

    @classmethod
    def from_receipt(cls, path: str | Path, *, health: Mapping[str, str]) -> "ActivationGuard":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("schema_version") not in SUPPORTED_RECEIPT_SCHEMAS:
            raise ValueError("unsupported activation receipt schema")
        guard = cls.__new__(cls)
        guard.candidate = str(payload["candidate"])
        guard.recovery = str(payload["recovery"])
        guard.active_link = Path(str(payload["active_link"]))
        guard.marker = Path(str(payload["marker"]))
        guard.services = tuple(str(item) for item in payload["services"])
        guard.health = dict(health)
        guard.database = Path(str(payload["database"]))
        guard.receipt = Path(path).resolve()
        guard.initial_deadline = int(payload.get("initial_deadline_seconds", 210))
        guard.recovery_deadline = int(payload.get("recovery_deadline_seconds", 180))
        guard.initial_health_deadline = _bounded_deadline(
            int(payload.get("initial_health_deadline_seconds", guard.initial_deadline)),
            name="initial health deadline",
        )
        guard.recovery_health_deadline = _bounded_deadline(
            int(payload.get("recovery_health_deadline_seconds", guard.recovery_deadline)),
            name="recovery health deadline",
        )
        guard.integrity_deadline = _bounded_deadline(
            int(payload.get("integrity_deadline_seconds", DEFAULT_INTEGRITY_DEADLINE_SECONDS)),
            name="integrity deadline",
        )
        guard.poll_seconds = 2.0
        guard.started_at = str(payload.get("started_at") or _now())
        guard.events = list(payload.get("events") or [])
        guard.state = str(payload.get("state") or "GUARD_ARMED")
        return guard

    def _write_event(self, state: str, **details: Any) -> None:
        if state not in STATES:
            raise ValueError("unknown guard state")
        self.state = state
        safe_details = {
            key: value
            for key, value in details.items()
            if key in {
                "reason",
                "deadline_seconds",
                "elapsed_seconds",
                "services_active",
                "health_ready",
                "symlink_verified",
                "marker_verified",
                "database_verified",
                "queues_verified",
                "integrity_verified",
            }
            and isinstance(value, (str, int, float, bool, list, dict))
        }
        self.events.append({"at": _now(), "state": state, **safe_details})
        payload = {
            "schema_version": RECEIPT_SCHEMA,
            "candidate": self.candidate,
            "recovery": self.recovery,
            "active_link": str(self.active_link),
            "marker": str(self.marker),
            "services": list(self.services),
            "health_names": sorted(self.health),
            "database": str(self.database),
            "initial_deadline_seconds": self.initial_deadline,
            "recovery_deadline_seconds": self.recovery_deadline,
            "initial_health_deadline_seconds": self.initial_health_deadline,
            "recovery_health_deadline_seconds": self.recovery_health_deadline,
            "integrity_deadline_seconds": self.integrity_deadline,
            "started_at": self.started_at,
            "updated_at": _now(),
            "state": self.state,
            "events": self.events,
        }
        _atomic_json(self.receipt, payload)

    def _switch(self, target: str) -> None:
        temporary = self.active_link.with_name(f".{self.active_link.name}.next.{os.getpid()}")
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        os.symlink(target, temporary)
        os.replace(temporary, self.active_link)

    def _restart(self) -> None:
        _run(["systemctl", "stop", *self.services], timeout=120)
        _run(["systemctl", "start", *self.services], timeout=120)

    def _lightweight_verification(self, expected: str) -> Dict[str, Any]:
        symlink_ok = os.path.realpath(self.active_link) == expected
        marker_ok = _marker(self.marker) == Path(expected).name
        service_states = _service_states(self.services)
        services_ok = all(value == "active" for value in service_states.values())
        health_ok = {name: _health(url) for name, url in self.health.items()}
        health_ready = all(health_ok.values())
        database = _database_readiness(self.database)
        return {
            "symlink_verified": symlink_ok,
            "marker_verified": marker_ok,
            "services_active": services_ok,
            "health_ready": health_ready,
            "database_verified": database["database_verified"],
            "queues_verified": database["queues_verified"],
            "service_states": service_states,
            "health": health_ok,
        }

    def _wait_for_health(self, expected: str, deadline: int, pending_state: str) -> tuple[bool, str]:
        start = time.monotonic()
        while time.monotonic() - start < deadline:
            facts = self._lightweight_verification(expected)
            if all(
                facts[key]
                for key in (
                    "symlink_verified",
                    "marker_verified",
                    "services_active",
                    "health_ready",
                    "database_verified",
                    "queues_verified",
                )
            ):
                self._write_event(
                    pending_state,
                    elapsed_seconds=round(time.monotonic() - start, 3),
                    **{key: facts[key] for key in ("services_active", "health_ready", "symlink_verified", "marker_verified", "database_verified", "queues_verified")},
                )
                return True, "ready"
            self._write_event(
                pending_state,
                elapsed_seconds=round(time.monotonic() - start, 3),
                services_active=facts["services_active"],
                health_ready=facts["health_ready"],
                symlink_verified=facts["symlink_verified"],
                marker_verified=facts["marker_verified"],
                database_verified=facts["database_verified"],
                queues_verified=facts["queues_verified"],
            )
            if "failed" in facts["service_states"].values():
                return False, "service_failed"
            time.sleep(self.poll_seconds)
        return False, "health_deadline_expired"

    def _integrity_gate(self) -> bool:
        return _database_integrity_ok(
            self.database,
            deadline_seconds=self.integrity_deadline,
        )

    @staticmethod
    def _facts_ready(facts: Mapping[str, Any]) -> bool:
        return all(
            bool(facts[key])
            for key in (
                "symlink_verified",
                "marker_verified",
                "services_active",
                "health_ready",
                "database_verified",
                "queues_verified",
            )
        )

    def activate(self) -> bool:
        preflight = self._lightweight_verification(self.recovery)
        if not self._facts_ready(preflight):
            self._write_event(
                "PRE_CUTOVER_DATABASE_FAILED",
                reason="pre_cutover_recovery_not_ready",
                database_verified=preflight["database_verified"],
                queues_verified=preflight["queues_verified"],
                integrity_verified=False,
            )
            return False
        if not self._integrity_gate():
            self._write_event(
                "PRE_CUTOVER_DATABASE_FAILED",
                reason="pre_cutover_integrity_verification_failed",
                database_verified=True,
                queues_verified=True,
                integrity_verified=False,
            )
            return False
        post_integrity_preflight = self._lightweight_verification(self.recovery)
        if not self._facts_ready(post_integrity_preflight):
            self._write_event(
                "PRE_CUTOVER_DATABASE_FAILED",
                reason="pre_cutover_post_integrity_readiness_failed",
                database_verified=post_integrity_preflight["database_verified"],
                queues_verified=post_integrity_preflight["queues_verified"],
                integrity_verified=True,
            )
            return False
        self._write_event(
            "PRE_CUTOVER_DATABASE_VERIFIED",
            database_verified=True,
            queues_verified=True,
            integrity_verified=True,
        )
        self._switch(self.candidate)
        self._restart()
        self._write_event("CANDIDATE_STARTING")
        ready, reason = self._wait_for_health(
            self.candidate,
            self.initial_health_deadline,
            "CANDIDATE_PENDING",
        )
        if not ready:
            self._write_event("CANDIDATE_HEALTH_FAILED", reason=reason)
            self.fallback()
            return False
        self._write_event("CANDIDATE_SERVICE_READY")
        if not self._integrity_gate():
            self._write_event(
                "CANDIDATE_DATABASE_FAILED",
                reason="candidate_integrity_verification_failed",
                integrity_verified=False,
            )
            self.fallback()
            return False
        final_facts = self._lightweight_verification(self.candidate)
        if not self._facts_ready(final_facts):
            self._write_event(
                "CANDIDATE_DATABASE_FAILED",
                reason="candidate_post_integrity_readiness_failed",
                integrity_verified=True,
            )
            self.fallback()
            return False
        self._write_event(
            "CANDIDATE_DATABASE_VERIFIED",
            database_verified=True,
            queues_verified=True,
            integrity_verified=True,
        )
        self._write_event("CANDIDATE_READY")
        return True

    def fallback(self) -> bool:
        self._write_event("FALLBACK_REQUESTED", reason="candidate_not_accepted")
        self._switch(self.recovery)
        self._restart()
        ready, reason = self._wait_for_health(
            self.recovery,
            self.recovery_health_deadline,
            "RECOVERY_PENDING",
        )
        if not ready:
            self._write_event("FALLBACK_INCOMPLETE", reason=f"recovery_{reason}")
            return False
        self._write_event("FALLBACK_SERVICE_READY")
        if not self._integrity_gate():
            self._write_event("FALLBACK_INCOMPLETE", reason="recovery_integrity_verification_failed")
            return False
        final_facts = self._lightweight_verification(self.recovery)
        if not self._facts_ready(final_facts):
            self._write_event("FALLBACK_INCOMPLETE", reason="recovery_post_integrity_readiness_failed")
            return False
        self._write_event(
            "FALLBACK_DATABASE_VERIFIED",
            database_verified=True,
            queues_verified=True,
            integrity_verified=True,
        )
        self._write_event("FALLBACK_COMPLETED")
        return True

    def finalize(self) -> bool:
        facts = self._lightweight_verification(self.candidate)
        integrity_recorded = any(
            event.get("state") == "CANDIDATE_DATABASE_VERIFIED"
            and event.get("integrity_verified") is True
            for event in self.events
        )
        if self.state == "CANDIDATE_READY" and integrity_recorded and self._facts_ready(facts):
            self._write_event("ACTIVATION_COMPLETED", **{key: facts[key] for key in ("services_active", "health_ready", "symlink_verified", "marker_verified", "database_verified", "queues_verified")})
            return True
        self._write_event("CANDIDATE_HEALTH_FAILED", reason="candidate_final_verification_failed")
        self.fallback()
        return False


def _parse_health(values: Iterable[str]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for value in values:
        name, separator, url = value.partition("=")
        if not separator or not name or not url or name in parsed:
            raise ValueError("health endpoints must use unique name=url entries")
        parsed[name] = url
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the independent activation guard")
    parser.add_argument("command", choices=("activate", "rollback", "finalize"))
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--recovery", required=True)
    parser.add_argument("--active-link", default="/opt/honeypot")
    parser.add_argument("--marker", default="/opt/honeypot/DEPLOYED_COMMIT")
    parser.add_argument("--services", required=True, help="comma-separated allowlist")
    parser.add_argument("--health", action="append", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--initial-deadline", type=int, default=210)
    parser.add_argument("--recovery-deadline", type=int, default=180)
    parser.add_argument("--initial-health-deadline", type=int)
    parser.add_argument("--recovery-health-deadline", type=int)
    parser.add_argument(
        "--integrity-deadline",
        type=int,
        default=DEFAULT_INTEGRITY_DEADLINE_SECONDS,
    )
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    health = _parse_health(args.health)
    receipt_path = Path(args.receipt)
    if args.command in {"rollback", "finalize"} and receipt_path.exists():
        guard = ActivationGuard.from_receipt(receipt_path, health=health)
    else:
        guard = ActivationGuard(
            candidate=args.candidate,
            recovery=args.recovery,
            active_link=args.active_link,
            marker=args.marker,
            services=tuple(item for item in args.services.split(",") if item),
            health=health,
            database=args.database,
            receipt=args.receipt,
            initial_deadline=args.initial_deadline,
            recovery_deadline=args.recovery_deadline,
            initial_health_deadline=args.initial_health_deadline,
            recovery_health_deadline=args.recovery_health_deadline,
            integrity_deadline=args.integrity_deadline,
            poll_seconds=args.poll_seconds,
        )
    if args.command == "activate":
        return 0 if guard.activate() else 2
    if args.command == "rollback":
        return 0 if guard.fallback() else 2
    return 0 if guard.finalize() else 2


if __name__ == "__main__":
    raise SystemExit(main())
