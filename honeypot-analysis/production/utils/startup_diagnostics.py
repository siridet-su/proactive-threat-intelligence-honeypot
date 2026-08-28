"""Privacy-safe, bounded startup-stage diagnostics for long-lived services.

The diagnostic record is deliberately small and owner-only.  It contains
stage names, timings, release identity, and closed error categories only; it
never serializes environment values, exception text, database rows, or event
payloads.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional


STARTUP_DIAGNOSTICS_SCHEMA = "service_startup_diagnostics.v1"
STARTUP_STAGES = (
    "PROCESS_STARTED",
    "RELEASE_IDENTITY_VERIFIED",
    "CONFIG_LOADED",
    "CREDENTIALS_RESOLVED",
    "DATABASE_OPEN_STARTED",
    "DATABASE_OPEN_COMPLETED",
    "SCHEMA_VERIFIED",
    "POLICIES_VERIFIED",
    "DEPENDENCIES_READY",
    "APPLICATION_CREATED",
    "SOCKET_BIND_STARTED",
    "SOCKET_BOUND",
    "HEALTH_ROUTE_READY",
    "SERVICE_READY",
    "STARTUP_FAILED",
)
STARTUP_STATUSES = frozenset({"running", "ready", "failed"})
STAGE_STATUSES = frozenset({"entered", "completed", "failed"})
ERROR_CATEGORIES = frozenset(
    {
        "CONFIGURATION_INVALID",
        "CREDENTIALS_UNAVAILABLE",
        "DATABASE_UNAVAILABLE",
        "DATABASE_LOCKED",
        "DATABASE_SCHEMA_INVALID",
        "DEPENDENCY_IMPORT_FAILED",
        "MANIFEST_INVALID",
        "POLICY_INVALID",
        "PERMISSION_DENIED",
        "SOCKET_BIND_FAILED",
        "HEALTH_ROUTE_UNAVAILABLE",
        "OS_ERROR",
        "STARTUP_ERROR",
    }
)
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_SAFE_SERVICE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_service_name(value: str) -> str:
    text = _SAFE_SERVICE_RE.sub("_", str(value or "service")).strip("._")
    return text[:80] or "service"


def _release_revision(release_root: Optional[Path] = None) -> str:
    """Read only the exact deployment marker, never arbitrary file content."""

    candidates = []
    if release_root is not None:
        candidates.append(Path(release_root))
    candidates.append(Path.cwd())
    for root in candidates:
        try:
            marker = root / "DEPLOYED_COMMIT"
            value = marker.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            continue
        if _REVISION_RE.fullmatch(value):
            return value
    return ""


def closed_error_category(exc: BaseException) -> str:
    """Map failures to a fixed category without retaining exception text."""

    if isinstance(exc, FileNotFoundError):
        return "CREDENTIALS_UNAVAILABLE"
    if isinstance(exc, PermissionError):
        return "PERMISSION_DENIED"
    if isinstance(exc, sqlite3.OperationalError):
        lowered = str(exc).lower()
        if "locked" in lowered or "busy" in lowered:
            return "DATABASE_LOCKED"
        return "DATABASE_UNAVAILABLE"
    if isinstance(exc, (ImportError, ModuleNotFoundError)):
        return "DEPENDENCY_IMPORT_FAILED"
    if isinstance(exc, (json.JSONDecodeError, ValueError, TypeError)):
        return "CONFIGURATION_INVALID"
    if isinstance(exc, OSError):
        return "OS_ERROR"
    return "STARTUP_ERROR"


class StartupDiagnostics:
    """Persist a bounded atomic startup receipt."""

    def __init__(
        self,
        service: str,
        *,
        path: Optional[str | Path] = None,
        release_root: Optional[str | Path] = None,
        clock: Callable[[], str] = utc_timestamp,
    ) -> None:
        self.service = _safe_service_name(service)
        default = Path("/var/lib/honeypot/startup") / f"{self.service}.json"
        self.path = Path(path or os.getenv("STARTUP_DIAGNOSTICS_PATH", default))
        self.release_root = Path(release_root) if release_root else None
        self.clock = clock
        self.started_at = self.clock()
        self._stages: list[Dict[str, Any]] = []
        self._status = "running"
        self._last_stage = ""
        self._write()

    @property
    def status(self) -> str:
        return self._status

    @property
    def stages(self) -> tuple[Dict[str, Any], ...]:
        return tuple(dict(stage) for stage in self._stages)

    def enter(self, stage: str) -> None:
        self._validate_stage(stage)
        if stage == "STARTUP_FAILED":
            raise ValueError("STARTUP_FAILED is recorded by fail()")
        if self._stages and self._stages[-1]["status"] == "entered":
            raise ValueError("previous startup stage is not completed")
        if any(item["stage"] == stage for item in self._stages):
            raise ValueError("startup stage cannot be entered twice")
        record = {"stage": stage, "status": "entered", "entered_at": self.clock()}
        self._stages.append(record)
        self._last_stage = stage
        self._write()

    def complete(self, stage: str) -> None:
        self._validate_stage(stage)
        if not self._stages or self._stages[-1]["stage"] != stage:
            raise ValueError("startup stages must complete in order")
        record = self._stages[-1]
        if record["status"] != "entered":
            raise ValueError("startup stage is not active")
        record["status"] = "completed"
        record["completed_at"] = self.clock()
        self._write()

    def ready(self) -> None:
        if not self._stages or self._stages[-1]["stage"] != "SERVICE_READY":
            raise ValueError("SERVICE_READY must be completed before ready()")
        if self._stages[-1]["status"] != "completed":
            raise ValueError("SERVICE_READY is incomplete")
        self._status = "ready"
        self._write()

    def fail(self, exc: BaseException | None = None, *, category: str = "") -> None:
        selected = category or (closed_error_category(exc) if exc else "STARTUP_ERROR")
        if selected not in ERROR_CATEGORIES:
            selected = "STARTUP_ERROR"
        if self._stages and self._stages[-1]["status"] == "entered":
            self._stages[-1]["status"] = "failed"
            self._stages[-1]["completed_at"] = self.clock()
        self._stages.append(
            {
                "stage": "STARTUP_FAILED",
                "status": "failed",
                "entered_at": self.clock(),
                "completed_at": self.clock(),
                "error_category": selected,
            }
        )
        self._status = "failed"
        self._write()

    def _validate_stage(self, stage: str) -> None:
        if stage not in STARTUP_STAGES or stage == "STARTUP_FAILED":
            raise ValueError("unknown startup stage")

    def _payload(self) -> Dict[str, Any]:
        return {
            "schema_version": STARTUP_DIAGNOSTICS_SCHEMA,
            "service": self.service,
            "pid": os.getpid(),
            "release_revision": _release_revision(self.release_root),
            "started_at": self.started_at,
            "updated_at": self.clock(),
            "status": self._status,
            "stages": [dict(stage) for stage in self._stages],
        }

    def _write(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # The service normally creates its private startup directory, but a
        # deployment may pre-create it as root-owned beneath the shared
        # runtime state directory.  The diagnostic record itself is always
        # owner-only; inability to tighten an already-existing parent must
        # not turn a bounded observability aid into a service startup gate.
        try:
            os.chmod(parent, 0o700)
        except PermissionError:
            pass
        payload = json.dumps(
            self._payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        fd, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=parent
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.write(b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
            try:
                directory_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


__all__ = [
    "ERROR_CATEGORIES",
    "STARTUP_DIAGNOSTICS_SCHEMA",
    "STARTUP_STAGES",
    "StartupDiagnostics",
    "closed_error_category",
]
