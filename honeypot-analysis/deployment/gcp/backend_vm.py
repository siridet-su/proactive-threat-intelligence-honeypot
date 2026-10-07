#!/usr/bin/env python3
"""Build, verify and stage an owner-only backend migration package (stdlib)."""
from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import io
import json
import os
import platform
import pwd
import re
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

SCHEMA = "pti_backend_vm_bundle.v1"
PLAN_SCHEMA = "pti_backend_vm_runtime_plan.v1"
COMPONENTS = frozenset({"configuration", "credentials", "model1", "model2",
    "next_distinct", "python_runtime", "systemd", "feeds", "rollback_backup", "host_helpers"})
CORE_UNITS = (
    "honeypot-ingest-api.service", "honeypot-session-worker.service",
    "honeypot-analysis-worker.service", "honeypot-enrichment-worker.service",
    "honeypot-dashboard-api.service", "honeypot-monitor-web.service",
    "honeypot-threat-hunt-worker.service", "honeypot-webhook-dispatcher.service",
    "honeypot-ai-advisory-worker.service", "honeypot-next-distinct-shadow.service",
    "honeypot-next-distinct-shadow-feeder.service", "model2-v7-receiver.service",
    "model2-v7-ensemble-bridge.service", "honeypot-feed-refresh.timer",
    "honeypot-session-count-monitor.timer", "honeypot-service-watchdog.timer",
)
DEPLOYED_COMPAT_UNITS = (
    "model2-v7-capture-backend.service", "model2-v7-capture-sensor.service",
    "model2-v7-capture.service", "model2-v7-sensor.service",
)
SKIP_DIRS = {"__pycache__", ".git", ".pytest_cache", "logs"}
SHA = re.compile(r"^[0-9a-f]{64}$")
UNIT = re.compile(r"^(?:honeypot-|model2-v7-)[\w.@-]+\.(?:service|timer)$")
BACKUP_ROOTS = ("/var/backups/honeypot/", "/var/backups/honeypot-external/")
EMPTY_CAPTURE_DIRECTORY = "/var/lib/model2-v7/pcap"


class ArchivePayload:
    """A verified bundle member copied without materializing it in memory."""

    def __init__(self, archive: tarfile.TarFile, name: str, size: int, sha256: str):
        self.archive = archive
        self.name = name
        self.size = size
        self.sha256 = sha256

    def open(self):
        stream = self.archive.extractfile(self.name)
        if stream is None:
            raise ValueError("source kit member is missing")
        return stream


class NoHealthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def command(args: list[str], timeout: int = 30) -> str:
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if result.returncode:
        # Never echo argv, stderr or config contents: they may contain credentials.
        raise ValueError(f"{Path(args[0]).name} failed with exit {result.returncode}")
    return result.stdout.decode().strip()


def safe_name(name: str) -> str:
    p = PurePosixPath(name)
    if not name or p.is_absolute() or ".." in p.parts or str(p) != name or "\\" in name:
        raise ValueError("unsafe archive member")
    return name


def outside_checkout(path: Path, repo: Path | None = None) -> None:
    resolved = path.resolve()
    if repo and resolved.is_relative_to(repo.resolve()):
        raise ValueError("packages and private inventories must be outside the checkout")
    for ancestor in (resolved.parent, *resolved.parents):
        metadata = ancestor / ".git"
        if metadata.is_file() or (metadata / "HEAD").is_file():
            raise ValueError("packages and private inventories must be outside the checkout")


def exclusive_json(path: Path, value: object) -> None:
    outside_checkout(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(encoded(value))


def target_path(value: str, *, allow_directory: bool = False) -> str:
    p = PurePosixPath(value)
    if not p.is_absolute() or ".." in p.parts or str(p) != value:
        raise ValueError("invalid runtime destination")
    if live_capture_path(value) and not (allow_directory and value == EMPTY_CAPTURE_DIRECTORY):
        raise ValueError("live pcap/spool paths are not runtime inputs")
    roots = ("/etc/honeypot/", "/etc/model2-v7/", "/opt/model2-v7/",
             "/opt/honeypot-model-bundles/", "/opt/honeypot-shadow/",
             "/opt/honeypot-python-runtimes/", "/var/lib/honeypot/feeds/",
             "/var/lib/honeypot/reports/", "/var/lib/honeypot-shadow/",
             "/var/lib/model2-v7/",
             "/var/backups/honeypot/", "/var/backups/honeypot-external/")
    if any(value == root.rstrip("/") or value.startswith(root) for root in roots):
        return value
    if allow_directory and value in {"/var/lib/honeypot", "/var/lib/honeypot-service-watchdog"}:
        return value
    if re.fullmatch(r"/opt/honeypot-releases/[0-9a-f]{40}(?:/[\w./-]+)?", value):
        return value
    if value == "/etc/haproxy/haproxy.cfg":
        return value
    if value.startswith("/etc/systemd/system/"):
        name = value[len("/etc/systemd/system/"):].split("/")[0].removesuffix(".d")
        if UNIT.fullmatch(name):
            return value
    if re.fullmatch(r"/usr/local/(?:libexec|sbin)/(?:honeypot-|model2-v7-)[\w.-]+", value):
        return value
    if re.fullmatch(r"/etc/credstore/(?:mongodb-uri|honeypot-[\w.-]+)", value):
        return value
    if re.fullmatch(r"/var/lib/honeypot/[\w.-]+\.(?:db|sqlite|sqlite3)", value):
        return value
    raise ValueError("runtime destination outside the backend layout")


def live_capture_path(value: str) -> bool:
    path = PurePosixPath(value)
    forbidden_dirs = {"pcap", "pcaps", "spool", "spools"}
    return (any(part.lower() in forbidden_dirs for part in path.parts)
            or path.suffix.lower() in {".pcap", ".pcapng", ".cap"})


def os_identity() -> dict[str, str]:
    result = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and key in {"ID", "VERSION_ID"}:
            result[key.lower()] = value.strip('"')
    result["architecture"] = platform.machine()
    return result


def health(units: list[str], probes: list[dict] | None = None,
           unit_metadata: dict[str, dict] | None = None) -> dict:
    checks = []
    for name in units:
        if not UNIT.fullmatch(name):
            raise ValueError("invalid backend unit name")
        metadata = (unit_metadata or {}).get(name, {})
        unit_type, state = metadata.get("type", ""), metadata.get("active_state", "")
        result = metadata.get("result", "")
        if not unit_type or not state or (unit_type == "oneshot" and not result):
            try:
                raw = command(["systemctl", "show", name, "--no-pager",
                               "--property=Type,ActiveState,Result"], timeout=5)
                fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
                unit_type = unit_type or fields.get("Type", "")
                state = state or fields.get("ActiveState", "")
                result = result or fields.get("Result", "")
            except (ValueError, OSError, subprocess.TimeoutExpired):
                state = "inactive_or_unavailable"
        passed = (state == "active" and (unit_type != "oneshot" or result == "success")
                  or unit_type == "oneshot" and state == "inactive" and result == "success")
        checks.append({"unit": name, "state": state or "inactive_or_unavailable",
                       "result": result,
                       "passed": passed})
    probes = probes if probes is not None else [
        {"url": f"http://127.0.0.1:{port}/health", "expected_status": 200}
        for port in (8080, 8081, 8090)]
    endpoints = []
    for probe in probes:
        # Health probes cannot carry secrets or send requests to arbitrary hosts.
        url = probe["url"]
        if not re.fullmatch(r"http://127\.0\.0\.1:\d+/(?:health(?:/(?:live|ready))?)", url):
            raise ValueError("health probe must use a local health endpoint")
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoHealthRedirect())
            with opener.open(url, timeout=3) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except (OSError, urllib.error.URLError):
            status = 0
        endpoints.append({"url": url, "status": status,
                          "passed": status == probe["expected_status"]})
    return {"passed": all(v["passed"] for v in checks + endpoints),
            "units": checks, "endpoints": endpoints}


def snapshot(output: Path) -> dict:
    health_units = set(CORE_UNITS)
    metadata_units = set(CORE_UNITS) | set(DEPLOYED_COMPAT_UNITS)
    for unit in CORE_UNITS:
        if unit.endswith(".timer"):
            metadata_units.add(unit[:-len(".timer")] + ".service")
    try:
        listing = command(["systemctl", "list-unit-files", "--no-legend", "--plain"])
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) < 2 or not UNIT.fullmatch(fields[0]) or "dashboard-v2" in fields[0]:
                continue
            if fields[1] in {"enabled", "enabled-runtime"}:
                health_units.add(fields[0])
                metadata_units.add(fields[0])
            if fields[0].endswith(".timer"):
                metadata_units.add(fields[0])
                companion = fields[0][:-len(".timer")] + ".service"
                if UNIT.fullmatch(companion):
                    metadata_units.add(companion)
    except (OSError, ValueError):
        pass
    details, accounts, unit_metadata = [], {}, {}
    for unit in sorted(metadata_units):
        record = {"name": unit, "paths": []}
        try:
            raw = command(["systemctl", "show", unit, "--no-pager",
                           "--property=User,Group,Type,ActiveState,Result,FragmentPath,DropInPaths,WorkingDirectory,EnvironmentFiles,ExecStart,LoadCredential,LoadCredentialEncrypted"])
            fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
            # ExecStart and environment values stay in RAM; export only file paths.
            candidates = re.findall(r"/(?:etc|opt|usr/local)/[^\s;{}()\"']+", raw)
            for name in shlex_credential_names(fields.get("LoadCredential", "")):
                implicit = Path("/etc/credstore") / name
                if implicit.is_file():
                    candidates.append(str(implicit))
            for value in sorted(set(candidates)):
                p = Path(value)
                entry = {"path": value, "exists": p.exists()}
                if p.is_file():
                    try:
                        entry.update(sha256=file_digest(p), bytes=p.stat().st_size)
                    except OSError:
                        entry["readable"] = False
                if p.is_symlink():
                    entry["resolved_path"] = str(p.resolve())
                record["paths"].append(entry)
            record["user"] = fields.get("User", "")
            record["group"] = fields.get("Group", "")
            record["type"] = fields.get("Type", "")
            record["active_state"] = fields.get("ActiveState", "")
            record["result"] = fields.get("Result", "")
            unit_metadata[unit] = {"type": record["type"],
                                   "active_state": record["active_state"],
                                   "result": record["result"]}
            if record["user"]:
                try:
                    account = pwd.getpwnam(record["user"])
                    accounts[record["user"]] = {"uid": account.pw_uid, "gid": account.pw_gid}
                except KeyError:
                    pass
        except (ValueError, OSError, subprocess.TimeoutExpired):
            record["unavailable"] = True
        details.append(record)
    active = Path("/opt/honeypot")
    revision = "unavailable"
    try:
        candidate = (active / "DEPLOYED_COMMIT").read_text().strip()
        if re.fullmatch(r"[0-9a-f]{40}", candidate):
            revision = candidate
    except OSError:
        pass
    receipt = {"schema_version": "pti_backend_vm_inventory.v1",
               "captured_at": datetime.now(timezone.utc).isoformat(),
               "os": os_identity(), "collector_python": platform.python_version(),
               "active_revision": revision, "active_root": str(active.resolve()),
               "units": details, "health": health(sorted(health_units),
                   unit_metadata=unit_metadata),
               "accounts": accounts,
               "required_components": sorted(COMPONENTS),
               "private_file_contents_collected": False}
    exclusive_json(output, receipt)
    return receipt


def shlex_credential_names(value: str) -> list[str]:
    # Only aliases are returned; credential values and encrypted blobs are never
    # exported. Explicit sources already appear in the path inventory above.
    return [part for part in value.split() if re.fullmatch(r"mongodb-uri|honeypot-[\w.-]+", part)]


def git_archive(repo: Path, revision: str) -> tuple[str, bytes]:
    rev = command(["git", "-C", str(repo), "rev-parse", "--verify", revision + "^{commit}"])
    if not re.fullmatch(r"[0-9a-f]{40}", rev):
        raise ValueError("invalid source revision")
    result = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar.gz",
                             rev + ":honeypot-analysis"], capture_output=True, check=False)
    if result.returncode:
        raise ValueError("backend source archive failed")
    validate_source(result.stdout)
    return rev, result.stdout


def validate_source(data: bytes) -> list[tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        entries = archive.getmembers()
        seen = set()
        for entry in entries:
            name = entry.name.rstrip("/")
            safe_name(name)
            if name in seen or not (entry.isfile() or entry.isdir()):
                raise ValueError("source archive has duplicate, link or special member")
            seen.add(name)
            if entry.isfile() and (Path(name).name == ".env" or
                    Path(name).suffix in {".db", ".sqlite", ".sqlite3", ".pem", ".key"}):
                raise ValueError("source archive contains a private/runtime file")
        return entries


def rule_inventory(source: bytes) -> dict:
    """Static identifiers only: presence is not evidence that a rule executes."""
    def identifiers(value: object, key: str) -> set[str]:
        found = set()
        if isinstance(value, dict):
            if isinstance(value.get(key), str):
                found.add(value[key])
            for child in value.values():
                found.update(identifiers(child, key))
        elif isinstance(value, list):
            for child in value:
                found.update(identifiers(child, key))
        return found

    with tarfile.open(fileobj=io.BytesIO(source), mode="r:gz") as archive:
        def read(name: str) -> bytes:
            stream = archive.extractfile(name)
            if stream is None:
                raise ValueError("rule-coverage source is incomplete")
            return stream.read()

        behavior = json.loads(read("configs/threat_hypothesis_behavior.trusted.json"))
        guidance = json.loads(read("configs/response_guidance_policy.v3.json"))
        tree = ast.parse(read("production/reporting/session_assessment_v4.py"))
    scopes = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
              and isinstance(node.value, str) and node.value.startswith("bounded_cowrie_")}
    return {"behavior_rule_ids": sorted(identifiers(behavior, "rule_id")),
            "guidance_rule_ids": sorted(identifiers(guidance, "rule_id")),
            "guidance_action_ids": sorted(identifiers(guidance, "action_id")),
            "declared_bounded_scopes": sorted(scopes)}


def coverage_gate(source: bytes, baseline: bytes, baseline_revision: str) -> dict:
    before, after = rule_inventory(baseline), rule_inventory(source)
    removed = {key: sorted(set(before[key]) - set(after[key])) for key in before}
    if any(removed.values()):
        missing = "; ".join(f"{key}: {', '.join(values)}"
                            for key, values in removed.items() if values)
        raise ValueError("rule coverage regressed against baseline: " + missing)
    return {"schema_version": "pti_backend_rule_coverage.v1",
            "baseline_revision": baseline_revision, "baseline": before,
            "candidate": after, "removed": removed,
            "added": {key: sorted(set(after[key]) - set(before[key])) for key in before},
            "static_presence_only": True, "runtime_semantics_qualified": False,
            "passed": True}


def asset_entries(plan: dict, source_root: Path, revision: str) -> tuple[dict, list, list]:
    if not isinstance(plan, dict) or plan.get("schema_version") != PLAN_SCHEMA:
        raise ValueError("invalid runtime plan schema")
    if not isinstance(plan.get("assets", []), list) or not isinstance(plan.get("links", []), list):
        raise ValueError("runtime plan assets and links must be lists")
    payloads, entries, directories = {}, [], {}
    covered = set()
    for asset in plan.get("assets", []):
        component = asset["component"]
        if component not in COMPONENTS:
            raise ValueError("unknown runtime component")
        source = target_path(asset["source"].replace("{revision}", revision))
        target = target_path(asset.get("target", source).replace("{revision}", revision))
        source_is_backup = any(source == root.rstrip("/") or source.startswith(root)
                               for root in BACKUP_ROOTS)
        if source_is_backup != (component == "rollback_backup"):
            raise ValueError("backup inputs must be rollback_backup assets under an approved backup root")
        p = source_root / source.lstrip("/")
        no_symlink_parents(p, source_root)
        if not p.exists() or p.is_symlink():
            raise ValueError("runtime input is missing or a symlink root")
        if p.is_dir():
            children = []
            for directory, names, files in os.walk(p, followlinks=False):
                directory_path = Path(directory)
                if live_capture_path(str(directory_path)) or any(
                        live_capture_path(str(directory_path / name)) for name in names + files):
                    raise ValueError("live pcap/spool paths are not runtime inputs")
                names[:] = sorted(name for name in names if name not in SKIP_DIRS)
                suffix = str(directory_path.relative_to(p))
                dest = target if suffix == "." else target + "/" + suffix
                st = directory_path.stat()
                directories[dest] = {"target": target_path(dest, allow_directory=True), "uid": st.st_uid,
                                     "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode) & 0o777}
                children.extend(Path(directory) / name for name in files)
                children.extend(Path(directory) / name for name in names
                                if (Path(directory) / name).is_symlink())
            children.sort()
        else:
            children = [p]
        # Preserve traversal permissions for scoped runtime ancestors too.
        if source == target:
            for ancestor in p.parents:
                logical = "/" + str(ancestor.relative_to(source_root)) if ancestor != source_root else "/"
                try:
                    dest = target_path(logical)
                except ValueError:
                    break
                st = ancestor.stat()
                directories[dest] = {"target": target_path(dest, allow_directory=True), "uid": st.st_uid,
                                     "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode) & 0o777}
        has_file_payload = False
        for child in children:
            suffix = str(child.relative_to(p)) if p.is_dir() else ""
            dest = target_path(target + ("/" + suffix if suffix else ""))
            st = child.lstat()
            common = {"target": dest, "component": component,
                      "uid": st.st_uid, "gid": st.st_gid,
                      "mode": stat.S_IMODE(st.st_mode) & 0o777}
            if child.is_symlink():
                link = os.readlink(child)
                if not Path(link).is_absolute():
                    link = os.path.normpath(str(Path(dest).parent / link))
                entries.append(dict(common, link_target=link))
            elif child.is_file():
                if child.name.endswith(("-wal", "-shm", ".pyc", ".pyo")):
                    raise ValueError("live WAL/SHM or bytecode cannot be a runtime input")
                if child.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
                    if component != "rollback_backup" or not source_is_backup:
                        raise ValueError("database input must be an explicit verified backup")
                    with sqlite3.connect(child.as_uri() + "?mode=ro&immutable=1", uri=True) as db:
                        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                            raise ValueError("SQLite backup integrity failed")
                name = "runtime/" + dest.lstrip("/")
                if name in payloads:
                    raise ValueError("duplicate runtime destination")
                payloads[name] = child
                entries.append(dict(common, archive_path=name))
                has_file_payload = True
            else:
                raise ValueError("runtime input contains a socket/device/special file")
        if has_file_payload:
            covered.add(component)
    for link in plan.get("links", []):
        component = link["component"]
        if component not in COMPONENTS:
            raise ValueError("unknown runtime link component")
        entries.append({"target": target_path(link["path"].replace("{revision}", revision)),
                        "component": component, "uid": 0, "gid": 0, "mode": 0o777,
                        "link_target": link["target"].replace("{revision}", revision)})
    targets = [entry["target"] for entry in entries]
    if len(targets) != len(set(targets)):
        raise ValueError("duplicate runtime destination")
    explicit_directories = plan.get("directories", [])
    if not isinstance(explicit_directories, list):
        raise ValueError("runtime plan directories must be a list")
    seen_directories = set()
    for directory in explicit_directories:
        if not isinstance(directory, dict) or set(directory) != {"target", "uid", "gid", "mode"}:
            raise ValueError("runtime directories require target, uid, gid and mode")
        target = target_path(directory["target"].replace("{revision}", revision),
                             allow_directory=True)
        if target in seen_directories:
            raise ValueError("duplicate runtime directory")
        seen_directories.add(target)
        if any(not isinstance(directory[key], int) or isinstance(directory[key], bool)
               or directory[key] < 0 for key in ("uid", "gid", "mode")) or directory["mode"] > 0o777:
            raise ValueError("invalid runtime directory ownership or mode")
        directories[target] = {"target": target, "uid": directory["uid"],
                               "gid": directory["gid"], "mode": directory["mode"]}
    if set(targets) & set(directories):
        raise ValueError("runtime file/link conflicts with a directory")
    external = plan.get("external_paths", [])
    for value in external:
        if not re.fullmatch(r"/usr/(?:bin|lib|lib64)/[\w./+-]+", value) or ".." in Path(value).parts:
            raise ValueError("external paths must be explicit OS dependencies")
    for entry in entries:
        if "link_target" in entry and entry["link_target"] not in targets + external:
            # Directory links are allowed only when they lead to bundled children.
            prefix = entry["link_target"].rstrip("/") + "/"
            if not any(path.startswith(prefix) for path in targets):
                raise ValueError("runtime symlink points outside declared inputs")
    missing = sorted(COMPONENTS - covered)
    unit_targets = {Path(v).name for v in targets if v.startswith("/etc/systemd/system/")}
    required_units = plan.get("required_units", list(CORE_UNITS))
    if (not isinstance(required_units, list) or not required_units
            or any(not isinstance(v, str) or not UNIT.fullmatch(v) for v in required_units)
            or len(required_units) != len(set(required_units))):
        raise ValueError("invalid required units")
    if not set(required_units).issubset(unit_targets) and "systemd" not in missing:
        missing.append("systemd")
        missing.sort()
    return payloads, entries + [{"missing_components": missing}], sorted(directories.values(), key=lambda v: v["target"])


def payload_size(value: bytes | Path | ArchivePayload) -> int:
    if isinstance(value, Path):
        return value.stat().st_size
    if isinstance(value, ArchivePayload):
        return value.size
    return len(value)


def payload_digest(value: bytes | Path | ArchivePayload) -> str:
    if isinstance(value, Path):
        return file_digest(value)
    if isinstance(value, ArchivePayload):
        return value.sha256
    return digest(value)


def payload_stream(value: bytes | Path | ArchivePayload):
    if isinstance(value, Path):
        return value.open("rb")
    if isinstance(value, ArchivePayload):
        return value.open()
    return io.BytesIO(value)


def write_bundle(output: Path, payloads: dict[str, bytes | Path | ArchivePayload],
                 manifest: dict) -> None:
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to overwrite package")
    fd, temp_name = tempfile.mkstemp(prefix=".backend-bundle-", dir=output.parent)
    os.fchmod(fd, 0o600)
    tmp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream, gzip.GzipFile(
                filename="", fileobj=stream, mode="wb", compresslevel=1, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|") as archive:
                values = {**payloads, "BUNDLE_MANIFEST.json": encoded(manifest)}
                for name, value in sorted(values.items()):
                    safe_name(name)
                    info = tarfile.TarInfo(name)
                    info.mode = 0o600
                    info.size = payload_size(value)
                    with payload_stream(value) as source_stream:
                        archive.addfile(info, source_stream)
        verify(tmp)
        os.link(tmp, output)  # exclusive publication, even with competing builders
    finally:
        tmp.unlink(missing_ok=True)


def build(repo: Path, revision: str, output: Path, references: list[str],
          plan_path: Path | None = None, runtime_root: Path = Path("/"),
          inventory_path: Path | None = None, coverage_baseline: str | None = None) -> dict:
    repo = repo.resolve()
    outside_checkout(output, repo)
    primary, source = git_archive(repo, revision)
    inventory = None
    if inventory_path:
        inventory = json.loads(inventory_path.read_text())
        if inventory.get("schema_version") != "pti_backend_vm_inventory.v1":
            raise ValueError("invalid inventory schema")
        active_revision = inventory.get("active_revision", "")
        if re.fullmatch(r"[0-9a-f]{40}", active_revision):
            if coverage_baseline and command(["git", "-C", str(repo), "rev-parse",
                    "--verify", coverage_baseline + "^{commit}"]) != active_revision:
                raise ValueError("coverage baseline differs from source-host inventory")
            coverage_baseline = active_revision
    coverage = None
    if coverage_baseline:
        floor, baseline_source = git_archive(repo, coverage_baseline)
        coverage = coverage_gate(source, baseline_source, floor)
        references = [*references, floor]
    payloads: dict[str, bytes | Path] = {"sources/backend.tar.gz": source,
                                       "backend_vm.py": Path(__file__).resolve().read_bytes(),
                                       "README.md": Path(__file__).with_name("README.md").read_bytes(),
                                       "runtime-plan.example.json": Path(__file__).with_name("runtime-plan.example.json").read_bytes()}
    # Operator documents belong to the kit, not an overlay on immutable source.
    for name in ("GCP_VM_REBUILD_RUNBOOK.md", "DEPLOYMENT_AND_RECOVERY.md"):
        document = Path(__file__).resolve().parents[2] / "docs" / name
        if document.is_file():
            payloads["operator-docs/" + name] = document.read_bytes()
    comparison = []
    seen_references = set()
    for ref in references:
        sha, data = git_archive(repo, ref)
        if sha in seen_references:
            continue
        seen_references.add(sha)
        payloads[f"sources/reference-{sha}.tar.gz"] = data
        changed = command(["git", "-C", str(repo), "diff", "--name-status", sha, primary,
                           "--", "honeypot-analysis/production", "honeypot-analysis/configs",
                           "honeypot-analysis/deployment"])
        comparison.append({"reference_revision": sha, "different": bool(changed),
                           "changed_paths": changed.splitlines()})
    payloads["CHANGE_REVIEW.json"] = encoded(comparison)
    if coverage:
        payloads["RULE_COVERAGE.json"] = encoded(coverage)
    dirty = bool(command(["git", "-C", str(repo), "status", "--porcelain"]))
    runtime, runtime_directories, missing = [], [], sorted(COMPONENTS)
    plan = None
    if plan_path:
        plan = json.loads(plan_path.read_text())
        assets, info, runtime_directories = asset_entries(plan, runtime_root.resolve(), primary)
        missing = info.pop()["missing_components"]
        runtime = info
        payloads.update(assets)
        payloads["runtime-plan.json"] = encoded(plan)
    if inventory:
        payloads["inventory.json"] = encoded(inventory)
    files = []
    for name, value in sorted(payloads.items()):
        safe_name(name)
        files.append({"path": name, "sha256": payload_digest(value),
                      "bytes": payload_size(value)})
    manifest = {"schema_version": SCHEMA, "primary_revision": primary,
                "files": files, "runtime_assets": runtime, "runtime_directories": runtime_directories,
                "missing_components": missing, "worktree_changes_excluded": dirty,
                "references": comparison, "contains_private_inputs": bool(runtime),
                "rule_coverage": coverage,
                "runtime_inputs_complete": not missing,
                "source_host_health_passed": bool(inventory and inventory.get("health", {}).get("passed")),
                "destination_qualified": False, "activated": False}
    write_bundle(output, payloads, manifest)
    return {"package": str(output), "sha256": file_digest(output),
            "revision": primary, "missing_components": missing,
            "rule_coverage_checked": coverage is not None,
            "runtime_inputs_complete": not missing}


def verify(package: Path, expected_sha: str | None = None) -> dict:
    if expected_sha and (not SHA.fullmatch(expected_sha) or file_digest(package) != expected_sha):
        raise ValueError("package SHA-256 mismatch")
    with tarfile.open(package, "r:gz") as archive:
        members = archive.getmembers()
        member_by_name = {item.name: item for item in members}
        names = [safe_name(v.name) for v in members]
        if len(names) != len(set(names)) or any(not v.isfile() for v in members):
            raise ValueError("bundle has duplicate, link or special member")
        raw = archive.extractfile(member_by_name["BUNDLE_MANIFEST.json"])
        if raw is None:
            raise ValueError("bundle manifest missing")
        manifest = json.load(raw)
        if manifest.get("schema_version") != SCHEMA or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("primary_revision", "")):
            raise ValueError("invalid bundle manifest")
        if ("source_kit_sha256" in manifest
                and (not isinstance(manifest["source_kit_sha256"], str)
                     or not SHA.fullmatch(manifest["source_kit_sha256"]))):
            raise ValueError("invalid source-kit provenance")
        declared = [v["path"] for v in manifest["files"]]
        if len(declared) != len(set(declared)) or set(names) != set(declared) | {"BUNDLE_MANIFEST.json"}:
            raise ValueError("bundle inventory mismatch")
        for entry in manifest["files"]:
            item = member_by_name[entry["path"]]
            if item.size != entry["bytes"] or not SHA.fullmatch(entry["sha256"]):
                raise ValueError("bundle size/hash declaration invalid")
            h = hashlib.sha256()
            with archive.extractfile(item) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(chunk)
            if h.hexdigest() != entry["sha256"]:
                raise ValueError("bundle file checksum mismatch")
            if entry["path"].startswith("sources/"):
                validate_source(archive.extractfile(item).read())
        coverage = manifest.get("rule_coverage")
        if coverage is not None:
            floor = coverage.get("baseline_revision", "")
            if not re.fullmatch(r"[0-9a-f]{40}", floor):
                raise ValueError("invalid rule-coverage baseline")
            baseline_name = f"sources/reference-{floor}.tar.gz"
            if baseline_name not in declared or "RULE_COVERAGE.json" not in declared:
                raise ValueError("rule-coverage baseline or receipt is missing")
            measured = coverage_gate(
                archive.extractfile(member_by_name["sources/backend.tar.gz"]).read(),
                archive.extractfile(member_by_name[baseline_name]).read(), floor)
            if coverage != measured or json.load(archive.extractfile(
                    member_by_name["RULE_COVERAGE.json"])) != measured:
                raise ValueError("rule-coverage receipt is inconsistent")
        if "inventory.json" in declared:
            inventory = json.load(archive.extractfile(member_by_name["inventory.json"]))
            active_revision = inventory.get("active_revision", "")
            if re.fullmatch(r"[0-9a-f]{40}", active_revision) and (
                    coverage is None or coverage.get("baseline_revision") != active_revision):
                raise ValueError("source-host inventory requires its rule-coverage baseline")
        targets = []
        mapped_runtime = set()
        for asset in manifest["runtime_assets"]:
            if not isinstance(asset, dict) or ("archive_path" in asset) == ("link_target" in asset):
                raise ValueError("runtime asset must be exactly one file or symlink")
            targets.append(target_path(asset["target"]))
            if asset["component"] not in COMPONENTS or type(asset["mode"]) is not int or not 0 <= asset["mode"] <= 0o777:
                raise ValueError("invalid runtime asset")
            if "archive_path" in asset:
                if (not isinstance(asset["archive_path"], str)
                        or asset["archive_path"] != "runtime/" + asset["target"].lstrip("/")):
                    raise ValueError("runtime archive/destination mismatch")
                if asset["archive_path"] not in declared:
                    raise ValueError("runtime payload is missing")
                mapped_runtime.add(asset["archive_path"])
            if not all(isinstance(asset[k], int) and not isinstance(asset[k], bool) and asset[k] >= 0 for k in ("uid", "gid")):
                raise ValueError("invalid runtime ownership")
        if len(targets) != len(set(targets)):
            raise ValueError("duplicate runtime destination")
        directory_targets = []
        for directory in manifest["runtime_directories"]:
            directory_targets.append(target_path(directory["target"],
                                                 allow_directory=True))
            if directory["target"] in targets or not all(isinstance(directory[k], int) and not isinstance(directory[k], bool) and directory[k] >= 0 for k in ("uid", "gid", "mode")) or directory["mode"] > 0o777:
                raise ValueError("invalid runtime directory")
        if len(directory_targets) != len(set(directory_targets)):
            raise ValueError("duplicate runtime directory")
        runtime_payloads = {name for name in declared if name.startswith("runtime/")}
        if runtime_payloads != mapped_runtime:
            raise ValueError("runtime payload is not mapped to exactly one asset")
        has_plan = "runtime-plan.json" in names
        if (manifest["runtime_assets"] or manifest["runtime_directories"]) and not has_plan:
            raise ValueError("runtime plan is missing")
        if has_plan:
            plan = json.load(archive.extractfile(member_by_name["runtime-plan.json"]))
            if not isinstance(plan, dict) or plan.get("schema_version") != PLAN_SCHEMA:
                raise ValueError("invalid runtime plan")
            external = plan.get("external_paths", [])
            if not isinstance(external, list):
                raise ValueError("invalid external dependency list")
            for value in external:
                if (not isinstance(value, str)
                        or not re.fullmatch(r"/usr/(?:bin|lib|lib64)/[\w./+-]+", value)
                        or ".." in Path(value).parts):
                    raise ValueError("invalid external dependency")
            required_units = plan.get("required_units", list(CORE_UNITS))
            if (not isinstance(required_units, list) or not required_units
                    or any(not isinstance(v, str) or not UNIT.fullmatch(v) for v in required_units)
                    or len(required_units) != len(set(required_units))):
                raise ValueError("invalid required units")
            for asset in manifest["runtime_assets"]:
                if "link_target" in asset:
                    link = asset["link_target"]
                    if (not isinstance(link, str) or not Path(link).is_absolute()
                            or ".." in Path(link).parts or live_capture_path(link)):
                        raise ValueError("invalid runtime symlink")
                    if link not in targets + external and not any(v.startswith(link.rstrip("/") + "/") for v in targets):
                        raise ValueError("unbound runtime symlink")
            covered = {asset["component"] for asset in manifest["runtime_assets"] if "archive_path" in asset}
            missing = COMPONENTS - covered
            unit_targets = {Path(v).name for v in targets if v.startswith("/etc/systemd/system/")}
            if not set(required_units).issubset(unit_targets):
                missing |= {"systemd"}
            if not missing.issubset(set(manifest["missing_components"])):
                raise ValueError("runtime completeness declaration is inconsistent")
        if manifest["runtime_inputs_complete"] != (not manifest["missing_components"]):
            raise ValueError("invalid runtime completeness flag")
        return manifest


def verify_source_kit(package: Path, expected_sha: str) -> dict:
    if not isinstance(expected_sha, str) or not SHA.fullmatch(expected_sha):
        raise ValueError("source kit requires a valid SHA-256 pin")
    manifest = verify(package, expected_sha)
    if (manifest["runtime_assets"] or manifest["runtime_directories"]
            or manifest["contains_private_inputs"] or manifest["runtime_inputs_complete"]
            or set(manifest["missing_components"]) != set(COMPONENTS)):
        raise ValueError("source kit must not contain runtime assets")
    with tarfile.open(package, "r:gz") as archive:
        names = set(archive.getnames())
        if "runtime-plan.json" in names or any(name.startswith("runtime/") for name in names):
            raise ValueError("source kit must not contain runtime assets")
        if "inventory.json" in names:
            inventory = json.load(archive.extractfile("inventory.json"))
            coverage = manifest.get("rule_coverage")
            floor = coverage.get("baseline_revision", "") if coverage else ""
            if (not isinstance(inventory, dict)
                    or inventory.get("schema_version") != "pti_backend_vm_inventory.v1"
                    or not re.fullmatch(r"[0-9a-f]{40}", floor)
                    or inventory.get("active_revision") != floor):
                raise ValueError("source-kit inventory must match its rule-coverage baseline")
    return manifest


def assemble(source_kit: Path, source_kit_sha256: str, output: Path,
             plan_path: Path, runtime_root: Path = Path("/"),
             inventory_path: Path | None = None) -> dict:
    """Complete a verified source-only kit with explicitly planned runtime inputs."""
    source_kit = source_kit.resolve()
    outside_checkout(output)
    source_manifest = verify_source_kit(source_kit, source_kit_sha256)
    primary = source_manifest["primary_revision"]
    plan = json.loads(plan_path.read_text())
    assets, runtime_assets, runtime_directories = asset_entries(
        plan, runtime_root.resolve(), primary)
    missing = runtime_assets.pop()["missing_components"]
    if missing:
        raise ValueError("runtime plan is incomplete: missing " + ", ".join(missing))

    inventory = None
    if inventory_path:
        inventory = json.loads(inventory_path.read_text())
        if (not isinstance(inventory, dict)
                or inventory.get("schema_version") != "pti_backend_vm_inventory.v1"):
            raise ValueError("invalid inventory schema")
        coverage = source_manifest.get("rule_coverage")
        floor = coverage.get("baseline_revision", "") if coverage else ""
        if (not re.fullmatch(r"[0-9a-f]{40}", floor)
                or inventory.get("active_revision") != floor):
            raise ValueError("inventory active revision differs from source-kit coverage baseline")

    with tarfile.open(source_kit, "r:gz") as archive:
        source_entries = {entry["path"]: entry for entry in source_manifest["files"]}
        payloads: dict[str, bytes | Path | ArchivePayload] = {}
        replace_inventory = inventory is not None
        current_files = {
            "backend_vm.py": Path(__file__).resolve(),
            "README.md": Path(__file__).with_name("README.md"),
            "runtime-plan.example.json": Path(__file__).with_name("runtime-plan.example.json"),
        }
        for name, entry in source_entries.items():
            if ((name in current_files and current_files[name].is_file())
                    or (replace_inventory and name == "inventory.json")):
                continue
            payloads[name] = ArchivePayload(archive, name, entry["bytes"], entry["sha256"])
        for name, path in current_files.items():
            if path.is_file():
                payloads[name] = path.read_bytes()
        current_runbook = Path(__file__).resolve().parents[2] / "docs" / "GCP_VM_REBUILD_RUNBOOK.md"
        if current_runbook.is_file():
            payloads["operator-docs/GCP_VM_REBUILD_RUNBOOK.md"] = current_runbook.read_bytes()
        payloads["runtime-plan.json"] = encoded(plan)
        payloads.update(assets)
        if inventory is not None:
            payloads["inventory.json"] = encoded(inventory)

        files = [{"path": name, "sha256": payload_digest(value),
                  "bytes": payload_size(value)} for name, value in sorted(payloads.items())]
        manifest = dict(source_manifest)
        manifest.update({
            "files": files,
            "runtime_assets": runtime_assets,
            "runtime_directories": runtime_directories,
            "missing_components": [],
            "contains_private_inputs": bool(runtime_assets),
            "runtime_inputs_complete": True,
            "source_host_health_passed": (
                bool(inventory and inventory.get("health", {}).get("passed"))
                if inventory is not None else source_manifest["source_host_health_passed"]),
            "destination_qualified": False,
            "activated": False,
            "source_kit_sha256": source_kit_sha256,
        })
        write_bundle(output, payloads, manifest)

    return {"package": str(output), "sha256": file_digest(output),
            "revision": primary, "missing_components": [],
            "rule_coverage_checked": source_manifest.get("rule_coverage") is not None,
            "runtime_inputs_complete": True,
            "source_kit_sha256": source_kit_sha256}


def no_symlink_parents(path: Path, root: Path) -> None:
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("destination contains a symlink")
        if parent == root:
            break


def stage(package: Path, destination: Path, expected_sha: str) -> dict:
    manifest = verify(package, expected_sha)
    root = destination.absolute()
    no_symlink_parents(root, Path("/"))
    if (root / "opt/honeypot").exists() or (root / "opt/honeypot").is_symlink():
        raise ValueError("destination already has an active backend")
    release = root / "opt/honeypot-releases" / manifest["primary_revision"]
    if release.exists() or release.is_symlink():
        raise ValueError("destination release already exists")
    with tarfile.open(package, "r:gz") as archive:
        bundle_members = {item.name: item for item in archive.getmembers()}
        data = archive.extractfile(bundle_members["sources/backend.tar.gz"]).read()
        source_entries = validate_source(data)
        writes = []
        for item in source_entries:
            if item.isfile():
                writes.append((release / item.name, item.mode & 0o777, ("source", item.name), None))
        runtime_assets = sorted(manifest["runtime_assets"], key=lambda asset:
            bundle_members[asset["archive_path"]].offset_data if "archive_path" in asset else -1)
        for asset in runtime_assets:
            path = root / asset["target"].lstrip("/")
            content = ("bundle", asset["archive_path"]) if "archive_path" in asset else None
            writes.append((path, asset["mode"], content, asset))
        marker = release / "DEPLOYED_COMMIT"
        writes.append((marker, 0o644, (manifest["primary_revision"] + "\n").encode(), None))
        paths = [path for path, *_ in writes]
        path_set = set(paths)
        if len(paths) != len(path_set):
            raise ValueError("staging destinations overlap")
        link_paths = {path for path, _, content, _ in writes if content is None}
        for path in paths:
            no_symlink_parents(path, root)
            if any(parent in link_paths or parent in path_set for parent in path.parents):
                raise ValueError("staged file/link is also a parent destination")
            if path.exists():
                raise ValueError("refusing to overwrite a destination file")
        if "runtime-plan.json" in bundle_members:
            plan = json.load(archive.extractfile(bundle_members["runtime-plan.json"]))
            if plan.get("host") != os_identity():
                raise ValueError("runtime assets require the recorded OS/version/architecture")
            for value in plan.get("external_paths", []):
                if not (root / value.lstrip("/")).exists():
                    raise ValueError("required OS dependency is missing")
            if root == Path("/"):
                for name, ids in plan.get("accounts", {}).items():
                    account = pwd.getpwnam(name)
                    if account.pw_uid != ids["uid"] or account.pw_gid != ids["gid"]:
                        raise ValueError("destination service account identity differs")
        else:
            plan = {}
        for directory in manifest["runtime_directories"]:
            path = root / directory["target"].lstrip("/")
            no_symlink_parents(path, root)
            if any(parent in path_set for parent in (path, *path.parents)):
                raise ValueError("runtime directory conflicts with a file/link")
            if path.exists() and not path.is_dir():
                raise ValueError("runtime directory destination is a file")
        # Preflight every destination before the first write; partial I/O failure
        # retains staged material for inspection without changing the active link.
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as source:
            source_members = {item.name: item for item in source.getmembers()}
            for path, mode, content, asset in writes:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if content is None:
                    link = asset["link_target"]
                    if root != Path("/") and Path(link).is_absolute():
                        link = str(root / link.lstrip("/"))
                    path.symlink_to(link)
                else:
                    if isinstance(content, bytes):
                        input_stream = io.BytesIO(content)
                    else:
                        member = (source_members[content[1]] if content[0] == "source"
                                  else bundle_members[content[1]])
                        container = source if content[0] == "source" else archive
                        input_stream = container.extractfile(member)
                    h = hashlib.sha256()
                    with input_stream, path.open("xb") as stream:
                        for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                            stream.write(chunk)
                            h.update(chunk)
                    os.chmod(path, mode)
                    if file_digest(path) != h.hexdigest():
                        raise ValueError("staged read-back checksum mismatch")
                if asset and os.geteuid() == 0:
                    os.chown(path, asset["uid"], asset["gid"], follow_symlinks=False)
        for directory in manifest["runtime_directories"]:
            path = root / directory["target"].lstrip("/")
            path.mkdir(mode=directory["mode"], parents=True, exist_ok=True)
            os.chmod(path, directory["mode"])
            if os.geteuid() == 0:
                os.chown(path, directory["uid"], directory["gid"])
        if os.geteuid() == 0 and "honeypot" in plan.get("accounts", {}):
            gid = plan["accounts"]["honeypot"]["gid"]
            for directory, names, files in os.walk(release, followlinks=False):
                os.chown(directory, 0, gid)
                os.chmod(directory, 0o750)
                for name in files:
                    path = Path(directory) / name
                    if not path.is_symlink():
                        os.chown(path, 0, gid)
            os.chown(release.parent, 0, gid)
            os.chmod(release.parent, 0o750)
    return {"release": str(release), "files_staged": len(writes),
            "runtime_inputs_complete": manifest["runtime_inputs_complete"],
            "activated": False, "remaining": ["accounts and directory permissions",
                "release manifest and storage successor", "network/provider bindings",
                "replacement qualification", "approved cutover and rollback rehearsal"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    p = sub.add_parser("snapshot")
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("build")
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--revision", required=True)
    p.add_argument("--reference-revision", action="append", default=[])
    p.add_argument("--coverage-baseline", help="Exact old-source rule floor; automatically pinned from inventory")
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--runtime-plan", type=Path)
    p.add_argument("--runtime-root", type=Path, default=Path("/"))
    p.add_argument("--inventory", type=Path)
    p = sub.add_parser("verify")
    source_group = p.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--bundle", type=Path)
    source_group.add_argument("--source-kit", type=Path)
    p.add_argument("--sha256")
    for operation in ("complete", "assemble"):
        p = sub.add_parser(operation)
        p.add_argument("--source-kit", type=Path, required=True)
        p.add_argument("--source-sha256", "--source-kit-sha256", "--sha256",
                       dest="source_kit_sha256", required=True)
        p.add_argument("--runtime-plan", type=Path, required=True)
        p.add_argument("--runtime-root", type=Path, default=Path("/"))
        p.add_argument("--inventory", type=Path)
        p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("stage")
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--destination-root", type=Path, required=True)
    p = sub.add_parser("health")
    p.add_argument("--unit", action="append")
    args = parser.parse_args()
    try:
        if args.operation == "snapshot":
            receipt = snapshot(args.output)
            result = {"inventory": str(args.output), "health_passed": receipt["health"]["passed"]}
        elif args.operation == "build":
            result = build(args.repo, args.revision, args.output, args.reference_revision,
                           args.runtime_plan, args.runtime_root, args.inventory, args.coverage_baseline)
        elif args.operation == "verify":
            if args.source_kit:
                if not args.sha256:
                    raise ValueError("--source-kit verification requires --sha256")
                manifest = verify_source_kit(args.source_kit, args.sha256)
            else:
                manifest = verify(args.bundle, args.sha256)
            result = {"verified": True, "revision": manifest["primary_revision"],
                      "runtime_inputs_complete": manifest["runtime_inputs_complete"],
                      "missing_components": manifest["missing_components"],
                      "source_host_health_passed": manifest["source_host_health_passed"],
                      "rule_coverage_checked": manifest.get("rule_coverage") is not None,
                      "destination_qualified": False}
        elif args.operation in {"complete", "assemble"}:
            result = assemble(args.source_kit, args.source_kit_sha256, args.output,
                              args.runtime_plan, args.runtime_root, args.inventory)
        elif args.operation == "stage":
            result = stage(args.bundle, args.destination_root, args.sha256)
        else:
            result = health(args.unit or list(CORE_UNITS))
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1 if args.operation == "health" and not result["passed"] else 0
    except (ValueError, KeyError, TypeError, OSError, tarfile.TarError,
            sqlite3.Error, subprocess.TimeoutExpired) as exc:
        # No file contents or subprocess stderr are exposed by error reporting.
        reason = str(exc) if type(exc) is ValueError else type(exc).__name__
        print(f"backend bundle stopped: {reason}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
