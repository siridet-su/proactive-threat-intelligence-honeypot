"""Install the reviewed Pi watchdog source and switch Cowrie to a passive probe.

Run as root on the existing Pi after placing honeypot-service-watchdog.py in a
root-readable staging location. No protected config is read into argv or Git.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import runpy
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ACTIVE_SCRIPT = Path("/usr/local/libexec/honeypot-service-watchdog.py")
ACTIVE_CONFIG = Path("/etc/honeypot/service-watchdog.json")
BACKUP_ROOT = Path("/var/backups/honeypot/service-watchdog")
TIMER = "honeypot-service-watchdog.timer"
SERVICE = "honeypot-service-watchdog.service"


def command(*args: str) -> None:
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[1]} failed with exit status {result.returncode}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_config() -> bytes:
    value = json.loads(ACTIVE_CONFIG.read_text(encoding="utf-8"))
    targets = [target for target in value.get("targets", []) if target.get("kind") == "systemd" and target.get("name") == "cowrie"]
    if len(targets) != 1 or targets[0].get("probe") != {"type": "tcp", "host": "127.0.0.1", "port": 22}:
        raise RuntimeError("Cowrie probe does not match the reviewed active configuration")
    targets[0]["probe"]["type"] = "tcp_listen"
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def install(staged_script: Path) -> Path:
    if os.geteuid() != 0:
        raise RuntimeError("root is required")
    for path in (ACTIVE_SCRIPT, ACTIVE_CONFIG, staged_script):
        if not path.is_file():
            raise RuntimeError(f"required file unavailable: {path}")
    ast.parse(staged_script.read_text(encoding="utf-8"))
    config_bytes = prepare_config()
    module = runpy.run_path(str(staged_script))
    probe = {"type": "tcp_listen", "host": "127.0.0.1", "port": 22, "timeout_seconds": 3}
    if module["probe_state"](probe) != (True, "tcp_listening"):
        raise RuntimeError("passive probe does not detect the active Cowrie listener")
    if BACKUP_ROOT.parent.stat().st_uid != 0 or BACKUP_ROOT.parent.stat().st_mode & 0o077:
        raise RuntimeError("protected backup parent is not root-only")

    os.umask(0o077)
    BACKUP_ROOT.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = BACKUP_ROOT / stamp
    directory.mkdir(mode=0o700)
    previous_script = directory / "honeypot-service-watchdog.py"
    previous_config = directory / "service-watchdog.json"
    shutil.copy2(ACTIVE_SCRIPT, previous_script)
    shutil.copy2(ACTIVE_CONFIG, previous_config)
    previous_script.chmod(0o600)
    previous_config.chmod(0o600)

    script_mode = stat.S_IMODE(ACTIVE_SCRIPT.stat().st_mode)
    config_mode = stat.S_IMODE(ACTIVE_CONFIG.stat().st_mode)
    script_temp = ACTIVE_SCRIPT.with_name(f".{ACTIVE_SCRIPT.name}.{stamp}.tmp")
    config_temp = ACTIVE_CONFIG.with_name(f".{ACTIVE_CONFIG.name}.{stamp}.tmp")
    try:
        with script_temp.open("xb") as handle:
            handle.write(staged_script.read_bytes())
            handle.flush()
            os.fsync(handle.fileno())
        script_temp.chmod(script_mode)
        with config_temp.open("xb") as handle:
            handle.write(config_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        config_temp.chmod(config_mode)
        module["load_config"](config_temp)

        command("/usr/bin/systemctl", "stop", TIMER)
        command("/usr/bin/systemctl", "stop", SERVICE)
        os.replace(script_temp, ACTIVE_SCRIPT)
        os.replace(config_temp, ACTIVE_CONFIG)
        command("/usr/bin/systemctl", "start", SERVICE)
        state = json.loads(Path("/var/lib/honeypot-service-watchdog/status.json").read_text(encoding="utf-8"))
        cowrie = state.get("targets", {}).get("systemd:cowrie", {})
        if cowrie.get("status") != "HEALTHY" or "tcp_listening" not in str(cowrie.get("reason")):
            raise RuntimeError("new watchdog run did not report Cowrie listening")
        command("/usr/bin/systemctl", "start", TIMER)
        command("/usr/bin/systemctl", "is-active", TIMER)
    except Exception:
        shutil.copy2(previous_script, ACTIVE_SCRIPT)
        shutil.copy2(previous_config, ACTIVE_CONFIG)
        ACTIVE_SCRIPT.chmod(script_mode)
        ACTIVE_CONFIG.chmod(config_mode)
        try:
            command("/usr/bin/systemctl", "start", TIMER)
        except Exception as rollback_error:
            raise RuntimeError(f"rollback restored files but timer restart failed: {rollback_error}") from rollback_error
        raise
    finally:
        script_temp.unlink(missing_ok=True)
        config_temp.unlink(missing_ok=True)
    manifest = {"schema_version": "cowrie_passive_probe_install.v1", "installed_at": stamp,
                "old_script_sha256": digest(previous_script), "new_script_sha256": digest(ACTIVE_SCRIPT),
                "old_config_sha256": digest(previous_config), "new_config_sha256": digest(ACTIVE_CONFIG)}
    (directory / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return directory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged-script", required=True, type=Path)
    args = parser.parse_args()
    directory = install(args.staged_script)
    print(json.dumps({"status": "installed", "backup_directory": str(directory),
                      "cowrie_probe": "tcp_listen", "timer": "active"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
