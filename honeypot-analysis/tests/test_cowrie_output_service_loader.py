"""Opt-in acceptance through Cowrie's real Twisted plugin loader and SSH stack."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import socket
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from production.cowrie_output.lifecycle import load_lifecycle_state
from production.cowrie_output.runtime import DEPLOYMENT_CONTRACT
from production.tools.cowrie_output_integration import build_bundle, render_config
from production.workers import sensor_forwarder


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_COWRIE_REVISION = "575146bc6b24d70082527d66cd805d9bae0e0db4"
SOURCE_VARIABLE = "COWRIE_SERVICE_SMOKE_SOURCE"
PYTHON_VARIABLE = "COWRIE_SERVICE_SMOKE_PYTHON"

pytestmark = pytest.mark.skipif(
    not os.environ.get(SOURCE_VARIABLE) or not os.environ.get(PYTHON_VARIABLE),
    reason="exact Cowrie service-smoke runtime was not requested",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for(predicate, *, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("service-faithful Cowrie condition timed out")


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _records(path: Path) -> list[dict]:
    content = path.read_bytes()
    assert content.endswith(b"\n")
    return [json.loads(line) for line in content.splitlines() if line]


def _start_cowrie(
    *, python: Path, runtime: Path, bundle: Path, port: int
) -> tuple[subprocess.Popen[bytes], dict[str, str]]:
    environment = {
        "HOME": str(runtime),
        "LANG": "C.UTF-8",
        "PATH": f"{python.parent}:/usr/bin:/bin",
        "PYTHONPATH": f"{bundle}:{runtime / 'src'}",
        "PYTHONDONTWRITEBYTECODE": "1",
        "VIRTUAL_ENV": str(python.parent.parent),
        "COWRIE_SSH_LISTEN_ENDPOINTS": f"tcp:{port}:interface=127.0.0.1",
        "COWRIE_TELNET_ENABLED": "no",
        "HONEYPOT_COWRIE_OUTPUT_ROOT": str(bundle),
        "HONEYPOT_COWRIE_CONFIG": str(runtime / "etc/cowrie.cfg"),
        "HONEYPOT_COWRIE_ROOT": str(runtime),
    }
    command = [
        str(python.parent / "twistd"),
        "--umask=0077",
        "--pidfile=var/run/cowrie.pid",
        "--logger",
        "production.cowrie_output.twisted_logger.logger",
        "-n",
        "cowrie",
    ]
    process = subprocess.Popen(
        command,
        cwd=runtime,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def ready() -> bool:
        if process.poll() is not None:
            raise AssertionError("Cowrie exited before its SSH listener became ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            return False

    _wait_for(ready)
    return process, environment


def _ssh_session(port: int, secret: str) -> None:
    environment = os.environ.copy()
    environment["SSHPASS"] = secret
    subprocess.run(
        [
            "sshpass",
            "-e",
            "ssh",
            "-tt",
            "-p",
            str(port),
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            "root@127.0.0.1",
        ],
        input=b"id\nexit\n",
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=15,
    )


def _forwarder_config(runtime: Path) -> SimpleNamespace:
    return SimpleNamespace(
        sensor_id="service-smoke-sensor",
        api_token="unused-in-isolated-smoke",
        cowrie_log_path=str(runtime / "var/log/cowrie/cowrie.json"),
        spool_path=str(runtime / "var/lib/cowrie/forwarder-spool.ndjson"),
        ingest_url="http://127.0.0.1:9/events",
        forwarder_batch_size=100,
        forwarder_timeout_seconds=1,
        forwarder_max_spool_bytes=8 * 1024 * 1024,
        forwarder_min_free_bytes=0,
        forwarder_max_line_bytes=64 * 1024,
    )


def test_real_cowrie_loader_ssh_restart_rotation_and_forwarder_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = Path(os.environ[SOURCE_VARIABLE]).resolve(strict=True)
    python = Path(os.environ[PYTHON_VARIABLE]).absolute()
    assert python.is_file()
    assert subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip() == EXPECTED_COWRIE_REVISION
    assert subprocess.run(
        [str(python), "--version"], check=True, capture_output=True, text=True
    ).stdout.strip() == "Python 3.12.3"
    assert subprocess.run(
        [str(python), "-c", "import twisted; print(twisted.__version__)"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip() == "25.5.0"
    compatibility = DEPLOYMENT_CONTRACT["compatibility"]
    assert _sha256(source / "src/cowrie/core/output.py") == compatibility[
        "cowrie_output_base_sha256"
    ]
    assert _sha256(source / "src/twisted/plugins/cowrie_plugin.py") == compatibility[
        "cowrie_output_loader_sha256"
    ]

    runtime = tmp_path / "cowrie"
    bundle = tmp_path / "bundle"
    shutil.copytree(
        source,
        runtime,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
    )
    manifest = build_bundle(ROOT, bundle, "1" * 40)
    plugin = runtime / "src/cowrie/output/sanitizedjson.py"
    plugin.symlink_to(bundle / "production/cowrie_output/sanitized_jsonlog.py")
    render_config(runtime / "etc/cowrie.cfg.dist", runtime / "etc/cowrie.cfg", bundle)
    logs = runtime / "var/log/cowrie"
    state_dir = runtime / "var/lib/cowrie"
    run_dir = runtime / "var/run"
    for directory in (logs, state_dir, run_dir):
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        directory.chmod(0o700)
    (runtime / "etc/userdb.txt").write_text("root:x:*\n", encoding="utf-8")
    (runtime / "etc/userdb.txt").chmod(0o600)

    feed = logs / "cowrie.json"
    feed.touch(mode=0o640)
    feed.chmod(0o640)
    yesterday = time.time() - 2 * 24 * 60 * 60
    os.utime(feed, (yesterday, yesterday))

    port = _free_port()
    process, environment = _start_cowrie(
        python=python, runtime=runtime, bundle=bundle, port=port
    )
    secrets_used = [secrets.token_urlsafe(24), secrets.token_urlsafe(24)]
    try:
        state_path = state_dir / "cowrie-output-lifecycle.json"
        _wait_for(
            lambda: state_path.exists()
            and load_lifecycle_state(state_path)["observer_registered"]
        )
        state = load_lifecycle_state(state_path)
        assert state["process_pid"] == process.pid
        assert state["component_id"] == manifest["component_id"]
        assert state["source_revision"] == manifest["git_revision"]
        assert state["module_sha256"] == manifest["files"][
            "production/cowrie_output/sanitized_jsonlog.py"
        ]["sha256"]
        assert state["class_discovered"]
        assert state["constructor_completed"]
        assert state["start_completed"]
        assert state["file_open_attempts"] == 1
        assert state["file_open_successes"] == 1

        _ssh_session(port, secrets_used[0])
        _wait_for(lambda: feed.exists() and len(_records(feed)) >= 5)
        first_records = _records(feed)
        first_count = len(first_records)
        event_ids = {item["eventid"] for item in first_records}
        assert {
            "cowrie.session.connect",
            "cowrie.client.version",
            "cowrie.login.success",
            "cowrie.session.closed",
        } <= event_ids
        assert list(logs.glob("cowrie.json.*"))
        assert stat.S_IMODE(feed.stat().st_mode) == 0o640
        assert all(
            stat.S_IMODE(path.stat().st_mode) == 0o600
            for path in logs.glob("cowrie.json.*")
        )
        assert (logs / "cowrie.log").stat().st_size > 0

        delivered: list[dict] = []

        def acknowledge(_config: object, events: list[dict]) -> dict:
            delivered.extend(events)
            return {"accepted": len(events), "duplicates": 0, "rejected": []}

        monkeypatch.setattr(sensor_forwarder, "post_events", acknowledge)
        forwarder = _forwarder_config(runtime)
        first_delivery = sensor_forwarder.forward_once(forwarder)
        assert first_delivery.sent == first_count
        assert first_delivery.remaining == 0
        assert sensor_forwarder.forward_once(forwarder).sent == 0

        _stop(process)
        port = _free_port()
        process, environment = _start_cowrie(
            python=python, runtime=runtime, bundle=bundle, port=port
        )
        _wait_for(
            lambda: load_lifecycle_state(state_path)["process_pid"] == process.pid
            and load_lifecycle_state(state_path)["observer_registered"]
        )
        _ssh_session(port, secrets_used[1])
        _wait_for(lambda: len(_records(feed)) >= first_count + 5)
        second_records = _records(feed)
        second_delivery = sensor_forwarder.forward_once(forwarder)
        assert second_delivery.sent == len(second_records) - first_count
        assert sensor_forwarder.forward_once(forwarder).sent == 0
        assert len(delivered) == len(second_records)

        persistent = b"".join(
            path.read_bytes()
            for path in [feed, logs / "cowrie.log", state_path]
            if path.exists()
        )
        assert all(secret.encode() not in persistent for secret in secrets_used)
        assert not Path(forwarder.spool_path).exists()
        assert not list(bundle.rglob("__pycache__"))
        assert not list(bundle.rglob("*.pyc"))
        assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    finally:
        _stop(process)
