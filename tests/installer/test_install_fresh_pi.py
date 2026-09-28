"""Fresh installer rejects unreviewed artifacts and mismatched capture scope."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import install_fresh_pi as installer  # noqa: E402


def reviewed_vars(tmp_path: Path) -> dict:
    data = {
        "pti_cowrie_bundle_revision": "a" * 40,
        "pti_decoy_commit": "b" * 40,
        "pti_docker_version": "1:2.3-4",
        "pti_compose_version": "2.3-4",
        "pti_zeek_interface": "wlan0",
        "pti_cowrie_interface": "wlan0",
        "pti_cowrie_ssh_port": 2222,
        "pti_cowrie_telnet_port": 2223,
        "pti_zeek_ports": [2222, 2223],
    }
    for name, digest in (
        ("pti_cowrie_archive", "pti_cowrie_sha256"),
        ("pti_cowrie_bundle", "pti_cowrie_bundle_sha256"),
        ("pti_decoy_archive", "pti_decoy_sha256"),
    ):
        path = tmp_path / name
        path.write_bytes(name.encode())
        data[name] = str(path)
        data[digest] = hashlib.sha256(path.read_bytes()).hexdigest()
    return data


def test_fresh_scope_requires_matching_listener_and_capture_ports(tmp_path):
    data = reviewed_vars(tmp_path)
    path = tmp_path / "vars.json"
    path.write_text(json.dumps(data))
    assert installer.reviewed_full_vars(path)["pti_zeek_ports"] == [2222, 2223]
    data["pti_zeek_ports"] = [22, 80]
    path.write_text(json.dumps(data))
    with pytest.raises(installer.InstallError, match="exactly match"):
        installer.reviewed_full_vars(path)


def test_reviewed_wifi_ports_can_change_together_before_install(tmp_path):
    data = reviewed_vars(tmp_path)
    data["pti_cowrie_ssh_port"] = 22
    data["pti_cowrie_telnet_port"] = 23
    data["pti_zeek_ports"] = [22, 23]
    path = tmp_path / "vars.json"
    path.write_text(json.dumps(data))
    assert installer.reviewed_full_vars(path)["pti_zeek_ports"] == [22, 23]


def test_fresh_artifact_digest_is_checked_before_host_mutation(tmp_path):
    data = reviewed_vars(tmp_path)
    data["pti_cowrie_bundle_sha256"] = "0" * 64
    path = tmp_path / "vars.json"
    path.write_text(json.dumps(data))
    with pytest.raises(installer.InstallError, match="differs"):
        installer.reviewed_full_vars(path)


def test_service_probe_rejects_unexpected_output(tmp_path):
    with patch.object(installer.subprocess, "run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "target | SUCCESS | rc=0 | (stdout) active\n"
        assert installer.service_property(tmp_path / "inventory", "cowrie.service", "ActiveState") == "active"
        run.return_value.stdout = "unexpected remote output"
        with pytest.raises(installer.InstallError, match="unexpected"):
            installer.service_property(tmp_path / "inventory", "cowrie.service", "ActiveState")
