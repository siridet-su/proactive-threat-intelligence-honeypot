from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest

from deployment.gcp.verify_rebuilt_vm import (
    ManifestError,
    release_tree_sha256,
    verify_manifest,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _concrete_manifest(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    root = tmp_path / "root"
    release_root = root / "opt" / "honeypot-releases" / ("a" * 40)
    manifest_path = release_root / "DEPLOYMENT_MANIFEST.json"
    source = release_root / "production" / "entrypoint.py"
    classification = release_root / "configs" / "classification.json"
    prediction = release_root / "configs" / "prediction.json"
    _write(source, b"print('ok')\n")
    _write(classification, b"{\"policy\":\"trusted\"}\n")
    _write(prediction, b"{\"advisory_only\":true}\n")

    model_root = root / "opt" / "honeypot-model-bundles" / "bundle"
    model_manifest = model_root / "FROZEN_MODEL_BUNDLE_MANIFEST.json"
    checkpoint = model_root / "transformer" / "checkpoint.bin"
    _write(model_manifest, b"{\"schema_version\":\"test\"}\n")
    _write(checkpoint, b"frozen\n")

    backup = root / "var" / "backups" / "run" / "production_pilot.db"
    backup_manifest = backup.with_name("production_pilot.db.manifest.json")
    backup.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(backup) as database:
        database.execute("PRAGMA user_version=3")
        database.execute("CREATE TABLE sessions(id INTEGER PRIMARY KEY)")
        database.commit()
    _write(backup_manifest, b"{\"schema_version\":\"sqlite_backup_manifest.v1\"}\n")

    release_entries = []
    for path in sorted((source, classification, prediction)):
        release_entries.append(
            {"path": str(path), "sha256": _sha256(path), "bytes": path.stat().st_size}
        )
    artifacts = [
        {
            "name": "transformer_checkpoint",
            "path": str(checkpoint),
            "sha256": _sha256(checkpoint),
            "bytes": checkpoint.stat().st_size,
        }
    ]
    document: dict[str, object] = {
        "schema_version": "gcp_vm_rebuild_manifest.v1",
        "source_commit": "a" * 40,
        "release": {
            "root": str(release_root),
            "manifest_path": str(manifest_path),
            "release_tree_sha256": release_tree_sha256(release_entries),
            "files": release_entries,
        },
        "policies": [
            {"name": "classification_rules", "path": str(classification), "sha256": _sha256(classification)},
            {"name": "prediction_policy", "path": str(prediction), "sha256": _sha256(prediction)},
        ],
        "model_bundle": {
            "bundle_id": "bundle",
            "manifest_path": str(model_manifest),
            "manifest_sha256": _sha256(model_manifest),
            "artifacts": artifacts,
        },
        "database": {
            "backup_path": str(backup),
            "backup_sha256": _sha256(backup),
            "backup_manifest_path": str(backup_manifest),
            "backup_manifest_sha256": _sha256(backup_manifest),
            "schema_version": 3,
        },
        "services": {
            "required_active": ["honeypot-session-worker.service"],
            "required_timers": ["honeypot-feed-refresh.timer"],
        },
        "network": {"frontend_port": 2222, "backend_role": "tailscale-pi-backend"},
    }
    _write(manifest_path, (json.dumps(document, sort_keys=True, indent=2) + "\n").encode())
    return root, manifest_path, document


def test_concrete_manifest_verifies_release_model_and_sqlite(tmp_path: Path) -> None:
    root, manifest_path, document = _concrete_manifest(tmp_path)

    result = verify_manifest(document, root=root, manifest_path=manifest_path)

    assert result["status"] == "valid"
    assert result["source_commit"] == "a" * 40
    assert result["database"]["quick_check"] == "ok"
    assert result["database"]["integrity_check"] == "ok"
    assert len(result["verified_files"]) == 3
    assert result["manifest_sha256"] == _sha256(manifest_path)


def test_manifest_rejects_path_escape_even_with_valid_hashes(tmp_path: Path) -> None:
    root, _, document = _concrete_manifest(tmp_path)
    release = document["release"]
    assert isinstance(release, dict)
    release["files"][0]["path"] = str(tmp_path / "outside")
    _write(tmp_path / "outside", b"print('ok')\n")
    release["files"][0]["sha256"] = _sha256(tmp_path / "outside")
    release["files"][0]["bytes"] = (tmp_path / "outside").stat().st_size
    release["release_tree_sha256"] = release_tree_sha256(release["files"])

    with pytest.raises(ManifestError, match="escapes its declared boundary"):
        verify_manifest(document, root=root)


def test_manifest_rejects_hash_mismatch(tmp_path: Path) -> None:
    root, _, document = _concrete_manifest(tmp_path)
    policies = document["policies"]
    assert isinstance(policies, list)
    policies[0]["sha256"] = "0" * 64

    with pytest.raises(ManifestError, match="sha256 mismatch"):
        verify_manifest(document, root=root)


def test_manifest_rejects_unresolved_placeholders(tmp_path: Path) -> None:
    root, _, document = _concrete_manifest(tmp_path)
    document["source_commit"] = "<40-HEX-GIT-COMMIT>"

    with pytest.raises(ManifestError, match="placeholder"):
        verify_manifest(document, root=root)


def test_redacted_inventory_is_owner_only_and_contains_no_addresses(tmp_path: Path) -> None:
    output = tmp_path / "inventory.json"
    script = Path(__file__).parents[1] / "deployment" / "gcp" / "collect_redacted_inventory.sh"
    completed = subprocess.run(
        ["bash", str(script), "--output", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == str(output)
    assert output.stat().st_mode & 0o777 == 0o600
    document = json.loads(output.read_text(encoding="utf-8"))
    encoded = output.read_text(encoding="utf-8")
    assert document["host"] == "<REDACTED>"
    assert document["secrets"] == "not collected; provision separately"
    assert "100." not in encoded
    assert "34." not in encoded
    assert "PRIVATE_KEY" not in encoded

