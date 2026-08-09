from __future__ import annotations

import json
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest

from production.tools.runtime_dependency_receipt import (
    BUILD_ENVIRONMENT_SCHEMA,
    FROZEN_LOCK_SHA256,
    RuntimeDependencyReceiptError,
    _write_owner_only_json,
    create_receipt,
    create_runtime_manifest,
    create_wheel_manifest,
    validate_runtime_manifest,
    validate_wheel_manifest,
    verify_receipt,
)


REVISION = "a" * 40
SOURCE_SHA256 = "c08bc65a81971c1dd5783182826503369466c7e67374d1646519adf05207b684"


def _write_wheel(path: Path, project: str, version: str) -> None:
    metadata_path = f"{project.replace('-', '_')}-{version}.dist-info/METADATA"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(metadata_path, f"Metadata-Version: 2.1\nName: {project}\nVersion: {version}\n")
        if project == "setuptools":
            archive.writestr(
                "setuptools/_vendor/packaging-24.2.dist-info/METADATA",
                "Metadata-Version: 2.1\nName: packaging\nVersion: 24.2\n",
            )


def _build_environment(prefix: str) -> dict:
    return {
        "schema_version": BUILD_ENVIRONMENT_SCHEMA,
        "base_os": {"id": "debian", "version_id": "13"},
        "base_image": {"reference": "docker.io/library/debian:13-slim", "digest": "sha256:" + "b" * 64},
        "architecture": "x86_64",
        "compiler": {"name": "gcc", "version": "14.2.0"},
        "configure_flags": [f"--prefix={prefix}", "--with-ensurepip=install"],
        "build_packages": [{"name": "gcc", "version": "14.2.0"}],
        "libc": {"implementation": "glibc", "version": "2.41"},
        "openssl_version": "OpenSSL 3.5.0",
        "sqlite_version": "3.46.1",
        "python": {
            "implementation": "CPython", "version": "3.12.13",
            "abi": "cpython-312-x86_64-linux-gnu", "platform": "linux-x86_64",
            "executable_relative_path": "bin/python3.12",
        },
        "installation_prefix": prefix,
    }


def _tar_directory(source: Path, destination: Path, archive_root: str) -> None:
    with tarfile.open(destination, "w:gz") as archive:
        archive.add(source, arcname=archive_root, recursive=True)


def _tar_wheels(root: Path, lock: Path, destination: Path) -> None:
    with tarfile.open(destination, "w:gz") as archive:
        archive.add(lock, arcname=lock.name)
        for wheel in sorted(root.glob("*.whl")):
            archive.add(wheel, arcname="wheels/" + wheel.name)


def _fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    runtime_root = tmp_path / "runtime"
    (runtime_root / "bin").mkdir(parents=True)
    executable = runtime_root / "bin/python3.12"
    executable.write_bytes(b"python-runtime")
    executable.chmod(0o755)
    (runtime_root / "bin/python3").symlink_to("python3.12")
    prefix = "/opt/honeypot-python-runtimes/cpython-3.12.13-test"
    environment = artifact_root / "BUILD_ENVIRONMENT.json"
    environment.write_text(json.dumps(_build_environment(prefix)), encoding="utf-8")
    source = artifact_root / "Python-3.12.13.tar.xz"
    source.write_bytes(b"reviewed-source")
    import production.tools.runtime_dependency_receipt as module
    real_hash = module.sha256_file
    monkeypatch.setattr(module, "sha256_file", lambda path: SOURCE_SHA256 if path == source.resolve() else real_hash(path))
    runtime_manifest = create_runtime_manifest(
        runtime_root=runtime_root, source_archive=source,
        source_url="https://www.python.org/ftp/python/3.12.13/Python-3.12.13.tar.xz",
        build_environment_path=environment,
    )
    runtime_manifest_path = artifact_root / "PYTHON_RUNTIME_MANIFEST.json"
    _write_owner_only_json(runtime_manifest_path, runtime_manifest)
    runtime_archive = artifact_root / "python-runtime.tar.gz"
    _tar_directory(runtime_root, runtime_archive, runtime_manifest["archive_root"])

    lock = artifact_root / "requirements-next-behavior-corpus.lock.txt"
    lock_source = Path(__file__).resolve().parents[1] / lock.name
    shutil.copyfile(lock_source, lock)
    requirements = [line.split("==", 1) for line in lock.read_text(encoding="utf-8").splitlines() if line]
    wheel_root = tmp_path / "wheels"
    wheel_root.mkdir()
    for project, version in requirements:
        filename = f"{project.replace('-', '_')}-{version}-py3-none-any.whl"
        _write_wheel(wheel_root / filename, project, version)
    monkeypatch.setattr(module, "sha256_file", lambda path: SOURCE_SHA256 if path == source.resolve() else real_hash(path))
    wheel_manifest = create_wheel_manifest(
        wheel_root=wheel_root, lock_path=lock,
        indexes=["https://pypi.org/simple", "https://download.pytorch.org/whl/cpu"],
        resolver_version="25.0.1",
        download_arguments=["--only-binary=:all:", "--python-version=3.12"],
    )
    wheel_manifest_path = artifact_root / "WHEEL_BUNDLE_MANIFEST.json"
    _write_owner_only_json(wheel_manifest_path, wheel_manifest)
    wheel_archive = artifact_root / "python-wheels.tar.gz"
    for path in [lock, *wheel_root.glob("*.whl")]:
        path.chmod(0o600)
    _tar_wheels(wheel_root, lock, wheel_archive)
    application = artifact_root / "application.tar.gz"
    application.write_bytes(b"application")
    return locals()


def test_runtime_and_wheel_manifests_are_content_addressed_and_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    runtime = validate_runtime_manifest(fixture["runtime_manifest"])
    wheels = validate_wheel_manifest(fixture["wheel_manifest"])
    assert runtime["runtime_id"].startswith("python_runtime_")
    assert runtime["inventory"]["bin/python3"]["type"] == "symlink"
    assert wheels["bundle_id"].startswith("python_wheels_")
    assert len(wheels["wheels"]) == 37


def test_receipt_verifies_every_artifact_and_rejects_mutation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    receipt = create_receipt(
        artifact_root=fixture["artifact_root"], application_revision=REVISION,
        application_archive=fixture["application"], runtime_manifest_path=fixture["runtime_manifest_path"],
        runtime_archive=fixture["runtime_archive"], wheel_manifest_path=fixture["wheel_manifest_path"],
        wheel_archive=fixture["wheel_archive"],
    )
    receipt_path = fixture["artifact_root"] / "RUNTIME_DEPENDENCY_RECEIPT.json"
    _write_owner_only_json(receipt_path, receipt)
    assert receipt_path.stat().st_mode & 0o777 == 0o600
    verified = verify_receipt(receipt_path, fixture["artifact_root"])
    assert verified["verified"] is True
    assert verified["wheel_count"] == 37

    fixture["application"].write_bytes(b"mutated")
    with pytest.raises(RuntimeDependencyReceiptError, match="identity mismatch"):
        verify_receipt(receipt_path, fixture["artifact_root"])


def test_receipt_rejects_recomputed_manifest_with_nonfrozen_python(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    changed = json.loads(json.dumps(fixture["runtime_manifest"]))
    changed["build_environment"]["python"]["version"] = "3.13.5"
    with pytest.raises(RuntimeDependencyReceiptError, match="frozen CPython"):
        validate_runtime_manifest(changed)


def test_runtime_manifest_rejects_recomputed_missing_executable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    changed = json.loads(json.dumps(fixture["runtime_manifest"]))
    del changed["inventory"]["bin/python3.12"]
    from production.tools.runtime_dependency_receipt import _sha256_json
    changed["inventory_sha256"] = _sha256_json(changed["inventory"])
    basis = {
        "source": changed["source"], "build_environment": changed["build_environment"],
        "archive_root": changed["archive_root"], "inventory_sha256": changed["inventory_sha256"],
    }
    changed["runtime_id"] = "python_runtime_" + _sha256_json(basis)
    with pytest.raises(RuntimeDependencyReceiptError, match="omits frozen Python executable"):
        validate_runtime_manifest(changed)


def test_wheel_manifest_rejects_missing_or_extra_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    wheel_root = fixture["wheel_root"]
    next(iter(wheel_root.glob("*.whl"))).unlink()
    with pytest.raises(RuntimeDependencyReceiptError, match="wheel count"):
        create_wheel_manifest(
            wheel_root=wheel_root, lock_path=fixture["lock"],
            indexes=["https://pypi.org/simple", "https://download.pytorch.org/whl/cpu"],
            resolver_version="25.0.1",
            download_arguments=["--only-binary=:all:", "--python-version=3.12"],
        )


def test_archive_rejects_unmanifested_overlay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    overlay = tmp_path / "overlay"
    overlay.write_text("unexpected", encoding="utf-8")
    # A clean replacement tar containing the runtime plus an overlay must fail.
    with tarfile.open(fixture["runtime_archive"], "w:gz") as archive:
        archive.add(fixture["runtime_root"], arcname=fixture["runtime_manifest"]["archive_root"])
        archive.add(overlay, arcname=fixture["runtime_manifest"]["archive_root"] + "/overlay")
    with pytest.raises(RuntimeDependencyReceiptError, match="closed inventory"):
        create_receipt(
            artifact_root=fixture["artifact_root"], application_revision=REVISION,
            application_archive=fixture["application"], runtime_manifest_path=fixture["runtime_manifest_path"],
            runtime_archive=fixture["runtime_archive"], wheel_manifest_path=fixture["wheel_manifest_path"],
            wheel_archive=fixture["wheel_archive"],
        )


def test_receipt_rejects_symlinked_artifact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path, monkeypatch)
    link = fixture["artifact_root"] / "application-link.tar.gz"
    link.symlink_to(fixture["application"].name)
    with pytest.raises(RuntimeDependencyReceiptError, match="symlink"):
        create_receipt(
            artifact_root=fixture["artifact_root"], application_revision=REVISION,
            application_archive=link, runtime_manifest_path=fixture["runtime_manifest_path"],
            runtime_archive=fixture["runtime_archive"], wheel_manifest_path=fixture["wheel_manifest_path"],
            wheel_archive=fixture["wheel_archive"],
        )
