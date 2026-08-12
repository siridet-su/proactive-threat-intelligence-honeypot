from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import production.ai_advisory.security as security


def _systemd_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    file_mode: int = 0o440,
    file_uid: int = 0,
    file_gid: int = 0,
    file_type: int = stat.S_IFREG,
    value: str = "mongodb://example.invalid/canonical",
) -> Path:
    mount_root = tmp_path / "credentials-root"
    credential_dir = mount_root / "unit.service"
    credential_dir.mkdir(parents=True)
    credential = credential_dir / "mongodb-uri"
    credential.write_text(value, encoding="utf-8")
    credential.chmod(file_mode)
    # The real mount is mode 0550; the fake stat below supplies that metadata
    # while keeping the temporary directory removable by the test runner.
    credential_dir.chmod(0o750)

    monkeypatch.setattr(security, "_SYSTEMD_CREDENTIALS_ROOT", mount_root)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(credential_dir))
    monkeypatch.setattr(
        security.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_flag=getattr(os, "ST_RDONLY", 1)),
    )
    real_stat = security.os.stat

    def fake_stat(path, *args, **kwargs):
        if Path(path) == credential_dir:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o550,
                st_uid=0,
                st_gid=0,
            )
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(security.os, "stat", fake_stat)
    real_fstat = security.os.fstat

    def fake_fstat(descriptor):
        metadata = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=file_type | file_mode,
            st_uid=file_uid,
            st_gid=file_gid,
            st_size=metadata.st_size,
        )

    monkeypatch.setattr(security.os, "fstat", fake_fstat)
    return credential


def test_systemd_loadcredential_accepts_reviewed_root_owned_0440_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential = _systemd_fixture(tmp_path, monkeypatch)

    assert security.read_mongodb_uri(str(credential)).endswith("/canonical")


@pytest.mark.parametrize(
    ("file_mode", "file_uid", "file_gid", "file_type"),
    [
        (0o600, 0, 0, stat.S_IFREG),  # owner-only but not the reviewed mount mode
        (0o444, 0, 0, stat.S_IFREG),  # world-readable
        (0o640, 0, 0, stat.S_IFREG),  # writable/group-readable variant
        (0o440, 1000, 0, stat.S_IFREG),  # unexpected owner
        (0o440, 0, 1000, stat.S_IFREG),  # unexpected group
        (0o440, 0, 0, stat.S_IFDIR),  # directory, not a file
    ],
)
def test_systemd_loadcredential_rejects_unsafe_representation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    file_mode: int,
    file_uid: int,
    file_gid: int,
    file_type: int,
) -> None:
    credential = _systemd_fixture(
        tmp_path,
        monkeypatch,
        file_mode=file_mode,
        file_uid=file_uid,
        file_gid=file_gid,
        file_type=file_type,
    )

    with pytest.raises(ValueError):
        security.read_mongodb_uri(str(credential))


def test_systemd_loadcredential_rejects_symlink_and_missing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential = _systemd_fixture(tmp_path, monkeypatch)
    target = credential.with_name("target")
    credential.parent.chmod(0o750)
    target.write_text("mongodb://example.invalid/target", encoding="utf-8")
    credential.unlink()
    credential.symlink_to(target)
    credential.parent.chmod(0o550)
    with pytest.raises(ValueError, match="symlink|unavailable"):
        security.read_mongodb_uri(str(credential))

    credential.parent.chmod(0o750)
    credential.unlink()
    credential.parent.chmod(0o550)
    with pytest.raises(ValueError, match="unavailable"):
        security.read_mongodb_uri(str(credential))
    credential.parent.chmod(0o750)
    target.unlink()
    credential.parent.rmdir()
    credential.parent.parent.rmdir()


def test_systemd_loadcredential_rejects_wrong_path_and_directory_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential = _systemd_fixture(tmp_path, monkeypatch)
    outside = tmp_path / "outside-uri"
    outside.write_text("mongodb://example.invalid/outside", encoding="utf-8")
    outside.chmod(0o600)
    with pytest.raises(ValueError, match="outside"):
        security.read_mongodb_uri(str(outside))

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "attacker-owned"))
    with pytest.raises(ValueError, match="invalid|unavailable|outside"):
        security.read_mongodb_uri(str(credential))

    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path / "credentials-root" / ".." / "other.service"))
    with pytest.raises(ValueError):
        security.read_mongodb_uri(str(credential))


@pytest.mark.parametrize("value", ["", "\x00"])
def test_systemd_loadcredential_rejects_empty_or_malformed_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    credential = _systemd_fixture(tmp_path, monkeypatch, value=value)
    with pytest.raises(ValueError):
        security.read_mongodb_uri(str(credential))


def test_ordinary_mongodb_uri_keeps_service_owned_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    ordinary = tmp_path / "mongodb-uri"
    ordinary.write_text("mongodb://example.invalid/ordinary", encoding="utf-8")
    ordinary.chmod(0o600)
    assert security.read_mongodb_uri(str(ordinary)).endswith("/ordinary")

    ordinary.chmod(0o640)
    with pytest.raises(ValueError, match="group or other"):
        security.read_mongodb_uri(str(ordinary))


def test_root_owned_ordinary_file_is_not_a_systemd_credential(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    ordinary = tmp_path / "mongodb-uri"
    ordinary.write_text("mongodb://example.invalid/root-owned", encoding="utf-8")
    ordinary.chmod(0o440)
    real_fstat = security.os.fstat

    def fake_fstat(descriptor):
        metadata = real_fstat(descriptor)
        return SimpleNamespace(
            st_mode=stat.S_IFREG | 0o440,
            st_uid=0,
            st_gid=0,
            st_size=metadata.st_size,
        )

    monkeypatch.setattr(security.os, "fstat", fake_fstat)
    with pytest.raises(ValueError, match="owned"):
        security.read_mongodb_uri(str(ordinary))
