from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from production.reproduction.next_behavior.safe_export import (
    SelectedSafeCorpusError,
    _classification_provenance_source_hashes,
)


def _write_sources(root: Path, *, selected_store: str = "selected-v1") -> tuple[Path, Path]:
    selected = root / "production/reproduction/next_behavior/selected_store.py"
    selected.parent.mkdir(parents=True)
    selected.write_text(selected_store, encoding="utf-8")
    safe_export = root / "production/reproduction/next_behavior/safe_export.py"
    safe_export.write_text("safe-export-v1", encoding="utf-8")
    return selected, safe_export


def test_deleted_legacy_builder_cannot_satisfy_provenance_inventory(
    tmp_path: Path,
) -> None:
    legacy = tmp_path / "production/tools/build_next_behavior_selected_corpus.py"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy-builder", encoding="utf-8")
    safe_export = tmp_path / "production/reproduction/next_behavior/safe_export.py"
    safe_export.parent.mkdir(parents=True)
    safe_export.write_text("safe-export", encoding="utf-8")

    with pytest.raises(SelectedSafeCorpusError, match="selected_store.py"):
        _classification_provenance_source_hashes(
            tmp_path,
            safe_export_path=safe_export,
        )


def test_provenance_binds_canonical_selected_store_implementation(
    tmp_path: Path,
) -> None:
    selected, safe_export = _write_sources(tmp_path)

    hashes = _classification_provenance_source_hashes(
        tmp_path,
        safe_export_path=safe_export,
    )

    assert hashes["selected_builder_sha256"] == hashlib.sha256(
        selected.read_bytes()
    ).hexdigest()


def test_selected_store_source_identity_changes_when_bytes_change(
    tmp_path: Path,
) -> None:
    selected, safe_export = _write_sources(tmp_path)
    first = _classification_provenance_source_hashes(
        tmp_path,
        safe_export_path=safe_export,
    )["selected_builder_sha256"]

    selected.write_text("selected-v2", encoding="utf-8")
    second = _classification_provenance_source_hashes(
        tmp_path,
        safe_export_path=safe_export,
    )["selected_builder_sha256"]

    assert second != first


@pytest.mark.parametrize(
    "missing_kind",
    ["selected_store", "safe_export"],
)
def test_missing_required_provenance_input_fails_closed(
    tmp_path: Path,
    missing_kind: str,
) -> None:
    selected, safe_export = _write_sources(tmp_path)
    if missing_kind == "selected_store":
        selected.unlink()
    else:
        safe_export.unlink()

    with pytest.raises(SelectedSafeCorpusError, match="required provenance source"):
        _classification_provenance_source_hashes(
            tmp_path,
            safe_export_path=safe_export,
        )

