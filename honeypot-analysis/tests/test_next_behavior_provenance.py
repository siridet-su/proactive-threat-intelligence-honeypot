from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from production.reproduction.next_behavior import (
    safe_export as safe_export_module,
)
from production.reproduction.next_behavior import selected_store as selected_store_module
from production.reproduction.next_behavior import zenodo_corpus
from production.reproduction.next_behavior.safe_export import (
    SelectedSafeCorpusError,
    _CANONICAL_LABEL_ADAPTER_RELATIVE_PATH,
    _classification_provenance_source_hashes,
    build_selected_safe_corpus,
)
from production.prediction.next_behavior_label_policy import (
    normalize_classifier_outputs,
)
from production.reproduction.next_behavior.selected_store import (
    SelectedCorpusBuildError,
    _CANONICAL_ZENODO_CORPUS_RELATIVE_PATH,
    _require_classifier_bound_preprocessing,
    _selected_store_provenance_source_hashes,
)


ROOT = Path(__file__).resolve().parents[1]


def _write_sources(
    root: Path,
    *,
    selected_store: str = "selected-v1",
) -> tuple[Path, Path, Path]:
    selected = root / "production/reproduction/next_behavior/selected_store.py"
    selected.parent.mkdir(parents=True)
    selected.write_text(selected_store, encoding="utf-8")
    safe_export = root / "production/reproduction/next_behavior/safe_export.py"
    safe_export.write_text("safe-export-v1", encoding="utf-8")
    label_adapter = root / "production/prediction/next_behavior_label_policy.py"
    label_adapter.parent.mkdir(parents=True)
    label_adapter.write_text("label-adapter-v1", encoding="utf-8")
    return selected, safe_export, label_adapter


def test_deleted_legacy_builder_cannot_satisfy_provenance_inventory(
    tmp_path: Path,
) -> None:
    legacy = tmp_path / "production/tools/build_next_behavior_selected_corpus.py"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy-builder", encoding="utf-8")
    safe_export = tmp_path / "production/reproduction/next_behavior/safe_export.py"
    safe_export.parent.mkdir(parents=True)
    safe_export.write_text("safe-export", encoding="utf-8")
    label_adapter = tmp_path / "production/prediction/next_behavior_label_policy.py"
    label_adapter.parent.mkdir(parents=True)
    label_adapter.write_text("label-adapter", encoding="utf-8")

    with pytest.raises(SelectedSafeCorpusError, match="selected_store.py"):
        _classification_provenance_source_hashes(
            tmp_path,
            safe_export_path=safe_export,
        )


def test_provenance_binds_canonical_selected_store_implementation(
    tmp_path: Path,
) -> None:
    selected, safe_export, _label_adapter = _write_sources(tmp_path)

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
    selected, safe_export, _label_adapter = _write_sources(tmp_path)
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


def test_deleted_relative_label_adapter_cannot_satisfy_provenance_inventory(
    tmp_path: Path,
) -> None:
    selected = tmp_path / "production/reproduction/next_behavior/selected_store.py"
    selected.parent.mkdir(parents=True)
    selected.write_text("selected-store", encoding="utf-8")
    safe_export = tmp_path / "production/reproduction/next_behavior/safe_export.py"
    safe_export.write_text("safe-export", encoding="utf-8")
    stale = (
        tmp_path
        / "production/reproduction/prediction/next_behavior_label_policy.py"
    )
    stale.parent.mkdir(parents=True)
    stale.write_text("stale-label-adapter", encoding="utf-8")

    with pytest.raises(
        SelectedSafeCorpusError,
        match="production/prediction/next_behavior_label_policy.py",
    ):
        _classification_provenance_source_hashes(
            tmp_path,
            safe_export_path=safe_export,
        )


def test_provenance_binds_canonical_label_adapter_and_changes_with_bytes(
    tmp_path: Path,
) -> None:
    _selected, safe_export, label_adapter = _write_sources(tmp_path)
    first = _classification_provenance_source_hashes(
        tmp_path,
        safe_export_path=safe_export,
    )["label_adapter_sha256"]

    assert first == hashlib.sha256(label_adapter.read_bytes()).hexdigest()
    label_adapter.write_text("label-adapter-v2", encoding="utf-8")
    second = _classification_provenance_source_hashes(
        tmp_path,
        safe_export_path=safe_export,
    )["label_adapter_sha256"]
    assert second != first


def test_label_adapter_provenance_path_is_the_imported_implementation() -> None:
    imported_source = Path(normalize_classifier_outputs.__code__.co_filename)

    assert imported_source.resolve() == (
        ROOT / _CANONICAL_LABEL_ADAPTER_RELATIVE_PATH
    ).resolve()


def test_safe_build_rejects_missing_provenance_before_creating_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = tmp_path / "production/reproduction/next_behavior/selected_store.py"
    selected.parent.mkdir(parents=True)
    selected.write_text("selected-store", encoding="utf-8")
    output_root = tmp_path / "outputs"
    monkeypatch.setattr(
        safe_export_module,
        "_require_repository_commit",
        lambda _root, commit: commit,
    )

    with pytest.raises(
        SelectedSafeCorpusError,
        match="production/prediction/next_behavior_label_policy.py",
    ):
        build_selected_safe_corpus(
            purpose="fit_model",
            private_database_path=tmp_path / "private.sqlite",
            classifier_manifest_path=tmp_path / "classifier.json",
            preprocessing_manifest_path=tmp_path / "preprocessing.json",
            historical_payload_path=tmp_path / "historical.json",
            pseudonymization_key=b"x" * 32,
            pseudonymization_key_id="fixture-key",
            safe_sessions_path=output_root / "safe.jsonl",
            examples_path=output_root / "examples.jsonl",
            source_receipts_path=output_root / "sources.json",
            corpus_receipt_path=output_root / "corpus.json",
            build_receipt_path=output_root / "build.json",
            code_commit="fixture-commit",
            repository_root=tmp_path,
        )

    assert not output_root.exists()


@pytest.mark.parametrize(
    "missing_kind",
    ["selected_store", "safe_export", "label_adapter"],
)
def test_missing_required_provenance_input_fails_closed(
    tmp_path: Path,
    missing_kind: str,
) -> None:
    selected, safe_export, label_adapter = _write_sources(tmp_path)
    if missing_kind == "selected_store":
        selected.unlink()
    else:
        if missing_kind == "safe_export":
            safe_export.unlink()
        else:
            label_adapter.unlink()

    with pytest.raises(SelectedSafeCorpusError, match="required provenance source"):
        _classification_provenance_source_hashes(
            tmp_path,
            safe_export_path=safe_export,
        )


def _write_selected_store_provenance_sources(
    root: Path,
) -> tuple[Path, Path]:
    label_adapter = root / "production/prediction/next_behavior_label_policy.py"
    label_adapter.parent.mkdir(parents=True)
    label_adapter.write_text("label-adapter-v1", encoding="utf-8")
    corpus_builder = (
        root / "production/reproduction/next_behavior/zenodo_corpus.py"
    )
    corpus_builder.parent.mkdir(parents=True)
    corpus_builder.write_text("zenodo-corpus-v1", encoding="utf-8")
    return label_adapter, corpus_builder


def test_deleted_zenodo_builder_cannot_satisfy_donor_provenance(
    tmp_path: Path,
) -> None:
    label_adapter = tmp_path / "production/prediction/next_behavior_label_policy.py"
    label_adapter.parent.mkdir(parents=True)
    label_adapter.write_text("label-adapter", encoding="utf-8")
    stale = tmp_path / "production/tools/build_next_behavior_zenodo_corpus.py"
    stale.parent.mkdir(parents=True)
    stale.write_text("deleted-builder", encoding="utf-8")

    with pytest.raises(
        SelectedCorpusBuildError,
        match="production/reproduction/next_behavior/zenodo_corpus.py",
    ):
        _selected_store_provenance_source_hashes(tmp_path)


def test_donor_provenance_binds_canonical_zenodo_implementation_bytes(
    tmp_path: Path,
) -> None:
    _label_adapter, corpus_builder = _write_selected_store_provenance_sources(
        tmp_path
    )
    first = _selected_store_provenance_source_hashes(tmp_path)

    assert first["corpus_builder_sha256"] == hashlib.sha256(
        corpus_builder.read_bytes()
    ).hexdigest()
    corpus_builder.write_text("zenodo-corpus-v2", encoding="utf-8")
    second = _selected_store_provenance_source_hashes(tmp_path)
    assert second["corpus_builder_sha256"] != first["corpus_builder_sha256"]


def test_canonical_zenodo_provenance_path_is_the_tracked_module() -> None:
    imported_source = Path(zenodo_corpus.__file__ or "")

    assert imported_source.resolve() == (
        ROOT / _CANONICAL_ZENODO_CORPUS_RELATIVE_PATH
    ).resolve()
    assert (
        selected_store_module._CANONICAL_ZENODO_CORPUS_RELATIVE_PATH
        == _CANONICAL_ZENODO_CORPUS_RELATIVE_PATH
    )


def _preprocessing_policy(path: Path, digest: str) -> dict:
    return {
        "preprocessing_contract_path": path.as_posix(),
        "preprocessing_contract_sha256": digest,
        "target_contract_id": (
            "next_distinct_trusted_behavior_phase_or_session_end.v2"
        ),
        "trusted_history_schema_version": (
            "prediction_trusted_history_manifest.v3"
        ),
        "trusted_history_maximum_phases": 8,
    }


def _write_preprocessing(path: Path, *, maximum: int = 8) -> str:
    value = {
        "schema_version": "next_behavior_preprocessing.v2",
        "target_contract_id": (
            "next_distinct_trusted_behavior_phase_or_session_end.v2"
        ),
        "phase_construction": {"maximum_sequence_length": maximum},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_preparation_requires_exact_classifier_bound_preprocessing_path_and_bytes(
    tmp_path: Path,
) -> None:
    relative = Path("configs/preprocessing.json")
    bound = tmp_path / relative
    digest = _write_preprocessing(bound)
    policy = _preprocessing_policy(relative, digest)

    assert _require_classifier_bound_preprocessing(
        policy=policy,
        repository_root=tmp_path,
        supplied_path=bound,
    ) == digest

    alternate = tmp_path / "alternate.json"
    alternate.write_bytes(bound.read_bytes())
    with pytest.raises(SelectedCorpusBuildError, match="path is not classifier-bound"):
        _require_classifier_bound_preprocessing(
            policy=policy,
            repository_root=tmp_path,
            supplied_path=alternate,
        )

    policy["preprocessing_contract_sha256"] = "0" * 64
    with pytest.raises(SelectedCorpusBuildError, match="SHA-256 mismatch"):
        _require_classifier_bound_preprocessing(
            policy=policy,
            repository_root=tmp_path,
            supplied_path=bound,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value.update(schema_version="next_behavior_preprocessing.v1"),
            "semantic binding",
        ),
        (
            lambda value: value.update(target_contract_id="legacy-target.v1"),
            "semantic binding",
        ),
        (
            lambda value: value["phase_construction"].update(
                maximum_sequence_length=7
            ),
            "semantic binding",
        ),
    ],
)
def test_preparation_rejects_incompatible_preprocessing_semantics(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    relative = Path("configs/preprocessing.json")
    bound = tmp_path / relative
    _write_preprocessing(bound)
    value = json.loads(bound.read_text(encoding="utf-8"))
    mutation(value)
    bound.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    policy = _preprocessing_policy(
        relative,
        hashlib.sha256(bound.read_bytes()).hexdigest(),
    )

    with pytest.raises(SelectedCorpusBuildError, match=message):
        _require_classifier_bound_preprocessing(
            policy=policy,
            repository_root=tmp_path,
            supplied_path=bound,
        )
