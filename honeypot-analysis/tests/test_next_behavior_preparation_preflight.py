from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from production.reproduction.next_behavior import preparation_preflight as preflight
from production.reproduction.next_behavior.preparation_preflight import (
    EXPERIMENT_POLICY_SCHEMA_VERSION,
    MAXIMUM_PHASES,
    MEMBER_INVENTORY_SCHEMA_VERSION,
    PREPROCESSING_SCHEMA_VERSION,
    REQUEST_SCHEMA_VERSION,
    SOURCE_SELECTION_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    TRUSTED_HISTORY_SCHEMA_VERSION,
    NextBehaviorPreparationPreflightError,
    run_static_preflight,
    verify_static_preflight_receipt,
)


ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: dict) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "path": path.name,
        "artifact_byte_sha256": _sha256(path),
        "schema_version": value["schema_version"],
    }


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _initialize_repository(path: Path) -> tuple[str, str]:
    _git(path, "init", "-q")
    _git(path, "add", ".")
    _git(
        path,
        "-c",
        "user.name=Preflight Test",
        "-c",
        "user.email=preflight@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )
    return _git(path, "rev-parse", "HEAD"), _git(path, "rev-parse", "HEAD^{tree}")


def _mandatory_provenance(repository: Path) -> dict:
    required_files = []
    for relative in preflight.MANDATORY_SUCCESSOR_PREPARATION_SOURCE_PATHS:
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
        required_files.append({"path": relative, "sha256": _sha256(destination)})
    import_bindings = [
        {
            "importer_path": importer_path,
            "module": module,
            "source_path": source_path,
        }
        for importer_path, module, source_path in (
            preflight.MANDATORY_SUCCESSOR_PREPARATION_IMPORT_BINDINGS
        )
    ]
    return {
        "required_files": required_files,
        "import_bindings": import_bindings,
    }


def _preprocessing() -> dict:
    return {
        "schema_version": PREPROCESSING_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "phase_construction": {"maximum_sequence_length": MAXIMUM_PHASES},
    }


def _experiment_policy() -> dict:
    return json.loads(
        (ROOT / "configs" / "next_behavior_experiment_policy.v2.json").read_text(
            encoding="utf-8"
        )
    )


def _frozen_inputs(artifact_root: Path) -> dict:
    declarations = preflight._expected_successor_members()
    names = [declaration["filename"] for declaration in declarations]
    receipts = [
        {
            **declaration,
            "sha256": hashlib.sha256(name.encode()).hexdigest(),
            "size_bytes": 100 + index,
            "archive_compressed_bytes": 50 + index,
            "archive_crc32": f"{index:08x}",
        }
        for index, (name, declaration) in enumerate(zip(names, declarations))
    ]
    selection = {
        "schema_version": SOURCE_SELECTION_SCHEMA_VERSION,
        "selection_id": preflight._SUCCESSOR_SELECTION_ID,
        "preserved_source_selection": dict(preflight._EXPECTED_PRESERVED_SELECTION),
        "source": dict(preflight._EXPECTED_SOURCE),
        "archive": dict(preflight._EXPECTED_ARCHIVE),
        "policy": copy.deepcopy(preflight._EXPECTED_SELECTION_POLICY),
        "members": declarations,
        "verification": {
            "status": "archive_members_verified",
            "member_receipts": receipts,
        },
    }
    inventory = {
        "schema_version": MEMBER_INVENTORY_SCHEMA_VERSION,
        "status": "member_inventory_frozen",
        "test_members_sealed": True,
        "source_selection_id": selection["selection_id"],
        "source_selection_sha256": preflight._sha256_json(selection),
        "member_count": len(receipts),
        "role_counts": dict(preflight.SUCCESSOR_ROLE_COUNTS),
        "ordered_member_receipts_sha256": preflight._sha256_json(receipts),
        "members": receipts,
    }
    inventory["inventory_id"] = preflight.stable_id(
        "nextbehaviorsuccessorinventory", inventory
    )
    selection_path = artifact_root / "selection.json"
    inventory_path = artifact_root / "inventory.json"
    selection_pin = _write_json(selection_path, selection)
    inventory_pin = _write_json(inventory_path, inventory)
    selection_pin.update(
        {"path": str(selection_path), "contract_sha256": preflight._sha256_json(selection)}
    )
    inventory_pin.update(
        {"path": str(inventory_path), "contract_sha256": preflight._sha256_json(inventory)}
    )
    return {"source_selection": selection_pin, "member_inventory": inventory_pin}


def _request(repository: Path, workspace: Path) -> dict:
    provenance = _mandatory_provenance(repository)
    preprocessing_path = repository / "configs" / "next_behavior_preprocessing.v2.json"
    preprocessing = _write_json(preprocessing_path, _preprocessing())
    preprocessing["path"] = "configs/next_behavior_preprocessing.v2.json"
    preprocessing.update(
        {
            "target_contract_id": TARGET_CONTRACT_ID,
            "trusted_history_schema_version": TRUSTED_HISTORY_SCHEMA_VERSION,
            "maximum_phases": MAXIMUM_PHASES,
        }
    )
    experiment = _write_json(repository / "experiment.json", _experiment_policy())
    frozen_inputs = _frozen_inputs(workspace / "member-inventory")
    (repository / "classifier.json").write_text("{}\n", encoding="utf-8")
    commit, tree = _initialize_repository(repository)
    return {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "repository": {"commit": commit, "tree": tree},
        "provenance": provenance,
        "classifier_environment": {
            "path": "classifier.json",
            "artifact_byte_sha256": _sha256(repository / "classifier.json"),
            "schema_version": "next_behavior_classifier_environment.v4",
        },
        "classifier_model": {
            "model_root": str(workspace / "test-model"),
            "binding_receipt": {},
        },
        "preprocessing": preprocessing,
        "frozen_inputs": frozen_inputs,
        "experiment_policy": experiment,
        "runtime": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "sqlite_minimum_version": sqlite3.sqlite_version,
            "dependencies": [],
        },
        "capacity": {
            "minimum_free_bytes": preflight.SAME_FILESYSTEM_MINIMUM_FREE_BYTES,
            "minimum_mem_available_bytes": preflight.MINIMUM_MEM_AVAILABLE_BYTES,
            "minimum_swap_free_bytes": preflight.MINIMUM_SWAP_FREE_BYTES,
        },
        "output_workspace": str(workspace),
    }


def _patch_classifier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        preflight,
        "_verify_classifier_environment",
        lambda _root, _value: {
            "schema_version": "next_behavior_classifier_environment.v4",
            "artifact_byte_sha256": "a" * 64,
            "source_identity_sha256": "b" * 64,
            "python": {
                "implementation": platform.python_implementation(),
                "version": platform.python_version(),
            },
            "dependency_lock": {"pins": []},
            "classification_policy": {
                "target_contract_id": TARGET_CONTRACT_ID,
                "trusted_history_schema_version": TRUSTED_HISTORY_SCHEMA_VERSION,
                "trusted_history_maximum_phases": MAXIMUM_PHASES,
                "files": [
                    {
                        "path": "configs/next_behavior_preprocessing.v2.json",
                        "sha256": _sha256(
                            _root / "configs" / "next_behavior_preprocessing.v2.json"
                        ),
                    }
                ],
            },
        },
    )
    monkeypatch.setattr(
        preflight,
        "_verify_classifier_model",
        lambda *_args, **_kwargs: {
            "checkpoint_sha256": "c" * 64,
            "full_asset_verification_status": "assets_verified",
        },
    )


def _patch_reviewed_host(
    monkeypatch: pytest.MonkeyPatch,
    reviewed_root: Path,
) -> None:
    monkeypatch.setattr(preflight, "REVIEWED_OUTPUT_ROOT", reviewed_root)
    observed = shutil.disk_usage(reviewed_root)
    frozen = observed._replace(
        total=128 * 1024**3,
        used=28 * 1024**3,
        free=100 * 1024**3,
    )
    monkeypatch.setattr(preflight.shutil, "disk_usage", lambda _path: frozen)
    monkeypatch.setattr(
        preflight,
        "_mount_identity",
        lambda path: {
            "target": str(reviewed_root),
            "source": "/dev/test-successor",
            "filesystem_type": "ext4",
            "options": ["rw"],
            "device_major_minor": "0:1",
            "st_dev": path.stat().st_dev,
        },
    )


def _meminfo(
    path: Path,
    *,
    available: int = 16 * 1024**2,
    swap: int = 8 * 1024**2,
) -> Path:
    path.write_text(
        f"MemAvailable: {available} kB\nSwapFree: {swap} kB\n",
        encoding="ascii",
    )
    return path


def test_static_preflight_emits_only_deterministic_readiness_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    reviewed_root = tmp_path / "next-behavior-successor"
    workspace = reviewed_root / "future-selected-store"
    repository.mkdir()
    workspace.mkdir(parents=True)
    _patch_reviewed_host(monkeypatch, reviewed_root)
    request = _request(repository, workspace)
    _patch_classifier(monkeypatch)
    before = sorted(path.relative_to(reviewed_root) for path in reviewed_root.rglob("*"))

    first = run_static_preflight(
        request,
        repository_root=repository,
        meminfo_path=_meminfo(tmp_path / "meminfo"),
    )
    second = run_static_preflight(
        copy.deepcopy(request),
        repository_root=repository,
        meminfo_path=tmp_path / "meminfo",
    )

    assert first == second
    assert (
        verify_static_preflight_receipt(
            first,
            request=request,
            repository_root=repository,
            meminfo_path=tmp_path / "meminfo",
        )
        == first
    )
    assert first["scope"] == {
        "corpus_database_opened": False,
        "source_archive_opened": False,
        "source_members_ingested": 0,
        "commands_classified": 0,
        "model_trained": False,
        "model_evaluated": False,
        "preparation_authorized": False,
    }
    after = sorted(path.relative_to(reviewed_root) for path in reviewed_root.rglob("*"))
    assert after == before


def test_repository_commit_tree_and_cleanliness_are_all_required(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "tracked").write_text("one\n", encoding="utf-8")
    commit, tree = _initialize_repository(repository)
    assert preflight._verify_repository(
        repository, {"commit": commit, "tree": tree}
    )["clean"] is True

    with pytest.raises(NextBehaviorPreparationPreflightError, match="commit mismatch"):
        preflight._verify_repository(
            repository, {"commit": "0" * 40, "tree": tree}
        )
    (repository / "untracked").write_text("drift\n", encoding="utf-8")
    with pytest.raises(NextBehaviorPreparationPreflightError, match="not clean"):
        preflight._verify_repository(repository, {"commit": commit, "tree": tree})


def test_complete_mandatory_provenance_inventory_is_accepted(tmp_path: Path) -> None:
    good = _mandatory_provenance(tmp_path)
    result = preflight._verify_provenance(tmp_path, good)
    assert tuple(item["path"] for item in result["required_files"]) == (
        preflight.MANDATORY_SUCCESSOR_PREPARATION_SOURCE_PATHS
    )
    assert len(result["import_bindings"]) == len(
        preflight.MANDATORY_SUCCESSOR_PREPARATION_IMPORT_BINDINGS
    )


def test_provenance_rejects_omitted_required_source(tmp_path: Path) -> None:
    request = _mandatory_provenance(tmp_path)
    request["required_files"].pop()
    with pytest.raises(NextBehaviorPreparationPreflightError, match="inventory mismatch"):
        preflight._verify_provenance(tmp_path, request)

def test_provenance_rejects_extra_or_substituted_source(tmp_path: Path) -> None:
    request = _mandatory_provenance(tmp_path)
    extra = tmp_path / "production" / "replacement.py"
    extra.write_text("# not reviewed\n", encoding="utf-8")
    request["required_files"].pop()
    request["required_files"].append(
        {"path": "production/replacement.py", "sha256": _sha256(extra)}
    )
    with pytest.raises(NextBehaviorPreparationPreflightError, match="inventory mismatch"):
        preflight._verify_provenance(tmp_path, request)

    request = _mandatory_provenance(tmp_path)
    request["required_files"].append(
        {"path": "production/replacement.py", "sha256": _sha256(extra)}
    )
    with pytest.raises(NextBehaviorPreparationPreflightError, match="inventory mismatch"):
        preflight._verify_provenance(tmp_path, request)


def test_provenance_requires_successor_inventory_implementations(
    tmp_path: Path,
) -> None:
    request = _mandatory_provenance(tmp_path)
    request["required_files"] = [
        item
        for item in request["required_files"]
        if item["path"]
        != "production/reproduction/next_behavior/successor_members.py"
    ]
    with pytest.raises(NextBehaviorPreparationPreflightError, match="inventory mismatch"):
        preflight._verify_provenance(tmp_path, request)

    request = _mandatory_provenance(tmp_path)
    for item in request["required_files"]:
        if item["path"] == (
            "production/reproduction/next_behavior/successor_contracts.py"
        ):
            item["path"] = "production/reproduction/next_behavior/replacement_contracts.py"
            break
    with pytest.raises(NextBehaviorPreparationPreflightError, match="inventory mismatch"):
        preflight._verify_provenance(tmp_path, request)


def test_provenance_rejects_missing_or_renamed_required_path(tmp_path: Path) -> None:
    request = _mandatory_provenance(tmp_path)
    relative = "production/prediction/next_behavior_label_policy.py"
    original = tmp_path / relative
    original.rename(original.with_name("renamed_label_policy.py"))
    with pytest.raises(NextBehaviorPreparationPreflightError, match="missing"):
        preflight._verify_provenance(tmp_path, request)


def test_provenance_rejects_false_ast_import_binding(tmp_path: Path) -> None:
    request = _mandatory_provenance(tmp_path)
    relative = "production/reproduction/next_behavior/safe_export.py"
    importer = tmp_path / relative
    source = importer.read_text(encoding="utf-8")
    source = source.replace(
        "from production.prediction.next_behavior_label_policy import (",
        "from production.prediction.next_behavior_model import (",
        1,
    )
    importer.write_text(source, encoding="utf-8")
    for item in request["required_files"]:
        if item["path"] == relative:
            item["sha256"] = _sha256(importer)
            break
    with pytest.raises(NextBehaviorPreparationPreflightError, match="AST import graph"):
        preflight._verify_provenance(tmp_path, request)


def test_provenance_rejects_omitted_or_substituted_import_binding(
    tmp_path: Path,
) -> None:
    request = _mandatory_provenance(tmp_path)
    request["import_bindings"].pop()
    with pytest.raises(
        NextBehaviorPreparationPreflightError,
        match="import-binding inventory mismatch",
    ):
        preflight._verify_provenance(tmp_path, request)

    request = _mandatory_provenance(tmp_path)
    request["import_bindings"][0] = {
        "importer_path": "production/reproduction/next_behavior/safe_export.py",
        "module": "production.prediction.next_behavior_model",
        "source_path": "production/prediction/next_behavior_model.py",
    }
    with pytest.raises(
        NextBehaviorPreparationPreflightError,
        match="import-binding inventory mismatch",
    ):
        preflight._verify_provenance(tmp_path, request)


def test_provenance_rejects_symlink_and_byte_change(tmp_path: Path) -> None:
    request = _mandatory_provenance(tmp_path)
    relative = "production/prediction/next_behavior_label_policy.py"
    source = tmp_path / relative
    source.write_text(source.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    with pytest.raises(NextBehaviorPreparationPreflightError, match="SHA-256 mismatch"):
        preflight._verify_provenance(tmp_path, request)

    request = _mandatory_provenance(tmp_path)
    source = tmp_path / relative
    backing = tmp_path / "label-policy-backing.py"
    source.rename(backing)
    source.symlink_to(backing)
    for item in request["required_files"]:
        if item["path"] == relative:
            item["sha256"] = _sha256(source)
            break
    with pytest.raises(NextBehaviorPreparationPreflightError, match="symlink"):
        preflight._verify_provenance(tmp_path, request)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(target_contract_id="wrong.v1"), "target contract"),
        (
            lambda value: value["phase_construction"].update(maximum_sequence_length=7),
            "maximum sequence",
        ),
    ],
)
def test_preprocessing_contract_mismatches_fail_closed(
    tmp_path: Path, mutation, message: str
) -> None:
    contract = _preprocessing()
    mutation(contract)
    path = tmp_path / "configs" / "next_behavior_preprocessing.v2.json"
    binding = _write_json(path, contract)
    binding["path"] = "configs/next_behavior_preprocessing.v2.json"
    binding.update(
        {
            "target_contract_id": TARGET_CONTRACT_ID,
            "trusted_history_schema_version": TRUSTED_HISTORY_SCHEMA_VERSION,
            "maximum_phases": MAXIMUM_PHASES,
        }
    )
    classifier = {
        "classification_policy": {
            "target_contract_id": TARGET_CONTRACT_ID,
            "files": [
                {
                    "path": "configs/next_behavior_preprocessing.v2.json",
                    "sha256": binding["artifact_byte_sha256"],
                }
            ],
        }
    }
    with pytest.raises(NextBehaviorPreparationPreflightError, match=message):
        preflight._verify_preprocessing(tmp_path, binding, classifier)


def test_preprocessing_requires_exact_classifier_bound_bytes(tmp_path: Path) -> None:
    path = tmp_path / "configs" / "next_behavior_preprocessing.v2.json"
    binding = _write_json(path, _preprocessing())
    binding["path"] = "configs/next_behavior_preprocessing.v2.json"
    binding.update(
        {
            "target_contract_id": TARGET_CONTRACT_ID,
            "trusted_history_schema_version": TRUSTED_HISTORY_SCHEMA_VERSION,
            "maximum_phases": MAXIMUM_PHASES,
        }
    )
    classifier = {
        "classification_policy": {
            "target_contract_id": TARGET_CONTRACT_ID,
            "files": [
                {
                    "path": "configs/next_behavior_preprocessing.v2.json",
                    "sha256": "0" * 64,
                }
            ],
        }
    }
    with pytest.raises(NextBehaviorPreparationPreflightError, match="exact preprocessing"):
        preflight._verify_preprocessing(tmp_path, binding, classifier)


def test_frozen_source_and_inventory_must_match_exactly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preflight, "REVIEWED_OUTPUT_ROOT", tmp_path)
    inputs = _frozen_inputs(tmp_path / "member-inventory")
    result = preflight._verify_frozen_inputs(tmp_path, inputs)
    assert result["member_count"] == 31

    inventory_path = tmp_path / "member-inventory" / "inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["members"].reverse()
    inputs["member_inventory"] = _write_json(inventory_path, inventory)
    inputs["member_inventory"].update(
        {
            "path": str(inventory_path),
            "contract_sha256": preflight._sha256_json(inventory),
        }
    )
    with pytest.raises(NextBehaviorPreparationPreflightError, match="membership mismatch"):
        preflight._verify_frozen_inputs(tmp_path, inputs)


def test_pre_staging_boundary_accepts_declaration_without_member_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    support_root = tmp_path / "support-preflight"
    support_root.mkdir()
    monkeypatch.setattr(preflight, "REVIEWED_OUTPUT_ROOT", tmp_path)
    support_module = __import__(
        "production.reproduction.next_behavior.support_preflight",
        fromlist=["_verify_historical_test_membership_artifact"],
    )
    monkeypatch.setattr(
        support_module,
        "SUPPORT_PREFLIGHT_ROOT",
        support_root,
    )
    monkeypatch.setattr(preflight, "SUPPORT_PREFLIGHT_ROOT", support_root)
    receipt = {
        "schema_version": "historical_test_session_membership.v1",
        "status": "sealed_pseudonymous_membership_frozen",
        "source_selection_sha256": preflight.HISTORICAL_SOURCE_SELECTION_SHA256,
        "test_source_member_membership_sha256": "1" * 64,
        "pseudonymization_key_id": preflight.HISTORICAL_PSEUDONYMIZATION_KEY_ID,
        "pseudonymization_key_fingerprint_sha256": (
            preflight.HISTORICAL_PSEUDONYMIZATION_KEY_FINGERPRINT_SHA256
        ),
        "artifact_format": "sorted_unique_nbsession_sha256_lines.v1",
        "artifact_sha256": "3" * 64,
        "artifact_size_bytes": 1,
        "session_count": preflight.HISTORICAL_TEST_SESSION_COUNT,
        "sorted_unique_membership_sha256": "4" * 64,
        "raw_content_emitted": False,
        "test_metrics_included": False,
    }
    receipt["receipt_id"] = preflight.stable_id(
        "historicaltestsessionmembership", receipt
    )
    receipt_path = support_root / "membership.receipt.json"
    artifact_path = support_root / "membership.txt"
    artifact_path.write_text("nbsession_" + "a" * 64 + "\n", encoding="ascii")
    receipt["artifact_sha256"] = _sha256(artifact_path)
    receipt["artifact_size_bytes"] = artifact_path.stat().st_size
    receipt["receipt_id"] = preflight.stable_id(
        "historicaltestsessionmembership",
        {key: item for key, item in receipt.items() if key != "receipt_id"},
    )
    receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    monkeypatch.setattr(
        support_module,
        "require_valid_historical_test_session_membership",
        lambda value: value,
    )
    monkeypatch.setattr(
        preflight,
        "require_valid_historical_test_session_membership",
        lambda value: value,
    )
    monkeypatch.setattr(
        support_module,
        "_verify_historical_test_membership_artifact",
        lambda **_kwargs: {"status": "verified_zero_intersection"},
    )
    monkeypatch.setattr(
        preflight,
        "_verify_historical_test_membership_artifact",
        lambda **_kwargs: {"status": "verified_zero_intersection"},
    )
    monkeypatch.setattr(
        preflight,
        "_head_source_archive",
        lambda _url: {
            "http_status": 200,
            "content_length_bytes": preflight._EXPECTED_ARCHIVE["size_bytes"],
            "accept_ranges": "bytes",
        },
    )
    selection_pin = {
        "path": "configs/next_behavior_source_selection.v2.json",
        "artifact_byte_sha256": _sha256(
            ROOT / "configs/next_behavior_source_selection.v2.json"
        ),
        "schema_version": SOURCE_SELECTION_SCHEMA_VERSION,
    }
    stage_a = {
        "stage": preflight.PRE_STAGING_STAGE,
        "source_selection": selection_pin,
        "source_archive_availability": {
            "schema_version": preflight.SOURCE_ARCHIVE_AVAILABILITY_SCHEMA_VERSION,
            "url": preflight._EXPECTED_ARCHIVE["download_url"],
            "expected_size_bytes": preflight._EXPECTED_ARCHIVE["size_bytes"],
            "expected_md5": preflight._EXPECTED_ARCHIVE["checksum"].removeprefix(
                "md5:"
            ),
        },
        "historical_test_membership": {
            "receipt_path": str(receipt_path),
            "receipt_byte_sha256": _sha256(receipt_path),
            "artifact_path": str(artifact_path),
            "artifact_byte_sha256": _sha256(artifact_path),
            "role_inventory_session_count": preflight.HISTORICAL_TEST_SESSION_COUNT,
            "role_inventory_session_membership_sha256": (
                preflight.HISTORICAL_TEST_SESSION_MEMBERSHIP_SHA256
            ),
        },
    }
    result = preflight._verify_frozen_inputs(ROOT, stage_a)
    assert result["stage"] == preflight.PRE_STAGING_STAGE
    assert result["declared_member_count"] == 31
    assert result["historical_test_membership"]["session_count"] == (
        preflight.HISTORICAL_TEST_SESSION_COUNT
    )


def test_pre_staging_boundary_rejects_completed_inventory(
    tmp_path: Path,
) -> None:
    inputs = _frozen_inputs(tmp_path / "member-inventory")
    inputs["stage"] = preflight.PRE_STAGING_STAGE
    with pytest.raises(NextBehaviorPreparationPreflightError, match="fields"):
        preflight._verify_frozen_inputs(ROOT, inputs)


def test_external_artifact_pin_accepts_distinct_byte_and_contract_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reviewed_root = tmp_path / "reviewed"
    reviewed_root.mkdir()
    monkeypatch.setattr(preflight, "REVIEWED_OUTPUT_ROOT", reviewed_root)
    value = {"schema_version": SOURCE_SELECTION_SCHEMA_VERSION, "value": 1}
    path = reviewed_root / "selection.json"
    pin = _write_json(path, value)
    pin.update(
        {"path": str(path), "contract_sha256": preflight._sha256_json(value)}
    )
    loaded, evidence = preflight._verify_external_pinned_json(
        pin,
        label="source_selection",
        expected_schema=SOURCE_SELECTION_SCHEMA_VERSION,
    )
    assert loaded == value
    assert evidence["artifact_byte_sha256"] == _sha256(path)
    assert evidence["contract_sha256"] == preflight._sha256_json(value)
    assert evidence["artifact_byte_sha256"] != evidence["contract_sha256"]


def test_external_artifact_pin_rejects_escape_and_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reviewed_root = tmp_path / "reviewed"
    reviewed_root.mkdir()
    monkeypatch.setattr(preflight, "REVIEWED_OUTPUT_ROOT", reviewed_root)
    value = {"schema_version": SOURCE_SELECTION_SCHEMA_VERSION}
    outside = tmp_path / "outside.json"
    pin = _write_json(outside, value)
    pin.update(
        {"path": str(outside), "contract_sha256": preflight._sha256_json(value)}
    )
    with pytest.raises(NextBehaviorPreparationPreflightError, match="escapes"):
        preflight._verify_external_pinned_json(
            pin,
            label="source_selection",
            expected_schema=SOURCE_SELECTION_SCHEMA_VERSION,
        )

    link = reviewed_root / "linked.json"
    link.symlink_to(outside)
    pin["path"] = str(link)
    with pytest.raises(NextBehaviorPreparationPreflightError, match="symlink"):
        preflight._verify_external_pinned_json(
            pin,
            label="source_selection",
            expected_schema=SOURCE_SELECTION_SCHEMA_VERSION,
        )


def test_external_artifact_pin_rejects_byte_contract_hash_confusion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reviewed_root = tmp_path / "reviewed"
    reviewed_root.mkdir()
    monkeypatch.setattr(preflight, "REVIEWED_OUTPUT_ROOT", reviewed_root)
    value = {"schema_version": SOURCE_SELECTION_SCHEMA_VERSION, "value": 1}
    path = reviewed_root / "selection.json"
    pin = _write_json(path, value)
    contract_hash = preflight._sha256_json(value)
    byte_hash = _sha256(path)
    assert byte_hash != contract_hash

    confused = dict(pin)
    confused.update(
        {"path": str(path), "artifact_byte_sha256": contract_hash, "contract_sha256": contract_hash}
    )
    with pytest.raises(NextBehaviorPreparationPreflightError, match="byte SHA-256"):
        preflight._verify_external_pinned_json(
            confused,
            label="source_selection",
            expected_schema=SOURCE_SELECTION_SCHEMA_VERSION,
        )

    confused["artifact_byte_sha256"] = byte_hash
    confused["contract_sha256"] = byte_hash
    with pytest.raises(NextBehaviorPreparationPreflightError, match="contract SHA-256"):
        preflight._verify_external_pinned_json(
            confused,
            label="source_selection",
            expected_schema=SOURCE_SELECTION_SCHEMA_VERSION,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target_contract_id", "legacy.v1", "target contract"),
    ],
)
def test_experiment_policy_mismatches_fail_closed(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    policy = _experiment_policy()
    policy[field] = value
    binding = _write_json(tmp_path / "experiment.json", policy)
    with pytest.raises(NextBehaviorPreparationPreflightError, match=message):
        preflight._verify_experiment_policy(
            tmp_path, binding, {"target_contract_id": TARGET_CONTRACT_ID}
        )


def test_experiment_policy_cannot_use_test_metrics_or_production_authority(
    tmp_path: Path,
) -> None:
    for mutation, message in (
        (lambda policy: policy["selection"].update(test_metrics_used=True), "selection"),
        (
            lambda policy: policy["authority"].update(production_change_allowed=True),
            "authority",
        ),
    ):
        policy = _experiment_policy()
        mutation(policy)
        binding = _write_json(tmp_path / "experiment.json", policy)
        with pytest.raises(NextBehaviorPreparationPreflightError, match=message):
            preflight._verify_experiment_policy(
                tmp_path, binding, {"target_contract_id": TARGET_CONTRACT_ID}
            )


def test_output_workspace_rejects_permission_read_only_directory(tmp_path: Path) -> None:
    workspace = tmp_path / "readonly"
    workspace.mkdir()
    workspace.chmod(0o555)
    try:
        with pytest.raises(NextBehaviorPreparationPreflightError, match="not writable"):
            preflight._probe_workspace(workspace)
    finally:
        workspace.chmod(0o755)


def test_output_workspace_rejects_read_only_mount_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = os.statvfs(tmp_path)

    class ReadOnlyStat:
        f_flag = original.f_flag | getattr(os, "ST_RDONLY", 1)

    monkeypatch.setattr(preflight.os, "statvfs", lambda _path: ReadOnlyStat())
    monkeypatch.setattr(preflight.os, "ST_RDONLY", getattr(os, "ST_RDONLY", 1), raising=False)
    with pytest.raises(NextBehaviorPreparationPreflightError, match="read-only"):
        preflight._probe_workspace(tmp_path)


def test_capacity_rejects_caller_lowered_reviewed_floors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preflight, "_mount_identity", lambda _path: {})
    capacity = {
        "minimum_free_bytes": 1,
        "minimum_mem_available_bytes": 1,
        "minimum_swap_free_bytes": 1,
    }
    with pytest.raises(NextBehaviorPreparationPreflightError, match="60 GiB"):
        preflight._verify_capacity(
            tmp_path,
            capacity,
            meminfo_path=_meminfo(tmp_path / "meminfo"),
        )


def test_capacity_rejects_disk_memory_and_swap_shortfalls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preflight, "_mount_identity", lambda _path: {})
    monkeypatch.setattr(preflight, "REVIEWED_OUTPUT_ROOT", tmp_path)
    base = {
        "minimum_free_bytes": preflight.SAME_FILESYSTEM_MINIMUM_FREE_BYTES,
        "minimum_mem_available_bytes": preflight.MINIMUM_MEM_AVAILABLE_BYTES,
        "minimum_swap_free_bytes": preflight.MINIMUM_SWAP_FREE_BYTES,
    }
    observed = shutil.disk_usage(tmp_path)
    low_disk = observed._replace(
        total=128 * 1024**3,
        used=69 * 1024**3,
        free=59 * 1024**3,
    )
    monkeypatch.setattr(preflight.shutil, "disk_usage", lambda _path: low_disk)
    with pytest.raises(NextBehaviorPreparationPreflightError, match="free space"):
        preflight._verify_capacity(
            tmp_path,
            base,
            meminfo_path=_meminfo(tmp_path / "meminfo"),
        )

    enough_disk = observed._replace(
        total=128 * 1024**3,
        used=28 * 1024**3,
        free=100 * 1024**3,
    )
    monkeypatch.setattr(preflight.shutil, "disk_usage", lambda _path: enough_disk)
    with pytest.raises(NextBehaviorPreparationPreflightError, match="memory"):
        preflight._verify_capacity(
            tmp_path,
            base,
            meminfo_path=_meminfo(
                tmp_path / "low-memory",
                available=9 * 1024**2,
            ),
        )
    with pytest.raises(NextBehaviorPreparationPreflightError, match="swap"):
        preflight._verify_capacity(
            tmp_path,
            base,
            meminfo_path=_meminfo(
                tmp_path / "low-swap",
                swap=5 * 1024**2,
            ),
        )


def test_output_workspace_must_be_under_reviewed_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reviewed_root = tmp_path / "reviewed"
    outside = tmp_path / "outside"
    reviewed_root.mkdir()
    outside.mkdir()
    monkeypatch.setattr(preflight, "REVIEWED_OUTPUT_ROOT", reviewed_root)
    with pytest.raises(NextBehaviorPreparationPreflightError, match="outside"):
        preflight._reviewed_workspace(outside)


@pytest.mark.parametrize(
    ("filesystem_type", "options", "message"),
    [
        ("btrfs", "rw,relatime", "ext4"),
        ("ext4", "ro,relatime", "writable"),
    ],
)
def test_mount_identity_rejects_non_ext4_or_read_only_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filesystem_type: str,
    options: str,
    message: str,
) -> None:
    device = tmp_path.stat().st_dev
    payload = {
        "filesystems": [
            {
                "target": str(tmp_path),
                "source": "/dev/test",
                "fstype": filesystem_type,
                "options": options,
                "maj:min": f"{os.major(device)}:{os.minor(device)}",
            }
        ]
    }

    class Completed:
        stdout = json.dumps(payload)

    monkeypatch.setattr(preflight.subprocess, "run", lambda *args, **kwargs: Completed())
    with pytest.raises(NextBehaviorPreparationPreflightError, match=message):
        preflight._mount_identity(tmp_path)


@pytest.mark.parametrize(
    ("target", "source", "message"),
    [
        ("/", "/dev/test", "dedicated /mnt/honeypot-data"),
        ("/mnt/honeypot-data", "overlay", "block device"),
    ],
)
def test_mount_identity_rejects_wrong_target_or_non_block_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    source: str,
    message: str,
) -> None:
    device = tmp_path.stat().st_dev
    payload = {
        "filesystems": [
            {
                "target": target,
                "source": source,
                "fstype": "ext4",
                "options": "rw,relatime",
                "maj:min": f"{os.major(device)}:{os.minor(device)}",
            }
        ]
    }

    class Completed:
        stdout = json.dumps(payload)

    monkeypatch.setattr(preflight.subprocess, "run", lambda *args, **kwargs: Completed())
    with pytest.raises(NextBehaviorPreparationPreflightError, match=message):
        preflight._mount_identity(tmp_path)


def test_runtime_requires_exact_python_sqlite_and_dependency_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "sqlite_minimum_version": sqlite3.sqlite_version,
        "dependencies": [],
    }
    assert preflight._verify_runtime(good)["python_version"] == platform.python_version()

    wrong = copy.deepcopy(good)
    wrong["python_version"] = "0.0.0"
    with pytest.raises(NextBehaviorPreparationPreflightError, match="Python runtime"):
        preflight._verify_runtime(wrong)

    wrong = copy.deepcopy(good)
    wrong["sqlite_minimum_version"] = "999.0.0"
    with pytest.raises(NextBehaviorPreparationPreflightError, match="SQLite runtime"):
        preflight._verify_runtime(wrong)

    wrong = copy.deepcopy(good)
    wrong["dependencies"] = [
        {"distribution": "definitely-not-installed-preflight", "version": "1.0"}
    ]
    with pytest.raises(NextBehaviorPreparationPreflightError, match="missing"):
        preflight._verify_runtime(wrong)


def test_runtime_must_match_classifier_environment_python_binding() -> None:
    runtime = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "sqlite_minimum_version": sqlite3.sqlite_version,
        "dependencies": [],
    }
    required = {
        "implementation": platform.python_implementation(),
        "version": "0.0.0",
    }
    with pytest.raises(
        NextBehaviorPreparationPreflightError,
        match="classifier environment",
    ):
        preflight._verify_runtime(runtime, required_python=required)


def test_repository_classifier_environment_and_source_identity_are_current() -> None:
    path = ROOT / "configs" / "next_behavior_classifier_environment.v1.json"
    result = preflight._verify_classifier_environment(
        ROOT,
        {
            "path": "configs/next_behavior_classifier_environment.v1.json",
            "artifact_byte_sha256": _sha256(path),
            "schema_version": "next_behavior_classifier_environment.v4",
        },
    )
    assert result["source_identity_sha256"] == (
        "fbbf3c60caa2d0650cdaba1254fec6a650cfb985a52a4be93d2ce4eb2bd49ffe"
    )
    assert result["python"] == {"implementation": "CPython", "version": "3.12.13"}
    assert result["classification_policy"]["target_contract_id"] == TARGET_CONTRACT_ID


def test_classifier_model_assets_are_fully_bound_and_checkpoint_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reviewed_root = tmp_path / "reviewed"
    model_root = tmp_path / "private-model"
    repository = tmp_path / "repository"
    reviewed_root.mkdir()
    model_root.mkdir()
    repository.mkdir()
    monkeypatch.setattr(preflight, "REVIEWED_OUTPUT_ROOT", reviewed_root)
    environment_path = repository / "classifier.json"
    environment_path.write_text("{}\n", encoding="utf-8")
    assets = {
        "config.json": b"config\n",
        "tokenizer.json": b"tokenizer\n",
        "checkpoint-1/model.safetensors": b"checkpoint\n",
    }
    model_hashes = {}
    for relative, content in assets.items():
        path = model_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        model_hashes[relative] = _sha256(path)
    manifest = {
        "classifier": {
            "adapter_sha256": "1" * 64,
            "pipeline_sha256": "2" * 64,
            "operation_parser_sha256": "3" * 64,
            "splitter_sha256": "4" * 64,
            "checkpoint_id": "checkpoint-1",
            "checkpoint_sha256": model_hashes["checkpoint-1/model.safetensors"],
            "files": model_hashes,
        }
    }
    environment_hash = _sha256(environment_path)
    receipt = {
        "schema_version": preflight.MODEL_ROOT_BINDING_SCHEMA_VERSION,
        "status": "model_root_frozen",
        "model_root": str(model_root),
        "classifier_environment_artifact_byte_sha256": environment_hash,
        "checkpoint_id": "checkpoint-1",
        "checkpoint_sha256": model_hashes["checkpoint-1/model.safetensors"],
        "files": model_hashes,
    }
    receipt_path = reviewed_root / "model-root-receipt.json"
    receipt_pin = _write_json(receipt_path, receipt)
    receipt_pin.update(
        {"path": str(receipt_path), "contract_sha256": preflight._sha256_json(receipt)}
    )
    binding = {"model_root": str(model_root), "binding_receipt": receipt_pin}
    monkeypatch.setattr(preflight, "load_classifier_manifest", lambda _path: manifest)
    monkeypatch.setattr(
        preflight,
        "verify_classifier_assets",
        lambda *_args, **_kwargs: {"status": "assets_verified"},
    )
    result = preflight._verify_classifier_model(
        repository,
        {
            "path": "classifier.json",
            "artifact_byte_sha256": environment_hash,
            "schema_version": "next_behavior_classifier_environment.v4",
        },
        {"artifact_byte_sha256": environment_hash},
        binding,
    )
    assert result["checkpoint_sha256"] == model_hashes[
        "checkpoint-1/model.safetensors"
    ]
    assert result["adapter_sha256"] == "1" * 64
    assert result["pipeline_sha256"] == "2" * 64
    assert result["operation_parser_sha256"] == "3" * 64
    assert result["splitter_sha256"] == "4" * 64
    assert result["full_asset_verification_status"] == "assets_verified"

    checkpoint = model_root / "checkpoint-1" / "model.safetensors"
    checkpoint.unlink()
    with pytest.raises(NextBehaviorPreparationPreflightError, match="missing.*checkpoint"):
        preflight._verify_classifier_model(
            repository,
            {"path": "classifier.json"},
            {"artifact_byte_sha256": environment_hash},
            binding,
        )
    checkpoint.write_bytes(b"tampered\n")
    with pytest.raises(NextBehaviorPreparationPreflightError, match="SHA-256 mismatch"):
        preflight._verify_classifier_model(
            repository,
            {"path": "classifier.json"},
            {"artifact_byte_sha256": environment_hash},
            binding,
        )


def test_repository_successor_experiment_policy_matches_static_gate() -> None:
    path = ROOT / "configs" / "next_behavior_experiment_policy.v2.json"
    result = preflight._verify_experiment_policy(
        ROOT,
        {
            "path": "configs/next_behavior_experiment_policy.v2.json",
            "artifact_byte_sha256": _sha256(path),
            "schema_version": EXPERIMENT_POLICY_SCHEMA_VERSION,
        },
        {
            "target_contract_id": TARGET_CONTRACT_ID,
            "trusted_history_schema_version": TRUSTED_HISTORY_SCHEMA_VERSION,
        },
    )
    assert result["target_contract_id"] == TARGET_CONTRACT_ID
    assert result["maximum_phases"] == 8
    assert result["test_metrics_used"] is False


def test_tampered_receipt_and_runtime_claims_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    reviewed_root = tmp_path / "next-behavior-successor"
    workspace = reviewed_root / "future-selected-store"
    repository.mkdir()
    workspace.mkdir(parents=True)
    _patch_reviewed_host(monkeypatch, reviewed_root)
    request = _request(repository, workspace)
    _patch_classifier(monkeypatch)
    receipt = run_static_preflight(
        request,
        repository_root=repository,
        meminfo_path=_meminfo(tmp_path / "meminfo"),
    )
    tampered = copy.deepcopy(receipt)
    tampered["capacity"]["filesystem"]["free_bytes"] += 1
    with pytest.raises(NextBehaviorPreparationPreflightError, match="SHA-256 mismatch"):
        verify_static_preflight_receipt(
            tampered,
            request=request,
            repository_root=repository,
            meminfo_path=tmp_path / "meminfo",
        )


def test_self_hashed_nested_receipt_forgery_fails_full_revalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    reviewed_root = tmp_path / "next-behavior-successor"
    workspace = reviewed_root / "future-selected-store"
    repository.mkdir()
    workspace.mkdir(parents=True)
    _patch_reviewed_host(monkeypatch, reviewed_root)
    request = _request(repository, workspace)
    _patch_classifier(monkeypatch)
    meminfo = _meminfo(tmp_path / "meminfo")
    receipt = run_static_preflight(
        request,
        repository_root=repository,
        meminfo_path=meminfo,
    )
    for field in (
        "provenance",
        "classifier_environment",
        "classifier_model",
        "preprocessing",
        "frozen_inputs",
        "experiment_policy",
        "runtime",
        "output_workspace",
        "capacity",
    ):
        forged = copy.deepcopy(receipt)
        forged[field] = None
        unhashed = {key: item for key, item in forged.items() if key != "receipt_sha256"}
        forged["receipt_sha256"] = preflight._sha256_json(unhashed)
        with pytest.raises(
            NextBehaviorPreparationPreflightError,
            match="nested evidence",
        ):
            verify_static_preflight_receipt(
                forged,
                request=request,
                repository_root=repository,
                meminfo_path=meminfo,
            )

    tampered = copy.deepcopy(receipt)
    tampered["scope"]["commands_classified"] = 1
    with pytest.raises(NextBehaviorPreparationPreflightError, match="non-static"):
        verify_static_preflight_receipt(
            tampered,
            request=request,
            repository_root=repository,
            meminfo_path=tmp_path / "meminfo",
        )
