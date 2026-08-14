from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
import copy
from pathlib import Path

import pytest

from production.prediction.next_behavior_contract import TARGET_CONTRACT_ID
from production.prediction.trusted_history import SCHEMA_VERSION as HISTORY_SCHEMA
from production.reproduction.next_behavior.corpus import (
    build_privacy_safe_session,
    build_source_member_receipt,
)
from production.reproduction.next_behavior.selected_store import (
    _rebuild_sessions_reference,
    _refresh_quarantine,
    open_selected_database,
)
from production.reproduction.next_behavior.source_selection_v2 import (
    COMPLETE_STATUS,
    build_successor_member_inventory,
    load_source_selection_v2,
    require_valid_successor_member_inventory,
)
from production.reproduction.next_behavior.support_preflight import (
    INVENTORY_SCHEMA_VERSION,
    SupportPreflightError,
    build_development_donor_authorization,
    build_development_donor_semantics_binding,
    build_support_preflight_receipt,
    import_verified_development_donor,
    ingest_new_development_members,
    require_validated_successor_inventory,
    require_valid_support_preflight_receipt,
    require_valid_development_donor_import,
    require_valid_development_donor_semantics_binding,
    require_complete_support_store_classification,
    run_support_preflight_from_store,
    validate_support_preflight_receipt,
    write_support_preflight_receipt,
)
from production.utils.serialization import stable_id, stable_json


HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64
HEX_F = "f" * 64
KEY = b"support-preflight-key-material!!"  # exactly 32 bytes
KEY_FINGERPRINT = hashlib.sha256(KEY).hexdigest()
KEY_ID = "next-behavior-hmac-" + KEY_FINGERPRINT[:16]


@pytest.fixture
def support_storage(tmp_path):
    root = tmp_path / "reviewed-support-preflight"
    root.mkdir()

    def probe(path: Path) -> dict:
        return {
            "mount_target": str(path),
            "source": "/dev/test-support",
            "fstype": "ext4",
            "mount_options": ["rw"],
            "available_bytes": 100 * 1024**3,
            "writable": True,
        }

    return root, probe


def _semantics() -> dict:
    return {
        "classifier_manifest_sha256": HEX_A,
        "classifier_source_identity_sha256": HEX_B,
        "classifier_environment_sha256": HEX_A,
        "environment_lock_sha256": HEX_B,
        "classifier_adapter_sha256": HEX_C,
        "classification_pipeline_sha256": HEX_D,
        "rule_policy_sha256": HEX_C,
        "trust_policy_sha256": HEX_D,
        "mitre_cache_sha256": HEX_E,
        "checkpoint_sha256": HEX_E,
        "preprocessing_sha256": HEX_F,
        "label_adapter_sha256": HEX_F,
        "source_member_inventory_sha256": HEX_B,
        "target_contract_id": TARGET_CONTRACT_ID,
        "trusted_history_schema_version": HISTORY_SCHEMA,
        "max_trusted_phases": 8,
    }


def _member(
    name: str,
    order: int,
    role: str,
    *,
    sha256: str | None = None,
    size: int = 100,
    crc32: str = "1234abcd",
) -> dict:
    return {
        "filename": name,
        "chronological_order": order,
        "experiment_role": role,
        "source_cohort": "final" if role == "test" else "development",
        "collection_date": name[:10],
        "source_sha256": sha256 or hashlib.sha256(name.encode()).hexdigest(),
        "source_size_bytes": size,
        "archive_crc32": crc32,
    }


def _inventory(
    receipt_overrides: dict[str, dict] | None = None,
) -> dict:
    root = Path(__file__).resolve().parents[1]
    selection = copy.deepcopy(
        load_source_selection_v2(root / "configs/next_behavior_source_selection.v2.json")
    )
    overrides = receipt_overrides or {}
    selection["verification"] = {
        "status": COMPLETE_STATUS,
        "member_receipts": [
            {
                **member,
                "size_bytes": 1_000 + index,
                "archive_compressed_bytes": 900 + index,
                "archive_crc32": f"{index:08x}",
                "sha256": hashlib.sha256(member["filename"].encode()).hexdigest(),
                **overrides.get(member["filename"], {}),
            }
            for index, member in enumerate(selection["members"], start=1)
        ],
    }
    return build_successor_member_inventory(selection)


def _validator(value):
    return require_valid_successor_member_inventory(value)


def _historical_membership(
    *, root: Path, inventory: dict, session_ids: list[str] | None = None,
    key_id: str = KEY_ID, key_fingerprint: str = KEY_FINGERPRINT,
) -> tuple[dict, Path]:
    ids = sorted(session_ids or ["nbsession_" + "f" * 64])
    payload = b"".join(value.encode("ascii") + b"\n" for value in ids)
    membership_digest = hashlib.sha256()
    for value in ids:
        encoded = value.encode("ascii")
        membership_digest.update(len(encoded).to_bytes(4, "big"))
        membership_digest.update(encoded)
    test_rows = [row for row in inventory["members"] if row["role"] == "test"]
    lineage = hashlib.sha256(
        stable_json(
            sorted(
                [
                    {
                        "filename": row["filename"],
                        "source_sha256": row["sha256"],
                        "experiment_role": row["role"],
                    }
                    for row in test_rows
                ],
                key=lambda row: (row["filename"], row["source_sha256"]),
            )
        ).encode()
    ).hexdigest()
    path = root / "historical-test-membership.txt"
    path.write_bytes(payload)
    receipt = {
        "schema_version": "historical_test_session_membership.v1",
        "status": "sealed_pseudonymous_membership_frozen",
        "source_selection_sha256": inventory["source_selection_sha256"],
        "test_source_member_membership_sha256": lineage,
        "pseudonymization_key_id": key_id,
        "pseudonymization_key_fingerprint_sha256": key_fingerprint,
        "artifact_format": "sorted_unique_nbsession_sha256_lines.v1",
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "artifact_size_bytes": len(payload),
        "session_count": len(ids),
        "sorted_unique_membership_sha256": membership_digest.hexdigest(),
        "raw_content_emitted": False,
        "test_metrics_included": False,
    }
    receipt["receipt_id"] = stable_id("historicaltestsessionmembership", receipt)
    return receipt, path


def _label(tactic: str, technique: str, suffix: str) -> dict:
    return {
        "tactic": tactic,
        "technique": technique,
        "source": "reviewed_rule",
        "trust_tier": "trusted_observation",
        "policy_sha256": HEX_C,
        "trust_policy_sha256": HEX_D,
        "checkpoint_sha256": "",
        "confidence": None,
        "confidence_bucket": "not_applicable",
        "agreement_status": "rule_only",
        "evidence_ref": f"private:{suffix}",
    }


def _safe_session(role: str, index: int) -> dict:
    member = f"{role}.json.gz"
    receipt = build_source_member_receipt(
        private_member_identifier=member,
        source_sha256=HEX_A,
        byte_size=100,
        chronological_order={"train": 1, "selection": 2, "calibration": 3}[role],
        collection_start="2025-07-01T00:00:00Z",
        collection_end="2025-07-01T00:00:03Z",
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )
    private = {
        "session_id": f"{role}-private-{index}",
        "protocol": "ssh",
        "status": "closed",
        "configuration_id": "configuration-a",
        "observation_groups": [
            {
                "group_id": f"{role}:{index}:1",
                "event_order": 1,
                "observed_at": "2025-07-01T00:00:01Z",
                "labels": [_label("discovery", "T1087", "discovery")],
                "session_context": {
                    "login_outcome": "success",
                    "command_count_bucket": "1",
                    "session_age_bucket": "under_10s",
                    "confirmed_transfer_observed": False,
                },
            },
            {
                "group_id": f"{role}:{index}:2",
                "event_order": 2,
                "observed_at": "2025-07-01T00:00:02Z",
                "labels": [_label("execution", "T1059", "execution")],
                "session_context": {
                    "login_outcome": "success",
                    "command_count_bucket": "2-5",
                    "session_age_bucket": "under_10s",
                    "confirmed_transfer_observed": False,
                },
            },
            {
                "group_id": f"{role}:{index}:3",
                "event_order": 3,
                "observed_at": "2025-07-01T00:00:03Z",
                "labels": [_label("discovery", "T1083", "discovery-2")],
                "session_context": {
                    "login_outcome": "success",
                    "command_count_bucket": "2-5",
                    "session_age_bucket": "under_10s",
                    "confirmed_transfer_observed": False,
                },
            },
        ],
    }
    return build_privacy_safe_session(
        private,
        receipt,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
    )["safe_session"]


def _sessions(count: int = 30) -> dict:
    return {
        role: [_safe_session(role, index) for index in range(count)]
        for role in ("train", "selection", "calibration")
    }


def _build_receipt(
    *, root: Path, count: int = 30, require_discovery: bool = True
) -> dict:
    inventory = _inventory()
    historical = _historical_kwargs(root, inventory)
    return build_support_preflight_receipt(
        safe_sessions_by_role=_sessions(count),
        successor_inventory=inventory,
        inventory_validator=_validator,
        source_selection_sha256=inventory["source_selection_sha256"],
        frozen_semantics=_semantics(),
        classification_receipt_sha256=HEX_B,
        donor_import_receipt_sha256=None,
        pseudonymization_key_id=KEY_ID,
        pseudonymization_key_fingerprint_sha256=KEY_FINGERPRINT,
        require_selection_discovery=require_discovery,
        **historical,
    )


def _historical_kwargs(root: Path, inventory: dict) -> dict:
    receipt, artifact_path = _historical_membership(
        root=root, inventory=inventory
    )

    def probe(path: Path) -> dict:
        return {
            "mount_target": str(path),
            "source": "/dev/test-support",
            "fstype": "ext4",
            "mount_options": ["rw"],
            "available_bytes": 100 * 1024**3,
            "writable": True,
        }

    return {
        "historical_test_membership_receipt": receipt,
        "historical_test_membership_artifact_path": artifact_path,
        "reviewed_root": root,
        "mount_probe": probe,
    }


def test_support_receipt_uses_canonical_phases_examples_and_passes_30_30_gate(
    tmp_path: Path,
):
    receipt = _build_receipt(root=tmp_path)

    assert receipt["status"] == "support_gate_passed"
    assert receipt["target_contract_id"] == TARGET_CONTRACT_ID
    assert receipt["trusted_history_schema_version"] == HISTORY_SCHEMA
    assert receipt["max_trusted_phases"] == 8
    assert receipt["pseudonymization_key_id"] == KEY_ID
    assert receipt["pseudonymization_key_fingerprint_sha256"] == KEY_FINGERPRINT
    assert receipt["protections"] == {
        "test_members_accessed": False,
        "test_metrics_used": False,
        "raw_content_emitted": False,
        "unknown_or_unresolved_labels": 0,
        "role_membership_intersections": {
            "train_selection": 0,
            "train_calibration": 0,
            "selection_calibration": 0,
        },
        "source_member_partition_isolation": {
            "status": "verified_disjoint_from_validated_inventory",
            "identity_basis": "filename_and_source_sha256",
            "development_member_count": 24,
            "test_member_count": 7,
            "development_membership_sha256": receipt["protections"][
                "source_member_partition_isolation"
            ]["development_membership_sha256"],
            "test_membership_sha256": receipt["protections"][
                "source_member_partition_isolation"
            ]["test_membership_sha256"],
            "filename_intersection_count": 0,
            "content_sha256_intersection_count": 0,
        },
        "historical_test_session_membership": {
            "status": "verified_zero_intersection",
            "receipt_id": receipt["protections"][
                "historical_test_session_membership"
            ]["receipt_id"],
            "receipt_sha256": receipt["protections"][
                "historical_test_session_membership"
            ]["receipt_sha256"],
            "artifact_sha256": receipt["protections"][
                "historical_test_session_membership"
            ]["artifact_sha256"],
            "session_count": 1,
            "intersection_count": 0,
        },
    }
    for role in ("train", "selection", "calibration"):
        metrics = receipt["roles"][role]
        assert metrics["sessions"] == 30
        assert metrics["trusted_groups"] == 90
        assert metrics["trusted_labels"] == 90
        assert metrics["trusted_history_manifests"] == 30
        assert len(metrics["trusted_history_membership_sha256"]) == 64
        assert metrics["distinct_behavior_phases"] == 90
        assert metrics["examples"] == 90
        assert metrics["nonterminal_targets"] == 60
        assert metrics["terminal_targets"] == 30
        assert metrics["target_tactics"] == {"discovery": 30, "execution": 30}
        assert metrics["target_techniques"] == {"T1059": 30, "T1083": 30}
        assert metrics["target_tactic_technique_pairs"] == {
            "discovery|T1083": 30,
            "execution|T1059": 30,
        }
        assert metrics["terminal_to_nonterminal_ratio"] == "0.500000"
    assert require_valid_support_preflight_receipt(receipt) == receipt


def test_support_receipt_below_gate_is_valid_fail_closed_evidence(tmp_path: Path):
    receipt = _build_receipt(root=tmp_path, count=29)
    assert receipt["status"] == "support_gate_failed"
    assert receipt["gate"]["passed"] is False
    assert receipt["gate"]["requirements"]["selection.execution"]["passed"] is False


def test_support_receipt_detects_hash_gate_and_safety_tampering(tmp_path: Path):
    receipt = _build_receipt(root=tmp_path)
    receipt["roles"]["selection"]["terminal_targets"] = 0
    errors = validate_support_preflight_receipt(receipt)
    assert "aggregate support hash is inconsistent" in errors
    assert "support gate does not match aggregate support" in errors
    assert "support preflight receipt identity is invalid" in errors

    receipt = _build_receipt(root=tmp_path)
    receipt["protections"]["test_members_accessed"] = True
    with pytest.raises(SupportPreflightError, match="test_members_accessed"):
        require_valid_support_preflight_receipt(receipt)


def test_support_receipt_write_is_immutable_and_content_hashed(support_storage):
    root, probe = support_storage
    receipt = _build_receipt(root=root, count=1)
    path = root / "support-preflight.json"
    digest = write_support_preflight_receipt(
        path, receipt, reviewed_root=root, mount_probe=probe
    )
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert json.loads(path.read_text()) == receipt
    with pytest.raises(SupportPreflightError, match="already exists"):
        write_support_preflight_receipt(
            path, receipt, reviewed_root=root, mount_probe=probe
        )


def test_cross_role_session_overlap_fails_closed(tmp_path: Path):
    sessions = _sessions(1)
    sessions["selection"] = sessions["train"]
    inventory = _inventory()
    with pytest.raises(SupportPreflightError, match="overlap"):
        build_support_preflight_receipt(
            safe_sessions_by_role=sessions,
            successor_inventory=inventory,
            inventory_validator=_validator,
            source_selection_sha256=inventory["source_selection_sha256"],
            frozen_semantics=_semantics(),
            classification_receipt_sha256=HEX_B,
            donor_import_receipt_sha256=None,
            pseudonymization_key_id=KEY_ID,
            pseudonymization_key_fingerprint_sha256=KEY_FINGERPRINT,
            require_selection_discovery=True,
            **_historical_kwargs(tmp_path, inventory),
        )


def test_unknown_semantic_label_fails_closed_before_receipt(tmp_path: Path):
    sessions = _sessions(1)
    sessions["train"][0]["observation_groups"][0]["tactics"] = ["invented-tactic"]
    inventory = _inventory()
    with pytest.raises(SupportPreflightError, match="unknown tactic"):
        build_support_preflight_receipt(
            safe_sessions_by_role=sessions,
            successor_inventory=inventory,
            inventory_validator=_validator,
            source_selection_sha256=inventory["source_selection_sha256"],
            frozen_semantics=_semantics(),
            classification_receipt_sha256=HEX_B,
            donor_import_receipt_sha256=None,
            pseudonymization_key_id=KEY_ID,
            pseudonymization_key_fingerprint_sha256=KEY_FINGERPRINT,
            require_selection_discovery=True,
            **_historical_kwargs(tmp_path, inventory),
        )


def test_inventory_requires_external_reviewed_validator(tmp_path: Path):
    inventory = _inventory()
    with pytest.raises(SupportPreflightError, match="reviewed successor"):
        build_support_preflight_receipt(
            safe_sessions_by_role=_sessions(1),
            successor_inventory=inventory,
            inventory_validator=None,  # type: ignore[arg-type]
            source_selection_sha256=inventory["source_selection_sha256"],
            frozen_semantics=_semantics(),
            classification_receipt_sha256=HEX_B,
            donor_import_receipt_sha256=None,
            pseudonymization_key_id=KEY_ID,
            pseudonymization_key_fingerprint_sha256=KEY_FINGERPRINT,
            require_selection_discovery=True,
            **_historical_kwargs(tmp_path, inventory),
        )


def test_official_successor_inventory_validator_hook_is_compatible():
    root = Path(__file__).resolve().parents[1]
    selection = copy.deepcopy(
        load_source_selection_v2(root / "configs/next_behavior_source_selection.v2.json")
    )
    selection["verification"] = {
        "status": COMPLETE_STATUS,
        "member_receipts": [
            {
                **member,
                "size_bytes": 1_000 + index,
                "archive_compressed_bytes": 900 + index,
                "archive_crc32": f"{index:08x}",
                "sha256": hashlib.sha256(member["filename"].encode()).hexdigest(),
            }
            for index, member in enumerate(selection["members"], start=1)
        ],
    }
    inventory = build_successor_member_inventory(selection)
    assert require_validated_successor_inventory(
        inventory,
        inventory_validator=require_valid_successor_member_inventory,
    ) == inventory


def test_test_member_is_rejected_before_any_path_is_opened(
    tmp_path, monkeypatch, support_storage
):
    root, probe = support_storage
    inventory = _inventory()
    opened = []
    original = Path.open

    def record_open(self, *args, **kwargs):
        opened.append(self)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", record_open)
    with pytest.raises(SupportPreflightError, match="test or unknown"):
        ingest_new_development_members(
            private_database_path=root / "support.sqlite",
            raw_directory=tmp_path,
            successor_inventory=inventory,
            inventory_validator=_validator,
            new_member_names=["2025-08-09.json.gz"],
            source_selection_sha256=inventory["source_selection_sha256"],
            reviewed_root=root,
            mount_probe=probe,
        )
    assert opened == []


def _gzip_member(path: Path, events: list[dict]) -> tuple[str, int, str]:
    payload = "".join(json.dumps(event, sort_keys=True) + "\n" for event in events).encode()
    with path.open("wb") as raw_handle:
        with gzip.GzipFile(fileobj=raw_handle, mode="wb", mtime=0) as handle:
            handle.write(payload)
    raw = path.read_bytes()
    import zlib

    return hashlib.sha256(raw).hexdigest(), len(raw), f"{zlib.crc32(raw) & 0xffffffff:08x}"


def test_new_development_scanner_requires_complete_frozen_development_membership(
    tmp_path, support_storage
):
    root, probe = support_storage
    path = tmp_path / "2025-07-18.json.gz"
    events = [
        {"eventid": "cowrie.session.connect", "session": "s1", "ts": "2025-07-18T00:00:00Z", "protocol": "ssh"},
        {"eventid": "cowrie.command.input", "session": "s1", "ts": "2025-07-18T00:00:01Z", "input": "id"},
        {"eventid": "cowrie.session.closed", "session": "s1", "ts": "2025-07-18T00:00:02Z"},
    ]
    digest, size, crc32 = _gzip_member(path, events)
    inventory = _inventory(
        {
            path.name: {
                "sha256": digest,
                "size_bytes": size,
                "archive_compressed_bytes": size,
                "archive_crc32": crc32,
            }
        }
    )
    # An unverified empty/pre-populated store is rejected before member files
    # can substitute for the reviewed six-member donor lineage.
    with pytest.raises(SupportPreflightError, match="donor-import lineage"):
        ingest_new_development_members(
            private_database_path=root / "support.sqlite",
            raw_directory=tmp_path,
            successor_inventory=inventory,
            inventory_validator=_validator,
            new_member_names=[path.name],
            source_selection_sha256=inventory["source_selection_sha256"],
            flush_size=1,
            reviewed_root=root,
            mount_probe=probe,
        )
    with pytest.raises(SupportPreflightError, match="selection is inconsistent"):
        require_complete_support_store_classification(
            private_database_path=root / "support.sqlite",
            expected_receipt_sha256=HEX_B,
            source_selection_sha256=inventory["source_selection_sha256"],
            frozen_semantics=_semantics(),
            successor_inventory=inventory,
            inventory_validator=_validator,
            reviewed_root=root,
            mount_probe=probe,
        )


def _create_donor(path: Path, inventory: dict) -> tuple[dict, dict]:
    allowed = [
        "2025-07-03.json.gz",
        "2025-07-10.json.gz",
        "2025-07-17.json.gz",
        "2025-07-24.json.gz",
        "2025-07-31.json.gz",
        "2025-08-07.json.gz",
    ]
    source_selection_sha256 = inventory["source_selection_sha256"]
    preparation = {
        "receipt_id": "preparation-1",
        "status": "prepared",
        "classifier_manifest_sha256": HEX_A,
        "classifier_adapter_sha256": HEX_C,
        "classification_pipeline_sha256": HEX_D,
        "preprocessing_sha256": HEX_F,
        "environment_lock_sha256": HEX_B,
        "label_policy_sha256": HEX_C,
        "trust_policy_sha256": HEX_D,
        "mitre_cache_sha256": HEX_E,
        "classification_checkpoint_sha256": HEX_E,
    }
    classification = {
        "schema_version": "next_behavior_selected_classification.v1",
        "status": "classification_complete",
        "cache_receipt_id": "cache-1",
        "classifier_manifest_sha256": HEX_A,
        "checkpoint_sha256": HEX_E,
        "rule_policy_sha256": HEX_C,
        "trust_policy_sha256": HEX_D,
        "label_adapter_sha256": HEX_F,
        "ingested_source_members_sha256": HEX_B,
        "source_selection_sha256": source_selection_sha256,
        "raw_content_emitted": False,
    }
    db = open_selected_database(path)
    try:
        db.execute("INSERT INTO metadata(key, value) VALUES (?, ?)", ("source_selection_sha256", source_selection_sha256))
        db.execute("INSERT INTO metadata(key, value) VALUES (?, ?)", ("final_corpus_preparation_receipt_id", "preparation-1"))
        db.execute("INSERT INTO metadata(key, value) VALUES (?, ?)", ("final_corpus_preparation_receipt_json", stable_json(preparation)))
        for member in inventory["members"]:
            name = member["filename"]
            role = member["role"]
            cohort = "final" if role == "test" else "development"
            donor_order = int(member["chronological_order"])
            db.execute(
                "INSERT INTO source_members VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, member["sha256"], member["size_bytes"], member["archive_crc32"], donor_order, cohort, role, "2025-07-01T00:00:00Z", "2025-07-01T00:00:02Z", "{}"),
            )
            session = f"session-{name}"
            db.execute(
                "INSERT INTO session_sources VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (session, name, cohort, role, donor_order, "2025-07-01T00:00:00Z", "2025-07-01T00:00:02Z", "ssh", "", 1, 1),
            )
            db.execute(
                "INSERT INTO command_events VALUES (?, ?, ?, ?, ?)",
                (name, 1, session, "2025-07-01T00:00:01Z", f"id-{name}"),
            )
            labels = stable_json([_label("discovery", "T1087", role)])
            db.execute(
                "INSERT INTO command_labels VALUES (?, ?, ?, ?)",
                (f"id-{name}", labels, "{}", "cache-1"),
            )
        db.execute(
            "INSERT INTO classification_cache_receipts VALUES (?, ?)",
            ("cache-1", stable_json(classification)),
        )
        _rebuild_sessions_reference(db)
        _refresh_quarantine(db)
        db.commit()
    finally:
        db.close()
    preparation_sha256 = hashlib.sha256(
        stable_json(preparation).encode()
    ).hexdigest()
    classification_sha256 = hashlib.sha256(
        stable_json(classification).encode()
    ).hexdigest()
    semantics_binding = build_development_donor_semantics_binding(
        donor_source_selection_sha256=source_selection_sha256,
        donor_preparation_receipt_sha256=preparation_sha256,
        donor_classification_receipt_sha256=classification_sha256,
        frozen_semantics=_semantics(),
    )
    assert (
        require_valid_development_donor_semantics_binding(semantics_binding)
        == semantics_binding
    )
    authorization = build_development_donor_authorization(
        donor_source_selection_sha256=source_selection_sha256,
        donor_preparation_receipt_id="preparation-1",
        donor_preparation_receipt_sha256=preparation_sha256,
        donor_classification_receipt_sha256=classification_sha256,
        donor_semantics_binding_receipt_sha256=hashlib.sha256(
            stable_json(semantics_binding).encode()
        ).hexdigest(),
        allowed_development_members=allowed,
        frozen_semantics=_semantics(),
    )
    return authorization, semantics_binding


def test_verified_donor_imports_only_six_development_members(
    tmp_path, support_storage
):
    root, probe = support_storage
    successor_orders = (1, 2, 3, 10, 17, 24)
    inventory = _inventory()
    donor_path = tmp_path / "donor.sqlite"
    authorization, semantics_binding = _create_donor(donor_path, inventory)
    target_path = root / "support.sqlite"
    result = import_verified_development_donor(
        donor_database_path=donor_path,
        target_database_path=target_path,
        successor_inventory=inventory,
        inventory_validator=_validator,
        donor_authorization=authorization,
        donor_semantics_binding_receipt=semantics_binding,
        reviewed_root=root,
        mount_probe=probe,
    )
    assert result["status"] == "verified_development_only_import"
    assert result["source_member_count"] == 6
    assert result["test_members_accessed"] is False
    assert require_valid_development_donor_import(result) == result
    db = open_selected_database(target_path)
    try:
        assert db.execute("SELECT COUNT(*) FROM source_members").fetchone()[0] == 6
        assert db.execute("SELECT COUNT(*) FROM source_members WHERE experiment_role='test'").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM command_labels").fetchone()[0] == 6
        assert [row[0] for row in db.execute(
            "SELECT chronological_order FROM source_members "
            "ORDER BY chronological_order"
        )] == list(successor_orders)
        assert db.execute(
            "SELECT COUNT(*) FROM command_labels WHERE command LIKE '%08-09%'"
        ).fetchone()[0] == 0
        donor_lineage = dict(
            db.execute(
                "SELECT key, value FROM metadata WHERE key IN "
                "('support_donor_import_receipt_json', "
                "'support_donor_import_receipt_sha256')"
            )
        )
        assert json.loads(
            donor_lineage["support_donor_import_receipt_json"]
        ) == result
        assert donor_lineage["support_donor_import_receipt_sha256"] == hashlib.sha256(
            stable_json(result).encode()
        ).hexdigest()
        commands = [
            row[0]
            for row in db.execute(
                "SELECT DISTINCT command FROM command_events ORDER BY command"
            )
        ]
        support_classification = {
            "schema_version": "next_behavior_selected_classification.v1",
            "status": "classification_complete",
            "cache_receipt_id": "support-cache-1",
            "classifier_manifest_sha256": HEX_A,
            "checkpoint_sha256": HEX_E,
            "rule_policy_sha256": HEX_C,
            "trust_policy_sha256": HEX_D,
            "label_adapter_sha256": HEX_F,
            "ingested_source_members_sha256": HEX_B,
            "source_selection_sha256": inventory["source_selection_sha256"],
            "unique_command_count": len(commands),
            "exact_command_membership_sha256": hashlib.sha256(
                stable_json(commands).encode()
            ).hexdigest(),
            "raw_content_emitted": False,
        }
        db.execute(
            "INSERT INTO classification_cache_receipts VALUES (?, ?)",
            ("support-cache-1", stable_json(support_classification)),
        )
        db.commit()
        support_classification_sha256 = hashlib.sha256(
            stable_json(support_classification).encode()
        ).hexdigest()
    finally:
        db.close()
    historical_receipt, historical_path = _historical_membership(
        root=root, inventory=inventory
    )
    receipt = run_support_preflight_from_store(
        private_database_path=target_path,
        pseudonymization_key=KEY,
        pseudonymization_key_id=KEY_ID,
        successor_inventory=inventory,
        inventory_validator=_validator,
        source_selection_sha256=inventory["source_selection_sha256"],
        frozen_semantics=_semantics(),
        classification_receipt_sha256=support_classification_sha256,
        donor_import_receipt_sha256=None,
        historical_test_membership_receipt=historical_receipt,
        historical_test_membership_artifact_path=historical_path,
        require_selection_discovery=True,
        reviewed_root=root,
        mount_probe=probe,
    )
    assert receipt["status"] == "support_gate_failed"
    assert receipt["roles"]["train"]["sessions"] == 4
    assert receipt["roles"]["selection"]["sessions"] == 1
    assert receipt["roles"]["calibration"]["sessions"] == 1
    assert receipt["protections"]["test_members_accessed"] is False


@pytest.mark.parametrize("alias_kind", ["same_path", "hardlink"])
def test_donor_import_rejects_same_file_alias_without_mutation(
    alias_kind: str, support_storage
):
    root, probe = support_storage
    inventory = _inventory()
    donor_path = root / "donor.sqlite"
    authorization, semantics_binding = _create_donor(donor_path, inventory)
    target_path = donor_path
    if alias_kind == "hardlink":
        target_path = root / "support.sqlite"
        target_path.hardlink_to(donor_path)

    def snapshot() -> dict:
        result = {}
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(donor_path) + suffix)
            result[suffix] = (
                (path.read_bytes(), path.stat().st_mtime_ns)
                if path.exists()
                else None
            )
        return result

    before = snapshot()
    with pytest.raises(SupportPreflightError, match="identical|same inode"):
        import_verified_development_donor(
            donor_database_path=donor_path,
            target_database_path=target_path,
            successor_inventory=inventory,
            inventory_validator=_validator,
            donor_authorization=authorization,
            donor_semantics_binding_receipt=semantics_binding,
            reviewed_root=root,
            mount_probe=probe,
        )
    assert snapshot() == before


def test_donor_semantic_hash_mismatch_fails_closed(tmp_path, support_storage):
    root, probe = support_storage
    inventory = _inventory()
    donor_path = tmp_path / "donor.sqlite"
    authorization, semantics_binding = _create_donor(donor_path, inventory)
    bad_semantics = dict(authorization["frozen_semantics"])
    bad_semantics["rule_policy_sha256"] = HEX_F
    semantics_binding = build_development_donor_semantics_binding(
        donor_source_selection_sha256=authorization[
            "donor_source_selection_sha256"
        ],
        donor_preparation_receipt_sha256=authorization[
            "donor_preparation_receipt_sha256"
        ],
        donor_classification_receipt_sha256=authorization[
            "donor_classification_receipt_sha256"
        ],
        frozen_semantics=bad_semantics,
    )
    authorization = build_development_donor_authorization(
        donor_source_selection_sha256=authorization[
            "donor_source_selection_sha256"
        ],
        donor_preparation_receipt_id=authorization[
            "donor_preparation_receipt_id"
        ],
        donor_preparation_receipt_sha256=authorization[
            "donor_preparation_receipt_sha256"
        ],
        donor_classification_receipt_sha256=authorization[
            "donor_classification_receipt_sha256"
        ],
        donor_semantics_binding_receipt_sha256=hashlib.sha256(
            stable_json(semantics_binding).encode()
        ).hexdigest(),
        allowed_development_members=authorization[
            "allowed_development_members"
        ],
        frozen_semantics=bad_semantics,
    )
    with pytest.raises(SupportPreflightError, match="rule_policy_sha256"):
        import_verified_development_donor(
            donor_database_path=donor_path,
            target_database_path=root / "target.sqlite",
            successor_inventory=inventory,
            inventory_validator=_validator,
            donor_authorization=authorization,
            donor_semantics_binding_receipt=semantics_binding,
            reviewed_root=root,
            mount_probe=probe,
        )


def test_zero_length_wal_with_stale_shm_is_safe_for_immutable_donor(
    tmp_path, support_storage
):
    root, probe = support_storage
    inventory = _inventory()
    donor_path = tmp_path / "donor.sqlite"
    authorization, semantics_binding = _create_donor(donor_path, inventory)
    wal_path = Path(str(donor_path) + "-wal")
    shm_path = Path(str(donor_path) + "-shm")
    wal_path.write_bytes(b"")
    shm_path.write_bytes(b"\x00" * 32_768)

    result = import_verified_development_donor(
        donor_database_path=donor_path,
        target_database_path=root / "target.sqlite",
        successor_inventory=inventory,
        inventory_validator=_validator,
        donor_authorization=authorization,
        donor_semantics_binding_receipt=semantics_binding,
        reviewed_root=root,
        mount_probe=probe,
    )

    assert result["donor_side_files"] == {
        "main_database_size_bytes": donor_path.stat().st_size,
        "wal_exists": True,
        "wal_size_bytes": 0,
        "shm_exists": True,
        "shm_size_bytes": 32_768,
        "rollback_journal_exists": False,
        "immutable_main_database_quick_check": "ok",
    }
    assert wal_path.exists() and wal_path.stat().st_size == 0
    assert shm_path.exists() and shm_path.stat().st_size == 32_768
    assert require_valid_development_donor_import(result) == result


@pytest.mark.parametrize(
    ("suffix", "payload", "message"),
    [
        ("-wal", b"uncheckpointed", "non-empty uncheckpointed WAL"),
        ("-journal", b"", "rollback journal"),
    ],
)
def test_uncheckpointed_donor_side_files_fail_before_import(
    tmp_path, suffix, payload, message, support_storage
):
    root, probe = support_storage
    inventory = _inventory()
    donor_path = tmp_path / "donor.sqlite"
    authorization, semantics_binding = _create_donor(donor_path, inventory)
    Path(str(donor_path) + suffix).write_bytes(payload)

    with pytest.raises(SupportPreflightError, match=message):
        import_verified_development_donor(
            donor_database_path=donor_path,
            target_database_path=root / "target.sqlite",
            successor_inventory=inventory,
            inventory_validator=_validator,
            donor_authorization=authorization,
            donor_semantics_binding_receipt=semantics_binding,
            reviewed_root=root,
            mount_probe=probe,
        )
    assert not (root / "target.sqlite").exists()
