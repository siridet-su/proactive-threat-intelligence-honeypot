from __future__ import annotations

import copy
import hashlib
import json

import pytest

from production.storage.mongodb_epoch import load_storage_epoch, verify_runtime_deployment
from production.tools.storage_epoch_version_revision import (
    CHANGED_FIELDS,
    RECEIPT_NAME,
    REVIEW_NAME,
    prepare_version_revision,
    verify_version_revision,
)
from production.utils.serialization import stable_json
from tests.test_mongodb_epoch import _receipt, _runtime_metadata


def _setup(tmp_path):
    source, _ = _receipt(tmp_path)
    data = source.read_bytes()
    return {
        "source_path": source,
        "expected_source_sha256": hashlib.sha256(data).hexdigest(),
        "expected_source_version": "8.0.29",
        "reviewed_version": "8.0.34",
        "output_dir": tmp_path / "reviewed",
    }, data


def _prepare(kwargs):
    return prepare_version_revision(**kwargs, approval_reference="synthetic-owner-review")


def test_revision_preserves_every_nonversion_field_and_historical_bytes(tmp_path):
    kwargs, original = _setup(tmp_path)
    result = _prepare(kwargs)
    assert kwargs["source_path"].read_bytes() == original
    source = load_storage_epoch(kwargs["source_path"])
    revised = load_storage_epoch(kwargs["output_dir"] / RECEIPT_NAME)
    expected = copy.deepcopy(source)
    expected["deployment_identity"]["mongodb_server_version"] = "8.0.34"
    expected["receipt_sha256"] = revised["receipt_sha256"]
    assert revised == expected
    assert revised["receipt_sha256"] != source["receipt_sha256"]
    assert result["epoch_identity_preserved"] is True
    assert result["runtime_guard_modified"] is False
    assert result["activated"] is False
    review = json.loads((kwargs["output_dir"] / REVIEW_NAME).read_text())
    assert review["changed_fields"] == CHANGED_FIELDS
    assert kwargs["output_dir"].stat().st_mode & 0o777 == 0o700
    for name in (RECEIPT_NAME, REVIEW_NAME):
        assert (kwargs["output_dir"] / name).stat().st_mode & 0o777 == 0o600
    assert verify_version_revision(**kwargs) == result


def test_preparation_refuses_existing_directory_without_overwrite(tmp_path):
    kwargs, _ = _setup(tmp_path)
    _prepare(kwargs)
    before = {p.name: p.read_bytes() for p in kwargs["output_dir"].iterdir()}
    with pytest.raises(FileExistsError):
        _prepare(kwargs)
    assert {p.name: p.read_bytes() for p in kwargs["output_dir"].iterdir()} == before


@pytest.mark.parametrize("new", ["8.0.29", "8.0.28", "8.1.1", "9.0.1", "8.0.34-rc1", "8.00.34", "8.0"])
def test_unreviewed_version_transition_rejected_before_output(tmp_path, new):
    kwargs, _ = _setup(tmp_path)
    kwargs["reviewed_version"] = new
    with pytest.raises(ValueError):
        _prepare(kwargs)
    assert not kwargs["output_dir"].exists()


@pytest.mark.parametrize("field,value", [
    ("expected_source_sha256", "0" * 64),
    ("expected_source_sha256", "not-a-hash"),
    ("expected_source_version", "8.0.32"),
])
def test_source_requires_both_external_hash_and_expected_version(tmp_path, field, value):
    kwargs, data = _setup(tmp_path)
    kwargs[field] = value
    with pytest.raises(ValueError):
        _prepare(kwargs)
    assert kwargs["source_path"].read_bytes() == data
    assert not kwargs["output_dir"].exists()


@pytest.mark.parametrize("reference", ["", " ", "owner\nnew-line", "x" * 256])
def test_approval_reference_must_be_explicit_bounded_metadata(tmp_path, reference):
    kwargs, _ = _setup(tmp_path)
    with pytest.raises(ValueError, match="approval reference"):
        prepare_version_revision(**kwargs, approval_reference=reference)
    assert not kwargs["output_dir"].exists()


def test_receipt_refuses_symlink_destination_parent(tmp_path):
    kwargs, _ = _setup(tmp_path)
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    kwargs["output_dir"] = alias / "reviewed"
    with pytest.raises(ValueError, match="symlink"):
        _prepare(kwargs)
    assert not (real / "reviewed").exists()


def test_receipt_refuses_output_inside_git_checkout(tmp_path):
    kwargs, _ = _setup(tmp_path)
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    kwargs["output_dir"] = root / "private"
    with pytest.raises(ValueError, match="outside Git"):
        _prepare(kwargs)
    assert not kwargs["output_dir"].exists()


@pytest.mark.parametrize("field", ["epoch_id", "rollback_mirror", "first_eligible_event_cutoff", "database", "provenance_rules"])
def test_verification_rejects_rehashed_nonversion_change(tmp_path, field):
    kwargs, _ = _setup(tmp_path)
    _prepare(kwargs)
    path = kwargs["output_dir"] / RECEIPT_NAME
    receipt = json.loads(path.read_text())
    if field == "epoch_id":
        # Also rebind the inner mirror hash, so rejection is not just bad hashing.
        receipt[field] = "different-epoch"
        receipt["rollback_mirror"]["epoch_id"] = receipt[field]
        receipt["rollback_mirror"]["identity_id"] = hashlib.sha256(stable_json({
            k: v for k, v in receipt["rollback_mirror"].items() if k != "identity_id"
        }).encode()).hexdigest()
    elif field == "rollback_mirror":
        receipt[field]["path"] = "/var/lib/honeypot/other-mirror.db"
        receipt[field]["identity_id"] = hashlib.sha256(stable_json({
            k: v for k, v in receipt[field].items() if k != "identity_id"
        }).encode()).hexdigest()
    elif field == "first_eligible_event_cutoff":
        receipt[field]["event_id"] = "different-cutoff"
        receipt["previous_sqlite_archive"]["cutoff"] = copy.deepcopy(receipt[field])
    elif field == "database":
        receipt[field] = "other-db"
    else:
        receipt[field]["attacker_command_markers_authoritative"] = True
    receipt["receipt_sha256"] = hashlib.sha256(stable_json({
        k: v for k, v in receipt.items() if k != "receipt_sha256"
    }).encode()).hexdigest()
    path.write_text(stable_json(receipt))
    with pytest.raises(ValueError):
        verify_version_revision(**kwargs)


def test_audit_cannot_claim_disabled_guard_even_with_new_hash(tmp_path):
    kwargs, _ = _setup(tmp_path)
    _prepare(kwargs)
    path = kwargs["output_dir"] / REVIEW_NAME
    review = json.loads(path.read_text())
    review["runtime_guard_modified"] = True
    review["review_sha256"] = hashlib.sha256(stable_json({
        k: v for k, v in review.items() if k != "review_sha256"
    }).encode()).hexdigest()
    path.write_text(stable_json(review))
    with pytest.raises(ValueError, match="inconsistent"):
        verify_version_revision(**kwargs)


@pytest.mark.parametrize("field,value", [("prepared_at", "not-a-timestamp"), ("prepared_at", "2026-10-06T00:00:00+07:00"), ("activated", 0)])
def test_audit_validates_utc_and_exact_boolean_types(tmp_path, field, value):
    kwargs, _ = _setup(tmp_path)
    _prepare(kwargs)
    path = kwargs["output_dir"] / REVIEW_NAME
    review = json.loads(path.read_text())
    review[field] = value
    review["review_sha256"] = hashlib.sha256(stable_json({
        k: v for k, v in review.items() if k != "review_sha256"
    }).encode()).hexdigest()
    path.write_text(stable_json(review))
    with pytest.raises(ValueError):
        verify_version_revision(**kwargs)


def test_runtime_version_guard_accepts_only_reviewed_version(tmp_path):
    kwargs, _ = _setup(tmp_path)
    _prepare(kwargs)
    receipt = load_storage_epoch(kwargs["output_dir"] / RECEIPT_NAME)

    class Database:
        def command(self, name):
            assert name == "hello"
            return {"isWritablePrimary": True, "setName": receipt["deployment_identity"]["replica_set_name"]}

    class Client:
        version = "8.0.34"
        def server_info(self):
            return {"version": self.version}

    class Mongo:
        database = Database()
        client = Client()

    mongo = Mongo()
    uri = "mongodb+srv://honeypot-canonical-retry.example.mongodb.net/honeypot_canonical_v1"
    metadata = _runtime_metadata(receipt)
    assert verify_runtime_deployment(receipt, uri, mongo, runtime_metadata=metadata)["mongodb_server_version"] == "8.0.34"
    for version in ("8.0.32", "8.0.35", "8.1.1"):
        mongo.client.version = version
        with pytest.raises(ValueError, match="server version"):
            verify_runtime_deployment(receipt, uri, mongo, runtime_metadata=metadata)
    mongo.client.version = "8.0.34"
    with pytest.raises(ValueError, match="endpoint"):
        verify_runtime_deployment(receipt, "mongodb+srv://wrong.example.mongodb.net", mongo, runtime_metadata=metadata)
