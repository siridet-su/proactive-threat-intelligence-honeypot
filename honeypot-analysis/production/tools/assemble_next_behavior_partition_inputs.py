#!/usr/bin/env python3
"""Assemble the canonical frozen v2 partition inputs from role bundles.

This is a pre-test provenance boundary.  It reconstructs every role artifact
from its safe-session payload, binds the resulting 4/1/1/7 membership to the
role inventories and historical-split sidecars, then publishes only a frozen
partition manifest and assembly receipt.  It never runs a model or evaluator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence

from production.prediction.next_behavior_contract import (
    require_valid_next_behavior_session,
)
from production.prediction.next_behavior_corpus import (
    require_valid_source_member_receipt,
)
from production.prediction.next_behavior_partitions import (
    MEMBER_ROLES,
    V2_DEVELOPMENT_CUTOFF,
    V2_FINAL_WINDOW_START,
    build_partition_manifest_v2,
    membership_sha256,
)
from production.prediction.next_behavior_preprocessing import (
    build_next_behavior_examples,
)
from production.tools.build_next_behavior_selected_corpus import (
    PURPOSE_TO_ROLE,
    ROLE_TO_COHORT,
)
from production.tools.build_next_behavior_selected_safe_corpus import (
    verify_selected_role_artifacts,
)
from production.utils.serialization import stable_id, stable_json


ASSEMBLY_SCHEMA_VERSION = "next_behavior_partition_input_assembly.v1"
HISTORICAL_EVIDENCE_SCHEMA_VERSION = "next_behavior_historical_split_evidence.v1"
ASSEMBLY_FILENAMES = {
    "partition_manifest": "partition_manifest.json",
    "assembly_receipt": "assembly_receipt.json",
}
CANONICAL_SAFE_PAYLOAD_DIRECTORY = "safe_payloads"
ROLE_BUNDLE_FILENAMES = {
    "safe_sessions": "safe_sessions.jsonl",
    "examples": "examples.jsonl",
    "source_receipts": "source_receipts.json",
    "corpus_receipt": "corpus_receipt.json",
    "build_receipt": "build_receipt.json",
    "role_inventory": "role_inventory.json",
    "historical_split_evidence": "historical_split_evidence.json",
}
_HISTORICAL_SPLITS = frozenset({"train", "calibration", "test", "not_present"})
_FORBIDDEN_PUBLIC_FIELDS = frozenset(
    {
        "command",
        "commands",
        "input",
        "password",
        "passwd",
        "src_ip",
        "source_ip",
        "username",
        "raw_session_id",
        "raw_command",
        "raw_commands",
    }
)


class PartitionInputAssemblyError(ValueError):
    """Raised when a v2 partition input cannot be trusted."""


@dataclass(frozen=True)
class RoleBundle:
    """Verified public artifacts needed to reconstruct one frozen role."""

    role: str
    paths: Mapping[str, Path]
    build_receipt: Mapping[str, Any]
    corpus_receipt: Mapping[str, Any]
    inventory: Mapping[str, Any]
    source_members: tuple[Dict[str, Any], ...]
    sessions: tuple[Dict[str, Any], ...]
    historical_split_by_session: Mapping[str, str]


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _is_sha256(value: Any) -> bool:
    text = _clean(value).lower()
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_object(path: Path, *, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PartitionInputAssemblyError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PartitionInputAssemblyError(f"{label} must be a JSON object")
    return dict(value)


def _read_canonical_jsonl(path: Path, *, label: str) -> list[Dict[str, Any]]:
    values: list[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.endswith("\n") or not line.strip():
                    raise PartitionInputAssemblyError(
                        f"{label} line {line_number} is not canonical JSONL"
                    )
                value = json.loads(line)
                if not isinstance(value, dict) or stable_json(value) + "\n" != line:
                    raise PartitionInputAssemblyError(
                        f"{label} line {line_number} is not canonical JSONL"
                    )
                values.append(dict(value))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PartitionInputAssemblyError(f"{label} is not valid JSONL") from exc
    if not values:
        raise PartitionInputAssemblyError(f"{label} is empty")
    return values


def _require_regular_file(path: Path, *, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise PartitionInputAssemblyError(f"{label} is missing or unsafe")


def _scan_public_value(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _clean(key).lower() in _FORBIDDEN_PUBLIC_FIELDS:
                raise PartitionInputAssemblyError(
                    f"public input contains forbidden field at {path}.{key}"
                )
            _scan_public_value(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_public_value(child, path=f"{path}[{index}]")


def _role_paths(directory: Path) -> Dict[str, Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise PartitionInputAssemblyError("role bundle directory is missing or unsafe")
    paths = {
        name: directory / filename
        for name, filename in ROLE_BUNDLE_FILENAMES.items()
    }
    for name, path in paths.items():
        _require_regular_file(path, label=f"role bundle {name}")
    return paths


def _require_build_evidence(
    receipt: Mapping[str, Any],
    *,
    evidence_path: Path,
    session_ids: Iterable[str],
) -> None:
    evidence = receipt.get("historical_split_evidence")
    if (
        not isinstance(evidence, Mapping)
        or set(evidence)
        != {
            "schema_version",
            "status",
            "artifact_sha256",
            "record_count",
            "session_membership_sha256",
        }
        or evidence.get("schema_version") != HISTORICAL_EVIDENCE_SCHEMA_VERSION
        or evidence.get("status") != "historical_split_evidence_complete"
        or not _is_sha256(evidence.get("artifact_sha256"))
        or not _is_sha256(evidence.get("session_membership_sha256"))
        or isinstance(evidence.get("record_count"), bool)
        or not isinstance(evidence.get("record_count"), int)
        or evidence["record_count"] < 1
    ):
        raise PartitionInputAssemblyError(
            "role build receipt historical split evidence binding is invalid"
        )
    canonical_session_hash = membership_sha256(session_ids)
    if (
        evidence["artifact_sha256"] != _sha256_file(evidence_path)
        or evidence["record_count"] != len(set(session_ids))
        or evidence["session_membership_sha256"] != canonical_session_hash
    ):
        raise PartitionInputAssemblyError(
            "role build receipt historical split evidence does not bind its payload"
        )


def _load_historical_evidence(
    path: Path,
    *,
    corpus_receipt_id: str,
    source_selection_sha256: str,
    sessions: Sequence[Mapping[str, Any]],
) -> Dict[str, str]:
    value = _read_object(path, label="historical split evidence")
    if set(value) != {
        "schema_version",
        "status",
        "selected_safe_corpus_receipt_id",
        "source_selection_sha256",
        "records",
    }:
        raise PartitionInputAssemblyError("historical split evidence fields are invalid")
    if (
        value.get("schema_version") != HISTORICAL_EVIDENCE_SCHEMA_VERSION
        or value.get("status") != "historical_split_evidence_complete"
        or value.get("selected_safe_corpus_receipt_id") != corpus_receipt_id
        or value.get("source_selection_sha256") != source_selection_sha256
    ):
        raise PartitionInputAssemblyError("historical split evidence bindings are invalid")
    records = value.get("records")
    if not isinstance(records, list) or not records:
        raise PartitionInputAssemblyError("historical split evidence records are invalid")
    expected = {
        _clean(session["session_id"]): (
            _clean(session["source_member_id"]),
            _clean(session["source_member_sha256"]).lower(),
        )
        for session in sessions
    }
    evidence: Dict[str, str] = {}
    previous_session_id = ""
    for index, record in enumerate(records):
        if not isinstance(record, Mapping) or set(record) != {
            "session_id",
            "source_member_id",
            "source_member_sha256",
            "historical_split",
        }:
            raise PartitionInputAssemblyError(
                f"historical split evidence record {index} is invalid"
            )
        session_id = _clean(record.get("session_id"))
        member_id = _clean(record.get("source_member_id"))
        member_sha = _clean(record.get("source_member_sha256")).lower()
        split = _clean(record.get("historical_split"))
        if (
            not session_id
            or session_id <= previous_session_id
            or session_id in evidence
            or split not in _HISTORICAL_SPLITS
            or expected.get(session_id) != (member_id, member_sha)
        ):
            raise PartitionInputAssemblyError(
                "historical split evidence records are not canonical or bound"
            )
        previous_session_id = session_id
        evidence[session_id] = split
    if set(evidence) != set(expected):
        raise PartitionInputAssemblyError(
            "historical split evidence does not exactly cover safe sessions"
        )
    _scan_public_value(value)
    return evidence


def _validate_inventory(
    inventory: Mapping[str, Any],
    *,
    role: str,
    receipt: Mapping[str, Any],
    source_members: Sequence[Mapping[str, Any]],
) -> None:
    purpose = next(key for key, value in PURPOSE_TO_ROLE.items() if value == role)
    expected_cohort = ROLE_TO_COHORT[role]
    if (
        inventory.get("schema_version") != "next_behavior_role_inventory.v1"
        or inventory.get("status") != "role_membership_frozen"
        or inventory.get("purpose") != purpose
        or inventory.get("role") != role
        or inventory.get("source_cohort") != expected_cohort
        or inventory.get("source_selection_sha256")
        != receipt.get("source_selection_sha256")
        or inventory.get("pseudonymization_key_id")
        != receipt.get("pseudonymization_key_id")
        or inventory.get("source_member_count") != len(source_members)
        or inventory.get("raw_content_emitted") is not False
        or inventory.get("partial_sessions_can_emit_terminal_target") is not False
    ):
        raise PartitionInputAssemblyError("role inventory bindings are invalid")
    identity = dict(inventory)
    inventory_id = identity.pop("inventory_id", None)
    if stable_id("nextbehaviorroleinventory", identity) != inventory_id:
        raise PartitionInputAssemblyError("role inventory identity is invalid")
    member_receipts = [
        {
            "source_sha256": _clean(member["sha256"]).lower(),
            "chronological_order": member["chronological_order"],
            "source_cohort": expected_cohort,
        }
        for member in sorted(source_members, key=lambda member: member["chronological_order"])
    ]
    member_hash = hashlib.sha256(stable_json(member_receipts).encode("utf-8")).hexdigest()
    if inventory.get("source_members_sha256") != member_hash:
        raise PartitionInputAssemblyError("role inventory source-member binding is invalid")
    reconciliation = receipt.get("pipeline_reconciliation")
    if (
        not isinstance(reconciliation, Mapping)
        or inventory.get("eligible_complete_session_count")
        != reconciliation.get("eligible_complete_nonquarantined_sessions")
    ):
        raise PartitionInputAssemblyError("role inventory session reconciliation is invalid")


def _load_role_bundle(role: str, directory: Path) -> RoleBundle:
    if role not in MEMBER_ROLES:
        raise PartitionInputAssemblyError("unknown frozen role")
    paths = _role_paths(directory)
    purpose = next(key for key, value in PURPOSE_TO_ROLE.items() if value == role)
    try:
        verification = verify_selected_role_artifacts(
            build_receipt_path=paths["build_receipt"],
            safe_sessions_path=paths["safe_sessions"],
            examples_path=paths["examples"],
            source_receipts_path=paths["source_receipts"],
            corpus_receipt_path=paths["corpus_receipt"],
            expected_purpose=purpose,
            # This validates final preparation evidence only; it never invokes
            # the evaluator or opens any training/evaluation result.
            allow_final=(role == "test"),
        )
    except ValueError as exc:
        raise PartitionInputAssemblyError(
            f"{role} role artifacts cannot be verified: {exc}"
        ) from exc
    if verification.get("status") != "selected_role_artifacts_verified":
        raise PartitionInputAssemblyError("role artifact verification is incomplete")
    build_receipt = _read_object(paths["build_receipt"], label="role build receipt")
    corpus_receipt = _read_object(paths["corpus_receipt"], label="role corpus receipt")
    inventory = _read_object(paths["role_inventory"], label="role inventory")
    source_receipts = _read_object(paths["source_receipts"], label="source receipts")
    if (
        set(source_receipts)
        != {
            "schema_version",
            "source_selection_sha256",
            "purpose",
            "role",
            "members",
        }
        or source_receipts.get("schema_version")
        != "next_behavior_selected_source_member_receipts.v1"
        or source_receipts.get("purpose") != purpose
        or source_receipts.get("role") != role
        or source_receipts.get("source_selection_sha256")
        != build_receipt.get("source_selection_sha256")
    ):
        raise PartitionInputAssemblyError("role source receipt bindings are invalid")
    members_value = source_receipts.get("members")
    if not isinstance(members_value, list):
        raise PartitionInputAssemblyError("role source receipts are invalid")
    members = tuple(require_valid_source_member_receipt(item) for item in members_value)
    member_ids = [member["member_id"] for member in members]
    if len(member_ids) != len(set(member_ids)):
        raise PartitionInputAssemblyError("role source receipts repeat a member")
    if (
        build_receipt.get("corpus_receipt_id") != corpus_receipt.get("receipt_id")
        or build_receipt.get("role") != role
        or build_receipt.get("purpose") != purpose
        or build_receipt.get("source_cohort") != ROLE_TO_COHORT[role]
    ):
        raise PartitionInputAssemblyError("role build/corpus receipt bindings are invalid")
    expected_orders = {
        "train": [1, 2, 3, 4],
        "selection": [5],
        "calibration": [6],
        "test": [7, 8, 9, 10, 11, 12, 13],
    }[role]
    if sorted(member["chronological_order"] for member in members) != expected_orders:
        raise PartitionInputAssemblyError(
            "role source receipts violate the frozen 4/1/1/7 chronology"
        )
    sessions = tuple(
        require_valid_next_behavior_session(item)
        for item in _read_canonical_jsonl(paths["safe_sessions"], label="safe sessions")
    )
    session_ids = [session["session_id"] for session in sessions]
    if len(session_ids) != len(set(session_ids)):
        raise PartitionInputAssemblyError("role safe sessions repeat a session")
    if {session["source_member_id"] for session in sessions} != set(member_ids):
        raise PartitionInputAssemblyError(
            "every frozen role source member must contribute a safe session"
        )
    _require_build_evidence(
        build_receipt,
        evidence_path=paths["historical_split_evidence"],
        session_ids=session_ids,
    )
    _validate_inventory(
        inventory,
        role=role,
        receipt=build_receipt,
        source_members=members,
    )
    evidence = _load_historical_evidence(
        paths["historical_split_evidence"],
        corpus_receipt_id=_clean(corpus_receipt.get("receipt_id")),
        source_selection_sha256=_clean(build_receipt.get("source_selection_sha256")),
        sessions=sessions,
    )
    for value in (build_receipt, corpus_receipt, inventory, source_receipts, *sessions):
        _scan_public_value(value)
    return RoleBundle(
        role=role,
        paths=paths,
        build_receipt=build_receipt,
        corpus_receipt=corpus_receipt,
        inventory=inventory,
        source_members=members,
        sessions=sessions,
        historical_split_by_session=evidence,
    )


def _shared_binding(bundles: Mapping[str, RoleBundle], field: str) -> str:
    values = {_clean(bundle.build_receipt.get(field)) for bundle in bundles.values()}
    if len(values) != 1 or not next(iter(values)):
        raise PartitionInputAssemblyError(f"role bundles disagree on {field}")
    return next(iter(values))


def _write_new(path: Path, payload: bytes) -> None:
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    except FileExistsError as exc:
        raise FileExistsError(f"refusing to overwrite existing output: {path}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _publish_output_directory(
    output_directory: Path,
    manifest: Mapping[str, Any],
    receipt: Mapping[str, Any],
    safe_payloads: Mapping[str, Sequence[Mapping[str, Any]]],
) -> None:
    if output_directory.exists() or output_directory.is_symlink():
        raise FileExistsError(
            f"refusing to overwrite existing partition assembly: {output_directory}"
        )
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_directory.name}.", dir=output_directory.parent))
    try:
        _write_new(
            staging / ASSEMBLY_FILENAMES["partition_manifest"],
            (stable_json(manifest) + "\n").encode("utf-8"),
        )
        _write_new(
            staging / ASSEMBLY_FILENAMES["assembly_receipt"],
            (stable_json(receipt) + "\n").encode("utf-8"),
        )
        staging_payloads = staging / CANONICAL_SAFE_PAYLOAD_DIRECTORY
        staging_payloads.mkdir()
        for role in MEMBER_ROLES:
            _write_new(
                staging_payloads / f"{role}.json",
                (stable_json(list(safe_payloads[role])) + "\n").encode("utf-8"),
            )
        try:
            os.mkdir(output_directory)
        except FileExistsError as exc:
            raise FileExistsError(
                f"refusing to overwrite existing partition assembly: {output_directory}"
            ) from exc
        published: list[Path] = []
        try:
            for filename in ASSEMBLY_FILENAMES.values():
                destination = output_directory / filename
                os.link(staging / filename, destination)
                published.append(destination)
            payload_directory = output_directory / CANONICAL_SAFE_PAYLOAD_DIRECTORY
            payload_directory.mkdir()
            for role in MEMBER_ROLES:
                destination = payload_directory / f"{role}.json"
                os.link(staging_payloads / f"{role}.json", destination)
                published.append(destination)
        except BaseException:
            for destination in published:
                destination.unlink(missing_ok=True)
            shutil.rmtree(output_directory, ignore_errors=True)
            raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def assemble_partition_inputs(
    *,
    role_bundle_directories: Mapping[str, Path],
    output_directory: Path,
) -> Dict[str, Any]:
    """Reconstruct and freeze the canonical v2 partition manifest.

    ``role_bundle_directories`` must contain exactly the four frozen roles.
    The function publishes a new directory containing the manifest and an
    index/receipt, and never overwrites a prior assembly.
    """

    if not isinstance(role_bundle_directories, Mapping) or set(role_bundle_directories) != set(MEMBER_ROLES):
        raise PartitionInputAssemblyError(
            "role bundle directories must define train, selection, calibration, and test"
        )
    bundles = {
        role: _load_role_bundle(role, Path(role_bundle_directories[role]))
        for role in MEMBER_ROLES
    }
    code_commit = _shared_binding(bundles, "code_commit")
    source_selection_sha256 = _shared_binding(bundles, "source_selection_sha256")
    pseudonymization_key_id = _shared_binding(bundles, "pseudonymization_key_id")
    max_sequence_length_text = _shared_binding(bundles, "max_sequence_length")
    try:
        max_sequence_length = int(max_sequence_length_text)
    except ValueError as exc:
        raise PartitionInputAssemblyError("role bundles disagree on max_sequence_length") from exc
    if max_sequence_length < 1:
        raise PartitionInputAssemblyError("max_sequence_length must be positive")
    policy_bindings = {
        field: _shared_binding(bundles, field)
        for field in (
            "preprocessing_sha256",
            "label_policy_sha256",
            "trust_policy_sha256",
            "classification_checkpoint_sha256",
        )
    }
    if not all(_is_sha256(value) for value in policy_bindings.values()):
        raise PartitionInputAssemblyError("role bundle policy bindings are invalid")
    source_members = [member for bundle in bundles.values() for member in bundle.source_members]
    member_ids = [member["member_id"] for member in source_members]
    if len(member_ids) != len(set(member_ids)):
        raise PartitionInputAssemblyError("source member occurs in more than one role bundle")
    source_members.sort(key=lambda member: member["chronological_order"])
    if [member["chronological_order"] for member in source_members] != list(range(1, 14)):
        raise PartitionInputAssemblyError("source members do not define frozen chronological orders 1 through 13")
    records = [session for bundle in bundles.values() for session in bundle.sessions]
    evidence = {
        session_id: split
        for bundle in bundles.values()
        for session_id, split in bundle.historical_split_by_session.items()
    }
    if len(evidence) != sum(len(bundle.historical_split_by_session) for bundle in bundles.values()):
        raise PartitionInputAssemblyError("historical split evidence repeats a safe session")
    manifest = build_partition_manifest_v2(
        records,
        source_members,
        preprocessing_sha256=policy_bindings["preprocessing_sha256"],
        label_policy_sha256=policy_bindings["label_policy_sha256"],
        trust_policy_sha256=policy_bindings["trust_policy_sha256"],
        code_commit=code_commit,
        historical_split_by_session=evidence,
        development_cutoff=V2_DEVELOPMENT_CUTOFF,
        final_window_start=V2_FINAL_WINDOW_START,
        max_sequence_length=max_sequence_length,
    )
    manifest_bytes = (stable_json(manifest) + "\n").encode("utf-8")
    safe_payloads = {
        role: sorted(
            (dict(session) for session in bundle.sessions),
            key=lambda session: _clean(session["session_id"]),
        )
        for role, bundle in bundles.items()
    }
    role_artifacts = {
        role: {
            "build_receipt_id": bundle.build_receipt["build_receipt_id"],
            "corpus_receipt_id": bundle.corpus_receipt["receipt_id"],
            "safe_sessions_sha256": _sha256_file(bundle.paths["safe_sessions"]),
            "examples_sha256": _sha256_file(bundle.paths["examples"]),
            "canonical_safe_payload_sha256": hashlib.sha256(
                (stable_json(safe_payloads[role]) + "\n").encode("utf-8")
            ).hexdigest(),
            "role_inventory_sha256": _sha256_file(bundle.paths["role_inventory"]),
            "historical_split_evidence_sha256": _sha256_file(bundle.paths["historical_split_evidence"]),
        }
        for role, bundle in bundles.items()
    }
    receipt: Dict[str, Any] = {
        "schema_version": ASSEMBLY_SCHEMA_VERSION,
        "status": "partition_inputs_assembled",
        "manifest_id": manifest["manifest_id"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "code_commit": code_commit,
        "source_selection_sha256": source_selection_sha256,
        "pseudonymization_key_id": pseudonymization_key_id,
        "protocol": manifest["protocol"],
        "max_sequence_length": max_sequence_length,
        "role_artifacts": role_artifacts,
        "test_opened": False,
        "raw_content_emitted": False,
    }
    receipt["assembly_id"] = stable_id("nextbehaviorpartitionassembly", receipt)
    _scan_public_value(manifest)
    _scan_public_value(receipt)
    _publish_output_directory(
        Path(output_directory), manifest, receipt, safe_payloads
    )
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    for role in MEMBER_ROLES:
        parser.add_argument(f"--{role}-bundle", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    receipt = assemble_partition_inputs(
        role_bundle_directories={
            role: getattr(args, f"{role}_bundle") for role in MEMBER_ROLES
        },
        output_directory=args.output_directory,
    )
    print(
        json.dumps(
            {
                "assembly_id": receipt["assembly_id"],
                "manifest_id": receipt["manifest_id"],
                "output": str(args.output_directory),
                "status": receipt["status"],
                "test_opened": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
