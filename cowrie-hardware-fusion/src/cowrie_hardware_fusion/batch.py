"""Receipt-driven dataset indexing and leakage-safe run-level splitting."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .dataset import DatasetContractError


INDEX_SCHEMA_VERSION = "dataset_source_index.v1"
SPLIT_SCHEMA_VERSION = "dataset_split_assignment.v1"
BATCH_BUILDER_VERSION = "0.1.0"
PARTITIONS = ("development_train", "calibration", "final_test")
DEFAULT_GROUP_AXES = (
    "scenario_variant_group",
    "workload_implementation_sha256",
    "command_template_group",
    "collection_batch",
)
SUPPORTED_GROUP_AXES = DEFAULT_GROUP_AXES + ("workload_family_group", "environment_group")
NON_BINDING_GROUP_VALUES = {
    "command_template_group": frozenset({"no-command"}),
    "workload_family_group": frozenset({"none"}),
    "workload_implementation_sha256": frozenset({"0" * 64}),
}


def group_value_is_non_binding(axis: str, value: str) -> bool:
    return value in NON_BINDING_GROUP_VALUES.get(axis, frozenset())


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def write_json_exclusive(path: Path, document: Mapping[str, Any]) -> None:
    """Durably write one JSON artifact without replacing prior evidence."""

    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2)
        + "\n"
    ).encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetContractError(f"cannot read JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise DatasetContractError(f"{path} must contain one JSON object")
    return value


def _validator(schema_dir: Path, filename: str) -> Draft202012Validator:
    schema = _load_json(schema_dir / filename)
    return Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def _validate(
    document: Mapping[str, Any], validator: Draft202012Validator, label: str
) -> None:
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    error = errors[0]
    location = ".".join(str(component) for component in error.absolute_path) or "$"
    raise DatasetContractError(f"{label}:{location}: {error.message}")


def _verify_receipt_content(
    receipt: Mapping[str, Any],
    *,
    run_dir: Path,
    telemetry_validator: Draft202012Validator,
) -> None:
    claimed_hash = receipt.get("receipt_sha256")
    if not isinstance(claimed_hash, str):
        raise DatasetContractError("collection receipt hash is missing")
    receipt_without_hash = dict(receipt)
    receipt_without_hash.pop("receipt_sha256", None)
    if canonical_sha256(receipt_without_hash) != claimed_hash:
        raise DatasetContractError("collection receipt content hash does not match")

    expected_receipt_id = "collection-receipt-v1-" + sha256(
        f"{receipt.get('run_id')}\0{receipt.get('metric_scope')}".encode("utf-8")
    ).hexdigest()[:40]
    if receipt.get("receipt_id") != expected_receipt_id:
        raise DatasetContractError("collection receipt identity does not match run/scope")

    expected_sequence = 0
    record_count = 0
    serialized_bytes = 0
    phase_counts = {"baseline": 0, "workload": 0, "recovery": 0}
    for segment in receipt["segments"]:
        filename = segment["filename"]
        if Path(filename).name != filename:
            raise DatasetContractError("segment filename is unsafe")
        path = run_dir / filename
        digest = sha256()
        segment_count = 0
        segment_bytes = 0
        first_sequence: int | None = None
        last_sequence: int | None = None
        try:
            handle = path.open("rb")
        except OSError as exc:
            raise DatasetContractError(f"segment is unavailable: {filename}") from exc
        with handle:
            for line_number, line in enumerate(handle, start=1):
                digest.update(line)
                segment_bytes += len(line)
                try:
                    sample = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise DatasetContractError(
                        f"invalid segment record {filename}:{line_number}"
                    ) from exc
                if not isinstance(sample, dict):
                    raise DatasetContractError(
                        f"invalid segment record {filename}:{line_number}"
                    )
                _validate(sample, telemetry_validator, f"{filename}:{line_number}")
                for field in ("run_id", "experiment_id", "metric_scope"):
                    if sample.get(field) != receipt.get(field):
                        raise DatasetContractError(
                            f"segment {field} mismatch {filename}:{line_number}"
                        )
                sequence = sample["time"]["sequence"]
                if sequence != expected_sequence:
                    raise DatasetContractError(
                        "noncontiguous segment sequence: "
                        f"expected {expected_sequence}, got {sequence}"
                    )
                phase = sample["phase"]
                phase_counts[phase] += 1
                expected_sequence += 1
                segment_count += 1
                if first_sequence is None:
                    first_sequence = sequence
                last_sequence = sequence
        if first_sequence is None or last_sequence is None:
            raise DatasetContractError(f"segment is empty: {filename}")
        observed = {
            "first_sequence": first_sequence,
            "last_sequence": last_sequence,
            "record_count": segment_count,
            "serialized_bytes": segment_bytes,
            "sha256": digest.hexdigest(),
        }
        for field, value in observed.items():
            if segment.get(field) != value:
                raise DatasetContractError(f"segment {filename} {field} does not match receipt")
        expected_filename = (
            f"part-{first_sequence:06d}-{last_sequence:06d}-{digest.hexdigest()}.jsonl"
        )
        if filename != expected_filename:
            raise DatasetContractError("segment filename is not content-addressed correctly")
        record_count += segment_count
        serialized_bytes += segment_bytes

    if receipt.get("record_count") != record_count:
        raise DatasetContractError("receipt record_count does not match segments")
    if receipt.get("serialized_bytes") != serialized_bytes:
        raise DatasetContractError("receipt serialized_bytes does not match segments")
    if receipt.get("phase_record_counts") != phase_counts:
        raise DatasetContractError("receipt phase_record_counts does not match segments")


def _indexed_run(
    run_root: Path,
    *,
    manifest_validator: Draft202012Validator,
    receipt_validator: Draft202012Validator,
    telemetry_validator: Draft202012Validator,
) -> dict[str, Any]:
    manifest_path = run_root / "manifest.json"
    manifest = _load_json(manifest_path)
    _validate(manifest, manifest_validator, str(manifest_path))
    if manifest.get("state") != "completed":
        raise DatasetContractError(f"{manifest_path} is not a completed manifest")

    receipt_paths = sorted(run_root.glob("scope=*/collection-receipt.json"))
    if not receipt_paths:
        raise DatasetContractError(f"{run_root} has no collection receipts")

    authorized_scopes = set(manifest["execution_boundary"]["metric_scopes"])
    observed_scopes: set[str] = set()
    receipt_ids = set(manifest["labels"]["evidence_receipt_ids"])
    indexed_receipts: list[dict[str, Any]] = []
    for receipt_path in receipt_paths:
        receipt = _load_json(receipt_path)
        _validate(receipt, receipt_validator, str(receipt_path))
        if receipt["run_id"] != manifest["run_id"]:
            raise DatasetContractError(f"{receipt_path} run_id does not match manifest")
        if receipt["experiment_id"] != manifest["experiment_id"]:
            raise DatasetContractError(f"{receipt_path} experiment_id does not match manifest")
        scope = receipt["metric_scope"]
        if scope in observed_scopes:
            raise DatasetContractError(
                f"duplicate receipt scope for run {manifest['run_id']}: {scope}"
            )
        if scope not in authorized_scopes:
            raise DatasetContractError(f"receipt scope is not authorized by manifest: {scope}")
        if receipt["receipt_id"] not in receipt_ids:
            raise DatasetContractError("completed manifest does not cite collection receipt")
        if receipt["collector"]["collector_id"] != manifest["collection"]["collector_id"]:
            raise DatasetContractError("receipt collector_id does not match manifest")
        if receipt["collector"]["source_sha256"] != manifest["collection"]["collector_sha256"]:
            raise DatasetContractError("receipt collector source does not match manifest")
        _verify_receipt_content(
            receipt,
            run_dir=receipt_path.parent,
            telemetry_validator=telemetry_validator,
        )
        observed_scopes.add(scope)
        indexed_receipts.append(
            {
                "receipt_id": receipt["receipt_id"],
                "receipt_sha256": receipt["receipt_sha256"],
                "metric_scope": scope,
                "record_count": receipt["record_count"],
                "serialized_bytes": receipt["serialized_bytes"],
                "segments": [
                    {
                        "filename": segment["filename"],
                        "sha256": segment["sha256"],
                        "record_count": segment["record_count"],
                        "serialized_bytes": segment["serialized_bytes"],
                    }
                    for segment in receipt["segments"]
                ],
            }
        )
    if observed_scopes != authorized_scopes:
        missing = ",".join(sorted(authorized_scopes - observed_scopes))
        raise DatasetContractError(f"completed run is missing authorized scopes: {missing}")

    groups = dict(manifest["split_groups"])
    groups["workload_implementation_sha256"] = manifest["workload"][
        "implementation_sha256"
    ]
    indexed_receipts.sort(key=lambda value: value["metric_scope"])
    raw_membership = [
        {
            "metric_scope": receipt["metric_scope"],
            "receipt_sha256": receipt["receipt_sha256"],
            "segment_sha256": [segment["sha256"] for segment in receipt["segments"]],
        }
        for receipt in indexed_receipts
    ]
    return {
        "run_id": manifest["run_id"],
        "experiment_id": manifest["experiment_id"],
        "manifest_content_sha256": canonical_sha256(manifest),
        "raw_membership_sha256": canonical_sha256(raw_membership),
        "pilot_only": manifest["provenance"]["pilot_only"],
        "labels": deepcopy(manifest["labels"]),
        "workload": {
            "scenario_id": manifest["workload"]["scenario_id"],
            "family": manifest["workload"]["family"],
            "variant_id": manifest["workload"]["variant_id"],
            "implementation_sha256": manifest["workload"]["implementation_sha256"],
            "intensity_percent": manifest["workload"]["intensity_percent"],
        },
        "groups": groups,
        "receipts": indexed_receipts,
    }


def build_dataset_index(
    dataset_id: str,
    run_roots: Sequence[Path],
    *,
    schema_dir: Path,
) -> dict[str, Any]:
    """Verify completed raw runs and freeze their exact receipt/segment membership."""

    if not run_roots:
        raise DatasetContractError("at least one run root is required")
    manifest_validator = _validator(schema_dir, "experiment_run_manifest.v1.schema.json")
    receipt_validator = _validator(
        schema_dir, "experiment_collection_receipt.v1.schema.json"
    )
    telemetry_validator = _validator(schema_dir, "hardware_telemetry_sample.v1.schema.json")
    runs = [
        _indexed_run(
            Path(root),
            manifest_validator=manifest_validator,
            receipt_validator=receipt_validator,
            telemetry_validator=telemetry_validator,
        )
        for root in run_roots
    ]
    runs.sort(key=lambda value: value["run_id"])
    run_ids = [run["run_id"] for run in runs]
    if len(run_ids) != len(set(run_ids)):
        raise DatasetContractError("dataset index contains duplicate run_id")

    segment_hashes: set[str] = set()
    for run in runs:
        for receipt in run["receipts"]:
            for segment in receipt["segments"]:
                digest = segment["sha256"]
                if digest in segment_hashes:
                    raise DatasetContractError(f"duplicate raw segment hash: {digest}")
                segment_hashes.add(digest)

    document: dict[str, Any] = {
        "schema_version": INDEX_SCHEMA_VERSION,
        "dataset_id": dataset_id,
        "builder_version": BATCH_BUILDER_VERSION,
        "runs": runs,
        "summary": {
            "run_count": len(runs),
            "eligible_run_count": sum(not run["pilot_only"] for run in runs),
            "pilot_run_count": sum(run["pilot_only"] for run in runs),
            "receipt_count": sum(len(run["receipts"]) for run in runs),
            "record_count": sum(
                receipt["record_count"]
                for run in runs
                for receipt in run["receipts"]
            ),
            "serialized_bytes": sum(
                receipt["serialized_bytes"]
                for run in runs
                for receipt in run["receipts"]
            ),
        },
    }
    document["index_sha256"] = canonical_sha256(document)
    _validate(document, _validator(schema_dir, "dataset_source_index.v1.schema.json"), "index")
    return document


class _DisjointSet:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, value: int) -> int:
        while self.parent[value] != value:
            self.parent[value] = self.parent[self.parent[value]]
            value = self.parent[value]
        return value

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def _connected_components(
    runs: Sequence[Mapping[str, Any]], group_axes: Sequence[str]
) -> list[list[Mapping[str, Any]]]:
    disjoint = _DisjointSet(len(runs))
    for axis in group_axes:
        owners: dict[str, int] = {}
        for index, run in enumerate(runs):
            value = run["groups"][axis]
            if group_value_is_non_binding(axis, value):
                continue
            if value in owners:
                disjoint.union(owners[value], index)
            else:
                owners[value] = index
    components: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for index, run in enumerate(runs):
        components[disjoint.find(index)].append(run)
    return list(components.values())


def generate_grouped_split(
    index: Mapping[str, Any],
    split_id: str,
    *,
    seed: int = 20260901,
    group_axes: Sequence[str] = DEFAULT_GROUP_AXES,
    target_fractions: Mapping[str, float] | None = None,
    schema_dir: Path,
) -> dict[str, Any]:
    """Assign whole connected run groups to train/calibration/test deterministically."""

    _validate(index, _validator(schema_dir, "dataset_source_index.v1.schema.json"), "index")
    index_without_hash = dict(index)
    claimed_index_hash = index_without_hash.pop("index_sha256")
    if canonical_sha256(index_without_hash) != claimed_index_hash:
        raise DatasetContractError("dataset index content hash does not match")
    axes = tuple(group_axes)
    if not axes or len(axes) != len(set(axes)):
        raise DatasetContractError("group axes must be non-empty and unique")
    unknown_axes = sorted(set(axes) - set(SUPPORTED_GROUP_AXES))
    if unknown_axes:
        raise DatasetContractError(f"unsupported group axes: {','.join(unknown_axes)}")

    fractions = dict(
        target_fractions
        or {"development_train": 0.70, "calibration": 0.15, "final_test": 0.15}
    )
    if set(fractions) != set(PARTITIONS):
        raise DatasetContractError("target fractions must define all three partitions")
    if any(value <= 0.0 or value >= 1.0 for value in fractions.values()):
        raise DatasetContractError("target fractions must be between zero and one")
    if abs(sum(fractions.values()) - 1.0) > 1e-9:
        raise DatasetContractError("target fractions must sum to one")

    eligible = [run for run in index["runs"] if not run["pilot_only"]]
    excluded = [
        {"run_id": run["run_id"], "reason": "pilot_only"}
        for run in index["runs"]
        if run["pilot_only"]
    ]
    components = _connected_components(eligible, axes)
    if len(components) < len(PARTITIONS):
        raise DatasetContractError(
            "fewer than three independent eligible group components; collect more "
            "variants/batches or use GroupKFold without claiming a final test"
        )

    def component_key(component: Sequence[Mapping[str, Any]]) -> tuple[int, str]:
        members = sorted(run["run_id"] for run in component)
        tie_breaker = canonical_sha256({"seed": seed, "members": members})
        return (-len(component), tie_breaker)

    ordered_components = sorted(components, key=component_key)
    partition_order = sorted(PARTITIONS, key=lambda name: (-fractions[name], name))
    component_partition: dict[int, str] = {}
    partition_counts = {name: 0 for name in PARTITIONS}
    total_runs = len(eligible)
    for position, component in enumerate(ordered_components):
        if position < len(PARTITIONS):
            partition = partition_order[position]
        else:
            partition = min(
                PARTITIONS,
                key=lambda name: (
                    partition_counts[name] / (fractions[name] * total_runs),
                    canonical_sha256(
                        {
                            "seed": seed,
                            "component": sorted(run["run_id"] for run in component),
                            "partition": name,
                        }
                    ),
                ),
            )
        component_partition[position] = partition
        partition_counts[partition] += len(component)

    assignments: list[dict[str, Any]] = []
    components_output: list[dict[str, Any]] = []
    for position, component in enumerate(ordered_components):
        member_ids = sorted(run["run_id"] for run in component)
        component_id = "group-v1-" + canonical_sha256(member_ids)[:24]
        partition = component_partition[position]
        components_output.append(
            {
                "component_id": component_id,
                "partition": partition,
                "run_ids": member_ids,
            }
        )
        assignments.extend(
            {
                "run_id": run_id,
                "partition": partition,
                "component_id": component_id,
            }
            for run_id in member_ids
        )
    assignments.sort(key=lambda value: value["run_id"])
    excluded.sort(key=lambda value: value["run_id"])
    components_output.sort(key=lambda value: value["component_id"])

    document: dict[str, Any] = {
        "schema_version": SPLIT_SCHEMA_VERSION,
        "split_id": split_id,
        "source_index_sha256": index["index_sha256"],
        "seed": seed,
        "group_axes": list(axes),
        "target_fractions": fractions,
        "partition_run_counts": partition_counts,
        "assignments": assignments,
        "excluded": excluded,
        "components": components_output,
    }
    document["assignment_sha256"] = canonical_sha256(document)
    _validate(
        document,
        _validator(schema_dir, "dataset_split_assignment.v1.schema.json"),
        "split assignment",
    )
    return document
