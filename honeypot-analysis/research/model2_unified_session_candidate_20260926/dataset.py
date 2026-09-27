"""Leakage and grouped-split validation for Model2 research episodes."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from typing import Any, Mapping, Sequence

from .contract import FEATURE_ORDER, FEATURE_SCHEMA_SHA256, LABEL_ORDER, SCHEMA_ID


DATASET_SCHEMA_VERSION = "model2_unified_session_dataset.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ROW_FIELDS = {
    "sample_id", "procedure_family_id", "duplicate_group_id", "variant_id", "repetition_id",
    "split", "dataset_schema_version", "feature_schema_id", "feature_schema_sha256",
    "extractor_code_sha256", "split_manifest_sha256", "source_binding", "source_evidence_sha256",
    "availability_states", "feature_vector", "labels", "label_provenance", "control_tags",
}
SOURCE_BINDING_FIELDS = {
    "source_session_id", "run_id", "measurement_id", "episode_id",
    "cowrie_event_log_sha256", "pcap_sha256", "zeek_conn_log_sha256",
}
LABEL_PROVENANCE_FIELDS = {
    "human_adjudication", "reviewer_blind_to_model_outputs", "labels_defined_before_fit",
    "model_outputs_used", "source_kind", "evidence_reference", "adjudication_protocol_sha256",
}
AVAILABILITY_FIELDS = {"cowrie", "auth", "pcap", "zeek_conn"}
CONTROL_TAGS = {
    "session_bound_transfer_activity", "valid_transfer_attempt", "transfer_basic",
    "benign_content_transfer_positive", "transfer_output_file", "transfer_redirect",
    "transfer_then_execute", "transfer_chmod", "transfer_extract", "transfer_cleanup",
    "mixed_ttp", "no_session_bound_transfer", "transfer_attempt_no_session_flow",
    "malformed_transfer", "wget_help",
    "curl_version", "embedded_transfer_text", "quoted_transfer_text",
    "url_without_transfer_tool", "local_file_operation", "execute_existing_local_file",
    "ordinary_auth_only", "discovery_only", "benign_auth_retry", "single_service_access",
    "single_success_t1110_hard_negative",
    "repeated_same_port", "network_unavailable",
}
T1105_NONTRANSFER_HARD_NEGATIVE_TAGS = {
    "no_session_bound_transfer", "transfer_attempt_no_session_flow",
    "malformed_transfer", "wget_help", "curl_version",
    "embedded_transfer_text", "quoted_transfer_text", "url_without_transfer_tool",
    "local_file_operation", "execute_existing_local_file", "ordinary_auth_only",
    "discovery_only", "benign_auth_retry", "single_service_access",
}


class DatasetContractError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def validate_rows(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate FIT/SELECTION rows only. Sealed final labels are never accepted."""
    if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence):
        raise DatasetContractError("rows_not_sequence")
    sample_ids: set[str] = set()
    source_bindings: set[tuple[str, ...]] = set()
    source_evidence_hashes: set[str] = set()
    family_split: dict[str, str] = {}
    duplicate_split: dict[str, str] = {}
    corpus_extractor_hash: str | None = None
    corpus_split_manifest_hash: str | None = None
    label_counts = {label: Counter() for label in LABEL_ORDER}
    split_label_counts = {
        split: {label: Counter() for label in LABEL_ORDER}
        for split in ("FIT", "SELECTION")
    }
    hard_negative_counts = {label: 0 for label in LABEL_ORDER}
    benign_content_transfer_positive_count = 0
    normalized: list[dict[str, Any]] = []

    for row in rows:
        if not isinstance(row, Mapping):
            raise DatasetContractError("row_not_object")
        if any(name in row for name in ("model1_prediction", "model2_prediction", "prediction", "model_score")):
            raise DatasetContractError("prediction_column_forbidden")
        if set(row) != ROW_FIELDS:
            raise DatasetContractError("row_field_allowlist_mismatch")
        sample_id = str(row.get("sample_id") or "")
        family = str(row.get("procedure_family_id") or "")
        duplicate_group = str(row.get("duplicate_group_id") or "")
        split = str(row.get("split") or "")
        if not sample_id or sample_id in sample_ids:
            raise DatasetContractError("sample_id_missing_or_duplicate")
        if not family or not duplicate_group or not str(row.get("variant_id") or "") or not str(row.get("repetition_id") or ""):
            raise DatasetContractError("group_identity_missing")
        if split not in {"FIT", "SELECTION"}:
            raise DatasetContractError("only_fit_and_selection_rows_are_permitted")
        if row.get("dataset_schema_version") != DATASET_SCHEMA_VERSION:
            raise DatasetContractError("dataset_schema_version_mismatch")
        if row.get("feature_schema_id") != SCHEMA_ID or row.get("feature_schema_sha256") != FEATURE_SCHEMA_SHA256:
            raise DatasetContractError("feature_schema_identity_mismatch")
        extractor_hash = str(row.get("extractor_code_sha256") or "")
        split_hash = str(row.get("split_manifest_sha256") or "")
        if not SHA256_RE.fullmatch(extractor_hash) or not SHA256_RE.fullmatch(split_hash):
            raise DatasetContractError("extraction_or_split_provenance_invalid")
        if corpus_extractor_hash is None:
            corpus_extractor_hash = extractor_hash
            corpus_split_manifest_hash = split_hash
        elif extractor_hash != corpus_extractor_hash or split_hash != corpus_split_manifest_hash:
            raise DatasetContractError("corpus_provenance_identity_mismatch")

        binding = row.get("source_binding")
        if not isinstance(binding, Mapping) or set(binding) != SOURCE_BINDING_FIELDS:
            raise DatasetContractError("source_binding_schema_invalid")
        binding_values = tuple(str(binding.get(name) or "") for name in (
            "source_session_id", "run_id", "measurement_id", "episode_id"
        ))
        if any(not isinstance(binding.get(name), str) or not value for name, value in zip(
            ("source_session_id", "run_id", "measurement_id", "episode_id"), binding_values
        )):
            raise DatasetContractError("source_binding_identity_missing")
        for name in ("cowrie_event_log_sha256", "pcap_sha256", "zeek_conn_log_sha256"):
            if not SHA256_RE.fullmatch(str(binding.get(name) or "")):
                raise DatasetContractError("source_binding_receipt_invalid")
        if binding_values in source_bindings:
            raise DatasetContractError("duplicate_source_episode")
        source_bindings.add(binding_values)
        evidence_hash = str(row.get("source_evidence_sha256") or "")
        if not SHA256_RE.fullmatch(evidence_hash) or evidence_hash in source_evidence_hashes:
            raise DatasetContractError("source_evidence_missing_or_duplicate")
        source_evidence_hashes.add(evidence_hash)

        availability = row.get("availability_states")
        if not isinstance(availability, Mapping) or set(availability) != AVAILABILITY_FIELDS or any(
            availability.get(name) != "COMPLETE" for name in AVAILABILITY_FIELDS
        ):
            raise DatasetContractError("required_source_unavailable")
        sample_ids.add(sample_id)
        for mapping, key in ((family_split, family), (duplicate_split, duplicate_group)):
            old = mapping.setdefault(key, split)
            if old != split:
                raise DatasetContractError("group_leakage_across_splits")

        if any(name in row for name in ("model1_prediction", "model2_prediction", "prediction", "model_score")):
            raise DatasetContractError("prediction_column_forbidden")
        vector = row.get("feature_vector")
        if not isinstance(vector, Mapping) or tuple(vector.keys()) != FEATURE_ORDER:
            raise DatasetContractError("feature_vector_order_or_schema_mismatch")
        for name, value in vector.items():
            if isinstance(value, bool):
                raise DatasetContractError("boolean_feature_value")
            try:
                number = float(value)
            except (TypeError, ValueError):
                raise DatasetContractError("non_numeric_feature_value") from None
            if not math.isfinite(number) or number < 0:
                raise DatasetContractError("invalid_feature_value")
        transfer_count = float(vector["transfer_tool_command_count"])
        network_count = float(vector["network_connection_count"])

        labels = row.get("labels")
        if not isinstance(labels, Mapping) or tuple(labels.keys()) != LABEL_ORDER:
            raise DatasetContractError("label_order_or_schema_mismatch")
        for label in LABEL_ORDER:
            value = labels[label]
            if not isinstance(value, bool):
                raise DatasetContractError("label_must_be_boolean")
            outcome = "positive" if value else "negative"
            label_counts[label][outcome] += 1
            split_label_counts[split][label][outcome] += 1

        adjudication = row.get("label_provenance")
        if (
            not isinstance(adjudication, Mapping)
            or set(adjudication) != LABEL_PROVENANCE_FIELDS
            or adjudication.get("model_outputs_used") is not False
            or not str(adjudication.get("evidence_reference") or "")
            or not SHA256_RE.fullmatch(str(adjudication.get("adjudication_protocol_sha256") or ""))
        ):
            raise DatasetContractError("independent_label_provenance_missing")
        source_kind = str(adjudication.get("source_kind") or "").lower()
        if source_kind == "preregistered_control_semantics":
            # Synthetic labels are defined by the controlled procedure before
            # fitting. Do not misstate them as independently human-adjudicated.
            if (
                adjudication.get("human_adjudication") is not False
                or adjudication.get("reviewer_blind_to_model_outputs") is not None
                or adjudication.get("labels_defined_before_fit") is not True
            ):
                raise DatasetContractError("controlled_label_provenance_invalid")
        elif source_kind == "independent_lab_adjudication":
            if (
                adjudication.get("human_adjudication") is not True
                or adjudication.get("reviewer_blind_to_model_outputs") is not True
                or adjudication.get("labels_defined_before_fit") is not False
            ):
                raise DatasetContractError("independent_label_provenance_missing")
        else:
            raise DatasetContractError("independent_label_provenance_missing")
        tags = row.get("control_tags", ())
        if (
            not isinstance(tags, Sequence)
            or isinstance(tags, (str, bytes))
            or any(not isinstance(tag, str) for tag in tags)
            or not set(tags).issubset(CONTROL_TAGS)
        ):
            raise DatasetContractError("control_tags_invalid")
        tag_set = set(tags)
        if tag_set.intersection(T1105_NONTRANSFER_HARD_NEGATIVE_TAGS):
            if labels["T1105"] is not False:
                raise DatasetContractError("nontransfer_hard_negative_must_be_t1105_negative")
            hard_negative_counts["T1105"] += 1
        if labels["T1105"] and "session_bound_transfer_activity" not in tag_set:
            raise DatasetContractError("t1105_positive_semantics_tag_missing")
        if "session_bound_transfer_activity" in tag_set and (transfer_count < 1 or network_count < 1):
            raise DatasetContractError("t1105_session_bound_evidence_missing")
        if "valid_transfer_attempt" in tag_set and transfer_count < 1:
            raise DatasetContractError("valid_transfer_attempt_feature_missing")
        if "transfer_attempt_no_session_flow" in tag_set and (transfer_count < 1 or network_count != 0):
            raise DatasetContractError("transfer_attempt_no_flow_control_invalid")
        if "session_bound_transfer_activity" in tag_set and labels["T1105"] is not True:
            raise DatasetContractError("t1105_transfer_label_conflict")
        if "benign_content_transfer_positive" in tag_set:
            if labels["T1105"] is not True or "session_bound_transfer_activity" not in tag_set:
                raise DatasetContractError("benign_content_transfer_must_be_t1105_positive")
            benign_content_transfer_positive_count += 1
        normalized.append(dict(row))

    manifest_payload = [
        {
            "sample_id": row["sample_id"],
            "procedure_family_id": row["procedure_family_id"],
            "duplicate_group_id": row["duplicate_group_id"],
            "variant_id": row["variant_id"],
            "repetition_id": row["repetition_id"],
            "split": row["split"],
            "dataset_schema_version": row["dataset_schema_version"],
            "feature_schema_id": row["feature_schema_id"],
            "feature_schema_sha256": row["feature_schema_sha256"],
            "extractor_code_sha256": row["extractor_code_sha256"],
            "split_manifest_sha256": row["split_manifest_sha256"],
            "source_binding": row["source_binding"],
            "source_evidence_sha256": row["source_evidence_sha256"],
            "availability_states": row["availability_states"],
            "feature_vector": row["feature_vector"],
            "labels": row["labels"],
            "label_provenance": row["label_provenance"],
            "control_tags": list(row.get("control_tags", ())),
        }
        for row in normalized
    ]
    return {
        "valid": True,
        "rows": len(normalized),
        "procedure_families": len(family_split),
        "duplicate_groups": len(duplicate_split),
        "unique_source_episodes": len(source_bindings),
        "split_rows": dict(Counter(row["split"] for row in normalized)),
        "label_support": {label: dict(counts) for label, counts in label_counts.items()},
        "split_label_support": {
            split: {label: dict(counts) for label, counts in label_map.items()}
            for split, label_map in split_label_counts.items()
        },
        "t1105_valid_nontransfer_hard_negative_rows": hard_negative_counts["T1105"],
        "t1105_benign_content_transfer_positive_rows": benign_content_transfer_positive_count,
        "dataset_content_sha256": hashlib.sha256(_canonical(manifest_payload)).hexdigest(),
    }


def training_blockers(
    validation: Mapping[str, Any],
    *,
    baseline_frozen: bool,
    baseline_identity_verified: bool,
    split_manifest_frozen: bool,
    support_rules_preregistered: bool,
    real_t1105_hard_negatives: bool,
    t1046_controls: bool,
    t1110_controls: bool,
    sealed_final_family_count: int,
) -> list[str]:
    """Return explicit blockers; no empirical floor is invented here."""
    blockers: list[str] = []
    if validation.get("valid") is not True:
        blockers.append("DATASET_VALIDATION_NOT_PASS")
    if int(validation.get("rows", 0)) <= 0:
        blockers.append("NO_INDEPENDENTLY_LABELLED_EPISODE_ROWS")
    split_rows = validation.get("split_rows", {})
    if int(split_rows.get("FIT", 0)) <= 0:
        blockers.append("NO_FIT_ROWS")
    if int(split_rows.get("SELECTION", 0)) <= 0:
        blockers.append("NO_SELECTION_ROWS")
    split_support = validation.get("split_label_support", {})
    for split in ("FIT", "SELECTION"):
        for label in LABEL_ORDER:
            counts = split_support.get(split, {}).get(label, {})
            if int(counts.get("positive", 0)) <= 0 or int(counts.get("negative", 0)) <= 0:
                blockers.append(f"{split}_LACKS_POSITIVE_OR_NEGATIVE_SUPPORT_{label}")
    if not baseline_frozen:
        blockers.append("MODEL1_AND_32F_BASELINE_NOT_FROZEN_FOR_PAIRED_COMPARISON")
    if not baseline_identity_verified:
        blockers.append("BASELINE_RUNTIME_IDENTITY_NOT_VERIFIED")
    if not split_manifest_frozen:
        blockers.append("PROCEDURE_FAMILY_SPLITS_NOT_FROZEN")
    if not support_rules_preregistered:
        blockers.append("PER_LABEL_SUPPORT_MINIMUMS_NOT_PREREGISTERED")
    if not real_t1105_hard_negatives or int(validation.get("t1105_valid_nontransfer_hard_negative_rows", 0)) <= 0:
        blockers.append("NO_INDEPENDENT_REAL_T1105_NONTRANSFER_HARD_NEGATIVES")
    if not t1046_controls:
        blockers.append("NO_INDEPENDENT_T1046_CONTROLLED_POSITIVE_AND_NEGATIVE_SUPPORT")
    if not t1110_controls:
        blockers.append("NO_INDEPENDENT_T1110_CONTROLLED_POSITIVE_AND_NEGATIVE_SUPPORT")
    if sealed_final_family_count <= 0:
        blockers.append("NO_SEALED_FINAL_PROCEDURE_FAMILIES")
    return blockers
