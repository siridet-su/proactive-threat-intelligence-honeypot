from __future__ import annotations

import unittest
import hashlib

from model2_unified_session_candidate_20260926.contract import (
    FEATURE_ORDER,
    FEATURE_SCHEMA_SHA256,
    LABEL_ORDER,
    SCHEMA_ID,
)
from model2_unified_session_candidate_20260926.dataset import (
    DATASET_SCHEMA_VERSION,
    DatasetContractError,
    training_blockers,
    validate_rows,
)


def row(sample, family, duplicate, split, labels=None):
    sample_hash = hashlib.sha256(sample.encode()).hexdigest()
    return {
        "sample_id": sample,
        "procedure_family_id": family,
        "duplicate_group_id": duplicate,
        "variant_id": f"variant-{sample}",
        "repetition_id": "rep-1",
        "split": split,
        "dataset_schema_version": DATASET_SCHEMA_VERSION,
        "feature_schema_id": SCHEMA_ID,
        "feature_schema_sha256": FEATURE_SCHEMA_SHA256,
        "extractor_code_sha256": "e" * 64,
        "split_manifest_sha256": "f" * 64,
        "source_binding": {
            "source_session_id": f"source-{sample}",
            "run_id": f"run-{sample}",
            "measurement_id": f"measurement-{sample}",
            "episode_id": f"episode-{sample}",
            "cowrie_event_log_sha256": "a" * 64,
            "pcap_sha256": "b" * 64,
            "zeek_conn_log_sha256": "c" * 64,
        },
        "source_evidence_sha256": sample_hash,
        "availability_states": {
            "cowrie": "COMPLETE",
            "auth": "COMPLETE",
            "pcap": "COMPLETE",
            "zeek_conn": "COMPLETE",
        },
        "feature_vector": {name: 0.0 for name in FEATURE_ORDER},
        "labels": labels or {label: False for label in LABEL_ORDER},
        "label_provenance": {
            "human_adjudication": True,
            "reviewer_blind_to_model_outputs": True,
            "labels_defined_before_fit": False,
            "model_outputs_used": False,
            "source_kind": "independent_lab_adjudication",
            "evidence_reference": "evidence-ref",
            "adjudication_protocol_sha256": "d" * 64,
        },
        "control_tags": [],
    }


class DatasetContractTests(unittest.TestCase):
    def test_empty_manifest_is_valid_mechanics_but_not_trainable(self):
        result = validate_rows([])
        self.assertTrue(result["valid"])
        self.assertEqual(result["rows"], 0)
        blockers = training_blockers(
            result,
            baseline_frozen=True,
            baseline_identity_verified=False,
            split_manifest_frozen=False,
            support_rules_preregistered=False,
            real_t1105_hard_negatives=False,
            t1046_controls=False,
            t1110_controls=False,
            sealed_final_family_count=0,
        )
        self.assertIn("NO_INDEPENDENTLY_LABELLED_EPISODE_ROWS", blockers)
        self.assertIn("NO_INDEPENDENT_REAL_T1105_NONTRANSFER_HARD_NEGATIVES", blockers)

    def test_nonempty_but_unbalanced_rows_do_not_pass_training_support_gate(self):
        validation = validate_rows([row("fit-1", "family-fit", "dup-fit", "FIT")])
        blockers = training_blockers(
            validation,
            baseline_frozen=True,
            baseline_identity_verified=True,
            split_manifest_frozen=True,
            support_rules_preregistered=True,
            real_t1105_hard_negatives=True,
            t1046_controls=True,
            t1110_controls=True,
            sealed_final_family_count=1,
        )
        self.assertIn("NO_SELECTION_ROWS", blockers)
        self.assertIn("FIT_LACKS_POSITIVE_OR_NEGATIVE_SUPPORT_T1105", blockers)

    def test_manifest_hash_is_reproducible_for_same_rows(self):
        rows = [row("s1", "family-fit", "dup-fit", "FIT")]
        self.assertEqual(validate_rows(rows)["dataset_content_sha256"], validate_rows(rows)["dataset_content_sha256"])

    def test_procedure_and_duplicate_groups_must_not_cross_splits(self):
        rows = [
            row("s1", "same-family", "dup1", "FIT"),
            row("s2", "same-family", "dup2", "SELECTION"),
        ]
        with self.assertRaisesRegex(DatasetContractError, "group_leakage_across_splits"):
            validate_rows(rows)

    def test_sealed_final_rows_are_not_opened_by_this_validator(self):
        with self.assertRaisesRegex(DatasetContractError, "only_fit_and_selection_rows_are_permitted"):
            validate_rows([row("s1", "family-final", "dup-final", "SEALED_FINAL")])

    def test_model_predictions_cannot_be_labels_or_features(self):
        bad = row("s1", "family-fit", "dup1", "FIT")
        bad["model2_prediction"] = {"T1105": True}
        with self.assertRaisesRegex(DatasetContractError, "prediction_column_forbidden"):
            validate_rows([bad])
        bad = row("s1", "family-fit", "dup1", "FIT")
        bad["label_provenance"]["source_kind"] = "model_output"
        with self.assertRaisesRegex(DatasetContractError, "independent_label_provenance_missing"):
            validate_rows([bad])

    def test_unapproved_metadata_fixture_fields_and_unavailable_sources_are_rejected(self):
        bad = row("s1", "family-fit", "dup1", "FIT")
        bad["fixture_uri"] = "https://fixture.invalid/secret"
        with self.assertRaisesRegex(DatasetContractError, "row_field_allowlist_mismatch"):
            validate_rows([bad])
        bad = row("s2", "family-fit", "dup2", "FIT")
        bad["availability_states"]["pcap"] = "UNAVAILABLE"
        with self.assertRaisesRegex(DatasetContractError, "required_source_unavailable"):
            validate_rows([bad])

    def test_duplicate_source_episode_and_evidence_are_rejected(self):
        first = row("s1", "family-fit", "dup1", "FIT")
        second = row("s2", "family-fit", "dup2", "FIT")
        second["source_binding"] = first["source_binding"]
        with self.assertRaisesRegex(DatasetContractError, "duplicate_source_episode"):
            validate_rows([first, second])
        second = row("s2", "family-fit", "dup2", "FIT")
        second["source_evidence_sha256"] = first["source_evidence_sha256"]
        with self.assertRaisesRegex(DatasetContractError, "source_evidence_missing_or_duplicate"):
            validate_rows([first, second])

    def test_corpus_extractor_split_and_schema_identity_must_be_frozen(self):
        first = row("s1", "family-fit", "dup1", "FIT")
        second = row("s2", "family-select", "dup2", "SELECTION")
        second["extractor_code_sha256"] = "9" * 64
        with self.assertRaisesRegex(DatasetContractError, "corpus_provenance_identity_mismatch"):
            validate_rows([first, second])
        second = row("s2", "family-select", "dup2", "SELECTION")
        second["feature_schema_sha256"] = "8" * 64
        with self.assertRaisesRegex(DatasetContractError, "feature_schema_identity_mismatch"):
            validate_rows([first, second])

    def test_benign_content_transfer_cannot_be_a_t1105_hard_negative(self):
        bad = row("s1", "family-fit", "dup1", "FIT")
        bad["control_tags"] = ["benign_content_transfer_positive", "session_bound_transfer_activity"]
        bad["labels"]["T1105"] = True
        bad["feature_vector"]["transfer_tool_command_count"] = 1.0
        bad["feature_vector"]["network_connection_count"] = 1.0
        self.assertEqual(validate_rows([bad])["t1105_valid_nontransfer_hard_negative_rows"], 0)

    def test_session_bound_transfer_positive_requires_transfer_command_and_bound_flow_features(self):
        item = row("s1", "family-fit", "dup1", "FIT")
        item["control_tags"] = ["valid_transfer_attempt", "session_bound_transfer_activity"]
        item["labels"]["T1105"] = True
        item["feature_vector"]["transfer_tool_command_count"] = 1.0
        with self.assertRaisesRegex(DatasetContractError, "t1105_session_bound_evidence_missing"):
            validate_rows([item])

    def test_controlled_scenario_provenance_does_not_claim_human_adjudication(self):
        item = row("s1", "family-fit", "dup1", "FIT")
        item["label_provenance"] = {
            "human_adjudication": False,
            "reviewer_blind_to_model_outputs": None,
            "labels_defined_before_fit": True,
            "model_outputs_used": False,
            "source_kind": "preregistered_control_semantics",
            "evidence_reference": "procedure-catalogue:no-transfer",
            "adjudication_protocol_sha256": "d" * 64,
        }
        self.assertTrue(validate_rows([item])["valid"])
        item["label_provenance"]["human_adjudication"] = True
        with self.assertRaisesRegex(DatasetContractError, "controlled_label_provenance_invalid"):
            validate_rows([item])

    def test_nontransfer_hard_negative_tags_require_negative_t1105(self):
        item = row("s1", "family-fit", "dup1", "FIT")
        item["control_tags"] = ["no_session_bound_transfer", "malformed_transfer"]
        self.assertEqual(validate_rows([item])["t1105_valid_nontransfer_hard_negative_rows"], 1)
        item["labels"]["T1105"] = True
        with self.assertRaisesRegex(DatasetContractError, "nontransfer_hard_negative_must_be_t1105_negative"):
            validate_rows([item])

    def test_legacy_benign_large_http_negative_tag_is_not_in_the_contract(self):
        item = row("s1", "family-fit", "dup1", "FIT")
        item["control_tags"] = ["benign_large_http"]
        with self.assertRaisesRegex(DatasetContractError, "control_tags_invalid"):
            validate_rows([item])


if __name__ == "__main__":
    unittest.main()
