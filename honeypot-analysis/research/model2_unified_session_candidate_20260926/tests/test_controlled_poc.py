from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from model2_unified_session_candidate_20260926.controlled_poc import (
    POC_WARNING,
    _collision_audit,
    _matched_benign_content_audit,
    build_corpus,
    run,
    train_and_evaluate,
)
from model2_unified_session_candidate_20260926.contract import FEATURE_ORDER, LABEL_ORDER


class ControlledPocTests(unittest.TestCase):
    def test_corpus_is_deterministic_balanced_and_grouped(self):
        first, manifest = build_corpus(repetitions=2)
        second, second_manifest = build_corpus(repetitions=2)
        self.assertEqual(first, second)
        self.assertEqual(manifest, second_manifest)
        self.assertEqual(manifest["rows_total"], 180)
        self.assertEqual(manifest["families_total"], 90)
        self.assertEqual(manifest["split_rows"], {"FIT": 60, "SELECTION": 60, "SEALED_FINAL": 60})
        for split in ("FIT", "SELECTION", "SEALED_FINAL"):
            subset = [row for row in first if row["split"] == split]
            for label in LABEL_ORDER:
                self.assertTrue(any(row["labels"][label] for row in subset))
                self.assertTrue(any(not row["labels"][label] for row in subset))
        family_splits = {}
        for row in first:
            old = family_splits.setdefault(row["procedure_family_id"], row["split"])
            self.assertEqual(old, row["split"])

    def test_rows_are_extracted_with_exact_schema_and_no_http_log(self):
        rows, manifest = build_corpus(repetitions=1)
        self.assertTrue(manifest["fit_selection_validation"]["valid"])
        for row in rows:
            self.assertEqual(tuple(row["feature_vector"]), FEATURE_ORDER)
            self.assertEqual(row["availability_states"]["zeek_conn"], "COMPLETE")
            rendered = str(row)
            self.assertNotIn("http_status", rendered)
            self.assertNotIn("response_body_len", rendered)

    def test_one_unified_artifact_has_three_heads(self):
        rows, _ = build_corpus(repetitions=2)
        artifact, evaluation = train_and_evaluate(rows)
        self.assertEqual(artifact["architecture"], "UNIFIED_ARTIFACT_WITH_THREE_OVR_HEADS")
        self.assertEqual(tuple(artifact["heads"]), LABEL_ORDER)
        self.assertEqual(len(artifact["selected_feature_names"]), len(FEATURE_ORDER))
        self.assertEqual(evaluation["scored_sealed_final_rows"], 60)
        self.assertEqual(evaluation["warning"], POC_WARNING)

    def test_benign_content_transfer_is_positive_and_matches_basic_transfer(self):
        rows, _ = build_corpus(repetitions=1)
        audit = _collision_audit(rows)
        paired = _matched_benign_content_audit(rows)
        self.assertEqual(audit["conflicting_vector_groups"], 0)
        self.assertEqual(paired["matched_pairs"], 3)
        self.assertEqual(paired["identical_feature_pairs"], 3)
        self.assertEqual(paired["identical_label_pairs"], 3)
        for row in rows:
            if "benign_content_transfer_positive" in row["control_tags"]:
                self.assertTrue(row["labels"]["T1105"])
                self.assertIn("session_bound_transfer_activity", row["control_tags"])

    def test_preregistered_negative_controls_and_mixed_labels_are_present_per_split(self):
        rows, _ = build_corpus(repetitions=1)
        for split in ("FIT", "SELECTION", "SEALED_FINAL"):
            subset = [row for row in rows if row["split"] == split]
            for tag in (
                "malformed_transfer", "embedded_transfer_text", "quoted_transfer_text",
                "url_without_transfer_tool", "local_file_operation", "execute_existing_local_file",
                "transfer_attempt_no_session_flow",
            ):
                self.assertTrue(any(tag in row["control_tags"] and not row["labels"]["T1105"] for row in subset))
            self.assertTrue(any(row["labels"] == {"T1105": True, "T1046": True, "T1110": True} for row in subset))
            self.assertTrue(any(row["labels"] == {"T1105": False, "T1046": True, "T1110": True} for row in subset))
            t1110_hard_negatives = [
                row for row in subset
                if "single_success_t1110_hard_negative" in row["control_tags"]
            ]
            self.assertEqual(len(t1110_hard_negatives), 3)
            self.assertTrue(all(row["labels"]["T1110"] is False for row in t1110_hard_negatives))

    def test_run_writes_research_only_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run(Path(directory), repetitions=1)
            self.assertFalse(result["claims"]["production_readiness"])
            self.assertEqual(result["claims"]["real_world_accuracy"], "NOT_ESTIMATED")
            self.assertEqual(len(list(Path(directory).glob("*.json"))), 4)
            self.assertTrue(result["evaluation_protocol"]["all_candidates_frozen_before_final_scoring"])
            self.assertTrue(result["evaluation_protocol"]["final_set_scored_in_one_evaluation_run"])
            self.assertEqual(result["collision_audit"]["conflicting_vector_groups"], 0)


if __name__ == "__main__":
    unittest.main()
