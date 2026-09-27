from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from model2_unified_session_candidate_20260926.controlled_poc import _episode, _procedures
from model2_unified_session_candidate_20260926.shadow_runtime import (
    ShadowRuntimeError,
    infer_envelope,
    load_candidate,
)


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "controlled_poc_output/MODEL2_UNIFIED_CONTROLLED_POC_ARTIFACT.v1.json"
SCHEMA = ROOT / "FEATURE_SCHEMA.v1.json"
MANIFEST = ROOT / "CANDIDATE_MANIFEST.v1.json"


class ShadowRuntimeTests(unittest.TestCase):
    def load(self):
        return load_candidate(ARTIFACT, feature_schema_path=SCHEMA, candidate_manifest_path=MANIFEST)

    def test_exact_artifact_loads_as_one_unified_candidate(self):
        model = self.load()
        self.assertEqual(tuple(model.heads), ("T1105", "T1046", "T1110"))
        self.assertEqual(len(model.selected_indices), 54)

    def test_shadow_inference_is_available_but_never_vote_eligible(self):
        procedure = next(item for item in _procedures() if item.family == "sealed-final-all")
        envelope, identity = _episode(procedure, 1)
        result = infer_envelope(envelope, self.load(), expected_identity=identity)
        self.assertEqual(result["status"], "VALID_RESEARCH_SHADOW")
        self.assertEqual(result["feature_count"], 54)
        self.assertFalse(result["rrf_vote_eligible"])
        self.assertTrue(result["one_unified_artifact"])
        self.assertEqual(result["t1105_gate"], "BLOCK")
        self.assertEqual(result["production_t1105_gate"], "BLOCK")
        self.assertFalse(result["canonical_write_authority"])
        self.assertFalse(result["response_authority"])
        self.assertTrue(all(not item["ensemble_vote_eligible"] for item in result["outputs"].values()))
        self.assertTrue(all(item["score_semantics"].endswith("NOT_CALIBRATED_PROBABILITY") for item in result["outputs"].values()))

    def test_required_smoke_cases_and_benign_transfer_label_agreement(self):
        model = self.load()
        results = {}
        for name in ("all", "none", "transfer-basic", "benign-content-transfer", "malformed-transfer", "discovery", "bruteforce"):
            procedure = next(item for item in _procedures() if item.family == f"sealed-final-{name}")
            envelope, identity = _episode(procedure, 1)
            results[name] = infer_envelope(envelope, model, expected_identity=identity)
            self.assertEqual(results[name]["status"], "VALID_RESEARCH_SHADOW", name)
            self.assertEqual(results[name]["model_artifact_sha256"], model.artifact_file_sha256)
            self.assertEqual(set(results[name]["outputs"]), {"T1105", "T1046", "T1110"})
            self.assertFalse(results[name]["rrf_vote_eligible"])
            self.assertTrue(all(not item["ensemble_vote_eligible"] for item in results[name]["outputs"].values()))
        basic = results["transfer-basic"]["outputs"]["T1105"]
        benign = results["benign-content-transfer"]["outputs"]["T1105"]
        self.assertEqual(basic["decision"], benign["decision"])
        self.assertEqual(basic["decision_score"], benign["decision_score"])
        self.assertEqual(basic["score_semantics"], "SIGMOID_DECISION_SCORE_NOT_CALIBRATED_PROBABILITY")

    def test_missing_episode_evidence_fails_closed_without_vector_or_vote(self):
        procedure = next(item for item in _procedures() if item.family == "fit-transfer-basic")
        envelope, identity = _episode(procedure, 1)
        envelope["network"]["complete"] = False
        result = infer_envelope(envelope, self.load(), expected_identity=identity)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertFalse(result["rrf_vote_eligible"])
        self.assertTrue(all(item["decision"] is None for item in result["outputs"].values()))

    def test_tampered_artifact_is_rejected_by_file_hash(self):
        value = json.loads(ARTIFACT.read_text())
        value["heads"]["T1105"]["threshold"] = 0.99
        with tempfile.TemporaryDirectory() as directory:
            tampered = Path(directory) / "artifact.json"
            tampered.write_text(json.dumps(value))
            with self.assertRaisesRegex(ShadowRuntimeError, "artifact_file_sha256_mismatch"):
                load_candidate(tampered, feature_schema_path=SCHEMA, candidate_manifest_path=MANIFEST)

    def test_manifest_bound_to_previous_model_identity_is_rejected(self):
        value = json.loads(MANIFEST.read_text())
        value["canonical_model_identity_sha256"] = "095ce820ae8e697247611dbf4b35304edb71d26aa3e85ea9d116dea31c89a027"
        with tempfile.TemporaryDirectory() as directory:
            old_manifest = Path(directory) / "old-manifest.json"
            old_manifest.write_text(json.dumps(value))
            with self.assertRaisesRegex(ShadowRuntimeError, "canonical_model_identity_mismatch"):
                load_candidate(ARTIFACT, feature_schema_path=SCHEMA, candidate_manifest_path=old_manifest)


if __name__ == "__main__":
    unittest.main()
