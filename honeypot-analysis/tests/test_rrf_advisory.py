import unittest

from production.ensemble import rrf_advisory as module
from production.ensemble.evidence import (
    MODEL2_UNIFIED54_ARTIFACT_SHA256,
    MODEL2_UNIFIED54_FEATURE_CONTRACT_SHA256,
    MODEL2_UNIFIED54_VERSION,
    MODEL2_V5_SHADOW_STATUS,
)


def advisory():
    return {
        "schema_version": "session_model1_ttp_advisory.v1",
        "session_id": "s1",
        "authority": "ADVISORY_ONLY",
        "techniques": [
            {"technique_id": "T1082", "supporting_command_events": 3, "rank": 1},
            {"technique_id": "T1105", "supporting_command_events": 2, "rank": 2},
            {"technique_id": "T1110", "supporting_command_events": 1, "rank": 3},
        ],
    }


def ensemble():
    binding = {"session_id": "s1", "run_id": "r1", "measurement_id": "m1", "episode_id": "e1"}
    return {
        "session_id": "s1", "run_id": "r1",
        "model2": {
            "available": True, "status": MODEL2_V5_SHADOW_STATUS,
            "model_version": MODEL2_UNIFIED54_VERSION,
            "artifact_sha256": MODEL2_UNIFIED54_ARTIFACT_SHA256,
            "feature_contract_sha256": MODEL2_UNIFIED54_FEATURE_CONTRACT_SHA256,
            "quality_status": "CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY",
            "capture_selection": "OUTCOME_INDEPENDENT_FIXED_SESSION_WINDOW_V1",
            "one_model": True, "one_inference_call": True,
            "independent_binary_heads": True, "argmax_used": False,
            "measurement_id": "m1", "episode_id": "e1", "binding": binding,
            "t1105_transfer_observed": True, "auth_binding": "PASS",
            "t1110_repeated_auth_observed": True,
            "available_at": "2026-09-26T12:00:01+00:00",
        },
        "results": [
            {"technique_id": "T1105", "model2_available": True, "model2_result": "PRESENT"},
            {"technique_id": "T1046", "model2_available": False, "model2_result": None,
             "model2_unavailable_reason": "t1046_not_observed"},
            {"technique_id": "T1110", "model2_available": True, "model2_result": "ABSENT"},
        ],
    }


class RrfTests(unittest.TestCase):
    def test_present_support_reranks_model1_candidates_only(self):
        result = module.build_rrf_advisory(advisory(), ensemble(), session_id="s1", session_ended=True)
        self.assertEqual(result["status"], "EXPERIMENTAL_RRF")
        self.assertEqual(result["recommendation_order"], ["T1105", "T1082", "T1110"])
        self.assertEqual(result["candidate_set_source"], "MODEL1_ONLY")
        self.assertFalse(next(x for x in result["rows"] if x["technique_id"] == "T1110")["model2_support_added"])

    def test_missing_transfer_gate_is_exact_model1_order(self):
        value = ensemble()
        value["model2"]["t1105_transfer_observed"] = False
        result = module.build_rrf_advisory(advisory(), value, session_id="s1", session_ended=True)
        self.assertEqual(result["status"], "MODEL1_ONLY")
        self.assertEqual(result["recommendation_order"], ["T1082", "T1105", "T1110"])

    def test_wrong_binding_falls_back(self):
        value = ensemble()
        value["model2"]["binding"]["episode_id"] = "wrong"
        model1 = advisory()
        model1["command_rank_lists"] = [
            {"command_ref": "index:0", "ranked_techniques": ["T1110", "T1105", "T1082"]},
        ]
        result = module.build_rrf_advisory(model1, value, session_id="s1", session_ended=True)
        self.assertEqual(result["recommendation_order"], result["baseline_order"])
        self.assertFalse(result["ordering_changed"])
        self.assertEqual(result["fallback_reason"], "model2_binding_mismatch")

    def test_model2_only_ttp_never_enters_candidates(self):
        value = ensemble()
        value["results"].append({"technique_id": "T1046", "model2_available": True, "model2_result": "PRESENT"})
        result = module.build_rrf_advisory(advisory(), value, session_id="s1", session_ended=True)
        self.assertNotIn("T1046", result["recommendation_order"])

    def test_t1110_single_success_style_result_cannot_vote(self):
        value = ensemble()
        value["model2"]["t1110_repeated_auth_observed"] = False
        value["results"][-1]["model2_result"] = "PRESENT"
        result = module.build_rrf_advisory(advisory(), value, session_id="s1", session_ended=True)
        row = next(item for item in result["rows"] if item["technique_id"] == "T1110")
        self.assertFalse(row["model2_support_added"])
        self.assertEqual(row["exclusion_reason"], "t1110_repeated_failed_auth_evidence_required")

    def test_weighted_voting_is_retained_as_separate_comparator(self):
        result = module.build_weighted_voting_advisory(advisory(), ensemble(), session_id="s1", session_ended=True)
        self.assertEqual(result["recommendation_order"][0], "T1105")
        self.assertEqual(result["score_semantics"], "VOTE_SCORE_NOT_PROBABILITY_OR_CONFIDENCE")

    def test_weighted_voting_keeps_model1_order_when_model2_unavailable(self):
        model1 = advisory()
        model1["command_rank_lists"] = [
            {"command_ref": "index:0", "ranked_techniques": ["T1110", "T1105", "T1082"]},
        ]
        result = module.build_weighted_voting_advisory(
            model1, {}, session_id="s1", session_ended=True,
        )
        self.assertEqual(result["recommendation_order"], ["T1082", "T1105", "T1110"])
        self.assertFalse(result["ordering_changed"])

    def test_full_formula_uses_per_command_topk_ranks(self):
        value = advisory()
        value["command_rank_lists"] = [
            {"command_ref": "index:0", "ranked_techniques": ["T1082", "T1105"]},
            {"command_ref": "index:1", "ranked_techniques": ["T1105", "T1082"]},
        ]
        result = module.build_rrf_advisory(value, ensemble(), session_id="s1", session_ended=True)
        row = next(item for item in result["rows"] if item["technique_id"] == "T1082")
        self.assertAlmostEqual(row["model1_rrf_component"], (1 / 61 + 1 / 62) / 2)
        self.assertEqual(result["model1_rank_source"], "per_command_topk")


if __name__ == "__main__":
    unittest.main()
