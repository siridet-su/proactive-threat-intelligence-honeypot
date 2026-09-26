from __future__ import annotations

import unittest
from datetime import datetime, timezone

from model2_unified_session_candidate_20260926.rrf import RRFContractError, rank_candidates


IDENTITY = {"session_id": "s1", "run_id": "r1", "measurement_id": "m1", "episode_id": "e1"}
MODEL_SHA = "a" * 64
SCHEMA_SHA = "b" * 64
NOW = datetime(2026, 9, 26, tzinfo=timezone.utc)


def m1(*labels):
    return [{"source_event_key": "cmd-1", "topk": [{"technique_id": label} for label in labels]}]


def m2(outputs, **gate_overrides):
    eligibility = {
        "session_binding": "PASS",
        "run_binding": "PASS",
        "measurement_binding": "PASS",
        "episode_binding": "PASS",
        "feature_complete": "PASS",
        "pcap_binding": "PASS",
        "zeek_binding": "PASS",
        "network_complete": "PASS",
        "auth_binding": "PASS",
    }
    eligibility.update(gate_overrides)
    return {
        "status": "VALID_SHADOW",
        "authority": "NON_AUTHORITATIVE_SHADOW_ONLY",
        "model_sha256": MODEL_SHA,
        "feature_contract_sha256": SCHEMA_SHA,
        "identity": IDENTITY,
        "generated_at": "2026-09-26T00:00:00Z",
        "eligibility": eligibility,
        "outputs": outputs,
    }


def rank(events, evidence=None, **kwargs):
    return rank_candidates(
        events,
        evidence,
        expected_identity=IDENTITY,
        expected_model_sha256=MODEL_SHA,
        expected_feature_contract_sha256=SCHEMA_SHA,
        now=NOW,
        **kwargs,
    )


class RRFMechanicsTests(unittest.TestCase):
    def test_t1105_model2_vote_is_blocked_by_default(self):
        result = rank(
            m1("T1046", "T1105"),
            m2({"T1105": {"result": "PRESENT"}, "T1046": {"result": "ABSENT"}}),
        )
        self.assertNotIn("T1105", result["model2_vote_labels"])

    def test_valid_t1046_vote_adds_support_without_creating_new_candidate(self):
        result = rank(
            m1("T1105", "T1046"),
            m2({"T1105": {"result": "PRESENT"}, "T1046": {"result": "PRESENT"}, "T1110": {"result": "PRESENT"}}),
        )
        self.assertEqual(result["candidates"][0]["technique_id"], "T1046")
        self.assertEqual({row["technique_id"] for row in result["candidates"]}, {"T1105", "T1046"})
        self.assertIn("T1046", result["model2_vote_labels"])
        self.assertNotIn("T1110", result["model2_vote_labels"])

    def test_missing_wrong_identity_wrong_hash_and_stale_fallback_exactly_to_model1(self):
        baseline = rank(m1("T1105", "T1046", "T1110"), None)
        cases = [
            m2({"T1046": {"result": "PRESENT"}}, session_binding="FAIL"),
            {**m2({"T1046": {"result": "PRESENT"}}), "identity": {**IDENTITY, "run_id": "wrong"}},
            {**m2({"T1046": {"result": "PRESENT"}}), "model_sha256": "f" * 64},
            {**m2({"T1046": {"result": "PRESENT"}}), "generated_at": "2026-09-25T00:00:00Z"},
        ]
        for invalid in cases:
            actual = rank(m1("T1105", "T1046", "T1110"), invalid)
            self.assertEqual(actual["candidates"], baseline["candidates"])

    def test_naive_now_and_invalid_expected_identity_fail_closed(self):
        events = m1("T1046", "T1110")
        evidence = m2({"T1046": {"result": "PRESENT"}})
        naive = rank_candidates(
            events,
            evidence,
            expected_identity=IDENTITY,
            expected_model_sha256=MODEL_SHA,
            expected_feature_contract_sha256=SCHEMA_SHA,
            now=datetime(2026, 9, 26),
        )
        self.assertEqual(naive["candidates"], rank(events)["candidates"])
        no_identity = rank_candidates(
            events,
            evidence,
            expected_identity={},
            expected_model_sha256=MODEL_SHA,
            expected_feature_contract_sha256=SCHEMA_SHA,
            now=NOW,
        )
        self.assertEqual(no_identity["candidates"], rank(events)["candidates"])

    def test_t1046_requires_exact_network_binding_and_t1110_auth_binding(self):
        t1046 = rank(m1("T1046"), m2({"T1046": {"result": "PRESENT"}}, pcap_binding="FAIL"))
        t1110 = rank(m1("T1110"), m2({"T1110": {"result": "PRESENT"}}, auth_binding="FAIL"))
        self.assertFalse(t1046["candidates"][0]["model2_support_added"])
        self.assertFalse(t1110["candidates"][0]["model2_support_added"])

    def test_absent_is_not_a_negative_vote_and_scores_are_not_confidence(self):
        baseline = rank(m1("T1105", "T1046"), None)
        with_absent = rank(
            m1("T1105", "T1046"),
            m2({"T1046": {"result": "ABSENT"}, "T1105": {"result": "ABSENT"}}),
        )
        self.assertEqual(with_absent["candidates"], baseline["candidates"])
        self.assertIn("RANK_SCORE_NOT_PROBABILITY", with_absent["ranking_semantics"])
        self.assertFalse(any("confidence" in key or "probability" in key for key in with_absent))
        self.assertFalse(any("confidence" in key or "probability" in key for key in with_absent["candidates"][0]))

    def test_event_dedup_and_deterministic_ties(self):
        events = [
            {"source_event_key": "cmd-a", "topk": [{"technique_id": "T1046"}, {"technique_id": "T1110"}]},
            {"source_event_key": "cmd-b", "topk": [{"technique_id": "T1110"}, {"technique_id": "T1046"}]},
        ]
        first = rank(events)
        second = rank(list(reversed(events)))
        self.assertEqual(first["candidates"], second["candidates"])
        self.assertEqual(first["candidates"][0]["technique_id"], "T1046")
        duplicate = events + [events[0]]
        self.assertEqual(rank(duplicate)["candidates"], rank(events)["candidates"])

    def test_model1_event_id_collision_fails_closed(self):
        events = [
            {"source_event_key": "cmd-a", "topk": [{"technique_id": "T1046"}]},
            {"source_event_key": "cmd-a", "topk": [{"technique_id": "T1110"}]},
        ]
        with self.assertRaisesRegex(RRFContractError, "model1_event_key_collision"):
            rank(events)

    def test_model1_subtechniques_collapse_to_parent(self):
        result = rank(m1("T1087.001", "T1105"))
        self.assertEqual({row["technique_id"] for row in result["candidates"]}, {"T1087", "T1105"})

    def test_no_model2_only_candidate_can_be_added(self):
        result = rank(
            m1("T1105"),
            m2({"T1046": {"result": "PRESENT"}, "T1105": {"result": "PRESENT"}}),
        )
        self.assertEqual([row["technique_id"] for row in result["candidates"]], ["T1105"])


if __name__ == "__main__":
    unittest.main()
