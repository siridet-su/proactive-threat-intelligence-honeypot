from __future__ import annotations

import unittest

from research.model2_formula_comparison_20260927.compare import eligible_votes, rank


class FormulaComparisonTest(unittest.TestCase):
    def test_single_success_never_votes_t1110(self) -> None:
        vector = {
            "transfer_tool_command_count": 0,
            "network_connection_count": 1,
            "network_distinct_destination_port_count": 1,
            "auth_failure_count": 0,
            "auth_max_failure_streak": 0,
        }
        self.assertNotIn("T1110", eligible_votes({"T1110": True}, vector))

    def test_repeated_failures_can_vote_t1110(self) -> None:
        vector = {
            "transfer_tool_command_count": 0,
            "network_connection_count": 1,
            "network_distinct_destination_port_count": 1,
            "auth_failure_count": 6,
            "auth_max_failure_streak": 6,
        }
        self.assertIn("T1110", eligible_votes({"T1110": True}, vector))

    def test_model2_never_creates_candidate(self) -> None:
        base = {"T1082": 0.1, "T1105": 0.05}
        self.assertEqual(set(rank(base, {"T1110"}, "gwrre")), set(base))

    def test_both_formulas_promote_supported_model1_candidate(self) -> None:
        base = {"T1082": 0.02, "T1105": 0.019}
        self.assertEqual(rank(base, {"T1105"}, "weighted")[0], "T1105")
        self.assertEqual(rank(base, {"T1105"}, "gwrre")[0], "T1105")


if __name__ == "__main__":
    unittest.main()
