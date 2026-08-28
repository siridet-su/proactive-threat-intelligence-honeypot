from __future__ import annotations

import json

from production.reporting.feedback_review import build_feedback_review


def test_feedback_review_decodes_json_backed_historical_rows() -> None:
    review = build_feedback_review(
        [
            {
                "session_id": "historical-session",
                "snapshot_id": "historical-snapshot",
                "label": "wrong",
                "predicted_top_tactic": "execution",
                "final_actual_next_tactic": "discovery",
                "predicted_ranking": json.dumps(
                    [
                        {
                            "tactic": "execution",
                            "confidence": "high",
                            "score": 0.8,
                            "sources": [
                                {
                                    "name": "external_seed_transition",
                                    "source_type": "empirical_external",
                                }
                            ],
                        }
                    ]
                ),
            },
            {
                "payload_json": json.dumps(
                    {
                        "session_id": "payload-session",
                        "snapshot_id": "payload-snapshot",
                        "label": "useful",
                        "predicted_top_tactic": "discovery",
                        "final_actual_next_tactic": "discovery",
                        "predicted_ranking": [
                            {
                                "tactic": "discovery",
                                "confidence": "low",
                                "score": 0.3,
                            }
                        ],
                    }
                )
            },
        ]
    )

    assert review["feedback_count"] == 2
    assert review["label_counts"] == {"wrong": 1, "useful": 1}
    assert review["high_confidence_wrong"][0]["session_id"] == (
        "historical-session"
    )
    assert review["high_confidence_wrong"][0]["source_names"] == [
        "external_seed_transition"
    ]
    assert review["low_confidence_useful"][0]["session_id"] == "payload-session"


def test_feedback_review_treats_malformed_json_as_missing_context() -> None:
    review = build_feedback_review(
        [
            {
                "payload_json": "{not-json",
                "predicted_ranking": "[not-json",
                "label": "needs_review",
            }
        ]
    )

    assert review["feedback_count"] == 1
    assert review["label_counts"] == {"needs_review": 1}
    assert review["missing_final_actual_next_tactic"] == 1
