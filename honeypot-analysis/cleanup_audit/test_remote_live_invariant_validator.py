from __future__ import annotations

import json
from pathlib import Path

from remote_live_invariant_validator import (
    assess_session_link_contract,
    derive_expected_session_links,
    deterministic_session_link_id,
    load_pre_metrics,
)


SOURCE = "session-controlled"
PREVIOUS = "session-previous-controlled"
IP_VALUE = "198.51.100.10"
HASSH_VALUE = "fixture-hassh"


class _RelatedStorage:
    def __init__(self, related: dict[tuple[str, str], list[str]]) -> None:
        self.related = related

    def find_sessions_by_observable(
        self,
        observable_type: str,
        observable_value: str,
        *,
        exclude_session_id: str,
        limit: int,
    ) -> list[dict]:
        assert exclude_session_id == SOURCE
        return [
            {"session_id": session_id}
            for session_id in self.related[(observable_type, observable_value)][:limit]
        ]


def _jobs() -> list[dict]:
    return [
        {
            "_id": "job-ip",
            "job_id": "job-ip",
            "observable_type": "ip",
            "observable_value": IP_VALUE,
        },
        {
            "_id": "job-hassh",
            "job_id": "job-hassh",
            "observable_type": "hassh",
            "observable_value": HASSH_VALUE,
        },
    ]


def _actual_document(contract: dict, observable_value: str) -> dict:
    return {
        "_id": contract["link_id"],
        "link_id": contract["link_id"],
        "session_id_a": contract["source_session_id"],
        "session_id_b": contract["related_session_id"],
        "link_type": contract["link_type"],
        "observable_type": contract["observable_type"],
        "observable_value": observable_value,
        "payload_json": json.dumps(
            {
                "link_id": contract["link_id"],
                "job_id": contract["job_id"],
                "source_session_id": contract["source_session_id"],
                "related_session_id": contract["related_session_id"],
            }
        ),
    }


def _completed_jobs(expected: dict[str, dict]) -> list[dict]:
    output = []
    for job in _jobs():
        ids = sorted(
            link_id
            for link_id, item in expected.items()
            if item["job_id"] == job["job_id"]
        )
        output.append(
            {
                **job,
                "result_json": json.dumps(
                    {"links_created": len(ids), "link_ids": ids}
                ),
            }
        )
    return output


def test_expected_link_count_is_derived_from_current_related_set() -> None:
    common_ip = [f"ip-target-{index}" for index in range(8)]
    common_hassh = [f"hassh-target-{index}" for index in range(7)]
    storage = _RelatedStorage(
        {
            ("ip", IP_VALUE): [*common_ip, PREVIOUS],
            ("hassh", HASSH_VALUE): [*common_hassh, PREVIOUS],
        }
    )

    expected = derive_expected_session_links(storage, SOURCE, _jobs(), 100)

    assert len(expected) == 17
    previous_links = [
        item for item in expected.values() if item["related_session_id"] == PREVIOUS
    ]
    assert {item["observable_type"] for item in previous_links} == {"ip", "hassh"}
    assert len(previous_links) == 2


def test_exact_current_link_set_passes_without_hard_coded_count() -> None:
    storage = _RelatedStorage(
        {
            ("ip", IP_VALUE): [f"ip-target-{index}" for index in range(9)],
            ("hassh", HASSH_VALUE): [f"hassh-target-{index}" for index in range(8)],
        }
    )
    expected = derive_expected_session_links(storage, SOURCE, _jobs(), 100)
    actual = [
        _actual_document(
            contract,
            IP_VALUE if contract["observable_type"] == "ip" else HASSH_VALUE,
        )
        for contract in expected.values()
    ]

    result = assess_session_link_contract(
        expected,
        actual,
        actual,
        _completed_jobs(expected),
    )

    assert result["expected_count"] == 17
    assert result["actual_count"] == 17
    assert result["contract_valid"] is True
    assert result["historical_replay_zero"] is True


def test_unrelated_window_link_fails_historical_replay_independently() -> None:
    storage = _RelatedStorage(
        {
            ("ip", IP_VALUE): ["ip-target"],
            ("hassh", HASSH_VALUE): ["hassh-target"],
        }
    )
    expected = derive_expected_session_links(storage, SOURCE, _jobs(), 100)
    actual = [
        _actual_document(
            contract,
            IP_VALUE if contract["observable_type"] == "ip" else HASSH_VALUE,
        )
        for contract in expected.values()
    ]
    replay_id = deterministic_session_link_id(
        "historical-source",
        "historical-target",
        "shared_observable",
        "ip",
        IP_VALUE,
    )
    replay = {
        "_id": replay_id,
        "link_id": replay_id,
        "session_id_a": "historical-source",
        "session_id_b": "historical-target",
    }

    result = assess_session_link_contract(
        expected,
        actual,
        [*actual, replay],
        _completed_jobs(expected),
    )

    assert result["contract_valid"] is True
    assert result["historical_replay_zero"] is False
    assert result["out_of_contract_window_ids"] == [replay_id]


def test_unexpected_controlled_link_fails_contract_even_when_count_can_match() -> None:
    storage = _RelatedStorage(
        {
            ("ip", IP_VALUE): ["ip-target"],
            ("hassh", HASSH_VALUE): ["hassh-target"],
        }
    )
    expected = derive_expected_session_links(storage, SOURCE, _jobs(), 100)
    actual = [
        _actual_document(
            contract,
            IP_VALUE if contract["observable_type"] == "ip" else HASSH_VALUE,
        )
        for contract in expected.values()
    ]
    actual.pop()
    unauthorized_id = deterministic_session_link_id(
        SOURCE,
        "unauthorized-target",
        "shared_observable",
        "hassh",
        HASSH_VALUE,
    )
    actual.append(
        {
            "_id": unauthorized_id,
            "link_id": unauthorized_id,
            "session_id_a": SOURCE,
            "session_id_b": "unauthorized-target",
            "link_type": "shared_observable",
            "observable_type": "hassh",
            "observable_value": HASSH_VALUE,
            "payload_json": json.dumps(
                {
                    "job_id": "job-hassh",
                    "source_session_id": SOURCE,
                    "related_session_id": "unauthorized-target",
                }
            ),
        }
    )

    result = assess_session_link_contract(
        expected,
        actual,
        actual,
        _completed_jobs(expected),
    )

    assert result["actual_count"] == result["expected_count"]
    assert result["contract_valid"] is False
    assert result["unexpected_ids"] == [unauthorized_id]
    assert result["missing_ids"]


def test_pre_metrics_requires_checked_at_boundary(tmp_path: Path) -> None:
    path = tmp_path / "pre.json"
    path.write_text(
        json.dumps({"metrics": {"collection_counts": {"session_links": 1}}})
    )

    counts, checked_at, error = load_pre_metrics(path)

    assert counts is None
    assert checked_at is None
    assert "checked_at" in str(error)

