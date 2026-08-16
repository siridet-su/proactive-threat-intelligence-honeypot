from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from production.classification.trust import classification_evidence_tier
from production.prediction.prediction_attck_label_v2 import (
    ADMISSION_CLASS,
    LABEL_MEANING,
    POLICY_SCHEMA_VERSION,
    PredictionAttckLabelV2Error,
    evaluate_prediction_candidate_v2,
    load_prediction_attck_label_policy_v2,
    validate_prediction_attck_label_policy_v2,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "configs" / "prediction_attck_label_policy.v2.json"
RULE_HASH = "51cfae25ff39238bbb48ee7143fda675dcb22a2be369b3c558970759799f89ee"
MEMBER_HASH = "a" * 64
V1_HASHES = {
    "configs/prediction_attck_label_policy.v1.json": "2f7669d7aacfb4ffa59cc2d9c0b89be88e2b16dfd80b551944ee07db6e8b1cc6",
    "configs/prediction_attck_rule_bindings.v1.json": "9eec0ed41f27f98c3530887b7326063fbc6dd4012b4630ebb8e30d7c4bbe90df",
    "configs/prediction_attck_label_environment.v1.json": "200f209ce1385d10cd38fa8bf78c37773d163d43a9efcd8422a8a71738f3b815",
    "configs/prediction_attck_label_known_answers.v1.json": "00ef47ca1aa2eaef5d3031698d6fdc48ba5b0cf2000a6756a5488f79af91e42a",
    "configs/prediction_attck_label_freeze_receipt.v1.json": "8ba835b6a7bc5b5ab342de23b60e417a3455476b03901f7f3dcd6123ab05e2f4",
    "production/prediction/prediction_attck_label.py": "28885527e05bd1711f39a798452435646c311054eef794186b8965ef938cdea9",
}


def _id(kind: str, name: str) -> str:
    return f"nb{kind}_{hashlib.sha256(name.encode()).hexdigest()}"


@pytest.fixture(scope="module")
def policy() -> dict:
    return load_prediction_attck_label_policy_v2(POLICY_PATH)


def _candidate(
    *,
    command: str,
    rule_id: str,
    tactic: str,
    technique: str,
    name: str = "event",
    parser_status: str = "abstained",
    source: str = "rule",
    event_order: int = 1,
    **extra,
) -> dict:
    candidate = {
        "event_id": _id("event", name),
        "source_member_id": _id("member", "member-one"),
        "source_member_sha256": MEMBER_HASH,
        "event_order": event_order,
        "source": source,
        "evidence_type": "command_regex",
        "rule_id": rule_id,
        "rule_reviewed": True,
        "rule_policy_sha256": RULE_HASH,
        "reviewed_technique": technique,
        "reviewed_tactic": tactic,
        "tactic": tactic,
        "parser_status": parser_status,
        "command": command,
        "prediction_context": {
            "reviewed": True,
            "class": "reviewed_literal_command_pattern",
        },
    }
    candidate.update(extra)
    return candidate


def _evaluate(policy: dict, **candidate) -> dict:
    return evaluate_prediction_candidate_v2(
        _candidate(**candidate),
        policy=policy,
        sanitizer_policy_id="privacy.v1",
        pseudonymization_policy_id="hmac.v1",
        parser_identity="parser.v2",
        splitter_identity="splitter.v1",
        labeler_identity="prediction-attck-labeler.v2",
    )


@pytest.mark.parametrize(
    "command,rule_id,tactic,technique",
    [
        (
            "nproc",
            "cmd-rule-091-t1082-system-information-discovery-runtime-hardware",
            "discovery",
            "T1082",
        ),
        (
            "bash /tmp/a.sh",
            "cmd-rule-097-t1059-command-and-scripting-interpreter-explicit-execution",
            "execution",
            "T1059",
        ),
        (
            "./a.sh",
            "cmd-rule-097-t1059-command-and-scripting-interpreter-explicit-execution",
            "execution",
            "T1059",
        ),
        (
            "chmod 755 /tmp/a.sh",
            "cmd-rule-089-t1222-file-permissions-modification-chmod",
            "defense-evasion",
            "T1222",
        ),
        (
            "history -c",
            "cmd-rule-098-t1070-indicator-removal-history-and-logs",
            "defense-evasion",
            "T1070",
        ),
        (
            "curl http://example.invalid/a",
            "cmd-rule-046-t1105-ingress-tool-transfer",
            "command-and-control",
            "T1105",
        ),
        (
            "wget http://example.invalid/a",
            "cmd-rule-046-t1105-ingress-tool-transfer",
            "command-and-control",
            "T1105",
        ),
        (
            "useradd analyst",
            "cmd-rule-021-t1136-create-account",
            "persistence",
            "T1136",
        ),
    ],
)
def test_reviewed_direct_literal_invocations_are_admitted(
    policy: dict, command: str, rule_id: str, tactic: str, technique: str
) -> None:
    result = _evaluate(
        policy,
        command=command,
        rule_id=rule_id,
        tactic=tactic,
        technique=technique,
        name=command,
    )
    assert result["status"] == "eligible", result
    assert result["label"]["eligibility_reason"] == ADMISSION_CLASS
    assert result["label"]["audit_metadata"]["admission_class"] == ADMISSION_CLASS
    assert result["label"]["tactic"] == tactic
    assert "command" not in result["label"]


def test_inert_lexical_mention_is_excluded(policy: dict) -> None:
    result = _evaluate(
        policy,
        command="echo nproc",
        rule_id="cmd-rule-091-t1082-system-information-discovery-runtime-hardware",
        tactic="discovery",
        technique="T1082",
    )
    assert result["status"] == "excluded"
    assert result["reason_code"] == "inert_lexical_match"


def test_conditional_fragment_remains_a_barrier(policy: dict) -> None:
    result = _evaluate(
        policy,
        command="bash /tmp/a.sh",
        rule_id="cmd-rule-097-t1059-command-and-scripting-interpreter-explicit-execution",
        tactic="execution",
        technique="T1059",
        operator_before="||",
    )
    assert result["status"] == "barrier"
    assert result["reason_code"] == "conditional_execution_unproven"


def test_model_only_and_historically_unreviewed_rules_are_not_restored(
    policy: dict,
) -> None:
    model = _evaluate(
        policy,
        command="nproc",
        rule_id="cmd-rule-091-t1082-system-information-discovery-runtime-hardware",
        tactic="discovery",
        technique="T1082",
        source="securebert",
        parser_status="parsed",
    )
    assert model["status"] == "excluded"
    assert model["reason_code"] == "model_only_or_unsupported_source"
    unreviewed = _evaluate(
        policy,
        command="powershell -enc Zg==",
        rule_id="cmd-rule-037-t1059-command-and-scripting-interpreter",
        tactic="execution",
        technique="T1059",
        parser_status="parsed",
        rule_reviewed=False,
    )
    assert unreviewed["status"] == "excluded"
    assert unreviewed["reason_code"] in {"rule_not_allowlisted", "unreviewed_rule"}
    assert set(policy["admission_class"]["rule_ids"]) == set(
        policy["legacy_literal_invocation_bindings"]
    )
    assert len(policy["admission_class"]["rule_ids"]) == 16


def test_corrected_t1053_binding_remains_persistence(policy: dict) -> None:
    result = _evaluate(
        policy,
        command="schtasks /create /tn demo /tr calc.exe",
        rule_id="cmd-rule-014-t1053-scheduled-task-job",
        tactic="persistence",
        technique="T1053",
        parser_status="parsed",
    )
    assert result["status"] == "eligible"
    assert result["label"]["tactic"] == "persistence"
    assert result["label"]["technique"] == "T1053"
    assert "cmd-rule-014-t1053-scheduled-task-job" not in policy["admission_class"]["rule_ids"]


@pytest.mark.parametrize(
    "extra,reason",
    [
        ({"malformed": True}, "malformed_evidence"),
        ({"conflicting_duplicate": True}, "conflicting_duplicate"),
        ({"dynamic_value": True}, "unresolved_value"),
        ({"unsupported_composition": True}, "unsupported_composition"),
    ],
)
def test_unknown_or_conflicting_evidence_remains_fail_closed(
    policy: dict, extra: dict, reason: str
) -> None:
    result = _evaluate(
        policy,
        command="nproc",
        rule_id="cmd-rule-091-t1082-system-information-discovery-runtime-hardware",
        tactic="discovery",
        technique="T1082",
        **extra,
    )
    assert result["status"] == "barrier"
    assert result["reason_code"] == reason


def test_literal_predicate_and_policy_identity_fail_closed_on_tamper(policy: dict) -> None:
    classification = json.loads(
        (ROOT / "configs" / "classification_rules.trusted.json").read_text(
            encoding="utf-8"
        )
    )
    tampered = copy.deepcopy(policy)
    tampered["legacy_literal_invocation_bindings"][
        "cmd-rule-091-t1082-system-information-discovery-runtime-hardware"
    ]["current_pattern"] = r"\banything\b"
    assert any(
        "pattern" in error
        for error in validate_prediction_attck_label_policy_v2(
            tampered, classification_policy=classification
        )
    )
    with pytest.raises(PredictionAttckLabelV2Error):
        evaluate_prediction_candidate_v2(
            _candidate(
                command="nproc",
                rule_id="cmd-rule-091-t1082-system-information-discovery-runtime-hardware",
                tactic="discovery",
                technique="T1082",
            ),
            policy=tampered,
            sanitizer_policy_id="privacy.v1",
            pseudonymization_policy_id="hmac.v1",
            parser_identity="parser.v2",
            splitter_identity="splitter.v1",
            labeler_identity="labeler.v2",
        )


def test_replay_and_content_identity_are_deterministic(policy: dict) -> None:
    kwargs = {
        "command": "nproc",
        "rule_id": "cmd-rule-091-t1082-system-information-discovery-runtime-hardware",
        "tactic": "discovery",
        "technique": "T1082",
    }
    first = _evaluate(policy, **kwargs)
    second = _evaluate(policy, **kwargs)
    assert first == second
    assert first["label"]["prediction_policy_sha256"] == policy["policy_sha256"]
    assert first["label"]["eligibility_reason"] == ADMISSION_CLASS


def test_label_meaning_and_canonical_trust_are_unchanged(policy: dict) -> None:
    assert policy["label_semantics"]["meaning"] == LABEL_MEANING
    assert not any(
        policy["label_semantics"][claim]
        for claim in (
            "canonical_observed_attck_behavior",
            "proven_execution",
            "successful_execution",
            "attacker_intent",
        )
    )
    canonical = {
        "classification_event_schema": "classification_event.v3",
        "source": "securebert",
        "ttp": "T1059",
        "tactic": "execution",
        "high_confidence": True,
    }
    before = classification_evidence_tier(canonical)
    _evaluate(
        policy,
        command="bash /tmp/a.sh",
        rule_id="cmd-rule-097-t1059-command-and-scripting-interpreter-explicit-execution",
        tactic="execution",
        technique="T1059",
    )
    assert classification_evidence_tier(canonical) == before == "audit_only_candidate"
    trust_sha = hashlib.sha256(
        (ROOT / "production" / "classification" / "trust.py").read_bytes()
    ).hexdigest()
    assert trust_sha == "22269cf5dff6c11bf1720b46bce56361b140678f1baff3150efe2806ebff2919"


def test_v1_frozen_contract_bytes_are_unchanged() -> None:
    for relative, expected in V1_HASHES.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected


def test_v2_known_answers_are_complete() -> None:
    fixture = json.loads(
        (ROOT / "configs" / "prediction_attck_label_known_answers.v2.json").read_text(
            encoding="utf-8"
        )
    )
    assert fixture["schema_version"] == "prediction_attck_label_known_answers.v2"
    assert fixture["policy_schema_version"] == POLICY_SCHEMA_VERSION
    assert fixture["admission_class"] == ADMISSION_CLASS
    assert len(fixture["cases"]) == 21
    assert len({case["case_id"] for case in fixture["cases"]}) == 21

