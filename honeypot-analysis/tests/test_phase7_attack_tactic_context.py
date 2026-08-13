from __future__ import annotations

import copy
import json
from pathlib import Path

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.trust import is_trusted_classification_event
from production.correlation.session_evidence_graph import build_session_evidence_graph
from production.policies.validate_classification_rules import validate_classification_rule_policy
from production.utils.config import ProductionConfig


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "configs" / "classification_rules.trusted.json"
CACHE = ROOT / "data" / "feeds" / "mitre_attack_cache.json"


class _Mitre:
    def __init__(self) -> None:
        self.techniques = json.loads(CACHE.read_text())["techniques"]

    def get_name(self, ttp: str) -> str:
        return self.techniques.get(ttp, {}).get("name", ttp)

    def get_tactics(self, ttp: str) -> list[str]:
        return [
            value.lower().replace(" ", "-")
            for value in self.techniques.get(ttp, {}).get("tactics", [])
        ]


def _classifier() -> NotebookParityClassifier:
    return NotebookParityClassifier(
        mitre_db=_Mitre(), rule_policy_path=str(POLICY)
    )


def _trusted(command: str) -> list[dict]:
    return [
        event for event in _classifier().classify(command)
        if is_trusted_classification_event(event)
    ]


def test_contextual_tactics_and_corrected_mappings() -> None:
    cases = {
        "crontab -e": [("T1053", "persistence")],
        "systemctl status ssh.service": [("T1082", "discovery")],
        "cat /root/.ssh/known_hosts": [("T1018", "discovery")],
        "cat /root/.ssh/id_rsa": [("T1552", "credential-access")],
        "scp user@host:/tmp/a /tmp/a": [("T1105", "command-and-control")],
    }
    for command, expected in cases.items():
        assert [(e["ttp"], e["tactic"]) for e in _trusted(command)] == expected


def test_direction_reads_and_sudoers_boundaries_fail_closed() -> None:
    assert not _trusted("scp /tmp/a user@host:/tmp/a")
    assert not [e for e in _trusted("cat /etc/sudoers") if e["ttp"] == "T1548"]
    assert [(e["ttp"], e["tactic"]) for e in _trusted(
        "echo NOPASSWD >> /etc/sudoers"
    )] == [("T1548", "privilege-escalation")]


def test_structural_and_independent_exact_evidence_are_both_retained() -> None:
    events = _trusted("cat /etc/passwd /root/.ssh/id_rsa")
    assert [(e["ttp"], e["tactic"]) for e in events] == [
        ("T1087.001", "discovery"),
        ("T1552", "credential-access"),
    ]
    assert all(e["observation_semantics"] == "submitted_command_attempt_not_outcome" for e in events)


def test_exact_subtechnique_is_preserved_in_graph() -> None:
    event = _trusted("cat /etc/passwd")[0]
    graph = build_session_evidence_graph({"classification_events": [event]})
    assert event["ttp"] == "T1087.001"
    assert any(node.get("ttp") == "T1087.001" for node in graph["nodes"])


def test_allowlist_and_bound_tactic_validation_fail_closed() -> None:
    policy = json.loads(POLICY.read_text())
    assert validate_classification_rule_policy(policy) == []

    duplicate = copy.deepcopy(policy)
    ids = duplicate["policy"]["runtime_authority"]["trusted_literal_fallback_rule_ids"]
    ids.append(ids[0])
    assert any("duplicates" in error for error in validate_classification_rule_policy(duplicate))

    invalid = copy.deepcopy(policy)
    invalid["policy"]["rules"][0]["reviewed_tactic"] = "impact"
    assert any("not valid for bound TTP" in error for error in validate_classification_rule_policy(invalid))

    missing = copy.deepcopy(policy)
    missing["mitre_cache_binding"]["sha256"] = "0" * 64
    assert any("SHA-256 mismatch" in error for error in validate_classification_rule_policy(missing))


def test_archive_mapping_is_bounded_to_invocation_attempt() -> None:
    event = _trusted("gzip backup.sql")[0]
    assert event["ttp"] == "T1560"
    assert event["observation_semantics"] == "submitted_command_attempt_not_outcome"


def test_unconfigured_prediction_default_is_fail_closed_not_vomm() -> None:
    policy = ProductionConfig().prediction_policy
    assert policy["enabled"] is False
    assert policy["prediction_mode"] == "disabled_pending_reviewed_prediction_policy"
    assert policy["prediction_triggers"]["enabled"] is False
    assert policy["predictive_alerts"]["enabled"] is False
