from __future__ import annotations

import copy
import json
from pathlib import Path

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.trust import is_trusted_classification_event
from production.policies.reference_provenance import (
    validate_reference_manifest,
)
from production.policies.threat_hypothesis_behavior_policy import (
    validate_behavior_policy,
)
from production.policies.validate_classification_rules import (
    validate_classification_rule_policy,
)
from production.policies.validate_response_guidance_policy import (
    validate_response_guidance_policy,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "configs"


def _load(name: str) -> dict:
    return json.loads((CONFIGS / name).read_text(encoding="utf-8"))


def test_reference_manifest_is_valid_and_marks_attck_replacement() -> None:
    manifest = _load("trusted_reference_manifest.v1.json")

    assert validate_reference_manifest(manifest) == []
    assert manifest["runtime_fetch"] == "disabled"
    assert manifest["source_artifacts"]["mitre-attack-enterprise"]["sha256"] == (
        "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4"
    )
    assert manifest["techniques"]["T1562"]["revoked"] is True
    assert manifest["techniques"]["T1562"]["superseded_by"] == "T1685"
    assert manifest["techniques"]["T1685"]["name"] == "Disable or Modify Tools"


def test_classification_references_bind_to_current_or_explicitly_retired_attck() -> None:
    policy = _load("classification_rules.trusted.json")

    assert validate_classification_rule_policy(policy) == []
    rules = {rule["rule_id"]: rule for rule in policy["policy"]["rules"]}
    assert rules[
        "cmd-rule-103-t1562-impair-defenses-kill-security-or-miner-processes"
    ]["ttp"] == "T1562"
    assert rules[
        "cmd-rule-103-t1562-impair-defenses-kill-security-or-miner-processes"
    ]["provenance"]["reference_status"] == "historical_pinned"
    retired = [
        rule
        for rule in rules.values()
        if rule.get("ttp") == "T1562" and rule.get("enabled") is False
    ]
    assert len(retired) == 3
    assert all(rule["enabled"] is False for rule in retired)

    forged = copy.deepcopy(policy)
    forged_rule = rules[
        "cmd-rule-103-t1562-impair-defenses-kill-security-or-miner-processes"
    ]
    forged_rule = next(
        rule for rule in forged["policy"]["rules"] if rule["rule_id"] == forged_rule["rule_id"]
    )
    forged_rule["references"][0]["url"] = "https://attack.mitre.org/techniques/T1685/"
    assert any("does not match TTP" in error for error in validate_classification_rule_policy(forged))

    forged_manifest = copy.deepcopy(policy)
    forged_manifest["reference_manifest"]["sha256"] = "0" * 64
    assert any("reference_manifest: SHA-256 mismatch" in error for error in validate_classification_rule_policy(forged_manifest))


def test_historical_t1562_mapping_is_explicitly_pinned_to_the_runtime_cache() -> None:
    cache = _load("../data/feeds/mitre_attack_cache.json")

    class Mitre:
        def get_name(self, ttp: str) -> str:
            return cache["techniques"].get(ttp, {}).get("name", ttp)

        def get_tactics(self, ttp: str) -> list[str]:
            return [
                value.lower().replace(" ", "-")
                for value in cache["techniques"].get(ttp, {}).get("tactics", [])
            ]

    events = NotebookParityClassifier(
        mitre_db=Mitre(),
        rule_policy_path=str(CONFIGS / "classification_rules.trusted.json"),
    ).classify("pkill -f kinsing")
    trusted = [event for event in events if is_trusted_classification_event(event)]

    assert [(event["ttp"], event["name"]) for event in trusted] == [
        ("T1562", "Impair Defenses")
    ]


def test_response_guidance_references_bind_to_snapshots_and_item_scopes() -> None:
    policy = _load("response_guidance_policy.v3.json")

    assert validate_response_guidance_policy(policy) == []
    assert set(policy["reference_scope_by_id"]) >= {
        rule["rule_id"] for rule in policy["finding_rules"]
    }
    assert set(policy["reference_scope_by_id"]) >= {
        action["action_id"]
        for playbook in policy["action_playbooks"]
        for action in playbook["actions"]
    }

    forged_source = copy.deepcopy(policy)
    forged_source["trusted_sources"]["mitre-t1105"]["snapshot_sha256"] = "0" * 64
    assert any("snapshot SHA-256 does not match" in error for error in validate_response_guidance_policy(forged_source))

    forged_scope = copy.deepcopy(policy)
    forged_scope["reference_scope_by_id"]["hunt-observed-transfer-indicators"]["supports"] = []
    assert any("reference_scope.supports" in error for error in validate_response_guidance_policy(forged_scope))


def test_threat_hypothesis_provenance_binds_runtime_artifacts_and_claim_boundary() -> None:
    policy = _load("threat_hypothesis_behavior.trusted.json")

    assert validate_behavior_policy(policy) == []
    scope = policy["provenance"]["reference_scope"]
    assert any("ordered" in value for value in scope["supports"])
    assert any("attacker intent" in value for value in scope["does_not_support"])

    forged_artifact = copy.deepcopy(policy)
    forged_artifact["provenance"]["source_artifacts"][0]["sha256"] = "0" * 64
    assert any("source_artifacts[0]: SHA-256 mismatch" in error for error in validate_behavior_policy(forged_artifact))

    forged_scope = copy.deepcopy(policy)
    forged_scope["provenance"]["reference_scope"]["does_not_support"] = []
    assert any("reference_scope.does_not_support" in error for error in validate_behavior_policy(forged_scope))
