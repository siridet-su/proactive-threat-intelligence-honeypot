"""Generate a conservative, scoped review of session-correlation policy rules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Mapping

from production.utils.serialization import utc_now


REVIEW_NOTES: Dict[str, str] = {
    "cowrie-file-transfer-correlates-t1105": "A Cowrie file-download event directly supports transfer into the emulated session, while the rule explicitly avoids execution and persistence claims.",
    "downloader-command-observed-correlates-t1105": "The rule distinguishes downloader intent from a successful Cowrie transfer event.",
    "download-then-execute-chain-correlates-t1059": "Ordered trusted command evidence supports an execution attempt candidate; successful execution and impact remain unconfirmed.",
    "ssh-login-failures-correlate-t1110": "Five observed failures support a report-only password-guessing hypothesis; the threshold remains an operational heuristic.",
    "linux-shadow-read-correlates-t1003-008": "The command directly references /etc/shadow, but successful access and credential recovery are not claimed.",
    "ssh-private-key-read-correlates-t1552-004": "The command directly references a private-key path, but collection is not claimed.",
    "history-or-log-cleanup-correlates-t1070": "Observed cleanup commands support an attempt candidate, not confirmed indicator removal.",
    "cron-modification-correlates-t1053": "Modification evidence is required; read-only crontab listing is excluded.",
    "authorized-keys-modification-correlates-t1098": "A write/copy/install/attribute-change operation is required; a path mention alone is excluded.",
    "recon-then-payload-chain-correlates-t1105": "The ordered pattern supports a possible staged workflow without claiming transfer success or execution.",
    "botnet-miner-staging-correlates-t1496": "Wording was softened in this pass to possible resource-hijacking attempt; successful mining, resource use, and impact are explicitly unconfirmed.",
    "shell-startup-persistence-correlates-t1546": "A startup-file modification operation is required and successful persistence is not claimed.",
    "remote-service-attempt-correlates-t1021": "The rule describes attempted SSH/SCP use and explicitly avoids successful lateral-movement claims.",
    "decode-then-execute-chain-correlates-t1140": "Trusted ordered decode and execution-command evidence supports a candidate chain, not successful decoding or execution.",
    "privilege-escalation-attempt-correlates-t1548": "The rule is explicitly attempt-level and does not claim successful privilege gain.",
}


def _md(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def build(policy_document: Mapping[str, Any]) -> Dict[str, Any]:
    rules = []
    for rule in policy_document.get("policy", {}).get("rules", []):
        if not isinstance(rule, dict) or rule.get("enabled") is False:
            continue
        rule_id = str(rule.get("rule_id") or "unknown")
        conditions = rule.get("conditions") or {}
        encoded_conditions = json.dumps(conditions, sort_keys=True)
        report_only = rule.get("apply_to_prediction") is False
        conservative = any(
            phrase in str(rule.get("reason") or "").lower()
            for phrase in ("not confirmed", "does not", "candidate", "hypothesis", "attempt")
        )
        rules.append({
            "rule_id": rule_id,
            "required_evidence": conditions,
            "mapped_ttp": rule.get("ttp"),
            "mapped_tactic": rule.get("tactic"),
            "cowrie_observability": (
                "direct Cowrie event and/or trusted command-derived evidence; "
                "classification evidence remains a candidate mapping"
            ),
            "directly_observable_from_cowrie": True,
            "wording_is_conservative": conservative,
            "report_only": report_only,
            "configured_confidence_field": rule.get("confidence"),
            "confidence_semantics": "developer-defined policy_strength, not probability",
            "ai_assisted_judgment": "acceptable" if report_only and conservative else "needs_wording_softening",
            "review_note": REVIEW_NOTES.get(rule_id, "Observable rule retained as report-only pending empirical evaluation."),
            "condition_types": sorted(set(
                match
                for match in (
                    "eventid" if '"type": "eventid"' in encoded_conditions else "",
                    "classification_ttp" if '"type": "classification_ttp"' in encoded_conditions else "",
                    "command_regex" if '"type": "command_regex"' in encoded_conditions else "",
                    "ordered_ttps" if '"type": "ordered_ttps"' in encoded_conditions else "",
                    "login_failure_count" if "login_fail" in encoded_conditions else "",
                )
                if match
            )),
        })
    return {
        "schema_version": "session_correlation_review.v1",
        "generated_at": utc_now(),
        "review_type": "researcher/AI-assisted consistency review",
        "validation_status": "not independent expert validation; not empirical rule precision",
        "scope": "Cowrie honeypot-observable SSH behavior",
        "rule_count": len(rules),
        "all_rules_report_only": all(item["report_only"] for item in rules),
        "confidence_semantics": "All numeric confidence fields are developer-defined policy strengths, not calibrated probabilities.",
        "prediction_promotion": "none; every reviewed rule remains apply_to_prediction=false",
        "rules": rules,
    }


def render(document: Mapping[str, Any]) -> str:
    lines = [
        "# Session Correlation Rule Review (2026-07-13)", "",
        "> Researcher/AI-assisted consistency review, not independent expert validation or an empirical precision study.", "",
        f"Reviewed **{document['rule_count']}** enabled rules. All remain report-only: **{document['all_rules_report_only']}**.", "",
        "Numeric `confidence` values are developer-defined `policy_strength` values, not probabilities.", "",
        "| Rule | Required evidence | TTP / tactic | Cowrie-observable | Conservative | Report-only | Judgment | Review note |",
        "|---|---|---|---:|---:|---:|---|---|",
    ]
    for item in document["rules"]:
        lines.append("| " + " | ".join(_md(value) for value in (
            item["rule_id"], ", ".join(item["condition_types"]),
            f"{item['mapped_ttp']} / {item['mapped_tactic']}",
            str(item["directly_observable_from_cowrie"]).lower(),
            str(item["wording_is_conservative"]).lower(),
            str(item["report_only"]).lower(), item["ai_assisted_judgment"], item["review_note"],
        )) + " |")
    lines.extend([
        "", "## Decision", "",
        "All rules remain report-only. No correlation rule was promoted into realtime prediction. The miner-staging rule wording was softened to avoid implying successful resource hijacking, execution, resource consumption, or impact.", "",
        "## Limitation", "",
        "This review assesses observable-evidence fit and conservative wording. It does not estimate empirical precision, recall, or calibrated probability.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="configs/session_ttp_correlation.trusted.json")
    parser.add_argument("--json-output", required=True)
    parser.add_argument("--markdown-output", required=True)
    args = parser.parse_args()
    document = build(json.loads(Path(args.policy).read_text(encoding="utf-8")))
    json_path = Path(args.json_output)
    md_path = Path(args.markdown_output)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render(document), encoding="utf-8")
    print(json.dumps({
        "rule_count": document["rule_count"],
        "all_rules_report_only": document["all_rules_report_only"],
        "judgments": {item["rule_id"]: item["ai_assisted_judgment"] for item in document["rules"]},
        "outputs": [str(json_path), str(md_path)],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
