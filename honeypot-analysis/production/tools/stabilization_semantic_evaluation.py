"""Execute the frozen independent stabilization semantic evaluation.

The evaluator is deliberately reporting-only: expectation mismatches are
preserved in its result document and never mutate runtime policies or labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from production.classification.classification_pipeline import (
    NotebookParityClassifier,
)
from production.classification.trust import (
    is_trusted_classification_event,
)
from production.policies.threat_hypothesis_behavior_policy import (
    policy_summary,
)
from production.policies.validate_stix_bundle import (
    validate_stix_bundle_document,
)
from production.reporting.artifacts import (
    attach_report_artifacts,
    build_stix_bundle,
    validate_report_artifact_manifest,
)
from production.reporting.response_guidance_v3 import (
    CURRENT_ACTIVATED_SEMANTIC_FAMILIES,
    validate_response_guidance_v3,
)
from production.reporting.session_assessment_v4 import (
    build_canonical_evidence_snapshot,
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.reporting.typed_semantic_facts import (
    build_typed_semantic_fact_set,
    build_typed_semantic_provenance,
    validate_typed_semantic_fact_set,
)
from production.reporting.typed_semantic_family_selection import (
    select_activated_semantic_family,
    validate_typed_semantic_family_selection,
)
from production.storage.backend import open_storage
from production.utils.config import ProductionConfig


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SPEC = (
    ROOT / "evaluation/stabilization_semantic_evaluation.v1.json"
)
DEFAULT_SPEC_HASH = (
    ROOT / "evaluation/stabilization_semantic_evaluation.v1.sha256"
)
BEHAVIOR_POLICY = (
    ROOT / "configs/threat_hypothesis_behavior.trusted.json"
)
CLASSIFICATION_POLICY = (
    ROOT / "configs/classification_rules.trusted.json"
)


class EvaluationContractError(ValueError):
    """Raised when the frozen input or evaluator contract is invalid."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def load_frozen_spec(
    spec_path: Path = DEFAULT_SPEC,
    hash_path: Path = DEFAULT_SPEC_HASH,
) -> tuple[dict[str, Any], str]:
    raw = spec_path.read_bytes()
    try:
        recorded = hash_path.read_text(encoding="utf-8").split()[0].lower()
    except (OSError, IndexError) as exc:
        raise EvaluationContractError(
            "frozen evaluation SHA-256 record is unavailable"
        ) from exc
    actual = _sha256_bytes(raw)
    if actual != recorded:
        raise EvaluationContractError(
            "frozen evaluation specification SHA-256 mismatch"
        )
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or value.get("schema_version")
        != "stabilization_semantic_evaluation.v1"
        or value.get("labels_frozen_before_execution") is not True
    ):
        raise EvaluationContractError(
            "frozen evaluation specification contract is invalid"
        )
    cases = value.get("cases")
    if not isinstance(cases, list) or len(cases) != 40:
        raise EvaluationContractError(
            "frozen evaluation must contain exactly 40 cases"
        )
    case_ids = [
        str(item.get("case_id") or "")
        for item in cases
        if isinstance(item, dict)
    ]
    if len(case_ids) != 40 or len(set(case_ids)) != 40:
        raise EvaluationContractError(
            "frozen evaluation case identities are invalid"
        )
    return value, actual


def _git_revision() -> str:
    value = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip().lower()
    if len(value) != 40:
        raise EvaluationContractError("evaluator Git revision is invalid")
    return value


def _payload(
    case: dict[str, Any],
    classifier: NotebookParityClassifier,
) -> dict[str, Any]:
    session_id = f"stabilization-{case['case_id'].lower()}"
    base = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
    events: list[dict[str, Any]] = []
    commands: list[str] = []
    successful: list[str] = []
    failed: list[str] = []
    classifications: list[dict[str, Any]] = []
    for index, source in enumerate(case["events"]):
        timestamp = (
            base + timedelta(seconds=index)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        if source["kind"] == "command":
            command = str(source["command"])
            outcome = str(source["outcome"])
            eventid = {
                "success": "cowrie.command.success",
                "failure": "cowrie.command.failed",
                "unknown": "cowrie.command.input",
            }[outcome]
            event: dict[str, Any] = {
                "session": session_id,
                "src_ip": "192.0.2.241",
                "timestamp": timestamp,
                "eventid": eventid,
                "input": command,
            }
            if outcome != "unknown":
                event["success"] = int(outcome == "success")
            commands.append(command)
            if outcome == "success":
                successful.append(command)
            elif outcome == "failure":
                failed.append(command)
            for event_index, classified in enumerate(
                classifier.classify(command)
            ):
                item = dict(classified)
                item.update(
                    {
                        "evidence_id": (
                            f"classification-{case['case_id']}-"
                            f"{index}-{event_index}"
                        ),
                        "event_timestamp": timestamp,
                        "cowrie_eventid": eventid,
                        "command_outcome": outcome,
                        "outcome_scope": (
                            "compound_event"
                            if item.get("subcommand_count", 1) > 1
                            else "fragment"
                        ),
                    }
                )
                classifications.append(item)
        elif source["kind"] == "transfer":
            event = {
                "session": session_id,
                "src_ip": "192.0.2.241",
                "timestamp": timestamp,
                "eventid": source["eventid"],
                "url": source["url"],
                "destfile": source["path"],
                "filename": source["path"],
                "shasum": source["sha256"],
            }
        else:
            raise EvaluationContractError(
                f"unsupported event kind in {case['case_id']}"
            )
        events.append(event)
    if case.get("inject_non_authoritative_context"):
        classifications.append(
            {
                "command": commands[0],
                "ttp": "T1105",
                "tactic": "command-and-control",
                "source": "securebert_unavailable",
                "high_confidence": False,
                "confidence": 0.99,
                "evidence_id": f"audit-only-{case['case_id']}",
                "event_timestamp": events[0]["timestamp"],
                "cowrie_eventid": events[0]["eventid"],
            }
        )
    return {
        "session_id": session_id,
        "src_ip": "192.0.2.241",
        "commands": commands,
        "commands_success": successful,
        "commands_failed": failed,
        "classification_events": classifications,
        "raw_events": events,
    }


def _contexts(case: dict[str, Any]) -> dict[str, Any]:
    if not case.get("inject_non_authoritative_context"):
        return {}
    return {
        "prediction_context": {
            "predicted_tactic": "credential-access",
            "recommendations": ["create a credential finding"],
        },
        "enrichment_context": {
            "reputation": "malicious",
            "recommendations": ["isolate the source automatically"],
        },
        "correlation_context": [
            {"claim": "the session belongs to a known actor"}
        ],
        "llm_context": {
            "hypothesis": "credential theft and execution succeeded"
        },
    }


def _typed_fact_set(
    payload: dict[str, Any],
    evaluator_revision: str,
) -> dict[str, Any]:
    snapshot, observed, _source, behavior = (
        build_canonical_evidence_snapshot(
            payload,
            payload["raw_events"],
            behavior_policy_path=str(BEHAVIOR_POLICY),
        )
    )
    provenance = build_typed_semantic_provenance(
        snapshot,
        observed_behavior=observed,
        behavior_policy_sha256=policy_summary(
            behavior,
            include_integrity=True,
        )["sha256"],
        classification_policy_sha256=_sha256_bytes(
            CLASSIFICATION_POLICY.read_bytes()
        ),
        evaluator_git_revision=evaluator_revision,
    )
    return build_typed_semantic_fact_set(
        observed,
        provenance=provenance,
    )


def _semantic_projection(
    fact_set: dict[str, Any],
    report: dict[str, Any],
) -> dict[str, Any]:
    guidance = deepcopy(report["response_guidance_v3"])
    # Wall-clock rendering metadata is intentionally excluded. Guidance IDs,
    # evidence, actions, traces, provenance, and every safety field remain in
    # the repeatability comparison.
    guidance.pop("generated_at", None)
    return {
        "fact_set": fact_set,
        "assessment_id": report["assessment_id"],
        "status": report["status"],
        "canonical_evidence": report["canonical_evidence"],
        "behavioral_findings": report["behavioral_findings"],
        "hypothesis_sets": report["hypothesis_sets"],
        "provenance": report["provenance"],
        "authority": report["authority"],
        "non_authoritative_context": report[
            "non_authoritative_context"
        ],
        "response_guidance_v3": guidance,
    }


def _case_outputs(
    case: dict[str, Any],
    classifier: NotebookParityClassifier,
    evaluator_revision: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    payload = _payload(case, classifier)
    fact_set = _typed_fact_set(payload, evaluator_revision)
    report = build_session_assessment_v4(
        [payload],
        raw_events=payload["raw_events"],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
        **_contexts(case),
    )
    return payload, fact_set, report


def _set_metric(
    expected_by_case: dict[str, set[str]],
    actual_by_case: dict[str, set[str]],
) -> dict[str, Any]:
    universe = sorted(
        set().union(*expected_by_case.values(), *actual_by_case.values())
    )
    per_label: dict[str, Any] = {}
    total_tp = total_fp = total_fn = 0
    for label in universe:
        tp = sum(
            label in expected_by_case[case_id]
            and label in actual_by_case[case_id]
            for case_id in expected_by_case
        )
        fp = sum(
            label not in expected_by_case[case_id]
            and label in actual_by_case[case_id]
            for case_id in expected_by_case
        )
        fn = sum(
            label in expected_by_case[case_id]
            and label not in actual_by_case[case_id]
            for case_id in expected_by_case
        )
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 1.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
        per_label[label] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }
        total_tp += tp
        total_fp += fp
        total_fn += fn
    micro_precision = (
        total_tp / (total_tp + total_fp)
        if total_tp + total_fp
        else 1.0
    )
    micro_recall = (
        total_tp / (total_tp + total_fn)
        if total_tp + total_fn
        else 1.0
    )
    micro_f1 = (
        2
        * micro_precision
        * micro_recall
        / (micro_precision + micro_recall)
        if micro_precision + micro_recall
        else 0.0
    )
    divisor = len(per_label) or 1
    return {
        "micro": {
            "tp": total_tp,
            "fp": total_fp,
            "fn": total_fn,
            "precision": micro_precision,
            "recall": micro_recall,
            "f1": micro_f1,
        },
        "macro": {
            "precision": sum(
                value["precision"] for value in per_label.values()
            )
            / divisor,
            "recall": sum(
                value["recall"] for value in per_label.values()
            )
            / divisor,
            "f1": sum(
                value["f1"] for value in per_label.values()
            )
            / divisor,
        },
        "per_label": per_label,
    }


def _operation_types(fact_set: dict[str, Any]) -> set[str]:
    operations = {
        str(operation.get("operation_type") or "")
        for fact in fact_set["facts"]
        for operation in fact["operations"]
        if operation.get("operation_type")
    }
    return operations or {"unknown"}


def _family_set(items: Iterable[dict[str, Any]]) -> set[str]:
    return {
        str(item.get("semantic_family"))
        for item in items
        if item.get("semantic_family")
    }


def _hypothesis_defects(report: dict[str, Any]) -> tuple[int, int]:
    contradicted = 0
    unfalsifiable = 0
    for hypothesis_set in report["hypothesis_sets"]:
        if (
            hypothesis_set.get("status") == "contradicted"
            or hypothesis_set.get("contradicted") is True
        ):
            contradicted += 1
        hypotheses = hypothesis_set.get("hypotheses") or []
        if not hypotheses:
            hypotheses = [hypothesis_set]
        for hypothesis in hypotheses:
            falsifiers = (
                hypothesis.get("falsifiers")
                or hypothesis.get("falsification_conditions")
                or hypothesis.get("disconfirming_evidence_required")
                or []
            )
            if not falsifiers:
                unfalsifiable += 1
    return contradicted, unfalsifiable


def run_evaluation(
    *,
    spec_path: Path = DEFAULT_SPEC,
    hash_path: Path = DEFAULT_SPEC_HASH,
) -> dict[str, Any]:
    spec, spec_sha256 = load_frozen_spec(spec_path, hash_path)
    revision = _git_revision()
    classifier = NotebookParityClassifier(
        bert_fn=None,
        rule_policy_path=str(CLASSIFICATION_POLICY),
    )
    expected: dict[str, dict[str, set[str]]] = {
        name: {} for name in (
            "classification",
            "typed_operations",
            "eligible_families",
            "findings",
            "guidance",
        )
    }
    actual: dict[str, dict[str, set[str]]] = {
        name: {} for name in expected
    }
    case_results: list[dict[str, Any]] = []
    total_outputs = 0
    unsupported_outputs = 0
    contradicted_hypotheses = 0
    unfalsifiable_hypotheses = 0
    abstention_correct = 0
    deterministic_cases = 0
    reference_valid_cases = 0
    artifact_valid_cases = 0
    persistence_valid_cases = 0
    with tempfile.TemporaryDirectory(
        prefix="honeypot-stabilization-evaluation-"
    ) as temporary:
        temp_root = Path(temporary)
        storage = open_storage(
            f"sqlite:///{temp_root / 'evaluation.db'}"
        )
        artifact_config = ProductionConfig(
            reports_dir=str(temp_root / "artifacts"),
            enable_artifacts=True,
            enable_stix_export=True,
            enable_pdf_export=True,
        )
        for case in spec["cases"]:
            case_id = case["case_id"]
            expected_values = case["expected"]
            payload, fact_set, report = _case_outputs(
                case,
                classifier,
                revision,
            )
            payload_two, fact_set_two, report_two = _case_outputs(
                case,
                classifier,
                revision,
            )
            deterministic = (
                payload_two == payload
                and _semantic_projection(fact_set_two, report_two)
                == _semantic_projection(fact_set, report)
            )
            deterministic_cases += int(deterministic)

            trusted_ttps = {
                str(item.get("ttp"))
                for item in payload["classification_events"]
                if item.get("ttp")
                and is_trusted_classification_event(item)
            }
            operations = _operation_types(fact_set)
            selected: set[str] = set()
            selection_errors: list[str] = []
            for family in CURRENT_ACTIVATED_SEMANTIC_FAMILIES:
                selection = select_activated_semantic_family(
                    fact_set,
                    family=family,
                )
                selection_errors.extend(
                    validate_typed_semantic_family_selection(
                        selection,
                        fact_set,
                    )
                )
                if selection["status"] == "matched":
                    selected.add(family)
            findings = _family_set(report["behavioral_findings"])
            guidance = _family_set(
                report["response_guidance_v3"]["advisory_actions"]
            )

            expected["classification"][case_id] = set(
                expected_values["classification_techniques"]
            )
            expected["typed_operations"][case_id] = set(
                expected_values["typed_operations"]
            )
            expected["eligible_families"][case_id] = set(
                expected_values["eligible_families"]
            )
            expected["findings"][case_id] = set(
                expected_values["finding_families"]
            )
            expected["guidance"][case_id] = set(
                expected_values["guidance_families"]
            )
            actual["classification"][case_id] = trusted_ttps
            actual["typed_operations"][case_id] = operations
            actual["eligible_families"][case_id] = selected
            actual["findings"][case_id] = findings
            actual["guidance"][case_id] = guidance

            typed_errors = validate_typed_semantic_fact_set(fact_set)
            assessment_errors = validate_session_assessment_v4(report)
            guidance_errors = validate_response_guidance_v3(
                report["response_guidance_v3"]
            )
            reference_errors = (
                typed_errors
                + selection_errors
                + assessment_errors
                + guidance_errors
            )
            reference_valid_cases += int(not reference_errors)

            contradicted, unfalsifiable = _hypothesis_defects(report)
            contradicted_hypotheses += contradicted
            unfalsifiable_hypotheses += unfalsifiable
            expected_maximum = int(
                expected_values.get("maximum_hypothesis_sets", 0)
            )
            if len(report["hypothesis_sets"]) > expected_maximum:
                unsupported_outputs += (
                    len(report["hypothesis_sets"]) - expected_maximum
                )
            for metric_name, value in (
                ("eligible_families", selected),
                ("findings", findings),
                ("guidance", guidance),
            ):
                unsupported_outputs += len(
                    value - expected[metric_name][case_id]
                )
                total_outputs += len(value)
            total_outputs += len(report["hypothesis_sets"])

            must_abstain = bool(expected_values["must_abstain"])
            abstained = not (selected or findings or guidance)
            abstention_ok = (not must_abstain) or abstained
            abstention_correct += int(abstention_ok)

            storage.save_session(payload)
            job_id = storage.enqueue_analysis_job(payload)
            claim = storage.claim_analysis_jobs(
                f"evaluation-{case_id}", 1, 30, 1
            )[0]
            storage.complete_analysis_job(
                job_id,
                claim["claim_owner"],
                claim["claim_token"],
                report,
            )
            persisted = json.loads(
                storage.list_rows_for_session(
                    "reports",
                    payload["session_id"],
                    limit=1,
                )[0]["payload_json"]
            )
            persistence_valid = persisted == report
            persistence_valid_cases += int(persistence_valid)

            stix = build_stix_bundle(report, payload)
            stix_errors = validate_stix_bundle_document(stix)
            rendered = attach_report_artifacts(
                report,
                payload,
                artifact_config,
            )
            manifest_path = (
                rendered.get("artifacts") or {}
            ).get("integrity_manifest", "")
            artifact_errors = list(stix_errors)
            if not manifest_path:
                artifact_errors.append(
                    "artifact integrity manifest was not generated"
                )
            else:
                artifact_errors.extend(
                    validate_report_artifact_manifest(manifest_path)
                )
            artifact_errors.extend(
                validate_session_assessment_v4(rendered)
            )
            artifact_valid_cases += int(not artifact_errors)

            differences = {
                name: {
                    "expected": sorted(expected[name][case_id]),
                    "actual": sorted(actual[name][case_id]),
                    "false_positive": sorted(
                        actual[name][case_id]
                        - expected[name][case_id]
                    ),
                    "false_negative": sorted(
                        expected[name][case_id]
                        - actual[name][case_id]
                    ),
                }
                for name in expected
                if expected[name][case_id] != actual[name][case_id]
            }
            case_results.append(
                {
                    "case_id": case_id,
                    "category": case["category"],
                    "expected": deepcopy(expected_values),
                    "actual": {
                        "classification_techniques": sorted(
                            trusted_ttps
                        ),
                        "typed_operations": sorted(operations),
                        "eligible_families": sorted(selected),
                        "finding_families": sorted(findings),
                        "guidance_families": sorted(guidance),
                        "hypothesis_set_count": len(
                            report["hypothesis_sets"]
                        ),
                        "assessment_id": report["assessment_id"],
                        "guidance_id": report[
                            "response_guidance_v3"
                        ]["guidance_id"],
                        "evidence_sha256": report[
                            "canonical_evidence"
                        ]["evidence_sha256"],
                        "fact_set_sha256": fact_set[
                            "fact_set_sha256"
                        ],
                    },
                    "differences": differences,
                    "checks": {
                        "must_abstain": must_abstain,
                        "abstention_correct": abstention_ok,
                        "reference_and_integrity_valid": (
                            not reference_errors
                        ),
                        "reference_and_integrity_errors": (
                            reference_errors
                        ),
                        "persistence_valid": persistence_valid,
                        "artifact_valid": not artifact_errors,
                        "artifact_errors": artifact_errors,
                        "deterministic_repeat": deterministic,
                        "manual_approval_required": report[
                            "response_guidance_v3"
                        ]["safety"][
                            "manual_approval_required"
                        ],
                        "automatic_execution": report[
                            "response_guidance_v3"
                        ]["safety"]["automatic_execution"],
                        "automatic_alerts_authorized": report[
                            "authority"
                        ]["automatic_alerts_authorized"],
                    },
                }
            )

    metrics = {
        name: _set_metric(expected[name], actual[name])
        for name in expected
    }
    case_count = len(spec["cases"])
    failed_cases = [
        item["case_id"]
        for item in case_results
        if item["differences"]
        or not all(
            (
                item["checks"]["abstention_correct"],
                item["checks"]["reference_and_integrity_valid"],
                item["checks"]["persistence_valid"],
                item["checks"]["artifact_valid"],
                item["checks"]["deterministic_repeat"],
                item["checks"]["manual_approval_required"],
                not item["checks"]["automatic_execution"],
                not item["checks"]["automatic_alerts_authorized"],
            )
        )
    ]
    return {
        "schema_version": (
            "stabilization_semantic_evaluation_result.v1"
        ),
        "evaluation_id": spec["evaluation_id"],
        "spec_sha256": spec_sha256,
        "evaluator_git_revision": revision,
        "policy_provenance": {
            "classification_policy_path": str(
                CLASSIFICATION_POLICY.relative_to(ROOT)
            ),
            "classification_policy_sha256": _sha256_bytes(
                CLASSIFICATION_POLICY.read_bytes()
            ),
            "behavior_policy_path": str(
                BEHAVIOR_POLICY.relative_to(ROOT)
            ),
            "behavior_policy_sha256": _sha256_bytes(
                BEHAVIOR_POLICY.read_bytes()
            ),
        },
        "independence": deepcopy(spec["authoring_record"]),
        "case_count": case_count,
        "metrics": metrics,
        "safety_and_integrity": {
            "unsupported_output_count": unsupported_outputs,
            "unsupported_output_rate": (
                unsupported_outputs / total_outputs
                if total_outputs
                else 0.0
            ),
            "contradicted_hypothesis_count": (
                contradicted_hypotheses
            ),
            "unfalsifiable_hypothesis_count": (
                unfalsifiable_hypotheses
            ),
            "abstention_correct_cases": abstention_correct,
            "abstention_correctness": (
                abstention_correct / case_count
            ),
            "reference_and_integrity_valid_cases": (
                reference_valid_cases
            ),
            "reference_and_integrity_rate": (
                reference_valid_cases / case_count
            ),
            "persistence_valid_cases": persistence_valid_cases,
            "persistence_valid_rate": (
                persistence_valid_cases / case_count
            ),
            "artifact_valid_cases": artifact_valid_cases,
            "artifact_valid_rate": (
                artifact_valid_cases / case_count
            ),
            "deterministic_repeat_cases": deterministic_cases,
            "deterministic_repeatability": (
                deterministic_cases / case_count
            ),
        },
        "failed_case_ids": failed_cases,
        "case_results": case_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
    )
    parser.add_argument(
        "--spec",
        type=Path,
        default=DEFAULT_SPEC,
    )
    parser.add_argument(
        "--spec-sha256",
        type=Path,
        default=DEFAULT_SPEC_HASH,
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_evaluation(
        spec_path=args.spec,
        hash_path=args.spec_sha256,
    )
    rendered = json.dumps(
        result,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    ) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
