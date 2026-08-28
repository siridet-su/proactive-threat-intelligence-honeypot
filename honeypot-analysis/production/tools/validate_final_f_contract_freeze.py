"""Offline validator for the Phase-0 Final F contract freeze.

This module is intentionally not imported by production runtime code.  It
validates proposed contracts and known-answer fixtures before later phases
implement them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[2]
BUNDLE_PATH = ROOT / "evaluation" / "final_f_contract_bundle.v1.json"
POLICY_PATH = ROOT / "evaluation" / "final_f_ai_advisory_policy.v2.proposed.json"
PROJECTION_PATH = ROOT / "evaluation" / "final_f_projection_known_answer.v2.json"
OUTPUT_PATH = ROOT / "evaluation" / "final_f_provider_output_known_answer.v2.json"
ABSTENTION_PATH = ROOT / "evaluation" / "final_f_provider_abstention_known_answer.v2.json"
RECEIPT_PATH = ROOT / "evaluation" / "final_f_contract_freeze_receipt.v1.json"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALIAS_RE = re.compile(r"^a_[0-9a-f]{32}$")


class FinalFContractError(ValueError):
    """Raised when a frozen Phase-0 artifact violates its contract."""


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinalFContractError(f"{path.name} must contain one JSON object")
    return value


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FinalFContractError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise FinalFContractError(f"{label} must be a list")
    return value


def _exact(value: Any, keys: Iterable[str], label: str) -> Mapping[str, Any]:
    result = _object(value, label)
    expected = set(keys)
    actual = set(result)
    if actual != expected:
        raise FinalFContractError(
            f"{label} keys differ: missing={sorted(expected - actual)} "
            f"unknown={sorted(actual - expected)}"
        )
    return result


def _strings(value: Any, label: str) -> list[str]:
    items = _list(value, label)
    if any(not isinstance(item, str) or not item for item in items):
        raise FinalFContractError(f"{label} must contain non-empty strings")
    if len(set(items)) != len(items):
        raise FinalFContractError(f"{label} contains duplicates")
    return items


def _aliases(value: Any, label: str) -> list[str]:
    items = _strings(value, label)
    if any(not ALIAS_RE.fullmatch(item) for item in items):
        raise FinalFContractError(f"{label} contains an invalid alias")
    return items


def _sha(value: Any, label: str) -> str:
    text = str(value or "")
    if not SHA256_RE.fullmatch(text):
        raise FinalFContractError(f"{label} must be lowercase SHA-256")
    return text


def _walk_keys(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            yield str(key)
            yield from _walk_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_keys(nested)


def validate_bundle(bundle: Mapping[str, Any]) -> None:
    expected = {
        "schema_version", "architecture_id", "status", "authority_model",
        "versions", "projection_contract", "provider_output_contract",
        "envelope_contracts", "enum_bindings", "chronology", "privacy", "eligibility",
        "compatibility", "evaluation_protocol",
    }
    _exact(bundle, expected, "contract bundle")
    if bundle["schema_version"] != "final_f_contract_bundle.v1":
        raise FinalFContractError("contract bundle schema is invalid")
    if bundle["status"] != "phase0_frozen_not_runtime_active":
        raise FinalFContractError("contract bundle must remain runtime-inactive")
    versions = _object(bundle["versions"], "versions")
    required_versions = {
        "assessment": "session_assessment.v6",
        "guidance": "response_guidance.v4",
        "projection": "ai_advisory_projection.v2",
        "provider_output": "ai_provider_output.v2",
        "validated_output": "ai_advisory_validated_output.v2",
        "rendered_output": "ai_advisory_rendered.v2",
        "record": "ai_advisory_record.v2",
        "task": "ai_advisory_task.v2",
        "vertex_request": "ai_vertex_request.v2",
        "policy": "ai_advisory_policy.v2",
    }
    if dict(versions) != required_versions:
        raise FinalFContractError("successor version catalog is not exact")
    enums = _object(bundle["enum_bindings"], "enum bindings")
    if enums.get("review_plan_step_type") != [
        "review_chain", "review_finding", "test_existing_hypothesis",
        "perform_manual_check", "resolve_evidence_gap",
    ]:
        raise FinalFContractError("review-plan step enum is not exact")
    if enums.get("review_plan_anchor_type") != [
        "chain", "finding", "hypothesis", "action", "evidence_gap",
    ]:
        raise FinalFContractError("review-plan anchor enum is not exact")
    for key in ("semantic_family", "operation_type", "outcome_status"):
        binding = _object(enums.get(key), f"enum binding {key}")
        if binding.get("mode") != "hash_bound_deterministic_source" or not binding.get("source") or not binding.get("binding"):
            raise FinalFContractError(f"enum binding {key} is not hash-bound")
    if enums.get("completion_code") != [
        "accepted", "rejected", "cache_replayed", "deterministic_abstention",
    ]:
        raise FinalFContractError("completion-code enum is not exact")
    chronology = _object(bundle["chronology"], "chronology")
    if chronology.get("chain_fact_list_is_chronology") is not False:
        raise FinalFContractError("chain fact order must not be treated as chronology")
    if chronology.get("classification_only_missing_sequence_creates_step") is not False:
        raise FinalFContractError("missing sequence must not create a chronology step")
    compatibility = _object(bundle["compatibility"], "compatibility")
    for key in ("historical_rewrite", "historical_requeue", "database_migration_required", "prediction_contract_changed"):
        if compatibility.get(key) is not False:
            raise FinalFContractError(f"compatibility.{key} must remain false")
    evaluation = _object(bundle["evaluation_protocol"], "evaluation_protocol")
    if evaluation.get("case_count") != 40:
        raise FinalFContractError("evaluation case count must remain 40")
    if evaluation.get("independent_reviewers_required_for_analyst_claims") != 2:
        raise FinalFContractError("two independent reviewers are required for analyst claims")
    if evaluation.get("prediction_sealed_data_used") is not False:
        raise FinalFContractError("prediction sealed data must remain excluded")


def validate_policy(policy: Mapping[str, Any], bundle: Mapping[str, Any]) -> None:
    expected = {
        "schema_version", "policy_id", "version", "status", "authority",
        "prompt_contract", "step_types", "anchor_types",
        "abstention_reason_codes", "limitation_codes", "evidence_gap_codes",
        "falsifier_codes", "analyst_question_templates",
        "explanation_templates", "limits",
    }
    _exact(policy, expected, "proposed policy")
    if policy["schema_version"] != bundle["versions"]["policy"]:
        raise FinalFContractError("proposed policy schema does not match bundle")
    if policy["status"] != "proposed_not_runtime_active":
        raise FinalFContractError("proposed policy must remain runtime-inactive")
    authority = _object(policy["authority"], "policy authority")
    if not authority or any(value is not False for value in authority.values()):
        raise FinalFContractError("every AI authority flag must be false")
    for key in (
        "step_types", "anchor_types", "abstention_reason_codes",
        "limitation_codes", "evidence_gap_codes", "falsifier_codes",
    ):
        _strings(policy[key], f"policy.{key}")
    for key in ("analyst_question_templates", "explanation_templates"):
        templates = _object(policy[key], f"policy.{key}")
        if not templates or any(not isinstance(value, str) or not value for value in templates.values()):
            raise FinalFContractError(f"policy.{key} must be non-empty reviewed strings")
    limits = _object(policy["limits"], "policy limits")
    if not limits or any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in limits.values()):
        raise FinalFContractError("policy limits must be positive integers")


def _reference_sets(projection: Mapping[str, Any]) -> dict[str, set[str]]:
    return {
        "fact": {str(item["fact_id"]) for item in projection["facts"]},
        "chain": {str(item["chain_id"]) for item in projection["chains"]},
        "relationship": {str(item["relationship_id"]) for item in projection["relationships"]},
        "finding": {str(item["finding_id"]) for item in projection["findings"]},
        "hypothesis": {str(item["hypothesis_id"]) for item in projection["hypotheses"]},
        "action": {str(item["action_id"]) for item in projection["actions"]},
        "evidence_gap": set(projection["evidence_gaps"]),
    }


def validate_projection(
    projection: Mapping[str, Any],
    bundle: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    contract = _object(bundle["projection_contract"], "projection contract")
    _exact(projection, contract["exact_keys"], "projection")
    if projection["schema_version"] != bundle["versions"]["projection"]:
        raise FinalFContractError("projection schema is invalid")
    for key in (
        "report_content_sha256", "evidence_sha256", "graph_sha256",
        "typed_fact_set_sha256", "guidance_content_sha256",
    ):
        _sha(projection[key], f"projection.{key}")
    nested = _object(contract["nested_exact_keys"], "projection nested keys")
    _exact(projection["provenance"], nested["provenance"], "projection.provenance")
    _exact(projection["authority"], nested["authority"], "projection.authority")
    if any(value is not False for value in projection["authority"].values()):
        raise FinalFContractError("projection AI authority flags must all be false")
    if projection["provenance"]["ai_policy_sha256"] != sha256_file(POLICY_PATH):
        raise FinalFContractError("projection policy bytes are not bound")
    if projection["provenance"]["projection_contract_sha256"] != sha256_file(BUNDLE_PATH):
        raise FinalFContractError("projection contract bytes are not bound")
    for key, value in projection["provenance"].items():
        if key.endswith("sha256"):
            _sha(value, f"projection.provenance.{key}")

    type_map = {
        "timeline_steps": "timeline_step", "facts": "fact", "chains": "chain",
        "relationships": "relationship", "findings": "finding",
        "hypotheses": "hypothesis", "actions": "action",
    }
    for collection, nested_name in type_map.items():
        for index, item in enumerate(_list(projection[collection], f"projection.{collection}")):
            _exact(item, nested[nested_name], f"projection.{collection}[{index}]")

    ordinals = [item["ordinal"] for item in projection["timeline_steps"]]
    if ordinals != list(range(1, len(ordinals) + 1)):
        raise FinalFContractError("timeline ordinals must be contiguous and ordered")
    fact_ordinals = {item["fact_id"]: item["causal_ordinal"] for item in projection["facts"]}
    if any(not ALIAS_RE.fullmatch(alias) for alias in fact_ordinals):
        raise FinalFContractError("fact alias is invalid")
    for item in projection["facts"]:
        _aliases(item["evidence_ids"], "fact evidence IDs")
        _aliases(item["entity_ids"], "fact entity IDs")
        if item["causal_ordinal"] not in ordinals:
            raise FinalFContractError("fact causal ordinal does not resolve")
    refs = _reference_sets(projection)
    for values in refs.values():
        for alias in values:
            if alias not in refs["evidence_gap"] and not ALIAS_RE.fullmatch(alias):
                raise FinalFContractError("projected object alias is invalid")
    for item in projection["relationships"]:
        if item["source_fact_id"] not in refs["fact"] or item["target_fact_id"] not in refs["fact"]:
            raise FinalFContractError("relationship fact reference does not resolve")
        if fact_ordinals[item["source_fact_id"]] >= fact_ordinals[item["target_fact_id"]]:
            raise FinalFContractError("relationship contradicts causal order")
    for item in projection["chains"]:
        if set(item["fact_ids"]) - refs["fact"] or set(item["relationship_ids"]) - refs["relationship"]:
            raise FinalFContractError("chain reference does not resolve")
        if not isinstance(item["ai_eligible"], bool):
            raise FinalFContractError("chain eligibility must be boolean")
    for item in projection["findings"]:
        if item["status"] != "supported":
            raise FinalFContractError("projection finding must be trusted/supported")
        if set(item["chain_ids"]) - refs["chain"] or set(item["relationship_ids"]) - refs["relationship"]:
            raise FinalFContractError("finding reference does not resolve")
    for item in projection["hypotheses"]:
        if set(item["chain_ids"]) - refs["chain"] or set(item["fact_ids"]) - refs["fact"]:
            raise FinalFContractError("hypothesis reference does not resolve")
    for item in projection["actions"]:
        if set(item["finding_ids"]) - refs["finding"]:
            raise FinalFContractError("action finding reference does not resolve")
        if item["requires_manual_approval"] is not True or item["safe_to_auto_execute"] is not False or item["execution_integration"] != "not_implemented":
            raise FinalFContractError("action safety boundary is invalid")
    if set(projection["limitations"]) - set(policy["limitation_codes"]):
        raise FinalFContractError("projection limitation code is not reviewed")
    if set(projection["evidence_gaps"]) - set(policy["evidence_gap_codes"]):
        raise FinalFContractError("projection evidence-gap code is not reviewed")

    allowed = _exact(projection["allowed_output"], nested["allowed_output"], "projection.allowed_output")
    expected_allowed = {
        "chain_ids": sorted(refs["chain"]),
        "relationship_ids": sorted(refs["relationship"]),
        "finding_ids": sorted(refs["finding"]),
        "hypothesis_ids": sorted(refs["hypothesis"]),
        "action_ids": sorted(refs["action"]),
        "limitation_codes": sorted(projection["limitations"]),
        "evidence_gap_codes": sorted(projection["evidence_gaps"]),
        "step_types": sorted(policy["step_types"]),
        "anchor_types": sorted(policy["anchor_types"]),
        "abstention_reason_codes": sorted(policy["abstention_reason_codes"]),
    }
    for key, expected_values in expected_allowed.items():
        if sorted(_strings(allowed[key], f"allowed_output.{key}")) != expected_values:
            raise FinalFContractError(f"allowed_output.{key} is not the exact projected catalog")
    template_domains = {
        "analyst_question_template_ids": set(policy["analyst_question_templates"]),
        "explanation_template_ids": set(policy["explanation_templates"]),
    }
    for key, domain in template_domains.items():
        values = _strings(allowed[key], f"allowed_output.{key}")
        if set(values) - domain:
            raise FinalFContractError(f"allowed_output.{key} contains an unreviewed template")
    _exact(projection["abstention"], nested["abstention"], "projection.abstention")
    basis = dict(projection)
    declared = basis.pop("projection_sha256")
    if declared != sha256_json(basis):
        raise FinalFContractError("projection content hash is invalid")

    prohibited = set(bundle["privacy"]["prohibited_fields"])
    found = prohibited.intersection(_walk_keys(projection))
    if found:
        raise FinalFContractError(f"projection contains prohibited fields: {sorted(found)}")


def _anchor_ids(projection: Mapping[str, Any]) -> dict[str, set[str]]:
    refs = _reference_sets(projection)
    return {
        "chain": refs["chain"], "finding": refs["finding"],
        "hypothesis": refs["hypothesis"], "action": refs["action"],
        "evidence_gap": refs["evidence_gap"],
    }


def validate_provider_output(
    output: Mapping[str, Any],
    projection: Mapping[str, Any],
    bundle: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    contract = _object(bundle["provider_output_contract"], "provider output contract")
    _exact(output, contract["exact_keys"], "provider output")
    if output["schema_version"] != bundle["versions"]["provider_output"]:
        raise FinalFContractError("provider output schema is invalid")
    if output["projection_sha256"] != projection["projection_sha256"]:
        raise FinalFContractError("provider output projection hash is stale")
    if output["policy_sha256"] != sha256_file(POLICY_PATH):
        raise FinalFContractError("provider output policy hash is invalid")
    prohibited = set(contract["prohibited_keys"])
    found = prohibited.intersection(_walk_keys(output))
    if found:
        raise FinalFContractError(f"provider output contains prohibited keys: {sorted(found)}")
    synthesis = _exact(output["synthesis"], contract["synthesis_exact_keys"], "synthesis")
    if synthesis["schema_version"] != "ai_advisory_synthesis_selection.v2":
        raise FinalFContractError("synthesis schema is invalid")

    allowed = projection["allowed_output"]
    list_domains = {
        "selected_chain_ids": "chain_ids",
        "selected_relationship_ids": "relationship_ids",
        "ranked_finding_ids": "finding_ids",
        "selected_hypothesis_ids": "hypothesis_ids",
        "ranked_action_ids": "action_ids",
        "selected_limitation_codes": "limitation_codes",
        "selected_evidence_gap_codes": "evidence_gap_codes",
    }
    selections: dict[str, list[str]] = {}
    for key, domain in list_domains.items():
        selections[key] = _strings(synthesis[key], f"synthesis.{key}")
        if set(selections[key]) - set(allowed[domain]):
            raise FinalFContractError(f"synthesis.{key} contains an invented reference")

    anchors = _anchor_ids(projection)
    selected_anchors = {
        "chain": set(selections["selected_chain_ids"]),
        "finding": set(selections["ranked_finding_ids"]),
        "hypothesis": set(selections["selected_hypothesis_ids"]),
        "action": set(selections["ranked_action_ids"]),
        "evidence_gap": set(selections["selected_evidence_gap_codes"]),
    }
    for index, item in enumerate(_list(synthesis["analyst_question_selections"], "question selections")):
        item = _exact(item, contract["question_selection_exact_keys"], f"question selection {index}")
        if item["template_id"] not in allowed["analyst_question_template_ids"]:
            raise FinalFContractError("question template is not allowed")
        if item["anchor_type"] not in anchors or item["anchor_id"] not in selected_anchors[item["anchor_type"]]:
            raise FinalFContractError("question anchor is not selected")
    explanation_pairs: set[tuple[str, str, str]] = set()
    for index, item in enumerate(_list(synthesis["explanation_template_selections"], "explanation selections")):
        item = _exact(item, contract["explanation_selection_exact_keys"], f"explanation selection {index}")
        if item["template_id"] not in allowed["explanation_template_ids"]:
            raise FinalFContractError("explanation template is not allowed")
        if item["anchor_type"] not in anchors or item["anchor_id"] not in selected_anchors[item["anchor_type"]]:
            raise FinalFContractError("explanation anchor is not selected")
        explanation_pairs.add((item["template_id"], item["anchor_type"], item["anchor_id"]))

    steps = _list(synthesis["review_plan"], "review plan")
    if [item.get("order") for item in steps if isinstance(item, Mapping)] != list(range(1, len(steps) + 1)):
        raise FinalFContractError("review plan order must be contiguous")
    expected_anchor = {
        "review_chain": "chain", "review_finding": "finding",
        "test_existing_hypothesis": "hypothesis",
        "perform_manual_check": "action", "resolve_evidence_gap": "evidence_gap",
    }
    related_domains = {
        "related_chain_ids": selected_anchors["chain"],
        "related_finding_ids": selected_anchors["finding"],
        "related_hypothesis_ids": selected_anchors["hypothesis"],
        "related_action_ids": selected_anchors["action"],
        "limitation_codes": set(selections["selected_limitation_codes"]),
        "evidence_gap_codes": selected_anchors["evidence_gap"],
    }
    for index, item in enumerate(steps):
        item = _exact(item, contract["review_plan_item_exact_keys"], f"review plan item {index}")
        if item["step_type"] not in expected_anchor or item["anchor_type"] != expected_anchor[item["step_type"]]:
            raise FinalFContractError("review-plan step and anchor types are inconsistent")
        if item["anchor_id"] not in selected_anchors[item["anchor_type"]]:
            raise FinalFContractError("review-plan anchor is not selected")
        for key, domain in related_domains.items():
            values = _strings(item[key], f"review plan item {index}.{key}")
            if set(values) - domain:
                raise FinalFContractError(f"review plan item {index}.{key} is not selected")
        for template_id in _strings(item["analyst_question_template_ids"], "plan question templates"):
            if template_id not in allowed["analyst_question_template_ids"]:
                raise FinalFContractError("plan question template is not allowed")
        explanation = str(item["explanation_template_id"] or "")
        if explanation and (explanation, item["anchor_type"], item["anchor_id"]) not in explanation_pairs:
            raise FinalFContractError("plan explanation selection is not grounded")

    if synthesis["abstained"] is True:
        if synthesis["abstention_reason_code"] not in allowed["abstention_reason_codes"]:
            raise FinalFContractError("abstention reason is not allowed")
        nonempty = [key for key in list_domains if synthesis[key]]
        nonempty += [key for key in ("analyst_question_selections", "explanation_template_selections", "review_plan") if synthesis[key]]
        if nonempty:
            raise FinalFContractError("abstention must not contain selections")
    elif synthesis["abstained"] is False:
        if synthesis["abstention_reason_code"] != "":
            raise FinalFContractError("non-abstention must have an empty reason")
        if not (selections["selected_chain_ids"] or len(selections["ranked_finding_ids"]) >= 2):
            raise FinalFContractError("non-abstaining synthesis lacks primary context")
        if not steps:
            raise FinalFContractError("non-abstaining synthesis requires a review plan")
    else:
        raise FinalFContractError("synthesis.abstained must be boolean")


def validate_freeze_receipt(receipt: Mapping[str, Any], *, repository_root: Path = ROOT) -> None:
    expected = {
        "schema_version", "status", "phase", "architecture_id",
        "contract_commit", "contract_tree", "files", "runtime_behavior_changed",
        "production_changed", "transformer_changed", "receipt_sha256",
    }
    _exact(receipt, expected, "freeze receipt")
    if receipt["schema_version"] != "final_f_contract_freeze_receipt.v1" or receipt["status"] != "COMPLETE_VALID" or receipt["phase"] != 0:
        raise FinalFContractError("freeze receipt identity/status is invalid")
    if receipt["runtime_behavior_changed"] is not False or receipt["production_changed"] is not False or receipt["transformer_changed"] is not False:
        raise FinalFContractError("Phase 0 receipt records an out-of-scope change")
    commit = str(receipt["contract_commit"] or "")
    tree = str(receipt["contract_tree"] or "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise FinalFContractError("freeze receipt Git identity is invalid")
    actual_tree = subprocess.run(
        ["git", "rev-parse", f"{commit}^{{tree}}"], cwd=repository_root,
        check=True, text=True, capture_output=True,
    ).stdout.strip()
    if actual_tree != tree:
        raise FinalFContractError("freeze receipt tree does not match commit")
    files = _list(receipt["files"], "freeze receipt files")
    paths: set[str] = set()
    for index, item in enumerate(files):
        item = _exact(item, {"path", "sha256"}, f"freeze receipt file {index}")
        relative = str(item["path"] or "")
        if not relative or relative.startswith("/") or ".." in Path(relative).parts or relative in paths:
            raise FinalFContractError("freeze receipt contains an unsafe/duplicate path")
        paths.add(relative)
        expected_sha = _sha(item["sha256"], f"freeze receipt file {relative}")
        blob = subprocess.run(
            ["git", "show", f"{commit}:{relative}"], cwd=repository_root,
            check=True, capture_output=True,
        ).stdout
        if hashlib.sha256(blob).hexdigest() != expected_sha:
            raise FinalFContractError(f"freeze receipt hash mismatch for {relative}")
    basis = dict(receipt)
    declared = basis.pop("receipt_sha256")
    if declared != sha256_json(basis):
        raise FinalFContractError("freeze receipt content hash is invalid")


def validate_phase0_artifacts(*, require_receipt: bool = False) -> dict[str, str]:
    bundle = _load(BUNDLE_PATH)
    policy = _load(POLICY_PATH)
    projection = _load(PROJECTION_PATH)
    output = _load(OUTPUT_PATH)
    abstention = _load(ABSTENTION_PATH)
    validate_bundle(bundle)
    validate_policy(policy, bundle)
    validate_projection(projection, bundle, policy)
    validate_provider_output(output, projection, bundle, policy)
    validate_provider_output(abstention, projection, bundle, policy)
    if RECEIPT_PATH.exists():
        validate_freeze_receipt(_load(RECEIPT_PATH))
    elif require_receipt:
        raise FinalFContractError("Phase 0 freeze receipt is missing")
    return {
        path.name: sha256_file(path)
        for path in (BUNDLE_PATH, POLICY_PATH, PROJECTION_PATH, OUTPUT_PATH, ABSTENTION_PATH)
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-receipt", action="store_true")
    args = parser.parse_args()
    hashes = validate_phase0_artifacts(require_receipt=args.require_receipt)
    print(json.dumps({"status": "PASS", "files": hashes}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
