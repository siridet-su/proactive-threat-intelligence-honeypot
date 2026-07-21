"""Validate realtime prediction policy provenance before deployment."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, Iterable, List


ALLOWED_SOURCE_TYPES = {
    "empirical_local",
    "external_cowrie_seed",
    "human_curated_attck_prior",
    "detection_correlation",
    "context_modifier",
    "risk_modifier",
    "heuristic_prior",
}

TRUSTED_RULE_SECTIONS = (
    "tactic_combination_rules",
    "mitre_association_rules",
    "sigma_correlation_rules",
)


def load_policy_file(path: str | Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, dict):
        raise ValueError("policy file must contain a JSON object")
    return loaded


def _policy_body(document: Dict[str, Any]) -> Dict[str, Any]:
    body = document.get("policy", document)
    return body if isinstance(body, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _rule_path(section: str, index: int, field: str = "") -> str:
    suffix = f".{field}" if field else ""
    return f"policy.{section}[{index}]{suffix}"


def _finite_nonnegative(value: Any) -> bool:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    return math.isfinite(number) and number >= 0.0


def _validate_weights(policy: Dict[str, Any], errors: List[str]) -> None:
    weights = policy.get("weights") or {}
    if not isinstance(weights, dict) or not weights:
        errors.append("policy.weights must be a non-empty object")
        return
    total = 0.0
    for name, value in weights.items():
        if not _finite_nonnegative(value):
            errors.append(f"policy.weights.{name} must be a finite non-negative number")
            continue
        total += float(value)
    if total <= 0.0:
        errors.append("policy.weights must contain at least one positive weight")


def _validate_prediction_mode(policy: Dict[str, Any], errors: List[str]) -> None:
    mode = str(policy.get("prediction_mode") or "primary_transition_with_fallback").strip()
    if mode not in {"primary_transition_with_fallback", "weighted_ensemble_baseline", "external_hard_backoff_vomm"}:
        errors.append("policy.prediction_mode must be primary_transition_with_fallback, weighted_ensemble_baseline, or external_hard_backoff_vomm")
    if "compute_weighted_ensemble_baseline" in policy and not isinstance(
        policy.get("compute_weighted_ensemble_baseline"),
        bool,
    ):
        errors.append("policy.compute_weighted_ensemble_baseline must be boolean")
    influence_scope = str(policy.get("weight_influence_scope") or "").strip()
    if influence_scope:
        expected_scope = (
            "production_ranking"
            if mode == "weighted_ensemble_baseline"
            else "not_applicable_external_authority"
            if mode == "external_hard_backoff_vomm"
            else "diagnostic_only"
        )
        if influence_scope not in {"diagnostic_only", "production_ranking", "not_applicable_external_authority"}:
            errors.append(
                "policy.weight_influence_scope must be diagnostic_only, production_ranking, or not_applicable_external_authority"
            )
        elif influence_scope != expected_scope:
            errors.append(
                "policy.weight_influence_scope must match the configured prediction_mode "
                f"({expected_scope})"
            )
    primary_transition = policy.get("primary_transition")
    if primary_transition is None:
        return
    if not isinstance(primary_transition, dict):
        errors.append("policy.primary_transition must be an object")
        return
    if "primary_model" in primary_transition and not str(primary_transition.get("primary_model") or "").strip():
        errors.append("policy.primary_transition.primary_model must be non-empty")
    source_order = primary_transition.get("source_order")
    if source_order is not None:
        if not isinstance(source_order, list) or not source_order:
            errors.append("policy.primary_transition.source_order must be a non-empty list")
        else:
            for index, item in enumerate(source_order):
                if not str(item or "").strip():
                    errors.append(f"policy.primary_transition.source_order[{index}] must be non-empty")
    if mode != "external_hard_backoff_vomm" and "fallback_scorer" in primary_transition and not str(primary_transition.get("fallback_scorer") or "").strip():
        errors.append("policy.primary_transition.fallback_scorer must be non-empty")
    if "min_transition_score" in primary_transition and not _finite_nonnegative(primary_transition.get("min_transition_score")):
        errors.append("policy.primary_transition.min_transition_score must be a finite non-negative number")
    if mode == "external_hard_backoff_vomm":
        if primary_transition.get("source_order") != ["external_seed_transition"]:
            errors.append("external_hard_backoff_vomm requires primary_transition.source_order to be [external_seed_transition]")
        if str(primary_transition.get("fallback_scorer") or "").strip():
            errors.append("external_hard_backoff_vomm must not configure a primary fallback scorer")
        if policy.get("compute_weighted_ensemble_baseline") is not False:
            errors.append("external_hard_backoff_vomm requires compute_weighted_ensemble_baseline=false")
        for field in (
            "external_transition_model_path",
            "external_transition_manifest_path",
            "external_transition_expected_artifact_sha256",
            "external_transition_expected_model_id",
            "external_transition_expected_manifest_id",
        ):
            if not str(policy.get(field) or "").strip():
                errors.append(f"external_hard_backoff_vomm requires policy.{field}")


def _validate_external_seed_decay(policy: Dict[str, Any], errors: List[str]) -> None:
    decay = policy.get("external_seed_weight_decay")
    if decay is None:
        return
    if not isinstance(decay, dict):
        errors.append("policy.external_seed_weight_decay must be an object")
        return
    if "enabled" in decay and not isinstance(decay.get("enabled"), bool):
        errors.append("policy.external_seed_weight_decay.enabled must be boolean")
    method = str(decay.get("method") or "maturity_multiplier").strip().lower()
    if method not in {"maturity_multiplier", "empirical_shrinkage"}:
        errors.append("policy.external_seed_weight_decay.method must be maturity_multiplier or empirical_shrinkage")
    count_source = str(decay.get("shrinkage_count_source") or "transitions").strip().lower()
    if count_source not in {"sessions", "transitions"}:
        errors.append("policy.external_seed_weight_decay.shrinkage_count_source must be sessions or transitions")
    for key in ("cold", "warming", "stable"):
        if key not in decay:
            errors.append(f"policy.external_seed_weight_decay.{key} is required")
            continue
        if not _finite_nonnegative(decay.get(key)):
            errors.append(f"policy.external_seed_weight_decay.{key} must be a finite non-negative number")
    for key in ("shrinkage_k", "min_multiplier", "max_multiplier"):
        if key in decay and not _finite_nonnegative(decay.get(key)):
            errors.append(f"policy.external_seed_weight_decay.{key} must be a finite non-negative number")
    if (
        _finite_nonnegative(decay.get("min_multiplier"))
        and _finite_nonnegative(decay.get("max_multiplier"))
        and float(decay.get("max_multiplier")) < float(decay.get("min_multiplier"))
    ):
        errors.append("policy.external_seed_weight_decay.max_multiplier must be greater than or equal to min_multiplier")


def _validate_actor_fingerprint_prior(policy: Dict[str, Any], errors: List[str]) -> None:
    prior = policy.get("actor_fingerprint_prior")
    if prior is None:
        return
    if not isinstance(prior, dict):
        errors.append("policy.actor_fingerprint_prior must be an object")
        return
    if "enabled" in prior and not isinstance(prior.get("enabled"), bool):
        errors.append("policy.actor_fingerprint_prior.enabled must be boolean")
    match_fields = prior.get("match_fields")
    if match_fields is not None:
        if not isinstance(match_fields, list) or not match_fields:
            errors.append("policy.actor_fingerprint_prior.match_fields must be a non-empty list")
        else:
            for index, field in enumerate(match_fields):
                if not str(field or "").strip():
                    errors.append(f"policy.actor_fingerprint_prior.match_fields[{index}] must be non-empty")
    for field in (
        "min_sessions",
        "min_transition_count",
        "min_prefix_transition_count",
        "min_tactic_transition_count",
        "prefix_max_length",
        "smoothing",
        "history_limit",
        "comparison_weight",
    ):
        if field in prior and not _finite_nonnegative(prior.get(field)):
            errors.append(f"policy.actor_fingerprint_prior.{field} must be a finite non-negative number")
    if "model_path" in prior and not isinstance(prior.get("model_path"), str):
        errors.append("policy.actor_fingerprint_prior.model_path must be a string")


def _validate_behavior_regime_classifier(policy: Dict[str, Any], errors: List[str]) -> None:
    classifier = policy.get("behavior_regime_classifier")
    if classifier is None:
        return
    if not isinstance(classifier, dict):
        errors.append("policy.behavior_regime_classifier must be an object")
        return
    if "enabled" in classifier and not isinstance(classifier.get("enabled"), bool):
        errors.append("policy.behavior_regime_classifier.enabled must be boolean")
    for field in (
        "min_commands",
        "automated_command_rate_per_minute",
        "human_command_rate_per_minute",
        "low_delay_variance_seconds2",
        "high_delay_variance_seconds2",
        "high_entropy_bits_per_char",
        "low_entropy_bits_per_char",
        "low_payload_diversity",
        "high_payload_diversity",
        "automated_threshold",
        "human_threshold",
    ):
        if field in classifier and not _finite_nonnegative(classifier.get(field)):
            errors.append(f"policy.behavior_regime_classifier.{field} must be a finite non-negative number")
    weights = classifier.get("feature_weights")
    if weights is not None:
        if not isinstance(weights, dict) or not weights:
            errors.append("policy.behavior_regime_classifier.feature_weights must be a non-empty object")
        else:
            for name, value in weights.items():
                if not str(name or "").strip():
                    errors.append("policy.behavior_regime_classifier.feature_weights keys must be non-empty")
                if not _finite_nonnegative(value):
                    errors.append(f"policy.behavior_regime_classifier.feature_weights.{name} must be a finite non-negative number")


def _validate_prediction_triggers(policy: Dict[str, Any], errors: List[str]) -> None:
    triggers = policy.get("prediction_triggers")
    if triggers is None:
        return
    if not isinstance(triggers, dict):
        errors.append("policy.prediction_triggers must be an object")
        return
    if "enabled" in triggers and not isinstance(triggers.get("enabled"), bool):
        errors.append("policy.prediction_triggers.enabled must be boolean")
    for key in ("eventids", "eventid_prefixes"):
        if key not in triggers:
            continue
        values = triggers.get(key)
        if not isinstance(values, list):
            errors.append(f"policy.prediction_triggers.{key} must be a list")
            continue
        for index, value in enumerate(values):
            if not str(value or "").strip():
                errors.append(f"policy.prediction_triggers.{key}[{index}] must be a non-empty string")
    if triggers.get("enabled", True):
        eventids = [str(item or "").strip() for item in _as_list(triggers.get("eventids")) if str(item or "").strip()]
        prefixes = [
            str(item or "").strip()
            for item in _as_list(triggers.get("eventid_prefixes"))
            if str(item or "").strip()
        ]
        if not eventids and not prefixes:
            errors.append("policy.prediction_triggers must include eventids or eventid_prefixes when enabled")


def _validate_predictive_alerts(policy: Dict[str, Any], errors: List[str]) -> None:
    alerts = policy.get("predictive_alerts")
    if alerts is None:
        return
    if not isinstance(alerts, dict):
        errors.append("policy.predictive_alerts must be an object")
        return
    if "enabled" in alerts and not isinstance(alerts.get("enabled"), bool):
        errors.append("policy.predictive_alerts.enabled must be boolean")
    if str(alerts.get("min_confidence", "medium")).strip().lower() not in {"low", "medium", "high"}:
        errors.append("policy.predictive_alerts.min_confidence must be low, medium, or high")
    if str(alerts.get("min_severity", "high")).strip().lower() not in {"info", "low", "medium", "high", "critical"}:
        errors.append("policy.predictive_alerts.min_severity must be info, low, medium, high, or critical")
    for field in ("min_score", "max_divergence_ratio"):
        if field in alerts and not _finite_nonnegative(alerts.get(field)):
            errors.append(f"policy.predictive_alerts.{field} must be a finite non-negative number")
    for field in ("min_active_scorers", "min_supporting_scorers", "max_alerts_per_snapshot"):
        if field in alerts:
            try:
                value = int(alerts.get(field))
            except (TypeError, ValueError):
                errors.append(f"policy.predictive_alerts.{field} must be an integer")
                continue
            if value < 0:
                errors.append(f"policy.predictive_alerts.{field} must be non-negative")
    if "block_on_coverage_below_minimum" in alerts and not isinstance(alerts.get("block_on_coverage_below_minimum"), bool):
        errors.append("policy.predictive_alerts.block_on_coverage_below_minimum must be boolean")
    for field in ("block_external_seed_only", "block_context_only"):
        if field in alerts and not isinstance(alerts.get(field), bool):
            errors.append(f"policy.predictive_alerts.{field} must be boolean")
    statuses = alerts.get("alert_on_session_status")
    if statuses is not None:
        if not isinstance(statuses, list):
            errors.append("policy.predictive_alerts.alert_on_session_status must be a list")
        elif not [item for item in statuses if str(item or "").strip()]:
            errors.append("policy.predictive_alerts.alert_on_session_status must include at least one non-empty status")
    severities = alerts.get("tactic_severity")
    if severities is not None:
        if not isinstance(severities, dict):
            errors.append("policy.predictive_alerts.tactic_severity must be an object")
        else:
            for tactic, severity in severities.items():
                if not str(tactic or "").strip():
                    errors.append("policy.predictive_alerts.tactic_severity keys must be non-empty")
                if str(severity or "").strip().lower() not in {"info", "low", "medium", "high", "critical"}:
                    errors.append(f"policy.predictive_alerts.tactic_severity.{tactic} has invalid severity")


def _validate_confidence_controls(policy: Dict[str, Any], errors: List[str]) -> None:
    controls = policy.get("confidence_controls")
    if controls is None:
        return
    if not isinstance(controls, dict):
        errors.append("policy.confidence_controls must be an object")
        return
    if "enabled" in controls and not isinstance(controls.get("enabled"), bool):
        errors.append("policy.confidence_controls.enabled must be boolean")
    for field in (
        "single_active_scorer_cap",
        "single_supporting_scorer_cap",
        "external_seed_only_cap",
        "external_seed_dominated_cap",
        "context_only_cap",
        "medium_divergence_cap",
        "high_divergence_cap",
        "low_classification_cap",
    ):
        if field in controls and str(controls.get(field) or "").strip().lower() not in {"", "low", "medium", "high"}:
            errors.append(f"policy.confidence_controls.{field} must be empty, low, medium, or high")
    for field in (
        "medium_divergence_ratio",
        "high_divergence_ratio",
        "low_classification_geomean",
        "unknown_or_noise_ratio",
    ):
        if field in controls and not _finite_nonnegative(controls.get(field)):
            errors.append(f"policy.confidence_controls.{field} must be a finite non-negative number")


def _validate_rule_prior_deduplication(policy: Dict[str, Any], errors: List[str]) -> None:
    dedup = policy.get("rule_prior_deduplication")
    if dedup is None:
        return
    if not isinstance(dedup, dict):
        errors.append("policy.rule_prior_deduplication must be an object")
        return
    if "enabled" in dedup and not isinstance(dedup.get("enabled"), bool):
        errors.append("policy.rule_prior_deduplication.enabled must be boolean")
    if str(dedup.get("method") or "max_contribution").strip().lower() != "max_contribution":
        errors.append("policy.rule_prior_deduplication.method must be max_contribution")
    scorers = dedup.get("scorers")
    if scorers is not None:
        if not isinstance(scorers, list) or not scorers:
            errors.append("policy.rule_prior_deduplication.scorers must be a non-empty list")
        else:
            for index, scorer in enumerate(scorers):
                if not str(scorer or "").strip():
                    errors.append(f"policy.rule_prior_deduplication.scorers[{index}] must be non-empty")
    if "require_shared_evidence_key" in dedup and not isinstance(dedup.get("require_shared_evidence_key"), bool):
        errors.append("policy.rule_prior_deduplication.require_shared_evidence_key must be boolean")


def _validate_hypotheses(rule: Dict[str, Any], path: str, errors: List[str]) -> None:
    hypotheses = rule.get("hypotheses") or []
    if not isinstance(hypotheses, list) or not hypotheses:
        errors.append(f"{path}.hypotheses must be a non-empty list")
        return
    for index, item in enumerate(hypotheses):
        item_path = f"{path}.hypotheses[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{item_path} must be an object")
            continue
        if not str(item.get("tactic") or "").strip():
            errors.append(f"{item_path}.tactic is required")
        if not _finite_nonnegative(item.get("score")):
            errors.append(f"{item_path}.score must be a finite non-negative number")
        if not str(item.get("reason") or "").strip():
            errors.append(f"{item_path}.reason is required")


def _validate_rule(section: str, index: int, rule: Dict[str, Any], errors: List[str]) -> None:
    path = _rule_path(section, index)
    if not bool(rule.get("enabled", True)):
        return
    rule_id = str(rule.get("rule_id") or "").strip()
    if not rule_id:
        errors.append(f"{path}.rule_id is required")
    source_type = str(rule.get("source_type") or "").strip()
    if source_type not in ALLOWED_SOURCE_TYPES:
        errors.append(f"{path}.source_type must be one of {sorted(ALLOWED_SOURCE_TYPES)}")
    provenance = rule.get("provenance")
    if not isinstance(provenance, dict) or not provenance:
        errors.append(f"{path}.provenance is required")
        provenance = {}
    else:
        for field in ("method", "basis", "author", "created", "version"):
            if not provenance.get(field):
                errors.append(f"{path}.provenance.{field} is required")
    references = [str(item).strip() for item in _as_list(rule.get("references")) if str(item).strip()]
    if source_type in {"human_curated_attck_prior", "detection_correlation", "risk_modifier"} and not references:
        errors.append(f"{path}.references is required for source_type={source_type}")
    if bool(provenance.get("generated_by_tie")):
        if not bool(provenance.get("reviewed")):
            errors.append(f"{path}.provenance.reviewed must be true for generated rules")
        if not (provenance.get("tie_output_id") or provenance.get("output_hash") or provenance.get("artifact_sha256")):
            errors.append(f"{path}.provenance needs tie_output_id, output_hash, or artifact_sha256 for generated rules")
    if "temporal_claim" in rule and not isinstance(rule.get("temporal_claim"), bool):
        errors.append(f"{path}.temporal_claim must be boolean")
    if section == "sigma_correlation_rules" and rule.get("temporal_claim") is not False:
        errors.append(f"{path}.temporal_claim must be false for Sigma detection-correlation rules")
    _validate_hypotheses(rule, path, errors)


def validate_policy_document(document: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if document.get("schema_version") not in (None, "prediction_policy.v1"):
        errors.append("schema_version must be prediction_policy.v1")
    policy = _policy_body(document)
    if not policy:
        errors.append("policy object is required")
        return errors
    # External hard-backoff authority deliberately has no ensemble weights.
    # Legacy policies keep the existing positive-weight validation.
    if str(policy.get("prediction_mode") or "").strip() != "external_hard_backoff_vomm":
        _validate_weights(policy, errors)
    _validate_prediction_mode(policy, errors)
    _validate_external_seed_decay(policy, errors)
    _validate_actor_fingerprint_prior(policy, errors)
    _validate_behavior_regime_classifier(policy, errors)
    _validate_confidence_controls(policy, errors)
    _validate_rule_prior_deduplication(policy, errors)
    _validate_prediction_triggers(policy, errors)
    _validate_predictive_alerts(policy, errors)
    for section in TRUSTED_RULE_SECTIONS:
        rules = policy.get(section) or []
        if not isinstance(rules, list):
            errors.append(f"policy.{section} must be a list")
            continue
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"{_rule_path(section, index)} must be an object")
                continue
            _validate_rule(section, index, rule, errors)
    return errors


def diff_policy_documents(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    old_policy = _policy_body(old)
    new_policy = _policy_body(new)
    changes: Dict[str, Any] = {
        "old_policy_id": old.get("policy_id"),
        "new_policy_id": new.get("policy_id"),
        "old_version": old.get("version"),
        "new_version": new.get("version"),
        "changed_top_level_keys": sorted(
            key for key in set(old_policy).union(new_policy) if old_policy.get(key) != new_policy.get(key)
        ),
    }
    for section in TRUSTED_RULE_SECTIONS:
        old_rules = {str(rule.get("rule_id") or ""): rule for rule in old_policy.get(section) or [] if isinstance(rule, dict)}
        new_rules = {str(rule.get("rule_id") or ""): rule for rule in new_policy.get(section) or [] if isinstance(rule, dict)}
        changes[section] = {
            "added": sorted(set(new_rules) - set(old_rules)),
            "removed": sorted(set(old_rules) - set(new_rules)),
            "changed": sorted(rule_id for rule_id in set(old_rules).intersection(new_rules) if old_rules[rule_id] != new_rules[rule_id]),
        }
    return changes


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate realtime prediction policy provenance.")
    parser.add_argument("--policy", required=True, help="Policy JSON path to validate.")
    parser.add_argument("--compare", help="Optional older policy JSON path for deployment diff.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    document = load_policy_file(args.policy)
    errors = validate_policy_document(document)
    output: Dict[str, Any] = {
        "policy": str(args.policy),
        "valid": not errors,
        "errors": errors,
    }
    if args.compare:
        output["diff"] = diff_policy_documents(load_policy_file(args.compare), document)
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        if errors:
            print("Prediction policy validation failed:")
            for error in errors:
                print(f"- {error}")
        else:
            print("Prediction policy validation passed.")
        if "diff" in output:
            print(json.dumps(output["diff"], indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
