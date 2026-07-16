"""Deterministic comparison of scoped next-tactic prediction models.

The tool evaluates only trusted, adjacent-deduplicated tactic sequences from
whole Cowrie sessions. It never mutates runtime policy, model artifacts, or
storage. The public package intentionally omits raw external and local session
data, so a run without session payload inputs produces an explicit
not-evaluated availability report rather than synthetic metrics.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import random
from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence

from production.prediction.prediction_backtest import (
    _brier_score,
    _prefix_payload,
    _tactic_steps,
)
from production.prediction.realtime_prediction import (
    FallbackProgressionScorer,
    RealtimePredictionEngine,
    build_transition_model,
)
from production.prediction.session_features import build_session_features
from production.storage.session_provenance import SESSION_SOURCE_PRODUCTION_LIVE
from production.tools.primary_transition_evaluation import chronological_split
from production.utils.serialization import utc_now


DEFAULT_POLICY_PATH = "configs/prediction_policy.trusted.json"
DEFAULT_EXTERNAL_MODEL_PATH = (
    "data/models/external_cowrie_seed_transition_model.compound_securebert.json"
)
DEFAULT_HISTORICAL_EVIDENCE_PATH = "evaluation/external_seed_weight_fit.json"
DEFAULT_EXTERNAL_PAYLOAD_PATH = "evaluation/next_tactic_external_session_payload.jsonl"
DEFAULT_OUTPUT_JSON = "evaluation/next_tactic_model_comparison.json"
DEFAULT_OUTPUT_CSV = "evaluation/next_tactic_model_comparison.csv"
DEFAULT_SEED = 20260714
DEFAULT_KAPPA_GRID = (1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0)


MODEL_SPECS: List[Dict[str, str]] = [
    {
        "model_id": "majority_class",
        "model": "Zero-order categorical / Majority Class Classifier",
        "role": "sanity baseline",
        "input_context": "training-set next-tactic prevalence only",
        "output": "fixed categorical next-tactic distribution",
        "abstention_support": "no; predicts when training targets exist",
        "limitation": "ignores all sequential context",
    },
    {
        "model_id": "first_order_markov",
        "model": "First-order Markov Chain (maximum likelihood)",
        "role": "simple sequence baseline",
        "input_context": "last trusted tactic",
        "output": "P(next tactic | last tactic)",
        "abstention_support": "yes; unseen last-tactic context",
        "limitation": "cannot use longer tactic history or external/local shrinkage",
    },
    {
        "model_id": "current_hard_backoff",
        "model": "Current Hard-backoff Variable-order Markov Model",
        "role": "incumbent baseline",
        "input_context": "tactic suffix up to 3, then technique, then last tactic",
        "output": "current runtime ranking from one selected source",
        "abstention_support": "operationally replaced by fixed fallback",
        "limitation": "hard source switching and heuristic fallback",
    },
    {
        "model_id": "empirical_bayes_vomm",
        "model": "Empirical-Bayes / Dirichlet-smoothed Variable-order Markov Model",
        "role": "proposed model",
        "input_context": "trusted tactic suffix up to 3, technique, then last tactic",
        "output": "posterior predictive next-tactic distribution",
        "abstention_support": "yes; no context meeting raw support threshold",
        "limitation": "local posterior updating requires clean local calibration data",
    },
    {
        "model_id": "fallback_progression",
        "model": "Fixed Progression Fallback",
        "role": "ablation only",
        "input_context": "last trusted tactic",
        "output": "policy-defined ranked tactic suggestions",
        "abstention_support": "limited; normally forces a suggestion",
        "limitation": "developer-defined heuristic, not a fitted probability model",
    },
    {
        "model_id": "external_only",
        "model": "External-only Variable-order Transition Model",
        "role": "source ablation",
        "input_context": "trusted tactic/technique context",
        "output": "external Cowrie transition ranking",
        "abstention_support": "yes; unsupported external context",
        "limitation": "external corpus is weak-labeled and may shift by protocol, configuration, or deployment",
    },
    {
        "model_id": "local_only",
        "model": "Local-only Variable-order Transition Model",
        "role": "source ablation",
        "input_context": "trusted tactic/technique context",
        "output": "deployment-local transition ranking",
        "abstention_support": "yes; insufficient or unsupported local context",
        "limitation": "public package does not retain enough local held-out evidence",
    },
    {
        "model_id": "multinomial_logistic_regression",
        "model": "L2-regularized Multinomial Logistic Regression",
        "role": "optional classical ML baseline",
        "input_context": "one-hot tactic/technique suffix features and sequence length",
        "output": "softmax next-tactic distribution",
        "abstention_support": "not enabled without a calibrated threshold",
        "limitation": "optional dependency and weak-label/class-imbalance overfitting risk",
    },
]


NOT_RECOMMENDED_MODELS = [
    {
        "model": "Hidden Markov Model",
        "reason": "The trusted tactics are already observed states and targets; latent-state semantics are not established.",
    },
    {
        "model": "Random Forest / XGBoost",
        "reason": "Flattened tabular features add overfitting risk without a useful sequential inductive bias.",
    },
    {
        "model": "RNN / LSTM / GRU / Transformer",
        "reason": "The available targets are classifier-derived weak labels, and no independently labeled tuning evidence demonstrates an advantage for a high-capacity sequence model.",
    },
    {
        "model": "Reinforcement learning",
        "reason": "There is no defensible action, reward, or intervention-learning problem in this advisory predictor.",
    },
    {
        "model": "Exact-command language model",
        "reason": "Exact next-command prediction is outside the Cowrie next-tactic thesis scope.",
    },
]


THESIS_DEFENSE_QA = [
    ("Why use Markov-family models?", "The target is the next observed tactic in a short trusted sequence, and the available evidence consists directly of interpretable transition counts."),
    ("Why not LSTM/Transformer?", "The targets are classifier-derived weak labels and materially imbalanced. No independently labeled tuning evidence currently demonstrates that a high-capacity neural model would generalize better than interpretable count-based models."),
    ("Why not HMM?", "HMMs are useful when meaningful states are hidden. Here ATT&CK tactic candidates are already the observed states and prediction target."),
    ("Why not Random Forest/XGBoost?", "They would flatten the sequence into tabular features, add overfitting risk, and provide no demonstrated advantage over transition counts."),
    ("Why compare with Majority Class Classifier?", "It tests whether any sequential model improves on class prevalence and exposes inflation caused by tactic imbalance."),
    ("Why compare with First-order Markov Chain?", "It is the simplest well-known sequential baseline and isolates the value of longer context and cross-source adaptation."),
    ("Why compare with the current hard-backoff model?", "It is the incumbent runtime behavior, so it is the required reference for any improvement claim."),
    ("What differs between hard backoff and Empirical-Bayes smoothing?", "Hard backoff chooses one source. The proposed model can combine external prior counts and validated local evidence continuously in one posterior distribution. In this external-only run no clean local update is available, so it reduces to a Dirichlet-smoothed external prior and does not demonstrate an improvement over hard backoff."),
    ("How does the external Cowrie dataset help?", "It supplies cold-start transition evidence when deployment-local trusted transitions are sparse."),
    ("Why is local accuracy not claimed?", "This run supplies no clean local held-out session corpus, so its metrics support external-sample comparison only."),
    ("How are weak labels handled?", "The shared trust predicate excludes audit-only, low-confidence, unsupported, and shell-noise classifications before sequence construction."),
    ("How is leakage prevented?", "Whole sessions are assigned to train, calibration, and test before transition cases are extracted, so no session crosses partitions. Each artifact records whether the supplied split was chronological or a deterministic fallback."),
    ("Why is Top-3 secondary?", "The empirical target vocabulary is small, so Top-3 is comparatively easy and less discriminating than Top-1, MRR, and normalized multiclass Brier score."),
    ("What does abstention mean?", "The model emits no empirical next-tactic ranking when the observed context lacks the configured raw transition support."),
    ("Are the scores calibrated probabilities?", "Not automatically. They are normalized model scores unless calibration is fitted and evaluated on held-out data."),
    ("What limitation belongs in the thesis?", "Results are limited to trusted Cowrie-observable evidence and classifier-derived weak labels. Protocol, collection-window, configuration balance, and local-generalization limits must be reported from the specific evaluation artifact."),
]


@dataclass(frozen=True)
class EvaluationCase:
    session_id: str
    actual: str
    features: Dict[str, Any]


@dataclass
class Predictor:
    predict: Callable[[EvaluationCase], Dict[str, float]]
    metadata: Dict[str, Any]


def _load_json(path_text: str) -> Any:
    return json.loads(Path(path_text).read_text(encoding="utf-8"))


def load_policy(path_text: str) -> Dict[str, Any]:
    document = _load_json(path_text)
    if not isinstance(document, dict):
        raise ValueError("prediction policy must be a JSON object")
    policy = document.get("policy") if isinstance(document.get("policy"), dict) else document
    return deepcopy(policy)


def load_transition_model(path_text: str) -> Dict[str, Any]:
    document = _load_json(path_text)
    if not isinstance(document, dict):
        raise ValueError("transition model must be a JSON object")
    model = document.get("model") if isinstance(document.get("model"), dict) else document
    return deepcopy(model)


def load_session_payloads(path_text: str) -> List[Dict[str, Any]]:
    path = Path(path_text)
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        payloads: List[Dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"invalid JSONL payload at {path_text}:{line_number}: {exc}"
                    ) from exc
                if not isinstance(payload, dict):
                    raise ValueError(
                        f"JSONL payload at {path_text}:{line_number} must be an object"
                    )
                payloads.append(dict(payload))
        return payloads

    document = _load_json(path_text)
    if isinstance(document, list):
        payloads = document
    elif isinstance(document, dict):
        payloads = document.get("sessions") or document.get("payloads") or []
    else:
        payloads = []
    if not isinstance(payloads, list):
        raise ValueError("session payload input must be a JSON list or contain sessions/payloads")
    return [dict(payload) for payload in payloads if isinstance(payload, dict)]


def split_session_payloads(
    payloads: Sequence[Dict[str, Any]],
) -> tuple[Dict[str, List[Dict[str, Any]]], str]:
    """Use recorded whole-session splits, or fall back to chronology."""

    labels = [str(payload.get("split") or "").strip() for payload in payloads]
    has_recorded_split = any(labels)
    if has_recorded_split:
        allowed = {"train", "calibration", "test"}
        if any(label not in allowed for label in labels):
            raise ValueError(
                "when any session has a split label, every session must use "
                "train, calibration, or test"
            )
        split = {
            name: [
                payload
                for payload, label in zip(payloads, labels)
                if label == name
            ]
            for name in ("train", "calibration", "test")
        }
        return split, "preassigned_whole_session_split"
    return chronological_split(payloads), "chronological_70_15_15_by_whole_session"


def payload_input_summary(payloads: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    protocols = sorted(
        {
            str(payload.get("protocol") or "unknown").strip() or "unknown"
            for payload in payloads
        }
    )
    schema_versions = sorted(
        {
            str(payload.get("schema_version") or "unspecified").strip()
            or "unspecified"
            for payload in payloads
        }
    )
    split_counts = Counter(
        str(payload.get("split") or "unassigned").strip() or "unassigned"
        for payload in payloads
    )
    split_transition_sessions: Counter[str] = Counter()
    split_transition_cases: Counter[str] = Counter()
    for payload in payloads:
        split_name = str(payload.get("split") or "unassigned").strip() or "unassigned"
        case_count = max(len(_tactic_steps(payload)) - 1, 0)
        if case_count:
            split_transition_sessions[split_name] += 1
            split_transition_cases[split_name] += case_count
    return {
        "sessions": len(payloads),
        "transition_sessions": sum(split_transition_sessions.values()),
        "transition_cases": sum(split_transition_cases.values()),
        "protocols": protocols,
        "schema_versions": schema_versions,
        "split_sessions": dict(sorted(split_counts.items())),
        "split_transition_sessions": dict(sorted(split_transition_sessions.items())),
        "split_transition_cases": dict(sorted(split_transition_cases.items())),
    }


def filter_local_production_payloads(
    payloads: Iterable[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Require both provenance dimensions before local evaluation."""

    accepted: List[Dict[str, Any]] = []
    excluded: Counter[str] = Counter()
    total = 0
    for payload in payloads:
        total += 1
        source = str(payload.get("session_source") or "").strip()
        external = payload.get("is_external_source")
        external_true = external is True or external == 1 or str(external).lower() == "true"
        if source != SESSION_SOURCE_PRODUCTION_LIVE:
            excluded["session_source_not_production_live"] += 1
            continue
        if not external_true:
            excluded["is_external_source_not_true"] += 1
            continue
        accepted.append(payload)
    return accepted, {
        "input_payloads": total,
        "accepted_payloads": len(accepted),
        "excluded_payloads": total - len(accepted),
        "excluded_reasons": dict(sorted(excluded.items())),
        "required_session_source": SESSION_SOURCE_PRODUCTION_LIVE,
        "required_is_external_source": True,
    }


def trusted_tactic_sequence(payload: Dict[str, Any]) -> List[str]:
    """Return the evaluator's trusted, adjacent-deduplicated tactic sequence."""

    return [str(step["tactic"]) for step in _tactic_steps(payload)]


def build_cases(payloads: Iterable[Dict[str, Any]]) -> List[EvaluationCase]:
    cases: List[EvaluationCase] = []
    for payload in payloads:
        steps = _tactic_steps(payload)
        if len(steps) < 2:
            continue
        session_id = str(payload.get("session_id") or "unknown")
        for index in range(len(steps) - 1):
            prefix_payload = _prefix_payload(payload, steps, index)
            features = build_session_features(prefix_payload)
            canonical_prefix = [str(step["tactic"]) for step in steps[: index + 1]]
            features["tactic_sequence"] = canonical_prefix
            features["last_tactic"] = canonical_prefix[-1]
            cases.append(
                EvaluationCase(
                    session_id=session_id,
                    actual=str(steps[index + 1]["tactic"]),
                    features=features,
                )
            )
    return cases


def _normalize(probabilities: Mapping[str, float]) -> Dict[str, float]:
    clean = {
        str(label): max(float(value), 0.0)
        for label, value in probabilities.items()
        if str(label).strip() and float(value) > 0.0
    }
    total = sum(clean.values())
    if total <= 0.0:
        return {}
    return {label: value / total for label, value in clean.items()}


def _ranking(probabilities: Mapping[str, float]) -> List[Dict[str, Any]]:
    normalized = _normalize(probabilities)
    return [
        {"tactic": tactic, "score": probability}
        for tactic, probability in sorted(
            normalized.items(), key=lambda item: (-item[1], item[0])
        )
    ]


def _model_tactics(model: Dict[str, Any]) -> set[str]:
    tactics = {str(item) for item in (model.get("start_counts") or {}) if str(item)}
    for current, counts in (model.get("transitions") or {}).items():
        tactics.add(str(current))
        tactics.update(str(item) for item in (counts or {}) if str(item))
    for counts in (model.get("prefix_transitions") or {}).values():
        tactics.update(str(item) for item in (counts or {}) if str(item))
    tactics.update(
        str(item)
        for item in (model.get("technique_tactics") or {}).values()
        if str(item)
    )
    tactics.discard("unknown")
    return tactics


def tactic_vocabulary(
    training_payloads: Iterable[Dict[str, Any]],
    *models: Dict[str, Any],
) -> List[str]:
    tactics: set[str] = set()
    for payload in training_payloads:
        tactics.update(trusted_tactic_sequence(payload))
    for model in models:
        tactics.update(_model_tactics(model))
    return sorted(tactic for tactic in tactics if tactic and tactic != "unknown")


def _counts(model: Dict[str, Any], field: str, context: str) -> Dict[str, float]:
    raw = (model.get(field) or {}).get(context) or {}
    return {str(label): float(count) for label, count in raw.items() if float(count) > 0.0}


def _technique_tactic_counts(model: Dict[str, Any], technique: str) -> Dict[str, float]:
    target_counts = _counts(model, "technique_transitions", technique)
    mapping = model.get("technique_tactics") or {}
    output: Dict[str, float] = defaultdict(float)
    for target_technique, count in target_counts.items():
        tactic = str(mapping.get(target_technique) or "").strip()
        if tactic and tactic != "unknown":
            output[tactic] += count
    return dict(output)


def _context_counts(
    external_model: Dict[str, Any],
    local_model: Dict[str, Any],
    features: Dict[str, Any],
    *,
    prefix_max_length: int,
    min_support: float,
) -> Dict[str, Any] | None:
    sequence = [str(item) for item in features.get("tactic_sequence") or [] if str(item)]
    max_prefix = min(max(prefix_max_length, 1), len(sequence))
    candidates: List[tuple[str, str, Dict[str, float], Dict[str, float]]] = []
    for length in range(max_prefix, 1, -1):
        context = ">".join(sequence[-length:])
        candidates.append(
            (
                "prefix",
                context,
                _counts(external_model, "prefix_transitions", context),
                _counts(local_model, "prefix_transitions", context),
            )
        )

    last_ttp = str(features.get("last_ttp") or "").strip()
    if last_ttp:
        candidates.append(
            (
                "technique",
                last_ttp,
                _technique_tactic_counts(external_model, last_ttp),
                _technique_tactic_counts(local_model, last_ttp),
            )
        )

    last_tactic = str(features.get("last_tactic") or "").strip()
    if last_tactic:
        candidates.append(
            (
                "tactic",
                last_tactic,
                _counts(external_model, "transitions", last_tactic),
                _counts(local_model, "transitions", last_tactic),
            )
        )

    for context_type, context, external_counts, local_counts in candidates:
        support = sum(external_counts.values()) + sum(local_counts.values())
        if support >= min_support:
            return {
                "context_type": context_type,
                "context": context,
                "external_counts": external_counts,
                "local_counts": local_counts,
                "raw_support": support,
            }
    return None


def empirical_bayes_probabilities(
    features: Dict[str, Any],
    external_model: Dict[str, Any],
    local_model: Dict[str, Any],
    vocabulary: Sequence[str],
    *,
    alpha: float,
    kappa: float,
    prefix_max_length: int,
    min_support: float,
) -> Dict[str, float]:
    """Compute the Dirichlet-smoothed posterior predictive distribution."""

    labels = [str(item) for item in vocabulary if str(item)]
    if not labels:
        return {}
    selected = _context_counts(
        external_model,
        local_model,
        features,
        prefix_max_length=prefix_max_length,
        min_support=min_support,
    )
    if selected is None:
        return {}
    external_counts = selected["external_counts"]
    local_counts = selected["local_counts"]
    external_total = sum(external_counts.values())
    local_total = sum(local_counts.values())
    safe_alpha = max(float(alpha), 0.0)
    safe_kappa = max(float(kappa), 0.0)
    external_denominator = external_total + safe_alpha * len(labels)
    if external_denominator > 0.0:
        external_prior = {
            label: (external_counts.get(label, 0.0) + safe_alpha) / external_denominator
            for label in labels
        }
    else:
        external_prior = {label: 1.0 / len(labels) for label in labels}
    posterior_denominator = local_total + safe_kappa
    if posterior_denominator <= 0.0:
        return {}
    posterior = {
        label: (
            local_counts.get(label, 0.0) + safe_kappa * external_prior[label]
        ) / posterior_denominator
        for label in labels
    }
    return _normalize(posterior)


def _majority_predictor(training_payloads: Sequence[Dict[str, Any]]) -> Predictor:
    counts: Counter[str] = Counter()
    for payload in training_payloads:
        sequence = trusted_tactic_sequence(payload)
        counts.update(sequence[1:])
    probabilities = _normalize(counts)
    return Predictor(
        predict=lambda case: dict(probabilities),
        metadata={"training_next_tactic_counts": dict(counts)},
    )


def _first_order_predictor(training_payloads: Sequence[Dict[str, Any]]) -> Predictor:
    model = build_transition_model(training_payloads)

    def predict(case: EvaluationCase) -> Dict[str, float]:
        last_tactic = str(case.features.get("last_tactic") or "")
        return _normalize(_counts(model, "transitions", last_tactic)) if last_tactic else {}

    return Predictor(predict=predict, metadata={"transition_model": _compact_model(model)})


def _engine_policy(
    policy: Dict[str, Any],
    *,
    source_order: Sequence[str] | None = None,
    fallback_scorer: str | None = None,
) -> Dict[str, Any]:
    updated = deepcopy(policy)
    updated["prediction_mode"] = "primary_transition_with_fallback"
    primary = dict(updated.get("primary_transition") or {})
    if source_order is not None:
        primary["source_order"] = list(source_order)
    if fallback_scorer is not None:
        primary["fallback_scorer"] = fallback_scorer
    updated["primary_transition"] = primary
    updated["compute_weighted_ensemble_baseline"] = False
    return updated


def _engine_predictor(
    policy: Dict[str, Any],
    local_model: Dict[str, Any],
    external_model: Dict[str, Any],
    *,
    source_order: Sequence[str] | None = None,
    fallback_scorer: str | None = None,
) -> Predictor:
    engine = RealtimePredictionEngine(
        _engine_policy(
            policy,
            source_order=source_order,
            fallback_scorer=fallback_scorer,
        ),
        transition_model=local_model,
        external_transition_model=external_model,
    )

    def predict(case: EvaluationCase) -> Dict[str, float]:
        snapshot = engine.predict(
            case.features,
            event_id=f"model-comparison:{case.session_id}",
        )
        return _normalize(
            {
                str(item.get("tactic") or ""): float(
                    item.get("calibrated_score", item.get("score")) or 0.0
                )
                for item in snapshot.get("final_ranking") or []
                if str(item.get("tactic") or "")
            }
        )

    return Predictor(
        predict=predict,
        metadata={"prediction_mode": "primary_transition_with_fallback"},
    )


def _fallback_predictor(policy: Dict[str, Any]) -> Predictor:
    scorer = FallbackProgressionScorer(policy.get("fallback_progression") or {})

    def predict(case: EvaluationCase) -> Dict[str, float]:
        return _normalize(
            {
                item.tactic: float(item.score)
                for item in scorer.score(case.features)
                if item.tactic and item.tactic != "unknown"
            }
        )

    return Predictor(predict=predict, metadata={"source_type": "heuristic_prior"})


def _compact_model(model: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "completed_sessions": int(model.get("completed_sessions") or 0),
        "usable_sessions": int(model.get("usable_sessions") or 0),
        "transition_count": float(model.get("transition_count") or 0.0),
        "prefix_transition_count": float(model.get("prefix_transition_count") or 0.0),
        "technique_transition_count": float(model.get("technique_transition_count") or 0.0),
    }


def _logistic_features(features: Dict[str, Any]) -> Dict[str, Any]:
    sequence = [str(item) for item in features.get("tactic_sequence") or [] if str(item)]
    output: Dict[str, Any] = {
        "sequence_length": len(sequence),
        f"last_tactic={features.get('last_tactic') or '<none>'}": 1.0,
        f"last_ttp={features.get('last_ttp') or '<none>'}": 1.0,
    }
    if len(sequence) >= 2:
        output[f"suffix2={'>'.join(sequence[-2:])}"] = 1.0
    if len(sequence) >= 3:
        output[f"suffix3={'>'.join(sequence[-3:])}"] = 1.0
    return output


def _logistic_predictor(
    training_cases: Sequence[EvaluationCase],
    calibration_cases: Sequence[EvaluationCase],
) -> tuple[Predictor | None, str]:
    if importlib.util.find_spec("sklearn") is None:
        return None, "scikit-learn is not installed; optional baseline skipped"
    labels = {case.actual for case in training_cases}
    if len(training_cases) < 30 or len(labels) < 2:
        return None, "insufficient training transitions or target classes for logistic regression"

    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression

    candidates = (0.01, 0.1, 1.0, 10.0)
    best_c = 1.0
    best_loss: float | None = None
    if calibration_cases:
        for candidate in candidates:
            vectorizer = DictVectorizer(sparse=True)
            matrix = vectorizer.fit_transform([_logistic_features(case.features) for case in training_cases])
            classifier = LogisticRegression(C=candidate, max_iter=1000, solver="lbfgs")
            classifier.fit(matrix, [case.actual for case in training_cases])
            losses = []
            for case in calibration_cases:
                values = classifier.predict_proba(
                    vectorizer.transform([_logistic_features(case.features)])
                )[0]
                ranking = _ranking(dict(zip(classifier.classes_, values)))
                losses.append(_brier_score(ranking, case.actual))
            loss = sum(losses) / len(losses)
            if best_loss is None or loss < best_loss:
                best_loss = loss
                best_c = candidate

    fit_cases = list(training_cases) + list(calibration_cases)
    vectorizer = DictVectorizer(sparse=True)
    matrix = vectorizer.fit_transform([_logistic_features(case.features) for case in fit_cases])
    classifier = LogisticRegression(C=best_c, max_iter=1000, solver="lbfgs")
    classifier.fit(matrix, [case.actual for case in fit_cases])

    def predict(case: EvaluationCase) -> Dict[str, float]:
        values = classifier.predict_proba(
            vectorizer.transform([_logistic_features(case.features)])
        )[0]
        return _normalize(dict(zip(classifier.classes_, values)))

    return (
        Predictor(
            predict=predict,
            metadata={
                "regularization": "L2",
                "selected_c": best_c,
                "calibration_brier": best_loss,
                "training_cases": len(fit_cases),
            },
        ),
        "",
    )


def _case_result(case: EvaluationCase, probabilities: Mapping[str, float]) -> Dict[str, Any]:
    ranking = _ranking(probabilities)
    predicted = [str(item["tactic"]) for item in ranking]
    rank = predicted.index(case.actual) + 1 if case.actual in predicted else 0
    brier_score = _brier_score(ranking, case.actual)
    return {
        "session_id": case.session_id,
        "actual": case.actual,
        "predicted": predicted,
        "rank": rank,
        "covered": bool(predicted),
        "brier_score": brier_score,
        "normalized_multiclass_brier_score": brier_score / 2.0,
    }


def _metric_core(
    results: Sequence[Dict[str, Any]],
    min_per_tactic_support: int,
    target_vocabulary: Sequence[str] | None = None,
) -> Dict[str, Any]:
    total = len(results)
    covered = [item for item in results if item.get("covered")]
    top1_hits = sum(int(item.get("rank") or 0) == 1 for item in results)
    top3_hits = sum(1 <= int(item.get("rank") or 0) <= 3 for item in results)
    reciprocal = sum(1.0 / int(item["rank"]) for item in results if int(item.get("rank") or 0) > 0)
    by_tactic: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in results:
        by_tactic[str(item.get("actual") or "unknown")].append(item)
    tactics = sorted(
        {
            str(tactic)
            for tactic in (target_vocabulary or [])
            if str(tactic) and str(tactic) != "unknown"
        }
        | set(by_tactic)
    )
    per_tactic = {}
    observed_top1: List[float] = []
    sufficient_top1: List[float] = []
    low_support_tactics: List[str] = []
    zero_support_tactics: List[str] = []
    sufficient_support_tactics: List[str] = []
    for tactic in tactics:
        items = by_tactic.get(tactic, [])
        support = len(items)
        enough_support = support >= min_per_tactic_support
        descriptive_top1 = (
            sum(int(item.get("rank") or 0) == 1 for item in items) / support
            if support
            else None
        )
        descriptive_mrr = (
            sum(
                1.0 / int(item["rank"])
                for item in items
                if int(item.get("rank") or 0) > 0
            )
            / support
            if support
            else None
        )
        descriptive_brier = (
            sum(float(item["brier_score"]) for item in items) / support
            if support
            else None
        )
        descriptive_normalized_brier = (
            sum(float(item["normalized_multiclass_brier_score"]) for item in items)
            / support
            if support
            else None
        )
        if descriptive_top1 is not None:
            observed_top1.append(descriptive_top1)
        if enough_support and descriptive_top1 is not None:
            sufficient_top1.append(descriptive_top1)
            sufficient_support_tactics.append(tactic)
            support_status = "sufficient_support"
        elif support:
            low_support_tactics.append(tactic)
            support_status = "low_support_descriptive_only"
        else:
            zero_support_tactics.append(tactic)
            support_status = "no_heldout_support"
        per_tactic[tactic] = {
            "support": support,
            "support_status": support_status,
            "reportable": enough_support,
            "top1_accuracy": (
                round(descriptive_top1, 6)
                if enough_support and descriptive_top1 is not None
                else None
            ),
            "mean_reciprocal_rank": (
                round(descriptive_mrr, 6)
                if enough_support and descriptive_mrr is not None
                else None
            ),
            "brier_score": (
                round(descriptive_brier, 6)
                if enough_support and descriptive_brier is not None
                else None
            ),
            "normalized_multiclass_brier_score": (
                round(descriptive_normalized_brier, 6)
                if enough_support and descriptive_normalized_brier is not None
                else None
            ),
            "descriptive_only": (
                {
                    "top1_accuracy": round(descriptive_top1, 6),
                    "mean_reciprocal_rank": round(descriptive_mrr, 6),
                    "brier_score": round(descriptive_brier, 6),
                    "normalized_multiclass_brier_score": round(
                        descriptive_normalized_brier,
                        6,
                    ),
                }
                if support and not enough_support
                else None
            ),
            "enough_support": enough_support,
        }
    macro_top1 = (
        sum(observed_top1) / len(observed_top1) if observed_top1 else None
    )
    supported_macro_top1 = (
        sum(sufficient_top1) / len(sufficient_top1) if sufficient_top1 else None
    )
    return {
        "evaluated_examples": total,
        "covered_examples": len(covered),
        "top1_accuracy": round(top1_hits / total, 6) if total else None,
        "all_case_accuracy": round(top1_hits / total, 6) if total else None,
        "top3_accuracy_secondary": round(top3_hits / total, 6) if total else None,
        "mean_reciprocal_rank": round(reciprocal / total, 6) if total else None,
        "brier_score": round(sum(float(item["brier_score"]) for item in results) / total, 6) if total else None,
        "normalized_multiclass_brier_score": (
            round(
                sum(float(item["normalized_multiclass_brier_score"]) for item in results)
                / total,
                6,
            )
            if total
            else None
        ),
        "coverage": round(len(covered) / total, 6) if total else None,
        "abstention_rate": round((total - len(covered)) / total, 6) if total else None,
        "selective_top1_accuracy": (
            round(sum(int(item.get("rank") or 0) == 1 for item in covered) / len(covered), 6)
            if covered
            else None
        ),
        "macro_top1_accuracy": (
            round(macro_top1, 6) if macro_top1 is not None else None
        ),
        "balanced_accuracy": (
            round(macro_top1, 6) if macro_top1 is not None else None
        ),
        "macro_recall": (
            round(macro_top1, 6) if macro_top1 is not None else None
        ),
        "macro_top1_accuracy_sufficient_support": (
            round(supported_macro_top1, 6)
            if supported_macro_top1 is not None
            else None
        ),
        "tactic_support_summary": {
            "minimum_support_for_reportable_per_tactic_metrics": min_per_tactic_support,
            "observed_target_tactic_count": len(observed_top1),
            "sufficient_support_tactics": sufficient_support_tactics,
            "low_support_tactics": low_support_tactics,
            "zero_support_tactics": zero_support_tactics,
            "balanced_accuracy_definition": (
                "unweighted mean Top-1 recall across target tactics observed in the held-out set"
            ),
        },
        "per_tactic": per_tactic,
    }


def _percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = int(round((len(ordered) - 1) * fraction))
    return round(float(ordered[index]), 6)


def _bootstrap_by_session(
    results: Sequence[Dict[str, Any]],
    *,
    iterations: int,
    seed: int,
    min_per_tactic_support: int,
    target_vocabulary: Sequence[str] | None = None,
) -> Dict[str, List[float] | None]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in results:
        grouped[str(item.get("session_id") or "unknown")].append(item)
    session_ids = sorted(grouped)
    fields = (
        "top1_accuracy",
        "mean_reciprocal_rank",
        "brier_score",
        "normalized_multiclass_brier_score",
        "macro_top1_accuracy",
        "coverage",
        "selective_top1_accuracy",
    )
    if len(session_ids) < 2 or iterations <= 0:
        return {field: None for field in fields}
    rng = random.Random(seed)
    sampled: Dict[str, List[float]] = {field: [] for field in fields}
    for _ in range(iterations):
        sample: List[Dict[str, Any]] = []
        for _index in session_ids:
            sample.extend(grouped[session_ids[rng.randrange(len(session_ids))]])
        metrics = _metric_core(
            sample,
            min_per_tactic_support,
            target_vocabulary,
        )
        for field in fields:
            value = metrics.get(field)
            if value is not None:
                sampled[field].append(float(value))
    return {
        field: (
            [_percentile(values, 0.025), _percentile(values, 0.975)]
            if values
            else None
        )
        for field, values in sampled.items()
    }


def summarize_predictions(
    cases: Sequence[EvaluationCase],
    predictor: Predictor,
    *,
    bootstrap_iterations: int,
    seed: int,
    min_per_tactic_support: int,
    target_vocabulary: Sequence[str] | None = None,
) -> Dict[str, Any]:
    results = [_case_result(case, predictor.predict(case)) for case in cases]
    metrics = _metric_core(
        results,
        min_per_tactic_support,
        target_vocabulary,
    )
    metrics["bootstrap_95ci_by_session"] = _bootstrap_by_session(
        results,
        iterations=bootstrap_iterations,
        seed=seed,
        min_per_tactic_support=min_per_tactic_support,
        target_vocabulary=target_vocabulary,
    )
    return metrics


def _calibrate_kappa(
    calibration_cases: Sequence[EvaluationCase],
    external_model: Dict[str, Any],
    local_model: Dict[str, Any],
    vocabulary: Sequence[str],
    *,
    alpha: float,
    kappa_grid: Sequence[float],
    prefix_max_length: int,
    min_support: float,
    min_cases: int,
) -> Dict[str, Any]:
    if len(calibration_cases) < min_cases or float(local_model.get("transition_count") or 0.0) <= 0.0:
        return {
            "status": "insufficient_local_calibration_data",
            "selected_kappa": None,
            "calibration_cases": len(calibration_cases),
            "grid": list(kappa_grid),
        }
    rows = []
    for kappa in kappa_grid:
        predictor = Predictor(
            predict=lambda case, value=kappa: empirical_bayes_probabilities(
                case.features,
                external_model,
                local_model,
                vocabulary,
                alpha=alpha,
                kappa=value,
                prefix_max_length=prefix_max_length,
                min_support=min_support,
            ),
            metadata={},
        )
        metrics = summarize_predictions(
            calibration_cases,
            predictor,
            bootstrap_iterations=0,
            seed=DEFAULT_SEED,
            min_per_tactic_support=1,
            target_vocabulary=vocabulary,
        )
        rows.append(
            {
                "kappa": float(kappa),
                "normalized_multiclass_brier_score": metrics.get(
                    "normalized_multiclass_brier_score"
                ),
            }
        )
    eligible = [
        row
        for row in rows
        if row["normalized_multiclass_brier_score"] is not None
    ]
    selected = min(
        eligible,
        key=lambda row: (
            float(row["normalized_multiclass_brier_score"]),
            float(row["kappa"]),
        ),
    )
    return {
        "status": "selected_on_calibration",
        "selected_kappa": selected["kappa"],
        "objective": "normalized_multiclass_brier_score",
        "calibration_cases": len(calibration_cases),
        "grid": rows,
    }


def _skipped_row(spec: Dict[str, str], scope: str, reason: str, data_used: str) -> Dict[str, Any]:
    return {
        **spec,
        "scope": scope,
        "status": "skipped",
        "reason": reason,
        "data_used": data_used,
        "metrics": None,
        "model_metadata": {},
    }


def evaluate_scope(
    *,
    scope: str,
    payloads: Sequence[Dict[str, Any]],
    policy: Dict[str, Any],
    selected_external_model: Dict[str, Any],
    alpha: float,
    kappa_grid: Sequence[float],
    min_calibration_cases: int,
    min_evaluation_examples: int,
    min_per_tactic_support: int,
    bootstrap_iterations: int,
    seed: int,
) -> Dict[str, Any]:
    specs = {item["model_id"]: item for item in MODEL_SPECS}
    if not payloads:
        data_used = f"{scope} session payloads unavailable in public package"
        return {
            "scope": scope,
            "status": "not_evaluated",
            "reason": "no session-level payload input was supplied",
            "split": {"train": 0, "calibration": 0, "test": 0},
            "heldout_cases": 0,
            "rows": [
                _skipped_row(spec, scope, "no held-out session cases available", data_used)
                for spec in MODEL_SPECS
            ],
        }

    split, split_method = split_session_payloads(payloads)
    train = split["train"]
    calibration = split["calibration"]
    test = split["test"]
    train_cases = build_cases(train)
    calibration_cases = build_cases(calibration)
    test_cases = build_cases(test)
    fit_payloads = list(train) + list(calibration)
    fit_cases = list(train_cases) + list(calibration_cases)
    local_fit_model = build_transition_model(
        fit_payloads if scope == "local" else [],
        prefix_max_length=int(policy.get("prefix_max_length", 3)),
        source_name="local_transition",
    )
    external_fit_model = (
        build_transition_model(
            fit_payloads,
            prefix_max_length=int(policy.get("prefix_max_length", 3)),
            source_name="external_seed_transition",
        )
        if scope == "external"
        else selected_external_model
    )
    vocabulary = tactic_vocabulary(
        fit_payloads,
        external_fit_model,
        local_fit_model,
    )
    local_train_model = build_transition_model(
        train if scope == "local" else [],
        prefix_max_length=int(policy.get("prefix_max_length", 3)),
        source_name="local_transition",
    )
    kappa_selection = _calibrate_kappa(
        calibration_cases if scope == "local" else [],
        external_fit_model,
        local_train_model,
        vocabulary,
        alpha=alpha,
        kappa_grid=kappa_grid,
        prefix_max_length=int(policy.get("prefix_max_length", 3)),
        min_support=float(policy.get("min_transition_count", 2)),
        min_cases=min_calibration_cases,
    )
    local_update_validated = kappa_selection["status"] == "selected_on_calibration"
    selected_kappa = float(kappa_selection.get("selected_kappa") or 1.0)
    bayes_local_model = local_fit_model if local_update_validated else build_transition_model([])

    predictors: Dict[str, Predictor] = {
        "majority_class": _majority_predictor(fit_payloads),
        "first_order_markov": _first_order_predictor(fit_payloads),
        "current_hard_backoff": _engine_predictor(
            policy,
            local_fit_model,
            external_fit_model,
        ),
        "empirical_bayes_vomm": Predictor(
            predict=lambda case: empirical_bayes_probabilities(
                case.features,
                external_fit_model,
                bayes_local_model,
                vocabulary,
                alpha=alpha,
                kappa=selected_kappa,
                prefix_max_length=int(policy.get("prefix_max_length", 3)),
                min_support=float(policy.get("min_transition_count", 2)),
            ),
            metadata={
                "alpha": alpha,
                "kappa_selection": kappa_selection,
                "local_update_validated": local_update_validated,
                "evaluation_mode": (
                    "external_prior_plus_local_posterior"
                    if local_update_validated
                    else "external_prior_only"
                ),
            },
        ),
        "fallback_progression": _fallback_predictor(policy),
        "external_only": _engine_predictor(
            policy,
            build_transition_model([]),
            external_fit_model,
            source_order=["external_seed_transition"],
            fallback_scorer="__no_fallback__",
        ),
    }
    if scope == "local":
        predictors["local_only"] = _engine_predictor(
            policy,
            local_fit_model,
            external_fit_model,
            source_order=["local_transition"],
            fallback_scorer="__no_fallback__",
        )

    logistic, logistic_reason = _logistic_predictor(train_cases, calibration_cases)
    if logistic is not None:
        predictors["multinomial_logistic_regression"] = logistic

    protocols = sorted(
        {
            str(payload.get("protocol") or "unknown").strip() or "unknown"
            for payload in payloads
        }
    )
    if scope == "external" and protocols == ["ssh"]:
        data_used = "privacy-minimized external Cowrie SSH classifier-derived weak-label sessions"
    elif scope == "external":
        data_used = "privacy-minimized external Cowrie mixed/unknown-protocol weak-label sessions"
    else:
        data_used = "local production_live external-source session payloads supplied to this run"
    rows = []
    for index, spec in enumerate(MODEL_SPECS):
        model_id = spec["model_id"]
        if model_id == "local_only" and scope != "local":
            rows.append(
                _skipped_row(
                    spec,
                    scope,
                    "local-only is not a valid source ablation for the external-corpus scope",
                    data_used,
                )
            )
            continue
        predictor = predictors.get(model_id)
        if predictor is None:
            reason = logistic_reason if model_id == "multinomial_logistic_regression" else "model input unavailable"
            rows.append(_skipped_row(spec, scope, reason, data_used))
            continue
        metrics = summarize_predictions(
            test_cases,
            predictor,
            bootstrap_iterations=bootstrap_iterations,
            seed=seed + index * 1009,
            min_per_tactic_support=min_per_tactic_support,
            target_vocabulary=vocabulary,
        )
        rows.append(
            {
                **spec,
                "scope": scope,
                "status": "evaluated" if test_cases else "skipped",
                "reason": "" if test_cases else "chronological split produced no held-out transition cases",
                "data_used": data_used,
                "metrics": metrics if test_cases else None,
                "model_metadata": predictor.metadata,
            }
        )

    return {
        "scope": scope,
        "status": "evaluated" if test_cases else "not_evaluated",
        "reason": "" if test_cases else "no held-out transition cases after the selected whole-session split",
        "split_method": split_method,
        "split": {key: len(value) for key, value in split.items()},
        "heldout_cases": len(test_cases),
        "identical_heldout_case_ids": sorted(
            f"{case.session_id}:{index}:{case.actual}"
            for index, case in enumerate(test_cases)
        ),
        "data_sufficiency": {
            "status": (
                "sufficient_for_weak_label_comparative_reporting"
                if len(test_cases) >= min_evaluation_examples
                else "insufficient_data"
            ),
            "minimum_examples": min_evaluation_examples,
            "metrics_are_descriptive_only": scope == "external" or len(test_cases) < min_evaluation_examples,
            "claim_scope": (
                "comparison against classifier-derived external weak labels; not expert-ground-truth accuracy"
                if scope == "external"
                else "deployment-local comparison only"
            ),
        },
        "training_model_summaries": {
            "external": _compact_model(external_fit_model),
            "local": _compact_model(local_fit_model),
        },
        "vocabulary": vocabulary,
        "kappa_selection": kappa_selection,
        "rows": rows,
    }


def _historical_evidence(path_text: str) -> Dict[str, Any]:
    path = Path(path_text)
    if not path.exists():
        return {"available": False, "path": path_text}
    document = _load_json(path_text)
    comparisons = {}
    for item in document.get("model_comparison") or []:
        label = str(item.get("label") or "")
        if label in {
            "local_transition_only",
            "external_seed_transition_only",
            "fallback_progression_only",
        }:
            comparisons[label] = item.get("metrics") or {}
    return {
        "available": True,
        "path": path_text,
        "interpretation": (
            "Historical external weak-label evidence only; not recomputed by this run and not local accuracy."
        ),
        "dataset_statistics": document.get("dataset_statistics") or {},
        "split": document.get("split") or {},
        "comparisons": comparisons,
        "limitations": document.get("limitations") or [],
    }


def _fmt(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def comparison_markdown(result: Dict[str, Any]) -> str:
    lines: List[str] = []
    for scope in result.get("evaluations") or []:
        lines.extend(
            [
                f"### {str(scope.get('scope') or '').title()} evaluation",
                "",
                "| Model | Role | Data used | Input context | Output | Abstention support | Pooled Top-1 | Macro Top-1 / balanced | Sufficient-support macro | MRR | Normalized Brier | Coverage | Abstention rate | Main limitation |",
                "|---|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
            ]
        )
        for row in scope.get("rows") or []:
            metrics = row.get("metrics") or {}
            lines.append(
                "| {model} | {role} | {data} | {context} | {output} | {abstention} | {top1} | {macro} | {supported_macro} | {mrr} | {brier} | {coverage} | {rate} | {limitation} |".format(
                    model=row["model"],
                    role=row["role"],
                    data=row.get("data_used") or "n/a",
                    context=row["input_context"],
                    output=row["output"],
                    abstention=row["abstention_support"],
                    top1=_fmt(metrics.get("top1_accuracy")),
                    macro=_fmt(metrics.get("macro_top1_accuracy")),
                    supported_macro=_fmt(
                        metrics.get("macro_top1_accuracy_sufficient_support")
                    ),
                    mrr=_fmt(metrics.get("mean_reciprocal_rank")),
                    brier=_fmt(metrics.get("normalized_multiclass_brier_score")),
                    coverage=_fmt(metrics.get("coverage")),
                    rate=_fmt(metrics.get("abstention_rate")),
                    limitation=row.get("reason") or row["limitation"],
                )
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def thesis_qa_markdown() -> str:
    lines = ["| Question likely asked | Answer |", "|---|---|"]
    lines.extend(f"| {question} | {answer} |" for question, answer in THESIS_DEFENSE_QA)
    return "\n".join(lines)


def _csv_rows(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    output = []
    for scope in result.get("evaluations") or []:
        for row in scope.get("rows") or []:
            metrics = row.get("metrics") or {}
            support_summary = metrics.get("tactic_support_summary") or {}
            aggregate_row = {
                    "row_type": "aggregate",
                    "scope": row.get("scope"),
                    "model_id": row.get("model_id"),
                    "model": row.get("model"),
                    "role": row.get("role"),
                    "status": row.get("status"),
                    "data_used": row.get("data_used"),
                    "input_context": row.get("input_context"),
                    "output": row.get("output"),
                    "abstention_support": row.get("abstention_support"),
                    "target_tactic": None,
                    "support": None,
                    "support_status": None,
                    "reportable": None,
                    "top1_accuracy": metrics.get("top1_accuracy"),
                    "top3_accuracy_secondary": metrics.get("top3_accuracy_secondary"),
                    "mean_reciprocal_rank": metrics.get("mean_reciprocal_rank"),
                    "brier_score": metrics.get("brier_score"),
                    "normalized_multiclass_brier_score": metrics.get(
                        "normalized_multiclass_brier_score"
                    ),
                    "coverage": metrics.get("coverage"),
                    "abstention_rate": metrics.get("abstention_rate"),
                    "selective_top1_accuracy": metrics.get("selective_top1_accuracy"),
                    "macro_top1_accuracy": metrics.get("macro_top1_accuracy"),
                    "balanced_accuracy": metrics.get("balanced_accuracy"),
                    "macro_recall": metrics.get("macro_recall"),
                    "macro_top1_accuracy_sufficient_support": metrics.get(
                        "macro_top1_accuracy_sufficient_support"
                    ),
                    "descriptive_top1_accuracy": None,
                    "descriptive_mean_reciprocal_rank": None,
                    "descriptive_normalized_multiclass_brier_score": None,
                    "low_support_tactics": ";".join(
                        support_summary.get("low_support_tactics") or []
                    ),
                    "zero_support_tactics": ";".join(
                        support_summary.get("zero_support_tactics") or []
                    ),
                    "evaluated_examples": metrics.get("evaluated_examples"),
                    "main_limitation": row.get("reason") or row.get("limitation"),
                }
            output.append(aggregate_row)
            for tactic, tactic_metrics in sorted(
                (metrics.get("per_tactic") or {}).items()
            ):
                descriptive = tactic_metrics.get("descriptive_only") or {}
                per_tactic_row = dict(aggregate_row)
                per_tactic_row.update(
                    {
                        "row_type": "per_tactic",
                        "target_tactic": tactic,
                        "support": tactic_metrics.get("support"),
                        "support_status": tactic_metrics.get("support_status"),
                        "reportable": tactic_metrics.get("reportable"),
                        "top1_accuracy": tactic_metrics.get("top1_accuracy"),
                        "top3_accuracy_secondary": None,
                        "mean_reciprocal_rank": tactic_metrics.get(
                            "mean_reciprocal_rank"
                        ),
                        "brier_score": tactic_metrics.get("brier_score"),
                        "normalized_multiclass_brier_score": tactic_metrics.get(
                            "normalized_multiclass_brier_score"
                        ),
                        "coverage": None,
                        "abstention_rate": None,
                        "selective_top1_accuracy": None,
                        "macro_top1_accuracy": None,
                        "balanced_accuracy": None,
                        "macro_recall": None,
                        "macro_top1_accuracy_sufficient_support": None,
                        "descriptive_top1_accuracy": descriptive.get(
                            "top1_accuracy"
                        ),
                        "descriptive_mean_reciprocal_rank": descriptive.get(
                            "mean_reciprocal_rank"
                        ),
                        "descriptive_normalized_multiclass_brier_score": descriptive.get(
                            "normalized_multiclass_brier_score"
                        ),
                        "low_support_tactics": None,
                        "zero_support_tactics": None,
                        "evaluated_examples": tactic_metrics.get("support"),
                        "main_limitation": (
                            "descriptive only; below minimum per-tactic support"
                            if not tactic_metrics.get("reportable")
                            else row.get("reason") or row.get("limitation")
                        ),
                    }
                )
                output.append(per_tactic_row)
    return output


def write_outputs(result: Dict[str, Any], json_path: str, csv_path: str) -> None:
    output_json = Path(json_path)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = _csv_rows(result)
    output_csv = Path(csv_path)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0]) if rows else ["scope", "model_id", "status"]
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_result(args: argparse.Namespace) -> Dict[str, Any]:
    policy = load_policy(args.policy)
    external_payloads = (
        load_session_payloads(args.external_payload_json)
        if args.external_payload_json
        else []
    )
    raw_local_payloads = (
        load_session_payloads(args.local_payload_json)
        if args.local_payload_json
        else []
    )
    local_payloads, local_provenance_filter = filter_local_production_payloads(
        raw_local_payloads
    )
    external_model = (
        load_transition_model(args.external_model)
        if local_payloads
        else build_transition_model([])
    )
    external_payload_summary = payload_input_summary(external_payloads)
    local_payload_summary = payload_input_summary(local_payloads)
    dataset_summary_path = getattr(args, "dataset_summary_json", None)
    dataset_summary = (
        _load_json(dataset_summary_path)
        if dataset_summary_path
        else {}
    )
    external_protocols = external_payload_summary.get("protocols") or []
    external_scope_statement = (
        "The supplied external comparison sample is confirmed SSH-only."
        if external_protocols == ["ssh"]
        else "The supplied external comparison corpus is mixed-protocol or protocol-unknown and is not evidence of SSH-only accuracy."
    )
    sample_scope = str(dataset_summary.get("sample_scope") or "unspecified")
    zenodo_partial_sample = (
        "COW160x4" in str(dataset_summary.get("dataset_source") or "")
        and sample_scope
        in {
            "one_daily_member_only",
            "two_time_spread_daily_members_approximately_500mb",
        }
    )
    selected_members = dataset_summary.get("selected_members")
    if not isinstance(selected_members, list):
        selected_members = (
            [dataset_summary["sample_member"]]
            if dataset_summary.get("sample_member")
            else []
        )
    processed_member_count = len(selected_members)
    reporting_interpretation = {
        "pooled_accuracy_warning": (
            "Pooled Top-1 can be inflated by target-class imbalance and highly regular repeated transition patterns. "
            "It must be reported with macro/balanced and per-tactic metrics."
        ),
        "macro_metric_priority": (
            "Balanced accuracy is reported as macro recall: the unweighted mean Top-1 recall across held-out target tactics with observed support."
        ),
        "low_support_policy": (
            "Per-tactic Top-1, MRR, and Brier are reportable only at or above the configured minimum support; lower-support values are descriptive only."
        ),
        "replacement_decision": (
            "additional_external_validation_not_replacement"
            if zenodo_partial_sample
            else "not_determined_by_this_evaluator"
        ),
        "replacement_reason": (
            f"Only {processed_member_count} of 52 daily members were processed, so full-corpus and cross-configuration generalization are untested."
            if zenodo_partial_sample
            else "Replacement requires dataset-specific provenance and full-corpus evidence."
        ),
        "full_52_member_processing_plan": (
            [
                "Keep all source members and intermediate identifiers in a private, non-Git workspace.",
                "Stream only session/event records needed for sequence reconstruction into a disk-backed store keyed by source session identifier.",
                "Store event ordering metadata and privacy-sensitive classification inputs only in the private staging store.",
                "Classify unique input fragments in bounded batches with the frozen rules, checkpoint, thresholds, disagreement policy, and trust predicate.",
                "Assemble and timestamp-sort complete closed sessions across member boundaries before assigning splits.",
                "Assign the earliest 70% of whole eligible sessions to train, the next 15% to calibration, and the latest 15% to held-out test.",
                "Generate privacy-minimized payloads, evaluate pooled and per-configuration results, verify privacy, and remove private staging data when retention is no longer required.",
            ]
            if zenodo_partial_sample
            else []
        ),
    }
    evaluations = [
        evaluate_scope(
            scope="external",
            payloads=external_payloads,
            policy=policy,
            selected_external_model=external_model,
            alpha=args.alpha,
            kappa_grid=args.kappa_grid,
            min_calibration_cases=args.min_calibration_cases,
            min_evaluation_examples=args.min_evaluation_examples,
            min_per_tactic_support=args.min_per_tactic_support,
            bootstrap_iterations=args.bootstrap_iterations,
            seed=args.seed,
        ),
        evaluate_scope(
            scope="local",
            payloads=local_payloads,
            policy=policy,
            selected_external_model=external_model,
            alpha=args.alpha,
            kappa_grid=args.kappa_grid,
            min_calibration_cases=args.min_calibration_cases,
            min_evaluation_examples=args.min_evaluation_examples,
            min_per_tactic_support=args.min_per_tactic_support,
            bootstrap_iterations=args.bootstrap_iterations,
            seed=args.seed + 500_000,
        ),
    ]
    return {
        "schema_version": "next_tactic_model_comparison.v2",
        "generated_at": utc_now(),
        "scope_statement": (
            "Next observed MITRE ATT&CK tactic from trusted Cowrie honeypot-observable tactic sequences. "
            + external_scope_statement
        ),
        "runtime_behavior_changed": False,
        "production_policy_changed": False,
        "scorer_weights_changed": False,
        "split_method": "recorded per evaluation scope",
        "trust_and_leakage_controls": {
            "shared_trust_predicate": "production.classification.trust.is_trusted_classification_event",
            "adjacent_tactic_deduplication": True,
            "whole_session_split_before_case_extraction": True,
            "external_and_local_results_separate": True,
        },
        "metric_semantics": {
            "top1_accuracy": "all-case accuracy; abstentions count as failures",
            "top3_accuracy_secondary": "secondary because the external empirical scope contains few tactics",
            "brier_score": "unnormalized multiclass Brier score in [0, 2], retained for backward compatibility; lower is better",
            "normalized_multiclass_brier_score": "multiclass Brier score divided by 2, yielding [0, 1]; lower is better",
            "macro_top1_accuracy": "unweighted mean per-tactic Top-1 recall across target tactics observed in held-out data",
            "balanced_accuracy": "identical to macro recall for this single-label multiclass task",
            "macro_recall": "alias of balanced accuracy and macro Top-1 in this task",
            "macro_top1_accuracy_sufficient_support": "unweighted mean per-tactic Top-1 over tactics meeting the configured reportable-support threshold",
            "per_tactic_metrics": "Top-1, MRR, and Brier are withheld as reportable metrics below the configured support threshold; any observed low-support values are marked descriptive-only",
            "coverage": "fraction of held-out cases receiving a non-empty ranking",
            "selective_top1_accuracy": "Top-1 accuracy among covered cases only",
            "scores_calibrated": False,
        },
        "input_provenance": {
            "policy": args.policy,
            "external_transition_model_for_external_scope": (
                "rebuilt only from supplied external train+calibration session payloads"
                if external_payloads
                else "not available"
            ),
            "retained_external_transition_model_for_local_scope": (
                args.external_model if local_payloads else "not loaded or used"
            ),
            "external_session_payloads": args.external_payload_json or "not supplied",
            "local_session_payloads": args.local_payload_json or "not supplied",
            "dataset_summary": dataset_summary,
            "external_payload_summary": external_payload_summary,
            "local_payload_summary": local_payload_summary,
            "local_provenance_filter": local_provenance_filter,
            "external_protocol_scope": (
                external_payload_summary.get("protocols")
                or ["unavailable; retained aggregate provenance says SSH/Telnet"]
            ),
        },
        "reporting_interpretation": reporting_interpretation,
        "parameters": {
            "seed": args.seed,
            "alpha": args.alpha,
            "kappa_grid": list(args.kappa_grid),
            "min_calibration_cases": args.min_calibration_cases,
            "min_evaluation_examples": args.min_evaluation_examples,
            "min_per_tactic_support": args.min_per_tactic_support,
            "bootstrap_iterations": args.bootstrap_iterations,
        },
        "optional_dependency_status": {
            "scikit_learn_available": importlib.util.find_spec("sklearn") is not None,
            "multinomial_logistic_regression": (
                "eligible_for_data-dependent evaluation"
                if importlib.util.find_spec("sklearn") is not None
                else "skipped unless scikit-learn is supplied by the evaluation environment"
            ),
        },
        "evaluations": evaluations,
        "historical_external_evidence": _historical_evidence(args.historical_evidence),
        "thesis_defense_qa": [
            {"question": question, "answer": answer}
            for question, answer in THESIS_DEFENSE_QA
        ],
        "not_recommended_models": NOT_RECOMMENDED_MODELS,
        "limitations": [
            "No production improvement is claimed unless a supplied held-out set supports it.",
            "The public package may include privacy-minimized external tactic sequences, but no raw Cowrie telemetry or local production sessions.",
            "A partial external sample cannot establish full-corpus or cross-configuration generalization.",
            "High pooled accuracy may reflect target imbalance and regular transition templates rather than uniformly strong tactic prediction.",
            "Macro/balanced and per-tactic metrics must accompany pooled Top-1 when reporting this evaluation.",
            "External tactic labels are classifier-derived weak labels, not independent expert ground truth.",
            "The exact historical rule revision used by the earlier external experiment is not proven by its artifact.",
            "Local prediction accuracy remains unclaimed when clean held-out local transitions are insufficient.",
            "Returned scores are not called calibrated probabilities without held-out calibration evidence.",
        ],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default=DEFAULT_POLICY_PATH)
    parser.add_argument("--external-model", default=DEFAULT_EXTERNAL_MODEL_PATH)
    parser.add_argument("--historical-evidence", default=DEFAULT_HISTORICAL_EVIDENCE_PATH)
    parser.add_argument("--external-payload-json", default=DEFAULT_EXTERNAL_PAYLOAD_PATH)
    parser.add_argument("--dataset-summary-json")
    parser.add_argument("--local-payload-json")
    parser.add_argument("--output-json", default=DEFAULT_OUTPUT_JSON)
    parser.add_argument("--output-csv", default=DEFAULT_OUTPUT_CSV)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument("--kappa-grid", type=float, nargs="+", default=list(DEFAULT_KAPPA_GRID))
    parser.add_argument("--min-calibration-cases", type=int, default=10)
    parser.add_argument("--min-evaluation-examples", type=int, default=30)
    parser.add_argument("--min-per-tactic-support", type=int, default=5)
    parser.add_argument("--bootstrap-iterations", type=int, default=1000)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    result = build_result(args)
    write_outputs(result, args.output_json, args.output_csv)
    print(comparison_markdown(result))
    print("\n### Thesis-defense questions\n")
    print(thesis_qa_markdown())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
