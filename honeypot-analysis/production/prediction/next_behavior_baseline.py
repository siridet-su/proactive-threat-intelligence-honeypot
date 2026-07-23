"""Standard-library baselines for the corrected next-behavior target.

The models in this module consume only ``next_behavior_example.v1`` records.
They model an exact next phase state (a canonical tactic set) or the terminal
outcome.  They neither adapt the historical single-tactic target nor read data
from disk.  A missing context produces an explicit abstention; callers must
choose a different model themselves if that is desired.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from production.prediction.next_behavior_contract import (
    EXAMPLE_SCHEMA_VERSION,
    TARGET_CONTRACT_ID,
    TERMINAL_OUTCOME,
)

BASELINE_SCHEMA_VERSION = "next_behavior_baseline.v1"
BASELINE_PREDICTION_SCHEMA_VERSION = "next_behavior_baseline_prediction.v1"
BASELINE_FAMILIES = frozenset(
    {
        "majority_terminal_prevalence",
        "first_order_phase_state_markov",
        "hard_backoff_vomm",
        "interpolated_vomm",
    }
)

PhaseState = Tuple[str, ...]
History = Tuple[PhaseState, ...]


class NextBehaviorBaselineError(ValueError):
    """Raised when corrected examples or a baseline artifact are invalid."""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _canonical_tactics(value: Any, *, path: str) -> PhaseState:
    if not isinstance(value, list) or not value:
        raise NextBehaviorBaselineError(f"{path} must be a non-empty tactic list")
    tactics: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise NextBehaviorBaselineError(f"{path} must contain only strings")
        tactic = _clean(item)
        if not tactic:
            raise NextBehaviorBaselineError(f"{path} contains an empty tactic")
        if tactic not in tactics:
            tactics.append(tactic)
    canonical = tuple(sorted(tactics))
    if list(value) != list(canonical):
        raise NextBehaviorBaselineError(f"{path} must be sorted and duplicate-free")
    return canonical


def _validated_example(example: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(example, Mapping):
        raise NextBehaviorBaselineError("example must be an object")
    if example.get("schema_version") != EXAMPLE_SCHEMA_VERSION:
        raise NextBehaviorBaselineError(
            f"example schema_version must be {EXAMPLE_SCHEMA_VERSION}"
        )
    if example.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise NextBehaviorBaselineError(
            "example must use the corrected phase-or-session-end target"
        )
    for field in ("example_id", "session_id"):
        field_value = example.get(field)
        if (
            not isinstance(field_value, str)
            or not field_value.strip()
            or field_value != field_value.strip()
        ):
            raise NextBehaviorBaselineError(f"example.{field} is required")
    model_input = example.get("model_input")
    if not isinstance(model_input, Mapping):
        raise NextBehaviorBaselineError("example.model_input must be an object")
    phases = model_input.get("phase_sequence")
    if not isinstance(phases, list) or not phases:
        raise NextBehaviorBaselineError(
            "example.model_input.phase_sequence must not be empty"
        )
    for index, phase in enumerate(phases):
        if not isinstance(phase, Mapping):
            raise NextBehaviorBaselineError(
                f"example.model_input.phase_sequence[{index}] must be an object"
            )
        _canonical_tactics(
            phase.get("tactics"),
            path=f"example.model_input.phase_sequence[{index}].tactics",
        )
    target = example.get("target")
    if not isinstance(target, Mapping):
        raise NextBehaviorBaselineError("example.target must be an object")
    outcome_type = target.get("outcome_type")
    if outcome_type == "session_end":
        if target.get("tactics") != []:
            raise NextBehaviorBaselineError("terminal target tactics must be empty")
        if target.get("terminal_outcome") != TERMINAL_OUTCOME:
            raise NextBehaviorBaselineError("terminal target marker is invalid")
    elif outcome_type == "next_behavior_phase":
        _canonical_tactics(target.get("tactics"), path="example.target.tactics")
        if _clean(target.get("terminal_outcome")):
            raise NextBehaviorBaselineError(
                "nonterminal target cannot carry a terminal marker"
            )
    else:
        raise NextBehaviorBaselineError("example.target.outcome_type is invalid")
    return deepcopy(dict(example))


def _validated_examples(
    examples: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    if not isinstance(examples, Sequence) or isinstance(examples, (str, bytes)):
        raise NextBehaviorBaselineError("examples must be a sequence")
    if not examples:
        raise NextBehaviorBaselineError("examples must not be empty")
    validated = [_validated_example(item) for item in examples]
    example_ids = [item["example_id"] for item in validated]
    if len(set(example_ids)) != len(example_ids):
        raise NextBehaviorBaselineError("example_id values must be unique")
    return validated


def phase_state(tactics: Iterable[Any]) -> PhaseState:
    """Return a deterministic, exact multilabel phase state."""

    values = sorted({_clean(item) for item in tactics if _clean(item)})
    if not values:
        raise NextBehaviorBaselineError("phase state must contain a tactic")
    return tuple(values)


def example_history(example: Mapping[str, Any]) -> History:
    """Extract the exact ordered phase-state prefix from one corrected example."""

    validated = _validated_example(example)
    return tuple(
        tuple(phase["tactics"])
        for phase in validated["model_input"]["phase_sequence"]
    )


def example_target_state(example: Mapping[str, Any]) -> PhaseState | None:
    """Return the next phase state, or ``None`` for session end."""

    validated = _validated_example(example)
    target = validated["target"]
    if target["outcome_type"] == "session_end":
        return None
    return tuple(target["tactics"])


def _state_record(state: PhaseState | None) -> Dict[str, Any]:
    if state is None:
        return {
            "outcome_type": "session_end",
            "tactics": [],
            "terminal_outcome": TERMINAL_OUTCOME,
        }
    return {
        "outcome_type": "next_behavior_phase",
        "tactics": list(state),
        "terminal_outcome": "",
    }


def _record_state(value: Mapping[str, Any]) -> PhaseState | None:
    if value.get("outcome_type") == "session_end":
        if value.get("tactics") != [] or value.get("terminal_outcome") != TERMINAL_OUTCOME:
            raise NextBehaviorBaselineError("artifact terminal state is invalid")
        return None
    if value.get("outcome_type") != "next_behavior_phase":
        raise NextBehaviorBaselineError("artifact outcome state is invalid")
    return _canonical_tactics(value.get("tactics"), path="artifact state tactics")


def _state_sort_key(state: PhaseState | None) -> str:
    return TERMINAL_OUTCOME if state is None else "|".join(state)


def _history_record(history: History) -> List[List[str]]:
    return [list(state) for state in history]


def _record_history(value: Any) -> History:
    if not isinstance(value, list) or not value:
        raise NextBehaviorBaselineError("artifact context must be a non-empty list")
    return tuple(
        _canonical_tactics(item, path="artifact context phase") for item in value
    )


def _artifact_id(value: Mapping[str, Any]) -> str:
    identity = deepcopy(dict(value))
    identity.pop("model_id", None)
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "nextbehaviorbaseline_" + hashlib.sha256(encoded).hexdigest()[:32]


def _counts_records(
    counts: Mapping[History, Counter[PhaseState | None]],
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for context in sorted(
        counts, key=lambda item: (len(item), tuple(map(_state_sort_key, item)))
    ):
        outcomes = [
            {"state": _state_record(state), "count": count}
            for state, count in sorted(
                counts[context].items(),
                key=lambda item: _state_sort_key(item[0]),
            )
        ]
        records.append({"context": _history_record(context), "outcomes": outcomes})
    return records


def _global_records(counts: Counter[PhaseState | None]) -> List[Dict[str, Any]]:
    return [
        {"state": _state_record(state), "count": count}
        for state, count in sorted(
            counts.items(), key=lambda item: _state_sort_key(item[0])
        )
    ]


def _build_artifact(
    examples: Sequence[Mapping[str, Any]],
    *,
    family: str,
    maximum_order: int,
    interpolation_decay: float | None = None,
    include_zero_order: bool = False,
) -> Dict[str, Any]:
    validated = _validated_examples(examples)
    if family not in BASELINE_FAMILIES:
        raise NextBehaviorBaselineError("baseline family is invalid")
    if isinstance(maximum_order, bool) or not isinstance(maximum_order, int) or maximum_order < 0:
        raise NextBehaviorBaselineError("maximum_order must be non-negative")
    if family != "majority_terminal_prevalence" and maximum_order < 1:
        raise NextBehaviorBaselineError("context baselines need a positive order")
    if interpolation_decay is not None and not (
        isinstance(interpolation_decay, (int, float))
        and not isinstance(interpolation_decay, bool)
        and 0.0 < float(interpolation_decay) <= 1.0
    ):
        raise NextBehaviorBaselineError(
            "interpolation_decay must be greater than zero and at most one"
        )

    global_counts: Counter[PhaseState | None] = Counter()
    context_counts: Dict[History, Counter[PhaseState | None]] = defaultdict(Counter)
    session_ids: set[str] = set()
    for example in validated:
        history = tuple(
            tuple(phase["tactics"])
            for phase in example["model_input"]["phase_sequence"]
        )
        target = (
            None
            if example["target"]["outcome_type"] == "session_end"
            else tuple(example["target"]["tactics"])
        )
        global_counts[target] += 1
        session_ids.add(example["session_id"])
        if maximum_order:
            for order in range(1, min(maximum_order, len(history)) + 1):
                context_counts[history[-order:]][target] += 1

    artifact: Dict[str, Any] = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "family": family,
        "maximum_order": maximum_order,
        "include_zero_order": bool(include_zero_order),
        "interpolation_decay": (
            float(interpolation_decay) if interpolation_decay is not None else None
        ),
        "training_example_count": len(validated),
        "training_session_count": len(session_ids),
        "training_example_ids": sorted(item["example_id"] for item in validated),
        "training_session_ids": sorted(session_ids),
        "terminal_target_count": global_counts[None],
        "terminal_prevalence": global_counts[None] / len(validated),
        "tactic_target_count": len(validated) - global_counts[None],
        "tactic_prevalence": (
            (len(validated) - global_counts[None]) / len(validated)
        ),
        "majority_outcome_state": _state_record(
            sorted(
                global_counts,
                key=lambda state: (
                    -global_counts[state],
                    _state_sort_key(state),
                ),
            )[0]
        ),
        "global_outcomes": _global_records(global_counts),
        "contexts": _counts_records(context_counts),
    }
    artifact["model_id"] = _artifact_id(artifact)
    return require_valid_baseline(artifact)


def fit_majority_terminal_prevalence(
    examples: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Fit exact-state majority and explicit terminal prevalence."""

    return _build_artifact(
        examples,
        family="majority_terminal_prevalence",
        maximum_order=0,
        include_zero_order=True,
    )


def fit_first_order_phase_state_markov(
    examples: Sequence[Mapping[str, Any]],
    *,
    include_zero_order: bool = False,
) -> Dict[str, Any]:
    """Fit transitions from the last exact phase state to the next state/end."""

    return _build_artifact(
        examples,
        family="first_order_phase_state_markov",
        maximum_order=1,
        include_zero_order=include_zero_order,
    )


def fit_hard_backoff_vomm(
    examples: Sequence[Mapping[str, Any]],
    *,
    maximum_order: int = 8,
    include_zero_order: bool = False,
) -> Dict[str, Any]:
    """Fit a VOMM whose longest observed suffix wins at prediction time."""

    return _build_artifact(
        examples,
        family="hard_backoff_vomm",
        maximum_order=maximum_order,
        include_zero_order=include_zero_order,
    )


def fit_interpolated_vomm(
    examples: Sequence[Mapping[str, Any]],
    *,
    maximum_order: int = 8,
    interpolation_decay: float = 0.5,
    include_zero_order: bool = False,
) -> Dict[str, Any]:
    """Fit a VOMM combining all observed suffix orders with frozen weights."""

    return _build_artifact(
        examples,
        family="interpolated_vomm",
        maximum_order=maximum_order,
        interpolation_decay=interpolation_decay,
        include_zero_order=include_zero_order,
    )


def _parse_outcomes(value: Any, *, path: str) -> Counter[PhaseState | None]:
    if not isinstance(value, list) or not value:
        raise NextBehaviorBaselineError(f"{path} must not be empty")
    counts: Counter[PhaseState | None] = Counter()
    for index, record in enumerate(value):
        if not isinstance(record, Mapping):
            raise NextBehaviorBaselineError(f"{path}[{index}] must be an object")
        state_value = record.get("state")
        if not isinstance(state_value, Mapping):
            raise NextBehaviorBaselineError(f"{path}[{index}].state is invalid")
        state = _record_state(state_value)
        count = record.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise NextBehaviorBaselineError(f"{path}[{index}].count is invalid")
        if state in counts:
            raise NextBehaviorBaselineError(f"{path} contains a duplicate state")
        counts[state] = count
    return counts


def require_valid_baseline(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate and copy a corrected-target baseline artifact."""

    if not isinstance(value, Mapping):
        raise NextBehaviorBaselineError("baseline artifact must be an object")
    artifact = deepcopy(dict(value))
    if artifact.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise NextBehaviorBaselineError("baseline schema_version is invalid")
    if artifact.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise NextBehaviorBaselineError(
            "baseline does not use the corrected target contract"
        )
    family = artifact.get("family")
    if family not in BASELINE_FAMILIES:
        raise NextBehaviorBaselineError("baseline family is invalid")
    maximum_order = artifact.get("maximum_order")
    if (
        isinstance(maximum_order, bool)
        or not isinstance(maximum_order, int)
        or maximum_order < 0
    ):
        raise NextBehaviorBaselineError("baseline maximum_order is invalid")
    if type(artifact.get("include_zero_order")) is not bool:
        raise NextBehaviorBaselineError("baseline include_zero_order must be boolean")
    if family == "interpolated_vomm":
        decay = artifact.get("interpolation_decay")
        if (
            isinstance(decay, bool)
            or not isinstance(decay, (int, float))
            or not 0.0 < float(decay) <= 1.0
        ):
            raise NextBehaviorBaselineError("baseline interpolation_decay is invalid")
    elif artifact.get("interpolation_decay") is not None:
        raise NextBehaviorBaselineError(
            "only interpolated VOMM may define interpolation_decay"
        )
    global_counts = _parse_outcomes(
        artifact.get("global_outcomes"), path="global_outcomes"
    )
    example_count = artifact.get("training_example_count")
    if (
        isinstance(example_count, bool)
        or not isinstance(example_count, int)
        or example_count < 1
        or sum(global_counts.values()) != example_count
    ):
        raise NextBehaviorBaselineError("training example count does not reconcile")
    terminal_count = artifact.get("terminal_target_count")
    tactic_count = artifact.get("tactic_target_count")
    if (
        isinstance(terminal_count, bool)
        or not isinstance(terminal_count, int)
        or terminal_count != global_counts.get(None, 0)
        or isinstance(tactic_count, bool)
        or not isinstance(tactic_count, int)
        or tactic_count != example_count - terminal_count
    ):
        raise NextBehaviorBaselineError("target prevalence counts do not reconcile")
    terminal_prevalence = artifact.get("terminal_prevalence")
    tactic_prevalence = artifact.get("tactic_prevalence")
    if (
        isinstance(terminal_prevalence, bool)
        or not isinstance(terminal_prevalence, (int, float))
        or float(terminal_prevalence) != terminal_count / example_count
        or isinstance(tactic_prevalence, bool)
        or not isinstance(tactic_prevalence, (int, float))
        or float(tactic_prevalence) != tactic_count / example_count
    ):
        raise NextBehaviorBaselineError("target prevalence values do not reconcile")
    majority = artifact.get("majority_outcome_state")
    if not isinstance(majority, Mapping):
        raise NextBehaviorBaselineError("majority_outcome_state is invalid")
    majority_state = _record_state(majority)
    expected_majority = sorted(
        global_counts,
        key=lambda state: (-global_counts[state], _state_sort_key(state)),
    )[0]
    if majority_state != expected_majority:
        raise NextBehaviorBaselineError("majority_outcome_state does not match counts")
    example_ids = artifact.get("training_example_ids")
    session_ids = artifact.get("training_session_ids")
    if (
        not isinstance(example_ids, list)
        or len(example_ids) != example_count
        or example_ids != sorted(set(example_ids))
        or not all(_clean(item) for item in example_ids)
    ):
        raise NextBehaviorBaselineError("training_example_ids are invalid")
    session_count = artifact.get("training_session_count")
    if (
        not isinstance(session_ids, list)
        or session_ids != sorted(set(session_ids))
        or not all(_clean(item) for item in session_ids)
        or isinstance(session_count, bool)
        or not isinstance(session_count, int)
        or session_count != len(session_ids)
        or session_count < 1
    ):
        raise NextBehaviorBaselineError("training session membership is invalid")
    contexts = artifact.get("contexts")
    if not isinstance(contexts, list):
        raise NextBehaviorBaselineError("contexts must be a list")
    seen: set[History] = set()
    for index, record in enumerate(contexts):
        if not isinstance(record, Mapping):
            raise NextBehaviorBaselineError(f"contexts[{index}] must be an object")
        context = _record_history(record.get("context"))
        if context in seen or len(context) > maximum_order:
            raise NextBehaviorBaselineError("baseline context is duplicate or too long")
        seen.add(context)
        _parse_outcomes(record.get("outcomes"), path=f"contexts[{index}].outcomes")
    if family == "majority_terminal_prevalence" and contexts:
        raise NextBehaviorBaselineError("majority baseline cannot contain contexts")
    if artifact.get("model_id") != _artifact_id(artifact):
        raise NextBehaviorBaselineError("baseline model_id does not match content")
    return artifact


def _distribution(counts: Mapping[PhaseState | None, int]) -> Dict[PhaseState | None, float]:
    total = sum(counts.values())
    return {state: count / total for state, count in counts.items()}


def _artifact_tables(
    artifact: Mapping[str, Any],
) -> tuple[Counter[PhaseState | None], Dict[History, Counter[PhaseState | None]]]:
    global_counts = _parse_outcomes(
        artifact["global_outcomes"], path="global_outcomes"
    )
    contexts: Dict[History, Counter[PhaseState | None]] = {}
    for index, record in enumerate(artifact["contexts"]):
        context = _record_history(record["context"])
        contexts[context] = _parse_outcomes(
            record["outcomes"], path=f"contexts[{index}].outcomes"
        )
    return global_counts, contexts


def _prediction_from_distribution(
    example: Mapping[str, Any],
    artifact: Mapping[str, Any],
    distribution: Mapping[PhaseState | None, float],
    *,
    used_context_lengths: Sequence[int],
    context_weights: Mapping[int, float],
) -> Dict[str, Any]:
    state_ranking = sorted(
        distribution, key=lambda state: (-distribution[state], _state_sort_key(state))
    )
    winner = state_ranking[0]
    tactics = sorted(
        {
            tactic
            for state in distribution
            if state is not None
            for tactic in state
        }
    )
    tactic_scores = {
        tactic: sum(
            score
            for state, score in distribution.items()
            if state is not None and tactic in state
        )
        for tactic in tactics
    }
    ranked_tactics = sorted(
        tactic_scores, key=lambda tactic: (-tactic_scores[tactic], tactic)
    )
    longest = min(
        artifact["maximum_order"],
        len(example["model_input"]["phase_sequence"]),
    )
    used_longest = max(used_context_lengths)
    return {
        "schema_version": BASELINE_PREDICTION_SCHEMA_VERSION,
        "target_contract_id": TARGET_CONTRACT_ID,
        "example_id": example["example_id"],
        "session_id": example["session_id"],
        "model_id": artifact["model_id"],
        "model_family": artifact["family"],
        "status": "predicted",
        "used_context_lengths": list(sorted(used_context_lengths, reverse=True)),
        "context_weights": {
            str(order): context_weights[order] for order in sorted(context_weights)
        },
        "requested_context_length": longest,
        "backoff_steps": max(longest - used_longest, 0),
        "zero_order_used": 0 in used_context_lengths,
        "predicted_terminal": winner is None,
        "predicted_tactics": [] if winner is None else list(winner),
        "terminal_score": float(distribution.get(None, 0.0)),
        "tactic_scores": tactic_scores,
        "ranked_tactics": ranked_tactics,
        "outcome_state_scores": [
            {
                "state": _state_record(state),
                "score": float(distribution[state]),
            }
            for state in state_ranking
        ],
    }


def predict_baseline(
    artifact: Mapping[str, Any],
    example: Mapping[str, Any],
) -> Dict[str, Any]:
    """Predict one corrected example without implicit model substitution."""

    model = require_valid_baseline(artifact)
    item = _validated_example(example)
    global_counts, contexts = _artifact_tables(model)
    history: History = tuple(
        tuple(phase["tactics"]) for phase in item["model_input"]["phase_sequence"]
    )
    family = model["family"]
    maximum = min(model["maximum_order"], len(history))

    if family == "majority_terminal_prevalence":
        return _prediction_from_distribution(
            item,
            model,
            _distribution(global_counts),
            used_context_lengths=[0],
            context_weights={0: 1.0},
        )

    supported: List[tuple[int, Counter[PhaseState | None]]] = []
    for order in range(maximum, 0, -1):
        counts = contexts.get(history[-order:])
        if counts:
            supported.append((order, counts))

    if not supported and model["include_zero_order"]:
        supported.append((0, global_counts))
    elif (
        family == "interpolated_vomm"
        and model["include_zero_order"]
        and all(order != 0 for order, _counts in supported)
    ):
        supported.append((0, global_counts))
    if not supported:
        return {
            "schema_version": BASELINE_PREDICTION_SCHEMA_VERSION,
            "target_contract_id": TARGET_CONTRACT_ID,
            "example_id": item["example_id"],
            "session_id": item["session_id"],
            "model_id": model["model_id"],
            "model_family": family,
            "status": "abstained",
            "reason": "unsupported_context",
            "used_context_lengths": [],
            "context_weights": {},
            "requested_context_length": maximum,
            "backoff_steps": None,
            "zero_order_used": False,
            "predicted_terminal": None,
            "predicted_tactics": [],
            "terminal_score": None,
            "tactic_scores": {},
            "ranked_tactics": [],
            "outcome_state_scores": [],
        }

    if family in {"hard_backoff_vomm", "first_order_phase_state_markov"}:
        order, counts = supported[0]
        return _prediction_from_distribution(
            item,
            model,
            _distribution(counts),
            used_context_lengths=[order],
            context_weights={order: 1.0},
        )

    decay = float(model["interpolation_decay"])
    raw_weights = {
        order: decay ** (maximum - order)
        for order, _counts in supported
    }
    weight_total = sum(raw_weights.values())
    weights = {order: value / weight_total for order, value in raw_weights.items()}
    combined: Dict[PhaseState | None, float] = defaultdict(float)
    for order, counts in supported:
        for state, probability in _distribution(counts).items():
            combined[state] += weights[order] * probability
    return _prediction_from_distribution(
        item,
        model,
        combined,
        used_context_lengths=[order for order, _counts in supported],
        context_weights=weights,
    )


def predict_many(
    artifact: Mapping[str, Any],
    examples: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Predict corrected examples in caller order while retaining their IDs."""

    return [predict_baseline(artifact, example) for example in examples]


def fit_corrected_target_baselines(
    examples: Sequence[Mapping[str, Any]],
    *,
    maximum_order: int = 8,
    interpolation_decay: float = 0.5,
    include_zero_order: bool = False,
) -> Dict[str, Dict[str, Any]]:
    """Fit the complete declared baseline set on identical examples."""

    return {
        "majority_terminal_prevalence": fit_majority_terminal_prevalence(examples),
        "first_order_phase_state_markov": fit_first_order_phase_state_markov(
            examples, include_zero_order=include_zero_order
        ),
        "hard_backoff_vomm": fit_hard_backoff_vomm(
            examples,
            maximum_order=maximum_order,
            include_zero_order=include_zero_order,
        ),
        "interpolated_vomm": fit_interpolated_vomm(
            examples,
            maximum_order=maximum_order,
            interpolation_decay=interpolation_decay,
            include_zero_order=include_zero_order,
        ),
    }


# Short aliases keep experiment scripts readable without changing semantics.
fit_majority_baseline = fit_majority_terminal_prevalence
fit_first_order_markov = fit_first_order_phase_state_markov
fit_all_baselines = fit_corrected_target_baselines
predict = predict_baseline
predict_baseline_many = predict_many
