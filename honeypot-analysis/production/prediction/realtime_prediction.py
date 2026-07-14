"""Config-driven real-time next-step prediction.

The engine is deliberately in-process for the pilot. Scorers are pure functions
over session features, which makes them easy to test and replay later.

Methodologically, the default tactic ranking path uses a transition-frequency /
Markov-style tactic transition model first and falls back to a simple progression
prior only when transition evidence is unavailable or too sparse. The older
weighted evidence-fusion model is retained as a comparison baseline. Risk
annotations, such as CVE/KEV/EPSS context, are computed separately because they
describe exposure or impact rather than the attacker's temporal next action.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Protocol

from production.classification.trust import is_trusted_classification_event
from production.utils.serialization import stable_id, utc_now
from production.correlation.session_ttp_knowledge import main_ttp_id
from production.correlation.campaign_clustering import build_session_fingerprint
from production.prediction.behavior_regime import classify_behavior_regime


TACTIC_PROGRESSION: Dict[str, List[str]] = {
    "initial-access": ["execution", "discovery", "persistence"],
    "execution": ["discovery", "credential-access", "collection"],
    "discovery": ["credential-access", "lateral-movement", "collection"],
    "credential-access": ["persistence", "lateral-movement", "exfiltration"],
    "persistence": ["defense-evasion", "command-and-control", "collection"],
    "privilege-escalation": ["defense-evasion", "credential-access", "persistence"],
    "defense-evasion": ["collection", "command-and-control", "exfiltration"],
    "lateral-movement": ["collection", "command-and-control", "exfiltration"],
    "collection": ["exfiltration", "command-and-control"],
    "command-and-control": ["exfiltration", "impact"],
    "exfiltration": ["impact"],
    "impact": [],
}


DEFAULT_TACTIC_COMBINATION_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "observed-discovery-credential-access",
        "enabled": True,
        "source_type": "heuristic_prior",
        "required_tactics": ["discovery", "credential-access"],
        "evidence_sources": [
            "MITRE ATT&CK tactic semantics",
            "MITRE CTID Technique Inference Engine supports associated-technique inference, not strict temporal ordering",
        ],
        "references": [
            "https://attack.mitre.org/",
            "https://github.com/center-for-threat-informed-defense/technique-inference-engine",
        ],
        "confidence_policy": "low-to-medium unless reinforced by local transition evidence",
        "hypotheses": [
            {
                "tactic": "command-and-control",
                "score": 0.45,
                "reason": "discovery plus credential access can precede payload staging or callback setup",
            },
            {
                "tactic": "persistence",
                "score": 0.30,
                "reason": "credential interest after discovery can lead to account or key persistence",
            },
        ],
    },
    {
        "rule_id": "observed-c2-execution",
        "evidence_key": "download-execution-chain",
        "enabled": True,
        "source_type": "heuristic_prior",
        "required_tactics": ["command-and-control", "execution"],
        "evidence_sources": [
            "MITRE ATT&CK tactic semantics",
            "common post-download execution tradecraft observed in honeypot command sessions",
        ],
        "references": [
            "https://attack.mitre.org/tactics/TA0011/",
            "https://attack.mitre.org/tactics/TA0002/",
        ],
        "confidence_policy": "low-to-medium unless reinforced by local transition evidence",
        "hypotheses": [
            {
                "tactic": "persistence",
                "score": 0.40,
                "reason": "command-and-control plus execution can indicate staging before persistence",
            },
            {
                "tactic": "defense-evasion",
                "score": 0.35,
                "reason": "execution after download commonly pairs with cleanup or hiding activity",
            },
        ],
    },
    {
        "rule_id": "observed-defense-evasion",
        "enabled": True,
        "source_type": "heuristic_prior",
        "required_flags": ["has_defense_evasion"],
        "evidence_sources": [
            "MITRE ATT&CK tactic semantics",
            "local operator heuristic for later-stage session triage",
        ],
        "references": ["https://attack.mitre.org/tactics/TA0005/"],
        "confidence_policy": "low unless reinforced by local transition evidence",
        "hypotheses": [
            {
                "tactic": "exfiltration",
                "score": 0.25,
                "reason": "defense evasion is present; later stages may include collection or exfiltration",
            }
        ],
    },
    {
        "rule_id": "downloader-without-execution",
        "enabled": True,
        "source_type": "heuristic_prior",
        "required_flags": ["has_downloader"],
        "absent_flags": ["has_execution"],
        "evidence_sources": [
            "MITRE ATT&CK tactic semantics",
            "common honeypot command ordering where download is followed by chmod/bash/sh execution",
        ],
        "references": [
            "https://attack.mitre.org/techniques/T1105/",
            "https://attack.mitre.org/tactics/TA0002/",
        ],
        "confidence_policy": "low-to-medium unless reinforced by the current session or local transitions",
        "hypotheses": [
            {
                "tactic": "execution",
                "score": 0.35,
                "reason": "download behavior was observed without a confirmed execution step",
            }
        ],
    },
]


DEFAULT_PREDICTION_POLICY: Dict[str, Any] = {
    "enabled": True,
    "prediction_mode": "primary_transition_with_fallback",
    "compute_weighted_ensemble_baseline": True,
    "primary_transition": {
        "primary_model": "transition_frequency",
        "source_order": ["local_transition", "external_seed_transition"],
        "fallback_scorer": "fallback_progression",
        "min_transition_score": 0.01,
    },
    "max_hypotheses": 5,
    "min_score": 0.01,
    "min_sessions_for_local": 50,
    "min_transition_count": 2,
    "transition_history_limit": 500,
    "external_transition_model_path": "",
    "external_min_sessions": 50,
    "external_min_transition_count": 2,
    "prefix_max_length": 3,
    "transition_smoothing": 0.05,
    "technique_to_tactic_aggregation": "max",
    "recency_decay_half_life_sessions": 0,
    "min_prefix_transition_count": 2,
    "min_technique_transition_count": 2,
    "min_tactic_transition_count": 2,
    "min_active_scorers": 1,
    "below_minimum_behavior": "low_confidence_flag",
    "confidence_damping": {
        "enabled": True,
        "mode": "geometric_mean",
        "damped_scorers": [
            "local_transition",
            "external_seed_transition",
            "actor_fingerprint_transition",
            "fallback_progression",
            "tactic_combination",
            "mitre_association",
        ],
    },
    "weights": {
        "local_transition": 0.30,
        "external_seed_transition": 0.20,
        "actor_fingerprint_transition": 0.0,
        "fallback_progression": 0.10,
        "tactic_combination": 0.12,
        "mitre_association": 0.13,
        "sigma_correlation": 0.05,
        "enrichment_context": 0.10,
    },
    "enrichment_context_mode": "scorer",
    "enrichment_context_multiplier": {
        "max_multiplier": 1.15,
        "min_enrichment_score": 0.01,
    },
    "external_seed_weight_decay": {
        "enabled": True,
        "method": "maturity_multiplier",
        "cold": 1.0,
        "warming": 0.5,
        "stable": 0.2,
        "shrinkage_count_source": "transitions",
        "shrinkage_k": 200.0,
        "min_multiplier": 0.0,
        "max_multiplier": 1.0,
    },
    "actor_fingerprint_prior": {
        "enabled": False,
        "match_fields": ["hassh_fingerprint", "ja3_fingerprint", "command_pattern_hash"],
        "min_sessions": 2,
        "min_transition_count": 1,
        "min_prefix_transition_count": 1,
        "min_tactic_transition_count": 1,
        "prefix_max_length": 3,
        "smoothing": 0.05,
        "history_limit": 500,
        "model_path": "",
        "comparison_weight": 0.15,
    },
    "behavior_regime_classifier": {
        "enabled": True,
        "min_commands": 2,
        "automated_command_rate_per_minute": 8.0,
        "human_command_rate_per_minute": 1.5,
        "low_delay_variance_seconds2": 4.0,
        "high_delay_variance_seconds2": 900.0,
        "high_entropy_bits_per_char": 4.2,
        "low_entropy_bits_per_char": 2.5,
        "low_payload_diversity": 0.40,
        "high_payload_diversity": 0.80,
        "automated_threshold": 0.65,
        "human_threshold": 0.35,
        "feature_weights": {
            "command_frequency": 0.35,
            "delay_regularity": 0.25,
            "command_entropy": 0.20,
            "payload_repetition": 0.20,
        },
    },
    "confidence_controls": {
        "enabled": True,
        "single_active_scorer_cap": "medium",
        "single_supporting_scorer_cap": "medium",
        "external_seed_only_cap": "low",
        "external_seed_dominated_cap": "medium",
        "context_only_cap": "low",
        "medium_divergence_ratio": 0.50,
        "medium_divergence_cap": "medium",
        "high_divergence_ratio": 0.75,
        "high_divergence_cap": "low",
        "low_classification_geomean": 0.65,
        "unknown_or_noise_ratio": 0.40,
        "low_classification_cap": "low",
    },
    "fallback_progression": TACTIC_PROGRESSION,
    "tactic_combination_rules": DEFAULT_TACTIC_COMBINATION_RULES,
    "mitre_association_rules": [],
    "sigma_correlation_rules": [],
    "rule_prior_deduplication": {
        "enabled": True,
        "method": "max_contribution",
        "scorers": ["tactic_combination", "mitre_association"],
        "require_shared_evidence_key": True,
    },
    "vulnerability_risk": {
        "enabled": True,
        "default_tactic": "impact",
        "high_epss_threshold": 0.70,
        "medium_epss_threshold": 0.30,
        "epss_scores": {},
    },
    "risk_annotators": {
        "vulnerability_risk": {
            "enabled": True,
        },
    },
    "calibration": {
        "enabled": False,
        "min_cases_per_bin": 20,
        "bins": [],
    },
    "maturity": {
        "cold": {
            "max_usable_sessions": 49,
            "max_transition_count": 49,
        },
        "warming": {
            "min_usable_sessions": 50,
            "min_transition_count": 50,
            "max_usable_sessions": 199,
            "max_transition_count": 299,
        },
        "stable": {
            "min_usable_sessions": 200,
            "min_transition_count": 300,
        },
        "cold_confidence_cap": "low",
        "warming_confidence_cap": "",
    },
}


@dataclass
class Hypothesis:
    tactic: str
    score: float
    reasons: List[str]
    source: str
    source_type: str
    technique: str = ""
    rule_id: str = ""
    evidence_sources: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    depends_on_classification: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "tactic": self.tactic,
            "score": round(float(self.score), 4),
            "reasons": list(self.reasons),
            "source": self.source,
            "source_type": self.source_type,
            "depends_on_classification": bool(self.depends_on_classification),
        }
        if self.technique:
            payload["technique"] = self.technique
        if self.rule_id:
            payload["rule_id"] = self.rule_id
        if self.evidence_sources:
            payload["evidence_sources"] = list(self.evidence_sources)
        if self.references:
            payload["references"] = list(self.references)
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


class Scorer(Protocol):
    name: str
    version: str

    def score(self, features: Dict[str, Any]) -> List[Hypothesis]:
        ...


def _unique(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _merge_policy(base: Dict[str, Any], overrides: Dict[str, Any] | None) -> Dict[str, Any]:
    merged = deepcopy(base)
    if not overrides:
        return merged
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            nested = dict(merged[key])
            nested.update(value)
            merged[key] = nested
        else:
            merged[key] = value
    return merged


def _rule_matches(rule: Dict[str, Any], tactics: set[str], flags: Dict[str, Any]) -> bool:
    if not bool(rule.get("enabled", True)):
        return False
    required_tactics = {
        str(tactic or "").strip()
        for tactic in rule.get("required_tactics") or []
        if str(tactic or "").strip()
    }
    if required_tactics and not required_tactics.issubset(tactics):
        return False
    required_flags = [
        str(flag or "").strip()
        for flag in rule.get("required_flags") or []
        if str(flag or "").strip()
    ]
    if any(not bool(flags.get(flag)) for flag in required_flags):
        return False
    absent_flags = [
        str(flag or "").strip()
        for flag in rule.get("absent_flags") or []
        if str(flag or "").strip()
    ]
    if any(bool(flags.get(flag)) for flag in absent_flags):
        return False
    return True


def _contains_any(values: Iterable[Any], needles: Iterable[Any]) -> bool:
    haystack = [str(value or "").lower() for value in values]
    for needle in needles:
        text = str(needle or "").lower().strip()
        if text and any(text in value for value in haystack):
            return True
    return False


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _technique_tactic_rows(technique_scores: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    rows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for key, payload in (technique_scores or {}).items():
        if isinstance(payload, dict):
            tactic = str(payload.get("tactic") or "").strip()
            technique = str(payload.get("technique") or key or "").strip()
            score = _safe_float(payload.get("score"), 0.0)
            row = dict(payload)
        else:
            tactic = ""
            technique = str(key or "").strip()
            score = _safe_float(payload, 0.0)
            row = {"score": score}
        if not tactic or score < 0.0:
            continue
        row["technique"] = technique
        row["score"] = score
        rows[tactic].append(row)
    return rows


def aggregate_technique_to_tactic(technique_scores: Dict[str, Any], method: str = "max") -> Dict[str, float]:
    """Aggregate ATT&CK technique-level scores into tactic-level scores.

    The prediction target is the next tactic, while some rules emit technique
    scores first. This helper makes the label-hierarchy aggregation rule
    explicit. The default `max` method avoids giving a tactic a higher score
    merely because it has more mapped techniques.
    """

    mode = str(method or "max").strip().lower()
    if mode not in {"max", "sum", "mean"}:
        mode = "max"
    aggregated: Dict[str, float] = {}
    for tactic, rows in _technique_tactic_rows(technique_scores).items():
        values = [_safe_float(row.get("score"), 0.0) for row in rows]
        if not values:
            continue
        if mode == "sum":
            score = sum(values)
        elif mode == "mean":
            score = sum(values) / len(values)
        else:
            score = max(values)
        aggregated[tactic] = round(score, 6)
    return aggregated


def _technique_tactic_metadata(rows: List[Dict[str, Any]], method: str) -> Dict[str, Any]:
    techniques = [str(row.get("technique") or "") for row in rows if str(row.get("technique") or "")]
    return {
        "technique_to_tactic_aggregation": {
            "method": str(method or "max"),
            "input_count": len(rows),
            "input_techniques": techniques,
            "input_scores": {
                str(row.get("technique") or index): round(_safe_float(row.get("score"), 0.0), 4)
                for index, row in enumerate(rows)
            },
        }
    }


def _mapped_tactic_from_value(value: Any) -> str:
    if isinstance(value, dict):
        if not value:
            return ""
        tactic, _score = max(value.items(), key=lambda item: _safe_float(item[1], 0.0))
        return str(tactic or "").strip()
    if isinstance(value, (list, tuple, set)):
        for item in value:
            text = str(item or "").strip()
            if text:
                return text
        return ""
    return str(value or "").strip()


def _mapped_tactic_for_technique(
    technique: str,
    item: Dict[str, Any],
    rule: Dict[str, Any],
    policy_map: Dict[str, Any],
) -> str:
    tactic = str(item.get("tactic") or "").strip()
    if tactic:
        return tactic
    technique_id = main_ttp_id(technique) or technique
    for mapping in (
        item.get("technique_tactic_map"),
        item.get("technique_tactics"),
        rule.get("technique_tactic_map"),
        rule.get("technique_tactics"),
        policy_map,
    ):
        if not isinstance(mapping, dict):
            continue
        value = mapping.get(technique) or mapping.get(technique_id)
        tactic = _mapped_tactic_from_value(value)
        if tactic:
            return tactic
    return ""


def _format_count(value: float) -> str:
    number = _safe_float(value)
    if abs(number - round(number)) < 0.0001:
        return str(int(round(number)))
    return f"{number:.2f}".rstrip("0").rstrip(".")


def _support_level(count: float, total: float, min_support: float) -> str:
    """Human-friendly transition support label for analyst display."""
    if total <= 0 or count <= 0:
        return "none"
    if count >= 100 or total >= 500:
        return "high"
    if count >= 20 or total >= 100:
        return "medium"
    if count >= max(min_support, 1):
        return "low"
    return "below_minimum"


def tactic_sequence_from_payload(payload: Dict[str, Any]) -> List[str]:
    """Extract ordered observed tactics from a stored session payload."""
    sequence: List[str] = []
    classification_events = [
        event for event in payload.get("classification_events") or []
        if isinstance(event, dict)
    ]
    for event in classification_events:
        if not is_trusted_classification_event(event):
            continue
        tactic = str(event.get("tactic") or "").strip()
        if tactic and tactic != "unknown":
            sequence.append(tactic)
    if not sequence and not classification_events:
        sequence = [
            str(tactic).strip()
            for tactic in payload.get("tactics") or []
            if str(tactic or "").strip() and str(tactic or "").strip() != "unknown"
        ]

    compressed: List[str] = []
    for tactic in sequence:
        if not compressed or compressed[-1] != tactic:
            compressed.append(tactic)
    return compressed


def technique_sequence_from_payload(payload: Dict[str, Any]) -> List[str]:
    """Extract ordered observed ATT&CK techniques from a stored session payload."""
    sequence: List[str] = []
    classification_events = [
        event for event in payload.get("classification_events") or []
        if isinstance(event, dict)
    ]
    for event in classification_events:
        if not is_trusted_classification_event(event):
            continue
        technique = main_ttp_id(event.get("ttp") or event.get("technique"))
        if technique and technique != "unknown":
            sequence.append(technique)
    if not sequence and not classification_events:
        sequence = [
            main_ttp_id(technique)
            for technique in payload.get("ttps") or []
            if str(technique or "").strip() and str(technique or "").strip() != "unknown"
        ]

    compressed: List[str] = []
    for technique in sequence:
        if not compressed or compressed[-1] != technique:
            compressed.append(technique)
    return compressed


def _technique_tactic_counts(payload: Dict[str, Any]) -> Dict[str, Counter]:
    counts: Dict[str, Counter] = defaultdict(Counter)
    for event in payload.get("classification_events") or []:
        if not isinstance(event, dict) or not is_trusted_classification_event(event):
            continue
        technique = main_ttp_id(event.get("ttp") or event.get("technique"))
        tactic = str(event.get("tactic") or "").strip()
        if technique and technique != "unknown" and tactic and tactic != "unknown":
            counts[technique][tactic] += 1
    return counts


def build_transition_model(
    session_payloads: Iterable[Dict[str, Any]],
    prefix_max_length: int | None = None,
    source_name: str = "local_transition",
    source_database: str = "",
    recency_half_life_sessions: float = 0.0,
) -> Dict[str, Any]:
    """Build local transition counts from completed stored sessions."""
    max_prefix_length = max(int(prefix_max_length or DEFAULT_PREDICTION_POLICY["prefix_max_length"]), 1)
    payload_list = [payload for payload in session_payloads if isinstance(payload, dict)]
    half_life = max(float(recency_half_life_sessions or 0.0), 0.0)
    transitions: Dict[str, Counter] = defaultdict(Counter)
    prefix_transitions: Dict[str, Counter] = defaultdict(Counter)
    technique_transitions: Dict[str, Counter] = defaultdict(Counter)
    technique_tactics: Dict[str, Counter] = defaultdict(Counter)
    start_counts: Counter = Counter()
    usable_sessions = 0
    completed_sessions = 0
    classification_event_count = 0
    trusted_classification_event_count = 0
    audit_only_classification_event_count = 0

    for payload_index, payload in enumerate(payload_list):
        if not payload.get("is_ended") and str(payload.get("status") or "") != "closed":
            continue
        payload_classifications = [
            event for event in payload.get("classification_events") or []
            if isinstance(event, dict)
        ]
        trusted_count = sum(
            1 for event in payload_classifications
            if is_trusted_classification_event(event)
        )
        classification_event_count += len(payload_classifications)
        trusted_classification_event_count += trusted_count
        audit_only_classification_event_count += len(payload_classifications) - trusted_count
        weight = 1.0
        if half_life > 0:
            weight = 0.5 ** (payload_index / half_life)
        completed_sessions += 1
        sequence = tactic_sequence_from_payload(payload)
        if sequence:
            usable_sessions += 1
            start_counts[sequence[0]] += weight
        for current_tactic, next_tactic in zip(sequence, sequence[1:]):
            transitions[current_tactic][next_tactic] += weight
        for index in range(1, len(sequence)):
            next_tactic = sequence[index]
            start = max(0, index - max_prefix_length)
            for prefix_start in range(start, index):
                prefix = sequence[prefix_start:index]
                if len(prefix) >= 2:
                    prefix_transitions[">".join(prefix)][next_tactic] += weight

        technique_sequence = technique_sequence_from_payload(payload)
        for current_technique, next_technique in zip(technique_sequence, technique_sequence[1:]):
            technique_transitions[current_technique][next_technique] += weight
        for technique, tactic_counts in _technique_tactic_counts(payload).items():
            technique_tactics[technique].update(tactic_counts)

    serializable_transitions = {
        tactic: dict(counter)
        for tactic, counter in sorted(transitions.items())
    }
    serializable_prefix_transitions = {
        prefix: dict(counter)
        for prefix, counter in sorted(prefix_transitions.items())
    }
    serializable_technique_transitions = {
        technique: dict(counter)
        for technique, counter in sorted(technique_transitions.items())
    }
    serializable_technique_tactics = {
        technique: counter.most_common(1)[0][0]
        for technique, counter in sorted(technique_tactics.items())
        if counter
    }
    transition_count = sum(sum(counter.values()) for counter in transitions.values())
    prefix_transition_count = sum(sum(counter.values()) for counter in prefix_transitions.values())
    technique_transition_count = sum(sum(counter.values()) for counter in technique_transitions.values())
    built_at = utc_now()
    return {
        "schema_version": "local_transition_model.v2",
        "source_name": source_name,
        "source_database": source_database,
        "built_at": built_at,
        "recency_decay_half_life_sessions": half_life,
        "completed_sessions": completed_sessions,
        "usable_sessions": usable_sessions,
        "classification_event_count": classification_event_count,
        "trusted_classification_event_count": trusted_classification_event_count,
        "audit_only_classification_event_count": audit_only_classification_event_count,
        "transition_count": transition_count,
        "prefix_transition_count": prefix_transition_count,
        "technique_transition_count": technique_transition_count,
        "prefix_max_length": max_prefix_length,
        "transitions": serializable_transitions,
        "prefix_transitions": serializable_prefix_transitions,
        "technique_transitions": serializable_technique_transitions,
        "technique_tactics": serializable_technique_tactics,
        "start_counts": dict(start_counts),
        "model_id": stable_id(
            "transitionmodel",
            {
                "completed_sessions": completed_sessions,
                "usable_sessions": usable_sessions,
                "trusted_classification_event_count": trusted_classification_event_count,
                "audit_only_classification_event_count": audit_only_classification_event_count,
                "transition_count": transition_count,
                "prefix_transition_count": prefix_transition_count,
                "technique_transition_count": technique_transition_count,
                "prefix_max_length": max_prefix_length,
                "source_name": source_name,
                "source_database": source_database,
                "recency_decay_half_life_sessions": half_life,
                "transitions": serializable_transitions,
                "prefix_transitions": serializable_prefix_transitions,
                "technique_transitions": serializable_technique_transitions,
            },
        ),
    }


DEFAULT_ACTOR_FINGERPRINT_MATCH_FIELDS = [
    "hassh_fingerprint",
    "ja3_fingerprint",
    "command_pattern_hash",
]


def _actor_fingerprint_policy(policy: Dict[str, Any] | None) -> Dict[str, Any]:
    raw = (policy or {}).get("actor_fingerprint_prior") if isinstance(policy, dict) else {}
    if not isinstance(raw, dict):
        raw = {}
    fields = [
        str(item or "").strip()
        for item in raw.get("match_fields") or DEFAULT_ACTOR_FINGERPRINT_MATCH_FIELDS
        if str(item or "").strip()
    ]
    if not fields:
        fields = list(DEFAULT_ACTOR_FINGERPRINT_MATCH_FIELDS)
    return {
        "enabled": bool(raw.get("enabled", False)),
        "match_fields": fields,
        "min_sessions": max(int(raw.get("min_sessions", 2) or 0), 0),
        "min_transition_count": max(float(raw.get("min_transition_count", 1) or 0.0), 0.0),
        "min_prefix_transition_count": max(float(raw.get("min_prefix_transition_count", raw.get("min_transition_count", 1)) or 0.0), 0.0),
        "min_tactic_transition_count": max(float(raw.get("min_tactic_transition_count", raw.get("min_transition_count", 1)) or 0.0), 0.0),
        "prefix_max_length": max(int(raw.get("prefix_max_length", (policy or {}).get("prefix_max_length", 3)) or 1), 1),
        "smoothing": max(float(raw.get("smoothing", (policy or {}).get("transition_smoothing", 0.05)) or 0.0), 0.0),
        "history_limit": max(int(raw.get("history_limit", (policy or {}).get("transition_history_limit", 500)) or 1), 1),
        "model_path": str(raw.get("model_path") or (policy or {}).get("actor_fingerprint_model_path") or "").strip(),
        "comparison_weight": max(float(raw.get("comparison_weight", 0.15) or 0.0), 0.0),
    }


def _fingerprint_field_value(fingerprint: Dict[str, Any], field: str) -> str:
    key = str(field or "").strip()
    if key == "source_ip":
        key = "src_ip"
    value = str((fingerprint or {}).get(key) or "").strip()
    if value.lower() == "unknown":
        return ""
    return value


def _fingerprint_model_key(field: str, value: str) -> str:
    return f"{field}:{value}"


def _fingerprint_keys(fingerprint: Dict[str, Any], fields: Iterable[str]) -> List[Dict[str, str]]:
    keys: List[Dict[str, str]] = []
    for field in fields:
        field_name = str(field or "").strip()
        value = _fingerprint_field_value(fingerprint, field_name)
        if not field_name or not value:
            continue
        keys.append(
            {
                "field": field_name,
                "value": value,
                "key": _fingerprint_model_key(field_name, value),
            }
        )
    return keys


def _empty_actor_fingerprint_transition_model(
    match_fields: List[str] | None = None,
    source_database: str = "",
) -> Dict[str, Any]:
    fields = list(match_fields or DEFAULT_ACTOR_FINGERPRINT_MATCH_FIELDS)
    built_at = utc_now()
    return {
        "schema_version": "actor_fingerprint_transition_model.v1",
        "source_name": "actor_fingerprint_transition",
        "source_type": "empirical_actor_fingerprint",
        "source_database": source_database,
        "built_at": built_at,
        "completed_sessions": 0,
        "usable_sessions": 0,
        "fingerprint_count": 0,
        "transition_count": 0,
        "prefix_transition_count": 0,
        "prefix_max_length": DEFAULT_PREDICTION_POLICY["prefix_max_length"],
        "match_fields": fields,
        "fingerprints": {},
        "provenance": {
            "method": "local_fingerprint_conditioned_transition_counts",
            "basis": "completed local sessions sharing HASSH, JA3, or command-pattern fingerprints",
            "named_actor_attribution": False,
        },
        "model_id": stable_id("actorfpmodel", {"built_at": built_at, "match_fields": fields, "fingerprints": {}}),
    }


def build_actor_fingerprint_transition_model(
    session_payloads: Iterable[Dict[str, Any]],
    policy: Dict[str, Any] | None = None,
    prefix_max_length: int | None = None,
    source_database: str = "",
    recency_half_life_sessions: float = 0.0,
) -> Dict[str, Any]:
    """Build a local transition model conditioned on durable session fingerprints.

    This is actor/tool fingerprint conditioning, not named-actor attribution.
    It reuses Cowrie-provided HASSH/JA3 values and locally derived command
    pattern hashes; it does not implement or infer the HASSH/JA3 algorithms.
    """

    config = _actor_fingerprint_policy(policy or {})
    match_fields = list(config["match_fields"])
    max_prefix_length = max(int(prefix_max_length or config["prefix_max_length"]), 1)
    half_life = max(float(recency_half_life_sessions or 0.0), 0.0)
    payload_list = [payload for payload in session_payloads if isinstance(payload, dict)]
    if not payload_list:
        model = _empty_actor_fingerprint_transition_model(match_fields, source_database)
        model["prefix_max_length"] = max_prefix_length
        model["recency_decay_half_life_sessions"] = half_life
        return model

    buckets: Dict[str, Dict[str, Any]] = {}
    completed_sessions = 0
    usable_sessions = 0

    for payload_index, payload in enumerate(payload_list):
        if not payload.get("is_ended") and str(payload.get("status") or "") != "closed":
            continue
        completed_sessions += 1
        sequence = tactic_sequence_from_payload(payload)
        if not sequence:
            continue
        fingerprint = build_session_fingerprint(payload)
        keys = _fingerprint_keys(fingerprint, match_fields)
        if not keys:
            continue
        usable_sessions += 1
        weight = 1.0
        if half_life > 0:
            weight = 0.5 ** (payload_index / half_life)
        session_id = str(payload.get("session_id") or "unknown")

        for key_info in keys:
            key = key_info["key"]
            bucket = buckets.setdefault(
                key,
                {
                    "fingerprint_type": key_info["field"],
                    "fingerprint_value": key_info["value"],
                    "session_count": 0,
                    "session_ids": [],
                    "start_counts": Counter(),
                    "transitions": defaultdict(Counter),
                    "prefix_transitions": defaultdict(Counter),
                },
            )
            bucket["session_count"] = int(bucket.get("session_count") or 0) + 1
            if session_id not in bucket["session_ids"] and len(bucket["session_ids"]) < 25:
                bucket["session_ids"].append(session_id)
            bucket["start_counts"][sequence[0]] += weight
            for current_tactic, next_tactic in zip(sequence, sequence[1:]):
                bucket["transitions"][current_tactic][next_tactic] += weight
            for index in range(1, len(sequence)):
                next_tactic = sequence[index]
                start = max(0, index - max_prefix_length)
                for prefix_start in range(start, index):
                    prefix = sequence[prefix_start:index]
                    if len(prefix) >= 2:
                        bucket["prefix_transitions"][">".join(prefix)][next_tactic] += weight

    serializable_fingerprints: Dict[str, Dict[str, Any]] = {}
    total_transition_count = 0.0
    total_prefix_transition_count = 0.0
    for key, bucket in sorted(buckets.items()):
        transitions = {
            tactic: dict(counter)
            for tactic, counter in sorted(bucket["transitions"].items())
        }
        prefix_transitions = {
            prefix: dict(counter)
            for prefix, counter in sorted(bucket["prefix_transitions"].items())
        }
        transition_count = sum(sum(_safe_float(value) for value in counter.values()) for counter in transitions.values())
        prefix_transition_count = sum(sum(_safe_float(value) for value in counter.values()) for counter in prefix_transitions.values())
        total_transition_count += transition_count
        total_prefix_transition_count += prefix_transition_count
        serializable_fingerprints[key] = {
            "fingerprint_type": bucket["fingerprint_type"],
            "fingerprint_value": bucket["fingerprint_value"],
            "session_count": int(bucket["session_count"]),
            "session_ids": list(bucket["session_ids"]),
            "start_counts": dict(bucket["start_counts"]),
            "transitions": transitions,
            "prefix_transitions": prefix_transitions,
            "transition_count": round(transition_count, 4),
            "prefix_transition_count": round(prefix_transition_count, 4),
        }

    built_at = utc_now()
    return {
        "schema_version": "actor_fingerprint_transition_model.v1",
        "source_name": "actor_fingerprint_transition",
        "source_type": "empirical_actor_fingerprint",
        "source_database": source_database,
        "built_at": built_at,
        "completed_sessions": completed_sessions,
        "usable_sessions": usable_sessions,
        "fingerprint_count": len(serializable_fingerprints),
        "transition_count": round(total_transition_count, 4),
        "prefix_transition_count": round(total_prefix_transition_count, 4),
        "prefix_max_length": max_prefix_length,
        "recency_decay_half_life_sessions": half_life,
        "match_fields": match_fields,
        "fingerprints": serializable_fingerprints,
        "provenance": {
            "method": "local_fingerprint_conditioned_transition_counts",
            "basis": "completed local sessions sharing HASSH, JA3, or command-pattern fingerprints",
            "named_actor_attribution": False,
        },
        "model_id": stable_id(
            "actorfpmodel",
            {
                "completed_sessions": completed_sessions,
                "usable_sessions": usable_sessions,
                "fingerprint_count": len(serializable_fingerprints),
                "transition_count": round(total_transition_count, 4),
                "prefix_transition_count": round(total_prefix_transition_count, 4),
                "prefix_max_length": max_prefix_length,
                "match_fields": match_fields,
                "fingerprints": serializable_fingerprints,
            },
        ),
    }


class LocalTransitionScorer:
    name = "local_transition"
    version = "1.0"

    def __init__(
        self,
        transition_model: Dict[str, Any] | None = None,
        min_sessions: int = 50,
        min_transition_count: int = 2,
        min_prefix_transition_count: int | None = None,
        min_technique_transition_count: int | None = None,
        min_tactic_transition_count: int | None = None,
        prefix_max_length: int = 3,
        smoothing: float = 0.05,
        name: str = "local_transition",
        source_type: str = "empirical_local",
        evidence_sources: List[str] | None = None,
        reason_prefix: str = "local history observed",
        training_source: str = "sessions.payload_json.classification_events",
        provenance: Dict[str, Any] | None = None,
    ) -> None:
        self.name = name
        self.transition_model = transition_model or build_transition_model([])
        self.min_sessions = max(int(min_sessions), 0)
        self.min_transition_count = max(float(min_transition_count), 0.0)
        self.min_prefix_transition_count = max(float(min_prefix_transition_count if min_prefix_transition_count is not None else min_transition_count), 0.0)
        self.min_technique_transition_count = max(float(min_technique_transition_count if min_technique_transition_count is not None else min_transition_count), 0.0)
        self.min_tactic_transition_count = max(float(min_tactic_transition_count if min_tactic_transition_count is not None else min_transition_count), 0.0)
        self.prefix_max_length = max(int(prefix_max_length), 1)
        self.smoothing = max(float(smoothing), 0.0)
        self.source_type = source_type
        self.evidence_sources = evidence_sources or ["completed local honeypot sessions"]
        self.reason_prefix = reason_prefix
        self.training_source = training_source
        self.provenance = provenance or {}

    def _counts_to_hypotheses(
        self,
        counts: Dict[str, Any],
        total: float,
        context: str,
        transition_type: str,
        min_support: float,
        technique_targets: bool = False,
    ) -> List[Hypothesis]:
        if total < min_support:
            return []
        denominator = total + (self.smoothing * max(len(counts), 1))
        technique_tactics = self.transition_model.get("technique_tactics") or {}
        usable_sessions = int(self.transition_model.get("usable_sessions") or 0)
        hypotheses: List[Hypothesis] = []
        for target, count_value in sorted(counts.items(), key=lambda item: _safe_float(item[1]), reverse=True):
            count = _safe_float(count_value)
            probability = (count + self.smoothing) / denominator if denominator else 0.0
            support_level = _support_level(count, total, min_support)
            tactic = str(target)
            technique = ""
            if technique_targets:
                technique = str(target)
                tactic = str(technique_tactics.get(technique) or "")
                if not tactic:
                    continue
            hypotheses.append(
                Hypothesis(
                    tactic=tactic,
                    technique=technique,
                    score=probability,
                    source=self.name,
                    source_type=self.source_type,
                    depends_on_classification=True,
                    reasons=[
                        (
                            f"{self.reason_prefix} {_format_count(count)}/{_format_count(total)} "
                            f"completed transitions ({transition_type}) from {context} to {target}; "
                            f"support={support_level}"
                        )
                    ],
                    evidence_sources=list(self.evidence_sources),
                    metadata={
                        "model_id": self.transition_model.get("model_id", ""),
                        "usable_sessions": usable_sessions,
                        "transition_count": round(total, 4),
                        "transition_support": round(count, 4),
                        "transition_probability": round(probability, 4),
                        "transition_support_level": support_level,
                        "transition_total": round(total, 4),
                        "support_share": round(count / total, 4) if total else 0.0,
                        "min_support": min_support,
                        "transition_type": transition_type,
                        "transition_context": context,
                        "training_source": self.training_source,
                        "provenance": dict(self.provenance),
                        "temporal_claim": True,
                    },
                )
            )
        return hypotheses

    def score(self, features: Dict[str, Any]) -> List[Hypothesis]:
        usable_sessions = int(self.transition_model.get("usable_sessions") or 0)
        if usable_sessions < self.min_sessions:
            return []

        tactic_sequence = [
            str(tactic or "").strip()
            for tactic in features.get("tactic_sequence") or []
            if str(tactic or "").strip()
        ]
        prefix_transitions = self.transition_model.get("prefix_transitions") or {}
        max_prefix = min(self.prefix_max_length, len(tactic_sequence))
        for prefix_length in range(max_prefix, 1, -1):
            prefix = ">".join(tactic_sequence[-prefix_length:])
            counts = prefix_transitions.get(prefix) or {}
            total = sum(_safe_float(count) for count in counts.values())
            hypotheses = self._counts_to_hypotheses(
                counts,
                total,
                context=prefix,
                transition_type="prefix",
                min_support=self.min_prefix_transition_count,
            )
            if hypotheses:
                return hypotheses

        last_ttp = main_ttp_id(features.get("last_ttp"))
        if last_ttp:
            technique_transitions = self.transition_model.get("technique_transitions") or {}
            counts = technique_transitions.get(last_ttp) or {}
            total = sum(_safe_float(count) for count in counts.values())
            hypotheses = self._counts_to_hypotheses(
                counts,
                total,
                context=last_ttp,
                transition_type="technique",
                min_support=self.min_technique_transition_count,
                technique_targets=True,
            )
            if hypotheses:
                return hypotheses

        last_tactic = str(features.get("last_tactic") or "").strip()
        if not last_tactic:
            return []
        transitions = self.transition_model.get("transitions") or {}
        counts = transitions.get(last_tactic) or {}
        total = sum(_safe_float(count) for count in counts.values())
        return self._counts_to_hypotheses(
            counts,
            total,
            context=last_tactic,
            transition_type="tactic",
            min_support=self.min_tactic_transition_count,
        )


class ActorFingerprintTransitionScorer:
    name = "actor_fingerprint_transition"
    version = "1.0"

    def __init__(
        self,
        transition_model: Dict[str, Any] | None = None,
        policy: Dict[str, Any] | None = None,
    ) -> None:
        config = _actor_fingerprint_policy(policy or {})
        self.enabled = bool(config["enabled"])
        self.transition_model = transition_model or build_actor_fingerprint_transition_model([], policy)
        self.match_fields = list(config["match_fields"] or self.transition_model.get("match_fields") or DEFAULT_ACTOR_FINGERPRINT_MATCH_FIELDS)
        self.min_sessions = int(config["min_sessions"])
        self.min_transition_count = float(config["min_transition_count"])
        self.min_prefix_transition_count = float(config["min_prefix_transition_count"])
        self.min_tactic_transition_count = float(config["min_tactic_transition_count"])
        self.prefix_max_length = int(config["prefix_max_length"])
        self.smoothing = float(config["smoothing"])

    def _matching_fingerprint(self, features: Dict[str, Any]) -> Dict[str, Any]:
        fingerprint = features.get("session_fingerprint") or {}
        if not isinstance(fingerprint, dict):
            return {}
        fingerprints = self.transition_model.get("fingerprints") or {}
        if not isinstance(fingerprints, dict):
            return {}
        for key_info in _fingerprint_keys(fingerprint, self.match_fields):
            entry = fingerprints.get(key_info["key"]) or {}
            if not isinstance(entry, dict):
                continue
            if int(entry.get("session_count") or 0) < self.min_sessions:
                continue
            return {
                "key": key_info["key"],
                "field": key_info["field"],
                "value": key_info["value"],
                "entry": entry,
            }
        return {}

    def _counts_to_hypotheses(
        self,
        counts: Dict[str, Any],
        total: float,
        context: str,
        transition_type: str,
        min_support: float,
        match: Dict[str, Any],
        depends_on_classification: bool,
    ) -> List[Hypothesis]:
        if total < min_support:
            return []
        denominator = total + (self.smoothing * max(len(counts), 1))
        entry = match.get("entry") or {}
        hypotheses: List[Hypothesis] = []
        for target, count_value in sorted(counts.items(), key=lambda item: _safe_float(item[1]), reverse=True):
            count = _safe_float(count_value)
            probability = (count + self.smoothing) / denominator if denominator else 0.0
            support_level = _support_level(count, total, min_support)
            hypotheses.append(
                Hypothesis(
                    tactic=str(target),
                    score=probability,
                    source=self.name,
                    source_type="empirical_actor_fingerprint",
                    depends_on_classification=depends_on_classification,
                    reasons=[
                        (
                            f"fingerprint-conditioned local history observed "
                            f"{_format_count(count)}/{_format_count(total)} completed transitions "
                            f"({transition_type}) from {context} to {target}; support={support_level}"
                        )
                    ],
                    evidence_sources=["completed local sessions sharing HASSH/JA3/command-pattern fingerprints"],
                    metadata={
                        "model_id": self.transition_model.get("model_id", ""),
                        "matched_fingerprint_key": match.get("key", ""),
                        "matched_fingerprint_type": match.get("field", ""),
                        "matched_fingerprint_value": match.get("value", ""),
                        "matched_session_count": int(entry.get("session_count") or 0),
                        "matched_session_ids": list(entry.get("session_ids") or []),
                        "fingerprint_count": int(self.transition_model.get("fingerprint_count") or 0),
                        "transition_count": round(total, 4),
                        "transition_support": round(count, 4),
                        "transition_probability": round(probability, 4),
                        "transition_support_level": support_level,
                        "transition_total": round(total, 4),
                        "support_share": round(count / total, 4) if total else 0.0,
                        "min_support": min_support,
                        "transition_type": transition_type,
                        "transition_context": context,
                        "training_source": "completed local sessions grouped by session_fingerprint",
                        "provenance": dict(self.transition_model.get("provenance") or {}),
                        "named_actor_attribution": False,
                        "temporal_claim": True,
                    },
                )
            )
        return hypotheses

    def score(self, features: Dict[str, Any]) -> List[Hypothesis]:
        if not self.enabled:
            return []
        match = self._matching_fingerprint(features)
        if not match:
            return []
        entry = match.get("entry") or {}
        tactic_sequence = [
            str(tactic or "").strip()
            for tactic in features.get("tactic_sequence") or []
            if str(tactic or "").strip()
        ]
        prefix_transitions = entry.get("prefix_transitions") or {}
        max_prefix = min(self.prefix_max_length, len(tactic_sequence))
        for prefix_length in range(max_prefix, 1, -1):
            prefix = ">".join(tactic_sequence[-prefix_length:])
            counts = prefix_transitions.get(prefix) or {}
            total = sum(_safe_float(count) for count in counts.values())
            hypotheses = self._counts_to_hypotheses(
                counts,
                total,
                context=prefix,
                transition_type="fingerprint_prefix",
                min_support=self.min_prefix_transition_count,
                match=match,
                depends_on_classification=True,
            )
            if hypotheses:
                return hypotheses

        last_tactic = str(features.get("last_tactic") or "").strip()
        if last_tactic:
            transitions = entry.get("transitions") or {}
            counts = transitions.get(last_tactic) or {}
            total = sum(_safe_float(count) for count in counts.values())
            return self._counts_to_hypotheses(
                counts,
                total,
                context=last_tactic,
                transition_type="fingerprint_tactic",
                min_support=self.min_tactic_transition_count,
                match=match,
                depends_on_classification=True,
            )

        start_counts = entry.get("start_counts") or {}
        total = sum(_safe_float(count) for count in start_counts.values())
        return self._counts_to_hypotheses(
            start_counts,
            total,
            context=str(match.get("field") or "fingerprint"),
            transition_type="fingerprint_start",
            min_support=self.min_transition_count,
            match=match,
            depends_on_classification=False,
        )


class FallbackProgressionScorer:
    name = "fallback_progression"
    version = "1.0"

    def __init__(self, progression: Dict[str, List[str]] | None = None) -> None:
        self.progression = progression or TACTIC_PROGRESSION

    def score(self, features: Dict[str, Any]) -> List[Hypothesis]:
        last_tactic = str(features.get("last_tactic") or "")
        if not last_tactic:
            return [
                Hypothesis(
                    tactic="discovery",
                    score=0.55,
                    source=self.name,
                    source_type="heuristic_prior",
                    depends_on_classification=False,
                    evidence_sources=["fallback prior used before tactics are observed"],
                    reasons=["no tactic observed yet; discovery is a common early interactive step"],
                ),
                Hypothesis(
                    tactic="execution",
                    score=0.45,
                    source=self.name,
                    source_type="heuristic_prior",
                    depends_on_classification=False,
                    evidence_sources=["fallback prior used before tactics are observed"],
                    reasons=["no tactic observed yet; execution is a common early command stage"],
                ),
            ]

        candidates = self.progression.get(last_tactic, [])
        if not candidates:
            return [
                Hypothesis(
                    tactic="unknown",
                    score=0.10,
                    source=self.name,
                    source_type="heuristic_prior",
                    depends_on_classification=True,
                    evidence_sources=["fallback progression table"],
                    reasons=[f"no fallback progression is configured after {last_tactic}"],
                )
            ]

        base_scores = [0.55, 0.30, 0.15]
        return [
            Hypothesis(
                tactic=tactic,
                score=base_scores[index] if index < len(base_scores) else 0.05,
                source=self.name,
                source_type="heuristic_prior",
                depends_on_classification=True,
                evidence_sources=["configured fallback progression table"],
                reasons=[f"last observed tactic is {last_tactic}; fallback progression suggests {tactic}"],
            )
            for index, tactic in enumerate(candidates)
        ]


class TacticCombinationScorer:
    name = "tactic_combination"
    version = "1.0"

    def __init__(self, rules: List[Dict[str, Any]] | None = None) -> None:
        self.rules = rules or DEFAULT_TACTIC_COMBINATION_RULES

    def score(self, features: Dict[str, Any]) -> List[Hypothesis]:
        tactics = set(features.get("observed_tactics") or [])
        flags = features.get("behavior_flags") or {}
        hypotheses: List[Hypothesis] = []

        for rule in self.rules:
            if not isinstance(rule, dict) or not _rule_matches(rule, tactics, flags):
                continue
            source_type = str(rule.get("source_type") or "heuristic_prior")
            rule_id = str(rule.get("rule_id") or "")
            evidence_sources = [str(item) for item in rule.get("evidence_sources") or [] if item]
            references = [str(item) for item in rule.get("references") or [] if item]
            metadata = {
                "rule_id": rule_id,
                "evidence_key": str(rule.get("evidence_key") or rule.get("deduplication_key") or ""),
                "deduplication_key": str(rule.get("deduplication_key") or rule.get("evidence_key") or ""),
                "confidence_policy": rule.get("confidence_policy", ""),
                "required_tactics": rule.get("required_tactics") or [],
                "required_flags": rule.get("required_flags") or [],
                "absent_flags": rule.get("absent_flags") or [],
            }
            for item in rule.get("hypotheses") or []:
                if not isinstance(item, dict):
                    continue
                tactic = str(item.get("tactic") or "").strip()
                if not tactic:
                    continue
                hypotheses.append(
                    Hypothesis(
                        tactic=tactic,
                        score=float(item.get("score") or 0.0),
                        source=self.name,
                        source_type=source_type,
                        rule_id=rule_id,
                        depends_on_classification=True,
                        evidence_sources=evidence_sources,
                        references=references,
                        reasons=[str(item.get("reason") or f"{rule_id} matched")],
                        metadata=metadata,
                    )
                )

        return hypotheses


class MitreAssociationScorer:
    name = "mitre_association"
    version = "1.0"

    def __init__(
        self,
        rules: List[Dict[str, Any]] | None = None,
        technique_to_tactic_aggregation: str = "max",
        technique_tactic_map: Dict[str, Any] | None = None,
    ) -> None:
        self.rules = rules or []
        self.technique_to_tactic_aggregation = str(technique_to_tactic_aggregation or "max")
        self.technique_tactic_map = technique_tactic_map or {}

    def score(self, features: Dict[str, Any]) -> List[Hypothesis]:
        observed_ttps = {main_ttp_id(item) for item in features.get("observed_ttps") or [] if item}
        observed_tactics = {str(item or "").strip() for item in features.get("observed_tactics") or [] if item}
        if not observed_ttps and not observed_tactics:
            return []
        hypotheses: List[Hypothesis] = []
        for rule in self.rules:
            if not isinstance(rule, dict) or not bool(rule.get("enabled", True)):
                continue
            required_ttps = {main_ttp_id(item) for item in rule.get("required_ttps") or [] if item}
            any_ttps = {main_ttp_id(item) for item in rule.get("any_ttps") or [] if item}
            required_tactics = {str(item or "").strip() for item in rule.get("required_tactics") or [] if item}
            if required_ttps and not required_ttps.issubset(observed_ttps):
                continue
            if any_ttps and not observed_ttps.intersection(any_ttps):
                continue
            if required_tactics and not required_tactics.issubset(observed_tactics):
                continue

            rule_id = str(rule.get("rule_id") or "")
            evidence_sources = [str(item) for item in rule.get("evidence_sources") or [] if item]
            references = [str(item) for item in rule.get("references") or [] if item]
            source_type = str(rule.get("source_type") or "human_curated_attck_prior")
            base_metadata = {
                "rule_id": rule_id,
                "evidence_key": str(rule.get("evidence_key") or rule.get("deduplication_key") or ""),
                "deduplication_key": str(rule.get("deduplication_key") or rule.get("evidence_key") or ""),
                "required_ttps": sorted(required_ttps),
                "any_ttps": sorted(any_ttps),
                "required_tactics": sorted(required_tactics),
                "confidence_policy": rule.get("confidence_policy", ""),
                "provenance": rule.get("provenance") or {},
                "inference_type": rule.get("inference_type") or "associated_technique_prior",
                "temporal_claim": bool(rule.get("temporal_claim", False)),
            }
            technique_scores: Dict[str, Dict[str, Any]] = {}
            for item in rule.get("hypotheses") or []:
                if not isinstance(item, dict):
                    continue
                technique = str(item.get("technique") or "").strip()
                tactic = str(item.get("tactic") or "").strip()
                score = _safe_float(item.get("score"), 0.0)
                reason = str(item.get("reason") or f"{rule_id} associated prior matched")
                if technique:
                    tactic = _mapped_tactic_for_technique(technique, item, rule, self.technique_tactic_map)
                    if tactic:
                        technique_scores[f"{technique}#{len(technique_scores)}"] = {
                            "technique": technique,
                            "tactic": tactic,
                            "score": score,
                            "reason": reason,
                        }
                        continue
                if not tactic:
                    continue
                hypotheses.append(
                    Hypothesis(
                        tactic=tactic,
                        score=score,
                        source=self.name,
                        source_type=source_type,
                        rule_id=rule_id,
                        depends_on_classification=True,
                        evidence_sources=evidence_sources,
                        references=references,
                        reasons=[reason],
                        metadata=base_metadata,
                    )
                )
            grouped = _technique_tactic_rows(technique_scores)
            aggregated = aggregate_technique_to_tactic(
                technique_scores,
                self.technique_to_tactic_aggregation,
            )
            for tactic, score in aggregated.items():
                rows = grouped.get(tactic, [])
                metadata = dict(base_metadata)
                metadata.update(_technique_tactic_metadata(rows, self.technique_to_tactic_aggregation))
                techniques = [
                    str(row.get("technique") or "")
                    for row in rows
                    if str(row.get("technique") or "")
                ]
                reasons = _unique(str(row.get("reason") or "") for row in rows)
                if len(rows) > 1:
                    reasons.append(
                        f"{len(rows)} technique scores aggregated to tactic {tactic} using "
                        f"{self.technique_to_tactic_aggregation}"
                    )
                hypotheses.append(
                    Hypothesis(
                        tactic=tactic,
                        technique=techniques[0] if len(techniques) == 1 else "",
                        score=score,
                        source=self.name,
                        source_type=source_type,
                        rule_id=rule_id,
                        depends_on_classification=True,
                        evidence_sources=evidence_sources,
                        references=references,
                        reasons=reasons,
                        metadata=metadata,
                    )
                )
        return hypotheses


class SigmaCorrelationScorer:
    name = "sigma_correlation"
    version = "1.0"

    def __init__(
        self,
        rules: List[Dict[str, Any]] | None = None,
        technique_to_tactic_aggregation: str = "max",
        technique_tactic_map: Dict[str, Any] | None = None,
    ) -> None:
        self.rules = rules or []
        self.technique_to_tactic_aggregation = str(technique_to_tactic_aggregation or "max")
        self.technique_tactic_map = technique_tactic_map or {}

    def score(self, features: Dict[str, Any]) -> List[Hypothesis]:
        sigma_hits = [str(item or "").strip() for item in features.get("sigma_hits") or [] if item]
        if not sigma_hits:
            return []
        hypotheses: List[Hypothesis] = []
        for rule in self.rules:
            if not isinstance(rule, dict) or not bool(rule.get("enabled", True)):
                continue
            min_hits = int(rule.get("min_sigma_hits") or 0)
            contains_any = rule.get("sigma_contains_any") or []
            required_hits = {str(item or "").strip() for item in rule.get("required_sigma_hits") or [] if item}
            if min_hits and len(sigma_hits) < min_hits:
                continue
            if contains_any and not _contains_any(sigma_hits, contains_any):
                continue
            if required_hits and not required_hits.issubset(set(sigma_hits)):
                continue

            rule_id = str(rule.get("rule_id") or "")
            evidence_sources = [str(item) for item in rule.get("evidence_sources") or [] if item]
            references = [str(item) for item in rule.get("references") or [] if item]
            source_type = str(rule.get("source_type") or "detection_correlation")
            base_metadata = {
                "rule_id": rule_id,
                "matched_sigma_hits": sigma_hits,
                "confidence_policy": rule.get("confidence_policy", ""),
                "provenance": rule.get("provenance") or {},
                "inference_type": rule.get("inference_type") or "indirect_detection_context",
                "temporal_claim": bool(rule.get("temporal_claim", False)),
            }
            technique_scores: Dict[str, Dict[str, Any]] = {}
            for item in rule.get("hypotheses") or []:
                if not isinstance(item, dict):
                    continue
                technique = str(item.get("technique") or "").strip()
                tactic = str(item.get("tactic") or "").strip()
                score = _safe_float(item.get("score"), 0.0)
                reason = str(item.get("reason") or f"{rule_id} Sigma correlation matched")
                if technique:
                    tactic = _mapped_tactic_for_technique(technique, item, rule, self.technique_tactic_map)
                    if tactic:
                        technique_scores[f"{technique}#{len(technique_scores)}"] = {
                            "technique": technique,
                            "tactic": tactic,
                            "score": score,
                            "reason": reason,
                        }
                        continue
                if not tactic:
                    continue
                hypotheses.append(
                    Hypothesis(
                        tactic=tactic,
                        score=score,
                        source=self.name,
                        source_type=source_type,
                        rule_id=rule_id,
                        depends_on_classification=False,
                        evidence_sources=evidence_sources,
                        references=references,
                        reasons=[reason],
                        metadata=base_metadata,
                    )
                )
            grouped = _technique_tactic_rows(technique_scores)
            aggregated = aggregate_technique_to_tactic(
                technique_scores,
                self.technique_to_tactic_aggregation,
            )
            for tactic, score in aggregated.items():
                rows = grouped.get(tactic, [])
                metadata = dict(base_metadata)
                metadata.update(_technique_tactic_metadata(rows, self.technique_to_tactic_aggregation))
                techniques = [
                    str(row.get("technique") or "")
                    for row in rows
                    if str(row.get("technique") or "")
                ]
                reasons = _unique(str(row.get("reason") or "") for row in rows)
                if len(rows) > 1:
                    reasons.append(
                        f"{len(rows)} technique scores aggregated to tactic {tactic} using "
                        f"{self.technique_to_tactic_aggregation}"
                    )
                hypotheses.append(
                    Hypothesis(
                        tactic=tactic,
                        technique=techniques[0] if len(techniques) == 1 else "",
                        score=score,
                        source=self.name,
                        source_type=source_type,
                        rule_id=rule_id,
                        depends_on_classification=False,
                        evidence_sources=evidence_sources,
                        references=references,
                        reasons=reasons,
                        metadata=metadata,
                    )
                )
        return hypotheses


class EnrichmentContextScorer:
    name = "enrichment_context"
    version = "1.0"

    def score(self, features: Dict[str, Any]) -> List[Hypothesis]:
        enrichment = features.get("enrichment_status") or {}
        context = features.get("enrichment_context") or {}
        providers = set(enrichment.get("providers") or [])
        providers.update(context.get("providers") or [])
        status = str(enrichment.get("status") or "")
        context_status = str(context.get("status") or "")
        if status in {"missing", "none", ""} and context_status in {"missing", "none", ""} and not providers:
            return []
        reasons = []
        if providers:
            reasons.append("enrichment context is available from " + ", ".join(sorted(providers)))
        else:
            reasons.append("enrichment context is available")

        tags = []
        for key in ("infrastructure_tags", "otx_tags", "abuse_tags", "abuseipdb_categories", "shodan_tags", "censys_labels"):
            tags.extend(str(item) for item in context.get(key) or [] if item)
        tag_text = " ".join(tags).lower()
        open_ports = context.get("open_ports") or []
        running_services = context.get("running_services") or []
        shodan_vulns = [str(item) for item in context.get("shodan_vulns") or [] if item]
        shodan_cpes = [str(item) for item in context.get("shodan_cpes") or [] if item]
        provider_status = context.get("provider_status") or {}
        risk_score = _safe_float(context.get("risk_score"), 0.0)
        vt_hit = bool(context.get("vt_hit"))
        vt_ratio = str(context.get("vt_detection_ratio") or "")
        total_reports = int(_safe_float(context.get("total_reports"), 0.0))

        base_metadata = {
            "enrichment_status": status or context_status,
            "providers": sorted(providers),
            "provider_status": provider_status if isinstance(provider_status, dict) else {},
            "risk_score": risk_score,
            "total_reports": total_reports,
            "vt_hit": vt_hit,
            "vt_detection_ratio": vt_ratio,
            "tags": tags,
            "open_ports": open_ports,
            "running_services": running_services,
            "shodan_vulns": shodan_vulns,
            "shodan_cpes": shodan_cpes,
            "raw_otx_pulse": context.get("raw_otx_pulse") or "",
            "inference_type": "indirect_infrastructure_context",
            "temporal_claim": False,
        }

        c2_score = 0.12
        discovery_score = 0.0
        credential_score = 0.0
        impact_score = 0.0
        evidence_sources = ["cached enrichment provider status"]
        if bool(context.get("is_tor_exit")):
            c2_score += 0.10
            discovery_score += 0.05
            reasons.append("source IP is tagged as Tor exit infrastructure")
        if bool(context.get("is_vpn")) or "vpn" in tag_text or "proxy" in tag_text:
            c2_score += 0.05
            discovery_score += 0.03
            reasons.append("source IP has proxy/VPN infrastructure context")
        if risk_score >= 75:
            c2_score += 0.10
            credential_score += 0.05
            reasons.append(f"AbuseIPDB-style risk score is high ({int(risk_score)})")
        elif risk_score >= 25:
            c2_score += 0.05
            reasons.append(f"AbuseIPDB-style risk score is elevated ({int(risk_score)})")
        if total_reports >= 20:
            c2_score += 0.05
            reasons.append(f"AbuseIPDB-style report volume is high ({total_reports} reports)")
        if vt_hit:
            c2_score += 0.10
            impact_score += 0.08
            reasons.append("VirusTotal-style context indicates a known malware association")
        if vt_ratio:
            reasons.append(f"VirusTotal-style detection ratio is {vt_ratio}")
        if "scanner" in tag_text or "brute force" in tag_text or "ssh" in tag_text:
            discovery_score += 0.10
            credential_score += 0.08
            reasons.append("provider tags indicate scanning, SSH, or brute-force behavior")
        if any(token in tag_text for token in ("c2", "command", "callback", "botnet", "malware", "dropper")):
            c2_score += 0.12
            reasons.append("OTX/Shodan/Censys tags indicate malware, dropper, callback, or C2 context")
        if any(token in tag_text for token in ("credential", "brute", "password", "ssh")):
            credential_score += 0.10
            reasons.append("provider tags indicate credential or SSH brute-force context")
        if open_ports or running_services:
            discovery_score += 0.06
            reasons.append("Shodan/Censys-style service context is present")
        if shodan_vulns:
            impact_score += 0.12
            evidence_sources.append("Shodan vulnerability context")
            reasons.append("Shodan-style vulnerability context is present: " + ", ".join(shodan_vulns[:5]))
        if shodan_cpes:
            discovery_score += 0.03
            reasons.append("Shodan-style CPE/service fingerprint context is present")

        hypotheses: List[Hypothesis] = []

        def add(tactic: str, score: float, reason_suffix: str) -> None:
            if score <= 0:
                return
            hypotheses.append(
                Hypothesis(
                    tactic=tactic,
                    score=min(score, 0.65),
                    source=self.name,
                    source_type="context_modifier",
                    depends_on_classification=False,
                    reasons=[reason + reason_suffix for reason in reasons],
                    evidence_sources=evidence_sources,
                    references=[
                        "https://otx.alienvault.com/",
                        "https://www.abuseipdb.com/",
                        "https://www.shodan.io/",
                        "https://search.censys.io/",
                        "https://www.virustotal.com/",
                    ],
                    metadata=base_metadata,
                )
            )

        add("command-and-control", c2_score, "; infrastructure context can increase callback/staging suspicion")
        add("discovery", discovery_score, "; exposed-service context can indicate scanning or service discovery")
        add("credential-access", credential_score, "; abuse context can indicate credential attack pressure")
        add("impact", impact_score, "; malware or vulnerability context raises post-compromise impact concern")
        return hypotheses


class VulnerabilityRiskScorer:
    name = "vulnerability_risk"
    version = "1.0"

    def __init__(self, policy: Dict[str, Any] | None = None) -> None:
        self.policy = policy or {}

    def score(self, features: Dict[str, Any]) -> List[Hypothesis]:
        if not bool(self.policy.get("enabled", True)):
            return []
        observed_cves = {
            str(cve or "").strip().upper()
            for cve in features.get("observed_cves") or []
            if str(cve or "").strip()
        }
        kev_matches = [
            item
            for item in features.get("kev_matches") or []
            if isinstance(item, dict)
        ]
        kev_cves = {
            str(item.get("cve_id") or item.get("cve") or "").strip().upper()
            for item in kev_matches
            if str(item.get("cve_id") or item.get("cve") or "").strip()
        }
        cves = sorted(observed_cves.union(kev_cves))
        if not cves and not kev_matches:
            return []

        epss_scores_raw = self.policy.get("epss_scores") or {}
        epss_scores = {
            str(cve).upper(): _safe_float(score, 0.0)
            for cve, score in epss_scores_raw.items()
        } if isinstance(epss_scores_raw, dict) else {}
        matched_epss = {
            cve: score
            for cve, score in epss_scores.items()
            if cve in observed_cves or cve in kev_cves
        }
        max_epss = max(matched_epss.values()) if matched_epss else 0.0
        high_epss = _safe_float(self.policy.get("high_epss_threshold"), 0.70)
        medium_epss = _safe_float(self.policy.get("medium_epss_threshold"), 0.30)

        score = 0.10
        reasons = []
        evidence_sources = []
        if cves:
            reasons.append("session references vulnerability identifiers: " + ", ".join(cves))
        if kev_matches:
            score += 0.25
            evidence_sources.append("CISA KEV cache")
            reasons.append("one or more referenced CVEs match known exploited vulnerability data")
        if max_epss >= high_epss:
            score += 0.20
            evidence_sources.append("EPSS policy cache")
            reasons.append(f"EPSS prior is high for a referenced CVE ({max_epss:.2f})")
        elif max_epss >= medium_epss:
            score += 0.10
            evidence_sources.append("EPSS policy cache")
            reasons.append(f"EPSS prior is elevated for a referenced CVE ({max_epss:.2f})")
        if not evidence_sources:
            evidence_sources.append("session command CVE extraction")
        if not reasons:
            reasons.append("vulnerability context is present in the current session")

        return [
            Hypothesis(
                tactic=str(self.policy.get("default_tactic") or "impact"),
                technique=str(self.policy.get("default_technique") or ""),
                score=min(score, 0.60),
                source=self.name,
                source_type="risk_modifier",
                depends_on_classification=False,
                reasons=[
                    reason + "; this is a risk/context modifier, not proof of the next tactic"
                    for reason in reasons
                ],
                evidence_sources=evidence_sources,
                references=[
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "https://www.first.org/epss/",
                ],
                metadata={
                    "observed_cves": cves,
                    "kev_cves": sorted(kev_cves),
                    "epss_scores": matched_epss,
                    "max_epss": round(max_epss, 4),
                    "inference_type": "vulnerability_risk_context",
                    "temporal_claim": False,
                },
            )
        ]


def _risk_level(score: float) -> str:
    if score >= 0.50:
        return "high"
    if score >= 0.30:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _risk_annotation_from_outputs(outputs_by_annotator: Dict[str, List[Hypothesis]]) -> Dict[str, Any]:
    """Summarize non-predictive risk evidence separately from tactic ranking.

    This is a contextual risk annotation, not a next-tactic probability. Keeping
    it outside the linear opinion pool avoids treating CVE/KEV/EPSS evidence as
    temporal attacker-behavior evidence.
    """

    annotations: List[Dict[str, Any]] = []
    reasons: List[str] = []
    evidence_sources: List[str] = []
    observed_cves: List[str] = []
    kev_cves: List[str] = []
    max_epss = 0.0
    max_score = 0.0

    for annotator_name, hypotheses in sorted(outputs_by_annotator.items()):
        for hypothesis in hypotheses:
            payload = hypothesis.to_dict()
            payload["annotator"] = annotator_name
            annotations.append(payload)
            max_score = max(max_score, float(hypothesis.score or 0.0))
            reasons.extend(str(reason) for reason in hypothesis.reasons if str(reason))
            evidence_sources.extend(str(source) for source in hypothesis.evidence_sources if str(source))
            metadata = hypothesis.metadata or {}
            observed_cves.extend(str(cve) for cve in metadata.get("observed_cves") or [] if str(cve))
            kev_cves.extend(str(cve) for cve in metadata.get("kev_cves") or [] if str(cve))
            max_epss = max(max_epss, _safe_float(metadata.get("max_epss"), 0.0))

    return {
        "schema_version": "risk_annotation.v1",
        "active": bool(annotations),
        "level": _risk_level(max_score),
        "score": round(max_score, 4),
        "excluded_from_tactic_ranking": True,
        "reason": (
            "Risk annotation is informational CVE/KEV/EPSS context; it does "
            "not contribute to next-tactic ranking or default alert severity."
        ),
        "annotations": annotations,
        "reasons": _unique(reasons),
        "evidence_sources": _unique(evidence_sources),
        "metadata": {
            "observed_cves": _unique(observed_cves),
            "kev_cves": _unique(kev_cves),
            "max_epss": round(max_epss, 4),
        },
    }


def confidence_label(score: float) -> str:
    if score >= 0.70:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"


def _calibrated_score(raw_score: float, calibration: Dict[str, Any]) -> tuple[float, Dict[str, Any]]:
    if not bool(calibration.get("enabled", False)):
        return raw_score, {"applied": False}
    min_cases = int(calibration.get("min_cases_per_bin") or 0)
    for bin_item in calibration.get("bins") or []:
        if not isinstance(bin_item, dict):
            continue
        lower = _safe_float(bin_item.get("min_score"), 0.0)
        upper = _safe_float(bin_item.get("max_score"), 1.0)
        include_upper = bool(bin_item.get("include_upper", upper >= 1.0))
        in_range = lower <= raw_score <= upper if include_upper else lower <= raw_score < upper
        if not in_range:
            continue
        cases = int(bin_item.get("cases") or 0)
        if cases < min_cases:
            return raw_score, {
                "applied": False,
                "reason": "insufficient calibration cases",
                "bin": dict(bin_item),
            }
        empirical = _safe_float(bin_item.get("empirical_accuracy"), raw_score)
        return min(max(empirical, 0.0), 1.0), {
            "applied": True,
            "method": str(calibration.get("method") or "empirical_binning"),
            "bin": dict(bin_item),
        }
    return raw_score, {"applied": False, "reason": "no calibration bin matched"}


def _enrichment_context_mode(policy: Dict[str, Any]) -> str:
    mode = str(policy.get("enrichment_context_mode") or "scorer").strip().lower()
    if mode in {"scorer", "excluded", "score_multiplier"}:
        return mode
    return "scorer"


def _enrichment_multiplier_summary(mode: str, policy: Dict[str, Any]) -> Dict[str, Any]:
    multiplier_policy = policy.get("enrichment_context_multiplier") or {}
    if not isinstance(multiplier_policy, dict):
        multiplier_policy = {}
    return {
        "mode": mode,
        "max_multiplier": round(max(_safe_float(multiplier_policy.get("max_multiplier"), 1.15), 1.0), 4),
        "min_enrichment_score": round(max(_safe_float(multiplier_policy.get("min_enrichment_score"), 0.01), 0.0), 4),
        "counts_as_supporting_scorer": mode == "scorer",
    }


def _enrichment_context_by_tactic(hypotheses: List[Hypothesis]) -> Dict[str, Hypothesis]:
    best: Dict[str, Hypothesis] = {}
    for hypothesis in hypotheses:
        tactic = str(hypothesis.tactic or "").strip()
        if not tactic:
            continue
        current = best.get(tactic)
        if current is None or _safe_float(hypothesis.score, 0.0) > _safe_float(current.score, 0.0):
            best[tactic] = hypothesis
    return best


def _apply_enrichment_context_multiplier(
    ranking: List[Dict[str, Any]],
    enrichment_outputs: List[Hypothesis],
    policy: Dict[str, Any],
    calibration_policy: Dict[str, Any],
) -> Dict[str, Any]:
    """Apply cached enrichment as a capped post-score context adjustment.

    This mode is deliberately distinct from weighted evidence fusion:
    enrichment does not become an active voter or supporting scorer. It can only
    multiply an already-ranked behavioral hypothesis by a small configured cap.
    """

    summary = _enrichment_multiplier_summary("score_multiplier", policy)
    summary.update({"applied": False, "adjusted_tactics": []})
    if not ranking:
        summary["reason"] = "no behavioral ranking to adjust"
        return summary
    by_tactic = _enrichment_context_by_tactic(enrichment_outputs)
    if not by_tactic:
        summary["reason"] = "no enrichment output available"
        return summary

    max_multiplier = _safe_float(summary.get("max_multiplier"), 1.15)
    min_score = _safe_float(summary.get("min_enrichment_score"), 0.01)
    adjusted_tactics: List[str] = []
    for item in ranking:
        tactic = str(item.get("tactic") or "")
        enrichment = by_tactic.get(tactic)
        if enrichment is None:
            continue
        enrichment_score = max(_safe_float(enrichment.score, 0.0), 0.0)
        if enrichment_score < min_score:
            continue
        before = max(_safe_float(item.get("score"), 0.0), 0.0)
        multiplier = min(max_multiplier, 1.0 + enrichment_score * (max_multiplier - 1.0))
        after = min(before * multiplier, 1.0)
        calibrated_score, calibration_meta = _calibrated_score(after, calibration_policy)
        item["score"] = round(after, 4)
        item["calibrated_score"] = round(calibrated_score, 4)
        item["calibration"] = calibration_meta
        item["confidence"] = confidence_label(calibrated_score)
        item.setdefault("context_adjustments", []).append(
            {
                "name": "enrichment_context",
                "source_type": enrichment.source_type,
                "mode": "score_multiplier",
                "raw_score": round(enrichment_score, 4),
                "multiplier": round(multiplier, 4),
                "score_before": round(before, 4),
                "score_after": round(after, 4),
                "counts_as_supporting_scorer": False,
                "evidence_sources": list(enrichment.evidence_sources),
                "metadata": dict(enrichment.metadata),
            }
        )
        reasons = item.setdefault("reasons", [])
        reason = (
            f"enrichment context multiplier applied with cap {max_multiplier:.2f}; "
            "context does not count as a supporting scorer"
        )
        if reason not in reasons:
            reasons.append(reason)
        adjusted_tactics.append(tactic)

    if not adjusted_tactics:
        summary["reason"] = "no ranked tactic matched enrichment context output"
        return summary
    ranking.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)
    summary["applied"] = True
    summary["adjusted_tactics"] = adjusted_tactics
    summary["reason"] = "applied capped post-score multiplier to matching ranked tactics"
    return summary


def _rule_prior_deduplication_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    config = policy.get("rule_prior_deduplication") or {}
    if not isinstance(config, dict):
        config = {}
    method = str(config.get("method") or "max_contribution").strip().lower()
    if method != "max_contribution":
        method = "max_contribution"
    scorers = {
        str(item or "").strip()
        for item in config.get("scorers") or ["tactic_combination", "mitre_association"]
        if str(item or "").strip()
    }
    return {
        "enabled": bool(config.get("enabled", True)),
        "method": method,
        "scorers": scorers,
        "require_shared_evidence_key": bool(config.get("require_shared_evidence_key", True)),
    }


def _rule_prior_deduplication_key(hypothesis: Hypothesis, policy: Dict[str, Any]) -> str:
    config = _rule_prior_deduplication_policy(policy)
    if not config["enabled"] or hypothesis.source not in config["scorers"]:
        return ""
    metadata = hypothesis.metadata or {}
    evidence_key = str(metadata.get("deduplication_key") or metadata.get("evidence_key") or "").strip()
    if config["require_shared_evidence_key"] and not evidence_key:
        return ""
    return f"{hypothesis.tactic}|{evidence_key or hypothesis.rule_id}"


def _empty_rule_prior_deduplication_summary(policy: Dict[str, Any]) -> Dict[str, Any]:
    config = _rule_prior_deduplication_policy(policy)
    return {
        "enabled": bool(config["enabled"]),
        "method": config["method"],
        "scorers": sorted(config["scorers"]),
        "deduplicated_source_count": 0,
        "groups": [],
    }


def _apply_rule_prior_deduplication(
    entry: Dict[str, Any],
    group_key: str,
    source_payload: Dict[str, Any],
    contribution_payload: Dict[str, Any],
    weighted_score: float,
    policy: Dict[str, Any],
) -> float:
    """Use max contribution for correlated rule priors while preserving sources."""

    if not group_key:
        return weighted_score
    config = _rule_prior_deduplication_policy(policy)
    if not config["enabled"]:
        return weighted_score

    groups = entry.setdefault("_rule_prior_dedup_groups", {})
    summary = entry.setdefault("rule_prior_deduplication", _empty_rule_prior_deduplication_summary(policy))
    group = groups.get(group_key)
    source_payload["pre_dedup_weighted_score"] = round(weighted_score, 4)
    contribution_payload["pre_dedup_contribution"] = round(weighted_score, 4)
    if group is None:
        groups[group_key] = {
            "weighted_score": weighted_score,
            "source": source_payload,
            "contribution": contribution_payload,
            "retained_source": source_payload.get("name", ""),
        }
        source_payload["deduplication"] = {
            "applied": False,
            "group_key": group_key,
            "method": config["method"],
        }
        contribution_payload["deduplication"] = dict(source_payload["deduplication"])
        return weighted_score

    retained_source = str(group.get("retained_source") or "")
    existing_weight = float(group.get("weighted_score") or 0.0)
    if weighted_score > existing_weight:
        old_source = group["source"]
        old_contribution = group["contribution"]
        old_source["weighted_score"] = 0.0
        old_source["deduplication"] = {
            "applied": True,
            "retained": False,
            "group_key": group_key,
            "method": config["method"],
            "retained_source": source_payload.get("name", ""),
            "reason": "lower correlated rule-prior contribution suppressed by max-contribution deduplication",
        }
        old_contribution["contribution"] = 0.0
        old_contribution["deduplication"] = dict(old_source["deduplication"])
        source_payload["deduplication"] = {
            "applied": True,
            "retained": True,
            "group_key": group_key,
            "method": config["method"],
            "suppressed_source": retained_source,
            "reason": "higher correlated rule-prior contribution retained by max-contribution deduplication",
        }
        contribution_payload["deduplication"] = dict(source_payload["deduplication"])
        groups[group_key] = {
            "weighted_score": weighted_score,
            "source": source_payload,
            "contribution": contribution_payload,
            "retained_source": source_payload.get("name", ""),
        }
        summary["deduplicated_source_count"] = int(summary.get("deduplicated_source_count") or 0) + 1
        summary.setdefault("groups", []).append(
            {
                "group_key": group_key,
                "retained_source": source_payload.get("name", ""),
                "suppressed_source": retained_source,
                "method": config["method"],
            }
        )
        return weighted_score - existing_weight

    source_payload["weighted_score"] = 0.0
    source_payload["deduplication"] = {
        "applied": True,
        "retained": False,
        "group_key": group_key,
        "method": config["method"],
        "retained_source": retained_source,
        "reason": "lower correlated rule-prior contribution suppressed by max-contribution deduplication",
    }
    contribution_payload["contribution"] = 0.0
    contribution_payload["deduplication"] = dict(source_payload["deduplication"])
    summary["deduplicated_source_count"] = int(summary.get("deduplicated_source_count") or 0) + 1
    summary.setdefault("groups", []).append(
        {
            "group_key": group_key,
            "retained_source": retained_source,
            "suppressed_source": source_payload.get("name", ""),
            "method": config["method"],
        }
    )
    return 0.0


def _confidence_index(label: str) -> int:
    order = {"low": 0, "medium": 1, "high": 2}
    return order.get(str(label or "").lower(), 0)


def _cap_confidence(label: str, cap: str) -> str:
    cap_text = str(cap or "").strip().lower()
    if not cap_text:
        return label
    labels = ["low", "medium", "high"]
    return labels[min(_confidence_index(label), _confidence_index(cap_text))]


def _str_set(values: Iterable[Any]) -> set[str]:
    return {
        str(value or "").strip()
        for value in values
        if str(value or "").strip()
    }


def _source_support(item: Dict[str, Any]) -> Dict[str, Any]:
    sources = [source for source in item.get("sources") or [] if isinstance(source, dict)]
    support_sources = [
        source
        for source in sources
        if _safe_float(source.get("weighted_score"), 0.0) > 0.0
    ]
    names = [str(source.get("name") or "") for source in support_sources if str(source.get("name") or "")]
    source_types = [str(source.get("source_type") or "") for source in support_sources if str(source.get("source_type") or "")]
    weighted_total = sum(_safe_float(source.get("weighted_score"), 0.0) for source in support_sources)
    dominant = {}
    if support_sources:
        dominant = max(support_sources, key=lambda source: _safe_float(source.get("weighted_score"), 0.0))
    dominant_name = str(dominant.get("name") or "")
    dominant_weighted_score = _safe_float(dominant.get("weighted_score"), 0.0)
    context_only_names = {"enrichment_context", "vulnerability_risk"}
    context_only_types = {"context_modifier", "risk_modifier"}
    name_set = set(names)
    type_set = set(source_types)
    return {
        "supporting_scorer_count": len(name_set),
        "supporting_scorers": sorted(name_set),
        "supporting_source_types": sorted(type_set),
        "local_support": "local_transition" in name_set,
        "external_seed_support": "external_seed_transition" in name_set,
        "external_seed_only": bool(name_set) and name_set == {"external_seed_transition"},
        "context_only": bool(name_set) and name_set.issubset(context_only_names),
        "context_or_risk_only": bool(type_set) and type_set.issubset(context_only_types),
        "dominant_source": dominant_name,
        "dominant_source_type": str(dominant.get("source_type") or ""),
        "dominant_weighted_score": round(dominant_weighted_score, 4),
        "dominance_ratio": round(dominant_weighted_score / weighted_total, 4) if weighted_total else 0.0,
        "weighted_total": round(weighted_total, 4),
    }


def _classification_quality_low(classification_quality: Dict[str, Any], controls: Dict[str, Any]) -> tuple[bool, str]:
    event_count = int(classification_quality.get("event_count") or 0)
    if event_count <= 0:
        return False, ""
    geomean = _safe_float(classification_quality.get("confidence_geomean"), 1.0)
    low_geomean = _safe_float(controls.get("low_classification_geomean"), 0.65)
    if classification_quality.get("confidence_available") and geomean < low_geomean:
        return True, f"classification confidence geomean {geomean:.2f} is below {low_geomean:.2f}"
    weak_count = int(classification_quality.get("unknown_count") or 0) + int(classification_quality.get("shell_noise_count") or 0)
    weak_ratio = weak_count / event_count
    max_weak_ratio = _safe_float(controls.get("unknown_or_noise_ratio"), 0.40)
    if weak_ratio >= max_weak_ratio:
        return True, f"classification unknown/shell-noise ratio {weak_ratio:.2f} is at or above {max_weak_ratio:.2f}"
    return False, ""


def _apply_confidence_controls(
    ranking: List[Dict[str, Any]],
    active_scorers: List[str],
    agreement: Dict[str, Any],
    classification_quality: Dict[str, Any],
    policy: Dict[str, Any],
) -> Dict[str, Any]:
    controls = policy.get("confidence_controls") or {}
    if not bool(controls.get("enabled", True)):
        for item in ranking:
            item["support"] = _source_support(item)
            item["confidence_controls"] = {
                "enabled": False,
                "original_confidence": item.get("confidence", ""),
                "final_confidence": item.get("confidence", ""),
                "caps_applied": [],
            }
        return {"enabled": False, "reason": "confidence controls disabled"}

    divergence_ratio = _safe_float(agreement.get("divergence_ratio"), 0.0)
    high_divergence_ratio = _safe_float(controls.get("high_divergence_ratio"), 0.75)
    medium_divergence_ratio = _safe_float(controls.get("medium_divergence_ratio"), 0.50)
    classification_low, classification_reason = _classification_quality_low(classification_quality, controls)
    summary = {
        "enabled": True,
        "active_scorer_count": len(active_scorers),
        "divergence_ratio": divergence_ratio,
        "classification_quality_low": classification_low,
        "classification_quality_reason": classification_reason,
        "items_adjusted": 0,
    }

    for item in ranking:
        original_label = str(item.get("confidence") or "low").strip().lower()
        final_label = original_label
        caps_applied: List[Dict[str, Any]] = []
        support = _source_support(item)

        def apply_cap(cap: Any, reason: str) -> None:
            nonlocal final_label
            cap_text = str(cap or "").strip().lower()
            if not cap_text:
                return
            before = final_label
            final_label = _cap_confidence(final_label, cap_text)
            caps_applied.append(
                {
                    "cap": cap_text,
                    "reason": reason,
                    "changed": before != final_label,
                }
            )

        if len(active_scorers) <= 1:
            apply_cap(controls.get("single_active_scorer_cap", "medium"), "only one active scorer produced any weighted output")
        if int(support.get("supporting_scorer_count") or 0) <= 1:
            apply_cap(controls.get("single_supporting_scorer_cap", "medium"), "ranked tactic is supported by only one scorer")
        if support.get("external_seed_only"):
            apply_cap(controls.get("external_seed_only_cap", "low"), "ranked tactic is supported only by the external seed prior")
        elif support.get("dominant_source") == "external_seed_transition" and not support.get("local_support"):
            apply_cap(controls.get("external_seed_dominated_cap", "medium"), "external seed prior dominates without local transition support")
        if support.get("context_only") or support.get("context_or_risk_only"):
            apply_cap(controls.get("context_only_cap", "low"), "ranked tactic is supported only by enrichment/risk context")
        if divergence_ratio >= high_divergence_ratio:
            apply_cap(controls.get("high_divergence_cap", "low"), "scorer disagreement is high")
        elif divergence_ratio >= medium_divergence_ratio:
            apply_cap(controls.get("medium_divergence_cap", "medium"), "scorer disagreement is elevated")
        if classification_low and any(bool(source.get("damped_by_classification_confidence")) for source in item.get("sources") or []):
            apply_cap(controls.get("low_classification_cap", "low"), classification_reason or "classification quality is low")

        item["support"] = support
        item["confidence_controls"] = {
            "enabled": True,
            "original_confidence": original_label,
            "final_confidence": final_label,
            "caps_applied": caps_applied,
        }
        item["confidence"] = final_label
        changed_caps = [cap for cap in caps_applied if cap.get("changed")]
        if changed_caps:
            summary["items_adjusted"] += 1
            reasons = item.setdefault("reasons", [])
            for cap in changed_caps:
                reason = f"confidence capped at {cap['cap']}: {cap['reason']}"
                if reason not in reasons:
                    reasons.append(reason)
    return summary


def _transition_count(model: Dict[str, Any]) -> int:
    return int(model.get("transition_count") or 0) + int(model.get("technique_transition_count") or 0)


def _model_maturity(model: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    thresholds = policy.get("maturity") or {}
    usable_sessions = int(model.get("usable_sessions") or 0)
    tactic_transitions = int(model.get("transition_count") or 0)
    prefix_transitions = int(model.get("prefix_transition_count") or 0)
    technique_transitions = int(model.get("technique_transition_count") or 0)
    local_transition_transitions = tactic_transitions + technique_transitions
    stable = thresholds.get("stable") or {}
    warming = thresholds.get("warming") or {}

    stable_sessions = int(stable.get("min_usable_sessions") or 200)
    stable_transitions = int(stable.get("min_transition_count") or 300)
    warming_sessions = int(warming.get("min_usable_sessions") or 50)
    warming_transitions = int(warming.get("min_transition_count") or 50)

    if usable_sessions >= stable_sessions and local_transition_transitions >= stable_transitions:
        maturity = "stable"
    elif usable_sessions >= warming_sessions and local_transition_transitions >= warming_transitions:
        maturity = "warming"
    else:
        maturity = "cold"

    prior_dominated = maturity == "cold"
    warning = ""
    if prior_dominated:
        warning = "Prediction is prior-dominated; treat confidence as low."
    elif maturity == "warming":
        warning = "Local transition model is warming up; confirm predictions against scorer evidence."

    confidence_cap = ""
    if maturity == "cold":
        confidence_cap = (
            str(thresholds.get("cold_confidence_cap"))
            if "cold_confidence_cap" in thresholds
            else "low"
        )
    elif maturity == "warming":
        confidence_cap = (
            str(thresholds.get("warming_confidence_cap"))
            if "warming_confidence_cap" in thresholds
            else ""
        )

    return {
        "local_transition_sessions": usable_sessions,
        "local_transition_transitions": local_transition_transitions,
        "tactic_transition_count": tactic_transitions,
        "prefix_transition_count": prefix_transitions,
        "technique_transition_count": technique_transitions,
        "maturity": maturity,
        "prior_dominated": prior_dominated,
        "confidence_cap": confidence_cap,
        "warning": warning,
        "thresholds": thresholds,
        "model_id": model.get("model_id", ""),
    }


def _local_transition_model_summary(model: Dict[str, Any], maturity: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "enabled": int(model.get("usable_sessions") or 0) > 0,
        "source_type": "empirical_local",
        "source_name": model.get("source_name") or "local_transition",
        "source_database": model.get("source_database") or "",
        "schema_version": model.get("schema_version", ""),
        "model_id": model.get("model_id", ""),
        "built_at": model.get("built_at", ""),
        "usable_sessions": int(model.get("usable_sessions") or 0),
        "completed_sessions": int(model.get("completed_sessions") or 0),
        "transition_count": int(_safe_float(model.get("transition_count")) + _safe_float(model.get("technique_transition_count"))),
        "tactic_transition_count": _safe_float(model.get("transition_count")),
        "prefix_transition_count": _safe_float(model.get("prefix_transition_count")),
        "technique_transition_count": _safe_float(model.get("technique_transition_count")),
        "recency_decay_half_life_sessions": _safe_float(model.get("recency_decay_half_life_sessions")),
        "maturity": maturity.get("maturity", "cold"),
        "prior_dominated": bool(maturity.get("prior_dominated")),
        "warning": maturity.get("warning", ""),
    }


def _external_seed_model_summary(model: Dict[str, Any]) -> Dict[str, Any]:
    usable_sessions = int(model.get("usable_sessions") or 0)
    tactic_transitions = int(model.get("transition_count") or 0)
    prefix_transitions = int(model.get("prefix_transition_count") or 0)
    technique_transitions = int(model.get("technique_transition_count") or 0)
    transition_total = tactic_transitions + technique_transitions
    provenance = model.get("provenance") or {}
    enabled = usable_sessions > 0 and transition_total > 0
    source_type = str(model.get("source_type") or provenance.get("source_type") or "external_cowrie_seed")
    warning = ""
    if enabled:
        warning = (
            "External Cowrie seed transition model is active; treat it as external prior "
            "until enough local sessions are available."
        )
    return {
        "enabled": enabled,
        "source_type": source_type,
        "usable_sessions": usable_sessions,
        "transition_count": transition_total,
        "tactic_transition_count": tactic_transitions,
        "prefix_transition_count": prefix_transitions,
        "technique_transition_count": technique_transitions,
        "model_id": model.get("model_id", ""),
        "schema_version": model.get("schema_version", ""),
        "dataset_handle": provenance.get("dataset_handle") or model.get("dataset_handle", ""),
        "built_at": provenance.get("built_at") or model.get("built_at", ""),
        "warning": warning,
    }


def _actor_fingerprint_model_summary(model: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    config = _actor_fingerprint_policy(policy)
    fingerprint_count = int(model.get("fingerprint_count") or 0)
    transition_count = _safe_float(model.get("transition_count")) + _safe_float(model.get("prefix_transition_count"))
    enabled = bool(config["enabled"]) and fingerprint_count > 0 and transition_count > 0
    warning = ""
    if enabled:
        warning = (
            "Actor/tool fingerprint transition prior is active; it is local behavioral "
            "conditioning, not named-actor attribution."
        )
    return {
        "enabled": enabled,
        "source_type": "empirical_actor_fingerprint",
        "source_name": model.get("source_name") or "actor_fingerprint_transition",
        "schema_version": model.get("schema_version", ""),
        "model_id": model.get("model_id", ""),
        "built_at": model.get("built_at", ""),
        "usable_sessions": int(model.get("usable_sessions") or 0),
        "completed_sessions": int(model.get("completed_sessions") or 0),
        "fingerprint_count": fingerprint_count,
        "transition_count": _safe_float(model.get("transition_count")),
        "prefix_transition_count": _safe_float(model.get("prefix_transition_count")),
        "match_fields": list(model.get("match_fields") or config["match_fields"]),
        "min_sessions": int(config["min_sessions"]),
        "named_actor_attribution": False,
        "warning": warning,
    }


def _classification_quality(features: Dict[str, Any]) -> Dict[str, Any]:
    events = [event for event in features.get("classification_events") or [] if isinstance(event, dict)]
    unknown_count = 0
    shell_noise_count = 0
    audit_only_count = 0
    high_confidence_count = 0
    low_confidence_count = 0
    for event in events:
        source = str(event.get("source") or "")
        tactic = str(event.get("tactic") or "")
        ttp = main_ttp_id(event.get("ttp"))
        confidence = _safe_float(event.get("confidence"), 0.0)
        if source == "shell_noise":
            shell_noise_count += 1
        audit_only = not is_trusted_classification_event(event)
        if audit_only:
            audit_only_count += 1
        if audit_only or not tactic or tactic == "unknown" or not ttp or ttp == "unknown":
            unknown_count += 1
        if confidence >= 0.70:
            high_confidence_count += 1
        elif confidence > 0:
            low_confidence_count += 1
    validation = features.get("classification_validation") or {}
    if not isinstance(validation, dict):
        validation = {}
    validation_status = str(validation.get("status") or features.get("classification_validation_status") or "unvalidated")
    return {
        "event_count": len(events),
        "source_counts": dict(features.get("classification_source_counts") or {}),
        "unknown_count": unknown_count,
        "shell_noise_count": shell_noise_count,
        "audit_only_count": audit_only_count,
        "high_confidence_count": high_confidence_count,
        "low_confidence_count": low_confidence_count,
        "confidence_available": bool(features.get("classification_confidence_available")),
        "confidence_count": int(features.get("classification_confidence_count") or 0),
        "confidence_min": _safe_float(features.get("classification_min_confidence"), 0.0),
        "confidence_average": _safe_float(features.get("classification_average_confidence"), 0.0),
        "confidence_geomean": _safe_float(features.get("classification_chain_confidence_geomean"), 0.0),
        "validation_status": validation_status,
        "validation": validation,
    }


def _calibration_status(calibration: Dict[str, Any]) -> Dict[str, Any]:
    enabled = bool(calibration.get("enabled", False))
    min_cases = int(calibration.get("min_cases_per_bin") or 0)
    bins = [item for item in calibration.get("bins") or [] if isinstance(item, dict)]
    ready_bins = [item for item in bins if int(item.get("cases") or 0) >= min_cases]
    if not enabled:
        status = "disabled"
    elif not bins:
        status = "enabled_no_bins"
    elif len(ready_bins) < len(bins):
        status = "enabled_partially_ready"
    else:
        status = "enabled_ready"
    return {
        "enabled": enabled,
        "status": status,
        "method": str(calibration.get("method") or "empirical_binning"),
        "min_cases_per_bin": min_cases,
        "bin_count": len(bins),
        "ready_bin_count": len(ready_bins),
    }


def _external_seed_decay_multiplier(
    decay: Dict[str, Any],
    model_maturity: Dict[str, Any],
) -> tuple[float, Dict[str, Any]]:
    """Return the multiplier applied to the external seed transition weight.

    `maturity_multiplier` is the legacy heuristic: the multiplier is read
    directly from the configured maturity bucket, e.g. cold/warming/stable.
    `empirical_shrinkage` is sample-size-dependent pseudo-count shrinkage:
    local_share = n / (n + k), external_multiplier = 1 - local_share, then
    optional min/max clipping is applied. This adjusts a scorer mixing weight;
    it is not Katz backoff, which redistributes probability mass across
    lower-order n-gram models.
    """

    method = str(decay.get("method") or "maturity_multiplier").strip().lower()
    maturity = str(model_maturity.get("maturity") or "cold")
    if method == "empirical_shrinkage":
        count_source = str(decay.get("shrinkage_count_source") or "transitions").strip().lower()
        if count_source == "sessions":
            local_count = _safe_float(model_maturity.get("local_transition_sessions"), 0.0)
        else:
            count_source = "transitions"
            local_count = _safe_float(model_maturity.get("local_transition_transitions"), 0.0)
        shrinkage_k = max(_safe_float(decay.get("shrinkage_k"), 200.0), 0.0)
        local_share = local_count / (local_count + shrinkage_k) if (local_count + shrinkage_k) > 0 else 0.0
        raw_multiplier = 1.0 - local_share
        # The n/(n+k) form already constrains the raw multiplier to [0, 1].
        # Keep configurable bounds as defensive safeguards if the formula changes.
        min_multiplier = max(_safe_float(decay.get("min_multiplier"), 0.0), 0.0)
        max_multiplier = max(_safe_float(decay.get("max_multiplier"), 1.0), min_multiplier)
        multiplier = min(max(raw_multiplier, min_multiplier), max_multiplier)
        return multiplier, {
            "method": "empirical_shrinkage",
            "maturity": maturity,
            "local_evidence_count": round(local_count, 4),
            "count_source": count_source,
            "shrinkage_k": round(shrinkage_k, 4),
            "local_interpolation_weight": round(local_share, 6),
            "external_prior_multiplier_raw": round(raw_multiplier, 6),
            "min_multiplier": round(min_multiplier, 6),
            "max_multiplier": round(max_multiplier, 6),
            "reason": (
                "external_seed_transition weight scaled by empirical shrinkage "
                "using local_share=n/(n+k); this adjusts a mixing weight, not "
                "Katz backoff probability-mass redistribution"
            ),
        }

    multiplier = _safe_float(decay.get(maturity), 1.0)
    return multiplier, {
        "method": "maturity_multiplier",
        "maturity": maturity,
        "policy": {
            "cold": _safe_float(decay.get("cold"), 1.0),
            "warming": _safe_float(decay.get("warming"), 1.0),
            "stable": _safe_float(decay.get("stable"), 1.0),
        },
        "reason": f"external_seed_transition weight scaled by local model maturity '{maturity}'",
    }


def _effective_weights(
    configured_weights: Dict[str, Any],
    model_maturity: Dict[str, Any],
    policy: Dict[str, Any],
) -> tuple[Dict[str, float], Dict[str, Any]]:
    weights = {
        str(name): max(_safe_float(weight), 0.0)
        for name, weight in (configured_weights or {}).items()
    }
    decay = policy.get("external_seed_weight_decay") or {}
    if not isinstance(decay, dict):
        decay = {}
    enabled = bool(decay.get("enabled", False))
    maturity = str(model_maturity.get("maturity") or "cold")
    configured_external = weights.get("external_seed_transition", 0.0)
    multiplier = 1.0
    details: Dict[str, Any] = {
        "method": str(decay.get("method") or "maturity_multiplier").strip().lower() or "maturity_multiplier",
        "maturity": maturity,
        "reason": "external seed weight decay not applied",
    }
    if enabled and configured_external > 0:
        multiplier, details = _external_seed_decay_multiplier(decay, model_maturity)
        weights["external_seed_transition"] = round(configured_external * multiplier, 6)
    return weights, {
        "enabled": enabled,
        "maturity": maturity,
        "configured_weight": round(configured_external, 6),
        "multiplier": round(multiplier, 6),
        "effective_weight": round(weights.get("external_seed_transition", 0.0), 6),
        **details,
    }


def _trust_status(
    final_ranking: List[Dict[str, Any]],
    active_scorers: List[str],
    model_maturity: Dict[str, Any],
    external_seed_model: Dict[str, Any],
    classification_quality: Dict[str, Any],
    calibration_status: Dict[str, Any],
    agreement: Dict[str, Any],
) -> Dict[str, Any]:
    top_sources = list((final_ranking[0] or {}).get("sources") or []) if final_ranking else []
    dominant = ""
    if top_sources:
        dominant_item = max(top_sources, key=lambda item: _safe_float(item.get("weighted_score")))
        dominant = str(dominant_item.get("name") or "")
    warnings: List[str] = []
    if model_maturity.get("warning"):
        warnings.append(str(model_maturity["warning"]))
    if external_seed_model.get("warning") and "external_seed_transition" in active_scorers:
        warnings.append(str(external_seed_model["warning"]))
    if agreement.get("warning"):
        warnings.append(str(agreement["warning"]))
    if classification_quality.get("validation_status") in {"", "unvalidated"}:
        warnings.append("Classification validation baseline is not available yet.")
    if calibration_status.get("status") == "disabled":
        warnings.append("Prediction confidence calibration is disabled.")
    local_active = "local_transition" in active_scorers
    external_active = "external_seed_transition" in active_scorers
    if local_active and dominant == "local_transition":
        evidence_posture = "local_dominated"
    elif external_active and dominant == "external_seed_transition":
        evidence_posture = "external_prior_dominated"
    elif local_active:
        evidence_posture = "local_supported"
    elif external_active:
        evidence_posture = "external_prior_supported"
    else:
        evidence_posture = "heuristic_or_context_only"
    return {
        "status": "review_required" if warnings else "nominal",
        "evidence_posture": evidence_posture,
        "dominant_source": dominant,
        "local_model_maturity": model_maturity.get("maturity", "cold"),
        "local_transition_active": local_active,
        "external_prior_active": external_active,
        "classification_validation_status": classification_quality.get("validation_status", "unvalidated"),
        "calibration_status": calibration_status.get("status", "disabled"),
        "scorer_disagreement": bool(agreement.get("disagreement")),
        "warnings": warnings,
    }


def _detect_agreement(
    raw_by_scorer: Dict[str, List[Hypothesis]],
    final_ranking: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if not final_ranking:
        return {
            "top_tactic": "",
            "top_by_scorer": {},
            "supporting_scorers": [],
            "divergent_scorers": [],
            "disagreement": False,
            "divergence_ratio": 0.0,
            "warning": "",
        }
    top_tactic = str(final_ranking[0].get("tactic") or "")
    top_by_scorer: Dict[str, str] = {}
    for scorer, hypotheses in raw_by_scorer.items():
        if not hypotheses:
            continue
        top = max(hypotheses, key=lambda item: float(item.score))
        if top.tactic:
            top_by_scorer[scorer] = top.tactic
    supporting = [scorer for scorer, tactic in top_by_scorer.items() if tactic == top_tactic]
    divergent = [scorer for scorer, tactic in top_by_scorer.items() if tactic != top_tactic]
    denominator = max(len(top_by_scorer), 1)
    divergence_ratio = round(len(divergent) / denominator, 4)
    warning = ""
    if divergence_ratio > 0.5:
        warning = "Majority of active scorers disagree with top prediction; confidence may be overstated."
    elif divergent:
        warning = "Some active scorers disagree with the top prediction."
    return {
        "top_tactic": top_tactic,
        "top_by_scorer": top_by_scorer,
        "supporting_scorers": supporting,
        "divergent_scorers": divergent,
        "disagreement": bool(divergent),
        "divergence_ratio": divergence_ratio,
        "warning": warning,
    }


class RealtimePredictionEngine:
    name = "realtime_prediction"
    version = "1.0"

    def __init__(
        self,
        policy: Dict[str, Any] | None = None,
        scorers: List[Scorer] | None = None,
        risk_annotators: List[Scorer] | None = None,
        transition_model: Dict[str, Any] | None = None,
        external_transition_model: Dict[str, Any] | None = None,
        actor_fingerprint_transition_model: Dict[str, Any] | None = None,
    ) -> None:
        merged = _merge_policy(DEFAULT_PREDICTION_POLICY, policy)
        self.policy = merged
        self.transition_model = transition_model or build_transition_model([])
        self.external_transition_model = external_transition_model or build_transition_model([])
        self.actor_fingerprint_transition_model = (
            actor_fingerprint_transition_model
            or build_actor_fingerprint_transition_model([], merged)
        )
        external_provenance = self.external_transition_model.get("provenance") or {}
        self.scorers = scorers or [
            LocalTransitionScorer(
                transition_model=self.transition_model,
                min_sessions=int(merged.get("min_sessions_for_local", 50)),
                min_transition_count=int(merged.get("min_transition_count", 2)),
                min_prefix_transition_count=int(merged.get("min_prefix_transition_count", merged.get("min_transition_count", 2))),
                min_technique_transition_count=int(merged.get("min_technique_transition_count", merged.get("min_transition_count", 2))),
                min_tactic_transition_count=int(merged.get("min_tactic_transition_count", merged.get("min_transition_count", 2))),
                prefix_max_length=int(merged.get("prefix_max_length", 3)),
                smoothing=float(merged.get("transition_smoothing", 0.05)),
            ),
            LocalTransitionScorer(
                transition_model=self.external_transition_model,
                min_sessions=int(merged.get("external_min_sessions", merged.get("min_sessions_for_local", 50))),
                min_transition_count=int(merged.get("external_min_transition_count", merged.get("min_transition_count", 2))),
                min_prefix_transition_count=int(merged.get("external_min_prefix_transition_count", merged.get("external_min_transition_count", merged.get("min_prefix_transition_count", 2)))),
                min_technique_transition_count=int(merged.get("external_min_technique_transition_count", merged.get("external_min_transition_count", merged.get("min_technique_transition_count", 2)))),
                min_tactic_transition_count=int(merged.get("external_min_tactic_transition_count", merged.get("external_min_transition_count", merged.get("min_tactic_transition_count", 2)))),
                prefix_max_length=int(merged.get("prefix_max_length", 3)),
                smoothing=float(merged.get("transition_smoothing", 0.05)),
                name="external_seed_transition",
                source_type=str(
                    self.external_transition_model.get("source_type")
                    or external_provenance.get("source_type")
                    or "external_cowrie_seed"
                ),
                evidence_sources=[
                    str(
                        external_provenance.get("dataset_handle")
                        or self.external_transition_model.get("dataset_handle")
                        or "external Cowrie honeypot seed dataset"
                    )
                ],
                reason_prefix="external Cowrie seed history observed",
                training_source=str(
                    external_provenance.get("training_source")
                    or "external_cowrie_seed.classification_events"
                ),
                provenance=external_provenance,
            ),
            ActorFingerprintTransitionScorer(
                transition_model=self.actor_fingerprint_transition_model,
                policy=merged,
            ),
            FallbackProgressionScorer(progression=merged.get("fallback_progression") or TACTIC_PROGRESSION),
            TacticCombinationScorer(rules=merged.get("tactic_combination_rules") or DEFAULT_TACTIC_COMBINATION_RULES),
            MitreAssociationScorer(
                rules=merged.get("mitre_association_rules") or [],
                technique_to_tactic_aggregation=str(merged.get("technique_to_tactic_aggregation") or "max"),
                technique_tactic_map=merged.get("technique_tactic_map") or {},
            ),
            SigmaCorrelationScorer(
                rules=merged.get("sigma_correlation_rules") or [],
                technique_to_tactic_aggregation=str(merged.get("technique_to_tactic_aggregation") or "max"),
                technique_tactic_map=merged.get("technique_tactic_map") or {},
            ),
            EnrichmentContextScorer(),
        ]
        risk_policy = dict(merged.get("vulnerability_risk") or {})
        risk_annotator_policy = merged.get("risk_annotators") or {}
        if isinstance(risk_annotator_policy, dict):
            vulnerability_annotator = risk_annotator_policy.get("vulnerability_risk")
            if isinstance(vulnerability_annotator, dict):
                risk_policy.update(vulnerability_annotator)
        self.risk_annotators = (
            risk_annotators
            if risk_annotators is not None
            else [VulnerabilityRiskScorer(policy=risk_policy)]
        )

    @property
    def enabled(self) -> bool:
        return bool(self.policy.get("enabled", True))

    def _classification_damping_factor(self, features: Dict[str, Any]) -> float:
        damping = self.policy.get("confidence_damping") or {}
        if not bool(damping.get("enabled", True)):
            return 1.0
        mode = str(damping.get("mode") or "geometric_mean")
        if mode == "minimum":
            key = "classification_min_confidence"
        elif mode == "average":
            key = "classification_average_confidence"
        else:
            key = "classification_chain_confidence_geomean"
        try:
            factor = float(features.get(key))
        except (TypeError, ValueError):
            factor = 1.0
        if factor <= 0 and features.get("classification_confidence_available") is False:
            return 1.0
        return min(max(factor, 0.0), 1.0)

    def _should_dampen(self, hypothesis: Hypothesis) -> bool:
        damping = self.policy.get("confidence_damping") or {}
        damped = set(damping.get("damped_scorers") or [])
        return bool(hypothesis.depends_on_classification and hypothesis.source in damped)

    def _prediction_mode(self) -> str:
        mode = str(self.policy.get("prediction_mode") or "primary_transition_with_fallback").strip()
        if mode in {"weighted_ensemble", "weighted"}:
            return "weighted_ensemble_baseline"
        if mode not in {"primary_transition_with_fallback", "weighted_ensemble_baseline"}:
            return "primary_transition_with_fallback"
        return mode

    def _primary_transition_config(self) -> Dict[str, Any]:
        config = self.policy.get("primary_transition") or {}
        if not isinstance(config, dict):
            config = {}
        source_order = (
            config.get("source_order")
            or self.policy.get("primary_transition_source_order")
            or ["local_transition", "external_seed_transition"]
        )
        if isinstance(source_order, str):
            source_order = [
                item.strip()
                for item in source_order.split(",")
                if item.strip()
            ]
        source_order = [
            str(item or "").strip()
            for item in (source_order or [])
            if str(item or "").strip()
        ] or ["local_transition", "external_seed_transition"]
        fallback_scorer = str(
            config.get("fallback_scorer")
            or self.policy.get("primary_transition_fallback_scorer")
            or "fallback_progression"
        ).strip() or "fallback_progression"
        min_transition_score = _safe_float(
            config.get("min_transition_score"),
            _safe_float(self.policy.get("min_score"), 0.01),
        )
        return {
            "primary_model": str(config.get("primary_model") or "transition_frequency"),
            "source_order": source_order,
            "fallback_scorer": fallback_scorer,
            "min_transition_score": max(min_transition_score, 0.0),
        }

    def _source_diagnostic(
        self,
        scorer_name: str,
        raw_outputs: List[Hypothesis],
        scorer_by_name: Dict[str, Scorer],
        min_transition_score: float,
    ) -> Dict[str, Any]:
        scorer = scorer_by_name.get(scorer_name)
        model: Dict[str, Any] = {}
        if scorer_name == "local_transition":
            model = self.transition_model
        elif scorer_name == "external_seed_transition":
            model = self.external_transition_model
        usable = [
            hypothesis
            for hypothesis in raw_outputs
            if hypothesis.tactic and float(hypothesis.score) >= min_transition_score
        ]
        reason = "transition evidence available"
        if not raw_outputs:
            usable_sessions = int(model.get("usable_sessions") or 0)
            min_sessions = int(getattr(scorer, "min_sessions", 0) or 0) if scorer is not None else 0
            if usable_sessions < min_sessions:
                reason = (
                    f"{scorer_name} has {usable_sessions} usable sessions; "
                    f"minimum is {min_sessions}"
                )
            else:
                reason = f"{scorer_name} produced no transition hypotheses meeting support thresholds"
        elif not usable:
            best_score = max(float(hypothesis.score) for hypothesis in raw_outputs)
            reason = (
                f"{scorer_name} best transition score {best_score:.4f} is below "
                f"minimum {min_transition_score:.4f}"
            )
        return {
            "name": scorer_name,
            "raw_output_count": len(raw_outputs),
            "usable_output_count": len(usable),
            "min_transition_score": round(min_transition_score, 4),
            "usable_sessions": int(model.get("usable_sessions") or 0),
            "transition_count": _safe_float(model.get("transition_count")),
            "prefix_transition_count": _safe_float(model.get("prefix_transition_count")),
            "technique_transition_count": _safe_float(model.get("technique_transition_count")),
            "reason": reason,
        }

    def _ranking_from_hypotheses(
        self,
        scorer_name: str,
        hypotheses: List[Hypothesis],
        scorer_by_name: Dict[str, Scorer],
        damping_factor: float,
        calibration_policy: Dict[str, Any],
        model_maturity: Dict[str, Any],
        max_hypotheses: int,
        min_score: float,
        coverage_reason: str = "",
    ) -> List[Dict[str, Any]]:
        scorer = scorer_by_name.get(scorer_name)
        combined: Dict[str, Dict[str, Any]] = {}
        for hypothesis in hypotheses:
            if not hypothesis.tactic:
                continue
            raw_score = max(float(hypothesis.score), 0.0)
            damped = self._should_dampen(hypothesis)
            adjusted_score = raw_score * damping_factor if damped else raw_score
            if adjusted_score < min_score:
                continue
            entry = combined.setdefault(
                hypothesis.tactic,
                {
                    "tactic": hypothesis.tactic,
                    "score": 0.0,
                    "reasons": [],
                    "sources": [],
                    "source_types": [],
                },
            )
            source_payload = {
                "name": scorer_name,
                "version": str(getattr(scorer, "version", "")),
                "source_type": hypothesis.source_type,
                "rule_id": hypothesis.rule_id,
                "configured_weight": round(_safe_float((self.policy.get("weights") or {}).get(scorer_name)), 4),
                "effective_weight": 1.0,
                "normalized_weight": 1.0,
                "raw_score": round(raw_score, 4),
                "adjusted_score": round(adjusted_score, 4),
                "weighted_score": round(adjusted_score, 4),
                "weighting_method": "primary_transition_no_weighted_ensemble",
                "damped_by_classification_confidence": damped,
                "damping_factor": round(damping_factor, 4) if damped else 1.0,
                "evidence_sources": list(hypothesis.evidence_sources),
                "references": list(hypothesis.references),
                "metadata": dict(hypothesis.metadata),
            }
            entry["score"] += adjusted_score
            entry["sources"].append(source_payload)
            if hypothesis.source_type and hypothesis.source_type not in entry["source_types"]:
                entry["source_types"].append(hypothesis.source_type)
            for reason in hypothesis.reasons:
                if reason not in entry["reasons"]:
                    entry["reasons"].append(reason)
            if coverage_reason and coverage_reason not in entry["reasons"]:
                entry["reasons"].append(coverage_reason)

        ranking: List[Dict[str, Any]] = []
        for entry in sorted(combined.values(), key=lambda item: item["score"], reverse=True):
            raw_score = float(entry["score"])
            calibrated_score, calibration_meta = _calibrated_score(raw_score, calibration_policy)
            label = confidence_label(calibrated_score)
            label = _cap_confidence(label, str(model_maturity.get("confidence_cap") or ""))
            reasons = list(entry.get("reasons") or [])
            if model_maturity.get("warning") and model_maturity["warning"] not in reasons:
                reasons.append(str(model_maturity["warning"]))
            ranking.append(
                {
                    **entry,
                    "reasons": reasons,
                    "score": round(raw_score, 4),
                    "calibrated_score": round(calibrated_score, 4),
                    "calibration": calibration_meta,
                    "confidence": label,
                    "coverage_below_minimum": False,
                }
            )
        if len(ranking) > max_hypotheses:
            ranking = ranking[:max_hypotheses]
        return ranking

    def _primary_transition_selection(
        self,
        raw_by_scorer: Dict[str, List[Hypothesis]],
        scorer_by_name: Dict[str, Scorer],
        features: Dict[str, Any],
        damping_factor: float,
        calibration_policy: Dict[str, Any],
        model_maturity: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = self._primary_transition_config()
        min_score = float(self.policy.get("min_score", 0.01))
        max_hypotheses = max(int(self.policy.get("max_hypotheses", 5)), 1)
        diagnostics: List[Dict[str, Any]] = []
        selected_source = ""
        selected_outputs: List[Hypothesis] = []
        for source_name in config["source_order"]:
            raw_outputs = raw_by_scorer.get(source_name, [])
            diagnostic = self._source_diagnostic(
                source_name,
                raw_outputs,
                scorer_by_name,
                float(config["min_transition_score"]),
            )
            diagnostics.append(diagnostic)
            usable = [
                hypothesis
                for hypothesis in raw_outputs
                if hypothesis.tactic and float(hypothesis.score) >= float(config["min_transition_score"])
            ]
            if usable:
                selected_source = source_name
                selected_outputs = usable
                break

        fallback_used = False
        fallback_reason = ""
        if not selected_outputs:
            fallback_used = True
            selected_source = config["fallback_scorer"]
            selected_outputs = [
                hypothesis
                for hypothesis in raw_by_scorer.get(selected_source, [])
                if hypothesis.tactic
            ]
            fallback_reason = (
                "no transition-frequency hypotheses met configured support "
                f"thresholds for primary sources: {', '.join(config['source_order'])}"
            )

        active_scorers = [selected_source] if selected_outputs else []
        ranking = self._ranking_from_hypotheses(
            selected_source,
            selected_outputs,
            scorer_by_name,
            damping_factor,
            calibration_policy,
            model_maturity,
            max_hypotheses=max_hypotheses,
            min_score=min_score,
            coverage_reason="" if active_scorers else "no primary transition or fallback scorer produced output",
        )
        active_weights = {selected_source: 1.0} if ranking and selected_source else {}
        agreement_raw = {selected_source: selected_outputs} if selected_source and selected_outputs else {}
        agreement = _detect_agreement(agreement_raw, ranking)
        transition_evidence_type = ""
        transition_count = 0.0
        evidence_count = 0.0
        transition_context = ""
        if ranking and not fallback_used:
            source = (ranking[0].get("sources") or [{}])[0]
            metadata = source.get("metadata") or {}
            transition_evidence_type = str(metadata.get("transition_type") or "")
            transition_count = _safe_float(metadata.get("transition_total"), 0.0)
            evidence_count = _safe_float(metadata.get("transition_support"), 0.0)
            transition_context = str(metadata.get("transition_context") or "")
        return {
            "prediction_mode": "primary_transition_with_fallback",
            "primary_model": config["primary_model"],
            "selected_source": selected_source,
            "fallback_used": fallback_used,
            "fallback_reason": fallback_reason,
            "transition_evidence_type": transition_evidence_type,
            "transition_context": transition_context,
            "transition_count": round(transition_count, 4),
            "evidence_count": round(evidence_count, 4),
            "checked_transition_sources": diagnostics,
            "ranking": ranking,
            "active_scorers": active_scorers,
            "active_weights": active_weights,
            "agreement": agreement,
            "coverage": {
                "active_scorer_count": len(active_scorers),
                "min_active_scorers": 1,
                "below_minimum": not bool(active_scorers),
                "reason": "" if active_scorers else "no primary transition or fallback scorer produced output",
            },
        }

    def predict(
        self,
        features: Dict[str, Any],
        event_id: str = "",
    ) -> Dict[str, Any]:
        configured_weights = self.policy.get("weights") or {}
        enrichment_mode = _enrichment_context_mode(self.policy)
        scorer_outputs: Dict[str, List[Dict[str, Any]]] = {}
        raw_by_scorer: Dict[str, List[Hypothesis]] = {}
        risk_by_annotator: Dict[str, List[Hypothesis]] = {}
        combined: Dict[str, Dict[str, Any]] = {}

        for scorer in self.scorers:
            raw_outputs = scorer.score(features)
            raw_by_scorer[scorer.name] = raw_outputs
            scorer_outputs[scorer.name] = [hypothesis.to_dict() for hypothesis in raw_outputs]

        for annotator in self.risk_annotators:
            raw_outputs = annotator.score(features)
            risk_by_annotator[annotator.name] = raw_outputs
            scorer_outputs[annotator.name] = [hypothesis.to_dict() for hypothesis in raw_outputs]

        model_maturity = _model_maturity(self.transition_model, self.policy)
        risk_annotator_names = {annotator.name for annotator in self.risk_annotators}
        ranking_configured_weights = {
            name: value
            for name, value in configured_weights.items()
            if name not in risk_annotator_names
        }
        if enrichment_mode != "scorer":
            ranking_configured_weights["enrichment_context"] = 0.0
        weights, external_seed_weight_policy = _effective_weights(
            ranking_configured_weights,
            model_maturity,
            self.policy,
        )
        active_scorers = [
            name
            for name, outputs in raw_by_scorer.items()
            if outputs and float(weights.get(name, 0.0)) > 0.0
        ]
        active_weight_total = sum(float(weights.get(name, 0.0)) for name in active_scorers)
        active_weights = {
            name: round(float(weights.get(name, 0.0)) / active_weight_total, 4)
            for name in active_scorers
        } if active_weight_total > 0 else {}
        damping_factor = self._classification_damping_factor(features)
        local_transition_model = _local_transition_model_summary(self.transition_model, model_maturity)
        external_seed_model = _external_seed_model_summary(self.external_transition_model)
        actor_fingerprint_model = _actor_fingerprint_model_summary(self.actor_fingerprint_transition_model, self.policy)
        classification_quality = _classification_quality(features)
        behavior_regime = classify_behavior_regime(features, self.policy.get("behavior_regime_classifier") or {})
        calibration_status = _calibration_status(self.policy.get("calibration") or {})
        min_active_scorers = int(self.policy.get("min_active_scorers", 1) or 1)
        coverage_below_minimum = len(active_scorers) < min_active_scorers
        coverage_reason = (
            f"insufficient scorer coverage: {len(active_scorers)} active scorer(s); "
            f"configured minimum is {min_active_scorers}"
            if coverage_below_minimum
            else ""
        )

        scorer_contributions: Dict[str, Dict[str, Any]] = {}
        for scorer in self.scorers:
            normalized_weight = active_weights.get(scorer.name, 0.0)
            scorer_contributions[scorer.name] = {
                "active": scorer.name in active_scorers,
                "configured_weight": round(float(configured_weights.get(scorer.name, 0.0)), 4),
                "effective_weight": round(float(weights.get(scorer.name, 0.0)), 4),
                "active_weight": normalized_weight,
                "outputs": [],
            }
            for hypothesis in raw_by_scorer.get(scorer.name, []):
                raw_score = max(float(hypothesis.score), 0.0)
                damped = self._should_dampen(hypothesis)
                adjusted_score = raw_score * damping_factor if damped else raw_score
                weighted_score = adjusted_score * normalized_weight
                contribution_payload = {
                    "tactic": hypothesis.tactic,
                    "technique": hypothesis.technique,
                    "rule_id": hypothesis.rule_id,
                    "source_type": hypothesis.source_type,
                    "raw_score": round(raw_score, 4),
                    "adjusted_score": round(adjusted_score, 4),
                    "contribution": round(weighted_score, 4),
                    "damped_by_classification_confidence": damped,
                    "damping_factor": round(damping_factor, 4) if damped else 1.0,
                    "evidence_sources": list(hypothesis.evidence_sources),
                }
                scorer_contributions[scorer.name]["outputs"].append(contribution_payload)
                if normalized_weight <= 0:
                    continue
                tactic = hypothesis.tactic
                entry = combined.setdefault(
                    tactic,
                    {
                        "tactic": tactic,
                        "score": 0.0,
                        "reasons": [],
                        "sources": [],
                        "source_types": [],
                    },
                )
                source_payload = {
                    "name": scorer.name,
                    "version": scorer.version,
                    "source_type": hypothesis.source_type,
                    "rule_id": hypothesis.rule_id,
                    "configured_weight": round(float(configured_weights.get(scorer.name, 0.0)), 4),
                    "effective_weight": round(float(weights.get(scorer.name, 0.0)), 4),
                    "normalized_weight": normalized_weight,
                    "raw_score": round(raw_score, 4),
                    "adjusted_score": round(adjusted_score, 4),
                    "weighted_score": round(weighted_score, 4),
                    "damped_by_classification_confidence": damped,
                    "damping_factor": round(damping_factor, 4) if damped else 1.0,
                    "evidence_sources": list(hypothesis.evidence_sources),
                    "references": list(hypothesis.references),
                    "metadata": dict(hypothesis.metadata),
                }
                score_delta = _apply_rule_prior_deduplication(
                    entry,
                    _rule_prior_deduplication_key(hypothesis, self.policy),
                    source_payload,
                    contribution_payload,
                    weighted_score,
                    self.policy,
                )
                entry["score"] += score_delta
                entry["sources"].append(source_payload)
                if hypothesis.source_type and hypothesis.source_type not in entry["source_types"]:
                    entry["source_types"].append(hypothesis.source_type)
                for reason in hypothesis.reasons:
                    if reason not in entry["reasons"]:
                        entry["reasons"].append(reason)
                if coverage_reason and coverage_reason not in entry["reasons"]:
                    entry["reasons"].append(coverage_reason)

        min_score = float(self.policy.get("min_score", 0.01))
        max_hypotheses = max(int(self.policy.get("max_hypotheses", 5)), 1)
        ranking = []
        calibration_policy = self.policy.get("calibration") or {}
        enrichment_context_summary = _enrichment_multiplier_summary(enrichment_mode, self.policy)
        for entry in sorted(combined.values(), key=lambda item: item["score"], reverse=True):
            if float(entry["score"]) < min_score:
                continue
            raw_combined_score = float(entry["score"])
            calibrated_score, calibration_meta = _calibrated_score(raw_combined_score, calibration_policy)
            label = confidence_label(calibrated_score)
            if coverage_below_minimum and str(self.policy.get("below_minimum_behavior")) == "low_confidence_flag":
                label = "low"
            label = _cap_confidence(label, str(model_maturity.get("confidence_cap") or ""))
            reasons = list(entry.get("reasons") or [])
            if model_maturity.get("warning") and model_maturity["warning"] not in reasons:
                reasons.append(str(model_maturity["warning"]))
            entry_payload = {
                key: value
                for key, value in entry.items()
                if not str(key).startswith("_")
            }
            ranking.append(
                {
                    **entry_payload,
                    "reasons": reasons,
                    "score": round(raw_combined_score, 4),
                    "calibrated_score": round(calibrated_score, 4),
                    "calibration": calibration_meta,
                    "confidence": label,
                    "coverage_below_minimum": coverage_below_minimum,
                }
            )

        if enrichment_mode == "score_multiplier":
            enrichment_context_summary = _apply_enrichment_context_multiplier(
                ranking,
                raw_by_scorer.get("enrichment_context", []),
                self.policy,
                calibration_policy,
            )
        if len(ranking) > max_hypotheses:
            ranking = ranking[:max_hypotheses]

        agreement_raw_by_scorer = {
            name: raw_by_scorer.get(name, [])
            for name in active_scorers
        }
        agreement = _detect_agreement(agreement_raw_by_scorer, ranking)
        confidence_control_summary = _apply_confidence_controls(
            ranking,
            active_scorers,
            agreement,
            classification_quality,
            self.policy,
        )
        if agreement.get("warning") and ranking:
            top_reasons = ranking[0].setdefault("reasons", [])
            if agreement["warning"] not in top_reasons:
                top_reasons.append(agreement["warning"])
        trust_status = _trust_status(
            ranking,
            active_scorers,
            model_maturity,
            external_seed_model,
            classification_quality,
            calibration_status,
            agreement,
        )
        risk_annotation = _risk_annotation_from_outputs(risk_by_annotator)
        prediction_mode = self._prediction_mode()
        weighted_ensemble_baseline: Dict[str, Any]
        if prediction_mode == "weighted_ensemble_baseline":
            weighted_ensemble_baseline = {
                "computed": False,
                "reason": "weighted ensemble is the active prediction mode",
            }
        elif bool(self.policy.get("compute_weighted_ensemble_baseline", True)):
            weighted_ensemble_baseline = {
                "computed": True,
                "prediction_mode": "weighted_ensemble_baseline",
                "final_ranking": deepcopy(ranking),
                "prediction": [item["tactic"] for item in ranking],
                "active_scorers": list(active_scorers),
                "active_weights": dict(active_weights),
                "effective_weights": dict(weights),
                "coverage": {
                    "active_scorer_count": len(active_scorers),
                    "min_active_scorers": min_active_scorers,
                    "below_minimum": coverage_below_minimum,
                    "reason": coverage_reason,
                },
                "agreement": deepcopy(agreement),
                "confidence_controls": deepcopy(confidence_control_summary),
            }
        else:
            weighted_ensemble_baseline = {
                "computed": False,
                "reason": "disabled by compute_weighted_ensemble_baseline policy setting",
            }

        primary_transition_summary: Dict[str, Any] = {
            "selected_source": "",
            "checked_transition_sources": [],
        }
        fallback_used = False
        fallback_reason = ""
        primary_model = "weighted_ensemble"
        transition_evidence_type = ""
        transition_context = ""
        transition_count = 0.0
        evidence_count = 0.0
        if prediction_mode == "primary_transition_with_fallback":
            primary_selection = self._primary_transition_selection(
                raw_by_scorer,
                {scorer.name: scorer for scorer in self.scorers},
                features,
                damping_factor,
                calibration_policy,
                model_maturity,
            )
            ranking = primary_selection["ranking"]
            active_scorers = primary_selection["active_scorers"]
            active_weights = primary_selection["active_weights"]
            agreement = primary_selection["agreement"]
            coverage = primary_selection["coverage"]
            min_active_scorers = int(coverage["min_active_scorers"])
            coverage_below_minimum = bool(coverage["below_minimum"])
            coverage_reason = str(coverage.get("reason") or "")
            confidence_control_summary = _apply_confidence_controls(
                ranking,
                active_scorers,
                agreement,
                classification_quality,
                self.policy,
            )
            if agreement.get("warning") and ranking:
                top_reasons = ranking[0].setdefault("reasons", [])
                if agreement["warning"] not in top_reasons:
                    top_reasons.append(agreement["warning"])
            trust_status = _trust_status(
                ranking,
                active_scorers,
                model_maturity,
                external_seed_model,
                classification_quality,
                calibration_status,
                agreement,
            )
            primary_model = str(primary_selection["primary_model"])
            fallback_used = bool(primary_selection["fallback_used"])
            fallback_reason = str(primary_selection.get("fallback_reason") or "")
            transition_evidence_type = str(primary_selection.get("transition_evidence_type") or "")
            transition_context = str(primary_selection.get("transition_context") or "")
            transition_count = _safe_float(primary_selection.get("transition_count"), 0.0)
            evidence_count = _safe_float(primary_selection.get("evidence_count"), 0.0)
            primary_transition_summary = {
                "primary_model": primary_model,
                "selected_source": str(primary_selection.get("selected_source") or ""),
                "source_order": self._primary_transition_config()["source_order"],
                "fallback_scorer": self._primary_transition_config()["fallback_scorer"],
                "fallback_used": fallback_used,
                "fallback_reason": fallback_reason,
                "transition_evidence_type": transition_evidence_type,
                "transition_context": transition_context,
                "transition_count": round(transition_count, 4),
                "evidence_count": round(evidence_count, 4),
                "checked_transition_sources": primary_selection["checked_transition_sources"],
            }

        snapshot = {
            "schema_version": "prediction_snapshot.v1",
            "engine": {"name": self.name, "version": self.version},
            "prediction_mode": prediction_mode,
            "primary_model": primary_model,
            "fallback_used": fallback_used,
            "fallback_reason": fallback_reason,
            "transition_evidence_type": transition_evidence_type,
            "transition_context": transition_context,
            "transition_count": round(transition_count, 4),
            "evidence_count": round(evidence_count, 4),
            "session_id": features.get("session_id", "unknown"),
            "src_ip": features.get("src_ip", "unknown"),
            "session_status": features.get("status", "active"),
            "event_id": event_id,
            "features_hash": features.get("features_hash") or stable_id("features", features),
            "generated_at": utc_now(),
            "weights": configured_weights,
            "effective_weights": weights,
            "active_weights": active_weights,
            "active_scorers": active_scorers,
            "external_seed_weight_policy": external_seed_weight_policy,
            "enrichment_context_mode": enrichment_context_summary,
            "coverage": {
                "active_scorer_count": len(active_scorers),
                "min_active_scorers": min_active_scorers,
                "below_minimum": coverage_below_minimum,
                "reason": coverage_reason,
            },
            "model_maturity": model_maturity,
            "local_transition_model": local_transition_model,
            "external_seed_model": external_seed_model,
            "actor_fingerprint_model": actor_fingerprint_model,
            "classification_quality": classification_quality,
            "behavior_regime": behavior_regime,
            "calibration_status": calibration_status,
            "trust_status": trust_status,
            "agreement": agreement,
            "confidence_controls": confidence_control_summary,
            "primary_transition": primary_transition_summary,
            "weighted_ensemble_baseline": weighted_ensemble_baseline,
            "confidence_damping": {
                "enabled": bool((self.policy.get("confidence_damping") or {}).get("enabled", True)),
                "mode": str((self.policy.get("confidence_damping") or {}).get("mode") or "geometric_mean"),
                "factor": round(damping_factor, 4),
                "damped_scorers": list((self.policy.get("confidence_damping") or {}).get("damped_scorers") or []),
            },
            "features": features,
            "scorer_outputs": scorer_outputs,
            "scorer_contributions": scorer_contributions,
            "risk_annotation": risk_annotation,
            "final_ranking": ranking,
            "prediction": [item["tactic"] for item in ranking],
        }
        snapshot["snapshot_id"] = stable_id(
            "predsnap",
            {
                "session_id": snapshot["session_id"],
                "event_id": event_id,
                "features_hash": snapshot["features_hash"],
                "ranking": snapshot["final_ranking"],
            },
        )
        return snapshot
