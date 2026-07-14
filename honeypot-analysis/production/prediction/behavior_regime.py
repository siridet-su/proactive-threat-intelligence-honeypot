"""Transparent behavioral-regime features for prediction research.

The classifier estimates whether a session looks automated/scripted or
human-operated/exploratory from simple threshold features. It is a meta-model
for later adaptive weighting experiments, not a direct next-tactic predictor,
and its output must remain metadata-only until offline evaluation justifies
using it to change scorer weights.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
PATH_RE = re.compile(r"(?<!\w)/(?:tmp|var|dev|proc|etc|home|root)[^\s;|&]*", re.IGNORECASE)


DEFAULT_BEHAVIOR_REGIME_POLICY: Dict[str, Any] = {
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
}


def behavior_regime_policy(policy: Dict[str, Any] | None) -> Dict[str, Any]:
    raw = dict(policy or {})
    merged = dict(DEFAULT_BEHAVIOR_REGIME_POLICY)
    for key, value in raw.items():
        if key == "feature_weights" and isinstance(value, dict):
            weights = dict(merged["feature_weights"])
            weights.update(value)
            merged["feature_weights"] = weights
        else:
            merged[key] = value
    merged["enabled"] = bool(merged.get("enabled", True))
    for key in (
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
        try:
            merged[key] = max(float(merged.get(key) or 0.0), 0.0)
        except (TypeError, ValueError):
            merged[key] = float(DEFAULT_BEHAVIOR_REGIME_POLICY[key])
    merged["min_commands"] = int(merged["min_commands"])
    weights = {}
    for key, value in (merged.get("feature_weights") or {}).items():
        try:
            weights[str(key)] = max(float(value), 0.0)
        except (TypeError, ValueError):
            weights[str(key)] = 0.0
    merged["feature_weights"] = weights or dict(DEFAULT_BEHAVIOR_REGIME_POLICY["feature_weights"])
    return merged


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def command_timing_events(
    raw_events: Iterable[Dict[str, Any]],
    classification_events: Iterable[Dict[str, Any]] | None = None,
    current_event: Dict[str, Any] | None = None,
) -> List[Dict[str, str]]:
    """Return timestamped commands without copying full Cowrie raw events."""

    rows: List[Dict[str, str]] = []
    seen = set()

    def add_row(timestamp: Any, command: Any, source: str) -> None:
        command_text = str(command or "").strip()
        timestamp_text = str(timestamp or "").strip()
        if not command_text:
            return
        key = (timestamp_text, command_text, source)
        if key in seen:
            return
        seen.add(key)
        rows.append({"timestamp": timestamp_text, "command": command_text, "source": source})

    for event in raw_events or []:
        if not isinstance(event, dict):
            continue
        eventid = str(event.get("eventid") or "")
        if eventid.startswith("cowrie.command."):
            add_row(event.get("timestamp"), event.get("input") or event.get("command"), "raw_event")
    if current_event and isinstance(current_event, dict):
        eventid = str(current_event.get("eventid") or "")
        if eventid.startswith("cowrie.command."):
            add_row(current_event.get("timestamp"), current_event.get("input") or current_event.get("command"), "current_event")
    for event in classification_events or []:
        if not isinstance(event, dict):
            continue
        if not event.get("timestamp"):
            continue
        add_row(event.get("timestamp"), event.get("command") or event.get("subcommand"), "classification_event")

    rows.sort(key=lambda item: parse_timestamp(item.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc))
    return rows


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _linear_score(value: float, low: float, high: float) -> float:
    if high <= low:
        return 1.0 if value >= high else 0.0
    if value <= low:
        return 0.0
    if value >= high:
        return 1.0
    return (value - low) / (high - low)


def _inverse_linear_score(value: float, low: float, high: float) -> float:
    return 1.0 - _linear_score(value, low, high)


def _command_entropy(commands: List[str]) -> float:
    text = "\n".join(commands)
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _normalize_command(command: str) -> str:
    text = URL_RE.sub("URL", command.lower())
    text = IP_RE.sub("IP", text)
    text = HASH_RE.sub("HASH", text)
    text = PATH_RE.sub(" PATH", text)
    return " ".join(text.split())


def _payload_diversity(commands: List[str]) -> float:
    if not commands:
        return 0.0
    normalized = {_normalize_command(command) for command in commands if command.strip()}
    return len(normalized) / len(commands)


def _timing_features(features: Dict[str, Any], commands: List[str]) -> Dict[str, Any]:
    rows = [row for row in features.get("command_timing_events") or [] if isinstance(row, dict)]
    parsed = [
        parse_timestamp(row.get("timestamp"))
        for row in rows
        if str(row.get("command") or "").strip()
    ]
    parsed = [item for item in parsed if item is not None]
    delays: List[float] = []
    window = 0.0
    if len(parsed) >= 2:
        parsed = sorted(parsed)
        window = max((parsed[-1] - parsed[0]).total_seconds(), 0.0)
        delays = [
            max((right - left).total_seconds(), 0.0)
            for left, right in zip(parsed, parsed[1:])
        ]
    elif features.get("duration") not in (None, ""):
        window = max(_safe_float(features.get("duration"), 0.0), 0.0)

    frequency = (len(commands) / (window / 60.0)) if window > 0 else 0.0
    variance = 0.0
    if len(delays) >= 2:
        mean = sum(delays) / len(delays)
        variance = sum((delay - mean) ** 2 for delay in delays) / len(delays)
    return {
        "timestamped_command_count": len(parsed),
        "observation_window_seconds": round(window, 4),
        "command_frequency_per_minute": round(frequency, 4),
        "inter_command_delays_seconds": [round(delay, 4) for delay in delays],
        "inter_command_delay_variance_seconds2": round(variance, 4),
    }


def classify_behavior_regime(features: Dict[str, Any], policy: Dict[str, Any] | None = None) -> Dict[str, Any]:
    config = behavior_regime_policy(policy)
    commands = [
        str(command or "").strip()
        for command in features.get("commands") or []
        if str(command or "").strip()
    ]
    timing = _timing_features(features, commands)
    entropy = _command_entropy(commands)
    diversity = _payload_diversity(commands)
    raw_features = {
        "command_count": len(commands),
        **timing,
        "command_entropy_bits_per_char": round(entropy, 4),
        "payload_diversity": round(diversity, 4),
    }
    if not config["enabled"]:
        return {
            "schema_version": "behavior_regime.v1",
            "enabled": False,
            "regime": "disabled",
            "automation_confidence": 0.0,
            "affects_weights": False,
            "raw_features": raw_features,
            "thresholds": config,
            "feature_scores": {},
            "reason": "behavior regime classifier disabled",
        }
    if len(commands) < int(config["min_commands"]):
        return {
            "schema_version": "behavior_regime.v1",
            "enabled": True,
            "regime": "insufficient_evidence",
            "automation_confidence": 0.0,
            "affects_weights": False,
            "raw_features": raw_features,
            "thresholds": config,
            "feature_scores": {},
            "reason": f"needs at least {int(config['min_commands'])} commands",
        }

    frequency_score = _linear_score(
        float(raw_features["command_frequency_per_minute"]),
        float(config["human_command_rate_per_minute"]),
        float(config["automated_command_rate_per_minute"]),
    )
    variance = float(raw_features["inter_command_delay_variance_seconds2"])
    regularity_score = _inverse_linear_score(
        variance,
        float(config["low_delay_variance_seconds2"]),
        float(config["high_delay_variance_seconds2"]),
    ) if len(raw_features["inter_command_delays_seconds"]) >= 2 else 0.0
    entropy_score = _linear_score(
        entropy,
        float(config["low_entropy_bits_per_char"]),
        float(config["high_entropy_bits_per_char"]),
    )
    repetition_score = _inverse_linear_score(
        diversity,
        float(config["low_payload_diversity"]),
        float(config["high_payload_diversity"]),
    )
    feature_scores = {
        "command_frequency": round(frequency_score, 4),
        "delay_regularity": round(regularity_score, 4),
        "command_entropy": round(entropy_score, 4),
        "payload_repetition": round(repetition_score, 4),
    }
    weights = dict(config.get("feature_weights") or {})
    weight_total = sum(max(float(value), 0.0) for value in weights.values())
    if weight_total <= 0:
        weight_total = 1.0
        weights = {key: 1.0 for key in feature_scores}
    confidence = sum(
        float(feature_scores.get(key, 0.0)) * max(float(weights.get(key, 0.0)), 0.0)
        for key in feature_scores
    ) / weight_total
    confidence = min(max(confidence, 0.0), 1.0)

    if confidence >= float(config["automated_threshold"]):
        regime = "automated_scripted"
    elif confidence <= float(config["human_threshold"]):
        regime = "human_exploratory"
    else:
        regime = "mixed_or_uncertain"
    return {
        "schema_version": "behavior_regime.v1",
        "enabled": True,
        "regime": regime,
        "automation_confidence": round(confidence, 4),
        "human_confidence": round(1.0 - confidence, 4),
        "affects_weights": False,
        "raw_features": raw_features,
        "thresholds": config,
        "feature_scores": feature_scores,
        "reason": "metadata only; does not change scorer weights without separate evaluation",
    }
