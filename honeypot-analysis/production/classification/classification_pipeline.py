"""Notebook-parity command classification for production session monitoring.

This module moves the runtime parts of notebook cell 3A into importable code:

- full rule table used for Cowrie shell commands
- shell-noise prefilter that does not drop rule-attributable commands
- rule/SecureBERT merge where deterministic rules win for raw shell commands
- optional auto-label helper for training data preparation
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from production.policies.validate_classification_rules import (
    validate_classification_rule_policy,
)
from production.semantics.command_operations import (
    parse_command_operation,
    structural_predicate_matches,
)
from production.classification.authority import (
    CLASSIFICATION_EVENT_SCHEMA_VERSION,
    SCHEMA_VERSION as AUTHORITY_DECISION_SCHEMA,
    candidate_authority_decision,
    command_authority_decision,
)
from production.utils.sensitive_data import redact_exception_for_log


@dataclass
class TTPPrediction:
    tid: str
    name: str
    confidence: float
    high_conf: bool
    source: str = ""
    rule_id: str = ""
    evidence_type: str = ""
    authority_decision: Optional[Dict[str, Any]] = None

    def to_event(self, command: str, tactic: str = "unknown") -> Dict[str, Any]:
        event = {
            "classification_event_schema": CLASSIFICATION_EVENT_SCHEMA_VERSION,
            "command": command,
            "ttp": None if self.tid == "T0000_UNKNOWN" else self.tid,
            "tactic": tactic,
            "source": self.source,
            "confidence": self.confidence,
            "name": self.name,
            "high_confidence": self.high_conf,
        }
        if self.rule_id:
            event["rule_id"] = self.rule_id
        if self.evidence_type:
            event["evidence_type"] = self.evidence_type
        if self.authority_decision is not None:
            event["authority_decision"] = dict(self.authority_decision)
        return event


@dataclass
class MergedResult:
    command: str
    bert_ttps: List[TTPPrediction]
    rule_ttps: List[TTPPrediction]
    source: str

    @property
    def final_ttps(self) -> List[TTPPrediction]:
        # Notebook behavior: rules are authoritative for raw shell commands.
        if self.rule_ttps:
            return [prediction for prediction in self.rule_ttps if prediction.high_conf]
        return [p for p in self.bert_ttps if p.high_conf]


@dataclass
class ClassificationResult:
    session_root: str
    session_pid: int
    cmd_ttps: List[TTPPrediction]
    session_top3: List[TTPPrediction]

    @property
    def high_conf_ids(self) -> List[str]:
        seen, out = set(), []
        for pred in self.cmd_ttps + self.session_top3:
            if pred.high_conf and pred.tid not in seen and pred.tid != "T0000_UNKNOWN":
                seen.add(pred.tid)
                out.append(pred.tid)
        return out


@dataclass(frozen=True)
class CommandFragment:
    text: str
    index: int
    count: int
    operator_before: str = ""
    operator_after: str = ""


CLASSIFICATION_RULE_POLICY_SCHEMA = "classification_rule_policy.v3"
DEFAULT_CLASSIFICATION_RULE_POLICY = "configs/classification_rules.trusted.json"

# Minimal emergency fallback only. Full command coverage lives in the versioned
# classification policy file so mappings are auditable and replaceable without
# editing Python code.
EMERGENCY_RULE_SPECS: List[Tuple[str, str, str]] = [
    (r"\bwhoami\b", "T1033", "System Owner/User Discovery"),
    (r"\buname\b.*-[asr]", "T1082", "System Information Discovery"),
    (r"\bcat\s+/etc/(passwd|shadow)\b", "T1003", "OS Credential Dumping"),
    (r"\b(curl|wget)\b.*http", "T1105", "Ingress Tool Transfer"),
    (r"\bhistory\s+-c\b|\brm\b.*bash_history", "T1070", "Indicator Removal"),
]


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _candidate_policy_paths(path_text: str = "") -> List[Path]:
    if path_text:
        return [Path(path_text)]
    env_path = os.getenv("CLASSIFICATION_RULES_PATH", "")
    if env_path:
        return [Path(env_path)]
    module_root = Path(__file__).resolve().parents[1]
    return [
        Path.cwd() / DEFAULT_CLASSIFICATION_RULE_POLICY,
        module_root / DEFAULT_CLASSIFICATION_RULE_POLICY,
    ]


def _attack_url(ttp: str) -> str:
    return f"https://attack.mitre.org/techniques/{_clean_text(ttp).upper().replace('.', '/')}/"


def load_classification_rule_policy(path_text: str = "") -> Dict[str, Any]:
    errors: List[str] = []
    explicitly_configured = bool(
        _clean_text(path_text) or _clean_text(os.getenv("CLASSIFICATION_RULES_PATH", ""))
    )
    for path in _candidate_policy_paths(path_text):
        try:
            if not path.exists():
                errors.append(f"not found: {path}")
                continue
            raw = path.read_bytes()
            loaded = json.loads(raw.decode("utf-8"))
            if not isinstance(loaded, dict):
                errors.append(f"JSON root must be object: {path}")
                continue
            validation_errors = validate_classification_rule_policy(loaded)
            if validation_errors:
                errors.extend(
                    f"{path}: {error}" for error in validation_errors
                )
                continue
            loaded.setdefault("source_path", str(path))
            loaded["source_sha256"] = hashlib.sha256(raw).hexdigest()
            loaded["load_status"] = "loaded"
            return loaded
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(redact_exception_for_log(exc))
    if explicitly_configured:
        return {
            "schema_version": CLASSIFICATION_RULE_POLICY_SCHEMA,
            "policy_id": "configured-policy-unavailable",
            "version": "0",
            "source_path": "configured_path_unavailable",
            "source_sha256": "",
            "load_status": "invalid",
            "load_errors": errors,
            "policy": {
                "enabled": False,
                "rule_review_mode": "reviewed_only",
                "rules": [],
            },
        }
    return {
        "schema_version": CLASSIFICATION_RULE_POLICY_SCHEMA,
        "policy_id": "emergency-python-fallback",
        "version": "0",
        "source_path": "python:production.classification.classification_pipeline.EMERGENCY_RULE_SPECS",
        "source_sha256": "",
        "load_status": "emergency_audit_only",
        "load_errors": errors,
        "policy": {
            "enabled": True,
            "rules": [
                {
                    "rule_id": f"emergency-{idx:02d}-{tid.lower()}",
                    "enabled": True,
                    "pattern": pattern,
                    "ttp": tid,
                    "technique_name": name,
                    "confidence": 1.0,
                    "source_type": "emergency_python_fallback",
                    "evidence_type": "command_regex",
                    "references": [{"name": f"MITRE ATT&CK {tid} {name}", "url": _attack_url(tid)}],
                    "provenance": {
                        "method": "minimal_emergency_python_fallback",
                        "basis": ["Classification policy file was unavailable"],
                        "author": "production.classification.classification_pipeline",
                        "reviewed": False,
                        "generated": False,
                        "created": "2026-06-02",
                        "version": "1.0",
                    },
                    "runtime_authority": {
                        "promotion_class": "audit_only",
                        "reviewed": False,
                        "safety_class": "literal_unambiguous",
                    },
                }
                for idx, (pattern, tid, name) in enumerate(EMERGENCY_RULE_SPECS, start=1)
            ],
        },
    }


def _policy_rules(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    body = document.get("policy", document)
    if not isinstance(body, dict):
        return []
    return [dict(rule) for rule in body.get("rules") or [] if isinstance(rule, dict)]


def _rule_metadata_by_spec(document: Dict[str, Any]) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    """Index policy metadata without changing the public three-tuple API."""

    indexed: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    body = document.get("policy", document)
    authority = body.get("runtime_authority") if isinstance(body, dict) else {}
    approved = set()
    if isinstance(authority, dict):
        approved = {
            _clean_text(item)
            for item in authority.get("trusted_literal_fallback_rule_ids", [])
            if _clean_text(item)
        }
    for rule in _policy_rules(document):
        pattern = _clean_text(rule.get("pattern"))
        tid = _clean_text(rule.get("ttp")).upper()
        name = _clean_text(rule.get("technique_name") or rule.get("name") or tid)
        if not pattern or not tid:
            continue
        item = dict(rule)
        runtime_authority = item.get("runtime_authority")
        if not isinstance(runtime_authority, dict):
            runtime_authority = {
                "promotion_class": (
                    "trusted_literal_fallback"
                    if _clean_text(item.get("rule_id")) in approved
                    else "audit_only"
                ),
                "reviewed": _clean_text(item.get("rule_id")) in approved,
                "safety_class": "literal_unambiguous",
            }
        item["runtime_authority"] = runtime_authority
        indexed[(pattern, tid, name)] = item
    return indexed


def _structural_rules(document: Dict[str, Any], review_mode: str) -> List[Dict[str, Any]]:
    emergency_fallback = document.get("policy_id") == "emergency-python-fallback"
    return [
        rule
        for rule in _policy_rules(document)
        if rule.get("enabled") is not False
        and rule.get("evidence_type") == "command_operation"
        and _rule_allowed_for_runtime(
            rule,
            review_mode,
            emergency_fallback=emergency_fallback,
        )
    ]


def _runtime_rule_review_mode(document: Dict[str, Any], rule_review_mode: str = "") -> str:
    configured = _clean_text(rule_review_mode)
    if not configured:
        body = document.get("policy", document)
        if isinstance(body, dict):
            configured = _clean_text(body.get("rule_review_mode"))
        if not configured:
            configured = _clean_text(document.get("rule_review_mode"))
    return (configured or "reviewed_only").lower()


def _rule_allowed_for_runtime(rule: Dict[str, Any], review_mode: str, *, emergency_fallback: bool = False) -> bool:
    if review_mode in {"all", "all_enabled", "include_unreviewed"}:
        return True
    if emergency_fallback:
        return True
    provenance = rule.get("provenance")
    if not isinstance(provenance, dict):
        return False
    return provenance.get("reviewed") is True


def load_rule_specs(
    path_text: str = "",
    rule_review_mode: str = "",
    *,
    policy_document: Optional[Dict[str, Any]] = None,
) -> List[Tuple[str, str, str]]:
    document = (
        policy_document
        if isinstance(policy_document, dict)
        else load_classification_rule_policy(path_text)
    )
    review_mode = _runtime_rule_review_mode(document, rule_review_mode)
    emergency_fallback = document.get("policy_id") == "emergency-python-fallback"
    specs: List[Tuple[str, str, str]] = []
    for rule in _policy_rules(document):
        if rule.get("enabled") is False:
            continue
        if not _rule_allowed_for_runtime(rule, review_mode, emergency_fallback=emergency_fallback):
            continue
        if rule.get("evidence_type") == "command_operation":
            continue
        pattern = _clean_text(rule.get("pattern"))
        tid = _clean_text(rule.get("ttp")).upper()
        name = _clean_text(rule.get("technique_name") or rule.get("name") or tid)
        if pattern and tid:
            specs.append((pattern, tid, name))
    if specs or not emergency_fallback:
        return specs
    return list(EMERGENCY_RULE_SPECS)


RULE_POLICY = load_classification_rule_policy()
RULE_SPECS: List[Tuple[str, str, str]] = load_rule_specs()
RULE_EVIDENCE_SOURCE = (
    "emergency_python_fallback"
    if RULE_POLICY.get("policy_id") == "emergency-python-fallback"
    else "rule"
)


def _compile_rules(rule_specs: Sequence[Tuple[str, str, str]]) -> List[Tuple[re.Pattern[str], str, str]]:
    compiled: List[Tuple[re.Pattern[str], str, str]] = []
    for pattern, tid, name in rule_specs:
        try:
            compiled.append((re.compile(pattern, re.IGNORECASE), tid, name))
        except re.error:
            continue
    return compiled


RULES: List[Tuple[re.Pattern[str], str, str]] = _compile_rules(RULE_SPECS)
_COMBINED_PATTERN = re.compile(
    "|".join(pattern.pattern for pattern, _, _ in RULES) if RULES else r"(?!)",
    re.IGNORECASE,
)
_NOISE_RE = re.compile(
    r"^(?:bash|sh|/bin/bash|/bin/sh|dash|zsh|ksh|whoami|id|pwd|hostname|exit|logout|clear|reset)$",
    re.IGNORECASE,
)


def split_compound_command(
    command: str,
    max_fragments: int = 20,
    *,
    split_pipes: bool = False,
) -> List[CommandFragment]:
    """Split a shell command into ordered subcommands without executing it.

    The splitter is intentionally conservative. It splits on common command
    sequence operators (`&&`, `||`, `;`, and newlines), but it keeps quoted text
    intact. Classification keeps simple pipelines intact by default because a
    full pipeline can carry its own rule meaning. Relationship analysis may set
    ``split_pipes=True`` to preserve producer-to-consumer structure without
    changing classifier behavior.
    """
    text = (command or "").strip()
    if not text:
        return []

    raw_parts: List[Dict[str, str]] = []
    buf: List[str] = []
    quote = ""
    escaped = False
    operator_before = ""
    i = 0

    def flush(operator_after: str = "") -> None:
        nonlocal buf, operator_before
        part = "".join(buf).strip()
        if part:
            raw_parts.append(
                {
                    "text": part,
                    "operator_before": operator_before,
                    "operator_after": operator_after,
                }
            )
            operator_before = operator_after
        elif operator_after:
            operator_before = operator_after
        buf = []

    while i < len(text):
        ch = text[i]

        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue

        if ch == "\\":
            buf.append(ch)
            escaped = True
            i += 1
            continue

        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            i += 1
            continue

        if ch in {"'", '"', "`"}:
            quote = ch
            buf.append(ch)
            i += 1
            continue

        operator = ""
        operator_len = 0
        if text.startswith("&&", i):
            operator = "&&"
            operator_len = 2
        elif text.startswith("||", i):
            operator = "||"
            operator_len = 2
        elif split_pipes and ch == "|":
            operator = "|"
            operator_len = 1
        elif ch == ";":
            operator = ";"
            operator_len = 1
        elif ch in {"\n", "\r"}:
            operator = "\\n"
            operator_len = 2 if ch == "\r" and i + 1 < len(text) and text[i + 1] == "\n" else 1

        if operator:
            if len(raw_parts) >= max(max_fragments - 1, 1):
                remainder = text[i:].strip()
                if remainder:
                    if buf and not str(buf[-1]).endswith(" "):
                        buf.append(" ")
                    buf.append(remainder)
                break
            flush(operator)
            i += operator_len
            continue

        buf.append(ch)
        i += 1

    flush("")

    if not raw_parts:
        return []
    count = len(raw_parts)
    return [
        CommandFragment(
            text=item["text"],
            index=index,
            count=count,
            operator_before=item.get("operator_before", ""),
            operator_after=item.get("operator_after", ""),
        )
        for index, item in enumerate(raw_parts)
    ]


def _rule_based_ttp_with_rules(
    command: str,
    rules: Sequence[Tuple[re.Pattern[str], str, str]],
    combined_pattern: re.Pattern[str],
    source: str = "rule",
    *,
    metadata_by_spec: Optional[Dict[Tuple[str, str, str], Dict[str, Any]]] = None,
    parser_decision: Optional[Dict[str, Any]] = None,
    policy_provenance: Optional[Dict[str, Any]] = None,
) -> List[TTPPrediction]:
    command = command or ""
    if not combined_pattern.search(command):
        return []

    matched: List[TTPPrediction] = []
    seen = set()
    for pattern, tid, name in rules:
        if tid not in seen and pattern.search(command):
            metadata = (metadata_by_spec or {}).get((pattern.pattern, tid, name), {})
            authority = candidate_authority_decision(
                parser_decision=parser_decision or {},
                evidence_type="command_regex",
                rule_metadata=metadata,
                policy_provenance=policy_provenance or {},
                emergency=source == "emergency_python_fallback",
            )
            matched.append(
                TTPPrediction(
                    tid=tid,
                    name=name,
                    confidence=1.0,
                    high_conf=bool(authority.get("trusted_eligible")),
                    source=source,
                    rule_id=_clean_text(metadata.get("rule_id")),
                    evidence_type="command_regex",
                    authority_decision=authority,
                )
            )
            seen.add(tid)
    return matched


def _operation_based_ttp(
    command: str,
    rules: Sequence[Dict[str, Any]],
    source: str = "rule",
    *,
    parsed: Optional[Dict[str, Any]] = None,
    policy_provenance: Optional[Dict[str, Any]] = None,
) -> List[TTPPrediction]:
    parsed = parsed if isinstance(parsed, dict) else parse_command_operation(command)
    parser_decision = command_authority_decision(command, parsed, structural_match=True)
    matched: List[TTPPrediction] = []
    seen: set[str] = set()
    for rule in rules:
        tid = _clean_text(rule.get("ttp")).upper()
        if tid in seen or not structural_predicate_matches(
            parsed,
            rule.get("operation_predicate") or {},
        ):
            continue
        authority = candidate_authority_decision(
            parser_decision=parser_decision,
            evidence_type="command_operation",
            rule_metadata=rule,
            policy_provenance=policy_provenance or {},
            emergency=source == "emergency_python_fallback",
        )
        matched.append(TTPPrediction(
            tid=tid,
            name=_clean_text(rule.get("technique_name") or tid),
            confidence=1.0,
            high_conf=bool(authority.get("trusted_eligible")),
            source=source,
            rule_id=_clean_text(rule.get("rule_id")),
            evidence_type="command_operation",
            authority_decision=authority,
        ))
        seen.add(tid)
    return matched


def rule_based_ttp(command: str) -> List[TTPPrediction]:
    parsed = parse_command_operation(command)
    policy_provenance = {
        "rule_policy_id": _clean_text(RULE_POLICY.get("policy_id")),
        "rule_policy_version": _clean_text(RULE_POLICY.get("version")),
        "rule_policy_sha256": _clean_text(RULE_POLICY.get("source_sha256")),
        "rule_policy_load_status": _clean_text(RULE_POLICY.get("load_status")),
    }
    parser_decision = command_authority_decision(command, parsed, structural_match=False)
    structural = _operation_based_ttp(
        command,
        _structural_rules(
            RULE_POLICY,
            _runtime_rule_review_mode(RULE_POLICY),
        ),
        RULE_EVIDENCE_SOURCE,
        parsed=parsed,
        policy_provenance=policy_provenance,
    )
    return structural or _rule_based_ttp_with_rules(
        command,
        RULES,
        _COMBINED_PATTERN,
        RULE_EVIDENCE_SOURCE,
        metadata_by_spec=_rule_metadata_by_spec(RULE_POLICY),
        parser_decision=parser_decision,
        policy_provenance=policy_provenance,
    )


def is_shell_noise(
    command: str,
    rules: Optional[Sequence[Tuple[re.Pattern[str], str, str]]] = None,
    combined_pattern: Optional[re.Pattern[str]] = None,
) -> bool:
    stripped = (command or "").strip()
    if not stripped:
        return True
    parts = [part.strip() for part in re.split(r"[;&|]+", stripped) if part.strip()]
    all_primitive = bool(parts) and all(_NOISE_RE.match(part) for part in parts)
    if not all_primitive:
        return False
    return not bool(_rule_based_ttp_with_rules(
        stripped,
        rules or RULES,
        combined_pattern or _COMBINED_PATTERN,
    ))


class NotebookParityClassifier:
    """Hybrid command classifier with explicit rule/model agreement semantics."""

    def __init__(
        self,
        bert_fn: Optional[Callable[[str], Tuple[Optional[str], float]]] = None,
        mitre_db: Any = None,
        high_confidence: float = 0.55,
        rule_policy_path: str = "",
        rule_review_mode: str = "",
        rule_specs: Optional[Sequence[Tuple[str, str, str]]] = None,
    ) -> None:
        self.bert_fn = bert_fn
        self.mitre_db = mitre_db
        self.high_confidence = high_confidence
        self.rule_policy = load_classification_rule_policy(rule_policy_path) if rule_specs is None else {}
        self.rule_review_mode = _runtime_rule_review_mode(self.rule_policy, rule_review_mode) if rule_specs is None else "explicit_rule_specs"
        self.rule_specs = (
            list(rule_specs)
            if rule_specs is not None
            else load_rule_specs(
                rule_policy_path,
                self.rule_review_mode,
                policy_document=self.rule_policy,
            )
        )
        self.structural_rules = (
            []
            if rule_specs is not None
            else _structural_rules(self.rule_policy, self.rule_review_mode)
        )
        self.rules = _compile_rules(self.rule_specs)
        self.rule_metadata = (
            {}
            if rule_specs is not None
            else _rule_metadata_by_spec(self.rule_policy)
        )
        self.combined_pattern = re.compile(
            "|".join(pattern.pattern for pattern, _, _ in self.rules) if self.rules else r"(?!)",
            re.IGNORECASE,
        )
        self.rule_policy_id = _clean_text(self.rule_policy.get("policy_id"))
        self.rule_policy_version = _clean_text(self.rule_policy.get("version"))
        self.rule_evidence_source = (
            "emergency_python_fallback"
            if self.rule_policy_id == "emergency-python-fallback"
            else "rule"
        )

    def _policy_provenance(self) -> Dict[str, Any]:
        return {
            "classification_event_schema": CLASSIFICATION_EVENT_SCHEMA_VERSION,
            "authority_decision_schema": AUTHORITY_DECISION_SCHEMA,
            "rule_policy_id": self.rule_policy_id,
            "rule_policy_version": self.rule_policy_version,
            "rule_review_mode": self.rule_review_mode,
            "rule_policy_path": _clean_text(self.rule_policy.get("source_path")),
            "rule_policy_sha256": _clean_text(
                self.rule_policy.get("source_sha256")
            ).lower(),
            "rule_policy_load_status": _clean_text(
                self.rule_policy.get("load_status")
            ),
        }

    def _technique_name(self, tid: Optional[str]) -> str:
        if not tid:
            return "Unknown"
        if self.mitre_db and hasattr(self.mitre_db, "get_name"):
            try:
                return self.mitre_db.get_name(tid) or "Unknown"
            except Exception:
                return "Unknown"
        return "Unknown"

    def _tactic(self, tid: Optional[str]) -> str:
        if not tid:
            return "unknown"
        if self.mitre_db and hasattr(self.mitre_db, "get_tactics"):
            try:
                tactics = self.mitre_db.get_tactics(tid)
                return tactics[0] if tactics else "unknown"
            except Exception:
                return "unknown"
        return "unknown"

    def _bert_prediction(self, command: str) -> TTPPrediction:
        if not self.bert_fn:
            return TTPPrediction(
                "T0000_UNKNOWN", "SecureBERT unavailable", 0.0, False,
                "securebert_unavailable", evidence_type="securebert",
            )
        try:
            tid, confidence = self.bert_fn(command)
            confidence = float(confidence or 0.0)
            if tid and confidence >= self.high_confidence:
                return TTPPrediction(
                    tid, self._technique_name(tid), round(confidence, 4), True,
                    "securebert", evidence_type="securebert",
                )
            return TTPPrediction(
                tid or "T0000_UNKNOWN",
                "Unclassified (low confidence)",
                round(confidence, 4),
                False,
                "securebert_low_confidence",
                evidence_type="securebert",
            )
        except Exception:
            return TTPPrediction(
                "T0000_UNKNOWN", "SecureBERT error", 0.0, False,
                "securebert_error", evidence_type="securebert",
            )

    def _classify_single(self, command: str) -> List[Dict[str, Any]]:
        command = (command or "").strip()
        if not command:
            return []

        parsed = parse_command_operation(command)
        parser_decision = command_authority_decision(
            command,
            parsed,
            structural_match=False,
        )
        rule_predictions = _operation_based_ttp(
            command,
            self.structural_rules,
            self.rule_evidence_source,
            parsed=parsed,
            policy_provenance=self._policy_provenance(),
        )
        if rule_predictions:
            parser_decision = command_authority_decision(
                command,
                parsed,
                structural_match=True,
            )
        else:
            rule_predictions = _rule_based_ttp_with_rules(
            command,
            self.rules,
            self.combined_pattern,
            self.rule_evidence_source,
            metadata_by_spec=self.rule_metadata,
            parser_decision=parser_decision,
            policy_provenance=self._policy_provenance(),
        )
        if is_shell_noise(command, self.rules, self.combined_pattern) and not rule_predictions:
            return [{
                "command": command,
                "ttp": None,
                "tactic": "unknown",
                "source": "shell_noise",
                "confidence": 0.0,
                "name": "Shell noise",
                "high_confidence": False,
                "agreement_status": "not_applicable",
                "confidence_semantics": "audit_only_shell_noise",
                "classification_event_schema": CLASSIFICATION_EVENT_SCHEMA_VERSION,
                "authority_decision": {
                    "schema_version": AUTHORITY_DECISION_SCHEMA,
                    "decision": "audit_only",
                    "trusted_eligible": False,
                    "safety_class": parser_decision.get("safety_class", "unknown"),
                    "reasons": ["shell_noise"],
                },
                **self._policy_provenance(),
            }]

        bert_prediction = self._bert_prediction(command)
        has_bert = bert_prediction.high_conf and bert_prediction.tid != "T0000_UNKNOWN"

        if rule_predictions:
            bert_tactic = self._tactic(bert_prediction.tid) if bert_prediction.tid != "T0000_UNKNOWN" else "unknown"
            events: List[Dict[str, Any]] = []
            for prediction in rule_predictions:
                rule_tactic = self._tactic(prediction.tid)
                emergency_rule = prediction.source == "emergency_python_fallback"
                source = prediction.source or "rule"
                agreement_status = "emergency_rule_only" if emergency_rule else "rule_only"
                authority = dict(prediction.authority_decision or {})
                high_confidence = bool(authority.get("trusted_eligible")) and not emergency_rule
                confidence_semantics = (
                    "unreviewed_emergency_rule_audit_only"
                    if emergency_rule
                    else "reviewed_rule_policy_match_not_calibrated_probability"
                )
                if has_bert:
                    if prediction.tid.upper() == bert_prediction.tid.upper():
                        if emergency_rule:
                            agreement_status = "emergency_rule_model_agreement_audit_only"
                        else:
                            source = "both"
                            agreement_status = "exact_technique_agreement"
                            confidence_semantics = "rule_model_agreement_not_calibrated_probability"
                    else:
                        source = "rule_securebert_disagreement"
                        high_confidence = False
                        if (
                            rule_tactic != "unknown"
                            and bert_tactic != "unknown"
                            and rule_tactic.lower() == bert_tactic.lower()
                        ):
                            agreement_status = "tactic_only_disagreement"
                        else:
                            agreement_status = "technique_and_tactic_disagreement"
                        confidence_semantics = "conflicting_classifier_outputs_audit_only"
                event = {
                    **prediction.to_event(command, rule_tactic),
                    "source": source,
                    "high_confidence": high_confidence,
                    "agreement_status": agreement_status,
                    "confidence_semantics": confidence_semantics,
                    "bert_ttp": None if bert_prediction.tid == "T0000_UNKNOWN" else bert_prediction.tid,
                    "bert_tactic": bert_tactic,
                    "bert_confidence": bert_prediction.confidence,
                    **self._policy_provenance(),
                }
                events.append(event)
            return events

        if has_bert:
            event = {
                **bert_prediction.to_event(command, self._tactic(bert_prediction.tid)),
                "agreement_status": "model_only",
                "confidence_semantics": "model_score_not_calibrated_probability",
                **self._policy_provenance(),
            }
            event["authority_decision"] = candidate_authority_decision(
                parser_decision=parser_decision,
                evidence_type="securebert",
                rule_metadata=None,
                policy_provenance=self._policy_provenance(),
            )
            event["high_confidence"] = False
            return [event]

        event = {
            **bert_prediction.to_event(command, "unknown"),
            "agreement_status": "model_below_policy_threshold",
            "confidence_semantics": "audit_only_model_score_not_calibrated_probability",
            **self._policy_provenance(),
        }
        event["authority_decision"] = candidate_authority_decision(
            parser_decision=parser_decision,
            evidence_type="securebert",
            rule_metadata=None,
            policy_provenance=self._policy_provenance(),
        )
        return [event]

    def classify(self, command: str) -> List[Dict[str, Any]]:
        original_command = (command or "").strip()
        fragments = split_compound_command(original_command)
        if not fragments:
            return []

        events: List[Dict[str, Any]] = []
        for fragment in fragments:
            for event in self._classify_single(fragment.text):
                item = dict(event)
                if fragment.count > 1:
                    item["original_command"] = original_command
                    item["subcommand"] = fragment.text
                    item["subcommand_index"] = fragment.index
                    item["subcommand_count"] = fragment.count
                    item["operator_before"] = fragment.operator_before
                    item["operator_after"] = fragment.operator_after
                events.append(item)
        return events


def auto_label_commands(
    commands: Sequence[str],
    exclude_ttps: Optional[set[str]] = None,
) -> List[Dict[str, Any]]:
    """Auto-label Cowrie commands from deterministic rules for later fine-tuning."""
    exclude_ttps = exclude_ttps or set()
    labeled: List[Dict[str, Any]] = []
    for command in commands:
        matches = [
            match
            for match in rule_based_ttp(command.strip())
            if match.high_conf and match.tid not in exclude_ttps
        ]
        for match in matches:
            labeled.append(
                {
                    "text": command,
                    "label": match.tid,
                    "label_name": match.name,
                    "source": "rule_multi" if len(matches) > 1 else "rule_single",
                    "confidence": match.confidence,
                }
            )
    return labeled


def merge_success_commands(
    commands: Sequence[str],
    bert_predictions: Sequence[TTPPrediction],
) -> List[MergedResult]:
    results: List[MergedResult] = []
    for command, bert in zip(commands, bert_predictions):
        rules = rule_based_ttp(command)
        if bert.high_conf and rules:
            source = (
                "both"
                if any(rule.tid.upper() == bert.tid.upper() for rule in rules)
                else "rule_securebert_disagreement"
            )
        elif bert.high_conf:
            source = "bert"
        elif rules:
            source = "rule"
        else:
            source = "none"
        results.append(MergedResult(command=command, bert_ttps=[bert], rule_ttps=rules, source=source))
    return results
