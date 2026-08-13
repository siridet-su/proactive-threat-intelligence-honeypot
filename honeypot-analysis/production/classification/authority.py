"""Domain-separated authority decisions for command classifications.

The parser and the reviewed rule table answer different questions.  The
parser says whether a command is sufficiently unambiguous to reason about;
the rule table says which ATT&CK mapping was reviewed.  This module is the
single gate joining those answers.  Callers must persist the returned object
with the classification event rather than re-deriving trust from ``source``
or model agreement.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


SCHEMA_VERSION = "command_authority_decision.v2"
CLASSIFICATION_EVENT_SCHEMA_VERSION = "classification_event.v3"

_CONDITIONAL_OPERATORS = frozenset({"&&", "||"})
_INERT_TEXT_FAMILIES = frozenset({"echo", "printf"})
_SEARCH_FAMILIES = frozenset({"grep", "egrep", "fgrep"})
_MUTATION_TECHNIQUES = frozenset(
    {
        "T1053",  # scheduled task/job modification
        "T1070",  # indicator removal
        "T1098",  # account manipulation
        "T1136",  # account creation
        "T1222",  # file permission modification
        "T1496",  # resource hijacking requires an actual miner invocation
        "T1543",  # service creation/modification
        "T1546",  # event-triggered execution configuration
        "T1547",  # boot/logon autostart configuration
        "T1548",  # elevation-control mechanism use/modification
        "T1562",  # defense impairment
    }
)
_DIRECT_MUTATION_FAMILIES = frozenset(
    {
        "chmod",
        "chown",
        "chgrp",
        "crontab",
        "kill",
        "killall",
        "pkill",
        "rm",
        "service",
        "systemctl",
        "useradd",
        "adduser",
        "usermod",
        "passwd",
        "sudo",
        "su",
    }
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _has_unresolved_value(value: Any) -> bool:
    text = _text(value)
    if not text:
        return False
    # These are shell expansion forms for which the parser intentionally does
    # not claim a concrete object/path.  Quoted literals are handled by the
    # parser and are not rejected here.
    return any(token in text for token in ("$", "`", "*", "?", "[", "]"))


def command_authority_decision(
    command: str,
    parsed: Optional[Dict[str, Any]],
    *,
    structural_match: bool = False,
    operator_before: str = "",
) -> Dict[str, Any]:
    """Return a deterministic parser safety decision.

    ``explicit_abstention`` is intentionally stronger than a regex match:
    once the structural parser declines to interpret a command, a legacy
    regex may remain useful audit evidence but cannot become trusted evidence.
    """

    parsed = parsed if isinstance(parsed, dict) else {}
    status = _text(parsed.get("parse_status")) or "missing"
    reasons: list[str] = []
    fragment_execution = (
        "conditional_unproven"
        if _text(operator_before) in _CONDITIONAL_OPERATORS
        else "submitted_direct"
    )
    if status != "parsed":
        reasons.append(_text(parsed.get("abstention_reason")) or "parser_abstention")
        return {
            "schema_version": SCHEMA_VERSION,
            "decision": "audit_only",
            "safety_class": "explicit_abstention",
            "trusted_eligible": False,
            "command": _text(command),
            "parse_status": status,
            "fragment_execution": fragment_execution,
            "reasons": sorted(set(reasons)),
        }

    entities = parsed.get("entities") if isinstance(parsed.get("entities"), dict) else {}
    for key, values in entities.items():
        for item in _list(values):
            if not isinstance(item, dict):
                continue
            if item.get("uncertain") is True or item.get("linkable") is False:
                reasons.append(f"uncertain_{key}")
            resolution = _text(
                item.get("resolution_status") or item.get("resolution")
            )
            if resolution and resolution not in {
                "literal",
                "recorded_resolved",
                "context_resolved",
            }:
                reasons.append(f"unresolved_{key}")
            if _has_unresolved_value(item.get("normalized_value")):
                reasons.append(f"dynamic_{key}")
    for token in _list(parsed.get("tokens")):
        if _has_unresolved_value(token):
            reasons.append("shell_expansion_or_glob")
    if parsed.get("abstention_reason"):
        reasons.append(_text(parsed.get("abstention_reason")))
    if reasons:
        return {
            "schema_version": SCHEMA_VERSION,
            "decision": "audit_only",
            "safety_class": "explicit_abstention",
            "trusted_eligible": False,
            "command": _text(command),
            "parse_status": status,
            "fragment_execution": fragment_execution,
            "reasons": sorted(set(reasons)),
        }

    if fragment_execution == "conditional_unproven":
        return {
            "schema_version": SCHEMA_VERSION,
            "decision": "audit_only",
            "safety_class": "conditional_fragment_unproven",
            "trusted_eligible": False,
            "command": _text(command),
            "parse_status": status,
            "fragment_execution": fragment_execution,
            "reasons": ["conditional_fragment_execution_not_proven"],
            "operation_context": _operation_context(parsed),
        }

    if structural_match:
        safety_class = "reviewed_structural_match"
        decision = "trusted"
    else:
        safety_class = "literal_unambiguous"
        decision = "audit_only"
    return {
        "schema_version": SCHEMA_VERSION,
        "decision": decision,
        "safety_class": safety_class,
        "trusted_eligible": decision == "trusted",
        "command": _text(command),
        "parse_status": status,
        "fragment_execution": fragment_execution,
        "operation_context": _operation_context(parsed),
        "reasons": [],
    }


def _normalized_paths(parsed: Dict[str, Any], entity_key: str) -> list[str]:
    entities = parsed.get("entities") if isinstance(parsed.get("entities"), dict) else {}
    values: list[str] = []
    for item in _list(entities.get(entity_key)):
        if isinstance(item, dict):
            value = _text(item.get("normalized_value") or item.get("raw_value"))
            if value:
                values.append(value)
    return values


def _operation_context(parsed: Dict[str, Any]) -> Dict[str, Any]:
    redirection_targets: list[str] = []
    for item in _list(parsed.get("redirections")):
        if not isinstance(item, dict):
            continue
        path = item.get("path") if isinstance(item.get("path"), dict) else {}
        value = _text(path.get("normalized_value") or item.get("target"))
        if value:
            redirection_targets.append(value)
    return {
        "command_family": _text(parsed.get("command_family")).lower(),
        "executable": _text(parsed.get("executable")),
        "operation_types": sorted({_text(item) for item in _list(parsed.get("operation_types")) if _text(item)}),
        "operands": [_text(item) for item in _list(parsed.get("operands")) if _text(item)],
        "read_paths": sorted(set(_normalized_paths(parsed, "read_paths"))),
        "write_paths": sorted(set(_normalized_paths(parsed, "write_paths"))),
        "redirection_targets": sorted(set(redirection_targets)),
    }


def _span_overlaps_literal(command: str, start: int, end: int, literal: str) -> bool:
    if not literal:
        return False
    cursor = 0
    lowered = command.lower()
    needle = literal.lower()
    while True:
        position = lowered.find(needle, cursor)
        if position < 0:
            return False
        if start < position + len(needle) and end > position:
            return True
        cursor = position + 1


def _regex_operation_context_allows(
    parser_decision: Dict[str, Any],
    metadata: Dict[str, Any],
) -> tuple[bool, list[str]]:
    """Prove that a regex match refers to an observed command operation.

    A regex is allowed to locate reviewed syntax, but it cannot by itself prove
    that an inert token was invoked or that a read modified a persistence
    target.  The parser-owned context supplies that missing authority.
    """

    reasons: list[str] = []
    promotion = metadata.get("runtime_authority")
    promotion = promotion if isinstance(promotion, dict) else {}
    if _text(promotion.get("operation_class")) != "reviewed_operation_context":
        reasons.append("regex_operation_class_missing")
        return False, reasons

    context = parser_decision.get("operation_context")
    context = context if isinstance(context, dict) else {}
    family = _text(context.get("command_family")).lower()
    executable = _text(context.get("executable"))
    operations = {_text(item) for item in _list(context.get("operation_types"))}
    read_paths = [_text(item) for item in _list(context.get("read_paths"))]
    write_paths = [_text(item) for item in _list(context.get("write_paths"))]
    redirect_paths = [_text(item) for item in _list(context.get("redirection_targets"))]
    command = _text(parser_decision.get("command"))
    match_start = metadata.get("regex_match_start")
    match_end = metadata.get("regex_match_end")
    if type(match_start) is not int or type(match_end) is not int:
        reasons.append("regex_match_context_missing")
        return False, reasons

    ttp = _text(metadata.get("ttp")).upper()
    overlaps_executable = _span_overlaps_literal(
        command, match_start, match_end, executable
    )
    overlaps_read_path = any(
        _span_overlaps_literal(command, match_start, match_end, path)
        for path in read_paths
    )
    overlaps_write_path = any(
        _span_overlaps_literal(command, match_start, match_end, path)
        for path in [*write_paths, *redirect_paths]
    )

    if family in _INERT_TEXT_FAMILIES and not redirect_paths:
        reasons.append("inert_text_mention_not_operation")
    if family in _SEARCH_FAMILIES and ttp in _MUTATION_TECHNIQUES:
        reasons.append("search_term_not_mutation_or_execution")
    if ttp in _MUTATION_TECHNIQUES:
        mutation_proven = overlaps_write_path or (
            overlaps_executable and family in _DIRECT_MUTATION_FAMILIES
        )
        if "file_read" in operations and not overlaps_write_path:
            mutation_proven = False
        if not mutation_proven:
            reasons.append("modification_or_execution_operation_not_proven")
    elif not (overlaps_executable or overlaps_read_path or overlaps_write_path):
        reasons.append("regex_match_not_bound_to_executable_or_operand")

    return not reasons, reasons


def candidate_authority_decision(
    *,
    parser_decision: Dict[str, Any],
    evidence_type: str,
    rule_metadata: Optional[Dict[str, Any]],
    policy_provenance: Dict[str, Any],
    emergency: bool = False,
) -> Dict[str, Any]:
    """Apply policy metadata to a parser decision for one candidate."""

    parser_decision = dict(parser_decision or {})
    reasons = list(parser_decision.get("reasons") or [])
    metadata = rule_metadata if isinstance(rule_metadata, dict) else {}
    provenance = policy_provenance if isinstance(policy_provenance, dict) else {}
    rule_id = _text(metadata.get("rule_id"))
    promotion = metadata.get("runtime_authority")
    if not isinstance(promotion, dict):
        promotion = {}

    trusted = bool(parser_decision.get("trusted_eligible"))
    if parser_decision.get("safety_class") == "explicit_abstention":
        trusted = False
        reasons.append("structural_parser_abstention_blocks_regex_promotion")
    if evidence_type == "command_operation":
        if (metadata.get("provenance") or {}).get("reviewed") is not True:
            trusted = False
            reasons.append("structural_rule_not_reviewed")
        if not trusted:
            reasons.append("structural_match_not_safe")
        decision = "trusted" if trusted else "audit_only"
    elif evidence_type == "command_regex":
        # Regexes are audit-only unless the rule itself carries an explicit,
        # reviewed promotion record.  Model agreement is deliberately not
        # consulted here and therefore cannot bypass this gate.
        if parser_decision.get("safety_class") == "literal_unambiguous":
            trusted = True
        if emergency:
            trusted = False
            reasons.append("emergency_rule")
        if _text(promotion.get("promotion_class")) != "trusted_literal_fallback":
            trusted = False
            reasons.append("regex_promotion_not_explicitly_approved")
        if promotion.get("reviewed") is not True:
            trusted = False
            reasons.append("regex_promotion_not_reviewed")
        if _text(promotion.get("safety_class")) != "literal_unambiguous":
            trusted = False
            reasons.append("regex_promotion_safety_class_missing")
        context_allowed, context_reasons = _regex_operation_context_allows(
            parser_decision,
            metadata,
        )
        if not context_allowed:
            trusted = False
            reasons.extend(context_reasons)
        if not provenance.get("rule_policy_id") or not provenance.get("rule_policy_version"):
            trusted = False
            reasons.append("rule_policy_provenance_missing")
        if not provenance.get("rule_policy_sha256"):
            trusted = False
            reasons.append("rule_policy_hash_missing")
        if not provenance.get("rule_policy_load_status") == "loaded":
            trusted = False
            reasons.append("rule_policy_not_loaded")
        decision = "trusted" if trusted else "audit_only"
    else:
        trusted = False
        reasons.append("unsupported_evidence_type")
        decision = "audit_only"

    return {
        "schema_version": SCHEMA_VERSION,
        "decision": decision,
        "trusted_eligible": decision == "trusted",
        "safety_class": _text(parser_decision.get("safety_class")) or "unknown",
        "evidence_type": evidence_type,
        "rule_id": rule_id,
        "reasons": sorted(set(_text(item) for item in reasons if _text(item))),
    }
