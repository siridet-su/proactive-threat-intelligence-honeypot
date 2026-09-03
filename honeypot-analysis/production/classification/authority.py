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


SCHEMA_VERSION = "command_authority_decision.v1"
CLASSIFICATION_EVENT_SCHEMA_VERSION = "classification_event.v2"
REVIEWED_OPERATION_CONTEXT = "reviewed_operation_context"

# These sets are deliberately small and describe parser-level authority
# context, not ATT&CK semantic truth.  They prevent a literal fallback from
# treating a token embedded in an inert/search command as an observed action.
_READ_COMMAND_FAMILIES = {
    "cat", "grep", "head", "less", "more", "tail", "wc", "awk", "sed",
}
_READ_OBSERVATION_TTPS = {
    "T1003", "T1016", "T1033", "T1049", "T1057", "T1069", "T1082",
    "T1083", "T1087", "T1552",
}
_WRITE_OR_CHANGE_TTPS = {
    "T1027", "T1053", "T1059", "T1070", "T1098", "T1136", "T1140",
    "T1222", "T1543", "T1546", "T1547", "T1548", "T1560", "T1562",
}
_INERT_TEXT_FAMILIES = {"echo", "printf"}


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


def _operation_context(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact parser context for the authority decision.

    This is syntax/provenance context only.  It deliberately does not claim
    that a command succeeded or that a real host was changed.
    """

    redirections = []
    for item in _list(parsed.get("redirections")):
        if isinstance(item, dict):
            redirections.append({
                "operator": _text(item.get("operator")),
                "target": _text((item.get("path") or {}).get("normalized_value"))
                if isinstance(item.get("path"), dict)
                else _text(item.get("target")),
            })
    return {
        "command_family": _text(parsed.get("command_family")).lower(),
        "operation_types": sorted(
            {_text(item) for item in _list(parsed.get("operation_types")) if _text(item)}
        ),
        "redirections": redirections,
        "parse_status": _text(parsed.get("parse_status")),
    }


def _regex_operation_context_allowed(
    parser_decision: Dict[str, Any],
    rule_metadata: Dict[str, Any],
) -> tuple[bool, str]:
    """Check the local operation context for a regex fallback.

    The rule metadata supplies the reviewed operation class; the parser
    supplies the observed command family/operations.  The result is a local
    authority boundary and is not a claim that the mapped ATT&CK behavior is
    semantically or statistically correct.
    """

    context = parser_decision.get("operation_context")
    if not isinstance(context, dict) or context.get("parse_status") != "parsed":
        return False, "operation_context_missing_or_unparsed"
    family = _text(context.get("command_family")).lower()
    operations = {
        _text(item) for item in _list(context.get("operation_types")) if _text(item)
    }
    redirections = [
        _text(item.get("operator"))
        for item in _list(context.get("redirections"))
        if isinstance(item, dict)
    ]
    ttp = _text(rule_metadata.get("ttp")).upper()
    operation_context = rule_metadata.get("runtime_authority")
    if not isinstance(operation_context, dict):
        operation_context = {}
    operation_context = operation_context.get("operation_context")
    context_class = (
        _text(operation_context.get("context_class"))
        if isinstance(operation_context, dict)
        else ""
    )

    if isinstance(operation_context, dict):
        required_family = _text(operation_context.get("required_command_family")).lower()
        if required_family and family != required_family:
            return False, "operation_command_family_mismatch"
        required_operations = {
            _text(item)
            for item in _list(operation_context.get("required_operation_types"))
            if _text(item)
        }
        if required_operations and not required_operations.issubset(operations):
            return False, "operation_type_requirement_unmet"

    target_binding = (
        operation_context.get("target_binding")
        if isinstance(operation_context, dict)
        else None
    )
    if target_binding is not None:
        if not isinstance(target_binding, dict):
            return False, "target_binding_missing_or_invalid"
        exact_paths = {
            _text(item).rstrip("/") or "/"
            for item in _list(target_binding.get("allowed_exact_paths"))
            if _text(item)
        }
        path_prefixes = {
            _text(item).rstrip("/") or "/"
            for item in _list(target_binding.get("allowed_path_prefixes"))
            if _text(item)
        }
        if not exact_paths and not path_prefixes:
            return False, "target_binding_paths_missing"
        write_targets = []
        for item in _list(context.get("redirections")):
            if not isinstance(item, dict):
                continue
            operator = _text(item.get("operator"))
            target = _text(item.get("target"))
            if operator in {">", ">>"}:
                write_targets.append(target)
        if not write_targets:
            return False, "target_binding_write_destination_missing"
        for target in write_targets:
            if target in exact_paths:
                continue
            if any(
                target == prefix or target.startswith(prefix + "/")
                for prefix in path_prefixes
            ):
                continue
            return False, "target_binding_unproven"

    if family in _INERT_TEXT_FAMILIES:
        # Text generation is not an observation of the mentioned token.  A
        # reviewed write rule may use an explicit redirection as its local
        # operation context; otherwise the fallback is audit-only.
        if not redirections or not any(item in {">", ">>"} for item in redirections):
            return False, "inert_text_or_quoted_token"
        if context_class != "write_or_change" and ttp not in _WRITE_OR_CHANGE_TTPS:
            return False, "inert_text_not_a_reviewed_change_context"

    if family in _READ_COMMAND_FAMILIES or "file_read" in operations:
        # A read/search command can support read-oriented observations, but a
        # persistence, execution, impact, or privilege-change token in the
        # same command cannot create that authority merely by naming a path or
        # indicator.
        if context_class != "read_observation" and ttp not in _READ_OBSERVATION_TTPS:
            return False, "read_only_or_search_context_not_change_authority"

    return True, "reviewed_operation_context"


def command_authority_decision(
    command: str,
    parsed: Optional[Dict[str, Any]],
    *,
    structural_match: bool = False,
) -> Dict[str, Any]:
    """Return a deterministic parser safety decision.

    ``explicit_abstention`` is intentionally stronger than a regex match:
    once the structural parser declines to interpret a command, a legacy
    regex may remain useful audit evidence but cannot become trusted evidence.
    """

    parsed = parsed if isinstance(parsed, dict) else {}
    status = _text(parsed.get("parse_status")) or "missing"
    context = _operation_context(parsed)
    reasons: list[str] = []
    if status != "parsed":
        reasons.append(_text(parsed.get("abstention_reason")) or "parser_abstention")
        return {
            "schema_version": SCHEMA_VERSION,
            "decision": "audit_only",
            "safety_class": "explicit_abstention",
            "trusted_eligible": False,
            "command": _text(command),
            "parse_status": status,
            "operation_context": context,
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
            "operation_context": context,
            "reasons": sorted(set(reasons)),
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
        "operation_context": context,
        "reasons": [],
    }


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
        if (metadata.get("provenance") or {}).get("reviewed") is not True:
            trusted = False
            reasons.append("regex_rule_provenance_not_reviewed")
        if _text(promotion.get("safety_class")) != "literal_unambiguous":
            trusted = False
            reasons.append("regex_promotion_safety_class_missing")
        if _text(promotion.get("operation_class")) != REVIEWED_OPERATION_CONTEXT:
            trusted = False
            reasons.append("regex_operation_context_missing_or_invalid")
        else:
            allowed, context_reason = _regex_operation_context_allowed(
                parser_decision,
                metadata,
            )
            if not allowed:
                trusted = False
                reasons.append(context_reason)
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
