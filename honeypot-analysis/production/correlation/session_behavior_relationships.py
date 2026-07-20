"""Conservative entity and relationship extraction for Cowrie command sessions.

The classifier remains the authority for candidate ATT&CK mappings. This module
uses direct Cowrie command observations to describe literal actions and connects
them only through explicit shell structure or shared normalized entities. It
does not execute commands, infer arbitrary shell semantics, or promote an
untrusted classification into ATT&CK evidence.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from production.classification.classification_pipeline import split_compound_command
from production.classification.trust import is_trusted_classification_event
from production.policies.threat_hypothesis_behavior_policy import (
    compile_pattern,
    policy_body,
    policy_summary,
    resolve_behavior_policy,
)
from production.utils.serialization import stable_id


SCHEMA_VERSION = "session_behavior_relationships.v1"


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _resolved_policy(
    policy_document: Optional[Dict[str, Any]] = None,
    policy_path: str = "",
) -> Dict[str, Any]:
    return resolve_behavior_policy(policy_document, policy_path)


def _policy_section(document: Dict[str, Any], name: str) -> Dict[str, Any]:
    value = policy_body(document).get(name)
    return value if isinstance(value, dict) else {}


def _parse_timestamp(value: Any) -> Optional[datetime]:
    text = _clean(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _sort_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
    parsed = _parse_timestamp(item.get("timestamp"))
    return (
        0 if parsed else 1,
        parsed or datetime.max.replace(tzinfo=timezone.utc),
        int(item.get("compound_command_index") or 0),
        int(item.get("fragment_index") or 0),
        int(item.get("source_index") or 0),
    )


def _event_evidence_id(session_id: str, index: int, event: Dict[str, Any]) -> str:
    return stable_id(
        "cowrie",
        {
            "session_id": session_id,
            "index": index,
            "eventid": event.get("eventid"),
            "timestamp": event.get("timestamp"),
            "shasum": event.get("shasum"),
        },
    )


def _command_outcome(event: Dict[str, Any]) -> str:
    eventid = _clean(event.get("eventid"))
    if eventid == "cowrie.command.success" or event.get("success") == 1:
        return "cowrie_reported_success"
    if eventid == "cowrie.command.failed" or event.get("success") == 0:
        return "cowrie_reported_failure"
    return "outcome_unknown"


def _safe_url(value: str) -> Optional[Dict[str, Any]]:
    raw = _clean(value).rstrip(".,)")
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        return None
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    netloc = host if not port or port == default_port else f"{host}:{port}"
    normalized = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))
    redacted = bool(parsed.username or parsed.password or parsed.query or parsed.fragment)
    return {
        "normalized_value": normalized,
        "original_value": normalized,
        "uncertain": False,
        "linkable": True,
        "redacted_components": redacted,
    }


def _normalize_path(value: str, cwd: str = "") -> Optional[Dict[str, Any]]:
    raw = _clean(value).strip("'\"").rstrip(",)")
    if not raw or raw in {".", "..", "/"}:
        return None
    if "://" in raw:
        return None
    if any(ch in raw for ch in {"*", "?", "[", "]"}):
        return {
            "normalized_value": raw,
            "original_value": raw,
            "uncertain": True,
            "linkable": False,
            "uncertainty_reason": "wildcard_path_not_resolved",
        }
    if "$" in raw or "`" in raw:
        return {
            "normalized_value": raw,
            "original_value": raw,
            "uncertain": True,
            "linkable": False,
            "uncertainty_reason": "shell_expansion_not_resolved",
        }
    if raw.startswith("~"):
        return {
            "normalized_value": raw,
            "original_value": raw,
            "uncertain": True,
            "linkable": False,
            "uncertainty_reason": "home_directory_not_resolved",
        }
    if raw.startswith("/"):
        return {
            "normalized_value": posixpath.normpath(raw),
            "original_value": raw,
            "uncertain": False,
            "linkable": True,
        }
    if raw.startswith("./") and cwd.startswith("/"):
        return {
            "normalized_value": posixpath.normpath(posixpath.join(cwd, raw[2:])),
            "original_value": raw,
            "uncertain": False,
            "linkable": True,
        }
    normalized = posixpath.normpath(raw)
    return {
        "normalized_value": f"relative:{normalized}",
        "original_value": raw,
        "uncertain": True,
        "linkable": False,
        "uncertainty_reason": "working_directory_unknown",
    }


def _tokens(command: str) -> List[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _executable(tokens: List[str], wrappers: Iterable[str] = ()) -> str:
    if not tokens:
        return ""
    wrapper_names = {_clean(value).lower() for value in wrappers if _clean(value)}
    index = 0
    while index < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[index]):
        index += 1
    while index < len(tokens) and posixpath.basename(tokens[index]).lower() in wrapper_names:
        index += 1
        while index < len(tokens) and tokens[index].startswith("-"):
            index += 1
    return posixpath.basename(tokens[index]).lower() if index < len(tokens) else ""


def _option_value(tokens: List[str], names: Iterable[str]) -> str:
    accepted = set(names)
    for index, token in enumerate(tokens):
        if token in accepted and index + 1 < len(tokens):
            return tokens[index + 1]
        for name in accepted:
            if token.startswith(name + "="):
                return token.split("=", 1)[1]
    return ""


def _path_values(command: str, pattern: re.Pattern[str]) -> List[str]:
    return [match.group(0) for match in pattern.finditer(command)]


def _entity_value(kind: str, raw: str, cwd: str = "") -> Optional[Dict[str, Any]]:
    normalized = _safe_url(raw) if kind == "url" else _normalize_path(raw, cwd)
    if not normalized:
        return None
    entity_id = stable_id(
        "entity",
        {"type": kind, "value": normalized["normalized_value"]},
    )
    return {"entity_id": entity_id, "entity_type": kind, **normalized}


def _add_entity(
    entities: Dict[str, List[Dict[str, Any]]],
    role: str,
    kind: str,
    raw: str,
    cwd: str = "",
) -> Optional[Dict[str, Any]]:
    entity = _entity_value(kind, raw, cwd)
    if not entity:
        return None
    if not any(item["entity_id"] == entity["entity_id"] for item in entities[role]):
        entities[role].append(entity)
    return entity


def extract_command_entities(
    command: str,
    *,
    cwd: str = "",
    operator_before: str = "",
    operator_after: str = "",
    policy_document: Optional[Dict[str, Any]] = None,
    policy_path: str = "",
) -> Dict[str, Any]:
    """Extract literal, high-precision actions and entities from one fragment."""

    document = _resolved_policy(policy_document, policy_path)
    body = policy_body(document)
    if not body.get("enabled"):
        return {
            "action_types": [],
            "entities": {
                "urls": [],
                "source_paths": [],
                "destination_paths": [],
                "executed_paths": [],
                "modified_paths": [],
                "deleted_paths": [],
                "account_names": [],
                "credential_paths": [],
                "artifact_hashes": [],
            },
            "pipe_producer": None,
            "pipe_consumer": None,
        }
    extraction = body.get("extraction") or {}
    patterns = extraction.get("patterns") or {}
    url_pattern = compile_pattern(document, patterns.get("url"))
    hash_pattern = compile_pattern(document, patterns.get("hash"))
    path_pattern = compile_pattern(document, patterns.get("path_token"))
    credential_pattern = compile_pattern(document, patterns.get("credential_path"))
    wrappers = extraction.get("command_wrappers") or []
    shell_interpreters = {
        _clean(value).lower() for value in extraction.get("shell_interpreters") or []
    }
    script_interpreters = {
        _clean(value).lower() for value in extraction.get("script_interpreters") or []
    }
    remote_definitions = extraction.get("remote_content_executables") or {}
    permission_definition = extraction.get("permission_modification") or {}
    deletion_definition = extraction.get("deletion") or {}
    account_definition = extraction.get("account") or {}

    tokens = _tokens(command)
    executable = _executable(tokens, wrappers)
    entities: Dict[str, List[Dict[str, Any]]] = {
        "urls": [],
        "source_paths": [],
        "destination_paths": [],
        "executed_paths": [],
        "modified_paths": [],
        "deleted_paths": [],
        "account_names": [],
        "credential_paths": [],
        "artifact_hashes": [],
    }
    action_types: List[str] = []

    for match in url_pattern.finditer(command):
        _add_entity(entities, "urls", "url", match.group(0), cwd)
    for match in hash_pattern.finditer(command):
        value = match.group(0).lower()
        entity = {
            "entity_id": stable_id("entity", {"type": "hash", "value": value}),
            "entity_type": "hash",
            "normalized_value": value,
            "original_value": value,
            "uncertain": False,
            "linkable": True,
        }
        entities["artifact_hashes"].append(entity)

    remote_definition = remote_definitions.get(executable) or {}
    if remote_definition and entities["urls"]:
        action_types.append("remote_content_access")
        output = _option_value(tokens, remote_definition.get("output_options") or [])
        if output:
            _add_entity(entities, "destination_paths", "path", output, cwd)
            action_types.append("transfer_attempt")
        elif bool(remote_definition.get("transfer_without_output")):
            action_types.append("transfer_attempt")
        elif operator_after == "|" and bool(remote_definition.get("pipe_source")):
            action_types.append("remote_content_pipe_source")

    permission_executables = {
        _clean(value).lower() for value in permission_definition.get("executables") or []
    }
    if executable in permission_executables:
        argument_start = int(permission_definition.get("path_argument_start") or 0)
        for value in tokens[argument_start:]:
            if not value.startswith("-"):
                _add_entity(entities, "modified_paths", "path", value, cwd)
        if entities["modified_paths"]:
            action_types.append(_clean(permission_definition.get("action_type")))

    if executable in script_interpreters:
        for value in tokens[1:]:
            if value.startswith("-"):
                continue
            if value.startswith(("/", "./", "~", "$")):
                _add_entity(entities, "executed_paths", "path", value, cwd)
                break
        if entities["executed_paths"]:
            action_types.append("execution_attempt")
        elif operator_before == "|" and executable in shell_interpreters:
            action_types.append("shell_pipe_consumer")
    elif tokens and tokens[0].startswith(("/", "./", "~", "$")):
        _add_entity(entities, "executed_paths", "path", tokens[0], cwd)
        if entities["executed_paths"]:
            action_types.append("execution_attempt")

    deletion_executables = {
        _clean(value).lower() for value in deletion_definition.get("executables") or []
    }
    if executable in deletion_executables:
        argument_start = int(deletion_definition.get("path_argument_start") or 0)
        for value in tokens[argument_start:]:
            if not value.startswith("-"):
                _add_entity(entities, "deleted_paths", "path", value, cwd)
        if entities["deleted_paths"]:
            action_types.append(_clean(deletion_definition.get("action_type")))

    authorized_keys_marker = _clean(account_definition.get("authorized_keys_marker"))
    authorized_account_pattern = compile_pattern(
        document,
        account_definition.get("authorized_keys_account_pattern"),
    )
    account_action_type = _clean(account_definition.get("action_type"))
    non_option_arguments = [
        token
        for token in tokens[1:]
        if not token.startswith("-")
    ]
    authorized_keys_is_copy_destination = bool(
        executable in {"cp", "install"}
        and non_option_arguments
        and authorized_keys_marker in non_option_arguments[-1]
    )
    in_place_sed = any(
        token == "--in-place" or token.startswith("-i")
        for token in tokens[1:]
    )
    authorized_keys_modified = bool(
        authorized_keys_marker
        and authorized_keys_marker in command
        and (
            re.search(
                rf"(?:>>?|\btee(?:\s+-a)?\b)[^\n]*{re.escape(authorized_keys_marker)}",
                command,
                re.IGNORECASE,
            )
            or (
                executable in {
                    "chmod",
                    "chown",
                    "mv",
                    "rm",
                    "sed",
                    "touch",
                    "truncate",
                }
                and not (executable == "sed" and not in_place_sed)
            )
            or authorized_keys_is_copy_destination
        )
    )
    if authorized_keys_modified:
        for value in _path_values(command, path_pattern):
            if authorized_keys_marker in value:
                _add_entity(entities, "modified_paths", "path", value, cwd)
                account = authorized_account_pattern.search(value)
                if account:
                    account_name = account.group(1)
                    entities["account_names"].append({
                        "entity_id": stable_id("entity", {"type": "account", "value": account_name}),
                        "entity_type": "account",
                        "normalized_value": account_name,
                        "original_value": account_name,
                        "uncertain": False,
                        "linkable": True,
                    })
        action_types.append(account_action_type)

    account_match = compile_pattern(document, account_definition.get("creation_pattern")).search(command)
    if account_match:
        account = account_match.group(1)
        entities["account_names"].append({
            "entity_id": stable_id("entity", {"type": "account", "value": account}),
            "entity_type": "account",
            "normalized_value": account,
            "original_value": account,
            "uncertain": False,
            "linkable": True,
        })
        action_types.append(account_action_type)

    for match in credential_pattern.finditer(command):
        value = match.group(0).strip()
        _add_entity(entities, "credential_paths", "path", value, cwd)
    if entities["credential_paths"]:
        action_types.append("credential_path_access")

    return {
        "action_types": list(dict.fromkeys(action_types)),
        "entities": entities,
        "pipe_producer": executable if operator_after == "|" else None,
        "pipe_consumer": executable if operator_before == "|" else None,
    }


def _trusted_mappings_for_fragment(
    classification_events: List[Dict[str, Any]],
    *,
    timestamp: str,
    original_command: str,
    fragment: str,
    fragment_index: int,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    mappings: List[Dict[str, Any]] = []
    refs: List[str] = []
    for event in classification_events:
        if not is_trusted_classification_event(event):
            continue
        event_timestamp = _clean(event.get("event_timestamp"))
        if timestamp and event_timestamp and timestamp != event_timestamp:
            continue
        event_original = _clean(event.get("original_command"))
        event_command = _clean(event.get("subcommand") or event.get("command"))
        exact = event_command == fragment
        pipeline_parent = fragment_index == 0 and not event_original and event_command == original_command
        if not exact and not pipeline_parent:
            continue
        ref = _clean(event.get("evidence_id"))
        mapping = {
            "evidence_ref": ref,
            "ttp": _clean(event.get("ttp")),
            "tactic": _clean(event.get("tactic")),
            "source": _clean(event.get("source")),
            "agreement_status": _clean(event.get("agreement_status")),
            "mapping_semantics": "trusted_candidate_attck_mapping",
        }
        key = (mapping["ttp"], mapping["tactic"], mapping["source"])
        if key not in {(item["ttp"], item["tactic"], item["source"]) for item in mappings}:
            mappings.append(mapping)
        if ref and ref not in refs:
            refs.append(ref)
    return mappings, refs


def _command_observation(
    *,
    session_id: str,
    command: str,
    original_command: str,
    timestamp: str,
    eventid: str,
    outcome: str,
    outcome_scope: str,
    compound_index: int,
    fragment_index: int,
    fragment_count: int,
    operator_before: str,
    operator_after: str,
    source_index: int,
    source_refs: List[str],
    mappings: List[Dict[str, Any]],
    cwd: str = "",
    policy_document: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    extracted = extract_command_entities(
        command,
        cwd=cwd,
        operator_before=operator_before,
        operator_after=operator_after,
        policy_document=policy_document,
    )
    evidence_id = stable_id(
        "command_action",
        {
            "session_id": session_id,
            "timestamp": timestamp,
            "original_command": original_command,
            "fragment_index": fragment_index,
            "command": command,
            # Source occurrence is part of identity.  Two identical commands can
            # legitimately arrive at the same timestamp and must remain separate
            # evidence observations while still being marked as duplicates below.
            "source_index": source_index,
        },
    )
    return {
        "evidence_id": evidence_id,
        "evidence_type": "direct_cowrie_command_observation",
        "source_evidence_refs": list(dict.fromkeys(ref for ref in source_refs if ref)),
        "command": command,
        "original_command": original_command,
        "timestamp": timestamp,
        "cowrie_eventid": eventid,
        "command_outcome": outcome,
        "outcome_scope": outcome_scope,
        "compound_command_index": compound_index,
        "fragment_index": fragment_index,
        "fragment_count": fragment_count,
        "operator_before": operator_before,
        "operator_after": operator_after,
        "source_index": source_index,
        "action_types": extracted["action_types"],
        "entities": extracted["entities"],
        "pipe_producer": extracted["pipe_producer"],
        "pipe_consumer": extracted["pipe_consumer"],
        "trusted_attck_mappings": mappings,
        "attck_mapping_semantics": (
            "trusted_candidate_mappings_attached"
            if mappings else "no_attck_mapping_promoted_from_literal_action"
        ),
    }


def _build_command_observations(
    session_payload: Dict[str, Any],
    policy_document: Dict[str, Any],
) -> List[Dict[str, Any]]:
    session_id = _clean(session_payload.get("session_id")) or "unknown"
    classification_events = [
        dict(item)
        for item in _as_list(session_payload.get("classification_events"))
        if isinstance(item, dict)
    ]
    raw_events = [
        dict(item)
        for item in _as_list(session_payload.get("raw_events"))
        if isinstance(item, dict)
    ]
    observations: List[Dict[str, Any]] = []
    covered: set[Tuple[str, str]] = set()
    compound_index = 0
    command_eventids = set(
        (_policy_section(policy_document, "event_types").get("command") or [])
    )

    for source_index, event in enumerate(raw_events):
        eventid = _clean(event.get("eventid"))
        if eventid not in command_eventids:
            continue
        original = _clean(event.get("input"))
        if not original:
            continue
        timestamp = _clean(event.get("timestamp"))
        fragments = split_compound_command(original, split_pipes=True)
        outcome = _command_outcome(event)
        outcome_scope = "compound_event" if len(fragments) > 1 else "fragment"
        raw_ref = _event_evidence_id(session_id, source_index, event)
        for fragment in fragments:
            mappings, mapping_refs = _trusted_mappings_for_fragment(
                classification_events,
                timestamp=timestamp,
                original_command=original,
                fragment=fragment.text,
                fragment_index=fragment.index,
            )
            observations.append(_command_observation(
                session_id=session_id,
                command=fragment.text,
                original_command=original,
                timestamp=timestamp,
                eventid=eventid,
                outcome=outcome,
                outcome_scope=outcome_scope,
                compound_index=compound_index,
                fragment_index=fragment.index,
                fragment_count=fragment.count,
                operator_before=fragment.operator_before,
                operator_after=fragment.operator_after,
                source_index=source_index,
                source_refs=[raw_ref] + mapping_refs,
                mappings=mappings,
                cwd=_clean(event.get("cwd")),
                policy_document=policy_document,
            ))
        covered.add((timestamp, original))
        compound_index += 1

    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for index, event in enumerate(classification_events):
        timestamp = _clean(event.get("event_timestamp"))
        original = _clean(event.get("original_command") or event.get("command"))
        if not original or (timestamp, original) in covered:
            continue
        key = (timestamp, original, _clean(event.get("cowrie_eventid")))
        grouped.setdefault(key, []).append({**event, "_source_index": index})

    for (timestamp, original, eventid), events in grouped.items():
        fragments = split_compound_command(original, split_pipes=True)
        first = events[0]
        outcome = _clean(first.get("command_outcome")) or "legacy_outcome_unknown"
        declared_scope = _clean(first.get("outcome_scope"))
        for fragment in fragments:
            matching_event = next(
                (
                    item for item in events
                    if _clean(item.get("subcommand") or item.get("command")) == fragment.text
                ),
                first,
            )
            fragment_outcome = _clean(matching_event.get("command_outcome")) or outcome
            fragment_scope = _clean(matching_event.get("outcome_scope")) or declared_scope
            outcome_scope = fragment_scope or (
                "compound_event" if len(fragments) > 1 else "legacy_unknown"
            )
            mappings, refs = _trusted_mappings_for_fragment(
                classification_events,
                timestamp=timestamp,
                original_command=original,
                fragment=fragment.text,
                fragment_index=fragment.index,
            )
            observations.append(_command_observation(
                session_id=session_id,
                command=fragment.text,
                original_command=original,
                timestamp=timestamp,
                eventid=eventid,
                outcome=fragment_outcome,
                outcome_scope=outcome_scope,
                compound_index=compound_index,
                fragment_index=fragment.index,
                fragment_count=fragment.count,
                operator_before=fragment.operator_before,
                operator_after=fragment.operator_after,
                source_index=int(matching_event.get("_source_index") or 0),
                source_refs=refs,
                mappings=mappings,
                policy_document=policy_document,
            ))
        compound_index += 1

    if not observations:
        for source_index, original in enumerate(_as_list(session_payload.get("commands"))):
            original = _clean(original)
            for fragment in split_compound_command(original, split_pipes=True):
                observations.append(_command_observation(
                    session_id=session_id,
                    command=fragment.text,
                    original_command=original,
                    timestamp="",
                    eventid="",
                    outcome="legacy_outcome_unknown",
                    outcome_scope="legacy_unknown",
                    compound_index=source_index,
                    fragment_index=fragment.index,
                    fragment_count=fragment.count,
                    operator_before=fragment.operator_before,
                    operator_after=fragment.operator_after,
                    source_index=source_index,
                    source_refs=[],
                    mappings=[],
                    policy_document=policy_document,
                ))

    observations.sort(key=_sort_key)
    seen_signatures: Dict[Tuple[Any, ...], str] = {}
    for sequence_index, item in enumerate(observations):
        item["sequence_index"] = sequence_index
        entity_signature = tuple(sorted(
            entity["entity_id"]
            for values in item.get("entities", {}).values()
            for entity in values
        ))
        signature = (
            item.get("command"),
            tuple(item.get("action_types") or []),
            entity_signature,
        )
        item["duplicate_of"] = seen_signatures.get(signature, "")
        seen_signatures.setdefault(signature, item["evidence_id"])
    return observations


def _build_transfer_observations(
    session_payload: Dict[str, Any],
    policy_document: Dict[str, Any],
) -> List[Dict[str, Any]]:
    session_id = _clean(session_payload.get("session_id")) or "unknown"
    observations: List[Dict[str, Any]] = []
    transfer_eventids = set(
        (_policy_section(policy_document, "event_types").get("transfer") or [])
    )
    hash_pattern = compile_pattern(
        policy_document,
        ((_policy_section(policy_document, "extraction").get("patterns") or {}).get("hash")),
    )
    for source_index, event in enumerate(_as_list(session_payload.get("raw_events"))):
        if not isinstance(event, dict) or _clean(event.get("eventid")) not in transfer_eventids:
            continue
        entities: Dict[str, List[Dict[str, Any]]] = {
            "urls": [], "destination_paths": [], "artifact_hashes": [],
        }
        path = _clean(event.get("outfile") or event.get("destfile"))
        if path:
            _add_entity(entities, "destination_paths", "path", path, _clean(event.get("cwd")))
        url = _clean(event.get("url"))
        if url:
            _add_entity(entities, "urls", "url", url)
        digest = _clean(event.get("shasum")).lower()
        if digest and hash_pattern.fullmatch(digest):
            entities["artifact_hashes"].append({
                "entity_id": stable_id("entity", {"type": "hash", "value": digest}),
                "entity_type": "hash",
                "normalized_value": digest,
                "original_value": digest,
                "uncertain": False,
                "linkable": True,
            })
        evidence_id = _event_evidence_id(session_id, source_index, event)
        observations.append({
            "evidence_id": evidence_id,
            "evidence_type": "direct_cowrie_transfer_event",
            "eventid": _clean(event.get("eventid")),
            "timestamp": _clean(event.get("timestamp")),
            "source_index": source_index,
            "action_types": ["cowrie_file_transfer_observed"],
            "action_status": "reported_success",
            "entities": entities,
            "limitations": [
                "Transfer into the Cowrie simulation does not establish execution or real-world compromise."
            ],
        })
    observations.sort(key=_sort_key)
    return observations


def _action_status(action: Dict[str, Any]) -> str:
    outcome = _clean(action.get("command_outcome"))
    scope = _clean(action.get("outcome_scope"))
    if scope == "fragment" and outcome == "cowrie_reported_success":
        return "reported_success"
    if scope == "fragment" and outcome == "cowrie_reported_failure":
        return "reported_failure"
    if outcome in {"cowrie_reported_success", "cowrie_reported_failure"}:
        return "compound_outcome_not_fragment_proof"
    return "outcome_unknown"


def _relationship(
    relationship_type: str,
    source: Dict[str, Any],
    target: Dict[str, Any],
    *,
    entity: Optional[Dict[str, Any]] = None,
    status: str = "supported",
    basis: Iterable[str] = (),
    limitations: Iterable[str] = (),
    connects_chain: bool = True,
) -> Dict[str, Any]:
    entity = entity or {}
    payload = {
        "type": relationship_type,
        "source": source.get("evidence_id"),
        "target": target.get("evidence_id"),
        "entity": entity.get("entity_id"),
    }
    return {
        "relationship_id": stable_id("relationship", payload),
        "relationship_type": relationship_type,
        "source_evidence_ref": source.get("evidence_id"),
        "target_evidence_ref": target.get("evidence_id"),
        "entity_ref": entity.get("entity_id", ""),
        "entity_type": entity.get("entity_type", "shell_structure"),
        "entity_value": entity.get("normalized_value", ""),
        "relationship_status": status,
        "basis": list(dict.fromkeys(_clean(item) for item in basis if _clean(item))),
        "limitations": list(dict.fromkeys(_clean(item) for item in limitations if _clean(item))),
        "connects_behavior_chain": connects_chain,
        "causality_semantics": "evidence_link_not_causal_proof",
    }


def _entity_roles(action: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    return action.get("entities") or {}


def _path_action_records(
    actions: List[Dict[str, Any]],
    policy_document: Dict[str, Any],
) -> Dict[str, List[Tuple[Dict[str, Any], str, Dict[str, Any]]]]:
    records: Dict[str, List[Tuple[Dict[str, Any], str, Dict[str, Any]]]] = {}
    role_actions = (_policy_section(policy_document, "relationships").get("path_action_roles") or {})
    for action in actions:
        if (action.get("conditional_execution") or {}).get("status") == "condition_not_satisfied":
            continue
        action_types = set(action.get("action_types") or [])
        for role, required_action in role_actions.items():
            if required_action not in action_types:
                continue
            for entity in _entity_roles(action).get(role) or []:
                records.setdefault(entity["entity_id"], []).append((action, required_action, entity))
    for values in records.values():
        values.sort(key=lambda item: _sort_key(item[0]))
    return records


def _build_relationships(
    actions: List[Dict[str, Any]],
    transfers: List[Dict[str, Any]],
    policy_document: Dict[str, Any],
) -> List[Dict[str, Any]]:
    relationships: List[Dict[str, Any]] = []
    extraction = _policy_section(policy_document, "extraction")
    account_definition = extraction.get("account") or {}
    account_action_type = _clean(account_definition.get("action_type"))
    account_relationship_type = _clean(account_definition.get("relationship_type"))
    relationship_policy = _policy_section(policy_document, "relationships")
    allowed_predecessors = relationship_policy.get("allowed_predecessors") or {}
    relationship_types = relationship_policy.get("relationship_types") or {}
    for action in actions:
        action["action_status"] = _action_status(action)

    by_compound: Dict[int, List[Dict[str, Any]]] = {}
    for action in actions:
        by_compound.setdefault(int(action.get("compound_command_index") or 0), []).append(action)
    for items in by_compound.values():
        items.sort(key=lambda item: int(item.get("fragment_index") or 0))
        for previous, current in zip(items, items[1:]):
            operator = _clean(current.get("operator_before"))
            if operator == "|":
                relationships.append(_relationship(
                    "piped_to", previous, current,
                    basis=["explicit_pipe_operator", "adjacent_pipeline_fragments"],
                    limitations=["Pipeline syntax supports data flow, not successful command execution."],
                ))
            elif operator in {"&&", "||"}:
                expected = "cowrie_reported_success" if operator == "&&" else "cowrie_reported_failure"
                status = "partially_supported"
                condition_status = "condition_unknown"
                connects_chain = True
                limitations = ["Fragment-level outcome is unavailable; conditional execution is not established."]
                if previous.get("outcome_scope") == "fragment":
                    predecessor_outcome = previous.get("command_outcome")
                    if predecessor_outcome == expected:
                        status = "supported"
                        condition_status = "condition_satisfied"
                        limitations = []
                    elif predecessor_outcome in {
                        "cowrie_reported_success",
                        "cowrie_reported_failure",
                    }:
                        status = "partially_supported"
                        condition_status = "condition_not_satisfied"
                        connects_chain = False
                        limitations = ["The reported predecessor outcome does not satisfy this shell condition."]
                current["conditional_execution"] = {
                    "operator": operator,
                    "status": condition_status,
                    "predecessor_evidence_ref": previous.get("evidence_id"),
                    "semantics": "shell_condition_not_fragment_execution_proof",
                }
                if condition_status == "condition_not_satisfied":
                    current["action_status"] = "conditional_not_observed"
                relationships.append(_relationship(
                    "conditional_successor" if operator == "&&" else "conditional_failure_successor",
                    previous,
                    current,
                    status=status,
                    basis=["explicit_shell_operator", "adjacent_compound_fragments"],
                    limitations=limitations,
                    connects_chain=connects_chain,
                ))
            elif operator in {";", "\\n"}:
                relationships.append(_relationship(
                    "explicit_sequence", previous, current,
                    status="supported",
                    basis=["explicit_shell_sequence_operator"],
                    limitations=["Sequence alone does not establish a shared objective or causal dependency."],
                    connects_chain=False,
                ))

    account_records: Dict[str, List[Tuple[Dict[str, Any], Dict[str, Any]]]] = {}
    for action in actions:
        if account_action_type not in set(action.get("action_types") or []):
            continue
        if (action.get("conditional_execution") or {}).get("status") == "condition_not_satisfied":
            continue
        for entity in _entity_roles(action).get("account_names") or []:
            account_records.setdefault(entity["entity_id"], []).append((action, entity))
    for records in account_records.values():
        records.sort(key=lambda item: _sort_key(item[0]))
        for (source, _), (target, entity) in zip(records, records[1:]):
            status = "supported"
            limitations: List[str] = []
            if _action_status(source) != "reported_success" or _action_status(target) != "reported_success":
                status = "partially_supported"
                limitations.append("Account-related command completion is failed, compound-scoped, or unknown.")
            relationships.append(_relationship(
                account_relationship_type,
                source,
                target,
                entity=entity,
                status=status,
                basis=["shared_normalized_account", "chronological_order"],
                limitations=limitations,
            ))

    for values in _path_action_records(actions, policy_document).values():
        previous_records: List[Tuple[Dict[str, Any], str, Dict[str, Any]]] = []
        for current, action_type, entity in values:
            allowed_previous = set(allowed_predecessors.get(action_type) or [])
            candidates = [record for record in previous_records if record[1] in allowed_previous]
            if candidates:
                source, _, _ = candidates[-1]
                status = "supported" if entity.get("linkable") else "partially_supported"
                limitations: List[str] = []
                if not entity.get("linkable"):
                    limitations.append("The shared relative or expanded path could not be resolved absolutely.")
                if _action_status(source) in {"reported_failure", "compound_outcome_not_fragment_proof"}:
                    status = "partially_supported"
                    limitations.append("The predecessor outcome does not prove successful completion.")
                if _action_status(current) in {"reported_failure", "compound_outcome_not_fragment_proof", "outcome_unknown"}:
                    status = "partially_supported"
                    limitations.append("The target action outcome is failed, compound-scoped, or unknown.")
                relationship_type = _clean(relationship_types.get(action_type))
                if not relationship_type:
                    previous_records.append((current, action_type, entity))
                    continue
                relationships.append(_relationship(
                    relationship_type,
                    source,
                    current,
                    entity=entity,
                    status=status,
                    basis=[
                        "shared_normalized_path" if entity.get("linkable") else "shared_unresolved_path",
                        "chronological_order",
                    ],
                    limitations=limitations,
                ))
            previous_records.append((current, action_type, entity))

    for transfer in transfers:
        transfer_time = _parse_timestamp(transfer.get("timestamp"))
        candidates: List[Tuple[int, Dict[str, Any], Dict[str, Any], str]] = []
        transfer_entities = _entity_roles(transfer)
        for action in actions:
            if "transfer_attempt" not in set(action.get("action_types") or []):
                continue
            action_time = _parse_timestamp(action.get("timestamp"))
            if transfer_time and action_time and action_time > transfer_time:
                continue
            for priority, role in ((3, "destination_paths"), (2, "urls"), (1, "artifact_hashes")):
                transfer_by_id = {item["entity_id"]: item for item in transfer_entities.get(role) or []}
                shared = [item for item in _entity_roles(action).get(role) or [] if item["entity_id"] in transfer_by_id]
                for entity in shared:
                    candidates.append((priority, action, entity, role))
        if not candidates:
            continue
        best_priority = max(item[0] for item in candidates)
        best = [item for item in candidates if item[0] == best_priority]
        unique_actions = {item[1]["evidence_id"] for item in best}
        if len(unique_actions) != 1:
            continue
        _, action, entity, role = best[-1]
        status = "partially_supported" if _action_status(action) == "reported_failure" else "supported"
        limitations = []
        if status == "partially_supported":
            limitations.append("Cowrie recorded a transfer event despite a failed command outcome; the conflict is retained.")
        relationships.append(_relationship(
            "cowrie_transfer_observed",
            action,
            transfer,
            entity=entity,
            status=status,
            basis=[f"matching_{role[:-1]}", "same_session", "chronological_order"],
            limitations=limitations,
        ))

    unique: Dict[str, Dict[str, Any]] = {}
    for relationship in relationships:
        unique.setdefault(relationship["relationship_id"], relationship)
    return list(unique.values())


def _collect_entities(
    actions: List[Dict[str, Any]],
    transfers: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    aggregated: Dict[str, Dict[str, Any]] = {}
    for observation in actions + transfers:
        for role, values in _entity_roles(observation).items():
            for value in values:
                entity = aggregated.setdefault(value["entity_id"], {
                    **value,
                    "roles": [],
                    "evidence_refs": [],
                })
                if role not in entity["roles"]:
                    entity["roles"].append(role)
                ref = _clean(observation.get("evidence_id"))
                if ref and ref not in entity["evidence_refs"]:
                    entity["evidence_refs"].append(ref)
    return sorted(aggregated.values(), key=lambda item: (item["entity_type"], item["normalized_value"]))


def _connected_chains(
    actions: List[Dict[str, Any]],
    transfers: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    policy_document: Dict[str, Any],
) -> List[Dict[str, Any]]:
    nodes = {item["evidence_id"]: item for item in actions + transfers}
    adjacency: Dict[str, set[str]] = {node_id: set() for node_id in nodes}
    connecting = [item for item in relationships if item.get("connects_behavior_chain")]
    for relationship in connecting:
        source = _clean(relationship.get("source_evidence_ref"))
        target = _clean(relationship.get("target_evidence_ref"))
        if source in nodes and target in nodes:
            adjacency[source].add(target)
            adjacency[target].add(source)

    chains: List[Dict[str, Any]] = []
    visited: set[str] = set()
    for node_id, neighbours in adjacency.items():
        if node_id in visited or not neighbours:
            continue
        stack = [node_id]
        component: set[str] = set()
        while stack:
            current = stack.pop()
            if current in component:
                continue
            component.add(current)
            stack.extend(adjacency.get(current, set()) - component)
        visited.update(component)
        ordered = sorted((nodes[item] for item in component), key=_sort_key)
        component_relationships = [
            item for item in connecting
            if item.get("source_evidence_ref") in component and item.get("target_evidence_ref") in component
        ]
        entity_refs = list(dict.fromkeys(
            _clean(item.get("entity_ref"))
            for item in component_relationships
            if _clean(item.get("entity_ref"))
        ))
        action_types = list(dict.fromkeys(
            action_type
            for item in ordered
            for action_type in item.get("action_types") or []
        ))
        limitations = list(dict.fromkeys(
            limitation
            for item in component_relationships
            for limitation in item.get("limitations") or []
        ))
        partial = any(item.get("relationship_status") != "supported" for item in component_relationships)
        if any(
            action_type == "execution_attempt" and _action_status(item) != "reported_success"
            for item in ordered
            for action_type in item.get("action_types") or []
        ):
            partial = True
        signatures = {
            (
                tuple(item.get("action_types") or []),
                tuple(sorted(
                    entity["entity_id"]
                    for values in _entity_roles(item).values()
                    for entity in values
                )),
            )
            for item in ordered
        }
        chain_id = stable_id("behavior_chain", {
            "evidence_refs": [item["evidence_id"] for item in ordered],
            "relationships": [item["relationship_id"] for item in component_relationships],
        })
        follow_on = ((_policy_section(policy_document, "claims").get("follow_on") or {}))
        progress_types = set(follow_on.get("progress_action_types") or [])
        completion_types = set(follow_on.get("completion_action_types") or [])
        has_transfer = bool(progress_types & set(action_types))
        has_execution = bool(completion_types & set(action_types))
        gaps: List[str] = []
        if has_transfer and not has_execution:
            gaps.append("No execution attempt linked to the transferred or referenced artifact was observed.")
        chains.append({
            "chain_id": chain_id,
            "entity_refs": entity_refs,
            "evidence_refs": [item["evidence_id"] for item in ordered],
            "relationships": component_relationships,
            "ordered_actions": ordered,
            "action_types": action_types,
            "chain_status": "partially_supported" if partial else "supported",
            "limitations": limitations,
            "evidence_diversity_count": len(signatures),
            "completion_gaps": gaps,
            "final_relevant_evidence_ref": ordered[-1]["evidence_id"],
            "final_timestamp": _clean(ordered[-1].get("timestamp")),
        })
    chains.sort(key=lambda item: (_parse_timestamp(item.get("final_timestamp")) or datetime.min.replace(tzinfo=timezone.utc), item["chain_id"]))
    return chains


def build_session_behavior_relationships(
    session_payload: Dict[str, Any],
    *,
    policy_document: Optional[Dict[str, Any]] = None,
    policy_path: str = "",
) -> Dict[str, Any]:
    """Build additive literal-action, entity, relationship, and chain evidence."""

    document = _resolved_policy(policy_document, policy_path)
    actions = _build_command_observations(session_payload, document)
    transfers = _build_transfer_observations(session_payload, document)
    relationships = _build_relationships(actions, transfers, document)
    chains = _connected_chains(actions, transfers, relationships, document)
    return {
        "schema_version": SCHEMA_VERSION,
        "behavior_policy": policy_summary(document),
        "ordered_command_observations": actions,
        "transfer_event_observations": transfers,
        "normalized_entities": _collect_entities(actions, transfers),
        "behavior_relationships": relationships,
        "connected_behavior_chains": chains,
        "semantics": (
            "Literal Cowrie command actions are linked only by explicit shell structure or shared "
            "normalized entities. They do not promote untrusted ATT&CK mappings or prove causality."
        ),
    }
