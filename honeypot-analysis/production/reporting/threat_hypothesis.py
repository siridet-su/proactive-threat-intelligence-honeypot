"""Deterministic observed-evidence relationships for session assessment v4.

This retained core builds evidence, supported behavioral findings, and bounded
falsifiable alternatives.  Historical v2/v3 records are read through the
immutable adapters in :mod:`session_assessment_v4`; no legacy report is
generated here.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

from production.correlation.session_evidence_graph import build_session_evidence_graph
from production.policies.threat_hypothesis_behavior_policy import (
    compile_pattern,
    policy_body,
    policy_summary,
    resolve_behavior_policy,
)
from production.utils.serialization import stable_id


EVIDENCE_STATUSES = {"supported", "partially_supported", "insufficient_evidence"}

_UNSUPPORTED_NARRATIVE_RE = re.compile(
    r"\b(?:confirmed\s+(?:compromise|intent|attribution)|definitive(?:ly)?|"
    r"successfully\s+(?:compromised|executed|persisted|exfiltrated|stole|harvested)|"
    r"attributed\s+to|the\s+actor\s+is|coordinated\s+campaign|"
    r"real[- ]world\s+compromise)\b",
    re.IGNORECASE,
)
_COMPLETED_TRANSFER_NARRATIVE_RE = re.compile(
    r"\b(?:downloaded|uploaded|transferred)\s+(?:file|artifact|payload|tool)\b|"
    r"\b(?:file|artifact|payload|tool)\s+(?:was\s+)?(?:downloaded|uploaded|transferred)\b",
    re.IGNORECASE,
)
_OPERATOR_ACTION_RE = re.compile(
    r"\b(?:block|disable|delete|patch|quarantine|isolate)\b",
    re.IGNORECASE,
)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _texts(values: Iterable[Any]) -> List[str]:
    output: List[str] = []
    for value in values or []:
        text = _clean(value.get("text")) if isinstance(value, dict) else _clean(value)
        if text and text not in output:
            output.append(text)
    return output


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _resolved_behavior_policy(
    policy_document: Optional[Dict[str, Any]] = None,
    policy_path: str = "",
) -> Dict[str, Any]:
    return resolve_behavior_policy(policy_document, policy_path)


def _claim_policy(document: Dict[str, Any]) -> Dict[str, Any]:
    body = policy_body(document)
    if not body.get("enabled"):
        return {}
    claims = body.get("claims")
    return claims if isinstance(claims, dict) else {}


def _session_value(session: Any, name: str, default: Any = None) -> Any:
    if isinstance(session, dict):
        return session.get(name, default)
    return getattr(session, name, default)


def _first_session_payload(sessions: Iterable[Any], raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    session_list = list(sessions or [])
    session = session_list[0] if session_list else {}
    return {
        "session_id": _session_value(session, "session_id", "unknown"),
        "src_ip": _clean(_session_value(session, "src_ip", "")),
        "commands": list(_session_value(session, "commands", []) or []),
        "commands_success": list(_session_value(session, "commands_success", []) or []),
        "commands_failed": list(_session_value(session, "commands_failed", []) or []),
        "classification_events": list(_session_value(session, "classification_events", []) or []),
        "raw_events": list(raw_events or _session_value(session, "raw_events", []) or []),
        "login_success": bool(_session_value(session, "login_success", False)),
        "session_evidence_graph": _session_value(session, "session_evidence_graph", {}) or {},
    }


def _event_evidence(raw_events: List[Dict[str, Any]], session_id: str) -> List[Dict[str, Any]]:
    allowed_eventids = {
        "cowrie.command.input",
        "cowrie.command.success",
        "cowrie.command.failed",
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
    }
    output: List[Dict[str, Any]] = []
    for index, event in enumerate(raw_events or []):
        if not isinstance(event, dict):
            continue
        eventid = _clean(event.get("eventid"))
        if eventid not in allowed_eventids:
            continue
        item = {
            "evidence_id": stable_id(
                "cowrie",
                {
                    "session_id": session_id,
                    "index": index,
                    "eventid": eventid,
                    "timestamp": event.get("timestamp"),
                    "shasum": event.get("shasum"),
                },
            ),
            "eventid": eventid,
            "timestamp": _clean(event.get("timestamp")),
            "evidence_type": "direct_cowrie_event",
        }
        if eventid in {"cowrie.command.success", "cowrie.command.failed"}:
            item["command_outcome"] = (
                "cowrie_reported_success"
                if eventid == "cowrie.command.success"
                else "cowrie_reported_failure"
            )
        if eventid in {"cowrie.session.file_download", "cowrie.session.file_upload"}:
            item["sha256"] = _clean(event.get("shasum"))
            item["transfer_observed"] = True
        output.append(item)
    return output


def build_observed_behavior(
    sessions: Iterable[Any],
    raw_events: Optional[List[Dict[str, Any]]] = None,
    *,
    behavior_policy_document: Optional[Dict[str, Any]] = None,
    behavior_policy_path: str = "",
) -> Dict[str, Any]:
    document = _resolved_behavior_policy(behavior_policy_document, behavior_policy_path)
    payload = _first_session_payload(sessions, list(raw_events or []))
    graph = payload.get("session_evidence_graph") or {}
    if (
        (
            payload.get("classification_events")
            or payload.get("raw_events")
            or payload.get("commands")
        )
        and (
            not graph.get("ordered_behavior_chain")
            or "connected_behavior_chains" not in graph
        )
    ):
        graph = build_session_evidence_graph(
            payload,
            behavior_policy_document=document,
            behavior_policy_path=behavior_policy_path,
        )
    chain = [dict(item) for item in graph.get("ordered_behavior_chain") or [] if isinstance(item, dict)]
    audit_only = [
        dict(item)
        for item in graph.get("audit_only_classification_candidates") or []
        if isinstance(item, dict)
    ]
    trusted_candidates = [
        {
            "evidence_id": _clean(item.get("evidence_id")),
            "sequence_index": item.get("sequence_index"),
            "technique_id": _clean(item.get("ttp")),
            "tactic": _clean(item.get("tactic")),
            "source": _clean(item.get("source")),
            "agreement_status": _clean(item.get("agreement_status")),
            "command_outcome": _clean(item.get("command_outcome")),
            "confidence": item.get("confidence"),
            "confidence_semantics": _clean(item.get("confidence_semantics")),
            "mapping_semantics": "candidate_attck_mapping_from_observed_command",
        }
        for item in chain
    ]
    adjacent_tactics: List[str] = []
    for item in chain:
        tactic = _clean(item.get("tactic"))
        if tactic and (not adjacent_tactics or adjacent_tactics[-1] != tactic):
            adjacent_tactics.append(tactic)
    events = _event_evidence(payload.get("raw_events") or [], _clean(payload.get("session_id")))
    return {
        "session_id": _clean(payload.get("session_id")) or "unknown",
        "src_ip": _clean(payload.get("src_ip")),
        "behavior_policy": graph.get("behavior_policy") or policy_summary(document),
        "ordered_behavior_chain": chain,
        "ordered_command_observations": [
            dict(item)
            for item in graph.get("ordered_command_observations") or []
            if isinstance(item, dict)
        ],
        "transfer_event_observations": [
            dict(item)
            for item in graph.get("transfer_event_observations") or []
            if isinstance(item, dict)
        ],
        "normalized_entities": [
            dict(item)
            for item in graph.get("normalized_entities") or []
            if isinstance(item, dict)
        ],
        "behavior_relationships": [
            dict(item)
            for item in graph.get("behavior_relationships") or []
            if isinstance(item, dict)
        ],
        "connected_behavior_chains": [
            dict(item)
            for item in graph.get("connected_behavior_chains") or []
            if isinstance(item, dict)
        ],
        "relationship_semantics": _clean(graph.get("relationship_semantics")),
        "trusted_attck_candidates": trusted_candidates,
        "audit_only_candidates": audit_only,
        "cowrie_event_evidence": events,
        "adjacent_deduplicated_tactic_sequence": adjacent_tactics,
        "observation_semantics": (
            "Commands and Cowrie events are observations. ATT&CK labels are candidate mappings; "
            "they do not prove attacker intent or real-world impact."
        ),
    }


def _claim(
    claim_type: str,
    text: str,
    evidence_status: str,
    evidence_refs: Iterable[str],
    limitations: Iterable[str],
) -> Dict[str, Any]:
    status = evidence_status if evidence_status in EVIDENCE_STATUSES else "insufficient_evidence"
    refs = [_clean(value) for value in evidence_refs if _clean(value)]
    return {
        "claim_id": stable_id("claim", {"type": claim_type, "text": text, "evidence_refs": refs}),
        "claim_type": claim_type,
        "text": text,
        "evidence_status": status,
        "evidence_refs": refs,
        "limitations": [_clean(value) for value in limitations if _clean(value)],
    }


def _matching_chain(chain: List[Dict[str, Any]], pattern: re.Pattern[str]) -> List[Dict[str, Any]]:
    return [item for item in chain if pattern.search(_clean(item.get("command")))]


def _persistence_chain(
    observed: Dict[str, Any],
    chain: List[Dict[str, Any]],
    pattern: re.Pattern[str],
    policy_document: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Return persistence mappings only when write-sensitive evidence agrees.

    The trusted policy also recognizes persistence families such as account
    creation, cron, services, and startup files.  Only ``authorized_keys`` is
    special here: mentioning or reading that path is not modification evidence.
    The literal command extractor remains authoritative for that distinction.
    """

    matches = _matching_chain(chain, pattern)
    account = ((policy_body(policy_document).get("extraction") or {}).get("account") or {})
    marker = _clean(account.get("authorized_keys_marker")).lower()
    if not marker:
        return matches
    observations = [
        item
        for item in observed.get("ordered_command_observations") or []
        if isinstance(item, dict)
    ]
    output: List[Dict[str, Any]] = []
    for item in matches:
        command = _clean(item.get("command"))
        if marker not in command.lower():
            output.append(item)
            continue
        timestamp = _clean(item.get("timestamp"))
        mutating = any(
            _clean(observation.get("command")) == command
            and (not timestamp or _clean(observation.get("timestamp")) == timestamp)
            and "account_modification_attempt" in set(observation.get("action_types") or [])
            for observation in observations
        )
        if mutating:
            output.append(item)
    return output


def _event_refs(observed: Dict[str, Any], eventid: str) -> List[str]:
    return [
        _clean(item.get("evidence_id"))
        for item in observed.get("cowrie_event_evidence") or []
        if item.get("eventid") == eventid and _clean(item.get("evidence_id"))
    ]


def _chain_refs(items: Iterable[Dict[str, Any]]) -> List[str]:
    return [_clean(item.get("evidence_id")) for item in items if _clean(item.get("evidence_id"))]


def _behavior_summary(observed: Dict[str, Any]) -> str:
    chain = observed.get("ordered_behavior_chain") or []
    if not chain:
        return "No trusted command-to-ATT&CK candidate mappings were available for this session."
    tactics: List[str] = []
    for item in chain:
        tactic = _clean(item.get("tactic"))
        if tactic and tactic not in tactics:
            tactics.append(tactic)
    transfer_count = len(_event_refs(observed, "cowrie.session.file_download"))
    summary = f"Observed {len(chain)} trusted command mapping(s) across tactics: {', '.join(tactics) or 'unknown'}."
    if transfer_count:
        summary += f" Cowrie recorded {transfer_count} successful file-transfer event(s); execution is not implied."
    connected_count = len(observed.get("connected_behavior_chains") or [])
    if connected_count:
        summary += f" {connected_count} evidence-linked behavior chain(s) were identified."
    return summary


def _literal_actions(observed: Dict[str, Any], *action_types: str) -> List[Dict[str, Any]]:
    wanted = set(action_types)
    return [
        item
        for item in observed.get("ordered_command_observations") or []
        if (
            isinstance(item, dict)
            and wanted.intersection(item.get("action_types") or [])
            and (item.get("conditional_execution") or {}).get("status") != "condition_not_satisfied"
        )
    ]


def _action_refs(items: Iterable[Dict[str, Any]]) -> List[str]:
    return [_clean(item.get("evidence_id")) for item in items if _clean(item.get("evidence_id"))]


def _connected_behavior_claims(
    observed: Dict[str, Any],
    policy_document: Dict[str, Any],
) -> List[Dict[str, Any]]:
    claims: List[Dict[str, Any]] = []
    definitions = _claim_policy(policy_document).get("connected") or []
    for chain in observed.get("connected_behavior_chains") or []:
        if not isinstance(chain, dict):
            continue
        action_types = set(chain.get("action_types") or [])
        status = (
            "supported"
            if chain.get("chain_status") == "supported"
            else "partially_supported"
        )
        matched_rule: Dict[str, Any] = {}
        for definition in definitions:
            if not isinstance(definition, dict):
                continue
            required = set(definition.get("required_action_types") or [])
            excluded = set(definition.get("excluded_action_types") or [])
            if required.issubset(action_types) and not excluded.intersection(action_types):
                matched_rule = definition
                break
        if not matched_rule:
            continue
        override = _clean(matched_rule.get("evidence_status_override"))
        if override in EVIDENCE_STATUSES:
            status = override
        limitations = list(chain.get("limitations") or []) + list(
            matched_rule.get("limitations") or []
        )
        claim = _claim(
            _clean(matched_rule.get("claim_type")),
            _clean(matched_rule.get("text")),
            status,
            chain.get("evidence_refs") or [],
            list(dict.fromkeys(limitations)),
        )
        claim.update({
            "claim_basis": "connected_behavior_chain",
            "connected_chain_id": _clean(chain.get("chain_id")),
            "behavior_policy_rule_id": _clean(matched_rule.get("rule_id")),
            "relationship_refs": [
                _clean(item.get("relationship_id"))
                for item in chain.get("relationships") or []
                if isinstance(item, dict) and _clean(item.get("relationship_id"))
            ],
        })
        claims.append(claim)
    return claims


def build_supported_assessment(
    observed: Dict[str, Any],
    behavior_policy_document: Optional[Dict[str, Any]] = None,
    behavior_policy_path: str = "",
) -> Dict[str, Any]:
    document = _resolved_behavior_policy(behavior_policy_document, behavior_policy_path)
    claims_policy = _claim_policy(document)
    independent = claims_policy.get("independent") or {}
    chain = list(observed.get("ordered_behavior_chain") or [])
    connected_claims = _connected_behavior_claims(observed, document)
    objectives: List[Dict[str, Any]] = list(connected_claims)
    credential_definition = independent.get("credential") or {}
    downloader_definition = independent.get("downloader") or {}
    execution_definition = independent.get("execution") or {}
    persistence_definition = independent.get("persistence") or {}
    cleanup_definition = independent.get("cleanup") or {}
    download_definition = independent.get("confirmed_download") or {}
    credential = _matching_chain(
        chain,
        compile_pattern(document, credential_definition.get("trusted_command_pattern")),
    )
    literal_downloader = _literal_actions(
        observed,
        *(downloader_definition.get("literal_action_types") or []),
    )
    downloader = literal_downloader or (
        _matching_chain(
            chain,
            compile_pattern(document, downloader_definition.get("legacy_command_pattern")),
        )
        if not observed.get("ordered_command_observations") else []
    )
    literal_execution = _literal_actions(
        observed,
        *(execution_definition.get("literal_action_types") or []),
    )
    execution = literal_execution or (
        _matching_chain(
            chain,
            compile_pattern(document, execution_definition.get("legacy_command_pattern")),
        )
        if not observed.get("ordered_command_observations") else []
    )
    persistence = _persistence_chain(
        observed,
        chain,
        compile_pattern(document, persistence_definition.get("trusted_command_pattern")),
        document,
    )
    cleanup = _matching_chain(
        chain,
        compile_pattern(document, cleanup_definition.get("trusted_command_pattern")),
    )
    confirmed_eventids = (
        (policy_body(document).get("event_types") or {}).get("confirmed_download") or []
    )
    download_refs = list(dict.fromkeys(
        ref
        for eventid in confirmed_eventids
        for ref in _event_refs(observed, eventid)
    ))

    if credential:
        objectives.append(_claim(
            _clean(credential_definition.get("claim_type")),
            _clean(credential_definition.get("text")),
            _clean(credential_definition.get("evidence_status")) or "partially_supported",
            _chain_refs(credential),
            credential_definition.get("limitations") or [],
        ))
    if downloader:
        objectives.append(_claim(
            _clean(downloader_definition.get("claim_type")),
            _clean(downloader_definition.get("text")),
            _clean(downloader_definition.get("evidence_status")) or "partially_supported",
            _action_refs(downloader),
            downloader_definition.get("limitations") or [],
        ))
    if download_refs:
        objectives.append(_claim(
            _clean(download_definition.get("claim_type")),
            _clean(download_definition.get("text")),
            _clean(download_definition.get("evidence_status")) or "supported",
            download_refs,
            download_definition.get("limitations") or [],
        ))
    if execution:
        successful_execution = [
            item
            for item in execution
            if item.get("command_outcome") == "cowrie_reported_success"
        ]
        unsuccessful_or_unknown = [
            item
            for item in execution
            if item.get("command_outcome") != "cowrie_reported_success"
        ]
        if successful_execution:
            objectives.append(_claim(
                _clean((execution_definition.get("claim_types") or {}).get("success")),
                "Cowrie reported success for an explicit artifact-execution command in the simulated shell.",
                "supported",
                _action_refs(successful_execution),
                ["Cowrie-reported success does not confirm execution on a real victim system."],
            ))
        if unsuccessful_or_unknown:
            failed = all(
                item.get("command_outcome") == "cowrie_reported_failure"
                for item in unsuccessful_or_unknown
            )
            objectives.append(_claim(
                _clean((execution_definition.get("claim_types") or {}).get("failure_or_unknown")),
                (
                    "Cowrie reported failure for an explicit artifact-execution command."
                    if failed
                    else "An explicit artifact-execution command was observed, but its outcome is unavailable."
                ),
                "supported" if failed else "partially_supported",
                _action_refs(unsuccessful_or_unknown),
                [
                    "Successful artifact execution is not established.",
                    "Cowrie shell behavior does not confirm execution on a real victim system.",
                ],
            ))
    if persistence:
        success = any(item.get("command_outcome") == "cowrie_reported_success" for item in persistence)
        objectives.append(_claim(
            _clean(persistence_definition.get("claim_type")),
            _clean(persistence_definition.get("text")),
            "supported" if success else "partially_supported",
            _chain_refs(persistence),
            persistence_definition.get("limitations") or [],
        ))
    if cleanup:
        success = any(item.get("command_outcome") == "cowrie_reported_success" for item in cleanup)
        objectives.append(_claim(
            _clean(cleanup_definition.get("claim_type")),
            _clean(cleanup_definition.get("text")),
            "supported" if success else "partially_supported",
            _chain_refs(cleanup),
            cleanup_definition.get("limitations") or [],
        ))

    if not objectives:
        status = "observed_behavior_only"
    elif any(item["evidence_status"] == "supported" for item in objectives):
        status = "supported"
    else:
        status = "partially_supported"
    return {
        "behavior_summary": _behavior_summary(observed),
        "assessment_status": status,
        "possible_objectives": objectives,
        "connected_behavior_claims": connected_claims,
        "claim_preference": "connected_behavior_chains_before_independent_command_claims",
        "behavior_policy": policy_summary(document),
        "unknowns": [
            "Named actor identity and intent are not established.",
            "Behavior outside Cowrie-observable SSH telemetry is unknown.",
        ],
    }


def build_follow_on_hypothesis(
    observed: Dict[str, Any],
    behavior_policy_document: Optional[Dict[str, Any]] = None,
    behavior_policy_path: str = "",
) -> Dict[str, Any]:
    document = _resolved_behavior_policy(behavior_policy_document, behavior_policy_path)
    claims_policy = _claim_policy(document)
    follow_on_policy = claims_policy.get("follow_on") or {}
    independent = claims_policy.get("independent") or {}
    persistence_definition = independent.get("persistence") or {}
    progress_types = set(follow_on_policy.get("progress_action_types") or [])
    completion_types = set(follow_on_policy.get("completion_action_types") or [])
    chain = list(observed.get("ordered_behavior_chain") or [])
    claims: List[Dict[str, Any]] = []
    gaps: List[Dict[str, Any]] = []
    disconfirming: List[Dict[str, Any]] = []
    external: List[Dict[str, Any]] = []
    incomplete_chains = []
    for connected in observed.get("connected_behavior_chains") or []:
        if not isinstance(connected, dict):
            continue
        action_types = set(connected.get("action_types") or [])
        has_transfer = bool(progress_types & action_types)
        has_execution = bool(completion_types & action_types)
        if has_transfer and not has_execution:
            incomplete_chains.append(connected)
    if incomplete_chains:
        for connected in incomplete_chains:
            refs = [
                _clean(value)
                for value in connected.get("evidence_refs") or []
                if _clean(value)
            ]
            claim = _claim(
                _clean(follow_on_policy.get("claim_type")),
                _clean(follow_on_policy.get("text")),
                _clean(follow_on_policy.get("evidence_status")) or "partially_supported",
                refs,
                follow_on_policy.get("limitations") or [],
            )
            claim.update({
                "claim_basis": "incomplete_connected_behavior_chain",
                "connected_chain_id": _clean(connected.get("chain_id")),
            })
            claims.append(claim)
            gaps.append({
                "text": "No execution attempt linked to this transferred or referenced artifact was observed.",
                "data_source": "Cowrie command and transfer relationships",
                "machine_evaluable": True,
                "connected_chain_id": _clean(connected.get("chain_id")),
            })
            action_types = set(connected.get("action_types") or [])
            if "cowrie_file_transfer_observed" not in action_types:
                gaps.append({
                    "text": "No Cowrie file-transfer event was linked to this transfer command.",
                    "data_source": "Cowrie session events",
                    "machine_evaluable": True,
                    "connected_chain_id": _clean(connected.get("chain_id")),
                })
            for action in connected.get("ordered_actions") or []:
                if not isinstance(action, dict):
                    continue
                if (
                    "transfer_attempt" in set(action.get("action_types") or [])
                    and action.get("action_status") == "reported_failure"
                ):
                    disconfirming.append({
                        "text": "Cowrie reported failure for a transfer command in this connected chain.",
                        "data_source": "Cowrie command outcome",
                        "machine_evaluable": True,
                        "evidence_refs": [_clean(action.get("evidence_id"))],
                        "connected_chain_id": _clean(connected.get("chain_id")),
                    })
        latest = incomplete_chains[-1]
        session_last = chain[-1] if chain else {}
        return {
            "claims": claims,
            "abstained": False,
            "abstention_reason": "",
            "basis_last_evidence_id": _clean(latest.get("final_relevant_evidence_ref")),
            "basis_session_last_trusted_evidence_id": _clean(session_last.get("evidence_id")),
            "basis_connected_chain_ids": [
                _clean(item.get("chain_id")) for item in incomplete_chains
            ],
            "disconfirming_observations": disconfirming,
            "evidence_gaps": gaps,
            "external_validation_suggestions": external,
            "scope": "post_session_cowrie_observable_behavior",
            "selection_semantics": "all_coherent_incomplete_chains_ordered_by_final_timestamp",
            "behavior_policy": policy_summary(document),
        }
    connected_chains = [
        item
        for item in observed.get("connected_behavior_chains") or []
        if isinstance(item, dict)
    ]
    session_last = chain[-1] if chain else {}
    final_connected = connected_chains[-1] if connected_chains else {}
    ref = _clean(
        final_connected.get("final_relevant_evidence_ref")
        or session_last.get("evidence_id")
    )

    unlinked_transfer_actions = _literal_actions(observed, "transfer_attempt")
    if unlinked_transfer_actions and not connected_chains:
        gaps.extend([
            {
                "text": (
                    "No Cowrie file-download event or explicit successful-download metadata "
                    "was linked to the observed transfer command."
                ),
                "data_source": "Cowrie command and transfer relationships",
                "machine_evaluable": True,
            },
            {
                "text": (
                    "No subsequent explicit artifact-execution command was linked to the "
                    "observed transfer command."
                ),
                "data_source": "Cowrie command and entity relationships",
                "machine_evaluable": True,
            },
        ])
        if not _persistence_chain(
            observed,
            chain,
            compile_pattern(document, persistence_definition.get("trusted_command_pattern")),
            document,
        ):
            gaps.append({
                "text": "No persistence-related command was observed in this session.",
                "data_source": "Cowrie command events",
                "machine_evaluable": True,
            })
    return {
        "claims": [],
        "abstained": True,
        "abstention_reason": (
            "No coherent incomplete connected behavior chain supports a bounded follow-on hypothesis."
        ),
        "basis_last_evidence_id": ref,
        "basis_session_last_trusted_evidence_id": _clean(session_last.get("evidence_id")),
        "basis_connected_chain_ids": [],
        "disconfirming_observations": disconfirming,
        "evidence_gaps": gaps,
        "external_validation_suggestions": external,
        "scope": "post_session_cowrie_observable_behavior",
        "selection_semantics": (
            "no_incomplete_connected_chain_abstention"
            if connected_chains
            else "no_connected_chain_abstention"
        ),
        "behavior_policy": policy_summary(document),
    }
