"""Evidence-grounded Threat Hypothesis v2 construction.

The canonical schema separates Cowrie observations, analytical claims,
post-session follow-on hypotheses, realtime model output, and contextual
intelligence. Legacy report aliases are generated from the canonical fields so
older API and artifact consumers remain readable during migration.
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
from production.reporting.smb_decision import (
    is_trusted_recommendation_action,
    is_trusted_recommendation_decision,
    is_trusted_recommendation_provenance,
)
from production.reporting.session_assessment import (
    attach_forecast_to_session_assessment,
    build_session_assessment_v3,
)
from production.utils.serialization import stable_id


SCHEMA_VERSION = "threat_hypothesis.v2"
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


def build_claim_evidence_summary(
    supported_assessment: Dict[str, Any],
    follow_on_hypothesis: Dict[str, Any],
) -> Dict[str, Any]:
    claims = list(supported_assessment.get("possible_objectives") or []) + list(
        follow_on_hypothesis.get("claims") or []
    )
    counts = {status: 0 for status in sorted(EVIDENCE_STATUSES)}
    for claim in claims:
        status = _clean(claim.get("evidence_status"))
        if status in counts:
            counts[status] += 1
    return {
        "metric_name": "claim_evidence_summary",
        "method": "claim_level_evidence_status_v2",
        "calibrated_probability": False,
        "claim_status_counts": counts,
        "claim_count": len(claims),
        "description": "Per-claim evidence labels; no global probability or confidence score is assigned.",
    }


def _canonical_claim_ids(report: Dict[str, Any]) -> set[str]:
    assessment = report.get("supported_assessment") or {}
    follow_on = report.get("follow_on_hypothesis") or {}
    claims = list(assessment.get("possible_objectives") or []) + list(follow_on.get("claims") or [])
    return {
        _clean(item.get("claim_id"))
        for item in claims
        if isinstance(item, dict) and _clean(item.get("claim_id"))
    }


def apply_validated_vertex_presentation(
    report: Dict[str, Any],
    narrative: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Attach optional Vertex wording without granting it analytical authority.

    The model must cite canonical claim IDs. Any unknown claim reference,
    unsupported high-impact wording, operator action, or ungrounded ATT&CK ID
    rejects the entire narrative. Canonical claims are never mutated.
    """

    presentation = dict(report.get("presentation") or {})
    presentation.setdefault("source", "deterministic_validated_claims")
    presentation.setdefault("ai_enriched", False)
    if not isinstance(narrative, dict):
        presentation["vertex_validation"] = {"status": "not_requested"}
        report["presentation"] = presentation
        return report

    summary = _clean(narrative.get("presentation_summary"))
    cited = {
        _clean(value)
        for value in narrative.get("grounded_claim_ids") or []
        if _clean(value)
    }
    allowed_claims = _canonical_claim_ids(report)
    trusted_ttps = {
        _clean(item.get("technique_id")).upper()
        for item in (report.get("observed_behavior") or {}).get("trusted_attck_candidates") or []
        if isinstance(item, dict) and _clean(item.get("technique_id"))
    }
    transfer_observed = any(
        isinstance(item, dict)
        and item.get("eventid") in {
            "cowrie.session.file_download",
            "cowrie.session.file_upload",
        }
        and bool(item.get("transfer_observed"))
        for item in (report.get("observed_behavior") or {}).get("cowrie_event_evidence") or []
    )
    mentioned_ttps = {match.upper() for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", summary)}

    rejection = ""
    if not summary:
        rejection = "missing_presentation_summary"
    elif len(summary) > 1200:
        rejection = "presentation_summary_too_long"
    elif not cited.issubset(allowed_claims):
        rejection = "unknown_claim_reference"
    elif allowed_claims and not cited:
        rejection = "missing_claim_grounding"
    elif not mentioned_ttps.issubset(trusted_ttps):
        rejection = "unsupported_attack_identifier"
    elif _UNSUPPORTED_NARRATIVE_RE.search(summary):
        rejection = "unsupported_high_impact_claim"
    elif not transfer_observed and _COMPLETED_TRANSFER_NARRATIVE_RE.search(summary):
        rejection = "unsupported_transfer_completion_claim"
    elif _OPERATOR_ACTION_RE.search(summary):
        rejection = "operator_action_outside_presentation_scope"

    if rejection:
        presentation["vertex_validation"] = {
            "status": "rejected",
            "reason": rejection,
        }
        presentation["ai_enriched"] = False
        report["presentation"] = presentation
        return report

    report["presentation"] = {
        "summary": summary,
        "source": "vertex_wording_from_validated_claims",
        "ai_enriched": True,
        "grounded_claim_ids": sorted(cited),
        "vertex_validation": {"status": "accepted"},
        "authority": "presentation_only",
    }
    report["executive_summary"] = summary
    report["ai_enriched"] = True
    report["analysis_mode"] = "vertex_presentation_only"
    return report


def _default_context(legacy_report: Dict[str, Any]) -> Dict[str, Any]:
    intelligence = legacy_report.get("honeypot_intelligence") or {}
    return {
        "reputation_and_ioc_metadata": {
            "ioc_table": legacy_report.get("ioc_table") or [],
            "campaign_intelligence": legacy_report.get("campaign_intelligence") or {},
        },
        "session_correlation": (
            intelligence.get("campaign_correlation") if isinstance(intelligence, dict) else {}
        ) or {},
        "session_ttp_correlations": legacy_report.get("session_correlations") or [],
        "sigma_matches": legacy_report.get("sigma_hits") or [],
        "kev_matches": legacy_report.get("kev_matches") or [],
        "influence_policy": "context_only_not_behavioral_claim_evidence",
    }


def _canonical_operator_actions(
    legacy_report: Dict[str, Any],
    observed: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Retain only policy-approved actions and label their evidence boundary."""

    candidates = [
        item for item in legacy_report.get("recommended_actions_structured") or []
        if isinstance(item, dict)
    ]
    trusted_decision = legacy_report.get("trusted_recommendation_decision") or {}
    if not candidates and isinstance(trusted_decision, dict):
        candidates = [
            item for item in trusted_decision.get("immediate_actions") or []
            if isinstance(item, dict)
        ]

    canonical_refs: set[str] = set()
    for key in (
        "ordered_behavior_chain",
        "ordered_command_observations",
        "cowrie_event_evidence",
    ):
        for item in observed.get(key) or []:
            if isinstance(item, dict) and _clean(item.get("evidence_id")):
                canonical_refs.add(_clean(item.get("evidence_id")))
    for chain in observed.get("connected_behavior_chains") or []:
        if not isinstance(chain, dict):
            continue
        canonical_refs.update(
            _clean(ref) for ref in chain.get("evidence_refs") or [] if _clean(ref)
        )

    output: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for action in candidates:
        if not is_trusted_recommendation_action(action):
            continue
        action_id = _clean(action.get("action_id") or action.get("action"))
        if not action_id or action_id in seen:
            continue
        seen.add(action_id)
        item = dict(action)
        refs = {_clean(ref) for ref in item.get("evidence_refs") or [] if _clean(ref)}
        scopes = {_clean(scope) for scope in item.get("evidence_scope") or [] if _clean(scope)}
        matched_refs = sorted(refs.intersection(canonical_refs))
        if matched_refs:
            item["grounding_status"] = "canonical_observed_evidence"
            item["canonical_evidence_refs"] = matched_refs
        elif scopes.intersection({"contextual_intelligence", "model_prediction"}):
            item["grounding_status"] = "context_or_prediction_only"
            item["canonical_evidence_refs"] = []
        elif scopes.intersection({"configured_asset_context", "session_context", "policy_default"}):
            item["grounding_status"] = "session_or_policy_context"
            item["canonical_evidence_refs"] = []
        else:
            item["grounding_status"] = "legacy_evidence_unverified"
            item["canonical_evidence_refs"] = []
            limitations = list(item.get("visibility_limitations") or [])
            limitation = "Legacy action lacks canonical v2 evidence references; verify its basis manually."
            if limitation not in limitations:
                limitations.append(limitation)
            item["visibility_limitations"] = limitations
        output.append(item)
    return output


def build_v2_report(
    legacy_report: Dict[str, Any],
    sessions: Iterable[Any],
    raw_events: Optional[List[Dict[str, Any]]] = None,
    contextual_intelligence: Optional[Dict[str, Any]] = None,
    *,
    behavior_policy_document: Optional[Dict[str, Any]] = None,
    behavior_policy_path: str = "",
) -> Dict[str, Any]:
    document = _resolved_behavior_policy(behavior_policy_document, behavior_policy_path)
    report = dict(legacy_report or {})
    observed = build_observed_behavior(
        sessions,
        raw_events=raw_events,
        behavior_policy_document=document,
        behavior_policy_path=behavior_policy_path,
    )
    assessment = build_supported_assessment(
        observed,
        behavior_policy_document=document,
        behavior_policy_path=behavior_policy_path,
    )
    follow_on = build_follow_on_hypothesis(
        observed,
        behavior_policy_document=document,
        behavior_policy_path=behavior_policy_path,
    )
    evidence_summary = build_claim_evidence_summary(assessment, follow_on)
    operator_actions = _canonical_operator_actions(report, observed)
    recommendation_provenance = report.get("recommendation_provenance") or {}
    trusted_decision = report.get("trusted_recommendation_decision")
    recommendation_authority = "trusted_policy_engine" if (
        is_trusted_recommendation_provenance(recommendation_provenance)
        or is_trusted_recommendation_decision(trusted_decision)
    ) else "policy_unavailable"
    report["recommended_actions_structured"] = operator_actions
    report["recommended_mitigations"] = [
        _clean(action.get("action"))
        for action in operator_actions
        if _clean(action.get("action"))
    ]
    if isinstance(trusted_decision, dict):
        trusted_decision = dict(trusted_decision)
        trusted_decision["immediate_actions"] = operator_actions
        report["trusted_recommendation_decision"] = trusted_decision
    report.update({
        "schema_version": SCHEMA_VERSION,
        "behavior_policy": policy_summary(document),
        "observed_behavior": observed,
        "supported_assessment": assessment,
        "follow_on_hypothesis": follow_on,
        "model_prediction": report.get("model_prediction") or {
            "status": "unavailable",
            "abstained": True,
            "separation_semantics": "statistical_prediction_not_observed_evidence",
        },
        "contextual_intelligence": contextual_intelligence or _default_context(report),
        "recommendations": {
            "operator_actions": operator_actions,
            "mitigations": report.get("recommended_mitigations") or [],
            "strategic": report.get("strategic_recommendations") or [],
            "authority": recommendation_authority,
            "grounding_contract": "canonical_v2_evidence_or_explicit_context_only",
            "manual_approval_required": True,
        },
        "limitations": [
            "Assessment is limited to Cowrie-observable SSH telemetry.",
            "ATT&CK mappings are command-level candidates, not proof of attacker intent.",
            "No claim establishes named attribution, real-world compromise, or victim impact.",
        ],
        "presentation": {
            "summary": assessment.get("behavior_summary") or "",
            "source": "deterministic_validated_claims",
            "ai_enriched": False,
        },
        "claim_evidence_summary": evidence_summary,
    })
    report = apply_legacy_aliases(report)
    report["session_assessment_v3"] = build_session_assessment_v3(report)
    return report


def attach_model_prediction(
    report: Dict[str, Any],
    prediction_snapshot: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if not prediction_snapshot:
        report.setdefault("model_prediction", {
            "status": "unavailable",
            "abstained": True,
            "separation_semantics": "statistical_prediction_not_observed_evidence",
        })
        return report
    if isinstance(prediction_snapshot.get("payload"), dict):
        prediction_snapshot = prediction_snapshot["payload"]
    ranking = list(prediction_snapshot.get("final_ranking") or [])
    coverage = prediction_snapshot.get("coverage") or {}
    report["model_prediction"] = {
        "status": "available" if ranking else "abstained",
        "snapshot_id": _clean(prediction_snapshot.get("snapshot_id")),
        "generated_at": _clean(prediction_snapshot.get("generated_at")),
        "engine": prediction_snapshot.get("engine") or {},
        "prediction_mode": _clean(prediction_snapshot.get("prediction_mode")),
        "primary_model": _clean(prediction_snapshot.get("primary_model")),
        "next_tactic_ranking": ranking,
        "support": {
            "transition_count": prediction_snapshot.get("transition_count", 0),
            "evidence_count": prediction_snapshot.get("evidence_count", 0),
            "transition_context": prediction_snapshot.get("transition_context") or "",
        },
        "coverage": coverage,
        "abstained": not bool(ranking),
        "abstention_reason": (
            _clean(coverage.get("reason")) or _clean(prediction_snapshot.get("fallback_reason"))
            if not ranking else ""
        ),
        "trust_status": prediction_snapshot.get("trust_status") or {},
        "separation_semantics": "statistical_prediction_not_observed_evidence",
    }
    assessment = report.get("session_assessment_v3")
    if isinstance(assessment, dict):
        report["session_assessment_v3"] = attach_forecast_to_session_assessment(
            assessment,
            report["model_prediction"],
        )
    return report


def apply_legacy_aliases(report: Dict[str, Any]) -> Dict[str, Any]:
    assessment = report.get("supported_assessment") or {}
    follow_on = report.get("follow_on_hypothesis") or {}
    objectives = list(assessment.get("possible_objectives") or [])
    follow_claims = list(follow_on.get("claims") or [])
    primary = (
        _clean(objectives[0].get("text"))
        if objectives
        else "Insufficient evidence to infer an attacker objective from Cowrie telemetry."
    )
    follow_text = (
        "; ".join(_clean(item.get("text")) for item in follow_claims if _clean(item.get("text")))
        if follow_claims
        else "Insufficient evidence to construct a bounded follow-on hypothesis."
    )
    old_chain = {
        _clean(item.get("technique_id")): item
        for item in report.get("kill_chain_analysis") or []
        if isinstance(item, dict)
    }
    legacy_chain = []
    for item in report.get("observed_behavior", {}).get("trusted_attck_candidates") or []:
        technique_id = _clean(item.get("technique_id"))
        previous = old_chain.get(technique_id) or {}
        legacy_chain.append({
            "tactic": _clean(item.get("tactic")),
            "technique_id": technique_id,
            "technique_name": previous.get("technique_name") or technique_id,
            "evidence": previous.get("evidence") or "Observed command with candidate ATT&CK mapping",
            "evidence_ref": _clean(item.get("evidence_id")),
            "command_outcome": _clean(item.get("command_outcome")),
            "mapping_semantics": "candidate_attck_mapping_not_confirmed_intent",
        })
    summary = report.get("claim_evidence_summary") or {}
    compatibility_strength = {
        "level": "Unscored",
        "reason": "Global confidence was retired; inspect claim-level evidence_status values.",
        "metric_name": "claim_evidence_summary",
        "method": "claim_level_evidence_status_v2",
        "calibrated_probability": False,
        "deprecated": True,
        "claim_status_counts": summary.get("claim_status_counts") or {},
        "description": "Compatibility alias only; not a probability or global confidence level.",
    }
    previous_hypothesis = report.get("threat_hypothesis") or {}
    report.update({
        "campaign_name": "Cowrie SSH Session Assessment",
        "executive_summary": _clean(assessment.get("behavior_summary")),
        "primary_objective": primary,
        "attack_type": primary,
        "post_session_follow_on_hypothesis": follow_text,
        "kill_chain_analysis": legacy_chain,
        "threat_actor_profile": {
            "type": "Unknown",
            "sophistication": "Unassessed",
            "description": "The observed behavior is insufficient to infer a reliable actor profile.",
            "assessment_semantics": "behavioral_summary_not_attribution",
        },
        "confidence": "Unscored",
        "confidence_source": "claim_evidence_summary_v2",
        "confidence_semantics": "not_a_calibrated_probability",
    })
    report["threat_hypothesis"] = {
        "stated_intent": primary,
        "predicted_next_action": follow_text,
        "post_session_follow_on_hypothesis": follow_text,
        "falsification_conditions": [
            _clean(item.get("text"))
            for item in follow_on.get("disconfirming_observations") or []
            if _clean(item.get("text"))
        ],
        "analytical_evidence_strength": compatibility_strength,
        "analytical_confidence": compatibility_strength,
        "hypothesis_status": (
            "insufficient_evidence" if follow_on.get("abstained") else "bounded_hypothesis"
        ),
        "scope": "post_session_cowrie_observable_behavior",
        "session_correlations": previous_hypothesis.get("session_correlations") or report.get("session_correlations") or [],
        "correlation_rules_fired": previous_hypothesis.get("correlation_rules_fired") or report.get("correlation_rules_fired") or [],
        "evidence_layer_summary": previous_hypothesis.get("evidence_layer_summary") or {},
        "canonical_schema": SCHEMA_VERSION,
    }
    return report
