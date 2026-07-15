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
from production.utils.serialization import stable_id


SCHEMA_VERSION = "threat_hypothesis.v2"
EVIDENCE_STATUSES = {"supported", "partially_supported", "insufficient_evidence"}

_DOWNLOADER_RE = re.compile(r"\b(?:curl|wget|tftp|ftp)\b\s+\S+", re.IGNORECASE)
_EXPLICIT_EXECUTION_RE = re.compile(
    r"(?:^|[;&|]\s*)(?:sh|bash|python\d*|perl)\s+(?:/tmp|/var/tmp|/dev/shm)/\S+|"
    r"(?:^|[;&|]\s*)(?:\./|/tmp/|/var/tmp/|/dev/shm/)\S+",
    re.IGNORECASE | re.MULTILINE,
)
_PERSISTENCE_RE = re.compile(
    r"\b(?:useradd|adduser)\b|authorized_keys|\bcrontab\b|"
    r"\bsystemctl\s+(?:enable|start)\b|(?:\.bashrc|\.profile|rc\.local)",
    re.IGNORECASE,
)
_CREDENTIAL_RE = re.compile(
    r"/etc/(?:passwd|shadow)|(?:^|/)\.ssh/id_(?:rsa|ed25519)|"
    r"\.aws/credentials|application_default_credentials|\.config/gcloud",
    re.IGNORECASE,
)
_CLEANUP_RE = re.compile(
    r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\brm\b[^\n]*(?:bash_history|auth\.log|/tmp/)",
    re.IGNORECASE,
)
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
) -> Dict[str, Any]:
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
        graph = build_session_evidence_graph(payload)
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


def _connected_behavior_claims(observed: Dict[str, Any]) -> List[Dict[str, Any]]:
    claims: List[Dict[str, Any]] = []
    for chain in observed.get("connected_behavior_chains") or []:
        if not isinstance(chain, dict):
            continue
        action_types = set(chain.get("action_types") or [])
        status = (
            "supported"
            if chain.get("chain_status") == "supported"
            else "partially_supported"
        )
        text = ""
        claim_type = ""
        limitations = list(chain.get("limitations") or [])
        if {"remote_content_pipe_source", "shell_pipe_consumer"}.issubset(action_types):
            claim_type = "piped_remote_content_execution_attempt"
            text = (
                "Remote content retrieval was piped directly to a shell interpreter, "
                "supporting an execution attempt without a separately observed stored artifact."
            )
            status = "partially_supported"
            limitations.append("Pipeline syntax does not establish successful retrieval or shell execution.")
        elif {"transfer_attempt", "permission_modification_attempt", "execution_attempt", "deletion_attempt"}.issubset(action_types):
            claim_type = "connected_artifact_activity"
            text = (
                "A connected sequence involving a transfer attempt, permission-modification "
                "attempt, execution attempt, and deletion attempt for the same artifact path was observed."
            )
            limitations.append("Deletion of an artifact does not by itself establish trace-removal intent.")
        elif {"transfer_attempt", "permission_modification_attempt", "execution_attempt"}.issubset(action_types):
            claim_type = "connected_transfer_permission_execution"
            text = (
                "A connected sequence involving a transfer attempt, permission-modification "
                "attempt, and execution attempt for the same artifact path was observed."
            )
        elif {"transfer_attempt", "execution_attempt"}.issubset(action_types):
            claim_type = "connected_transfer_execution"
            text = "A transfer attempt and execution attempt referencing the same artifact path were observed."
        elif "cowrie_file_transfer_observed" in action_types and "execution_attempt" not in action_types:
            claim_type = "observed_transfer_without_linked_execution"
            text = (
                "A transfer into Cowrie was observed, but no execution attempt linked to the "
                "transferred artifact was identified."
            )
        elif {"transfer_attempt", "permission_modification_attempt"}.issubset(action_types):
            claim_type = "connected_transfer_permission_change"
            text = (
                "A transfer attempt and permission-modification attempt referencing the same "
                "artifact path were observed; linked execution was not observed."
            )
        if not claim_type:
            continue
        claim = _claim(
            claim_type,
            text,
            status,
            chain.get("evidence_refs") or [],
            list(dict.fromkeys(limitations)),
        )
        claim.update({
            "claim_basis": "connected_behavior_chain",
            "connected_chain_id": _clean(chain.get("chain_id")),
            "relationship_refs": [
                _clean(item.get("relationship_id"))
                for item in chain.get("relationships") or []
                if isinstance(item, dict) and _clean(item.get("relationship_id"))
            ],
        })
        claims.append(claim)
    return claims


def build_supported_assessment(observed: Dict[str, Any]) -> Dict[str, Any]:
    chain = list(observed.get("ordered_behavior_chain") or [])
    connected_claims = _connected_behavior_claims(observed)
    objectives: List[Dict[str, Any]] = list(connected_claims)
    credential = _matching_chain(chain, _CREDENTIAL_RE)
    literal_downloader = _literal_actions(observed, "transfer_attempt")
    downloader = literal_downloader or (
        _matching_chain(chain, _DOWNLOADER_RE)
        if not observed.get("ordered_command_observations") else []
    )
    literal_execution = _literal_actions(observed, "execution_attempt")
    execution = literal_execution or (
        _matching_chain(chain, _EXPLICIT_EXECUTION_RE)
        if not observed.get("ordered_command_observations") else []
    )
    persistence = _matching_chain(chain, _PERSISTENCE_RE)
    cleanup = _matching_chain(chain, _CLEANUP_RE)
    download_refs = _event_refs(observed, "cowrie.session.file_download")

    if credential:
        objectives.append(_claim(
            "possible_credential_access_preparation",
            "Possible credential-related discovery or access preparation within the observed SSH session.",
            "partially_supported",
            _chain_refs(credential),
            ["Successful credential acquisition or use is not established.", "Attacker intent is not directly observable."],
        ))
    if downloader:
        objectives.append(_claim(
            "possible_tool_transfer_or_staging",
            "Possible tool transfer or payload staging within the Cowrie session.",
            "partially_supported",
            _action_refs(downloader),
            [
                "A downloader command alone does not establish successful transfer.",
                "Real-world compromise is outside Cowrie visibility.",
            ],
        ))
    if download_refs:
        objectives.append(_claim(
            "observed_cowrie_file_transfer",
            "Cowrie recorded a file transfer into the simulated honeypot environment.",
            "supported",
            download_refs,
            [
                "The Cowrie transfer event does not establish artifact execution or persistence.",
                "Transfer into Cowrie does not establish transfer to a real victim system.",
            ],
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
                "possible_artifact_execution",
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
                "attempted_artifact_execution",
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
            "possible_continued_access_preparation",
            "Possible preparation for continued access within the simulated SSH environment.",
            "supported" if success else "partially_supported",
            _chain_refs(persistence),
            ["Continued access, re-entry, and persistence outside Cowrie are not established."],
        ))
    if cleanup:
        success = any(item.get("command_outcome") == "cowrie_reported_success" for item in cleanup)
        objectives.append(_claim(
            "possible_trace_removal",
            "Possible trace-removal or defense-evasion behavior within the observed session.",
            "supported" if success else "partially_supported",
            _chain_refs(cleanup),
            ["A cleanup-related command does not establish successful post-execution cleanup."],
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
        "unknowns": [
            "Named actor identity and intent are not established.",
            "Behavior outside Cowrie-observable SSH telemetry is unknown.",
        ],
    }


def build_follow_on_hypothesis(observed: Dict[str, Any]) -> Dict[str, Any]:
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
        has_transfer = bool({"transfer_attempt", "cowrie_file_transfer_observed"} & action_types)
        has_execution = bool({"execution_attempt", "shell_pipe_consumer"} & action_types)
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
                "possible_follow_on_execution",
                "Possible later execution of the artifact referenced by an incomplete evidence-linked transfer chain.",
                "partially_supported",
                refs,
                ["Successful execution and persistence are not established."],
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
        if not _matching_chain(chain, _PERSISTENCE_RE):
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


def build_v2_report(
    legacy_report: Dict[str, Any],
    sessions: Iterable[Any],
    raw_events: Optional[List[Dict[str, Any]]] = None,
    contextual_intelligence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    report = dict(legacy_report or {})
    observed = build_observed_behavior(sessions, raw_events=raw_events)
    assessment = build_supported_assessment(observed)
    follow_on = build_follow_on_hypothesis(observed)
    evidence_summary = build_claim_evidence_summary(assessment, follow_on)
    report.update({
        "schema_version": SCHEMA_VERSION,
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
            "operator_actions": report.get("recommended_actions_structured") or [],
            "mitigations": report.get("recommended_mitigations") or [],
            "strategic": report.get("strategic_recommendations") or [],
            "authority": "trusted_policy_engine",
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
    return apply_legacy_aliases(report)


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
