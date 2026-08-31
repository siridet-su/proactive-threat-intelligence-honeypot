from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from production.api.dashboard_api import _current_decision_payload
from production.reporting.response_guidance_v3 import (
    build_response_guidance_v3_from_session,
    validate_response_guidance_v3,
)
from production.reporting.session_assessment_v4 import (
    build_session_assessment_v4,
    validate_session_assessment_v4,
)
from production.utils.serialization import stable_json


ROOT = Path(__file__).resolve().parents[1]
GUIDANCE_POLICY = ROOT / "configs" / "response_guidance_policy.v3.json"
BEHAVIOR_POLICY = ROOT / "configs" / "threat_hypothesis_behavior.trusted.json"
CLASSIFICATION_POLICY = ROOT / "configs" / "classification_rules.trusted.json"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(stable_json(value).encode("utf-8"))


def _full_session(
    *,
    session_id: str = "phase4c-binding-session",
    event_id: str = "phase4c-event-0",
    command: str = "cat /home/alice/.ssh/id_rsa",
    received_at: str = "2026-08-27T00:00:00Z",
) -> tuple[dict, dict]:
    event = {
        "eventid": "cowrie.command.input",
        "session": session_id,
        "input": command,
        "timestamp": received_at,
    }
    payload_sha256 = _sha256_json(event)
    entry = {
        "event_id": event_id,
        "received_at": received_at,
        "payload_sha256": payload_sha256,
    }
    manifest_basis = {
        "schema_version": "durable_session_event_manifest.v1",
        "session_id": session_id,
        "through_event_id": event_id,
        "through_received_at": received_at,
        "event_entries": [entry],
    }
    manifest = {
        **manifest_basis,
        "event_count": 1,
        "manifest_sha256": _sha256_json(manifest_basis),
    }
    session = {
        "session_id": session_id,
        "src_ip": "192.0.2.44",
        "protocol": "ssh",
        "dst_port": 22,
        "commands": [command],
        "raw_events": [event],
        "canonical_event_manifest": manifest,
        "classification_events": [
            {
                "command": command,
                "ttp": "T1552",
                "tactic": "credential-access",
                "source": "rule",
                "evidence_id": "phase4c-credential-observation",
                "cowrie_eventid": "cowrie.command.input",
            }
        ],
    }
    return session, event


def _full_report(*, session_id: str = "phase4c-binding-session") -> dict:
    session, event = _full_session(session_id=session_id)
    report = build_session_assessment_v4(
        [session],
        raw_events=[event],
        behavior_policy_path=str(BEHAVIOR_POLICY),
        classification_policy_path=str(CLASSIFICATION_POLICY),
        response_guidance_policy_path=str(GUIDANCE_POLICY),
    )
    assert validate_session_assessment_v4(report) == []
    guidance = report["response_guidance_v3"]
    assert guidance["binding"]["status"] == "verified"
    assert guidance["validation"] == {"status": "valid", "errors": []}
    return report


def _rehash_v3_evidence(guidance: dict) -> None:
    evidence = guidance["canonical_evidence"]
    evidence.pop("evidence_sha256", None)
    evidence["evidence_sha256"] = _sha256_json(evidence)
    guidance["provenance"]["canonical_evidence_sha256"] = evidence[
        "evidence_sha256"
    ]


class _StoredReportStorage:
    def __init__(self, report: dict):
        self.report = report

    def get_current_report_for_session(self, session_id: str) -> dict:
        assert session_id == self.report["canonical_evidence"]["session_id"]
        return {"payload": self.report}


def test_complete_binding_resolves_all_components_and_is_deterministic() -> None:
    first = _full_report()
    second = _full_report()
    first_guidance = first["response_guidance_v3"]
    second_guidance = second["response_guidance_v3"]

    assert first_guidance["guidance_id"] == second_guidance["guidance_id"]
    assert validate_response_guidance_v3(first_guidance) == []
    assert {
        key: value["status"]
        for key, value in first_guidance["binding"].items()
        if isinstance(value, dict) and "status" in value
    } == {
        "durable_prefix": "verified",
        "assessment": "verified",
        "graph": "verified",
        "policy": "verified",
        "reference_resolution": "verified",
    }
    assert first_guidance["binding"]["reference_resolution"]["typed_fact_set"][
        "status"
    ] == "verified"


def test_dashboard_returns_stored_bound_guidance_and_does_not_advance_prefix() -> None:
    report = _full_report()
    stored = report["response_guidance_v3"]
    later_snapshot = copy.deepcopy(report["canonical_evidence"])
    later_snapshot["durable_event_manifest"]["through_event_id"] = "later-event"
    storage = _StoredReportStorage(report)

    shown = _current_decision_payload(
        type("Config", (), {"enable_response_guidance": True})(),
        storage,
        report["canonical_evidence"]["session_id"],
        later_snapshot,
        report_recommendations={"advisory_actions": [{"action_id": "ignored"}]},
    )

    assert shown["guidance_id"] == stored["guidance_id"]
    assert shown["presentation_semantics"]["mode"] == "stored_durable_prefix_bound"
    assert shown["presentation_semantics"]["recomputed"] is False
    assert shown["canonical_evidence"] == stored["canonical_evidence"]


def test_dashboard_abstains_when_stored_prefix_is_stale_or_invalid() -> None:
    report = _full_report()
    forged = copy.deepcopy(report)
    forged_guidance = forged["response_guidance_v3"]
    forged_guidance["canonical_evidence"]["durable_event_manifest"][
        "through_received_at"
    ] = "2026-08-27T00:01:00Z"
    _rehash_v3_evidence(forged_guidance)
    storage = _StoredReportStorage(forged)

    shown = _current_decision_payload(
        type("Config", (), {"enable_response_guidance": True})(),
        storage,
        forged["canonical_evidence"]["session_id"],
        forged["canonical_evidence"],
    )

    assert shown["status"] == "unavailable"
    assert shown["advisory_actions"] == []
    assert shown["presentation_semantics"]["mode"] == "stored_guidance_unverified"
    assert shown["validation"]["status"] == "rejected"


def test_binding_fails_closed_for_missing_prefix_and_assessment_mismatch() -> None:
    guidance = copy.deepcopy(_full_report()["response_guidance_v3"])
    guidance["canonical_evidence"].pop("durable_event_manifest", None)
    _rehash_v3_evidence(guidance)
    errors = validate_response_guidance_v3(guidance)
    assert any("durable prefix" in error for error in errors)

    guidance = copy.deepcopy(_full_report()["response_guidance_v3"])
    guidance["binding"]["assessment"]["assessment_id"] = "wrong-assessment"
    errors = validate_response_guidance_v3(guidance)
    assert any("assessment content identity" in error for error in errors)


def test_policy_binding_requires_actual_current_file_content(tmp_path: Path) -> None:
    guidance = copy.deepcopy(_full_report()["response_guidance_v3"])
    policy_binding = guidance["binding"]["policy"]
    original_path = Path(policy_binding["path"])
    altered = json.loads(original_path.read_text(encoding="utf-8"))
    altered["policy_id"] = "substituted-policy"
    altered_path = tmp_path / "substituted-policy.json"
    altered_path.write_text(json.dumps(altered, sort_keys=True), encoding="utf-8")
    policy_binding["path"] = str(altered_path)

    errors = validate_response_guidance_v3(guidance)
    assert any("resolved policy file hash mismatch" in error for error in errors)
    assert any("resolved policy canonical hash mismatch" in error for error in errors)
    assert any("resolved policy policy_id mismatch" in error for error in errors)

    missing = copy.deepcopy(_full_report()["response_guidance_v3"])
    missing["binding"]["policy"]["path"] = str(tmp_path / "missing.json")
    errors = validate_response_guidance_v3(missing)
    assert any("resolved policy unavailable" in error for error in errors)


def test_policy_hash_shape_without_content_is_not_verified(tmp_path: Path) -> None:
    guidance = copy.deepcopy(_full_report()["response_guidance_v3"])
    guidance["binding"]["policy"]["path"] = str(tmp_path / "missing.json")
    guidance["binding"]["policy"]["file_sha256"] = "a" * 64
    guidance["binding"]["policy"]["document_sha256"] = "b" * 64
    errors = validate_response_guidance_v3(guidance)
    assert any("resolved policy unavailable" in error for error in errors)


def test_policy_binding_rejects_wrong_version_malformed_and_tampered_claims(
    tmp_path: Path,
) -> None:
    guidance = _full_report()["response_guidance_v3"]
    original_path = Path(guidance["binding"]["policy"]["path"])
    original_raw = original_path.read_bytes()
    original_document = json.loads(original_raw.decode("utf-8"))

    wrong_version_document = copy.deepcopy(original_document)
    wrong_version_document["version"] = "3.7.1-substituted"
    wrong_version_path = tmp_path / "wrong-version.json"
    wrong_version_path.write_text(
        json.dumps(wrong_version_document, sort_keys=True), encoding="utf-8"
    )

    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text("{not-json", encoding="utf-8")

    # Keep the policy bytes valid but alter only the claimed digest in the
    # guidance binding; the actual file must still be read and compared.
    wrong_claim = copy.deepcopy(guidance)
    wrong_claim["binding"]["policy"]["file_sha256"] = "a" * 64
    claim_errors = validate_response_guidance_v3(wrong_claim)
    assert any("resolved policy file hash mismatch" in error for error in claim_errors)

    # A same-size substitution must not be accepted merely because the path
    # and byte length look plausible.
    same_size_id = "x" * len(original_document["policy_id"])
    same_size_raw = original_raw.replace(
        b'"policy_id": "cowrie-observed-evidence-response-guidance"',
        f'"policy_id": "{same_size_id}"'.encode("utf-8"),
    )
    assert len(same_size_raw) == len(original_raw)
    same_size_path = tmp_path / "same-size.json"
    same_size_path.write_bytes(same_size_raw)

    for path, expected_fragment in (
        (wrong_version_path, "resolved policy version mismatch"),
        (malformed_path, "resolved policy unavailable"),
        (same_size_path, "resolved policy file hash mismatch"),
    ):
        candidate = copy.deepcopy(guidance)
        candidate["binding"]["policy"]["path"] = str(path)
        errors = validate_response_guidance_v3(candidate)
        assert any(expected_fragment in error for error in errors)


def test_reference_resolution_rejects_missing_tampered_wrong_type_and_cross_prefix() -> None:
    baseline = _full_report()["response_guidance_v3"]

    missing = copy.deepcopy(baseline)
    missing["binding"]["reference_resolution"]["resolved"] = [
        item
        for item in missing["binding"]["reference_resolution"]["resolved"]
        if item.get("reference_type") != "typed_fact"
    ]
    errors = validate_response_guidance_v3(missing)
    assert any("typed_fact" in error and "unresolved" in error for error in errors)

    tampered = copy.deepcopy(baseline)
    typed = next(
        item
        for item in tampered["binding"]["reference_resolution"]["resolved"]
        if item.get("reference_type") == "typed_fact"
    )
    typed["content"]["fact_id"] = "tampered-in-content"
    errors = validate_response_guidance_v3(tampered)
    assert any("content hash mismatch" in error for error in errors)

    wrong_type = copy.deepcopy(baseline)
    evidence = next(
        item
        for item in wrong_type["binding"]["reference_resolution"]["resolved"]
        if item.get("reference_type") == "evidence"
    )
    evidence["reference_type"] = "unexpected"
    errors = validate_response_guidance_v3(wrong_type)
    assert any("required reference is unresolved" in error for error in errors)

    cross_prefix = copy.deepcopy(baseline)
    cross_prefix["binding"]["reference_resolution"]["typed_fact_set"][
        "canonical_evidence_sha256"
    ] = "c" * 64
    errors = validate_response_guidance_v3(cross_prefix)
    assert any("crosses the evidence prefix" in error for error in errors)


def test_reference_resolution_rejects_malformed_and_tampered_reference_content() -> None:
    baseline = _full_report()["response_guidance_v3"]

    malformed_prefix = copy.deepcopy(baseline)
    malformed_prefix["canonical_evidence"]["durable_event_manifest"][
        "event_entries"
    ] = [{"event_id": "phase4c-event-0"}]
    _rehash_v3_evidence(malformed_prefix)
    errors = validate_response_guidance_v3(malformed_prefix)
    assert any("durable prefix" in error for error in errors)

    tampered_hash = copy.deepcopy(baseline)
    evidence = next(
        item
        for item in tampered_hash["binding"]["reference_resolution"]["resolved"]
        if item.get("reference_type") == "evidence"
    )
    evidence["content_sha256"] = "a" * 64
    errors = validate_response_guidance_v3(tampered_hash)
    assert any("content hash mismatch" in error for error in errors)

    malformed_reference = copy.deepcopy(baseline)
    malformed_reference["binding"]["reference_resolution"]["required"].append(
        {"reference_type": "evidence"}
    )
    errors = validate_response_guidance_v3(malformed_reference)
    assert any("required reference is unresolved" in error for error in errors)


def test_reference_resolution_rejects_graph_tamper_unresolved_and_conflicting_ids() -> None:
    baseline = _full_report()["response_guidance_v3"]

    graph_tamper = copy.deepcopy(baseline)
    graph_tamper["canonical_evidence"]["semantic_graph"]["evidence_nodes"].append(
        {"evidence_id": "unexpected"}
    )
    _rehash_v3_evidence(graph_tamper)
    errors = validate_response_guidance_v3(graph_tamper)
    assert any("graph" in error for error in errors)

    unresolved = copy.deepcopy(baseline)
    resolution = unresolved["binding"]["reference_resolution"]
    resolution["required"].append({"reference_type": "evidence", "reference_id": "missing-ref"})
    errors = validate_response_guidance_v3(unresolved)
    assert any("missing-ref" in error for error in errors)

    conflicting = copy.deepcopy(baseline)
    evidence = conflicting["canonical_evidence"]
    conflicting_id = evidence["direct_cowrie_events"][0]["evidence_id"]
    evidence.setdefault("direct_cowrie_events", []).append({
        "evidence_id": conflicting_id,
        "different": True,
    })
    _rehash_v3_evidence(conflicting)
    errors = validate_response_guidance_v3(conflicting)
    assert any("evidence reference content is ambiguous" in error for error in errors)


def test_binding_identity_detects_reference_reordering_and_manual_safety_tamper() -> None:
    baseline = _full_report()["response_guidance_v3"]

    reordered = copy.deepcopy(baseline)
    resolved = reordered["binding"]["reference_resolution"]["resolved"]
    resolved.reverse()
    errors = validate_response_guidance_v3(reordered)
    assert any("guidance_id is inconsistent" in error for error in errors)

    unsafe = copy.deepcopy(baseline)
    unsafe["safety"]["automatic_execution"] = True
    unsafe["advisory_actions"] = [
        {**action, "safe_to_auto_execute": True, "requires_manual_approval": False}
        for action in unsafe["advisory_actions"]
    ]
    errors = validate_response_guidance_v3(unsafe)
    assert any("automatic execution must be false" in error for error in errors)
    assert any("guidance safety boundary is invalid" in error for error in errors)


def test_output_identity_detects_selected_action_set_change() -> None:
    baseline = _full_report()["response_guidance_v3"]
    changed = copy.deepcopy(baseline)
    changed["advisory_actions"].append(copy.deepcopy(changed["advisory_actions"][0]))
    errors = validate_response_guidance_v3(changed)
    assert any("guidance_id is inconsistent" in error for error in errors)


def test_historical_guidance_remains_read_only_and_new_no_policy_output_abstains() -> None:
    legacy = {
        "schema_version": "response_guidance.v2",
        "guidance_id": "historical-v2",
    }
    original = copy.deepcopy(legacy)
    from production.reporting.response_guidance_v3 import read_legacy_response_guidance

    adapted = read_legacy_response_guidance(legacy)
    assert legacy == original
    assert adapted["status"] == "legacy_read_only"
    assert adapted["recomputed"] is False

    unavailable = build_response_guidance_v3_from_session(
        _full_session()[0],
        policy_path=str(ROOT / "configs" / "missing-response-guidance-policy.json"),
    )
    assert unavailable["status"] == "unavailable"
    assert unavailable["advisory_actions"] == []
    assert unavailable["safety"]["automatic_execution"] is False
    assert validate_response_guidance_v3(unavailable)
