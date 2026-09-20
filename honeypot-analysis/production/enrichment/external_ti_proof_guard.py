"""Durable at-most-once safety guard for bounded source-IP proofs.

The guard is deliberately separate from the provider cache.  It records only
bounded operational claim state in an auxiliary storage object and never
grants authority to write canonical enrichment, trusted ATT&CK, or response
records.  A successful claim is consumed permanently for the proof campaign:
if a worker dies after claiming and before the HTTP request is known to have
completed, the next worker fails closed instead of retrying the request.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from production.utils.serialization import stable_id, utc_now


PROOF_GUARD_COLLECTION = "external_ti_provider_proof_guard"
PROOF_GUARD_SCHEMA = "external_ti_provider_proof_guard.v1"
PROOF_GUARD_AUTHORITY = "NON_AUTHORITATIVE_OPERATIONAL_SAFETY_STATE"
PROOF_GUARD_MODE_DISABLED = "DISABLED"
PROOF_GUARD_MODE_PRE_FLIGHT = "PRE_FLIGHT_ONLY"
PROOF_GUARD_MODE_REAL = "REAL_PROOF"
PROOF_GUARD_MODES = frozenset(
    {PROOF_GUARD_MODE_DISABLED, PROOF_GUARD_MODE_PRE_FLIGHT, PROOF_GUARD_MODE_REAL}
)
# Keep this set aligned with the source-IP governance policy.  OTX is an
# explicitly authorized bounded source-IP lookup in policy v2.2; omitting it
# here makes the worker raise before it can record a provider result.
PROOF_GUARD_PROVIDERS = frozenset({"abuseipdb", "otx", "shodan_official"})
PROOF_GUARD_RESULT_CLASSES = frozenset(
    {"DATA", "NO_DATA", "AUTH_FAILED", "RATE_LIMITED", "REQUEST_FAILED", "NORMALIZATION_FAILED"}
)
PROOF_GUARD_STATES = frozenset({"TARGET_CLAIMED", "CLAIMED", "REQUEST_COMPLETED"})
_CAMPAIGN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class ProofGuardError(RuntimeError):
    """A malformed or unavailable durable proof guard must fail closed."""


def normalize_public_source_ip(value: Any) -> str:
    """Return a canonical globally routable IP or raise without persisting it."""

    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
    except ValueError as exc:
        raise ProofGuardError("source-IP proof target is invalid") from exc
    if not parsed.is_global:
        raise ProofGuardError("source-IP proof target is not globally routable")
    return str(parsed)


def source_ip_digest(normalized_source_ip: str) -> str:
    normalized = normalize_public_source_ip(normalized_source_ip)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def target_guard_id(proof_campaign_id: str) -> str:
    campaign = _campaign(proof_campaign_id)
    return stable_id("eti_proof_target", {"proof_campaign_id": campaign})


def provider_guard_id(proof_campaign_id: str, provider: str) -> str:
    campaign = _campaign(proof_campaign_id)
    name = _provider(provider)
    return stable_id(
        "eti_proof_provider",
        {"proof_campaign_id": campaign, "provider": name},
    )


def _campaign(value: Any) -> str:
    campaign = str(value or "").strip()
    if not _CAMPAIGN_RE.fullmatch(campaign):
        raise ProofGuardError("proof campaign identity is invalid")
    return campaign


def _provider(value: Any) -> str:
    provider = str(value or "").strip().lower()
    if provider not in PROOF_GUARD_PROVIDERS:
        raise ProofGuardError("provider is not authorized for the source-IP proof")
    return provider


def _mode(value: Any) -> str:
    mode = str(value or "").strip().upper()
    if mode not in PROOF_GUARD_MODES - {PROOF_GUARD_MODE_DISABLED}:
        raise ProofGuardError("proof guard mode is invalid")
    return mode


def _bounded_text(value: Any, field: str, maximum: int = 256, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ProofGuardError(f"proof guard {field} is required")
    if len(text) > maximum or "\x00" in text:
        raise ProofGuardError(f"proof guard {field} is oversized")
    return text


def _validate_digest(value: Any) -> str:
    digest = str(value or "").strip().lower()
    if not _DIGEST_RE.fullmatch(digest):
        raise ProofGuardError("proof guard source-IP digest is invalid")
    return digest


def build_target_claim(
    proof_campaign_id: str,
    normalized_source_ip: str,
    *,
    cutoff_utc: str,
    first_observed_at: str,
    mode: str,
    claimed_at: Optional[str] = None,
) -> Dict[str, Any]:
    campaign = _campaign(proof_campaign_id)
    normalized = normalize_public_source_ip(normalized_source_ip)
    selected_mode = _mode(mode)
    now = _bounded_text(claimed_at or utc_now(), "claimed_at", 80)
    first_seen = _bounded_text(first_observed_at or now, "first_observed_at", 80)
    cutoff = _bounded_text(cutoff_utc, "cutoff_utc", 80)
    digest = source_ip_digest(normalized)
    identity = target_guard_id(campaign)
    return {
        "guard_id": identity,
        "schema_version": PROOF_GUARD_SCHEMA,
        "authority": PROOF_GUARD_AUTHORITY,
        "claim_type": "target",
        "proof_campaign_id": campaign,
        "provider": "",
        "state": "TARGET_CLAIMED",
        "mode": selected_mode,
        "normalized_observable_type": "source_ip",
        "normalized_source_ip_digest": digest,
        "cutoff_utc": cutoff,
        "target_guard_id": identity,
        "first_observed_at": first_seen,
        "claimed_at": now,
        "completed_at": "",
        "result_class": "",
        "http_status": None,
        "provenance": {
            "component": "external_ti_proof_guard",
            "schema_version": PROOF_GUARD_SCHEMA,
            "cache_authority": PROOF_GUARD_AUTHORITY,
            "source_ip_representation": "sha256_normalized_public_ip",
        },
        "created_at": now,
        "updated_at": now,
    }


def build_provider_claim(
    proof_campaign_id: str,
    provider: str,
    *,
    normalized_source_ip: str,
    target_claim_id: str,
    cutoff_utc: str,
    first_observed_at: str,
    mode: str,
    claimed_at: Optional[str] = None,
) -> Dict[str, Any]:
    campaign = _campaign(proof_campaign_id)
    name = _provider(provider)
    normalized = normalize_public_source_ip(normalized_source_ip)
    selected_mode = _mode(mode)
    now = _bounded_text(claimed_at or utc_now(), "claimed_at", 80)
    first_seen = _bounded_text(first_observed_at or now, "first_observed_at", 80)
    cutoff = _bounded_text(cutoff_utc, "cutoff_utc", 80)
    target_id = _bounded_text(target_claim_id, "target_guard_id", 128)
    identity = provider_guard_id(campaign, name)
    return {
        "guard_id": identity,
        "schema_version": PROOF_GUARD_SCHEMA,
        "authority": PROOF_GUARD_AUTHORITY,
        "claim_type": "provider",
        "proof_campaign_id": campaign,
        "provider": name,
        "state": "CLAIMED",
        "mode": selected_mode,
        "normalized_observable_type": "source_ip",
        "normalized_source_ip_digest": source_ip_digest(normalized),
        "cutoff_utc": cutoff,
        "target_guard_id": target_id,
        "first_observed_at": first_seen,
        "claimed_at": now,
        "completed_at": "",
        "result_class": "",
        "http_status": None,
        "provenance": {
            "component": "external_ti_proof_guard",
            "schema_version": PROOF_GUARD_SCHEMA,
            "cache_authority": PROOF_GUARD_AUTHORITY,
            "source_ip_representation": "sha256_normalized_public_ip",
        },
        "created_at": now,
        "updated_at": now,
    }


def validate_guard_record(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate a stored row before it can authorize any provider request."""

    item = dict(record)
    if str(item.get("schema_version") or "") != PROOF_GUARD_SCHEMA:
        raise ProofGuardError("proof guard schema is invalid")
    if str(item.get("authority") or "") != PROOF_GUARD_AUTHORITY:
        raise ProofGuardError("proof guard authority is invalid")
    claim_type = str(item.get("claim_type") or "").strip().lower()
    if claim_type not in {"target", "provider"}:
        raise ProofGuardError("proof guard claim type is invalid")
    campaign = _campaign(item.get("proof_campaign_id"))
    selected_mode = _mode(item.get("mode"))
    state = str(item.get("state") or "").strip().upper()
    if state not in PROOF_GUARD_STATES:
        raise ProofGuardError("proof guard state is invalid")
    digest = _validate_digest(item.get("normalized_source_ip_digest"))
    if str(item.get("normalized_observable_type") or "") != "source_ip":
        raise ProofGuardError("proof guard observable type is invalid")
    guard_id = _bounded_text(item.get("guard_id"), "guard_id", 128)
    expected_id = (
        target_guard_id(campaign)
        if claim_type == "target"
        else provider_guard_id(campaign, item.get("provider"))
    )
    if guard_id != expected_id:
        raise ProofGuardError("proof guard identity is invalid")
    provider = ""
    if claim_type == "target":
        if state != "TARGET_CLAIMED" or str(item.get("provider") or ""):
            raise ProofGuardError("target proof guard state is invalid")
    else:
        provider = _provider(item.get("provider"))
        if state == "TARGET_CLAIMED":
            raise ProofGuardError("provider proof guard state is invalid")
    target_id = _bounded_text(item.get("target_guard_id"), "target_guard_id", 128)
    if claim_type == "target" and target_id != guard_id:
        raise ProofGuardError("target proof guard binding is invalid")
    if claim_type == "provider" and target_id != target_guard_id(campaign):
        raise ProofGuardError("provider proof guard target binding is invalid")
    for field in ("cutoff_utc", "first_observed_at", "claimed_at", "created_at", "updated_at"):
        _bounded_text(item.get(field), field, 80)
    completed_at = _bounded_text(item.get("completed_at"), "completed_at", 80, required=False)
    result_class = str(item.get("result_class") or "").strip().upper()
    if state == "REQUEST_COMPLETED" and result_class not in PROOF_GUARD_RESULT_CLASSES:
        raise ProofGuardError("completed proof guard result is invalid")
    if state != "REQUEST_COMPLETED" and (completed_at or result_class):
        raise ProofGuardError("incomplete proof guard has completion state")
    provenance = item.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ProofGuardError("proof guard provenance is invalid")
    if str(provenance.get("component") or "") != "external_ti_proof_guard":
        raise ProofGuardError("proof guard provenance is invalid")
    if str(provenance.get("source_ip_representation") or "") != "sha256_normalized_public_ip":
        raise ProofGuardError("proof guard source-IP representation is invalid")
    if item.get("http_status") not in (None, ""):
        try:
            status = int(item["http_status"])
        except (TypeError, ValueError) as exc:
            raise ProofGuardError("proof guard HTTP status is invalid") from exc
        if status < 100 or status > 599:
            raise ProofGuardError("proof guard HTTP status is invalid")
    item.update(
        {
            "guard_id": guard_id,
            "proof_campaign_id": campaign,
            "provider": provider,
            "mode": selected_mode,
            "state": state,
            "normalized_source_ip_digest": digest,
            "result_class": result_class,
            "completed_at": completed_at,
            "target_guard_id": target_id,
        }
    )
    return item


@dataclass(frozen=True)
class ProofGuardDecision:
    allowed: bool
    code: str
    provider: str = ""
    claim_id: str = ""
    target_claim_id: str = ""
    source_ip_digest: str = ""


class ExternalTIProofGuard:
    """Storage-backed claim coordinator used immediately before provider HTTP."""

    def __init__(self, storage: Any, proof_campaign_id: str, mode: str) -> None:
        self.storage = storage
        self.proof_campaign_id = _campaign(proof_campaign_id)
        self.mode = _mode(mode)

    def claim_target(
        self,
        normalized_source_ip: str,
        *,
        cutoff_utc: str,
        first_observed_at: str,
    ) -> ProofGuardDecision:
        try:
            entry = build_target_claim(
                self.proof_campaign_id,
                normalized_source_ip,
                cutoff_utc=cutoff_utc,
                first_observed_at=first_observed_at,
                mode=self.mode,
            )
            result = self.storage.claim_external_ti_proof_target(entry)
            decision = str(result.get("decision") or "")
            if decision not in {"CLAIMED", "EXISTING"}:
                return ProofGuardDecision(False, decision or "TARGET_DENIED")
            stored = validate_guard_record(result.get("record") or {})
            if stored["normalized_source_ip_digest"] != entry["normalized_source_ip_digest"]:
                return ProofGuardDecision(False, "TARGET_MISMATCH")
            return ProofGuardDecision(
                True,
                decision,
                claim_id=stored["guard_id"],
                target_claim_id=stored["guard_id"],
                source_ip_digest=stored["normalized_source_ip_digest"],
            )
        except Exception:
            return ProofGuardDecision(False, "GUARD_STORAGE_UNAVAILABLE")

    def claim_provider(
        self,
        provider: str,
        normalized_source_ip: str,
        *,
        target_claim_id: str,
        cutoff_utc: str,
        first_observed_at: str,
    ) -> ProofGuardDecision:
        name = str(provider or "").strip().lower()
        try:
            entry = build_provider_claim(
                self.proof_campaign_id,
                name,
                normalized_source_ip=normalized_source_ip,
                target_claim_id=target_claim_id,
                cutoff_utc=cutoff_utc,
                first_observed_at=first_observed_at,
                mode=self.mode,
            )
            result = self.storage.claim_external_ti_proof_provider(entry)
            decision = str(result.get("decision") or "")
            if decision != "CLAIMED":
                return ProofGuardDecision(
                    False,
                    decision or "PROVIDER_DENIED",
                    provider=name,
                    claim_id=entry["guard_id"],
                    target_claim_id=target_claim_id,
                    source_ip_digest=entry["normalized_source_ip_digest"],
                )
            stored = validate_guard_record(result.get("record") or {})
            return ProofGuardDecision(
                True,
                "CLAIMED",
                provider=name,
                claim_id=stored["guard_id"],
                target_claim_id=stored["target_guard_id"],
                source_ip_digest=stored["normalized_source_ip_digest"],
            )
        except Exception:
            return ProofGuardDecision(False, "GUARD_STORAGE_UNAVAILABLE", provider=name)

    def claim_for_provider(
        self,
        provider: str,
        normalized_source_ip: str,
        *,
        cutoff_utc: str,
        first_observed_at: str,
    ) -> ProofGuardDecision:
        target = self.claim_target(
            normalized_source_ip,
            cutoff_utc=cutoff_utc,
            first_observed_at=first_observed_at,
        )
        if not target.allowed:
            return ProofGuardDecision(
                False,
                target.code,
                provider=str(provider or "").strip().lower(),
                target_claim_id=target.target_claim_id,
                source_ip_digest=target.source_ip_digest,
            )
        return self.claim_provider(
            provider,
            normalized_source_ip,
            target_claim_id=target.target_claim_id,
            cutoff_utc=cutoff_utc,
            first_observed_at=first_observed_at,
        )

    def complete_provider(
        self,
        provider: str,
        result_class: str,
        *,
        http_status: Optional[int] = None,
        completed_at: Optional[str] = None,
    ) -> bool:
        name = _provider(provider)
        outcome = str(result_class or "").strip().upper()
        if outcome not in PROOF_GUARD_RESULT_CLASSES:
            raise ProofGuardError("provider result class is invalid")
        result = self.storage.complete_external_ti_proof_provider(
            proof_campaign_id=self.proof_campaign_id,
            provider=name,
            result_class=outcome,
            http_status=http_status,
            completed_at=completed_at or utc_now(),
        )
        return bool(result)


def _utc_day(value: Any) -> str:
    """Return a compact UTC day without accepting a local-time ambiguity."""

    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(timezone.utc).strftime("%Y%m%d")
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).strftime("%Y%m%d")


def production_guard_campaigns(
    campaign_base: str,
    normalized_source_ip: str,
    *,
    observed_at: Any,
    max_daily_targets: int,
) -> tuple[str, str]:
    """Build secret-free daily quota and per-target request identities.

    The quota identity exposes neither the source IP nor its digest and has a
    fixed number of deterministic slots.  The request identity carries only a
    one-way digest, so duplicate worker instances converge on one durable
    provider claim for the same source and UTC day.
    """

    base = _campaign(campaign_base)
    normalized = normalize_public_source_ip(normalized_source_ip)
    digest = source_ip_digest(normalized)
    try:
        target_limit = int(max_daily_targets)
    except (TypeError, ValueError) as exc:
        raise ProofGuardError("production proof daily target limit is invalid") from exc
    if target_limit < 1 or target_limit > 100:
        raise ProofGuardError("production proof daily target limit is invalid")
    day = _utc_day(observed_at)
    base_digest = hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]
    slot = int(digest[:16], 16) % target_limit
    quota_campaign = f"eti-prod-quota:{base_digest}:{day}:{slot:03d}"
    request_campaign = f"eti-prod-request:{base_digest}:{day}:{digest}"
    return _campaign(quota_campaign), _campaign(request_campaign)


class ExternalTIProductionGuard:
    """Bounded continuous source-IP guard with a durable daily target cap."""

    def __init__(
        self,
        storage: Any,
        campaign_base: str,
        mode: str,
        *,
        max_daily_targets: int,
    ) -> None:
        self.storage = storage
        self.campaign_base = _campaign(campaign_base)
        self.mode = _mode(mode)
        if self.mode != PROOF_GUARD_MODE_REAL:
            raise ProofGuardError("production source-IP guard requires REAL_PROOF mode")
        self.max_daily_targets = int(max_daily_targets)
        if self.max_daily_targets < 1 or self.max_daily_targets > 100:
            raise ProofGuardError("production proof daily target limit is invalid")
        self._claimed_provider_guards: Dict[str, ExternalTIProofGuard] = {}

    def claim_for_provider(
        self,
        provider: str,
        normalized_source_ip: str,
        *,
        cutoff_utc: str,
        first_observed_at: str,
    ) -> ProofGuardDecision:
        name = _provider(provider)
        try:
            quota_campaign, request_campaign = production_guard_campaigns(
                self.campaign_base,
                normalized_source_ip,
                observed_at=first_observed_at,
                max_daily_targets=self.max_daily_targets,
            )
            quota_guard = ExternalTIProofGuard(
                self.storage,
                quota_campaign,
                self.mode,
            )
            quota = quota_guard.claim_target(
                normalized_source_ip,
                cutoff_utc=cutoff_utc,
                first_observed_at=first_observed_at,
            )
            if not quota.allowed:
                return ProofGuardDecision(
                    False,
                    f"DAILY_QUOTA_{quota.code}",
                    provider=name,
                    target_claim_id=quota.target_claim_id,
                    source_ip_digest=quota.source_ip_digest,
                )
            request_guard = ExternalTIProofGuard(
                self.storage,
                request_campaign,
                self.mode,
            )
            decision = request_guard.claim_for_provider(
                name,
                normalized_source_ip,
                cutoff_utc=cutoff_utc,
                first_observed_at=first_observed_at,
            )
            if decision.allowed:
                self._claimed_provider_guards[name] = request_guard
            return decision
        except Exception:
            return ProofGuardDecision(False, "GUARD_STORAGE_UNAVAILABLE", provider=name)

    def complete_provider(
        self,
        provider: str,
        result_class: str,
        *,
        http_status: Optional[int] = None,
        completed_at: Optional[str] = None,
    ) -> bool:
        name = _provider(provider)
        guard = self._claimed_provider_guards.pop(name, None)
        if guard is None:
            raise ProofGuardError("production provider claim is not active")
        return guard.complete_provider(
            name,
            result_class,
            http_status=http_status,
            completed_at=completed_at,
        )
