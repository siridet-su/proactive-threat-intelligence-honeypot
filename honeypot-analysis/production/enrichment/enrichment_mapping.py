"""
Section 1B — IP Enrichment Mapping (v2)
========================================

CHANGES FROM v1:
  [FIX-A] raw_otx_pulse / campaign_hint split.
    Previously: otx_pulse was a single field used directly as the campaign name
    in improved_3c. This caused low-quality report names like "SSH Brute Force IPs".
    Now:
      raw_otx_pulse  → stores the original OTX pulse name verbatim (AI input only)
      campaign_hint  → reserved for the AI-synthesized campaign name written back
                       after the Claude synthesis step; starts as None
    The pipeline must never copy raw_otx_pulse directly to campaign_name.

  [FIX-B] Shodan/Censys infrastructure fields added.
    Previously: only asn and geo (country) were mapped, providing little analytical
    depth beyond "this IP is in China on DigitalOcean".
    Now: open_ports, infrastructure_tags, is_tor_exit, is_vpn, host_type, and
    running_services are mapped. The sophistication scorer and discovery evidence
    builder in improved_3c can now make statements like "attacker masked origin
    via Tor exit node" or "infrastructure is residential — likely compromised host".

  [FIX-C] VirusTotal hash fields added at IP level.
    Previously: file hashes appeared in the IOC table but were never enriched.
    Now: vt_detection_ratio, vt_malware_family, and vt_hit are mapped onto IP
    objects when the offline enrichment collector has associated a hash with an IP
    session. These are opportunistic — missing values degrade gracefully to None/False.
    Zero detections are stored as vt_hit=False and must NOT be interpreted as clean.

  [FIX-D] AbuseIPDB risk_score guard documentation.
    risk_score is retained but the field-map comment now explicitly states the
    constraint: it must never be the primary driver of sophistication scoring.
    A fresh APT VPS will score 0. A noisy Mirai bot will score 100. These are
    inverted from their actual sophistication level. The field is useful only as
    one corroborating signal when combined with ja3_label, hassh_label, and
    infrastructure_tags.

FIELD MAPPING (enrichment JSON key → IP object attribute):
  raw_otx_pulse        → ip.raw_otx_pulse      (verbatim OTX pulse name — AI input only)
  campaign_hint        → ip.campaign_hint       (AI-synthesized name — written at analysis time)
  otx_tags             → ip.otx_tags            (list — structured controlled vocabulary)
  ja3_label            → ip.ja3_label
  hassh_label          → ip.hassh_label
  asn                  → ip.asn
  country              → ip.geo
  risk_score           → ip.risk_score          (int — NEVER primary sophistication signal)
  isp                  → ip.isp
  first_seen           → ip.first_seen
  last_seen            → ip.last_seen
  total_reports        → ip.total_reports
  abuse_tags           → ip.abuse_tags          (list)
  ja3                  → ip.ja3
  hassh                → ip.hassh
  open_ports           → ip.open_ports          (list[int])
  infrastructure_tags  → ip.infrastructure_tags (list[str]: tor, vpn, compromised_router …)
  is_tor_exit          → ip.is_tor_exit         (bool)
  is_vpn               → ip.is_vpn              (bool)
  host_type            → ip.host_type           (str: vps | dedicated | residential | shared)
  running_services     → ip.running_services    (list[str]: ssh, http, smtp …)
  vt_detection_ratio   → ip.vt_detection_ratio  (str: "45/70" or None)
  vt_malware_family    → ip.vt_malware_family   (str or None)
  vt_hit               → ip.vt_hit             (bool — False does NOT mean clean)
"""

from typing import Any, Dict, List, Optional

from production.utils.sensitive_data import redact_exception_for_log


# FIELD MAPPING TABLE  (v2)
#
# Format: json_key → (ip_attribute_name, default_value)
#
# Rules:
#   1. Adding a new source field requires only a new entry here — no code changes.
#   2. List defaults must be [] (not None) so iteration is always safe.
#   3. Bool defaults must be False, not None, so truthiness checks are safe.
#   4. raw_otx_pulse and campaign_hint are SEPARATE. See module docstring.
#   5. risk_score default is 0 — absence of reports ≠ safe. See [FIX-D].
_ENRICHMENT_FIELD_MAP: Dict[str, tuple] = {
    # ── OTX ──────────────────────────────────────────────────────────────────
    # IMPORTANT: raw_otx_pulse is stored verbatim for AI consumption as evidence.
    # It must NEVER be copied directly to campaign_name in the analysis layer.
    # campaign_hint is populated by the AI synthesis step, not by this mapper.
    #
    # BACKWARD COMPATIBILITY: older enrichment JSON files (and the demo file
    # demo_enrichment_credential_stuffing.json) use "otx_pulse" as the key.
    # Both "raw_otx_pulse" (new) and "otx_pulse" (legacy) are mapped to the
    # same ip attribute: ip.raw_otx_pulse. The legacy key is checked first
    # in apply_enrichment_to_ip() and is overridden if the new key also exists.
    # Do NOT remove the legacy entry — it ensures old enrichment DBs continue
    # to work without requiring a data migration.
    "otx_pulse":           ("raw_otx_pulse",       None),   # LEGACY key — maps to raw_otx_pulse
    "raw_otx_pulse":       ("raw_otx_pulse",       None),   # NEW key — takes precedence if both present
    "campaign_hint":       ("campaign_hint",        None),
    "otx_tags":            ("otx_tags",             []),

    # ── Fingerprints ─────────────────────────────────────────────────────────
    "ja3_label":           ("ja3_label",            None),
    "hassh_label":         ("hassh_label",          None),
    "ja3":                 ("ja3",                  None),
    "hassh":               ("hassh",                None),

    # ── Network / Geo ─────────────────────────────────────────────────────────
    "asn":                 ("asn",                  None),
    "country":             ("geo",                  None),
    "isp":                 ("isp",                  None),

    # ── AbuseIPDB ────────────────────────────────────────────────────────────
    # WARNING: risk_score is a crowd complaint counter, not a sophistication
    # indicator. A fresh APT VPS scores 0. A Mirai bot scores 100. This field
    # must only be used as ONE corroborating signal alongside fingerprint data.
    # The sophistication scorer in improved_3c must NOT use risk_score as a
    # primary input. See _build_analytical_confidence() for the correct usage.
    "risk_score":          ("risk_score",           0),
    "total_reports":       ("total_reports",        0),
    "abuse_tags":          ("abuse_tags",           []),
    # AbuseIPDB returns a 'categories' field — list of integer category codes.
    # These are decoded to human-readable labels by decode_abuseipdb_categories().
    # Stored as ip.abuseipdb_categories (list[str]).
    "abuseipdb_categories": ("abuseipdb_categories", []),

    # ── Temporal ─────────────────────────────────────────────────────────────
    "first_seen":          ("first_seen",           None),
    "last_seen":           ("last_seen",            None),

    # ── Shodan / Censys infrastructure ──────────────────────────────────────
    # These fields provide attacker infrastructure context that ASN+geo cannot.
    # infrastructure_tags examples: tor, vpn, compromised_router, cdn, scanner,
    #   bulletproof_hosting, residential_proxy, mobile_carrier, cloud_provider
    # host_type examples: vps, dedicated, residential, shared, mobile
    # A residential IP suggests compromised device (bot node).
    # A VPS with SSH open on non-standard ports suggests deliberate operator infra.
    "open_ports":          ("open_ports",           []),
    "infrastructure_tags": ("infrastructure_tags",  []),
    "is_tor_exit":         ("is_tor_exit",          False),
    "is_vpn":              ("is_vpn",               False),
    "host_type":           ("host_type",            None),
    "running_services":    ("running_services",     []),
    "shodan_tags":         ("shodan_tags",          []),    # Shodan-specific tag list

    # ── VirusTotal (hash-keyed, associated to IP by session) ─────────────────
    # vt_hit=False does NOT mean the file is clean — it means no current
    # AV signatures match. Polymorphic droppers and fresh malware routinely
    # return 0/70. These fields are opportunistic: use hits, ignore misses.
    "vt_detection_ratio":  ("vt_detection_ratio",  None),
    "vt_malware_family":   ("vt_malware_family",   None),
    "vt_hit":              ("vt_hit",              False),
}

# Fields whose content is a list of infrastructure behaviour tags.
# Used by the analysis layer to validate types and generate human-readable labels.
_INFRASTRUCTURE_TAG_FIELDS = {"infrastructure_tags", "otx_tags", "abuse_tags",
                               "open_ports", "running_services", "abuseipdb_categories"}


# ABUSEIPDB CATEGORY DECODER
# Source: https://www.abuseipdb.com/categories
# Maps integer category code → human-readable label.
# Used to convert raw 'categories' arrays from AbuseIPDB API to readable labels.
_ABUSEIPDB_CATEGORY_LABELS: Dict[int, str] = {
    1:  "DNS Compromise",
    2:  "DNS Poisoning",
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute Force",
    6:  "Ping of Death",
    7:  "Phishing",
    8:  "Fraud/VoIP",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def decode_abuseipdb_categories(categories: List[int]) -> List[str]:
    """Convert AbuseIPDB integer category codes to human-readable labels.

    Example:
        decode_abuseipdb_categories([18, 22]) → ['Brute Force', 'SSH']

    Unknown codes are preserved as 'Category-{n}' so new codes don't get silently dropped.
    """
    return [
        _ABUSEIPDB_CATEGORY_LABELS.get(c, f"Category-{c}")
        for c in (categories or [])
        if isinstance(c, int)
    ]


def apply_enrichment_to_ip(ip_obj: Any, enrichment_record: Optional[Dict]) -> Any:
    """
    Write all enrichment fields onto ip_obj as direct attributes.

    Parameters
    ----------
    ip_obj           : IP object from ioc_bundle (any object with __dict__)
    enrichment_record: dict from enrichment_db[ip_value], or None if not found

    Behaviour
    ---------
    - If enrichment_record is None, safe defaults are applied so getattr()
      never raises AttributeError downstream.
    - List fields are always coerced to list even if the JSON stored a scalar.
    - Bool fields are always coerced to bool.
    - raw_otx_pulse is stored verbatim; campaign_hint defaults to None so
      the analysis layer can distinguish "not yet synthesized" from "not found".
    - BACKWARD COMPATIBILITY: if the enrichment record contains the legacy key
      "otx_pulse" but NOT "raw_otx_pulse", the legacy value is used. If both
      keys exist, "raw_otx_pulse" takes precedence. This ensures old enrichment
      databases (including demo_enrichment_credential_stuffing.json which uses
      "otx_pulse") continue to work without a data migration.

    Returns ip_obj with attributes set (mutates in place and returns for chaining).
    """
    if not enrichment_record:
        for _, (attr, default) in _ENRICHMENT_FIELD_MAP.items():
            if not hasattr(ip_obj, attr):
                # Deep-copy mutable defaults so objects don't share list references
                setattr(ip_obj, attr, list(default) if isinstance(default, list) else default)
        return ip_obj

    # Track which attributes have already been written so that when both the
    # legacy key ("otx_pulse") and the new key ("raw_otx_pulse") exist in the
    # same record, the new key wins (it appears later in _ENRICHMENT_FIELD_MAP
    # and overwrites the legacy value written first).
    for json_key, (attr, default) in _ENRICHMENT_FIELD_MAP.items():
        # Use sentinel to distinguish "key absent" from "key present with None value"
        _ABSENT = object()
        raw_value = enrichment_record.get(json_key, _ABSENT)

        # Skip if this key is completely absent from the record — do not
        # overwrite a value that was already written by the legacy key alias.
        if raw_value is _ABSENT:
            # Only set default if the attribute hasn't been written yet at all
            if not hasattr(ip_obj, attr):
                setattr(ip_obj, attr,
                        list(default) if isinstance(default, list) else default)
            continue

        value = raw_value

        # Coerce list fields
        if isinstance(default, list) and not isinstance(value, list):
            value = [value] if value is not None else []

        # Coerce bool fields
        if isinstance(default, bool) and not isinstance(value, bool):
            value = bool(value)

        setattr(ip_obj, attr, value)

    return ip_obj


def _describe_infrastructure(ip_obj: Any) -> str:
    """
    Produce a human-readable infrastructure label for an IP object.

    Used in discovery evidence and analyst-facing output. Never used to drive
    scoring directly.

    Examples:
      "Tor exit node (residential)"
      "VPN endpoint — DigitalOcean, ports: 22, 80, 443"
      "Compromised router (residential)"
      "VPS — Hetzner, running: ssh, http"
    """
    parts = []

    infra_tags = getattr(ip_obj, 'infrastructure_tags', []) or []
    is_tor     = getattr(ip_obj, 'is_tor_exit', False)
    is_vpn     = getattr(ip_obj, 'is_vpn', False)
    host_type  = getattr(ip_obj, 'host_type', None)
    isp        = getattr(ip_obj, 'isp', None)
    ports      = getattr(ip_obj, 'open_ports', []) or []
    services   = getattr(ip_obj, 'running_services', []) or []

    if is_tor:
        parts.append("Tor exit node")
    elif is_vpn:
        parts.append("VPN endpoint")
    elif 'compromised_router' in infra_tags:
        parts.append("Compromised router")
    elif 'residential_proxy' in infra_tags:
        parts.append("Residential proxy")
    elif 'bulletproof_hosting' in infra_tags:
        parts.append("Bulletproof hosting")
    elif 'scanner' in infra_tags:
        parts.append("Known scanner")

    host_label = f"({host_type})" if host_type else ""
    if host_label:
        parts.append(host_label)

    if isp:
        parts.append(f"— {isp}")

    if ports:
        parts.append(f"ports: {', '.join(str(p) for p in sorted(ports)[:8])}")

    if services and not ports:
        parts.append(f"running: {', '.join(services[:5])}")

    if not parts:
        return "No infrastructure data"

    return " ".join(parts)


def _infrastructure_sophistication_signal(ip_obj: Any) -> tuple:
    """
    Return (score_delta: int, reason: str) from infrastructure tags.

    This signal contributes to the sophistication score but is ADDITIVE — it
    never overrides fingerprint or behavioral evidence.

    Score deltas:
      +2  Tor exit or residential proxy  → origin masking = deliberate tradecraft
      +1  VPN endpoint                   → basic operational security
      +1  Bulletproof hosting            → deliberate choice to avoid takedown
      -1  Known scanner / CDN            → likely automated, not targeted
       0  VPS / dedicated / unknown      → neutral
      -2  Shared hosting                 → unlikely to be deliberate attack infra
    """
    infra_tags = getattr(ip_obj, 'infrastructure_tags', []) or []
    is_tor     = getattr(ip_obj, 'is_tor_exit', False)
    is_vpn     = getattr(ip_obj, 'is_vpn', False)
    host_type  = getattr(ip_obj, 'host_type', None)

    if is_tor or 'residential_proxy' in infra_tags:
        return 2, "Tor/residential proxy — deliberate origin masking"
    if is_vpn:
        return 1, "VPN endpoint — basic operational security observed"
    if 'bulletproof_hosting' in infra_tags:
        return 1, "Bulletproof hosting — deliberate infrastructure choice"
    if 'scanner' in infra_tags or 'cdn' in infra_tags:
        return -1, "Known scanner/CDN infrastructure — likely automated"
    if host_type == 'shared':
        return -2, "Shared hosting — unlikely deliberate attack infrastructure"
    return 0, ""


def load_enrichment_db(path: str) -> Dict[str, Dict]:
    """
    Load the enrichment JSON database from disk.

    The database is produced by the offline enrichment collector
    (enrichment_collector.py) and keyed by IP string.

    Returns an empty dict (not an exception) if the file is missing or corrupt,
    so the pipeline degrades gracefully rather than crashing.
    """
    import json
    import os
    if not os.path.exists(path):
        print(f"[1B] Enrichment DB not found at {path} — proceeding without enrichment")
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        ip_count = len(data)
        # Report field coverage so gaps are visible at startup
        sample_keys = set()
        for record in list(data.values())[:5]:
            sample_keys.update(record.keys())
        mapped = sample_keys & set(_ENRICHMENT_FIELD_MAP.keys())
        unmapped = sample_keys - set(_ENRICHMENT_FIELD_MAP.keys())
        print(f"[1B] Loaded enrichment DB: {ip_count} IP records from {path}")
        print(f"[1B] Field coverage: {len(mapped)} mapped, {len(unmapped)} unmapped "
              f"({', '.join(sorted(unmapped)[:5])})" if unmapped else
              f"[1B] Field coverage: {len(mapped)} mapped fields, none unmapped")
        return data
    except Exception as e:
        print(f"[1B] Failed to load enrichment DB: {redact_exception_for_log(e)}")
        return {}


def enrich_ioc_bundle(ioc_bundle: Any, enrichment_db: Dict[str, Dict]) -> Any:
    """
    Apply enrichment to every IP in ioc_bundle in place.

    Changes from v1:
      - Reports new infrastructure fields (is_tor_exit, infrastructure_tags, host_type)
      - Reports VT hit status
      - Explicitly warns when raw_otx_pulse is present (so the caller knows
        to run campaign name synthesis before building the hypothesis)
      - Validates that risk_score is present but warns if it's the only signal

    Returns ioc_bundle with all IP objects enriched.
    """
    if not enrichment_db:
        print("[1B] No enrichment data available — IP objects left unenriched")
        return ioc_bundle

    enriched_count   = 0
    pulse_found      = 0
    legacy_key_count = 0  # IPs whose enrichment record used "otx_pulse" (legacy key)
    tor_found        = 0
    vt_hits          = 0
    score_only_count = 0  # IPs where risk_score is the only signal (warn)

    for ip_obj in getattr(ioc_bundle, 'ips', []):
        ip_str = getattr(ip_obj, 'value', str(ip_obj))
        record = enrichment_db.get(ip_str)
        apply_enrichment_to_ip(ip_obj, record)

        if record:
            enriched_count += 1

            # Detect whether the legacy "otx_pulse" key was the source of the pulse.
            # This is purely informational — apply_enrichment_to_ip already handled
            # the backward compatibility correctly, so no fix is needed here.
            uses_legacy_key = ('otx_pulse' in record and
                               'raw_otx_pulse' not in record)
            if uses_legacy_key:
                legacy_key_count += 1

            has_fingerprint = (
                getattr(ip_obj, 'ja3_label', None) or
                getattr(ip_obj, 'hassh_label', None) or
                getattr(ip_obj, 'infrastructure_tags', [])
            )
            has_score_only = (
                getattr(ip_obj, 'risk_score', 0) > 0 and
                not has_fingerprint
            )
            if has_score_only:
                score_only_count += 1

            if getattr(ip_obj, 'raw_otx_pulse', None):
                pulse_found += 1
            if getattr(ip_obj, 'is_tor_exit', False):
                tor_found += 1
            if getattr(ip_obj, 'vt_hit', False):
                vt_hits += 1

            infra_desc = _describe_infrastructure(ip_obj)
            print(
                f"  [1B] Enriched {ip_str}: "
                f"risk={getattr(ip_obj, 'risk_score', 0)} "
                f"| asn={getattr(ip_obj, 'asn', 'N/A')} "
                f"| ja3={str(getattr(ip_obj, 'ja3_label', 'N/A'))[:40]} "
                f"| infra=[{infra_desc}] "
                f"| otx_tags={getattr(ip_obj, 'otx_tags', [])}"
                + (f" | pulse(legacy)={record.get('otx_pulse','')[:50]}"
                   if uses_legacy_key else
                   f" | pulse={str(getattr(ip_obj, 'raw_otx_pulse', ''))[:50]}"
                   if getattr(ip_obj, 'raw_otx_pulse', None) else "")
            )
        else:
            print(f"  [1B] No enrichment record for {ip_str}")

    total_ips = len(getattr(ioc_bundle, 'ips', []))
    print(f"[1B] Enrichment complete: {enriched_count}/{total_ips} IPs enriched")

    if legacy_key_count:
        print(f"[1B] ℹ Legacy 'otx_pulse' key detected in {legacy_key_count} record(s) — "
              f"mapped to raw_otx_pulse automatically. Enrichment DB does not need migration.")
    if pulse_found:
        print(f"[1B] ⚠ OTX pulse found on {pulse_found} IP(s) — campaign name synthesis "
              f"required before hypothesis generation. Do NOT copy raw_otx_pulse directly.")
    if tor_found:
        print(f"[1B] Tor exit node(s) detected: {tor_found} IP(s) — origin masking noted")
    if vt_hits:
        print(f"[1B] VirusTotal hits: {vt_hits} IP(s) have associated known malware hashes")
    if score_only_count:
        print(f"[1B] ⚠ {score_only_count} IP(s) have risk_score but NO fingerprint data — "
              f"sophistication scorer will not use risk_score alone. "
              f"Consider adding Shodan enrichment for these IPs.")

    return ioc_bundle
