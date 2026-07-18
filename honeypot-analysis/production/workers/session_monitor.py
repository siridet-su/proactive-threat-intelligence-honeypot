"""
session_monitor.py
==================
Real-time honeypot session monitor.

Testable in Colab with log replay.
Production-ready: same code, different event source.

Usage (Colab test):
    from production.workers.session_monitor import SessionMonitor, CowrieLogReplayer
    monitor = SessionMonitor(feeds=feeds, mitre_db=mitre_db)
    for event in CowrieLogReplayer("demo_cowrie_credential_stuffing.json").stream(delay=0.05):
        alerts = monitor.on_event(event)
        for a in alerts:
            print(a)
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Any

from production.classification.trust import (
    classification_audit_reason,
    classification_evidence_tier,
    is_trusted_classification_event,
)
from production.utils.credential_hmac import (
    CREDENTIAL_HMAC_SCHEME,
    CredentialHasher,
    credential_metadata_for_provenance,
)
from production.utils.sensitive_data import (
    redact_exception_for_log,
    redact_for_artifact,
    redact_for_log,
)
from production.utils.serialization import command_observation_provenance, stable_id


def _safe_log_text(value: Any, *, max_chars: int = 1_000) -> str:
    try:
        detail = redact_for_log(value, max_string_chars=max_chars)
    except Exception:
        return "[REDACTION FAILED]"
    return str(detail)


def _safe_exception_text(exc: BaseException) -> str:
    return redact_exception_for_log(exc)


def _safe_reporting_mapping(value: Any, label: str) -> Dict[str, Any]:
    try:
        redacted = redact_for_artifact(value)
    except Exception:
        raise ValueError(f"{label} redaction failed") from None
    if not isinstance(redacted, dict):
        raise TypeError(f"{label} must redact to an object")
    return redacted


def _safe_command_text(value: Any) -> str:
    try:
        redacted = redact_for_artifact({"command": str(value)})
    except Exception:
        return "[REDACTION FAILED]"
    command = redacted.get("command") if isinstance(redacted, dict) else None
    return command if isinstance(command, str) else "[REDACTION FAILED]"

try:
    from production.correlation.session_ttp_knowledge import (
        is_subtechnique_id as _is_subtechnique_id,
        main_ttp_id as _main_ttp_id,
    )
except Exception:
    def _main_ttp_id(value: Any) -> str:
        text = str(value or "").strip().upper()
        if re.match(r"^T\d{4}\.\d{3}$", text):
            return text.split(".", 1)[0]
        return text

    def _is_subtechnique_id(value: Any) -> bool:
        return bool(re.match(r"^T\d{4}\.\d{3}$", str(value or "").strip().upper()))


# Maps: current tactic â†’ likely next tactics (probability order)
_TACTIC_PROGRESSION: Dict[str, List[str]] = {
    "initial-access":       ["execution", "discovery", "persistence"],
    "execution":            ["discovery", "credential-access", "collection"],
    "discovery":            ["credential-access", "lateral-movement", "collection"],
    "credential-access":    ["persistence", "lateral-movement", "exfiltration"],
    "persistence":          ["defense-evasion", "command-and-control", "collection"],
    "privilege-escalation": ["defense-evasion", "credential-access", "persistence"],
    "defense-evasion":      ["collection", "command-and-control", "exfiltration"],
    "lateral-movement":     ["collection", "command-and-control", "exfiltration"],
    "collection":           ["exfiltration", "command-and-control"],
    "command-and-control":  ["exfiltration", "impact"],
    "exfiltration":         ["impact"],
    "impact":               [],
}

# Each tuple: (regex, TTP_ID, tactic)
_KEYWORD_TTP_RULES: List[tuple] = [
    (r'\b(whoami|id\b|uname)', 'T1033', 'discovery'),
    (r'cat /etc/(passwd|shadow)', 'T1003', 'credential-access'),
    (r'\b(ps aux|ps -ef)\b', 'T1057', 'discovery'),
    (r'(ls -la?|find /|locate )', 'T1083', 'discovery'),
    (r'\b(wget|curl)\b.*https?://', 'T1105', 'command-and-control'),
    (r'chmod \+x|chmod 777', 'T1059', 'execution'),
    (r'(crontab|/etc/cron)', 'T1053', 'persistence'),
    (r'(useradd |adduser |passwd )', 'T1136', 'persistence'),
    (r'(authorized_keys|ssh-keygen)', 'T1098', 'persistence'),
    (r'(iptables|ufw\b)', 'T1562', 'defense-evasion'),
    (r'(history -c|rm -rf /var/log)', 'T1070', 'defense-evasion'),
    (r'(nc -|ncat |socat )', 'T1105', 'command-and-control'),
    (r'\bsudo\b|\bsu -\b', 'T1078', 'privilege-escalation'),
    (r'(python\S* -c|perl \S* -e|bash -i)', 'T1059', 'execution'),
    (r'^\s*(?:\./|/tmp/|/var/tmp/|/dev/shm/)[^\s;&|]+', 'T1059', 'execution'),
    (r'base64 (-d|--decode)', 'T1027', 'defense-evasion'),
    (r'(scp |rsync ).+@', 'T1041', 'exfiltration'),
    (r'CVE-\d{4}-\d{4,7}', '__CVE__', 'initial-access'),
]



class CampaignTracker:
    """
    Cross-session campaign correlation.

    Tracks fingerprints from each closed session and detects when a new session
    shares fingerprints with a previously observed actor â€” even if the IP changed.

    Fingerprints used (in priority order):
      1. JA3 hash (TLS fingerprint â€” very reliable)
      2. HASSH hash (SSH client fingerprint â€” reliable)
      3. ASN (same ISP/provider â€” medium confidence)
      4. Command pattern overlap (â‰¥60% similar commands â€” medium confidence)

    Usage
    -----
        tracker = CampaignTracker()
        # When session ends:
        result = tracker.check_and_register(state)
        if result['is_returning_actor']:
            print(f"Returning actor! Linked to: {result['linked_sessions']}")
    """

    def __init__(self, min_overlap: float = 0.60):
        self.min_overlap = min_overlap
        self._profiles: list = []   # list of session fingerprint dicts

    def check_and_register(self, state: "SessionState") -> dict:
        """
        Check if this session matches a known actor, then register it.

        Returns
        -------
        dict with:
          - is_returning_actor (bool)
          - confidence (str): 'HIGH' / 'MEDIUM' / 'LOW'
          - match_signals (list): which fingerprints matched
          - linked_sessions (list): session IDs that matched
          - linked_ips (list): IPs from matched sessions
        """
        result = {
            "is_returning_actor": False,
            "confidence":         "LOW",
            "match_signals":      [],
            "linked_sessions":    [],
            "linked_ips":         [],
        }

        fp = self._build_fingerprint(state)
        matches = []

        for prev in self._profiles:
            signals = self._compare(fp, prev)
            if signals:
                matches.append({
                    "session_id": prev["session_id"],
                    "src_ip":     prev["src_ip"],
                    "signals":    signals,
                })

        if matches:
            result["is_returning_actor"] = True
            all_signals = [s for m in matches for s in m["signals"]]
            result["match_signals"]   = list(set(all_signals))
            result["linked_sessions"] = [m["session_id"] for m in matches]
            result["linked_ips"]      = list(set(m["src_ip"] for m in matches))
            # JA3 or HASSH = HIGH confidence; 2+ other signals = MEDIUM
            if any(s in ("ja3", "hassh") for s in result["match_signals"]):
                result["confidence"] = "HIGH"
            elif len(result["match_signals"]) >= 2:
                result["confidence"] = "MEDIUM"
            else:
                result["confidence"] = "LOW"

        # Register this session's fingerprint
        self._profiles.append(fp)
        return result

    def _build_fingerprint(self, state: "SessionState") -> dict:
        return {
            "session_id":     state.session_id,
            "src_ip":         state.src_ip,
            "ja3":            getattr(state, "ja3", None),           # TLS (Zeek/Suricata)
            "hassh":          state.hassh,                            # SSH (cowrie.client.kex)
            "client_version": getattr(state, "client_version", ""),  # SSH-2.0-PuTTY etc.
            "asn":            getattr(state, "asn", None),
            "cmd_set":        set(state.commands[:20]),
            "ttps":           set(state.ttps),
        }

    def _compare(self, fp: dict, prev: dict) -> list:
        """Return list of matching signal names, empty if no match."""
        signals = []

        # JA3 fingerprint â€” TLS client hello (highest confidence)
        # Available from Zeek, Suricata, or web honeypot (NOT from Cowrie SSH alone)
        if fp["ja3"] and prev["ja3"] and fp["ja3"] == prev["ja3"]:
            signals.append("ja3")

        # HASSH fingerprint â€” SSH crypto negotiation (equivalent of JA3 for SSH)
        # Available from cowrie.client.kex event
        if fp["hassh"] and prev["hassh"] and fp["hassh"] == prev["hassh"]:
            signals.append("hassh")

        # SSH client version string (e.g. "SSH-2.0-PuTTY_Release_0.79")
        # Useful when hassh not captured â€” confirms same tool
        cv1 = fp.get("client_version", "")
        cv2 = prev.get("client_version", "")
        if cv1 and cv2 and cv1 == cv2 and cv1 != "":
            signals.append("client_version")

        # ASN match (same network provider / hosting range)
        if fp["asn"] and prev["asn"] and fp["asn"] == prev["asn"]:
            signals.append("asn")

        # Command pattern overlap (Jaccard similarity â‰¥ min_overlap)
        if fp["cmd_set"] and prev["cmd_set"]:
            inter = len(fp["cmd_set"] & prev["cmd_set"])
            union = len(fp["cmd_set"] | prev["cmd_set"])
            if union > 0 and inter / union >= self.min_overlap:
                signals.append(f"cmd_overlap_{inter}/{union}")

        # TTP set overlap (â‰¥3 shared TTPs from different IP = notable)
        if fp["src_ip"] != prev["src_ip"] and len(fp["ttps"] & prev["ttps"]) >= 3:
            signals.append(f"ttp_overlap_{len(fp['ttps'] & prev['ttps'])}")

        return signals

    @property
    def profile_count(self) -> int:
        return len(self._profiles)

    def __repr__(self) -> str:
        return f"<CampaignTracker profiles={self.profile_count}>"


@dataclass
class AlertEvent:
    """Structured alert emitted when a session crosses a threshold."""
    session_id:     str
    src_ip:         str
    timestamp:      str
    severity:       str          # LOW / MEDIUM / HIGH / CRITICAL
    reason:         str
    ttps_observed:  List[str]
    tactics_observed: List[str]
    prediction:     List[str]    # predicted next tactics
    commands_sample: List[str]
    kev_matches:    List[dict] = field(default_factory=list)
    sigma_hits:     List[str]  = field(default_factory=list)

    def __str__(self) -> str:
        pred = " -> ".join(self.prediction[:3]) or "unknown"
        kev  = f" | KEV:{len(self.kev_matches)}" if self.kev_matches else ""
        return (
            f"[{self.severity}] {self.session_id[:8]} ({self.src_ip}) | "
            f"{self.reason}{kev} | "
            f"TTPs: {','.join(self.ttps_observed[-4:])} | "
            f"Next: {pred}"
        )


@dataclass
class SessionState:
    """Per-session accumulator (lives in memory during the session)."""
    session_id:       str
    src_ip:           str
    start_time:       str
    src_port:         int          = 0
    dst_ip:           str          = ""
    dst_port:         int          = 22
    sensor:           str          = ""
    protocol:         str          = "ssh"
    # SSH fingerprints (for campaign correlation)
    hassh:            Optional[str] = None    # SSH client HASSH hash (from cowrie.client.kex)
    ja3:              Optional[str] = None    # TLS JA3 hash (from Zeek/Suricata/web honeypot â€” not Cowrie SSH)
    client_version:   str          = ""       # e.g. "SSH-2.0-PuTTY_Release_0.79"
    # Login tracking
    login_username:   str          = ""
    login_password:   str          = ""       # redacted unless raw storage is explicitly enabled
    login_password_hash: str       = ""       # stable hash for clustering without exposing plaintext
    login_password_hash_aliases: List[str] = field(default_factory=list)
    login_password_redacted: str   = ""
    credential_metadata: dict      = field(default_factory=dict)
    # Session data
    ttps:             List[str]    = field(default_factory=list)
    tactics:          List[str]    = field(default_factory=list)
    commands:         List[str]    = field(default_factory=list)
    commands_success: List[str]    = field(default_factory=list)
    commands_failed:  List[str]    = field(default_factory=list)
    ttp_command_map:  Dict[str, List[str]] = field(default_factory=dict)
    ttp_sources:      Dict[str, List[str]] = field(default_factory=dict)
    classification_events: List[dict] = field(default_factory=list)
    session_ttp_correlations: List[dict] = field(default_factory=list)
    session_ttp_correlation_summary: dict = field(default_factory=dict)
    session_evidence_graph: dict = field(default_factory=dict)
    session_evidence_graph_summary: dict = field(default_factory=dict)
    raw_events:       List[dict]   = field(default_factory=list)
    sigma_hits:       List[str]    = field(default_factory=list)
    kev_matches:      List[dict]   = field(default_factory=list)
    alerts_fired:     List[str]    = field(default_factory=list)
    login_attempts:   int          = 0
    login_success:    bool         = False
    is_ended:         bool         = False
    duration:         float        = 0.0      # seconds (from session.closed)
    asn:              Optional[str] = None
    geo:              Optional[str] = None
    isp:              Optional[str] = None
    risk_score:       int          = 0
    vt_hit:           bool         = False
    vt_detection_ratio: Optional[str] = None
    vt_malware_family: Optional[str] = None
    is_tor_exit:      bool         = False
    is_vpn:           bool         = False
    host_type:        Optional[str] = None
    infrastructure_tags: List[str] = field(default_factory=list)
    otx_tags:         List[str]    = field(default_factory=list)
    abuse_tags:       List[str]    = field(default_factory=list)
    abuseipdb_categories: List[str] = field(default_factory=list)
    shodan_tags:      List[str]    = field(default_factory=list)
    shodan_hostnames: List[str]    = field(default_factory=list)
    shodan_cpes:      List[str]    = field(default_factory=list)
    shodan_vulns:     List[str]    = field(default_factory=list)
    censys_labels:    List[str]    = field(default_factory=list)
    censys_api:       Optional[str] = None
    shodan_api:       Optional[str] = None
    open_ports:       List[int]    = field(default_factory=list)
    running_services: List[str]    = field(default_factory=list)
    total_reports:    int          = 0
    provider_status:  dict         = field(default_factory=dict)
    raw_otx_pulse:    Optional[str] = None
    enrichment_status: dict        = field(default_factory=dict)
    classification_policy: dict    = field(default_factory=dict)
    credential_policy: dict        = field(default_factory=dict)
    process_events:   List[dict]   = field(default_factory=list)
    session_metadata: dict         = field(default_factory=dict)
    process_sessions_summary: List[dict] = field(default_factory=list)
    bpg_list:         List[dict]   = field(default_factory=list)
    ioc_summary:      dict         = field(default_factory=dict)
    process_tree_status: dict      = field(default_factory=dict)

    @property
    def unique_tactics(self) -> List[str]:
        seen, out = set(), []
        for t in self.tactics:
            if t not in seen:
                seen.add(t); out.append(t)
        return out


class SessionMonitor:
    """
    Real-time session monitor.

    - Processes Cowrie events one at a time (streaming).
    - Classifies commands via SecureBERT (if injected) or keyword fallback.
    - Checks Sigma/KEV thresholds after every command.
    - Predicts next attacker action from MITRE tactic chains.
    - Calls on_session_end_callback when session closes (trigger full pipeline).

    Parameters
    ----------
    feeds       : ThreatFeedDB from production.enrichment.threat_feed_loader (Sigma + CISA KEV)
    mitre_db    : MitreAttackDB from production.enrichment.mitre_attack_loader
    enrichment_db : Optional pre-fetched enrichment records keyed by source IP.
    bert_fn     : Optional callable(command: str) â†’ (ttp_id: str, confidence: float)
                  Pass your SecureBERT classify function here.
                  Falls back to keyword matching when None.
        classification_fn : Optional callable(command: str) -> list[dict]
                  Pass the production notebook-parity classifier here when
                  multiple TTPs per command and rule/SecureBERT merge metadata
                  are needed.
    prediction_fn : Optional callable(SessionState) -> list[str]
                  Pass the production realtime prediction engine here when
                  alert text should use the same ranked prediction shown in
                  the monitor. Falls back to the legacy tactic table when
                  omitted or when the callback fails.
    on_alert    : Optional callback(AlertEvent) â€” called immediately on alert.
    on_session_end : Optional callback(SessionState) â€” called when session closes.
    propagate_session_end_errors : re-raise close callback failures so a durable
                  queue owner can retry the event. Defaults to legacy containment.
    thresholds  : dict override (else reads from defaults below).
    classification_policy : dict override for SecureBERT/rule fallback behavior.
    credential_policy : dict override for captured credential redaction/hash behavior.
    """

    # Default alert thresholds
    DEFAULT_THRESHOLDS = {
        "sigma_hits_medium":      2,   # â‰¥2 Sigma HIGH keywords â†’ MEDIUM alert
        "sigma_hits_high":        4,   # â‰¥4 Sigma HIGH keywords â†’ HIGH alert
        "ttps_medium":            3,   # â‰¥3 unique TTPs â†’ MEDIUM alert
        "ttps_high":              6,   # â‰¥6 unique TTPs â†’ HIGH alert
        "kev_cve_found":          1,   # any KEV CVE â†’ CRITICAL alert
        "login_brute_threshold":  5,   # â‰¥5 failed logins â†’ MEDIUM alert
        "dropper_pattern":        True, # wget/curl + chmod = HIGH alert
        "recon_manual_minutes":   2,   # session >2 min with recon = manual attacker
    }

    DEFAULT_CLASSIFICATION_POLICY = {
        # securebert_first preserves legacy behavior when bert_fn is provided.
        # rules_first is usually better for raw shell commands with obvious TTPs.
        "strategy": "securebert_first",
        "bert_min_confidence": 0.45,
        "keyword_fallback_on_low_confidence": True,
        "keyword_fallback_on_error": True,
    }

    DEFAULT_CREDENTIAL_POLICY = {
        "store_raw_credentials": False,
        "redaction": "[REDACTED]",
        "hash_algorithm": "disabled",
        "sanitize_raw_events": True,
        "redact_fields": ["password", "passwd"],
    }

    def __init__(
        self,
        feeds=None,
        mitre_db=None,
        enrichment_db: Optional[dict] = None,
        bert_fn: Optional[Callable[[str], tuple]] = None,
        classification_fn: Optional[Callable[[str], List[dict]]] = None,
        prediction_fn: Optional[Callable[[SessionState], List[str]]] = None,
        on_alert: Optional[Callable[[AlertEvent], None]] = None,
        on_session_end: Optional[Callable[[SessionState], None]] = None,
        propagate_session_end_errors: bool = False,
        thresholds: Optional[dict] = None,
        classification_policy: Optional[dict] = None,
        credential_policy: Optional[dict] = None,
        credential_hasher: Optional[CredentialHasher] = None,
    ):
        self.feeds          = feeds
        self.mitre_db       = mitre_db
        self.enrichment_db  = enrichment_db or {}
        self.bert_fn        = bert_fn
        self.classification_fn = classification_fn
        self.prediction_fn  = prediction_fn
        self.on_alert       = on_alert or self._default_alert_handler
        self.on_session_end = on_session_end
        self.propagate_session_end_errors = bool(propagate_session_end_errors)
        self.thresholds     = {**self.DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.classification_policy = {
            **self.DEFAULT_CLASSIFICATION_POLICY,
            **(classification_policy or {}),
        }
        self.credential_policy = {
            **self.DEFAULT_CREDENTIAL_POLICY,
            **(credential_policy or {}),
        }
        if self.credential_policy.get("store_raw_credentials") is not False:
            raise ValueError(
                "SessionMonitor must not store plaintext credentials in derived sessions"
            )
        if self.credential_policy.get("sanitize_raw_events") is not True:
            raise ValueError("SessionMonitor must sanitize derived raw events")
        if self.credential_policy.get("redaction") != "[REDACTED]":
            raise ValueError("SessionMonitor requires the canonical redaction marker")
        if set(self.credential_policy.get("redact_fields") or []) != {
            "password",
            "passwd",
        }:
            raise ValueError(
                "SessionMonitor credential redact_fields must be password and passwd"
            )
        self.credential_hasher = credential_hasher
        requested_hash_algorithm = str(
            self.credential_policy.get("hash_algorithm", "disabled")
        ).strip().lower()
        if credential_hasher is None and requested_hash_algorithm not in {
            "",
            "disabled",
            "none",
        }:
            raise ValueError(
                "credential hashing was requested without a CredentialHasher"
            )
        if (
            credential_hasher is not None
            and credential_policy is not None
            and "hash_algorithm" in credential_policy
            and requested_hash_algorithm != CREDENTIAL_HMAC_SCHEME
        ):
            raise ValueError(
                f"credential hash_algorithm must be {CREDENTIAL_HMAC_SCHEME}"
            )
        self._sessions:     Dict[str, SessionState] = {}
        self._sigma_kws:    List[str] = self._load_sigma_keywords()
        self._stats         = {"events": 0, "alerts": 0, "sessions": 0}
        self.campaign_tracker = CampaignTracker()  # cross-session correlation


    def on_event(self, event: dict) -> List[AlertEvent]:
        """
        Process one Cowrie event. Returns list of alerts fired (may be empty).
        Call this for every line from cowrie.json.
        """
        self._stats["events"] += 1
        eid        = event.get("eventid", "")
        session_id = event.get("session", "unknown")
        src_ip     = event.get("src_ip", "unknown")
        timestamp  = event.get("timestamp", datetime.now(timezone.utc).isoformat())

        # Ensure session exists
        state = self._get_or_create(session_id, src_ip, timestamp)
        state.raw_events.append(self._sanitize_event(event))

        if event.get("src_port"):   state.src_port     = int(event["src_port"])
        if event.get("dst_ip"):     state.dst_ip       = event["dst_ip"]
        if event.get("dst_port"):   state.dst_port     = int(event["dst_port"])
        if event.get("sensor"):     state.sensor       = event["sensor"]
        if event.get("protocol"):   state.protocol     = event["protocol"]

        alerts: List[AlertEvent] = []

        if eid == "cowrie.client.kex":
            # HASSH fingerprint â€” key for campaign correlation
            if event.get("hassh"):
                state.hassh = event["hassh"]

        elif eid == "cowrie.client.version":
            if event.get("version"):
                state.client_version = event["version"]

        elif eid == "cowrie.login.failed":
            state.login_attempts += 1
            alerts += self._check_thresholds(state)

        elif eid == "cowrie.login.success":
            state.login_success  = True
            self._record_login_success(state, event)

        elif eid in ("cowrie.command.input", "cowrie.command.success",
                     "cowrie.command.failed"):
            raw_command = event.get("input", "")
            cmd = "" if raw_command is None else str(raw_command).strip()
            if cmd:
                safe_cmd = _safe_command_text(cmd)
                state.commands.append(safe_cmd)
                compound_command_index = len(state.commands) - 1
                # Use 'success' field from Cowrie (1=success) or eventid
                is_success = (event.get("success") == 1 or
                              eid == "cowrie.command.success")
                if is_success:
                    state.commands_success.append(safe_cmd)
                elif eid == "cowrie.command.failed" or event.get("success") == 0:
                    state.commands_failed.append(safe_cmd)

                if is_success:
                    command_outcome = "cowrie_reported_success"
                elif eid == "cowrie.command.failed" or event.get("success") == 0:
                    command_outcome = "cowrie_reported_failure"
                else:
                    command_outcome = "outcome_unknown"

                # Classify command â†’ TTP
                for classification_index, classification in enumerate(self._classify_many_with_source(cmd)):
                    try:
                        classification = _safe_reporting_mapping(
                            dict(classification),
                            "classification",
                        )
                    except Exception:
                        classification = {
                            "command": "[REDACTION FAILED]",
                            "ttp": None,
                            "tactic": "unknown",
                            "source": "redaction_failed",
                            "confidence": 0.0,
                        }
                    classified_command = (
                        classification.get("subcommand")
                        or classification.get("command")
                        or safe_cmd
                    )
                    classification["cowrie_eventid"] = eid
                    classification["event_timestamp"] = timestamp
                    classification["command_outcome"] = command_outcome
                    classification["compound_command_index"] = compound_command_index
                    try:
                        fragment_count = int(classification.get("subcommand_count") or 1)
                    except (TypeError, ValueError):
                        fragment_count = 1
                    classification["outcome_scope"] = (
                        "compound_event" if fragment_count > 1 else "fragment"
                    )
                    classification["evidence_tier"] = classification_evidence_tier(classification)
                    classification["evidence_id"] = stable_id(
                        "class",
                        {
                            "session_id": session_id,
                            "timestamp": timestamp,
                            "eventid": eid,
                            "command": classified_command,
                            "classification_index": classification_index,
                            "ttp": classification.get("ttp"),
                            "source": classification.get("source"),
                        },
                    )
                    if classification["evidence_tier"] != "trusted_observation":
                        classification["audit_reason"] = classification_audit_reason(classification)
                    ttp = classification.get("ttp")
                    tactic = classification.get("tactic")
                    source = classification.get("source")

                    if ttp and is_trusted_classification_event(classification):
                        tactic = self._resolve_tactic(ttp, tactic or "unknown")
                        classification["tactic"] = tactic

                        if ttp not in state.ttps:
                            state.ttps.append(ttp)

                        if tactic not in state.tactics:
                            state.tactics.append(tactic)

                        mapped_cmds = state.ttp_command_map.setdefault(ttp, [])
                        if classified_command not in mapped_cmds:
                            mapped_cmds.append(classified_command)

                        sources = state.ttp_sources.setdefault(ttp, [])
                        if source and source not in sources:
                            sources.append(source)

                    state.classification_events.append(classification)

                # Sigma keyword match
                sigma_hits = self._sigma_match(cmd)
                state.sigma_hits.extend(sigma_hits)

                # CISA KEV scan (CVEs in command text)
                kev = self._kev_scan(cmd)
                if kev:
                    state.kev_matches.extend(kev)

                alerts += self._check_thresholds(state)

        elif eid == "cowrie.session.closed":
            state.duration = float(event.get("duration", 0))
            alerts += self._finalize_session(state)

        self._stats["alerts"] += len(alerts)
        for a in alerts:
            self.on_alert(a)
        return alerts

    def get_session(self, session_id: str) -> Optional[SessionState]:
        return self._sessions.get(session_id)

    def get_stats(self) -> dict:
        return {
            **self._stats,
            "active_sessions": sum(1 for s in self._sessions.values() if not s.is_ended),
        }


    def _get_or_create(self, session_id: str, src_ip: str, timestamp: str) -> SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(
                session_id=session_id,
                src_ip=src_ip,
                start_time=timestamp,
            )
            self._sessions[session_id].classification_policy = dict(self.classification_policy)
            self._sessions[session_id].credential_policy = {
                "store_raw_credentials": bool(self.credential_policy.get("store_raw_credentials", False)),
                "sanitize_raw_events": bool(self.credential_policy.get("sanitize_raw_events", True)),
                **self._credential_hash_summary(),
            }
            self._stats["sessions"] += 1
        return self._sessions[session_id]

    def _credential_hash_summary(self) -> dict:
        if self.credential_hasher is not None:
            return self.credential_hasher.safe_summary()
        return {
            "hash_algorithm": str(
                self.credential_policy.get("hash_algorithm", CREDENTIAL_HMAC_SCHEME)
            ),
            "hashing_enabled": False,
            "active_key_id": "",
            "correlation_key_ids": [],
        }

    def _hash_secret_bundle(self, value: str) -> tuple[str, tuple[str, ...]]:
        if not value or self.credential_hasher is None:
            return "", ()
        return self.credential_hasher.digests(value)

    def _event_secret_bundle(
        self,
        event: dict,
        field: str,
    ) -> tuple[str, tuple[str, ...]]:
        raw_value = event.get(field, "")
        value = "" if raw_value is None else str(raw_value)
        # SessionMonitor consumes raw Cowrie events. Never trust sensor-supplied
        # derived hashes; recompute them from the raw value at this boundary.
        return self._hash_secret_bundle(value)

    def _sanitize_event(self, event: dict) -> dict:
        try:
            projection = _safe_reporting_mapping(
                {"raw_events": [event]},
                "derived event",
            )
            projected_events = projection.get("raw_events")
            if (
                not isinstance(projected_events, list)
                or len(projected_events) != 1
                or not isinstance(projected_events[0], dict)
            ):
                raise ValueError("derived event projection failed")
            sanitized = projected_events[0]
        except Exception:
            sanitized = {
                "eventid": _safe_command_text(event.get("eventid", "")),
                "session": _safe_command_text(event.get("session", "unknown")),
                "redaction_status": "failed_closed",
            }

        redaction = str(self.credential_policy.get("redaction", "[REDACTED]"))
        for field in self.credential_policy.get("redact_fields", ["password", "passwd"]):
            sanitized.pop(f"{field}_hash", None)
            sanitized.pop(f"{field}_hash_aliases", None)
            if field in sanitized and sanitized[field] not in (None, ""):
                digest, aliases = self._event_secret_bundle(event, field)
                if digest:
                    sanitized[f"{field}_hash"] = digest
                if aliases:
                    sanitized[f"{field}_hash_aliases"] = list(aliases)
                sanitized[field] = redaction
        return sanitized

    def _record_login_success(self, state: SessionState, event: dict) -> None:
        raw_password = event.get("password", "")
        password = "" if raw_password is None else str(raw_password)
        redaction = str(self.credential_policy.get("redaction", "[REDACTED]"))

        raw_username = event.get("username", "")
        state.login_username = redaction if raw_username not in (None, "") else ""
        active_digest, digest_aliases = self._event_secret_bundle(event, "password")
        state.login_password_hash = active_digest
        state.login_password_hash_aliases = list(digest_aliases)
        state.login_password_redacted = redaction if password else ""
        state.login_password = state.login_password_redacted
        state.credential_metadata = credential_metadata_for_provenance(
            {
                "credential_observed": bool(password),
                "raw_password_stored": bool(
                    self.credential_policy.get("store_raw_credentials", False)
                ),
                "password_hash_present": bool(state.login_password_hash),
                "password_hash_alias_count": len(state.login_password_hash_aliases),
                "raw_events_sanitized": bool(
                    self.credential_policy.get("sanitize_raw_events", True)
                ),
                **self._credential_hash_summary(),
            }
        )

    def _apply_session_enrichment(self, state: SessionState) -> None:
        if not self.enrichment_db:
            state.enrichment_status = {"status": "missing", "source": "none"}
            return

        record = self.enrichment_db.get(state.src_ip)
        if not record:
            state.enrichment_status = {"status": "missing", "source": "enrichment_db"}
            return

        try:
            from production.enrichment.enrichment_mapping import apply_enrichment_to_ip

            class _EnrichedSessionView:
                value = state.src_ip

            view = _EnrichedSessionView()
            apply_enrichment_to_ip(view, record)
            for attr in (
                "asn", "geo", "isp", "infrastructure_tags", "is_tor_exit",
                "is_vpn", "host_type", "open_ports", "running_services",
                "shodan_tags", "raw_otx_pulse", "otx_tags", "risk_score",
                "abuse_tags", "abuseipdb_categories", "vt_hit",
                "vt_detection_ratio", "vt_malware_family", "censys_labels",
                "provider_status", "total_reports", "shodan_hostnames",
                "shodan_cpes", "shodan_vulns", "censys_api", "shodan_api",
            ):
                if hasattr(view, attr):
                    setattr(state, attr, getattr(view, attr))
            state.enrichment_status = {
                "status": "applied",
                "source": "enrichment_db",
                "fields": sorted(record.keys()),
            }
        except Exception as e:
            state.enrichment_status = {
                "status": "failed",
                "source": "enrichment_db",
                "error": _safe_exception_text(e),
            }


    def _resolve_tactic(self, ttp: str, fallback: str = "unknown") -> str:
        """
        Resolve a normalized MITRE ATT&CK tactic slug from a TTP ID.

        Examples:
            T1003 -> credential-access
            T1033 -> discovery
            T1059 -> execution
            T1105 -> command-and-control

        The MITRE loader owns tactic normalization via get_tactics().
        This wrapper keeps SessionMonitor independent from MITRE cache internals.
        """
        if not ttp:
            return fallback or "unknown"
        ttp = _main_ttp_id(ttp)

        if self.mitre_db and hasattr(self.mitre_db, "get_tactics"):
            try:
                tactics = self.mitre_db.get_tactics(ttp) or []
                if tactics:
                    return tactics[0]
            except Exception:
                pass

        return fallback or "unknown"

    def _classify(self, cmd: str) -> tuple:
        """Returns (ttp_id, tactic). Uses the configured classification policy."""
        result = self._classify_with_source(cmd) if hasattr(self, "_classify_with_source") else None

        if result:
            ttp, tactic, *_rest = result
            if ttp:
                ttp = _main_ttp_id(ttp)
                tactic = self._resolve_tactic(ttp, tactic or "unknown")
            return ttp, tactic

        # Legacy fallback path, retained for compatibility.
        cmd_lower = cmd.lower()

        if self.bert_fn:
            try:
                ttp, confidence = self.bert_fn(cmd)
                if confidence > 0.45 and ttp:
                    tactic = self._resolve_tactic(ttp, "unknown")
                    return ttp, tactic
            except Exception:
                pass

        for pattern, ttp_id, tactic in _KEYWORD_TTP_RULES:
            if ttp_id == "__CVE__":
                continue
            if re.search(pattern, cmd_lower):
                tactic = self._resolve_tactic(ttp_id, tactic)
                return ttp_id, tactic

        return None, None
    def _classify_many_with_source(self, cmd: str) -> List[dict]:
        """Returns normalized classification event dicts for a command."""
        policy = self.classification_policy
        strategy = policy.get("strategy", "securebert_first")

        if self.classification_fn and strategy == "notebook_merge":
            try:
                results = self.classification_fn(cmd) or []
                normalized = []

                for result in results:
                    item = dict(result)
                    item.setdefault("command", cmd)
                    item.setdefault("ttp", None)
                    item.setdefault("tactic", "unknown")
                    item.setdefault("source", "notebook_merge")
                    item.setdefault("confidence", 0.0)

                    if item.get("ttp"):
                        item["tactic"] = self._resolve_tactic(
                            item.get("ttp"),
                            item.get("tactic") or "unknown",
                        )

                    normalized.append(item)

                return normalized or [{
                    "command": cmd,
                    "ttp": None,
                    "tactic": "unknown",
                    "source": "unclassified",
                    "confidence": 0.0,
                }]

            except Exception as exc:
                return [{
                    "command": cmd,
                    "ttp": None,
                    "tactic": "unknown",
                    "source": "notebook_merge_error",
                    "confidence": 0.0,
                    "error": _safe_exception_text(exc),
                }]

        events: List[dict] = []
        for fragment in self._split_command_fragments(cmd):
            fragment_text = fragment["text"]
            ttp, tactic, source, confidence = self._classify_with_source(fragment_text)
            source_ttp = ttp
            if ttp:
                active_ttp = _main_ttp_id(ttp)
                if active_ttp != ttp:
                    ttp = active_ttp
                    tactic = self._resolve_tactic(ttp, tactic or "unknown")

            if ttp:
                tactic = self._resolve_tactic(ttp, tactic or "unknown")

            event = {
                "command": fragment_text,
                "ttp": ttp,
                "tactic": tactic or "unknown",
                "source": source,
                "confidence": confidence,
            }
            if source_ttp and source_ttp != ttp:
                event.update(
                    {
                        "source_ttp": source_ttp,
                        "source_subtechnique": source_ttp if _is_subtechnique_id(source_ttp) else "",
                        "technique_granularity": "subtechnique_collapsed",
                    }
                )
            elif ttp:
                event["technique_granularity"] = "parent"
            if fragment["count"] > 1:
                event.update(
                    {
                        "original_command": cmd,
                        "subcommand": fragment_text,
                        "subcommand_index": fragment["index"],
                        "subcommand_count": fragment["count"],
                        "operator_before": fragment.get("operator_before", ""),
                        "operator_after": fragment.get("operator_after", ""),
                    }
                )
            events.append(event)

        return events or [{
            "command": cmd,
            "ttp": None,
            "tactic": "unknown",
            "source": "unclassified",
            "confidence": 0.0,
        }]

    def _split_command_fragments(self, cmd: str) -> List[dict]:
        try:
            from production.classification.classification_pipeline import split_compound_command

            fragments = split_compound_command(cmd)
            return [
                {
                    "text": fragment.text,
                    "index": fragment.index,
                    "count": fragment.count,
                    "operator_before": fragment.operator_before,
                    "operator_after": fragment.operator_after,
                }
                for fragment in fragments
            ]
        except Exception:
            text = (cmd or "").strip()
            return [{
                "text": text,
                "index": 0,
                "count": 1,
                "operator_before": "",
                "operator_after": "",
            }] if text else []


    def _classify_with_source(self, cmd: str) -> tuple:
        """
        Returns:
            (ttp_id, tactic, source, confidence)

        Supported strategies:
            securebert_first
            rules_first
            securebert_only
            rules_only
            notebook_merge
        """
        policy = getattr(self, "classification_policy", {}) or {}
        strategy = policy.get("strategy", "securebert_first")
        min_conf = float(policy.get("bert_min_confidence", 0.55))
        fallback_low = bool(policy.get("keyword_fallback_on_low_confidence", True))
        fallback_error = bool(policy.get("keyword_fallback_on_error", True))

        text = (cmd or "").strip()
        lowered = text.lower()

        if not lowered:
            return None, "unknown", "empty", 0.0

        def finalize(result: tuple) -> tuple:
            ttp, tactic, source, confidence = result
            if ttp:
                tactic = self._resolve_tactic(_main_ttp_id(ttp), tactic)
            return ttp, tactic, source, confidence

        def rule_result() -> tuple:
            if hasattr(self, "_keyword_classify"):
                return finalize(self._keyword_classify(lowered))

            for pattern, ttp_id, tactic in _KEYWORD_TTP_RULES:
                if ttp_id == "__CVE__":
                    continue
                if re.search(pattern, lowered):
                    return ttp_id, self._resolve_tactic(ttp_id, tactic), "rule", 1.0

            return None, "unknown", "unclassified", 0.0

        def bert_result() -> tuple:
            if hasattr(self, "_securebert_classify"):
                return finalize(self._securebert_classify(text))

            if not self.bert_fn:
                return None, "unknown", "securebert_unavailable", 0.0

            try:
                ttp, confidence = self.bert_fn(text)
                if ttp:
                    return ttp, self._resolve_tactic(ttp, "unknown"), "securebert", float(confidence or 0.0)
            except Exception as exc:
                return None, "unknown", f"securebert_error:{type(exc).__name__}", 0.0

            return None, "unknown", "securebert_empty", 0.0

        if strategy == "rules_only":
            return rule_result()

        if strategy == "securebert_only":
            b_ttp, b_tactic, b_source, b_conf = bert_result()
            if b_ttp and b_conf >= min_conf:
                return b_ttp, b_tactic, "securebert", b_conf
            return None, "unknown", b_source or "securebert_low_confidence", b_conf

        if strategy == "rules_first":
            r_ttp, r_tactic, r_source, r_conf = rule_result()
            if r_ttp:
                return r_ttp, r_tactic, r_source, r_conf

            b_ttp, b_tactic, b_source, b_conf = bert_result()
            if b_ttp and b_conf >= min_conf:
                return b_ttp, b_tactic, "securebert", b_conf

            return None, "unknown", b_source or "unclassified", b_conf

        if strategy == "notebook_merge":
            r_ttp, r_tactic, r_source, r_conf = rule_result()
            b_ttp, b_tactic, b_source, b_conf = bert_result()

            bert_ok = bool(b_ttp and b_conf >= min_conf)

            if r_ttp and bert_ok:
                if _main_ttp_id(r_ttp) == _main_ttp_id(b_ttp):
                    return r_ttp, self._resolve_tactic(r_ttp, r_tactic), "both", 1.0

                return r_ttp, self._resolve_tactic(r_ttp, r_tactic), "rule", 1.0

            if r_ttp:
                return r_ttp, self._resolve_tactic(r_ttp, r_tactic), "rule", 1.0

            if bert_ok:
                return b_ttp, self._resolve_tactic(b_ttp, b_tactic), "securebert", b_conf

            if b_ttp and not bert_ok and fallback_low:
                return None, "unknown", "securebert_low_confidence", b_conf

            if b_source and "error" in str(b_source) and fallback_error:
                return None, "unknown", b_source, b_conf

            return None, "unknown", "unclassified", 0.0

        # Default: securebert_first
        b_ttp, b_tactic, b_source, b_conf = bert_result()
        if b_ttp and b_conf >= min_conf:
            return b_ttp, self._resolve_tactic(b_ttp, b_tactic), "securebert", b_conf

        if b_ttp and b_conf < min_conf and not fallback_low:
            return None, "unknown", "securebert_low_confidence", b_conf

        if b_source and "error" in str(b_source) and not fallback_error:
            return None, "unknown", b_source, b_conf

        r_ttp, r_tactic, r_source, r_conf = rule_result()
        if r_ttp:
            return r_ttp, self._resolve_tactic(r_ttp, r_tactic), r_source, r_conf

        return None, "unknown", "unclassified", 0.0


    def _securebert_classify(self, cmd: str) -> tuple:
        """
        Classify a command with injected SecureBERT.

        Returns:
            (ttp, tactic, source, confidence)
        """
        if not self.bert_fn:
            return None, "unknown", "securebert_unavailable", 0.0

        try:
            result = self.bert_fn(cmd)

            ttp = None
            confidence = 0.0

            if isinstance(result, dict):
                ttp = (
                    result.get("ttp")
                    or result.get("ttp_id")
                    or result.get("technique_id")
                    or result.get("label")
                )
                confidence = float(
                    result.get("confidence")
                    or result.get("score")
                    or 0.0
                )
            elif isinstance(result, (tuple, list)) and len(result) >= 2:
                ttp = result[0]
                confidence = float(result[1] or 0.0)
            elif isinstance(result, str):
                ttp = result
                confidence = 1.0

            if not ttp:
                return None, "unknown", "securebert_empty", confidence

            tactic = self._resolve_tactic(ttp, "unknown")
            return ttp, tactic, "securebert", confidence

        except Exception as exc:
            return None, "unknown", f"securebert_error:{type(exc).__name__}", 0.0


    def _keyword_classify(self, text: str) -> tuple:
        """Deterministic shell-command rule classifier."""
        lowered = (text or "").lower()

        for pattern, ttp_id, tactic in _KEYWORD_TTP_RULES:
            if ttp_id == "__CVE__":
                continue
            if re.search(pattern, lowered):
                tactic = self._resolve_tactic(ttp_id, tactic)
                return ttp_id, tactic, "rule", 1.0

        return None, "unknown", "unclassified", 0.0


    def _sigma_match(self, cmd: str) -> List[str]:
        """Return Sigma keyword hits in this command."""
        cmd_lower = cmd.lower()
        return [kw for kw in self._sigma_kws if kw in cmd_lower]

    def _kev_scan(self, text: str) -> List[dict]:
        """Scan text for CVE IDs and check against CISA KEV."""
        if not self.feeds:
            return []
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
        matches = []
        for cve in set(cves):
            details = self.feeds.get_kev_details(cve.upper())
            if details:
                matches.append({"cve_id": cve.upper(), **details})
        return matches

    def _predict_next(self, state: SessionState) -> List[str]:
        """Predict next likely tactics based on current tactic chain."""
        if self.prediction_fn:
            try:
                predicted = [
                    str(item or "").strip()
                    for item in (self.prediction_fn(state) or [])
                    if str(item or "").strip()
                ]
                if predicted:
                    return predicted
            except Exception:
                pass

        if not state.unique_tactics:
            return ["discovery", "execution"]
        last_tactic = state.unique_tactics[-1]
        return _TACTIC_PROGRESSION.get(last_tactic, ["unknown"])

    def _check_thresholds(self, state: SessionState) -> List[AlertEvent]:
        """Check all thresholds. Return new alerts not previously fired."""
        alerts = []
        t = self.thresholds

        def _emit(severity: str, reason: str, kev=None, sigma=None, alert_key: Optional[str] = None) -> AlertEvent:
            key = alert_key or f"{severity}:{reason}"
            if key in state.alerts_fired:
                return None
            state.alerts_fired.append(key)
            return AlertEvent(
                session_id=state.session_id,
                src_ip=state.src_ip,
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity=severity,
                reason=reason,
                ttps_observed=list(state.ttps),
                tactics_observed=list(state.unique_tactics),
                prediction=self._predict_next(state),
                commands_sample=state.commands[-3:],
                kev_matches=kev or state.kev_matches,
                sigma_hits=sigma or [],
            )

        # CRITICAL: CISA KEV CVE found in command
        if state.kev_matches:
            cve_id = state.kev_matches[-1].get('cve_id', '')
            a = _emit("CRITICAL",
                      f"CISA KEV CVE observed: {cve_id}",
                      kev=state.kev_matches,
                      alert_key=f"kev:{cve_id or 'observed'}")
            if a: alerts.append(a)

        # HIGH: dropper pattern (wget/curl + chmod)
        has_download = any(re.search(r'(wget |curl ).+http', c.lower()) for c in state.commands)
        has_exec     = any(re.search(r'chmod \+x|chmod 777', c.lower()) for c in state.commands)
        if has_download and has_exec:
            a = _emit("HIGH", "Dropper pattern: download + chmod+x observed",
                      alert_key="dropper_pattern")
            if a: alerts.append(a)

        # HIGH: many unique TTPs
        if len(state.ttps) >= t.get("ttps_high", 6):
            a = _emit("HIGH", f"{len(state.ttps)} unique TTPs in single session",
                      alert_key="ttps_high")
            if a: alerts.append(a)

        # HIGH: many Sigma hits
        if len(state.sigma_hits) >= t.get("sigma_hits_high", 4):
            a = _emit("HIGH", f"{len(state.sigma_hits)} Sigma HIGH signals matched",
                      sigma=list(set(state.sigma_hits)),
                      alert_key="sigma_hits_high")
            if a: alerts.append(a)

        # MEDIUM: TTP threshold
        if len(state.ttps) >= t.get("ttps_medium", 3):
            a = _emit("MEDIUM", f"{len(state.ttps)} TTPs observed â€” escalating attack",
                      alert_key="ttps_medium")
            if a: alerts.append(a)

        # MEDIUM: Sigma hits
        if len(state.sigma_hits) >= t.get("sigma_hits_medium", 2):
            a = _emit("MEDIUM", f"{len(state.sigma_hits)} Sigma signals matched",
                      sigma=list(set(state.sigma_hits)),
                      alert_key="sigma_hits_medium")
            if a: alerts.append(a)

        # MEDIUM: brute force
        if state.login_attempts >= t.get("login_brute_threshold", 5):
            a = _emit("MEDIUM", f"Brute force: {state.login_attempts} login attempts",
                      alert_key="login_brute_threshold")
            if a: alerts.append(a)

        return alerts

    def _finalize_session(self, state: SessionState) -> List[AlertEvent]:
        """Called on session end. Run campaign correlation, then trigger pipeline."""
        state.is_ended = True
        alerts: List[AlertEvent] = []
        self._apply_session_enrichment(state)

        campaign = self.campaign_tracker.check_and_register(state)
        if campaign["is_returning_actor"] and campaign["confidence"] in ("HIGH", "MEDIUM"):
            reason = (
                f"Returning actor [{campaign['confidence']}] | "
                f"Signals: {', '.join(campaign['match_signals'][:3])} | "
                f"Prev IPs: {', '.join(campaign['linked_ips'][:3])}"
            )
            key = f"RETURNING:{state.session_id}"
            if key not in state.alerts_fired:
                state.alerts_fired.append(key)
                severity = "CRITICAL" if campaign["confidence"] == "HIGH" else "HIGH"
                alert = AlertEvent(
                    session_id=state.session_id,
                    src_ip=state.src_ip,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    severity=severity,
                    reason=reason,
                    ttps_observed=list(state.ttps),
                    tactics_observed=list(state.unique_tactics),
                    prediction=self._predict_next(state),
                    commands_sample=state.commands[-3:],
                )
                alerts.append(alert)

        if self.on_session_end:
            try:
                self.on_session_end(state)
            except Exception as e:
                if self.propagate_session_end_errors:
                    raise
                print(f"  [Monitor] on_session_end failed: {_safe_exception_text(e)}")

        return alerts

    def _load_sigma_keywords(self) -> List[str]:
        """Load Sigma HIGH keywords for real-time matching."""
        if not self.feeds:
            return []
        try:
            kws = self.feeds.get_keywords_for_level("high")
            print(f"  [Monitor] Loaded {len(kws)} Sigma HIGH keywords for real-time matching")
            return kws
        except Exception:
            return []

    @staticmethod
    def _default_alert_handler(alert: AlertEvent) -> None:
        icons = {"CRITICAL": "!! CRITICAL", "HIGH": "!  HIGH", "MEDIUM": "~  MEDIUM", "LOW": "   LOW"}
        print(
            f"\n  {_safe_log_text(icons.get(alert.severity, alert.severity), max_chars=40)} ALERT: "
            f"{_safe_log_text(alert)}"
        )
        if alert.kev_matches:
            for m in alert.kev_matches:
                print(
                    "    KEV: "
                    f"{_safe_log_text(m.get('cve_id', ''), max_chars=80)} â€” "
                    f"{_safe_log_text(m.get('name', ''), max_chars=60)}"
                )
                print(
                    "    Action: "
                    f"{_safe_log_text(m.get('required_action', ''), max_chars=80)}"
                )


def _build_trusted_reporting_views(state: SessionState, mitre_db: Any = None) -> tuple[dict, dict]:
    """Build observed report facts from trusted command classifications only.

    Event-level classifications take precedence over legacy aggregate fields so
    historical low-confidence candidates cannot be promoted during reanalysis.
    """

    classification_events = [
        item for item in getattr(state, "classification_events", []) or []
        if isinstance(item, dict)
    ]
    if classification_events:
        tactic_summary: Dict[str, List[str]] = {}
        ttp_command_map: Dict[str, List[str]] = {}
        for event in classification_events:
            if not is_trusted_classification_event(event):
                continue
            ttp_id = _main_ttp_id(event.get("ttp"))
            if not ttp_id:
                continue
            tactic = str(event.get("tactic") or "").strip()
            tactics = [tactic] if tactic and tactic != "unknown" else []
            if not tactics and mitre_db and hasattr(mitre_db, "get_tactics"):
                tactics = mitre_db.get_tactics(ttp_id) or []
            for resolved_tactic in tactics or ["unknown"]:
                bucket = tactic_summary.setdefault(str(resolved_tactic), [])
                if ttp_id not in bucket:
                    bucket.append(ttp_id)
            command = str(event.get("command") or event.get("input") or "").strip()
            if command:
                commands = ttp_command_map.setdefault(ttp_id, [])
                if command not in commands:
                    commands.append(command)
        return tactic_summary, ttp_command_map

    tactic_summary: Dict[str, List[str]] = {}
    for ttp_id in getattr(state, "ttps", []) or []:
        tactics = []
        if mitre_db and hasattr(mitre_db, "get_tactics"):
            tactics = mitre_db.get_tactics(ttp_id) or []
        for tactic in tactics or ["unknown"]:
            tactic_summary.setdefault(tactic, []).append(ttp_id)
    return tactic_summary, {
        ttp: list(commands)
        for ttp, commands in (getattr(state, "ttp_command_map", {}) or {}).items()
    }


def build_pipeline_trigger(
    coordinator_class,
    feeds=None,
    mitre_db=None,
    config: dict = None,
    enrichment_db: dict = None,
    max_tokens: int = 4000,
    enable_vertex_narrative: bool = False,
    smb_asset_profile_path: str = "",
    smb_action_policy_path: str = "",
):
    """
    Returns an on_session_end callback that runs the full analysis pipeline
    when a Cowrie session ends.

    Usage (Colab)
    -------------
        from production.reporting.reporting_pipeline import ImprovedAsyncSwarmCoordinator
        trigger = build_pipeline_trigger(
            ImprovedAsyncSwarmCoordinator,
            feeds=feeds, mitre_db=mitre_db, config=config,
        )
        monitor = SessionMonitor(feeds=feeds, mitre_db=mitre_db, on_session_end=trigger)
    """
    import asyncio

    def _on_session_end(state: SessionState) -> None:
        safe_session_label = _safe_log_text(state.session_id, max_chars=32)[:8]
        if not state.commands and not state.login_success:
            print(f"  [Pipeline] Session {safe_session_label} skipped (no commands)")
            return

        print(f"\n  [Pipeline] Session {safe_session_label} ended - "
              f"{len(state.commands)} cmds | {len(state.ttps)} TTPs | "
              f"{len(state.kev_matches)} KEV hits")

        try:
            tactic_summary, raw_ttp_command_map = _build_trusted_reporting_views(
                state,
                mitre_db,
            )
            reporting_view = _safe_reporting_mapping(
                {
                    "src_ip": state.src_ip,
                    "session_id": state.session_id,
                    "start_time": state.start_time,
                    "commands": state.commands,
                    "commands_success": state.commands_success,
                    "commands_failed": getattr(state, "commands_failed", []),
                    "classification_events": getattr(
                        state, "classification_events", []
                    ),
                    "raw_events": getattr(state, "raw_events", []),
                    "session_evidence_graph": getattr(
                        state, "session_evidence_graph", {}
                    ),
                    "ttp_sources": getattr(state, "ttp_sources", {}),
                    "tactic_summary": tactic_summary,
                    "ttp_command_map": raw_ttp_command_map,
                    "session_ttp_correlations": getattr(
                        state, "session_ttp_correlations", []
                    ),
                    "session_ttp_correlation_summary": getattr(
                        state, "session_ttp_correlation_summary", {}
                    ),
                    "bpg_list": getattr(state, "bpg_list", []),
                    "login_attempts": state.login_attempts,
                    "login_success": state.login_success,
                    "login_username": getattr(state, "login_username", ""),
                    "login_password": getattr(
                        state, "login_password_redacted", ""
                    ),
                    "credential_metadata": credential_metadata_for_provenance(
                        getattr(state, "credential_metadata", {})
                    ),
                    "enrichment_status": getattr(state, "enrichment_status", {}),
                    "classification_policy": getattr(
                        state, "classification_policy", {}
                    ),
                    "ioc_summary": getattr(state, "ioc_summary", {}),
                    "process_tree_status": getattr(
                        state, "process_tree_status", {}
                    ),
                    "src_port": getattr(state, "src_port", 0),
                    "dst_ip": getattr(state, "dst_ip", ""),
                    "dst_port": getattr(state, "dst_port", 22),
                    "sensor": getattr(state, "sensor", ""),
                    "protocol": getattr(state, "protocol", "ssh"),
                    "duration": getattr(state, "duration", 0.0),
                    "client_version": getattr(state, "client_version", ""),
                    "hassh": getattr(state, "hassh", None),
                    "ja3": getattr(state, "ja3", None),
                    "asn": getattr(state, "asn", None),
                    "geo": getattr(state, "geo", None),
                    "isp": getattr(state, "isp", None),
                    "kev_matches": getattr(state, "kev_matches", []),
                    "sigma_hits": getattr(state, "sigma_hits", []),
                },
                "session reporting view",
            )
        except Exception as exc:
            safe_error = _safe_exception_text(exc)
            print(f"  [Pipeline] Reporting view failed: {safe_error}")
            state.pipeline_error = safe_error
            return None

        # All fields match what enrichment_mapping_1b / improved_3c expect.
        class _IP:
            def __init__(self, ip, view):
                self.value       = ip
                self.risk_score  = 0

                self.raw_otx_pulse     = None
                self.campaign_hint     = None
                self.otx_tags          = []

                # HASSH is captured live from cowrie.client.kex
                # ja3 would come from Zeek/Suricata enrichment (None until then)
                self.hassh_label       = view.get('hassh')
                self.ja3_label         = view.get('ja3')
                self.hassh             = view.get('hassh')
                self.ja3               = view.get('ja3')
                self.ssh_client        = view.get('client_version', '')

                self.asn               = view.get('asn')
                self.geo               = view.get('geo')
                self.isp               = view.get('isp')

                self.abuseipdb_categories = []
                self.abuse_tags           = []
                self.total_reports        = 0

                self.infrastructure_tags  = []
                self.is_tor_exit          = False
                self.is_vpn               = False
                self.host_type            = None
                self.open_ports           = []
                self.running_services     = []
                self.shodan_tags          = []   # Shodan-specific tags (separate from infra)

                self.vt_detection_ratio   = None
                self.vt_malware_family    = None
                self.vt_hit               = False

                self.first_seen           = None
                self.last_seen            = None

                self.kev_matches          = view.get('kev_matches', [])
                self.sigma_hits           = view.get('sigma_hits', [])

        class _Sess:
            """Bridge from SessionState to pipeline session format."""
            def __init__(self, view):
                self.src_ip             = view.get('src_ip', '')
                self.session_id         = view.get('session_id', '')
                self.start_time         = view.get('start_time', '')
                self.commands           = view.get('commands', [])
                self.commands_success   = view.get('commands_success', [])
                self.commands_failed    = view.get('commands_failed', [])
                self.classification_events = view.get('classification_events', [])
                self.raw_events          = view.get('raw_events', [])
                self.session_evidence_graph = view.get('session_evidence_graph', {})
                self.ttp_sources        = view.get('ttp_sources', {})
                self.login_attempts     = view.get('login_attempts', 0)
                self.login_success      = view.get('login_success', False)
                self.login_username     = view.get('login_username', '')
                self.login_password     = view.get('login_password', '')
                self.credential_metadata = view.get('credential_metadata', {})
                self.enrichment_status  = view.get('enrichment_status', {})
                # Real Cowrie fields
                self.src_port           = view.get('src_port', 0)
                self.dst_ip             = view.get('dst_ip', '')
                self.dst_port           = view.get('dst_port', 22)
                self.sensor             = view.get('sensor', '')
                self.protocol           = view.get('protocol', 'ssh')
                self.duration           = view.get('duration', 0.0)
                self.client_version     = view.get('client_version', '')

        class _Bundle:
            def __init__(self, view):
                self.ips     = [_IP(view.get('src_ip', ''), view)]
                self.urls    = []
                self.hashes  = []
                self.domains = []
                self.ports   = []

                class _SimpleIOC:
                    def __init__(self, payload):
                        self.type = payload.get("type", "")
                        self.value = payload.get("value", "")
                        self.confidence = payload.get("confidence", "medium")
                        self.first_seen = payload.get("first_seen", "")
                        self.honeypot = payload.get("honeypot", False)
                        self.note = payload.get("note", "")
                        self.risk_score = 0

                ioc_summary = view.get("ioc_summary", {}) or {}
                existing_ips = {view.get('src_ip', '')}
                for item in ioc_summary.get("ips", []):
                    if item.get("value") and item.get("value") not in existing_ips:
                        self.ips.append(_SimpleIOC(item))
                        existing_ips.add(item.get("value"))
                self.urls = [_SimpleIOC(item) for item in ioc_summary.get("urls", [])]
                self.hashes = [_SimpleIOC(item) for item in ioc_summary.get("hashes", [])]
                self.domains = [_SimpleIOC(item) for item in ioc_summary.get("domains", [])]
                self.ports = [_SimpleIOC(item) for item in ioc_summary.get("ports", [])]

        ioc_bundle   = _Bundle(reporting_view)
        sessions_obj = [_Sess(reporting_view)]

        # enrichment_db contains pre-fetched API data keyed by IP.
        # If enrichment_db is None (no pre-fetched data), the _IP object above
        # already has safe defaults â€” pipeline still runs with Cowrie-only data.
        try:
            from production.enrichment.enrichment_mapping import apply_enrichment_to_ip
            record = enrichment_db.get(state.src_ip) if enrichment_db else None
            apply_enrichment_to_ip(ioc_bundle.ips[0], record)
            if record:
                for attr in ("asn", "geo", "isp"):
                    if hasattr(ioc_bundle.ips[0], attr):
                        setattr(state, attr, getattr(ioc_bundle.ips[0], attr))
                state.enrichment_status = {
                    "status": "applied",
                    "source": "pipeline_trigger.enrichment_db",
                    "fields": sorted(record.keys()),
                }
                print(
                    "  [Pipeline] Enrichment applied for "
                    f"{_safe_log_text(state.src_ip, max_chars=80)}"
                )
            else:
                print(
                    "  [Pipeline] No enrichment record for "
                    f"{_safe_log_text(state.src_ip, max_chars=80)} â€” "
                    "using Cowrie-only data"
                )
        except Exception as e:
            print(f"  [Pipeline] Enrichment skipped: {_safe_exception_text(e)}")

        try:
            reporting_view["enrichment_status"] = _safe_reporting_mapping(
                getattr(state, "enrichment_status", {}),
                "enrichment status",
            )
            sessions_obj[0].enrichment_status = reporting_view[
                "enrichment_status"
            ]
            for collection_name in ("ips", "urls", "hashes", "domains", "ports"):
                for ioc in getattr(ioc_bundle, collection_name, []) or []:
                    safe_ioc = _safe_reporting_mapping(vars(ioc), "enriched IOC")
                    for field_name, field_value in safe_ioc.items():
                        setattr(ioc, field_name, field_value)
        except Exception as exc:
            safe_error = _safe_exception_text(exc)
            print(f"  [Pipeline] Enriched IOC redaction failed: {safe_error}")
            state.pipeline_error = safe_error
            return None

        try:
            # base_url='' and model='' â†’ VertexAI client reads from COLAB_CONFIG
            coord = coordinator_class(
                base_url='',
                model='',
                max_tokens=max_tokens,
            )
            coord.enable_vertex_narrative = bool(enable_vertex_narrative)
            coord.recommendation_asset_profile_path = str(smb_asset_profile_path or "")
            coord.recommendation_action_policy_path = str(smb_action_policy_path or "")

            # Reporting inputs are the centrally redacted projection built
            # above; the raw SessionState remains available to storage.
            tactic_summary = reporting_view.get("tactic_summary", {})
            ttp_command_map = reporting_view.get("ttp_command_map", {})
            session_correlations = reporting_view.get(
                "session_ttp_correlations", []
            )
            raw_events = reporting_view.get("raw_events", [])
            bpg_list = reporting_view.get("bpg_list", [])
            data_provenance = {
                "session": {
                    "session_id": reporting_view.get("session_id", ""),
                    "src_ip": reporting_view.get("src_ip", ""),
                    "raw_event_count": len(raw_events),
                    **command_observation_provenance(
                        reporting_view.get("commands", []),
                        reporting_view.get("commands_success", []),
                        reporting_view.get("commands_failed", []),
                    ),
                },
                "classification": {
                    "policy": reporting_view.get("classification_policy", {}),
                    "event_count": len(
                        reporting_view.get("classification_events", [])
                    ),
                    "ttp_sources": reporting_view.get("ttp_sources", {}),
                },
                "session_ttp_correlation": reporting_view.get(
                    "session_ttp_correlation_summary", {}
                ),
                "credential_metadata": reporting_view.get(
                    "credential_metadata", {}
                ),
                "enrichment": reporting_view.get("enrichment_status", {}),
                "ioc_extraction": reporting_view.get("ioc_summary", {}),
                "behavior_graph": {
                    "status": reporting_view.get("process_tree_status", {}),
                    "bpg_count": len(bpg_list),
                },
            }
            try:
                from production.enrichment.threat_feed_loader import check_feeds_status
                data_provenance["feeds"] = _safe_reporting_mapping(
                    check_feeds_status(),
                    "feed status",
                )
            except Exception as e:
                data_provenance["feeds"] = {
                    "status": "unavailable",
                    "error": _safe_exception_text(e),
                }

            try:
                asyncio.get_running_loop()
                running_loop = True
            except RuntimeError:
                running_loop = False

            if running_loop:
                # Colab/Jupyter: avoid nested event loop
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(
                        asyncio.run,
                        coord.analyze(
                            ioc_bundle, tactic_summary, sessions_obj,
                            bpg_list=bpg_list,
                            ttp_command_map=ttp_command_map,
                            raw_events=raw_events,
                            session_correlations=session_correlations,
                        )
                    ).result(timeout=300)
            else:
                result = asyncio.run(
                    coord.analyze(
                        ioc_bundle, tactic_summary, sessions_obj,
                        bpg_list=bpg_list,
                        ttp_command_map=ttp_command_map,
                        raw_events=raw_events,
                        session_correlations=session_correlations,
                    )
                )

            # result["confidence"] is a long string e.g. "High â€” 7 confirmed techniques..."
            # analytical_evidence_strength is heuristic, not calibrated probability.
            def _extract_level(res: dict) -> str:
                raw = res.get("confidence", "") or ""
                if not raw:
                    hypothesis = res.get("threat_hypothesis", {}) or {}
                    ac = (
                        hypothesis.get("analytical_evidence_strength")
                        or hypothesis.get("analytical_confidence")
                        or res.get("analytical_evidence_strength")
                        or res.get("analytical_confidence", {})
                    )
                    raw = (ac.get("level", "") or "") if isinstance(ac, dict) else ""
                # Scan for severity keyword in the raw string
                for lvl in ("critical", "high", "medium", "low"):
                    if lvl in raw.lower():
                        return lvl.capitalize()
                return raw[:20].strip() if raw else "unknown"

            if not isinstance(result, dict):
                raise RuntimeError("Coordinator returned no report")
            result.setdefault("data_provenance", {}).update(data_provenance)
            result.setdefault(
                "ioc_summary",
                reporting_view.get("ioc_summary", {}),
            )
            result.setdefault("bpg_list", bpg_list)
            result = _safe_reporting_mapping(result, "report")
            level = _extract_level(result)
            print(
                "  [Pipeline] Done - analytical_evidence_strength="
                f"{_safe_log_text(level, max_chars=40)}"
            )
            return result
        except Exception as e:
            safe_error = _safe_exception_text(e)
            print(f"  [Pipeline] Failed: {safe_error}")
            state.pipeline_error = safe_error
            return None

    return _on_session_end


class CowrieLogReplayer:
    """
    Replays a cowrie.json logfile as a simulated real-time stream.
    Used for Colab testing without a live Pi 5 connection.

    The replayer preserves relative timing between events (scaled by speed).
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._events: List[dict] = []
        self._load()

    def _load(self) -> None:
        try:
            with open(self.log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self._events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            print(
                f"  [Replayer] Loaded {len(self._events)} events from "
                f"{_safe_log_text(self.log_path)}"
            )
        except FileNotFoundError:
            print(f"  [Replayer] File not found: {_safe_log_text(self.log_path)}")

    def stream(self, delay: float = 0.05, realtime_scale: float = 0.0):
        """
        Yield events one at a time with optional delay.

        Parameters
        ----------
        delay          : Fixed delay between events (seconds). Used when
                         realtime_scale = 0 (default).
        realtime_scale : If > 0, scale actual event timestamps. E.g. 0.01
                         means 1% of real time (100x speedup).
                         Overrides `delay` when set.
        """
        prev_ts = None
        for event in self._events:
            if realtime_scale > 0 and prev_ts:
                try:
                    curr_ts = datetime.fromisoformat(event.get("timestamp", ""))
                    gap = (curr_ts - prev_ts).total_seconds() * realtime_scale
                    if 0 < gap < 30:
                        time.sleep(gap)
                except Exception:
                    time.sleep(delay)
            else:
                time.sleep(delay)

            try:
                prev_ts = datetime.fromisoformat(event.get("timestamp", ""))
            except Exception:
                pass

            yield event

    def get_sessions(self) -> Dict[str, List[dict]]:
        """Group events by session ID."""
        sessions: Dict[str, List[dict]] = {}
        for e in self._events:
            sid = e.get("session", "unknown")
            sessions.setdefault(sid, []).append(e)
        return sessions


# Quick self-test (python session_monitor.py)
if __name__ == "__main__":
    import sys, os

    log_file = sys.argv[1] if len(sys.argv) > 1 else "demo_cowrie_credential_stuffing.json"

    # Try to load feeds
    feeds = None
    mitre_db = None
    try:
        from production.enrichment.threat_feed_loader import load_threat_feeds
        feeds = load_threat_feeds()
        print(f"  Feeds loaded: {_safe_log_text(feeds)}")
    except Exception as e:
        print(
            f"  Feeds unavailable ({_safe_exception_text(e)}) â€” "
            "running without KEV/Sigma"
        )

    try:
        from production.enrichment.mitre_attack_loader import load_mitre_attack_db
        mitre_db = load_mitre_attack_db()
        print(f"  MITRE DB: {_safe_log_text(mitre_db)}")
    except Exception as e:
        print(f"  MITRE DB unavailable ({_safe_exception_text(e)})")

    all_alerts: List[AlertEvent] = []

    def on_session_done(state: SessionState):
        print(f"\n  [Pipeline] Session {_safe_log_text(state.session_id, max_chars=32)[:8]} ended â€” "
              f"{len(state.commands)} commands, {len(state.ttps)} TTPs, "
              f"{len(state.kev_matches)} KEV matches")
        print(f"  [Pipeline] Would now trigger: SecureBERT + AI full analysis")

    monitor = SessionMonitor(
        feeds=feeds,
        mitre_db=mitre_db,
        on_session_end=on_session_done,
    )

    replayer = CowrieLogReplayer(log_file)

    print(f"\n=== Starting real-time replay of {_safe_log_text(log_file)} ===\n")
    for event in replayer.stream(delay=0.02):
        monitor.on_event(event)

    stats = monitor.get_stats()
    print(f"\n=== Replay complete ===")
    print(f"  Events processed : {stats['events']}")
    print(f"  Sessions seen    : {stats['sessions']}")
    print(f"  Alerts fired     : {stats['alerts']}")
