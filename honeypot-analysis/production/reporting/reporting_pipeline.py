"""
Improved Section 3C: Threat Hypothesis Generation (Honeypot Edition) â€” v2
==========================================================================

Changes from v1:

  [FIX 1]  HIGH_CONF_THRESHOLD reverted to 0.55 â€” 0.75 caused mass abstention
           and routed everything to the inaccurate session-level SecureBERT fallback.
  [FIX 2]  Ollama/Groq API path replaced with Vertex AI Gemini.
           Compatibility aliases are retained so external notebook code that
           imports OllamaClient or GroqClient continues to work. All config via
           environment variables:
             VERTEX_PROJECT_ID / GOOGLE_CLOUD_PROJECT â€” required
             VERTEX_LOCATION   â€” default: us-central1
             VERTEX_MODEL      â€” default: gemini-1.5-pro
             VERTEX_ACCESS_TOKEN â€” optional; otherwise ADC/google-auth is used
  [FIX 3]  Campaign name synthesis â€” AI synthesizes name from OTX evidence.
           Previously: raw OTX pulse name was copied directly as campaign_name.
           Problem: pulse names like "SSH Brute Force IPs March 2024" produced
           low-quality reports. A crowdsourced pulse name is evidence, not output.
           Fix: _synthesize_campaign_name() passes raw_otx_pulse, otx_tags,
           behavioral signals, and fingerprints to Claude. AI synthesizes a
           professional campaign name. Falls back to deterministic name if AI fails.
           The synthesized name is written to ip.campaign_hint (new field in 1B)
           so it persists for display. raw_otx_pulse is preserved as evidence.
  [FIX 4]  Recommendations generated entirely from parsed command artifacts â€”
           no TTPâ†’text lookup tables anywhere in this file.
  [FIX 5]  Threat actor profile display fixed â€” rendered as structured text,
           not a raw Python dict.
  [FIX 5b] Enrichment fields now correctly mapped onto IP objects (1B v2).
           New fields consumed: raw_otx_pulse, infrastructure_tags, is_tor_exit,
           is_vpn, host_type, vt_hit, vt_malware_family.
  [FIX 6]  Honeypot-specific fields â€” all retained and extended:
           - Honeypot awareness assessment
           - Campaign correlation (uses raw_otx_pulse not otx_pulse)
           - Attacker playbook extraction
           - Falsification conditions and analytical confidence
           - IOC table with file hashes
           - Attack timeline
           - Strategic controls (config-keyed by OTX tags)
           - Campaign intelligence
  [FIX 7]  Sophistication scorer adds Shodan infrastructure signal.
           Previously: only JA3/HASSH fingerprints and behavioral patterns scored.
           Now: _infrastructure_sophistication_signal() (from production.enrichment.enrichment_mapping)
           contributes an additive delta. Tor exit / residential proxy +2;
           VPN +1; bulletproof hosting +1; scanner/CDN -1; shared hosting -2.
           This is always additive â€” never the primary driver.
  [FIX 8]  AbuseIPDB risk_score guard made explicit in code.
           risk_score is intentionally NOT used in the sophistication scorer.
           It appears only in _build_analytical_confidence() as one corroborating
           signal with a documented cap. A fresh APT VPS scores 0. A Mirai bot
           scores 100. These are inverted from their true sophistication. Code
           comment enforces this contract for future maintainers.
  [FIX 9]  VirusTotal intelligence surfaced opportunistically.
           When vt_hit=True on an IP object, vt_malware_family is used in:
           - _build_campaign_intelligence(): identifies malware family context.
           - _generate_dynamic_recommendations(): adds family-specific removal note.
           vt_hit=False is never interpreted as "clean" â€” code comments enforce this.
  [FIX 10] Infrastructure context in _build_discovery_evidence() and
           _predict_next_action() â€” Tor/VPN/residential proxy presence noted
           in evidence and prediction narratives.

Hardcoding policy (strictly enforced):
  - NO TTP ID â†’ recommendation text mappings.
  - NO fixed strings for specific attacker behaviour.
  - Logic and structure live in code.
  - Content comes from: observed commands, enrichment data, config files, raw events.
"""

import asyncio
import copy
import re
import json
import os
import sys
import threading
from collections.abc import Callable
from typing import Dict, Any, List, Optional, Tuple
from abc import ABC, abstractmethod
from enum import Enum
from collections import Counter

from production.reporting.threat_hypothesis import (
    apply_validated_vertex_presentation,
    attach_model_prediction,
    build_observed_behavior,
    build_v2_report,
)
from production.utils.sensitive_data import (
    redact_exception_for_log,
    redact_for_artifact,
    redact_for_log,
)


def _safe_log_text(value: Any, *, max_chars: int = 1_000) -> str:
    try:
        redacted = redact_for_log(value, max_string_chars=max_chars)
    except Exception:
        return "[REDACTION FAILED]"
    return str(redacted)


def _safe_exception_text(exc: BaseException) -> str:
    return redact_exception_for_log(exc)


def _exception_http_status(exc: BaseException) -> Optional[int]:
    """Read a structured HTTP status without rendering exception text."""

    try:
        response = getattr(exc, "response", None)
    except Exception:
        response = None
    owners = (exc, response)
    for owner in owners:
        if owner is None:
            continue
        for attribute in ("status_code", "status", "code"):
            try:
                status = int(getattr(owner, attribute, None))
            except Exception:
                continue
            if 100 <= status <= 599:
                return status
    return None


def _exception_retry_after(exc: BaseException, *, maximum: int = 120) -> Optional[int]:
    """Return a bounded structured Retry-After delay, if one is available."""

    try:
        headers = getattr(getattr(exc, "response", None), "headers", None)
        raw_value = headers.get("retry-after") if hasattr(headers, "get") else None
        delay = int(float(raw_value))
    except Exception:
        return None
    return min(max(delay, 0), maximum)


def _safe_reporting_text(value: Any, label: str) -> str:
    try:
        redacted = redact_for_artifact(value)
    except Exception:
        raise ValueError(f"{label} redaction failed") from None
    if not isinstance(redacted, str):
        raise TypeError(f"{label} must redact to text")
    return redacted


def _safe_reporting_mapping(value: Any, label: str) -> Dict[str, Any]:
    try:
        redacted = redact_for_artifact(value)
    except Exception:
        raise ValueError(f"{label} redaction failed") from None
    if not isinstance(redacted, dict):
        raise TypeError(f"{label} must redact to an object")
    return redacted

try:
    import requests as _requests_lib
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    from production.enrichment.enrichment_mapping import (
        _infrastructure_sophistication_signal,
        _describe_infrastructure,
    )
    _ENRICHMENT_HELPERS_AVAILABLE = True
except ImportError:
    _ENRICHMENT_HELPERS_AVAILABLE = False

    def _infrastructure_sophistication_signal(ip_obj: Any) -> tuple:
        """Fallback when production.enrichment.enrichment_mapping is not importable."""
        return 0, ""

    def _describe_infrastructure(ip_obj: Any) -> str:
        return "No infrastructure data"



COLAB_CONFIG = {
    "project_id": "",                              # Set VERTEX_PROJECT_ID in your environment.

    "model": "gemini-2.5-pro",          # GA â€” à¹„à¸¡à¹ˆà¸•à¹‰à¸­à¸‡ enable à¹ƒà¸™ Model Garden

    "location": "us-central1",    # Vertex AI à¹„à¸¡à¹ˆà¸¡à¸µ global endpoint â€” à¸•à¹‰à¸­à¸‡à¹ƒà¸Šà¹‰ region à¹€à¸ªà¸¡à¸­

    "auto_colab_auth": True,
}


# PATTERN 1: CENTRALIZED PROMPTS & TOKEN BUDGET

class CTIPrompts:
    """Central repository for AI prompts."""

    SYSTEM_PROMPT = (
        'You are a Lead Cyber Threat Intelligence (CTI) Analyst specialising in '
        'honeypot intelligence. The environment is a DECEPTION SYSTEM â€” every '
        'connection is hostile. Your task is to produce a THREAT HYPOTHESIS, not '
        'an incident report. The hypothesis must be forward-looking and falsifiable.\n\n'
        'REQUIRED JSON SCHEMA:\n'
        '{\n'
        '  "campaign_name": "Synthesized professional name â€” NOT a copy of the raw OTX pulse name. '
        'Derive from: OTX tags + behavioral signals + fingerprints + tactic pattern. '
        'Example: \'Operation Cloud Harvest â€” Credential-Focused Linux Intrusion\'",\n'
        '  "executive_summary": "Concise narrative grounded in observed indicators",\n'
        '  "primary_objective": "Attacker primary goal â€” highest-impact observed activity",\n'
        '  "target_platform": "Derived ONLY from observed commands/paths",\n'
        '  "threat_actor_profile": {\n'
        '    "type": "Organised group / Lone actor / Botnet / etc",\n'
        '    "sophistication": "Low / Medium / High / Very High",\n'
        '    "description": "Profile based on JA3/HASSH fingerprints, Shodan infrastructure '
        'tags (tor, vpn, bulletproof_hosting, residential), and behavioral patterns"\n'
        '  },\n'
        '  "honeypot_intelligence": {\n'
        '    "attacker_awareness": "aware / unaware / uncertain + evidence",\n'
        '    "campaign_correlation": "Single campaign / Independent actors + evidence",\n'
        '    "attacker_playbook": ["What the attacker was hunting for on real targets"],\n'
        '    "credential_targets": ["Specific credential types observed being sought"]\n'
        '  },\n'
        '  "threat_hypothesis": {\n'
        '    "stated_intent": "What attacker is trying to achieve",\n'
        '    "predicted_next_action": "Possible next observable behaviour, stated as a hypothesis and grounded in session evidence",\n'
        '    "falsification_conditions": ["Evidence that would disprove this assessment"],\n'
        '    "analytical_confidence": {\n'
        '      "level": "Low / Medium / High",\n'
        '      "reason": "Heuristic analytical evidence strength grounded in specific gaps or strengths; not a calibrated probability"\n'
        '    }\n'
        '  },\n'
        '  "kill_chain_analysis": [\n'
        '    {\n'
        '      "tactic": "MITRE Tactic Category",\n'
        '      "technique_id": "TXXXX",\n'
        '      "technique_name": "Name of technique",\n'
        '      "evidence": "Exact command or artifact",\n'
        '      "attacker_intent": "What attacker was trying to achieve"\n'
        '    }\n'
        '  ],\n'
        '  "recommended_mitigations": ["Specific actionable items for REAL systems"],\n'
        '  "strategic_recommendations": ["Policy-level controls to prevent recurrence"],\n'
        '  "campaign_intelligence": "What real organisations should check/defend based on this playbook"\n'
        '}\n\n'
        'CRITICAL RULES:\n'
        '1. This is a HONEYPOT â€” assess whether attacker knew this.\n'
        '2. Every technique must be grounded in exact observed evidence.\n'
        '3. Falsification conditions must be specific and observable.\n'
        '4. Mitigations reference actual artefacts (specific IPs, file paths, account names).\n'
        '5. Output JSON inside <json_output> tags only.\n'
        '6. Do NOT hallucinate evidence.\n'
        '7. campaign_name must be AI-synthesized â€” NEVER copy raw_otx_pulse verbatim.\n'
        '8. If infrastructure_tags include tor/vpn/residential, mention origin masking.\n'
        '9. AbuseIPDB risk_score is a crowd complaint counter â€” do NOT use it to assess '
        'sophistication. A fresh APT VPS will score 0. Use JA3/HASSH/infrastructure instead.\n'
        '10. If vt_malware_family is present, reference the specific malware family name.\n'
        '11. Campaign Correlation: If IPs have DIFFERENT OTX pulses or ASNs, state EXPLICITLY that these are UNRELATED opportunistic attacks targeting the same honeypot. DO NOT group them into a single coordinated campaign.\n'
        '12. Sophistication: Justify using ONLY the exact tools/fingerprints provided. Do NOT hallucinate capabilities like "Metasploit" or "Custom Tooling" unless explicitly present in the evidence.\n'
        '13. Falsification Conditions: Must follow scientific methodology (e.g. finding the exact opposite evidence, or payload failed to execute). Do NOT use generic "connection blocked by firewall".\n'
        '14. Kill Chain: The "evidence" column must contain ONLY the raw malicious command or artefact. Do NOT put recommendations or mitigations in the "evidence" column.\n'
    )

    # ANALYST_SYSTEM_PROMPT â€” used in Phase 3 refactor (AI-as-Analyst mode).
    # The AI receives a structured evidence brief and answers specific
    # analytical questions. It does NOT rewrite the full report.
    ANALYST_SYSTEM_PROMPT = (
        'You are a presentation editor for a Cowrie SSH honeypot report. The input '
        'contains validated deterministic claims. You may improve wording only. You '
        'must not add objectives, actor attribution, campaign claims, recommendations, '
        'falsification conditions, predictions, confidence, or facts.\n\n'
        'Output JSON inside <json_output> tags with exactly these keys:\n'
        '{\n'
        '  "presentation_summary": "A concise summary of only the validated claims",\n'
        '  "grounded_claim_ids": ["Every canonical claim_id used in the summary"]\n'
        '}\n\n'
        'Do not introduce ATT&CK identifiers absent from the input. Do not claim '
        'confirmed intent, compromise, execution, persistence, exfiltration, or '
        'attribution. Do not propose operator actions. If there are no analytical '
        'claims, summarize only the observed behavior and return an empty claim-ID list.'
    )


    # ANALYTICAL_FIELD_NAMES â€” single source of truth for all fields the AI
    # is responsible for in analyst mode. JSONValidator.ANALYTICAL_FIELDS
    # references this so that adding a new analytical question only requires
    # updating this one constant.
    ANALYTICAL_FIELD_NAMES: frozenset = frozenset({
        'presentation_summary',
        'grounded_claim_ids',
    })


class TokenBudget:
    """Token tracking for model inference."""

    def __init__(self, max_tokens: int = 4000, per_turn: int = 500):
        self.max_tokens = max_tokens
        self.per_turn = per_turn
        self.used = 0
        self.turns = 0

    def estimate(self, text: str) -> int:
        return len(text) // 4

    def has_budget(self) -> bool:
        return self.used < self.max_tokens

    def consume(self, text: str, reason: str = ""):
        est = self.estimate(text)
        if self.used + est > self.max_tokens:
            raise RuntimeError(
                f"Token budget exceeded! Used: {self.used}, "
                f"Estimated: {est}, Max: {self.max_tokens}"
            )
        self.used += est
        self.turns += 1
        print(f"  Turn {self.turns}: {est} tokens ({_safe_log_text(reason)}) | "
              f"Total: {self.used}/{self.max_tokens}")

    def consume_safe(self, text: str, reason: str = "") -> None:
        """Like consume() but logs a warning instead of raising on overflow.
        Used for response tokens â€” we already received the data, raising would waste it."""
        est = self.estimate(text)
        self.used += est
        self.turns += 1
        if self.used > self.max_tokens:
            print(f"  [Budget] WARN: Budget exceeded â€” "
                  f"{self.used}/{self.max_tokens} tokens ({_safe_log_text(reason)})")
        else:
            print(f"  Turn {self.turns}: {est} tokens ({_safe_log_text(reason)}) | "
                  f"Total: {self.used}/{self.max_tokens}")

    def remaining(self) -> int:
        return max(0, self.max_tokens - self.used)


# PATTERN 2: STRUCTURED THINKING PHASES

class AnalysisPhase(Enum):
    DISCOVERY = "discovery"
    ANALYSIS = "analysis"
    SYNTHESIS = "synthesis"


def build_structured_prompt(phase: AnalysisPhase, detected_ttps: List[str] = None) -> str:
    """Build prompt with EXPLICIT GROUNDING LOCK."""
    detected_ttps_str = ', '.join(detected_ttps) if detected_ttps else 'NONE'

    system_msg = (
        'You are a Lead CTI Analyst specialising in honeypot intelligence.\n\n'
        'ABSOLUTE GROUNDING RULES:\n'
        f'1. FORBIDDEN from inventing any technique NOT in: [{detected_ttps_str}]\n'
        '2. For EVERY technique, cite the EXACT command/evidence.\n'
        '3. If proof is absent, DO NOT list the technique.\n'
        '4. This is a HONEYPOT â€” assess attacker awareness explicitly.\n'
        '5. Output valid JSON ONLY â€” no extra text.\n'
    )

    if phase == AnalysisPhase.SYNTHESIS:
        thinking = (
            f'<analysis>\n'
            f'Locked techniques: {detected_ttps_str}\n'
            'Step 1: Ground each technique in actual observed evidence.\n'
            'Step 2: Assess honeypot awareness from command patterns.\n'
            'Step 3: Build falsification conditions from specific artefacts.\n'
            'Step 4: Predict next action from last observed technique chain.\n'
            'Step 5: Final validation â€” zero ungrounded techniques.\n'
            '</analysis>\n\n'
        )
    else:
        thinking = (
            f'<analysis>\n'
            f'Available evidence: {detected_ttps_str}\n'
            'Step 1: Ground each technique in exact commands.\n'
            'Step 2: Identify honeypot-specific attacker signals.\n'
            '</analysis>\n\n'
        )

    return f"{system_msg}\n{thinking}"


# PATTERN 3: JSON VALIDATION

class JSONValidator:
    """Schema validation and recovery for AI-generated JSON."""

    REQUIRED_FIELDS = {
        'campaign_name', 'executive_summary', 'primary_objective',
        'target_platform', 'threat_actor_profile', 'kill_chain_analysis',
        'recommended_mitigations', 'threat_hypothesis', 'honeypot_intelligence'
    }

    @staticmethod
    def prune_ungrounded_ttps(data: dict, detected_ttps: List[str]) -> dict:
        if not detected_ttps or 'kill_chain_analysis' not in data:
            return data
        detected_set = set(detected_ttps)
        pruned_chain = []
        for phase in data.get('kill_chain_analysis', []):
            ttp_id = phase.get('technique_id', '')
            if ttp_id in detected_set:
                pruned_chain.append(phase)
            else:
                print(
                    "    PRUNING: Removing ungrounded TTP "
                    f"{_safe_log_text(ttp_id)}"
                )
        data['kill_chain_analysis'] = pruned_chain
        return data

    @staticmethod
    def validate(data: dict, detected_ttps: List[str] = None,
                 tactic_summary: Dict[str, List[str]] = None) -> Tuple[bool, str]:
        if not isinstance(data, dict):
            return False, "Root must be dict"
        missing = JSONValidator.REQUIRED_FIELDS - set(data.keys())
        if missing:
            return False, f"Missing fields: {missing}"
        if not isinstance(data.get('kill_chain_analysis'), list):
            return False, "kill_chain_analysis must be list"
        if not isinstance(data.get('recommended_mitigations'), list):
            return False, "recommended_mitigations must be list"
        if detected_ttps:
            output_ttps = {
                phase.get('technique_id', '')
                for phase in data.get('kill_chain_analysis', [])
            }
            ungrounded = output_ttps - set(detected_ttps)
            if ungrounded:
                data = JSONValidator.prune_ungrounded_ttps(data, detected_ttps)
                if not data.get('kill_chain_analysis'):
                    return False, f"All techniques ungrounded. Evidence has: {set(detected_ttps)}"
        return True, "OK"

    @staticmethod
    def enforce_grounding_strict(data: dict, detected_ttps: List[str]) -> Tuple[bool, str]:
        detected_set = set(detected_ttps or [])
        if not detected_set:
            return False, "No detected TTPs"
        if not isinstance(data, dict):
            return False, "AI output is not a dict"
        if not data.get('kill_chain_analysis'):
            return False, "Missing kill_chain_analysis"
        found_ttps = set()
        for i, phase in enumerate(data.get('kill_chain_analysis', [])):
            if not isinstance(phase, dict):
                return False, f"Phase {i} is not a dict"
            ttp_id = (phase.get('technique_id', '') or
                      phase.get('ttp', '') or
                      phase.get('technique', '') or
                      phase.get('id', ''))
            if not ttp_id:
                return False, f"Phase {i}: Missing technique_id"
            found_ttps.add(ttp_id)
        ungrounded = found_ttps - detected_set
        if ungrounded:
            return False, f"HARD VIOLATION: {len(ungrounded)} ungrounded TTP(s): {ungrounded}"
        for phase in data.get('kill_chain_analysis', []):
            ttp_id = (phase.get('technique_id', '') or phase.get('ttp', '') or
                      phase.get('technique', '') or phase.get('id', ''))
            if ttp_id:
                phase['technique_id'] = ttp_id
                for alt in ['ttp', 'technique', 'id']:
                    phase.pop(alt, None)
        return True, f"OK ({len(found_ttps)} techniques verified)"

    @staticmethod
    def repair(raw_text: str) -> Tuple[bool, dict]:
        def _programmatic_repair(text: str) -> dict:
            for _ in range(15):
                try:
                    return json.loads(text)
                except json.JSONDecodeError as e:
                    if "Expecting ',' delimiter" in e.msg:
                        text = text[:e.pos] + ',' + text[e.pos:]
                    else:
                        raise
            return json.loads(text)

        attempts = [
            lambda t: json.loads(t),
            lambda t: json.loads(re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', t)),
            lambda t: json.loads(re.sub(r',(\s*[}\]])', r'\1', t)),
            lambda t: json.loads(re.sub(r'(\{|,)\s*([a-zA-Z_]\w*)\s*:', r'\1"\2":', t)),
            # Fix missing commas between key-value pairs or array items
            lambda t: json.loads(re.sub(r'(["\]}])\s+(?=["{\[])', r'\1, ', t)),
            lambda t: _programmatic_repair(t),
        ]
        for i, attempt in enumerate(attempts, 1):
            try:
                result = attempt(raw_text)
                print(f"    JSON repair succeeded (attempt {i})")
                return True, result
            except Exception as e:
                print(
                    f"    Repair attempt {i} failed: "
                    f"{_safe_exception_text(e)[:100]}"
                )
                continue
        return False, {}

    # Single source of truth lives in CTIPrompts.ANALYTICAL_FIELD_NAMES.
    # Do not duplicate this set here â€” reference it directly so that adding
    # a new analytical question only requires one change in CTIPrompts.
    ANALYTICAL_FIELDS: frozenset = CTIPrompts.ANALYTICAL_FIELD_NAMES

    @staticmethod
    def validate_analytical(data: dict) -> Tuple[bool, str]:
        """
        Validate the analytical layer JSON returned by the AI in analyst mode.

        Unlike validate(), this does NOT check for TTP grounding or kill_chain_analysis â€”
        the AI in analyst mode never touches those factual fields.
        """
        if not isinstance(data, dict):
            return False, "Analytical output must be a dict"
        missing = JSONValidator.ANALYTICAL_FIELDS - set(data.keys())
        if missing:
            return False, f"Missing analytical fields: {missing}"
        if not isinstance(data.get('presentation_summary'), str):
            return False, "'presentation_summary' must be a string"
        if not isinstance(data.get('grounded_claim_ids'), list):
            return False, "'grounded_claim_ids' must be a list"
        return True, "OK"


# PATTERN 4: AI CLIENT (Ollama â€” local inference)

class VertexAIClient:
    """
    Vertex AI Gemini client with the same public contract as the previous
    GroqClient/OllamaClient implementation.

    Required configuration:
      - VERTEX_PROJECT_ID or GOOGLE_CLOUD_PROJECT

    Optional configuration:
      - VERTEX_LOCATION       default: us-central1
      - VERTEX_MODEL          default: gemini-1.5-pro
      - VERTEX_ACCESS_TOKEN   OAuth token; otherwise Google ADC is used
      - VERTEX_API_ENDPOINT   full API base override
    """

    _VERTEX_LOCATION = "us-central1"
    _VERTEX_MODEL = "gemini-2.5-pro"
    _FALLBACK_MODELS: list = []

    def __init__(
        self,
        token_budget: TokenBudget,
        base_url: str = "",
        model: str = "",
        *,
        project_id: str = "",
        location: str = "",
        request_timeout_seconds: float = 45.0,
        outer_timeout_seconds: float = 50.0,
        max_retries: int = 2,
        retry_delay_seconds: float = 2.0,
    ):
        self.budget = token_budget
        self.MAX_RETRIES = max(1, min(int(max_retries), 5))
        self.MAX_PROMPT_CHARS = 6000
        request_timeout = max(float(request_timeout_seconds), 0.001)
        self.OUTER_TIMEOUT_SECONDS = max(
            float(outer_timeout_seconds),
            request_timeout,
        )
        self._TIMEOUTS = [request_timeout] * self.MAX_RETRIES
        self._RETRY_DELAYS = [
            max(float(retry_delay_seconds), 0.0)
        ] * self.MAX_RETRIES
        self._project_id = str(project_id or "").strip()
        self._location = str(location or "").strip()
        self._model_override = model or ""
        self._genai_client = None            # compatibility injection hook
        self._genai_clients: Dict[int, Any] = {}
        self._colab_auth_done: bool = False  # auth once per instance

    def _resolve_project_id(self) -> str:
        return (
            self._project_id or
            os.environ.get("VERTEX_PROJECT_ID", "") or
            os.environ.get("GOOGLE_CLOUD_PROJECT", "") or
            os.environ.get("GCLOUD_PROJECT", "") or
            COLAB_CONFIG.get("project_id", "")
        )

    def _resolve_location(self) -> str:
        return (
            self._location or
            os.environ.get("VERTEX_LOCATION", "") or
            COLAB_CONFIG.get("location", "") or
            self._VERTEX_LOCATION
        )

    def _resolve_model(self) -> str:
        return (
            os.environ.get("VERTEX_MODEL", "") or
            self._model_override or
            COLAB_CONFIG.get("model", "") or
            self._VERTEX_MODEL
        )

    def _ensure_colab_auth(self) -> None:
        """Run google.colab.auth once per instance (Colab only)."""
        if self._colab_auth_done:
            return
        if COLAB_CONFIG.get("auto_colab_auth", False):
            try:
                import google.colab.auth as _colab_auth
                _colab_auth.authenticate_user()
                print("  [GenAI] Colab auth completed")
            except ImportError:
                pass   # not running in Colab â€” OK
            except Exception as e:
                print(f"  [GenAI] Colab auth warning: {_safe_exception_text(e)}")
        self._colab_auth_done = True

    def _get_client(self, timeout_seconds: Optional[float] = None):
        """Return a Vertex client with an actual bounded SDK HTTP timeout."""
        if self._genai_client is not None:
            return self._genai_client
        timeout = max(float(timeout_seconds or self._TIMEOUTS[0]), 0.001)
        timeout_ms = max(1, int(timeout * 1_000))
        if timeout_ms in self._genai_clients:
            return self._genai_clients[timeout_ms]
        self._ensure_colab_auth()
        try:
            from google import genai          # pip install google-genai
            from google.genai import types as _genai_types

            client = genai.Client(
                vertexai=True,
                project=self._resolve_project_id(),
                location=self._resolve_location(),
                http_options=_genai_types.HttpOptions(
                    timeout=timeout_ms,
                    retry_options=_genai_types.HttpRetryOptions(attempts=1),
                ),
            )
            self._genai_clients[timeout_ms] = client
            return client
        except ImportError:
            print("  [GenAI] google-genai not installed â€” run: pip install google-genai")
            return None
        except Exception as e:
            print(f"  [GenAI] Failed to create client: {_safe_exception_text(e)}")
            return None

    def available(self) -> bool:
        if not self._resolve_project_id():
            print("  [GenAI] Project not set â€” set VERTEX_PROJECT_ID "
                  "or GOOGLE_CLOUD_PROJECT")
            return False
        try:
            from google import genai  # noqa: F401
            return True
        except ImportError:
            print("  [GenAI] google-genai not installed â€” run: pip install google-genai")
            return False

    def _post_sync(self, messages: list, timeout: int,
                   model_override: str = None,
                   response_mime_type: str = "application/json") -> str:
        from google.genai import types as _genai_types

        model  = model_override or self._resolve_model()

        # Split system instruction and user content
        system_parts: list = []
        user_parts:   list = []
        for msg in messages:
            role    = msg.get("role", "")
            content = str(msg.get("content", ""))
            if not content:
                continue
            try:
                safe_content = redact_for_artifact(content)
            except Exception:
                raise RuntimeError("Vertex prompt redaction failed") from None
            if not isinstance(safe_content, str):
                raise RuntimeError("Vertex prompt redaction returned invalid text")
            if role == "system":
                system_parts.append(safe_content)
            else:
                user_parts.append(safe_content)

        user_text   = "\n".join(user_parts).strip()
        system_text = "\n".join(system_parts).strip()
        client = self._get_client(timeout)
        if client is None:
            raise RuntimeError("genai.Client could not be initialized")

        config = _genai_types.GenerateContentConfig(
            temperature=0.1,
            top_p=0.9,
            max_output_tokens=8192,   # 4096 truncates multi-session analytical output
            response_mime_type=response_mime_type,
            system_instruction=system_text if system_text else None,
        )

        response = client.models.generate_content(
            model=model,
            contents=user_text,
            config=config,
        )
        response_text = response.text or ""

        # Track token usage so the budget counter reflects actual API consumption
        if response_text:
            self.budget.consume_safe(response_text, f"vertex/{model}")

        return response_text

    async def _run_with_outer_timeout(
        self,
        call: Callable[[], str],
        timeout_seconds: float,
    ) -> str:
        """Run one SDK call without occupying asyncio's shared executor forever.

        The SDK timeout is the primary cancellation mechanism. The daemon thread
        is a final containment boundary for a client implementation that ignores
        its timeout; a timed-out call cannot keep the analysis coroutine or the
        event loop's default executor blocked.
        """

        loop = asyncio.get_running_loop()
        result_future = loop.create_future()

        def deliver_result(value: Any = None, error: Optional[BaseException] = None) -> None:
            if result_future.done():
                return
            if error is not None:
                result_future.set_exception(error)
            else:
                result_future.set_result(value)

        def run() -> None:
            try:
                value = call()
            except BaseException as exc:
                try:
                    loop.call_soon_threadsafe(deliver_result, None, exc)
                except RuntimeError:
                    return
            else:
                try:
                    loop.call_soon_threadsafe(deliver_result, value, None)
                except RuntimeError:
                    return

        thread = threading.Thread(
            target=run,
            name="vertex-sdk-request",
            daemon=True,
        )
        thread.start()
        try:
            return await asyncio.wait_for(
                asyncio.shield(result_future),
                timeout=max(float(timeout_seconds), 0.001),
            )
        except asyncio.CancelledError:
            result_future.cancel()
            raise
        except TimeoutError:
            result_future.cancel()
            raise TimeoutError("Vertex request exceeded outer timeout") from None


    def _extract_json(self, text: str) -> Optional[str]:
        """
        Extract a JSON object string from a model response.

        Strategy (in order):
          1. Direct parse  â€” response_mime_type='application/json' returns bare JSON
          2. <json_output> tag â€” some model prompts wrap output in XML tags
          3. ```json ... ``` code fence
          4. Greedy {.*} regex (DOTALL) â€” unformatted prose with embedded JSON
          5. Truncated-JSON repair â€” response cut off mid-object (max_output_tokens hit)
        """
        import json as _json

        # Strip chain-of-thought tags before any other processing
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

        if text.startswith("{"):
            try:
                _json.loads(text)   # fast-path: already valid JSON
                return text
            except _json.JSONDecodeError:
                pass  # might be truncated â€” fall through to repair

        match = re.search(r"<json_output>(.*?)</json_output>", text, re.DOTALL)
        if match:
            return match.group(1).strip()

        match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            return match.group(1).strip()

        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            candidate = match.group(1).strip()
            try:
                _json.loads(candidate)
                return candidate          # valid â€” return immediately
            except _json.JSONDecodeError:
                pass                      # truncated â€” fall through to repair

        # The response was cut mid-object. Close all open braces/brackets.
        brace_start = text.find("{")
        if brace_start != -1:
            fragment = text[brace_start:]
            # Walk backwards to find last complete value boundary
            # then close all remaining open containers
            for trim_pos in range(len(fragment) - 1, 0, -1):
                ch = fragment[trim_pos]
                if ch in (',', '"', ']', '}'):
                    stub = fragment[:trim_pos + 1].rstrip(',')
                    # Count unclosed braces/brackets
                    opens = 0
                    open_sq = 0
                    in_str = False
                    esc = False
                    for c in stub:
                        if esc:
                            esc = False
                            continue
                        if c == '\\':
                            esc = True
                            continue
                        if c == '"':
                            in_str = not in_str
                            continue
                        if in_str:
                            continue
                        if c == '{':
                            opens += 1
                        elif c == '}':
                            opens -= 1
                        elif c == '[':
                            open_sq += 1
                        elif c == ']':
                            open_sq -= 1
                    closer = ']' * max(0, open_sq) + '}' * max(0, opens)
                    if closer:
                        candidate = stub + closer
                        try:
                            _json.loads(candidate)
                            print(f"    [ExtractJSON] Repaired truncated JSON "
                                  f"(closed {opens} braces, {open_sq} brackets)")
                            return candidate
                        except _json.JSONDecodeError:
                            continue

        return None

    async def infer_with_retry(self,
                               prompt: str,
                               system: str = "",
                               phase: AnalysisPhase = AnalysisPhase.SYNTHESIS,
                               detected_ttps: List[str] = None,
                               tactic_summary: Dict[str, List[str]] = None) -> dict:
        if not self.available():
            print("  [VertexClient] Unavailable â€” deterministic baseline will be used")
            return {}

        if len(prompt) > self.MAX_PROMPT_CHARS:
            half = self.MAX_PROMPT_CHARS // 2
            omitted = len(prompt) - self.MAX_PROMPT_CHARS
            prompt = (
                prompt[:half] +
                f"\n\n... [{omitted} chars omitted to fit model context] ...\n\n" +
                prompt[-half:]
            )
            print(f"  Prompt capped at {self.MAX_PROMPT_CHARS} chars ({omitted} omitted)")

        safe_phase = _safe_log_text(getattr(phase, "value", phase), max_chars=40)
        print(
            f"\n  Vertex Inference [{safe_phase}] "
            f"model={_safe_log_text(self._resolve_model())}"
        )
        if detected_ttps:
            print(f"  Grounding Lock: {_safe_log_text(detected_ttps)}")
        self.budget.consume(prompt, f"Initial prompt ({safe_phase})")

        thinking_prefix = build_structured_prompt(phase, detected_ttps)
        full_system = f"{thinking_prefix}\n\n{system}" if system else thinking_prefix
        messages = [
            {"role": "system", "content": full_system},
            {"role": "user", "content": prompt},
        ]

        current_model = None
        fallback_queue = list(self._FALLBACK_MODELS)

        for attempt in range(1, self.MAX_RETRIES + 1):
            timeout = self._TIMEOUTS[attempt - 1]
            model_label = current_model or self._resolve_model()
            print(f"    Attempt {attempt}/{self.MAX_RETRIES} "
                  f"(timeout={timeout}s) model={_safe_log_text(model_label)}")
            try:
                raw_text = await self._run_with_outer_timeout(
                    lambda m=current_model: self._post_sync(
                        messages,
                        timeout,
                        model_override=m,
                    ),
                    max(timeout, self.OUTER_TIMEOUT_SECONDS),
                )
                print(f"       Response: {len(raw_text)} chars")
                # Consume response tokens (safe â€” doesn't raise after receiving data)
                self.budget.consume_safe(raw_text, f"Response (attempt {attempt})")
                if not raw_text:
                    if fallback_queue:
                        current_model = fallback_queue.pop(0)
                        print(
                            "       Empty response â€” switching to "
                            f"{_safe_log_text(current_model)}"
                        )
                    raise ValueError("Empty response from Vertex model")

                extracted_json = self._extract_json(raw_text)
                if not extracted_json:
                    preview = _safe_log_text(
                        raw_text[:200].replace("\n", " "),
                        max_chars=200,
                    )
                    print(f"       [DEBUG] No extractable JSON. Preview: {preview}...")
                    raise ValueError("No JSON found in Vertex response")

                try:
                    parsed = json.loads(extracted_json)
                except json.JSONDecodeError as jde:
                    success, parsed = JSONValidator.repair(extracted_json)
                    if not success:
                        raise ValueError(
                            f"JSON repair failed: {_safe_exception_text(jde)}"
                        )

                parsed = _safe_reporting_mapping(parsed, "Vertex response")

                is_valid, error_msg = JSONValidator.validate(
                    parsed, detected_ttps=detected_ttps,
                    tactic_summary=tactic_summary
                )
                if not is_valid:
                    print(f"       Schema error: {_safe_log_text(error_msg)}")
                    if attempt < self.MAX_RETRIES:
                        delay = self._RETRY_DELAYS[attempt - 1]
                        print(f"       Waiting {delay}s before retry...")
                        await asyncio.sleep(delay)
                        continue
                    raise ValueError(f"Schema validation failed: {error_msg}")

                print(f"    Parse succeeded on attempt {attempt} "
                      f"(model={_safe_log_text(model_label)})")
                return parsed

            except asyncio.CancelledError:
                raise
            except TimeoutError:
                print("       Vertex request exceeded the outer timeout; using deterministic fallback")
                return {}
            except Exception as e:
                safe_error = _safe_exception_text(e)
                print(f"       Attempt {attempt} failed: {safe_error[:160]}")
                if attempt == self.MAX_RETRIES:
                    return {}
                delay = self._RETRY_DELAYS[attempt - 1]
                if _exception_http_status(e) == 429:
                    retry_after = _exception_retry_after(e)
                    if retry_after is not None:
                        delay = max(delay, retry_after + 2)
                    delay = max(delay, 30)
                print(f"       Waiting {delay}s before retry...")
                await asyncio.sleep(delay)

        return {}

    async def infer_analytical(self,
                               evidence_brief: str,
                               detected_ttps: List[str]) -> dict:
        if not self.available():
            print("  [VertexClient] Unavailable â€” skipping analytical inference")
            return {}

        if len(evidence_brief) > self.MAX_PROMPT_CHARS:
            half = self.MAX_PROMPT_CHARS // 2
            omitted = len(evidence_brief) - self.MAX_PROMPT_CHARS
            evidence_brief = (
                evidence_brief[:half] +
                f"\n\n... [{omitted} chars omitted] ...\n\n" +
                evidence_brief[-half:]
            )
            print(f"  Evidence brief capped at {self.MAX_PROMPT_CHARS} chars ({omitted} omitted)")

        messages = [
            {"role": "system", "content": CTIPrompts.ANALYST_SYSTEM_PROMPT},
            {"role": "user", "content": evidence_brief},
        ]
        models_to_try = [self._resolve_model()] + list(self._FALLBACK_MODELS)
        attempted_models: set = set()

        for attempt in range(1, self.MAX_RETRIES + 1):
            if len(attempted_models) >= len(models_to_try):
                print(f"    [Analyst] All {len(models_to_try)} model(s) tried â€” stopping")
                break
            timeout = self._TIMEOUTS[attempt - 1]
            model = models_to_try[min(attempt - 1, len(models_to_try) - 1)]
            attempted_models.add(model)
            print(f"    [Analyst] Attempt {attempt}/{self.MAX_RETRIES} "
                  f"model={_safe_log_text(model)} timeout={timeout}s")
            try:
                raw_text = await self._run_with_outer_timeout(
                    lambda m=model: self._post_sync(
                        messages,
                        timeout,
                        model_override=m,
                    ),
                    max(timeout, self.OUTER_TIMEOUT_SECONDS),
                )
                if not raw_text:
                    print(
                        "    [Analyst] Empty response from "
                        f"{_safe_log_text(model)}"
                    )
                    continue

                extracted = self._extract_json(raw_text)
                if not extracted:
                    preview = _safe_log_text(
                        raw_text[:120].replace(chr(10), " "),
                        max_chars=120,
                    )
                    print(f"    [Analyst] No JSON found in response (preview: "
                          f"{preview})")
                    continue

                try:
                    parsed = json.loads(extracted)
                except json.JSONDecodeError as jde:
                    success, parsed = JSONValidator.repair(extracted)
                    if not success:
                        print(
                            "    [Analyst] JSON repair failed: "
                            f"{_safe_exception_text(jde)}"
                        )
                        continue

                parsed = _safe_reporting_mapping(parsed, "Vertex response")

                is_valid, msg = JSONValidator.validate_analytical(parsed)
                if not is_valid:
                    print(f"    [Analyst] Schema error: {_safe_log_text(msg)}")
                    if attempt < self.MAX_RETRIES:
                        delay = self._RETRY_DELAYS[attempt - 1]
                        print(f"    [Analyst] Waiting {delay}s before retry...")
                        await asyncio.sleep(delay)
                    continue

                print(f"    [Analyst] OK â€” analytical layer received "
                      f"({len(raw_text)} chars, attempt {attempt})")
                return parsed

            except asyncio.CancelledError:
                raise
            except TimeoutError:
                print(
                    "    [Analyst] Vertex request exceeded the outer timeout; "
                    "using deterministic fallback"
                )
                return {}
            except Exception as e:
                print(f"    [Analyst] Attempt {attempt} failed: "
                      f"{_safe_exception_text(e)[:160]}")
                status = _exception_http_status(e)
                if status == 404:
                    print(
                        "    [Analyst] 404 â€” model "
                        f"'{_safe_log_text(model)}' not found/not enabled. "
                        "Check Vertex AI Model Garden."
                    )
                    continue  # à¸¥à¸­à¸‡à¹‚à¸¡à¹€à¸”à¸¥à¸•à¸±à¸§à¸–à¸±à¸”à¹„à¸›
                if status == 429:
                    retry_after = _exception_retry_after(e)
                    wait = retry_after if retry_after is not None else self._RETRY_DELAYS[attempt - 1]
                    print(f"    [Analyst] Rate limited â€” waiting {wait}s")
                    await asyncio.sleep(wait)
                elif attempt < self.MAX_RETRIES:
                    await asyncio.sleep(self._RETRY_DELAYS[attempt - 1])

        print("  [Analyst] All attempts exhausted â€” returning empty (deterministic fallback applies)")
        return {}


# Compatibility aliases retained so older notebook code does not need to change.
GroqClient = VertexAIClient
OllamaClient = VertexAIClient


# CAMPAIGN NAME SYNTHESIS

async def _legacy_synthesize_campaign_name_disabled(
        ioc_bundle,
        tactic_summary: Dict[str, List[str]],
        fingerprint_text: str,
        behavioral_patterns: Dict[str, int]) -> str:
    """
    Synthesize a professional campaign name from OTX evidence + behavioral signals.

    WHY THIS EXISTS:
      OTX pulse names are crowdsourced. They are frequently low quality:
      "SSH Brute Force IPs March 2024", "Bad IP scanning", "Malicious IPs".
      Copying a pulse name verbatim as campaign_name makes the final report
      look amateurish and adds no analytical value.

    HOW IT WORKS:
      1. Collect raw_otx_pulse, otx_tags, infrastructure_tags, fingerprints,
         top observed tactics, and behavioral pattern counts.
      2. Pass these as structured evidence to Claude (claude-haiku-4-5).
      3. Claude synthesizes a professional campaign name using analyst conventions
         (Operation <Noun>, <Adjective> <Target> Campaign, etc.).
      4. Falls back to a deterministic name derived from the same evidence if
         the API call fails or returns an unusable result.

    IMPORTANT:
      - raw_otx_pulse is passed as INPUT EVIDENCE to the model, not as output.
      - The synthesized name is written to ip.campaign_hint on the highest-risk IP
        so it persists beyond this function call.
      - This function never raises â€” all exceptions produce the fallback name.
      - TODO: swap the Ollama call here for Anthropic when ready (search "Ollama synthesis").
    """
    # Collect evidence
    raw_pulses = []
    all_otx_tags = set()
    all_infra_tags = set()
    is_any_tor = False
    is_any_vpn = False

    for ip in ioc_bundle.ips:
        pulse = getattr(ip, 'raw_otx_pulse', None)
        if pulse:
            raw_pulses.append(pulse)
        all_otx_tags.update(getattr(ip, 'otx_tags', []) or [])
        all_infra_tags.update(getattr(ip, 'infrastructure_tags', []) or [])
        if getattr(ip, 'is_tor_exit', False):
            is_any_tor = True
        if getattr(ip, 'is_vpn', False):
            is_any_vpn = True

    top_tactics = sorted(tactic_summary.keys())[:4]
    cred_hunting = behavioral_patterns.get('credential_hunting', 0) > 0
    manual_recon = behavioral_patterns.get('manual_recon', 0) > 0

    # Build the deterministic fallback first so the function always has a result
    def _deterministic_fallback() -> str:
        if all_otx_tags:
            tag_sample = ', '.join(sorted(all_otx_tags)[:3])
            return f"Multi-Vector Intrusion â€” {tag_sample}"
        if top_tactics:
            tactic_sample = ' / '.join(top_tactics[:2])
            return (f"Operation Unknown â€” {tactic_sample} "
                    f"({len(ioc_bundle.ips)} source IPs)")
        return (f"Unclassified Campaign â€” "
                f"{len(ioc_bundle.ips)} IPs, "
                f"{len(tactic_summary)} tactics")

    # If there's no OTX data and no tags, skip AI and return deterministic
    if not raw_pulses and not all_otx_tags and not all_infra_tags:
        name = _deterministic_fallback()
        print(
            "  [Campaign Name] No OTX data â€” deterministic: "
            f"{_safe_log_text(name)}"
        )
        return name

    evidence_block = (
        f"Raw OTX pulse names (crowdsourced â€” do NOT copy verbatim): "
        f"{'; '.join(raw_pulses[:3]) if raw_pulses else 'None'}\n"
        f"OTX tags (controlled vocabulary): {', '.join(sorted(all_otx_tags)) or 'None'}\n"
        f"Shodan infrastructure tags: {', '.join(sorted(all_infra_tags)) or 'None'}\n"
        f"Tor exit node present: {is_any_tor}\n"
        f"VPN infrastructure: {is_any_vpn}\n"
        f"Top observed MITRE tactics: {', '.join(top_tactics) or 'None'}\n"
        f"JA3/HASSH fingerprint context: {fingerprint_text[:200] or 'None'}\n"
        f"Manual recon observed: {manual_recon}\n"
        f"Credential hunting observed: {cred_hunting}\n"
        f"Source IP count: {len(ioc_bundle.ips)}\n"
    )

    synthesis_prompt = (
        "You are a senior CTI analyst. Generate a single professional campaign name "
        "for a threat hypothesis report, using the evidence below.\n\n"
        "RULES:\n"
        "1. Do NOT copy the raw OTX pulse name verbatim â€” it is low-quality crowdsourced data.\n"
        "2. Synthesize from the OTX tags, infrastructure, and tactics â€” not the pulse string.\n"
        "3. Use analyst naming conventions: 'Operation <Noun>', "
        "'<Adjective> <Target> Campaign', or '<Technique>-Focused <Platform> Intrusion'.\n"
        "4. Keep it under 12 words.\n"
        "5. If Tor or VPN infrastructure is present, the name may hint at covert operations.\n"
        "6. Respond with ONLY the campaign name â€” no explanation, no quotes, no JSON.\n\n"
        f"EVIDENCE:\n{evidence_block}"
    )

    try:
        client = VertexAIClient(TokenBudget(max_tokens=1024))
        if not client.available():
            raise RuntimeError("Vertex AI unavailable")

        models_to_try = [client._resolve_model()] + list(client._FALLBACK_MODELS)
        messages = [{"role": "user", "content": synthesis_prompt}]

        name = ""
        for model in models_to_try:
            try:
                raw_name = client._post_sync(
                    messages,
                    timeout=20,
                    model_override=model,
                    response_mime_type="text/plain",
                )
                raw_name = _safe_reporting_text(raw_name, "campaign name")
                name = re.sub(
                    r'<think>.*?</think>', '', raw_name, flags=re.DOTALL
                ).strip().strip('"\'')
                if name and len(name) >= 4:
                    print(
                        "  [Campaign Name] Got response from Vertex model="
                        f"{_safe_log_text(model)}"
                    )
                    break
                print(
                    "  [Campaign Name] model="
                    f"{_safe_log_text(model)} returned empty - trying next"
                )
            except Exception as model_err:
                print(
                    "  [Campaign Name] model="
                    f"{_safe_log_text(model)} failed: "
                    f"{_safe_exception_text(model_err)[:100]} - trying next"
                )
                import time
                time.sleep(2)
                continue

        if not name or len(name) < 4 or len(name.split()) > 15:
            raise ValueError(f"Unusable campaign name from Vertex: {repr(name)}")

        for pulse in raw_pulses:
            if name.lower().strip() == pulse.lower().strip():
                raise ValueError("Vertex echoed raw pulse name verbatim - rejecting")

        print(
            "  [Campaign Name] Vertex synthesized: "
            f"{_safe_log_text(name)}"
        )

        best_ip = max(ioc_bundle.ips, key=lambda x: getattr(x, 'risk_score', 0),
                      default=None)
        if best_ip is not None:
            best_ip.campaign_hint = name

        return name


    except Exception as e:
        try:
            fallback = _safe_reporting_text(
                _deterministic_fallback(),
                "campaign fallback",
            )
        except Exception:
            fallback = "Cowrie SSH Session Assessment"
        print(
            "  [Campaign Name] Vertex synthesis failed "
            f"({_safe_exception_text(e)[:120]}) â€” using deterministic: "
            f"{_safe_log_text(fallback)}"
        )
        return fallback


async def _synthesize_campaign_name(
        ioc_bundle,
        tactic_summary: Dict[str, List[str]],
        fingerprint_text: str,
        behavioral_patterns: Dict[str, int]) -> str:
    """Compatibility wrapper; AI-generated campaign naming is disabled."""

    return "Cowrie SSH Session Assessment"


# VT INTELLIGENCE EXTRACTION

def _extract_vt_intelligence(ioc_bundle) -> Dict[str, Any]:
    """
    Extract VirusTotal intelligence from enriched IP objects.

    Returns a summary dict with confirmed malware families and detection counts.

    CRITICAL INTERPRETATION RULE:
      vt_hit=False does NOT mean the file is clean. Polymorphic malware, freshly
      compiled droppers, and Mirai variants routinely return 0/70 detections.
      This function only surfaces positive hits â€” it never asserts cleanliness
      from the absence of VT data.

    Returns:
      {
        "has_hits": bool,
        "malware_families": list[str],   # unique confirmed families
        "hit_count": int,                # number of IPs with VT hits
        "detection_ratios": list[str],   # e.g. ["45/70", "12/70"]
        "narrative": str,                # human-readable summary for reports
      }
    """
    families = []
    ratios = []
    hit_count = 0

    for ip in ioc_bundle.ips:
        if getattr(ip, 'vt_hit', False):
            hit_count += 1
            family = getattr(ip, 'vt_malware_family', None)
            if family:
                families.append(family)
            ratio = getattr(ip, 'vt_detection_ratio', None)
            if ratio:
                ratios.append(ratio)

    unique_families = list(dict.fromkeys(families))  # preserve order, deduplicate

    if not hit_count:
        narrative = (
            "No VirusTotal matches on associated hashes. "
            "Note: absence of VT detections does NOT indicate cleanliness â€” "
            "polymorphic and freshly compiled malware routinely evade AV signatures."
        )
    elif unique_families:
        narrative = (
            f"VirusTotal confirmed {hit_count} associated malware hash(es). "
            f"Identified families: {', '.join(unique_families)}. "
            f"Add these families to EDR block lists and hunt for related IOCs."
        )
    else:
        narrative = (
            f"VirusTotal flagged {hit_count} hash(es) but no malware family "
            f"attribution available. Review detections manually."
        )

    return {
        "has_hits": hit_count > 0,
        "malware_families": unique_families,
        "hit_count": hit_count,
        "detection_ratios": ratios,
        "narrative": narrative,
    }


# DYNAMIC RECOMMENDATION ENGINE â€” NO TTPâ†’TEXT MAPPINGS

def _derive_actions_from_command(cmd: str, add_fn) -> None:
    """
    Parse a single observed command and emit zero or more recommended actions.

    All actions are derived from artefacts extracted from the command string
    itself â€” account names, file paths, URLs, IPs. No TTP ID is consulted.
    """
    # Unauthorised account creation
    m = re.search(r'useradd\s+(?:-\S+\s+)*(\w+)', cmd)
    if m:
        add_fn(f"Check whether account `{m.group(1)}` exists on authorized real systems; "
               f"remove it only if confirmed unauthorized. Cowrie observed an account-creation command: `{cmd[:80]}`")

    # Attacker SSH key implanted
    m = re.search(r'authorized_keys.*?(ssh-\S+\s+\S+)', cmd)
    if m:
        add_fn(f"Search authorized real systems for the observed SSH public-key material and "
               f"remove it only if confirmed unauthorized: `{m.group(1)[:70]}`")
    elif 'authorized_keys' in cmd:
        add_fn(f"Audit ~/.ssh/authorized_keys on authorized real systems; Cowrie observed a "
               f"key-modification command, not confirmed real-host persistence: `{cmd[:80]}`")

    # Cron-based persistence
    if 'crontab' in cmd and '-' in cmd:
        path_m = re.search(r'(/tmp/\S+|/var/tmp/\S+|/dev/shm/\S+)', cmd)
        path = path_m.group(1) if path_m else "scheduled payload"
        add_fn(f"Check authorized real systems for a cron entry referencing `{path}` and remove it "
               f"only if confirmed unauthorized. Cowrie observed: `{cmd[:80]}`")

    # Credential exfiltration via curl POST
    m = re.search(r'curl.*?-d\s+@([^\s]+)\s+(https?://[^\s]+)', cmd)
    if m:
        add_fn(f"Review network and application telemetry for an attempted upload of `{m.group(1)}` "
               f"to `{m.group(2)}`; rotate credentials only if exposure is corroborated")

    # File download and execution
    m = re.search(r'wget\s+(https?://\S+)\s+-O\s+(\S+)', cmd)
    if m:
        add_fn(f"Search authorized telemetry for an attempted transfer from `{m.group(1)}` to "
               f"`{m.group(2)}`; the command alone does not confirm a completed download")

    # Alternate wget pattern
    m = re.search(r'wget\s+(https?://\S+)', cmd)
    if m and '-O' not in cmd:
        add_fn(f"Review `{m.group(1)}` and block it only if policy or corroborating telemetry supports "
               f"that action; Cowrie observed: `{cmd[:80]}`")

    # Log file truncation
    m = re.search(r'truncate.*?(/var/log/\S+)', cmd)
    if m:
        add_fn(f"Check integrity and backups for `{m.group(1)}`; Cowrie observed a truncation command, "
               f"but successful evidence removal on a real host is not established")

    # History clearing
    if 'unset HISTFILE' in cmd or 'history -c' in cmd:
        add_fn("Verify remote or immutable logging coverage; Cowrie observed a history-cleanup command, "
               "but successful real-host history deletion is not established")

    # Sudo privilege enumeration
    if re.search(r'\bsudo\s+-l\b', cmd):
        add_fn("Review /etc/sudoers and sudo audit logs on authorized real systems; Cowrie observed a "
               "sudo-enumeration command, not confirmed privilege escalation")

    # Password / shadow file access
    m = re.search(r'cat\s+(/etc/(?:passwd|shadow))', cmd)
    if m:
        add_fn(f"Review access telemetry and integrity for `{m.group(1)}`; Cowrie observed a read command, "
               "but successful credential acquisition is not established")

    # Credential grep across home directories
    m = re.search(r'grep.*?(/home/[^\s]+)', cmd)
    if m:
        add_fn(f"Audit `{m.group(1)}` for plaintext secrets and review access telemetry; Cowrie observed "
               f"a search command: `{cmd[:80]}`")

    # Cloud credential access
    m = re.search(r'cat\s+(/home/[^/]+/\.aws/credentials|'
                  r'/home/[^/]+/\.config/gcloud/[^\s]+)', cmd)
    if m:
        add_fn(f"Audit cloud API and file-access telemetry related to `{m.group(1)}`; rotate credentials "
               f"only if real exposure or unauthorized use is corroborated")

    # usermod privilege escalation
    m = re.search(r'usermod\s+-aG\s+(?:sudo|wheel|admin)\s+(\w+)', cmd)
    if m:
        add_fn(f"Check group membership for `{m.group(1)}` on authorized real systems and revert only "
               f"a confirmed unauthorized change. Cowrie observed: `{cmd[:80]}`")


def _generate_dynamic_recommendations(
        ttp_command_map: Dict[str, List[str]],
        ioc_bundle,
        raw_events: List[dict],
        vt_intel: Dict[str, Any] = None) -> List[str]:
    """
    Generate all tactical recommendations from observed command artefacts only.

    Sources (in order):
      1. Attacker source IPs from ioc_bundle (block at perimeter).
      2. Each observed command parsed for specific artefacts.
      3. File download events from cowrie.session.file_download (hash + path).
      4. VirusTotal intelligence (vt_intel) â€” surfaces confirmed malware family
         in removal instructions when vt_hit=True.
         IMPORTANT: vt_hit=False is silently ignored â€” it does NOT mean clean.
         Polymorphic droppers routinely return 0/70 on VT.

    No TTP ID is consulted for recommendation text at any point.
    """
    vt_intel = vt_intel or {}
    vt_families = vt_intel.get("malware_families", [])

    recommendations = []
    seen = set()

    def add(rec: str):
        if rec not in seen:
            seen.add(rec)
            recommendations.append(rec)

    # 1. Preserve the source as a correlation lead; do not infer maliciousness
    # or recommend a permanent block from a single honeypot observation.
    for ip in ioc_bundle.ips:
        note = getattr(ip, 'note', None) or 'observed in attack session'
        add(
            f"Review source IP `{ip.value}` in real authentication and network logs; "
            f"consider temporary rate limiting only if repeated or corroborated â€” {note}"
        )

    # 2. Parse every observed command for artefacts
    for ttp, commands in ttp_command_map.items():
        for cmd in commands:
            _derive_actions_from_command(cmd, add)

    # 3. File download events â€” surface hash for AV/EDR; add family when VT confirmed it
    for event in raw_events:
        if event.get('eventid') == 'cowrie.session.file_download':
            outfile = event.get('outfile', '')
            shasum  = event.get('shasum', '')
            url     = event.get('url') or 'source URL unavailable in event'
            if outfile and shasum:
                family_note = (
                    f" â€” VirusTotal family: {', '.join(vt_families[:2])}"
                    if vt_families else ""
                )
                add(
                    f"Scan all systems for file `{outfile}` "
                    f"(SHA256: `{shasum}`){family_note} â€” "
                    f"Cowrie recorded a transfer from `{url}` â€” "
                    f"validate the artifact before adding the hash to AV/EDR controls"
                )
            elif outfile:
                add(
                    f"Search authorized telemetry for file `{outfile}`; Cowrie recorded a transfer "
                    f"from `{url}`, but execution and real-host presence are not established"
                )

    # 4. Family-specific hunt recommendations when VT confirms a known malware family
    if vt_intel.get("has_hits") and vt_families:
        for family in vt_families[:3]:
            add(
                f"Hunt for {family} indicators across all endpoints â€” "
                f"VirusTotal confirmed this family in associated session hashes. "
                f"Update EDR signatures and run a full threat hunt."
            )

    return recommendations


def _generate_strategic_recommendations(
        otx_tags: set,
        config: dict) -> List[str]:
    """
    Generate strategic (policy-level) recommendations from config file.

    Keyed by OTX enrichment tags â€” not by TTP IDs.
    Strategic controls are defined in configs/threat_intel_config.json under
    'strategic_controls' as a dict from tag â†’ list of control strings.
    """
    strategic_controls = config.get("strategic_controls", {})
    if not strategic_controls:
        return []

    recommendations = []
    seen = set()
    for tag in otx_tags:
        for control in strategic_controls.get(tag, []):
            if control not in seen:
                seen.add(control)
                recommendations.append(control)
    return recommendations


def _default_recommendation_policy_paths() -> Tuple[str, str]:
    configured_asset = str(os.getenv("SMB_ASSET_PROFILE_PATH") or "").strip()
    configured_policy = str(os.getenv("SMB_ACTION_POLICY_PATH") or "").strip()
    if (
        configured_asset
        and configured_policy
        and os.path.exists(configured_asset)
        and os.path.exists(configured_policy)
    ):
        return configured_asset, configured_policy
    candidates = [
        os.path.dirname(os.path.abspath(__file__)),
        os.getcwd(),
    ]
    for base_dir in candidates:
        asset_path = os.path.join(base_dir, "configs", "smb_asset_profile.example.json")
        policy_path = os.path.join(base_dir, "configs", "smb_action_playbooks.trusted.json")
        if os.path.exists(asset_path) and os.path.exists(policy_path):
            return asset_path, policy_path
    base_dir = candidates[0]
    return (
        os.path.join(base_dir, "configs", "smb_asset_profile.example.json"),
        os.path.join(base_dir, "configs", "smb_action_playbooks.trusted.json"),
    )


def _default_prediction_policy_path() -> str:
    candidates = [
        os.path.dirname(os.path.abspath(__file__)),
        os.getcwd(),
    ]
    for base_dir in candidates:
        policy_path = os.path.join(base_dir, "configs", "prediction_policy.trusted.json")
        if os.path.exists(policy_path):
            return policy_path
    return os.path.join(candidates[0], "configs", "prediction_policy.trusted.json")


def _prediction_tactic_severity_map(
    policy_path: str = "",
    policy_document: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Load tactic severity from the realtime prediction policy.

    This keeps report emphasis aligned with the predictive-alert policy instead
    of maintaining a separate hardcoded TTP allowlist in the report builder.
    """

    severity: Dict[str, str] = {
        "credential-access": "medium",
        "defense-evasion": "medium",
        "command-and-control": "high",
        "persistence": "high",
        "privilege-escalation": "high",
        "lateral-movement": "critical",
        "exfiltration": "critical",
        "impact": "critical",
    }
    document: Any = policy_document
    if document is None:
        path = policy_path or _default_prediction_policy_path()
        try:
            with open(path, "r", encoding="utf-8") as f:
                document = json.load(f)
        except Exception:
            document = {}
    try:
        policy = document.get("policy", document) if isinstance(document, dict) else {}
        configured = ((policy.get("predictive_alerts") or {}).get("tactic_severity") or {})
        if isinstance(configured, dict):
            severity.update({
                str(tactic).strip().lower(): str(value).strip().lower()
                for tactic, value in configured.items()
                if str(tactic).strip()
            })
    except Exception:
        pass
    return severity


def _completed_actions_from_observed_ttps(
        tactic_summary: Dict[str, List[str]],
        ttp_command_map: Dict[str, List[str]],
        policy_path: str = "",
        policy_document: Optional[Dict[str, Any]] = None,
        limit: int = 20) -> List[str]:
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    tactic_severity = _prediction_tactic_severity_map(
        policy_path,
        policy_document,
    )
    ttp_to_tactic: Dict[str, str] = {}
    for tactic, ttps in (tactic_summary or {}).items():
        for ttp in ttps or []:
            ttp_to_tactic[str(ttp)] = str(tactic).strip().lower()

    candidates = []
    seen = set()
    for ttp, commands in (ttp_command_map or {}).items():
        tactic = ttp_to_tactic.get(str(ttp), "")
        rank = severity_rank.get(tactic_severity.get(tactic, "low"), 1)
        for cmd in commands or []:
            text = str(cmd)[:200]
            if not text or text in seen:
                continue
            seen.add(text)
            candidates.append((rank, str(ttp), text))
    candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
    return [text for _rank, _ttp, text in candidates[:limit]]


def _session_payload_for_recommendations(
        sessions: List[Any],
        raw_events: List[dict],
        tactic_summary: Dict[str, List[str]],
        ttp_command_map: Dict[str, List[str]]) -> Dict[str, Any]:
    commands = _extract_observed_commands(sessions)
    first = sessions[0] if sessions else None
    classification_events: List[dict] = []
    commands_success: List[str] = []
    commands_failed: List[str] = []
    for session in sessions or []:
        for command in getattr(session, "commands_success", []) or []:
            text = str(command or "").strip()
            if text and text not in commands_success:
                commands_success.append(text)
        for command in getattr(session, "commands_failed", []) or []:
            text = str(command or "").strip()
            if text and text not in commands_failed:
                commands_failed.append(text)
        for event in getattr(session, "classification_events", []) or []:
            if isinstance(event, dict):
                classification_events.append(event)

    src_ip = getattr(first, "src_ip", None) if first is not None else None
    sensor = getattr(first, "sensor", None) if first is not None else None
    protocol = getattr(first, "protocol", None) if first is not None else None
    dst_port = getattr(first, "dst_port", None) if first is not None else None
    login_success = bool(getattr(first, "login_success", False)) if first is not None else False
    username = getattr(first, "login_username", None) if first is not None else None

    for event in raw_events or []:
        if not isinstance(event, dict):
            continue
        src_ip = src_ip or event.get("src_ip")
        sensor = sensor or event.get("sensor") or event.get("sensor_id")
        protocol = protocol or event.get("protocol")
        dst_port = dst_port or event.get("dst_port")
        username = username or event.get("username")
        if event.get("eventid") == "cowrie.login.success":
            login_success = True

    ttps = list(dict.fromkeys(str(ttp) for ttps in (tactic_summary or {}).values() for ttp in ttps))
    tactics = list(dict.fromkeys(str(tactic) for tactic in (tactic_summary or {}).keys()))
    return {
        "session_id": getattr(first, "session_id", "unknown") if first is not None else "unknown",
        "src_ip": src_ip or "unknown",
        "sensor": sensor or "",
        "protocol": protocol or "ssh",
        "dst_port": dst_port or 22,
        "login_success": login_success,
        "login_username": username or "",
        "commands": commands,
        "commands_success": commands_success,
        "commands_failed": commands_failed,
        "raw_events": raw_events or [],
        "classification_events": classification_events,
        "session_evidence_graph": (
            getattr(first, "session_evidence_graph", {}) if first is not None else {}
        ) or {},
        "tactics": tactics,
        "ttps": ttps,
        "ttp_command_map": ttp_command_map or {},
    }


def _build_trusted_recommendation_decision(
        sessions: List[Any],
        raw_events: List[dict],
        tactic_summary: Dict[str, List[str]],
    ttp_command_map: Dict[str, List[str]],
    mitre_db: Any = None,
    asset_profile_path: str = "",
    action_policy_path: str = "",
    prediction_snapshot: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build report actions from the same trusted policy engine used by production.

    This keeps the report recommendation authority out of the LLM. The AI may
    explain the report, but the actual actions come from policy-as-code with
    evidence conditions, references, and asset context.
    """
    try:
        from production.reporting.smb_decision import (
            build_smb_decision,
            load_action_policy,
            load_asset_profile,
        )
    except Exception as exc:
        return {
            "status": "unavailable",
            "authority": "policy_unavailable",
            "reason": f"policy engine import failed: {_safe_exception_text(exc)}",
            "immediate_actions": [],
        }

    default_asset_path, default_policy_path = _default_recommendation_policy_paths()
    asset_path = asset_profile_path or default_asset_path
    policy_path = action_policy_path or default_policy_path
    session_payload = _session_payload_for_recommendations(
        sessions, raw_events, tactic_summary, ttp_command_map
    )
    try:
        decision = build_smb_decision(
            session_payload=session_payload,
            prediction_snapshot=prediction_snapshot,
            report_recommendations={},
            asset_profile=load_asset_profile(asset_path),
            action_policy=load_action_policy(policy_path),
            mitre_db=mitre_db,
        )
        decision.setdefault("status", "unavailable")
        decision.setdefault("authority", "policy_unavailable")
        return decision
    except Exception as exc:
        return {
            "status": "error",
            "authority": "policy_unavailable",
            "reason": f"policy engine failed: {_safe_exception_text(exc)}",
            "immediate_actions": [],
        }


# HONEYPOT-SPECIFIC ANALYSIS FUNCTIONS

def _assess_honeypot_awareness(sessions: List[Any],
                               behavioral_rules: dict) -> dict:
    """
    Assess whether the attacker suspected they were in a honeypot/VM.

    Evasion command patterns come from behavioral_rules config
    ('vm_detection' key) â€” not hardcoded here.
    """
    evasion_kw = behavioral_rules.get("vm_detection", [])
    awareness_signals = []

    for s in sessions:
        cmds = getattr(s, 'commands_success', [])
        for cmd in cmds:
            if any(kw in cmd.lower() for kw in evasion_kw):
                awareness_signals.append(cmd)

    if awareness_signals:
        assessment = "aware"
        evidence = awareness_signals[:3]
    else:
        assessment = "unaware"
        evidence = []

    return {
        "assessment": assessment,
        "evidence": evidence,
        "note": (
            "Attacker ran environment detection commands â€” may have identified "
            "honeypot and altered behaviour" if awareness_signals else
            "No honeypot/VM detection commands observed â€” attacker proceeded "
            "as if in a real environment"
        )
    }


_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _is_real_ip(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(text and text.lower() not in {"unknown", "none", "n/a"} and _IPV4_RE.fullmatch(text))


def _extract_session_source_ips(sessions: List[Any], raw_events: List[dict] = None) -> List[str]:
    """Return attacker/source IPs directly observed in this report's sessions."""
    raw_events = raw_events or []
    ips = []
    seen = set()

    def add(value: Any) -> None:
        text = str(value or "").strip()
        if _is_real_ip(text) and text not in seen:
            seen.add(text)
            ips.append(text)

    for session in sessions or []:
        add(getattr(session, "src_ip", None))
    for event in raw_events:
        add(event.get("src_ip") or event.get("_src_ip"))
    return ips


def _extract_direct_evidence_ips(sessions: List[Any], raw_events: List[dict] = None) -> set:
    """
    IPs the AI may safely mention in narrative fields.

    This is intentionally stricter than ioc_bundle.ips because that bundle may
    include related or enriched indicators. Narrative claims should stay grounded
    in the current session's raw evidence.
    """
    raw_events = raw_events or []
    ips = set(_extract_session_source_ips(sessions, raw_events))

    for session in sessions or []:
        for attr in ("dst_ip", "source_ip", "attacker_ip"):
            value = getattr(session, attr, None)
            if _is_real_ip(value):
                ips.add(str(value).strip())
        for cmd in getattr(session, "commands_success", []) or []:
            ips.update(_IPV4_RE.findall(str(cmd)))

    for event in raw_events:
        for key in ("dst_ip", "_dst_ip"):
            value = event.get(key)
            if _is_real_ip(value):
                ips.add(str(value).strip())
        for key in ("input", "message", "url"):
            ips.update(_IPV4_RE.findall(str(event.get(key, ""))))

    return ips


def _extract_observed_commands(sessions: List[Any]) -> List[str]:
    commands = []
    for session in sessions or []:
        for attr in ("commands_success", "commands"):
            for cmd in getattr(session, attr, []) or []:
                text = str(cmd or "").strip()
                if text and text not in commands:
                    commands.append(text)
    return commands


def _looks_like_command_claim(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    first = text.split()[0] if text.split() else ""
    shell_commands = {
        "cat", "chmod", "chown", "crontab", "curl", "echo", "grep",
        "history", "hostname", "id", "ifconfig", "ip", "ls", "mkdir", "nc",
        "netcat", "netstat", "ps", "python", "rm", "sh", "ss", "sudo",
        "uname", "useradd", "wget", "whoami",
    }
    return first in shell_commands or any(token in text for token in (" /", "&&", "|", ";", "/tmp/"))


def _ungrounded_command_claims(value: str, observed_commands: List[str]) -> List[str]:
    observed_lower = [cmd.lower() for cmd in observed_commands or []]
    bad = []
    for claim in re.findall(r'[`"\']([^`"\']{2,160})[`"\']', str(value or "")):
        claim_l = claim.lower().strip()
        if not _looks_like_command_claim(claim_l):
            continue
        if not any(claim_l in cmd or cmd in claim_l for cmd in observed_lower):
            bad.append(claim)
    return bad


def _completed_action_conflicts(
        prediction: str,
        observed_commands: List[str]) -> List[str]:
    """Return post-session prediction claims that repeat observed actions."""
    pred_l = str(prediction or "").lower()
    observed_lower = [cmd.lower() for cmd in observed_commands or []]
    conflicts: List[str] = []

    observed_urls = set()
    observed_paths = set()
    sensitive_paths = {
        "/etc/passwd",
        "/etc/shadow",
        "/home/exampleuser/.ssh/id_rsa",
        ".ssh/id_rsa",
    }
    for cmd in observed_lower:
        observed_urls.update(re.findall(r"https?://[^\s'\";|&]+", cmd))
        observed_paths.update(re.findall(r"(?:/tmp|/var/tmp|/dev/shm)/[^\s'\";|&]+", cmd))
        observed_paths.update(path for path in sensitive_paths if path in cmd)

    def prediction_mentions_any(values: set) -> bool:
        return any(value and value in pred_l for value in values)

    download_terms = (
        "download", "fetch", "retrieve", "payload staging",
        "tool transfer", "ingress tool transfer", "wget", "curl",
    )
    execution_terms = (
        "execute", "execution", "run payload", "run the payload",
        "launch", "make executable", "chmod",
    )
    read_terms = ("read", "dump", "cat ", "access", "exfiltrate")

    if any("chmod" in cmd for cmd in observed_lower) and (
            "chmod" in pred_l or "make executable" in pred_l):
        conflicts.append("chmod/make executable already observed")
    if any("history -c" in cmd or "rm -rf" in cmd for cmd in observed_lower) and (
            "history" in pred_l or "clear tracks" in pred_l or "cleanup" in pred_l):
        conflicts.append("cleanup/history clearing already observed")
    if prediction_mentions_any(observed_urls) and any(term in pred_l for term in download_terms):
        conflicts.append("payload/tool download from observed URL already occurred")
    if prediction_mentions_any(observed_paths) and any(term in pred_l for term in execution_terms):
        conflicts.append("execution or permission change for observed payload path already occurred")
    if prediction_mentions_any(sensitive_paths) and any(term in pred_l for term in read_terms):
        conflicts.append("sensitive file access already observed")

    return list(dict.fromkeys(conflicts))


def _drop_ungrounded_narrative(
        value: str,
        field: str,
        observed_commands: List[str],
        warnings: List[dict],
        allow_future_examples: bool = False) -> str:
    bad = _ungrounded_command_claims(value, observed_commands)
    if not bad:
        return value

    if allow_future_examples:
        lower_value = str(value or "").lower()
        completed_language = any(
            phrase in lower_value
            for phrase in (
                "already", "observed", "completed", "has completed",
                "attempted", "executed", "performed",
            )
        )
        if not completed_language:
            return value

    warnings.append({
        "field": field,
        "dropped_unobserved_commands": bad,
        "reason": "Final narrative field referenced command evidence outside direct session observations",
    })
    return ""


def _validate_ai_grounding(
        analytical: dict,
        allowed_ips: set,
        observed_commands: Optional[List[str]] = None) -> dict:
    """
    Drop AI narrative fields that introduce IPs not present in direct evidence.

    The deterministic layer remains intact. This only prevents Gemini/Vertex from
    carrying an ungrounded IP or actor into executive summaries and predictions.
    """
    if not analytical:
        return analytical or {}

    cleaned = dict(analytical)
    warnings = []
    observed_commands = observed_commands or []
    narrative_fields = (
        "executive_summary",
        "correlation_reasoning",
        "sophistication_justification",
        "threat_actor_description",
        "predicted_next_action",
        "honeypot_awareness_note",
    )
    for field in narrative_fields:
        value = cleaned.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        if allowed_ips:
            mentioned = set(_IPV4_RE.findall(value))
            ungrounded = sorted(ip for ip in mentioned if ip not in allowed_ips)
        else:
            ungrounded = []
        ungrounded_commands = []
        if field != "predicted_next_action":
            ungrounded_commands = _ungrounded_command_claims(value, observed_commands)

        if ungrounded or ungrounded_commands:
            cleaned[field] = ""
            warning = {
                "field": field,
                "reason": "AI field referenced evidence outside direct session observations",
            }
            if ungrounded:
                warning["dropped_unobserved_ips"] = ungrounded
            if ungrounded_commands:
                warning["dropped_unobserved_commands"] = ungrounded_commands
            warnings.append(warning)

    prediction = cleaned.get("predicted_next_action")
    if isinstance(prediction, str) and prediction.strip():
        completed_conflicts = _completed_action_conflicts(prediction, observed_commands)
        if completed_conflicts:
            cleaned["predicted_next_action"] = ""
            warnings.append({
                "field": "predicted_next_action",
                "dropped_completed_action_claims": completed_conflicts,
                "reason": "AI predicted an action that already occurred in the session",
            })

    if warnings:
        cleaned["_grounding_warnings"] = warnings
    return cleaned


def _reject_ai_operator_actions(analytical: dict, warnings: List[dict]) -> None:
    """
    Enforce the recommendation boundary.

    The LLM may write narrative analysis, but it is not allowed to introduce,
    replace, or extend operator remediation actions. Report actions come only
    from the trusted policy engine.
    """
    if not isinstance(analytical, dict):
        return
    blocked_fields = (
        "recommended_mitigations",
        "recommended_actions",
        "operator_actions",
        "remediation_actions",
        "strategic_recommendations",
    )
    for field in blocked_fields:
        value = analytical.get(field)
        if value in (None, "", []):
            continue
        analytical[field] = [] if isinstance(value, list) else ""
        warnings.append({
            "field": field,
            "reason": (
                "AI-proposed operator action rejected; remediation actions must "
                "come from the trusted policy engine."
            ),
        })


def _derive_primary_objective(
        current: str,
        tactic_summary: Dict[str, List[str]],
        ttp_command_map: Dict[str, List[str]],
        playbook: Dict[str, Any] = None) -> str:
    """Derive a conservative objective from observed tactics/TTPs."""
    if (
        current
        and current != "Under analysis"
        and not re.search(
            r"\b(?:harvest(?:ing)?|confirmed|persistent access|payload execution|compromise)\b",
            current,
            re.IGNORECASE,
        )
    ):
        return current

    playbook = playbook or {}
    tactics = {str(t).lower() for t in (tactic_summary or {}).keys()}
    ttps = {str(t) for t in (ttp_command_map or {}).keys()}

    credential_targets = playbook.get("credential_targets") or []
    if credential_targets:
        return (
            "Possible credential-related discovery or access preparation involving "
            + ", ".join(str(t) for t in credential_targets[:3])
        )
    if "T1105" in ttps:
        return "Possible tool transfer or payload staging"
    if "T1003" in ttps or "credential-access" in tactics:
        return "Possible credential-related discovery or access preparation"
    if "command-and-control" in tactics:
        return "Observed command or transfer behavior mapped to Command and Control"
    if "discovery" in tactics:
        return "Observed host and environment discovery behavior"
    return "Insufficient evidence to infer an attacker objective from Cowrie telemetry."


def _build_evidence_grounded_actor_profile(
        tactic_summary: Dict[str, List[str]],
        ttp_command_map: Dict[str, List[str]],
        sessions: List[Any],
        raw_events: List[dict] = None,
        behavioral_score: int = 0,
        score_reasons: List[str] = None) -> Dict[str, Any]:
    """Describe only behavior supported by trusted command and Cowrie evidence.

    Behavioral score inputs are accepted for compatibility but are deliberately
    not rendered as actor identity, organization, or attribution claims.
    """

    raw_events = raw_events or []
    score_reasons = score_reasons or []
    tactics = sorted(str(value) for value in (tactic_summary or {}) if str(value))
    ttps = sorted({
        str(ttp)
        for values in (tactic_summary or {}).values()
        for ttp in values or []
        if str(ttp)
    })
    commands: List[str] = []
    for values in (ttp_command_map or {}).values():
        for command in values or []:
            text = str(command or "").strip()
            if text and text not in commands:
                commands.append(text)
    if not commands:
        for session in sessions or []:
            for command in getattr(session, "commands_success", []) or []:
                text = str(command or "").strip()
                if text and text not in commands:
                    commands.append(text)

    eventids = {
        str(event.get("eventid") or "").strip()
        for event in raw_events
        if isinstance(event, dict)
    }
    command_text = "\n".join(commands).lower()
    has_downloader = bool(re.search(r"\b(?:curl|wget|tftp|ftp)\b\s+\S+", command_text))
    has_download_event = "cowrie.session.file_download" in eventids

    observed_facts: List[str] = []
    if tactics:
        observed_facts.append(f"Trusted command mappings contain tactics: {', '.join(tactics)}.")
    if ttps:
        observed_facts.append(f"Trusted command mappings contain techniques: {', '.join(ttps)}.")
    if commands:
        observed_facts.append(f"{len(commands)} trusted command observation(s) support this profile.")
    if has_download_event:
        observed_facts.append("Cowrie recorded a successful file-download event in the session.")
    elif has_downloader:
        observed_facts.append(
            "A downloader command was observed, but Cowrie did not record a successful file-download event."
        )

    supported_inferences: List[str] = []
    tactic_set = set(tactics)
    if "discovery" in tactic_set:
        supported_inferences.append("The trusted commands support host or environment discovery behavior.")
    if has_downloader and not has_download_event:
        supported_inferences.append(
            "The command supports attempted tool transfer or possible payload staging; transfer success is not established."
        )
    elif has_download_event:
        supported_inferences.append(
            "A file was transferred into the honeypot; this does not by itself establish execution."
        )
    if "execution" in tactic_set:
        supported_inferences.append("Trusted command evidence supports execution behavior within the honeypot.")
    if "persistence" in tactic_set:
        supported_inferences.append("Trusted command evidence supports a persistence-related action within the honeypot.")

    return {
        "type": "Unknown",
        "sophistication": "Unassessed",
        "description": "The observed behavior is insufficient to infer a reliable actor profile.",
        "observed_facts": observed_facts,
        "supported_inferences": supported_inferences,
        "unsupported_possibilities": [
            "Actor identity and group structure are not established.",
            "No behavior beyond the trusted commands and Cowrie events is asserted.",
        ],
        "assessment_semantics": "evidence_grounded_behavioral_profile_not_attribution",
    }


def _build_deterministic_executive_summary(
        source_ips: List[str],
        tactic_summary: Dict[str, List[str]],
        ttp_command_map: Dict[str, List[str]],
        primary_objective: str,
        ioc_bundle=None) -> str:
    """Create a readable, evidence-only fallback summary."""
    source_text = ", ".join(source_ips) if source_ips else "unknown source IP"
    commands = []
    for cmd_list in (ttp_command_map or {}).values():
        for cmd in cmd_list:
            text = str(cmd or "").strip()
            if text and text not in commands:
                commands.append(text)

    tactic_names = sorted(str(t) for t in (tactic_summary or {}).keys())
    tactic_text = ", ".join(tactic_names) if tactic_names else "no mapped tactics"
    command_text = (
        " Observed commands include "
        + "; ".join(f"`{cmd}`" for cmd in commands[:5])
        + "."
        if commands
        else " No shell commands were observed."
    )

    external_urls = []
    for url in getattr(ioc_bundle, "urls", []) or []:
        value = getattr(url, "value", "")
        if value and value not in external_urls:
            external_urls.append(value)
    url_text = (
        " External URLs were observed for payload/tool-transfer context: "
        + ", ".join(f"`{url}`" for url in external_urls[:3])
        + "; they are not treated as confirmed C2 or exfiltration without upload/exfil evidence."
        if external_urls
        else ""
    )

    return (
        f"Observed source IP {source_text} produced a session mapped to tactics: {tactic_text}. "
        f"The conservative objective is: {primary_objective or 'Under analysis'}."
        f"{command_text}{url_text}"
    )


def _build_campaign_correlation(ioc_bundle, source_ips: Optional[List[str]] = None) -> dict:
    """
    Correlate sessions across IPs to determine if this is a single
    coordinated campaign or independent actors.

    CHANGE FROM v1: reads raw_otx_pulse (not otx_pulse) â€” the former is the
    verbatim crowdsourced pulse name used as evidence for correlation logic.
    The synthesized campaign_hint is separate and must never be compared here.

    NEW: infrastructure correlation â€” if multiple IPs share the same host_type
    (e.g., all VPS from the same ISP) or both use Tor exit nodes, this is noted
    as an additional coordination signal.
    """
    pulses = {}
    otx_tags = set()
    asns = set()
    infra_tags_all = set()
    tor_count = 0
    vpn_count = 0
    host_types = []

    source_ip_set = {str(ip) for ip in (source_ips or []) if _is_real_ip(ip)}
    ip_items = list(getattr(ioc_bundle, "ips", []) or [])
    if source_ip_set:
        scoped = [ip for ip in ip_items if getattr(ip, "value", None) in source_ip_set]
        if scoped:
            ip_items = scoped

    for ip in ip_items:
        # Use raw_otx_pulse â€” the verbatim pulse name for correlation logic.
        # DO NOT use campaign_hint here; that is the synthesized output, not input.
        pulse = getattr(ip, 'raw_otx_pulse', None)
        tags  = getattr(ip, 'otx_tags', []) or []
        asn   = getattr(ip, 'asn', None)
        infra = getattr(ip, 'infrastructure_tags', []) or []

        if pulse:
            pulses[ip.value] = pulse
        otx_tags.update(tags)
        if asn:
            asns.add(asn)
        infra_tags_all.update(infra)
        if getattr(ip, 'is_tor_exit', False):
            tor_count += 1
        if getattr(ip, 'is_vpn', False):
            vpn_count += 1
        ht = getattr(ip, 'host_type', None)
        if ht:
            host_types.append(ht)

    unique_pulses = set(pulses.values())
    coordinated = len(unique_pulses) == 1 and len(ip_items) > 1

    # Infrastructure coordination signals
    infra_signals = []
    if tor_count > 1:
        infra_signals.append(f"{tor_count} IPs routing through Tor exit nodes")
    if vpn_count > 1:
        infra_signals.append(f"{vpn_count} IPs using VPN endpoints")
    if host_types:
        dominant_type = max(set(host_types), key=host_types.count)
        if host_types.count(dominant_type) > 1:
            infra_signals.append(
                f"majority of IPs are {dominant_type} infrastructure "
                f"({host_types.count(dominant_type)}/{len(host_types)})"
            )

    base_assessment = (
        f"Single coordinated campaign across {len(ip_items)} source IPs "
        f"from {len(asns)} ASN(s)" if coordinated else
        f"Multiple independent campaigns or actors across {len(asns)} ASN(s)"
    )
    if infra_signals:
        base_assessment += f". Infrastructure pattern: {'; '.join(infra_signals)}."

    return {
        "campaign_names": list(unique_pulses),   # raw pulse names â€” for display as evidence
        "common_tags":    list(otx_tags),
        "asns_observed":  list(asns),
        "infra_tags":     list(infra_tags_all),
        "tor_count":      tor_count,
        "vpn_count":      vpn_count,
        "coordinated":    coordinated,
        "assessment":     base_assessment,
    }


def _extract_attacker_playbook(ttp_command_map: Dict[str, List[str]]) -> dict:
    """
    Extract what the attacker was hunting for by parsing observed commands.

    This reveals their playbook against REAL targets â€” not what they found
    in the honeypot (which is fake), but what they were looking for.
    All extraction is from command string parsing, not TTP lookup.
    """
    credential_targets = []
    services_probed = []
    data_sought = []

    for ttp, commands in ttp_command_map.items():
        for cmd in commands:
            # Cloud credential files
            cloud_m = re.findall(
                r'(\.aws/credentials|\.config/gcloud/[^\s]+|'
                r'\.azure/[^\s]+|\.kube/config)', cmd
            )
            credential_targets.extend(cloud_m)

            # SSH keys
            ssh_m = re.findall(r'(\.ssh/id_[^\s]+|\.ssh/authorized_keys)', cmd)
            credential_targets.extend(ssh_m)

            # Generic secret patterns
            if re.search(r'grep.*?(password|passwd|secret|api_key|token)', cmd, re.I):
                data_sought.append("plaintext secrets in home directories")

            # Services being probed
            svc_m = re.findall(
                r'(nginx|apache|mysql|postgres|mongodb|redis|elasticsearch)',
                cmd, re.I
            )
            services_probed.extend([s.lower() for s in svc_m])

            # .netrc files
            if '.netrc' in cmd:
                credential_targets.append('.netrc (FTP/HTTP credentials)')

            # Web application config files
            web_m = re.findall(r'(config\.php|settings\.py|\.env|wp-config)', cmd)
            data_sought.extend(web_m)

    return {
        "credential_targets": list(dict.fromkeys(credential_targets)),
        "services_probed": list(dict.fromkeys(services_probed)),
        "data_sought": list(dict.fromkeys(data_sought))
    }


def _build_campaign_intelligence(playbook: dict,
                                 campaign_correlation: dict,
                                 ioc_bundle,
                                 vt_intel: Dict[str, Any] = None) -> str:
    """
    Produce a campaign intelligence summary for real organisations.

    Replaces the asset register â€” instead of 'what did WE lose', this answers
    'what should REAL organisations running similar infrastructure check.'
    Derived entirely from observed attacker behaviour.

    CHANGES FROM v1:
      - Surfaces confirmed VT malware family names when available.
      - Notes origin masking (Tor/VPN) as an operational security indicator
        that real defenders should be aware of in their log analysis.
      - Uses campaign_correlation infra_tags field (new in v2).
    """
    vt_intel = vt_intel or {}
    lines = []

    creds = playbook.get("credential_targets", [])
    if creds:
        lines.append(
            f"Organisations should immediately audit: "
            f"{', '.join(f'`{c}`' for c in creds[:5])} â€” "
            f"these were specifically sought by this campaign."
        )

    services = playbook.get("services_probed", [])
    if services:
        lines.append(
            f"Web/database servers running "
            f"{', '.join(services[:4])} are likely targets â€” "
            f"review access logs for these services."
        )

    tags = campaign_correlation.get("common_tags", [])
    if tags:
        lines.append(
            f"OTX intelligence tags for this campaign: "
            f"{', '.join(tags)} â€” search your SIEM for these indicators."
        )

    otx_pulses = campaign_correlation.get("campaign_names", [])
    if otx_pulses:
        lines.append(
            f"OTX pulse corroboration: {'; '.join(otx_pulses)}. "
            f"Cross-reference with threat intelligence platforms for additional IOC lists. "
            f"Note: pulse names are crowdsourced and may be low quality."
        )

    # Infrastructure origin masking â€” tells defenders what to look for in logs
    tor_count = campaign_correlation.get("tor_count", 0)
    vpn_count = campaign_correlation.get("vpn_count", 0)
    if tor_count > 0 or vpn_count > 0:
        masking_parts = []
        if tor_count:
            masking_parts.append(f"{tor_count} Tor exit node(s)")
        if vpn_count:
            masking_parts.append(f"{vpn_count} VPN endpoint(s)")
        lines.append(
            f"Attacker used origin masking via {' and '.join(masking_parts)}. "
            f"Source IPs may not represent the true operator location. "
            f"Block the observed IPs but treat geolocation attribution with low confidence."
        )

    c2_urls = [u.value for u in ioc_bundle.urls]
    if c2_urls:
        lines.append(
            f"Block observed external URLs at perimeter/proxy until reviewed: "
            f"{', '.join(f'`{u}`' for u in c2_urls[:5])}"
        )

    # VT-confirmed malware families â€” surface for defensive hunting
    vt_families = vt_intel.get("malware_families", [])
    if vt_intel.get("has_hits") and vt_families:
        lines.append(
            f"VirusTotal confirmed malware family association: "
            f"{', '.join(vt_families)}. "
            f"Hunt for these families across endpoints and update EDR signatures."
        )

    return " ".join(lines) if lines else "Insufficient data for campaign intelligence."


def _build_ioc_table(raw_events: List[dict], ioc_bundle, sessions: List[Any]) -> dict:
    """
    Build IOC table entirely from observed data.

    File hashes come from cowrie.session.file_download events.
    Accounts come from parsed useradd/usermod commands in sessions.
    SSH keys come from authorized_keys commands.
    """
    # File hashes â€” from honeypot download events
    file_hashes = {}
    c2_urls = set()
    for event in raw_events:
        if event.get('eventid') == 'cowrie.session.file_download':
            outfile = event.get('outfile', '')
            shasum = event.get('shasum', '')
            url = event.get('url', '')
            if outfile and shasum:
                file_hashes[outfile] = shasum
            if url:
                c2_urls.add(url)

    # Accounts and SSH keys from command parsing
    created_accounts = set()
    implanted_keys = set()
    suspicious_paths = set()

    for s in sessions:
        for cmd in getattr(s, 'commands_success', []):
            # Account creation
            m = re.search(r'useradd\s+(?:-\S+\s+)*(\w+)', cmd)
            if m:
                created_accounts.add(m.group(1))
            # SSH key implantation
            m = re.search(r'(ssh-\w+\s+\S+)\s*>>', cmd)
            if m:
                implanted_keys.add(m.group(1)[:80])
            # Suspicious file paths (tmp, hidden files)
            paths = re.findall(r'(/tmp/\.[^\s]+|/var/tmp/\.[^\s]+|'
                               r'/dev/shm/[^\s]+)', cmd)
            suspicious_paths.update(paths)

    external_urls = list(c2_urls | {u.value for u in ioc_bundle.urls})
    return {
        "source_ips": [ip.value for ip in ioc_bundle.ips],
        # external_urls is the accurate field. c2_urls is kept only for schema
        # compatibility and remains empty unless a future parser can confirm C2.
        "external_urls": external_urls,
        "c2_urls": [],
        "file_hashes": file_hashes,
        "suspicious_paths": list(suspicious_paths),
        "created_accounts": list(created_accounts),
        "implanted_ssh_keys": list(implanted_keys)
    }


# Labels for timeline events â€” generated from event data, not hardcoded strings.
_TIMELINE_LABEL_FNS = {
    "cowrie.session.connect": lambda e: (
        f"Connection from {e.get('src_ip', '?')}:{e.get('src_port', '?')}"
    ),
    "cowrie.login.failed": lambda e: (
        f"Failed login â€” user {e.get('username', '?')} "
        f"from {e.get('src_ip', '?')}"
    ),
    "cowrie.login.success": lambda e: (
        f"Successful login â€” user {e.get('username', '?')} "
        f"from {e.get('src_ip', '?')}"
    ),
    "cowrie.session.file_download": lambda e: (
        f"File downloaded to {e.get('outfile', '?')} "
        f"from {e.get('url', '?')} "
        f"(SHA256: {e.get('shasum', 'unknown')[:16]}...)"
    ),
    "cowrie.session.closed": lambda e: (
        f"Session closed from {e.get('src_ip', '?')} "
        f"(duration: {e.get('duration', '?')}s)"
    ),
}

# Which event types are significant enough for the key events list.
_SIGNIFICANT_EVENTS = {
    "cowrie.login.success",
    "cowrie.session.file_download",
}


def _timeline_event_key(event: dict) -> tuple:
    """Return a stable key for suppressing duplicate human timeline entries."""
    timestamp = str(event.get("timestamp") or "")[:19]
    if event.get("eventid") == "cowrie.login.success":
        return (
            event.get("eventid", ""),
            timestamp,
            event.get("src_ip", ""),
            event.get("username", ""),
        )
    return (
        event.get("eventid", ""),
        timestamp,
        event.get("src_ip", ""),
        event.get("username", ""),
        event.get("url", ""),
        event.get("outfile", ""),
        event.get("shasum", ""),
    )


def _build_attack_timeline(raw_events: List[dict]) -> dict:
    """
    Build attack timeline from raw Cowrie events.

    SUPPORTED FORMATS:
      A. Raw Cowrie JSON (correct):
            {"eventid": "cowrie.login.success", "timestamp": "...",
             "src_ip": "...", "username": "...", "password": "..."}
         Produced by: json.load(cowrie_log) or cowrie_raw_events from 1A adapter.

      B. Processed process-tree format (fallback, limited):
            {"UtcTime": "...", "_src_ip": "...", "CommandLine": "...",
             "_is_shell_node": True, "_file_hash": "...", "_success": True}
         Produced by: raw_input from cowrie_to_events() â€” this is the WRONG
         variable to pass. The timeline will only show session-start and file
         download events. Login usernames will not appear.
         Root cause: cowrie_to_events() discards original eventid structure.
         Fix: use cowrie_raw_events (3rd return value from updated 1A adapter).

    Label text is generated by _TIMELINE_LABEL_FNS â€” format strings over
    event fields. No sentence about specific attackers is written in this file.
    """
    if not raw_events:
        return {}

    # Raw telemetry remains authoritative in storage.  The reporting timeline
    # operates only on a centrally redacted projection so credentials embedded
    # in commands, URLs, exception text, or unexpected fields cannot escape.
    safe_events = [
        _safe_reporting_mapping(event, "timeline event")
        for event in raw_events
        if isinstance(event, dict)
    ]
    if not safe_events:
        return {}

    # Inspect the first event to determine which format we have.
    sample = safe_events[0]
    is_raw_cowrie = 'eventid' in sample
    is_processed  = 'UtcTime' in sample and '_src_ip' in sample

    if not is_raw_cowrie and is_processed:
        # Warn clearly so the caller knows to fix the variable they're passing.
        print(
            "[Timeline] WARNING: received processed process-tree events (raw_input), "
            "not raw Cowrie events (cowrie_raw_events). "
            "Timeline will be incomplete â€” login usernames unavailable. "
            "Fix: update 1A adapter call to unpack 3-tuple and pass cowrie_raw_events."
        )
        return _build_attack_timeline_from_processed(safe_events)

    if not is_raw_cowrie:
        print("[Timeline] WARNING: unrecognised event format â€” timeline skipped.")
        return {}

    timestamps = [e.get('timestamp', '') for e in safe_events if e.get('timestamp')]
    if not timestamps:
        return {}

    first = min(timestamps)
    last  = max(timestamps)

    key_events = []
    seen_event_keys = set()
    for event in safe_events:
        eid = event.get('eventid', '')
        if eid in _SIGNIFICANT_EVENTS and eid in _TIMELINE_LABEL_FNS:
            event_key = _timeline_event_key(event)
            if event_key in seen_event_keys:
                continue
            seen_event_keys.add(event_key)
            key_events.append({
                "timestamp": event.get('timestamp', ''),
                "event":     _TIMELINE_LABEL_FNS[eid](event),
                "src_ip":    event.get('src_ip', '')
            })

    key_events.sort(key=lambda x: x['timestamp'])

    return {
        "first_seen": first,
        "last_seen":  last,
        "key_events": key_events
    }


def _build_attack_timeline_from_processed(processed_events: List[dict]) -> dict:
    """
    Fallback timeline builder for the process-tree format produced by cowrie_to_events().

    This format has no eventid, username, or password fields. We can only infer:
      - Session starts:    _is_shell_node=True  (implies successful login)
      - File downloads:    _file_hash != ''     (command was wget/curl download)

    Called automatically by _build_attack_timeline when the wrong format is detected.
    Do NOT call directly â€” always call _build_attack_timeline().
    """
    timestamps = [e.get('UtcTime', '') for e in processed_events if e.get('UtcTime')]
    if not timestamps:
        return {}

    first = min(timestamps)
    last  = max(timestamps)

    key_events = []
    seen_sessions = set()

    for event in processed_events:
        ts  = event.get('UtcTime', '')
        ip  = event.get('_src_ip', '?')
        sid = event.get('_session_id', '')

        # Session start (shell node = session with at least one command = login succeeded)
        if event.get('_is_shell_node') and sid not in seen_sessions:
            seen_sessions.add(sid)
            key_events.append({
                "timestamp": ts,
                "event":     f"Session established from {ip} (login successful â€” credentials unavailable in processed format)",
                "src_ip":    ip
            })

        # File download (command node with a file hash)
        file_hash = event.get('_file_hash', '')
        cmd_line  = event.get('CommandLine', '')
        if file_hash and not event.get('_is_shell_node'):
            key_events.append({
                "timestamp": ts,
                "event":     (f"File downloaded via '{cmd_line[:60]}' "
                              f"(SHA256: {file_hash[:16]}...)"),
                "src_ip":    ip
            })

    key_events.sort(key=lambda x: x['timestamp'])

    return {
        "first_seen": first,
        "last_seen":  last,
        "key_events": key_events
    }


def _predict_next_action(ttp_command_map: Dict[str, List[str]],
                         ioc_bundle,
                         tactic_summary: Dict[str, List[str]],
                         ordered_behavior_chain: List[Dict[str, Any]] = None) -> str:
    """
    Predict attacker's next action from last observed technique and enrichment.

    Derived from:
      1. Artefacts extracted from the last observed commands (accounts, keys, crons).
      2. OTX tags from enriched IPs (cloud theft, backdoor, etc.).
      3. Infrastructure tags â€” Tor/VPN presence suggests deliberate origin masking,
         which predicts the operator will rotate infrastructure before re-entry.

    No TTPâ†’prediction lookup table.
    """
    predictions = []

    chain = [item for item in ordered_behavior_chain or [] if isinstance(item, dict)]
    if chain:
        final_command = str(chain[-1].get("command") or "").strip()
    else:
        flattened = [
            str(command).strip()
            for commands in (ttp_command_map or {}).values()
            for command in commands or []
            if str(command).strip()
        ]
        final_command = flattened[-1] if flattened else ""

    if final_command:
        m = re.search(r'\b(?:useradd|adduser)\b\s+(?:-\S+\s+)*(\w+)', final_command)
        if m:
            predictions.append(
                f"Possible follow-on re-entry attempt using the observed account `{m.group(1)}`; "
                "account creation success is not established"
            )
        if 'authorized_keys' in final_command:
            predictions.append(
                "Possible follow-on re-entry attempt using the observed SSH public-key modification; "
                "successful key installation is not established"
            )
        if 'crontab' in final_command.lower():
            path_m = re.search(r'(/tmp/\S+|/var/tmp/\S+)', final_command)
            path = path_m.group(1) if path_m else "the referenced command"
            predictions.append(
                f"Possible scheduled execution of `{path}`; subsequent execution is not observed"
            )
        if re.search(r"\b(?:curl|wget|tftp|ftp)\b\s+\S+", final_command, re.IGNORECASE):
            predictions.append(
                "Possible later execution of an artifact referenced by the final observed downloader command; "
                "successful transfer, execution, and persistence are not established"
            )

    command_text = "\n".join(
        str(command).lower()
        for commands in (ttp_command_map or {}).values()
        for command in commands or []
    )
    observed_cloud_credential_access = bool(re.search(
        r"(?:\.aws/credentials|\.config/gcloud|application_default_credentials)",
        command_text,
    ))
    observed_persistence_change = bool(re.search(
        r"(?:useradd|adduser|authorized_keys|crontab|systemctl\s+(?:enable|start))",
        command_text,
    ))
    observed_downloader = any(
        str(ttp).split(".", 1)[0] == "T1105"
        and any(re.search(r"\b(?:curl|wget|tftp|ftp)\b\s+\S+", str(cmd), re.IGNORECASE) for cmd in commands or [])
        for ttp, commands in (ttp_command_map or {}).items()
    )
    observed_payload_execution = bool(re.search(
        r"(?:(?:^|[;&|]\s*)(?:sh|bash|python\d*|perl)\s+(?:/tmp|/var/tmp|/dev/shm)/|"
        r"(?:^|[;&|]\s*)(?:\./|/tmp/|/var/tmp/|/dev/shm/)[^\s;&|]+)",
        command_text,
        re.IGNORECASE | re.MULTILINE,
    ))
    if observed_downloader and not observed_payload_execution and not predictions:
        predictions.append(
            "Possible follow-on execution of an artifact referenced by the observed downloader command; "
            "successful download, execution, and persistence are not confirmed"
        )
    if observed_cloud_credential_access and final_command and re.search(
        r"(?:\.aws/credentials|\.config/gcloud|application_default_credentials)",
        final_command,
    ):
        predictions.append(
            "Possible follow-on cloud API access using credentials referenced in the observed commands; "
            "successful use is not confirmed"
        )
    if observed_persistence_change and final_command and re.search(
        r"(?:useradd|adduser|authorized_keys|crontab|systemctl\s+(?:enable|start))",
        final_command,
        re.IGNORECASE,
    ):
        predictions.append(
            "Possible follow-on access through the observed persistence-related account or SSH-key change"
        )

    if not predictions:
        return "Insufficient evidence to construct a falsifiable follow-on hypothesis."

    return "; ".join(list(dict.fromkeys(predictions))[:3])


def _soften_follow_on_hypothesis(value: Any) -> str:
    """Normalize follow-on text as a bounded hypothesis rather than a fact."""

    text = str(value or "").strip()
    if not text or text.lower().startswith("insufficient evidence"):
        return "Insufficient evidence to construct a falsifiable follow-on hypothesis."
    text = re.sub(r"\bwill likely\b", "may", text, flags=re.IGNORECASE)
    text = re.sub(r"\bwill\b", "may", text, flags=re.IGNORECASE)
    if not re.search(r"\b(possible|possibly|may|might|hypothesis)\b", text, re.IGNORECASE):
        text = f"Possible follow-on behavior: {text}"
    return text


def _summarize_correlation_evidence(correlation: Dict[str, Any]) -> List[str]:
    """Create compact analyst-readable evidence strings for correlation rules."""

    summaries: List[str] = []
    evidence_items = correlation.get("evidence") or []
    if not isinstance(evidence_items, list):
        evidence_items = []
    for item in evidence_items:
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type") or "").strip()
        if item_type in {"command", "classification_event"}:
            command = str(item.get("command") or item.get("original_command") or "").strip()
            if command:
                summaries.append(f"command: {command[:220]}")
                continue
        if item_type == "raw_event":
            eventid = str(item.get("eventid") or "").strip()
            detail = str(item.get("input") or item.get("outfile") or item.get("shasum") or "").strip()
            summaries.append(f"event: {eventid} {detail}".strip()[:240])
            continue
        if item_type in {"tactic_sequence", "ttp_sequence"}:
            sequence = item.get("sequence") or []
            required = item.get("required_sequence") or []
            summaries.append(f"{item_type}: observed={sequence} required={required}"[:240])
            continue
        if item_type in {"evidence_graph_flag", "evidence_graph_count", "event_count", "login_failures"}:
            summaries.append(json.dumps(item, sort_keys=True, ensure_ascii=False)[:240])
            continue
    if not summaries:
        for result in correlation.get("matched_conditions") or []:
            if not isinstance(result, dict):
                continue
            description = str(result.get("description") or "").strip()
            if description:
                summaries.append(description[:240])
    return list(dict.fromkeys(summaries))[:8]


def _build_session_correlation_hunting_context(
        session_correlations: List[Dict[str, Any]] = None,
        session_id: str = "") -> Dict[str, Any]:
    """Normalize session-level correlations for post-session hunting reports.

    These entries are deliberately represented as hunting hypotheses/correlations,
    not as raw command classifications. A correlation can support the threat
    hypothesis, but its `source_type`, `confidence`, and evidence must remain
    visible so analysts can judge trust.
    """

    findings: List[Dict[str, Any]] = []
    source_counts: Counter = Counter()
    tactic_counts: Counter = Counter()
    for item in session_correlations or []:
        if not isinstance(item, dict):
            continue
        main_ttp = str(item.get("ttp") or "").strip()
        tactic = str(item.get("tactic") or "").strip()
        source_type = str(item.get("source_type") or "").strip()
        if source_type:
            source_counts[source_type] += 1
        if tactic:
            tactic_counts[tactic] += 1
        finding = {
            "session_id": str(item.get("session_id") or session_id or "unknown"),
            "correlation_id": str(item.get("correlation_id") or ""),
            "rule_id": str(item.get("rule_id") or ""),
            "correlation_rule_fired": str(item.get("rule_id") or ""),
            "predicted_technique": {
                "main_ttp": main_ttp,
                "technique_name": str(item.get("technique_name") or main_ttp),
                "tactic": tactic,
            },
            "main_ttp": main_ttp,
            "source_ttp": str(item.get("source_ttp") or main_ttp),
            "source_subtechnique": str(item.get("source_subtechnique") or ""),
            "technique_granularity": str(item.get("technique_granularity") or "parent"),
            "source_type": source_type,
            "confidence": item.get("confidence"),
            "evidence_type": str(item.get("evidence_type") or ""),
            "temporal_claim": bool(item.get("temporal_claim", False)),
            "apply_to_prediction": bool(item.get("apply_to_prediction", False)),
            "reason": str(item.get("reason") or ""),
            "evidence": _summarize_correlation_evidence(item),
            "matched_conditions": item.get("matched_conditions") or [],
            "references": item.get("references") or [],
            "provenance": item.get("provenance") or {},
        }
        findings.append(finding)

    return {
        "schema_version": "session_threat_hunting_context.v1",
        "session_id": session_id or (findings[0]["session_id"] if findings else "unknown"),
        "status": "available" if findings else "not_available",
        "interpretation": (
            "Session correlations are post-session hunting hypotheses. They support "
            "analyst triage and threat-hunting leads, but they do not replace raw "
            "command-level classifications."
        ),
        "correlation_count": len(findings),
        "correlation_rules_fired": [item["rule_id"] for item in findings if item.get("rule_id")],
        "main_ttps": sorted({item["main_ttp"] for item in findings if item.get("main_ttp")}),
        "source_type_counts": dict(sorted(source_counts.items())),
        "tactic_counts": dict(sorted(tactic_counts.items())),
        "session_correlations": findings,
    }


def _detect_target_platform(
        sessions: List[Any],
        ttp_command_map: Dict[str, List[str]],
        platform_rules: dict = None,
        mitre_db=None,
        detected_ttps: List[str] = None) -> str:
    """
    Deterministically detect the target platform from observed command evidence.

    Signal priority:
      1. Command-based evidence (most authoritative â€” actual attacker commands)
         Signals loaded from platform_rules (config.json) â€” no hardcoded lists.
      2. MITRE ATT&CK platform data for detected TTPs (tiebreaker when no commands)

    Mixed signals (e.g. vssadmin on Linux) are preserved as 'Multi-platform (Linux+Windows)'
    and noted as a cross-OS error indicator.
    """
    platform_rules = platform_rules or {}

    # config.json keys: linux, windows, cloud, web_application, database, network_device
    # These replace the old hardcoded _linux_signals / _windows_signals lists.
    _linux_signals   = platform_rules.get('linux', [
        # Minimal safety net â€” only used if config.json fails to load
        '/etc/', 'bash', 'chmod', 'crontab', 'authorized_keys'
    ])
    _windows_signals = platform_rules.get('windows', [
        'powershell', 'cmd.exe', 'vssadmin', 'net user ', 'reg add'
    ])
    _network_signals = platform_rules.get('network_device', [
        'show running-config', 'show ip route', 'enable secret', 'conf t'
    ])
    _cloud_signals   = platform_rules.get('cloud', [])

    all_cmds: List[str] = []
    for cmds in ttp_command_map.values():
        all_cmds.extend(str(c).lower() for c in cmds)
    for s in sessions:
        all_cmds.extend(str(c).lower() for c in getattr(s, 'commands_success', []))

    if all_cmds:
        linux_hits   = sum(1 for cmd in all_cmds
                           if any(sig in cmd for sig in _linux_signals))
        windows_hits = sum(1 for cmd in all_cmds
                           if any(sig in cmd for sig in _windows_signals))
        network_hits = sum(1 for cmd in all_cmds
                           if any(sig in cmd for sig in _network_signals))
        cloud_hits   = sum(1 for cmd in all_cmds
                           if any(sig in cmd for sig in _cloud_signals))

        if network_hits > linux_hits and network_hits > windows_hits:
            return 'Network Device'
        if cloud_hits > linux_hits and cloud_hits > windows_hits:
            return 'Cloud (IaaS/Container)'
        if linux_hits > 0 and windows_hits == 0:
            return 'Linux'
        if windows_hits > 0 and linux_hits == 0:
            return 'Windows'
        if linux_hits > 0 and windows_hits > 0:
            if linux_hits >= windows_hits * 3:
                return 'Linux (cross-OS command errors detected)'
            return 'Multi-platform (Linux + Windows indicators observed)'

    # Used when no command evidence exists (connection observed but no commands)
    if mitre_db and detected_ttps:
        mitre_platforms: Dict[str, int] = {}
        for ttp in detected_ttps:
            for plat in mitre_db.get_platforms(ttp):
                mitre_platforms[plat] = mitre_platforms.get(plat, 0) + 1
        if mitre_platforms:
            top = max(mitre_platforms, key=mitre_platforms.get)
            # Normalise MITRE platform names to match our output format
            plat_map = {
                'Linux': 'Linux', 'macOS': 'macOS', 'Windows': 'Windows',
                'Containers': 'Cloud (IaaS/Container)', 'IaaS': 'Cloud (IaaS/Container)',
                'Network': 'Network Device',
            }
            return plat_map.get(top, top) + ' (MITRE inferred â€” no command evidence)'

    return 'Unknown'


def _build_legacy_falsification_conditions(
        ttp_command_map: Dict[str, List[str]],
        ioc_bundle,
        raw_events: List[dict] = None) -> List[str]:
    """
    Generate scientifically valid falsification conditions from observed artefacts.

    SCIENTIFIC METHODOLOGY:
    A falsification condition answers: 'What observable evidence, if absent after
    monitoring, would DISPROVE this prediction?'

    It is NOT an impact assessment ('no encrypted files found').
    It is NOT a result of a defensive action ('no connection after firewall block').

    Correct structure:
      'After [monitoring action] for [time window], if [specific observable] is
      absent, then [specific prediction] is falsified.'

    Each condition must:
      1. Name a specific monitoring action (log review, network capture, etc.)
      2. Specify a time window
      3. Describe the specific observable to look for
      4. Name the hypothesis component it would disprove
    """
    conditions = []
    seen = set()
    raw_events = raw_events or []

    def add(cond: str):
        if cond not in seen:
            seen.add(cond)
            conditions.append(cond)

    all_cmds_flat = [
        (ttp, cmd) for ttp, cmds in ttp_command_map.items()
        for cmd in cmds[:2]
    ]
    all_command_text = "\n".join(str(cmd) for _, cmd in all_cmds_flat)
    has_downloader = any(
        str(ttp).split(".", 1)[0] == "T1105"
        and re.search(r"\b(?:curl|wget|tftp|ftp)\b\s+\S+", str(cmd), re.IGNORECASE)
        for ttp, cmd in all_cmds_flat
    )
    has_payload_execution = any(
        str(ttp).split(".", 1)[0] == "T1059"
        for ttp, _ in all_cmds_flat
    ) or bool(re.search(
        r"(?:chmod\s+\+x|(?:^|[;&|]\s*)(?:sh|bash)\s+(?:/tmp|/var/tmp|/dev/shm)/|"
        r"(?:^|[;&|]\s*)(?:\./|/tmp/|/var/tmp/|/dev/shm/)[^\s;&|]+)",
        all_command_text,
        re.IGNORECASE | re.MULTILINE,
    ))
    has_persistence = bool(re.search(
        r"(?:useradd|adduser|authorized_keys|crontab|systemctl\s+(?:enable|start)|"
        r"(?:\.bashrc|\.profile|rc\.local))",
        all_command_text,
        re.IGNORECASE,
    ))
    has_successful_download_event = any(
        isinstance(event, dict)
        and str(event.get("eventid") or "") == "cowrie.session.file_download"
        for event in raw_events
    )

    if has_downloader and not has_payload_execution:
        add(
            "Review subsequent Cowrie command and process events for this session and linked sessions "
            "for 7 days: if no downloaded or staged artifact is executed, the payload-execution "
            "follow-on hypothesis is falsified."
        )
        if not has_persistence:
            add(
                "Review subsequent Cowrie commands and file-change telemetry for 7 days: if no account, "
                "SSH-key, scheduled-task, service, or shell-startup modification is observed, the "
                "persistence follow-on hypothesis is falsified."
            )
        if not has_successful_download_event:
            add(
                "Review the session's Cowrie raw events: if no `cowrie.session.file_download` event or "
                "explicit successful-download metadata is present, a successful payload transfer is not "
                "established and the confirmed-download interpretation is falsified."
            )

    for ttp, cmd in all_cmds_flat:
        cmd_l = cmd.lower()

        # SSH key exfiltration â†’ predict lateral movement via stolen key
        if re.search(r'id_rsa|authorized_keys|ssh.{0,10}key', cmd_l):
            m = re.search(r'https?://([\d.]+[^\s]*)', cmd)
            dest = m.group(0) if m else 'the observed C2 endpoint'
            add(
                f"Monitor internal SSH authentication logs for 30 days: "
                f"if no successful login attempts are observed from any IP not "
                f"on the approved access list using a key fingerprint derived from "
                f"`/root/.ssh/id_rsa` or `~/.ssh/id_rsa`, the lateral-movement-via-stolen-key "
                f"hypothesis is falsified."
            )

        # Cron persistence â†’ predict scheduled payload execution
        if 'crontab' in cmd_l:
            path_m = re.search(r'(/tmp/\S+|/var/tmp/\S+)', cmd)
            path = path_m.group(1) if path_m else '/tmp/<payload>'
            add(
                f"After removing the cron entry, monitor process execution logs "
                f"(e.g. auditd or /var/log/syslog) for 7 days: if `{path}` is "
                f"never executed by cron or any other scheduled mechanism, the "
                f"persistence hypothesis is falsified."
            )

        # Systemd persistence â†’ predict service auto-restart
        if 'systemctl enable' in cmd_l or 'systemctl start' in cmd_l:
            svc_m = re.search(r'systemctl\s+(?:enable|start)\s+(\S+)', cmd)
            svc = svc_m.group(1) if svc_m else '<malicious service>'
            add(
                f"After removing systemd unit `{svc}`, reboot the host and inspect "
                f"`systemctl list-units --all` within 1 hour: if `{svc}` does not "
                f"reappear in the unit list, the self-reinstalling persistence hypothesis "
                f"is falsified."
            )

        # C2 beacon â†’ predict continued callback traffic
        m = re.search(r'curl.{0,30}(https?://[\d.]+:\d+[^\s]*)', cmd)
        if m:
            url = m.group(1)
            add(
                f"Capture all outbound traffic to `{url}` for 72 hours after blocking: "
                f"if no TLS/HTTP connection attempts are observed from any internal host "
                f"to this endpoint (including from new IPs not yet blocked), the active-C2 "
                f"hypothesis is falsified."
            )

        # XMRig / miner deployment â†’ predict CPU anomaly
        if any(k in cmd_l for k in ['xmrig', 'monero', 'pool.', 'minerd', 'cryptominer']):
            add(
                "Monitor host CPU utilisation via the monitoring platform for 7 days: "
                "if sustained CPU usage >80% correlated with network connections to mining "
                "pool IP ranges is absent, the cryptomining persistence hypothesis is falsified."
            )

        # Ransomware / backup destruction â†’ predict encrypted or missing files
        if any(k in cmd_l for k in ['vssadmin', 'rm -rf /var/backups', 'enc.sh', '.enc']):
            add(
                "Run `find / -name '*.enc' -o -name '*.locked' -newer /var/log/auth.log 2>/dev/null` "
                "within 24 hours: if no files with ransomware extensions and a modification "
                "timestamp matching the attack window are present, the file-encryption "
                "execution hypothesis is falsified (note: attacker may have failed to execute)."
            )

        # Cloud credentials â†’ predict cloud API abuse
        m = re.search(
            r'cat\s+(/home/[^/]+/\.aws/credentials|/home/[^/]+/\.config/gcloud/[^\s]+)', cmd
        )
        if m:
            add(
                f"Review cloud provider audit logs (AWS CloudTrail / GCP Audit Log) for 14 days: "
                f"if no API calls are observed from IP addresses other than approved corporate "
                f"egress IPs using credentials stored at `{m.group(1)}`, the cloud-credential-abuse "
                f"hypothesis is falsified."
            )

    # If prediction is lateral movement via SSH keys
    has_exfil = any(
        re.search(r'curl.*post|wget.*post|id_rsa', cmd.lower())
        for _, cmd in all_cmds_flat
    )
    if has_exfil and not conditions:
        add(
            "Monitor internal network authentication logs and East-West SSH traffic for 30 days: "
            "if no SSH session is initiated from any host using a key fingerprint matching the "
            "exfiltrated key (`/root/.ssh/id_rsa`), the lateral-movement prediction is falsified."
        )

    return conditions[:6]  # cap at 6 â€” quality over quantity


def _build_falsification_conditions(
        ttp_command_map: Dict[str, List[str]],
        ioc_bundle,
        raw_events: List[dict] = None) -> List[str]:
    """Return only disconfirming observations available in Cowrie telemetry.

    Checks requiring endpoint, cloud, EDR, or enterprise authentication logs are
    external validation suggestions in the v2 schema, not falsification facts.
    """

    raw_events = [event for event in raw_events or [] if isinstance(event, dict)]
    commands = [
        str(command).strip()
        for values in (ttp_command_map or {}).values()
        for command in values or []
        if str(command).strip()
    ]
    command_text = "\n".join(commands)
    has_downloader = bool(re.search(r"\b(?:curl|wget|tftp|ftp)\b\s+\S+", command_text, re.IGNORECASE))
    has_execution = bool(re.search(
        r"(?:(?:^|[;&|]\s*)(?:sh|bash|python\d*|perl)\s+(?:/tmp|/var/tmp|/dev/shm)/|"
        r"(?:^|[;&|]\s*)(?:\./|/tmp/|/var/tmp/|/dev/shm/)\S+)",
        command_text,
        re.IGNORECASE | re.MULTILINE,
    ))
    has_persistence = bool(re.search(
        r"\b(?:useradd|adduser)\b|authorized_keys|\bcrontab\b|"
        r"\bsystemctl\s+(?:enable|start)\b|(?:\.bashrc|\.profile|rc\.local)",
        command_text,
        re.IGNORECASE,
    ))
    has_download_event = any(
        str(event.get("eventid") or "") == "cowrie.session.file_download"
        for event in raw_events
    )
    failed_commands = [
        str(event.get("input") or "").strip()
        for event in raw_events
        if str(event.get("eventid") or "") == "cowrie.command.failed"
        and str(event.get("input") or "").strip()
    ]

    conditions: List[str] = []
    if has_downloader and not has_download_event:
        conditions.append(
            "No `cowrie.session.file_download` event or explicit successful-download metadata "
            "was observed; a successful-transfer interpretation is therefore unsupported."
        )
    if has_downloader and not has_execution:
        conditions.append(
            "No subsequent explicit artifact-execution command was observed in the captured "
            "Cowrie session; an execution follow-on is not confirmed by current telemetry."
        )
    if has_downloader and not has_persistence:
        conditions.append(
            "No account, SSH-key, scheduled-task, service, or shell-startup modification was "
            "observed in Cowrie; persistence is not supported by current telemetry."
        )
    for command in failed_commands[:3]:
        conditions.append(
            f"Cowrie reported failure for the observed command `{command[:160]}`; claims relying "
            "on successful completion of that command are disconfirmed."
        )
    return list(dict.fromkeys(conditions))[:6]



def _build_legacy_analytical_confidence(
        detected_ttps: List[str],
        sessions: List[Any],
        ioc_bundle,
        ai_enriched: bool,
        vt_intel: Dict[str, Any] = None,
        thresholds: Dict[str, int] = None) -> dict:
    """
    Derive heuristic analytical evidence strength, not prediction probability.

    Args:
        thresholds: dict from honeypot_config.alert_thresholds (config.json).
                    Keys: min_techniques_for_high_confidence,
                          min_techniques_for_medium_confidence
                    If not provided, falls back to config defaults (10, 5).
    Scoring factors:
      + Number of confirmed TTPs
      + OTX pulse corroboration (raw_otx_pulse present on any IP)
      + Confirmed C2 exfiltration destination
      + VirusTotal confirmed malware family (new in v2)
      - Evidence gap: cloud credential theft indicated but no cloud API log confirmation

    EXPLICIT RISK_SCORE GUARD:
      AbuseIPDB risk_score is intentionally NOT used here. It measures crowd
      complaint volume, not attacker sophistication. A fresh APT actor VPS will
      score 0 (no complaints yet). A Mirai bot scanning millions of IPs will
      score 100. Using risk_score to boost confidence would produce exactly the
      wrong result for APT detection. JA3/HASSH/infrastructure signals already
      cover what risk_score attempts to measure.
    """
    vt_intel = vt_intel or {}
    thresholds = thresholds or {}
    HIGH_TTP_THRESHOLD = thresholds.get('min_techniques_for_high_confidence', 10)
    MED_TTP_THRESHOLD  = thresholds.get('min_techniques_for_medium_confidence', 5)
    score = 0
    reasons = []

    if len(detected_ttps) >= HIGH_TTP_THRESHOLD:
        score += 2
        reasons.append(f"{len(detected_ttps)} trusted mapped techniques across sessions")
    elif len(detected_ttps) >= MED_TTP_THRESHOLD:
        score += 1
        reasons.append(f"{len(detected_ttps)} trusted mapped techniques")

    # External corroboration from OTX â€” use raw_otx_pulse (verbatim pulse name).
    # This checks whether any OTX pulse was associated with the observed IPs,
    # which provides external corroboration independent of our own analysis.
    has_otx = any(getattr(ip, 'raw_otx_pulse', None) for ip in ioc_bundle.ips)
    if has_otx:
        score += 1
        reasons.append("OTX pulse corroborates observed campaign pattern")

    command_text = "\n".join(
        str(cmd).lower()
        for session in sessions or []
        for cmd in getattr(session, "commands_success", []) or []
    )

    # Confirmed exfiltration requires upload/credential-exfil style evidence.
    # A URL in a wget/curl download is tool transfer context, not proof of C2 or
    # exfiltration by itself.
    has_exfil = bool(re.search(
        r'(curl\s+-x\s+post|curl\s+.*\bpost\b|wget\s+.*\bpost\b|'
        r'post\s+-d\s+@|collect/keys|exfil|id_rsa)',
        command_text,
        re.IGNORECASE,
    ))
    if has_exfil:
        score += 1
        reasons.append("credential/file exfiltration command confirmed in session commands")
    elif getattr(ioc_bundle, "urls", None):
        reasons.append(
            "external URL observed for payload/tool transfer; not counted as exfiltration"
        )

    # VT corroboration â€” a confirmed malware family is an independent data point
    if vt_intel.get("has_hits") and vt_intel.get("malware_families"):
        score += 1
        families = ', '.join(vt_intel["malware_families"][:2])
        reasons.append(f"VirusTotal confirmed malware family: {families}")

    # Evidence gap: cloud tag but no cloud API confirmation
    otx_tags = set()
    for ip in ioc_bundle.ips:
        otx_tags.update(getattr(ip, 'otx_tags', []) or [])
    if 'cloud-credential-theft' in otx_tags and not any(
        'cloudtrail' in str(getattr(ip, 'note', ''))
        for ip in ioc_bundle.ips
    ):
        score -= 1
        reasons.append(
            "cloud credential theft indicated but no cloud API activity confirmed"
        )

    if score >= 3:
        level = "High"
    elif score >= 1:
        level = "Medium"
    else:
        level = "Low"

    return {
        "level": level,
        "reason": ("; ".join(reasons)
                   if reasons else "Insufficient evidence for strength assessment"),
        "metric_name": "analytical_evidence_strength",
        "method": "heuristic_evidence_strength_v1",
        "calibrated_probability": False,
        "description": (
            "Heuristic strength of the evidence supporting the post-session analysis; "
            "this is not a calibrated prediction probability."
        ),
    }


def _build_analytical_confidence(
        detected_ttps: List[str],
        sessions: List[Any],
        ioc_bundle,
        ai_enriched: bool,
        vt_intel: Dict[str, Any] = None,
        thresholds: Dict[str, int] = None) -> dict:
    """Deprecated global-confidence alias for v2 claim-level evidence labels."""

    return {
        "level": "Unscored",
        "reason": (
            "Global analytical confidence was retired because behavioral observations, "
            "model scores, and external reputation are not a single calibrated quantity."
        ),
        "metric_name": "claim_evidence_summary",
        "method": "claim_level_evidence_status_v2",
        "calibrated_probability": False,
        "deprecated": True,
        "observed_candidate_mapping_count": len(set(detected_ttps or [])),
        "description": "Inspect each canonical claim's evidence_status and evidence_refs.",
    }


def _threat_hypothesis_semantics(follow_on: str) -> Dict[str, Any]:
    insufficient = str(follow_on or "").lower().startswith("insufficient evidence")
    return {
        "hypothesis_status": "insufficient_evidence" if insufficient else "supported_candidate",
        "scope": "post_session_cowrie_observable_behavior",
        "claim_type": "analytical_follow_on_hypothesis",
        "limitations": [
            "Not an exact next-command prediction.",
            "Not named-actor attribution.",
            "Does not confirm real-world compromise or impact outside the honeypot.",
            "Analytical evidence strength is heuristic and not a calibrated probability.",
        ],
    }


# MAIN COORDINATOR

_DEPENDENCY_UNSET = object()


class ImprovedAsyncSwarmCoordinator:
    """
    Enhanced async swarm coordinator â€” honeypot-aware threat hypothesis edition.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        max_tokens: int = 4000,
        mitre_name_map: dict = None,
        enable_vertex_narrative: bool = False,
        *,
        threat_intel_config: Optional[Dict[str, Any]] = None,
        threat_feeds: Any = _DEPENDENCY_UNSET,
        mitre_db: Any = _DEPENDENCY_UNSET,
        behavior_policy_document: Optional[Dict[str, Any]] = None,
        behavior_policy_path: str = "",
        classification_policy: Optional[Dict[str, Any]] = None,
        classification_rules_path: str = "",
        prediction_policy: Optional[Dict[str, Any]] = None,
        prediction_policy_path: str = "",
        prediction_context: Optional[Dict[str, Any]] = None,
        recommendation_asset_profile_path: str = "",
        recommendation_action_policy_path: str = "",
        cisa_cache_path: str = "",
        sigma_cache_path: str = "",
        mitre_cache_path: str = "",
        vertex_project_id: str = "",
        vertex_location: str = "",
        vertex_request_timeout_seconds: float = 45.0,
        vertex_outer_timeout_seconds: float = 50.0,
        vertex_max_retries: int = 2,
        vertex_retry_delay_seconds: float = 2.0,
    ):
        # base_url and model are accepted for backward compatibility with
        # existing notebook call sites, but VertexAIClient reads endpoint,
        # project, location, model, and auth from VERTEX_* / Google env vars.
        self.base_url = base_url
        self.model    = model
        self.budget   = TokenBudget(max_tokens=max_tokens)
        self.ai_client = GroqClient(
            self.budget,
            base_url=base_url,
            model=model,
            project_id=vertex_project_id,
            location=vertex_location,
            request_timeout_seconds=vertex_request_timeout_seconds,
            outer_timeout_seconds=vertex_outer_timeout_seconds,
            max_retries=vertex_max_retries,
            retry_delay_seconds=vertex_retry_delay_seconds,
        )
        self.enable_vertex_narrative = bool(enable_vertex_narrative)
        self.recommendation_asset_profile_path = str(
            recommendation_asset_profile_path or ""
        )
        self.recommendation_action_policy_path = str(
            recommendation_action_policy_path or ""
        )
        self.behavior_policy_document = (
            copy.deepcopy(behavior_policy_document)
            if isinstance(behavior_policy_document, dict)
            else None
        )
        self.behavior_policy_path = str(behavior_policy_path or "")
        self.classification_policy = copy.deepcopy(classification_policy or {})
        self.classification_rules_path = str(classification_rules_path or "")
        self.prediction_policy = (
            copy.deepcopy(prediction_policy)
            if isinstance(prediction_policy, dict)
            else None
        )
        self.prediction_policy_path = str(prediction_policy_path or "")
        self.prediction_context = copy.deepcopy(prediction_context or {})
        self.cisa_cache_path = str(cisa_cache_path or "")
        self.sigma_cache_path = str(sigma_cache_path or "")
        self.mitre_cache_path = str(mitre_cache_path or "")
        self.detected_ttps = []

        # Production passes an explicitly resolved MITRE dependency, including
        # None when loading is disabled. Legacy callers that omit it retain the
        # historical auto-load behavior.
        if mitre_db is not _DEPENDENCY_UNSET and mitre_db is not None:
            self.mitre_db = mitre_db
        elif mitre_name_map is not None:
            # Wrap legacy dict in a thin adapter so .get_tactics() etc. work
            from production.enrichment.mitre_attack_loader import MitreAttackDB, TechniqueRecord
            techniques = {
                tid: TechniqueRecord(tid=tid, name=name)
                for tid, name in mitre_name_map.items()
            }
            self.mitre_db = MitreAttackDB(techniques, version="custom")
        elif mitre_db is _DEPENDENCY_UNSET:
            # Best-practice path: load live data from MITRE ATT&CK STIX
            try:
                from production.enrichment.mitre_attack_loader import load_mitre_attack_db
                self.mitre_db = load_mitre_attack_db()
            except ImportError:
                from production.enrichment.mitre_attack_loader import MitreAttackDB
                self.mitre_db = MitreAttackDB({}, version="unavailable")
                print("  [Coordinator] production.enrichment.mitre_attack_loader not found - "
                      "technique IDs will display as-is")
        else:
            from production.enrichment.mitre_attack_loader import MitreAttackDB

            self.mitre_db = MitreAttackDB({}, version="disabled")

        # Backward-compat alias (existing code uses self.mitre_name_map.get())
        self.mitre_name_map = self.mitre_db

        if threat_intel_config is not None:
            self.config = copy.deepcopy(threat_intel_config)
        else:
            # Legacy notebook compatibility only. Production injects the
            # resolved document, including an explicit empty dictionary.
            base_dir = os.path.dirname(__file__)
            local_path = os.path.join(base_dir, 'configs', 'threat_intel_config.json')
            legacy_local_path = os.path.join(base_dir, 'threat_intel_config.json')
            colab_path = '/content/threat_intel_config.json'
            if os.path.exists(colab_path):
                config_path = colab_path
            elif os.path.exists(local_path):
                config_path = local_path
            else:
                config_path = legacy_local_path
            self.config = {}
            try:
                if os.path.exists(config_path):
                    with open(config_path, 'r', encoding='utf-8') as f:
                        loaded_config = json.load(f)
                    if isinstance(loaded_config, dict):
                        self.config = loaded_config
                else:
                    print(
                        "Config not found at "
                        f"{_safe_log_text(config_path)} â€” using internal defaults."
                    )
            except Exception as e:
                print(f"Could not load config: {_safe_exception_text(e)}")

        self.sophistication_rules = copy.deepcopy(
            self.config.get("sophistication_rules", {})
        )
        self.behavioral_rules = copy.deepcopy(
            self.config.get("behavioral_rules", {})
        )
        self.platform_rules = copy.deepcopy(
            self.config.get("platform_rules", {})
        )
        self.attack_type_rules = copy.deepcopy(
            self.config.get("attack_type_rules", {})
        )

        if threat_feeds is _DEPENDENCY_UNSET:
            try:
                from production.enrichment.threat_feed_loader import load_threat_feeds

                self.threat_feeds = load_threat_feeds()
            except ImportError:
                self.threat_feeds = None
                print("  [Coordinator] threat_feed_loader not found â€” "
                      "CISA KEV and Sigma enrichment disabled")
            except Exception as e:
                self.threat_feeds = None
                print(
                    "  [Coordinator] threat feeds init failed (non-fatal): "
                    f"{_safe_exception_text(e)}"
                )
        else:
            self.threat_feeds = threat_feeds

        if self.threat_feeds is not None:
            try:
            # Merge Sigma community keywords into sophistication_rules so the
            # scorer uses community-maintained detection terms alongside config.json
                sigma_high_kws = self.threat_feeds.sigma.get_keywords_for_level("high")
                sigma_medium_kws = self.threat_feeds.sigma.get_keywords_for_level("medium")
                sigma_brute_kws = self.threat_feeds.get_bruteforce_keywords()
                if sigma_high_kws:
                    existing_high = self.sophistication_rules.setdefault("high", {})
                    existing_high.setdefault("keywords", [])
                    existing_high["keywords"] = list(set(
                        existing_high["keywords"] + sigma_high_kws
                    ))
                if sigma_medium_kws:
                    existing_med = self.sophistication_rules.setdefault("medium", {})
                    existing_med.setdefault("keywords", [])
                    existing_med["keywords"] = list(set(
                        existing_med["keywords"] + sigma_medium_kws
                    ))
                if sigma_brute_kws:
                    existing_low = self.sophistication_rules.setdefault("low", {})
                    existing_low.setdefault("keywords", [])
                    existing_low["keywords"] = list(set(
                        existing_low["keywords"] + sigma_brute_kws
                    ))
                print(f"  [Coordinator] Sigma keywords merged: "
                      f"{len(sigma_high_kws)} high / "
                      f"{len(sigma_medium_kws)} medium / "
                      f"{len(sigma_brute_kws)} brute-force")
            except Exception as e:
                print(
                    "  [Coordinator] injected threat feeds could not provide "
                    f"Sigma keywords: {_safe_exception_text(e)}"
                )

    def _truncate_to_budget(self, text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        half = max_chars // 2
        omitted = len(text) - max_chars
        return (
            text[:half] +
            f"\n\n... [{omitted} chars omitted] ...\n\n" +
            text[-half:]
        )

    def _build_system_prompt(self) -> str:
        return CTIPrompts.SYSTEM_PROMPT

    async def analyze(self,
                      ioc_bundle: Any,
                      tactic_summary: Dict[str, List[str]],
                      sessions: List[Any],
                      bpg_list: List[Dict],
                      ttp_command_map: Dict[str, List[str]] = None,
                      raw_events: List[dict] = None,
                      session_correlations: List[Dict[str, Any]] = None) -> dict:
        """
        Main analysis entry point.

        raw_events: raw Cowrie event list passed through from 1A ingestion.
                    Required for IOC table (file hashes) and timeline construction.
        """
        raw_events = raw_events or []

        print("\n" + "=" * 70)
        print("HONEYPOT THREAT HYPOTHESIS â€” Deterministic-First Architecture")
        print("=" * 70)

        detected_ttps = list(set().union(*tactic_summary.values())) if tactic_summary else []
        self.detected_ttps = detected_ttps
        print(
            "Detected TTPs (Grounding Lock): "
            f"{_safe_log_text(detected_ttps)}"
        )

        if not detected_ttps:
            print("\nEARLY EXIT: No TTPs detected â€” returning fallback hypothesis")
            fallback = self._fallback_hypothesis(ioc_bundle, tactic_summary)
            decision = _build_trusted_recommendation_decision(
                sessions,
                raw_events,
                tactic_summary,
                ttp_command_map or {},
                mitre_db=self.mitre_db,
                asset_profile_path=self.recommendation_asset_profile_path,
                action_policy_path=self.recommendation_action_policy_path,
                prediction_snapshot=self.prediction_context,
            )
            actions = [
                item for item in decision.get("immediate_actions") or []
                if isinstance(item, dict)
            ]
            fallback["trusted_recommendation_decision"] = decision
            fallback["recommended_actions_structured"] = actions
            fallback["recommended_mitigations"] = [
                str(item.get("action") or "").strip()
                for item in actions
                if str(item.get("action") or "").strip()
            ]
            fallback["recommendation_provenance"] = {
                "authority": decision.get("authority") or "policy_unavailable",
                "status": decision.get("status") or "unavailable",
                "policy": (decision.get("trust") or {}).get("policy") or {},
                "policy_action_count": len(actions),
                "rejected_action_count": len(decision.get("rejected_actions") or []),
                "fallback_actions_allowed": False,
            }
            fallback_report = build_v2_report(
                fallback,
                sessions,
                raw_events=raw_events,
                behavior_policy_document=self.behavior_policy_document,
                behavior_policy_path=self.behavior_policy_path,
            )
            return _safe_reporting_mapping(
                attach_model_prediction(fallback_report, self.prediction_context),
                "report",
            )

        # STEP 1: Deterministic baseline
        print("\n[Step 1] Building deterministic baseline...")
        base_hypothesis = await self._build_deterministic_hypothesis(
            ioc_bundle, tactic_summary, sessions,
            ttp_command_map=ttp_command_map,
            raw_events=raw_events,
            session_correlations=session_correlations,
        )

        base_is_grounded, base_msg = JSONValidator.enforce_grounding_strict(
            base_hypothesis, detected_ttps
        )
        if not base_is_grounded:
            raise RuntimeError(f"Baseline hallucination detected: {base_msg}")
        print(f"  Baseline validated: {_safe_log_text(base_msg)}")

        normalized_base = self._normalize_hypothesis(
            base_hypothesis,
            ioc_bundle,
            tactic_summary,
            sessions,
            ttp_command_map=ttp_command_map,
            raw_events=raw_events,
            session_correlations=session_correlations,
            confidence="Unscored",
            confidence_source="claim_evidence_summary_v2",
            ai_enriched=False,
        )
        canonical_report = build_v2_report(
            normalized_base,
            sessions,
            raw_events=raw_events,
            behavior_policy_document=self.behavior_policy_document,
            behavior_policy_path=self.behavior_policy_path,
        )
        canonical_report = attach_model_prediction(
            canonical_report,
            self.prediction_context,
        )

        if not self.enable_vertex_narrative:
            print("\n[Step 2] Vertex narrative disabled; returning deterministic v2 claims")
            return _safe_reporting_mapping(
                apply_validated_vertex_presentation(canonical_report, None),
                "report",
            )

        # Vertex receives only validated canonical claims and can edit wording only.
        print("\n[Step 2] Optional Vertex presentation wording...")
        vertex_evidence = _safe_reporting_mapping(
            {
                "schema_version": canonical_report.get("schema_version"),
                "observed_behavior": canonical_report.get("observed_behavior"),
                "supported_assessment": canonical_report.get("supported_assessment"),
                "follow_on_hypothesis": canonical_report.get("follow_on_hypothesis"),
                "limitations": canonical_report.get("limitations"),
            },
            "Vertex evidence",
        )
        evidence_brief = json.dumps(
            vertex_evidence,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        analytical_result = await self.ai_client.infer_analytical(
            evidence_brief=evidence_brief,
            detected_ttps=detected_ttps
        )

        if not analytical_result:
            canonical_report["presentation"]["vertex_validation"] = {
                "status": "unavailable",
                "reason": "no_valid_model_output",
            }
            return _safe_reporting_mapping(canonical_report, "report")

        report = apply_validated_vertex_presentation(canonical_report, analytical_result)
        print(
            "Final: presentation="
            f"{_safe_log_text(report.get('presentation', {}).get('vertex_validation', {}).get('status', 'unknown'))} "
            f"| tokens={self.budget.used}/{self.budget.max_tokens}"
        )
        return _safe_reporting_mapping(report, "report")

    def _verify_analytical_claims(
            self,
            analytical: dict,
            ioc_bundle,
            ttp_command_map: Dict[str, List[str]]) -> dict:
        """
        Post-generation hallucination check on the AI's free-text analytical fields.

        Builds an 'evidence vocabulary' from actual session commands, JA3/HASSH labels,
        and VT malware families. Scans threat_actor_description and
        sophistication_justification for named tool terms (from the sophistication
        keyword lists in config) that do NOT appear anywhere in the evidence.

        When an unverified claim is found:
          - Appends '[UNVERIFIED CLAIM â€” not found in session evidence]' inline.
          - Logs the flagged tool to console for analyst awareness.
          - Does NOT discard the field â€” analysts can evaluate the flagged claim.
        """
        import re as _re

        # Build evidence vocabulary: every meaningful token from actual observed data
        evidence_tokens: set = set()

        # From JA3/HASSH fingerprint labels and VT families (per IP)
        for ip in ioc_bundle.ips:
            for attr in ('ja3_label', 'hassh_label', 'vt_malware_family'):
                val = getattr(ip, attr, None) or ''
                for tok in _re.split(r'[\s/\-_,]+', val.lower()):
                    if len(tok) > 2:
                        evidence_tokens.add(tok)

        # From actual session commands
        for cmds in ttp_command_map.values():
            for cmd in cmds:
                for tok in str(cmd).lower().split():
                    clean = tok.strip(r'`\'"();,./')
                    if len(clean) > 2:
                        evidence_tokens.add(clean)

        # Load known tool vocabulary from config (sophistication keywords)
        known_tools: List[str] = []
        for level_cfg in self.config.get('sophistication_rules', {}).values():
            known_tools.extend(level_cfg.get('keywords', []))
        # Also include behavioral rule terms
        for rule_list in self.config.get('behavioral_rules', {}).values():
            if isinstance(rule_list, list):
                for term in rule_list:
                    if isinstance(term, str) and ' ' not in term and len(term) > 3:
                        known_tools.append(term.lower())

        # Fields to scan (free-text, AI-generated)
        fields_to_check = ['threat_actor_description', 'sophistication_justification']
        flagged_total: List[str] = []

        for field in fields_to_check:
            text = analytical.get(field, '')
            if not text:
                continue
            flagged_in_field: List[str] = []
            for tool in known_tools:
                tool_lower = tool.lower().strip()
                if not tool_lower or len(tool_lower) < 3:
                    continue
                # Tool mentioned in AI text but not in evidence?
                # Use word-boundary match to avoid false positives
                # (e.g. 'kill' in 'skilled', 'set' in 'reset', 'off' in 'offset')
                pattern = _re.compile(r'\b' + _re.escape(tool_lower) + r'\b', _re.IGNORECASE)
                if (pattern.search(text) and
                        not any(tool_lower in ev for ev in evidence_tokens)):
                    flagged_in_field.append(tool)

            if flagged_in_field:
                flagged_total.extend(flagged_in_field)
                marker = (
                    f" [NOTE: The following tool(s) were cited but NOT found in "
                    f"session evidence â€” treat as unverified: "
                    f"{', '.join(set(flagged_in_field))}]"
                )
                analytical[field] = text + marker

        if flagged_total:
            print(
                "  [Verify] âš  Unverified tool claims flagged in analytical output: "
                f"{_safe_log_text(list(set(flagged_total)))}"
            )
        else:
            print("  [Verify] âœ“ All tool claims in analytical output match session evidence")

        return analytical

    def _legacy_merge_analytical_layer_disabled(
            self,
            base_hypothesis: dict,
            analytical: dict,
            ioc_bundle,
            tactic_summary: Dict[str, List[str]],
            sessions: List[Any],
            ttp_command_map: Dict[str, List[str]] = None,
            raw_events: List[dict] = None,
            session_correlations: List[Dict[str, Any]] = None) -> dict:
        """
        Merge the deterministic factual layer with the AI analytical layer.

        MERGE RULES:
          - Factual fields (kill_chain_analysis, ioc_table, attack_timeline,
            recommended_mitigations, strategic_recommendations) come EXCLUSIVELY
            from base_hypothesis â€” the AI cannot overwrite them.
          - Analytical fields (executive_summary, correlation_reasoning,
            sophistication_justification, predicted_next_action,
            falsification_conditions, attacker_playbook, honeypot_awareness_note)
            come from the AI analytical layer if present, else fall back to
            deterministic values.
          - Structural fields (campaign_name, sophistication level, score, IOCs)
            always come from base_hypothesis.
        """
        ttp_command_map = ttp_command_map or {}
        raw_events = raw_events or []
        vt_intel = _extract_vt_intelligence(ioc_bundle)

        kill_chain       = base_hypothesis.get('kill_chain_analysis', [])
        ioc_table        = base_hypothesis.get('ioc_table') or _build_ioc_table(
            raw_events, ioc_bundle, sessions)
        timeline         = base_hypothesis.get('attack_timeline') or _build_attack_timeline(
            raw_events)
        mitigations      = base_hypothesis.get('recommended_mitigations', [])
        structured_recs  = base_hypothesis.get('recommended_actions_structured', [])
        trusted_decision = base_hypothesis.get('trusted_recommendation_decision', {})
        artifact_recs    = base_hypothesis.get('artifact_recommendations', [])
        recommendation_provenance = base_hypothesis.get('recommendation_provenance', {})
        strategic_recs   = base_hypothesis.get('strategic_recommendations', [])
        campaign_name    = base_hypothesis.get('campaign_name', 'Unknown Operation')
        primary_obj      = base_hypothesis.get('primary_objective', 'Under analysis')
        target_platform  = base_hypothesis.get('target_platform', 'Unknown')
        tap_base         = base_hypothesis.get('threat_actor_profile', {})
        campaign_intel   = base_hypothesis.get('campaign_intelligence', '')
        session_id = getattr(sessions[0], "session_id", "unknown") if sessions else "unknown"
        hunting_context = (
            base_hypothesis.get("threat_hunting_context")
            or _build_session_correlation_hunting_context(session_correlations, session_id)
        )

        # Strip private metadata keys before rendering
        tap_clean = {k: v for k, v in tap_base.items() if not k.startswith('_')}

        allowed_ai_ips = _extract_direct_evidence_ips(sessions, raw_events)
        observed_commands = _extract_observed_commands(sessions)
        analytical = _validate_ai_grounding(
            analytical, allowed_ai_ips, observed_commands=observed_commands
        )
        grounding_warnings = analytical.get("_grounding_warnings", [])
        _reject_ai_operator_actions(analytical, grounding_warnings)
        if grounding_warnings:
            print(
                "  [Verify] AI grounding warnings: "
                f"{_safe_log_text(grounding_warnings)}"
            )

        exec_summary = (
            analytical.get('executive_summary') or
            base_hypothesis.get('executive_summary', 'N/A')
        )
        exec_summary = (
            _drop_ungrounded_narrative(
                exec_summary,
                "executive_summary",
                observed_commands,
                grounding_warnings,
            )
            or base_hypothesis.get('executive_summary', 'N/A')
        )

        # Actor-profile claims remain deterministic and evidence-grounded. The AI
        # may help with other narrative fields, but it cannot infer actor identity,
        # organization, or behavior beyond the trusted observations.
        ai_soph_just = analytical.get('sophistication_justification', '')
        ai_actor_desc = analytical.get('threat_actor_description', '')
        if ai_soph_just or ai_actor_desc:
            grounding_warnings.append({
                "field": "threat_actor_profile",
                "reason": (
                    "AI actor-profile prose was not promoted; actor-profile fields "
                    "are derived only from trusted command and Cowrie evidence."
                ),
            })
        actor_profile = dict(tap_clean)
        actor_profile.setdefault("type", "Unknown")
        actor_profile.setdefault("sophistication", "Unassessed")
        actor_profile.setdefault(
            "description",
            "The observed behavior is insufficient to infer a reliable actor profile.",
        )

        # Build enriched honeypot_intelligence
        source_ips = _extract_session_source_ips(sessions, raw_events)
        corr = _build_campaign_correlation(ioc_bundle, source_ips=source_ips)
        corr_reasoning = analytical.get('correlation_reasoning', corr.get('assessment', ''))
        ai_playbook = analytical.get('attacker_playbook', [])
        ai_awareness_note = analytical.get('honeypot_awareness_note', '')
        base_hi = base_hypothesis.get('honeypot_intelligence', {})
        if not isinstance(base_hi, dict):
            base_hi = {}
        base_awareness = (
            base_hi.get('attacker_awareness') or
            _assess_honeypot_awareness(sessions, self.behavioral_rules)
        )
        base_playbook = base_hi.get('attacker_playbook', [])
        awareness_detail = ai_awareness_note
        if not awareness_detail:
            if isinstance(base_awareness, dict):
                awareness_detail = base_awareness.get('note', '')
            else:
                awareness_detail = str(base_awareness)

        honeypot_intel = {
            "attacker_awareness": base_awareness,
            "attacker_awareness_detail": awareness_detail,
            "honeypot_awareness_note": awareness_detail,
            "campaign_correlation": corr,
            "correlation_reasoning": corr_reasoning,
            "attacker_playbook": ai_playbook if ai_playbook else base_playbook,
            "credential_targets": base_hi.get('credential_targets', []),
            "session_correlation_findings": hunting_context,
        }

        # Build enriched threat_hypothesis
        ai_predicted     = analytical.get('predicted_next_action', '')
        ai_predicted = _drop_ungrounded_narrative(
            ai_predicted,
            "predicted_next_action",
            observed_commands,
            grounding_warnings,
            allow_future_examples=True,
        )
        base_th          = base_hypothesis.get('threat_hypothesis', {})
        follow_on_hypothesis = _soften_follow_on_hypothesis(
            ai_predicted
            or base_th.get('post_session_follow_on_hypothesis')
            or base_th.get('predicted_next_action', '')
        )

        # Derive primary_objective from AI playbook when actors are uncoordinated.
        # The deterministic template uses singular language ("Credential harvesting â€”
        # targeting X") which directly contradicts a multi-actor correlation verdict.
        # The AI playbook items describe what each independent actor was hunting for,
        # making them the correct source for a multi-actor objective statement.
        effective_primary_obj = _derive_primary_objective(
            primary_obj, tactic_summary, ttp_command_map, _extract_attacker_playbook(ttp_command_map)
        )
        if ai_playbook and not corr.get('coordinated', True):
            n_actors = len(corr.get('campaign_names', []))
            if n_actors > 1:
                playbook_summary = '; '.join(str(p) for p in ai_playbook[:3])
                effective_primary_obj = (
                    f"{n_actors} independent actors with separate objectives â€” "
                    f"{playbook_summary}"
                )
        elif ai_playbook and corr.get('coordinated', False):
            # Single coordinated campaign â€” use AI's primary_objective if available,
            # otherwise keep deterministic value. Playbook items are descriptive
            # sentences (e.g. "System kernel version (uname -a)") not objectives.
            ai_primary = analytical.get('primary_objective', '')
            if ai_primary and ai_primary != 'Under analysis':
                effective_primary_obj = ai_primary

        analytical_confidence = _build_analytical_confidence(
            list(set().union(*tactic_summary.values())),
            sessions, ioc_bundle, ai_enriched=True, vt_intel=vt_intel
        )
        threat_hyp = {
            "stated_intent":          effective_primary_obj,
            # Compatibility field for older monitor/API code.
            "predicted_next_action":  follow_on_hypothesis,
            # Preferred label: this is post-session analytical follow-on hunting,
            # not the realtime prediction engine's live next-step forecast.
            "post_session_follow_on_hypothesis": follow_on_hypothesis,
            # Deterministic conditions are tied to observed artifacts. AI may
            # explain them but does not replace them with ungrounded falsifiers.
            "falsification_conditions": base_th.get('falsification_conditions', []),
            "session_correlations": hunting_context.get("session_correlations", []),
            "correlation_rules_fired": hunting_context.get("correlation_rules_fired", []),
            "analytical_evidence_strength": analytical_confidence,
            "analytical_confidence": analytical_confidence,
            **_threat_hypothesis_semantics(follow_on_hypothesis),
        }


        return {
            # Structural â€” always deterministic
            "campaign_name":           campaign_name,
            "primary_objective":       effective_primary_obj,
            "target_platform":         target_platform,
            "kill_chain_analysis":     kill_chain,
            "recommended_mitigations": mitigations,
            "recommended_actions_structured": structured_recs,
            "trusted_recommendation_decision": trusted_decision,
            "artifact_recommendations": artifact_recs,
            "recommendation_provenance": recommendation_provenance,
            "strategic_recommendations": strategic_recs,
            "campaign_intelligence":   campaign_intel,
            "ioc_table":               ioc_table,
            "attack_timeline":         timeline,
            # AI-enriched analytical fields
            "executive_summary": exec_summary,
            "threat_actor_profile": actor_profile,
            "honeypot_intelligence": honeypot_intel,
            "threat_hypothesis":     threat_hyp,
            "threat_hunting_context": hunting_context,
            "session_correlations": hunting_context.get("session_correlations", []),
            "correlation_rules_fired": hunting_context.get("correlation_rules_fired", []),
            # Report metadata
            "phases": self._convert_kill_chain_to_phases(kill_chain),
            "attack_type": effective_primary_obj,
            "analysis_mode": "ai_enriched_vertex",
            "confidence": analytical_confidence.get('level', 'medium'),
            "confidence_source": "heuristic_analytical_evidence_strength",
            "confidence_semantics": "not_a_calibrated_probability",
            "ai_enriched": True,
            "ai_validation_warnings": grounding_warnings,
            "post_session_follow_on_hypothesis": follow_on_hypothesis,
            "tokens_used": self.budget.used,
            "token_budget": self.budget.max_tokens,
            "recommended_actions": mitigations,
        }

    def _merge_analytical_layer(
            self,
            base_hypothesis: dict,
            analytical: dict,
            ioc_bundle,
            tactic_summary: Dict[str, List[str]],
            sessions: List[Any],
            ttp_command_map: Dict[str, List[str]] = None,
            raw_events: List[dict] = None,
            session_correlations: List[Dict[str, Any]] = None) -> dict:
        """Compatibility merge that grants Vertex presentation authority only."""

        normalized = self._normalize_hypothesis(
            base_hypothesis,
            ioc_bundle,
            tactic_summary,
            sessions,
            ttp_command_map=ttp_command_map,
            raw_events=raw_events,
            session_correlations=session_correlations,
            confidence="Unscored",
            confidence_source="claim_evidence_summary_v2",
            ai_enriched=False,
        )
        report = build_v2_report(
            normalized,
            sessions,
            raw_events=raw_events or [],
            behavior_policy_document=self.behavior_policy_document,
            behavior_policy_path=self.behavior_policy_path,
        )
        report = attach_model_prediction(report, self.prediction_context)
        return apply_validated_vertex_presentation(report, analytical)

    def _build_evidence_brief(self,
                              ioc_bundle,
                              tactic_summary: Dict[str, List[str]],
                              sessions: List[Any],
                              base_hypothesis: dict,
                              ttp_command_map: Dict[str, List[str]] = None,
                              raw_events: List[dict] = None,
                              session_correlations: List[Dict[str, Any]] = None) -> str:
        """
        Build a structured evidence brief for the AI analytical layer.

        This replaces the old flat-text _build_discovery_evidence() for AI consumption.
        The brief contains pre-computed facts from deterministic code â€” the AI reasons
        over these facts rather than re-interpreting raw log data.

        Returns a formatted string (JSON + plain text) suitable for the AI user message.
        """
        ttp_command_map = ttp_command_map or {}
        session_id = getattr(sessions[0], "session_id", "unknown") if sessions else "unknown"
        hunting_context = (
            base_hypothesis.get("threat_hunting_context")
            or _build_session_correlation_hunting_context(session_correlations, session_id)
        )

        source_ips = _extract_session_source_ips(sessions, raw_events)
        direct_evidence_ips = sorted(_extract_direct_evidence_ips(sessions, raw_events))
        corr       = _build_campaign_correlation(ioc_bundle, source_ips=source_ips)
        awareness  = _assess_honeypot_awareness(sessions, self.behavioral_rules)
        playbook   = _extract_attacker_playbook(ttp_command_map)
        vt_intel   = _extract_vt_intelligence(ioc_bundle)

        tap        = base_hypothesis.get('threat_actor_profile', {})
        soph_level = tap.get('sophistication', 'Unknown')
        soph_score = tap.get('_score', 'N/A')
        soph_reasons = tap.get('_score_reasons', [])

        # Import AbuseIPDB decoder once for this brief build
        try:
            from production.enrichment.enrichment_mapping import decode_abuseipdb_categories as _decode_abuse
        except ImportError:
            _decode_abuse = lambda x: x  # passthrough if not available

        ip_profiles = []
        profile_ips = list(getattr(ioc_bundle, "ips", []) or [])
        if source_ips:
            source_ip_set = set(source_ips)
            scoped_profiles = [
                ip for ip in profile_ips
                if getattr(ip, "value", None) in source_ip_set
            ]
            if scoped_profiles:
                profile_ips = scoped_profiles
        for ip in profile_ips:
            # Decode AbuseIPDB integer category codes to human-readable labels
            raw_categories = getattr(ip, 'abuseipdb_categories', []) or []
            decoded_categories = (
                _decode_abuse(raw_categories)
                if any(isinstance(c, int) for c in raw_categories)
                else raw_categories  # already decoded (string labels)
            )
            ip_profiles.append({
                "ip":              ip.value,
                "otx_pulse_raw":   getattr(ip, 'raw_otx_pulse', None) or 'N/A',
                "otx_tags":        getattr(ip, 'otx_tags', []) or [],
                "asn":             getattr(ip, 'asn', None) or 'N/A',
                "geo":             getattr(ip, 'geo', None) or 'N/A',
                "ja3_label":       getattr(ip, 'ja3_label', None) or 'N/A',
                "hassh_label":     getattr(ip, 'hassh_label', None) or 'N/A',
                "infrastructure_tags": getattr(ip, 'infrastructure_tags', []) or [],
                "is_tor_exit":     getattr(ip, 'is_tor_exit', False),
                "is_vpn":          getattr(ip, 'is_vpn', False),
                "host_type":       getattr(ip, 'host_type', None) or 'N/A',
                "vt_malware_family": getattr(ip, 'vt_malware_family', None) or 'N/A',
                "shodan_tags":     getattr(ip, 'shodan_tags', []) or [],
                "abuseipdb_categories": decoded_categories,
            })

        cmd_evidence = {}
        for ttp, cmds in ttp_command_map.items():
            cmd_evidence[ttp] = [str(c)[:500] for c in cmds[:3]]

        # Each entry is enriched with MITRE ATT&CK description + affected platforms
        # from live STIX data (updated every 30 days) so AI has full context.
        ttp_chain = []
        for tactic, ttps in sorted(tactic_summary.items()):
            for ttp in sorted(ttps):
                cmds = cmd_evidence.get(ttp, [])
                ttp_chain.append({
                    "technique_id":   ttp,
                    "tactic":         tactic,
                    "technique_name": self.mitre_db.get_name(ttp) or self.mitre_name_map.get(ttp, ttp),
                    # MITRE ATT&CK description (truncated to 300 chars to save token budget)
                    "mitre_description": (
                        (self.mitre_db.get_description(ttp) or '')[:300] or None
                    ),
                    # Platforms this technique targets (from MITRE STIX)
                    "mitre_platforms": self.mitre_db.get_platforms(ttp),
                    "observed_commands": cmds,
                })

        cmd_samples = []
        for s in sessions:
            for cmd in getattr(s, 'commands_success', [])[:5]:
                if len(cmd_samples) < 15:
                    cmd_samples.append(str(cmd)[:120])

        timeline = _build_attack_timeline(raw_events or [])
        timeline_events = []
        for ts, entries in sorted(timeline.items()) if isinstance(timeline, dict) else []:
            for entry in (entries if isinstance(entries, list) else [entries]):
                timeline_events.append(f"{ts}: {entry}")
        # Extract completed actions for prediction grounding. This is ordered by
        # the same tactic severity policy used by realtime predictive alerts, so
        # report emphasis does not depend on a hidden hardcoded TTP allowlist.
        completed_actions = _completed_actions_from_observed_ttps(
            tactic_summary,
            ttp_command_map or {},
            policy_path=self.prediction_policy_path,
            policy_document=self.prediction_policy,
        )

        cisa_kev_matches = []
        if self.threat_feeds:
            import re as _re_kev
            # Collect all text that might contain CVE IDs
            cve_search_text = []
            for ip in ioc_bundle.ips:
                cve_search_text.append(getattr(ip, 'raw_otx_pulse', '') or '')
                cve_search_text += (getattr(ip, 'otx_tags', []) or [])
            full_text = ' '.join(str(t) for t in cve_search_text)
            found_cves = list(set(_re_kev.findall(
                r'CVE-\d{4}-\d{4,7}', full_text, _re_kev.IGNORECASE
            )))
            cisa_kev_matches = self.threat_feeds.check_cves(
                [c.upper() for c in found_cves]
            )
            if cisa_kev_matches:
                print(f"  [CISA KEV] {len(cisa_kev_matches)} actively-exploited CVE(s) "
                      f"in observed OTX pulses: "
                      f"{_safe_log_text([m.get('cve_id', '') for m in cisa_kev_matches])}")

        sigma_matched_commands = []
        if self.threat_feeds:
            all_cmds_lower = ' '.join(
                str(c).lower() for s in sessions
                for c in getattr(s, 'commands_success', [])
            )
            sigma_high_kws = self.threat_feeds.sigma.get_keywords_for_level("high")
            sigma_matched_commands = [
                kw for kw in sigma_high_kws
                if kw and len(kw) > 3 and kw in all_cmds_lower
            ][:20]  # cap at 20

        # Compute target_platform once for use in both facts and the brief
        target_platform = _detect_target_platform(
            sessions, ttp_command_map or {},
            platform_rules=self.platform_rules,
            mitre_db=self.mitre_db,
            detected_ttps=list(set().union(*tactic_summary.values()))
            if tactic_summary else [],
        )

        facts = {
            "FIXED_sophistication_level": soph_level,
            "FIXED_sophistication_score":  soph_score,
            "FIXED_sophistication_reasons": soph_reasons,
            "FIXED_campaign_coordinated":  corr['coordinated'],
            "FIXED_campaign_assessment":   corr['assessment'],
            "FIXED_unique_otx_pulses":     corr['campaign_names'],
            "FIXED_asns_observed":         corr['asns_observed'],
            "FIXED_honeypot_awareness":    awareness,
            "FIXED_vt_hits":               vt_intel.get('has_hits', False),
            "FIXED_vt_families":           vt_intel.get('malware_families', []),
            # CISA KEV: actively-exploited CVEs found in OTX pulse data
            "FIXED_cisa_kev_matches":      cisa_kev_matches,
            "FIXED_cisa_kev_count":        len(cisa_kev_matches),
            # Target platform: deterministic from commands + MITRE fallback
            # AI must NOT contradict this â€” it is pre-computed from evidence.
            "FIXED_target_platform":       target_platform,
            "FIXED_observed_source_ips":    source_ips,
            "FIXED_allowed_narrative_ips":  direct_evidence_ips,
            "FIXED_session_correlation_count": hunting_context.get("correlation_count", 0),
            "FIXED_session_correlation_source_types": hunting_context.get("source_type_counts", {}),
        }

        brief = {
            "task": "threat_hypothesis_analysis",
            "detected_ttps":  list(set().union(*tactic_summary.values())),
            "pre_computed_facts": facts,
            "ip_enrichment_profiles": ip_profiles,
            "ttp_chain_with_evidence": ttp_chain,
            "session_correlation_hunting_context": hunting_context,
            "command_samples": cmd_samples,
            "attack_timeline_ordered": timeline_events[:20],
            "already_completed_observed_actions": completed_actions,
            "already_completed_high_impact_actions": completed_actions,
            "credential_targets": playbook.get('credential_targets', []),
            "data_sought": playbook.get('data_sought', []),
            # Sigma community-matched detection signals in observed commands
            "sigma_community_matched_signals": sigma_matched_commands,
        }

        # Build conditional executive_summary and prediction instructions
        coordinated = facts['FIXED_campaign_coordinated']
        n_source_ips = len(source_ips)
        if coordinated and n_source_ips > 1:
            exec_summary_instruction = (
                "Write a 3-4 sentence CTI executive summary. "
                "Cite attacker IPs, tools observed, and highest-impact action. "
                "Treat this as a SINGLE coordinated actor."
            )
        elif n_source_ips > 1:
            exec_summary_instruction = (
                f"Write a 3-4 sentence CTI executive summary describing the "
                f"{n_source_ips} directly observed source IPs in this report. "
                f"Only mention source IPs listed in FIXED_observed_source_ips. "
                f"If evidence does not prove coordination, describe them as "
                f"separate observed sources, not a single actor."
            )
        else:
            exec_summary_instruction = (
                "Write a 3-4 sentence CTI executive summary for the single directly "
                "observed source IP in FIXED_observed_source_ips. Do not introduce "
                "additional actors, adjacent IPs, or infrastructure not present in "
                "FIXED_allowed_narrative_ips. Cite observed commands and the "
                "highest-impact action."
            )

        prediction_instruction = (
            "Based ONLY on the attack_timeline_ordered and already_completed_observed_actions, "
            "identify what has ALREADY occurred, then predict the single most likely "
            "NEXT action NOT YET OBSERVED. Do not predict something that already happened. "
            "A wget/curl download URL is payload/tool transfer evidence, not exfiltration "
            "unless an upload, POST, collect, exfil, or private-key theft command is observed. "
            "If SSH key exfiltration is already in the timeline, predict what comes AFTER that â€” "
            "e.g. lateral movement using the stolen key. Use session_correlation_hunting_context "
            "only as supporting threat-hunting context with visible confidence/source_type; "
            "do not treat correlation candidates as raw commands."
        )

        brief_str = json.dumps(brief, indent=2, ensure_ascii=False)
        return (
            "Analyze the following structured evidence brief and answer each of the "
            "seven analytical questions defined in the system prompt.\n\n"
            f"ANALYTICAL QUESTION CUSTOMISATION:\n"
            f"  executive_summary: {exec_summary_instruction}\n"
            f"  predicted_next_action: {prediction_instruction}\n\n"
            "=== STRUCTURED EVIDENCE BRIEF ===\n" + brief_str
        )

    def _build_discovery_evidence(self, ioc_bundle, tactic_summary,
                                  sessions, bpg_list=None) -> str:

        ctx = ["### DISCOVERY EVIDENCE ###\n"]

        ctx.append("1. INFRASTRUCTURE WITH FULL ENRICHMENT:")
        for ip in ioc_bundle.ips:
            ja3        = getattr(ip, 'ja3_label', None) or 'N/A'
            hassh      = getattr(ip, 'hassh_label', None) or 'N/A'
            # Use raw_otx_pulse â€” the verbatim pulse name. This is EVIDENCE for
            # the AI rewrite, not the campaign name. The AI must synthesize a name
            # from this, not copy it verbatim.
            raw_pulse  = getattr(ip, 'raw_otx_pulse', None) or 'N/A'
            asn        = getattr(ip, 'asn', None) or 'N/A'
            geo        = getattr(ip, 'geo', None) or 'N/A'
            infra      = ', '.join(getattr(ip, 'infrastructure_tags', []) or []) or 'N/A'
            is_tor     = getattr(ip, 'is_tor_exit', False)
            is_vpn     = getattr(ip, 'is_vpn', False)
            host_type  = getattr(ip, 'host_type', None) or 'N/A'
            vt_family  = getattr(ip, 'vt_malware_family', None) or 'N/A'
            ctx.append(
                f"  - IP: {ip.value}"
                f" | JA3: {ja3}"
                f" | HASSH: {hassh}"
                f" | OTX pulse (raw): {raw_pulse}"
                f" | ASN: {asn}"
                f" | GEO: {geo}"
                f" | infra_tags: [{infra}]"
                f" | tor: {is_tor}"
                f" | vpn: {is_vpn}"
                f" | host_type: {host_type}"
                f" | vt_family: {vt_family}"
            )

        ctx.append("\n2. CLIENT FINGERPRINT CLASSIFICATION:")
        for ip in ioc_bundle.ips:
            ja3   = getattr(ip, 'ja3_label', None)
            hassh = getattr(ip, 'hassh_label', None)
            infra = _describe_infrastructure(ip)
            if ja3 or hassh or infra != "No infrastructure data":
                ctx.append(
                    f"  - {ip.value}: JA3={ja3} | HASSH={hassh} | infra=[{infra}]"
                )

        ctx.append("\n3. OBSERVED TECHNIQUES:")
        for tactic, ttps in tactic_summary.items():
            ctx.append(f"  {tactic}: {', '.join(ttps[:5])}")

        ctx.append("\n4. COMMAND SAMPLES:")
        count = 0
        for s in sessions:
            for cmd in getattr(s, 'commands_success', [])[:3]:
                if count < 10:
                    ctx.append(f"  - {cmd[:120]}")
                    count += 1

        if bpg_list:
            ctx.append("\n5. ATTACK CHAIN PROGRESSION:")
            for i, bpg in enumerate(bpg_list[:5], 1):
                chain_str = " -> ".join(bpg.get("chain", [])[:8])
                ctx.append(f"  Chain {i}: {chain_str}")

        ctx.append("\nCLASSIFICATION RULES (for AI rewrite):")
        ctx.append("  - This is a HONEYPOT â€” assess whether attacker was aware")
        ctx.append("  - Commodity JA3/HASSH = Low/Medium sophistication")
        ctx.append("  - Manual recon commands suggest human operator, not bot")
        ctx.append("  - OTX pulse (raw) is crowdsourced noise â€” synthesize a professional")
        ctx.append("    campaign name from it, do NOT copy verbatim")
        ctx.append("  - Tor/VPN infrastructure = origin masking; note this in the")
        ctx.append("    prediction and threat actor profile")
        ctx.append("  - AbuseIPDB risk_score is NOT a sophistication indicator â€” ignore it")
        ctx.append("  - vt_malware_family is confirmed malware â€” reference it by name")

        corr = _build_campaign_correlation(ioc_bundle)
        ctx.append("\n[FIXED - DO NOT OVERRIDE] CAMPAIGN CORRELATION VERDICT:")
        ctx.append(f"  coordinated={corr['coordinated']}")
        ctx.append(f"  assessment='{corr['assessment']}'")
        ctx.append(f"  unique_pulses={corr['campaign_names']}")
        ctx.append(f"  asns_observed={corr['asns_observed']}")
        if not corr['coordinated']:
            ctx.append("  => These are UNRELATED opportunistic actors. The executive_summary")
            ctx.append("     and campaign_correlation field MUST reflect this. DO NOT merge them.")
        ctx.append("\n[FIXED - DO NOT OVERRIDE] Kill chain evidence fields are PRE-POPULATED.")
        ctx.append("  The 'evidence' field must contain ONLY the raw observed command or artifact.")
        ctx.append("  Remediations, mitigations, and recommendations MUST NOT appear in 'evidence'.")
        ctx.append("  If evidence is a command, reproduce it exactly as observed.")
        ctx.append("  If evidence is a file/path artifact, state the path only.")

        return "\n".join(ctx)

    async def _build_deterministic_hypothesis(
            self, ioc_bundle, tactic_summary, sessions,
            ttp_command_map: Dict[str, List[str]] = None,
            raw_events: List[dict] = None,
            session_correlations: List[Dict[str, Any]] = None) -> dict:
        """
        Build zero-hallucination baseline with full honeypot-specific fields.
        """
        raw_events = raw_events or []
        ttp_command_map = ttp_command_map or {}
        session_id = getattr(sessions[0], "session_id", "unknown") if sessions else "unknown"
        hunting_context = _build_session_correlation_hunting_context(session_correlations, session_id)

        platform, attack_type = await self._detect_platform_and_attack_type_ai(
            sessions, tactic_summary
        )

        score = 0
        score_reasons = []

        high_conf_ips = [ip for ip in ioc_bundle.ips
                         if getattr(ip, 'confidence', '') == 'high']
        if len(high_conf_ips) > 10:
            score += 1
            score_reasons.append(f"Distributed infrastructure ({len(high_conf_ips)} IPs)")

        all_ja3 = [getattr(ip, 'ja3_label', None) for ip in ioc_bundle.ips
                   if getattr(ip, 'ja3_label', None)]
        all_hassh = [getattr(ip, 'hassh_label', None) for ip in ioc_bundle.ips
                     if getattr(ip, 'hassh_label', None)]
        fingerprint_text = ' '.join(all_ja3 + all_hassh).lower()

        _adv = self.sophistication_rules.get("high", {})
        _cust = self.sophistication_rules.get("medium", {})
        _comm = self.sophistication_rules.get("low", {})

        # Keywords come entirely from config.json + Sigma (merged at __init__).
        # No hardcoded fallback â€” if both config.json and Sigma fail to load,
        # scorer returns 0 (safe default: Low sophistication assumed).
        _advanced_kw  = set(_adv.get("keywords", []))
        _custom_kw    = set(_cust.get("keywords", []))
        _commodity_kw = set(_comm.get("keywords", []))

        def _kw_hit(text: str, kw_set: set) -> Optional[str]:
            """
            Return the first matching keyword from kw_set found in text,
            or None if no keyword matches.

            WORD-BOUNDARY RULE (fixes false positive on 'exploit' â†’ 'post-exploitation'):
              Single-word keywords (no internal spaces, after stripping) use word-boundary
              matching so that 'exploit' does NOT match 'post-exploitation', 'beacon' does
              NOT match 'beaconing', etc.
              Multi-word phrases (e.g. 'cobalt strike', 'custom implant') use substring
              matching because phrase boundaries make false positives extremely unlikely.
              Keywords with trailing/leading spaces (e.g. 'go ') are stripped before
              matching and treated as single words with word-boundary enforcement.

            Returns the matching keyword string for use in score_reasons detail.
            """
            for k in kw_set:
                k_stripped = k.strip()
                if not k_stripped:
                    continue
                if ' ' in k_stripped:
                    # Multi-word phrase â€” substring is fine
                    if k_stripped in text:
                        return k_stripped
                else:
                    # Single word â€” enforce word boundary.
                    # Use negative lookbehind/lookahead for alphanumeric characters so that:
                    #   'exploit' matches 'exploit' and 'exploited' but NOT 'post-exploitation'
                    #   'go' matches ' go ' and 'go ' but NOT 'golang' or 'good'
                    # Note: re.escape handles hyphens (e.g. 'custom-built') correctly.
                    pattern = r'(?<![a-z0-9])' + re.escape(k_stripped) + r'(?![a-z0-9])'
                    if re.search(pattern, text):
                        return k_stripped
            return None

        adv_hit  = _kw_hit(fingerprint_text, _advanced_kw)
        cust_hit = _kw_hit(fingerprint_text, _custom_kw)
        comm_hit = _kw_hit(fingerprint_text, _commodity_kw)

        if adv_hit:
            score += 3
            score_reasons.append(f"Advanced implant fingerprints â€” matched: '{adv_hit}' (+3)")
        elif cust_hit:
            score += 1
            score_reasons.append(f"Modified/custom tooling fingerprints â€” matched: '{cust_hit}' (+1)")
        elif comm_hit:
            score -= 2
            score_reasons.append(f"Commodity tool fingerprints â€” matched: '{comm_hit}' (-2)")

        _behavioral = self.behavioral_rules
        _botnet_kw = _behavioral.get("botnet_noise", [
            'wget ', 'curl -', 'chmod 777', 'chmod +x', 'rm -rf /tmp', 'history -c'
        ])
        _manual_kw = _behavioral.get("manual_recon", [
            'cat /proc/cpuinfo', 'uname -a', 'lscpu', 'free -m', 'dmesg', 'mount'
        ])
        _persistence_kw = _behavioral.get("targeted_persistence", ['authorized_keys'])

        total_cmds = bot_noise_cmds = manual_recon_cmds = persistence_cmds = 0
        for s in sessions:
            cmds = getattr(s, 'commands_success', [])
            total_cmds += len(cmds)
            for cmd in cmds:
                cl = cmd.lower()
                if any(k in cl for k in _botnet_kw):
                    bot_noise_cmds += 1
                elif any(k in cl for k in _manual_kw):
                    manual_recon_cmds += 1
                elif any(k in cl for k in _persistence_kw):
                    persistence_cmds += 1

        if bot_noise_cmds > 0 and manual_recon_cmds == 0:
            score -= 2
            score_reasons.append("Downloader or cleanup command pattern observed (-2)")
        if manual_recon_cmds > 0:
            score += 3
            score_reasons.append("Environment reconnaissance command observed (+3)")
        if persistence_cmds > 0:
            score += 1
            score_reasons.append("Targeted SSH key persistence (+1)")

        # These are deliberate negative signals: a skilled operator adapts to the
        # environment. Using Windows commands on Linux (vssadmin) or trying 3+
        # reverse shell payloads in rapid succession and failing all of them
        # indicates automation or low-skill operators, not high-end tradecraft.
        _windows_only_cmds = ['vssadmin', 'net user ', 'reg add', 'cmd.exe', 'powershell']
        _reverse_shell_attempts = ['bash -i >&', 'nc -e ', 'python3 -c.*socket', 'python -c.*socket']
        import re as _re
        cross_os_errors = sum(
            1 for s in sessions
            for cmd in getattr(s, 'commands_success', [])
            if any(k in cmd.lower() for k in _windows_only_cmds)
        )
        if cross_os_errors > 0:
            score -= 2
            score_reasons.append(
                f"Cross-OS command error: Windows cmd on Linux host "
                f"({cross_os_errors} instance(s)) â€” indicates automation or low tradecraft (-2)"
            )

        # Count rapid-fire reverse shell attempts across all session commands
        all_cmds_flat = [
            cmd for s in sessions for cmd in getattr(s, 'commands_success', [])
        ]
        failed_shell_count = sum(
            1 for cmd in all_cmds_flat
            if any(_re.search(p, cmd, _re.IGNORECASE) for p in _reverse_shell_attempts)
        )
        if failed_shell_count >= 3:
            score -= 2
            score_reasons.append(
                f"{failed_shell_count} rapid-fire reverse shell attempts â€” spray-and-pray "
                f"automation, not disciplined operator tradecraft (-2)"
            )
        elif failed_shell_count >= 2:
            score -= 1
            score_reasons.append(
                f"{failed_shell_count} reverse shell attempts in session "
                f"â€” low execution quality (-1)"
            )

        detected_tactics = set(tactic_summary.keys()) if tactic_summary else set()
        if 'Credential Access' in detected_tactics and len(detected_tactics) == 1:
            score -= 1
            score_reasons.append("Only Credential Access (scanning only) (-1)")

        # A skilled operator has low error rates and diverse commands.
        # High failure rates and low unique-command ratios are strong indicators
        # of copy-pasted scripts, commodity automation, or low-skill operators.
        total_success = sum(
            len(getattr(s, 'commands_success', [])) for s in sessions
        )
        total_failed = sum(
            len(getattr(s, 'commands_failed', [])) for s in sessions
        )
        all_success_cmds = [
            cmd for s in sessions
            for cmd in getattr(s, 'commands_success', [])
        ]

        if total_success + total_failed > 0:
            error_rate = total_failed / (total_success + total_failed)
            if error_rate > 0.50:
                score -= 1
                score_reasons.append(
                    f"High command failure rate ({error_rate:.0%} of commands failed) "
                    f"\u2014 script execution errors indicate low tradecraft (-1)"
                )

        if all_success_cmds:
            unique_cmds = set(str(c).strip() for c in all_success_cmds)
            unique_ratio = len(unique_cmds) / len(all_success_cmds)
            if unique_ratio < 0.30 and len(all_success_cmds) > 5:
                score -= 1
                score_reasons.append(
                    f"Low unique command ratio ({unique_ratio:.0%} unique of {len(all_success_cmds)} total) "
                    f"\u2014 repeated commands indicate automated scripting, not manual operation (-1)"
                )
            if len(unique_cmds) < 5:
                score -= 1
                score_reasons.append(
                    f"Extremely limited command set ({len(unique_cmds)} unique commands) "
                    f"\u2014 insufficient behavioral diversity for actor profiling (-1)"
                )

        # IMPORTANT: AbuseIPDB risk_score is deliberately NOT included here.
        # A fresh APT VPS scores 0; a noisy Mirai bot scores 100. Using risk_score
        # would produce inverted sophistication results for APT detection.
        # Shodan infrastructure tags are used instead, as they characterise the
        # deliberate infrastructure choices the operator made.
        for ip in ioc_bundle.ips:
            delta, reason = _infrastructure_sophistication_signal(ip)
            if delta != 0 and reason:
                score += delta
                sign = f"+{delta}" if delta > 0 else str(delta)
                score_reasons.append(
                    f"[{ip.value}] {reason} ({sign})"
                )
                break  # One infrastructure signal per run â€” avoid multi-IP stacking

        if score >= 4:
            sophistication_level = 'High'
        elif score >= 1:
            sophistication_level = 'Medium'
        else:
            sophistication_level = 'Low'

        print(
            "Behavioral complexity heuristic: "
            f"{_safe_log_text(sophistication_level)} (Score: {score})"
        )
        for r in score_reasons:
            print(f"    - {_safe_log_text(r)}")

        ttps_flat = set().union(*tactic_summary.values()) if tactic_summary else set()
        command_evidence = self._extract_command_evidence_for_ttps(
            sessions, tactic_summary,
            ttp_command_map=ttp_command_map,
            raw_events=raw_events
        )
        kill_chain = []
        for ttp in sorted(ttps_flat):
            tactic = "Unknown Tactic"
            for tac, ttps_in_tac in tactic_summary.items():
                if ttp in ttps_in_tac:
                    tactic = tac
                    break
            evidence = command_evidence.get(ttp, f"Detected from attack evidence ({ttp})")
            kill_chain.append({
                'tactic': tactic,
                'technique_id': ttp,
                'technique_name': self.mitre_name_map.get(ttp, ttp),
                'evidence': evidence
            })

        source_ips = _extract_session_source_ips(sessions, raw_events)
        campaign_correlation = _build_campaign_correlation(ioc_bundle, source_ips=source_ips)
        campaign_name = "Cowrie SSH Session Assessment"

        vt_intel = _extract_vt_intelligence(ioc_bundle)
        if vt_intel["has_hits"]:
            print(
                f"  VT intel: {vt_intel['hit_count']} hit(s), families: "
                f"{_safe_log_text(vt_intel['malware_families'])}"
            )
        else:
            print("  VT intel: no confirmed hits "
                  "(absence does not mean clean â€” polymorphic malware evades AV)")

        artifact_recommendations = _generate_dynamic_recommendations(
            ttp_command_map, ioc_bundle, raw_events, vt_intel=vt_intel
        )
        trusted_recommendation_decision = _build_trusted_recommendation_decision(
            sessions,
            raw_events,
            tactic_summary,
            ttp_command_map,
            mitre_db=self.mitre_db,
            asset_profile_path=self.recommendation_asset_profile_path,
            action_policy_path=self.recommendation_action_policy_path,
            prediction_snapshot=self.prediction_context,
        )
        structured_recommendations = [
            action for action in trusted_recommendation_decision.get("immediate_actions", [])
            if isinstance(action, dict)
        ]
        recommendations = [
            str(action.get("action") or "").strip()
            for action in structured_recommendations
            if str(action.get("action") or "").strip()
        ]

        honeypot_awareness = _assess_honeypot_awareness(sessions, self.behavioral_rules)
        campaign_correlation = _build_campaign_correlation(ioc_bundle, source_ips=source_ips)
        playbook = _extract_attacker_playbook(ttp_command_map)

        ordered_chain = build_observed_behavior(
            sessions,
            raw_events,
            behavior_policy_document=self.behavior_policy_document,
            behavior_policy_path=self.behavior_policy_path,
        ).get("ordered_behavior_chain", [])
        predicted_next = _predict_next_action(
            ttp_command_map,
            ioc_bundle,
            tactic_summary,
            ordered_behavior_chain=ordered_chain,
        )
        falsification = _build_falsification_conditions(
            ttp_command_map, ioc_bundle, raw_events=raw_events
        )

        otx_tags = set()
        for ip in ioc_bundle.ips:
            otx_tags.update(getattr(ip, 'otx_tags', []) or [])

        strategic_recs = _generate_strategic_recommendations(otx_tags, self.config)

        # Supplement strategic recommendations with CISA KEV required actions
        # if any actively-exploited CVEs were found in OTX pulse data
        if self.threat_feeds:
            import re as _re_strat
            cve_search_text = []
            for ip in ioc_bundle.ips:
                cve_search_text.append(getattr(ip, 'raw_otx_pulse', '') or '')
                cve_search_text += (getattr(ip, 'otx_tags', []) or [])
            found_cves = list(set(_re_strat.findall(
                r'CVE-\d{4}-\d{4,7}',
                ' '.join(str(t) for t in cve_search_text),
                _re_strat.IGNORECASE
            )))
            kev_matches = self.threat_feeds.check_cves(
                [c.upper() for c in found_cves]
            )
            seen_strat = set(strategic_recs)
            for kev in kev_matches:
                action = kev.get('required_action', '')
                if action and action not in seen_strat:
                    strategic_recs.append(
                        f"[CISA KEV] {kev['cve_id']} ({kev['vendor']} {kev['product']}): "
                        f"{action}"
                    )
                    seen_strat.add(action)

        campaign_intel = _build_campaign_intelligence(
            playbook, campaign_correlation, ioc_bundle, vt_intel=vt_intel
        )

        ioc_table = _build_ioc_table(raw_events, ioc_bundle, sessions)
        timeline = _build_attack_timeline(raw_events)

        analytical_confidence = _build_analytical_confidence(
            list(ttps_flat), sessions, ioc_bundle,
            ai_enriched=False, vt_intel=vt_intel,
            thresholds=self.config.get('honeypot_config', {}).get('alert_thresholds', {})
        )

        primary_objective = "Under analysis"
        primary_objective = _derive_primary_objective(
            primary_objective, tactic_summary, ttp_command_map, playbook
        )
        deterministic_summary = _build_deterministic_executive_summary(
            source_ips, tactic_summary, ttp_command_map, primary_objective, ioc_bundle
        )

        mitigations_baseline = []
        # 1. Always include: block source IPs at perimeter
        if ioc_bundle.ips:
            ip_list = ', '.join(i.value for i in ioc_bundle.ips[:5])
            mitigations_baseline.append(
                f"Block attacker source IPs at perimeter: {ip_list}"
            )
        # 2. MITRE ATT&CK mitigations for each detected TTP
        #    Uses live data from mitre_db (loaded from MITRE STIX, auto-refreshed 30d)
        seen_mit = set()
        for tactic, ttps in sorted(tactic_summary.items()):
            for ttp in sorted(ttps):
                ttp_name = self.mitre_db.get_name(ttp)
                mitre_mits = self.mitre_db.get_mitigations(ttp)
                if mitre_mits:
                    # Add top 2 MITRE mitigations per technique
                    for mit in mitre_mits[:2]:
                        entry = f"[MITRE {ttp} {ttp_name}] {mit}"
                        if entry not in seen_mit:
                            seen_mit.add(entry)
                            mitigations_baseline.append(entry)
                else:
                    # Fallback: generic tactic-level review
                    entry = f"Review {tactic} controls â€” technique detected: {ttp} ({ttp_name})"
                    if entry not in seen_mit:
                        seen_mit.add(entry)
                        mitigations_baseline.append(entry)

        return {
            "campaign_name": campaign_name,
            "executive_summary": deterministic_summary,
            "primary_objective": primary_objective,
            "target_platform": _detect_target_platform(
                sessions, ttp_command_map or {},
                platform_rules=self.platform_rules,
                mitre_db=self.mitre_db,
                detected_ttps=list(ttps_flat),
            ),
            "threat_actor_profile": _build_evidence_grounded_actor_profile(
                tactic_summary,
                ttp_command_map or {},
                sessions,
                raw_events=raw_events,
                behavioral_score=score,
                score_reasons=score_reasons,
            ),
            "honeypot_intelligence": {
                "attacker_awareness": honeypot_awareness,
                "campaign_correlation": campaign_correlation,
                "session_correlation_findings": hunting_context,
                "attacker_playbook": playbook.get("data_sought", []) + playbook.get("services_probed", []),
                "credential_targets": playbook.get("credential_targets", [])
            },
            "threat_hypothesis": {
                "stated_intent": primary_objective,
                "predicted_next_action": predicted_next,
                "post_session_follow_on_hypothesis": predicted_next,
                "falsification_conditions": falsification,
                "session_correlations": hunting_context.get("session_correlations", []),
                "correlation_rules_fired": hunting_context.get("correlation_rules_fired", []),
                "analytical_evidence_strength": analytical_confidence,
                "analytical_confidence": analytical_confidence,
                **_threat_hypothesis_semantics(predicted_next),
            },
            "post_session_follow_on_hypothesis": predicted_next,
            "threat_hunting_context": hunting_context,
            "session_correlations": hunting_context.get("session_correlations", []),
            "correlation_rules_fired": hunting_context.get("correlation_rules_fired", []),
            "kill_chain_analysis": kill_chain,
            "recommended_mitigations": recommendations,
            "recommended_actions_structured": structured_recommendations,
            "trusted_recommendation_decision": trusted_recommendation_decision,
            "artifact_recommendations": artifact_recommendations,
            "recommendation_provenance": {
                "authority": (
                    trusted_recommendation_decision.get("authority")
                    or "policy_unavailable"
                ),
                "status": trusted_recommendation_decision.get("status") or "unavailable",
                "policy": (
                    (trusted_recommendation_decision.get("trust") or {}).get("policy")
                    if isinstance(trusted_recommendation_decision, dict) else {}
                ),
                "policy_action_count": len(structured_recommendations),
                "rejected_action_count": len(trusted_recommendation_decision.get("rejected_actions", [])),
                "fallback_actions_allowed": False,
                "note": (
                    "Recommended actions are produced only by the trusted policy engine. "
                    "AI and artifact parser outputs are not operator-action authorities."
                ),
            },
            "strategic_recommendations": strategic_recs,
            "campaign_intelligence": campaign_intel,
            "ioc_table": ioc_table,
            "attack_timeline": timeline,
            "confidence": analytical_confidence.get('level', 'high'),
            "confidence_source": "heuristic_analytical_evidence_strength",
            "confidence_semantics": "not_a_calibrated_probability",
        }

    async def _detect_platform_and_attack_type_ai(
            self, sessions, tactic_summary) -> Tuple[str, str]:
        platform = 'Unknown'
        attack_type = " / ".join(sorted(tactic_summary.keys())) if tactic_summary else 'Unknown'
        return platform, attack_type

    def _extract_command_evidence_for_ttps(
            self, sessions, tactic_summary, ttp_command_map=None,
            raw_events: List[dict] = None) -> Dict[str, str]:
        """
        Build per-TTP evidence strings with source IP annotation.

        IP attribution strategy:
          1. Build cmd_to_ip from raw Cowrie events (cowrie.command.input has
             both 'input' (the command) and 'src_ip'). This is the most reliable
             source since each event is tied to a specific session/IP.
          2. For commands not in raw_events (e.g. extracted from sessions object),
             fall back to ioc_bundle IP order (session order approximation).
          3. Evidence string format: '[185.x.x.x] cmd; [45.x.x.x] cmd2'
             This makes multi-actor evidence immediately distinguishable.
        """
        ttp_evidence: Dict[str, str] = {}
        all_ttps = set().union(*tactic_summary.values()) if tactic_summary else set()
        if not all_ttps:
            return ttp_evidence

        # cowrie.command.input events contain both 'input' (the command text)
        # and 'src_ip' (the attacker IP that typed it).
        cmd_to_ip: Dict[str, str] = {}
        if raw_events:
            for ev in raw_events:
                eid = ev.get('eventid', '')
                if eid in ('cowrie.command.input', 'cowrie.command.success'):
                    cmd_text = ev.get('input') or ev.get('command') or ''
                    ip = ev.get('src_ip', '')
                    if cmd_text and ip:
                        # Strip trailing whitespace but preserve full command
                        cmd_to_ip[cmd_text.strip()] = ip

        def _annotate(cmd: str) -> str:
            """Return '[IP] cmd' if the command's source IP is known, else just cmd."""
            cmd_s = str(cmd).strip()
            ip = cmd_to_ip.get(cmd_s, '')
            if not ip:
                # Fuzzy fallback: check if any known cmd is a prefix of this one
                for known_cmd, known_ip in cmd_to_ip.items():
                    if cmd_s.startswith(known_cmd[:40]) or known_cmd.startswith(cmd_s[:40]):
                        ip = known_ip
                        break
            prefix = f"[{ip}] " if ip else ''
            return f"{prefix}{cmd_s[:300]}"

        if ttp_command_map:
            for ttp in all_ttps:
                cmds = ttp_command_map.get(ttp, [])
                if cmds:
                    parts = [_annotate(c) for c in cmds[:4]]
                    ttp_evidence[ttp] = 'Observed commands: ' + '; '.join(parts)

        all_session_cmds: List[str] = []
        for s in sessions:
            for c in getattr(s, 'commands_success', []):
                all_session_cmds.append(str(c))

        general_parts = [_annotate(c) for c in all_session_cmds[:5]]
        general_sample = '; '.join(general_parts)

        for ttp in sorted(all_ttps):
            if ttp in ttp_evidence:
                continue
            tactic_found = next(
                (t for t, ttps in tactic_summary.items() if ttp in ttps), None
            )
            phase_label = (
                f"Detected from {tactic_found} phase"
                if tactic_found else "Detected from attack session"
            )
            if general_sample:
                ttp_evidence[ttp] = (
                    f"{phase_label}. Session evidence: {general_sample}"
                )
            else:
                ttp_evidence[ttp] = f"{phase_label} (no session commands captured)"

        return ttp_evidence

    def _normalize_hypothesis(self, hypothesis: dict, ioc_bundle, tactic_summary,
                              sessions, ttp_command_map=None, raw_events=None,
                              confidence=None, confidence_source=None,
                              ai_enriched=None,
                              session_correlations: List[Dict[str, Any]] = None) -> dict:
        """
        Normalize to standard schema. Honeypot fields are populated from
        deterministic functions if AI did not fill them.

        VT intel is extracted here so it's available for _build_analytical_confidence
        and campaign_intelligence fallback without requiring a separate call.
        """
        raw_events = raw_events or []
        ttp_command_map = ttp_command_map or {}
        session_id = getattr(sessions[0], "session_id", "unknown") if sessions else "unknown"
        hunting_context = (
            hypothesis.get("threat_hunting_context")
            or _build_session_correlation_hunting_context(session_correlations, session_id)
        )

        if not hypothesis:
            return self._fallback_hypothesis(ioc_bundle, tactic_summary)

        if confidence is None:
            kc = hypothesis.get('kill_chain_analysis', [])
            confidence = 'medium' if kc and all(e.get('evidence') for e in kc) else 'low'

        if confidence_source is None:
            confidence_source = 'ai_enriched' if confidence == 'medium' else 'deterministic_baseline'

        if ai_enriched is None:
            ai_enriched = (confidence_source == 'ai_enriched')

        # Extract VT intel for use in fallback confidence and intelligence fields
        vt_intel = _extract_vt_intelligence(ioc_bundle)

        # Ensure honeypot fields are present â€” fill deterministically if AI omitted them
        tap = hypothesis.get('threat_actor_profile', {})
        if not isinstance(tap, dict):
            tap = {}
        grounded_actor_profile = _build_evidence_grounded_actor_profile(
            tactic_summary,
            ttp_command_map,
            sessions,
            raw_events=raw_events,
            behavioral_score=int(tap.get("_score") or 0),
            score_reasons=tap.get("_score_reasons") or [],
        )
        grounded_actor_profile = {
            key: value
            for key, value in grounded_actor_profile.items()
            if not key.startswith("_")
        }
        honeypot_intel = hypothesis.get('honeypot_intelligence', {})
        if not honeypot_intel:
            honeypot_intel = {
                "attacker_awareness": _assess_honeypot_awareness(sessions, self.behavioral_rules),
                "campaign_correlation": _build_campaign_correlation(ioc_bundle),
                "session_correlation_findings": hunting_context,
                "attacker_playbook": [],
                "credential_targets": []
            }
        elif isinstance(honeypot_intel, dict):
            honeypot_intel.setdefault("session_correlation_findings", hunting_context)

        threat_hyp = hypothesis.get('threat_hypothesis', {})
        if not threat_hyp:
            fallback_follow_on = _soften_follow_on_hypothesis(_predict_next_action(
                ttp_command_map, ioc_bundle, tactic_summary
            ))
            analytical_evidence_strength = _build_analytical_confidence(
                list(self.detected_ttps), sessions, ioc_bundle,
                ai_enriched, vt_intel=vt_intel,
                thresholds=self.config.get('honeypot_config', {}).get('alert_thresholds', {})
            )
            threat_hyp = {
                "stated_intent": hypothesis.get('primary_objective', 'Under analysis'),
                "predicted_next_action": fallback_follow_on,
                "post_session_follow_on_hypothesis": fallback_follow_on,
                "falsification_conditions": _build_falsification_conditions(
                    ttp_command_map, ioc_bundle, raw_events=raw_events
                ),
                "session_correlations": hunting_context.get("session_correlations", []),
                "correlation_rules_fired": hunting_context.get("correlation_rules_fired", []),
                "analytical_evidence_strength": analytical_evidence_strength,
                "analytical_confidence": analytical_evidence_strength,
                **_threat_hypothesis_semantics(fallback_follow_on),
            }
        elif isinstance(threat_hyp, dict):
            threat_hyp.setdefault("session_correlations", hunting_context.get("session_correlations", []))
            threat_hyp.setdefault("correlation_rules_fired", hunting_context.get("correlation_rules_fired", []))
            strength = threat_hyp.get("analytical_evidence_strength") or threat_hyp.get("analytical_confidence")
            if isinstance(strength, dict):
                threat_hyp.setdefault("analytical_evidence_strength", strength)
                threat_hyp.setdefault("analytical_confidence", strength)
            follow_on = (
                threat_hyp.get("post_session_follow_on_hypothesis")
                or threat_hyp.get("predicted_next_action")
                or ""
            )
            if follow_on:
                threat_hyp.setdefault("predicted_next_action", follow_on)
                follow_on = _soften_follow_on_hypothesis(follow_on)
                threat_hyp["post_session_follow_on_hypothesis"] = follow_on
                threat_hyp["predicted_next_action"] = follow_on
                for key, value in _threat_hypothesis_semantics(follow_on).items():
                    threat_hyp.setdefault(key, value)

        ioc_table = hypothesis.get('ioc_table') or _build_ioc_table(
            raw_events, ioc_bundle, sessions
        )
        timeline = hypothesis.get('attack_timeline') or _build_attack_timeline(raw_events)

        otx_tags = set()
        for ip in ioc_bundle.ips:
            otx_tags.update(getattr(ip, 'otx_tags', []) or [])
        strategic_recs = (
            hypothesis.get('strategic_recommendations') or
            _generate_strategic_recommendations(otx_tags, self.config)
        )

        return {
            "campaign_name": hypothesis.get("campaign_name", "Unknown Operation"),
            "executive_summary": hypothesis.get("executive_summary", "N/A"),
            "primary_objective": hypothesis.get("primary_objective", "N/A"),
            "target_platform": hypothesis.get("target_platform", "Unknown"),
            "threat_actor_profile": grounded_actor_profile,
            "honeypot_intelligence": honeypot_intel,
            "threat_hypothesis": threat_hyp,
            "threat_hunting_context": hunting_context,
            "session_correlations": hunting_context.get("session_correlations", []),
            "correlation_rules_fired": hunting_context.get("correlation_rules_fired", []),
            "kill_chain_analysis": hypothesis.get("kill_chain_analysis", []),
            "recommended_mitigations": hypothesis.get("recommended_mitigations", []),
            "recommended_actions_structured": hypothesis.get("recommended_actions_structured", []),
            "trusted_recommendation_decision": hypothesis.get("trusted_recommendation_decision", {}),
            "artifact_recommendations": hypothesis.get("artifact_recommendations", []),
            "recommendation_provenance": hypothesis.get("recommendation_provenance", {}),
            "strategic_recommendations": strategic_recs,
            "campaign_intelligence": hypothesis.get("campaign_intelligence", ""),
            "ioc_table": ioc_table,
            "attack_timeline": timeline,
            "phases": self._convert_kill_chain_to_phases(
                hypothesis.get("kill_chain_analysis", [])
            ),
            "attack_type": hypothesis.get("primary_objective", "N/A"),
            "analysis_mode": (
                "ai_enriched_vertex" if ai_enriched else "deterministic_baseline"
            ),
            "post_session_follow_on_hypothesis": (
                threat_hyp.get("post_session_follow_on_hypothesis")
                or threat_hyp.get("predicted_next_action", "")
            ),
            "confidence": confidence,
            "confidence_source": confidence_source,
            "ai_enriched": ai_enriched,
            "tokens_used": self.budget.used,
            "token_budget": self.budget.max_tokens,
            "recommended_actions": hypothesis.get("recommended_mitigations", [])
        }

    def _convert_kill_chain_to_phases(self, kill_chain: list) -> list:
        return [
            {
                "phase": f"{e.get('tactic', 'Unknown')} â€” "
                         f"{e.get('technique_name', '')} ({e.get('technique_id', '?')})",
                "ttps": [e.get('technique_id', '?')],
                "description": e.get('evidence', '')
            }
            for e in kill_chain
        ]

    def _fallback_hypothesis(self, ioc_bundle, tactic_summary) -> dict:
        print(f"Using fallback hypothesis | tokens={self.budget.used}/{self.budget.max_tokens}")
        return {
            "campaign_name": "Automated Attack â€” Unable to Classify",
            "executive_summary": (
                f"Detected {len(ioc_bundle.ips)} unique IPs and "
                f"{len(tactic_summary)} tactics â€” insufficient evidence to classify"
            ),
            "primary_objective": "Unknown (insufficient evidence)",
            "target_platform": "Unknown",
            "threat_actor_profile": {"type": "Unknown", "sophistication": "Unknown",
                                     "description": "N/A"},
            "honeypot_intelligence": {},
            "threat_hypothesis": {
                "stated_intent": "Unknown",
                "predicted_next_action": "Insufficient evidence to construct a falsifiable follow-on hypothesis.",
                "post_session_follow_on_hypothesis": "Insufficient evidence to construct a falsifiable follow-on hypothesis.",
                "falsification_conditions": [],
                "analytical_evidence_strength": {
                    "level": "Low",
                    "reason": "Fallback: no trusted TTPs detected",
                    "metric_name": "analytical_evidence_strength",
                    "method": "heuristic_evidence_strength_v1",
                    "calibrated_probability": False,
                    "description": "Heuristic evidence strength; not a calibrated probability.",
                },
                "analytical_confidence": {
                    "level": "Low",
                    "reason": "Compatibility alias for heuristic analytical evidence strength",
                    "calibrated_probability": False,
                },
                **_threat_hypothesis_semantics(
                    "Insufficient evidence to construct a falsifiable follow-on hypothesis."
                ),
            },
            "kill_chain_analysis": [],
            "recommended_mitigations": [],
            "recommended_actions_structured": [],
            "trusted_recommendation_decision": {},
            "recommendation_provenance": {
                "authority": "policy_unavailable",
                "status": "pending_policy_evaluation",
                "policy_action_count": 0,
                "fallback_actions_allowed": False,
            },
            "strategic_recommendations": [],
            "campaign_intelligence": "",
            "ioc_table": {},
            "attack_timeline": {},
            "phases": [],
            "attack_type": "Unknown",
            "post_session_follow_on_hypothesis": "Insufficient evidence",
            "confidence": "low",
            "confidence_source": "fallback",
            "ai_enriched": False,
            "tokens_used": self.budget.used,
            "token_budget": self.budget.max_tokens,
            "recommended_actions": []
        }


# DISPLAY HELPER (fixes raw dict rendering â€” Bug 5a)

def print_hypothesis_report(result: dict) -> None:
    """
    Render the hypothesis to stdout in readable format.

    Previously: print(result['threat_actor_profile']) â†’ raw Python dict.
    Now: each field extracted and formatted explicitly.
    """
    try:
        result = _safe_reporting_mapping(result, "report")
    except Exception:
        print("\n[Report unavailable: redaction failed]")
        return

    print("\n" + "=" * 70)
    print("[OK] Threat Hypothesis Complete")
    print("=" * 70)

    print(f"Campaign      : {result.get('campaign_name', 'N/A')}")
    print(f"Confidence    : {result.get('confidence', 'N/A')} "
          f"[source: {result.get('confidence_source', 'N/A')}] "
          f"[ai_enriched: {result.get('ai_enriched', False)}]")
    print(f"Tokens Used   : {result.get('tokens_used', 0)} / "
          f"{result.get('token_budget', 0)}")

    print(f"\nExecutive Summary:\n   {result.get('executive_summary', 'N/A')}")

    tap = result.get('threat_actor_profile', {})
    print(f"\nThreat Actor Profile:")
    print(f"   Type           : {tap.get('type', 'Unknown')}")
    print(f"   Sophistication : {tap.get('sophistication', 'Unknown')}")
    print(f"   Description    : {tap.get('description', 'N/A')}")

    hi = result.get('honeypot_intelligence', {})
    if hi:
        awareness = hi.get('attacker_awareness', {})
        print(f"\nHoneypot Intelligence:")
        if isinstance(awareness, dict):
            print(f"   Attacker awareness : {awareness.get('assessment', 'N/A')}")
            print(f"   Note               : {awareness.get('note', 'N/A')}")
        cc = hi.get('campaign_correlation', {})
        if isinstance(cc, dict):
            print(f"   Campaign           : {cc.get('assessment', 'N/A')}")
        targets = hi.get('credential_targets', [])
        if targets:
            print(f"   Credential targets : {', '.join(targets[:5])}")

    th = result.get('threat_hypothesis', {})
    if th:
        print(f"\nThreat Hypothesis:")
        print(f"   Stated intent      : {th.get('stated_intent', 'N/A')}")
        follow_on = (
            th.get('post_session_follow_on_hypothesis')
            or th.get('predicted_next_action', 'N/A')
        )
        print(f"   Follow-on hypothesis: {follow_on}")
        ac = th.get('analytical_confidence', {})
        if isinstance(ac, dict):
            print(f"   Confidence         : {ac.get('level', 'N/A')} â€” "
                  f"{ac.get('reason', 'N/A')}")
        fc = th.get('falsification_conditions', [])
        if fc:
            print(f"   Falsification:")
            for cond in fc[:4]:
                print(f"     * {cond}")

    print(f"\nAttack Phases ({len(result.get('kill_chain_analysis', []))} techniques):")
    for entry in result.get('kill_chain_analysis', []):
        print(f"   [{entry.get('technique_id', '?')}] "
              f"{entry.get('tactic', '?')} â€” {entry.get('technique_name', '?')}")
        # Full evidence is required for forensic use â€” do NOT truncate here.
        # IR teams use this for IOC hunting, EDR queries, and SIEM correlation.
        # Truncating URLs, file paths, or hashes makes this evidence unusable.
        evidence_str = str(entry.get('evidence', ''))
        print(f"       > {evidence_str}")

    timeline = result.get('attack_timeline', {})
    if timeline:
        print(f"\nAttack Timeline: {timeline.get('first_seen', '?')} "
              f"to {timeline.get('last_seen', '?')}")
        for evt in timeline.get('key_events', [])[:5]:
            print(f"   {evt.get('timestamp', '?')} â€” {evt.get('event', '?')}")

    ioc = result.get('ioc_table', {})
    if ioc:
        print(f"\nIOC Summary:")
        if ioc.get('source_ips'):
            print(f"   Source IPs         : {', '.join(ioc['source_ips'][:6])}")
        if ioc.get('external_urls') or ioc.get('c2_urls'):
            urls = ioc.get('external_urls') or ioc.get('c2_urls')
            print(f"   External URLs      : {', '.join(urls[:3])}")
        if ioc.get('file_hashes'):
            print(f"   File hashes:")
            for path, sha in ioc['file_hashes'].items():
                print(f"     {path} â†’ SHA256: {sha}")
        if ioc.get('created_accounts'):
            print(f"   Created accounts   : {', '.join(ioc['created_accounts'])}")
        if ioc.get('implanted_ssh_keys'):
            print(f"   Implanted SSH keys : {len(ioc['implanted_ssh_keys'])} key(s)")

    print(f"\nRecommended Actions:")
    for action in result.get('recommended_mitigations', []):
        print(f"   * {action}")

    strategic = result.get('strategic_recommendations', [])
    if strategic:
        print(f"\nStrategic Recommendations:")
        for rec in strategic:
            print(f"   * {rec}")

    ci = result.get('campaign_intelligence', '')
    if ci:
        print(f"\nCampaign Intelligence:\n   {ci}")


# JUPYTER-SAFE ASYNCIO RUNNER

def run_async_in_jupyter(coro):
    try:
        import nest_asyncio
        nest_asyncio.apply()
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)
