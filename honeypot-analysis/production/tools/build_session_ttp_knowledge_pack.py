"""Build a versioned session TTP knowledge pack.

This command is intentionally conservative. It can package the currently
trusted correlation policy and record metadata about ATT&CK, Sigma, and
external Cowrie artifacts, but it does not pretend those artifacts have been
converted into active correlation rules unless a rule is actually emitted.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from production.utils.serialization import utc_now
from production.correlation.session_ttp_knowledge import (
    KNOWLEDGE_PACK_SCHEMA_VERSION,
    file_sha256,
    load_json_document,
    main_ttp_id,
    normalize_correlation_document,
    source_artifact_status,
    summarize_rules,
)


LEVEL_CONFIDENCE = {
    "critical": 0.78,
    "high": 0.72,
    "medium": 0.62,
    "low": 0.52,
}

LEVEL_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "info": 0,
}

GENERIC_KEYWORDS = {
    "",
    ".",
    "..",
    "/",
    "sh",
    "id",
    "ls",
    "cat",
    "env",
    "pwd",
    "who",
    "echo",
    "bash",
    "sudo",
    "grep",
    "find",
    "touch",
    "chmod",
    "chown",
    "delete",
    "flush",
    "password",
    "passwd",
    "user",
    "name",
    "file",
    "path",
    "root",
    "admin",
    "test",
    "temp",
    "tmp",
}

SPECIFIC_COMMAND_TOKENS = {
    "curl",
    "wget",
    "scp",
    "sftp",
    "tftp",
    "rsync",
    "ftp",
    "ncat",
    "socat",
    "base64",
    "certutil",
    "powershell",
    "python",
    "perl",
    "crontab",
    "ssh-keygen",
    "authorized_keys",
    "iptables",
}

TACTIC_TAG_PREFIX = "attack."
TTP_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
RAW_TTP_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
CODE_TOKEN_RE = re.compile(r"`([^`]{2,80})`|<code>([^<]{2,80})</code>", re.IGNORECASE)
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]{2,80})\]\([^)]+\)")


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _slug(value: Any) -> str:
    return _clean_text(value).lower().replace(" ", "-").replace("_", "-")


def _safe_rule_id(*parts: Any) -> str:
    text = "-".join(_clean_text(part) for part in parts if _clean_text(part))
    text = re.sub(r"[^a-zA-Z0-9_.-]+", "-", text).strip("-").lower()
    return text.replace(".", "-")[:180]


def _policy_rules(base_policy_path: str) -> List[Dict[str, Any]]:
    if not base_policy_path:
        return []
    document = load_json_document(base_policy_path)
    normalized = normalize_correlation_document(document, base_policy_path)
    rules = [
        dict(rule)
        for rule in ((normalized.get("policy") or {}).get("rules") or [])
        if isinstance(rule, dict)
    ]
    for rule in rules:
        provenance = dict(rule.get("provenance") or {})
        provenance.setdefault("generated", False)
        provenance.setdefault("source_artifact", base_policy_path)
        provenance.setdefault("artifact_sha256", file_sha256(base_policy_path))
        rule["provenance"] = provenance
        rule.setdefault("source_document_type", "policy")
        rule.setdefault("source_document_path", base_policy_path)
    return rules


def _load_mitre_techniques(path: str) -> Dict[str, Dict[str, Any]]:
    if not path or not Path(path).exists():
        return {}
    document = load_json_document(path)
    techniques = document.get("techniques") or {}
    return techniques if isinstance(techniques, dict) else {}


def _technique_details(techniques: Dict[str, Dict[str, Any]], tid: str, fallback_tactic: str = "") -> Tuple[str, str, List[str]]:
    record = techniques.get(tid) or {}
    name = _clean_text(record.get("name") or tid)
    raw_tactics = [_slug(item) for item in _as_list(record.get("tactics")) if _clean_text(item)]
    tactic = raw_tactics[0] if raw_tactics else fallback_tactic
    platforms = [_clean_text(item) for item in _as_list(record.get("platforms")) if _clean_text(item)]
    return name, tactic, platforms


def _active_technique_details(
    techniques: Dict[str, Dict[str, Any]],
    source_tid: str,
    fallback_tactic: str = "",
) -> Tuple[str, str, List[str], str, str, str]:
    """Return parent technique details while preserving source sub-technique."""

    source_tid = _clean_text(source_tid).upper()
    active_tid = main_ttp_id(source_tid)
    source_name, source_tactic, source_platforms = _technique_details(techniques, source_tid, fallback_tactic)
    active_name, active_tactic, active_platforms = _technique_details(
        techniques,
        active_tid,
        source_tactic or fallback_tactic,
    )
    platforms = active_platforms or source_platforms
    return active_tid, active_name, active_tactic or source_tactic, platforms, source_tid, source_name


def _attack_technique_url(tid: str) -> str:
    return f"https://attack.mitre.org/techniques/{_clean_text(tid).upper().replace('.', '/')}/"


def _extract_ttp_ids(value: Any) -> List[str]:
    found: List[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in {"technique_id", "technique", "ttp", "attack_id", "mitre_id"}:
                found.extend(_extract_ttp_ids(item))
            elif str(key).lower() in {"techniques", "ttps", "attack", "attack_ids", "mitre_attack"}:
                found.extend(_extract_ttp_ids(item))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            found.extend(_extract_ttp_ids(item))
    else:
        text = _clean_text(value)
        found.extend(match.group(0).upper() for match in RAW_TTP_RE.finditer(text))
    return _unique_source_ttps(found)


def _unique_source_ttps(values: Iterable[Any]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        text = _clean_text(value).upper()
        if not text or not RAW_TTP_RE.fullmatch(text):
            continue
        if text not in seen:
            seen.add(text)
            output.append(text)
    return output


def _unique_ttps(values: Iterable[Any]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        text = _clean_text(value).upper()
        if not text:
            continue
        active = main_ttp_id(text)
        if active and active not in seen:
            seen.add(active)
            output.append(active)
    return output


def _confidence_from_support(count: float, total: float, base: float = 0.50, cap: float = 0.78) -> float:
    total = max(float(total or 0.0), 1.0)
    count = max(float(count or 0.0), 0.0)
    probability = count / total
    support_bonus = min(count / 100.0, 0.15)
    return round(min(cap, max(base, base + probability * 0.20 + support_bonus)), 4)


def _safe_sigma_keywords(keywords: Iterable[Any], max_keywords: int = 12) -> List[str]:
    safe: List[str] = []
    for keyword in keywords:
        text = _clean_text(keyword)
        folded = text.lower().strip("'\"")
        if len(folded) < 4:
            continue
        if folded in GENERIC_KEYWORDS:
            continue
        specific = (
            folded in SPECIFIC_COMMAND_TOKENS
            or any(folded.startswith(f"{token} ") for token in SPECIFIC_COMMAND_TOKENS)
            or any(folded.startswith(f"{token}.") for token in SPECIFIC_COMMAND_TOKENS)
            or len(folded) >= 8
            or any(marker in folded for marker in ("/", "-", "=", " ", ".", "_", ":", "$", "*"))
        )
        if not specific:
            continue
        if not any(ch.isalnum() for ch in folded):
            continue
        if "\x00" in folded or "\n" in folded or "\r" in folded:
            continue
        if len(folded) > 120:
            continue
        if text not in safe:
            safe.append(text)
        if len(safe) >= max_keywords:
            break
    return safe


def _safe_command_keywords(keywords: Iterable[Any], max_keywords: int = 12) -> List[str]:
    return _safe_sigma_keywords(keywords, max_keywords=max_keywords)


def _extract_mitre_description_keywords(record: Dict[str, Any], max_keywords: int = 12) -> List[str]:
    description = _clean_text(record.get("description"))
    candidates: List[str] = []
    for match in CODE_TOKEN_RE.finditer(description):
        token = match.group(1) or match.group(2) or ""
        candidates.append(token)
    for match in MARKDOWN_LINK_RE.finditer(description):
        label = _clean_text(match.group(1))
        folded = label.lower()
        if folded in SPECIFIC_COMMAND_TOKENS or any(marker in folded for marker in ("/", "-", "=", ".", "_", ":", "$", "*")):
            candidates.append(label)
    for token in SPECIFIC_COMMAND_TOKENS:
        pattern = re.compile(rf"(?<![A-Za-z0-9_.-]){re.escape(token)}(?![A-Za-z0-9_.-])", re.IGNORECASE)
        if pattern.search(description):
            candidates.append(token)
    return _safe_command_keywords(candidates, max_keywords=max_keywords)


def _regex_for_keywords(keywords: List[str]) -> str:
    escaped = [re.escape(keyword) for keyword in keywords]
    return r"(?:" + "|".join(escaped) + r")"


def _sigma_rules_iter(document: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    rules = document.get("rules") or {}
    if isinstance(rules, dict):
        for rule_id, rule in rules.items():
            if isinstance(rule, dict):
                yield str(rule_id), rule
    elif isinstance(rules, list):
        for index, rule in enumerate(rules):
            if isinstance(rule, dict):
                yield str(rule.get("id") or rule.get("rule_id") or index), rule


def _sigma_attack_tags(rule: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    ttps: List[str] = []
    tactics: List[str] = []
    for tag in _as_list(rule.get("tags")):
        text = _clean_text(tag).lower()
        match = TTP_TAG_RE.match(text)
        if match:
            tid = match.group(1).upper()
            if tid not in ttps:
                ttps.append(tid)
            continue
        if text.startswith(TACTIC_TAG_PREFIX) and not text.startswith("attack.t"):
            tactic = _slug(text[len(TACTIC_TAG_PREFIX):])
            if tactic and tactic not in tactics:
                tactics.append(tactic)
    return ttps, tactics


def _sigma_level_allowed(level: str, minimum_level: str) -> bool:
    return LEVEL_ORDER.get(_clean_text(level).lower(), 0) >= LEVEL_ORDER.get(_clean_text(minimum_level).lower(), 1)


def _sigma_platform_allowed(rule: Dict[str, Any], platforms: List[str]) -> bool:
    logsource = rule.get("logsource") if isinstance(rule.get("logsource"), dict) else {}
    product = _clean_text(logsource.get("product")).lower()
    service = _clean_text(logsource.get("service")).lower()
    if product in {"linux", "unix"} or service in {"auditd", "sshd", "ssh"}:
        return True
    if product in {"network", "proxy", "firewall"}:
        return True
    if not platforms:
        return True
    return any(platform.lower() in {"linux", "macos", "network"} for platform in platforms)


def _generate_sigma_correlation_rules(
    sigma_cache_path: str,
    mitre_cache_path: str,
    *,
    min_level: str = "medium",
    max_rules: int = 50,
    apply_to_prediction: bool = False,
) -> List[Dict[str, Any]]:
    if not sigma_cache_path or not Path(sigma_cache_path).exists():
        return []
    sigma_document = load_json_document(sigma_cache_path)
    techniques = _load_mitre_techniques(mitre_cache_path)
    artifact_hash = file_sha256(sigma_cache_path)
    created = utc_now().split("T", 1)[0]
    generated: List[Dict[str, Any]] = []
    for sigma_id, rule in _sigma_rules_iter(sigma_document):
        level = _clean_text(rule.get("level") or "low").lower()
        if not _sigma_level_allowed(level, min_level):
            continue
        ttps, tactic_tags = _sigma_attack_tags(rule)
        if not ttps:
            continue
        keywords = _safe_sigma_keywords(rule.get("keywords") or [])
        if not keywords:
            continue
        for tid in ttps:
            fallback_tactic = tactic_tags[0] if tactic_tags else ""
            active_tid, technique_name, tactic, platforms, source_tid, source_name = _active_technique_details(
                techniques,
                tid,
                fallback_tactic,
            )
            if not tactic:
                continue
            if not _sigma_platform_allowed(rule, platforms):
                continue
            title = _clean_text(rule.get("title") or sigma_id)
            source_is_subtechnique = bool(source_tid and source_tid != active_tid)
            rule_id = f"sigma-{sigma_id}-{source_tid}".lower().replace(".", "-")
            references = [
                {
                    "name": f"Sigma rule {sigma_id}: {title}",
                    "url": "https://github.com/SigmaHQ/sigma",
                },
                {
                    "name": f"MITRE ATT&CK {active_tid} {technique_name}",
                    "url": _attack_technique_url(active_tid),
                },
            ]
            if source_is_subtechnique:
                references.append(
                    {
                        "name": f"Source ATT&CK sub-technique {source_tid} {source_name}",
                        "url": _attack_technique_url(source_tid),
                    }
                )
            generated.append(
                {
                    "rule_id": rule_id,
                    "enabled": True,
                    "ttp": active_tid,
                    "source_ttp": source_tid if source_is_subtechnique else active_tid,
                    "source_subtechnique": source_tid if source_is_subtechnique else "",
                    "technique_granularity": "subtechnique_collapsed" if source_is_subtechnique else "parent",
                    "tactic": tactic,
                    "technique_name": technique_name,
                    "confidence": LEVEL_CONFIDENCE.get(level, 0.52),
                    "evidence_type": "session_correlated_candidate",
                    "source_type": "sigma_detection_correlation",
                    "temporal_claim": False,
                    "apply_to_prediction": bool(apply_to_prediction),
                    "reason": (
                        f"Sigma rule '{title}' explicitly tags {source_tid} and contains command/detection "
                        "keywords that can be matched against Cowrie command text. This is detection "
                        "context, not a temporal next-step claim. The active TTP is collapsed to the "
                        f"parent technique {active_tid} for scope control."
                    ),
                    "conditions": {
                        "any": [
                            {
                                "type": "command_regex",
                                "pattern": _regex_for_keywords(keywords),
                                "description": f"Command text matches extracted Sigma keywords from '{title}'.",
                            }
                        ]
                    },
                    "references": references,
                    "provenance": {
                        "method": "sigma_cache_attack_tag_keyword_import",
                        "basis": [
                            "Sigma rule has explicit ATT&CK technique tag",
                            "Sigma cache contains extracted detection keywords",
                            "MITRE ATT&CK cache used for technique name/tactic when available",
                        ],
                        "author": "production.tools.build_session_ttp_knowledge_pack",
                        "reviewed": False,
                        "generated": True,
                        "source_artifact": sigma_cache_path,
                        "artifact_sha256": artifact_hash,
                        "source_rule_id": sigma_id,
                        "source_rule_title": title,
                        "source_ttp": source_tid,
                        "active_ttp": active_tid,
                        "created": created,
                        "version": "1.0",
                    },
                    "metadata": {
                        "sigma_id": sigma_id,
                        "sigma_title": title,
                        "sigma_level": level,
                        "sigma_status": rule.get("status") or "",
                        "sigma_tags": rule.get("tags") or [],
                        "sigma_keywords": keywords,
                        "source_ttp": source_tid,
                        "source_subtechnique": source_tid if source_is_subtechnique else "",
                        "active_ttp": active_tid,
                        "technique_granularity": "subtechnique_collapsed" if source_is_subtechnique else "parent",
                        "logsource": rule.get("logsource") or {},
                        "generation_warning": (
                            "Generated from Sigma detection metadata. Review before enabling "
                            "prediction influence."
                        ),
                    },
                }
            )
            if len(generated) >= max_rules:
                return generated
    return generated


def _generate_mitre_command_correlation_rules(
    mitre_cache_path: str,
    *,
    max_rules: int = 25,
    apply_to_prediction: bool = False,
) -> List[Dict[str, Any]]:
    """Generate conservative candidate rules from ATT&CK command examples.

    These are not temporal claims. They only say that MITRE ATT&CK text for a
    technique includes concrete command/tool examples that matched Cowrie text.
    """

    if not mitre_cache_path or not Path(mitre_cache_path).exists():
        return []
    techniques = _load_mitre_techniques(mitre_cache_path)
    artifact_hash = file_sha256(mitre_cache_path)
    created = utc_now().split("T", 1)[0]
    generated: List[Dict[str, Any]] = []
    for source_tid, record in sorted(techniques.items()):
        if not isinstance(record, dict):
            continue
        active_tid, technique_name, tactic, platforms, source_tid, source_name = _active_technique_details(
            techniques,
            source_tid,
            "",
        )
        if not tactic:
            continue
        if platforms and not any(str(platform).lower() in {"linux", "macos", "network"} for platform in platforms):
            continue
        keywords = _extract_mitre_description_keywords(record)
        if not keywords:
            continue
        source_is_subtechnique = source_tid != active_tid
        references = [
            {
                "name": f"MITRE ATT&CK {active_tid} {technique_name}",
                "url": _attack_technique_url(active_tid),
            }
        ]
        if source_is_subtechnique:
            references.append(
                {
                    "name": f"Source ATT&CK sub-technique {source_tid} {source_name}",
                    "url": _attack_technique_url(source_tid),
                }
            )
        generated.append(
            {
                "rule_id": _safe_rule_id("mitre-command", source_tid),
                "enabled": True,
                "ttp": active_tid,
                "source_ttp": source_tid,
                "source_subtechnique": source_tid if source_is_subtechnique else "",
                "technique_granularity": "subtechnique_collapsed" if source_is_subtechnique else "parent",
                "tactic": tactic,
                "technique_name": technique_name,
                "confidence": 0.58,
                "evidence_type": "knowledge_pack_correlation",
                "source_type": "mitre_attack_stix",
                "temporal_claim": False,
                "apply_to_prediction": bool(apply_to_prediction),
                "reason": (
                    f"MITRE ATT&CK technique text for {source_tid} includes concrete command/tool "
                    "examples that can be matched against Cowrie command text. This is observed-behavior "
                    "context, not a next-step or causality claim."
                ),
                "conditions": {
                    "any": [
                        {
                            "type": "command_regex",
                            "pattern": _regex_for_keywords(keywords),
                            "description": f"Command text matches concrete examples extracted from ATT&CK {source_tid}.",
                        }
                    ]
                },
                "references": references,
                "provenance": {
                    "method": "mitre_attack_cache_description_code_token_import",
                    "basis": [
                        "MITRE ATT&CK cache contains technique descriptions",
                        "Concrete command/tool examples were extracted from code-formatted text",
                        "Rule is candidate observed-behavior context and defaults to no prediction influence",
                    ],
                    "author": "production.tools.build_session_ttp_knowledge_pack",
                    "reviewed": False,
                    "generated": True,
                    "source_artifact": mitre_cache_path,
                    "artifact_sha256": artifact_hash,
                    "source_ttp": source_tid,
                    "active_ttp": active_tid,
                    "created": created,
                    "version": "1.0",
                },
                "metadata": {
                    "source_ttp": source_tid,
                    "source_subtechnique": source_tid if source_is_subtechnique else "",
                    "active_ttp": active_tid,
                    "mitre_keywords": keywords,
                    "platforms": platforms,
                    "generation_warning": (
                        "Generated from ATT&CK technique text. Review before enabling prediction influence."
                    ),
                },
            }
        )
        if len(generated) >= max_rules:
            break
    return generated


def _car_analytics_iter(document: Any) -> Iterable[Tuple[str, Dict[str, Any]]]:
    if isinstance(document, dict):
        analytics = (
            document.get("analytics")
            or document.get("rules")
            or document.get("detections")
            or document.get("car_analytics")
            or document.get("objects")
        )
        if isinstance(analytics, dict):
            for analytic_id, analytic in analytics.items():
                if isinstance(analytic, dict):
                    yield str(analytic_id), analytic
        elif isinstance(analytics, list):
            for index, analytic in enumerate(analytics):
                if isinstance(analytic, dict):
                    yield str(analytic.get("id") or analytic.get("rule_id") or index), analytic
        else:
            yield str(document.get("id") or document.get("rule_id") or "car-analytic"), document
    elif isinstance(document, list):
        for index, analytic in enumerate(document):
            if isinstance(analytic, dict):
                yield str(analytic.get("id") or analytic.get("rule_id") or index), analytic


def _extract_car_keywords(analytic: Dict[str, Any]) -> List[str]:
    candidates: List[Any] = []
    for key in ("keywords", "command_keywords", "commands", "command", "query", "logic", "description"):
        value = analytic.get(key)
        if isinstance(value, (list, tuple, set)):
            candidates.extend(value)
        elif isinstance(value, str):
            candidates.extend(CODE_TOKEN_RE.findall(value))
            candidates.append(value)
    flattened = []
    for item in candidates:
        if isinstance(item, tuple):
            flattened.extend(part for part in item if part)
        else:
            flattened.append(item)
    return _safe_command_keywords(flattened)


def _generate_car_correlation_rules(
    car_cache_path: str,
    mitre_cache_path: str,
    *,
    max_rules: int = 25,
    apply_to_prediction: bool = False,
) -> List[Dict[str, Any]]:
    if not car_cache_path or not Path(car_cache_path).exists():
        return []
    document = load_json_document(car_cache_path)
    techniques = _load_mitre_techniques(mitre_cache_path)
    artifact_hash = file_sha256(car_cache_path)
    created = utc_now().split("T", 1)[0]
    generated: List[Dict[str, Any]] = []
    for analytic_id, analytic in _car_analytics_iter(document):
        ttps = _extract_ttp_ids(analytic)
        if not ttps:
            continue
        keywords = _extract_car_keywords(analytic)
        if not keywords:
            continue
        title = _clean_text(analytic.get("title") or analytic.get("name") or analytic_id)
        for tid in ttps:
            active_tid, technique_name, tactic, platforms, source_tid, source_name = _active_technique_details(
                techniques,
                tid,
                "",
            )
            if not tactic:
                continue
            source_is_subtechnique = source_tid != active_tid
            references = [
                {"name": f"MITRE CAR analytic {analytic_id}: {title}", "url": "https://car.mitre.org/"},
                {"name": f"MITRE ATT&CK {active_tid} {technique_name}", "url": _attack_technique_url(active_tid)},
            ]
            if source_is_subtechnique:
                references.append(
                    {"name": f"Source ATT&CK sub-technique {source_tid} {source_name}", "url": _attack_technique_url(source_tid)}
                )
            generated.append(
                {
                    "rule_id": _safe_rule_id("car", analytic_id, source_tid),
                    "enabled": True,
                    "ttp": active_tid,
                    "source_ttp": source_tid,
                    "source_subtechnique": source_tid if source_is_subtechnique else "",
                    "technique_granularity": "subtechnique_collapsed" if source_is_subtechnique else "parent",
                    "tactic": tactic,
                    "technique_name": technique_name,
                    "confidence": 0.64,
                    "evidence_type": "knowledge_pack_correlation",
                    "source_type": "mitre_car_analytic",
                    "temporal_claim": False,
                    "apply_to_prediction": bool(apply_to_prediction),
                    "reason": (
                        f"MITRE CAR-style analytic '{title}' maps to {source_tid} and contains "
                        "command/query terms that matched Cowrie command text. This is detection "
                        "analytic context, not temporal prediction."
                    ),
                    "conditions": {
                        "any": [
                            {
                                "type": "command_regex",
                                "pattern": _regex_for_keywords(keywords),
                                "description": f"Command text matches terms extracted from CAR analytic '{title}'.",
                            }
                        ]
                    },
                    "references": references,
                    "provenance": {
                        "method": "mitre_car_analytic_keyword_import",
                        "basis": [
                            "CAR analytic contains ATT&CK technique reference",
                            "CAR analytic contains command/query keywords",
                            "Rule is candidate observed-behavior context and defaults to no prediction influence",
                        ],
                        "author": "production.tools.build_session_ttp_knowledge_pack",
                        "reviewed": False,
                        "generated": True,
                        "source_artifact": car_cache_path,
                        "artifact_sha256": artifact_hash,
                        "source_rule_id": analytic_id,
                        "source_rule_title": title,
                        "source_ttp": source_tid,
                        "active_ttp": active_tid,
                        "created": created,
                        "version": "1.0",
                    },
                    "metadata": {
                        "car_id": analytic_id,
                        "car_title": title,
                        "car_keywords": keywords,
                        "source_ttp": source_tid,
                        "active_ttp": active_tid,
                        "platforms": platforms,
                    },
                }
            )
            if len(generated) >= max_rules:
                return generated
    return generated


def _generate_external_seed_correlation_rules(
    external_seed_model_path: str,
    mitre_cache_path: str,
    *,
    min_support: float = 25.0,
    max_rules: int = 25,
    apply_to_prediction: bool = False,
) -> List[Dict[str, Any]]:
    """Generate observed sequence rules from an external Cowrie transition model."""

    if not external_seed_model_path or not Path(external_seed_model_path).exists():
        return []
    document = load_json_document(external_seed_model_path)
    model = document.get("model") if isinstance(document.get("model"), dict) else document
    if not isinstance(model, dict):
        return []
    techniques = _load_mitre_techniques(mitre_cache_path)
    technique_transitions = model.get("technique_transitions") or {}
    if not isinstance(technique_transitions, dict):
        return []
    technique_tactics = model.get("technique_tactics") or {}
    if not isinstance(technique_tactics, dict):
        technique_tactics = {}
    artifact_hash = file_sha256(external_seed_model_path)
    created = utc_now().split("T", 1)[0]
    usable_sessions = int(model.get("usable_sessions") or 0)
    generated: List[Dict[str, Any]] = []
    candidates: List[Tuple[float, str, str, float]] = []
    for source_ttp, targets in technique_transitions.items():
        if not isinstance(targets, dict):
            continue
        total = sum(float(value or 0.0) for value in targets.values())
        for target_ttp, count in targets.items():
            count = float(count or 0.0)
            if count >= min_support:
                candidates.append((count, _clean_text(source_ttp).upper(), _clean_text(target_ttp).upper(), total))
    candidates.sort(reverse=True)
    for count, source_ttp, target_ttp, total in candidates:
        source_active = main_ttp_id(source_ttp)
        target_active, technique_name, tactic, _platforms, target_source, target_name = _active_technique_details(
            techniques,
            target_ttp,
            "",
        )
        if not tactic:
            tactic_values = technique_tactics.get(target_active) or technique_tactics.get(target_ttp) or {}
            if isinstance(tactic_values, dict) and tactic_values:
                tactic = max(tactic_values.items(), key=lambda item: float(item[1] or 0.0))[0]
        if not tactic:
            continue
        source_is_subtechnique = target_source != target_active
        generated.append(
            {
                "rule_id": _safe_rule_id("external-seed-sequence", source_ttp, target_ttp),
                "enabled": True,
                "ttp": target_active,
                "source_ttp": target_source,
                "source_subtechnique": target_source if source_is_subtechnique else "",
                "technique_granularity": "subtechnique_collapsed" if source_is_subtechnique else "parent",
                "tactic": tactic,
                "technique_name": technique_name,
                "confidence": _confidence_from_support(count, total, base=0.55, cap=0.76),
                "evidence_type": "external_dataset_correlation",
                "source_type": "external_cowrie_seed",
                "temporal_claim": True,
                "apply_to_prediction": bool(apply_to_prediction),
                "reason": (
                    f"External Cowrie seed sessions observed {source_active} followed by {target_active} "
                    f"{count:.0f} time(s). This rule only fires after both techniques are observed in "
                    "the current session, so it supports session-level behavior rather than inventing "
                    "a final TTP from context alone."
                ),
                "conditions": {
                    "all": [
                        {
                            "type": "ordered_ttps",
                            "sequence": [source_active, target_active],
                            "description": "Current session contains a technique sequence observed in the external Cowrie seed model.",
                        }
                    ]
                },
                "references": [
                    {"name": "External Cowrie seed transition model", "url": ""},
                    {"name": f"MITRE ATT&CK {target_active} {technique_name}", "url": _attack_technique_url(target_active)},
                ],
                "provenance": {
                    "method": "external_cowrie_seed_technique_transition_import",
                    "basis": [
                        "External Cowrie dataset was classified into ATT&CK technique sequences",
                        "Technique transition met minimum support threshold",
                        "Rule requires the sequence to be observed in the current session before correlating",
                    ],
                    "author": "production.tools.build_session_ttp_knowledge_pack",
                    "reviewed": False,
                    "generated": True,
                    "source_artifact": external_seed_model_path,
                    "artifact_sha256": artifact_hash,
                    "source_model_id": model.get("model_id") or document.get("model_id") or "",
                    "source_model_type": model.get("source_type") or "external_cowrie_seed",
                    "usable_sessions": usable_sessions,
                    "transition_support": count,
                    "transition_total_from_source": total,
                    "source_ttp": target_source,
                    "active_ttp": target_active,
                    "created": created,
                    "version": "1.0",
                },
                "metadata": {
                    "source_sequence": [source_ttp, target_ttp],
                    "active_sequence": [source_active, target_active],
                    "transition_support": count,
                    "transition_probability": round(count / max(total, 1.0), 4),
                    "usable_sessions": usable_sessions,
                    "min_support": min_support,
                },
            }
        )
        if len(generated) >= max_rules:
            break
    return generated


def build_knowledge_pack(
    *,
    base_policy_path: str = "",
    mitre_cache_path: str = "",
    sigma_cache_path: str = "",
    car_cache_path: str = "",
    external_seed_model_path: str = "",
    pack_id: str = "honeypot-session-ttp-knowledge-pack",
    version: str = "",
    generate_sigma_rules: bool = False,
    generate_mitre_command_rules: bool = False,
    generate_car_rules: bool = False,
    generate_external_seed_rules: bool = False,
    sigma_min_level: str = "medium",
    max_sigma_rules: int = 50,
    max_mitre_command_rules: int = 25,
    max_car_rules: int = 25,
    max_external_seed_rules: int = 25,
    external_seed_min_support: float = 25.0,
    sigma_apply_to_prediction: bool = False,
    mitre_apply_to_prediction: bool = False,
    car_apply_to_prediction: bool = False,
    external_seed_apply_to_prediction: bool = False,
) -> Dict[str, Any]:
    rules = _policy_rules(base_policy_path)
    base_rule_count = len(rules)
    sigma_generated_rules: List[Dict[str, Any]] = []
    mitre_generated_rules: List[Dict[str, Any]] = []
    car_generated_rules: List[Dict[str, Any]] = []
    external_seed_generated_rules: List[Dict[str, Any]] = []
    if generate_sigma_rules:
        sigma_generated_rules = _generate_sigma_correlation_rules(
            sigma_cache_path,
            mitre_cache_path,
            min_level=sigma_min_level,
            max_rules=max_sigma_rules,
            apply_to_prediction=sigma_apply_to_prediction,
        )
        rules.extend(sigma_generated_rules)
    if generate_mitre_command_rules:
        mitre_generated_rules = _generate_mitre_command_correlation_rules(
            mitre_cache_path,
            max_rules=max_mitre_command_rules,
            apply_to_prediction=mitre_apply_to_prediction,
        )
        rules.extend(mitre_generated_rules)
    if generate_car_rules:
        car_generated_rules = _generate_car_correlation_rules(
            car_cache_path,
            mitre_cache_path,
            max_rules=max_car_rules,
            apply_to_prediction=car_apply_to_prediction,
        )
        rules.extend(car_generated_rules)
    if generate_external_seed_rules:
        external_seed_generated_rules = _generate_external_seed_correlation_rules(
            external_seed_model_path,
            mitre_cache_path,
            min_support=external_seed_min_support,
            max_rules=max_external_seed_rules,
            apply_to_prediction=external_seed_apply_to_prediction,
        )
        rules.extend(external_seed_generated_rules)
    generated_rule_count = sum(1 for rule in rules if isinstance(rule.get("provenance"), dict) and rule["provenance"].get("generated"))
    unreviewed_generated_rule_count = sum(
        1
        for rule in rules
        if isinstance(rule.get("provenance"), dict)
        and rule["provenance"].get("generated")
        and not rule["provenance"].get("reviewed")
    )
    generated_prediction_rule_count = sum(
        1
        for rule in rules
        if isinstance(rule.get("provenance"), dict)
        and rule["provenance"].get("generated")
        and bool(rule.get("apply_to_prediction"))
    )
    if generated_prediction_rule_count:
        review_status = "generated_prediction_influence_requires_review"
    elif unreviewed_generated_rule_count:
        review_status = "generated_unreviewed_no_prediction_influence"
    elif generated_rule_count:
        review_status = "generated_reviewed"
    else:
        review_status = "manual_or_metadata_only"
    source_artifacts = []
    import_status: Dict[str, Any] = {}
    if base_policy_path:
        source_artifacts.append(source_artifact_status(base_policy_path, "trusted_policy"))
        import_status["trusted_policy"] = {
            "status": "active_rules_imported",
            "path": base_policy_path,
            "active_rule_count": base_rule_count,
        }
    generated_by_source = {
        "mitre_attack": len(mitre_generated_rules),
        "sigma": len(sigma_generated_rules),
        "mitre_car": len(car_generated_rules),
        "external_seed_transition": len(external_seed_generated_rules),
    }
    generated_notes = {
        "mitre_attack": "Generated conservative candidate correlation rules from ATT&CK command/tool examples.",
        "sigma": "Generated conservative candidate correlation rules from explicit Sigma ATT&CK tags and keywords.",
        "mitre_car": "Generated conservative candidate correlation rules from MITRE CAR-style analytics.",
        "external_seed_transition": "Generated observed-sequence correlation rules from external Cowrie seed transitions.",
    }
    for name, path, source_type in (
        ("mitre_attack", mitre_cache_path, "mitre_attack_cache"),
        ("sigma", sigma_cache_path, "sigma_rule_cache"),
        ("mitre_car", car_cache_path, "mitre_car_analytic_cache"),
        ("external_seed_transition", external_seed_model_path, "external_cowrie_seed_model"),
    ):
        if not path:
            import_status[name] = {
                "status": "not_configured",
                "active_rule_count": 0,
                "note": "No source path was supplied.",
            }
            continue
        artifact = source_artifact_status(path, source_type)
        source_artifacts.append(artifact)
        generated_count = generated_by_source.get(name, 0)
        status = "active_rules_generated" if generated_count else ("metadata_only" if artifact.get("exists") else "missing")
        import_status[name] = {
            "status": status,
            "path": path,
            "active_rule_count": generated_count,
            "note": generated_notes.get(name) if generated_count else "Source artifact recorded for provenance. No automatic executable session-correlation rules were generated from this source yet.",
        }
    return {
        "schema_version": KNOWLEDGE_PACK_SCHEMA_VERSION,
        "pack_id": pack_id,
        "version": version or utc_now().replace(":", "").replace("+", "Z"),
        "generated_at": utc_now(),
        "owner": "honeypot-cloud-analysis",
        "generation_method": "trusted_policy_packaging_with_source_metadata",
        "review_status": review_status,
        "generation_options": {
            "generate_sigma_rules": bool(generate_sigma_rules),
            "generate_mitre_command_rules": bool(generate_mitre_command_rules),
            "generate_car_rules": bool(generate_car_rules),
            "generate_external_seed_rules": bool(generate_external_seed_rules),
            "sigma_min_level": sigma_min_level,
            "max_sigma_rules": max_sigma_rules,
            "max_mitre_command_rules": max_mitre_command_rules,
            "max_car_rules": max_car_rules,
            "max_external_seed_rules": max_external_seed_rules,
            "external_seed_min_support": external_seed_min_support,
            "sigma_apply_to_prediction": bool(sigma_apply_to_prediction),
            "mitre_apply_to_prediction": bool(mitre_apply_to_prediction),
            "car_apply_to_prediction": bool(car_apply_to_prediction),
            "external_seed_apply_to_prediction": bool(external_seed_apply_to_prediction),
        },
        "rules": rules,
        "source_artifacts": source_artifacts,
        "import_status": import_status,
        "summary": {
            "rule_count": len(rules),
            "active_rule_count": sum(1 for rule in rules if bool(rule.get("enabled", True))),
            "generated_prediction_rule_count": generated_prediction_rule_count,
            "unreviewed_generated_rule_count": unreviewed_generated_rule_count,
            **summarize_rules(rules),
        },
        "limitations": [
            "Rules imported from the trusted policy remain human-curated unless provenance says generated=true.",
            "ATT&CK, Sigma, and external seed artifacts are recorded as metadata unless this command emits active rules from them.",
            "External source metadata is context, not temporal proof of the next attacker step.",
            "Generated Sigma rules are candidate observed-behavior correlations. They default to apply_to_prediction=false.",
            "Generated ATT&CK, CAR, and external seed rules are candidate observed-behavior correlations and default to apply_to_prediction=false.",
        ],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a session TTP knowledge pack.")
    parser.add_argument("--base-policy", default="configs/session_ttp_correlation.trusted.json")
    parser.add_argument("--mitre-cache", default="")
    parser.add_argument("--sigma-cache", default="")
    parser.add_argument("--car-cache", default="")
    parser.add_argument("--external-seed-model", default="")
    parser.add_argument("--generate-sigma-rules", action="store_true", help="Generate candidate rules from Sigma ATT&CK tags plus extracted keywords.")
    parser.add_argument("--generate-mitre-command-rules", action="store_true", help="Generate candidate rules from MITRE ATT&CK command/tool examples in the technique cache.")
    parser.add_argument("--generate-car-rules", action="store_true", help="Generate candidate rules from a MITRE CAR-style analytic JSON file.")
    parser.add_argument("--generate-external-seed-rules", action="store_true", help="Generate observed-sequence rules from the external Cowrie seed transition model.")
    parser.add_argument("--sigma-min-level", default="medium", choices=sorted(LEVEL_ORDER), help="Minimum Sigma severity to convert.")
    parser.add_argument("--max-sigma-rules", type=int, default=50)
    parser.add_argument("--max-mitre-command-rules", type=int, default=25)
    parser.add_argument("--max-car-rules", type=int, default=25)
    parser.add_argument("--max-external-seed-rules", type=int, default=25)
    parser.add_argument("--external-seed-min-support", type=float, default=25.0)
    parser.add_argument("--sigma-apply-to-prediction", action="store_true", help="Let generated Sigma candidate rules affect realtime prediction features.")
    parser.add_argument("--mitre-apply-to-prediction", action="store_true", help="Let generated MITRE ATT&CK candidate rules affect realtime prediction features.")
    parser.add_argument("--car-apply-to-prediction", action="store_true", help="Let generated CAR candidate rules affect realtime prediction features.")
    parser.add_argument("--external-seed-apply-to-prediction", action="store_true", help="Let generated external seed sequence rules affect realtime prediction features.")
    parser.add_argument("--pack-id", default="honeypot-session-ttp-knowledge-pack")
    parser.add_argument("--version", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--json", action="store_true", help="Print the generated pack to stdout.")
    return parser


def main(argv: List[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    pack = build_knowledge_pack(
        base_policy_path=args.base_policy,
        mitre_cache_path=args.mitre_cache,
        sigma_cache_path=args.sigma_cache,
        car_cache_path=args.car_cache,
        external_seed_model_path=args.external_seed_model,
        pack_id=args.pack_id,
        version=args.version,
        generate_sigma_rules=args.generate_sigma_rules,
        generate_mitre_command_rules=args.generate_mitre_command_rules,
        generate_car_rules=args.generate_car_rules,
        generate_external_seed_rules=args.generate_external_seed_rules,
        sigma_min_level=args.sigma_min_level,
        max_sigma_rules=args.max_sigma_rules,
        max_mitre_command_rules=args.max_mitre_command_rules,
        max_car_rules=args.max_car_rules,
        max_external_seed_rules=args.max_external_seed_rules,
        external_seed_min_support=args.external_seed_min_support,
        sigma_apply_to_prediction=args.sigma_apply_to_prediction,
        mitre_apply_to_prediction=args.mitre_apply_to_prediction,
        car_apply_to_prediction=args.car_apply_to_prediction,
        external_seed_apply_to_prediction=args.external_seed_apply_to_prediction,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(pack, indent=2, sort_keys=True), encoding="utf-8")
    if args.json:
        print(json.dumps(pack, indent=2, sort_keys=True))
    else:
        print(f"Wrote session TTP knowledge pack: {output}")
        print(f"Rules: {pack['summary']['rule_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
