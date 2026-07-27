"""Audit ATT&CK coverage across production mapping layers.

This module is intentionally read-only. It answers which ATT&CK techniques are
covered by command rules, SecureBERT labels, session-correlation knowledge,
prediction policy, and SMB recommendation policy. It does not change runtime
classification or recommendation behavior.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from production.enrichment.mitre_attack_loader import load_mitre_attack_db

from production.classification.classification_pipeline import RULE_POLICY, RULE_SPECS
from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log
from production.correlation.session_ttp_knowledge import load_correlation_knowledge, main_ttp_id, parse_path_list


TTP_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


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


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _load_json(path_text: str) -> Dict[str, Any]:
    if not path_text:
        return {}
    path = Path(path_text)
    if not path.exists():
        return {}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def _extract_ttps(value: Any) -> Set[str]:
    found: Set[str] = set()
    if isinstance(value, dict):
        for item in value.values():
            found.update(_extract_ttps(item))
        return found
    if isinstance(value, (list, tuple, set)):
        for item in value:
            found.update(_extract_ttps(item))
        return found
    for match in TTP_RE.finditer(str(value or "")):
        found.add(main_ttp_id(match.group(0).upper()))
    return found


def _mitre_main_ttps(mitre_cache_path: str) -> Set[str]:
    if not mitre_cache_path:
        return set()
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            db = load_mitre_attack_db(cache_path=mitre_cache_path, force_refresh=False, silent=True)
    except TypeError:
        db = load_mitre_attack_db(mitre_cache_path)
    except Exception:
        return set()
    techniques = getattr(db, "_techniques", {}) or {}
    return {
        main_ttp_id(tid)
        for tid in techniques
        if _clean(tid) and main_ttp_id(tid).upper().startswith("T")
    }


def _classification_rule_ttps() -> Set[str]:
    return {main_ttp_id(tid) for _pattern, tid, _name in RULE_SPECS if _clean(tid)}


def _securebert_label_ttps(model_path: str, checkpoint_path: str = "") -> Set[str]:
    candidates = []
    if checkpoint_path:
        candidates.append(Path(checkpoint_path) / "config.json")
    if model_path:
        candidates.append(Path(model_path) / "config.json")
        candidates.append(Path(model_path) / "checkpoint-6765" / "config.json")
    for path in candidates:
        if not path.exists():
            continue
        try:
            config = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        labels = config.get("id2label") or {}
        if isinstance(labels, dict):
            return {main_ttp_id(label) for label in labels.values() if TTP_RE.fullmatch(str(label or ""))}
    return set()


def _session_correlation_ttps(policy_path: str, knowledge_pack_paths: Any) -> Dict[str, Any]:
    try:
        document = load_correlation_knowledge(policy_path, knowledge_pack_paths)
    except Exception as exc:
        return {"error": redact_exception_for_log(exc), "ttps": [], "summary": {}}
    rules = ((document.get("policy") or {}).get("rules") or [])
    ttps = {
        main_ttp_id(rule.get("ttp"))
        for rule in rules
        if isinstance(rule, dict) and _clean(rule.get("ttp")) and rule.get("enabled", True)
    }
    return {
        "ttps": sorted(ttps),
        "summary": document.get("knowledge_summary") or {},
    }


def _smb_policy_ttps(policy_path: str) -> Set[str]:
    policy = _load_json(policy_path)
    return _extract_ttps(policy)


def _coverage_entry(name: str, covered: Iterable[str], universe: Iterable[str], *, notes: str = "") -> Dict[str, Any]:
    covered_set = {main_ttp_id(item) for item in covered if _clean(item)}
    universe_set = {main_ttp_id(item) for item in universe if _clean(item)}
    unknown = sorted(covered_set - universe_set) if universe_set else []
    denominator = len(universe_set)
    return {
        "name": name,
        "covered_count": len(covered_set),
        "universe_count": denominator,
        "coverage_percent": round((len(covered_set & universe_set) / denominator * 100.0), 2) if denominator else 0.0,
        "covered_ttps": sorted(covered_set),
        "unknown_or_not_in_mitre_cache": unknown,
        "notes": notes,
    }


def build_coverage_audit(config: ProductionConfig) -> Dict[str, Any]:
    mitre_universe = _mitre_main_ttps(config.mitre_attack_path)
    session_corr = _session_correlation_ttps(
        config.session_ttp_correlation_policy_path,
        config.session_ttp_knowledge_pack_paths,
    )
    securebert_ttps = _securebert_label_ttps(
        config.securebert_model_path,
        config.securebert_checkpoint_path,
    )
    entries = [
        _coverage_entry(
            "classification_policy_rules",
            _classification_rule_ttps(),
            mitre_universe,
            notes=(
                "Active command rules loaded from classification rule policy. "
                f"source={RULE_POLICY.get('source_path', '') or RULE_POLICY.get('policy_id', '')}"
            ),
        ),
        _coverage_entry(
            "securebert_label_space",
            securebert_ttps,
            mitre_universe,
            notes="Labels read from HuggingFace config.json when available.",
        ),
        _coverage_entry(
            "session_ttp_correlation_active_policy_and_packs",
            session_corr.get("ttps") or [],
            mitre_universe,
            notes="Combined trusted policy plus configured knowledge packs.",
        ),
        _coverage_entry(
            "smb_action_policy_ttp_references",
            _smb_policy_ttps(config.smb_action_policy_path),
            mitre_universe,
            notes="TTP references in SMB action playbooks/trusted source metadata.",
        ),
    ]
    hardcoded_surfaces = [
        {
            "file": "production/classification/classification_pipeline.py",
            "symbol": "EMERGENCY_RULE_SPECS",
            "risk": "Only a minimal Python fallback remains if the versioned classification policy cannot be loaded.",
        },
        {
            "file": "production/workers/session_monitor.py",
            "symbol": "_KEYWORD_TTP_RULES / _TACTIC_PROGRESSION",
            "risk": "Legacy fallback classification and next-step text are manually bounded.",
        },
        {
            "file": "configs/session_ttp_correlation.trusted.json",
            "symbol": "policy.rules",
            "risk": "Base session-level correlations are curated subset unless generated knowledge packs are configured.",
        },
        {
            "file": "configs/smb_action_playbooks.trusted.json",
            "symbol": "risk_rules / goal_rules / action_playbooks",
            "risk": "Curated SMB playbooks are trustworthy but do not contain per-technique coverage for the full ATT&CK space.",
        },
    ]
    return {
        "schema_version": "coverage_audit.v1",
        "mitre_cache_path": config.mitre_attack_path,
        "mitre_main_ttp_count": len(mitre_universe),
        "session_ttp_knowledge_pack_paths": parse_path_list(config.session_ttp_knowledge_pack_paths),
        "session_ttp_knowledge_summary": session_corr.get("summary") or {},
        "coverage": entries,
        "hardcoded_surfaces": hardcoded_surfaces,
        "recommendations": [
            "Use generated session TTP knowledge packs for observed-evidence coverage; prediction remains advisory and consumes no generated correlation rules.",
            "Expand command coverage through versioned classification rule policy files, not Python tables.",
            "Use MITRE mitigations as reference guidance for uncovered techniques, not as automatic remediation authority.",
            "Keep AI outputs explanatory only; reject any AI-added operator action not backed by trusted policy.",
        ],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit ATT&CK coverage across production mapping layers.")
    parser.add_argument("--config", default="", help="Optional production_config.json path.")
    parser.add_argument("--json", action="store_true", help="Emit JSON only.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    config = ProductionConfig.from_env(args.config or None)
    audit = build_coverage_audit(config)
    if args.json:
        print(json.dumps(audit, indent=2, sort_keys=True))
    else:
        print("ATT&CK coverage audit")
        print(json.dumps(audit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
