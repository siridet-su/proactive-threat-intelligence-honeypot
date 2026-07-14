"""Notebook actor-attribution helper moved into production."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


@dataclass
class ActorMatch:
    actor: str
    score: float
    matched_ttps: List[str]
    tactic_coverage: Dict[str, List[str]] = field(default_factory=dict)
    total_actor_ttps: int = 0

    @property
    def confidence_label(self) -> str:
        if self.score >= 30:
            return "HIGH"
        if self.score >= 15:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["confidence_label"] = self.confidence_label
        return data


def load_actor_db(path: str) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    if not path:
        return {}, {}
    if not Path(path).exists():
        return {}, {}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if "actor_db" in raw:
        return raw.get("actor_db", {}), raw.get("tactic_map", {})
    return raw, {}


def technique_to_tactics(tid: str, tactic_map: Dict[str, Any], mitre_db: Any = None) -> List[str]:
    base = tid.split(".")[0]
    value = tactic_map.get(base, tactic_map.get(tid, []))
    if isinstance(value, str):
        value = [value]
    if value:
        return value
    if mitre_db and hasattr(mitre_db, "get_tactics"):
        try:
            tactics = mitre_db.get_tactics(tid)
            return tactics or ["Unknown"]
        except Exception:
            pass
    return ["Unknown"]


def attribute_actor(
    detected_ids: Iterable[str],
    actor_db: Dict[str, List[str]],
    tactic_map: Dict[str, Any] | None = None,
    mitre_db: Any = None,
    min_ttp_overlap: int = 2,
    top_actors: int = 5,
) -> Tuple[List[ActorMatch], Dict[str, List[str]]]:
    tactic_map = tactic_map or {}
    detected = {tid for tid in detected_ids if tid}
    tactic_summary: Dict[str, List[str]] = {}
    for tid in detected:
        for tactic in technique_to_tactics(tid, tactic_map, mitre_db=mitre_db):
            tactic_summary.setdefault(tactic, [])
            if tid not in tactic_summary[tactic]:
                tactic_summary[tactic].append(tid)

    matches: List[ActorMatch] = []
    for actor, actor_ttps in actor_db.items():
        actor_set = set(actor_ttps)
        overlap = detected & actor_set
        if len(overlap) < min_ttp_overlap:
            continue
        union = detected | actor_set
        score = round((len(overlap) / len(union)) * 100, 2) if union else 0
        tactic_coverage: Dict[str, List[str]] = {}
        for tid in overlap:
            for tactic in technique_to_tactics(tid, tactic_map, mitre_db=mitre_db):
                tactic_coverage.setdefault(tactic, [])
                if tid not in tactic_coverage[tactic]:
                    tactic_coverage[tactic].append(tid)
        matches.append(ActorMatch(actor, score, sorted(overlap), tactic_coverage, len(actor_ttps)))
    return sorted(matches, key=lambda item: item.score, reverse=True)[:top_actors], tactic_summary


def enrich_report_with_actor_attribution(
    report: Dict[str, Any],
    session_payload: Dict[str, Any],
    actor_db_path: str,
    mitre_db: Any = None,
) -> Dict[str, Any]:
    campaign_summary = session_payload.get("campaign_summary") or {}
    if isinstance(campaign_summary, dict) and campaign_summary:
        report["campaign_context"] = {
            "status": campaign_summary.get("status") or "",
            "campaign_id": campaign_summary.get("campaign_id") or "",
            "matched_existing_campaign": bool(campaign_summary.get("matched_existing_campaign")),
            "campaign_session_count": campaign_summary.get("campaign_session_count") or 0,
            "max_confirmed_severity": campaign_summary.get("max_confirmed_severity") or "",
            "fingerprint": campaign_summary.get("fingerprint") or {},
        }
    actor_db, tactic_map = load_actor_db(actor_db_path)
    if not actor_db:
        report.setdefault("actor_attribution", {"status": "skipped", "reason": "actor_db_unavailable"})
        return report
    matches, tactic_summary = attribute_actor(session_payload.get("ttps", []), actor_db, tactic_map, mitre_db=mitre_db)
    report["actor_matches"] = [match.to_dict() for match in matches]
    report["tactic_summary"] = tactic_summary
    report["actor_attribution"] = {
        "status": "matched" if matches else "no_specific_actor",
        "match_count": len(matches),
        "actor_db_path": actor_db_path,
    }
    return report
