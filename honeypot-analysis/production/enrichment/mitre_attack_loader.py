"""
mitre_attack_loader.py
======================
Loads MITRE ATT&CK Enterprise data from the official STIX GitHub repository.

Best-practice design:
  - Single responsibility: fetch → parse → cache → serve
  - Auto-refresh every CACHE_MAX_AGE_DAYS days (default: 30)
  - Graceful degradation: if download fails, returns empty DB — pipeline continues
  - Compact cache: saves only fields used (~200KB vs 25MB raw STIX)
  - No extra dependencies: only `requests` (already in requirements)

Usage:
    from production.enrichment.mitre_attack_loader import load_mitre_attack_db
    db = load_mitre_attack_db()
    db.get_name("T1078")           # → "Valid Accounts"
    db.get_tactics("T1078")        # → ["persistence", "privilege-escalation", ...]
    db.get_platforms("T1078")      # → ["Linux", "Windows", "macOS", ...]
    db.get_mitigations("T1078")    # → ["Privileged Account Management", ...]
    db.get_description("T1078")    # → "Adversaries may obtain and abuse..."
"""

from __future__ import annotations

import json
import os
import sys
import time
import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional

if __package__ in {None, ""}:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from production.utils.sensitive_data import redact_exception_for_log
from production.enrichment.cache_io import (
    atomic_write_cache,
    feed_refresh_lock,
    load_cache_json,
)

# ── Configuration ──────────────────────────────────────────────────────────────
MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack-14.1.json"
)
CACHE_FILENAME      = "mitre_attack_cache.json"
CACHE_MAX_AGE_DAYS  = 30   # industry standard: refresh monthly with ATT&CK quarterly updates
CACHE_SCHEMA_VERSION = "2"  # bump to force refresh when cache format changes
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024

# Colab uploads to /content/; local files stay beside this script
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_COLAB_CACHE = f"/content/{CACHE_FILENAME}"
_LOCAL_CACHE  = os.path.join(_SCRIPT_DIR, "data", "feeds", CACHE_FILENAME)
_LEGACY_LOCAL_CACHE = os.path.join(_SCRIPT_DIR, CACHE_FILENAME)


# ── Data Model ─────────────────────────────────────────────────────────────────

@dataclass
class TechniqueRecord:
    """Compact representation of one ATT&CK technique."""
    tid:          str
    name:         str
    tactics:      List[str] = field(default_factory=list)
    platforms:    List[str] = field(default_factory=list)
    description:  str = ""
    mitigations:  List[str] = field(default_factory=list)
    is_subtechnique: bool = False

    def to_dict(self) -> dict:
        return {
            "name":           self.name,
            "tactics":        self.tactics,
            "platforms":      self.platforms,
            "description":    self.description,
            "mitigations":    self.mitigations,
            "is_subtechnique": self.is_subtechnique,
        }

    @classmethod
    def from_dict(cls, tid: str, d: dict) -> "TechniqueRecord":
        return cls(
            tid=tid,
            name=d.get("name", tid),
            tactics=d.get("tactics", []),
            platforms=d.get("platforms", []),
            description=d.get("description", ""),
            mitigations=d.get("mitigations", []),
            is_subtechnique=d.get("is_subtechnique", False),
        )


class MitreAttackDB:
    """
    In-memory ATT&CK database. Provides O(1) lookups for all fields.
    Designed to be passed as `mitre_db` to ImprovedAsyncSwarmCoordinator.
    """

    def __init__(self, techniques: Dict[str, TechniqueRecord],
                 version: str = "unknown"):
        self._techniques  = techniques   # {"T1078": TechniqueRecord}
        self.version      = version
        self.technique_count = len(techniques)

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_name(self, tid: str) -> str:
        """T1078 → 'Valid Accounts'"""
        rec = self._techniques.get(tid)
        return rec.name if rec else tid

    @staticmethod
    def _normalize_tactic_name(tactic: str) -> str:
        """Normalize ATT&CK tactic names to the project-wide slug format."""
        return str(tactic).strip().lower().replace(" ", "-")

    def get_tactics(self, tid: str) -> List[str]:
        """
        T1078 → ['persistence', 'privilege-escalation', ...]

        The cache stores display names such as ``Credential Access``.
        Runtime components such as SessionMonitor and tactic progression logic
        use normalized slug names such as ``credential-access``. Keeping this
        normalization here gives every caller one consistent MITRE interface.
        """
        rec = self._techniques.get(tid)
        if not rec:
            return []

        normalized: List[str] = []
        for tactic in rec.tactics or []:
            value = self._normalize_tactic_name(tactic)
            if value and value not in normalized:
                normalized.append(value)
        return normalized

    def get_tactics_display(self, tid: str) -> List[str]:
        """T1078 → ['Persistence', 'Privilege Escalation', ...] for UI/report display."""
        rec = self._techniques.get(tid)
        return list(rec.tactics) if rec else []

    def get_platforms(self, tid: str) -> List[str]:
        """T1078 → ['Linux', 'Windows', 'macOS', ...]"""
        rec = self._techniques.get(tid)
        return rec.platforms if rec else []

    def get_mitigations(self, tid: str) -> List[str]:
        """T1078 → ['Privileged Account Management', ...]"""
        rec = self._techniques.get(tid)
        return rec.mitigations if rec else []

    def get_description(self, tid: str) -> str:
        """Returns first sentence of ATT&CK technique description."""
        rec = self._techniques.get(tid)
        if not rec or not rec.description:
            return ""
        # Return first sentence only (concise for evidence briefs)
        first = rec.description.split(". ")[0]
        return first[:200] + ("..." if len(first) > 200 else "")

    def get_record(self, tid: str) -> Optional[TechniqueRecord]:
        return self._techniques.get(tid)

    # Backward-compat dict interface (drop-in for existing mitre_name_map usage)
    def get(self, tid: str, default: str = None) -> str:
        """dict-compatible .get() for drop-in replacement of mitre_name_map."""
        rec = self._techniques.get(tid)
        if rec:
            return rec.name
        return default if default is not None else tid

    def __repr__(self) -> str:
        return (f"<MitreAttackDB version={self.version} "
                f"techniques={self.technique_count}>")

    # ── Serialization ───────────────────────────────────────────────────────────

    def to_cache_dict(self) -> dict:
        return {
            "_schema":    CACHE_SCHEMA_VERSION,
            "_version":   self.version,
            "_fetched":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "techniques": {
                tid: rec.to_dict()
                for tid, rec in self._techniques.items()
            },
        }

    @classmethod
    def from_cache_dict(cls, data: dict) -> "MitreAttackDB":
        techniques = {
            tid: TechniqueRecord.from_dict(tid, rec)
            for tid, rec in data.get("techniques", {}).items()
        }
        return cls(techniques, version=data.get("_version", "unknown"))


# ── STIX Parser ────────────────────────────────────────────────────────────────

def _parse_stix_bundle(bundle: dict) -> MitreAttackDB:
    """
    Parse MITRE ATT&CK STIX 2.1 bundle into MitreAttackDB.
    Handles: techniques, sub-techniques, tactics, platforms, mitigations.
    """
    objects = bundle.get("objects", [])

    # ── Index by STIX ID ─────────────────────────────────────────────────────
    by_id: Dict[str, dict] = {obj["id"]: obj for obj in objects}

    # ── Extract version from identity object ──────────────────────────────────
    version = "unknown"
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", "unknown")
            break

    # ── Build technique records ───────────────────────────────────────────────
    techniques: Dict[str, TechniqueRecord] = {}
    stix_id_to_tid: Dict[str, str] = {}  # stix_id → T1078 (for relationship lookup)

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Find ATT&CK ID (T1078 or T1078.001)
        tid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                break
        if not tid:
            continue

        # Tactics from kill_chain_phases
        tactics = [
            phase["phase_name"].replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        # Platforms
        platforms = obj.get("x_mitre_platforms", [])

        # Description — strip STIX citation markers like (Citation: X)
        raw_desc = obj.get("description", "")
        import re as _re
        desc = _re.sub(r'\(Citation:[^)]+\)', '', raw_desc).strip()

        techniques[tid] = TechniqueRecord(
            tid=tid,
            name=obj.get("name", tid),
            tactics=tactics,
            platforms=platforms,
            description=desc,
            mitigations=[],  # filled in below
            is_subtechnique=obj.get("x_mitre_is_subtechnique", False),
        )
        stix_id_to_tid[obj["id"]] = tid

    # ── Attach mitigations via relationships ──────────────────────────────────
    # course-of-action (mitigation) → "mitigates" → attack-pattern (technique)
    mitigation_names: Dict[str, str] = {
        obj["id"]: obj.get("name", "")
        for obj in objects
        if obj.get("type") == "course-of-action"
    }

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "mitigates":
            continue
        source_id = obj.get("source_ref", "")
        target_id = obj.get("target_ref", "")
        mitigation_name = mitigation_names.get(source_id)
        tid = stix_id_to_tid.get(target_id)
        if mitigation_name and tid and tid in techniques:
            techniques[tid].mitigations.append(mitigation_name)

    print(f"  [MITRE] Parsed {len(techniques)} techniques "
          f"({sum(1 for t in techniques.values() if not t.is_subtechnique)} base, "
          f"{sum(1 for t in techniques.values() if t.is_subtechnique)} sub-techniques)")
    return MitreAttackDB(techniques, version=version)


# ── Cache Management ───────────────────────────────────────────────────────────

def _cache_path() -> str:
    """Returns writable cache path (Colab preferred, then local)."""
    # In Colab /content/ is writable; in local env use script directory
    if os.path.exists("/content"):
        return _COLAB_CACHE
    if os.path.exists(_LOCAL_CACHE):
        return _LOCAL_CACHE
    if os.path.exists(_LEGACY_LOCAL_CACHE):
        return _LEGACY_LOCAL_CACHE
    return _LOCAL_CACHE


def _cache_is_fresh(path: str) -> bool:
    """True if cache file exists, has correct schema, and is within max age."""
    if not os.path.exists(path):
        return False
    try:
        data = load_cache_json(path, CACHE_SCHEMA_VERSION)
        fetched_str = data.get("_fetched", "")
        if not fetched_str:
            return False
        fetched = datetime.datetime.fromisoformat(fetched_str.rstrip("Z"))
        # Ensure timezone-aware so subtraction works regardless of system locale
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=datetime.timezone.utc)
        age_days = (datetime.datetime.now(datetime.timezone.utc) - fetched).days
        if age_days >= CACHE_MAX_AGE_DAYS:
            print(f"  [MITRE] Cache is {age_days} days old (max {CACHE_MAX_AGE_DAYS}) — refreshing")
            return False
        return True
    except Exception:
        return False


def _load_from_cache(path: str) -> Optional[MitreAttackDB]:
    try:
        data = load_cache_json(path, CACHE_SCHEMA_VERSION)
        db = MitreAttackDB.from_cache_dict(data)
        raw_fetched = data.get("_fetched", "2000-01-01T00:00:00+00:00")
        fetched = datetime.datetime.fromisoformat(raw_fetched.rstrip("Z"))
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=datetime.timezone.utc)
        age_days = (datetime.datetime.now(datetime.timezone.utc) - fetched).days
        print(f"  [MITRE] Loaded {db.technique_count} techniques from cache "
              f"(version={db.version}, age={age_days}d)")
        return db
    except Exception as e:
        print(f"  [MITRE] Cache load failed: {redact_exception_for_log(e)}")
        return None


def _save_to_cache(db: MitreAttackDB, path: str) -> None:
    try:
        atomic_write_cache(path, db.to_cache_dict())
        size_kb = os.path.getsize(path) // 1024
        print(f"  [MITRE] Cache saved to {path} ({size_kb}KB)")
    except Exception as e:
        print(f"  [MITRE] Cache save failed (non-fatal): {redact_exception_for_log(e)}")


def _fetch_from_mitre(url: str = MITRE_STIX_URL,
                      timeout: int = 60) -> Optional[MitreAttackDB]:
    """Download STIX bundle from MITRE GitHub and parse it."""
    try:
        import requests
        print(f"  [MITRE] Downloading ATT&CK STIX data from GitHub...")
        print(f"          (This happens once every {CACHE_MAX_AGE_DAYS} days)")
        resp = requests.get(url, timeout=timeout, stream=True)
        resp.raise_for_status()
        content_length = resp.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_DOWNLOAD_BYTES:
            raise ValueError("MITRE feed response exceeds configured limit")

        # Read with progress hint
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=1024 * 256):  # 256KB chunks
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_DOWNLOAD_BYTES:
                raise ValueError("MITRE feed response exceeds configured limit")
        raw = b"".join(chunks)
        print(f"  [MITRE] Downloaded {total // 1024 // 1024}MB — parsing...")

        bundle = json.loads(raw)
        db = _parse_stix_bundle(bundle)
        print(f"  [MITRE] ATT&CK {db.version} ready ({db.technique_count} techniques)")
        return db

    except ImportError:
        print("  [MITRE] requests not available — cannot download ATT&CK data")
        return None
    except Exception as e:
        print(f"  [MITRE] Download failed: {redact_exception_for_log(e)}")
        return None


# ── Public Entry Point ─────────────────────────────────────────────────────────

_GLOBAL_DB: Optional[MitreAttackDB] = None   # module-level singleton
_GLOBAL_DB_PATH: Optional[str] = None


def load_mitre_attack_db(
    cache_path: str = None,
    force_refresh: bool = False,
    silent: bool = False,
    allow_network_refresh: bool = True,
) -> MitreAttackDB:
    """
    Load MITRE ATT&CK Enterprise database.

    Priority:
      1. Module-level singleton (fastest — same session)
      2. Disk cache (fast — seconds)
      3. Download from MITRE GitHub (slow — ~5-15s, once per 30 days)
      4. Empty DB (graceful fallback — pipeline continues)

    Args:
        cache_path:     Override cache file path. Auto-detected if None.
        force_refresh:  Ignore cache and re-download. Useful after ATT&CK releases.
        silent:         Suppress progress messages.
    """
    global _GLOBAL_DB, _GLOBAL_DB_PATH

    path = cache_path or _cache_path()
    cache_identity = os.path.abspath(path)

    # Singleton — reuse within same Python session
    if (
        _GLOBAL_DB is not None
        and _GLOBAL_DB_PATH == cache_identity
        and not force_refresh
    ):
        return _GLOBAL_DB

    if not silent:
        print(f"  [MITRE] Initializing ATT&CK database...")

    # Try cache first
    if not force_refresh and _cache_is_fresh(path):
        db = _load_from_cache(path)
        if db:
            _GLOBAL_DB = db
            _GLOBAL_DB_PATH = cache_identity
            return db

    if not allow_network_refresh:
        if os.path.exists(path):
            db = _load_from_cache(path)
            if db:
                _GLOBAL_DB = db
                _GLOBAL_DB_PATH = cache_identity
                return db
        empty = MitreAttackDB({}, version="unavailable")
        _GLOBAL_DB = empty
        _GLOBAL_DB_PATH = cache_identity
        return empty

    # Download from MITRE. The lock prevents overlapping scheduled/manual
    # refreshes and the second freshness check avoids a duplicate download.
    try:
        with feed_refresh_lock(path):
            if not force_refresh and _cache_is_fresh(path):
                db = _load_from_cache(path)
                if db:
                    _GLOBAL_DB = db
                    _GLOBAL_DB_PATH = cache_identity
                    return db
            db = _fetch_from_mitre()
            if db:
                _save_to_cache(db, path)
                _GLOBAL_DB = db
                _GLOBAL_DB_PATH = cache_identity
                return db
    except TimeoutError:
        print("  [MITRE] Refresh already in progress; using available cache")

    # Graceful fallback — try stale cache before giving up
    if os.path.exists(path):
        print("  [MITRE] Using stale cache as fallback")
        db = _load_from_cache(path)
        if db:
            _GLOBAL_DB = db
            _GLOBAL_DB_PATH = cache_identity
            return db

    # Last resort — empty DB (pipeline works without ATT&CK enrichment)
    print("  [MITRE] WARNING: Could not load ATT&CK data — "
          "technique names will show as raw IDs")
    empty = MitreAttackDB({}, version="unavailable")
    _GLOBAL_DB = empty
    _GLOBAL_DB_PATH = cache_identity
    return empty


def clear_singleton() -> None:
    """Force reload on next call (useful in testing / after force_refresh)."""
    global _GLOBAL_DB, _GLOBAL_DB_PATH
    _GLOBAL_DB = None
    _GLOBAL_DB_PATH = None


# ── CLI convenience ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    force = "--refresh" in sys.argv
    db = load_mitre_attack_db(force_refresh=force)
    print(f"\nDB: {db}")
    print(f"\nSample lookups:")
    for tid in ["T1078", "T1059", "T1098", "T1190", "T1133"]:
        print(f"  {tid}: {db.get_name(tid)}")
        print(f"    tactics  : {db.get_tactics(tid)}")
        print(f"    platforms: {db.get_platforms(tid)}")
        print(f"    mitigations ({len(db.get_mitigations(tid))}): "
              f"{db.get_mitigations(tid)[:2]}")
