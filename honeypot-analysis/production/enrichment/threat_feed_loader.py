"""
threat_feed_loader.py
=====================
Loads authoritative external threat intelligence feeds.

Feeds included:
  1. CISA KEV (Known Exploited Vulnerabilities)
     - Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
     - Updates: daily
     - Use: flag if observed CVEs/techniques overlap with actively-exploited vulns

  2. Sigma Rules (SigmaHQ community detection rules)
     - Source: https://github.com/SigmaHQ/sigma (rules/linux/*, rules/network/*)
     - Updates: continuous community contributions
     - Use: replace/supplement hardcoded keyword lists in configs/threat_intel_config.json

Both feeds are cached locally and auto-refreshed on schedule.

Usage:
    from production.enrichment.threat_feed_loader import load_threat_feeds, ThreatFeedDB
    feeds = load_threat_feeds()

    # CISA KEV
    feeds.is_actively_exploited("CVE-2021-44228")   # â†’ True (Log4Shell)
    feeds.get_kev_details("CVE-2021-44228")          # â†’ {vendor, product, ...}

    # Sigma
    feeds.get_sigma_keywords("ssh_bruteforce")       # â†’ ["hydra", "medusa", ...]
    feeds.get_all_sigma_tags()                       # â†’ ["attack.credential_access", ...]
"""

from __future__ import annotations

import json
import os
import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

# â”€â”€ Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
SIGMA_RULES_INDEX_URL = (
    "https://api.github.com/repos/SigmaHQ/sigma/git/trees/"
    "master?recursive=1"
)
# Only fetch rules from these paths (SSH, Linux, Network â€” relevant to honeypot)
SIGMA_RELEVANT_PATHS = [
    "rules/linux/",
    "rules/network/",
    "rules/application/ssh",
]

CISA_CACHE_FILENAME  = "cisa_kev_cache.json"
SIGMA_CACHE_FILENAME = "sigma_rules_cache.json"
CISA_MAX_AGE_DAYS    = 1    # KEV updates daily â€” refresh often
SIGMA_MAX_AGE_DAYS   = 7    # Sigma rules: weekly refresh sufficient
CACHE_SCHEMA_VERSION = "1"

_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_COLAB_BASE  = "/content"
_LOCAL_FEED_DIR = os.path.join(_SCRIPT_DIR, "data", "feeds")


def _cache_path(filename: str) -> str:
    if os.path.exists(_COLAB_BASE):
        return os.path.join(_COLAB_BASE, filename)
    structured = os.path.join(_LOCAL_FEED_DIR, filename)
    if os.path.exists(structured):
        return structured
    legacy = os.path.join(_SCRIPT_DIR, filename)
    if os.path.exists(legacy):
        return legacy
    return structured


def _is_fresh(path: str, max_age_days: int) -> bool:
    if not os.path.exists(path):
        return False
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("_schema") != CACHE_SCHEMA_VERSION:
            return False
        fetched = datetime.datetime.fromisoformat(
            data.get("_fetched", "2000-01-01T00:00:00+00:00")
        )
        return (datetime.datetime.now(datetime.timezone.utc) - fetched).days < max_age_days
    except Exception:
        return False


def _save_cache(path: str, data: dict) -> None:
    try:
        data["_schema"]  = CACHE_SCHEMA_VERSION
        data["_fetched"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        size_kb = os.path.getsize(path) // 1024
        print(f"  [FeedLoader] Cache saved: {os.path.basename(path)} ({size_kb}KB)")
    except Exception as e:
        print(f"  [FeedLoader] Cache save failed (non-fatal): {e}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Part 1: CISA Known Exploited Vulnerabilities (KEV)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@dataclass
class KEVEntry:
    cve_id:           str
    vendor:           str
    product:          str
    vulnerability_name: str
    date_added:       str
    short_description: str
    required_action:  str
    due_date:         str

    def to_dict(self) -> dict:
        return {
            "vendor":           self.vendor,
            "product":          self.product,
            "name":             self.vulnerability_name,
            "date_added":       self.date_added,
            "description":      self.short_description,
            "required_action":  self.required_action,
            "due_date":         self.due_date,
        }


class CisaKevDB:
    """In-memory CISA KEV database."""

    def __init__(self, entries: Dict[str, KEVEntry], catalog_version: str = "unknown"):
        self._entries        = entries          # {"CVE-2021-44228": KEVEntry}
        self.catalog_version = catalog_version
        self.count           = len(entries)

    def is_actively_exploited(self, cve_id: str) -> bool:
        """True if CVE is in CISA's Known Exploited Vulnerabilities catalog."""
        return cve_id.upper() in self._entries

    def get_details(self, cve_id: str) -> Optional[dict]:
        """Returns KEV details dict or None if not in catalog."""
        entry = self._entries.get(cve_id.upper())
        return entry.to_dict() if entry else None

    def match_product(self, product_name: str) -> List[str]:
        """Returns CVE IDs for a given product name (case-insensitive partial match)."""
        term = product_name.lower()
        return [
            cve for cve, e in self._entries.items()
            if term in e.product.lower() or term in e.vendor.lower()
        ]

    def __repr__(self) -> str:
        return f"<CisaKevDB catalog={self.catalog_version} entries={self.count}>"


def _fetch_cisa_kev() -> Optional[CisaKevDB]:
    try:
        import requests
        print("  [CISA KEV] Downloading from CISA...")
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        entries: Dict[str, KEVEntry] = {}
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cveID", "").upper()
            if not cve:
                continue
            entries[cve] = KEVEntry(
                cve_id=cve,
                vendor=vuln.get("vendorProject", ""),
                product=vuln.get("product", ""),
                vulnerability_name=vuln.get("vulnerabilityName", ""),
                date_added=vuln.get("dateAdded", ""),
                short_description=vuln.get("shortDescription", ""),
                required_action=vuln.get("requiredAction", ""),
                due_date=vuln.get("dueDate", ""),
            )

        catalog_version = data.get("catalogVersion", "unknown")
        db = CisaKevDB(entries, catalog_version)
        print(f"  [CISA KEV] {db.count} CVEs loaded (catalog v{catalog_version})")
        return db

    except ImportError:
        print("  [CISA KEV] requests not available")
        return None
    except Exception as e:
        print(f"  [CISA KEV] Download failed: {type(e).__name__}: {e}")
        return None


def _load_cisa_cache(path: str, label: str = "cache") -> Optional[CisaKevDB]:
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        entries = {}
        for cve, v in raw.get("entries", {}).items():
            entries[cve] = KEVEntry(
                cve_id=cve,
                vendor=v.get("vendor", ""),
                product=v.get("product", ""),
                vulnerability_name=v.get("name", ""),
                date_added=v.get("date_added", ""),
                short_description=v.get("description", ""),
                required_action=v.get("required_action", ""),
                due_date=v.get("due_date", ""),
            )
        db = CisaKevDB(entries, raw.get("catalog_version", "unknown"))
        print(f"  [CISA KEV] Loaded {db.count} CVEs from {label}")
        return db
    except Exception as e:
        print(f"  [CISA KEV] Cache load failed: {e}")
        return None


def load_cisa_kev(force_refresh: bool = False, cache_path: Optional[str] = None) -> CisaKevDB:
    """Load CISA KEV catalog with daily auto-refresh."""
    path = cache_path or _cache_path(CISA_CACHE_FILENAME)

    if not force_refresh and _is_fresh(path, CISA_MAX_AGE_DAYS):
        db = _load_cisa_cache(path)
        if db:
            return db


    db = _fetch_cisa_kev()
    if db:
        cache_data = {
            "catalog_version": db.catalog_version,
            "entries": {
                cve: entry.to_dict()
                for cve, entry in db._entries.items()
            },
        }
        _save_cache(path, cache_data)
        return db

    if os.path.exists(path):
        db = _load_cisa_cache(path, label="stale cache")
        if db:
            print("  [CISA KEV] Refresh failed; using stale cache")
            return db

    # Fallback: empty
    print("  [CISA KEV] Using empty fallback â€” KEV checks disabled")
    return CisaKevDB({}, catalog_version="unavailable")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Part 2: Sigma Rules (SigmaHQ community detection keywords)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@dataclass
class SigmaRule:
    rule_id:     str
    title:       str
    status:      str
    level:       str          # informational / low / medium / high / critical
    tags:        List[str]    # ["attack.credential_access", "attack.t1110"]
    keywords:    List[str]    # detection keywords extracted from rule
    logsource:   dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "title":     self.title,
            "status":    self.status,
            "level":     self.level,
            "tags":      self.tags,
            "keywords":  self.keywords,
            "logsource": self.logsource,
        }


class SigmaRuleDB:
    """Index of Sigma rules grouped by category."""

    def __init__(self, rules: List[SigmaRule]):
        self._rules = rules
        self._by_id: Dict[str, SigmaRule] = {r.rule_id: r for r in rules}
        # Index: ATT&CK tag â†’ rules
        self._by_attack_tag: Dict[str, List[SigmaRule]] = {}
        for r in rules:
            for tag in r.tags:
                if tag.startswith("attack."):
                    self._by_attack_tag.setdefault(tag, []).append(r)

    def get_keywords_for_level(self, level: str = "high") -> List[str]:
        """Return all unique keywords from rules at given severity level or above."""
        level_order = ["informational", "low", "medium", "high", "critical"]
        min_idx = level_order.index(level) if level in level_order else 0
        keywords: Set[str] = set()
        for rule in self._rules:
            lvl = rule.level.lower()
            if lvl in level_order and level_order.index(lvl) >= min_idx:
                keywords.update(rule.keywords)
        return sorted(keywords)

    def get_keywords_by_tag(self, attack_tag: str) -> List[str]:
        """e.g. 'attack.credential_access' â†’ all keywords from matching rules."""
        keywords: Set[str] = set()
        for rule in self._by_attack_tag.get(attack_tag, []):
            keywords.update(rule.keywords)
        return sorted(keywords)

    def get_ssh_bruteforce_keywords(self) -> List[str]:
        """Convenience: SSH brute force detection keywords."""
        kws: Set[str] = set()
        for rule in self._rules:
            title_lower = rule.title.lower()
            tags_str    = " ".join(rule.tags).lower()
            if ("ssh" in title_lower or "brute" in title_lower or
                    "t1110" in tags_str or "credential" in tags_str):
                kws.update(rule.keywords)
        return sorted(kws)

    def get_all_attack_tags(self) -> List[str]:
        return sorted(self._by_attack_tag.keys())

    @property
    def count(self) -> int:
        return len(self._rules)

    def __repr__(self) -> str:
        return f"<SigmaRuleDB rules={self.count}>"


def _parse_sigma_yaml_minimal(content: str, filename: str) -> Optional[SigmaRule]:
    """
    Minimal YAML parser for Sigma rules.
    Avoids requiring PyYAML â€” parses only the fields we need.
    """
    try:
        import re

        def _get_field(key: str) -> str:
            m = re.search(rf'^{key}:\s*(.+)$', content, re.MULTILINE)
            return m.group(1).strip().strip("'\"") if m else ""

        def _get_list_field(key: str) -> List[str]:
            # Match simple YAML lists: key:\n    - item1\n    - item2
            m = re.search(
                rf'^{key}:\s*\n((?:\s+- .+\n?)+)',
                content, re.MULTILINE
            )
            if not m:
                # Also try inline: key: [item1, item2]
                m2 = re.search(rf'^{key}:\s*\[([^\]]+)\]', content, re.MULTILINE)
                if m2:
                    return [x.strip().strip("'\"") for x in m2.group(1).split(",")]
                return []
            items = re.findall(r'^\s+- (.+)$', m.group(1), re.MULTILINE)
            return [x.strip().strip("'\"") for x in items]

        def _extract_keywords(text: str) -> List[str]:
            """Extract string values from detection section."""
            kws = []
            # Find lines that look like: - 'keyword' or - keyword
            for m in re.finditer(r"[-|]\s+'([^']+)'", text):
                val = m.group(1).strip()
                if 2 < len(val) < 100 and not val.startswith("%"):
                    kws.append(val.lower())
            for m in re.finditer(r'^        - ([^\s\'\"\[{].+)$', text, re.MULTILINE):
                val = m.group(1).strip()
                if 2 < len(val) < 100 and not val.startswith("%"):
                    kws.append(val.lower())
            return list(set(kws))

        rule_id = _get_field("id")
        title   = _get_field("title")
        status  = _get_field("status")
        level   = _get_field("level") or "medium"
        tags    = _get_list_field("tags")

        # Extract detection section for keywords
        det_match = re.search(r'^detection:(.*?)(?=^[a-z]|\Z)',
                              content, re.MULTILINE | re.DOTALL)
        keywords = _extract_keywords(det_match.group(1)) if det_match else []

        # Logsource
        ls_match = re.search(r'^logsource:\s*\n((?:\s+.+\n?)+)',
                              content, re.MULTILINE)
        logsource = {}
        if ls_match:
            for line in ls_match.group(1).splitlines():
                kv = re.match(r'\s+(\w+):\s*(.+)', line)
                if kv:
                    logsource[kv.group(1)] = kv.group(2).strip().strip("'\"")

        if not title:
            return None

        return SigmaRule(
            rule_id=rule_id or filename,
            title=title,
            status=status,
            level=level,
            tags=[t.strip() for t in tags if t.strip()],
            keywords=keywords,
            logsource=logsource,
        )
    except Exception:
        return None


def _fetch_sigma_rules() -> Optional[SigmaRuleDB]:
    """
    Download Sigma rules from SigmaHQ GitHub.
    Fetches only rules relevant to honeypot (Linux/SSH/Network).
    """
    try:
        import requests

        print("  [Sigma] Fetching rule index from SigmaHQ GitHub...")
        # Get tree of all files
        resp = requests.get(SIGMA_RULES_INDEX_URL, timeout=30)
        if resp.status_code == 403:
            # Rate limited â€” use alternative approach
            print("  [Sigma] GitHub API rate limited â€” using direct file list")
            return _fetch_sigma_rules_direct(requests)
        resp.raise_for_status()
        tree = resp.json().get("tree", [])

        # Filter to relevant paths only
        relevant_files = [
            item for item in tree
            if item.get("type") == "blob"
            and item.get("path", "").endswith(".yml")
            and any(item["path"].startswith(p) for p in SIGMA_RELEVANT_PATHS)
        ]

        print(f"  [Sigma] Found {len(relevant_files)} relevant rule files â€” downloading...")
        rules: List[SigmaRule] = []

        base_url = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/"
        for item in relevant_files[:200]:  # cap at 200 to avoid rate limits
            try:
                r = requests.get(base_url + item["path"], timeout=10)
                if r.status_code == 200:
                    rule = _parse_sigma_yaml_minimal(r.text, item["path"])
                    if rule:
                        rules.append(rule)
            except Exception:
                continue

        db = SigmaRuleDB(rules)
        print(f"  [Sigma] {db.count} rules loaded")
        return db

    except ImportError:
        print("  [Sigma] requests not available")
        return None
    except Exception as e:
        print(f"  [Sigma] Download failed: {type(e).__name__}: {e}")
        return None


def _fetch_sigma_rules_direct(requests_module) -> Optional[SigmaRuleDB]:
    """Fallback: fetch a curated list of high-value Sigma rules directly."""
    CURATED_RULES = [
        "rules/linux/auditd/lnx_auditd_ssh_bruteforce.yml",
        "rules/linux/auditd/lnx_auditd_susp_shell.yml",
        "rules/linux/process_creation/proc_creation_lnx_susp_cron.yml",
        "rules/linux/process_creation/proc_creation_lnx_base64_decode.yml",
        "rules/network/net_connection_to_suspicious_port.yml",
    ]
    base_url = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/"
    rules: List[SigmaRule] = []
    for path in CURATED_RULES:
        try:
            r = requests_module.get(base_url + path, timeout=10)
            if r.status_code == 200:
                rule = _parse_sigma_yaml_minimal(r.text, path)
                if rule:
                    rules.append(rule)
        except Exception:
            continue
    db = SigmaRuleDB(rules)
    print(f"  [Sigma] Loaded {db.count} curated rules (fallback mode)")
    return db


def _load_sigma_cache(path: str, label: str = "cache") -> Optional[SigmaRuleDB]:
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        rules = [
            SigmaRule(
                rule_id=rule_id,
                title=d["title"],
                status=d.get("status", ""),
                level=d.get("level", "medium"),
                tags=d.get("tags", []),
                keywords=d.get("keywords", []),
                logsource=d.get("logsource", {}),
            )
            for rule_id, d in raw.get("rules", {}).items()
        ]
        db = SigmaRuleDB(rules)
        print(f"  [Sigma] Loaded {db.count} rules from {label}")
        return db
    except Exception as e:
        print(f"  [Sigma] Cache load failed: {e}")
        return None


def load_sigma_rules(force_refresh: bool = False, cache_path: Optional[str] = None) -> SigmaRuleDB:
    """Load Sigma rules with weekly auto-refresh."""
    path = cache_path or _cache_path(SIGMA_CACHE_FILENAME)

    if not force_refresh and _is_fresh(path, SIGMA_MAX_AGE_DAYS):
        db = _load_sigma_cache(path)
        if db:
            return db

    db = _fetch_sigma_rules()
    if db and db.count > 0:
        cache_data = {
            "rules": {
                r.rule_id: r.to_dict()
                for r in db._rules
            }
        }
        _save_cache(path, cache_data)
        return db

    if os.path.exists(path):
        db = _load_sigma_cache(path, label="stale cache")
        if db:
            print("  [Sigma] Refresh failed; using stale cache")
            return db

    print("  [Sigma] Using empty fallback â€” Sigma enrichment disabled")
    return SigmaRuleDB([])


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Part 3: Combined ThreatFeedDB facade
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ThreatFeedDB:
    """
    Unified threat intelligence facade.
    Provides all external feed data through a single object.
    """

    def __init__(self, kev: CisaKevDB, sigma: SigmaRuleDB):
        self.kev   = kev
        self.sigma = sigma

    # â”€â”€ KEV pass-throughs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def is_actively_exploited(self, cve_id: str) -> bool:
        return self.kev.is_actively_exploited(cve_id)

    def get_kev_details(self, cve_id: str) -> Optional[dict]:
        return self.kev.get_details(cve_id)

    def check_cves(self, cve_list: List[str]) -> List[dict]:
        """Check a list of CVEs against KEV. Returns matches only."""
        matches = []
        for cve in cve_list:
            details = self.get_kev_details(cve)
            if details:
                matches.append({"cve_id": cve, **details})
        return matches

    # â”€â”€ Sigma pass-throughs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def get_bruteforce_keywords(self) -> List[str]:
        return self.sigma.get_ssh_bruteforce_keywords()

    def get_keywords_for_level(self, level: str = "high") -> List[str]:
        return self.sigma.get_keywords_for_level(level)

    def __repr__(self) -> str:
        return f"<ThreatFeedDB kev={self.kev} sigma={self.sigma}>"


# â”€â”€ Module-level singletons â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_GLOBAL_FEEDS: Optional[ThreatFeedDB] = None


def load_threat_feeds(
    force_refresh: bool = False,
    cisa_cache_path: Optional[str] = None,
    sigma_cache_path: Optional[str] = None,
) -> ThreatFeedDB:
    """
    Load all threat feeds. Uses singletons per session.

    Args:
        force_refresh: Re-download all feeds ignoring cache age.
    """
    global _GLOBAL_FEEDS
    if _GLOBAL_FEEDS is not None and not force_refresh and not cisa_cache_path and not sigma_cache_path:
        return _GLOBAL_FEEDS

    print("  [ThreatFeeds] Initializing external threat intelligence feeds...")
    kev   = load_cisa_kev(force_refresh=force_refresh, cache_path=cisa_cache_path)
    sigma = load_sigma_rules(force_refresh=force_refresh, cache_path=sigma_cache_path)
    _GLOBAL_FEEDS = ThreatFeedDB(kev, sigma)
    print(f"  [ThreatFeeds] Ready: {_GLOBAL_FEEDS}")
    return _GLOBAL_FEEDS


def check_feeds_status() -> dict:
    """
    Unified status check for all threat intelligence feeds.

    Returns a dict with cache age, counts, and staleness for each feed.
    Covers: CISA KEV, Sigma Rules, MITRE ATT&CK (if available).

    Example output:
        {
          "cisa_kev":  {"status": "fresh", "age_hours": 4.2,
                        "entries": 1590, "catalog": "2026.05.08"},
          "sigma":     {"status": "fresh", "age_days": 2.1, "rules": 200},
          "mitre":     {"status": "fresh", "age_days": 5.0, "techniques": 625},
          "summary":   "All feeds fresh. KEV: 1590 CVEs | Sigma: 200 rules | MITRE: 625 techniques"
        }
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    result = {}

    # â”€â”€ CISA KEV â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    kev_path = _cache_path(CISA_CACHE_FILENAME)
    kev_info: dict = {"status": "missing", "age_hours": None, "entries": 0}
    if os.path.exists(kev_path):
        try:
            with open(kev_path, encoding="utf-8") as f:
                raw = json.load(f)
            fetched = datetime.datetime.fromisoformat(
                raw.get("_fetched", "2000-01-01T00:00:00+00:00")
            )
            age_h = (now - fetched).total_seconds() / 3600
            kev_info = {
                "status":  "fresh" if age_h < CISA_MAX_AGE_DAYS * 24 else "stale",
                "age_hours": round(age_h, 1),
                "entries": len(raw.get("entries", {})),
                "catalog": raw.get("catalog_version", "unknown"),
            }
        except Exception as e:
            kev_info = {"status": "corrupt", "error": str(e)}
    result["cisa_kev"] = kev_info

    # â”€â”€ Sigma Rules â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    sigma_path = _cache_path(SIGMA_CACHE_FILENAME)
    sigma_info: dict = {"status": "missing", "age_days": None, "rules": 0}
    if os.path.exists(sigma_path):
        try:
            with open(sigma_path, encoding="utf-8") as f:
                raw = json.load(f)
            fetched = datetime.datetime.fromisoformat(
                raw.get("_fetched", "2000-01-01T00:00:00+00:00")
            )
            age_d = (now - fetched).total_seconds() / 86400
            sigma_info = {
                "status": "fresh" if age_d < SIGMA_MAX_AGE_DAYS else "stale",
                "age_days": round(age_d, 1),
                "rules":  len(raw.get("rules", {})),
            }
        except Exception as e:
            sigma_info = {"status": "corrupt", "error": str(e)}
    result["sigma"] = sigma_info

    # â”€â”€ MITRE ATT&CK â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        from production.enrichment.mitre_attack_loader import _cache_path as _mitre_cache_path, CACHE_FILENAME as _MITRE_CACHE_FILE
        mitre_path = _mitre_cache_path()
        mitre_info: dict = {"status": "missing", "age_days": None, "techniques": 0}
        if os.path.exists(mitre_path):
            with open(mitre_path, encoding="utf-8") as f:
                raw = json.load(f)
            fetched_str = raw.get("_fetched", "2000-01-01T00:00:00+00:00")
            fetched = datetime.datetime.fromisoformat(fetched_str)
            age_d = (now - fetched).total_seconds() / 86400
            mitre_max = raw.get("_max_age_days", 30)
            mitre_info = {
                "status":     "fresh" if age_d < mitre_max else "stale",
                "age_days":   round(age_d, 1),
                "techniques": len(raw.get("techniques", {})),
                "version":    raw.get("_version", raw.get("version", "unknown")),
            }
        result["mitre"] = mitre_info
    except Exception as _e:
        result["mitre"] = {"status": "unavailable", "error": str(_e)}

    # â”€â”€ Summary line â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    kev_s   = f"KEV: {kev_info.get('entries', 0)} CVEs [{kev_info['status']}]"
    sigma_s = f"Sigma: {sigma_info.get('rules', 0)} rules [{sigma_info['status']}]"
    mitre_s = f"MITRE: {result['mitre'].get('techniques', 0)} techniques [{result['mitre']['status']}]"
    stale   = [n for n, v in result.items()
               if isinstance(v, dict) and v.get("status") in ("stale", "missing", "corrupt")]
    health  = f"[!] STALE: {stale}" if stale else "All feeds fresh"
    result["summary"] = f"{health} | {kev_s} | {sigma_s} | {mitre_s}"

    return result


def print_feeds_status() -> None:
    """Print a human-readable feed status table to stdout."""
    status = check_feeds_status()
    print("\n=== Threat Intelligence Feed Status ===")
    for feed, info in status.items():
        if feed == "summary":
            continue
        if not isinstance(info, dict):
            continue
        state   = info.get("status", "?")
        icon    = "OK " if state == "fresh" else "[!]"
        detail  = ""
        if feed == "cisa_kev":
            detail = (f"  {info.get('entries', 0)} CVEs  "
                      f"age={info.get('age_hours', '?')}h  "
                      f"catalog={info.get('catalog', '?')}")
        elif feed == "sigma":
            detail = (f"  {info.get('rules', 0)} rules  "
                      f"age={info.get('age_days', '?')}d")
        elif feed == "mitre":
            detail = (f"  {info.get('techniques', 0)} techniques  "
                      f"age={info.get('age_days', '?')}d  "
                      f"v={info.get('version', '?')}")
        print(f"  {icon} {feed:<12} {state:<10}{detail}")
    print(f"\n  {status.get('summary', '')}\n")



def scan_history_for_new_kev(
    session_history: list,
    feeds: "ThreatFeedDB",
) -> list:
    """
    KEV Re-scan: scan stored session history for CVEs newly added to CISA KEV.

    Call this after feeds.refresh() or on a schedule to retroactively detect
    sessions that contained CVEs which CISA has since added to the catalog.

    Parameters
    ----------
    session_history : List of dicts with keys:
                        - session_id (str)
                        - src_ip (str)
                        - commands (List[str])
    feeds           : ThreatFeedDB (must have fresh KEV data loaded)

    Returns
    -------
    List of match dicts: [{session_id, src_ip, cve_id, name, required_action, ...}]

    Usage
    -----
        from production.enrichment.threat_feed_loader import load_threat_feeds, scan_history_for_new_kev
        feeds = load_threat_feeds(force_refresh=True)   # refresh first
        hits  = scan_history_for_new_kev(session_history, feeds)
    """
    import re as _re
    hits = []
    for session in session_history:
        sid     = session.get("session_id", "unknown")
        src_ip  = session.get("src_ip", "unknown")
        cmds    = session.get("commands", [])
        full_text = " ".join(str(c) for c in cmds)

        # Extract CVE IDs from command text
        cves = list(set(_re.findall(r"CVE-\d{4}-\d{4,7}", full_text, _re.IGNORECASE)))
        for cve in cves:
            details = feeds.get_kev_details(cve.upper())
            if details:
                hits.append({
                    "session_id":      sid,
                    "src_ip":          src_ip,
                    "cve_id":          cve.upper(),
                    "name":            details.get("name", ""),
                    "vendor":          details.get("vendor", ""),
                    "product":         details.get("product", ""),
                    "required_action": details.get("required_action", ""),
                    "due_date":        details.get("due_date", ""),
                })

    if hits:
        print(f"  [KEV Re-scan] {len(hits)} KEV match(es) found in "
              f"{len(session_history)} session(s)")
    else:
        print(f"  [KEV Re-scan] No KEV CVEs in {len(session_history)} session(s)")
    return hits


# â”€â”€ CLI test â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if __name__ == "__main__":
    import sys
    force = "--refresh" in sys.argv

    # Always print status first
    print_feeds_status()

    feeds = load_threat_feeds(force_refresh=force)

    print("\n-- CISA KEV Tests --")
    test_cves = ["CVE-2021-44228", "CVE-2022-26134", "CVE-2021-26084", "CVE-FAKE-0000"]
    for cve in test_cves:
        status = "ACTIVELY EXPLOITED [!]" if feeds.is_actively_exploited(cve) else "not in KEV"
        print(f"  {cve}: {status}")
        if feeds.is_actively_exploited(cve):
            d = feeds.get_kev_details(cve)
            print(f"    {d['vendor']} {d['product']} -- {d['name'][:60]}")

    print("\n-- Sigma SSH/Brute-force Keywords (sample) --")
    kws = feeds.get_bruteforce_keywords()
    print(f"  Total keywords: {len(kws)}")
    print(f"  Sample: {kws[:10]}")

