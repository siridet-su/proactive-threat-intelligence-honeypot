"""Notebook cell 3B IoC extraction as production code."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse


RE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
RE_URL = re.compile(r"https?://[^\s'\"<>|,;)(]+")
RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|info|biz|ru|cn|tk|ml|top|xyz|site|online)\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")

PRIVATE_NETS = [ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]
INVALID_IPS = {"0.0.0.0", "255.255.255.255", "127.0.0.1", "0.0.0.1"}
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".vbs", ".hta", ".sh", ".elf", ".bin"}
SUSPICIOUS_PORTS = {4444, 4445, 4446, 1234, 1337, 31337, 8888, 8889, 9999, 6666, 7777, 2222, 5555, 6667, 9001, 9002}


@dataclass
class IoC:
    type: str
    value: str
    confidence: str = "high"
    first_seen: str = ""
    honeypot: bool = False
    note: str = ""

    def __hash__(self) -> int:
        return hash((self.type, self.value.lower()))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IoC) and hash(self) == hash(other)


@dataclass
class IoCBundle:
    ips: List[IoC] = field(default_factory=list)
    urls: List[IoC] = field(default_factory=list)
    domains: List[IoC] = field(default_factory=list)
    hashes: List[IoC] = field(default_factory=list)
    ports: List[IoC] = field(default_factory=list)

    @property
    def all(self) -> List[IoC]:
        return self.ips + self.urls + self.domains + self.hashes + self.ports

    def summary(self) -> Dict[str, List[str]]:
        return {
            "IPs": [ioc.value for ioc in self.ips],
            "URLs": [ioc.value for ioc in self.urls],
            "Domains": [ioc.value for ioc in self.domains],
            "Hashes": [ioc.value for ioc in self.hashes],
            "Ports": [ioc.value for ioc in self.ports],
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ips": [asdict(ioc) for ioc in self.ips],
            "urls": [asdict(ioc) for ioc in self.urls],
            "domains": [asdict(ioc) for ioc in self.domains],
            "hashes": [asdict(ioc) for ioc in self.hashes],
            "ports": [asdict(ioc) for ioc in self.ports],
            "summary": self.summary(),
            "total": len(self.all),
        }


def is_private_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
        return any(address in network for network in PRIVATE_NETS)
    except ValueError:
        return False


def extract_iocs(text: str, first_seen: str = "") -> IoCBundle:
    bundle = IoCBundle()
    seen: set[IoC] = set()

    def add(ioc: IoC) -> None:
        if ioc in seen:
            return
        seen.add(ioc)
        ioc.first_seen = ioc.first_seen or first_seen
        if ioc.type in {"ipv4", "ipv6"}:
            bundle.ips.append(ioc)
        elif ioc.type == "url":
            bundle.urls.append(ioc)
        elif ioc.type == "domain":
            bundle.domains.append(ioc)
        elif ioc.type == "port":
            bundle.ports.append(ioc)
        else:
            bundle.hashes.append(ioc)

    url_spans = set()
    for match in RE_URL.finditer(text or ""):
        value = match.group().rstrip(".,;)")
        parsed = urlparse(value)
        confidence = "high" if any(value.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) else "medium"
        if parsed.port and parsed.port in SUSPICIOUS_PORTS:
            confidence = "high"
        add(IoC("url", value, confidence))
        url_spans.add((match.start(), match.end()))

    for match in RE_IPV4.finditer(text or ""):
        value = match.group()
        if value in INVALID_IPS:
            continue
        if any(start <= match.start() <= match.end() <= end for start, end in url_spans):
            continue
        add(IoC("ipv4", value, "low" if is_private_ip(value) else "high"))

    url_domains = {urlparse(ioc.value).netloc.lower() for ioc in bundle.urls}
    for match in RE_DOMAIN.finditer(text or ""):
        value = match.group().lower()
        if any(start <= match.start() <= match.end() <= end for start, end in url_spans):
            continue
        if value not in url_domains:
            add(IoC("domain", value, "medium"))

    hash_spans = set()
    for pattern, kind in ((RE_SHA256, "sha256"), (RE_SHA1, "sha1"), (RE_MD5, "md5")):
        for match in pattern.finditer(text or ""):
            if any(start <= match.start() <= match.end() <= end for start, end in hash_spans):
                continue
            add(IoC(kind, match.group(), "high"))
            hash_spans.add((match.start(), match.end()))

    return bundle


def extract_iocs_honeypot(text: str, first_seen: str = "", force_high: bool = False, session_nodes: Optional[Iterable[Any]] = None) -> IoCBundle:
    bundle = extract_iocs(text, first_seen)
    nodes = list(session_nodes or [])

    if force_high:
        for ioc in bundle.all:
            ioc.honeypot = True
        for ioc in bundle.ips:
            ioc.confidence = "high"

    seen_ips = {ioc.value for ioc in bundle.ips}
    for node in nodes:
        src_ip = getattr(node, "src_ip", "")
        if src_ip and src_ip not in seen_ips and src_ip not in INVALID_IPS:
            bundle.ips.append(IoC("ipv4", src_ip, "high", first_seen, True, "attacker src_ip"))
            seen_ips.add(src_ip)

    seen_hashes = {ioc.value.lower() for ioc in bundle.hashes}
    for node in nodes:
        file_hash = getattr(node, "file_hash", "")
        if file_hash and file_hash.lower() not in seen_hashes:
            bundle.hashes.append(
                IoC("sha256", file_hash, "high", first_seen, True, f"downloaded via: {getattr(node, 'command_line', '')[:60]}")
            )
            seen_hashes.add(file_hash.lower())

    seen_ports = set()
    for node in nodes:
        dst_port = int(getattr(node, "dst_port", 0) or 0)
        if getattr(node, "suspicious", False) and dst_port and dst_port not in seen_ports:
            for ioc in bundle.urls:
                if urlparse(ioc.value).port == dst_port:
                    ioc.confidence = "high"
                    ioc.note = f"suspicious port {dst_port}"
            bundle.ports.append(IoC("port", str(dst_port), "high", first_seen, True, f"used in: {getattr(node, 'command_line', '')[:60]}"))
            seen_ports.add(dst_port)

    if nodes:
        commands = [node for node in nodes if getattr(node, "command_line", "").strip()]
        failed = [node for node in commands if not getattr(node, "success", True)]
        if commands and len(failed) / len(commands) >= 0.5:
            for ioc in bundle.ips:
                if ioc.confidence == "high":
                    ioc.confidence = "medium"
                    ioc.note = f"mostly failed session ({len(failed)}/{len(commands)} commands failed)"

    return bundle


def merge_bundles(bundles: Iterable[IoCBundle]) -> IoCBundle:
    merged = IoCBundle()
    seen: set[IoC] = set()
    for bundle in bundles:
        for ioc in bundle.all:
            if ioc in seen:
                continue
            seen.add(ioc)
            if ioc.type in {"ipv4", "ipv6"}:
                merged.ips.append(ioc)
            elif ioc.type == "url":
                merged.urls.append(ioc)
            elif ioc.type == "domain":
                merged.domains.append(ioc)
            elif ioc.type == "port":
                merged.ports.append(ioc)
            else:
                merged.hashes.append(ioc)
    return merged


def extract_from_process_sessions(process_sessions: Iterable[Any]) -> IoCBundle:
    bundles = []
    for session in process_sessions:
        first_seen = session.events[0].get("UtcTime", "") if getattr(session, "events", None) else ""
        force_high = any(getattr(node, "ioc_force_high", False) for node in session.nodes)
        bundles.append(
            extract_iocs_honeypot(
                session.all_text,
                first_seen=first_seen,
                force_high=force_high,
                session_nodes=session.nodes,
            )
        )
    return merge_bundles(bundles)
