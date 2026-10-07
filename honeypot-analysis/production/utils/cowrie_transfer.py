"""Distinguish Cowrie network transfers from local redirection artifacts.

Cowrie emits ``cowrie.session.file_download`` for both wget/curl downloads
and shell output redirection. Only the former includes a source URL. The
event ID (or an artifact hash) alone is not proof of a network transfer.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit


def is_cowrie_network_transfer(event: Mapping[str, Any]) -> bool:
    eventid = event.get("eventid")
    if eventid == "cowrie.session.file_upload":
        return True
    if eventid != "cowrie.session.file_download":
        return False
    url = event.get("url")
    if not isinstance(url, str) or not url or len(url) > 4096:
        return False
    try:
        parsed = urlsplit(url)
        return parsed.scheme.lower() in {"http", "https", "ftp", "sftp"} and bool(parsed.hostname)
    except ValueError:
        return False
