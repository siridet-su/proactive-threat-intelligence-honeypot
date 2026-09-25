"""
ftp-door — passive FTP decoy.

Uses pyftpdlib, one read-only decoy account from the shared VFS schema, and
four bait export/backup files. Login and command telemetry goes to
Deception Core; RETR of a bait file asks Core for bounded decoy content.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time

import httpx
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ftp-door")

VFS_SCHEMA_PATH = os.environ.get(
    "VFS_SCHEMA_PATH", "/data/vfs_schema_updated_2026-07-22.json"
)
FTP_ROOT = os.environ.get("FTP_ROOT", "/ftp-root")
DECEPTION_CORE_URL = os.environ.get(
    "DECEPTION_CORE_URL", "http://deception-core:9000"
).rstrip("/")
DECIDE_URL = DECEPTION_CORE_URL + "/v1/decide"
TRACK_URL = DECEPTION_CORE_URL + "/v1/track"
MASQUERADE_ADDRESS = os.environ.get("FTP_MASQUERADE_ADDRESS", "")
PASSIVE_PORTS_START = int(os.environ.get("FTP_PASSIVE_PORT_START", "30000"))
PASSIVE_PORTS_END = int(os.environ.get("FTP_PASSIVE_PORT_END", "30009"))

# Lure filename -> (initial LIST size, approximate file age in days).
LURE_FILES = {
    "backup_2026-07.sql.gz": (48213, 1),
    "backup_2026-06.sql.gz": (46890, 31),
    "customers_export.csv": (8420, 3),
    "invoices_Q1_2026.csv": (15310, 5),
}


def _load_ftp_credentials() -> tuple[str, str]:
    with open(VFS_SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = json.load(f)
    odoo_conf = schema["static_contents"]["odoo_conf_content"]
    user_match = re.search(r"^db_user\s*=\s*(\S+)", odoo_conf, re.MULTILINE)
    pass_match = re.search(r"^db_password\s*=\s*(\S+)", odoo_conf, re.MULTILINE)
    if not user_match or not pass_match:
        raise RuntimeError("หา db_user/db_password ใน odoo_conf_content ไม่เจอ")
    return user_match.group(1), pass_match.group(1)


def _setup_ftp_root() -> None:
    os.makedirs(FTP_ROOT, exist_ok=True)
    now = time.time()
    for name, (size, age_days) in LURE_FILES.items():
        path = os.path.join(FTP_ROOT, name)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.truncate(size)
        mtime = now - age_days * 86400
        os.utime(path, (mtime, mtime))


def _post_track(command: str, ip: str) -> None:
    """Send a best-effort activity update to Core without blocking the FTP loop."""
    try:
        httpx.post(
            TRACK_URL,
            json={"ip": ip, "door": "ftp", "command": command},
            timeout=3,
        )
    except Exception:
        # Do not log command text: failed-login commands contain submitted secrets.
        log.debug("track post failed (ignored)", exc_info=True)


def _track_login(ip: str, username: str, password: str, ok: bool) -> None:
    """Send the attempted login to Core for its per-IP behavior classifier."""
    if ok:
        command = f"ftp-login-ok username={username!r}"
    else:
        command = f"ftp-login username={username!r} password={password!r}"
    threading.Thread(target=_post_track, args=(command, ip), daemon=True).start()


class DeceptionFTPHandler(FTPHandler):
    def on_login(self, username: str) -> None:
        _track_login(self.remote_ip, username, "", ok=True)

    def on_login_failed(self, username: str, password: str) -> None:
        _track_login(self.remote_ip, username, password, ok=False)

    def ftp_RETR(self, file: str) -> None:
        filename = os.path.basename(file)
        if filename in LURE_FILES:
            try:
                self._fill_lure_content(filename, file)
            except Exception:
                log.exception("deception-core call failed for %s", filename)
        return super().ftp_RETR(file)

    def _fill_lure_content(self, filename: str, real_path: str) -> None:
        payload = {
            "ip": self.remote_ip,
            "door": "ftp",
            "mode": "bash",
            "cwd": "/",
            "files_str": ", ".join(LURE_FILES.keys()),
            "target": filename,
            "command": f"cat {filename}",
        }
        resp = httpx.post(DECIDE_URL, json=payload, timeout=15)
        resp.raise_for_status()
        content = resp.json().get("content", "")
        data = content.encode("utf-8") if isinstance(content, str) else content
        with open(real_path, "wb") as f:
            f.write(data)


def main() -> None:
    _setup_ftp_root()
    ftp_user, ftp_password = _load_ftp_credentials()
    log.info("ftp-door: user=%s (password loaded from vfs schema, not logged)", ftp_user)

    authorizer = DummyAuthorizer()
    # Read-only: change directory, list, retrieve; no upload/delete/create.
    authorizer.add_user(ftp_user, ftp_password, FTP_ROOT, perm="elr")

    handler = DeceptionFTPHandler
    handler.authorizer = authorizer
    # pyftpdlib prepends the FTP response code to this string.
    handler.banner = "220 ProFTPD 1.3.8a Server ready."
    if MASQUERADE_ADDRESS:
        handler.masquerade_address = MASQUERADE_ADDRESS
    handler.passive_ports = range(PASSIVE_PORTS_START, PASSIVE_PORTS_END + 1)

    server = FTPServer(("0.0.0.0", 21), handler)
    server.max_cons = 10
    server.max_cons_per_ip = 5
    server.serve_forever()


if __name__ == "__main__":
    main()
