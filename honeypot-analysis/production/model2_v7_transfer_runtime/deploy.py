#!/usr/bin/env python3
"""Deploy the bounded Model2 transfer fix to Pi and GCP with local rollback.

Run only after reviewing the files and tests. This touches three Model2 services
and the Pi capture override; it does not alter model or policy artifacts.
"""

from __future__ import annotations

import hashlib
import pathlib
import shlex
import subprocess
import sys
import time


HERE = pathlib.Path(__file__).resolve().parent
GCP_DIR = "/opt/model2-v7/honeypot-analysis/evaluation/model2_v7_32_feature_generation_20260913_v1/production_runtime_v1"
PI_DIR = "/opt/model2-v7/production_runtime_v1"
OVERRIDE = "/etc/systemd/system/model2-v7-pi-capture-transfer.service.d/transfer-http.conf"
BASELINE = {
    "gcp": {
        "v7_capstone_runtime.py": "bb2a1731c64d9ed05becb65c96e3d468ca52c586de2942da80eac4570ccb72ec",
        "v7_offline_zeek.py": "686bb7c1b97079a775bfad1e0be006fc2c000545b6d7f207ed691be6c9a3d501",
        "v7_transfer_binding.py": "44aa6f6290b6f7a86cbe3d378bf4b1373ee2c22cbfae1fcb0d502c9b6e471a38",
    },
    "pi": {
        "v7_pi_observer.py": "cfeef8973f7b2174a1bacb00d795a1f342a26f41d663012ef7ba3c15fd72c91d",
        "v7_offline_zeek.py": "6de58e9f5c32168418088ddefd53098dd9ac3ac7c1f844f2cca82443b88220b6",
        "v7_transfer_binding.py": "461228338a2224197068d10830e60a97975e14d99fea80a3017c3a5b566f667f",
    },
}
FILES = {
    "gcp": ("v7_capstone_runtime.py", "v7_transfer_binding.py"),
    "pi": ("v7_pi_observer.py", "v7_offline_zeek.py", "v7_transfer_binding.py", "model2-v7-pi-capture-transfer.override.conf"),
}
SSH = ["ssh", "-F", "/home/rubchek/.ssh/config", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
SCP = ["scp", "-O", "-F", "/home/rubchek/.ssh/config", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
HOSTS = {"gcp": "honeypot-gcp", "pi": "cpe27@10.58.33.42"}
BACKUP = "/var/backups/model2-transfer-20260924-r3"
SITES = ("gcp",)
PI_OVERRIDE_BASELINE = "d1f3b704a7cc801ee633e7d70560582d89c87612311ad8ce30c4ded2079b6132"


def run(command: list[str], *, capture: bool = False) -> str:
    result = subprocess.run(command, check=True, text=True, stdout=subprocess.PIPE if capture else None, timeout=90)
    return result.stdout.strip() if capture else ""


def ssh(site: str, command: str, *, capture: bool = False) -> str:
    port = ["-J", "honeypot-gcp", "-p", "2222"] if site == "pi" else []
    return run([*SSH, *port, HOSTS[site], command], capture=capture)


def scp(site: str, name: str, destination: str) -> None:
    port = ["-o", "ProxyJump=honeypot-gcp", "-P", "2222"] if site == "pi" else []
    run([*SCP, *port, str(HERE / name), f"{HOSTS[site]}:{destination}/{name}"])


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_baseline(site: str) -> None:
    directory = GCP_DIR if site == "gcp" else PI_DIR
    for name, expected in BASELINE[site].items():
        actual = ssh(site, f"sudo -n sha256sum {shlex.quote(directory + '/' + name)}", capture=True).split()[0]
        if actual != expected:
            raise RuntimeError(f"{site}:{name} baseline changed; refusing install")
    for name in FILES[site]:
        if not (HERE / name).is_file():
            raise RuntimeError(f"candidate file missing: {name}")
    if site == "pi":
        actual = ssh(site, f"sudo -n sha256sum {shlex.quote(OVERRIDE)}", capture=True).split()[0]
        if actual != PI_OVERRIDE_BASELINE:
            raise RuntimeError("Pi capture override baseline changed; refusing install")


def prepare(site: str) -> str:
    stage = ssh(site, "mktemp -d -p /var/tmp model2-transfer.XXXXXXXX", capture=True)
    for name in FILES[site]:
        scp(site, name, stage)
        expected = sha256(HERE / name)
        actual = ssh(site, f"sha256sum {shlex.quote(stage + '/' + name)}", capture=True).split()[0]
        if actual != expected:
            raise RuntimeError(f"{site}:{name} transfer hash mismatch")
    return stage


def backup(site: str) -> None:
    directory = GCP_DIR if site == "gcp" else PI_DIR
    names = list(BASELINE[site])
    command = f"sudo -n mkdir -m 700 {shlex.quote(BACKUP)} && " + " && ".join(
        f"sudo -n cp -p {shlex.quote(directory + '/' + name)} {shlex.quote(BACKUP + '/' + name)}" for name in names
    )
    if site == "pi":
        command += f" && sudo -n cp -p {shlex.quote(OVERRIDE)} {shlex.quote(BACKUP + '/transfer-http.conf')}"
    ssh(site, command)


def install(site: str, stage: str) -> None:
    directory = GCP_DIR if site == "gcp" else PI_DIR
    for name in FILES[site]:
        if name.endswith(".conf"):
            target = OVERRIDE
        else:
            target = directory + "/" + name
        ssh(site, f"sudo -n install -D -o root -g root -m 0644 {shlex.quote(stage + '/' + name)} {shlex.quote(target)}")
        actual = ssh(site, f"sudo -n sha256sum {shlex.quote(target)}", capture=True).split()[0]
        if actual != sha256(HERE / name):
            raise RuntimeError(f"{site}:{name} installed hash mismatch")
    if site == "pi":
        ssh(site, "sudo -n systemctl daemon-reload && sudo -n systemctl restart model2-v7-pi-capture-transfer.service model2-v7-pi-observer.service")
        services = ("model2-v7-pi-capture-transfer.service", "model2-v7-pi-observer.service")
    else:
        ssh(site, "sudo -n systemctl restart model2-v7-receiver.service")
        services = ("model2-v7-receiver.service",)
    time.sleep(3)
    for service in services:
        if ssh(site, f"systemctl is-active {service}", capture=True) != "active":
            raise RuntimeError(f"{site}:{service} inactive after install")


def rollback(site: str) -> None:
    directory = GCP_DIR if site == "gcp" else PI_DIR
    for name in BASELINE[site]:
        ssh(site, f"sudo -n cp -p {shlex.quote(BACKUP + '/' + name)} {shlex.quote(directory + '/' + name)}")
    if site == "pi":
        ssh(site, f"sudo -n cp -p {shlex.quote(BACKUP + '/transfer-http.conf')} {shlex.quote(OVERRIDE)} && sudo -n systemctl daemon-reload && sudo -n systemctl restart model2-v7-pi-capture-transfer.service model2-v7-pi-observer.service")
    else:
        ssh(site, "sudo -n systemctl restart model2-v7-receiver.service")


def main() -> int:
    prepared: dict[str, str] = {}
    backed_up: list[str] = []
    try:
        for site in SITES:
            verify_baseline(site)
            prepared[site] = prepare(site)
        for site in SITES:
            backup(site)
            backed_up.append(site)
        for site in SITES:
            install(site, prepared[site])
        print("Model2 transfer runtime installed; services active on", ",".join(SITES), "; backups retained at", BACKUP)
        return 0
    except Exception as exc:
        print(f"deployment failed: {exc}", file=sys.stderr)
        for site in reversed(backed_up):
            try:
                rollback(site)
                print(f"rolled back {site}", file=sys.stderr)
            except Exception as rollback_exc:
                print(f"ROLLBACK FAILED for {site}: {rollback_exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
