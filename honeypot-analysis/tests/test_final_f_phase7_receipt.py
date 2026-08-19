from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from production.utils.serialization import stable_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PROJECT_ROOT.parent
RECEIPT_PATH = PROJECT_ROOT / "evaluation" / "final_f_phase7_qualification_receipt.v1.json"


def test_phase7_receipt_binds_frozen_basis_and_hash() -> None:
    receipt = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))
    assert receipt["schema_version"] == "final_f_phase7_qualification_receipt.v1"
    assert receipt["status"] == "COMPLETE_VALID"
    assert receipt["phase"] == 7
    basis_commit = receipt["qualification_commit_full"]
    tree = subprocess.run(
        ["git", "show", "-s", "--format=%T", basis_commit],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert tree == receipt["qualification_tree"]
    assert receipt["qualification_result"]["phase8_authorized"] is True
    assert receipt["source_changes"]["runtime_source_changes"] is False
    for item in receipt["phase_receipts"]:
        path = PROJECT_ROOT / item["path"].split("honeypot-analysis/", 1)[-1]
        assert path.is_file(), path
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
    basis = dict(receipt)
    recorded = basis.pop("receipt_sha256")
    assert hashlib.sha256(stable_json(basis).encode("utf-8")).hexdigest() == recorded
