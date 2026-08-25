from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from production.utils.serialization import stable_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PROJECT_ROOT.parent
RECEIPT_PATH = (
    PROJECT_ROOT / "evaluation" / "final_f_phase3_projection_receipt.v1.json"
)


def test_phase3_projection_receipt_is_content_addressed() -> None:
    receipt = json.loads(RECEIPT_PATH.read_text(encoding="utf-8"))
    assert receipt["schema_version"] == "final_f_phase3_projection_receipt.v1"
    assert receipt["status"] == "COMPLETE_VALID"
    assert receipt["phase"] == 3
    for key in ("implementation", "freeze"):
        commit = receipt[f"{key}_commit"]
        tree = subprocess.run(
            ["git", "show", "-s", "--format=%T", commit],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert tree == receipt[f"{key}_tree"]
    for item in receipt["files"]:
        content = subprocess.run(
            ["git", "show", f"{receipt['freeze_commit']}:{item['path']}"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
        ).stdout
        assert hashlib.sha256(content).hexdigest() == item["sha256"]
    basis = dict(receipt)
    recorded = basis.pop("receipt_sha256")
    assert hashlib.sha256(stable_json(basis).encode("utf-8")).hexdigest() == recorded
