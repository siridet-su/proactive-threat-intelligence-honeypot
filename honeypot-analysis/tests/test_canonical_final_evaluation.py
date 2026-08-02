from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "evaluation/canonical_final_evaluation.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_canonical_final_evaluation_is_complete_and_content_addressed() -> None:
    document = json.loads(CANONICAL.read_text(encoding="utf-8"))

    assert document["schema_version"] == "canonical_final_evaluation.v1"
    assert document["status"] == "complete_with_disclosed_limitations"
    claims = document["claims"]
    claim_ids = [claim["claim_id"] for claim in claims]
    assert len(claim_ids) == len(set(claim_ids))
    assert {
        "next_tactic.historical_single_checkpoint",
        "next_tactic.external_vomm_reference",
        "typed_semantic_authority.v2",
        "selection_status.original_generation",
        "current_production_acceptance",
    } <= set(claim_ids)

    single = json.loads(
        (ROOT / "evaluation/next_tactic_benchmark_evidence/single_checkpoint_evaluation.json")
        .read_text(encoding="utf-8")
    )
    historical = next(
        claim for claim in claims
        if claim["claim_id"] == "next_tactic.historical_single_checkpoint"
    )
    assert historical["metrics"] == single["metrics"]
    assert historical["promotion_gate"] == single["promotion_gate"]

    retained = list(document["retained_raw_inputs"])
    for claim in claims:
        retained.extend(claim.get("source_artifacts", []))
    seen: set[str] = set()
    for artifact in retained:
        path = str(artifact["path"])
        if path in seen:
            continue
        seen.add(path)
        target = ROOT / path
        assert target.is_file(), path
        assert _sha256(target) == artifact["sha256"], path

    superseded = document["superseded_artifacts"]
    assert len(superseded) >= 5
    assert len({item["path"] for item in superseded}) == len(superseded)
    for artifact in superseded:
        assert artifact["status"] == "superseded"
        assert not (ROOT / artifact["path"]).exists(), artifact["path"]
        assert len(artifact["sha256"]) == 64

    boundaries = " ".join(document["acceptance_boundaries"]).lower()
    assert all(term in boundaries for term in ("prediction", "evidence", "historical"))
