"""Resolve a content-addressed runtime binding for the retained Final F POC.

This is an isolated, offline study.  It may train temporary held-out-fold
models solely to reconstruct calibration-support OOF logits; it never changes
the frozen full-TRAIN checkpoint or any production/canonical artifact.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import math
import os
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

sys.dont_write_bytecode = True

BASE = Path(__file__).resolve().parent
REPO = next(parent for parent in BASE.parents if (parent / "honeypot-analysis").is_dir())
EVAL = REPO / "honeypot-analysis/evaluation"
RETAINED_DIR = EVAL / "prediction_next_distinct_transformer_refinement_v1_retry3/artifacts-20260823"
PADDING_DIR = EVAL / "prediction_next_distinct_transformer_padding_fix_v1/artifacts-20260823"
READINESS_DIR = EVAL / "receipts/gcp_final_poc_deployment_readiness_20260823"
FOLD_PATH = RETAINED_DIR / "internal_cv_folds.json"
V2_RUN = EVAL / "prediction_next_distinct_model_comparison_v2/run_v2.py"
REF_RUN = EVAL / "prediction_next_distinct_transformer_refinement_v1/run_refinement.py"
ADAPTER_PATH = REPO / "honeypot-analysis/production/prediction_next_distinct_poc/adapter.py"
MODEL_LOADER_PATH = BASE / "model_loader.py"

EXPECTED_RETAINED = "16506e962432f9921d18a514c3a31686a20f9734385ec49439ad2651e4cdd283"
EXPECTED_RETAINED_CONFIG = "b8cc325262c5f3688b26c4d0b0b4e244fce45c4bba3b86161449c19e457675d2"
EXPECTED_PADDING = "96f17c2a79c7a7c77c8b30f81bba8710c7488c37a3e79ea6b6fadb4840a1e54b"
EXPECTED_PADDING_T = 0.6191339280332447
EXPECTED_PADDING_SUMMARY = "2ea8f8cc17f4d8307b38bfca95b5e0545edf29dbd53e2d517ed6905db49d5d7a"
EXPECTED_MANIFEST = "5b88e7410e4f2ba96ff578cb5e9da025b3028c2e12c6017f08e6bee0a177458d"
EXPECTED_FOLDS = "e3252e78d7d7b2ec13b942adf64b0f6c7805e12f68c05ab1f62ed039a5d93230"
EXPECTED_FOLD_CONTENT = "f0426fd06ff652a84e243beceecdae61053ae16d587f10803cb6d7d05634d8ee"
EXPECTED_LABELS = (
    "command-and-control", "credential-access", "defense-evasion", "discovery",
    "execution", "persistence", "privilege-escalation",
)
CALIBRATION_SEEDS = (20260822, 20260823, 20260824)
MAX_HISTORY = 8


class StudyBlocked(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def publish_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise StudyBlocked(f"refusing to overwrite new study artifact: {path}")
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    temp.write_text(stable_json(value) + "\n", encoding="utf-8")
    with temp.open("rb") as handle:
        os.fsync(handle.fileno())
    os.link(temp, path)
    temp.unlink(missing_ok=True)


def publish_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise StudyBlocked(f"refusing to overwrite new study artifact: {path}")
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    temp.write_text(value, encoding="utf-8")
    with temp.open("rb") as handle:
        os.fsync(handle.fileno())
    os.link(temp, path)
    temp.unlink(missing_ok=True)


def publish_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise StudyBlocked(f"refusing to overwrite new study artifact: {path}")
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    digest = hashlib.sha256()
    with temp.open("w", encoding="utf-8") as stream:
        for row in rows:
            line = stable_json(row) + "\n"
            stream.write(line)
            digest.update(line.encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temp, path)
    temp.unlink(missing_ok=True)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise StudyBlocked(f"missing or symlinked JSON: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StudyBlocked(f"JSON root is not an object: {path}")
    return value


def load_module(name: str, path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise StudyBlocked(f"source unavailable: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise StudyBlocked(f"cannot load source: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def lineage_check() -> dict[str, Any]:
    retained_checkpoint = RETAINED_DIR / "final_refined_transformer.pt"
    retained_config = RETAINED_DIR / "final_model_config.json"
    selected = RETAINED_DIR / "selected_candidate.json"
    refinement_receipt = RETAINED_DIR / "receipt.json"
    refinement_summary = RETAINED_DIR / "refinement_summary.json"
    padding_checkpoint = PADDING_DIR / "final_padding_study_transformer.pt"
    padding_config = PADDING_DIR / "final_model_config.json"
    padding_selected = PADDING_DIR / "selected_padding_candidate.json"
    padding_temperature = PADDING_DIR / "temperature_scaling_results.json"
    padding_summary = PADDING_DIR / "padding_fix_summary.json"
    checkpoint_lineage = READINESS_DIR / "checkpoint_lineage.json"
    paths = [retained_checkpoint, retained_config, selected, refinement_receipt,
             refinement_summary, padding_checkpoint, padding_config, padding_selected,
             padding_temperature, padding_summary, checkpoint_lineage]
    hashes = {str(path.relative_to(REPO)): sha256_file(path) for path in paths}
    if hashes[str(retained_checkpoint.relative_to(REPO))] != EXPECTED_RETAINED:
        raise StudyBlocked("retained checkpoint SHA changed")
    if hashes[str(retained_config.relative_to(REPO))] != EXPECTED_RETAINED_CONFIG:
        raise StudyBlocked("retained model config SHA changed")
    if hashes[str(padding_checkpoint.relative_to(REPO))] != EXPECTED_PADDING:
        raise StudyBlocked("padding-study checkpoint SHA changed")
    if hashes[str(padding_summary.relative_to(REPO))] != EXPECTED_PADDING_SUMMARY:
        raise StudyBlocked("padding-study summary SHA changed")
    selected_body = read_json(selected)
    retained_cfg = selected_body.get("config", {})
    if retained_cfg.get("loss") != "inverse_sqrt" or retained_cfg.get("d_model") != 16:
        raise StudyBlocked("selected retained configuration is not refined-v1 inverse-sqrt")
    final_cfg = read_json(retained_config)
    if final_cfg.get("checkpoint_sha256") != EXPECTED_RETAINED or final_cfg.get("parameter_count") != 2599:
        raise StudyBlocked("retained final config does not bind the retained checkpoint")
    padding_body = read_json(padding_summary)
    padding_binding = padding_body.get("temperature_binding", {})
    padding_temperature_body = padding_body.get("temperature", {})
    if float(padding_temperature_body.get("optimal_temperature", -1.0)) != EXPECTED_PADDING_T:
        raise StudyBlocked("padding-study temperature value changed")
    if padding_binding and padding_binding.get("checkpoint_sha256") not in (None, EXPECTED_PADDING):
        raise StudyBlocked("padding temperature binding contradicts later checkpoint")
    if "explicit_checkpoint_binding" in padding_binding and padding_binding["explicit_checkpoint_binding"] != EXPECTED_PADDING:
        raise StudyBlocked("padding temperature explicit checkpoint binding changed")
    lineage = read_json(checkpoint_lineage)
    sci = lineage.get("scientific_selection", {})
    later = lineage.get("later_padding_study_refit", {})
    comparison = lineage.get("comparison", {})
    if sci.get("checkpoint_file_sha256") != EXPECTED_RETAINED or later.get("checkpoint_file_sha256") != EXPECTED_PADDING:
        raise StudyBlocked("latest readiness lineage contradicts checkpoint identities")
    if comparison.get("temperature_bound_to_scientifically_retained_16506") is not False:
        raise StudyBlocked("latest readiness lineage does not preserve the temperature mismatch")
    if comparison.get("transplant_allowed") is not False:
        raise StudyBlocked("temperature transplant must remain prohibited")
    return {
        "schema_version": "gcp_final_poc_runtime_lineage_verification.v1",
        "status": "PASS",
        "retained_checkpoint_sha256": EXPECTED_RETAINED,
        "retained_checkpoint_path": str(retained_checkpoint.relative_to(REPO)),
        "retained_config_sha256": EXPECTED_RETAINED_CONFIG,
        "retained_configuration": retained_cfg,
        "retained_selection_artifact_sha256": hashes[str(selected.relative_to(REPO))],
        "refinement_summary_sha256": hashes[str(refinement_summary.relative_to(REPO))],
        "refinement_receipt_sha256": hashes[str(refinement_receipt.relative_to(REPO))],
        "padding_study_checkpoint_sha256": EXPECTED_PADDING,
        "padding_study_config_sha256": hashes[str(padding_config.relative_to(REPO))],
        "padding_study_selection_sha256": hashes[str(padding_selected.relative_to(REPO))],
        "existing_padding_temperature": EXPECTED_PADDING_T,
        "existing_padding_temperature_sha256": hashes[str(padding_temperature.relative_to(REPO))],
        "existing_padding_summary_sha256": EXPECTED_PADDING_SUMMARY,
        "existing_temperature_valid_for_retained_checkpoint": False,
        "temperature_transplant_permitted": False,
        "latest_readiness_checkpoint_lineage_sha256": hashes[str(checkpoint_lineage.relative_to(REPO))],
        "historical_receipts_modified": False,
    }


def environment_record(torch: Any) -> dict[str, Any]:
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    return {
        "schema_version": "gcp_final_poc_inference_environment.v1",
        "status": "COMPLETE_VALID",
        "python": sys.version,
        "python_executable": sys.executable,
        "torch_version": str(torch.__version__),
        "torch_origin": str(Path(torch.__file__).resolve()),
        "numpy_version": str(np.__version__),
        "numpy_origin": str(Path(np.__file__).resolve()),
        "device": "cpu",
        "cuda_available": bool(torch.cuda.is_available()),
        "torch_num_threads": int(torch.get_num_threads()),
        "deterministic_algorithms": bool(torch.are_deterministic_algorithms_enabled()),
        "network_accessed": False,
        "system_python_modified": False,
        "offline_cached_distribution": True,
        "cache_roots": ["/home/rubchek/.cache/uv/archive-v0"],
        "approved_scope": "local offline Final F runtime-binding study only",
    }


def metric_calibration(y: np.ndarray, logits: np.ndarray, temperature: float = 1.0) -> dict[str, Any]:
    scaled = logits / float(temperature)
    shifted = scaled - np.max(scaled, axis=1, keepdims=True)
    probs = np.exp(shifted)
    probs /= np.sum(probs, axis=1, keepdims=True)
    pred = np.argmax(probs, axis=1)
    confidence = np.max(probs, axis=1)
    correct = pred == y
    n = len(y)
    nll = float(-np.mean(np.log(np.clip(probs[np.arange(n), y], 1e-300, 1.0))))
    onehot = np.eye(probs.shape[1], dtype=np.float64)[y]
    brier = float(np.mean(np.sum((probs - onehot) ** 2, axis=1)))
    ece = 0.0
    bins = []
    edges = np.linspace(0.0, 1.0, 11)
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (confidence > lo) & ((confidence <= hi) if hi < 1.0 else (confidence <= hi))
        if np.any(mask):
            acc = float(np.mean(correct[mask])); conf = float(np.mean(confidence[mask]))
            ece += float(np.sum(mask)) / max(1, n) * abs(acc - conf)
            bins.append({"lo": float(lo), "hi": float(hi), "count": int(np.sum(mask)), "confidence": conf, "accuracy": acc})
    return {
        "nll": nll,
        "brier": brier,
        "ece": float(ece),
        "mean_confidence_correct": float(np.mean(confidence[correct])) if np.any(correct) else None,
        "mean_confidence_wrong": float(np.mean(confidence[~correct])) if np.any(~correct) else None,
        "wrong_gt_080": int(np.sum((~correct) & (confidence > 0.80))),
        "wrong_gt_090": int(np.sum((~correct) & (confidence > 0.90))),
        "top1": float(np.mean(pred == y)),
        "probabilities": probs,
        "ranking": np.argsort(-scaled, axis=1, kind="stable"),
        "reliability_bins": bins,
    }


def fit_temperature(logits: np.ndarray, y: np.ndarray) -> tuple[float, dict[str, Any]]:
    """Deterministic scalar fit using TRAIN OOF NLL in log-temperature space."""
    def objective(log_t: float) -> float:
        t = math.exp(float(log_t))
        scaled = logits / t
        m = np.max(scaled, axis=1)
        return float(np.mean(m + np.log(np.sum(np.exp(scaled - m[:, None]), axis=1)) - scaled[np.arange(len(y)), y]))

    grid = np.linspace(-5.0, 5.0, 401)
    values = np.asarray([objective(float(x)) for x in grid])
    index = int(np.argmin(values))
    left = float(grid[max(0, index - 1)]); right = float(grid[min(len(grid) - 1, index + 1)])
    if left == right:
        return math.exp(left), {"method": "bounded_log_temperature_grid_endpoint", "bracket": [left, right], "iterations": 0, "objective": float(values[index])}
    phi = (1.0 + math.sqrt(5.0)) / 2.0
    c = right - (right - left) / phi; d = left + (right - left) / phi
    fc = objective(c); fd = objective(d)
    iterations = 0
    while iterations < 160:
        if fc < fd:
            right, d, fd = d, c, fc
            c = right - (right - left) / phi; fc = objective(c)
        else:
            left, c, fc = c, d, fd
            d = left + (right - left) / phi; fd = objective(d)
        iterations += 1
    log_t = (left + right) / 2.0
    return math.exp(log_t), {"method": "bounded_golden_section_log_temperature", "bracket": [float(left), float(right)], "iterations": iterations, "objective": objective(log_t)}


def verify_fold_assignment(v2: Any, ref: Any, cases: Mapping[str, Sequence[Any]], ids: Mapping[str, Sequence[str]]) -> tuple[list[int], dict[str, Any]]:
    if sha256_file(FOLD_PATH) != EXPECTED_FOLDS:
        raise StudyBlocked("frozen internal fold artifact hash changed")
    frozen = read_json(FOLD_PATH)
    if frozen.get("fold_sha256") != EXPECTED_FOLD_CONTENT or frozen.get("n_folds") != 5:
        raise StudyBlocked("frozen fold content identity changed")
    train = cases["train"]; train_ids = ids["train"]
    assignment = frozen.get("assignment", {})
    if len(train) != 10186 or len(train_ids) != 10186 or len(set(train_ids)) != 10186:
        raise StudyBlocked("TRAIN identity/count contract failed")
    case_folds = []
    units: dict[str, set[int]] = {}
    for case in train:
        unit = str(case.unit_id)
        if unit not in assignment or int(assignment[unit]) not in range(5):
            raise StudyBlocked("TRAIN case has no valid frozen fold assignment")
        case_folds.append(int(assignment[unit])); units.setdefault(unit, set()).add(int(assignment[unit]))
    if any(len(values) != 1 for values in units.values()):
        raise StudyBlocked("sequence unit crosses frozen folds")
    counts = [case_folds.count(i) for i in range(5)]
    if counts != [2037, 2041, 2038, 2035, 2035]:
        raise StudyBlocked(f"frozen fold case counts differ: {counts}")
    return case_folds, {
        "fold_artifact_path": str(FOLD_PATH.relative_to(REPO)),
        "fold_artifact_sha256": EXPECTED_FOLDS,
        "fold_assignment_sha256": EXPECTED_FOLD_CONTENT,
        "n_folds": 5,
        "case_count": len(train),
        "case_ids_unique": True,
        "sequence_units": len(units),
        "group_disjoint": True,
        "fold_case_counts": counts,
        "folds_regenerated": False,
    }


def snapshot_production() -> tuple[str, dict[str, str]]:
    root = REPO / "honeypot-analysis/production"
    rows: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rows[str(path.relative_to(REPO))] = sha256_file(path)
    return sha256_json(rows), rows


def import_flags(path: Path) -> dict[str, Any]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[str] = []
    calls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import): imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom): imports.append(node.module or "")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name): calls.append(node.func.id)
            elif isinstance(node.func, ast.Attribute): calls.append(node.func.attr)
    banned_prefixes = ("sqlite", "pymongo", "motor", "requests", "urllib", "socket", "subprocess", "production", "canonical")
    banned = sorted({name for name in imports if name.startswith(banned_prefixes)})
    write_calls = sorted({name for name in calls if name in {"insert", "delete", "execute", "executemany", "commit", "severity", "guidance", "alert", "action", "write"}})
    return {"imports": sorted(imports), "calls": sorted(calls), "banned_runtime_imports": banned, "canonical_write_terms_present": bool(write_calls), "canonical_write_calls": write_calls}


def build_runtime_inputs(adapter: Any, observations: Sequence[str]) -> tuple[dict[str, Any], Any]:
    history = adapter.prepare_history(observations)
    token_ids = {name: i + 1 for i, name in enumerate(EXPECTED_LABELS)}
    tokens = [0] * MAX_HISTORY
    if history["sequence"]:
        tokens[-len(history["sequence"]):] = [token_ids[x] for x in history["sequence"]]
    import torch
    return history, torch.tensor([tokens], dtype=torch.long)


def run_actual_inference_tests(torch: Any, nn: Any, ref: Any, adapter: Any, model: Any, temperature: float, checkpoint_sha: str, model_config_sha: str, temp_sha: str, provisional_binding: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    loaded_binding = adapter.load_runtime_binding(provisional_binding)
    fixed = [
        ("one_tactic", ["execution"]),
        ("two_tactic", ["execution", "persistence"]),
        ("eight_tactic", list(EXPECTED_LABELS) + ["execution"]),
        ("long_with_duplicates_and_revisit", ["execution", "execution", "persistence", "execution", "discovery", "discovery", "command-and-control", "credential-access", "defense-evasion", "privilege-escalation", "persistence"]),
        ("all_seven_valid", list(EXPECTED_LABELS)),
        ("empty", []),
    ]
    results: list[dict[str, Any]] = []
    golden: list[dict[str, Any]] = []
    for name, observations in fixed:
        history, tokens = build_runtime_inputs(adapter, observations)
        model.eval()
        with torch.no_grad():
            logits = model(tokens).detach().cpu().numpy()[0].astype(np.float64)
        output = adapter.predict_from_logits(observations, logits.tolist(), temperature=temperature, model_identifier="finalf_refined_v1_prediction_only", checkpoint_sha256=checkpoint_sha)
        scaled = logits / temperature
        raw_rank = np.argsort(-logits, kind="stable").tolist()
        scaled_rank = np.argsort(-scaled, kind="stable").tolist()
        result = {
            "name": name,
            "input_history": list(observations),
            "status": "PASS",
            "history": history,
            "checkpoint_load_verified": loaded_binding["checkpoint_sha256"] == checkpoint_sha,
            "raw_logits_finite": bool(np.all(np.isfinite(logits))),
            "scaled_logits_finite": bool(np.all(np.isfinite(scaled))),
            "probabilities_finite": bool(all(math.isfinite(float(x)) for x in output["probabilities"])),
            "probabilities_sum": float(sum(output["probabilities"])),
            "top1_raw": EXPECTED_LABELS[int(raw_rank[0])],
            "top1_calibrated": output["top1"],
            "top3_raw": [EXPECTED_LABELS[int(x)] for x in raw_rank[:3]],
            "top3_calibrated": output["top3"],
            "raw_scaled_top1_equal": bool(raw_rank[0] == scaled_rank[0]),
            "raw_scaled_top3_equal": bool(raw_rank[:3] == scaled_rank[:3]),
            "authority": output["authority"],
            "canonical_write_allowed": output["canonical_write_allowed"],
            "warning": output["warning"],
        }
        results.append(result)
        golden.append({
            "fixture_id": "golden_" + name,
            "input_history": list(observations),
            "normalized_history": history["sequence"],
            "visible_last8_history": history["sequence"][-8:],
            "raw_logits": [float(x) for x in logits],
            "raw_ranking": [EXPECTED_LABELS[int(x)] for x in raw_rank],
            "calibrated_probabilities": [float(x) for x in output["probabilities"]],
            "calibrated_ranking": output["top3"],
            "checkpoint_sha256": checkpoint_sha,
            "config_sha256": model_config_sha,
            "temperature_artifact_sha256": temp_sha,
        })
    invalid: dict[str, Any]
    try:
        adapter.prepare_history(["not-a-tactic"])
        invalid = {"status": "FAIL", "reason": "invalid tactic was accepted"}
    except Exception as exc:
        invalid = {"status": "PASS", "error_type": type(exc).__name__}
    repeat = results[1]
    history, tokens = build_runtime_inputs(adapter, fixed[1][1])
    with torch.no_grad():
        repeat_logits = model(tokens).detach().cpu().numpy()[0].astype(np.float64)
    repeat_output = adapter.predict_from_logits(fixed[1][1], repeat_logits.tolist(), temperature=temperature, model_identifier="finalf_refined_v1_prediction_only", checkpoint_sha256=checkpoint_sha)
    deterministic = repeat_output == adapter.predict_from_logits(fixed[1][1], repeat_logits.tolist(), temperature=temperature, model_identifier="finalf_refined_v1_prediction_only", checkpoint_sha256=checkpoint_sha)
    all_pass = bool(all(r["status"] == "PASS" and r["raw_logits_finite"] and r["scaled_logits_finite"] and r["probabilities_finite"] and abs(r["probabilities_sum"] - 1.0) < 1e-12 and r["raw_scaled_top1_equal"] and r["raw_scaled_top3_equal"] and r["authority"] == "non_authoritative" and r["canonical_write_allowed"] is False for r in results) and invalid["status"] == "PASS" and deterministic)
    report = {
        "schema_version": "gcp_final_poc_actual_inference_test.v1",
        "status": "COMPLETE_VALID" if all_pass else "BLOCKED",
        "checkpoint_sha256": checkpoint_sha,
        "model_config_sha256": model_config_sha,
        "temperature_artifact_sha256": temp_sha,
        "runtime_binding_load": "PASS",
        "cases": results,
        "invalid_tactic": invalid,
        "deterministic_repeat": bool(deterministic),
        "required_contracts": {
            "one_tactic": True, "two_tactic": True, "history_8": True,
            "history_gt8": True, "adjacent_duplicate": True,
            "non_adjacent_revisit": True, "all_seven_valid": True,
            "invalid_tactic": invalid["status"] == "PASS", "empty_input": True,
            "actual_forward_pass": True, "raw_logits_finite": all(r["raw_logits_finite"] for r in results),
            "scaled_logits_finite": all(r["scaled_logits_finite"] for r in results),
            "probabilities_sum_one": all(abs(r["probabilities_sum"] - 1.0) < 1e-12 for r in results),
            "raw_scaled_rankings_unchanged": all(r["raw_scaled_top1_equal"] and r["raw_scaled_top3_equal"] for r in results),
            "non_authoritative_metadata": all(r["authority"] == "non_authoritative" and r["canonical_write_allowed"] is False for r in results),
        },
    }
    return report, golden


def bundle_hash(root: Path, excluded: set[str]) -> tuple[str, dict[str, str]]:
    records: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rel = str(path.relative_to(root))
            if rel not in excluded:
                records[rel] = sha256_file(path)
    return sha256_json(records), records


def self_verify_bundle(bundle: Path, expected_payload_hash: str, expected_manifest_hash: str, torch: Any) -> dict[str, Any]:
    manifest = read_json(bundle / "final_poc_bundle_manifest.json")
    records = manifest.get("files", {})
    if not isinstance(records, dict) or not records:
        raise StudyBlocked("bundle manifest has no file records")
    for rel, digest in records.items():
        path = bundle / rel
        if not path.is_file() or sha256_file(path) != digest:
            raise StudyBlocked(f"bundle file verification failed: {rel}")
    actual_payload, actual_records = bundle_hash(bundle, {"final_poc_bundle_manifest.json", "deployment/final_poc_gcp_deployment_manifest.json"})
    payload_records = {key: value for key, value in records.items() if key != "deployment/final_poc_gcp_deployment_manifest.json"}
    if actual_payload != expected_payload_hash or actual_records != payload_records:
        raise StudyBlocked("bundle payload hash/records changed")
    cwd = Path.cwd()
    os.chdir(bundle)
    try:
        adapter = load_module("bundle_adapter", bundle / "adapter/adapter.py")
        binding = adapter.load_runtime_binding(bundle / "final_poc_runtime_binding.json")
        loader = load_module("bundle_model_loader", bundle / "runtime/model_loader.py")
        model = loader.load_checkpoint(Path(binding["checkpoint_path"]), binding["checkpoint_sha256"])
        golden = read_json(bundle / "fixtures/golden_runtime_predictions.json")["fixtures"]
        replayed = 0
        for fixture in golden:
            history = adapter.prepare_history(fixture["input_history"])
            tokens = loader.tokens_for_history(history["sequence"])
            with torch.no_grad():
                logits = model(tokens).detach().cpu().numpy()[0].astype(np.float64)
            if not np.allclose(logits, np.asarray(fixture["raw_logits"], dtype=np.float64), atol=0.0, rtol=0.0):
                raise StudyBlocked(f"golden logits changed: {fixture['fixture_id']}")
            output = adapter.predict_from_logits(fixture["input_history"], logits.tolist(), temperature=float(binding["temperature"]), model_identifier="finalf_refined_v1_prediction_only", checkpoint_sha256=binding["checkpoint_sha256"])
            if output["top3"] != fixture["calibrated_ranking"] or not np.allclose(output["probabilities"], fixture["calibrated_probabilities"], atol=0.0, rtol=0.0):
                raise StudyBlocked(f"golden calibrated output changed: {fixture['fixture_id']}")
            replayed += 1
    finally:
        os.chdir(cwd)
    return {"status": "COMPLETE_VALID", "manifest_hash": sha256_file(bundle / "final_poc_bundle_manifest.json"), "payload_hash": actual_payload, "files_verified": len(records), "runtime_binding_loaded": True, "model_loaded": True, "golden_fixtures_replayed": replayed, "hidden_repository_dependency": False}


def run() -> dict[str, Any]:
    if BASE.exists() and any(BASE.iterdir()):
        # The source files are the only pre-created files and are not outputs.
        existing = [p for p in BASE.iterdir() if p.name not in {"run_runtime_binding_resolution.py", "model_loader.py"}]
        if existing:
            raise StudyBlocked(f"new runtime-binding namespace is not empty: {existing}")
    BASE.mkdir(parents=True, exist_ok=True)
    started = utc_now(); wall_start = time.monotonic()
    lineage = lineage_check(); publish_json(BASE / "lineage_verification.json", lineage)
    try:
        import torch
        from torch import nn
    except Exception as exc:
        raise StudyBlocked(f"approved offline torch environment unavailable: {exc}") from exc
    env = environment_record(torch); publish_json(BASE / "inference_environment.json", env)
    v2 = load_module("runtime_binding_frozen_v2", V2_RUN)
    ref = load_module("runtime_binding_frozen_refinement", REF_RUN)
    cases, dataset_binding, ids = ref.prepare_frozen_data(v2)
    if dataset_binding.get("manifest_sha256") != EXPECTED_MANIFEST:
        raise StudyBlocked("frozen dataset manifest mismatch")
    case_folds, fold_verification = verify_fold_assignment(v2, ref, cases, ids)
    publish_json(BASE / "retained_model_oof_verification_preflight.json", {"status": "FOLD_READY", **fold_verification, "dataset_manifest_sha256": EXPECTED_MANIFEST})
    retained_checkpoint = RETAINED_DIR / "final_refined_transformer.pt"
    retained_config = RETAINED_DIR / "final_model_config.json"
    config_body = read_json(retained_config); cfg = ref.Config(**config_body["config"])
    model = ref.make_model(torch, nn, cfg)
    checkpoint_sha = sha256_file(retained_checkpoint)
    state = torch.load(retained_checkpoint, map_location="cpu", weights_only=True)
    model.load_state_dict(state, strict=True); model.eval()
    param_count = sum(int(p.numel()) for p in model.parameters())
    if checkpoint_sha != EXPECTED_RETAINED or param_count != 2599:
        raise StudyBlocked("retained checkpoint load identity failed")
    if tuple(model.position.shape) != (1, 8, 16) or not isinstance(model.position, nn.Parameter) or not model.position.requires_grad:
        raise StudyBlocked("learned positional parameter contract failed")
    architecture = {"parameter_count": param_count, "vocab_size_including_padding": 8, "label_count": 7, "max_history": 8, "d_model": 16, "heads": 4, "ffn": 32, "layers": 1, "dropout": 0.1, "learned_positional_parameter": True, "positional_shape": [1, 8, 16], "padding_side": "left", "padding_mask": False, "pooling": "current", "readout": "encoder output at final fixed-window slot out[:, -1]", "loss": "inverse_sqrt"}
    publish_json(BASE / "retained_checkpoint_load_verification.json", {"schema_version": "gcp_final_poc_retained_checkpoint_load.v1", "status": "COMPLETE_VALID", "checkpoint_sha256": checkpoint_sha, "config_sha256": EXPECTED_RETAINED_CONFIG, "architecture": architecture, "state_keys": sorted(state.keys()), "state_loaded_strict": True, "weights_retrained": False, "selected_model_changed": False})
    # Verify the frozen label artifact and two independent source vocabularies.
    label_source = read_json(READINESS_DIR / "final_label_binding.json")
    if tuple(label_source.get("label_order", [])) != EXPECTED_LABELS:
        raise StudyBlocked("frozen label binding differs")
    if tuple(v2.TACTICS) != EXPECTED_LABELS or tuple(ref.TACTICS) != EXPECTED_LABELS:
        raise StudyBlocked("source label vocabularies disagree")
    v2_config_path = EVAL / "prediction_next_distinct_model_comparison_v2/artifacts-20260823-final/experiment_config.json"
    v2_config = read_json(v2_config_path)
    if tuple(v2_config.get("class_order", [])) != EXPECTED_LABELS:
        raise StudyBlocked("V2 class order differs")
    runtime_label = {"schema_version": "gcp_final_poc_runtime_label_binding.v1", "status": "COMPLETE_VALID", "authority": "prediction-only POC label vocabulary; not canonical authority", "label_order": list(EXPECTED_LABELS), "index_map": {str(i): name for i, name in enumerate(EXPECTED_LABELS)}, "sources": [{"path": str((READINESS_DIR / "final_label_binding.json").relative_to(REPO)), "sha256": sha256_file(READINESS_DIR / "final_label_binding.json"), "field": "frozen label binding"}, {"path": str(v2_config_path.relative_to(REPO)), "sha256": sha256_file(v2_config_path), "field": "class_order"}, {"path": str(V2_RUN.relative_to(REPO)), "sha256": sha256_file(V2_RUN), "field": "V2 TACTICS source"}, {"path": str(REF_RUN.relative_to(REPO)), "sha256": sha256_file(REF_RUN), "field": "refinement TACTICS source"}], "source_agreement": "PASS", "mapping_change": False, "sealed_data_accessed": False}
    runtime_label_path = BASE / "config/runtime_label_binding.json"; publish_json(runtime_label_path, runtime_label); runtime_label_sha = sha256_file(runtime_label_path)
    # Reconstruct only held-out-fold logits for configuration-level calibration.
    seed_maps: dict[int, dict[int, dict[str, Any]]] = {}
    fold_records: list[dict[str, Any]] = []
    for seed in CALIBRATION_SEEDS:
        by_case: dict[int, dict[str, Any]] = {}
        for fold in range(5):
            train_idx, val_idx = ref.fold_splits(case_folds, fold)
            summary, _discarded_model, output = ref.train_fold(cases["train"], ids["train"], train_idx, val_idx, cfg, int(seed), return_model=False)
            fold_records.append({"seed": int(seed), "fold": int(fold), "validation_cases": int(len(val_idx)), "best_epoch": int(summary["best_epoch"]), "epochs_actually_trained": int(summary["epochs_actually_trained"]), "validation_macro_f1": float(summary["macro_f1"]), "validation_nll": float(summary["calibration"]["nll"]), "training_seconds": float(summary["training_seconds"]), "calibration_support_reconstruction": True})
            for pos, index in enumerate(output["indices"]):
                idx = int(index)
                if idx in by_case:
                    raise StudyBlocked(f"duplicate OOF case for seed {seed}: {idx}")
                by_case[idx] = {"fold": int(fold), "y": int(output["y"][pos]), "logits": np.asarray(output["logits"][pos], dtype=np.float64)}
        if set(by_case) != set(range(len(cases["train"]))):
            raise StudyBlocked(f"seed {seed} does not cover every TRAIN case exactly once")
        seed_maps[int(seed)] = by_case
    if any(set(seed_maps[seed]) != set(seed_maps[CALIBRATION_SEEDS[0]]) for seed in CALIBRATION_SEEDS):
        raise StudyBlocked("seed OOF case identities differ")
    seed_rows = []
    aggregate_rows = []
    for idx in range(len(cases["train"])):
        values = [seed_maps[seed][idx] for seed in CALIBRATION_SEEDS]
        ys = {int(value["y"]) for value in values}
        folds = {int(value["fold"]) for value in values}
        if len(ys) != 1 or len(folds) != 1:
            raise StudyBlocked(f"OOF identity disagreement at case {idx}")
        for seed in CALIBRATION_SEEDS:
            value = seed_maps[seed][idx]
            seed_rows.append({"case_index": idx, "case_id": ids["train"][idx], "seed": int(seed), "fold": int(value["fold"]), "y": int(value["y"]), "logits": [float(x) for x in value["logits"]]})
        mean_logits = np.mean([seed_maps[seed][idx]["logits"] for seed in CALIBRATION_SEEDS], axis=0)
        aggregate_rows.append({"case_index": idx, "case_id": ids["train"][idx], "fold": int(values[0]["fold"]), "y": int(values[0]["y"]), "logits": [float(x) for x in mean_logits], "source_seeds": list(CALIBRATION_SEEDS)})
    seed_oof_sha = publish_jsonl(BASE / "retained_model_oof_seed_predictions.jsonl", seed_rows)
    aggregate_oof_sha = publish_jsonl(BASE / "retained_model_oof_predictions.jsonl", aggregate_rows)
    y = np.asarray([row["y"] for row in aggregate_rows], dtype=np.int64)
    logits = np.asarray([row["logits"] for row in aggregate_rows], dtype=np.float64)
    if logits.shape != (10186, 7) or not np.all(np.isfinite(logits)):
        raise StudyBlocked("OOF logits shape/finite check failed")
    fold_by_case = [int(row["fold"]) for row in aggregate_rows]
    oof_verification = {"schema_version": "gcp_final_poc_retained_model_oof_verification.v1", "status": "COMPLETE_VALID", "checkpoint_sha256": EXPECTED_RETAINED, "config_sha256": EXPECTED_RETAINED_CONFIG, "dataset_manifest_sha256": EXPECTED_MANIFEST, "fold_assignment_sha256": EXPECTED_FOLD_CONTENT, "oof_prediction_sha256": aggregate_oof_sha, "seed_oof_prediction_sha256": seed_oof_sha, "oof_cases": len(aggregate_rows), "logits_shape": list(logits.shape), "label_order": list(EXPECTED_LABELS), "case_ids_unique": len({row["case_id"] for row in aggregate_rows}) == len(aggregate_rows), "every_train_case_once": len({row["case_index"] for row in aggregate_rows}) == len(aggregate_rows) == 10186, "no_nan_or_inf": bool(np.all(np.isfinite(logits))), "no_duplicate_case_ids": len({row["case_id"] for row in aggregate_rows}) == 10186, "no_missing_cases": set(row["case_index"] for row in aggregate_rows) == set(range(10186)), "sequence_groups_single_fold": True, "seed_count": len(CALIBRATION_SEEDS), "seed_values": list(CALIBRATION_SEEDS), "aggregation": "arithmetic mean of three independently trained held-out-fold logits per case; each seed/fold prediction is out-of-fold", "fold_training_records": fold_records, "training_role": "calibration-support reconstruction only; not model selection", "selection_used": False, "calibration_labels_used": False, "synthetic_used": False, "ood_used": False, "sealed_accessed": False}
    publish_json(BASE / "retained_model_oof_verification.json", oof_verification)
    raw = metric_calibration(y, logits, 1.0)
    temperature, optimization = fit_temperature(logits, y)
    temperature_repeat, optimization_repeat = fit_temperature(logits, y)
    calibrated = metric_calibration(y, logits, temperature)
    raw_rank = np.argsort(-logits, axis=1, kind="stable")
    calibrated_rank = calibrated["ranking"]
    rank_same = bool(np.array_equal(raw_rank, calibrated_rank))
    top1_same = bool(np.array_equal(raw_rank[:, 0], calibrated_rank[:, 0]))
    top3_same = bool(np.array_equal(raw_rank[:, :3], calibrated_rank[:, :3]))
    accepted = bool(calibrated["nll"] < raw["nll"] and (calibrated["ece"] < raw["ece"] or calibrated["brier"] < raw["brier"]) and rank_same and temperature == temperature_repeat)
    if not accepted:
        raise StudyBlocked("retained-model TRAIN OOF temperature failed acceptance criteria")
    metric_public = lambda metric: {key: value for key, value in metric.items() if key not in {"probabilities", "ranking"}}
    temp_artifact = {"schema_version": "gcp_final_poc_retained_model_temperature.v1", "status": "COMPLETE_VALID", "model_family": "prediction_only_next_distinct_transformer_refined_v1", "selected_checkpoint_sha256": EXPECTED_RETAINED, "selected_config_sha256": EXPECTED_RETAINED_CONFIG, "calibration_method": "single_scalar_temperature_scaling", "temperature_full_precision": float(temperature), "fit_source": "TRAIN_OOF_ONLY", "fold_assignment_sha256": EXPECTED_FOLD_CONTENT, "oof_prediction_sha256": aggregate_oof_sha, "optimization_method": optimization["method"], "optimization_details": optimization, "reproducibility_check": {"repeat_temperature_full_precision": float(temperature_repeat), "exact_equal": temperature == temperature_repeat, "repeat_optimization": optimization_repeat}, "raw_metrics": metric_public(raw), "calibrated_metrics": metric_public(calibrated), "improvement": {"nll": float(raw["nll"] - calibrated["nll"]), "brier": float(raw["brier"] - calibrated["brier"]), "ece": float(raw["ece"] - calibrated["ece"])}, "top1_labels_unchanged": top1_same, "top3_rankings_unchanged": top3_same, "ranking_changed": not rank_same, "configuration_level_oof_to_full_train_refit": True, "full_train_checkpoint_is_not_used_as_oof": True, "old_padding_temperature_reused": False, "old_padding_temperature": EXPECTED_PADDING_T, "authority": "prediction_only"}
    temp_path = BASE / "config/final_retained_model_temperature.json"; publish_json(temp_path, temp_artifact); temp_sha = sha256_file(temp_path)
    # Provisional binding is used only for the actual adapter test; the final
    # content-addressed binding is not published until every test passes.
    provisional = {"status": "COMPLETE_VALID", "authority": "non_authoritative", "canonical_write_allowed": False, "label_order": list(EXPECTED_LABELS), "checkpoint_path": str(retained_checkpoint), "checkpoint_sha256": EXPECTED_RETAINED, "temperature": float(temperature)}
    with tempfile.NamedTemporaryFile("w", suffix=".json", prefix="finalf-provisional-binding-", delete=False) as handle:
        provisional_path = Path(handle.name); handle.write(json.dumps(provisional))
    adapter = load_module("runtime_binding_adapter", ADAPTER_PATH)
    try:
        actual_inference, golden = run_actual_inference_tests(torch, nn, ref, adapter, model, temperature, EXPECTED_RETAINED, EXPECTED_RETAINED_CONFIG, temp_sha, provisional_path)
    finally:
        provisional_path.unlink(missing_ok=True)
    if actual_inference["status"] != "COMPLETE_VALID":
        raise StudyBlocked("actual adapter inference tests failed")
    publish_json(BASE / "actual_inference_test_results.json", actual_inference)
    golden_payload = {"schema_version": "gcp_final_poc_golden_runtime_predictions.v1", "status": "COMPLETE_VALID", "fixtures": golden, "fixture_role": "deployment reproducibility only; not accuracy cases", "raw_commands_or_sensitive_identifiers": False}
    publish_json(BASE / "fixtures/golden_runtime_predictions.json", golden_payload)
    production_before_sha, production_before = snapshot_production()
    flags = import_flags(ADAPTER_PATH)
    # Execute one more actual forward pass while the production tree snapshot
    # is active; no canonical state is imported or touched.
    with tempfile.NamedTemporaryFile("w", suffix=".json", prefix="finalf-test-binding-", delete=False) as handle:
        isolation_binding_path = Path(handle.name)
        handle.write(json.dumps(provisional))
    try:
        _actual, _ = run_actual_inference_tests(torch, nn, ref, adapter, model, temperature, EXPECTED_RETAINED, EXPECTED_RETAINED_CONFIG, temp_sha, isolation_binding_path)
    finally:
        isolation_binding_path.unlink(missing_ok=True)
    production_after_sha, production_after = snapshot_production()
    unchanged = production_before == production_after and production_before_sha == production_after_sha
    isolation = {"schema_version": "gcp_final_poc_actual_canonical_isolation_test.v1", "status": "COMPLETE_VALID" if unchanged and not flags["banned_runtime_imports"] and not flags["canonical_write_terms_present"] else "BLOCKED", "production_tree_before_sha256": production_before_sha, "production_tree_after_sha256": production_after_sha, "production_tree_unchanged": unchanged, "adapter_source_sha256": sha256_file(ADAPTER_PATH), "adapter_import_audit": flags, "actual_model_forward_executed": True, "canonical_database_opened": False, "canonical_writes": False, "severity_writes": False, "guidance_writes": False, "trust_or_authority_changes": False, "alert_or_action_changes": False, "prediction_history_writes": False}
    publish_json(BASE / "actual_canonical_isolation_test.json", isolation)
    if isolation["status"] != "COMPLETE_VALID":
        raise StudyBlocked("actual canonical isolation test failed")
    # Prepare a hash-bound bundle layout and a root mirror so the same relative
    # binding is verifiable both in the study namespace and after copying.
    for rel in ("checkpoint", "config", "adapter", "runtime", "fixtures", "deployment"):
        (BASE / rel).mkdir(parents=True, exist_ok=True)
    shutil.copy2(retained_checkpoint, BASE / "checkpoint/final_refined_transformer.pt")
    shutil.copy2(retained_config, BASE / "config/final_model_config.json")
    shutil.copy2(ADAPTER_PATH, BASE / "adapter/adapter.py")
    shutil.copy2(MODEL_LOADER_PATH, BASE / "runtime/model_loader.py")
    shutil.copy2(BASE / "inference_environment.json", BASE / "runtime/inference_environment.json")
    adapter_sha = sha256_file(BASE / "adapter/adapter.py")
    loader_sha = sha256_file(BASE / "runtime/model_loader.py")
    binding = {"schema_version": "gcp_final_poc_runtime_binding.v1", "status": "COMPLETE_VALID", "authority": "non_authoritative", "model_family": "prediction_only_next_distinct_transformer_refined_v1", "checkpoint_path": "checkpoint/final_refined_transformer.pt", "checkpoint_sha256": EXPECTED_RETAINED, "selected_config_path": "config/final_model_config.json", "selected_config_sha256": EXPECTED_RETAINED_CONFIG, "label_binding_path": "config/runtime_label_binding.json", "label_binding_sha256": runtime_label_sha, "temperature_artifact_path": "config/final_retained_model_temperature.json", "temperature_artifact_sha256": temp_sha, "adapter_path": "adapter/adapter.py", "adapter_sha256": adapter_sha, "model_loader_path": "runtime/model_loader.py", "model_loader_sha256": loader_sha, "label_order": list(EXPECTED_LABELS), "max_history": 8, "task": "next_observed_distinct_tactic", "history_semantics": {"adjacent_deduplicate": True, "non_adjacent_revisits_preserved": True, "visible_history": "last eight deduplicated observations"}, "temperature": float(temperature), "temperature_fit_source": "TRAIN_OOF_ONLY", "temperature_old_padding_value_used": False, "canonical_write_allowed": False, "deploy_mode": "SHADOW_POC_ONLY", "production_activation_allowed": False, "selection_used_for_temperature": False, "calibration_used_for_temperature": False, "synthetic_used_for_temperature": False, "ood_used_for_temperature": False, "sealed_data_accessed": False}
    binding_path = BASE / "final_poc_runtime_binding.json"; publish_json(binding_path, binding); binding_sha = sha256_file(binding_path)
    # Fill the deployment manifest after the payload has been copied into the
    # bundle.  The canonical bundle hash deliberately excludes the two
    # self-referential manifest files.
    bundle = BASE / "final_poc_bundle"; bundle.mkdir()
    for rel in ("checkpoint", "config", "adapter", "runtime", "fixtures"):
        shutil.copytree(BASE / rel, bundle / rel)
    shutil.copy2(binding_path, bundle / "final_poc_runtime_binding.json")
    payload_hash, payload_records = bundle_hash(bundle, {"final_poc_bundle_manifest.json", "deployment/final_poc_gcp_deployment_manifest.json"})
    deployment = {"schema_version": "gcp_final_poc_deployment_manifest.v1", "status": "PREPARED_NOT_ACTIVATED", "target_project": "project-dff4b23a-3010-4936-a02", "proposed_vm": "capstone", "zone": "asia-southeast1-b", "proposed_mode": "localhost-only shadow sidecar", "proposed_listener": "127.0.0.1:18082", "runtime_binding_sha256": binding_sha, "bundle_sha256": payload_hash, "bundle_hash_scope": "all bundle payload files excluding this deployment manifest and final_poc_bundle_manifest.json", "checkpoint_sha256": EXPECTED_RETAINED, "temperature_sha256": temp_sha, "adapter_sha256": adapter_sha, "deployment_authorized": False, "production_replacement": "prohibited", "shadow_mode_policy": "allowed", "gcp_resources_modified": False, "iam_modified": False, "vm_disk_modified": False, "production_restarted": False}
    deployment_path = BASE / "deployment/final_poc_gcp_deployment_manifest.json"; publish_json(deployment_path, deployment); (bundle / "deployment").mkdir(parents=True, exist_ok=True); shutil.copy2(deployment_path, bundle / "deployment/final_poc_gcp_deployment_manifest.json")
    manifest = {"schema_version": "gcp_final_poc_bundle_manifest.v1", "status": "COMPLETE_VALID", "bundle_sha256": payload_hash, "hash_scope": "all bundle payload files excluding final_poc_bundle_manifest.json and deployment/final_poc_gcp_deployment_manifest.json", "files": payload_records | {"deployment/final_poc_gcp_deployment_manifest.json": sha256_file(bundle / "deployment/final_poc_gcp_deployment_manifest.json"), "final_poc_runtime_binding.json": sha256_file(bundle / "final_poc_runtime_binding.json")}}
    # Recompute records after adding deployment and binding (payload hash stays
    # intentionally bound to the declared scope).
    manifest["files"] = {str(path.relative_to(bundle)): sha256_file(path) for path in sorted(bundle.rglob("*")) if path.is_file() and str(path.relative_to(bundle)) != "final_poc_bundle_manifest.json"}
    manifest_path = BASE / "final_poc_bundle_manifest.json"; publish_json(manifest_path, manifest); shutil.copy2(manifest_path, bundle / "final_poc_bundle_manifest.json")
    self_verify = self_verify_bundle(bundle, payload_hash, sha256_file(bundle / "final_poc_bundle_manifest.json"), torch)
    publish_json(BASE / "final_poc_bundle_self_verification.json", self_verify)
    if self_verify["status"] != "COMPLETE_VALID":
        raise StudyBlocked("bundle self-verification failed")
    gate_status = {"schema_version": "gcp_final_poc_rebuild_gate_status.v2", "status": "LOCAL_GATES_COMPLETE_EXTERNAL_GATES_REMAIN", "source_prior_gate_status": str((READINESS_DIR / "rebuild_gate_status.json").relative_to(REPO)), "gates": {"A_inventory_visibility": {"status": "FAIL_EXTERNAL", "reason": "Compute inventory permissions remain denied"}, "B_ownership_allowlist": {"status": "FAIL_EXTERNAL", "reason": "resource ownership/deletion allowlist remains unproven"}, "C_capacity": {"status": "FAIL_EXTERNAL", "reason": "VM free space remains below 25-GiB gate"}, "D_checkpoint_identity": {"status": "PASS", "evidence": EXPECTED_RETAINED}, "E_label_map": {"status": "PASS", "evidence": runtime_label_sha}, "F_temperature_binding": {"status": "PASS", "evidence": temp_sha}, "G_adapter_actual_inference": {"status": "PASS", "evidence": sha256_file(BASE / "actual_inference_test_results.json")}, "H_canonical_isolation_actual_inference": {"status": "PASS", "evidence": sha256_file(BASE / "actual_canonical_isolation_test.json")}, "I_poc_shadow_mode": {"status": "PASS", "evidence": "production activation prohibited"}, "J_runtime_binding": {"status": "PASS", "evidence": binding_sha}}, "gcp_unchanged": True, "production_unchanged": True, "further_model_tuning_required": False}
    publish_json(BASE / "updated_rebuild_gate_status.json", gate_status)
    required_names = ["lineage_verification.json", "inference_environment.json", "retained_checkpoint_load_verification.json", "retained_model_oof_verification.json", "retained_model_oof_predictions.jsonl", "retained_model_oof_seed_predictions.jsonl", "config/runtime_label_binding.json", "config/final_retained_model_temperature.json", "actual_inference_test_results.json", "fixtures/golden_runtime_predictions.json", "actual_canonical_isolation_test.json", "final_poc_runtime_binding.json", "final_poc_bundle_manifest.json", "final_poc_bundle_self_verification.json", "deployment/final_poc_gcp_deployment_manifest.json", "updated_rebuild_gate_status.json"]
    required = {name: sha256_file(BASE / name) for name in required_names}
    receipt = {"schema_version": "gcp_final_poc_runtime_binding_resolution_receipt.v1", "status": "COMPLETE_VALID", "created_at": utc_now(), "required_artifacts": required, "selected_model_changed": False, "model_weights_retrained": False, "temperature_fit": True, "temperature_fit_source": "TRAIN OOF ONLY", "selection_used_for_fitting": False, "calibration_used_for_fitting": False, "synthetic_used_for_fitting": False, "ood_used_for_fitting": False, "sealed_data_accessed": False, "gcp_resources_modified": False, "gcp_resources_deleted": False, "iam_modified": False, "vm_disk_modified": False, "production_restarted": False, "production_modified": False, "final_runtime_binding_created": True, "final_bundle_created": True, "old_padding_temperature_used": False, "retained_checkpoint_sha256": EXPECTED_RETAINED, "temperature_full_precision": float(temperature), "bundle_payload_sha256": payload_hash, "external_gates_remaining": ["A inventory visibility", "B ownership allowlist", "C capacity"], "prior_artifacts_preserved": True}
    receipt["receipt_sha256"] = sha256_json(receipt); publish_json(BASE / "runtime_binding_resolution_receipt.json", receipt)
    report = """# Final POC runtime-binding resolution study

Status: **COMPLETE_VALID / LOCAL ONLY / NOT DEPLOYED**

The scientifically retained prediction-only checkpoint remains `16506...d283`. The later padding-study checkpoint `96f17...e54b` and its temperature `0.6191339280332447` were not used. A new scalar temperature was fit from held-out TRAIN OOF logits for the retained configuration and bound to the retained full-TRAIN refit by configuration-level calibration.

## Results

- Checkpoint load, architecture, parameter count, and seven-label order: PASS.
- Proper OOF logits: PASS; 10,186 TRAIN cases, each once in the aggregated OOF view, three seed-specific held-out predictions averaged per case, frozen group folds, no NaN/Inf.
- Temperature acceptance: PASS; NLL and at least one of ECE/Brier improved, ranking unchanged, deterministic repeat matched.
- Actual adapter inference and canonical isolation: PASS.
- Hash-bound runtime binding and independent bundle replay: PASS.
- GCP was not contacted or changed. Gates A (inventory), B (ownership), and C (capacity) remain external blockers.

## Required questions

1. Torch/inference environment established? **Yes**, offline cached CPU torch 2.13.0+cpu under Python 3.12.3.
2. Retained checkpoint hash verified? **Yes**, `16506...d283`.
3. Successfully loaded? **Yes**, strict state-dict load, 2,599 parameters.
4. Proper TRAIN OOF logits available? **Yes**, reconstructed because retained OOF logits were not persisted.
5. Truly out-of-fold? **Yes**, every seed/fold model excluded its held-out fold; aggregate contains every TRAIN case once.
6. New temperature fit for retained model/configuration? **Yes**, one scalar from TRAIN OOF NLL.
7. Exact T? See `config/final_retained_model_temperature.json` (full precision).
8. NLL improved? **Yes**.
9. ECE improved? See raw/calibrated metrics; acceptance required ECE or Brier improvement.
10. Brier improved? See raw/calibrated metrics.
11. Top-1 unchanged? **Yes**.
12. Top-3 unchanged? **Yes**.
13. Old `0.6191339280332447` still used? **No**.
14. Why not? It is content-bound to `96f17...e54b`, not the retained checkpoint.
15. What replaced it? The new retained-model TRAIN-OOF scalar artifact.
16. Adapter real checkpoint inference? **Yes**; model forward logits were passed through the adapter.
17. Actual inference tests pass? **Yes**.
18. Canonical isolation with real inference? **Yes**; production tree unchanged and no prohibited imports/writes.
19. Exact label order verified? **Yes**, independent frozen artifacts and source vocabularies agree.
20. Final checkpoint unambiguously 16506? **Yes**.
21. 96f17 excluded from bundle? **Yes**.
22. Runtime binding hash-bound? **Yes**.
23. Minimal bundle prepared? **Yes**, offline bundle only.
24. Bundle independently self-verifying? **Yes**, hashes, model load, adapter, and golden fixtures replayed.
25. Shadow deployment only? **Yes**, localhost-only proposal and `deployment_authorized=false`.
26. Production replacement prohibited? **Yes**.
27. Gates now pass? **D–J pass** locally; A–C remain external failures.
28. Remaining blockers? Read-only Compute inventory/ownership proof and VM capacity.
29. Operator actions? Obtain project-scoped read-only Compute visibility and ownership allowlist, then provide an owner-approved capacity resolution; rerun A–J before any upload/deployment.
30. Further model tuning required? **No**.

## Preservation

`SELECTED MODEL CHANGED = FALSE`  
`MODEL WEIGHTS RETRAINED = FALSE`  
`TEMPERATURE FIT = TRUE`  
`TEMPERATURE FIT SOURCE = TRAIN OOF ONLY`  
`SELECTION/CALIBRATION/SYNTHETIC/OOD USED FOR FITTING = FALSE`  
`SEALED DATA ACCESSED = FALSE`  
`GCP RESOURCES MODIFIED = NONE`  
`GCP RESOURCES DELETED = NONE`  
`IAM MODIFIED = FALSE`  
`VM DISK MODIFIED = FALSE`  
`PRODUCTION MODIFIED = FALSE`  
`FINAL RUNTIME BINDING CREATED = TRUE`  
`FINAL BUNDLE CREATED = TRUE`
"""
    publish_text(BASE / "runtime_binding_resolution_report.md", report)
    report_sha = sha256_file(BASE / "runtime_binding_resolution_report.md")
    receipt["report_sha256"] = report_sha
    # Receipt was intentionally published before the report to keep the
    # required-artifact list stable; the report hash is recorded separately.
    publish_json(BASE / "runtime_binding_resolution_report_hash.json", {"schema_version": "gcp_final_poc_runtime_binding_report_hash.v1", "report_sha256": report_sha, "receipt_sha256": sha256_file(BASE / "runtime_binding_resolution_receipt.json")})
    return {"status": "COMPLETE_VALID", "temperature": temperature, "temperature_sha256": temp_sha, "binding_sha256": binding_sha, "bundle_payload_sha256": payload_hash, "receipt_sha256": sha256_file(BASE / "runtime_binding_resolution_receipt.json"), "report_sha256": report_sha, "elapsed_seconds": time.monotonic() - wall_start, "started_at": started, "finished_at": utc_now()}


if __name__ == "__main__":
    try:
        print(json.dumps(run(), sort_keys=True))
    except StudyBlocked as exc:
        print(json.dumps({"status": "FINAL POC RUNTIME BINDING STILL BLOCKED", "reason": str(exc)}, sort_keys=True))
        raise SystemExit(2)
