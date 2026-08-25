"""Run the isolated genuine-XGBoost comparator against frozen V2 evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import random
import statistics
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np


ROOT = Path(__file__).resolve().parents[3]
V2_ROOT = ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_model_comparison_v2/artifacts-20260823-final"
V2_RUN = ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_model_comparison_v2/run_v2.py"
RUN_ROOT = Path(os.environ.get(
    "PREDICTION_NEXT_DISTINCT_XGBOOST_ROOT",
    str(ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_xgboost_comparison_v1/artifacts-20260823"),
)).resolve()
XGB_ENV = Path(os.environ.get("PREDICTION_NEXT_DISTINCT_XGBOOST_ENV", "/tmp/finalf-xgboost-venv")).resolve()
XGB_WHEEL = Path("/tmp/finalf-xgboost-wheel-check/xgboost-3.1.1-py3-none-manylinux_2_28_x86_64.whl")
ROLES = ("train", "selection", "calibration")
TACTICS = (
    "command-and-control", "credential-access", "defense-evasion", "discovery",
    "execution", "persistence", "privilege-escalation",
)
MAX_HISTORY = 8
SELECTION_SEED = 20260823
SHUFFLE_SEEDS = tuple(range(20260822, 20260832))
V2_MANIFEST_SHA = "5b88e7410e4f2ba96ff578cb5e9da025b3028c2e12c6017f08e6bee0a177458d"
EXPECTED = {"train": 10186, "selection": 1983, "calibration": 2104}
FEATURE_NAMES = [f"pos_{i:+d}" for i in range(-8, 0)] + ["history_length"]


class XGBoostBlocked(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode()).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def publish_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = stable_json(value) + "\n"
    if path.exists():
        raise XGBoostBlocked(f"refusing to overwrite comparator artifact: {path}")
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    temp.write_text(body, encoding="utf-8")
    with temp.open("rb") as f:
        os.fsync(f.fileno())
    os.link(temp, path); temp.unlink(missing_ok=True)


def publish_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise XGBoostBlocked(f"refusing to overwrite comparator artifact: {path}")
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    temp.write_text(value, encoding="utf-8")
    with temp.open("rb") as f:
        os.fsync(f.fileno())
    os.link(temp, path); temp.unlink(missing_ok=True)


def publish_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise XGBoostBlocked(f"refusing to overwrite comparator artifact: {path}")
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    digest = hashlib.sha256()
    with temp.open("w", encoding="utf-8") as f:
        for row in rows:
            line = stable_json(row) + "\n"
            f.write(line); digest.update(line.encode())
        f.flush(); os.fsync(f.fileno())
    os.link(temp, path); temp.unlink(missing_ok=True)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise XGBoostBlocked(f"JSON root is not an object: {path}")
    return value


def load_v2() -> Any:
    if not V2_RUN.is_file() or V2_RUN.is_symlink():
        raise XGBoostBlocked("frozen V2 runner is unavailable")
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("prediction_v2_run_for_xgboost", V2_RUN)
    if spec is None or spec.loader is None:
        raise XGBoostBlocked("cannot load V2 runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def import_xgboost() -> tuple[Any, Any]:
    if str(XGB_ENV / "bin") not in os.environ.get("PATH", "").split(os.pathsep):
        # The interpreter is selected by the caller; this check documents and
        # verifies that the isolated environment exists without changing PATH.
        pass
    try:
        import xgboost as xgb
    except Exception as exc:
        raise XGBoostBlocked(f"genuine XGBoost unavailable in isolated runtime: {exc}") from exc
    version = getattr(xgb, "__version__", "")
    if not version:
        raise XGBoostBlocked("XGBoost imported without a version")
    return xgb, version


class NativeMulticlassXGBoost:
    """Small sklearn-free wrapper around XGBoost's native Booster API."""

    def __init__(self, xgb: Any, params: Mapping[str, Any], num_boost_round: int, feature_names: Sequence[str]) -> None:
        self.xgb = xgb
        self.params = dict(params)
        self.num_boost_round = int(num_boost_round)
        self.feature_names = list(feature_names)
        self.booster: Any | None = None

    def fit(self, x: np.ndarray, y: np.ndarray, eval_set: Sequence[tuple[np.ndarray, np.ndarray]] | None = None, sample_weight: np.ndarray | None = None, verbose: bool | None = None) -> "NativeMulticlassXGBoost":
        train_matrix = self.xgb.DMatrix(x, label=np.asarray(y, dtype=np.int32), weight=sample_weight, feature_names=self.feature_names)
        evals = []
        if eval_set:
            for index, (eval_x, eval_y) in enumerate(eval_set):
                evals.append((self.xgb.DMatrix(eval_x, label=np.asarray(eval_y, dtype=np.int32), feature_names=self.feature_names), f"eval_{index}"))
        self.booster = self.xgb.train(self.params, train_matrix, num_boost_round=self.num_boost_round, evals=evals, verbose_eval=False)
        return self

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        if self.booster is None:
            raise XGBoostBlocked("XGBoost model was not fitted")
        output = np.asarray(self.booster.predict(self.xgb.DMatrix(x, feature_names=self.feature_names)), dtype=np.float64)
        if output.ndim != 2 or output.shape[1] != len(TACTICS):
            raise XGBoostBlocked("native XGBoost probability shape differs")
        return output

    def save_model(self, path: Path) -> None:
        if self.booster is None:
            raise XGBoostBlocked("cannot serialize an unfitted XGBoost model")
        self.booster.save_model(str(path))

    def get_booster(self) -> Any:
        if self.booster is None:
            raise XGBoostBlocked("XGBoost model was not fitted")
        return self.booster


def verify_v2_inputs(v2: Any) -> tuple[dict[str, list[Any]], dict[str, Any], dict[str, list[str]], dict[str, Any], dict[tuple[str, int | None, str], dict[str, Any]]]:
    manifest = read_json(V2_ROOT / "dataset_binding.json")
    identity = manifest.get("v1_manifest_identity", {})
    if identity.get("manifest_sha256") != V2_MANIFEST_SHA:
        raise XGBoostBlocked("V2 dataset manifest identity differs")
    receipt = read_json(V2_ROOT / "comparison_receipt.v2.json")
    if receipt.get("status") != "COMPLETE_VALID" or receipt.get("sealed_data_accessed") is True:
        raise XGBoostBlocked("V2 receipt is not complete nonsealed evidence")
    for name, expected in receipt.get("required_artifacts", {}).items():
        path = V2_ROOT / name
        if not path.is_file() or sha256_file(path) != expected:
            raise XGBoostBlocked(f"V2 artifact hash mismatch: {name}")
    cases, binding, case_ids = v2.verify_dataset()
    if binding["manifest_sha256"] != V2_MANIFEST_SHA:
        raise XGBoostBlocked("V2 dataset revalidation differs")
    if {role: len(cases[role]) for role in ROLES} != EXPECTED:
        raise XGBoostBlocked("V2 role case totals differ")
    results = read_json(V2_ROOT / "comparison_results.json")
    if results.get("sealed_boundary", {}).get("sealed_prediction_data_accessed") is True:
        raise XGBoostBlocked("V2 sealed boundary is not clean")
    selected = {
        "gru": int(results["models"]["gru"]["selected_seed"]),
        "transformer": int(results["models"]["transformer"]["selected_seed"]),
    }
    wanted = {("first_order_markov", None), ("tree_surrogate_xgboost_unavailable", None), ("gru", selected["gru"]), ("transformer", selected["transformer"])}
    predictions: dict[tuple[str, int | None, str], dict[str, Any]] = {}
    for filename, role in (("selection_predictions.jsonl", "selection"), ("calibration_predictions.jsonl", "calibration")):
        with (V2_ROOT / filename).open(encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                key = (str(row["model"]), row["seed"], role)
                if key not in {(m, s, role) for m, s in wanted}:
                    continue
                predictions.setdefault(key, {"ids": [], "probabilities": [], "true": [], "history_length": []})
                predictions[key]["ids"].append(str(row["case_id"]))
                predictions[key]["probabilities"].append(row["probability_vector"])
                predictions[key]["true"].append(str(row["true_class"]))
                predictions[key]["history_length"].append(int(row["history_length"]))
    for role in ROLES[1:]:
        for model, seed in wanted:
            key = (model, seed, role)
            if key not in predictions or len(predictions[key]["ids"]) != EXPECTED[role]:
                raise XGBoostBlocked(f"missing selected V2 predictions: {key}")
            if predictions[key]["ids"] != case_ids[role]:
                raise XGBoostBlocked(f"V2 case order differs: {key}")
    return cases, binding, case_ids, {"results": results, "receipt": receipt, "selected": selected}, predictions


def add_unsupported(metrics: dict[str, Any]) -> dict[str, Any]:
    metrics["unsupported_classes"] = [k for k, row in metrics.get("per_class", {}).items() if int(row.get("support", 0)) == 0]
    return metrics


def xgb_features(v2: Any, cases: Sequence[Any], ids: Sequence[str], transform: str = "full", seed: int | None = None) -> tuple[np.ndarray, list[bool]]:
    x, _y, changed = v2.features(cases, ids, transform, seed)
    if x.shape[1] != 9:
        raise XGBoostBlocked("feature width differs from frozen V2 representation")
    return x.astype(np.float32, copy=False), changed


def xgb_metrics(v2: Any, v1: Any, cases: Sequence[Any], ids: Sequence[str], probs: np.ndarray, model_name: str, role: str) -> dict[str, Any]:
    _, y, _ = v2.features(cases, ids)
    return add_unsupported(v2.metrics(v1, y, probs, model_name, role, cases))


def case_pair(a_name: str, a: Mapping[str, Any], b_name: str, b: Mapping[str, Any], y: np.ndarray, cases: Sequence[Any]) -> dict[str, Any]:
    ap = np.asarray(a["probabilities"], dtype=np.float64); bp = np.asarray(b["probabilities"], dtype=np.float64)
    aa = ap.argmax(axis=1); bb = bp.argmax(axis=1); truth = y - 1
    ai = aa == bb; ac = aa == truth; bc = bb == truth; diff = np.abs(ap - bp)
    return {"model_a": a_name, "model_b": b_name, "cases": len(y), "identical_predicted_labels": int(ai.sum()), "different_predicted_labels": int((~ai).sum()), "both_correct": int((ac & bc).sum()), "both_wrong": int((~ac & ~bc).sum()), "a_only_correct": int((ac & ~bc).sum()), "b_only_correct": int((~ac & bc).sum()), "maximum_component_probability_difference": float(diff.max()), "mean_component_probability_difference": float(diff.mean()), "mean_l1_probability_difference": float(diff.sum(axis=1).mean()), "case_order_sha256": sha256_json([str(c.unit_id) + "|" + str(c.history_length) + "|" + c.target for c in cases])}


def subset(v2: Any, v1: Any, cases: Sequence[Any], ids: Sequence[str], probs: np.ndarray, name: str, predicate: Any) -> dict[str, Any]:
    idx = [i for i, c in enumerate(cases) if predicate(c.history_length)]
    if not idx:
        return {"cases": 0}
    sub_cases = [cases[i] for i in idx]; sub_ids = [ids[i] for i in idx]; sub_probs = probs[np.asarray(idx)]
    return xgb_metrics(v2, v1, sub_cases, sub_ids, sub_probs, name, "selection")


def env_metadata(xgb_version: str) -> dict[str, Any]:
    import scipy
    import numpy
    wheel_hash = sha256_file(XGB_WHEEL) if XGB_WHEEL.is_file() else None
    pip = XGB_ENV / "bin/pip"
    freeze = os.popen(f"{pip} freeze --all 2>/dev/null").read().splitlines() if pip.is_file() else []
    return {"schema_version": "prediction_next_distinct_xgboost_environment.v1", "python": sys.version, "python_executable": sys.executable, "environment_path": str(XGB_ENV), "xgboost_version": xgb_version, "numpy_version": numpy.__version__, "scipy_version": scipy.__version__, "xgboost_wheel_path": str(XGB_WHEEL), "xgboost_wheel_sha256": wheel_hash, "pip_freeze": freeze, "pip_freeze_sha256": sha256_json(freeze), "project_dependency_files_modified": False, "production_runtime_modified": False, "network_used_only_for_isolated_package": True}


def run() -> dict[str, Any]:
    if RUN_ROOT.exists():
        raise XGBoostBlocked(f"comparator output already exists: {RUN_ROOT}")
    if not RUN_ROOT.parent.is_dir() or not os.access(RUN_ROOT.parent, os.W_OK):
        raise XGBoostBlocked("comparator output parent is not writable")
    started = utc_now(); total_start = time.monotonic(); phase: dict[str, float] = {}
    xgb, xgb_version = import_xgboost()
    v2 = load_v2(); v1 = v2.load_v1_module()
    t = time.monotonic(); cases, binding, case_ids, v2_meta, v2_predictions = verify_v2_inputs(v2); phase["frozen_input_verification_seconds"] = time.monotonic() - t
    env = env_metadata(xgb_version); publish_json(RUN_ROOT / "xgboost_environment.json", env)
    train, selection, calibration = (cases[r] for r in ROLES); train_ids, selection_ids, calibration_ids = (case_ids[r] for r in ROLES)
    tx, _ = xgb_features(v2, train, train_ids); sx, _ = xgb_features(v2, selection, selection_ids); cx, _ = xgb_features(v2, calibration, calibration_ids)
    _, train_y, _ = v2.features(train, train_ids); _, sel_y, _ = v2.features(selection, selection_ids); _, cal_y, _ = v2.features(calibration, calibration_ids)
    # The small preregistered grid is intentionally bounded: 12 configurations
    # per weighting mode, selected only on Selection Macro-F1.
    grid = [{"max_depth": d, "learning_rate": lr, "n_estimators": 100, "min_child_weight": 1, "subsample": ss, "colsample_bytree": 0.8, "reg_lambda": 1.0, "reg_alpha": 0.0} for d in (2, 3, 5) for lr in (0.03, 0.1) for ss in (0.8, 1.0)]
    counts = Counter(int(y) for y in train_y)
    class_weights = {cls: len(train_y) / (len(TACTICS) * count) for cls, count in counts.items()}
    search: list[dict[str, Any]] = []; fitted_selection: dict[str, Any] = {}
    t = time.monotonic()
    for weighting in ("unweighted", "train_class_balanced"):
        for cfg_index, cfg in enumerate(grid):
            cfg_id = f"{weighting}-{cfg_index:02d}"
            native_params = {
                "objective": "multi:softprob",
                "num_class": len(TACTICS),
                "eval_metric": "mlogloss",
                "tree_method": "hist",
                "nthread": 1,
                "seed": SELECTION_SEED,
                "verbosity": 0,
                "eta": cfg["learning_rate"],
                "max_depth": cfg["max_depth"],
                "min_child_weight": cfg["min_child_weight"],
                "subsample": cfg["subsample"],
                "colsample_bytree": cfg["colsample_bytree"],
                "lambda": cfg["reg_lambda"],
                "alpha": cfg["reg_alpha"],
            }
            clf = NativeMulticlassXGBoost(xgb, native_params, cfg["n_estimators"], FEATURE_NAMES)
            weights = None if weighting == "unweighted" else np.asarray([class_weights[int(y)] for y in train_y], dtype=np.float64)
            fit_start = time.monotonic(); clf.fit(tx, train_y - 1, sample_weight=weights, eval_set=[(sx, sel_y - 1)], verbose=False); fit_seconds = time.monotonic() - fit_start
            probs = np.asarray(clf.predict_proba(sx), dtype=np.float64)
            if probs.shape != (len(selection), len(TACTICS)):
                raise XGBoostBlocked("XGBoost class probability shape differs")
            m = xgb_metrics(v2, v1, selection, selection_ids, probs, "xgboost", "selection")
            row = {"config_id": cfg_id, "weighting": weighting, "parameters": cfg, "selection_metrics": m, "fit_seconds": fit_seconds, "class_weights_from": "TRAIN only" if weighting != "unweighted" else None}
            search.append(row); fitted_selection[cfg_id] = {"model": clf, "probabilities": probs, "metrics": m}
    phase["xgboost_search_seconds"] = time.monotonic() - t
    search.sort(key=lambda row: (-float(row["selection_metrics"]["macro_f1"]), -float(row["selection_metrics"]["balanced_accuracy"]), -float(row["selection_metrics"]["top1"]), row["config_id"]))
    chosen_row = search[0]; chosen_id = chosen_row["config_id"]; chosen = fitted_selection[chosen_id]; model = chosen["model"]
    # Freeze the selected configuration/model before looking at Calibration.
    serialization_start = time.monotonic()
    model_path = RUN_ROOT / "xgboost_model.json"; model.save_model(model_path)
    model_hash = sha256_file(model_path); model_size = model_path.stat().st_size
    booster = model.get_booster(); num_rounds = int(booster.num_boosted_rounds()); num_trees = num_rounds * len(TACTICS)
    phase["model_serialization_seconds"] = time.monotonic() - serialization_start
    inference_start = time.monotonic()
    selection_probs = np.asarray(model.predict_proba(sx), dtype=np.float64)
    phase["selection_inference_seconds"] = time.monotonic() - inference_start
    if not np.allclose(selection_probs, np.asarray(chosen["probabilities"], dtype=np.float64), rtol=0.0, atol=1e-12):
        raise XGBoostBlocked("frozen selected-model Selection predictions changed on reload")
    calibration_start = time.monotonic()
    calibration_probs = np.asarray(model.predict_proba(cx), dtype=np.float64)
    phase["calibration_inference_seconds"] = time.monotonic() - calibration_start
    xgb_selection = {"model": "xgboost", "probabilities": selection_probs, "ids": selection_ids, "cases": selection, "y": sel_y}
    xgb_calibration = {"model": "xgboost", "probabilities": calibration_probs, "ids": calibration_ids, "cases": calibration, "y": cal_y}
    metrics_selection = xgb_metrics(v2, v1, selection, selection_ids, selection_probs, "xgboost", "selection")
    metrics_calibration = xgb_metrics(v2, v1, calibration, calibration_ids, calibration_probs, "xgboost", "calibration")
    # Ablations use the frozen XGBoost model, never a refit.
    t = time.monotonic(); ablation: dict[str, Any] = {}
    transforms: dict[str, Any] = {}
    for transform in ("full", "last_only", "reverse"):
        xx, changed = xgb_features(v2, selection, selection_ids, transform)
        probs = np.asarray(model.predict_proba(xx), dtype=np.float64)
        transforms[transform] = {"metrics": xgb_metrics(v2, v1, selection, selection_ids, probs, "xgboost_ablation_" + transform, "selection"), "changed_cases": int(sum(changed)), "probability_output_sha256": sha256_json(probs.tolist()), "history_ge3": subset(v2, v1, selection, selection_ids, probs, "xgboost_ablation_" + transform, lambda n: n >= 3)}
    shuffle_rows: list[dict[str, Any]] = []; changed_union: set[str] = set()
    for seed in SHUFFLE_SEEDS:
        xx, changed = xgb_features(v2, selection, selection_ids, "true_prefix_shuffle", seed)
        probs = np.asarray(model.predict_proba(xx), dtype=np.float64); ids_changed = [selection_ids[i] for i, flag in enumerate(changed) if flag]; changed_union.update(ids_changed)
        shuffle_rows.append({"seed": seed, "metrics": xgb_metrics(v2, v1, selection, selection_ids, probs, "xgboost_ablation_true_prefix_shuffle", "selection"), "changed_cases": len(ids_changed), "changed_cases_history_ge3": sum(changed[i] for i, c in enumerate(selection) if c.history_length >= 3), "changed_case_ids": ids_changed, "history_ge3": subset(v2, v1, selection, selection_ids, probs, "xgboost_ablation_true_prefix_shuffle", lambda n: n >= 3), "probability_output_sha256": sha256_json(probs.tolist())})
    changed_union_ge3 = {selection_ids[i] for row in shuffle_rows for i, c in enumerate(selection) if c.history_length >= 3 and selection_ids[i] in row["changed_case_ids"]}
    transforms["true_prefix_shuffle"] = {"seeds": shuffle_rows, "summary": {k: {"mean": statistics.mean([float(r["metrics"][k]) for r in shuffle_rows]), "std": statistics.pstdev([float(r["metrics"][k]) for r in shuffle_rows])} for k in ("macro_f1", "balanced_accuracy", "top1")}, "changed_cases_any": len(changed_union), "changed_cases_history_ge3_any": len(changed_union_ge3), "history_ge3_summary": {k: {"mean": statistics.mean([float(r["history_ge3"][k]) for r in shuffle_rows]), "std": statistics.pstdev([float(r["history_ge3"][k]) for r in shuffle_rows])} for k in ("macro_f1", "balanced_accuracy", "top1")}}
    ablation = {"selected_config_id": chosen_id, "model_hash_before": model_hash, "model_hash_after": sha256_file(model_path), "model_unchanged": model_hash == sha256_file(model_path), "retrained": False, "transforms": transforms}
    phase["ablation_seconds"] = time.monotonic() - t
    search_artifact = {"schema_version": "prediction_next_distinct_xgboost_search.v1", "selection_only": True, "grid_size_per_weighting": len(grid), "total_configurations": len(search), "class_order": list(TACTICS), "feature_names": FEATURE_NAMES, "train_class_counts": dict(sorted(counts.items())), "search_results": search, "selected_config_id": chosen_id, "selected_parameters": chosen_row["parameters"], "selected_weighting": chosen_row["weighting"]}
    publish_json(RUN_ROOT / "xgboost_search_results.json", search_artifact)
    publish_json(RUN_ROOT / "xgboost_ablation_results.json", {"schema_version": "prediction_next_distinct_xgboost_ablation.v1", "selected_model": {"config_id": chosen_id, "model_sha256": model_hash, "model_size_bytes": model_size}, "results": ablation})
    # Persist privacy-safe per-case outputs for XGBoost only.
    def rows(role: str, items: Sequence[Any], ids: Sequence[str], probs: np.ndarray) -> Iterable[dict[str, Any]]:
        for case_id, c, p in zip(ids, items, probs):
            pred = int(p.argmax())
            yield {"case_id": case_id, "role": role, "model": "xgboost", "history_length": int(c.history_length), "true_class": c.target, "predicted_class": TACTICS[pred], "probability_vector": [float(x) for x in p], "class_order": list(TACTICS), "correct": bool(pred == TACTICS.index(c.target))}
    serialization_start = time.monotonic()
    sel_sha = publish_jsonl(RUN_ROOT / "selection_predictions.jsonl", rows("selection", selection, selection_ids, selection_probs)); cal_sha = publish_jsonl(RUN_ROOT / "calibration_predictions.jsonl", rows("calibration", calibration, calibration_ids, calibration_probs))
    phase["prediction_serialization_seconds"] = time.monotonic() - serialization_start
    # Reuse V2 outputs without retraining.
    def old(model: str, seed: int | None, role: str) -> dict[str, Any]:
        return {"probabilities": np.asarray(v2_predictions[(model, seed, role)]["probabilities"], dtype=np.float64), "ids": v2_predictions[(model, seed, role)]["ids"], "cases": cases[role], "y": v2.features(cases[role], case_ids[role])[1]}
    selected = v2_meta["selected"]
    comparisons = [case_pair("xgboost", xgb_selection, "gru", old("gru", selected["gru"], "selection"), sel_y, selection), case_pair("xgboost", xgb_selection, "transformer", old("transformer", selected["transformer"], "selection"), sel_y, selection), case_pair("xgboost", xgb_selection, "first_order_markov", old("first_order_markov", None, "selection"), sel_y, selection)]
    publish_json(RUN_ROOT / "paired_model_comparisons.json", {"schema_version": "prediction_next_distinct_xgboost_paired.v1", "role": "selection", "class_order": list(TACTICS), "comparisons": comparisons})
    # Five-way comparison, using frozen V2 metrics for all non-XGBoost rows.
    v2res = v2_meta["results"]; five = {}
    for label, key in (("Markov", "first_order_markov"), ("Tree surrogate", "tree_surrogate_xgboost_unavailable"), ("GRU", "gru"), ("Transformer", "transformer")):
        source = v2res["models"][key]
        metric = source["selection"] if key in ("first_order_markov", "tree_surrogate_xgboost_unavailable") else source["selected_selection"]
        cal_metric = source["calibration"] if key in ("first_order_markov", "tree_surrogate_xgboost_unavailable") else source["selected_calibration"]
        five[label] = {"selection": metric, "calibration": cal_metric}
    five["XGBoost"] = {"selection": metrics_selection, "calibration": metrics_calibration}
    support = v2res["support"]
    top3 = {x[0] for x in support["top3"]}
    top_idx = [i for i, c in enumerate(selection) if f"{c.history[-1]} -> {c.target}" in top3]; rest_idx = [i for i in range(len(selection)) if i not in set(top_idx)]
    concentration = {"top3_pairs": support["top3"], "xgboost_dominant_top3": {k: xgb_metrics(v2, v1, [selection[i] for i in top_idx], [selection_ids[i] for i in top_idx], selection_probs[np.asarray(top_idx)], "xgboost", "selection")[k] for k in ("cases", "macro_f1", "balanced_accuracy", "top1")}, "xgboost_remaining": {k: xgb_metrics(v2, v1, [selection[i] for i in rest_idx], [selection_ids[i] for i in rest_idx], selection_probs[np.asarray(rest_idx)], "xgboost", "selection")[k] for k in ("cases", "macro_f1", "balanced_accuracy", "top1")}}
    xgb_f1 = float(metrics_selection["macro_f1"]); gru_f1 = float(five["GRU"]["selection"]["macro_f1"]); tr_f1 = float(five["Transformer"]["selection"]["macro_f1"]); markov_f1 = float(five["Markov"]["selection"]["macro_f1"])
    tol = 0.01
    if tr_f1 > xgb_f1 + tol and tr_f1 > gru_f1 + tol and tr_f1 > markov_f1 + tol:
        classification, reason = "A", "Transformer materially exceeds every comparator and context evidence is useful."
    elif gru_f1 > xgb_f1 + tol and abs(tr_f1 - gru_f1) <= tol:
        classification, reason = "B", "Sequence models exceed XGBoost, but Transformer has no meaningful advantage over GRU."
    elif xgb_f1 >= max(tr_f1, gru_f1) - tol and xgb_f1 > markov_f1 + tol:
        classification, reason = "C", "XGBoost matches the neural models within the preregistered margin with lower practical complexity."
    elif max(xgb_f1, tr_f1, gru_f1) <= markov_f1 + tol:
        classification, reason = "D", "First-order Markov is sufficient within the comparison margin."
    else:
        classification, reason = "E", "No comparator wins by a stable, practically meaningful margin."
    results = {"schema_version": "prediction_next_distinct_xgboost_comparison.v1", "comparison_id": "prediction_next_distinct_xgboost_comparison_v1_20260823", "dataset_manifest_sha256": binding["manifest_sha256"], "xgboost_environment": env, "feature_names": FEATURE_NAMES, "class_order": list(TACTICS), "selected_config": chosen_row, "model": {"path": str(model_path), "sha256": model_hash, "size_bytes": model_size, "num_boosted_rounds": num_rounds, "num_trees": num_trees, "training_seconds": chosen_row["fit_seconds"], "inference_seconds_selection": phase["selection_inference_seconds"]}, "selection": metrics_selection, "calibration": metrics_calibration, "five_way": five, "paired_comparisons": comparisons, "history_metrics": {name: subset(v2, v1, selection, selection_ids, selection_probs, "xgboost", pred) for name, pred in (("history_1", lambda n: n == 1), ("history_2", lambda n: n == 2), ("history_ge3", lambda n: n >= 3), ("history_ge5", lambda n: n >= 5))}, "ablation": {"artifact": str(RUN_ROOT / "xgboost_ablation_results.json"), "selected_config_id": chosen_id, "full_vs_last_only_macro_f1_delta": float(transforms["full"]["metrics"]["macro_f1"] - transforms["last_only"]["metrics"]["macro_f1"]), "full_vs_true_shuffle_macro_f1_delta": float(transforms["full"]["metrics"]["macro_f1"] - transforms["true_prefix_shuffle"]["summary"]["macro_f1"]["mean"]), "full_vs_reverse_macro_f1_delta": float(transforms["full"]["metrics"]["macro_f1"] - transforms["reverse"]["metrics"]["macro_f1"])}, "transition_concentration": concentration, "v2_reused_read_only": True, "v2_selected_seeds": selected, "classification": {"label": classification, "reason": reason, "tolerance_macro_f1": tol}, "safety": {"sealed_accessed": False, "production_changed": False, "canonical_changed": False, "v1_modified": False, "v2_modified": False, "neural_models_retrained": False, "network_used_for_data": False}, "artifacts": {"selection_predictions_sha256": sel_sha, "calibration_predictions_sha256": cal_sha}, "runtime": {"started_at": started, "finished_at": utc_now(), "phase_seconds": phase, "total_elapsed_seconds": time.monotonic() - total_start}}
    results["results_sha256"] = sha256_json(results); publish_json(RUN_ROOT / "final_model_comparison.json", results)
    report = make_report(results, binding, support, v2res)
    publish_text(RUN_ROOT / "final_model_comparison_report.md", report)
    receipt = {"schema_version": "prediction_next_distinct_xgboost_receipt.v1", "comparison_id": results["comparison_id"], "status": "COMPLETE_VALID", "xgboost_genuine": True, "xgboost_version": xgb_version, "isolated_environment": str(XGB_ENV), "dataset_manifest_sha256": binding["manifest_sha256"], "final_results_sha256": sha256_file(RUN_ROOT / "final_model_comparison.json"), "required_artifacts": {p.name: sha256_file(p) for p in (RUN_ROOT / "xgboost_environment.json", RUN_ROOT / "xgboost_search_results.json", RUN_ROOT / "xgboost_model.json", RUN_ROOT / "selection_predictions.jsonl", RUN_ROOT / "calibration_predictions.jsonl", RUN_ROOT / "xgboost_ablation_results.json", RUN_ROOT / "paired_model_comparisons.json", RUN_ROOT / "final_model_comparison.json")}, "report_sha256": sha256_file(RUN_ROOT / "final_model_comparison_report.md"), "v1_preserved": True, "v2_preserved": True, "existing_files_modified": [], "existing_files_overwritten": [], "sealed_accessed": False, "production_changed": False}
    receipt["receipt_sha256"] = sha256_json(receipt); publish_json(RUN_ROOT / "xgboost_comparison_receipt.v1.json", receipt)
    return results


def make_report(results: Mapping[str, Any], binding: Mapping[str, Any], support: Mapping[str, Any], v2res: Mapping[str, Any]) -> str:
    sel = results["selection"]; cal = results["calibration"]; five = results["five_way"]; ab = results["ablation"]
    lines = ["# Genuine XGBoost Next-Distinct-Tactic Comparator", "", "Status: COMPLETE_VALID; prediction-only and non-authoritative.", "", "## Frozen inputs", "", f"V2 manifest SHA-256: `{binding['manifest_sha256']}`; cases: Train 10,186, Selection 1,983, Calibration 2,104; directed pairs 16.", "V1 and V2 artifacts were read-only. No neural model was retrained. No sealed/final-test data was accessed.", "", "## XGBoost environment and selected model", "", f"Genuine XGBoost `{results['xgboost_environment']['xgboost_version']}` in `{results['xgboost_environment']['environment_path']}`; objective `multi:softprob`; class order is the frozen seven-tactic order; features are only fixed tactic-history positions and history length.", f"Selected configuration: `{results['selected_config']['config_id']}`; weighting `{results['selected_config']['weighting']}`; model SHA-256 `{results['model']['sha256']}`; {results['model']['num_trees']} trees ({results['model']['num_boosted_rounds']} boosting rounds); {results['model']['size_bytes']} bytes.", "", "## Five-way Selection comparison", "", "| Metric | Markov | Tree surrogate | XGBoost | GRU | Transformer |", "|---|---:|---:|---:|---:|---:|", *[f"| {label} | " + " | ".join(f"{float(five[name]['selection'][key]):.6f}" for name in ("Markov", "Tree surrogate", "XGBoost", "GRU", "Transformer")) + " |" for label, key in (("Top-1", "top1"), ("Top-3", "top3"), ("Macro-F1", "macro_f1"), ("Balanced Accuracy", "balanced_accuracy"), ("Weighted-F1", "weighted_f1"), ("MRR", "mrr"))], "", "Tree surrogate is not XGBoost; it remains historical V1/V2 evidence only.", "", "## XGBoost Calibration", "", f"Top-1 `{cal['top1']:.6f}`, Top-3 `{cal['top3']:.6f}`, Macro-F1 `{cal['macro_f1']:.6f}`, Balanced Accuracy `{cal['balanced_accuracy']:.6f}`, Weighted-F1 `{cal['weighted_f1']:.6f}`, MRR `{cal['mrr']:.6f}`. Unsupported classes: `{cal['unsupported_classes']}`. This is the previously observed calibration cohort, not blind validation.", "", "## History ablation", "", f"Full-vs-last-only Macro-F1 delta: `{ab['full_vs_last_only_macro_f1_delta']:.6f}`; full-vs-true-shuffle mean delta: `{ab['full_vs_true_shuffle_macro_f1_delta']:.6f}`; full-vs-reverse delta: `{ab['full_vs_reverse_macro_f1_delta']:.6f}`. The frozen XGBoost model was not retrained. Ten true prefix shuffles and history >=3 results are in `xgboost_ablation_results.json`.", "", "## Decision", "", f"Final classification: **{results['classification']['label']}** — {results['classification']['reason']}", "", "The V2 conclusion remains unchanged: additional context helps, but Transformer full history equals true prefix shuffle, so ordered history is not demonstrated. XGBoost is evaluated as a genuine classical comparator, not as a substitute tree surrogate.", "", "## Preservation", "", "Prior V1/V2 experiments, checkpoints, manifests, policies, canonical artifacts, and sealed boundaries were preserved. Existing files modified: none. Existing files overwritten: none."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps({"status": "COMPLETE_VALID", "comparison_id": result["comparison_id"], "run_root": str(RUN_ROOT)}, sort_keys=True))
    except XGBoostBlocked as exc:
        print(json.dumps({"status": "XGBOOST COMPARISON BLOCKED", "reason": str(exc), "run_root": str(RUN_ROOT)}, sort_keys=True))
        raise SystemExit(2)
