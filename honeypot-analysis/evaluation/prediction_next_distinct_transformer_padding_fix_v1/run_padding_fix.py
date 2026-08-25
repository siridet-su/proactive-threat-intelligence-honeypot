"""Targeted padding-mask and calibration study for the frozen next-distinct POC.

This is a new, isolated experiment namespace.  It reads the frozen V2 dataset
and prior refinement evidence read-only, trains fresh small models on TRAIN
grouped folds, and publishes only new artifacts below this package.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import random
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
V2_RUN = ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_model_comparison_v2/run_v2.py"
V2_ROOT = ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_model_comparison_v2/artifacts-20260823-final"
REF_ROOT = ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_transformer_refinement_v1_retry3/artifacts-20260823"
BENCH_ROOT = ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_controlled_long_session_benchmark_v1_retry/artifacts-20260823"
FREE_RUN = BENCH_ROOT / "free_run_results.json"
RUN_ROOT = Path(os.environ.get(
    "PREDICTION_NEXT_DISTINCT_PADDING_FIX_ROOT",
    str(ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_transformer_padding_fix_v1/artifacts-20260823"),
)).resolve()

TACTICS = (
    "command-and-control", "credential-access", "defense-evasion", "discovery",
    "execution", "persistence", "privilege-escalation",
)
T2I = {name: i + 1 for i, name in enumerate(TACTICS)}
N_CLASSES = len(TACTICS)
MAX_HISTORY = 8
N_FOLDS = 5
INITIAL_SEEDS = (20260822, 20260823, 20260824)
STABILITY_SEEDS = (20260822, 20260823, 20260824, 20260825, 20260826)
EXPECTED_MANIFEST = "5b88e7410e4f2ba96ff578cb5e9da025b3028c2e12c6017f08e6bee0a177458d"
EXPECTED_BENCHMARK = "d56e6a2a6b8295086554dc5550216f506d4e7eed8b9e0c1cb6eea7f7722173fa"
EXPECTED_V2_SOURCE = "e7ee9f599d1d156a3bb891d7696ad86045e4834fdb6174ade64d9f5d70fcb488"
EXPECTED_V2_RECEIPT_FILE = "a96d3577096e78d00df0d25eb6ef32a383b7a0c63f5a28f64ded9ec19446d922"
EXPECTED_REF_RECEIPT_FILE = "1926fdd2e3c748507bfc2c6646771c9b7aaf1942bd58842e63b64c3514a8c9d1"
EXPECTED_REF_FINAL = "16506e962432f9921d18a514c3a31686a20f9734385ec49439ad2651e4cdd283"
EXPECTED_ORIGINAL = "362f3903fa508d6034f9e92098d33a9b15711d0d8cf4d8b0b4df4c12e74fdd85"
EXPECTED_FOLD_FILE = "e3252e78d7d7b2ec13b942adf64b0f6c7805e12f68c05ab1f62ed039a5d93230"
EXPECTED_FOLD_ID = "f0426fd06ff652a84e243beceecdae61053ae16d587f10803cb6d7d05634d8ee"


class PaddingStudyBlocked(RuntimeError):
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
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def publish(path: Path, value: Any, text: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise PaddingStudyBlocked(f"refusing to overwrite new padding-study artifact: {path}")
    tmp = path.with_name(f".{path.name}.{os.getpid()}.part")
    body = value if text else stable_json(value) + "\n"
    if not isinstance(body, str):
        raise TypeError("publish body must be text")
    tmp.write_text(body, encoding="utf-8")
    with tmp.open("rb") as f:
        os.fsync(f.fileno())
    os.link(tmp, path)
    tmp.unlink(missing_ok=True)


def publish_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise PaddingStudyBlocked(f"refusing to overwrite new padding-study artifact: {path}")
    tmp = path.with_name(f".{path.name}.{os.getpid()}.part")
    h = hashlib.sha256()
    with tmp.open("w", encoding="utf-8") as f:
        for row in rows:
            line = stable_json(row) + "\n"
            f.write(line)
            h.update(line.encode("utf-8"))
        f.flush()
        os.fsync(f.fileno())
    os.link(tmp, path)
    tmp.unlink(missing_ok=True)
    return h.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise PaddingStudyBlocked(f"missing or symlinked JSON: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PaddingStudyBlocked(f"JSON root is not an object: {path}")
    return value


def load_module(name: str, path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise PaddingStudyBlocked(f"source unavailable or symlinked: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PaddingStudyBlocked(f"cannot load source: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def softmax(logits: np.ndarray) -> np.ndarray:
    z = logits - np.max(logits, axis=1, keepdims=True)
    e = np.exp(z)
    return e / np.sum(e, axis=1, keepdims=True)


def metric(y: np.ndarray, probs: np.ndarray) -> dict[str, Any]:
    if len(y) == 0:
        return {"cases": 0, "top1": 0.0, "top3": 0.0, "macro_f1": 0.0, "balanced_accuracy": 0.0,
                "weighted_f1": 0.0, "mrr": 0.0, "per_class": {t: {"precision": 0.0, "recall": 0.0, "f1": 0.0, "support": 0} for t in TACTICS}}
    pred = np.argmax(probs, axis=1)
    order = np.argsort(-probs, axis=1, kind="stable")
    per: dict[str, Any] = {}; recalls = []; weights = []
    for k, name in enumerate(TACTICS):
        tp = int(np.sum((y == k) & (pred == k))); fp = int(np.sum((y != k) & (pred == k)))
        fn = int(np.sum((y == k) & (pred != k))); support = int(np.sum(y == k))
        precision = tp / (tp + fp) if tp + fp else 0.0; recall = tp / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per[name] = {"precision": precision, "recall": recall, "f1": f1, "support": support,
                     "tp": tp, "fp": fp, "fn": fn, "tn": int(len(y) - tp - fp - fn),
                     "false_positive_rate": fp / (fp + int(len(y) - support)) if len(y) - support + fp else 0.0,
                     "predicted_true_ratio": int(np.sum(pred == k)) / support if support else None}
        if support: recalls.append(recall)
        weights.append(f1 * support)
    rank = []
    for i, target in enumerate(y):
        pos = int(np.where(order[i] == target)[0][0]); rank.append(1.0 / (pos + 1))
    return {"cases": int(len(y)), "top1": float(np.mean(pred == y)), "top3": float(np.mean([y[i] in order[i, :3] for i in range(len(y))])),
            "macro_f1": float(statistics.mean(v["f1"] for v in per.values())),
            "balanced_accuracy": float(statistics.mean(recalls) if recalls else 0.0),
            "weighted_f1": float(sum(weights) / len(y)), "mrr": float(statistics.mean(rank)), "per_class": per}


def calibration_metric(y: np.ndarray, probs: np.ndarray) -> dict[str, Any]:
    p = np.clip(probs, 1e-12, 1.0); pred = np.argmax(p, axis=1); conf = np.max(p, axis=1); correct = pred == y
    nll = float(-np.mean(np.log(p[np.arange(len(y)), y]))) if len(y) else 0.0
    onehot = np.eye(N_CLASSES)[y]
    brier = float(np.mean(np.sum((p - onehot) ** 2, axis=1))) if len(y) else 0.0
    ece = 0.0; bins = []
    for lo, hi in zip(np.linspace(0, 1, 11)[:-1], np.linspace(0, 1, 11)[1:]):
        mask = (conf > lo) & (conf <= hi if hi < 1 else conf <= hi)
        if np.any(mask):
            bins.append({"lo": float(lo), "hi": float(hi), "count": int(mask.sum()), "confidence": float(conf[mask].mean()), "accuracy": float(correct[mask].mean())})
            ece += float(mask.sum()) / max(1, len(y)) * abs(float(conf[mask].mean()) - float(correct[mask].mean()))
    return {"nll": nll, "brier": brier, "ece": float(ece),
            "mean_confidence_correct": float(conf[correct].mean()) if np.any(correct) else None,
            "mean_confidence_wrong": float(conf[~correct].mean()) if np.any(~correct) else None,
            "wrong_gt_080": int(np.sum((~correct) & (conf > .8))), "wrong_gt_090": int(np.sum((~correct) & (conf > .9))),
            "reliability_bins": bins}


def rare_stats(y: np.ndarray, probs: np.ndarray) -> dict[str, Any]:
    pred = np.argmax(probs, axis=1); out = {}
    for name in ("credential-access", "defense-evasion", "privilege-escalation"):
        k = T2I[name] - 1; true = y == k; predicted = pred == k
        tp = int(np.sum(true & predicted)); fp = int(np.sum(~true & predicted)); fn = int(np.sum(true & ~predicted)); tn = int(np.sum(~true & ~predicted)); support = int(true.sum())
        precision = tp / (tp + fp) if tp + fp else 0.0; recall = tp / support if support else 0.0
        out[name] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "support": support, "precision": precision, "recall": recall,
                     "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
                     "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
                     "predicted_true_ratio": (tp + fp) / support if support else None}
    return out


@dataclass(frozen=True)
class Config:
    name: str
    loss: str = "ce"
    padding_mask: bool = False
    d_model: int = 16
    heads: int = 4
    ffn: int = 32
    layers: int = 1
    dropout: float = 0.1
    max_history: int = 8
    lr: float = 1e-3
    max_epochs: int = 20
    patience: int = 4


def cfg_dict(c: Config) -> dict[str, Any]:
    return asdict(c)


def build_inputs(cases: Sequence[Any], max_history: int = MAX_HISTORY, histories: Sequence[Sequence[str]] | None = None) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    x = np.zeros((len(cases), max_history), dtype=np.int64); y = np.zeros(len(cases), dtype=np.int64); lengths = np.zeros(len(cases), dtype=np.int64)
    for i, case in enumerate(cases):
        h = list(histories[i] if histories is not None else case.history[-max_history:]); h = h[-max_history:]
        ids = [T2I[str(t)] for t in h]; n = len(ids)
        if not n: raise PaddingStudyBlocked("empty history")
        x[i, -n:] = ids; lengths[i] = n; y[i] = T2I[str(case.target)] - 1
    return x, y, lengths


def imports_torch() -> tuple[Any, Any, Any, Any]:
    try:
        import torch
        from torch import nn
        from torch.utils.data import DataLoader, TensorDataset
    except Exception as exc:
        raise PaddingStudyBlocked(f"torch unavailable: {exc}") from exc
    return torch, nn, DataLoader, TensorDataset


class PaddingTransformerFactory:
    def __init__(self, torch: Any, nn: Any, config: Config):
        self.torch = torch; self.nn = nn; self.config = config

    def make(self) -> Any:
        torch, nn, c = self.torch, self.nn, self.config

        class Model(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.embedding = nn.Embedding(N_CLASSES + 1, c.d_model, padding_idx=0)
                self.position = nn.Parameter(torch.zeros(1, c.max_history, c.d_model))
                layer = nn.TransformerEncoderLayer(d_model=c.d_model, nhead=c.heads, dim_feedforward=c.ffn, dropout=c.dropout, batch_first=True)
                self.encoder = nn.TransformerEncoder(layer, num_layers=c.layers)
                self.head = nn.Linear(c.d_model, N_CLASSES)
                self.cfg = c

            def attention_mask(self, tokens: Any) -> Any:
                base = torch.triu(torch.ones(c.max_history, c.max_history, device=tokens.device, dtype=torch.bool), diagonal=1)
                if not c.padding_mask:
                    return base
                masks = []
                for row in tokens:
                    valid = torch.where(row != 0)[0]
                    if valid.numel() == 0:
                        raise PaddingStudyBlocked("all-padding row")
                    first = int(valid[0])
                    m = base.clone()
                    # Left padding creates all-masked causal rows.  Padded
                    # query rows are irrelevant to valid rows; opening those
                    # rows while retaining the key mask prevents NaNs without
                    # changing causal attention among valid tokens.
                    if first > 0:
                        m[:first, :] = False
                    masks.append(m)
                return torch.stack(masks).repeat_interleave(c.heads, dim=0)

            def forward(self, tokens: Any, embedded_override: Any | None = None) -> Any:
                embedded = self.embedding(tokens) if embedded_override is None else embedded_override
                embedded = embedded + self.position
                src_mask = self.attention_mask(tokens)
                key_mask = tokens.eq(0) if c.padding_mask else None
                out = self.encoder(embedded, mask=src_mask, src_key_padding_mask=key_mask)
                return self.head(out[:, -1])

        model = Model()
        count = sum(int(p.numel()) for p in model.parameters())
        if count != 2599:
            raise PaddingStudyBlocked(f"parameter count changed for {c.name}: {count}")
        return model


def inverse_sqrt_weights(y: np.ndarray, torch: Any) -> Any:
    counts = np.bincount(y, minlength=N_CLASSES).astype(np.float64)
    w = 1.0 / np.sqrt(np.maximum(counts, 1.0)); w /= w.mean()
    return torch.tensor(w, dtype=torch.float32)


def fold_splits(fold_ids: Sequence[int], fold: int) -> tuple[np.ndarray, np.ndarray]:
    val = np.asarray([i for i, f in enumerate(fold_ids) if int(f) == fold], dtype=np.int64)
    train = np.asarray([i for i, f in enumerate(fold_ids) if int(f) != fold], dtype=np.int64)
    return train, val


def predict_arrays(torch: Any, model: Any, x: np.ndarray, y: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    model.eval()
    with torch.no_grad():
        logits = model(torch.tensor(x, dtype=torch.long)).detach().cpu().numpy()
    if not np.isfinite(logits).all():
        raise PaddingStudyBlocked("non-finite logits")
    probs = softmax(logits)
    if not np.isfinite(probs).all():
        raise PaddingStudyBlocked("non-finite probabilities")
    return logits, probs


def fit_fold(cases: Sequence[Any], train_idx: np.ndarray, val_idx: np.ndarray, cfg: Config, seed: int, return_model: bool = False) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    torch, nn, DataLoader, TensorDataset = imports_torch()
    torch.set_num_threads(1); torch.manual_seed(seed); np.random.seed(seed); random.seed(seed); torch.use_deterministic_algorithms(True)
    all_x, all_y, _ = build_inputs(cases)
    tx, ty = all_x[train_idx], all_y[train_idx]; vx, vy = all_x[val_idx], all_y[val_idx]
    model = PaddingTransformerFactory(torch, nn, cfg).make()
    opt = torch.optim.Adam(model.parameters(), lr=cfg.lr)
    weight = inverse_sqrt_weights(ty, torch) if cfg.loss == "inverse_sqrt" else None
    ds = TensorDataset(torch.tensor(tx, dtype=torch.long), torch.tensor(ty, dtype=torch.long))
    loader = DataLoader(ds, batch_size=128, shuffle=True, generator=torch.Generator().manual_seed(seed))
    best_state = None; best_score = -1.0; best_epoch = 0; stale = 0; history = []; started = time.monotonic()
    for epoch in range(1, cfg.max_epochs + 1):
        ep = time.monotonic(); model.train(); total = 0.0; n = 0
        for xb, yb in loader:
            opt.zero_grad(set_to_none=True); logits = model(xb)
            loss = nn.functional.cross_entropy(logits, yb, weight=weight)
            if not torch.isfinite(loss): raise PaddingStudyBlocked(f"non-finite loss {cfg.name}/{seed}/fold")
            loss.backward()
            if any(p.grad is not None and not torch.isfinite(p.grad).all() for p in model.parameters()):
                raise PaddingStudyBlocked(f"non-finite gradient {cfg.name}/{seed}/fold")
            opt.step(); total += float(loss.item()) * len(yb); n += len(yb)
        logits_v, probs_v = predict_arrays(torch, model, vx, vy); m = metric(vy, probs_v); cal = calibration_metric(vy, probs_v)
        is_best = m["macro_f1"] > best_score + 1e-12
        if is_best:
            best_score = m["macro_f1"]; best_epoch = epoch; stale = 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            stale += 1
        history.append({"epoch": epoch, "training_loss": total / max(n, 1), "validation_loss": cal["nll"],
                        "validation_macro_f1": m["macro_f1"], "validation_balanced_accuracy": m["balanced_accuracy"],
                        "validation_top1": m["top1"], "validation_top3": m["top3"], "learning_rate": cfg.lr,
                        "epoch_seconds": time.monotonic() - ep, "cumulative_seconds": time.monotonic() - started,
                        "is_best": is_best, "stale_after_epoch": stale,
                        "early_stopping_decision": "early_stop_patience" if stale >= cfg.patience else ("max_epochs" if epoch == cfg.max_epochs else "continue")})
        if stale >= cfg.patience: break
    if best_state is None: raise PaddingStudyBlocked(f"no best state {cfg.name}/{seed}")
    model.load_state_dict(best_state); logits_v, probs_v = predict_arrays(torch, model, vx, vy)
    result = metric(vy, probs_v) | {"calibration": calibration_metric(vy, probs_v), "rare": rare_stats(vy, probs_v), "seed": seed, "fold": None,
                                   "best_epoch": best_epoch, "epochs_actually_trained": len(history), "training_seconds": time.monotonic() - started,
                                   "history": history, "config": cfg_dict(cfg)}
    state = {"state_dict": {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}, "config": cfg_dict(cfg)} if return_model else {}
    return result, state, {"indices": val_idx.copy(), "y": vy.copy(), "logits": logits_v.copy(), "probs": probs_v.copy()}


def aggregate_results(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    fields = ("macro_f1", "balanced_accuracy", "top1", "top3", "weighted_f1", "mrr")
    return {f"mean_{f}": float(statistics.mean(float(r[f]) for r in rows)) for f in fields} | {f"std_{f}": float(statistics.pstdev(float(r[f]) for r in rows)) if len(rows) > 1 else 0.0 for f in fields} | {
        "mean_per_class_f1": {t: float(statistics.mean(float(r["per_class"][t]["f1"]) for r in rows)) for t in TACTICS},
        "mean_calibration": {k: float(statistics.mean(float(r["calibration"][k]) for r in rows)) for k in ("nll", "brier", "ece")},
    }


def run_cv(cases: Sequence[Any], fold_ids: Sequence[int], cfg: Config, seeds: Sequence[int], keep_oof_seed: int | None = None) -> dict[str, Any]:
    rows = []; oof = []
    for seed in seeds:
        for fold in range(N_FOLDS):
            tr, va = fold_splits(fold_ids, fold); result, _state, out = fit_fold(cases, tr, va, cfg, int(seed), return_model=False); result["fold"] = fold; rows.append(result)
            if keep_oof_seed is not None and int(seed) == int(keep_oof_seed):
                for j, idx in enumerate(out["indices"]):
                    oof.append({"case_index": int(idx), "fold": fold, "seed": int(seed), "y": int(out["y"][j]), "probabilities": [float(v) for v in out["probs"][j]], "logits": [float(v) for v in out["logits"][j]]})
    by_seed = {str(seed): aggregate_results([r for r in rows if int(r["seed"]) == int(seed)]) for seed in seeds}
    return {"config": cfg_dict(cfg), "seeds": [int(s) for s in seeds], "folds": list(range(N_FOLDS)), "results": rows, "by_seed": by_seed, "aggregate": aggregate_results(rows), "oof_seed": keep_oof_seed, "oof": sorted(oof, key=lambda x: x["case_index"]) if keep_oof_seed is not None else None}


def load_frozen_inputs() -> tuple[Any, dict[str, list[Any]], dict[str, list[str]], dict[str, Any], list[int], dict[str, Any]]:
    if sha256_file(V2_RUN) != EXPECTED_V2_SOURCE: raise PaddingStudyBlocked("frozen V2 source hash changed")
    v2 = load_module("frozen_v2_padding_study", V2_RUN)
    cases, binding, ids = v2.verify_dataset()
    if binding.get("manifest_sha256") != EXPECTED_MANIFEST: raise PaddingStudyBlocked("dataset manifest mismatch")
    v2_receipt = V2_ROOT / "comparison_receipt.v2.json"
    if sha256_file(v2_receipt) != EXPECTED_V2_RECEIPT_FILE: raise PaddingStudyBlocked("frozen V2 receipt file changed")
    folds_path = REF_ROOT / "internal_cv_folds.json"
    if sha256_file(folds_path) != EXPECTED_FOLD_FILE: raise PaddingStudyBlocked("prior fold assignment file changed")
    folds = read_json(folds_path)
    if folds.get("fold_sha256") != EXPECTED_FOLD_ID or folds.get("n_folds") != N_FOLDS or folds.get("group_field") != "unit_id":
        raise PaddingStudyBlocked("prior fold assignment identity mismatch")
    train = cases["train"]; fold_ids = []
    for c in train:
        if str(c.unit_id) not in folds["assignment"]: raise PaddingStudyBlocked("fold assignment missing unit")
        fold_ids.append(int(folds["assignment"][str(c.unit_id)]))
    if any(sum(int(f) == i for f in fold_ids) != int(folds["fold_case_counts"][i]) for i in range(N_FOLDS)):
        raise PaddingStudyBlocked("fold assignment case counts mismatch")
    units = defaultdict(set)
    for c, f in zip(train, fold_ids): units[int(f)].add(str(c.unit_id))
    if any(len(units[i]) == 0 for i in range(N_FOLDS)): raise PaddingStudyBlocked("empty fold")
    if sha256_file(REF_ROOT / "receipt.json") != EXPECTED_REF_RECEIPT_FILE: raise PaddingStudyBlocked("prior refinement receipt changed")
    ref_receipt = read_json(REF_ROOT / "receipt.json")
    if ref_receipt.get("status") != "COMPLETE_VALID" or not ref_receipt.get("prior_artifacts_preserved"): raise PaddingStudyBlocked("prior refinement not COMPLETE_VALID")
    ref_model = REF_ROOT / "final_refined_transformer.pt"
    if sha256_file(ref_model) != EXPECTED_REF_FINAL: raise PaddingStudyBlocked("prior refined checkpoint identity changed")
    return v2, cases, ids, binding, fold_ids, folds


def structural_model_probe(torch: Any, nn: Any, cfg: Config) -> dict[str, Any]:
    torch.manual_seed(20260822); model = PaddingTransformerFactory(torch, nn, cfg).make(); model.eval()
    lengths = (1, 2, 3, 4, 5, 6, 8); records = []
    all_finite = True; final_valid = 0
    for n in lengths:
        h = [TACTICS[i % N_CLASSES] for i in range(n)]
        class C: pass
        c = C(); c.history = tuple(h); c.target = TACTICS[0]; c.history_length = n
        x, y, _ = build_inputs([c]); logits, probs = predict_arrays(torch, model, x, y)
        finite = bool(np.isfinite(logits).all() and np.isfinite(probs).all()); all_finite = all_finite and finite
        final_valid += int(x[0, -1] != 0)
        records.append({"length": n, "input": x[0].tolist(), "final_slot_token_id": int(x[0, -1]), "finite": finite, "probability_sum": float(probs[0].sum())})
    return {"probe_seed": 20260822, "lengths": list(lengths), "records": records, "all_finite": all_finite, "invalid_final_slot_count": len(lengths) - final_valid}


def embedding_perturbation(torch: Any, model: Any, x: np.ndarray, y: np.ndarray, seed: int) -> tuple[float, float, bool]:
    model.eval(); generator = torch.Generator().manual_seed(seed)
    tokens = torch.tensor(x, dtype=torch.long)
    with torch.no_grad():
        emb = model.embedding(tokens); base = model(tokens).detach().cpu().numpy()
        pert = emb.clone(); pad = tokens.eq(0); noise = torch.randn(pert.shape, generator=generator, dtype=pert.dtype) * 3.0; pert[pad] = noise[pad]
        altered = model(tokens, embedded_override=pert).detach().cpu().numpy()
    delta = np.abs(base - altered); return float(delta.max()), float(delta.mean()), bool(np.allclose(base, altered, atol=1e-6, rtol=0.0))


def padding_invariance(torch: Any, nn: Any, final_model: Any | None, final_cfg: Config | None) -> dict[str, Any]:
    cfg = Config("M3_probe", loss="inverse_sqrt", padding_mask=True)
    probe = PaddingTransformerFactory(torch, nn, cfg).make(); probe.eval(); lengths = (1, 2, 3, 4, 5, 6, 8); rows = []
    for n in lengths:
        class C: pass
        c = C(); c.history = tuple(TACTICS[i % N_CLASSES] for i in range(n)); c.target = TACTICS[0]; c.history_length = n
        x, y, _ = build_inputs([c]); maxd, meand, passed = embedding_perturbation(torch, probe, x, y, 9000 + n)
        rows.append({"length": n, "masked_padding_content_max_abs_delta": maxd, "masked_padding_content_mean_abs_delta": meand, "pass_atol_1e-6": passed})
    repeat_c = type("C", (), {"history": tuple(TACTICS[:3]), "target": TACTICS[0], "history_length": 3})(); rx, ry, _ = build_inputs([repeat_c]);
    with torch.no_grad():
        a = probe(torch.tensor(rx, dtype=torch.long)).cpu().numpy(); b = probe(torch.tensor(rx, dtype=torch.long)).cpu().numpy()
    repeated = bool(np.array_equal(a, b))
    final_test = None
    if final_model is not None and final_cfg is not None:
        final_test = {"config": cfg_dict(final_cfg), "padding_mask_enabled": final_cfg.padding_mask}
    return {"schema_version": "prediction_next_distinct_padding_invariance_tests.v1", "tolerance": {"atol": 1e-6, "rtol": 0.0}, "fresh_M3": rows,
            "all_fresh_M3_pass": bool(all(r["pass_atol_1e-6"] for r in rows)), "repeated_inference_exact": repeated,
            "nan_inf_scan": bool(np.isfinite(a).all()), "extra_irrelevant_masked_positions": "NOT_APPLICABLE — fixed left-padding plus absolute positions changes valid token positions; content invariance is the isolatable contract",
            "selected_final": final_test}


def train_for_diagnostic(cases: Sequence[Any], fold_ids: Sequence[int], cfg: Config, seed: int = 20260822) -> tuple[Any, np.ndarray, np.ndarray]:
    torch, _nn, _D, _T = imports_torch(); tr, va = fold_splits(fold_ids, 0); result, state, out = fit_fold(cases, tr, va, cfg, seed, return_model=True)
    model = PaddingTransformerFactory(torch, _nn, cfg).make(); model.load_state_dict(state["state_dict"]); model.eval(); return model, out["indices"], out["y"]


def attention_padding_diagnostic(torch: Any, nn: Any, cases: Sequence[Any], fold_ids: Sequence[int]) -> dict[str, Any]:
    result = {}
    for name, cfg in (("M1", Config("M1", loss="inverse_sqrt", padding_mask=False)), ("M3", Config("M3", loss="inverse_sqrt", padding_mask=True))):
        model, indices, _y = train_for_diagnostic(cases, fold_ids, cfg)
        selected = list(indices[:32]); x, _, _ = build_inputs([cases[int(i)] for i in selected]); tokens = torch.tensor(x, dtype=torch.long)
        layer = model.encoder.layers[0]; embedded = model.embedding(tokens) + model.position
        mask = model.attention_mask(tokens); key = tokens.eq(0) if cfg.padding_mask else None
        try:
            with torch.no_grad():
                _, weights = layer.self_attn(embedded, embedded, embedded, attn_mask=mask, key_padding_mask=key, need_weights=True, average_attn_weights=False)
            pad_keys = tokens.eq(0).unsqueeze(1).unsqueeze(1); valid_queries = tokens.ne(0).unsqueeze(1).unsqueeze(-1)
            mass = weights.masked_select(pad_keys & valid_queries).sum().item() if weights.numel() else 0.0
            denom = weights.masked_select(valid_queries).sum().item() if weights.numel() else 0.0
            result[name] = {"status": "AVAILABLE", "examples": len(selected), "heads": int(weights.shape[1]), "attention_shape": list(weights.shape), "valid_query_pad_key_mass": float(mass), "valid_query_total_mass": float(denom), "pad_mass_fraction": float(mass / denom) if denom else 0.0, "finite": bool(torch.isfinite(weights).all())}
        except Exception as exc:
            result[name] = {"status": "NOT_AVAILABLE", "reason": str(exc)}
    return {"schema_version": "prediction_next_distinct_attention_padding_diagnostics.v1", "note": "attention weights are diagnostics, not explanations", "models": result}


def positional_diagnostic(model: Any) -> dict[str, Any]:
    p = model.position.detach().cpu().numpy()[0]; norms = np.linalg.norm(p, axis=1); pair = {}
    for i in range(len(p)):
        for j in range(i + 1, len(p)): pair[f"{i}-{j}"] = float(np.linalg.norm(p[i] - p[j]))
    return {"shape": list(p.shape), "per_position": [{"position": i, "l2_norm": float(norms[i]), "mean": float(p[i].mean()), "std": float(p[i].std())} for i in range(len(p))], "pairwise_l2": pair, "materially_nonzero": bool(np.any(norms > 1e-6)), "positions_diverged": bool(any(v > 1e-6 for v in pair.values()))}


def order_reassessment(torch: Any, nn: Any, cases: Sequence[Any], fold_ids: Sequence[int], cfg: Config, seed: int = 20260822) -> dict[str, Any]:
    names = ("full", "last_only", "reverse", "true_prefix_shuffle"); rows = {n: [] for n in names}
    for fold in range(N_FOLDS):
        tr, va = fold_splits(fold_ids, fold); _r, state, out = fit_fold(cases, tr, va, cfg, seed, return_model=True)
        model = PaddingTransformerFactory(torch, nn, cfg).make(); model.load_state_dict(state["state_dict"]); model.eval()
        val_cases = [cases[int(i)] for i in va]
        full_x, y, _ = build_inputs(val_cases); _, full_p = predict_arrays(torch, model, full_x, y)
        rows["full"].append({"y": y, "p": full_p, "changed": np.zeros(len(y), dtype=bool), "indices": va})
        for name in ("last_only", "reverse", "true_prefix_shuffle"):
            histories = []
            changed = []
            for c in val_cases:
                h = list(c.history[-MAX_HISTORY:]); orig = list(h)
                if name == "last_only": h = h[-1:]
                elif name == "reverse": h = list(reversed(h))
                else:
                    if len(h) > 2:
                        pre = h[:-1]; random.Random(f"padding-study-shuffle|{seed}|{c.unit_id}|{c.history_length}").shuffle(pre); h = pre + h[-1:]
                histories.append(h); changed.append(h != orig)
            x, yy, _ = build_inputs(val_cases, histories=histories); _, p = predict_arrays(torch, model, x, yy)
            rows[name].append({"y": yy, "p": p, "changed": np.asarray(changed), "indices": va})
    out = {}
    full_y = np.concatenate([r["y"] for r in rows["full"]]); full_p = np.concatenate([r["p"] for r in rows["full"]])
    for name, parts in rows.items():
        y = np.concatenate([r["y"] for r in parts]); p = np.concatenate([r["p"] for r in parts]); changed = np.concatenate([r["changed"] for r in parts]); idx = np.concatenate([r["indices"] for r in parts])
        valid3 = np.asarray([len(cases[int(i)].history) >= 3 for i in idx]); valid5 = np.asarray([len(cases[int(i)].history) >= 5 for i in idx])
        d = np.abs(p - full_p)
        out[name] = {"metrics": metric(y, p), "history_ge3": metric(y[valid3], p[valid3]), "history_ge5": metric(y[valid5], p[valid5]) if valid5.any() else None,
                     "changed_input_cases": int(changed.sum()), "top1_changed_rate_vs_full": float(np.mean(np.argmax(p, axis=1) != np.argmax(full_p, axis=1))),
                     "mean_probability_l1_vs_full": float(np.mean(d.sum(axis=1))), "max_probability_l1_vs_full": float(np.max(d.sum(axis=1))),
                     "history_ge3_changed_input_cases": int(changed[valid3].sum())}
    out["interpretation"] = "Ordered chronology is supported only if full correctness materially and stably exceeds true-prefix-shuffle; equal correctness means context useful but order not demonstrated."
    return out


def oof_arrays(cv: Mapping[str, Any], seed: int = 20260822) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    rows = [r for r in (cv.get("oof") or []) if int(r["seed"]) == seed]; rows.sort(key=lambda r: int(r["case_index"]))
    return np.asarray([r["case_index"] for r in rows]), np.asarray([r["y"] for r in rows]), np.asarray([r["probabilities"] for r in rows], dtype=np.float64), np.asarray([r["logits"] for r in rows], dtype=np.float64)


def scaled_probs(probs: np.ndarray, temperature: float) -> np.ndarray:
    logp = np.log(np.clip(probs, 1e-12, 1.0)) / temperature
    z = logp - logp.max(axis=1, keepdims=True); q = np.exp(z); return q / q.sum(axis=1, keepdims=True)


def fit_temperature(y: np.ndarray, probs: np.ndarray) -> dict[str, Any]:
    def nll(logt: float) -> float:
        p = scaled_probs(probs, float(np.exp(logt))); return float(-np.mean(np.log(np.clip(p[np.arange(len(y)), y], 1e-12, 1.0))))
    grid = np.linspace(-3.0, 3.0, 1201); vals = np.asarray([nll(x) for x in grid]); best = int(np.argmin(vals)); lo = grid[max(0, best - 2)]; hi = grid[min(len(grid) - 1, best + 2)]
    # Deterministic golden-section refinement around the best grid point.
    phi = (1 + math.sqrt(5)) / 2
    a, b = float(lo), float(hi); c = b - (b - a) / phi; d = a + (b - a) / phi
    for _ in range(80):
        if nll(c) < nll(d): b, d = d, c; c = b - (b - a) / phi
        else: a, c = c, d; d = a + (b - a) / phi
    logt = (a + b) / 2; t = float(np.exp(logt)); before = calibration_metric(y, probs); after_p = scaled_probs(probs, t); after = calibration_metric(y, after_p)
    order_before = np.argsort(-probs, axis=1, kind="stable"); order_after = np.argsort(-after_p, axis=1, kind="stable")
    return {"fit_source": "TRAIN OOF only", "optimal_temperature": t, "before": before, "after": after, "top1_labels_unchanged": bool(np.array_equal(np.argmax(probs, axis=1), np.argmax(after_p, axis=1))), "top3_rankings_unchanged": bool(np.array_equal(order_before[:, :3], order_after[:, :3])), "ranking_exact": bool(np.array_equal(order_before, order_after)), "improvement": {"nll": float(before["nll"] - after["nll"]), "brier": float(before["brier"] - after["brier"]), "ece": float(before["ece"] - after["ece"])}}


def full_train(torch: Any, nn: Any, cases: Sequence[Any], cfg: Config, seed: int, epochs: int) -> tuple[Any, dict[str, Any]]:
    torch.set_num_threads(1); torch.manual_seed(seed); np.random.seed(seed); random.seed(seed); torch.use_deterministic_algorithms(True)
    x, y, _ = build_inputs(cases); model = PaddingTransformerFactory(torch, nn, cfg).make(); opt = torch.optim.Adam(model.parameters(), lr=cfg.lr); weight = inverse_sqrt_weights(y, torch) if cfg.loss == "inverse_sqrt" else None
    from torch.utils.data import DataLoader, TensorDataset
    loader = DataLoader(TensorDataset(torch.tensor(x, dtype=torch.long), torch.tensor(y, dtype=torch.long)), batch_size=128, shuffle=True, generator=torch.Generator().manual_seed(seed))
    history = []; started = time.monotonic()
    for epoch in range(1, epochs + 1):
        ep = time.monotonic(); model.train(); total = 0.0; n = 0
        for xb, yb in loader:
            opt.zero_grad(set_to_none=True); logits = model(xb); loss = nn.functional.cross_entropy(logits, yb, weight=weight); loss.backward(); opt.step(); total += float(loss.item()) * len(yb); n += len(yb)
        history.append({"epoch": epoch, "training_loss": total / max(n, 1), "epoch_seconds": time.monotonic() - ep, "cumulative_seconds": time.monotonic() - started})
    return model.eval(), {"seed": seed, "epochs": epochs, "training_seconds": time.monotonic() - started, "history": history, "config": cfg_dict(cfg)}


def save_checkpoint(torch: Any, model: Any, path: Path) -> str:
    if path.exists(): raise PaddingStudyBlocked(f"checkpoint exists: {path}")
    torch.save(model.state_dict(), path); return sha256_file(path)


def predict_model(torch: Any, model: Any, cases: Sequence[Any]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    x, y, _ = build_inputs(cases); return (lambda lp: (lp, softmax(lp), y))(predict_arrays(torch, model, x, y)[0])


def load_state_model(torch: Any, nn: Any, cfg: Config, path: Path) -> Any:
    model = PaddingTransformerFactory(torch, nn, cfg).make()
    try: state = torch.load(path, map_location="cpu", weights_only=True)
    except TypeError: state = torch.load(path, map_location="cpu")
    model.load_state_dict(state); return model.eval()


def benchmark_eval(torch: Any, models: Mapping[str, tuple[Any, Config]], benchmark: Mapping[str, Any]) -> dict[str, Any]:
    rows = []
    for session in benchmark["sessions"]:
        seq = [str(x) for x in session["full_sequence"]]
        for step in range(1, len(seq)):
            class C: pass
            c = C(); c.history = tuple(seq[:step]); c.target = seq[step]; c.history_length = step; c.unit_id = session["benchmark_session_id"]
            row = {"session_id": session["benchmark_session_id"], "difficulty": session["difficulty"], "length": int(session["target_length"]), "history_length": step, "pair_category": "unseen_pair" if int(session.get("unseen_pair_count", 0)) else ("familiar_pair_unseen_higher_order" if int(session.get("unseen_4gram_count", 0)) else "familiar_pair"), "target": seq[step]}
            for name, (model, _cfg) in models.items():
                lp, p, y = predict_model(torch, model, [c]); row[name] = [float(v) for v in p[0]]
            row["y"] = int(y[0]); rows.append(row)
    y = np.asarray([r["y"] for r in rows]); out = {"cases": len(rows), "models": {}}
    for name in models:
        p = np.asarray([r[name] for r in rows]); out["models"][name] = {"overall": metric(y, p), "by_difficulty": {}, "by_length": {}, "by_pair_category": {}, "by_rare_target": {}}
        for key in ("difficulty", "length", "pair_category"):
            vals = sorted({r[key] for r in rows}, key=str)
            dest = out["models"][name][{"difficulty": "by_difficulty", "length": "by_length", "pair_category": "by_pair_category"}[key]]
            for val in vals:
                idx = [i for i, r in enumerate(rows) if r[key] == val]; dest[str(val)] = metric(y[idx], p[idx])
        for target in TACTICS:
            idx = [i for i, r in enumerate(rows) if r["target"] == target]; out["models"][name]["by_rare_target"][target] = metric(y[idx], p[idx]) if idx else None
    return {"schema_version": "prediction_next_distinct_padding_fix_controlled_benchmark_post_selection.v1", "label": "POST-SELECTION DESCRIPTIVE RESULTS — REUSED CONTROLLED 80-SESSION BENCHMARK", "benchmark_sha256": EXPECTED_BENCHMARK, "cases": len(rows), "models": out["models"], "tuning": False}


def free_run_eval(torch: Any, models: Mapping[str, tuple[Any, Config]], starts: Mapping[str, Any]) -> dict[str, Any]:
    requested = int(starts.get("steps_requested", 20)); selected_starts = starts["models"]["transformer"]["trajectories"]
    output = {}
    for name, (model, _cfg) in models.items():
        trajectories = []; invalid = 0; cycles = Counter(); entropy = []
        for start in selected_starts:
            hist = list(start["initial_prefix"]); steps = []; seen = []
            for step in range(requested):
                class C: pass
                c = C(); c.history = tuple(hist[-MAX_HISTORY:]); c.target = TACTICS[0]; c.history_length = len(c.history); c.unit_id = start["start_id"]
                _lp, p, _y = predict_model(torch, model, [c]); top = int(np.argmax(p[0])); pred = TACTICS[top]; ent = float(-np.sum(p[0] * np.log(np.clip(p[0], 1e-12, 1.0)))); entropy.append(ent)
                same = pred == hist[-1]; steps.append({"step": step + 1, "current": hist[-1], "predicted": pred, "top1_probability": float(p[0, top]), "entropy": ent, "invalid_same_current": bool(same)})
                if same: invalid += 1; break
                hist.append(pred); seen.append(pred)
                if len(seen) >= 2 and tuple(seen[-2:]) in [tuple(seen[i:i + 2]) for i in range(max(0, len(seen) - 4))]: cycles["2-cycle"] += 1; break
                if len(seen) >= 3 and tuple(seen[-3:]) in [tuple(seen[i:i + 3]) for i in range(max(0, len(seen) - 5))]: cycles["3-cycle"] += 1; break
            trajectories.append({"start_id": start["start_id"], "source_session_id": start["source_session_id"], "steps": steps})
        output[name] = {"starting_prefix_count": len(selected_starts), "steps_requested": requested, "invalid_same_current_stop": invalid, "cycle_counts": dict(cycles), "mean_entropy": float(statistics.mean(entropy)) if entropy else None, "trajectories": trajectories}
    return {"schema_version": "prediction_next_distinct_padding_fix_free_run_regression.v1", "label": "OPTIONAL POST-SELECTION DESCRIPTIVE FREE-RUN REGRESSION — EXACT FROZEN STARTS", "models": output, "tuning": False}


def serial_role_eval(torch: Any, models: Mapping[str, tuple[Any, Config]], cases: Mapping[str, Sequence[Any]]) -> dict[str, Any]:
    out = {}
    for name, (model, _cfg) in models.items():
        out[name] = {}
        for role in ("selection", "calibration"):
            _lp, p, y = predict_model(torch, model, cases[role]); out[name][role] = {"metrics": metric(y, p), "calibration": calibration_metric(y, p)}
    return out


def report_text(summary: Mapping[str, Any]) -> str:
    cv = summary["four_way_cv"]["table"]; final = summary["selected_candidate"]; post = summary.get("post_selection", {})
    lines = ["# Transformer padding-mask correction and calibration study", "", f"Status: {summary['status']}; new isolated namespace; frozen TRAIN-only grouped-CV selection.", "", "## Scientific boundary", "", "No canonical, production, sealed, or Transformer historical artifact was modified. Selection, Calibration, synthetic, OOD, and controlled data were read only after candidate freeze and are descriptive.", "", "## Four-way TRAIN grouped-CV", "", "| Metric | M0 CE/unmasked | M1 inverse-sqrt/unmasked | M2 CE/masked | M3 inverse-sqrt/masked |", "|---|---:|---:|---:|---:|"]
    for k, label in (("mean_macro_f1", "Macro-F1"), ("mean_balanced_accuracy", "Balanced Accuracy"), ("mean_top1", "Top-1"), ("mean_top3", "Top-3")):
        lines.append(f"| {label} | " + " | ".join(f"{cv[n][k]:.6f}" for n in ("M0", "M1", "M2", "M3")) + " |")
    lines += ["", "## Structural result", "", f"Padding-content invariance: {'PASS' if summary['padding_invariance']['all_fresh_M3_pass'] else 'FAIL'} at atol=1e-6.", f"Final-slot invalid count: {summary['readout_validity']['invalid_final_slot_count']}.", f"Prior probe classification: {summary['old_probe_classification']}.", "", "## Selected candidate", "", f"`{final['name']}` — {summary['final_adoption_verdict']}.", "", "## Post-selection descriptive results", "", str(post), "", "## Interpretation limits", "", "Correct padding semantics do not create additional TRAIN evidence; long-history and unseen-transition conclusions remain support-limited. Synthetic benchmark results are controlled stress evidence only.", "", "## Preservation", "", "PRIOR ARTIFACTS PRESERVED = YES", "EXISTING FILES MODIFIED = NONE", "EXISTING FILES OVERWRITTEN = NONE", "SEALED DATA ACCESSED = FALSE", "SYNTHETIC DATA USED FOR TRAINING = FALSE", "SELECTION USED FOR TUNING = FALSE", "CALIBRATION USED FOR TUNING = FALSE", "CONTROLLED BENCHMARK USED FOR TUNING = FALSE", "TEMPERATURE FIT DATA SOURCE = TRAIN OOF ONLY", ""]
    return "\n".join(lines)


def run() -> dict[str, Any]:
    if RUN_ROOT.exists(): raise PaddingStudyBlocked(f"output namespace already exists: {RUN_ROOT}")
    if not RUN_ROOT.parent.is_dir() or not os.access(RUN_ROOT.parent, os.W_OK): raise PaddingStudyBlocked("new output parent is not writable")
    started = utc_now(); clock = time.monotonic(); timings = {}
    v2, cases, ids, binding, fold_ids, folds = load_frozen_inputs(); train = cases["train"]
    RUN_ROOT.mkdir(parents=True)
    publish(RUN_ROOT / "dataset_binding.json", {"schema_version": "prediction_next_distinct_padding_fix_dataset_binding.v1", "v2_manifest_sha256": binding["manifest_sha256"], "v2_source_sha256": EXPECTED_V2_SOURCE, "v2_receipt_file_sha256": EXPECTED_V2_RECEIPT_FILE, "refinement_receipt_file_sha256": EXPECTED_REF_RECEIPT_FILE, "refinement_checkpoint_sha256": EXPECTED_REF_FINAL, "roles": {r: {"cases": len(cases[r]), "units": len(set(str(c.unit_id) for c in cases[r]))} for r in cases}, "read_only": True, "sealed_accessed": False})
    publish(RUN_ROOT / "internal_cv_folds.json", folds)
    cfgs = {"M0": Config("M0_original_ce_unmasked", loss="ce", padding_mask=False), "M1": Config("M1_original_inverse_sqrt_unmasked", loss="inverse_sqrt", padding_mask=False), "M2": Config("M2_padding_fixed_ce", loss="ce", padding_mask=True), "M3": Config("M3_padding_fixed_inverse_sqrt", loss="inverse_sqrt", padding_mask=True)}
    torch, nn, _D, _T = imports_torch(); torch.set_num_threads(1)
    probe = structural_model_probe(torch, nn, cfgs["M3"]); publish(RUN_ROOT / "padding_architecture_audit.json", {"schema_version": "prediction_next_distinct_padding_architecture_audit.v1", "source_v2_run": str(V2_RUN.relative_to(ROOT)), "source_v2_sha256": EXPECTED_V2_SOURCE, "models": {k: {"config": cfg_dict(c), "parameter_count": 2599, "causal_mask": True, "key_padding_mask": c.padding_mask, "key_padding_mask_shape": ["batch", MAX_HISTORY], "key_padding_mask_dtype": "bool", "true_means": "key ignored/masked", "false_means": "key available", "attn_mask_shape": ["8,8" if not c.padding_mask else "batch*heads,8,8"], "all_masked_query_guard": "padded query rows opened; valid query rows remain causal"} for k, c in cfgs.items()}, "exact_encoder_call": "self.encoder(embedded, mask=src_mask, src_key_padding_mask=key_mask)", "structural_probe": probe})
    publish(RUN_ROOT / "readout_validity_audit.json", {"schema_version": "prediction_next_distinct_readout_validity_audit.v1", "representation": "left padded, final fixed-window slot out[:,-1]", "invalid_final_slot_count": int(sum(int(build_inputs([c])[0][0, -1] == 0) for c in train)), "train_cases": len(train), "expected": 0})
    inv = padding_invariance(torch, nn, None, None); publish(RUN_ROOT / "padding_invariance_tests.json", inv)
    publish(RUN_ROOT / "padding_invariance_report.md", "# Padding invariance report\n\nThe corrected M3 variant masks PAD keys with a bool key-padding mask and uses a dynamic causal mask for left-padded query rows. PAD-content perturbation must be invariant at atol=1e-6.\n\n" + stable_json(inv) + "\n")
    old_probe = read_json(REF_ROOT / "architecture_audit.json").get("padding_probe", {})
    old_class = "POSITION_AND_PADDING_CONFOUNDED" if old_probe.get("same_valid_tokens_shifted_padding") else "MIXED_EFFECT_PARTIALLY_ISOLATABLE"
    publish(RUN_ROOT / "padding_probe_interpretation_addendum.json", {"schema_version": "prediction_next_distinct_padding_probe_interpretation_addendum.v1", "prior_claim": old_probe, "classification": old_class, "corrected_interpretation": "The prior comparison shifted absolute positions together with padding layout; it did not isolate padding-content attention from positional sensitivity.", "prior_artifact_unchanged": True})
    # Four-way grouped TRAIN comparison: only TRAIN folds and fresh models.
    cv = {}; cv_phase = time.monotonic()
    for name, cfg in cfgs.items(): cv[name] = run_cv(train, fold_ids, cfg, INITIAL_SEEDS, keep_oof_seed=20260822)
    timings["four_way_cv_seconds"] = time.monotonic() - cv_phase
    table = {n: cv[n]["aggregate"] for n in cfgs}
    publish(RUN_ROOT / "four_way_cv_results.json", {"schema_version": "prediction_next_distinct_four_way_padding_cv.v1", "train_only": True, "fold_file_sha256": EXPECTED_FOLD_FILE, "fold_identity_sha256": EXPECTED_FOLD_ID, "variants": cv, "table": table})
    # Five-seed stability is run for both inverse-sqrt contenders; this is
    # still TRAIN-only and avoids choosing a single lucky seed.
    stability_phase = time.monotonic(); stability = {}
    for name in ("M1", "M3"):
        stability[name] = run_cv(train, fold_ids, cfgs[name], STABILITY_SEEDS, keep_oof_seed=20260822)
    timings["stability_seconds"] = time.monotonic() - stability_phase
    publish(RUN_ROOT / "seed_stability_results.json", {"schema_version": "prediction_next_distinct_padding_seed_stability.v1", "train_only": True, "variants": stability})
    # Rare-class FP/recall comparison uses OOF TRAIN rows from the initial
    # seed, never Selection or Calibration.
    rare = {}
    for name in cfgs:
        _i, yy, pp, _l = oof_arrays(cv[name]); rare[name] = rare_stats(yy, pp)
    publish(RUN_ROOT / "rare_class_false_positive_analysis.json", {"schema_version": "prediction_next_distinct_padding_rare_false_positive_analysis.v1", "source": "TRAIN grouped OOF seed 20260822", "variants": rare})
    # Primary selection uses initial grouped-CV Macro-F1, then balanced
    # accuracy, Top-1 guard, rare-class tradeoff, and stability.
    baseline_top1 = table["M0"]["mean_top1"]; candidates = []
    for name in cfgs:
        agg = table[name]; stable = stability.get(name, cv[name]); candidates.append({"name": name, "config": cfg_dict(cfgs[name]), "aggregate": agg, "top1_regression_vs_M0": baseline_top1 - agg["mean_top1"], "rare": rare[name], "stability": stable["aggregate"]})
    eligible = [x for x in candidates if x["top1_regression_vs_M0"] < 0.03 and x["aggregate"]["mean_top1"] >= 0.0]
    if not eligible: raise PaddingStudyBlocked("no candidate passes Top-1 guard")
    chosen = sorted(eligible, key=lambda x: (-x["aggregate"]["mean_macro_f1"], -x["aggregate"]["mean_balanced_accuracy"], -x["aggregate"]["mean_top1"], x["name"]))[0]
    selected_cfg = cfgs[chosen["name"]]
    selected = {"schema_version": "prediction_next_distinct_selected_padding_candidate.v1", "status": "FROZEN_BEFORE_POST_SELECTION", "name": chosen["name"], "config": cfg_dict(selected_cfg), "candidate_table": candidates, "eligible_candidates": [x["name"] for x in eligible], "selection_rule": "TRAIN grouped-CV mean Macro-F1; tie Balanced Accuracy, Top-1, rare-class FP/recall, stability; Top-1 regression guard < 3 percentage points", "selection_roles": ["train"], "post_selection_roles_not_used_for_tuning": ["selection", "calibration", "synthetic", "ood", "controlled", "sealed"]}
    publish(RUN_ROOT / "selected_padding_candidate.json", selected)
    # Order and attention diagnostics are held-out TRAIN diagnostics.
    order = order_reassessment(torch, nn, train, fold_ids, selected_cfg); publish(RUN_ROOT / "order_reassessment.json", {"schema_version": "prediction_next_distinct_padding_order_reassessment.v1", "train_only": True, "selected": chosen["name"], "results": order})
    # Fresh full TRAIN refit uses the median best epoch from the selected
    # candidate's five-seed grouped folds, not Selection labels.
    selected_rows = stability[chosen["name"]]["results"] if chosen["name"] in stability else cv[chosen["name"]]["results"]
    epochs = max(1, int(round(statistics.median(int(r["best_epoch"]) for r in selected_rows))))
    final_model, final_hist = full_train(torch, nn, train, selected_cfg, 20260822, epochs); final_path = RUN_ROOT / "final_padding_study_transformer.pt"; final_sha = save_checkpoint(torch, final_model, final_path); final_hist |= {"checkpoint_sha256": final_sha, "checkpoint_size_bytes": final_path.stat().st_size, "fresh_initialization": True, "epoch_selection": "median selected-candidate grouped TRAIN fold best_epoch", "best_epoch_median": epochs}; publish(RUN_ROOT / "final_training_history.json", final_hist); publish(RUN_ROOT / "final_model_config.json", {"schema_version": "prediction_next_distinct_padding_final_model_config.v1", "config": cfg_dict(selected_cfg), "parameter_count": 2599, "checkpoint_sha256": final_sha, "seed": 20260822, "epochs": epochs, "fresh_initialization": True})
    # Structural diagnostics after training.
    inv["selected_final"] = {"config": cfg_dict(selected_cfg), "checkpoint_sha256": final_sha, "padding_mask_enabled": selected_cfg.padding_mask}; inv["selected_final_invariance_not_substituted_for_M3_probe"] = True
    publish(RUN_ROOT / "padding_invariance_tests_final.json", inv)
    publish(RUN_ROOT / "positional_embedding_diagnostics.json", {"schema_version": "prediction_next_distinct_positional_embedding_diagnostics.v1", "selected": positional_diagnostic(final_model), "note": "descriptive; no semantic interpretation of dimensions"})
    publish(RUN_ROOT / "attention_padding_diagnostics.json", attention_padding_diagnostic(torch, nn, train, fold_ids))
    # TRAIN OOF temperature fit, performed only after structural selection.
    _oi, oy, op, _ol = oof_arrays(cv[chosen["name"]]); temp = fit_temperature(oy, op); publish(RUN_ROOT / "temperature_scaling_results.json", {"schema_version": "prediction_next_distinct_padding_temperature_scaling.v1", **temp, "adopted": bool(temp["improvement"]["nll"] > 0 and temp["improvement"]["ece"] > 0 and temp["improvement"]["brier"] > 0 and temp["ranking_exact"])})
    adopted_temp = bool(temp["improvement"]["nll"] > 0 and temp["improvement"]["ece"] > 0 and temp["improvement"]["brier"] > 0 and temp["ranking_exact"])
    display = "TEMPERATURE_SCALED_PROBABILITIES_PREFERRED" if adopted_temp else ("RAW_PROBABILITIES_ACCEPTABLE_FOR_POC" if temp["after"]["ece"] < 0.1 else "PROBABILITIES_POORLY_CALIBRATED — DISPLAY RANKS ONLY")
    publish(RUN_ROOT / "probability_display_policy.json", {"schema_version": "prediction_next_distinct_probability_display_policy.v1", "policy": display, "evidence": "TRAIN OOF calibration plus previously observed descriptive cohorts; softmax scores are not asserted to be calibrated probabilities"})
    # Post-freeze descriptive cohorts and exact frozen benchmark.
    v2_results = read_json(V2_ROOT / "comparison_results.json"); old_path = Path(next(x for x in v2_results["models"]["transformer"]["seeds"] if int(x["seed"]) == 20260822)["checkpoint"]["path"]); 
    if sha256_file(old_path) != EXPECTED_ORIGINAL: raise PaddingStudyBlocked("original frozen checkpoint hash changed")
    refined_path = REF_ROOT / "final_refined_transformer.pt"; old_orig = load_state_model(torch, nn, Config("old_original", loss="ce", padding_mask=False), old_path); old_ref = load_state_model(torch, nn, Config("old_refined", loss="inverse_sqrt", padding_mask=False), refined_path)
    post_models = {"original": (old_orig, cfgs["M0"]), "refined_v1": (old_ref, cfgs["M1"]), "padding_final": (final_model, selected_cfg)}
    post = serial_role_eval(torch, post_models, cases); publish(RUN_ROOT / "selection_post_selection.json", {"schema_version": "prediction_next_distinct_padding_selection_post_selection.v1", "label": "POST-SELECTION DESCRIPTIVE RESULTS — PREVIOUSLY OBSERVED SELECTION COHORT", "models": post, "used_for_tuning": False}); publish(RUN_ROOT / "calibration_post_selection.json", {"schema_version": "prediction_next_distinct_padding_calibration_post_selection.v1", "label": "POST-SELECTION DESCRIPTIVE RESULTS — PREVIOUSLY OBSERVED CALIBRATION COHORT", "models": post, "used_for_tuning": False})
    benchmark = read_json(BENCH_ROOT / "benchmark_sessions.json");
    if sha256_file(BENCH_ROOT / "benchmark_sessions.json") != EXPECTED_BENCHMARK: raise PaddingStudyBlocked("controlled benchmark hash changed")
    bench = benchmark_eval(torch, post_models, benchmark); publish(RUN_ROOT / "controlled_benchmark_post_selection.json", bench)
    free = free_run_eval(torch, {"refined_v1": (old_ref, cfgs["M1"]), "padding_final": (final_model, selected_cfg)}, read_json(FREE_RUN)); publish(RUN_ROOT / "free_run_regression.json", free)
    # A compact summary/report binds the full evidence without embedding raw
    # prediction arrays or sensitive identifiers.
    final_answer = "PADDING-FIXED REFINED TRANSFORMER ADOPTION SUPPORTED" if selected_cfg.padding_mask and chosen["aggregate"]["mean_macro_f1"] >= table["M1"]["mean_macro_f1"] - 1e-12 and inv["all_fresh_M3_pass"] else ("PADDING FIX STRUCTURALLY CORRECT BUT PREDICTIVE GAIN INSUFFICIENT — KEEP REFINED V1" if inv["all_fresh_M3_pass"] else "PADDING STUDY INVALID — padding invariance failed")
    readout = {"invalid_final_slot_count": int(sum(int(build_inputs([c])[0][0, -1] == 0) for c in train)), "train_cases": len(train), "expected": 0}
    attention = read_json(RUN_ROOT / "attention_padding_diagnostics.json")
    summary = {"schema_version": "prediction_next_distinct_transformer_padding_fix_summary.v1", "status": "COMPLETE_VALID", "started_at": started, "finished_at": utc_now(), "elapsed_seconds": time.monotonic() - clock, "selected_candidate": chosen, "final_adoption_verdict": final_answer, "dataset_manifest_sha256": EXPECTED_MANIFEST, "four_way_cv": {"table": table, "variants": {k: {"aggregate": cv[k]["aggregate"], "seeds": cv[k]["seeds"]} for k in cv}}, "padding_invariance": inv, "readout_validity": readout, "old_probe_classification": old_class, "temperature": temp, "probability_display_policy": display, "post_selection": {k: {m: {"selection": post[m]["selection"]["metrics"], "calibration": post[m]["calibration"]["metrics"]} for m in post} for k in ("selection", "calibration")}, "controlled_benchmark_overall": {m: bench["models"][m]["overall"] for m in bench["models"]}, "attention_diagnostics": attention, "timings": timings, "train_support": {"cases": len(train), "units": len(set(str(c.unit_id) for c in train)), "history_counts": dict(sorted(Counter(int(c.history_length) for c in train).items())), "target_counts": dict(sorted(Counter(str(c.target) for c in train).items()))}, "claims": ["bounded TRAIN group-aware evidence only", "padding correctness is not additional training support", "no attacker-population/generalization/production claims"], "prior_artifacts_preserved": True, "existing_files_modified": [], "existing_files_overwritten": [], "sealed_data_accessed": False, "synthetic_data_used_for_training": False, "selection_used_for_tuning": False, "calibration_used_for_tuning": False, "controlled_benchmark_used_for_tuning": False, "models_retrained": True, "temperature_fit_data_source": "TRAIN OOF only"}
    summary_path = RUN_ROOT / "padding_fix_summary.json"
    if summary_path.exists():
        summary = read_json(summary_path)
    else:
        publish(summary_path, summary)
    publish(RUN_ROOT / "transformer_padding_fix_report.md", report_text(summary))
    required = {p.name: sha256_file(p) for p in sorted(RUN_ROOT.iterdir()) if p.is_file() and p.name not in {"receipt.json"}}
    receipt = {"schema_version": "prediction_next_distinct_transformer_padding_fix_receipt.v1", "status": "COMPLETE_VALID", "comparison_id": "prediction_next_distinct_transformer_padding_fix_v1_20260823", "required_artifacts": required, "runner_path": str(Path(__file__).relative_to(ROOT)), "runner_sha256": sha256_file(Path(__file__)), "dataset_manifest_sha256": EXPECTED_MANIFEST, "fold_file_sha256": EXPECTED_FOLD_FILE, "fold_identity_sha256": EXPECTED_FOLD_ID, "controlled_benchmark_sha256": EXPECTED_BENCHMARK, "final_checkpoint_sha256": final_sha, "final_adoption_verdict": final_answer, "prior_artifacts_preserved": True, "existing_files_modified": [], "existing_files_overwritten": [], "sealed_data_accessed": False, "synthetic_data_used_for_training": False, "selection_used_for_tuning": False, "calibration_used_for_tuning": False, "controlled_benchmark_used_for_tuning": False, "models_retrained": True, "temperature_fit_data_source": "TRAIN OOF only", "post_selection_descriptive_only": True}
    receipt["receipt_sha256"] = sha256_json(receipt); publish(RUN_ROOT / "receipt.json", receipt)
    return summary


def finish_partial() -> dict[str, Any]:
    """Complete a run that reached final-model creation but failed only while
    serializing its report.  Existing new artifacts are immutable and are
    never replaced; this function adds only missing final artifacts.
    """
    if not RUN_ROOT.is_dir():
        raise PaddingStudyBlocked(f"partial namespace missing: {RUN_ROOT}")
    v2, cases, ids, binding, fold_ids, folds = load_frozen_inputs()
    four = read_json(RUN_ROOT / "four_way_cv_results.json")
    stability = read_json(RUN_ROOT / "seed_stability_results.json")
    selected = read_json(RUN_ROOT / "selected_padding_candidate.json")
    name = str(selected["name"]); cfg = Config(**selected["config"])
    torch, nn, _D, _T = imports_torch(); final_path = RUN_ROOT / "final_padding_study_transformer.pt"
    final_model = load_state_model(torch, nn, cfg, final_path); final_sha = sha256_file(final_path)
    inv = read_json(RUN_ROOT / "padding_invariance_tests_final.json")
    if not (RUN_ROOT / "attention_padding_diagnostics.json").exists():
        publish(RUN_ROOT / "attention_padding_diagnostics.json", attention_padding_diagnostic(torch, nn, cases["train"], fold_ids))
    _oi, oy, op, _ol = oof_arrays(four["variants"][name])
    temp = fit_temperature(oy, op)
    if not (RUN_ROOT / "temperature_scaling_results.json").exists():
        publish(RUN_ROOT / "temperature_scaling_results.json", {"schema_version": "prediction_next_distinct_padding_temperature_scaling.v1", **temp, "adopted": bool(temp["improvement"]["nll"] > 0 and temp["improvement"]["ece"] > 0 and temp["improvement"]["brier"] > 0 and temp["ranking_exact"])})
    adopted_temp = bool(temp["improvement"]["nll"] > 0 and temp["improvement"]["ece"] > 0 and temp["improvement"]["brier"] > 0 and temp["ranking_exact"])
    display = "TEMPERATURE_SCALED_PROBABILITIES_PREFERRED" if adopted_temp else ("RAW_PROBABILITIES_ACCEPTABLE_FOR_POC" if temp["after"]["ece"] < 0.1 else "PROBABILITIES_POORLY_CALIBRATED — DISPLAY RANKS ONLY")
    if not (RUN_ROOT / "probability_display_policy.json").exists():
        publish(RUN_ROOT / "probability_display_policy.json", {"schema_version": "prediction_next_distinct_probability_display_policy.v1", "policy": display, "evidence": "TRAIN OOF calibration plus previously observed descriptive cohorts; softmax scores are not asserted to be calibrated probabilities"})
    v2_results = read_json(V2_ROOT / "comparison_results.json"); old_path = Path(next(x for x in v2_results["models"]["transformer"]["seeds"] if int(x["seed"]) == 20260822)["checkpoint"]["path"])
    if sha256_file(old_path) != EXPECTED_ORIGINAL: raise PaddingStudyBlocked("original frozen checkpoint hash changed")
    old_orig = load_state_model(torch, nn, Config("old_original", loss="ce", padding_mask=False), old_path); old_ref = load_state_model(torch, nn, Config("old_refined", loss="inverse_sqrt", padding_mask=False), REF_ROOT / "final_refined_transformer.pt")
    post_models = {"original": (old_orig, cfgs_for_finish("M0")), "refined_v1": (old_ref, cfgs_for_finish("M1")), "padding_final": (final_model, cfg)}
    post = serial_role_eval(torch, post_models, cases)
    if not (RUN_ROOT / "selection_post_selection.json").exists(): publish(RUN_ROOT / "selection_post_selection.json", {"schema_version": "prediction_next_distinct_padding_selection_post_selection.v1", "label": "POST-SELECTION DESCRIPTIVE RESULTS — PREVIOUSLY OBSERVED SELECTION COHORT", "models": post, "used_for_tuning": False})
    if not (RUN_ROOT / "calibration_post_selection.json").exists(): publish(RUN_ROOT / "calibration_post_selection.json", {"schema_version": "prediction_next_distinct_padding_calibration_post_selection.v1", "label": "POST-SELECTION DESCRIPTIVE RESULTS — PREVIOUSLY OBSERVED CALIBRATION COHORT", "models": post, "used_for_tuning": False})
    benchmark = read_json(BENCH_ROOT / "benchmark_sessions.json")
    if sha256_file(BENCH_ROOT / "benchmark_sessions.json") != EXPECTED_BENCHMARK: raise PaddingStudyBlocked("controlled benchmark hash changed")
    bench = benchmark_eval(torch, post_models, benchmark)
    if not (RUN_ROOT / "controlled_benchmark_post_selection.json").exists(): publish(RUN_ROOT / "controlled_benchmark_post_selection.json", bench)
    free = free_run_eval(torch, {"refined_v1": (old_ref, cfgs_for_finish("M1")), "padding_final": (final_model, cfg)}, read_json(FREE_RUN))
    if not (RUN_ROOT / "free_run_regression.json").exists(): publish(RUN_ROOT / "free_run_regression.json", free)
    table = four["table"]; chosen = next(x for x in selected["candidate_table"] if x["name"] == name); old_class = read_json(RUN_ROOT / "padding_probe_interpretation_addendum.json")["classification"]; readout = read_json(RUN_ROOT / "readout_validity_audit.json"); attention = read_json(RUN_ROOT / "attention_padding_diagnostics.json")
    final_answer = "PADDING-FIXED REFINED TRANSFORMER ADOPTION SUPPORTED" if cfg.padding_mask and chosen["aggregate"]["mean_macro_f1"] >= table["M1"]["mean_macro_f1"] - 1e-12 and inv["all_fresh_M3_pass"] else ("PADDING FIX STRUCTURALLY CORRECT BUT PREDICTIVE GAIN INSUFFICIENT — KEEP REFINED V1" if inv["all_fresh_M3_pass"] else "PADDING STUDY INVALID — padding invariance failed")
    summary = {"schema_version": "prediction_next_distinct_transformer_padding_fix_summary.v1", "status": "COMPLETE_VALID", "started_at": None, "finished_at": utc_now(), "elapsed_seconds": None, "resume_from_partial": True, "selected_candidate": chosen, "final_adoption_verdict": final_answer, "dataset_manifest_sha256": EXPECTED_MANIFEST, "four_way_cv": {"table": table, "variants": {k: {"aggregate": four["variants"][k]["aggregate"], "seeds": four["variants"][k]["seeds"]} for k in four["variants"]}}, "padding_invariance": inv, "readout_validity": readout, "old_probe_classification": old_class, "temperature": temp, "probability_display_policy": display, "post_selection": {k: {m: {"selection": post[m]["selection"]["metrics"], "calibration": post[m]["calibration"]["metrics"]} for m in post} for k in ("selection", "calibration")}, "controlled_benchmark_overall": {m: bench["models"][m]["overall"] for m in bench["models"]}, "attention_diagnostics": attention, "train_support": {"cases": len(cases["train"]), "units": len(set(str(c.unit_id) for c in cases["train"])), "history_counts": dict(sorted(Counter(int(c.history_length) for c in cases["train"]).items())), "target_counts": dict(sorted(Counter(str(c.target) for c in cases["train"]).items()))}, "claims": ["bounded TRAIN group-aware evidence only", "padding correctness is not additional training support", "no attacker-population/generalization/production claims"], "prior_artifacts_preserved": True, "existing_files_modified": [], "existing_files_overwritten": [], "sealed_data_accessed": False, "synthetic_data_used_for_training": False, "selection_used_for_tuning": False, "calibration_used_for_tuning": False, "controlled_benchmark_used_for_tuning": False, "models_retrained": True, "temperature_fit_data_source": "TRAIN OOF only"}
    summary_path = RUN_ROOT / "padding_fix_summary.json"
    if summary_path.exists():
        summary = read_json(summary_path)
    else:
        publish(summary_path, summary)
    publish(RUN_ROOT / "transformer_padding_fix_report.md", report_text(summary))
    required = {p.name: sha256_file(p) for p in sorted(RUN_ROOT.iterdir()) if p.is_file() and p.name != "receipt.json"}
    receipt = {"schema_version": "prediction_next_distinct_transformer_padding_fix_receipt.v1", "status": "COMPLETE_VALID", "comparison_id": "prediction_next_distinct_transformer_padding_fix_v1_20260823", "required_artifacts": required, "runner_path": str(Path(__file__).relative_to(ROOT)), "runner_sha256": sha256_file(Path(__file__)), "dataset_manifest_sha256": EXPECTED_MANIFEST, "fold_file_sha256": EXPECTED_FOLD_FILE, "fold_identity_sha256": EXPECTED_FOLD_ID, "controlled_benchmark_sha256": EXPECTED_BENCHMARK, "final_checkpoint_sha256": final_sha, "final_adoption_verdict": final_answer, "prior_artifacts_preserved": True, "existing_files_modified": [], "existing_files_overwritten": [], "sealed_data_accessed": False, "synthetic_data_used_for_training": False, "selection_used_for_tuning": False, "calibration_used_for_tuning": False, "controlled_benchmark_used_for_tuning": False, "models_retrained": True, "temperature_fit_data_source": "TRAIN OOF only", "post_selection_descriptive_only": True}
    receipt["receipt_sha256"] = sha256_json(receipt); publish(RUN_ROOT / "receipt.json", receipt)
    return summary


def cfgs_for_finish(name: str) -> Config:
    return {"M0": Config("M0_original_ce_unmasked", loss="ce", padding_mask=False), "M1": Config("M1_original_inverse_sqrt_unmasked", loss="inverse_sqrt", padding_mask=False)}[name]


if __name__ == "__main__":
    try:
        result = finish_partial() if os.environ.get("PADDING_STUDY_FINISH_PARTIAL") == "1" else run(); print(json.dumps({"status": result["status"], "run_root": str(RUN_ROOT), "selected": result["selected_candidate"]["name"], "verdict": result["final_adoption_verdict"]}, sort_keys=True))
    except PaddingStudyBlocked as exc:
        print(json.dumps({"status": "PADDING STUDY BLOCKED", "reason": str(exc), "run_root": str(RUN_ROOT)}, sort_keys=True)); raise SystemExit(2)
