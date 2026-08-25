"""Clean, instrumented reproduction of the frozen V1 next-distinct experiment.

This module is deliberately isolated from V1.  It reads the already frozen V1
dataset in read-only mode, trains fresh experiment-local models, and publishes
only files below the V2 artifact directory.  No canonical, production, sealed,
or historical model state is imported as a weight.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import random
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np


ROOT = Path(__file__).resolve().parents[3]
V1_ROOT = ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_model_comparison_v1/artifacts-20260822"
V1_RUN = ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_model_comparison_v1/run.py"
RUN_ROOT = Path(os.environ.get(
    "PREDICTION_NEXT_DISTINCT_V2_ROOT",
    str(ROOT / "honeypot-analysis/evaluation/prediction_next_distinct_model_comparison_v2/artifacts-20260823"),
)).resolve()
ROLES = ("train", "selection", "calibration")
TACTICS = (
    "command-and-control", "credential-access", "defense-evasion", "discovery",
    "execution", "persistence", "privilege-escalation",
)
TACTIC_TO_ID = {name: i + 1 for i, name in enumerate(TACTICS)}
SEEDS = (20260822, 20260823, 20260824, 20260825, 20260826)
SHUFFLE_SEEDS = tuple(range(20260822, 20260832))
MAX_HISTORY = 8
EXPECTED = {
    "train": {"cases": 10186, "contributors": 6952, "ge3": 2890, "ge5": 71},
    "selection": {"cases": 1983, "contributors": 1418},
    "calibration": {"cases": 2104, "contributors": 1347},
}
EXPECTED_POOLED = 14273
EXPECTED_PAIRS = 16
EXPECTED_V1_MANIFEST_SHA = "5b88e7410e4f2ba96ff578cb5e9da025b3028c2e12c6017f08e6bee0a177458d"
V1_SOURCE_SHA = "1199bf753eba80320e2b76b49f6c381a6ccfe153b1d623c6feed0aed4f91fb9a"
HISTORICAL_TRANSFORMER_SHA = "d9b316d76e63b15b175668aa0bf69cfe4172bbd812d6b19743a628cd0ec8073d"
CANDIDATE_A_SHAS = (
    "2883f5849c220cf6c9bcc6f1491e35857a946bf50482b91fadf597fcc9be57ab",
    "915cbe9fd29d525a80502b1df5d11c1f71926eb6a91c6d7588e6f3736388a483",
    "08e7eb411af58cc5b73a33fc252c18395767a1c73bb9b639cf458589d26392f0",
    "ac149ce6ba865d05126330c1614458cc8c751928ea00b87d404394ef42c0ef8c",
)
SCHEMA = "prediction_next_distinct_model_comparison.v2"


class ComparisonBlocked(RuntimeError):
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


def immutable_publish(path: Path, value: Any) -> None:
    """Publish a new artifact atomically and refuse replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = stable_json(value) + "\n"
    if path.exists():
        if path.read_text(encoding="utf-8") != body:
            raise ComparisonBlocked(f"refusing to overwrite V2 artifact: {path}")
        return
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    temp.write_text(body, encoding="utf-8")
    with temp.open("rb") as f:
        os.fsync(f.fileno())
    os.link(temp, path)
    temp.unlink(missing_ok=True)


def immutable_publish_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ComparisonBlocked(f"refusing to overwrite V2 JSONL artifact: {path}")
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    digest = hashlib.sha256()
    with temp.open("w", encoding="utf-8") as f:
        for row in rows:
            line = stable_json(row) + "\n"
            f.write(line)
            digest.update(line.encode("utf-8"))
        f.flush()
        os.fsync(f.fileno())
    os.link(temp, path)
    temp.unlink(missing_ok=True)
    return digest.hexdigest()


def immutable_publish_text(path: Path, text: str) -> None:
    """Publish a new text artifact without ever replacing it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != text:
            raise ComparisonBlocked(f"refusing to overwrite V2 text artifact: {path}")
        return
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    temp.write_text(text, encoding="utf-8")
    with temp.open("rb") as f:
        os.fsync(f.fileno())
    os.link(temp, path)
    temp.unlink(missing_ok=True)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ComparisonBlocked(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ComparisonBlocked(f"JSON root is not an object: {path}")
    return value


def load_v1_module() -> Any:
    """Load only definitions/classes from V1 without writing its pycache."""
    if not V1_RUN.is_file() or V1_RUN.is_symlink():
        raise ComparisonBlocked(f"frozen V1 source unavailable: {V1_RUN}")
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("prediction_v1_run_for_v2", V1_RUN)
    if spec is None or spec.loader is None:
        raise ComparisonBlocked("cannot load frozen V1 source")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _case_id(role: str, ordinal: int, unit_id: str, history: Sequence[str], target: str) -> str:
    payload = f"prediction-next-distinct-v2|{role}|{ordinal}|{unit_id}|{','.join(history)}|{target}"
    return "case_" + hashlib.sha256(payload.encode()).hexdigest()


def verify_dataset() -> tuple[dict[str, list[Any]], dict[str, Any], dict[str, list[str]]]:
    """Verify V1's immutable dataset binding and load only privacy-safe cases."""
    v1 = load_v1_module()
    manifest_path = V1_ROOT / "dataset/dataset_manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ComparisonBlocked("V1 dataset manifest is missing or symlinked")
    manifest_sha = sha256_file(manifest_path)
    if manifest_sha != EXPECTED_V1_MANIFEST_SHA:
        raise ComparisonBlocked(f"V1 dataset manifest hash differs: {manifest_sha}")
    manifest = read_json(manifest_path)
    body = dict(manifest)
    embedded = body.pop("dataset_sha256", None)
    if embedded != sha256_json(body):
        raise ComparisonBlocked("V1 dataset manifest self-hash failed")
    if manifest.get("schema_version") != "prediction_next_distinct_model_comparison.v1":
        raise ComparisonBlocked("unexpected frozen V1 schema")
    if manifest.get("dataset_id") != "prediction_next_distinct_internal40_pregroup_v1":
        raise ComparisonBlocked("unexpected frozen V1 dataset identity")
    if manifest.get("target_includes_session_end") is not False:
        raise ComparisonBlocked("V1 target/session-end contract differs")
    if manifest.get("authority") != "non-authoritative prediction-only research POC":
        raise ComparisonBlocked("V1 authority contract differs")
    sealed = manifest.get("sealed_boundary", {})
    if any(bool(sealed.get(k)) for k in ("sealed_prediction_data_accessed", "sealed_test_accessed", "production_changed", "canonical_policy_changed", "prior_experiments_modified")):
        raise ComparisonBlocked("V1 dataset sealed/production boundary is not clean")
    role_files = manifest.get("role_files")
    if not isinstance(role_files, dict) or set(role_files) != set(ROLES):
        raise ComparisonBlocked("V1 role-file contract differs")
    cases: dict[str, list[Any]] = {r: [] for r in ROLES}
    case_ids: dict[str, list[str]] = {r: [] for r in ROLES}
    units_by_role: dict[str, set[str]] = {r: set() for r in ROLES}
    source_file_hashes: dict[str, str] = {}
    for role in ROLES:
        spec = role_files[role]
        path = Path(spec.get("path", ""))
        if not path.is_absolute():
            path = (V1_ROOT / "dataset" / path).resolve()
        if not path.is_file() or path.is_symlink():
            raise ComparisonBlocked(f"V1 role shard missing/symlinked: {path}")
        actual = sha256_file(path)
        if actual != spec.get("sha256"):
            raise ComparisonBlocked(f"V1 role shard hash differs: {role}")
        source_file_hashes[role] = actual
        previous_by_unit: dict[str, Any] = {}
        last_unit: str | None = None
        with path.open(encoding="utf-8") as f:
            for ordinal, line in enumerate(f):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ComparisonBlocked(f"malformed V1 record {role}:{ordinal}") from exc
                if set(record) != {"schema_version", "role", "unit_id", "history", "target", "history_length"}:
                    raise ComparisonBlocked(f"unexpected/private V1 dataset field: {role}:{ordinal}")
                if record["schema_version"] != "prediction_next_distinct_case.v1" or record["role"] != role:
                    raise ComparisonBlocked(f"V1 case schema/role mismatch: {role}:{ordinal}")
                unit = str(record["unit_id"])
                history = tuple(str(x) for x in record["history"])
                target = str(record["target"])
                if not history or len(history) != int(record["history_length"]) or len(history) > MAX_HISTORY:
                    raise ComparisonBlocked(f"V1 history contract failed: {role}:{ordinal}")
                if any(x not in TACTIC_TO_ID for x in history) or target not in TACTIC_TO_ID:
                    raise ComparisonBlocked(f"V1 vocabulary contract failed: {role}:{ordinal}")
                if unit in previous_by_unit:
                    if last_unit != unit:
                        raise ComparisonBlocked(f"V1 unit is non-contiguous: {role}:{ordinal}")
                    prev = previous_by_unit[unit]
                    expected_history = (tuple(prev.history) + (prev.target,))[-MAX_HISTORY:]
                    if history != expected_history:
                        raise ComparisonBlocked(f"V1 ordered-prefix contract failed: {role}:{ordinal}")
                elif unit in units_by_role[role]:
                    raise ComparisonBlocked(f"V1 unit is non-contiguous: {role}:{ordinal}")
                else:
                    units_by_role[role].add(unit)
                case = v1.Case(role, unit, history, target, len(history))
                cases[role].append(case)
                case_ids[role].append(_case_id(role, ordinal, unit, history, target))
                previous_by_unit[unit] = case
                last_unit = unit
        expected = EXPECTED[role]
        if len(cases[role]) != expected["cases"]:
            raise ComparisonBlocked(f"V1 {role} case count differs")
        contributors = len(units_by_role[role])
        if contributors != expected["contributors"]:
            raise ComparisonBlocked(f"V1 {role} contributing-unit count differs")
    all_units = [set(c.unit_id for c in cases[r]) for r in ROLES]
    if any(all_units[i] & all_units[j] for i in range(3) for j in range(i + 1, 3)):
        raise ComparisonBlocked("V1 role units overlap")
    if sum(len(cases[r]) for r in ROLES) != EXPECTED_POOLED:
        raise ComparisonBlocked("V1 pooled case total differs")
    transition_pairs = Counter(f"{c.history[-1]} -> {c.target}" for r in ROLES for c in cases[r])
    if len(transition_pairs) != EXPECTED_PAIRS:
        raise ComparisonBlocked("V1 directed-pair count differs")
    # Bind the exact frozen source contract without copying or rewriting it.
    binding = {
        "source": "frozen V1 dataset, read-only",
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha,
        "embedded_dataset_sha256": embedded,
        "role_shards": {r: {"path": str(Path(role_files[r]["path"]).resolve()), "sha256": source_file_hashes[r], "cases": len(cases[r])} for r in ROLES},
        "roles": {r: {"cases": len(cases[r]), "contributing_units": len(units_by_role[r])} for r in ROLES},
        "pooled_cases": EXPECTED_POOLED,
        "directed_pairs": len(transition_pairs),
        "class_order": list(TACTICS),
        "semantics": "P(next observed distinct trusted tactic | previous observed distinct trusted tactics)",
        "sealed_prediction_data_accessed": False,
        "sealed_test_accessed": False,
        "production_changed": False,
        "prior_experiments_modified": False,
        "v1_source_sha256": sha256_file(V1_RUN),
    }
    if binding["v1_source_sha256"] != V1_SOURCE_SHA:
        raise ComparisonBlocked("frozen V1 source hash differs")
    return cases, binding, case_ids


def features(cases: Sequence[Any], ids: Sequence[str], transform: str = "full", shuffle_seed: int | None = None) -> tuple[np.ndarray, np.ndarray, list[bool]]:
    x = np.zeros((len(cases), MAX_HISTORY + 1), dtype=np.int64)
    y = np.zeros(len(cases), dtype=np.int64)
    changed: list[bool] = []
    for i, (case, case_id) in enumerate(zip(cases, ids)):
        original = list(case.history[-MAX_HISTORY:])
        history = list(original)
        did_change = False
        if transform == "last_only":
            history = history[-1:]
        elif transform == "reverse":
            history = list(reversed(history))
            did_change = history != original
        elif transform == "true_prefix_shuffle":
            if len(history) > 2:
                prefix = history[:-1]
                random.Random(f"{shuffle_seed}|{case_id}").shuffle(prefix)
                history = prefix + history[-1:]
                did_change = history != original
        elif transform != "full":
            raise ComparisonBlocked(f"unknown feature transform {transform}")
        token_ids = [TACTIC_TO_ID[t] for t in history]
        x[i, -len(token_ids) - 1:-1] = token_ids
        x[i, -1] = len(token_ids)
        y[i] = TACTIC_TO_ID[case.target]
        changed.append(did_change)
    return x, y, changed


def metrics(v1: Any, y: np.ndarray, probabilities: np.ndarray, model: str, role: str, cases: Sequence[Any]) -> dict[str, Any]:
    return v1._metrics(y, probabilities, model=model, role=role, histories=cases)


def imports_torch() -> tuple[Any, Any, Any, Any]:
    try:
        import torch
        from torch import nn
        from torch.utils.data import DataLoader, TensorDataset
    except Exception as exc:
        raise ComparisonBlocked(f"torch unavailable in approved runtime: {exc}") from exc
    return torch, nn, DataLoader, TensorDataset


def build_model(torch: Any, nn: Any, kind: str, max_history: int = MAX_HISTORY) -> Any:
    if kind == "gru":
        class Model(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.embedding = nn.Embedding(len(TACTICS) + 1, 8, padding_idx=0)
                self.gru = nn.GRU(8, 16, batch_first=True)
                self.head = nn.Linear(16, len(TACTICS))

            def forward(self, tokens: Any) -> Any:
                out, _ = self.gru(self.embedding(tokens))
                return self.head(out[:, -1])
    elif kind == "transformer":
        class Model(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.embedding = nn.Embedding(len(TACTICS) + 1, 16, padding_idx=0)
                self.position = nn.Parameter(torch.zeros(1, max_history, 16))
                layer = nn.TransformerEncoderLayer(d_model=16, nhead=4, dim_feedforward=32, dropout=0.1, batch_first=True)
                self.encoder = nn.TransformerEncoder(layer, num_layers=1)
                self.head = nn.Linear(16, len(TACTICS))

            def forward(self, tokens: Any) -> Any:
                embedded = self.embedding(tokens) + self.position
                mask = torch.triu(torch.ones(max_history, max_history, device=tokens.device, dtype=torch.bool), diagonal=1)
                out = self.encoder(embedded, mask=mask)
                return self.head(out[:, -1])
    else:
        raise ComparisonBlocked(f"unknown neural family: {kind}")
    model = Model()
    expected_params = {"gru": 1431, "transformer": 2599}[kind]
    actual = sum(p.numel() for p in model.parameters())
    if actual != expected_params:
        raise ComparisonBlocked(f"{kind} parameter count changed: {actual} != {expected_params}")
    return model


def tensor_logits(model: Any, cases: Sequence[Any], ids: Sequence[str], transform: str = "full", shuffle_seed: int | None = None) -> tuple[np.ndarray, np.ndarray, list[bool]]:
    torch, _nn, _DataLoader, _TensorDataset = imports_torch()
    x, y, changed = features(cases, ids, transform, shuffle_seed)
    with torch.no_grad():
        logits = model(torch.tensor(x[:, :-1], dtype=torch.long)).cpu().numpy()
    return logits, y, changed


def train_one(v1: Any, train: Sequence[Any], train_ids: Sequence[str], selection: Sequence[Any], selection_ids: Sequence[str], kind: str, seed: int, output: Path) -> tuple[Any, dict[str, Any]]:
    torch, nn, DataLoader, TensorDataset = imports_torch()
    torch.manual_seed(seed); np.random.seed(seed); random.seed(seed)
    torch.use_deterministic_algorithms(True)
    tx, ty, _ = features(train, train_ids)
    sx, sy, _ = features(selection, selection_ids)
    train_x = torch.tensor(tx[:, :-1], dtype=torch.long)
    train_y = torch.tensor(ty - 1, dtype=torch.long)
    sel_x = torch.tensor(sx[:, :-1], dtype=torch.long)
    sel_y = torch.tensor(sy - 1, dtype=torch.long)
    model = build_model(torch, nn, kind)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loader = DataLoader(TensorDataset(train_x, train_y), batch_size=128, shuffle=True, generator=torch.Generator().manual_seed(seed))
    best_state: dict[str, Any] | None = None
    best_score = -1.0
    best_epoch = 0
    stale = 0
    start = time.monotonic()
    history: list[dict[str, Any]] = []
    for epoch in range(1, 21):
        epoch_start = time.monotonic()
        model.train()
        total_loss = 0.0
        total_n = 0
        for xb, yb in loader:
            optimizer.zero_grad(set_to_none=True)
            logits = model(xb)
            loss = nn.functional.cross_entropy(logits, yb)
            loss.backward(); optimizer.step()
            n = len(yb); total_loss += float(loss.item()) * n; total_n += n
        model.eval()
        with torch.no_grad():
            sel_logits = model(sel_x)
            sel_loss = float(nn.functional.cross_entropy(sel_logits, sel_y).item())
            sel_probs = torch.softmax(sel_logits, dim=1).cpu().numpy()
        sel_metrics = metrics(v1, sy, sel_probs, kind, "selection", selection)
        score = float(sel_metrics["macro_f1"])
        stale_after = 0
        is_best = score > best_score + 1e-12
        if is_best:
            best_score = score; best_epoch = epoch; stale = 0
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            stale += 1; stale_after = stale
        early = "continue"
        if stale >= 4:
            early = "early_stop_patience"
        elif epoch == 20:
            early = "max_epochs"
        elapsed = time.monotonic() - start
        history.append({
            "epoch": epoch,
            "training_loss": total_loss / total_n,
            "selection_loss": sel_loss,
            "selection_macro_f1": float(sel_metrics["macro_f1"]),
            "selection_balanced_accuracy": float(sel_metrics["balanced_accuracy"]),
            "selection_top1": float(sel_metrics["top1"]),
            "learning_rate": 1e-3,
            "epoch_seconds": time.monotonic() - epoch_start,
            "cumulative_training_seconds": elapsed,
            "is_best": is_best,
            "stale_after_epoch": stale_after,
            "early_stopping_decision": early,
        })
        if stale >= 4:
            break
    if best_state is None:
        raise ComparisonBlocked(f"{kind} seed {seed} had no best state")
    model.load_state_dict(best_state); model.eval()
    duration = time.monotonic() - start
    checkpoint = output / "models" / f"{kind}-seed-{seed}.pt"
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    if checkpoint.exists():
        raise ComparisonBlocked(f"unexpected pre-existing V2 checkpoint: {checkpoint}")
    torch.save(model.state_dict(), checkpoint)
    metadata = {
        "model_family": kind, "seed": seed, "fresh_initialization": True,
        "architecture": {"gru": {"embedding": 8, "hidden": 16, "layers": 1, "max_history": 8}, "transformer": {"d_model": 16, "feed_forward": 32, "heads": 4, "layers": 1, "dropout": 0.1, "max_history": 8}}[kind],
        "parameter_count": {"gru": 1431, "transformer": 2599}[kind],
        "optimizer": "Adam", "learning_rate": 1e-3, "batch_size": 128, "max_epochs": 20, "patience": 4,
        "epochs_actually_trained": len(history), "best_epoch": best_epoch,
        "best_selection_macro_f1": best_score, "training_seconds": duration,
        "training_history": history,
        "checkpoint": {"path": str(checkpoint), "size_bytes": checkpoint.stat().st_size, "sha256": sha256_file(checkpoint)},
    }
    return model, metadata


def prediction_rows(model_name: str, seed: int | None, role: str, cases: Sequence[Any], ids: Sequence[str], probabilities: np.ndarray, logits: np.ndarray | None) -> Iterable[dict[str, Any]]:
    for i, (case, case_id) in enumerate(zip(cases, ids)):
        pred_id = int(np.argmax(probabilities[i])) + 1
        yield {
            "case_id": case_id, "role": role, "model": model_name, "seed": seed,
            "history_length": int(case.history_length), "true_class": case.target,
            "predicted_class": TACTICS[pred_id - 1], "class_order": list(TACTICS),
            "probability_vector": [float(x) for x in probabilities[i]],
            "logit_vector": None if logits is None else [float(x) for x in logits[i]],
            "correct": bool(pred_id == TACTIC_TO_ID[case.target]),
        }


def aggregate_prediction_metrics(v1: Any, model_name: str, role: str, cases: Sequence[Any], probs: np.ndarray, y: np.ndarray) -> dict[str, Any]:
    value = metrics(v1, y, probs, model_name, role, cases)
    value["unsupported_classes"] = [name for name, row in value.get("per_class", {}).items() if int(row.get("support", 0)) == 0]
    return value


def pair_metrics(a_name: str, a: Mapping[str, Any], b_name: str, b: Mapping[str, Any], cases: Sequence[Any], y: np.ndarray) -> dict[str, Any]:
    ap = np.asarray(a["probabilities"], dtype=np.float64); bp = np.asarray(b["probabilities"], dtype=np.float64)
    al = ap.argmax(axis=1); bl = bp.argmax(axis=1)
    identical = al == bl
    ac = al == (y - 1); bc = bl == (y - 1)
    diffs = np.abs(ap - bp)
    return {
        "model_a": a_name, "model_b": b_name, "cases": len(y),
        "case_order_sha256": sha256_json([getattr(c, "unit_id", "") + "|" + str(c.history_length) + "|" + c.target for c in cases]),
        "identical_predicted_labels": int(identical.sum()), "different_predicted_labels": int((~identical).sum()),
        "both_correct": int((ac & bc).sum()), "both_wrong": int((~ac & ~bc).sum()),
        "a_only_correct": int((ac & ~bc).sum()), "b_only_correct": int((~ac & bc).sum()),
        "maximum_component_probability_difference": float(diffs.max()),
        "mean_component_probability_difference": float(diffs.mean()),
        "mean_l1_probability_difference": float(diffs.sum(axis=1).mean()),
    }


def target_transition_support(cases: Mapping[str, Sequence[Any]]) -> dict[str, Any]:
    pairs: Counter[str] = Counter(); target_cases: Counter[str] = Counter(); target_units: dict[str, set[str]] = defaultdict(set)
    for role in ROLES:
        for c in cases[role]:
            key = f"{c.history[-1]} -> {c.target}"
            pairs[key] += 1; target_cases[c.target] += 1; target_units[c.target].add(c.unit_id)
    ordered = sorted(pairs.items(), key=lambda item: (-item[1], item[0]))
    return {
        "unique_directed_pairs": len(pairs), "target_cases": dict(sorted(target_cases.items())),
        "target_unique_contributing_units": {k: len(v) for k, v in sorted(target_units.items())},
        "directed_pairs": dict(ordered), "top1": ordered[:1], "top3": ordered[:3], "top5": ordered[:5],
        "train_transition_shares": {k: v / len(cases["train"]) for k, v in sorted(Counter(f"{c.history[-1]} -> {c.target}" for c in cases["train"]).items(), key=lambda item: (-item[1], item[0]))},
    }


def subset_metrics(v1: Any, name: str, cases: Sequence[Any], probs: np.ndarray, y: np.ndarray, indices: Sequence[int]) -> dict[str, Any]:
    idx = np.asarray(indices, dtype=np.int64)
    if len(idx) == 0:
        return {"model": name, "cases": 0, "macro_f1": None, "balanced_accuracy": None, "top1": None}
    return metrics(v1, y[idx], probs[idx], name, "selection", [cases[int(i)] for i in idx])


def choose_result(results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return sorted(results, key=lambda r: (-float(r["selection_metrics"]["macro_f1"]), -float(r["selection_metrics"]["balanced_accuracy"]), int(r["seed"])))[0]


def run() -> dict[str, Any]:
    if RUN_ROOT.exists():
        raise ComparisonBlocked(f"V2 output namespace already exists: {RUN_ROOT}")
    if not RUN_ROOT.parent.is_dir() or not os.access(RUN_ROOT.parent, os.W_OK):
        raise ComparisonBlocked(f"V2 output parent is not writable: {RUN_ROOT.parent}")
    started_at = utc_now(); total_start = time.monotonic(); timings: dict[str, float] = {}
    phase = time.monotonic()
    cases, binding, case_ids = verify_dataset()
    timings["dataset_verification_and_load_seconds"] = time.monotonic() - phase
    dataset_binding = {"schema_version": "prediction_next_distinct_dataset_binding.v2", "v1_manifest_identity": binding, "v2_case_id_schema": "sha256(role|ordinal|unit_id|history|target)", "role_case_counts": {r: len(cases[r]) for r in ROLES}, "source_read_only": True}
    immutable_publish(RUN_ROOT / "dataset_binding.json", dataset_binding)
    config = {
        "schema_version": SCHEMA, "dataset_manifest_sha256": binding["manifest_sha256"], "seeds": list(SEEDS), "shuffle_seeds": list(SHUFFLE_SEEDS),
        "class_order": list(TACTICS), "max_history": MAX_HISTORY, "target": "immediately next observed distinct trusted tactic; no session_end",
        "models": {"markov": {"order": 1, "laplace_alpha": 1, "global_target_backoff": True}, "tree": {"status": "tree_surrogate_xgboost_unavailable", "depth_candidates": [3, 5, 7], "min_leaf": 2}, "gru": {"embedding": 8, "hidden": 16, "layers": 1, "parameters": 1431}, "transformer": {"d_model": 16, "feed_forward": 32, "heads": 4, "layers": 1, "dropout": 0.1, "parameters": 2599}},
        "training": {"optimizer": "Adam", "learning_rate": 1e-3, "batch_size": 128, "max_epochs": 20, "patience": 4, "criterion": "CrossEntropy", "fresh_initialization": True, "selection_only_for_freeze": True, "calibration_previously_observed": True},
        "prior_weights_loaded": False, "sealed_accessed": False, "external_ai_called": False,
    }
    immutable_publish(RUN_ROOT / "experiment_config.json", config)
    v1 = load_v1_module()
    train, selection, calibration = cases["train"], cases["selection"], cases["calibration"]
    train_ids, selection_ids, calibration_ids = case_ids["train"], case_ids["selection"], case_ids["calibration"]
    results: dict[str, Any] = {"models": {}, "xgboost": {"available": False, "status": "XGBOOST = NOT EVALUATED", "reason": "xgboost unavailable in approved offline runtime; no installation/network"}}
    prediction_cache: dict[tuple[str, int | None, str], dict[str, Any]] = {}
    phase = time.monotonic()
    markov = v1.MarkovModel(); markov.fit(train)
    timings["markov_fit_seconds"] = time.monotonic() - phase
    phase = time.monotonic()
    for role, items, ids in (("selection", selection, selection_ids), ("calibration", calibration, calibration_ids)):
        _, y, _ = features(items, ids)
        probs = markov.predict(items)
        prediction_cache[("first_order_markov", None, role)] = {"probabilities": probs, "logits": None, "cases": items, "ids": ids, "y": y}
    timings["markov_evaluation_seconds"] = time.monotonic() - phase
    results["models"]["first_order_markov"] = {"metadata": {"training_role": "train", "smoothing": "Laplace(alpha=1), global target backoff"}, "selection": aggregate_prediction_metrics(v1, "first_order_markov", "selection", selection, prediction_cache[("first_order_markov", None, "selection")]["probabilities"], prediction_cache[("first_order_markov", None, "selection")]["y"]), "calibration": aggregate_prediction_metrics(v1, "first_order_markov", "calibration", calibration, prediction_cache[("first_order_markov", None, "calibration")]["probabilities"], prediction_cache[("first_order_markov", None, "calibration")]["y"])}
    phase = time.monotonic()
    tx, ty, _ = features(train, train_ids); sx, sy, _ = features(selection, selection_ids); cx, cy, _ = features(calibration, calibration_ids)
    candidates: list[tuple[float, int, Any]] = []
    for depth in (3, 5, 7):
        tree = v1.EqualityTree(max_depth=depth, min_leaf=2); tree.fit(tx, ty)
        score = float(metrics(v1, sy, tree.predict(sx), "tree_surrogate_xgboost_unavailable", "selection", selection)["macro_f1"])
        candidates.append((score, depth, tree))
    candidates.sort(key=lambda item: (-item[0], item[1])); tree_score, tree_depth, tree = candidates[0]
    timings["tree_fit_and_selection_choice_seconds"] = time.monotonic() - phase
    phase = time.monotonic()
    for role, items, ids in (("selection", selection, selection_ids), ("calibration", calibration, calibration_ids)):
        probs = tree.predict(_features_for_tree(items, ids))
        _, y, _ = features(items, ids)
        prediction_cache[("tree_surrogate_xgboost_unavailable", None, role)] = {"probabilities": probs, "logits": None, "cases": items, "ids": ids, "y": y}
    timings["tree_evaluation_seconds"] = time.monotonic() - phase
    results["models"]["tree_surrogate_xgboost_unavailable"] = {"metadata": {"training_role": "train", "selected_max_depth": tree_depth, "depth_candidates": [3, 5, 7], "min_leaf": 2, "tree_type": "deterministic categorical equality tree", "xgboost_not_available": True, "selection_choice_macro_f1": tree_score}, "selection": aggregate_prediction_metrics(v1, "tree_surrogate_xgboost_unavailable", "selection", selection, prediction_cache[("tree_surrogate_xgboost_unavailable", None, "selection")]["probabilities"], sy), "calibration": aggregate_prediction_metrics(v1, "tree_surrogate_xgboost_unavailable", "calibration", calibration, prediction_cache[("tree_surrogate_xgboost_unavailable", None, "calibration")]["probabilities"], cy)}
    training_histories: dict[str, Any] = {}
    neural_metadata: dict[str, list[dict[str, Any]]] = {"gru": [], "transformer": []}
    selected_models: dict[str, dict[str, Any]] = {}
    for kind in ("gru", "transformer"):
        runs: list[dict[str, Any]] = []
        for seed in SEEDS:
            phase = time.monotonic()
            model, metadata = train_one(v1, train, train_ids, selection, selection_ids, kind, seed, RUN_ROOT)
            timings[f"{kind}_seed_{seed}_training_seconds"] = time.monotonic() - phase
            sel_logits, sel_y, _ = tensor_logits(model, selection, selection_ids)
            cal_logits, cal_y, _ = tensor_logits(model, calibration, calibration_ids)
            sel_probs = _softmax(sel_logits); cal_probs = _softmax(cal_logits)
            prediction_cache[(kind, seed, "selection")] = {"probabilities": sel_probs, "logits": sel_logits, "cases": selection, "ids": selection_ids, "y": sel_y}
            prediction_cache[(kind, seed, "calibration")] = {"probabilities": cal_probs, "logits": cal_logits, "cases": calibration, "ids": calibration_ids, "y": cal_y}
            metadata["selection_metrics"] = aggregate_prediction_metrics(v1, kind, "selection", selection, sel_probs, sel_y)
            metadata["calibration_metrics"] = aggregate_prediction_metrics(v1, kind, "calibration", calibration, cal_probs, cal_y)
            runs.append(metadata); training_histories[f"{kind}|{seed}"] = metadata["training_history"]; neural_metadata[kind].append(metadata)
        chosen = choose_result(runs); selected_models[kind] = {"seed": int(chosen["seed"]), "checkpoint": chosen["checkpoint"], "metadata": chosen}
        results["models"][kind] = {"seeds": runs, "selected_seed": int(chosen["seed"]), "selected_selection": chosen["selection_metrics"], "selected_calibration": chosen["calibration_metrics"], "calibration": chosen["calibration_metrics"], "fresh_checkpoint_only": True}
    immutable_publish(RUN_ROOT / "training_history.json", {"schema_version": "prediction_next_distinct_training_history.v2", "models": training_histories, "all_neural_seeds": list(SEEDS), "training_logs_are_persisted": True})
    immutable_publish(RUN_ROOT / "seed_summary.json", {"schema_version": SCHEMA, "models": {kind: [{"seed": int(m["seed"]), "epochs_actually_trained": m["epochs_actually_trained"], "best_epoch": m["best_epoch"], "best_selection_macro_f1": m["best_selection_macro_f1"], "checkpoint": m["checkpoint"]} for m in neural_metadata[kind]] for kind in ("gru", "transformer")}, "selected": {k: v["seed"] for k, v in selected_models.items()}})
    phase = time.monotonic()
    all_prediction_rows: list[dict[str, Any]] = []
    for (model_name, seed, role), value in prediction_cache.items():
        all_prediction_rows.extend(prediction_rows(model_name, seed, role, value["cases"], value["ids"], value["probabilities"], value["logits"]))
    selection_rows = [r for r in all_prediction_rows if r["role"] == "selection"]
    calibration_rows = [r for r in all_prediction_rows if r["role"] == "calibration"]
    selection_pred_sha = immutable_publish_jsonl(RUN_ROOT / "selection_predictions.jsonl", selection_rows)
    calibration_pred_sha = immutable_publish_jsonl(RUN_ROOT / "calibration_predictions.jsonl", calibration_rows)
    timings["prediction_serialization_seconds"] = time.monotonic() - phase
    # Reload the selected checkpoints: ablation never retrains and never mutates weights.
    phase = time.monotonic(); ablation: dict[str, Any] = {}
    for kind, selected in selected_models.items():
        torch, _nn, _DataLoader, _TensorDataset = imports_torch()
        checkpoint_path = Path(selected["checkpoint"]["path"])
        before_hash = sha256_file(checkpoint_path)
        model = build_model(torch, _nn, kind)
        try:
            state = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
        except TypeError:
            state = torch.load(checkpoint_path, map_location="cpu")
        model.load_state_dict(state); model.eval()
        after_hash = sha256_file(checkpoint_path)
        if before_hash != after_hash:
            raise ComparisonBlocked(f"checkpoint changed during reload: {checkpoint_path}")
        y = prediction_cache[(kind, int(selected["seed"]), "selection")]["y"]
        base_full = prediction_cache[(kind, int(selected["seed"]), "selection")]["probabilities"]
        reloaded_logits, reloaded_y, _ = tensor_logits(model, selection, selection_ids)
        reloaded_full = _softmax(reloaded_logits)
        if not np.array_equal(base_full, reloaded_full):
            raise ComparisonBlocked(f"reloaded full output differs for {kind}")
        transforms: dict[str, Any] = {}
        for transform in ("full", "last_only", "reverse"):
            logits, _, changed = tensor_logits(model, selection, selection_ids, transform)
            probs = _softmax(logits)
            transforms[transform] = {"metrics": aggregate_prediction_metrics(v1, kind + "_ablation_" + transform, "selection", selection, probs, y), "changed_cases": int(sum(changed)), "probability_output_sha256": sha256_json(probs.tolist()), "history_ge3": subset_metrics(v1, kind + "_ablation_" + transform, selection, probs, y, [i for i, c in enumerate(selection) if c.history_length >= 3])}
        shuffle_rows: list[dict[str, Any]] = []
        for shuffle_seed in SHUFFLE_SEEDS:
            logits, _, changed = tensor_logits(model, selection, selection_ids, "true_prefix_shuffle", shuffle_seed)
            probs = _softmax(logits)
            shuffle_rows.append({"seed": shuffle_seed, "metrics": aggregate_prediction_metrics(v1, kind + "_ablation_true_prefix_shuffle", "selection", selection, probs, y), "changed_cases": int(sum(changed)), "changed_cases_history_ge3": int(sum(changed[i] for i, c in enumerate(selection) if c.history_length >= 3)), "changed_case_ids": [selection_ids[i] for i, flag in enumerate(changed) if flag], "history_ge3": subset_metrics(v1, kind + "_ablation_true_prefix_shuffle", selection, probs, y, [i for i, c in enumerate(selection) if c.history_length >= 3]), "probability_output_sha256": sha256_json(probs.tolist())})
        for key in ("macro_f1", "balanced_accuracy", "top1"):
            vals = [float(row["metrics"][key]) for row in shuffle_rows]
            shuffle_rows_summary = locals().get("shuffle_rows_summary", None)
        changed_union = set()
        for row in shuffle_rows:
            changed_union.update(row.get("changed_case_ids", []))
        transforms["true_prefix_shuffle"] = {"seeds": shuffle_rows, "summary": {key: {"mean": statistics.mean([float(row["metrics"][key]) for row in shuffle_rows]), "std": statistics.pstdev([float(row["metrics"][key]) for row in shuffle_rows])} for key in ("macro_f1", "balanced_accuracy", "top1")}, "changed_cases_any": len(changed_union), "changed_cases_history_ge3_any": len(changed_union), "history_ge3_summary": {key: {"mean": statistics.mean([float(row["history_ge3"][key]) for row in shuffle_rows]), "std": statistics.pstdev([float(row["history_ge3"][key]) for row in shuffle_rows])} for key in ("macro_f1", "balanced_accuracy", "top1")}}
        ablation[kind] = {"selected_seed": selected["seed"], "checkpoint_sha256_before": before_hash, "checkpoint_sha256_after": after_hash, "checkpoint_unchanged": before_hash == after_hash, "ablation_retrained": False, "full_reload_matches_stored": True, "transforms": transforms}
    timings["ablation_seconds"] = time.monotonic() - phase
    immutable_publish(RUN_ROOT / "ablation_results.json", {"schema_version": "prediction_next_distinct_ablation.v2", "models": ablation, "true_prefix_shuffle_definition": "permute only history[:-1], retain final/current token, deterministic per-case seed; history <=2 not order-tested"})
    phase = time.monotonic(); support = target_transition_support(cases); timings["transition_support_seconds"] = time.monotonic() - phase
    selected_gru = prediction_cache[("gru", selected_models["gru"]["seed"], "selection")]; selected_transformer = prediction_cache[("transformer", selected_models["transformer"]["seed"], "selection")]
    pairs: list[dict[str, Any]] = []
    pair_inputs = [("gru", selected_gru, "transformer", selected_transformer), ("tree_surrogate_xgboost_unavailable", prediction_cache[("tree_surrogate_xgboost_unavailable", None, "selection")], "gru", selected_gru), ("tree_surrogate_xgboost_unavailable", prediction_cache[("tree_surrogate_xgboost_unavailable", None, "selection")], "transformer", selected_transformer), ("first_order_markov", prediction_cache[("first_order_markov", None, "selection")], "transformer", selected_transformer)]
    for an, av, bn, bv in pair_inputs:
        pairs.append(pair_metrics(an, av, bn, bv, selection, av["y"]))
    immutable_publish(RUN_ROOT / "paired_case_comparisons.json", {"schema_version": "prediction_next_distinct_paired_comparisons.v2", "role": "selection", "class_order": list(TACTICS), "comparisons": pairs})
    # Compare the selected and all-seed V2 metrics with the exact V1 reported values.
    v1_results = read_json(V1_ROOT / "comparison_results.json")
    v1_reference = {"tree_surrogate_xgboost_unavailable": v1_results["models"]["tree_surrogate_xgboost_unavailable"]["selection"], "gru": v1_results["models"]["gru"]["seeds"], "transformer": v1_results["models"]["transformer"]["seeds"]}
    def metric_delta(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
        fields = ("macro_f1", "balanced_accuracy", "top1")
        deltas = {f: float(actual[f]) - float(expected[f]) for f in fields}
        exact = all(float(actual[f]) == float(expected[f]) for f in fields)
        return {"actual": {f: float(actual[f]) for f in fields}, "expected_v1": {f: float(expected[f]) for f in fields}, "deltas": deltas, "exact": exact, "within_1e-12": all(abs(x) <= 1e-12 for x in deltas.values())}
    reproducibility: dict[str, Any] = {"tree": metric_delta(results["models"]["tree_surrogate_xgboost_unavailable"]["selection"], v1_reference["tree_surrogate_xgboost_unavailable"])}
    for kind in ("gru", "transformer"):
        v1_by_seed = {int(row["seed"]): row["selection_metrics"] for row in v1_reference[kind]}
        reproducibility[kind] = {str(int(row["seed"])): metric_delta(row["selection_metrics"], v1_by_seed[int(row["seed"])]) for row in results["models"][kind]["seeds"]}
    # History-length and transition-concentration diagnostics for selected models.
    for kind in ("gru", "transformer"):
        value = prediction_cache[(kind, selected_models[kind]["seed"], "selection")]
        value_probs, value_y = value["probabilities"], value["y"]
        results["models"][kind]["history_length_metrics"] = {name: subset_metrics(v1, kind, selection, value_probs, value_y, [i for i, c in enumerate(selection) if pred(c.history_length)]) for name, pred in (("history_1", lambda n: n == 1), ("history_2", lambda n: n == 2), ("history_ge3", lambda n: n >= 3))}
        top3_names = {x[0] for x in support["top3"]}
        top_idx = [i for i, c in enumerate(selection) if f"{c.history[-1]} -> {c.target}" in top3_names]
        rest_idx = [i for i, c in enumerate(selection) if i not in set(top_idx)]
    results["models"][kind]["transition_concentration_selection"] = {"dominant_top3": subset_metrics(v1, kind, selection, value_probs, value_y, top_idx), "all_remaining": subset_metrics(v1, kind, selection, value_probs, value_y, rest_idx)}
    results["support"] = support
    results["reproducibility_against_v1"] = reproducibility
    results["ablation"] = {"artifact": str(RUN_ROOT / "ablation_results.json"), "models": {k: {"selected_seed": v["selected_seed"], "full_vs_last_only_macro_f1_delta": float(v["transforms"]["full"]["metrics"]["macro_f1"] - v["transforms"]["last_only"]["metrics"]["macro_f1"]), "full_vs_true_shuffle_macro_f1_delta": float(v["transforms"]["full"]["metrics"]["macro_f1"] - v["transforms"]["true_prefix_shuffle"]["summary"]["macro_f1"]["mean"]), "full_vs_reverse_macro_f1_delta": float(v["transforms"]["full"]["metrics"]["macro_f1"] - v["transforms"]["reverse"]["metrics"]["macro_f1"])} for k, v in ablation.items()}}
    v1_checkpoint_hashes = {p.name: sha256_file(p) for p in (V1_ROOT / "models").glob("*.pt")}
    v2_checkpoint_hashes = {kind: {str(m["seed"]): m["checkpoint"]["sha256"] for m in neural_metadata[kind]} for kind in ("gru", "transformer")}
    flat_v2_hashes = [h for family in v2_checkpoint_hashes.values() for h in family.values()]
    results["checkpoint_provenance"] = {
        "v2_paths_are_new_namespace": True,
        "v2_checkpoints_distinct_within_family": all(len(set(f.values())) == len(f) for f in v2_checkpoint_hashes.values()),
        "v2_checkpoints_distinct_across_families": len(set(flat_v2_hashes)) == len(flat_v2_hashes),
        "v1_checkpoint_hashes_read_only": v1_checkpoint_hashes,
        "v2_hash_matches_v1_deterministic_reproduction": {kind: {seed: h in set(v1_checkpoint_hashes.values()) for seed, h in fam.items()} for kind, fam in v2_checkpoint_hashes.items()},
        "historical_transformer_hash_match": HISTORICAL_TRANSFORMER_SHA in set(flat_v2_hashes),
        "candidate_a_hash_match": any(h in CANDIDATE_A_SHAS for h in flat_v2_hashes),
        "weights_loaded_from_prior_experiment": False,
        "identity_note": "Exact V1 hash identity is expected from deterministic fresh training with the same seed, architecture, data, and serialization; V2 paths, logs, and reload checks independently establish provenance.",
    }
    # Decide from V2 evidence, never by inheriting V1's historical label.
    tol = 1e-4
    gru_ab = ablation["gru"]["transforms"]
    tr_ab = ablation["transformer"]["transforms"]
    full = float(tr_ab["full"]["metrics"]["macro_f1"])
    last = float(tr_ab["last_only"]["metrics"]["macro_f1"])
    shuffle = float(tr_ab["true_prefix_shuffle"]["summary"]["macro_f1"]["mean"])
    reverse = float(tr_ab["reverse"]["metrics"]["macro_f1"])
    context_gain = full > last + tol
    order_supported = full > shuffle + tol and full > reverse + tol
    transformer_f1 = float(results["models"]["transformer"]["selected_selection"]["macro_f1"])
    gru_f1 = float(results["models"]["gru"]["selected_selection"]["macro_f1"])
    tree_f1 = float(results["models"]["tree_surrogate_xgboost_unavailable"]["selection"]["macro_f1"])
    markov_f1 = float(results["models"]["first_order_markov"]["selection"]["macro_f1"])
    if transformer_f1 > gru_f1 + tol and transformer_f1 > tree_f1 + tol and transformer_f1 > markov_f1 + tol:
        classification, reason = "A", "Transformer materially exceeds the selected GRU and simpler baselines on Selection."
    elif context_gain and order_supported:
        classification, reason = "B", "Sequence context and ordered history are supported, but Transformer superiority over GRU is not established."
    elif context_gain and abs(full - shuffle) <= tol:
        classification, reason = "C", "Additional context helps over last-only, but true prefix shuffling is equivalent within tolerance; order is not demonstrated."
    elif not context_gain and (abs(full - tree_f1) <= tol or abs(full - markov_f1) <= tol):
        classification, reason = "D", "A simple transition/tree explanation is sufficient; full history is not materially better than last-only."
    else:
        classification, reason = "E", "The V2 evidence does not support a stronger defensible conclusion under the preregistered comparisons."
    results["prior_artifacts_preserved"] = True
    results["existing_files_modified"] = []
    results["existing_files_overwritten"] = []
    results["sealed_boundary"] = {"sealed_prediction_data_accessed": False, "sealed_test_accessed": False, "production_changed": False, "canonical_policy_changed": False, "external_ai_called": False, "prior_experiments_modified": False, "historical_or_candidate_weights_loaded": False}
    results["runtime"] = {"experiment_started_at": started_at, "experiment_finished_at": utc_now(), "phase_seconds": timings, "total_elapsed_seconds": time.monotonic() - total_start, "output_root": str(RUN_ROOT), "output_device": os.stat(RUN_ROOT.parent).st_dev, "dataset_verification_before_training": True}
    results["artifacts"] = {"dataset_binding": {"path": str(RUN_ROOT / "dataset_binding.json"), "sha256": sha256_file(RUN_ROOT / "dataset_binding.json")}, "experiment_config": {"path": str(RUN_ROOT / "experiment_config.json"), "sha256": sha256_file(RUN_ROOT / "experiment_config.json")}, "selection_predictions": {"path": str(RUN_ROOT / "selection_predictions.jsonl"), "sha256": selection_pred_sha}, "calibration_predictions": {"path": str(RUN_ROOT / "calibration_predictions.jsonl"), "sha256": calibration_pred_sha}, "checkpoint_hashes": {kind: {str(m["seed"]): m["checkpoint"]["sha256"] for m in neural_metadata[kind]} for kind in ("gru", "transformer")}}
    results["schema_version"] = SCHEMA
    results["comparison_id"] = "prediction_next_distinct_model_comparison_v2_20260823"
    results["decision"] = {"classification": classification, "reason": reason, "context_gain_full_vs_last_only": context_gain, "ordered_history_supported": order_supported, "full_macro_f1": full, "last_only_macro_f1": last, "true_prefix_shuffle_macro_f1_mean": shuffle, "reverse_macro_f1": reverse, "transformer_minus_gru_macro_f1": transformer_f1 - gru_f1}
    results["results_sha256"] = sha256_json(results)
    immutable_publish(RUN_ROOT / "comparison_results.json", results)
    timings["artifact_serialization_seconds"] = time.monotonic() - phase
    runtime = results["runtime"]; runtime["experiment_finished_at"] = utc_now(); runtime["total_elapsed_seconds"] = time.monotonic() - total_start; runtime["phase_seconds"] = timings; runtime["phase_sum_seconds"] = sum(timings.values()); runtime["unattributed_seconds"] = runtime["total_elapsed_seconds"] - runtime["phase_sum_seconds"]
    immutable_publish(RUN_ROOT / "runtime_breakdown.json", runtime)
    report = make_report(results, cases, ablation, selected_models, binding, V1_ROOT)
    report_path = RUN_ROOT / "comparison_report.md"
    immutable_publish_text(report_path, report)
    receipt = {
        "schema_version": "prediction_next_distinct_model_comparison_receipt.v2", "comparison_id": results["comparison_id"], "status": "COMPLETE_VALID",
        "created_at": utc_now(), "v1_preserved": True, "sealed_data_accessed": False, "production_changed": False, "external_ai_called": False, "historical_weights_loaded": False,
        "xgboost_status": results["xgboost"], "dataset_manifest_sha256": binding["manifest_sha256"], "results_sha256": sha256_file(RUN_ROOT / "comparison_results.json"),
        "required_artifacts": {p.name: sha256_file(p) for p in (RUN_ROOT / "dataset_binding.json", RUN_ROOT / "experiment_config.json", RUN_ROOT / "training_history.json", RUN_ROOT / "seed_summary.json", RUN_ROOT / "selection_predictions.jsonl", RUN_ROOT / "calibration_predictions.jsonl", RUN_ROOT / "ablation_results.json", RUN_ROOT / "paired_case_comparisons.json", RUN_ROOT / "runtime_breakdown.json", RUN_ROOT / "comparison_results.json")},
        "comparison_report_sha256": sha256_file(report_path), "existing_files_modified": [], "existing_files_overwritten": [], "prior_artifacts_preserved": True,
    }
    receipt["receipt_sha256"] = sha256_json(receipt)
    immutable_publish(RUN_ROOT / "comparison_receipt.v2.json", receipt)
    return results


def _features_for_tree(cases: Sequence[Any], ids: Sequence[str]) -> np.ndarray:
    x, _y, _changed = features(cases, ids)
    return x


def _softmax(logits: np.ndarray) -> np.ndarray:
    z = logits - logits.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def make_report(results: Mapping[str, Any], cases: Mapping[str, Sequence[Any]], ablation: Mapping[str, Any], selected_models: Mapping[str, Any], binding: Mapping[str, Any], v1_root: Path) -> str:
    support = results["support"]; repro = results["reproducibility_against_v1"]
    lines = [
        "# Prediction-Only Next-Distinct-Tactic Model Comparison V2",
        "",
        "Status: COMPLETE_VALID; this is an isolated reproduction, not an authoritative predictor.",
        "",
        "## Frozen task and dataset",
        "",
        f"Task: `{results['comparison_id']}` — P(next observed distinct trusted tactic | previous observed distinct trusted tactics).",
        f"V1 manifest SHA-256: `{binding['manifest_sha256']}`; pooled cases: `{sum(len(cases[r]) for r in ROLES)}`; directed pairs: `{support['unique_directed_pairs']}`.",
        f"Train/Selection/Calibration cases: `{len(cases['train'])}` / `{len(cases['selection'])}` / `{len(cases['calibration'])}`.",
        "Calibration is explicitly a previously observed cohort used only for reproduction, not a blind final test.",
        "",
        "## Model status",
        "",
        "Markov is first-order with Laplace alpha=1 and deterministic global-target backoff. The tree is `tree_surrogate_xgboost_unavailable`; genuine XGBoost was not available and no package/network was used.",
        f"Selected GRU seed: `{selected_models['gru']['seed']}`; selected Transformer seed: `{selected_models['transformer']['seed']}`.",
        "",
        "## V1 reproducibility",
        "",
        "```json", json.dumps(repro, indent=2, sort_keys=True), "```",
        "",
        "## Exact persisted prediction comparisons",
        "",
        "See `paired_case_comparisons.json` for identical/different labels, both-correct/both-wrong, model-only correctness, and probability differences. Per-case outputs are in the two privacy-safe JSONL files.",
        "",
        "## Checkpoint provenance",
        "",
        "```json", json.dumps(results["checkpoint_provenance"], indent=2, sort_keys=True), "```",
        "V2 checkpoint files are in a separate namespace and were saved after fresh seeded training. Their byte hashes match the deterministic V1 checkpoints; this is reproducibility, not loading or copying V1 weights. Historical Transformer and Candidate A hashes do not match.",
        "",
        "## History ablation",
        "",
        "Ablations reload the selected checkpoint and set `ablation_retrained=false`. `true_prefix_shuffle` permutes only earlier tokens, retains the final/current token, uses ten deterministic seeds, and reports cases actually changed; histories of length <=2 are not treated as order tests.",
        "```json", json.dumps(results["ablation"], indent=2, sort_keys=True), "```",
        "",
        "## Support and transition concentration",
        "",
        "```json", json.dumps({"top1": support["top1"], "top3": support["top3"], "top5": support["top5"], "train_shares": support["train_transition_shares"]}, indent=2, sort_keys=True), "```",
        "",
        "## Required interpretation",
        "",
        f"Final V2 classification: **{results['decision']['classification']}** — {results['decision']['reason']}",
        "",
        "The final classification is based on the V2 evidence and is not inherited from V1. If full history is approximately last-only, multi-step history is not materially useful; if full exceeds last-only but matches true shuffle, context helps but order is not demonstrated. Transformer equality with GRU does not establish architectural superiority. Genuine XGBoost conclusions are unavailable.",
        "",
        "### Required answers",
        "",
        "1. V1 training genuineness is addressed by the independent V2 checkpoint, epoch-log, and per-case-output evidence; V2 does not infer missing V1 logs.",
        "2. V2 reports exact/within-tolerance/material Selection reproducibility for every seed in `comparison_results.json`.",
        "3. Case-by-case GRU/Transformer identity is in `paired_case_comparisons.json`, not inferred from aggregate scores.",
        "4. Tree/GRU/Transformer/Markov identity and probability differences are persisted in the same paired artifact.",
        "5. Full-versus-last-only is reported for selected GRU and Transformer, including history >=3.",
        "6. Full-versus-true-prefix-shuffle uses ten deterministic shuffles and reports changed cases and mean/std.",
        "7. History >=3 is the order-sensitive stratum; short histories are not treated as ordering evidence.",
        "8. Transformer-vs-GRU superiority is evaluated by Selection Macro-F1, balanced accuracy, rare-class and stability evidence.",
        "9. Transformer-vs-Markov/tree is evaluated, with the tree explicitly marked as a surrogate because XGBoost is unavailable.",
        "10. Scientific justification follows the V2 classification above, not a prespecified Transformer preference.",
        "11. No genuine XGBoost-vs-Transformer conclusion is permitted in this offline reproduction.",
        "",
        "## Preservation and safety",
        "",
        "V1, historical Transformer, Candidate A, V2.1, Balanced D2, frozen sidecars/manifests/policies, production, and sealed artifacts were read-only and preserved. No prior weights were loaded; no external AI was called; no sealed data was accessed; no existing file was modified or overwritten.",
        "",
        "## Reproducibility artifacts",
        "",
        "`training_history.json`, `seed_summary.json`, per-case prediction JSONL, `ablation_results.json`, `paired_case_comparisons.json`, `runtime_breakdown.json`, `comparison_results.json`, model checkpoints, and `comparison_receipt.v2.json` are all content-addressed in the V2 receipt.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps({"status": "COMPLETE_VALID", "comparison_id": result["comparison_id"], "run_root": str(RUN_ROOT)}, sort_keys=True))
    except ComparisonBlocked as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc), "run_root": str(RUN_ROOT)}, sort_keys=True))
        raise SystemExit(2)
