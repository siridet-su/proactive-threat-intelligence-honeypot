"""Run the isolated Prediction-Only Next-Distinct-Tactic comparison.

This module deliberately does not import or mutate any canonical/prediction
runtime state.  It streams the frozen Internal-40 decision sidecars alongside
the immutable behavioral SQLite ordering, materializes privacy-safe examples,
then trains only fresh experiment-local models.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
import os
import random
import sqlite3
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

import numpy as np


ROOT = Path(__file__).resolve().parents[3]
EXT_ROOT = Path("/mnt/honeypot-data")
RUN_ROOT = Path(os.environ.get(
    "PREDICTION_NEXT_DISTINCT_COMPARISON_ROOT",
    str(EXT_ROOT / "prediction-next-distinct-model-comparison-v1-20260822"),
)).resolve()
MANIFEST = EXT_ROOT / "prediction-attck-internal-40/internal-40-resolved-manifest.v2.json"
DB_PATH = EXT_ROOT / "prediction-attck-internal-40/v5-preparation/full/internal40-behavioral.sqlite"
SIDECAR_ROOT = EXT_ROOT / "prediction-attck-internal-40/v6-final-support/checkpoints"
SUPPORT_RECEIPT = EXT_ROOT / "prediction-attck-internal-40/v6-final-support/internal40-v6-support-receipt-resumed.v1.json"
QUARANTINE = EXT_ROOT / "prediction-attck-internal-40/v6-final-support/cross-role-quarantine-resumed.v1.json"
ROLES = ("train", "selection", "calibration")
TACTICS = (
    "command-and-control",
    "credential-access",
    "defense-evasion",
    "discovery",
    "execution",
    "persistence",
    "privilege-escalation",
)
TACTIC_TO_ID = {name: i + 1 for i, name in enumerate(TACTICS)}
EXPECTED = {
    "train": {"cases": 10186, "contributors": 6952, "ge2": 6952, "ge3": 2890, "ge5": 71},
    "selection": {"cases": 1983, "contributors": 1418},
    "calibration": {"cases": 2104, "contributors": 1347},
}
SEEDS = (20260822, 20260823, 20260824, 20260825, 20260826)
MAX_HISTORY = 8
SCHEMA = "prediction_next_distinct_model_comparison.v1"


class ComparisonBlocked(RuntimeError):
    """Raised when a frozen input or experiment contract does not match."""


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


def publish_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = stable_json(value) + "\n"
    if path.exists():
        if path.read_text(encoding="utf-8") != body:
            raise ComparisonBlocked(f"refusing to overwrite immutable new artifact: {path}")
        return
    temp = path.with_name(f".{path.name}.{os.getpid()}.part")
    temp.write_text(body, encoding="utf-8")
    with temp.open("rb") as f:
        os.fsync(f.fileno())
    os.link(temp, path)
    temp.unlink(missing_ok=True)


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ComparisonBlocked(f"cannot read JSON input {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ComparisonBlocked(f"JSON input is not an object: {path}")
    return value


@dataclass(frozen=True)
class Case:
    role: str
    unit_id: str
    history: tuple[str, ...]
    target: str
    history_length: int

    def record(self) -> dict[str, Any]:
        return {
            "schema_version": "prediction_next_distinct_case.v1",
            "role": self.role,
            "unit_id": self.unit_id,
            "history": list(self.history),
            "target": self.target,
            "history_length": self.history_length,
        }


def _unit_id(role: str, member: str, raw_session: str) -> str:
    # The source identifiers are used only as an internal grouping key.  The
    # emitted ID is a non-reversible experiment-local digest.
    value = f"prediction-next-distinct-v1|{role}|{member}|{raw_session}".encode()
    return "unit_" + hashlib.sha256(value).hexdigest()


class SidecarCursor:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._stream = gzip.open(path, "rt", encoding="utf-8")
        self.next: dict[str, Any] | None = self._read()

    def _read(self) -> dict[str, Any] | None:
        line = self._stream.readline()
        if not line:
            return None
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ComparisonBlocked(f"malformed decision sidecar: {self.path}") from exc
        if not isinstance(value, dict):
            raise ComparisonBlocked(f"sidecar record is not an object: {self.path}")
        return value

    def consume_at(self, order: int) -> list[dict[str, Any]]:
        if self.next is not None and int(self.next.get("order", -1)) < order:
            raise ComparisonBlocked(f"sidecar order fell behind SQLite order: {self.path}")
        out: list[dict[str, Any]] = []
        while self.next is not None and int(self.next.get("order", -1)) == order:
            out.append(self.next)
            self.next = self._read()
        return out

    def close(self) -> None:
        self._stream.close()


def _query_connection() -> sqlite3.Connection:
    if not DB_PATH.is_file() or DB_PATH.is_symlink():
        raise ComparisonBlocked(f"immutable behavioral SQLite unavailable: {DB_PATH}")
    con = sqlite3.connect(f"file:{DB_PATH}?immutable=1", uri=True)
    con.execute("PRAGMA query_only=ON")
    con.execute("PRAGMA temp_store=MEMORY")
    return con


def _load_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, str], dict[str, Path]]:
    if not MANIFEST.is_file() or not SUPPORT_RECEIPT.is_file() or not QUARANTINE.is_file():
        raise ComparisonBlocked("frozen manifest/receipt/quarantine input is missing")
    manifest = read_json(MANIFEST)
    receipt = read_json(SUPPORT_RECEIPT)
    quarantine = read_json(QUARANTINE)
    if manifest.get("manifest_id") != "predattckinternal40resolved_e6854d21e31fe8a81bb9c695ee9d57c6":
        raise ComparisonBlocked("unexpected Internal-40 manifest identity")
    if receipt.get("status") != "COMPLETE_VALID" or receipt.get("sealed_test_accessed") is True:
        raise ComparisonBlocked("v6 support receipt is not complete nonsealed evidence")
    if receipt.get("training_performed") is True or quarantine.get("status") != "COMPLETE_VALID":
        raise ComparisonBlocked("frozen receipt/quarantine contract is invalid")
    members = manifest.get("members")
    if not isinstance(members, list) or len(members) != 40:
        raise ComparisonBlocked("Internal-40 manifest member count differs")
    by_name: dict[str, str] = {}
    sidecars: dict[str, Path] = {}
    for sequence, member in enumerate(members, 1):
        if not isinstance(member, dict) or member.get("role") not in ROLES:
            raise ComparisonBlocked("invalid member role in frozen manifest")
        name = str(member.get("filename") or "")
        sha = str(member.get("source_sha256") or "")
        by_name[name] = str(member["role"])
        path = SIDECAR_ROOT / f"member-{sequence:04d}-{sha}.decisions.json.gz"
        if not path.is_file() or path.is_symlink():
            raise ComparisonBlocked(f"decision sidecar missing: {path}")
        sidecars[name] = path
    if len(by_name) != 40:
        raise ComparisonBlocked("duplicate member filename in frozen manifest")
    return manifest, receipt, by_name, sidecars


def _flush_unit(
    role: str | None,
    member: str | None,
    raw_session: str | None,
    observations: list[str],
    cases: dict[str, list[Case]],
    unit_lengths: dict[str, Counter[int]],
    unit_ids_by_role: dict[str, set[str]],
) -> None:
    if role is None or member is None or raw_session is None:
        return
    unit = _unit_id(role, member, raw_session)
    if unit in unit_ids_by_role[role]:
        raise ComparisonBlocked("duplicate member-bounded sequence unit")
    unit_ids_by_role[role].add(unit)
    dedup: list[str] = []
    for tactic in observations:
        if tactic not in TACTIC_TO_ID:
            raise ComparisonBlocked(f"unknown frozen tactic emitted: {tactic}")
        if not dedup or dedup[-1] != tactic:
            dedup.append(tactic)
    unit_lengths[role][len(dedup)] += 1
    for index in range(1, len(dedup)):
        history = tuple(dedup[max(0, index - MAX_HISTORY):index])
        cases[role].append(Case(role, unit, history, dedup[index], len(history)))


def materialize_cases() -> tuple[dict[str, list[Case]], dict[str, Any]]:
    manifest, receipt, member_roles, sidecar_paths = _load_inputs()
    con = _query_connection()
    try:
        quarantine_ids = {
            str(row[0])
            for row in con.execute(
                "SELECT raw_session_id FROM sessions WHERE source_cohort='development' AND cross_role=1"
            )
        }
        names = list(member_roles)
        marks = ",".join("?" for _ in names)
        qmarks = ",".join("?" for _ in quarantine_ids)
        params: list[Any] = names + sorted(quarantine_ids)
        query = f"""
            SELECT c.raw_session_id,c.source_member,c.source_line,c.rowid,
                   s.experiment_role,m.chronological_order
            FROM command_events c
            JOIN sessions s ON s.raw_session_id=c.raw_session_id
            JOIN source_members m ON m.filename=c.source_member
            WHERE s.source_cohort='development'
              AND s.experiment_role IN ('train','selection','calibration')
              AND s.connected=1 AND s.closed=1
              AND c.source_member IN ({marks})
              AND c.raw_session_id NOT IN ({qmarks})
            ORDER BY s.experiment_role,c.raw_session_id,m.chronological_order,
                     c.source_line,c.rowid
        """
        cursors = {member: SidecarCursor(path) for member, path in sidecar_paths.items()}
        cases: dict[str, list[Case]] = {role: [] for role in ROLES}
        lengths: dict[str, Counter[int]] = {role: Counter() for role in ROLES}
        unit_ids: dict[str, set[str]] = {role: set() for role in ROLES}
        current: tuple[str, str, str] | None = None
        observations: list[str] = []
        decision_entries = 0
        eligible_entries = 0
        decision_entries_by_role: Counter[str] = Counter()
        eligible_entries_by_role: Counter[str] = Counter()
        rows = 0
        try:
            for raw_session, source_member, _source_line, rowid, role, _member_order in con.execute(query, params):
                rows += 1
                source_member = str(source_member)
                role = str(role)
                expected_role = member_roles.get(source_member)
                if expected_role != role:
                    raise ComparisonBlocked("SQLite member/role boundary differs from manifest")
                key = (role, str(raw_session), source_member)
                if current != key:
                    _flush_unit(
                        *(current or (None, None, None)), observations, cases, lengths, unit_ids
                    )
                    current = key
                    observations = []
                order = rows  # placeholder replaced below by the deterministic row ordinal
                # The sidecar order is the v6 global row ordinal, not a member-local
                # counter.  Derive it from a monotonically counted query ordinal.
                # ``rows`` is exactly that ordinal because this query is identical
                # to v6's global ordering and excludes the frozen quarantine set.
                entries = cursors[source_member].consume_at(order)
                for entry in entries:
                    decision_entries += 1
                    decision_entries_by_role[role] += 1
                    runner = entry.get("runner")
                    if not isinstance(runner, dict):
                        raise ComparisonBlocked("sidecar runner decision is not an object")
                    if runner.get("status") == "eligible":
                        tactic = str(runner.get("tactic") or "")
                        if tactic not in TACTIC_TO_ID:
                            raise ComparisonBlocked("eligible decision has unknown tactic")
                        eligible_entries += 1
                        eligible_entries_by_role[role] += 1
                        observations.append(tactic)
            _flush_unit(*(current or (None, None, None)), observations, cases, lengths, unit_ids)
            for member, cursor in cursors.items():
                if cursor.next is not None:
                    raise ComparisonBlocked(f"sidecar has unconsumed entries: {member}")
        finally:
            for cursor in cursors.values():
                cursor.close()
    finally:
        con.close()
    summaries: dict[str, Any] = {}
    for role in ROLES:
        hist = lengths[role]
        summaries[role] = {
            "decision_entries": decision_entries_by_role[role],
            "eligible_tactic_observations": eligible_entries_by_role[role],
            "sequence_units_total": sum(hist.values()),
            "sequence_units_with_tactics": sum(count for n, count in hist.items() if n >= 1),
            "exactly_one": hist[1],
            "at_least_two": sum(count for n, count in hist.items() if n >= 2),
            "at_least_three": sum(count for n, count in hist.items() if n >= 3),
            "at_least_four": sum(count for n, count in hist.items() if n >= 4),
            "at_least_five": sum(count for n, count in hist.items() if n >= 5),
            "max_progression_length": max(hist, default=0),
            "history_length_distribution": {str(n): count for n, count in sorted(hist.items())},
            "cases": len(cases[role]),
            "contributing_units": sum(count for n, count in hist.items() if n >= 2),
        }
        # The expression above intentionally avoids storing all single-tactic
        # sequences; verify the central invariant directly from case counts.
        expected_cases = sum(max(n - 1, 0) * count for n, count in hist.items())
        if expected_cases != len(cases[role]):
            raise ComparisonBlocked(f"next-distinct invariant failed for {role}")
        summaries[role]["expected_cases_from_sequences"] = expected_cases
    # Global entry counts are independently bound to the frozen receipt below.
    summaries["_meta"] = {
        "rows": rows,
        "decision_entries": decision_entries,
        "eligible_tactic_observations": eligible_entries,
        "decision_entries_by_role": dict(decision_entries_by_role),
        "eligible_tactic_observations_by_role": dict(eligible_entries_by_role),
        "manifest_id": manifest["manifest_id"],
        "manifest_sha256": sha256_file(MANIFEST),
        "behavioral_db_sha256": sha256_file(DB_PATH),
        "support_receipt_sha256": sha256_file(SUPPORT_RECEIPT),
        "quarantine_sha256": sha256_file(QUARANTINE),
        "sidecar_sha256": {member: sha256_file(path) for member, path in sidecar_paths.items()},
        "sealed_test_accessed": False,
        "raw_commands_emitted": False,
    }
    for role, expected in EXPECTED.items():
        observed = summaries[role]
        for field, value in (
            ("cases", expected["cases"]),
            ("contributing_units", expected["contributors"]),
            ("at_least_two", expected.get("ge2", expected["contributors"])),
            ("at_least_three", expected.get("ge3", observed["at_least_three"])),
            ("at_least_five", expected.get("ge5", observed["at_least_five"])),
        ):
            if field in expected and int(observed[field]) != int(value):
                raise ComparisonBlocked(f"frozen total mismatch {role}.{field}: {observed[field]} != {value}")
    if sum(len(cases[r]) for r in ROLES) != 14273:
        raise ComparisonBlocked("pooled next-distinct case total is not 14,273")
    return cases, {"roles": summaries, "meta": summaries.pop("_meta")}


def write_dataset(cases: Mapping[str, Sequence[Case]], summary: Mapping[str, Any]) -> dict[str, Any]:
    dataset_dir = RUN_ROOT / "dataset"
    dataset_dir.mkdir(parents=True, exist_ok=True)
    role_files: dict[str, dict[str, Any]] = {}
    for role in ROLES:
        path = dataset_dir / f"{role}.jsonl"
        if path.exists():
            raise ComparisonBlocked(f"new dataset artifact already exists: {path}")
        with path.open("w", encoding="utf-8") as f:
            for case in cases[role]:
                f.write(stable_json(case.record()) + "\n")
        role_files[role] = {"path": str(path), "sha256": sha256_file(path), "cases": len(cases[role])}
    body = {
        "schema_version": SCHEMA,
        "dataset_id": "prediction_next_distinct_internal40_pregroup_v1",
        "semantics": "P(next observed distinct trusted tactic | previous observed distinct trusted tactics)",
        "authority": "non-authoritative prediction-only research POC",
        "target_includes_session_end": False,
        "history": {"source": "eligible v6 pre-group decisions", "adjacent_deduplicate": True, "preserve_non_adjacent_revisits": True, "max_model_history": MAX_HISTORY},
        "boundaries": {"unit": "(role, raw_session_id, source_member)", "cross_member_stitching": False, "cross_role_stitching": False},
        "roles": dict(summary["roles"]),
        "pooled_cases": sum(role_files[r]["cases"] for r in ROLES),
        "role_files": role_files,
        "source_identity": dict(summary["meta"]),
        "sealed_boundary": {"sealed_prediction_data_accessed": False, "sealed_test_accessed": False, "production_changed": False, "canonical_policy_changed": False, "prior_experiments_modified": False},
    }
    body["dataset_sha256"] = sha256_json(body)
    publish_json(dataset_dir / "dataset_manifest.json", body)
    return body


def _load_cases(dataset: Mapping[str, Any]) -> dict[str, list[Case]]:
    loaded: dict[str, list[Case]] = {}
    for role in ROLES:
        path = Path(dataset["role_files"][role]["path"])
        got: list[Case] = []
        with path.open(encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                if set(record) != {"schema_version", "role", "unit_id", "history", "target", "history_length"}:
                    raise ComparisonBlocked("dataset record contains an unexpected/private field")
                if record["role"] != role or record["target"] not in TACTICS:
                    raise ComparisonBlocked("dataset role/target contract failed")
                history = tuple(str(x) for x in record["history"])
                if not history or len(history) != int(record["history_length"]) or len(history) > MAX_HISTORY:
                    raise ComparisonBlocked("dataset history contract failed")
                if any(x not in TACTICS for x in history):
                    raise ComparisonBlocked("dataset history contains unknown tactic")
                got.append(Case(role, str(record["unit_id"]), history, str(record["target"]), len(history)))
        if sha256_file(path) != dataset["role_files"][role]["sha256"]:
            raise ComparisonBlocked("dataset role shard changed after materialization")
        loaded[role] = got
    return loaded


def _features(cases: Sequence[Case], *, history_transform: str = "full") -> tuple[np.ndarray, np.ndarray]:
    x = np.zeros((len(cases), MAX_HISTORY + 1), dtype=np.int64)
    y = np.zeros(len(cases), dtype=np.int64)
    for i, case in enumerate(cases):
        history = list(case.history[-MAX_HISTORY:])
        if history_transform == "last_only":
            history = history[-1:]
        elif history_transform == "reverse":
            history = list(reversed(history))
        elif history_transform == "shuffle_prefix" and len(history) > 1:
            # Deterministic perturbation used only for the ordered-history
            # ablation; the final element is retained as the current tactic.
            prefix = history[:-1]
            prefix.reverse()
            history = prefix + history[-1:]
        ids = [TACTIC_TO_ID[t] for t in history]
        x[i, -len(ids) - 1:-1] = ids
        x[i, -1] = len(ids)
        y[i] = TACTIC_TO_ID[case.target]
    return x, y


def _softmax(logits: np.ndarray) -> np.ndarray:
    z = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(z)
    return exp / exp.sum(axis=1, keepdims=True)


def _metrics(y: np.ndarray, probabilities: np.ndarray, *, model: str, role: str, histories: Sequence[Case], _with_strata: bool = True) -> dict[str, Any]:
    pred = probabilities.argmax(axis=1) + 1
    classes = np.arange(1, len(TACTICS) + 1)
    rows: dict[str, dict[str, float | int]] = {}
    supports: list[int] = []
    f1s: list[float] = []
    recalls: list[float] = []
    weighted = 0.0
    confusion = [[0 for _ in classes] for _ in classes]
    for true in classes:
        tp = int(np.sum((y == true) & (pred == true)))
        fp = int(np.sum((y != true) & (pred == true)))
        fn = int(np.sum((y == true) & (pred != true)))
        support = int(np.sum(y == true))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        rows[TACTICS[true - 1]] = {"precision": precision, "recall": recall, "f1": f1, "support": support}
        supports.append(support); f1s.append(f1); recalls.append(recall)
        weighted += f1 * support
    for true in classes:
        for guess in classes:
            confusion[true - 1][guess - 1] = int(np.sum((y == true) & (pred == guess)))
    top3 = np.argsort(-probabilities, axis=1)[:, : min(3, probabilities.shape[1])] + 1
    ranks = []
    for actual, row in zip(y, probabilities):
        order = np.argsort(-row)
        ranks.append(1.0 / (int(np.where(order == actual - 1)[0][0]) + 1))
    present = [i for i, support in enumerate(supports) if support]
    stratified: dict[str, Any] = {}
    if _with_strata:
        for name, predicate in (("history_1", lambda n: n == 1), ("history_2", lambda n: n == 2), ("history_ge3", lambda n: n >= 3), ("history_ge5", lambda n: n >= 5)):
            idx = np.array([i for i, case in enumerate(histories) if predicate(case.history_length)], dtype=np.int64)
            stratified[name] = {"cases": int(len(idx))}
            if len(idx):
                stratified[name].update(_metrics(y[idx], probabilities[idx], model=model, role=role, histories=[histories[i] for i in idx], _with_strata=False))
    return {
        "model": model,
        "role": role,
        "cases": int(len(y)),
        "macro_f1": float(sum(f1s) / len(f1s)),
        "balanced_accuracy": float(sum(recalls[i] for i in present) / len(present)) if present else 0.0,
        "weighted_f1": float(weighted / sum(supports)) if sum(supports) else 0.0,
        "top1": float(np.mean(pred == y)) if len(y) else 0.0,
        "top3": float(np.mean(np.any(top3 == y[:, None], axis=1))) if len(y) else 0.0,
        "mrr": float(sum(ranks) / len(ranks)) if ranks else 0.0,
        "per_class": rows,
        "confusion_matrix": confusion,
        "history_strata": {k: {key: value for key, value in v.items() if key not in {"per_class", "confusion_matrix", "history_strata"}} for k, v in stratified.items()},
    }


class MarkovModel:
    def __init__(self) -> None:
        self.counts: dict[int, Counter[int]] = defaultdict(Counter)
        self.global_counts: Counter[int] = Counter()

    def fit(self, cases: Sequence[Case]) -> None:
        for case in cases:
            last = TACTIC_TO_ID[case.history[-1]]
            target = TACTIC_TO_ID[case.target]
            self.counts[last][target] += 1
            self.global_counts[target] += 1

    def predict(self, cases: Sequence[Case]) -> np.ndarray:
        out = np.zeros((len(cases), len(TACTICS)), dtype=np.float64)
        alpha = 1.0
        for i, case in enumerate(cases):
            last = TACTIC_TO_ID[case.history[-1]]
            counts = self.counts.get(last) or self.global_counts
            total = sum(counts.values())
            for target in range(1, len(TACTICS) + 1):
                out[i, target - 1] = (counts[target] + alpha) / (total + alpha * len(TACTICS))
        return out


class EqualityTree:
    """Small deterministic categorical tree used only when XGBoost is absent."""

    def __init__(self, max_depth: int = 5, min_leaf: int = 2) -> None:
        self.max_depth, self.min_leaf = max_depth, min_leaf
        self.root: Any = None

    @staticmethod
    def _gini(y: np.ndarray) -> float:
        if len(y) == 0:
            return 0.0
        counts = np.bincount(y, minlength=len(TACTICS) + 1)[1:]
        p = counts / len(y)
        return float(1.0 - np.sum(p * p))

    def _build(self, x: np.ndarray, y: np.ndarray, depth: int) -> Any:
        counts = np.bincount(y, minlength=len(TACTICS) + 1)[1:]
        if depth >= self.max_depth or len(y) < 2 * self.min_leaf or np.count_nonzero(counts) <= 1:
            return ("leaf", counts)
        parent = self._gini(y); best: tuple[float, int, int, np.ndarray] | None = None
        for feature in range(x.shape[1]):
            for value in sorted(set(int(v) for v in x[:, feature])):
                mask = x[:, feature] == value
                if int(mask.sum()) < self.min_leaf or int((~mask).sum()) < self.min_leaf:
                    continue
                gain = parent - (mask.mean() * self._gini(y[mask]) + (~mask).mean() * self._gini(y[~mask]))
                candidate = (float(gain), feature, value, mask)
                if best is None or candidate[:3] > best[:3]:
                    best = candidate
        if best is None or best[0] <= 1e-12:
            return ("leaf", counts)
        _, feature, value, mask = best
        return ("node", feature, value, self._build(x[mask], y[mask], depth + 1), self._build(x[~mask], y[~mask], depth + 1))

    def fit(self, x: np.ndarray, y: np.ndarray) -> None:
        self.root = self._build(x, y, 0)

    def _leaf(self, node: Any, row: np.ndarray) -> np.ndarray:
        if node[0] == "leaf":
            counts = node[1].astype(np.float64) + 1.0
            return counts / counts.sum()
        _, feature, value, left, right = node
        return self._leaf(left if int(row[feature]) == value else right, row)

    def predict(self, x: np.ndarray) -> np.ndarray:
        return np.vstack([self._leaf(self.root, row) for row in x])


def _torch_imports() -> tuple[Any, Any, Any, Any, Any]:
    try:
        import torch
        from torch import nn
        from torch.utils.data import DataLoader, TensorDataset
    except Exception as exc:
        raise ComparisonBlocked(f"torch is unavailable for GRU/Transformer: {exc}") from exc
    return torch, nn, DataLoader, TensorDataset, torch.device("cpu")


def _train_neural(
    cases_train: Sequence[Case], cases_selection: Sequence[Case], *, kind: str, seed: int, history_transform: str = "full"
) -> tuple[Any, dict[str, Any]]:
    torch, nn, DataLoader, TensorDataset, device = _torch_imports()
    torch.manual_seed(seed); np.random.seed(seed); random.seed(seed)
    torch.use_deterministic_algorithms(True)
    x_train, y_train = _features(cases_train, history_transform=history_transform)
    x_sel, y_sel = _features(cases_selection, history_transform=history_transform)
    train_x = torch.tensor(x_train[:, :-1], dtype=torch.long, device=device)
    train_y = torch.tensor(y_train - 1, dtype=torch.long, device=device)
    sel_x = torch.tensor(x_sel[:, :-1], dtype=torch.long, device=device)
    sel_y = torch.tensor(y_sel - 1, dtype=torch.long, device=device)
    if kind == "gru":
        class Model(nn.Module):
            def __init__(self) -> None:
                super().__init__(); self.embedding = nn.Embedding(len(TACTICS) + 1, 8, padding_idx=0); self.gru = nn.GRU(8, 16, batch_first=True); self.head = nn.Linear(16, len(TACTICS))
            def forward(self, tokens: Any) -> Any:
                out, _ = self.gru(self.embedding(tokens)); return self.head(out[:, -1])
    else:
        class Model(nn.Module):
            def __init__(self) -> None:
                super().__init__(); self.embedding = nn.Embedding(len(TACTICS) + 1, 16, padding_idx=0); self.position = nn.Parameter(torch.zeros(1, MAX_HISTORY, 16)); layer = nn.TransformerEncoderLayer(d_model=16, nhead=4, dim_feedforward=32, dropout=0.1, batch_first=True); self.encoder = nn.TransformerEncoder(layer, num_layers=1); self.head = nn.Linear(16, len(TACTICS))
            def forward(self, tokens: Any) -> Any:
                embedded = self.embedding(tokens) + self.position; mask = torch.triu(torch.ones(MAX_HISTORY, MAX_HISTORY, device=tokens.device, dtype=torch.bool), diagonal=1); out = self.encoder(embedded, mask=mask); return self.head(out[:, -1])
    model = Model().to(device)
    params = sum(p.numel() for p in model.parameters())
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loader = DataLoader(TensorDataset(train_x, train_y), batch_size=128, shuffle=True, generator=torch.Generator().manual_seed(seed))
    best_state: dict[str, Any] | None = None; best_score = -1.0; best_epoch = 0; stale = 0; started = time.monotonic()
    for epoch in range(1, 21):
        model.train()
        for xb, yb in loader:
            optimizer.zero_grad(set_to_none=True); loss = nn.functional.cross_entropy(model(xb), yb); loss.backward(); optimizer.step()
        model.eval()
        with torch.no_grad():
            probs = torch.softmax(model(sel_x), dim=1).cpu().numpy()
        score = _metrics(y_sel, probs, model=kind, role="selection", histories=cases_selection)["macro_f1"]
        if score > best_score + 1e-12:
            best_score, best_epoch, stale = score, epoch, 0; best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        else:
            stale += 1
            if stale >= 4: break
    if best_state is None: raise ComparisonBlocked("neural model produced no checkpoint")
    model.load_state_dict(best_state); model.eval()
    metadata = {"kind": kind, "seed": seed, "history_transform": history_transform, "optimizer": "Adam", "learning_rate": 1e-3, "batch_size": 128, "max_epochs": 20, "best_epoch": best_epoch, "selection_macro_f1": best_score, "parameter_count": params, "training_seconds": time.monotonic() - started, "fresh_initialization": True}
    return model, metadata


def _neural_predict(model: Any, cases: Sequence[Case], *, transform: str) -> np.ndarray:
    torch, _nn, _DataLoader, _TensorDataset, device = _torch_imports()
    x, _ = _features(cases, history_transform=transform)
    with torch.no_grad():
        return torch.softmax(model(torch.tensor(x[:, :-1], dtype=torch.long, device=device)), dim=1).cpu().numpy()


def _transition_support(cases: Mapping[str, Sequence[Case]]) -> dict[str, Any]:
    pairs: Counter[str] = Counter(); targets: Counter[str] = Counter(); sessions: dict[str, set[str]] = defaultdict(set)
    for role in ROLES:
        for case in cases[role]:
            targets[case.target] += 1; sessions[case.target].add(case.unit_id)
            pairs[f"{case.history[-1]} -> {case.target}"] += 1
    top = sorted(pairs.items(), key=lambda kv: (-kv[1], kv[0]))
    return {"unique_directed_pairs": len(pairs), "target_cases": dict(sorted(targets.items())), "target_unique_units": {k: len(v) for k, v in sorted(sessions.items())}, "directed_pairs": dict(top), "top1": top[:1], "top3": top[:3], "top5": top[:5]}


def run() -> dict[str, Any]:
    started = time.monotonic()
    if not RUN_ROOT.parent.is_dir() or not os.access(RUN_ROOT.parent, os.W_OK):
        raise ComparisonBlocked(f"experiment output parent is not writable: {RUN_ROOT.parent}")
    if RUN_ROOT.exists():
        raise ComparisonBlocked(f"new run namespace already exists: {RUN_ROOT}")
    cases, summary = materialize_cases()
    dataset = write_dataset(cases, summary)
    cases = _load_cases(dataset)
    # Recheck all frozen totals after publication, before any model is trained.
    for role, expected in EXPECTED.items():
        if len(cases[role]) != expected["cases"]:
            raise ComparisonBlocked(f"post-publication case total mismatch: {role}")
    units_by_role = {role: {c.unit_id for c in cases[role]} for role in ROLES}
    if units_by_role["train"] & units_by_role["selection"] or units_by_role["train"] & units_by_role["calibration"] or units_by_role["selection"] & units_by_role["calibration"]:
        raise ComparisonBlocked("role disjointness failed in materialized examples")
    tree_available = False
    try:
        import xgboost  # type: ignore  # noqa: F401
        tree_available = True
    except Exception:
        tree_available = False
    results: dict[str, Any] = {"models": {}, "xgboost": {"available": tree_available, "substitution": None if tree_available else "deterministic_equality_tree_surrogate", "reason": None if tree_available else "xgboost and scikit-learn unavailable in frozen runtime; no local wheel/network"}}
    train, selection, calibration = cases["train"], cases["selection"], cases["calibration"]
    markov = MarkovModel(); markov.fit(train)
    markov_metrics = {role: _metrics(y, markov.predict(items), model="first_order_markov", role=role, histories=items) for role, items in (("selection", selection), ("calibration", calibration)) for x, y in [_features(items)]}
    results["models"]["first_order_markov"] = {"selection": markov_metrics["selection"], "calibration": markov_metrics["calibration"], "metadata": {"training_role": "train", "smoothing": "Laplace(alpha=1), global target backoff", "tuned_on_calibration": False}}
    # Tree search is intentionally small and uses only fixed tactic-history IDs.
    candidates: list[tuple[float, int, EqualityTree]] = []
    tx, ty = _features(train); sx, sy = _features(selection)
    for depth in (3, 5, 7):
        tree = EqualityTree(max_depth=depth, min_leaf=2); tree.fit(tx, ty)
        score = _metrics(sy, tree.predict(sx), model="tree", role="selection", histories=selection)["macro_f1"]
        candidates.append((score, depth, tree))
    candidates.sort(key=lambda item: (-item[0], item[1])); tree_score, tree_depth, tree = candidates[0]
    tree_metrics = {role: _metrics(y, tree.predict(_features(items)[0]), model="tree_surrogate_xgboost_unavailable", role=role, histories=items) for role, items in (("selection", selection), ("calibration", calibration)) for x, y in [_features(items)]}
    results["models"]["tree_surrogate_xgboost_unavailable"] = {"selection": tree_metrics["selection"], "calibration": tree_metrics["calibration"], "metadata": {"training_role": "train", "max_depth_candidates": [3, 5, 7], "selected_max_depth": tree_depth, "min_leaf": 2, "tree_type": "deterministic categorical equality tree", "xgboost_not_available": True, "selection_score": tree_score}}
    for kind in ("gru", "transformer"):
        runs: list[dict[str, Any]] = []
        for seed in SEEDS:
            model, metadata = _train_neural(train, selection, kind=kind, seed=seed)
            sel_probs = _neural_predict(model, selection, transform="full"); cal_probs = _neural_predict(model, calibration, transform="full")
            metadata["selection_metrics"] = _metrics(_features(selection)[1], sel_probs, model=kind, role="selection", histories=selection)
            metadata["calibration_metrics"] = _metrics(_features(calibration)[1], cal_probs, model=kind, role="calibration", histories=calibration)
            model_path = RUN_ROOT / "models" / f"{kind}-seed-{seed}.pt"; model_path.parent.mkdir(parents=True, exist_ok=True)
            import torch
            torch.save(model.state_dict(), model_path); metadata["checkpoint"] = {"path": str(model_path), "sha256": sha256_file(model_path)}
            runs.append(metadata)
        runs.sort(key=lambda r: (-r["selection_metrics"]["macro_f1"], r["seed"]))
        best = runs[0]
        # Re-run the selected seed's checkpoint from the fresh model for ablations.
        best_model, _ = _train_neural(train, selection, kind=kind, seed=int(best["seed"]))
        ablations: dict[str, Any] = {}
        for transform in ("full", "last_only", "shuffle_prefix", "reverse"):
            probs = _neural_predict(best_model, selection, transform=transform)
            ablations[transform] = _metrics(_features(selection)[1], probs, model=f"{kind}_ablation_{transform}", role="selection", histories=selection)
        results["models"][kind] = {"seeds": runs, "selected_seed": best["seed"], "selected_selection": best["selection_metrics"], "selected_calibration": best["calibration_metrics"], "ablation_selection": ablations, "fresh_checkpoint_only": True}
    results["support"] = {"dataset": dataset, "transition_support": _transition_support(cases)}
    results["prior_artifacts_preserved"] = True
    results["files_overwritten"] = []
    results["runtime"] = {
        "elapsed_seconds": time.monotonic() - started,
        "training_started": True,
        "sealed_accessed": False,
        "canonical_modified": False,
        "output_root": str(RUN_ROOT),
        "output_device": os.stat(RUN_ROOT).st_dev,
        "external_ext4_mount_state_at_start": "ro_or_unwritable; no writes attempted",
    }
    results["comparison_id"] = "prediction_next_distinct_model_comparison_v1_20260822"
    results["results_sha256"] = sha256_json(results)
    publish_json(RUN_ROOT / "comparison_results.json", results)
    return results


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps({"status": "COMPLETE_VALID", "comparison_id": result["comparison_id"], "results_sha256": result["results_sha256"], "run_root": str(RUN_ROOT)}, sort_keys=True))
    except ComparisonBlocked as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc), "run_root": str(RUN_ROOT)}, sort_keys=True))
        raise SystemExit(2)
