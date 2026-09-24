"""Fail-closed experimental Model2 projection from a verified 32F row.

This changes only the model input, not retained network evidence. The old
measurement remains available for audit. No Cowrie outcome or technique label
is consulted when selecting the exact backend SSH flow.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import statistics
from collections import Counter
from typing import Any, Mapping


FEATURE_ORDER = (
    "v7_c_auth_attempt_count_episode", "v7_c_auth_failure_count_episode",
    "v7_c_auth_success_count_episode", "v7_c_auth_attempt_rate_episode",
    "v7_c_auth_failure_rate_episode", "v7_c_auth_failure_fraction_episode",
    "v7_c_auth_max_failure_streak_episode", "v7_c_auth_event_span_s_episode",
    "v7_c_auth_interarrival_median_s_episode", "v7_c_auth_interarrival_iqr_s_episode",
    "v7_c_auth_interarrival_cv_episode", "v7_c_burst_window_count_episode",
    "v7_c_preauth_session_count_episode", "v7_c_authenticated_session_count_episode",
    "v7_c_session_duration_median_s_episode", "v7_c_failed_to_success_transition_count_episode",
    "v7_cowrie_event_count_episode", "v7_z_connection_count_episode",
    "v7_z_distinct_destination_port_count_episode", "v7_z_port_fanout_ratio_episode",
    "v7_z_connection_rate_per_s_episode", "v7_z_destination_port_entropy_episode",
    "v7_z_protocol_diversity_episode", "v7_z_flow_count_episode",
    "v7_z_orig_bytes_sum_episode", "v7_z_resp_bytes_sum_episode",
    "v7_z_orig_packets_sum_episode", "v7_z_resp_packets_sum_episode",
    "v7_z_duration_sum_s_episode", "v7_z_duration_median_s_episode",
    "v7_z_failed_connection_fraction_episode", "v7_z_interarrival_cv_episode",
)
FAILED_STATES = frozenset({"S0", "REJ", "RSTO", "RSTR", "OTH", "ERR"})


SOURCE_SCHEMA_SHA256 = "cf985643ce89c3d1f86f6c45943c3ba3af6cf13c60c4b41e215c7c7bc8990a20"
PROJECTION_CONTRACT = {
    "schema_version": "model2_backend_ssh_only_projection.v1",
    "source_feature_schema_sha256": SOURCE_SCHEMA_SHA256,
    "feature_order": list(FEATURE_ORDER),
    "cowrie_features": "copy_verified_source_values_0_16",
    "network_features": "recompute_15_from_one_exact_backend_ssh_tuple",
    "flow_selection": "exact_cowrie_backend_tuple_only_no_target_label_or_outcome",
    "missing_or_ambiguous": "unavailable_no_imputation",
}
PROJECTION_SHA256 = hashlib.sha256(json.dumps(PROJECTION_CONTRACT, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ProjectionError(ValueError):
    """Source evidence cannot support one independent model-input vector."""


def _stamp(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        raise ProjectionError("network_window_missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProjectionError("network_window_invalid") from exc
    if parsed.tzinfo is None:
        raise ProjectionError("network_window_timezone_missing")
    return parsed.astimezone(dt.timezone.utc)


def _matches(flow: Mapping[str, Any], bound: Mapping[str, Any]) -> bool:
    try:
        return (str(flow["id.orig_h"]) == str(bound["src_ip"])
                and int(flow["id.orig_p"]) == int(bound["src_port"])
                and str(flow["id.resp_h"]) == str(bound["dst_ip"])
                and int(flow["id.resp_p"]) == int(bound["dst_port"]))
    except (KeyError, TypeError, ValueError):
        return False


def _network_features(flows: list[Mapping[str, Any]], start: dt.datetime,
                      end: dt.datetime) -> dict[str, float]:
    """Reproduce frozen 15F Zeek aggregation; checked against full source row."""
    if not flows or start >= end:
        raise ProjectionError("network_measurement_incomplete")
    count = len(flows)
    ports = [int(flow["id.resp_p"]) for flow in flows]
    port_counts = Counter(ports)
    entropy = -sum((n / count) * math.log(n / count) for n in port_counts.values())
    starts = sorted(_stamp(flow["ts_utc"]).timestamp() for flow in flows)
    intervals = [right - left for left, right in zip(starts, starts[1:])]
    if any(interval < 0 for interval in intervals):
        raise ProjectionError("network_flow_timing_invalid")
    mean_interval = statistics.fmean(intervals) if intervals else 0.0
    durations = [float(flow["duration"]) for flow in flows]
    values = (
        float(count), float(len(port_counts)), float(len(port_counts) / count),
        float(count / (end - start).total_seconds()), entropy,
        float(len({str(flow["proto"]) for flow in flows})), float(count),
        *[sum(float(flow[field]) for flow in flows)
          for field in ("orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")],
        float(sum(durations)), float(statistics.median(durations)),
        float(sum(str(flow["conn_state"]) in FAILED_STATES for flow in flows) / count),
        float(statistics.pstdev(intervals) / mean_interval) if intervals and mean_interval else 0.0,
    )
    if len(values) != 15 or not all(math.isfinite(value) for value in values):
        raise ProjectionError("network_feature_invalid")
    return dict(zip(FEATURE_ORDER[17:], values))


def project_backend_only(row: Mapping[str, Any]) -> dict[str, Any]:
    """Project a complete source episode or fail closed; never invent a flow."""
    try:
        if row.get("measurement_validity") != "VALID" or row.get("complete_cz_vector") is not True:
            raise ProjectionError("valid_complete_source_required")
        if row.get("feature_schema_sha256") != SOURCE_SCHEMA_SHA256 or tuple(row.get("feature_order", ())) != FEATURE_ORDER:
            raise ProjectionError("source_feature_contract_mismatch")
        vector = row["feature_vector"]
        flows = row["network_flows"]
        bound = row["cowrie_binding"]["backend_tuple"]
        window = row["evidence"]["network"]
        if not isinstance(vector, Mapping) or set(vector) != set(FEATURE_ORDER) or not isinstance(flows, list) or not flows:
            raise ProjectionError("source_feature_or_flow_missing")
        start, end = _stamp(window["window_start_utc"]), _stamp(window["window_end_utc"])
        if start >= end:
            raise ProjectionError("network_window_invalid")
        source_z = _network_features(flows, start, end)
        if any(not math.isclose(float(vector[name]), source_z[name], rel_tol=1e-8, abs_tol=1e-8)
               for name in FEATURE_ORDER[17:]):
            raise ProjectionError("source_network_materialization_mismatch")
        backend = [flow for flow in flows if isinstance(flow, Mapping) and _matches(flow, bound)]
        if len(backend) != 1:
            raise ProjectionError("exact_backend_flow_not_unique")
        backend_z = _network_features(backend, start, end)
        projected = {name: float(vector[name]) if index < 17 else backend_z[name]
                     for index, name in enumerate(FEATURE_ORDER)}
        if not all(math.isfinite(value) for value in projected.values()):
            raise ProjectionError("projected_feature_nonfinite")
        result = dict(row)
        result["feature_vector"] = projected
        result["source_feature_vector_sha256"] = row.get("feature_vector_sha256")
        result["feature_vector_sha256"] = hashlib.sha256(json.dumps(projected, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        result["model_input_projection_sha256"] = PROJECTION_SHA256
        result["model_input_projection_state"] = "EXPERIMENTAL_BACKEND_SSH_ONLY"
        return result
    except ProjectionError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ProjectionError("source_evidence_invalid") from exc
