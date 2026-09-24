"""Source-bound, label-independent Model2 projection regression checks."""

from __future__ import annotations

import copy
import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "production" / "model2_v7_transfer_runtime"))
from model2_backend_only_projection import (  # noqa: E402
    FEATURE_ORDER, ProjectionError, _network_features, project_backend_only,
)


def _row() -> dict:
    backend = {"id.orig_h": "192.0.2.1", "id.orig_p": 5000,
               "id.resp_h": "192.0.2.2", "id.resp_p": 2298,
               "ts_utc": "2026-09-24T00:00:01+00:00", "proto": "tcp",
               "duration": 2.0, "orig_bytes": 100, "resp_bytes": 200,
               "orig_pkts": 2, "resp_pkts": 3, "conn_state": "SF"}
    transfer = {**backend, "id.orig_h": "192.0.2.3", "id.orig_p": 5001,
                "id.resp_h": "198.51.100.10", "id.resp_p": 80,
                "ts_utc": "2026-09-24T00:00:03+00:00", "resp_bytes": 10000}
    start = dt.datetime.fromisoformat("2026-09-24T00:00:00+00:00")
    end = dt.datetime.fromisoformat("2026-09-24T00:00:10+00:00")
    source = {name: 0.0 for name in FEATURE_ORDER}
    source.update(_network_features([backend, transfer], start, end))
    return {
        "measurement_validity": "VALID", "complete_cz_vector": True,
        "feature_schema_sha256": "cf985643ce89c3d1f86f6c45943c3ba3af6cf13c60c4b41e215c7c7bc8990a20",
        "feature_order": list(FEATURE_ORDER), "feature_vector": source,
        "feature_vector_sha256": "prior-source-hash", "network_flows": [backend, transfer],
        "cowrie_binding": {"backend_tuple": {"src_ip": "192.0.2.1", "src_port": 5000,
                                             "dst_ip": "192.0.2.2", "dst_port": 2298}},
        "evidence": {"network": {"window_start_utc": start.isoformat(),
                                 "window_end_utc": end.isoformat()}},
    }


def test_projected_network_uses_only_exact_backend_and_preserves_source() -> None:
    source = _row()
    result = project_backend_only(source)
    assert source["feature_vector"]["v7_z_resp_bytes_sum_episode"] == 10200
    assert result["feature_vector"]["v7_z_resp_bytes_sum_episode"] == 200
    assert result["feature_vector"]["v7_z_flow_count_episode"] == 1
    assert result["source_feature_vector_sha256"] == "prior-source-hash"
    assert result["feature_vector_sha256"] != "prior-source-hash"
    assert source["feature_vector"]["v7_z_resp_bytes_sum_episode"] == 10200


def test_cowrie_download_label_cannot_change_model_input() -> None:
    first = _row()
    second = copy.deepcopy(first)
    second["ground_truth_events"] = [{"eventid": "cowrie.session.file_download"}]
    second["labels"] = [1, 0, 0]
    assert project_backend_only(first)["feature_vector"] == project_backend_only(second)["feature_vector"]


def test_ambiguous_backend_fails_closed() -> None:
    source = _row()
    source["network_flows"].append(dict(source["network_flows"][0]))
    source["feature_vector"].update(_network_features(source["network_flows"],
                                                      dt.datetime.fromisoformat(source["evidence"]["network"]["window_start_utc"]),
                                                      dt.datetime.fromisoformat(source["evidence"]["network"]["window_end_utc"])))
    with pytest.raises(ProjectionError, match="exact_backend_flow_not_unique"):
        project_backend_only(source)


def test_source_network_mismatch_fails_closed() -> None:
    source = _row()
    source["feature_vector"]["v7_z_resp_bytes_sum_episode"] += 1
    with pytest.raises(ProjectionError, match="source_network_materialization_mismatch"):
        project_backend_only(source)
