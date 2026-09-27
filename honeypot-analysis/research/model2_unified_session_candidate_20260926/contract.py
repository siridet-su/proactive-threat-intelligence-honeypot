"""Ordered feature contract for a future unified session-level Model2 PoC."""

from __future__ import annotations

from dataclasses import dataclass


SCHEMA_ID = "model2_unified_session_research.v1"
FEATURE_SCHEMA_SHA256 = "28cc1a43e59259c5939dacdb889cdbe4e13fbdaa71b197264e27907a071d13c1"
LABEL_ORDER = ("T1105", "T1046", "T1110")
UNIT = "one complete, identity-bound Cowrie session episode"


@dataclass(frozen=True)
class Feature:
    name: str
    group: str
    source: str
    semantics: str


FEATURES = (
    Feature("session_duration_seconds", "session", "Cowrie connect/closed timestamps", "Closed-session duration."),
    Feature("cowrie_event_count", "session", "Allowlisted Cowrie event types", "Safe event count; transfer-result events excluded."),
    Feature("command_event_count", "session", "Cowrie command events", "Count after stable source-event-key deduplication."),
    Feature("unique_command_family_count", "session", "Normalized command families", "Distinct finite command families; raw text discarded."),
    Feature("repeated_command_event_count", "session", "Normalized command families", "Repeated family occurrences; distinct source events retained."),
    Feature("command_failure_count", "session", "Explicit Cowrie command-failure events", "Does not include file-download result events."),
    Feature("unknown_command_family_count", "session", "Normalized command families", "Commands outside the reviewed finite family map."),
    Feature("command_density_per_minute", "session", "Cowrie command events and duration", "Command event count divided by duration in minutes."),
    Feature("inter_command_gap_mean_seconds", "session", "Ordered command timestamps", "Mean adjacent gap; structural zero only with fewer than two commands."),
    Feature("inter_command_gap_stddev_seconds", "session", "Ordered command timestamps", "Population standard deviation of adjacent gaps."),
    Feature("recognized_behavior_family_count", "session", "Normalized command/auth families", "Distinct recognized behavior families."),
    Feature("adjacent_family_transition_count", "sequence", "Ordered normalized event families", "Count of adjacent behavior-family changes."),
    Feature("distinct_adjacent_family_transition_count", "sequence", "Ordered normalized event families", "Distinct directed adjacent family pairs."),
    Feature("auth_before_command_count", "sequence", "Ordered auth and command events", "Auth events with a later command in this episode."),
    Feature("discovery_before_transfer_count", "sequence", "Ordered normalized command families", "Discovery events followed later by transfer-tool intent."),
    Feature("transfer_before_execution_count", "sequence", "Ordered normalized command families", "Transfer-tool events followed later by execution-family commands."),
    Feature("transfer_before_permission_change_count", "sequence", "Ordered normalized command families", "Transfer-tool events followed later by permission-change commands."),
    Feature("transfer_before_archive_count", "sequence", "Ordered normalized command families", "Transfer-tool events followed later by archive-family commands."),
    Feature("transfer_before_cleanup_count", "sequence", "Ordered normalized command families", "Transfer-tool events followed later by cleanup-family commands."),
    Feature("max_repeated_family_run_length", "sequence", "Ordered normalized event families", "Longest contiguous same-family run."),
    Feature("transfer_tool_command_count", "transfer_intent", "Cowrie command.input parsed in memory", "Recognized client attempts; not a transfer-success claim."),
    Feature("transfer_wget_command_count", "transfer_intent", "Cowrie command.input parsed in memory", "wget-family attempt count."),
    Feature("transfer_curl_command_count", "transfer_intent", "Cowrie command.input parsed in memory", "curl-family attempt count."),
    Feature("transfer_other_known_tool_count", "transfer_intent", "Cowrie command.input parsed in memory", "Allowlisted fetch/ftp/tftp attempt count."),
    Feature("transfer_http_scheme_count", "transfer_intent", "URL scheme parsed in memory", "HTTP intent count; URI/host/path never retained."),
    Feature("transfer_https_scheme_count", "transfer_intent", "URL scheme parsed in memory", "HTTPS intent count; encrypted response remains unobserved."),
    Feature("transfer_other_scheme_count", "transfer_intent", "URL scheme parsed in memory", "Other recognized scheme count."),
    Feature("transfer_unknown_scheme_count", "transfer_intent", "URL scheme parsed in memory", "Scheme not safely resolved."),
    Feature("transfer_default_web_port_count", "transfer_intent", "Port normalized in memory", "Default web port class (80/443); literal port discarded."),
    Feature("transfer_other_well_known_port_count", "transfer_intent", "Port normalized in memory", "Non-web port below 1024; literal port discarded."),
    Feature("transfer_nonstandard_port_count", "transfer_intent", "Port normalized in memory", "Port >=1024; literal port discarded."),
    Feature("transfer_unknown_port_count", "transfer_intent", "Port normalized in memory", "No safely resolved port."),
    Feature("transfer_output_intent_count", "transfer_intent", "Allowlisted wget/curl options", "Output-file/name intent; filename never retained."),
    Feature("transfer_redirect_requested_count", "transfer_intent", "Reviewed wget/curl redirect semantics", "Redirect-follow requested/default intent; not an observed redirect."),
    Feature("transfer_pipe_to_shell_intent_count", "transfer_intent", "Command syntax parsed in memory", "Pipe to allowlisted shell intent; not execution proof."),
    Feature("transfer_unique_destination_count", "transfer_intent", "Normalized host parsed in memory", "Distinct-destination count only; host values discarded."),
    Feature("network_connection_count", "network", "Exact-episode Zeek conn.log", "Uniquely bound Zeek flows."),
    Feature("network_tcp_connection_count", "network", "Exact-episode Zeek conn.log", "Bound TCP flows."),
    Feature("network_udp_connection_count", "network", "Exact-episode Zeek conn.log", "Bound UDP flows."),
    Feature("network_distinct_destination_port_count", "network", "Exact-episode Zeek conn.log", "Distinct destination-port count; literal values discarded."),
    Feature("network_destination_service_class_count", "network", "Exact-episode Zeek conn.log", "Distinct finite service classes only."),
    Feature("network_repeated_destination_service_count", "network", "Exact-episode Zeek conn.log", "Flows repeating an already seen service class."),
    Feature("network_established_connection_count", "network", "Zeek conn_state", "conn_state=SF; not transfer success."),
    Feature("network_unanswered_or_rejected_connection_count", "network", "Zeek conn_state", "conn_state=S0 or REJ only."),
    Feature("network_orig_bytes_sum", "network", "Zeek conn.log orig_bytes", "Reported originator-byte sum."),
    Feature("network_resp_bytes_sum", "network", "Zeek conn.log resp_bytes", "Reported responder-byte sum."),
    Feature("network_flow_duration_sum_seconds", "network", "Zeek conn.log duration", "Reported duration sum."),
    Feature("auth_attempt_count", "authentication", "Cowrie login.success/login.failed", "Exact-session auth-event count."),
    Feature("auth_failure_count", "authentication", "Cowrie login.failed", "Explicit failed-auth count."),
    Feature("auth_success_count", "authentication", "Cowrie login.success", "Explicit successful-auth count."),
    Feature("auth_failure_fraction", "authentication", "Cowrie auth events", "Failures/attempts; zero only with complete zero-attempt telemetry."),
    Feature("auth_distinct_username_count", "authentication", "Cowrie username values in memory", "Distinct normalized count only; names never emitted."),
    Feature("auth_max_failure_streak", "authentication", "Ordered Cowrie auth events", "Longest consecutive failed-auth sequence."),
    Feature("auth_interarrival_cv", "authentication", "Ordered Cowrie auth timestamps", "Auth-gap coefficient of variation; structural zero if fewer than two gaps."),
)

FEATURE_ORDER = tuple(item.name for item in FEATURES)
FEATURE_BY_NAME = {item.name: item for item in FEATURES}

# These are evidence gates, never predictor inputs. Failure of any gate means
# no vector and no Model2 output; absent network capture is not encoded as zero.
REQUIRED_AVAILABILITY_GATES = (
    "cowrie_session_exact_binding",
    "cowrie_event_stream_complete",
    "cowrie_connect_and_close_observed",
    "stable_source_event_keys_present",
    "auth_telemetry_complete",
    "episode_pcap_finalized_without_disqualifying_drops",
    "zeek_conn_log_complete_and_bound_to_same_pcap",
    "every_flow_bound_to_exact_episode",
    "all_identity_fields_match",
)

FORBIDDEN_FEATURE_TOKENS = (
    "label", "target", "ttp", "technique_id", "prediction", "model_output",
    "session_id", "source_session_id", "run_id", "measurement_id", "episode_id",
    "procedure_id", "case_id", "fixture", "receipt", "timestamp_exact",
    "file_download", "artifact_hash", "sha256", "http_status", "response_body",
    "cookie", "password", "credential", "token", "secret", "uri", "hostname",
    "filename", "payload", "literal_ip", "literal_port",
)
