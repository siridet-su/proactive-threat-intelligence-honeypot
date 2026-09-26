"""Fail-closed extractor mechanics for the research-only unified Model2 schema.

The input is a sanitized episode envelope from a future acquisition adapter.
This code does not open PCAPs, run Zeek, read secrets, access Mongo, or call
production services. Raw commands and usernames are used only in memory.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import shlex
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .contract import FEATURE_ORDER, LABEL_ORDER


IDENTITY_FIELDS = ("source_session_id", "run_id", "measurement_id", "episode_id")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHELL_NAMES = {"sh", "bash", "dash", "zsh"}
TRANSFER_TOOLS = {"wget": "wget", "curl": "curl", "fetch": "other", "ftp": "other", "tftp": "other"}
WRAPPERS = {"sudo", "doas", "command", "env"}
BEHAVIOR_FAMILIES = {
    "wget": "transfer", "curl": "transfer", "fetch": "transfer", "ftp": "transfer", "tftp": "transfer",
    "nmap": "discovery", "nc": "discovery", "netcat": "discovery", "telnet": "discovery",
    "ss": "discovery", "netstat": "discovery", "ping": "discovery", "traceroute": "discovery",
    "whoami": "identity", "id": "identity", "uname": "identity", "hostname": "identity", "groups": "identity",
    "ls": "filesystem", "find": "filesystem", "pwd": "filesystem", "cat": "filesystem", "head": "filesystem", "tail": "filesystem", "stat": "filesystem",
    "sh": "execution", "bash": "execution", "dash": "execution", "zsh": "execution", "python": "execution", "python3": "execution", "perl": "execution", "php": "execution",
    "chmod": "permission", "chown": "permission",
    "tar": "archive", "gzip": "archive", "bzip2": "archive", "xz": "archive", "unzip": "archive", "zip": "archive",
    "rm": "cleanup", "shred": "cleanup", "unlink": "cleanup",
}
AUTH_EVENTS = {"cowrie.login.failed": "failure", "cowrie.login.success": "success"}
COMMAND_INPUT = "cowrie.command.input"
COMMAND_FAILURE = "cowrie.command.failed"
SAFE_EVENTS = {
    COMMAND_INPUT, COMMAND_FAILURE, "cowrie.command.success",
    *AUTH_EVENTS, "cowrie.session.connect", "cowrie.session.closed",
}
# These outcomes must not affect features or source-event counts.
EXCLUDED_OUTCOME_EVENTS = {
    "cowrie.session.file_download",
    "cowrie.session.file_download.failed",
}
KNOWN_CONN_FAILURE_STATES = {"S0", "REJ"}


class FeatureContractError(ValueError):
    """Source evidence cannot safely produce a complete feature vector."""


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _finite_nonnegative(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise FeatureContractError(f"invalid_numeric:{field}")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise FeatureContractError(f"missing_numeric:{field}") from None
    if not math.isfinite(number) or number < 0:
        raise FeatureContractError(f"invalid_numeric:{field}")
    return number


def _sha(value: Any, field: str) -> str:
    digest = _text(value).lower()
    if not SHA256_RE.fullmatch(digest):
        raise FeatureContractError(f"invalid_digest:{field}")
    return digest


def _time(value: Any, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    except ValueError:
        raise FeatureContractError(f"invalid_timestamp:{field}") from None
    if parsed.tzinfo is None:
        raise FeatureContractError(f"naive_timestamp:{field}")
    return parsed.astimezone(timezone.utc)


def _identity(actual: Any, expected: Mapping[str, Any], source: str) -> dict[str, str]:
    if not isinstance(actual, Mapping):
        raise FeatureContractError(f"identity_missing:{source}")
    result: dict[str, str] = {}
    for field in IDENTITY_FIELDS:
        got, want = _text(actual.get(field)), _text(expected.get(field))
        if not got or not want or got != want:
            raise FeatureContractError(f"identity_mismatch:{source}:{field}")
        result[field] = got
    return result


def _tokens(raw: Any) -> list[str]:
    if not isinstance(raw, str) or not raw.strip():
        return []
    try:
        return shlex.split(raw, posix=True)
    except ValueError:
        return []


def _executable(tokens: Sequence[str]) -> tuple[str, int]:
    index = 0
    while index < len(tokens):
        name = tokens[index].rsplit("/", 1)[-1].lower()
        if name in WRAPPERS:
            index += 1
            if name == "env":
                while index < len(tokens) and "=" in tokens[index] and not tokens[index].startswith("-"):
                    index += 1
            continue
        if name == "busybox" and index + 1 < len(tokens):
            return tokens[index + 1].rsplit("/", 1)[-1].lower(), index + 1
        return name, index
    return "", 0


def _pipe_to_shell(raw: Any) -> bool:
    """Recognize a syntactic shell pipe without matching quoted text."""
    if not isinstance(raw, str) or not raw.strip():
        return False
    try:
        lexer = shlex.shlex(raw, posix=True, punctuation_chars="|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return False
    for index, token in enumerate(tokens[:-1]):
        if token != "|":
            continue
        target = tokens[index + 1].rsplit("/", 1)[-1].lower()
        if target in SHELL_NAMES:
            return True
    return False


def _port_class(port: int | None, scheme: str) -> str:
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    if port is None:
        return "unknown"
    if port in {80, 443}:
        return "default_web"
    if 0 < port < 1024:
        return "other_well_known"
    if 1024 <= port <= 65535:
        return "nonstandard"
    return "unknown"


def _transfer(raw: Any) -> dict[str, Any] | None:
    tokens = _tokens(raw)
    executable, executable_index = _executable(tokens)
    tool = TRANSFER_TOOLS.get(executable)
    if tool is None:
        return None
    args = tokens[executable_index + 1:]
    # Help/version invocations and bare/malformed wget/curl commands are
    # hard negatives for transfer intent, not transfer attempts.
    if any(token in {"--help", "-h", "--version", "-V"} for token in args):
        return None
    urls = []
    for token in args:
        candidate = token[6:] if token.startswith("--url=") else token
        if not candidate.startswith("-") and "://" in candidate:
            urls.append(candidate.strip("\"'"))
    if tool in {"wget", "curl"} and not urls:
        return None
    if tool == "other" and not urls and not any(not token.startswith("-") for token in args):
        return None
    schemes: list[str] = []
    ports: list[str] = []
    hosts: set[str] = set()
    for url in urls:
        try:
            parsed = urlsplit(url)
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port
        except ValueError:
            scheme, host, port = "", "", None
        schemes.append(scheme if scheme in {"http", "https"} else (scheme or "unknown"))
        if host:
            hosts.add(host)
        ports.append(_port_class(port, scheme))
    if not urls:
        schemes, ports = ["unknown"], ["unknown"]

    if executable == "wget":
        # GNU wget uses case-sensitive -O/--output-document for the
        # downloaded object; -o/--output-file writes a log instead.
        output = any(token == "-O" or token == "--output-document" or token.startswith("--output-document=") for token in args)
        max_redirect_zero = "--max-redirect=0" in args
        if "--max-redirect" in args:
            idx = args.index("--max-redirect")
            max_redirect_zero = max_redirect_zero or (idx + 1 < len(args) and args[idx + 1] == "0")
        redirect = bool(urls) and not max_redirect_zero  # Cowrie wget follows redirects by default.
    elif executable == "curl":
        output = any(token in {"-o", "-O", "--output", "--remote-name"} or token.startswith("--output=") for token in args)
        # Curl GET does not follow redirects unless explicitly requested.
        redirect = bool(urls) and any(token in {"-L", "--location", "--location-trusted"} for token in args)
    else:
        output, redirect = False, False

    return {
        "tool": tool,
        "schemes": schemes,
        "ports": ports,
        "output": output,
        "redirect": redirect,
        "pipe_shell": _pipe_to_shell(raw),
        "hosts": hosts,
    }


def _cv(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    variance = sum((item - mean) ** 2 for item in values) / len(values)
    return math.sqrt(variance) / mean


def _event_fingerprint(event: Mapping[str, Any]) -> str:
    # Use only fields relevant to this extractor. In particular, do not read,
    # serialize, hash, return, or persist password/cookie/payload fields.
    command = event.get("input", event.get("command"))
    username = event.get("username")
    signature = {
        "eventid": _text(event.get("eventid")),
        "timestamp": _text(event.get("timestamp")),
        "session_id": _text(event.get("session_id")),
        "source_sequence": event.get("source_sequence"),
        "command_digest": hashlib.sha256(command.encode("utf-8")).hexdigest() if isinstance(command, str) else "",
        "username_digest": hashlib.sha256(username.casefold().encode("utf-8")).hexdigest() if isinstance(username, str) else "",
        "command_projection": event.get("command_projection"),
        "username_sha256": _text(event.get("username_sha256")),
        "success": event.get("success"),
    }
    payload = json.dumps(signature, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _projected_command(event: Mapping[str, Any]) -> tuple[str, dict[str, Any] | None] | None:
    value = event.get("command_projection")
    if not isinstance(value, Mapping):
        return None
    family = _text(value.get("family"))
    if family not in set(BEHAVIOR_FAMILIES.values()) | {"other"}:
        raise FeatureContractError("command_projection_family_invalid")
    raw_transfer = value.get("transfer")
    if raw_transfer is None:
        return family, None
    if not isinstance(raw_transfer, Mapping):
        raise FeatureContractError("command_projection_transfer_invalid")
    tool = _text(raw_transfer.get("tool"))
    schemes = raw_transfer.get("schemes")
    ports = raw_transfer.get("ports")
    destinations = raw_transfer.get("destination_digests")
    if tool not in {"wget", "curl", "other"}:
        raise FeatureContractError("command_projection_tool_invalid")
    if not isinstance(schemes, list) or not schemes or any(item not in {"http", "https", "unknown", "ftp", "tftp"} for item in schemes):
        raise FeatureContractError("command_projection_scheme_invalid")
    if not isinstance(ports, list) or len(ports) != len(schemes) or any(item not in {"default_web", "other_well_known", "nonstandard", "unknown"} for item in ports):
        raise FeatureContractError("command_projection_port_invalid")
    if not isinstance(destinations, list) or any(not SHA256_RE.fullmatch(_text(item)) for item in destinations):
        raise FeatureContractError("command_projection_destination_invalid")
    if any(not isinstance(raw_transfer.get(name), bool) for name in ("output", "redirect", "pipe_shell")):
        raise FeatureContractError("command_projection_boolean_invalid")
    return family, {
        "tool": tool,
        "schemes": list(schemes),
        "ports": list(ports),
        "output": raw_transfer["output"],
        "redirect": raw_transfer["redirect"],
        "pipe_shell": raw_transfer["pipe_shell"],
        "hosts": set(destinations),
    }


def _validated_flows(network: Mapping[str, Any], expected: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if network.get("complete") is not True:
        raise FeatureContractError("zeek_episode_incomplete")
    identity = _identity(network.get("identity"), expected, "zeek")
    pcap = network.get("pcap")
    zeek = network.get("zeek")
    if not isinstance(pcap, Mapping) or not isinstance(zeek, Mapping):
        raise FeatureContractError("pcap_or_zeek_receipt_missing")
    if pcap.get("finalized") is not True or _finite_nonnegative(pcap.get("drop_count"), "pcap_drop_count") != 0:
        raise FeatureContractError("pcap_not_complete")
    pcap_sha = _sha(pcap.get("sha256"), "pcap")
    if zeek.get("status") != "COMPLETE":
        raise FeatureContractError("zeek_conn_log_incomplete")
    if _sha(zeek.get("pcap_sha256"), "zeek_pcap") != pcap_sha:
        raise FeatureContractError("zeek_pcap_binding_mismatch")
    conn_sha = _sha(zeek.get("conn_log_sha256"), "conn_log")
    if _identity(zeek.get("identity"), expected, "zeek_log") != identity:
        raise FeatureContractError("zeek_identity_binding_mismatch")
    flows = network.get("flows")
    if not isinstance(flows, Sequence) or isinstance(flows, (str, bytes)):
        raise FeatureContractError("zeek_flows_missing")
    seen_uid: set[str] = set()
    for flow in flows:
        if not isinstance(flow, Mapping):
            raise FeatureContractError("zeek_flow_invalid")
        uid = _text(flow.get("uid"))
        if not uid or uid in seen_uid:
            raise FeatureContractError("zeek_uid_missing_or_duplicate")
        seen_uid.add(uid)
        if flow.get("flow_binding") != "PASS" or _identity(flow.get("episode_binding"), expected, f"flow:{uid}") != identity:
            raise FeatureContractError("zeek_flow_episode_binding_failed")
        tuple_value = flow.get("tuple")
        if not isinstance(tuple_value, Mapping) or any(not _text(tuple_value.get(k)) for k in ("orig_h", "orig_p", "resp_h", "resp_p", "proto")):
            raise FeatureContractError("zeek_flow_tuple_incomplete")
        _finite_nonnegative(flow.get("duration"), "flow_duration")
        _finite_nonnegative(flow.get("orig_bytes"), "flow_orig_bytes")
        _finite_nonnegative(flow.get("resp_bytes"), "flow_resp_bytes")
    # Keep references out of the vector; validate hash so provenance can be
    # checked by the caller without retaining the log contents.
    _ = conn_sha
    return list(flows)


def extract_features(envelope: Mapping[str, Any], *, expected_identity: Mapping[str, Any]) -> dict[str, Any]:
    """Return one full vector, or raise FeatureContractError; never zero-fill."""
    if not isinstance(envelope, Mapping):
        raise FeatureContractError("episode_envelope_invalid")
    identity = dict(expected_identity)
    if any(not _text(identity.get(field)) for field in IDENTITY_FIELDS):
        raise FeatureContractError("expected_identity_incomplete")

    cowrie = envelope.get("cowrie")
    network = envelope.get("network")
    if not isinstance(cowrie, Mapping) or cowrie.get("complete") is not True:
        raise FeatureContractError("cowrie_episode_incomplete")
    bound_cowrie = _identity(cowrie.get("identity"), identity, "cowrie")
    cowrie_sha = _sha(cowrie.get("event_log_sha256"), "cowrie_event_log")
    if cowrie.get("auth_telemetry_complete") is not True:
        raise FeatureContractError("auth_telemetry_incomplete")
    flows = _validated_flows(network if isinstance(network, Mapping) else {}, identity)

    raw_events = cowrie.get("events")
    if not isinstance(raw_events, Sequence) or isinstance(raw_events, (str, bytes)):
        raise FeatureContractError("cowrie_events_missing")
    unique: dict[str, tuple[str, int, Mapping[str, Any]]] = {}
    for event in raw_events:
        if not isinstance(event, Mapping):
            raise FeatureContractError("cowrie_event_invalid")
        event_type = _text(event.get("eventid"))
        if event_type in EXCLUDED_OUTCOME_EVENTS:
            continue
        if event_type not in SAFE_EVENTS:
            continue
        key = _text(event.get("source_event_key"))
        if not key:
            raise FeatureContractError("stable_source_event_key_missing")
        sequence = event.get("source_sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise FeatureContractError("stable_source_sequence_missing")
        if _text(event.get("session_id")) != identity["source_session_id"]:
            raise FeatureContractError("cowrie_event_session_binding_failed")
        fingerprint = _event_fingerprint(event)
        previous = unique.get(key)
        if previous and (previous[0] != fingerprint or previous[1] != sequence):
            raise FeatureContractError("source_event_key_collision")
        unique[key] = (fingerprint, sequence, event)

    sequence_owners: dict[int, str] = {}
    events: list[tuple[datetime, int, str, Mapping[str, Any]]] = []
    for key, (_, sequence, event) in unique.items():
        owner = sequence_owners.setdefault(sequence, key)
        if owner != key:
            raise FeatureContractError("source_sequence_collision")
        when = _time(event.get("timestamp"), "cowrie_event")
        events.append((when, sequence, key, event))
    events.sort(key=lambda item: (item[0], item[1]))
    if any(events[index][1] > events[index + 1][1] for index in range(len(events) - 1)):
        raise FeatureContractError("source_time_order_conflict")
    connects = [item[0] for item in events if item[3].get("eventid") == "cowrie.session.connect"]
    closes = [item[0] for item in events if item[3].get("eventid") == "cowrie.session.closed"]
    if len(connects) != 1 or len(closes) != 1 or closes[0] < connects[0]:
        raise FeatureContractError("session_connect_close_not_unique_or_ordered")
    duration = (closes[0] - connects[0]).total_seconds()
    if duration <= 0:
        raise FeatureContractError("session_duration_not_positive")

    vector = {name: 0.0 for name in FEATURE_ORDER}
    vector["session_duration_seconds"] = duration
    vector["cowrie_event_count"] = float(len(events))

    commands: list[tuple[datetime, int, str, str, Mapping[str, Any]]] = []
    auth: list[tuple[datetime, int, str, Mapping[str, Any]]] = []
    families: list[str] = []
    family_seen: set[str] = set()
    command_family_seen: set[str] = set()
    family_counts: Counter[str] = Counter()
    username_values: set[str] = set()
    auth_results: list[str] = []
    transfer_records: list[tuple[int, datetime, str, Mapping[str, Any], dict[str, Any]]] = []

    for when, sequence, key, event in events:
        event_type = _text(event.get("eventid"))
        if event_type in AUTH_EVENTS:
            result = AUTH_EVENTS[event_type]
            auth.append((when, sequence, result, event))
            auth_results.append(result)
            family = "auth"
            raw_username = _text(event.get("username"))
            username_digest = _text(event.get("username_sha256"))
            if username_digest:
                if not SHA256_RE.fullmatch(username_digest):
                    raise FeatureContractError("username_projection_invalid")
                username_values.add(username_digest)
            elif raw_username:
                username_values.add(raw_username.casefold())
        elif event_type == COMMAND_INPUT:
            projected = _projected_command(event)
            raw_command = event.get("input", event.get("command"))
            if projected is None:
                tokens = _tokens(raw_command)
                executable, _ = _executable(tokens)
                family = BEHAVIOR_FAMILIES.get(executable, "other")
                detail = _transfer(raw_command)
            else:
                family, detail = projected
            commands.append((when, sequence, key, family, event))
            family_counts[family] += 1
            command_family_seen.add(family)
            if detail is not None:
                transfer_records.append((len(commands) - 1, when, family, event, detail))
        elif event_type == COMMAND_FAILURE:
            vector["command_failure_count"] += 1.0
            family = "command_failure"
        else:
            family = "session_boundary"
        families.append(family)
        if family not in {"other", "command_failure", "session_boundary"}:
            family_seen.add(family)

    command_times = [item[0] for item in commands]
    command_gaps = [(b - a).total_seconds() for a, b in zip(command_times, command_times[1:])]
    if any(gap < 0 for gap in command_gaps):
        raise FeatureContractError("command_order_invalid")
    vector["command_event_count"] = float(len(commands))
    vector["unique_command_family_count"] = float(len(command_family_seen))
    vector["repeated_command_event_count"] = float(sum(max(0, n - 1) for n in family_counts.values()))
    vector["unknown_command_family_count"] = float(family_counts.get("other", 0))
    vector["command_density_per_minute"] = len(commands) * 60.0 / duration
    vector["inter_command_gap_mean_seconds"] = sum(command_gaps) / len(command_gaps) if command_gaps else 0.0
    if len(command_gaps) >= 2:
        gap_mean = vector["inter_command_gap_mean_seconds"]
        vector["inter_command_gap_stddev_seconds"] = math.sqrt(sum((gap - gap_mean) ** 2 for gap in command_gaps) / len(command_gaps))
    vector["recognized_behavior_family_count"] = float(len(family_seen))

    behavior_events = [(when, sequence, family) for when, sequence, _, family, _ in commands]
    behavior_events.extend((when, sequence, "auth") for when, sequence, _, _ in auth)
    behavior_events.sort(key=lambda item: (item[0], item[1]))
    ordered_families = [family for _, _, family in behavior_events]
    adjacent = list(zip(ordered_families, ordered_families[1:]))
    vector["adjacent_family_transition_count"] = float(sum(a != b for a, b in adjacent))
    vector["distinct_adjacent_family_transition_count"] = float(len({(a, b) for a, b in adjacent if a != b}))
    max_run = run = 0
    previous_family = None
    for family in ordered_families:
        run = run + 1 if family == previous_family else 1
        max_run = max(max_run, run)
        previous_family = family
    vector["max_repeated_family_run_length"] = float(max_run)
    auth_positions = [(when, sequence) for when, sequence, _, _ in auth]
    vector["auth_before_command_count"] = float(
        sum(any((command[0], command[1]) > auth_position for command in commands) for auth_position in auth_positions)
    )
    transfer_positions = [index for index, *_ in transfer_records]
    family_positions = {family: [i for i, item in enumerate(commands) if item[3] == family] for family in {"discovery", "execution", "permission", "archive", "cleanup"}}
    def count_later(target: str) -> float:
        targets = family_positions[target]
        return float(sum(any(j > i for j in targets) for i in transfer_positions))
    vector["discovery_before_transfer_count"] = float(sum(any(j < i for j in family_positions["discovery"]) for i in transfer_positions))
    vector["transfer_before_execution_count"] = count_later("execution")
    vector["transfer_before_permission_change_count"] = count_later("permission")
    vector["transfer_before_archive_count"] = count_later("archive")
    vector["transfer_before_cleanup_count"] = count_later("cleanup")

    transfer_hosts: set[str] = set()
    for _, _, _, _, detail in transfer_records:
        vector["transfer_tool_command_count"] += 1.0
        vector[{"wget": "transfer_wget_command_count", "curl": "transfer_curl_command_count", "other": "transfer_other_known_tool_count"}[detail["tool"]]] += 1.0
        for scheme in detail["schemes"]:
            key = {
                "http": "transfer_http_scheme_count", "https": "transfer_https_scheme_count",
                "unknown": "transfer_unknown_scheme_count",
            }.get(scheme, "transfer_other_scheme_count")
            vector[key] += 1.0
        for port_class in detail["ports"]:
            key = {
                "default_web": "transfer_default_web_port_count",
                "other_well_known": "transfer_other_well_known_port_count",
                "nonstandard": "transfer_nonstandard_port_count",
                "unknown": "transfer_unknown_port_count",
            }[port_class]
            vector[key] += 1.0
        vector["transfer_output_intent_count"] += float(detail["output"])
        vector["transfer_redirect_requested_count"] += float(detail["redirect"])
        vector["transfer_pipe_to_shell_intent_count"] += float(detail["pipe_shell"])
        transfer_hosts.update(detail["hosts"])
    vector["transfer_unique_destination_count"] = float(len(transfer_hosts))

    port_values: set[int] = set()
    service_classes: set[str] = set()
    service_occurrences: Counter[str] = Counter()
    for flow in flows:
        tuple_value = flow["tuple"]
        try:
            destination_port = int(tuple_value["resp_p"])
        except (TypeError, ValueError):
            raise FeatureContractError("zeek_destination_port_invalid") from None
        port_values.add(destination_port)
        service_class = _port_class(destination_port, "")
        service_classes.add(service_class)
        service_occurrences[service_class] += 1
        proto = _text(tuple_value.get("proto")).lower()
        if proto == "tcp":
            vector["network_tcp_connection_count"] += 1.0
        elif proto == "udp":
            vector["network_udp_connection_count"] += 1.0
        else:
            raise FeatureContractError("zeek_protocol_unknown")
        state = _text(flow.get("conn_state")).upper()
        if state == "SF":
            vector["network_established_connection_count"] += 1.0
        elif state in KNOWN_CONN_FAILURE_STATES:
            vector["network_unanswered_or_rejected_connection_count"] += 1.0
        vector["network_orig_bytes_sum"] += _finite_nonnegative(flow.get("orig_bytes"), "flow_orig_bytes")
        vector["network_resp_bytes_sum"] += _finite_nonnegative(flow.get("resp_bytes"), "flow_resp_bytes")
        vector["network_flow_duration_sum_seconds"] += _finite_nonnegative(flow.get("duration"), "flow_duration")
    vector["network_connection_count"] = float(len(flows))
    vector["network_distinct_destination_port_count"] = float(len(port_values))
    vector["network_destination_service_class_count"] = float(len(service_classes))
    vector["network_repeated_destination_service_count"] = float(sum(max(0, count - 1) for count in service_occurrences.values()))

    vector["auth_attempt_count"] = float(len(auth))
    vector["auth_failure_count"] = float(auth_results.count("failure"))
    vector["auth_success_count"] = float(auth_results.count("success"))
    vector["auth_failure_fraction"] = vector["auth_failure_count"] / len(auth) if auth else 0.0
    vector["auth_distinct_username_count"] = float(len(username_values))
    max_streak = streak = 0
    for result in auth_results:
        streak = streak + 1 if result == "failure" else 0
        max_streak = max(max_streak, streak)
    vector["auth_max_failure_streak"] = float(max_streak)
    auth_times = [item[0] for item in auth]
    auth_gaps = [(b - a).total_seconds() for a, b in zip(auth_times, auth_times[1:])]
    vector["auth_interarrival_cv"] = _cv(auth_gaps)

    if tuple(vector) != FEATURE_ORDER or any(not math.isfinite(value) or value < 0 for value in vector.values()):
        raise FeatureContractError("feature_vector_invalid")
    pcap = network["pcap"]
    zeek = network["zeek"]
    return {
        "schema_id": "model2_unified_session_research.v1",
        "status": "AVAILABLE",
        "authority": "RESEARCH_ONLY_NON_AUTHORITATIVE",
        "identity": bound_cowrie,
        "feature_order": list(FEATURE_ORDER),
        "feature_vector": vector,
        "provenance": {
            "cowrie_event_log_sha256": cowrie_sha,
            "pcap_sha256": _sha(pcap.get("sha256"), "pcap"),
            "zeek_conn_log_sha256": _sha(zeek.get("conn_log_sha256"), "conn_log"),
            "zeek_pcap_sha256": _sha(zeek.get("pcap_sha256"), "zeek_pcap"),
            "http_log_used": False,
            "raw_command_or_username_retained": False,
        },
        "outputs": {label: {"status": "NOT_TRAINED", "decision": None, "score": None} for label in LABEL_ORDER},
    }


def extract_or_unavailable(envelope: Mapping[str, Any], *, expected_identity: Mapping[str, Any]) -> dict[str, Any]:
    """Safe adapter: return no vector on any missing, stale, or misbound input."""
    try:
        return extract_features(envelope, expected_identity=expected_identity)
    except FeatureContractError as exc:
        return {
            "schema_id": "model2_unified_session_research.v1",
            "status": "UNAVAILABLE",
            "authority": "RESEARCH_ONLY_NON_AUTHORITATIVE",
            "reason_code": str(exc),
            "feature_vector": None,
            "outputs": {label: {"status": "UNAVAILABLE", "decision": None, "score": None} for label in LABEL_ORDER},
        }
