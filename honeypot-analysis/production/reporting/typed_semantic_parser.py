"""Conservative parser for the documented typed-semantic shell subset."""

from __future__ import annotations

import posixpath
import shlex
from copy import deepcopy
from typing import Any, Dict, Iterable, List, Tuple

from production.utils.serialization import stable_id


_WRAPPERS = {"env", "nohup", "setsid", "sudo"}
_READ_TOOLS = {"cat", "cut", "grep", "head", "less", "more", "stat", "tail", "wc"}
_SYSTEMCTL_READ = {
    "cat",
    "get-default",
    "is-active",
    "is-enabled",
    "is-failed",
    "list-dependencies",
    "list-sockets",
    "list-timers",
    "list-unit-files",
    "list-units",
    "show",
    "status",
}
_SYSTEMCTL_MODIFY = {
    "daemon-reload",
    "disable",
    "edit",
    "enable",
    "mask",
    "reload",
    "restart",
    "start",
    "stop",
    "unmask",
}
_UNSUPPORTED_SHELL_TOKENS = {
    "&",
    "&&",
    "|",
    "||",
    ";",
    "<<",
    "<<<",
    "<>",
    ">|",
    "<&",
    ">&",
}
_SHELL_EXECUTABLES = {"sh", "bash", "dash", "zsh", "ksh"}
_SCRIPT_EXECUTABLE_PREFIXES = ("python", "perl", "ruby", "node")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _unique(values: Iterable[str]) -> List[str]:
    output: List[str] = []
    for value in values:
        cleaned = _clean(value)
        if cleaned and cleaned not in output:
            output.append(cleaned)
    return output


def _empty_entities(policy: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    roles = (policy.get("vocabulary") or {}).get("entity_roles") or []
    return {role: [] for role in roles}


def _path_value(
    raw_value: str,
    working_directory: str,
    working_directory_status: str,
) -> Dict[str, Any]:
    raw = _clean(raw_value)
    uncertain = False
    linkable = False
    reason = "none"
    candidate = ""
    if not raw:
        normalized = ""
        uncertain = True
        reason = "empty_path"
    elif any(character in raw for character in ("$", "`")):
        normalized = raw
        uncertain = True
        reason = "shell_expansion_not_resolved"
    elif raw.startswith("~"):
        normalized = raw
        uncertain = True
        reason = "home_directory_not_resolved"
    elif any(character in raw for character in ("*", "?", "[", "]")):
        normalized = raw
        uncertain = True
        reason = "wildcard_path_not_resolved"
    elif raw.startswith("/"):
        normalized = posixpath.normpath(raw)
        candidate = normalized
        linkable = True
    elif working_directory.startswith("/") and working_directory_status in {
        "observed",
        "confirmed",
    }:
        normalized = posixpath.normpath(
            posixpath.join(working_directory, raw)
        )
        candidate = normalized
        linkable = True
    elif working_directory.startswith("/"):
        relative = posixpath.normpath(raw)
        normalized = f"relative:{relative}"
        candidate = posixpath.normpath(
            posixpath.join(working_directory, relative)
        )
        uncertain = True
        reason = "conditional_working_directory"
    else:
        normalized = f"relative:{posixpath.normpath(raw)}"
        uncertain = True
        reason = "working_directory_unknown"
    return {
        "normalized_value": normalized,
        "original_value": raw,
        "uncertain": uncertain,
        "linkable": linkable,
        "uncertainty_reason": reason,
        "candidate_normalized_value": candidate,
    }


def _entity(
    entity_type: str,
    raw_value: str,
    *,
    working_directory: str = "",
    working_directory_status: str = "unknown",
) -> Dict[str, Any]:
    raw = _clean(raw_value)
    if entity_type == "path":
        values = _path_value(
            raw,
            working_directory,
            working_directory_status,
        )
    else:
        values = {
            "normalized_value": raw,
            "original_value": raw,
            "uncertain": False,
            "linkable": bool(raw),
            "uncertainty_reason": "none",
            "candidate_normalized_value": raw,
        }
    identity_value = (
        values["normalized_value"]
        if values["linkable"]
        else f"unresolved:{values['normalized_value']}"
    )
    return {
        "entity_id": stable_id(
            "typed_semantic_entity",
            {"type": entity_type, "value": identity_value},
        ),
        "entity_type": entity_type,
        **values,
        "source_entity_ref": "",
        "redacted_components": False,
    }


def _add_entity(
    entities: Dict[str, List[Dict[str, Any]]],
    role: str,
    entity_type: str,
    raw_value: str,
    *,
    working_directory: str = "",
    working_directory_status: str = "unknown",
) -> str:
    if role not in entities or not _clean(raw_value):
        return ""
    item = _entity(
        entity_type,
        raw_value,
        working_directory=working_directory,
        working_directory_status=working_directory_status,
    )
    existing = next(
        (
            value
            for value in entities[role]
            if value.get("entity_id") == item["entity_id"]
        ),
        None,
    )
    if existing is None:
        entities[role].append(item)
    return item["entity_id"]


def _source_entity(item: Dict[str, Any]) -> Dict[str, Any]:
    normalized = _clean(item.get("normalized_value"))
    original = _clean(item.get("original_value"))
    uncertain = item.get("uncertain") is True
    linkable = item.get("linkable") is True and not uncertain
    candidate = normalized if linkable else ""
    entity_type = _clean(item.get("entity_type"))
    identity_value = normalized if linkable else f"unresolved:{normalized}"
    return {
        "entity_id": stable_id(
            "typed_semantic_entity",
            {"type": entity_type, "value": identity_value},
        ),
        "entity_type": entity_type,
        "normalized_value": normalized,
        "original_value": original,
        "uncertain": uncertain,
        "linkable": linkable,
        "uncertainty_reason": (
            _clean(item.get("uncertainty_reason")) or "none"
        ),
        "candidate_normalized_value": candidate,
        "source_entity_ref": _clean(item.get("entity_id")),
        "redacted_components": item.get("redacted_components") is True,
    }


def _merge_source_entities(
    entities: Dict[str, List[Dict[str, Any]]],
    source: Any,
) -> None:
    if not isinstance(source, dict):
        return
    for role, values in source.items():
        if role not in entities or not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, dict):
                continue
            normalized = _source_entity(value)
            if (
                normalized["entity_id"]
                and not any(
                    item["entity_id"] == normalized["entity_id"]
                    for item in entities[role]
                )
            ):
                entities[role].append(normalized)


def _shell_tokens(command: str) -> Tuple[str, str, List[str]]:
    if not _clean(command):
        return "empty", "missing_operand", []
    if "$(" in command or "`" in command or "<(" in command or ">(" in command:
        return "unsupported", "unsupported_shell_syntax", []
    try:
        lexer = shlex.shlex(
            command,
            posix=True,
            punctuation_chars="<>&|",
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return "malformed", "malformed_quoting", []
    if any(token in _UNSUPPORTED_SHELL_TOKENS for token in tokens):
        return "unsupported", "unsupported_shell_syntax", []
    if any("$" in token or "`" in token for token in tokens):
        return "unsupported", "expansion_unresolved", []
    return "parsed", "", tokens


def _unwrap(tokens: List[str]) -> Tuple[List[str], str]:
    output = list(tokens)
    while output and "=" in output[0] and not output[0].startswith(("/", "./")):
        name, _, _value = output[0].partition("=")
        if not name.replace("_", "a").isalnum() or name[0].isdigit():
            break
        output.pop(0)
    while output and posixpath.basename(output[0]).lower() in _WRAPPERS:
        wrapper = posixpath.basename(output.pop(0)).lower()
        if wrapper == "env":
            while output and (
                output[0] in {"-i", "--ignore-environment", "--"}
                or (
                    "=" in output[0]
                    and not output[0].startswith(("/", "./"))
                )
            ):
                output.pop(0)
        elif wrapper == "setsid":
            while output and output[0] in {
                "-c",
                "--ctty",
                "-f",
                "--fork",
                "-w",
                "--wait",
                "--",
            }:
                output.pop(0)
        elif output and output[0].startswith("-"):
            return [], "unsupported_option"
    return output, ""


def _redirections(
    tokens: List[str],
    entities: Dict[str, List[Dict[str, Any]]],
    working_directory: str,
    working_directory_status: str,
) -> Tuple[List[str], List[Dict[str, Any]], str]:
    arguments: List[str] = []
    redirects: List[Dict[str, Any]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token not in {"<", ">", ">>"}:
            arguments.append(token)
            index += 1
            continue
        if index + 1 >= len(tokens) or tokens[index + 1] in {"<", ">", ">>"}:
            return [], [], "missing_operand"
        if arguments and arguments[-1].isdigit():
            return [], [], "unsupported_shell_syntax"
        target = tokens[index + 1]
        role = {
            "<": "read_paths",
            ">": "created_paths",
            ">>": "appended_paths",
        }[token]
        entity_ref = _add_entity(
            entities,
            role,
            "path",
            target,
            working_directory=working_directory,
            working_directory_status=working_directory_status,
        )
        redirects.append({
            "operator": token,
            "target": target,
            "entity_ref": entity_ref,
        })
        index += 2
    return arguments, redirects, ""


def _non_options(arguments: Iterable[str]) -> List[str]:
    return [value for value in arguments if value and not value.startswith("-")]


def _pathish(value: str) -> bool:
    return bool(
        value
        and (
            value.startswith(("/", "./", "../", "~"))
            or "/" in value
        )
    )


def _unsupported_option(
    arguments: Iterable[str],
    *,
    exact: Iterable[str] = (),
    short_characters: str = "",
) -> bool:
    """Return true when an option is outside a deliberately small subset."""

    allowed = set(exact)
    for value in arguments:
        if value == "--":
            continue
        if not value.startswith("-") or value == "-":
            continue
        if value in allowed:
            continue
        if (
            short_characters
            and value.startswith("-")
            and not value.startswith("--")
            and all(character in short_characters for character in value[1:])
        ):
            continue
        return True
    return False


def _redirect_operation_types(
    redirects: Iterable[Dict[str, Any]],
) -> List[str]:
    return [
        {
            "<": "file_read",
            ">": "file_write",
            ">>": "file_append",
        }[item["operator"]]
        for item in redirects
    ]


def _operation(
    operation_type: str,
    *,
    proof_scope: str,
    entity_refs: Iterable[str] = (),
    source_literal_action: str = "",
) -> Dict[str, Any]:
    return {
        "operation_type": operation_type,
        "proof_scope": proof_scope,
        "entity_refs": _unique(entity_refs),
        "source_literal_action": _clean(source_literal_action),
    }


def _add_operation(
    operations: List[Dict[str, Any]],
    item: Dict[str, Any],
) -> None:
    signature = (
        item.get("operation_type"),
        tuple(item.get("entity_refs") or []),
        item.get("source_literal_action"),
    )
    if signature not in {
        (
            existing.get("operation_type"),
            tuple(existing.get("entity_refs") or []),
            existing.get("source_literal_action"),
        )
        for existing in operations
    }:
        operations.append(item)


def _read_path_entities(
    values: Iterable[str],
    entities: Dict[str, List[Dict[str, Any]]],
    working_directory: str,
    working_directory_status: str,
) -> List[str]:
    return [
        reference
        for reference in (
            _add_entity(
                entities,
                "read_paths",
                "path",
                value,
                working_directory=working_directory,
                working_directory_status=working_directory_status,
            )
            for value in values
        )
        if reference
    ]


def _general_operations(
    executable: str,
    arguments: List[str],
    redirects: List[Dict[str, Any]],
    *,
    operator_before: str,
    entities: Dict[str, List[Dict[str, Any]]],
    working_directory: str,
    working_directory_status: str,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    operations: List[Dict[str, Any]] = []
    abstentions: List[str] = []
    lowered = [value.lower() for value in arguments]
    non_options = _non_options(arguments)

    if executable == "uptime":
        if any(value not in {"-p", "--pretty", "-s", "--since"} for value in arguments):
            abstentions.append("unsupported_option")
        else:
            _add_operation(operations, _operation(
                "host_uptime_inspection",
                proof_scope="general_command_semantics",
            ))
    elif executable == "df":
        if _unsupported_option(
            arguments,
            exact={"--human-readable", "--si", "--portability"},
            short_characters="hHkPTi",
        ):
            return [], ["unsupported_option"]
        targets = [value for value in arguments if not value.startswith("-")]
        refs = _read_path_entities(
            targets,
            entities,
            working_directory,
            working_directory_status,
        )
        _add_operation(operations, _operation(
            "filesystem_capacity_inspection",
            proof_scope="general_command_semantics",
            entity_refs=refs,
        ))
    elif executable == "uname":
        if any(not value.startswith("-") for value in arguments):
            abstentions.append("unsupported_option")
        else:
            _add_operation(operations, _operation(
                "system_identity_inspection",
                proof_scope="general_command_semantics",
            ))
    elif executable in {"id", "whoami"}:
        if _unsupported_option(
            arguments,
            exact={"--user", "--group", "--groups", "--name"},
            short_characters="ugGnrz",
        ):
            return [], ["unsupported_option"]
        _add_operation(operations, _operation(
            "account_identity_inspection",
            proof_scope="general_command_semantics",
        ))
    elif executable == "hostname":
        if non_options:
            abstentions.append("unsupported_option")
        else:
            _add_operation(operations, _operation(
                "system_identity_inspection",
                proof_scope="general_command_semantics",
            ))
    elif executable == "ip":
        positional = [value.lower() for value in arguments if not value.startswith("-")]
        if positional[:2] in (["route", "show"], ["route", "list"]):
            _add_operation(operations, _operation(
                "network_route_inspection",
                proof_scope="general_command_semantics",
            ))
        else:
            abstentions.append("unsupported_option")
    elif executable == "ps":
        if any(
            value not in {"aux", "ax", "-ef", "-e", "-f", "-A"}
            for value in arguments
        ):
            return [], ["unsupported_option"]
        _add_operation(operations, _operation(
            "process_inspection",
            proof_scope="general_command_semantics",
        ))
    elif executable == "ss":
        if _unsupported_option(
            arguments,
            exact={"--numeric", "--listening", "--tcp", "--udp", "--processes"},
            short_characters="Hnltupaeo46",
        ):
            return [], ["unsupported_option"]
        else:
            _add_operation(operations, _operation(
                "network_socket_inspection",
                proof_scope="general_command_semantics",
            ))
    elif executable == "getent":
        if non_options and non_options[0].lower() == "passwd":
            ref = _add_entity(entities, "account_names", "account", "passwd")
            _add_operation(operations, _operation(
                "account_database_inspection",
                proof_scope="general_command_semantics",
                entity_refs=[ref],
            ))
        else:
            abstentions.append("unsupported_option")
    elif executable == "find":
        if any(
            value in {"-delete", "-exec", "-execdir", "-ok", "-okdir"}
            for value in arguments
        ):
            return [], ["unsupported_option"]
        sources: List[str] = []
        for value in arguments:
            if value.startswith("-") or value in {"!", "(", ")"}:
                break
            sources.append(value)
        if not sources:
            abstentions.append("missing_operand")
        else:
            refs = _read_path_entities(
                sources,
                entities,
                working_directory,
                working_directory_status,
            )
            _add_operation(operations, _operation(
                "filesystem_search",
                proof_scope="general_command_semantics",
                entity_refs=refs,
            ))
    elif executable in _READ_TOOLS or executable == "sed":
        in_place = executable == "sed" and any(
            value == "--in-place" or value.startswith("-i")
            for value in arguments
        )
        if executable == "sed":
            if _unsupported_option(
                arguments,
                exact={"--in-place", "-i", "-n", "--quiet", "--silent"},
            ):
                return [], ["unsupported_option"]
            positional = [
                value for value in arguments if not value.startswith("-")
            ]
            # The first positional token is the sed program, never a path.
            candidates = positional[1:] if positional else []
            if not positional:
                return [], ["missing_operand"]
        elif executable == "cat":
            if _unsupported_option(
                arguments,
                exact={
                    "--number",
                    "--number-nonblank",
                    "--show-all",
                    "--show-ends",
                    "--show-tabs",
                },
                short_characters="AbEnstTuv",
            ):
                return [], ["unsupported_option"]
            candidates = [
                value for value in arguments
                if not value.startswith("-") and value != "-"
            ]
        elif executable in {"head", "tail"}:
            # Count-taking options require a complete option/value pair.
            candidates = []
            index = 0
            while index < len(arguments):
                value = arguments[index]
                if value in {"-n", "--lines", "-c", "--bytes"}:
                    if index + 1 >= len(arguments):
                        return [], ["missing_operand"]
                    index += 2
                elif value.startswith("-"):
                    return [], ["unsupported_option"]
                else:
                    candidates.append(value)
                    index += 1
        elif executable in {"cut", "grep"}:
            # Pattern/field syntax is intentionally not interpreted.  Only a
            # simple option-free form is promoted, and the first operand is
            # the selector rather than a path.
            if any(value.startswith("-") for value in arguments):
                return [], ["unsupported_option"]
            candidates = arguments[1:] if arguments else []
            if not arguments:
                return [], ["missing_operand"]
        else:
            if _unsupported_option(
                arguments,
                exact={"--dereference", "--file-system"},
                short_characters="Lfc",
            ):
                return [], ["unsupported_option"]
            candidates = [
                value for value in arguments if not value.startswith("-")
            ]
        if not candidates and not (
            operator_before == "|"
            or any(item["operator"] == "<" for item in redirects)
        ):
            # Commands such as ``cat`` may read stdin, but without an
            # observed pipeline or input redirect there is no target identity.
            abstentions.append("ambiguous_operand")
        refs = _read_path_entities(
            candidates,
            entities,
            working_directory,
            working_directory_status,
        )
        _add_operation(operations, _operation(
            "file_read",
            proof_scope="general_command_semantics",
            entity_refs=refs,
        ))
        if in_place:
            modify_refs = [
                _add_entity(
                    entities,
                    "modified_paths",
                    "path",
                    value,
                    working_directory=working_directory,
                    working_directory_status=working_directory_status,
                )
                for value in candidates
            ]
            if not any(modify_refs):
                abstentions.append("missing_operand")
            else:
                _add_operation(operations, _operation(
                    "file_modify",
                    proof_scope="general_command_semantics",
                    entity_refs=modify_refs,
                ))
    elif executable in {"echo", "printf"}:
        if not arguments:
            abstentions.append("missing_operand")
        else:
            literal_ref = _add_entity(
                entities,
                "literal_values",
                "literal",
                "literal_argument_present",
            )
            _add_operation(operations, _operation(
                "literal_data_emission",
                proof_scope="general_command_semantics",
                entity_refs=[literal_ref],
            ))
    elif executable == "base64":
        decoding = any(value in {"-d", "--decode"} for value in lowered)
        if _unsupported_option(
            arguments,
            exact={"-d", "--decode", "--ignore-garbage"},
        ):
            return [], ["unsupported_option"]
        sources = [
            value
            for value in non_options
            if value.lower() not in {"decode"}
        ]
        has_stream_input = operator_before == "|" or any(
            item["operator"] == "<" for item in redirects
        )
        if not decoding:
            abstentions.append("unsupported_option")
        elif not sources and not has_stream_input:
            abstentions.append("missing_operand")
        else:
            refs = _read_path_entities(
                sources,
                entities,
                working_directory,
                working_directory_status,
            )
            _add_operation(operations, _operation(
                "decode_transform",
                proof_scope="general_command_semantics",
                entity_refs=refs,
            ))
    elif executable == "tar":
        option_token = next(
            (value for value in arguments if value.startswith("-")),
            "",
        )
        compact = option_token.lstrip("-")
        create = "c" in compact
        try:
            option_index = arguments.index(option_token)
        except ValueError:
            option_index = -1
        if (
            not create
            or "f" not in compact
            or option_index < 0
            or any(character not in "czjJvf" for character in compact)
            or any(
                value.startswith("-") and value != option_token
                for value in arguments
            )
        ):
            abstentions.append("unsupported_option")
        elif option_index + 2 >= len(arguments):
            abstentions.append("missing_operand")
        else:
            destination = arguments[option_index + 1]
            sources = [
                value
                for value in arguments[option_index + 2 :]
                if not value.startswith("-")
            ]
            if not sources:
                abstentions.append("missing_operand")
            else:
                destination_ref = _add_entity(
                    entities,
                    "archive_paths",
                    "path",
                    destination,
                    working_directory=working_directory,
                    working_directory_status=working_directory_status,
                )
                source_refs = _read_path_entities(
                    sources,
                    entities,
                    working_directory,
                    working_directory_status,
                )
                _add_operation(operations, _operation(
                    "file_read",
                    proof_scope="general_command_semantics",
                    entity_refs=source_refs,
                ))
                _add_operation(operations, _operation(
                    "archive_create",
                    proof_scope="general_command_semantics",
                    entity_refs=[destination_ref, *source_refs],
                ))
    elif executable == "crontab":
        if len(arguments) == 1 and arguments[0] in {"-l", "--list"}:
            _add_operation(operations, _operation(
                "schedule_inspect",
                proof_scope="general_command_semantics",
            ))
        elif len(arguments) == 1 and arguments[0] in {"-r", "--remove"}:
            _add_operation(operations, _operation(
                "schedule_delete",
                proof_scope="general_command_semantics",
            ))
        elif len(arguments) == 1 and arguments[0] in {"-e", "--edit"}:
            _add_operation(operations, _operation(
                "schedule_modify",
                proof_scope="general_command_semantics",
            ))
        elif any(value.startswith("-") for value in arguments):
            abstentions.append("unsupported_option")
        elif len(non_options) == 1:
            ref = _add_entity(
                entities,
                "schedule_targets",
                "schedule",
                non_options[-1],
            )
            _add_operation(operations, _operation(
                "schedule_modify",
                proof_scope="general_command_semantics",
                entity_refs=[ref],
            ))
        else:
            abstentions.append("missing_operand")
    elif executable == "systemctl":
        if any(value.startswith("-") for value in arguments):
            return [], ["unsupported_option"]
        subcommand = next(
            (value.lower() for value in arguments if not value.startswith("-")),
            "",
        )
        remaining = [
            value
            for value in non_options
            if value.lower() != subcommand
        ]
        refs = [
            _add_entity(entities, "service_names", "service", value)
            for value in remaining
        ]
        if subcommand in _SYSTEMCTL_READ:
            _add_operation(operations, _operation(
                "service_inspect",
                proof_scope="general_command_semantics",
                entity_refs=refs,
            ))
        elif subcommand in _SYSTEMCTL_MODIFY and (
            subcommand == "daemon-reload" or refs
        ):
            _add_operation(operations, _operation(
                "service_modify",
                proof_scope="general_command_semantics",
                entity_refs=refs,
            ))
        else:
            abstentions.append(
                "missing_operand" if not subcommand else "unsupported_option"
            )
    elif executable == "cd":
        if any(value.startswith("-") for value in arguments):
            abstentions.append("unsupported_option")
        elif len(non_options) != 1:
            abstentions.append("missing_operand")
        else:
            ref = _add_entity(
                entities,
                "destination_paths",
                "path",
                non_options[0],
                working_directory=working_directory,
                working_directory_status=working_directory_status,
            )
            _add_operation(operations, _operation(
                "working_directory_change",
                proof_scope="general_command_semantics",
                entity_refs=[ref],
            ))
    elif executable == "chmod":
        if _unsupported_option(
            arguments,
            exact={"--recursive", "--changes", "--quiet", "--silent", "--verbose"},
            short_characters="Rfcv",
        ):
            return [], ["unsupported_option"]
        if len(non_options) < 2:
            abstentions.append("missing_operand")
        else:
            targets = non_options[1:]
            refs = [
                _add_entity(
                    entities,
                    "modified_paths",
                    "path",
                    value,
                    working_directory=working_directory,
                    working_directory_status=working_directory_status,
                )
                for value in targets
            ]
            _add_operation(operations, _operation(
                "permission_modify",
                proof_scope="general_command_semantics",
                entity_refs=refs,
            ))
    elif executable == "rm":
        if _unsupported_option(
            arguments,
            exact={"--force", "--interactive", "--recursive", "--verbose"},
            short_characters="fIrRdv",
        ):
            return [], ["unsupported_option"]
        if not non_options:
            abstentions.append("missing_operand")
        else:
            refs = [
                _add_entity(
                    entities,
                    "deleted_paths",
                    "path",
                    value,
                    working_directory=working_directory,
                    working_directory_status=working_directory_status,
                )
                for value in non_options
            ]
            _add_operation(operations, _operation(
                "file_delete",
                proof_scope="general_command_semantics",
                entity_refs=refs,
            ))
    elif executable in _SHELL_EXECUTABLES or executable.startswith(
        _SCRIPT_EXECUTABLE_PREFIXES
    ):
        inline = "-c" in arguments
        if any(
            value.startswith("-") and value not in {"-c", "--"}
            for value in arguments
        ):
            return [], ["unsupported_option"]
        scripts = [
            value
            for value in non_options
            if value not in {"-c"}
        ]
        if inline:
            if arguments.index("-c") + 1 >= len(arguments):
                return [], ["missing_operand"]
            literal_ref = _add_entity(
                entities,
                "literal_values",
                "literal",
                "inline_program_present",
            )
            _add_operation(operations, _operation(
                "execution_attempt",
                proof_scope="general_command_semantics",
                entity_refs=[literal_ref],
            ))
        elif scripts:
            refs = [
                _add_entity(
                    entities,
                    "executed_paths",
                    "path",
                    scripts[0],
                    working_directory=working_directory,
                    working_directory_status=working_directory_status,
                )
            ]
            _add_operation(operations, _operation(
                "execution_attempt",
                proof_scope="general_command_semantics",
                entity_refs=refs,
            ))
        elif operator_before != "|":
            abstentions.append("missing_operand")
    elif executable in {"curl", "wget"}:
        if executable == "curl":
            value_options = {
                "-o",
                "--output",
                "--connect-timeout",
                "--max-time",
                "-A",
                "--user-agent",
            }
            flags = {
                "-L",
                "--location",
                "-s",
                "--silent",
                "-S",
                "--show-error",
                "-f",
                "--fail",
            }
        else:
            value_options = {
                "-O",
                "-o",
                "--output-document",
                "--timeout",
                "--user-agent",
            }
            flags = {"-q", "--quiet", "-nv", "--no-verbose"}
        index = 0
        while index < len(arguments):
            value = arguments[index]
            if value in value_options:
                if index + 1 >= len(arguments):
                    return [], ["missing_operand"]
                index += 2
            elif value in flags or not value.startswith("-"):
                index += 1
            else:
                return [], ["unsupported_option"]
        url_refs = [
            value.get("entity_id")
            for value in entities.get("urls") or []
            if value.get("entity_id")
        ]
        if not url_refs:
            abstentions.append("missing_operand")
        else:
            destination_refs = [
                value.get("entity_id")
                for value in entities.get("destination_paths") or []
                if value.get("entity_id")
            ]
            _add_operation(operations, _operation(
                "remote_content_access",
                proof_scope="general_command_semantics",
                entity_refs=[*url_refs, *destination_refs],
            ))
            _add_operation(operations, _operation(
                "transfer_attempt",
                proof_scope="general_command_semantics",
                entity_refs=[*url_refs, *destination_refs],
            ))
    elif executable == "cp":
        if len(non_options) < 2:
            abstentions.append("missing_operand")
        else:
            source_refs = _read_path_entities(
                non_options[:-1],
                entities,
                working_directory,
                working_directory_status,
            )
            destination_ref = _add_entity(
                entities,
                "created_paths",
                "path",
                non_options[-1],
                working_directory=working_directory,
                working_directory_status=working_directory_status,
            )
            _add_operation(operations, _operation(
                "file_read",
                proof_scope="general_command_semantics",
                entity_refs=source_refs,
            ))
            _add_operation(operations, _operation(
                "file_write",
                proof_scope="general_command_semantics",
                entity_refs=[destination_ref],
            ))
    elif executable == "mv":
        if len(non_options) < 2:
            abstentions.append("missing_operand")
        else:
            refs = [
                _add_entity(
                    entities,
                    "source_paths" if index < len(non_options) - 1 else "destination_paths",
                    "path",
                    value,
                    working_directory=working_directory,
                    working_directory_status=working_directory_status,
                )
                for index, value in enumerate(non_options)
            ]
            _add_operation(operations, _operation(
                "file_move",
                proof_scope="general_command_semantics",
                entity_refs=refs,
            ))
    elif executable == "mkdir":
        if not non_options:
            abstentions.append("missing_operand")
        else:
            refs = [
                _add_entity(
                    entities,
                    "created_paths",
                    "path",
                    value,
                    working_directory=working_directory,
                    working_directory_status=working_directory_status,
                )
                for value in non_options
            ]
            _add_operation(operations, _operation(
                "directory_create",
                proof_scope="general_command_semantics",
                entity_refs=refs,
            ))
    else:
        abstentions.append("unsupported_executable")
    return operations, _unique(abstentions)


def extract_typed_semantics(
    observation: Dict[str, Any],
    *,
    working_directory: str,
    working_directory_status: str,
    policy: Dict[str, Any],
) -> Dict[str, Any]:
    """Return typed operations and entities without interpreting full shell."""

    entities = _empty_entities(policy)
    _merge_source_entities(entities, observation.get("entities") or {})
    parse_status, parse_reason, tokens = _shell_tokens(
        _clean(observation.get("command"))
    )
    operations: List[Dict[str, Any]] = []
    abstentions: List[str] = [parse_reason] if parse_reason else []
    redirects: List[Dict[str, Any]] = []
    executable = ""
    arguments: List[str] = []

    if parse_status == "parsed":
        unwrapped, wrapper_error = _unwrap(tokens)
        if wrapper_error:
            parse_status = "unsupported"
            abstentions.append(wrapper_error)
        elif not unwrapped:
            parse_status = "empty"
            abstentions.append("missing_operand")
        else:
            without_redirects, redirects, redirect_error = _redirections(
                unwrapped,
                entities,
                working_directory,
                working_directory_status,
            )
            if redirect_error:
                parse_status = "unsupported"
                abstentions.append(redirect_error)
            elif not without_redirects:
                parse_status = "empty"
                abstentions.append("missing_operand")
            else:
                executable = posixpath.basename(without_redirects[0]).lower()
                arguments = without_redirects[1:]
                general, general_abstentions = _general_operations(
                    executable,
                    arguments,
                    redirects,
                    operator_before=_clean(observation.get("operator_before")),
                    entities=entities,
                    working_directory=working_directory,
                    working_directory_status=working_directory_status,
                )
                operations.extend(general)
                abstentions.extend(general_abstentions)

                hard_abstention = bool(
                    {
                        "missing_operand",
                        "unsupported_executable",
                        "unsupported_option",
                        "ambiguous_operand",
                    }
                    & set(general_abstentions)
                )
                literal_map = policy.get("literal_action_map") or {}
                if not hard_abstention:
                    for literal in observation.get("action_types") or []:
                        operation_type = literal_map.get(literal)
                        if not operation_type:
                            continue
                        refs = [
                            item.get("entity_id")
                            for values in entities.values()
                            for item in values
                            if isinstance(item, dict)
                            and item.get("entity_id")
                        ]
                        if operation_type == "credential_path_read":
                            credential_refs = {
                                item.get("entity_id")
                                for item in entities.get(
                                    "credential_paths", []
                                )
                                if isinstance(item, dict)
                                and item.get("entity_id")
                            }
                            general_read_refs = {
                                entity_ref
                                for operation in operations
                                if operation.get("operation_type")
                                == "file_read"
                                for entity_ref in (
                                    operation.get("entity_refs") or []
                                )
                            }
                            refs = sorted(
                                credential_refs & general_read_refs
                            )
                            if not refs:
                                continue
                        existing = next(
                            (
                                item
                                for item in operations
                                if item.get("operation_type") == operation_type
                            ),
                            None,
                        )
                        if existing is not None:
                            existing["entity_refs"] = _unique([
                                *existing.get("entity_refs", []),
                                *refs,
                            ])
                            existing["source_literal_action"] = literal
                        else:
                            _add_operation(operations, _operation(
                                operation_type,
                                proof_scope="literal_command",
                                entity_refs=refs,
                                source_literal_action=literal,
                            ))

                for redirect in redirects:
                    operation_type = {
                        "<": "file_read",
                        ">": "file_write",
                        ">>": "file_append",
                    }[redirect["operator"]]
                    _add_operation(operations, _operation(
                        operation_type,
                        proof_scope="shell_syntax",
                        entity_refs=[redirect["entity_ref"]],
                    ))

    abstentions = _unique(abstentions)
    if parse_status != "parsed":
        operations = []
    if not operations:
        operations = [_operation(
            "unknown",
            proof_scope="unresolved",
        )]
    return {
        "parse": {
            "status": parse_status,
            "abstention_reasons": abstentions,
            "executable": executable,
            "arguments": arguments,
            "redirections": redirects,
        },
        "operations": operations,
        "entities": entities,
    }


def extract_transfer_semantics(
    observation: Dict[str, Any],
    *,
    working_directory: str,
    working_directory_status: str,
    policy: Dict[str, Any],
) -> Dict[str, Any]:
    entities = _empty_entities(policy)
    _merge_source_entities(entities, observation.get("entities") or {})
    references = [
        item.get("entity_id")
        for values in entities.values()
        for item in values
        if isinstance(item, dict) and item.get("entity_id")
    ]
    return {
        "parse": {
            "status": "parsed",
            "abstention_reasons": [],
            "executable": "",
            "arguments": [],
            "redirections": [],
        },
        "operations": [_operation(
            "transfer_observed",
            proof_scope="direct_cowrie_event",
            entity_refs=references,
            source_literal_action="cowrie_file_transfer_observed",
        )],
        "entities": deepcopy(entities),
    }
