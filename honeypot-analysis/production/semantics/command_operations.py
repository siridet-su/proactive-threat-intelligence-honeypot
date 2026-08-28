"""Conservative, side-effect-free command-operation parsing.

The parser recognizes syntax and literal operands only.  It does not execute a
shell, assign ATT&CK techniques, infer command success, or claim real-host
effects.  Callers must independently bind parsed operations to authoritative
Cowrie observations and outcomes.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from copy import deepcopy
from typing import Any, Iterable


SCHEMA_VERSION = "command_operation_parse.v1"
_WRAPPERS = {"env", "nohup", "setsid", "sudo"}
_SHELL_INTERPRETERS = {"bash", "dash", "ksh", "sh", "zsh"}
_SCRIPT_INTERPRETERS = {
    *_SHELL_INTERPRETERS,
    "lua",
    "node",
    "perl",
    "php",
    "python",
    "python2",
    "python3",
    "ruby",
}
_READ_COMMANDS = {
    "cat",
    "grep",
    "head",
    "less",
    "more",
    "tail",
    "wc",
}
_REDIRECTS = {"<", ">", ">>"}
_UNSUPPORTED_SHELL_TOKENS = {
    "&",
    "&&",
    "(",
    ")",
    ";",
    "<>",
    "<&",
    ">|",
    ">&",
    "<<<",
    "<<",
    "|",
    "||",
}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = _clean(value)
        if text and text not in result:
            result.append(text)
    return result


def _result(command: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "parse_status": "empty",
        "abstention_reason": "missing_operand",
        "command_family": "",
        "executable": "",
        "wrappers": [],
        "options": [],
        "operands": [],
        "redirections": [],
        "operation_types": [],
        "entities": {},
        "tokens": [],
        "unwrapped_tokens": [],
    }


def _path(raw: str, cwd: str, cwd_status: str) -> dict[str, Any]:
    value = _clean(raw)
    item = {
        "raw_value": value,
        "normalized_value": value,
        "resolution_status": "unresolved",
        "linkable": False,
    }
    if not value:
        return item
    if any(marker in value for marker in ("$", "`", "*", "?", "[", "]")):
        item["resolution_status"] = "dynamic_path_not_resolved"
        return item
    if value.startswith("~"):
        item["resolution_status"] = "home_directory_not_resolved"
        return item
    if value.startswith("/"):
        item.update({
            "normalized_value": posixpath.normpath(value),
            "resolution_status": "recorded_resolved",
            "linkable": True,
        })
        return item
    if _clean(cwd).startswith("/") and _clean(cwd_status) in {
        "confirmed",
        "observed",
    }:
        item.update({
            "normalized_value": posixpath.normpath(
                posixpath.join(_clean(cwd), value)
            ),
            "resolution_status": "context_resolved",
            "linkable": True,
        })
        return item
    item["normalized_value"] = f"relative:{posixpath.normpath(value)}"
    item["resolution_status"] = (
        "conditional_working_directory"
        if _clean(cwd).startswith("/")
        else "working_directory_unknown"
    )
    return item


def _tokenize(command: str) -> tuple[list[str], str]:
    if not _clean(command):
        return [], "missing_operand"
    if any(marker in command for marker in ("$(", "`", "<(", ">(")):
        return [], "unsupported_shell_syntax"
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="<>&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return [], "malformed_quoting"
    if any(token in _UNSUPPORTED_SHELL_TOKENS for token in tokens):
        return [], "unsupported_shell_syntax"
    if any("$" in token or "`" in token for token in tokens):
        return [], "expansion_unresolved"
    if any(any(marker in token for marker in ("*", "?", "[", "]")) for token in tokens):
        return [], "wildcard_not_resolved"
    return tokens, ""


def _unwrap(tokens: list[str]) -> tuple[list[str], list[str], str]:
    remaining = list(tokens)
    wrappers: list[str] = []
    while remaining and _ASSIGNMENT.fullmatch(remaining[0]):
        remaining.pop(0)
    while remaining and posixpath.basename(remaining[0]).lower() in _WRAPPERS:
        wrapper = posixpath.basename(remaining.pop(0)).lower()
        wrappers.append(wrapper)
        if wrapper == "env":
            while remaining and (
                remaining[0] in {"-i", "--ignore-environment", "--"}
                or _ASSIGNMENT.fullmatch(remaining[0])
            ):
                remaining.pop(0)
        elif wrapper == "setsid":
            while remaining and remaining[0] in {
                "-c",
                "--ctty",
                "-f",
                "--fork",
                "-w",
                "--wait",
                "--",
            }:
                remaining.pop(0)
        elif remaining and remaining[0].startswith("-"):
            return [], wrappers, "unsupported_wrapper_option"
    return remaining, wrappers, ""


def _remove_redirections(
    tokens: list[str], cwd: str, cwd_status: str
) -> tuple[list[str], list[dict[str, Any]], str]:
    remaining: list[str] = []
    redirects: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token not in _REDIRECTS:
            remaining.append(token)
            index += 1
            continue
        if index + 1 >= len(tokens) or tokens[index + 1] in _REDIRECTS:
            return [], [], "missing_operand"
        target = tokens[index + 1]
        redirects.append({
            "operator": token,
            "target": target,
            "path": _path(target, cwd, cwd_status),
        })
        index += 2
    return remaining, redirects, ""


def _add_entity(
    output: dict[str, Any], role: str, value: str, cwd: str, cwd_status: str
) -> None:
    item = _path(value, cwd, cwd_status)
    values = output["entities"].setdefault(role, [])
    if item not in values:
        values.append(item)


def _read_operands(executable: str, arguments: list[str]) -> list[str]:
    if executable == "cat":
        return [value for value in arguments if value != "--" and not value.startswith("-")]
    # These utilities accept option values.  The typed parser remains the
    # authoritative detailed operand parser; structural classification needs
    # only literal path operands and therefore takes the final non-option.
    candidates = [value for value in arguments if value != "--" and not value.startswith("-")]
    return candidates[-1:] if candidates else []


def parse_command_operation(
    command: str,
    *,
    working_directory: str = "",
    working_directory_status: str = "",
) -> dict[str, Any]:
    """Parse one already-split command fragment into neutral operations."""

    text = _clean(command)
    result = _result(text)
    tokens, error = _tokenize(text)
    if error:
        result["parse_status"] = "malformed" if error == "malformed_quoting" else "unsupported"
        result["abstention_reason"] = error
        return result
    result["tokens"] = list(tokens)
    unwrapped, wrappers, error = _unwrap(tokens)
    result["wrappers"] = wrappers
    if error or not unwrapped:
        result["parse_status"] = "unsupported" if error else "empty"
        result["abstention_reason"] = error or "missing_operand"
        return result
    without_redirects, redirects, error = _remove_redirections(
        unwrapped, working_directory, working_directory_status
    )
    result["redirections"] = redirects
    if error or not without_redirects:
        result["parse_status"] = "unsupported" if error else "empty"
        result["abstention_reason"] = error or "missing_operand"
        return result
    result["unwrapped_tokens"] = list(without_redirects)
    executable_token = without_redirects[0]
    executable = posixpath.basename(executable_token).lower()
    arguments = without_redirects[1:]
    result.update({
        "parse_status": "parsed",
        "abstention_reason": "",
        "command_family": executable,
        "executable": executable_token,
        "options": [value for value in arguments if value.startswith("-")],
        "operands": [value for value in arguments if not value.startswith("-")],
    })

    operations: list[str] = []
    if executable == "crontab":
        if arguments in (["-l"], ["--list"]):
            operations.append("schedule_inspect")
        elif arguments in (["-e"], ["--edit"]):
            operations.append("schedule_modify")
        elif arguments in (["-r"], ["--remove"]):
            operations.append("schedule_delete")
        elif len(arguments) == 1 and not arguments[0].startswith("-"):
            operations.append("schedule_modify")
            _add_entity(
                result,
                "schedule_targets",
                arguments[0],
                working_directory,
                working_directory_status,
            )
        else:
            result["parse_status"] = "unsupported"
            result["abstention_reason"] = "unsupported_option"
    elif executable in _READ_COMMANDS:
        operands = _read_operands(executable, arguments)
        if operands:
            operations.append("file_read")
            for operand in operands:
                _add_entity(
                    result,
                    "read_paths",
                    operand,
                    working_directory,
                    working_directory_status,
                )
    elif executable in {"chmod", "chown", "chgrp"}:
        operands = [value for value in arguments if not value.startswith("-")]
        if len(operands) >= 2:
            operations.append("permission_modify")
            for operand in operands[1:]:
                _add_entity(
                    result,
                    "modified_paths",
                    operand,
                    working_directory,
                    working_directory_status,
                )
    elif executable == "uptime" and all(
        value in {"-p", "--pretty", "-s", "--since"}
        for value in arguments
    ):
        operations.append("host_uptime_inspection")
    elif executable == "df":
        operations.append("filesystem_capacity_inspection")
        for operand in [value for value in arguments if not value.startswith("-")]:
            _add_entity(
                result,
                "read_paths",
                operand,
                working_directory,
                working_directory_status,
            )
    elif executable == "uname":
        operations.append("system_identity_inspection")
    elif executable in {"id", "whoami"}:
        operations.append("account_identity_inspection")
    elif executable == "ip" and arguments and arguments[0] in {"route", "address", "addr", "link"}:
        operations.append("network_route_inspection")
    elif executable == "ps":
        operations.append("process_inspection")
    elif executable in {"ss", "netstat"}:
        operations.append("network_socket_inspection")
    elif executable == "getent" and arguments and arguments[0] == "passwd":
        operations.append("account_database_inspection")
    elif executable == "find" and arguments:
        operations.append("filesystem_search")
        _add_entity(
            result,
            "read_paths",
            arguments[0],
            working_directory,
            working_directory_status,
        )
    elif executable == "systemctl" and arguments:
        if arguments[0] in {"status", "show", "is-active", "is-enabled"}:
            operations.append("service_inspect")
        elif arguments[0] in {
            "start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask"
        }:
            operations.append("service_modify")
        else:
            result["parse_status"] = "unsupported"
            result["abstention_reason"] = "unsupported_option"
    elif executable == "rm":
        operands = [value for value in arguments if not value.startswith("-")]
        if operands:
            operations.append("file_delete")
            for operand in operands:
                _add_entity(
                    result,
                    "deleted_paths",
                    operand,
                    working_directory,
                    working_directory_status,
                )
    elif executable == "mkdir":
        operands = [value for value in arguments if not value.startswith("-")]
        if operands:
            operations.append("directory_create")
            for operand in operands:
                _add_entity(
                    result,
                    "created_paths",
                    operand,
                    working_directory,
                    working_directory_status,
                )
    elif executable in _SCRIPT_INTERPRETERS:
        if "-c" in arguments:
            index = arguments.index("-c")
            if index + 1 < len(arguments):
                operations.append("execution_attempt")
                result["entities"]["literal_values"] = [{
                    "raw_value": "inline_program_present",
                    "normalized_value": "inline_program_present",
                    "resolution_status": "literal_identity",
                    "linkable": True,
                }]
            else:
                result["parse_status"] = "unsupported"
                result["abstention_reason"] = "missing_operand"
        else:
            script_index = next(
                (
                    index
                    for index, value in enumerate(arguments)
                    if value == "--" or not value.startswith("-")
                ),
                None,
            )
            if script_index is not None:
                if arguments[script_index] == "--":
                    script_index += 1
                if script_index < len(arguments):
                    script = arguments[script_index]
                    path = _path(script, working_directory, working_directory_status)
                    if path["linkable"]:
                        operations.append("execution_attempt")
                        _add_entity(
                            result,
                            "executed_paths",
                            script,
                            working_directory,
                            working_directory_status,
                        )
                    else:
                        result["parse_status"] = "unsupported"
                        result["abstention_reason"] = path["resolution_status"]
    elif executable_token.startswith(("/", "./", "../")):
        path = _path(executable_token, working_directory, working_directory_status)
        if path["linkable"]:
            operations.append("execution_attempt")
            _add_entity(
                result,
                "executed_paths",
                executable_token,
                working_directory,
                working_directory_status,
            )
        else:
            result["parse_status"] = "unsupported"
            result["abstention_reason"] = path["resolution_status"]

    result["operation_types"] = _unique(operations)
    return deepcopy(result)


def structural_predicate_matches(
    parsed: dict[str, Any], predicate: dict[str, Any]
) -> bool:
    """Evaluate a reviewed, closed structural rule against parsed syntax."""

    if parsed.get("parse_status") != "parsed" or not isinstance(predicate, dict):
        return False
    families = {_clean(value).lower() for value in predicate.get("command_families") or []}
    required = {_clean(value) for value in predicate.get("required_operation_types") or []}
    operations = set(parsed.get("operation_types") or [])
    if families and _clean(parsed.get("command_family")).lower() not in families:
        return False
    if required and not required.issubset(operations):
        return False
    expected_paths = {
        posixpath.normpath(_clean(value))
        for value in predicate.get("operand_paths_any") or []
        if _clean(value).startswith("/")
    }
    if expected_paths:
        observed_paths = {
            _clean(item.get("normalized_value"))
            for values in (parsed.get("entities") or {}).values()
            for item in values or []
            if isinstance(item, dict) and item.get("linkable") is True
        }
        if not expected_paths.intersection(observed_paths):
            return False
    return bool(families or required or expected_paths)
