"""Notebook process tree and behavior provenance graph helpers."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List


@dataclass
class ProcessNode:
    pid: int
    ppid: int
    image: str
    command_line: str
    timestamp: str = ""
    user: str = ""
    children: List["ProcessNode"] = field(default_factory=list)
    src_ip: str = ""
    session_id: str = ""
    ioc_force_high: bool = False
    file_hash: str = ""
    success: bool = True
    dst_port: int = 0
    suspicious: bool = False
    is_shell_node: bool = False

    @property
    def name(self) -> str:
        return self.image.replace("\\", "/").split("/")[-1]


@dataclass
class ProcessSession:
    root_pid: int
    root_name: str
    nodes: List[ProcessNode] = field(default_factory=list)

    @property
    def events(self) -> List[Dict[str, str]]:
        return [{"UtcTime": node.timestamp} for node in self.nodes if node.timestamp]

    @property
    def commands(self) -> List[str]:
        return [node.command_line for node in self.nodes if node.command_line.strip()]

    @property
    def commands_success(self) -> List[str]:
        return [node.command_line for node in self.nodes if node.command_line.strip() and node.success]

    @property
    def all_text(self) -> str:
        return "\n".join(self.commands)

    @property
    def all_text_success(self) -> str:
        return "\n".join(self.commands_success)


TRANSPARENT_PROCESSES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "explorer.exe", "services.exe", "svchost.exe",
    "bash", "sh", "dash", "zsh", "fish", "sudo", "su", "login", "sshd",
}


def _node_from_dict(event: Dict[str, Any]) -> ProcessNode:
    return ProcessNode(
        pid=int(event.get("ProcessId", event.get("pid", 0)) or 0),
        ppid=int(event.get("ParentProcessId", event.get("ppid", 0)) or 0),
        image=event.get("Image", event.get("image", "")),
        command_line=(event.get("CommandLine", event.get("command_line", "")) or "").strip(),
        timestamp=str(event.get("UtcTime", event.get("timestamp", ""))),
        user=event.get("User", event.get("user", "")),
        src_ip=event.get("_src_ip", ""),
        session_id=event.get("_session_id", ""),
        ioc_force_high=bool(event.get("_ioc_force_high", False)),
        file_hash=event.get("_file_hash", ""),
        success=bool(event.get("_success", True)),
        dst_port=int(event.get("_dst_port", 0) or 0),
        suspicious=bool(event.get("_suspicious", False)),
        is_shell_node=bool(event.get("_is_shell_node", False)),
    )


def parse_dict_logs(logs: Iterable[Dict[str, Any]]) -> List[ProcessNode]:
    nodes = []
    for event in logs:
        try:
            nodes.append(_node_from_dict(event))
        except (TypeError, ValueError):
            continue
    return nodes


def parse_csv_logs(text: str) -> List[ProcessNode]:
    return parse_dict_logs(csv.DictReader(io.StringIO(text)))


def parse_raw_text(text: str) -> List[ProcessNode]:
    nodes = []
    for index, line in enumerate(text.splitlines(), 1000):
        command = line.strip()
        if command:
            nodes.append(ProcessNode(index, index - 1 if index > 1000 else 0, "unknown", command))
    return nodes


def build_tree(nodes: List[ProcessNode]) -> Dict[int, ProcessNode]:
    pid_map = {node.pid: node for node in nodes}
    for node in nodes:
        parent = pid_map.get(node.ppid)
        if parent and parent.pid != node.pid:
            parent.children.append(node)
    return pid_map


def collect_subtree(node: ProcessNode) -> List[ProcessNode]:
    result = [node]
    for child in node.children:
        result.extend(collect_subtree(child))
    return result


def build_sessions(nodes: List[ProcessNode]) -> List[ProcessSession]:
    pid_map = build_tree(nodes)
    roots = [node for node in nodes if node.ppid not in pid_map]
    sessions: List[ProcessSession] = []
    for root in roots:
        if root.name.lower() in TRANSPARENT_PROCESSES and root.children:
            for child in root.children:
                sessions.append(ProcessSession(child.pid, child.name, collect_subtree(child)))
        else:
            sessions.append(ProcessSession(root.pid, root.name, collect_subtree(root)))
    return [session for session in sessions if session.commands]


def parse_and_build_sessions(source: Any) -> List[ProcessSession]:
    if isinstance(source, list):
        nodes = parse_dict_logs(source)
    elif isinstance(source, str):
        if "CommandLine" in source[:300] or "ProcessId" in source[:300]:
            nodes = parse_csv_logs(source)
        else:
            nodes = parse_raw_text(source)
    else:
        raise TypeError(f"Unsupported input type: {type(source)}")
    return build_sessions(nodes) if nodes else []


def build_bpg(session: ProcessSession) -> Dict[str, Any]:
    chain = [
        node.command_line
        for node in session.nodes
        if node.command_line.strip() and not node.is_shell_node and node.success
    ]
    seen, unique_chain = set(), []
    for command in chain:
        if command not in seen:
            seen.add(command)
            unique_chain.append(command)
    return {
        "session": f"{session.root_name} (PID {session.root_pid})",
        "chain": unique_chain,
        "chain_str": " -> ".join(command[:60] for command in unique_chain),
        "depth": len(unique_chain),
    }


def process_events_to_context(process_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    sessions = parse_and_build_sessions(process_events)
    return {
        "process_session_count": len(sessions),
        "process_sessions": [
            {
                "root_pid": session.root_pid,
                "root_name": session.root_name,
                "commands": session.commands,
                "commands_success": session.commands_success,
            }
            for session in sessions
        ],
        "bpg_list": [build_bpg(session) for session in sessions],
    }
