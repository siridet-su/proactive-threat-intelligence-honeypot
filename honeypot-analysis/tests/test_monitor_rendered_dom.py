from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


MONITOR_HTML = Path(__file__).parents[1] / "production" / "api" / "static" / "monitor.html"


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is required for the rendered-DOM regression")
def test_admin_authorized_commands_replace_only_matching_cells() -> None:
    html = MONITOR_HTML.read_text(encoding="utf-8")
    assert "UNIQUE_RENDERED_DOM_RAW_COMMAND" not in html
    assert "Reveal with admin token" in html
    assert "window.prompt" in html
    assert "void loadInternalCommands(adminToken, state.detailSessionId);" in html
    loader_start = html.index("    async function loadInternalCommands")
    loader_end = html.index("    function normalizedEventType", loader_start)
    assert loader_start >= 0 and loader_end > loader_start
    loader = html[loader_start:loader_end]
    assert "/api/internal/session-commands?session_id=" in loader
    assert "cache: 'no-store'" in loader
    assert "'Authorization': `Bearer ${token}`" in loader
    node_script = r'''
const fs = require("fs");
const vm = require("vm");
const html = fs.readFileSync(0, "utf8");
const start = html.indexOf("    function normalizedEventType");
const end = html.indexOf("    function renderSensitiveCommandChain", start);
if (start < 0 || end < 0) throw new Error("sensitive command helpers are not present");
const block = html.slice(start, end);
const context = { window: {}, document: {}, console };
vm.runInNewContext(
    "function arrayMaybe(value) { return Array.isArray(value) ? value : []; }\n" + block + "\nwindow.__monitorSensitiveCommandTestHooks = { mapSensitiveCommands, applySensitiveCommandsToExecutionChain };",
    context,
);
const hooks = context.window.__monitorSensitiveCommandTestHooks;
if (!hooks) throw new Error("test hooks were not exported");

const events = [
    { event_id: "event-1", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:01Z", payload: {} },
    { event_id: "event-2", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:02Z", payload: {} },
];
const commands = [
    { event_id: "event-1", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:01Z", input: "UNIQUE_RENDERED_DOM_RAW_COMMAND" },
    { event_id: "not-an-event", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:02Z", input: "must-not-render" },
];
const mapping = hooks.mapSensitiveCommands(events, commands);
if (mapping.matches.length !== 1 || mapping.unmatched.length !== 1) throw new Error("stable event mapping failed");
const nodes = [
    { dataset: { commandEventId: "event-1", commandTimestamp: "2026-08-05T00:00:01Z" }, textContent: "command content withheld by privacy policy" },
    { dataset: { commandEventId: "event-2", commandTimestamp: "2026-08-05T00:00:02Z" }, textContent: "command content withheld by privacy policy" },
];
const root = { querySelectorAll: () => nodes };
if (hooks.applySensitiveCommandsToExecutionChain(mapping.matches, root) !== 1) throw new Error("DOM update count mismatch");
if (nodes[0].textContent !== "UNIQUE_RENDERED_DOM_RAW_COMMAND") throw new Error("matched raw command was not rendered");
if (nodes[1].textContent !== "command content withheld by privacy policy") throw new Error("unmatched row lost privacy placeholder");

const fallback = hooks.mapSensitiveCommands(
    [{ event_id: "", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:03Z", payload: {} }],
    [{ event_id: "", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:03Z", input: "timestamp-fallback" }],
);
if (fallback.matches.length !== 1) throw new Error("unique timestamp fallback failed");
const ambiguous = hooks.mapSensitiveCommands(
    [
        { event_id: "", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:04Z", payload: {} },
        { event_id: "", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:04Z", payload: {} },
    ],
    [{ event_id: "", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:04Z", input: "ambiguous" }],
);
if (ambiguous.matches.length !== 0 || ambiguous.unmatched.length !== 1) throw new Error("ambiguous fallback was promoted");
const duplicate = hooks.mapSensitiveCommands(
    [{ event_id: "event-duplicate", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:05Z", payload: {} }],
    [
        { event_id: "event-duplicate", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:05Z", input: "first" },
        { event_id: "event-duplicate", eventid: "cowrie.command.input", timestamp: "2026-08-05T00:00:05Z", input: "second" },
    ],
);
if (duplicate.matches.length !== 1 || duplicate.unmatched.length !== 1) throw new Error("duplicate event identity was promoted");
'''
    completed = subprocess.run(
        ["node", "-e", node_script],
        input=html,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
