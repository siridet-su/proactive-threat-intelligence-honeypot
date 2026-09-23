// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";

import { ForensicTimestampRow } from "../src/components/filesystem/ForensicTimestamp";
import { FilesystemInspector } from "../src/components/filesystem/FilesystemInspector";
import { formatSessionMetadata } from "../src/components/filesystem/AuditSessionSelect";
import { deriveForensicTimestamp, formatTimestamp } from "../src/components/filesystem/filesystemUtils";
import type { FilesystemClosedSession } from "../src/lib/dashboardTypes";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const closedSession = {
  sessionId: "forensic-time-session",
  sourceIp: "198.51.100.80",
  lifecycle: {
    startedAt: "2026-09-23T02:10:00.000Z",
    closedAt: "2026-09-23T02:15:00.000Z",
  },
  cwdState: {
    path: "/var/log",
    status: "confirmed",
    observedAt: "2026-09-23T02:14:30.000Z",
    sourceEventId: "event-time",
  },
  auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 2 },
} as FilesystemClosedSession;

describe("FSV-013 forensic time presentation", () => {
  it("formats absolute evidence time in an explicit, stable UTC zone", () => {
    expect(formatTimestamp("2026-09-23T02:15:00.000Z")).toContain("UTC");
    expect(formatTimestamp("2026-09-23T02:15:00.000Z")).toContain("23 Sept 2026");

    expect(deriveForensicTimestamp("Closed", closedSession.lifecycle.closedAt)).toMatchObject({
      label: "Closed",
      zone: "UTC",
      iso: "2026-09-23T02:15:00.000Z",
      available: true,
    });
    expect(deriveForensicTimestamp("Observed", "invalid")).toEqual({
      label: "Observed",
      zone: "UTC",
      iso: null,
      absolute: "unavailable",
      available: false,
    });
  });

  it("uses explicit Observed and Closed labels with UTC in session-list metadata", () => {
    const retained = formatSessionMetadata(closedSession);
    expect(retained.timeStr).toMatch(/^Closed .* UTC$/);

    const active = formatSessionMetadata({
      ...closedSession,
      lifecycle: undefined,
    } as never);
    expect(active.timeStr).toMatch(/^Observed .* UTC$/);
    expect(active.timeStr).not.toContain("Last observed");
  });

  it("copies the exact authoritative ISO value from a labelled detail row", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const container = document.createElement("div");
    const root = createRoot(container);
    await act(async () => root.render(createElement(ForensicTimestampRow, {
      label: "Closed",
      value: closedSession.lifecycle.closedAt,
      copyable: true,
    })));

    const time = container.querySelector("time");
    expect(time?.dateTime).toBe("2026-09-23T02:15:00.000Z");
    expect(time?.textContent).toContain("UTC");
    const copy = container.querySelector<HTMLButtonElement>('button[aria-label="Copy Closed ISO timestamp"]');
    expect(copy).not.toBeNull();
    await act(async () => copy?.click());
    expect(writeText).toHaveBeenCalledWith("2026-09-23T02:15:00.000Z");
    await act(async () => root.unmount());
  });

  it("wires Observed, Started, and Closed labelled copyable times into retained-session details", async () => {
    const container = document.createElement("div");
    const root = createRoot(container);
    await act(async () => root.render(createElement(FilesystemInspector, {
      embedded: true,
      selectedSession: closedSession,
      selectedClosedSession: closedSession,
      selectedNode: null,
      sessions: [],
      selectedSessionId: closedSession.sessionId,
      onSelectSession: vi.fn(),
      onSelectPath: vi.fn(),
    })));

    for (const label of ["Observed", "Started", "Closed"]) {
      const row = container.querySelector(`[data-forensic-time-row="${label}"]`);
      expect(row).not.toBeNull();
      expect(row?.textContent).toContain("UTC");
      expect(row?.querySelector(`button[aria-label="Copy ${label} ISO timestamp"]`)).not.toBeNull();
    }
    expect(container.textContent).not.toContain("Invalid Date");
    await act(async () => root.unmount());
  });
});
