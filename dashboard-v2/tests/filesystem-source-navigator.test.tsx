// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FilesystemContextPanel } from "../src/components/filesystem/FilesystemContextPanel";
import { SessionSourceList } from "../src/components/filesystem/SessionSourceList";
import type { FilesystemTopologySession } from "../src/lib/dashboardTypes";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const sessions: FilesystemTopologySession[] = [
  {
    sessionId: "same-ip-older",
    sourceIp: "10.58.33.209",
    cwdState: {
      path: "/tmp",
      status: "confirmed",
      observedAt: "2026-09-24T02:00:00Z",
    },
    auditSummary: { visitedPaths: ["/tmp"], homeOnly: false, eventCount: 1 },
  },
  {
    sessionId: "same-ip-latest",
    sourceIp: "10.58.33.209",
    cwdState: {
      path: "/etc",
      status: "confirmed",
      observedAt: "2026-09-24T03:00:00Z",
    },
    auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 2 },
  },
  {
    sessionId: "other-source",
    sourceIp: "10.58.33.2",
    cwdState: {
      path: "/home/test",
      status: "confirmed",
      observedAt: "2026-09-24T01:00:00Z",
    },
    auditSummary: { visitedPaths: ["/home/test"], homeOnly: true, eventCount: 1 },
  },
];

describe("live topology source navigator", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("renders one row per active IP and selects that source's latest session", async () => {
    const onSelectSession = vi.fn();

    await act(async () => {
      root.render(createElement(SessionSourceList, {
        sessions,
        selectedSessionId: "same-ip-older",
        onSelectSession,
      }));
    });

    const sourceRows = container.querySelectorAll('[role="listitem"]');
    expect(sourceRows).toHaveLength(2);
    expect(container.textContent).toContain("2 sessions · 2 paths");
    expect(container.textContent).toContain("Latest: …/etc");
    expect(container.textContent).not.toContain("same-ip-older");
    expect(container.textContent).not.toContain("Closed");

    const sourceButton = container.querySelector<HTMLButtonElement>(
      'button[aria-label^="Inspect active source 10.58.33.209"]',
    );
    await act(async () => sourceButton?.click());
    expect(onSelectSession).toHaveBeenCalledWith("same-ip-latest");
  });

  it("hides the navigator when only one active IP exists", async () => {
    await act(async () => {
      root.render(createElement(FilesystemContextPanel, {
        selectedSession: sessions[0],
        selectedClosedSession: null,
        selectedNode: null,
        sessions: [sessions[0]],
        selectedSessionId: sessions[0].sessionId,
        onSelectSession: vi.fn(),
        onSelectPath: vi.fn(),
        onOpenAudit: vi.fn(),
      }));
    });

    expect(container.textContent).not.toContain("Source navigator");
    expect(container.textContent).not.toContain("Browse sources");
  });

  it("shows an active-source count when more than one IP is available", async () => {
    await act(async () => {
      root.render(createElement(FilesystemContextPanel, {
        selectedSession: sessions[0],
        selectedClosedSession: null,
        selectedNode: null,
        sessions,
        selectedSessionId: sessions[0].sessionId,
        onSelectSession: vi.fn(),
        onSelectPath: vi.fn(),
        onOpenAudit: vi.fn(),
      }));
    });

    const toggle = Array.from(container.querySelectorAll("button")).find((button) =>
      button.textContent?.includes("Source navigator"),
    );
    expect(toggle?.textContent).toContain("2");
    expect(container.textContent).not.toContain("Browse sources");
  });
});
