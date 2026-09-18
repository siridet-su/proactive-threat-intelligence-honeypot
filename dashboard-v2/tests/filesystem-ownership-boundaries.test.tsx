// @vitest-environment happy-dom
import { act, createElement, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import type { FilesystemTopologySession, SessionTerminateAction, SessionCwdHistoryEvent } from "../src/lib/dashboardTypes";
import { useResponseActionController } from "../src/components/filesystem/ResponseActionController";
import { useAuditReplay } from "../src/components/filesystem/useAuditReplay";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("server-only", () => ({}));

const componentRoot = resolve(process.cwd(), "src/components/filesystem");

function readComponent(name: string): string {
  return readFileSync(resolve(componentRoot, name), "utf8");
}

const session: FilesystemTopologySession = {
  sessionId: "session-a",
  sourceIp: "192.0.2.10",
  cwdState: {
    path: "/",
    status: "confirmed",
    observedAt: "2026-09-19T00:00:00.000Z",
    sourceEventId: null,
  },
  auditSummary: { visitedPaths: ["/"], homeOnly: false, eventCount: 1 },
};

function responseAction(status: SessionTerminateAction["status"] = "requested"): SessionTerminateAction {
  return {
    actionId: "action-a",
    sessionId: "session-a",
    action: "terminate_session",
    status,
    requestedBy: "operator",
    requestedAt: new Date().toISOString(),
    deliveredAt: null,
    verifiedAt: null,
    failureCategory: null,
  };
}

function jsonResponse(payload: unknown): Response {
  return { ok: true, json: async () => payload } as Response;
}

function ResponseProbe({
  selectedSession,
  enabled,
  sessionIsLive = true,
  renderCount = 0,
}: {
  selectedSession: FilesystemTopologySession | null;
  enabled: boolean;
  sessionIsLive?: boolean;
  renderCount?: number;
}) {
  const state = useResponseActionController({ selectedSession, enabled, sessionIsLive });
  return createElement("output", { "data-render-count": renderCount, "data-capability": state.visibleTerminateCapability });
}

function ReplayProbe({ onSelect, noise = 0 }: { onSelect: (id: string | null, source?: "user" | "playback") => void; noise?: number }) {
  const history: SessionCwdHistoryEvent[] = [
    { id: "event-c", sessionId: "session-a", fromPath: "/b", toPath: "/c", command: "cd /c", action: "change", status: "confirmed", at: "2026-09-19T00:00:10.000Z" },
    { id: "event-b", sessionId: "session-a", fromPath: "/a", toPath: "/b", command: "cd /b", action: "change", status: "confirmed", at: "2026-09-19T00:00:05.000Z" },
    { id: "event-a", sessionId: "session-a", fromPath: "/", toPath: "/a", command: "cd /a", action: "change", status: "confirmed", at: "2026-09-19T00:00:00.000Z" },
  ];
  const [selectedId, setSelectedId] = useState<string | null>("event-a");
  const replay = useAuditReplay({
    viewMode: "audit",
    history,
    anchoredHop: null,
    historyTotalItems: 3,
    historyTotalSuccessfulItems: 3,
    historyComplete: true,
    showFailedAttempts: true,
    selectedHistoryEventId: selectedId,
    initialPacingMode: "uniform",
    onSelectHistoryEventId: (id, source) => {
      onSelect(id, source);
      if (id) setSelectedId(id);
    },
  });
  return createElement(
    "div",
    { "data-noise": noise, "data-selected": selectedId, "data-playing": String(replay.isPlaying) },
    createElement("button", { type: "button", onClick: replay.handleTogglePlay }, "play"),
  );
}

describe("FA-012 ownership boundaries", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    act(() => root.unmount());
    container.remove();
  });

  it("keeps orchestration hooks out of route-history and response presentation modules", () => {
    const historySource = readComponent("CwdRouteHistory.tsx");
    const panelSource = readComponent("ResponseActionPanel.tsx");
    expect(historySource).not.toContain("useResponseAction");
    expect(historySource).not.toContain("setTimeout");
    expect(panelSource).not.toMatch(/from ["']\.\/use(ResponseAction|AuditReplay)|fetch\s*\(|new EventSource|setTimeout\s*\(/);
  });

  it("has exactly one page-level owner for each filesystem orchestration hook", () => {
    const pageSource = readComponent("FilesystemActivity.tsx");
    expect(pageSource.match(/useFilesystemStreaming\s*\(/g)).toHaveLength(1);
    expect(pageSource.match(/useSessionCwdHistory\s*\(/g)).toHaveLength(1);
    expect(pageSource.match(/useFilesystemUrlState\s*\(/g)).toHaveLength(1);
    expect(pageSource.match(/useAuditReplay\s*\(/g)).toHaveLength(1);
    expect(readComponent("ResponseActionController.tsx").match(/useResponseAction\s*\(/g)).toHaveLength(1);
  });

  it("does not request response capability while inactive and does not duplicate it across rerenders", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ available: true, action: null }));
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => {
      root.render(createElement(ResponseProbe, { selectedSession: session, enabled: false }));
      await Promise.resolve();
    });
    expect(fetchMock).not.toHaveBeenCalled();

    await act(async () => {
      root.render(createElement(ResponseProbe, { selectedSession: session, enabled: true, renderCount: 1 }));
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      root.render(createElement(ResponseProbe, { selectedSession: session, enabled: true, renderCount: 2 }));
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("aborts the old capability lifecycle when the selected session changes", async () => {
    let firstSignal: AbortSignal | undefined;
    let resolveFirst: ((value: Response) => void) | undefined;
    const firstResponse = new Promise<Response>((resolve) => {
      resolveFirst = resolve;
    });
    const fetchMock = vi.fn()
      .mockImplementationOnce((_url: string, init?: RequestInit) => {
        firstSignal = init?.signal as AbortSignal | undefined;
        return firstResponse;
      })
      .mockResolvedValue(jsonResponse({ available: true, action: null }));
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => {
      root.render(createElement(ResponseProbe, { selectedSession: session, enabled: true }));
      await Promise.resolve();
    });
    const nextSession = { ...session, sessionId: "session-b" };
    await act(async () => {
      root.render(createElement(ResponseProbe, { selectedSession: nextSession, enabled: true }));
      await Promise.resolve();
    });
    expect(firstSignal?.aborted).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    resolveFirst?.(jsonResponse({ available: true, action: null }));
  });

  it("keeps one strict response poller across controller rerenders", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ available: true, action: responseAction("requested") }))
      .mockResolvedValue(jsonResponse({ available: true, action: responseAction("verified") }));
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => {
      root.render(createElement(ResponseProbe, { selectedSession: session, enabled: true, renderCount: 1 }));
      await Promise.resolve();
    });
    await act(async () => {
      root.render(createElement(ResponseProbe, { selectedSession: session, enabled: true, renderCount: 2 }));
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(999);
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await act(async () => {
      vi.advanceTimersByTime(1);
      await Promise.resolve();
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("advances exactly one replay hop per autoplay timer after a presentational rerender", async () => {
    vi.useFakeTimers();
    const onSelect = vi.fn();
    await act(async () => {
      root.render(createElement(ReplayProbe, { onSelect }));
      await Promise.resolve();
    });

    await act(async () => {
      (container.querySelector("button") as HTMLButtonElement).click();
      await Promise.resolve();
    });
    expect(vi.getTimerCount()).toBeGreaterThan(0);
    await act(async () => {
      root.render(createElement(ReplayProbe, { onSelect, noise: 1 }));
      await Promise.resolve();
    });
    await act(async () => {
      await vi.advanceTimersToNextTimerAsync();
      await Promise.resolve();
    });
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith("event-b", "playback");
    expect(vi.getTimerCount()).toBe(1);
  });
});
