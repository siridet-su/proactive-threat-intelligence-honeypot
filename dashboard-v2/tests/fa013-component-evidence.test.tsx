// @vitest-environment happy-dom
import { act, createElement, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
  SessionCwdHistoryEvent,
  FilesystemTopologySnapshot,
} from "../src/lib/dashboardTypes";
import { CwdRouteHistory } from "../src/components/filesystem/CwdRouteHistory";
import { ResponseActionPanel } from "../src/components/filesystem/ResponseActionPanel";
import {
  TopologyCanvas,
  deriveTopologyPresentationContext,
} from "../src/components/filesystem/TopologyCanvas";
import { useAuditReplay } from "../src/components/filesystem/useAuditReplay";
import { useResponseActionController } from "../src/components/filesystem/ResponseActionController";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("server-only", () => ({}));
MotionGlobalConfig.skipAnimations = true;

const session: FilesystemTopologySession = {
  sessionId: "live-session",
  sourceIp: "192.0.2.10",
  cwdState: {
    path: "/var/log",
    status: "confirmed",
    observedAt: "2026-09-19T00:00:00.000Z",
    sourceEventId: null,
  },
  auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 3 },
};

const event = (id: string, at: string, toPath = `/${id}`): SessionCwdHistoryEvent => ({
  id,
  sessionId: "audit-session",
  fromPath: "/",
  toPath,
  command: `cd ${toPath}`,
  action: "change",
  status: "confirmed",
  at,
});

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function fireInputChange(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function fireKey(element: HTMLElement, key: string): void {
  element.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
}

function ResponseComposition({ enabled }: { enabled: boolean }) {
  const responseAction = useResponseActionController({
    selectedSession: session,
    sessionIsLive: false,
    enabled,
  });
  return createElement(ResponseActionPanel, {
    selectedSession: session,
    sessionIsLive: false,
    visibleTerminateAction: responseAction.visibleTerminateAction,
    visibleTerminateCapability: responseAction.visibleTerminateCapability,
    terminateDialogOpen: responseAction.terminateDialogOpen,
    onTerminateDialogOpenChange: responseAction.setTerminateDialogOpen,
    terminateProcessing: responseAction.terminateProcessing,
    terminateError: responseAction.terminateError,
    onTerminateErrorChange: responseAction.setTerminateError,
    operationToast: responseAction.operationToast,
    onOperationToastChange: responseAction.setOperationToast,
    onTerminateSession: responseAction.handleTerminateSession,
  });
}

describe("FA-013 production component evidence", () => {
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

  it("E: polls the controlled Response tab with bounded cadence and aborts on disable", async () => {
    vi.useFakeTimers();
    const requestedAt = new Date(Date.now()).toISOString();
    const pending = {
      actionId: "action-1",
      sessionId: session.sessionId,
      action: "terminate_session",
      status: "requested",
      requestedBy: "operator",
      requestedAt,
      deliveredAt: null,
      verifiedAt: null,
      failureCategory: null,
    } as const;
    const verified = { ...pending, status: "verified", verifiedAt: requestedAt };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ available: true, action: pending }))
      .mockResolvedValueOnce(jsonResponse({ available: true, action: pending }))
      .mockResolvedValueOnce(jsonResponse({ available: true, action: verified }));
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => root.render(createElement(ResponseComposition, { enabled: true })));
    await act(async () => Promise.resolve());
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await act(async () => vi.advanceTimersByTimeAsync(100));
    await act(async () => Promise.resolve());
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await act(async () => vi.advanceTimersByTimeAsync(150));
    await act(async () => Promise.resolve());
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(container.textContent).toContain("Session disconnected");

    const abortingFetch = vi.fn((_url: string, init?: RequestInit) => new Promise<Response>((resolve) => {
      init?.signal?.addEventListener("abort", () => resolve(jsonResponse({ available: true, action: pending })));
    }));
    vi.stubGlobal("fetch", abortingFetch);
    await act(async () => root.render(createElement(ResponseComposition, { enabled: false })));
    await act(async () => root.render(createElement(ResponseComposition, { enabled: true })));
    await act(async () => Promise.resolve());
    const signal = abortingFetch.mock.calls[0][1]?.signal as AbortSignal;
    await act(async () => root.render(createElement(ResponseComposition, { enabled: false })));
    expect(signal.aborted).toBe(true);
  });

  it("F: renders a valid empty topology as live no-activity without creating a freshness owner", async () => {
    vi.useFakeTimers();
    const snapshot: FilesystemTopologySnapshot = {
      nodes: [],
      sessions: [],
      recentClosedSessions: [],
      truncated: false,
      generatedAt: "2026-09-19T00:00:00.000Z",
      latestTelemetryAt: null,
    };
    const freshnessState = {
      classification: "fresh" as const,
      label: "Live · No activity",
      detail: "No authoritative telemetry activity has been observed yet.",
      badgeClass: "",
      dotClass: "",
      isDegraded: false,
      isStale: false,
      telemetryAgeMs: null,
      snapshotReceiptAgeMs: 0,
      retrievalAgeMs: 0,
      telemetryStatus: "none" as const,
    };
    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot,
      regionStatus: "ready",
      streamState: "live",
      freshnessState,
      selectedSessionId: null,
      selectedPath: null,
      onSelectSession: () => {},
      onSelectPath: () => {},
      staleThresholdMs: 30_000,
      presentationContext: { mode: "live" },
    })));
    expect(container.textContent).toContain("No active honeypot sessions");
    expect(container.textContent).toContain("No attacker is currently connected.");
    expect(container.textContent).not.toContain("Offline");
    expect(container.textContent).not.toContain("Stale");
    expect(vi.getTimerCount()).toBe(0);

    const degradedFreshness = {
      ...freshnessState,
      classification: "degraded" as const,
      label: "Degraded",
      detail: "Reconnecting transport — displaying retained snapshot.",
      isDegraded: true,
    };
    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot,
      regionStatus: "ready",
      streamState: "stale",
      freshnessState: degradedFreshness,
      selectedSessionId: null,
      selectedPath: null,
      onSelectSession: () => {},
      onSelectPath: () => {},
      onRefresh: () => {},
      onReconnect: () => {},
      staleThresholdMs: 30_000,
      presentationContext: { mode: "live" },
    })));
    expect(container.textContent).toContain("Degraded connection");
    expect(container.textContent).toContain("Showing retained snapshot");
    expect(container.textContent).not.toContain("Refresh snapshot");
    expect(container.textContent).not.toContain("Reconnect now");
    expect(container.textContent).not.toContain("Offline");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("I: drives the production scrubber by elapsed position and hop-key fallback", async () => {
    const events = [event("event-c", "2026-09-19T00:30:00.000Z", "/c"), event("event-b", "2026-09-19T00:00:05.000Z", "/b"), event("event-a", "2026-09-19T00:00:00.000Z", "/a")];
    const selected = vi.fn();
    function ReplayHarness() {
      const [selectedId, setSelectedId] = useState("event-a");
      const replay = useAuditReplay({
        viewMode: "audit",
        history: events,
        anchoredHop: null,
        historyTotalItems: 3,
        historyTotalSuccessfulItems: 3,
        historyComplete: true,
        selectedHistoryEventId: selectedId,
        onSelectHistoryEventId: (id) => {
          if (id) setSelectedId(id);
          selected(id);
        },
      });
      return createElement(CwdRouteHistory, {
        selectedSession: { ...session, sessionId: "audit-session" },
        history: events,
        historyStatus: "ready",
        historyCursor: null,
        historyTotalItems: 3,
        historyTotalSuccessfulItems: 3,
        historyComplete: true,
        replay: replay.presentation,
        activeTab: "replay",
        responsePanel: null,
        onClearHop: () => {},
        onShowLatestHop: () => {},
        onSelectHistoryEventId: (id) => {
          if (id) setSelectedId(id);
          selected(id);
        },
        onLoadEarlier: () => {},
      });
    }
    await act(async () => root.render(createElement(ReplayHarness)));
    const range = container.querySelector('input[type="range"]') as HTMLInputElement;
    expect(range.max).toBe("1800000");
    await act(async () => fireInputChange(range, "5000"));
    expect(selected).toHaveBeenCalledWith("event-b");
    await act(async () => fireKey(range, "Home"));
    await act(async () => fireKey(range, "End"));
    expect(selected).toHaveBeenLastCalledWith("event-c");
  });

  it("FSV-001: enforces explicit presentation context and distinguishes retained audit evidence from live telemetry", async () => {
    const auditSnapshot: FilesystemTopologySnapshot = {
      nodes: [
        { path: "/", parentPath: null, depth: 0, sessionIds: ["closed-session-1"], observedAt: "2026-09-17T11:45:00.000Z" },
        { path: "/etc", parentPath: "/", depth: 1, sessionIds: ["closed-session-1"], observedAt: "2026-09-17T11:45:00.000Z" },
      ],
      sessions: [
        {
          sessionId: "closed-session-1",
          sourceIp: "192.0.2.44",
          cwdState: { path: "/etc", status: "confirmed", observedAt: "2026-09-17T11:45:00.000Z", sourceEventId: "ev-1" },
          auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 1 },
        },
      ],
      recentClosedSessions: [],
      truncated: false,
      generatedAt: "2026-09-22T20:00:00.000Z",
      latestTelemetryAt: null,
    };

    const freshnessState = {
      classification: "fresh" as const,
      label: "Live",
      detail: "Authoritative telemetry is current.",
      badgeClass: "",
      dotClass: "",
      isDegraded: false,
      isStale: false,
      telemetryAgeMs: 0,
      snapshotReceiptAgeMs: 0,
      retrievalAgeMs: 0,
      telemetryStatus: "valid" as const,
    };

    // 1. Audit mode with retained closed session (valid timestamps)
    const closedSession: FilesystemClosedSession = {
      sessionId: "closed-session-1",
      sourceIp: "192.0.2.44",
      cwdState: { path: "/etc", status: "confirmed", observedAt: "2026-09-17T11:45:00.000Z", sourceEventId: "ev-1" },
      auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 1 },
      lifecycle: {
        startedAt: "2026-09-17T11:39:55.000Z",
        closedAt: "2026-09-17T11:46:00.000Z",
      },
    };

    const derivedRetained = deriveTopologyPresentationContext("audit", closedSession);
    expect(derivedRetained).toEqual({
      mode: "audit",
      session: {
        lifecycle: "retained",
        observedAt: "2026-09-17T11:45:00.000Z",
        startedAt: "2026-09-17T11:39:55.000Z",
        closedAt: "2026-09-17T11:46:00.000Z",
      },
    });

    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot: auditSnapshot,
      regionStatus: "ready",
      streamState: "live",
      freshnessState,
      selectedSessionId: "closed-session-1",
      selectedPath: "/etc",
      onSelectSession: () => {},
      onSelectPath: () => {},
      staleThresholdMs: 30_000,
      presentationContext: derivedRetained,
    })));

    // Audit evidence region must exist through its accessible label and remain visible at all breakpoints
    const evidenceEl = container.querySelector<HTMLElement>('[aria-label="Audit evidence timestamps"]');
    expect(evidenceEl).not.toBeNull();
    const classList = evidenceEl?.className.split(/\s+/) ?? [];
    expect(classList).not.toContain("hidden");
    expect(classList).not.toContain("sm:hidden");
    expect(classList).not.toContain("md:hidden");
    expect(classList).not.toContain("lg:hidden");
    expect(classList).not.toContain("xl:hidden");
    expect(classList).not.toContain("2xl:inline");
    expect(classList).not.toContain("truncate");
    expect(classList).not.toContain("whitespace-nowrap");
    expect(classList).not.toContain("overflow-hidden");
    expect(classList.some((c) => c.startsWith("line-clamp"))).toBe(false);
    expect(classList).toContain("whitespace-normal");
    expect(classList).toContain("break-words");

    // Retained audit session must NEVER be labelled as active session
    expect(container.textContent).not.toContain("1 active session");
    expect(container.textContent).toContain("1 retained session");

    // Authoritative evidence timestamps must be labelled
    expect(evidenceEl?.textContent).toContain("Observed 17 Sept 2026");
    expect(evidenceEl?.textContent).toContain("Closed 17 Sept 2026");

    // Client view-materialization timestamp (generatedAt) must not be exposed as telemetry freshness
    expect(container.textContent).not.toContain("Snapshot 23 Sept 2026");
    expect(container.textContent).not.toContain("Snapshot generated at");
    expect(container.textContent).not.toContain("Telemetry Just now");

    // 2. Retained closed session with null timestamps -> shows unavailable
    const retainedNullSession: FilesystemClosedSession = {
      sessionId: "closed-session-null",
      sourceIp: "192.0.2.45",
      cwdState: { path: "/var", status: "confirmed", observedAt: null, sourceEventId: "ev-2" },
      auditSummary: { visitedPaths: ["/var"], homeOnly: false, eventCount: 1 },
      lifecycle: {
        startedAt: null,
        closedAt: null,
      },
    };

    const derivedNullRetained = deriveTopologyPresentationContext("audit", retainedNullSession);
    expect(derivedNullRetained).toEqual({
      mode: "audit",
      session: {
        lifecycle: "retained",
        observedAt: null,
        startedAt: null,
        closedAt: null,
      },
    });

    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot: auditSnapshot,
      regionStatus: "ready",
      streamState: "live",
      freshnessState,
      selectedSessionId: "closed-session-null",
      selectedPath: "/var",
      onSelectSession: () => {},
      onSelectPath: () => {},
      staleThresholdMs: 30_000,
      presentationContext: derivedNullRetained,
    })));

    const nullEvidenceEl = container.querySelector<HTMLElement>('[aria-label="Audit evidence timestamps"]');
    expect(nullEvidenceEl).not.toBeNull();
    expect(nullEvidenceEl?.textContent).toContain("Observed unavailable");
    expect(nullEvidenceEl?.textContent).toContain("Closed unavailable");
    expect(nullEvidenceEl?.textContent).not.toContain("No timestamp");

    // 3. Retained closed session with invalid timestamps -> shows unavailable rather than "No timestamp"
    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot: auditSnapshot,
      regionStatus: "ready",
      streamState: "live",
      freshnessState,
      selectedSessionId: "closed-session-invalid",
      selectedPath: "/var",
      onSelectSession: () => {},
      onSelectPath: () => {},
      staleThresholdMs: 30_000,
      presentationContext: {
        mode: "audit",
        session: {
          lifecycle: "retained",
          observedAt: "invalid-date",
          startedAt: null,
          closedAt: "bad-timestamp",
        },
      },
    })));

    const invalidEvidenceEl = container.querySelector<HTMLElement>('[aria-label="Audit evidence timestamps"]');
    expect(invalidEvidenceEl?.textContent).toContain("Observed unavailable");
    expect(invalidEvidenceEl?.textContent).toContain("Closed unavailable");
    expect(invalidEvidenceEl?.textContent).not.toContain("No timestamp");

    // 4. Active audit investigation with missing observedAt -> shows unavailable and Active investigation, no Closed label
    const activeSessionMissing: FilesystemTopologySession = {
      sessionId: "active-session-missing",
      sourceIp: "192.0.2.46",
      cwdState: { path: "/etc", status: "confirmed", observedAt: null, sourceEventId: "ev-3" },
      auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 1 },
    };

    const derivedActiveMissing = deriveTopologyPresentationContext("audit", activeSessionMissing);
    expect(derivedActiveMissing).toEqual({
      mode: "audit",
      session: {
        lifecycle: "active",
        observedAt: null,
        startedAt: null,
        closedAt: null,
      },
    });

    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot: auditSnapshot,
      regionStatus: "ready",
      streamState: "live",
      freshnessState,
      selectedSessionId: "active-session-missing",
      selectedPath: "/etc",
      onSelectSession: () => {},
      onSelectPath: () => {},
      staleThresholdMs: 30_000,
      presentationContext: derivedActiveMissing,
    })));

    const activeMissingEl = container.querySelector<HTMLElement>('[aria-label="Audit evidence timestamps"]');
    expect(activeMissingEl?.textContent).toContain("Observed unavailable");
    expect(activeMissingEl?.textContent).toContain("Active investigation");
    expect(activeMissingEl?.textContent).not.toContain("Closed");
    expect(container.textContent).toContain("active session investigation");
    expect(container.textContent).not.toContain("retained");

    // 5. Active audit investigation with valid observedAt
    const activeSessionValid: FilesystemTopologySession = {
      sessionId: "active-session-1",
      sourceIp: "192.0.2.46",
      cwdState: { path: "/etc", status: "confirmed", observedAt: "2026-09-17T11:45:00.000Z", sourceEventId: "ev-4" },
      auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 1 },
    };

    const derivedActiveValid = deriveTopologyPresentationContext("audit", activeSessionValid);
    expect(derivedActiveValid).toEqual({
      mode: "audit",
      session: {
        lifecycle: "active",
        observedAt: "2026-09-17T11:45:00.000Z",
        startedAt: null,
        closedAt: null,
      },
    });

    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot: auditSnapshot,
      regionStatus: "ready",
      streamState: "live",
      freshnessState,
      selectedSessionId: "active-session-1",
      selectedPath: "/etc",
      onSelectSession: () => {},
      onSelectPath: () => {},
      staleThresholdMs: 30_000,
      presentationContext: derivedActiveValid,
    })));

    const activeValidEl = container.querySelector<HTMLElement>('[aria-label="Audit evidence timestamps"]');
    expect(activeValidEl?.textContent).toContain("Observed 17 Sept 2026");
    expect(activeValidEl?.textContent).toContain("Active investigation");
    expect(activeValidEl?.textContent).not.toContain("Closed");

    // 6. Audit mode without selected session -> neutral wording
    const derivedNoSession = deriveTopologyPresentationContext("audit", null);
    expect(derivedNoSession).toEqual({
      mode: "audit",
      session: null,
    });

    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot: auditSnapshot,
      regionStatus: "ready",
      streamState: "live",
      freshnessState,
      selectedSessionId: null,
      selectedPath: null,
      onSelectSession: () => {},
      onSelectPath: () => {},
      staleThresholdMs: 30_000,
      presentationContext: derivedNoSession,
    })));

    const noSessionEvidenceEl = container.querySelector<HTMLElement>('[aria-label="Audit evidence timestamps"]');
    expect(noSessionEvidenceEl?.textContent).toContain("Historical audit data");
    expect(noSessionEvidenceEl?.textContent).not.toContain("Observed");
    expect(noSessionEvidenceEl?.textContent).not.toContain("Closed");
    expect(container.textContent).not.toContain("retained session");
    expect(container.textContent).not.toContain("active session");

    // 7. Live mode preserves active session count and live freshness semantics
    const derivedLive = deriveTopologyPresentationContext("live");
    expect(derivedLive).toEqual({ mode: "live" });

    await act(async () => root.render(createElement(TopologyCanvas, {
      snapshot: auditSnapshot,
      regionStatus: "ready",
      streamState: "live",
      freshnessState,
      selectedSessionId: "live-session-1",
      selectedPath: "/etc",
      onSelectSession: () => {},
      onSelectPath: () => {},
      staleThresholdMs: 30_000,
      presentationContext: derivedLive,
    })));

    expect(container.textContent).toContain("1 active session");
    expect(container.textContent).toContain("Telemetry");
    expect(container.textContent).toContain("Snapshot");
    expect(container.querySelector('[aria-label="Audit evidence timestamps"]')).toBeNull();
  });
});
