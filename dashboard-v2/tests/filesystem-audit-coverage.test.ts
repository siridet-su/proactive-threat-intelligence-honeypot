import { describe, expect, it } from "vitest";

import type {
  FilesystemClosedSession,
  SessionCwdHistoryEvent,
} from "../src/lib/dashboardTypes";
import {
  buildAuditSnapshot,
  deriveAuditCoverage,
} from "../src/components/filesystem/filesystemUtils";

describe("FSV-002: Truthful history and topology coverage", () => {
  const sessionWithSummaryPaths: FilesystemClosedSession = {
    sessionId: "closed-audit-1",
    sourceIp: "192.0.2.100",
    cwdState: {
      path: "/var/log",
      status: "confirmed",
      observedAt: "2026-09-17T12:00:00.000Z",
      sourceEventId: "ev-current",
    },
    auditSummary: {
      visitedPaths: ["/var/log", "/opt/deep/recon", "/etc/nginx"],
      homeOnly: false,
      eventCount: 5,
    },
    lifecycle: {
      startedAt: "2026-09-17T11:50:00.000Z",
      closedAt: "2026-09-17T12:05:00.000Z",
    },
  };

  const partialHistory: SessionCwdHistoryEvent[] = [
    {
      id: "ev-1",
      sessionId: "closed-audit-1",
      sequence: "5",
      at: "2026-09-17T12:00:00.000Z",
      fromPath: "/etc/nginx",
      toPath: "/var/log",
      action: "changed",
      status: "confirmed",
      sourceEventId: "src-1",
    },
  ];

  it("1. buildAuditSnapshot includes a historical path found only in session.auditSummary.visitedPaths when the loaded history page does not contain that path", () => {
    const snapshot = buildAuditSnapshot(null, sessionWithSummaryPaths, partialHistory);
    expect(snapshot.nodes.some((node) => node.path === "/opt/deep/recon")).toBe(true);
  });

  it("2. Ancestors of a summary-only path are materialized", () => {
    const snapshot = buildAuditSnapshot(null, sessionWithSummaryPaths, partialHistory);
    expect(snapshot.nodes.some((node) => node.path === "/opt")).toBe(true);
    expect(snapshot.nodes.some((node) => node.path === "/opt/deep")).toBe(true);
    const deepNode = snapshot.nodes.find((node) => node.path === "/opt/deep/recon");
    expect(deepNode?.parentPath).toBe("/opt/deep");
    expect(deepNode?.depth).toBe(3);
  });

  it("3. Summary-only nodes have observedAt null unless current/history evidence supplies a timestamp", () => {
    const snapshot = buildAuditSnapshot(null, sessionWithSummaryPaths, partialHistory);
    const reconNode = snapshot.nodes.find((node) => node.path === "/opt/deep/recon");
    expect(reconNode?.observedAt).toBeNull();
    const deepNode = snapshot.nodes.find((node) => node.path === "/opt/deep");
    expect(deepNode?.observedAt).toBeNull();
  });

  it("4. Current/history evidence upgrades the timestamp of a path also present in auditSummary", () => {
    const snapshot = buildAuditSnapshot(null, sessionWithSummaryPaths, partialHistory);
    const varLogNode = snapshot.nodes.find((node) => node.path === "/var/log");
    expect(varLogNode?.observedAt).toBe("2026-09-17T12:00:00.000Z");

    const etcNode = snapshot.nodes.find((node) => node.path === "/etc/nginx");
    expect(etcNode?.observedAt).toBe("2026-09-17T12:00:00.000Z");
  });

  it("5. failed_change.toPath remains excluded", () => {
    const historyWithFailed: SessionCwdHistoryEvent[] = [
      ...partialHistory,
      {
        id: "ev-failed",
        sessionId: "closed-audit-1",
        sequence: "4",
        at: "2026-09-17T11:58:00.000Z",
        fromPath: "/etc/nginx",
        toPath: "/nonexistent/typo/dir",
        action: "failed_change",
        status: "conditional_candidate",
        sourceEventId: "src-failed",
      },
    ];

    const snapshot = buildAuditSnapshot(null, sessionWithSummaryPaths, historyWithFailed);
    expect(snapshot.nodes.some((node) => node.path === "/nonexistent/typo/dir")).toBe(false);
    expect(snapshot.nodes.some((node) => node.path === "/nonexistent")).toBe(false);
  });

  it("6. Partial event coverage reports Loaded N of M and never complete", () => {
    const partialCoverage = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: 10,
      historyTotalItems: 50,
      historyComplete: false,
      historyStatus: "ready",
      auditSummaryEventCount: 50,
    });
    expect(partialCoverage.eventCoverage).toBe("partial");
    expect(partialCoverage.loadedEvents).toBe(10);
    expect(partialCoverage.totalEvents).toBe(50);
    expect(partialCoverage.unloadedEvents).toBe(40);
    expect(partialCoverage.wording).toContain("Loaded 10 of 50 retained events");
    expect(partialCoverage.wording).toContain("Earlier events remain unloaded");
    expect(partialCoverage.wording).not.toContain("complete");
    expect(partialCoverage.wording).not.toContain("all events");
  });

  it("7. historyComplete=true with loadedEvents < authoritative eventCount still reports partial", () => {
    const failClosedCoverage = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: 10,
      historyTotalItems: 10,
      historyComplete: true,
      historyStatus: "ready",
      auditSummaryEventCount: 50,
    });
    expect(failClosedCoverage.eventCoverage).toBe("partial");
    expect(failClosedCoverage.totalEvents).toBe(50);
    expect(failClosedCoverage.unloadedEvents).toBe(40);
    expect(failClosedCoverage.wording).toContain("Loaded 10 of 50 retained events");
    expect(failClosedCoverage.wording).toContain("Earlier events remain unloaded");
  });

  it("8. Complete coverage requires loadedEvents >= authoritative total", () => {
    const completeCoverage = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: 50,
      historyTotalItems: 50,
      historyComplete: true,
      historyStatus: "ready",
      auditSummaryEventCount: 50,
    });
    expect(completeCoverage.eventCoverage).toBe("complete");
    expect(completeCoverage.loadedEvents).toBe(50);
    expect(completeCoverage.totalEvents).toBe(50);
    expect(completeCoverage.unloadedEvents).toBe(0);
    expect(completeCoverage.wording).toContain("All 50 retained events are loaded");

    const zeroComplete = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: 0,
      historyTotalItems: 0,
      historyComplete: true,
      historyStatus: "ready",
      auditSummaryEventCount: 0,
    });
    expect(zeroComplete.eventCoverage).toBe("complete");
    expect(zeroComplete.totalEvents).toBe(0);
    expect(zeroComplete.unloadedEvents).toBe(0);
    expect(zeroComplete.wording).toContain("0 retained events recorded");
  });

  it("9. Loading, refreshing and error states preserve truthful loaded/total facts", () => {
    const initialLoading = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: 0,
      historyTotalItems: 0,
      historyComplete: false,
      historyStatus: "loading",
      auditSummaryEventCount: 25,
    });
    expect(initialLoading.eventCoverage).toBe("loading");
    expect(initialLoading.totalEvents).toBe(25);
    expect(initialLoading.loadedEvents).toBe(0);
    expect(initialLoading.unloadedEvents).toBe(25);
    expect(initialLoading.wording).toContain("Retained event history is loading");

    const refreshing = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: 15,
      historyTotalItems: 40,
      historyComplete: false,
      historyStatus: "refreshing",
      auditSummaryEventCount: 40,
    });
    expect(refreshing.loadedEvents).toBe(15);
    expect(refreshing.totalEvents).toBe(40);
    expect(refreshing.unloadedEvents).toBe(25);
    expect(refreshing.wording).toContain("Loaded 15 of 40 retained events");
    expect(refreshing.wording).toContain("Retained event history is refreshing");
    expect(refreshing.wording).toContain("25 earlier events remain unloaded");

    const errorNoData = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: 0,
      historyTotalItems: 0,
      historyComplete: false,
      historyStatus: "error",
      auditSummaryEventCount: 30,
    });
    expect(errorNoData.eventCoverage).toBe("error");
    expect(errorNoData.totalEvents).toBe(30);
    expect(errorNoData.wording).toContain("directory coverage remains available");
    expect(errorNoData.wording).toContain("Retained event history is unavailable");

    const errorWithData = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: 12,
      historyTotalItems: 30,
      historyComplete: false,
      historyStatus: "error",
      auditSummaryEventCount: 30,
    });
    expect(errorWithData.eventCoverage).toBe("error");
    expect(errorWithData.loadedEvents).toBe(12);
    expect(errorWithData.totalEvents).toBe(30);
    expect(errorWithData.wording).toContain("Loaded 12 of 30 retained events");
    expect(errorWithData.wording).toContain("Remaining event history is unavailable");
  });

  it("10. Coverage wording distinguishes authoritative directory coverage from event history coverage", () => {
    const model = deriveAuditCoverage({
      hasSelectedSession: true,
      loadedEvents: 5,
      historyTotalItems: 20,
      historyComplete: false,
      historyStatus: "ready",
      auditSummaryEventCount: 20,
    });
    expect(model.pathCoverage).toMatchObject({
      source: "auditSummary",
      status: "authoritative",
    });
    expect(model.wording).toContain("authoritative directory coverage");
    expect(model.wording).toContain("Loaded 5 of 20 retained events");
  });

  it("11. The old unconditional 'All historical directories...' claim is absent", () => {
    const states = [
      deriveAuditCoverage({ hasSelectedSession: false, loadedEvents: 0 }),
      deriveAuditCoverage({ hasSelectedSession: true, loadedEvents: 0, historyStatus: "loading", auditSummaryEventCount: 10 }),
      deriveAuditCoverage({ hasSelectedSession: true, loadedEvents: 5, historyTotalItems: 20, historyStatus: "ready" }),
      deriveAuditCoverage({ hasSelectedSession: true, loadedEvents: 20, historyTotalItems: 20, historyComplete: true, historyStatus: "ready" }),
      deriveAuditCoverage({ hasSelectedSession: true, loadedEvents: 0, historyStatus: "error", auditSummaryEventCount: 5 }),
      deriveAuditCoverage({ hasSelectedSession: true, loadedEvents: 5, historyStatus: "error", auditSummaryEventCount: 15 }),
    ];
    for (const state of states) {
      expect(state.wording).not.toContain("All historical directories touched by this session are preserved on the canvas.");
    }
  });

  describe("Audit correction: refresh and error boundaries with complete/partial/zero/singular data", () => {
    it("1. complete 40/40 + refreshing: states all events remain loaded and refreshing, not loading earlier events", () => {
      const model = deriveAuditCoverage({
        hasSelectedSession: true,
        loadedEvents: 40,
        historyTotalItems: 40,
        historyComplete: true,
        historyStatus: "refreshing",
        auditSummaryEventCount: 40,
      });
      expect(model.eventCoverage).toBe("complete");
      expect(model.loadedEvents).toBe(40);
      expect(model.totalEvents).toBe(40);
      expect(model.unloadedEvents).toBe(0);
      expect(model.wording).toContain("All 40 retained events remain loaded");
      expect(model.wording).toContain("refreshing");
      expect(model.wording).not.toContain("loading earlier events");
      expect(model.wording).not.toContain("remain unloaded");
    });

    it("2. partial 15/40 + refreshing: preserves N/M facts and states refreshing without claiming complete", () => {
      const model = deriveAuditCoverage({
        hasSelectedSession: true,
        loadedEvents: 15,
        historyTotalItems: 40,
        historyComplete: false,
        historyStatus: "refreshing",
        auditSummaryEventCount: 40,
      });
      expect(model.eventCoverage).toBe("partial");
      expect(model.loadedEvents).toBe(15);
      expect(model.totalEvents).toBe(40);
      expect(model.unloadedEvents).toBe(25);
      expect(model.wording).toContain("Loaded 15 of 40 retained events");
      expect(model.wording).toContain("refreshing");
      expect(model.wording).not.toContain("complete");
      expect(model.wording).not.toContain("all events");
    });

    it("3. zero loaded of non-zero total + refreshing: states loaded 0 of total and refreshing", () => {
      const model = deriveAuditCoverage({
        hasSelectedSession: true,
        loadedEvents: 0,
        historyTotalItems: 0,
        historyComplete: false,
        historyStatus: "refreshing",
        auditSummaryEventCount: 25,
      });
      expect(model.loadedEvents).toBe(0);
      expect(model.totalEvents).toBe(25);
      expect(model.unloadedEvents).toBe(25);
      expect(model.wording).toContain("Loaded 0 of 25 retained events");
      expect(model.wording).toContain("refreshing");
    });

    it("4. complete 30/30 + error: states all events remain loaded and latest refresh failed, not remaining history unavailable", () => {
      const model = deriveAuditCoverage({
        hasSelectedSession: true,
        loadedEvents: 30,
        historyTotalItems: 30,
        historyComplete: true,
        historyStatus: "error",
        auditSummaryEventCount: 30,
      });
      expect(model.eventCoverage).toBe("error");
      expect(model.loadedEvents).toBe(30);
      expect(model.totalEvents).toBe(30);
      expect(model.unloadedEvents).toBe(0);
      expect(model.wording).toContain("All 30 retained events remain loaded");
      expect(model.wording).toMatch(/refresh failed|refresh is unavailable|refresh.*failed/i);
      expect(model.wording).not.toContain("Remaining event history is unavailable");
    });

    it("5. partial 12/30 + error: preserves Loaded 12 of 30 and states remaining history is unavailable", () => {
      const model = deriveAuditCoverage({
        hasSelectedSession: true,
        loadedEvents: 12,
        historyTotalItems: 30,
        historyComplete: false,
        historyStatus: "error",
        auditSummaryEventCount: 30,
      });
      expect(model.eventCoverage).toBe("error");
      expect(model.loadedEvents).toBe(12);
      expect(model.totalEvents).toBe(30);
      expect(model.unloadedEvents).toBe(18);
      expect(model.wording).toContain("Loaded 12 of 30 retained events");
      expect(model.wording).toContain("Remaining event history is unavailable");
    });

    it("6. zero total + error: truthfully represents 0 retained events recorded and retrieval failed", () => {
      const model = deriveAuditCoverage({
        hasSelectedSession: true,
        loadedEvents: 0,
        historyTotalItems: 0,
        historyComplete: true,
        historyStatus: "error",
        auditSummaryEventCount: 0,
      });
      expect(model.eventCoverage).toBe("error");
      expect(model.loadedEvents).toBe(0);
      expect(model.totalEvents).toBe(0);
      expect(model.unloadedEvents).toBe(0);
      expect(model.wording).toContain("0 retained events recorded");
      expect(model.wording).toMatch(/failed|unavailable/i);
      expect(model.wording).not.toContain("Loaded 0 of 0");
    });

    it("7. singular complete 1/1 wording: uses grammatically truthful singular form", () => {
      const model = deriveAuditCoverage({
        hasSelectedSession: true,
        loadedEvents: 1,
        historyTotalItems: 1,
        historyComplete: true,
        historyStatus: "ready",
        auditSummaryEventCount: 1,
      });
      expect(model.eventCoverage).toBe("complete");
      expect(model.loadedEvents).toBe(1);
      expect(model.totalEvents).toBe(1);
      expect(model.unloadedEvents).toBe(0);
      expect(model.wording).toContain("The retained event is loaded");
      expect(model.wording).not.toContain("All 1 retained event");
    });
  });
});
