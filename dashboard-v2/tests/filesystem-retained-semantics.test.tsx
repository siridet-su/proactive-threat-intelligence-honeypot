// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
MotionGlobalConfig.skipAnimations = true;

import {
  deriveAuthoritativeAuditMetrics,
  createAuditScopeKey,
} from "../src/components/filesystem/useAuditDirectory";
import {
  AuditFilterControls,
  getPresetDateRange,
} from "../src/components/filesystem/AuditFilterControls";
import {
  AuditSessionSelect,
  formatSessionMetadata,
} from "../src/components/filesystem/AuditSessionSelect";
import { AuditNoticeRegion } from "../src/components/filesystem/AuditNoticeRegion";
import type {
  AuditDirectorySummary,
  FilesystemClosedSession,
  FilesystemTopologySession,
} from "../src/lib/dashboardTypes";

function createClosedSession(
  sessionId: string,
  closedAt: string | null,
  options?: {
    startedAt?: string | null;
    paths?: string[];
    homeOnly?: boolean;
    sourceIp?: string;
    eventCount?: number;
  },
): FilesystemClosedSession {
  return {
    sessionId,
    sourceIp: options?.sourceIp ?? "10.58.33.209",
    cwdState: {
      path: options?.paths?.[0] ?? "/",
      status: "confirmed",
      observedAt: "2026-09-20T10:00:00.000Z",
      sourceEventId: `evt-${sessionId}`,
    },
    lifecycle: {
      startedAt: options?.startedAt ?? null,
      closedAt: closedAt ?? null,
    },
    auditSummary: {
      visitedPaths: options?.paths ?? ["/"],
      homeOnly: options?.homeOnly ?? false,
      eventCount: options?.eventCount ?? (options?.paths?.length ?? 1),
    },
  };
}

function createActiveSession(
  sessionId: string,
  observedAt: string | null,
  options?: {
    paths?: string[];
    homeOnly?: boolean;
    sourceIp?: string;
    eventCount?: number;
  },
): FilesystemTopologySession {
  return {
    sessionId,
    sourceIp: options?.sourceIp ?? "192.168.1.100",
    cwdState: {
      path: options?.paths?.[0] ?? "/",
      status: "confirmed",
      observedAt: observedAt ?? "",
      sourceEventId: `evt-${sessionId}`,
    },
    auditSummary: {
      visitedPaths: options?.paths ?? ["/"],
      homeOnly: options?.homeOnly ?? false,
      eventCount: options?.eventCount ?? (options?.paths?.length ?? 1),
    },
  };
}

describe("FSV-004: Retained time and count semantics", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-20T12:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("A. Retained Closed-at filtering", () => {
    it("Yesterday includes closed session with closedAt yesterday and excludes startedAt yesterday with closedAt today", () => {
      const yesterdayRange = getPresetDateRange("yesterday");
      expect(yesterdayRange?.from).toBeDefined();
      expect(yesterdayRange?.to).toBeDefined();

      const closedYesterday = createClosedSession("sess-yesterday", "2026-09-19T15:00:00.000Z", {
        startedAt: "2026-09-19T10:00:00.000Z",
      });

      const startedYesterdayClosedToday = createClosedSession("sess-started-yday", "2026-09-20T02:00:00.000Z", {
        startedAt: "2026-09-19T20:00:00.000Z",
      });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [closedYesterday, startedYesterdayClosedToday],
        snapshotRecentClosedSessions: [],
        timeRange: "yesterday",
      });

      expect(metrics.filteredClosedSessions.map((s) => s.sessionId)).toEqual(["sess-yesterday"]);
      expect(metrics.retainedLoadedCount).toBe(1);
    });

    it("excludes closed sessions with null, empty, or invalid closedAt", () => {
      const nullClosed = createClosedSession("sess-null", null, {
        startedAt: "2026-09-19T10:00:00.000Z",
      });
      const emptyClosed = createClosedSession("sess-empty", "", {
        startedAt: "2026-09-19T10:00:00.000Z",
      });
      const invalidClosed = createClosedSession("sess-invalid", "invalid-iso-date", {
        startedAt: "2026-09-19T10:00:00.000Z",
      });
      const validClosed = createClosedSession("sess-valid", "2026-09-19T12:00:00.000Z");

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [nullClosed, emptyClosed, invalidClosed, validClosed],
        snapshotRecentClosedSessions: [],
        timeRange: "yesterday",
      });

      expect(metrics.filteredClosedSessions.map((s) => s.sessionId)).toEqual(["sess-valid"]);
      expect(metrics.retainedLoadedCount).toBe(1);
    });

    it("passes inclusive from and to bounds", () => {
      const yesterdayRange = getPresetDateRange("yesterday")!;
      const atExactFrom = createClosedSession("sess-from", yesterdayRange.from.toISOString());
      const atExactTo = createClosedSession("sess-to", yesterdayRange.to.toISOString());
      const beforeFrom = createClosedSession(
        "sess-before",
        new Date(yesterdayRange.from.getTime() - 1000).toISOString(),
      );
      const afterTo = createClosedSession(
        "sess-after",
        new Date(yesterdayRange.to.getTime() + 1000).toISOString(),
      );

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [atExactFrom, atExactTo, beforeFrom, afterTo],
        snapshotRecentClosedSessions: [],
        timeRange: "yesterday",
      });

      const matchedIds = metrics.filteredClosedSessions.map((s) => s.sessionId);
      expect(matchedIds).toContain("sess-from");
      expect(matchedIds).toContain("sess-to");
      expect(matchedIds).not.toContain("sess-before");
      expect(matchedIds).not.toContain("sess-after");
    });
  });

  describe("B. Active separation", () => {
    it("active session observed yesterday is not a retained Yesterday match and contributes zero to retained counts", () => {
      const activeObservedYesterday = createActiveSession("active-yday", "2026-09-19T14:00:00.000Z");
      const closedYesterday = createClosedSession("closed-yday", "2026-09-19T16:00:00.000Z");

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeObservedYesterday],
        authoritativeClosedSessions: [closedYesterday],
        snapshotRecentClosedSessions: [],
        timeRange: "yesterday",
      });

      // Retained counts count ONLY closed sessions
      expect(metrics.retainedLoadedCount).toBe(1);
      expect(metrics.activeVisibleCount).toBe(1);
      expect(metrics.filteredClosedSessions.map((s) => s.sessionId)).toEqual(["closed-yday"]);
    });

    it("active selected session when time filter is active is marked isSelectedFilteredOut", () => {
      const activeObservedYesterday = createActiveSession("active-yday", "2026-09-19T14:00:00.000Z");

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeObservedYesterday],
        authoritativeClosedSessions: [],
        snapshotRecentClosedSessions: [],
        selectedSessionId: "active-yday",
        timeRange: "yesterday",
      });

      expect(metrics.isSelectedFilteredOut).toBe(true);
    });
  });

  describe("C. Authoritative counts", () => {
    it("separates retainedTotalCount, retainedMatchingCount, and retainedLoadedCount", () => {
      const summary: AuditDirectorySummary = {
        totalSessions: 120,
        homeOnlyCount: 30,
        matchingCount: 80,
      };

      const loadedClosed: FilesystemClosedSession[] = [];
      for (let i = 0; i < 25; i++) {
        loadedClosed.push(createClosedSession(`sess-${i}`, "2026-09-19T12:00:00.000Z", { paths: ["/var/log"] }));
      }
      const activeSession = createActiveSession("active-1", "2026-09-20T11:00:00.000Z", { paths: ["/var/log"] });

      const scopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/var/log" });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: loadedClosed,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        targetPathFilter: "/var/log",
      });

      expect(metrics.retainedTotalCount).toBe(120);
      expect(metrics.retainedMatchingCount).toBe(80);
      expect(metrics.retainedLoadedCount).toBe(25);
      expect(metrics.activeVisibleCount).toBe(1);
      expect(metrics.retainedCountStatus).toBe("authoritative");
    });

    it("time-only summary with totalSessions=40 and no matchingCount yields 40 exact retained matches and active does not make it 41", () => {
      const summary: AuditDirectorySummary = {
        totalSessions: 40,
        homeOnlyCount: 10,
      };

      const active = createActiveSession("active-1", "2026-09-20T10:00:00.000Z");
      const yesterdayRange = getPresetDateRange("yesterday")!;
      const scopeKey = createAuditScopeKey({
        hideHome: false,
        targetPath: null,
        from: yesterdayRange.from.getTime(),
        to: yesterdayRange.to.getTime(),
      });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [active],
        authoritativeClosedSessions: [],
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        timeRange: "yesterday",
      });

      expect(metrics.retainedMatchingCount).toBe(40);
      expect(metrics.retainedTotalCount).toBe(40);
      expect(metrics.activeVisibleCount).toBe(1);
      expect(metrics.retainedCountStatus).toBe("authoritative");
    });

    it("stale, loading, error, or mismatched summaries cannot provide exact count", () => {
      const summary: AuditDirectorySummary = {
        totalSessions: 100,
        matchingCount: 75,
      };
      const scopeA = createAuditScopeKey({ hideHome: false, targetPath: "/var" });
      const scopeB = createAuditScopeKey({ hideHome: false, targetPath: "/etc" });

      // Loading
      const loadingMetrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [],
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeA,
        currentScopeKey: scopeA,
        summaryStatus: "loading",
      });
      expect(loadingMetrics.retainedMatchingCount).toBeNull();
      expect(loadingMetrics.retainedCountStatus).toBe("loading");

      // Error
      const errorMetrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [],
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeA,
        currentScopeKey: scopeA,
        summaryStatus: "error",
      });
      expect(errorMetrics.retainedMatchingCount).toBeNull();
      expect(errorMetrics.retainedCountStatus).toBe("error");

      // Stale
      const staleMetrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [],
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeA,
        currentScopeKey: scopeA,
        summaryStatus: "stale",
      });
      expect(staleMetrics.retainedMatchingCount).toBeNull();
      expect(staleMetrics.retainedCountStatus).toBe("stale");

      // Mismatch
      const mismatchMetrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [],
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeB,
        currentScopeKey: scopeA,
        summaryStatus: "success",
      });
      expect(mismatchMetrics.retainedMatchingCount).toBeNull();
      expect(mismatchMetrics.retainedCountStatus).toBe("loaded-only");
    });

    it("contradictory matchingCount smaller than loaded count fails closed to loaded-only", () => {
      const summary: AuditDirectorySummary = {
        totalSessions: 50,
        matchingCount: 5, // summary claims only 5 match
      };

      // but we have 10 loaded closed sessions that match
      const loaded: FilesystemClosedSession[] = [];
      for (let i = 0; i < 10; i++) {
        loaded.push(createClosedSession(`sess-${i}`, "2026-09-19T10:00:00.000Z", { paths: ["/var/log"] }));
      }

      const scopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/var/log" });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        targetPathFilter: "/var/log",
      });

      // Contradictory evidence: 5 < 10. Must fail closed:
      expect(metrics.retainedMatchingCount).toBeNull();
      expect(metrics.retainedCountStatus).toBe("loaded-only");
    });

    it("complete directory with no summary establishes exact matching equal to loaded count", () => {
      const loaded = [
        createClosedSession("sess-1", "2026-09-19T10:00:00.000Z"),
        createClosedSession("sess-2", "2026-09-19T11:00:00.000Z"),
      ];

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        isDirectoryComplete: true,
      });

      expect(metrics.retainedMatchingCount).toBe(2);
      expect(metrics.retainedLoadedCount).toBe(2);
      expect(metrics.retainedCountStatus).toBe("authoritative");
    });
  });

  describe("D. Presentation components", () => {
    let container: HTMLDivElement;
    let root: Root;

    beforeEach(() => {
      container = document.createElement("div");
      document.body.appendChild(container);
      root = createRoot(container);
    });

    afterEach(() => {
      act(() => {
        root.unmount();
      });
      container.remove();
    });

    it("AuditFilterControls renders authoritative matching and loaded counts with aria-label", async () => {
      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: true,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath: vi.fn(),
            timeRange: "all",
            onSelectTimeRange: vi.fn(),
            distinctPaths: [],
            homeOnlyCount: 5,
            filteredCount: 25,
            totalCount: 120,
            onResetFilters: vi.fn(),
            retainedMatchingCount: 80,
            retainedLoadedCount: 25,
            retainedTotalCount: 120,
            retainedCountStatus: "authoritative",
          }),
        );
      });

      const coverageEl = container.querySelector('[aria-label="Retained audit result coverage"]');
      expect(coverageEl).not.toBeNull();
      expect(coverageEl?.textContent).toContain("80 retained matching · 25 loaded");
    });

    it("AuditFilterControls renders loaded and unavailable/loading status when summary is not authoritative", async () => {
      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: true,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath: vi.fn(),
            timeRange: "all",
            onSelectTimeRange: vi.fn(),
            distinctPaths: [],
            homeOnlyCount: 5,
            filteredCount: 15,
            totalCount: 15,
            onResetFilters: vi.fn(),
            retainedMatchingCount: null,
            retainedLoadedCount: 15,
            retainedTotalCount: null,
            retainedCountStatus: "loading",
          }),
        );
      });

      const coverageEl = container.querySelector('[aria-label="Retained audit result coverage"]');
      expect(coverageEl?.textContent).toContain("15 retained loaded · exact count loading");
    });

    it("AuditSessionSelect renames group to Retained sessions and displays loaded of matching", async () => {
      const closed = createClosedSession("sess-closed-1", "2026-09-19T10:00:00.000Z");
      const active = createActiveSession("sess-active-1", "2026-09-20T10:00:00.000Z");

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [active],
            recentClosedSessions: [closed],
            selectedSessionId: "sess-closed-1",
            onSelectSession: vi.fn(),
            hasActiveFilters: true,
          }),
        );
      });

      // Open the dropdown
      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      await act(async () => {
        trigger.click();
      });

      const groups = container.querySelectorAll('[role="group"]');
      const groupLabels = Array.from(groups).map((g) => g.getAttribute("aria-label") ?? "");
      expect(groupLabels.some((l) => l.includes("Retained sessions"))).toBe(true);
      expect(groupLabels.some((l) => l.includes("Closed Sessions"))).toBe(false);
    });

    it("AuditNoticeRegion truthfully reports 0 retained sessions match and does not label active as retained", () => {
      const activeSession = createActiveSession("active-1", "2026-09-20T10:00:00.000Z", {
        sourceIp: "10.58.33.209",
      });

      act(() => {
        root.render(
          createElement(AuditNoticeRegion, {
            expiredSessionId: null,
            allSessions: [activeSession],
            setExpiredSessionId: vi.fn(),
            handleUserSelectSession: vi.fn(),
            switchViewMode: vi.fn(),
            hasActiveFilters: true,
            isSelectedFilteredOut: true,
            filteredSessionsCount: 0,
            totalSessionsCount: 10,
            targetPathFilter: "/etc",
            hideHomeOnly: false,
            selectedSession: activeSession,
            filteredActiveSessions: [activeSession],
            filteredClosedSessions: [],
            handleResetAuditFilters: vi.fn(),
            handleClearSelection: vi.fn(),
            retainedMatchingCount: 0,
            retainedLoadedCount: 0,
          }),
        );
      });

      expect(container.textContent).toContain("0 retained sessions match filter");
      expect(container.textContent).not.toContain("which is retained but falls outside");
    });
  });

  describe("E. Timestamp metadata formatting", () => {
    it("closed session uses closedAt with 'Closed ' prefix even when startedAt differs", () => {
      const session = createClosedSession("sess-1", "2026-09-19T14:30:00.000Z", {
        startedAt: "2026-09-18T09:00:00.000Z",
      });
      const meta = formatSessionMetadata(session);
      expect(meta.timeStr).toMatch(/^Closed /);
      expect(meta.timeStr).not.toContain("Sep 18");
      expect(meta.timeStr).toContain("Sep 19");
    });

    it("active session uses observedAt with 'Last observed ' prefix", () => {
      const active = createActiveSession("active-1", "2026-09-20T08:15:00.000Z");
      const meta = formatSessionMetadata(active);
      expect(meta.timeStr).toMatch(/^Last observed /);
    });

    it("missing or invalid timestamp produces explicit unavailable wording and never Invalid Date", () => {
      const nullClosed = createClosedSession("sess-null", null);
      const metaNull = formatSessionMetadata(nullClosed);
      expect(metaNull.timeStr).toBe("Closed time unavailable");
      expect(metaNull.timeStr).not.toContain("Invalid Date");

      const invalidClosed = createClosedSession("sess-inv", "not-a-date");
      const metaInv = formatSessionMetadata(invalidClosed);
      expect(metaInv.timeStr).toBe("Closed time unavailable");
      expect(metaInv.timeStr).not.toContain("Invalid Date");

      const nullActive = createActiveSession("act-null", null);
      const metaActNull = formatSessionMetadata(nullActive);
      expect(metaActNull.timeStr).toBe("Last observed unavailable");
      expect(metaActNull.timeStr).not.toContain("Invalid Date");
    });
  });
});
