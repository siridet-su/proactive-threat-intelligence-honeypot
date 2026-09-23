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
  evaluateScopeAwareSummaryCounts,
  formatRetainedSubtitleCoverage,
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
      expect(meta.timeStr).not.toContain("18 Sept 2026");
      expect(meta.timeStr).toContain("19 Sept 2026");
      expect(meta.timeStr).toContain("UTC");
    });

    it("active session uses observedAt with an explicit Observed label and UTC zone", () => {
      const active = createActiveSession("active-1", "2026-09-20T08:15:00.000Z");
      const meta = formatSessionMetadata(active);
      expect(meta.timeStr).toMatch(/^Observed /);
      expect(meta.timeStr).toContain("UTC");
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
      expect(metaActNull.timeStr).toBe("Observed time unavailable");
      expect(metaActNull.timeStr).not.toContain("Invalid Date");
    });
  });

function fireInputChange(input: HTMLInputElement, value: string) {
  const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value",
  )?.set;
  if (nativeInputValueSetter) {
    nativeInputValueSetter.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

  describe("F. Audit correction: Evidence states and scope isolation", () => {
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

    it("1. Notice with retainedMatchingCount=null, retainedLoadedCount=0, status=loading must not contain '0 retained sessions match'", () => {
      const activeSession = createActiveSession("act-1", "2026-09-20T10:00:00.000Z");

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
            targetPathFilter: "/var/log",
            hideHomeOnly: false,
            selectedSession: activeSession,
            filteredActiveSessions: [activeSession],
            filteredClosedSessions: [],
            handleResetAuditFilters: vi.fn(),
            handleClearSelection: vi.fn(),
            retainedMatchingCount: null,
            retainedLoadedCount: 0,
            retainedCountStatus: "loading",
          }),
        );
      });

      expect(container.textContent).not.toContain("0 retained sessions match");
      expect(container.textContent).toContain("0 retained sessions loaded; exact match count loading");
    });

    it("2. Notice with retainedMatchingCount=null, retainedLoadedCount=2, status=error/stale/loaded-only must disclose loaded and exact count unavailable, not '2 match'", () => {
      const closed1 = createClosedSession("c-1", "2026-09-19T10:00:00.000Z");
      const closed2 = createClosedSession("c-2", "2026-09-19T11:00:00.000Z");
      const activeSession = createActiveSession("act-1", "2026-09-20T10:00:00.000Z");

      act(() => {
        root.render(
          createElement(AuditNoticeRegion, {
            expiredSessionId: null,
            allSessions: [closed1, closed2, activeSession],
            setExpiredSessionId: vi.fn(),
            handleUserSelectSession: vi.fn(),
            switchViewMode: vi.fn(),
            hasActiveFilters: true,
            isSelectedFilteredOut: true,
            filteredSessionsCount: 3,
            totalSessionsCount: 10,
            targetPathFilter: "/var/log",
            hideHomeOnly: false,
            selectedSession: activeSession,
            filteredActiveSessions: [activeSession],
            filteredClosedSessions: [closed1, closed2],
            handleResetAuditFilters: vi.fn(),
            handleClearSelection: vi.fn(),
            retainedMatchingCount: null,
            retainedLoadedCount: 2,
            retainedCountStatus: "error",
          }),
        );
      });

      expect(container.textContent).not.toContain("2 match");
      expect(container.textContent).not.toContain("2 other retained sessions match");
      expect(container.textContent).toContain("2 retained sessions loaded; exact match count unavailable");
    });

    it("3. Canvas subtitle under non-authoritative count distinguishes loaded count from exact matching count", () => {
      // Subtitle under loading state:
      const loadingSubtitle = formatRetainedSubtitleCoverage({
        retainedMatchingCount: null,
        retainedLoadedCount: 2,
        retainedCountStatus: "loading",
        isSelectedFilteredOut: true,
        hasActiveFilters: true,
        coverageWording: "Loaded 5 of 10 events",
      });
      expect(loadingSubtitle).toContain("2 retained sessions loaded; exact match count loading");
      expect(loadingSubtitle).not.toContain("2 matching");

      // Subtitle under error/stale state:
      const errorSubtitle = formatRetainedSubtitleCoverage({
        retainedMatchingCount: null,
        retainedLoadedCount: 2,
        retainedCountStatus: "error",
        isSelectedFilteredOut: true,
        hasActiveFilters: true,
        coverageWording: "Loaded 5 of 10 events",
      });
      expect(errorSubtitle).toContain("2 retained sessions loaded; exact match count unavailable");
      expect(errorSubtitle).not.toContain("2 matching");

      // Subtitle under authoritative matching state:
      const authSubtitle = formatRetainedSubtitleCoverage({
        retainedMatchingCount: 10,
        retainedLoadedCount: 2,
        retainedCountStatus: "authoritative",
        isSelectedFilteredOut: true,
        hasActiveFilters: true,
        coverageWording: "Loaded 5 of 10 events",
      });
      expect(authSubtitle).toContain("10 matching retained sessions available · 2 loaded");
    });

    it("4. Retained selected session with lifecycle object and closedAt: null must be labelled retained and not active", () => {
      const closedWithNull = createClosedSession("c-null", null, { sourceIp: "10.0.0.1" });

      act(() => {
        root.render(
          createElement(AuditNoticeRegion, {
            expiredSessionId: null,
            allSessions: [closedWithNull],
            setExpiredSessionId: vi.fn(),
            handleUserSelectSession: vi.fn(),
            switchViewMode: vi.fn(),
            hasActiveFilters: true,
            isSelectedFilteredOut: true,
            filteredSessionsCount: 1,
            totalSessionsCount: 10,
            targetPathFilter: "/etc",
            hideHomeOnly: false,
            selectedSession: closedWithNull,
            filteredActiveSessions: [],
            filteredClosedSessions: [],
            handleResetAuditFilters: vi.fn(),
            handleClearSelection: vi.fn(),
            retainedMatchingCount: 1,
            retainedLoadedCount: 0,
            retainedCountStatus: "authoritative",
          }),
        );
      });

      expect(container.textContent).toContain("Retained session 10.0.0.1");
      expect(container.textContent).not.toContain("Active session 10.0.0.1");
      expect(formatSessionMetadata(closedWithNull).timeStr).toBe("Closed time unavailable");
    });

    it("5. Active selected session remains labelled active and never described as retained", () => {
      const activeSession = createActiveSession("act-1", "2026-09-20T10:00:00.000Z", { sourceIp: "10.0.0.2" });

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
            filteredSessionsCount: 1,
            totalSessionsCount: 10,
            targetPathFilter: "/etc",
            hideHomeOnly: false,
            selectedSession: activeSession,
            filteredActiveSessions: [activeSession],
            filteredClosedSessions: [],
            handleResetAuditFilters: vi.fn(),
            handleClearSelection: vi.fn(),
            retainedMatchingCount: 1,
            retainedLoadedCount: 0,
            retainedCountStatus: "authoritative",
          }),
        );
      });

      expect(container.textContent).toContain("Active session 10.0.0.2");
      expect(container.textContent).not.toContain("Retained session 10.0.0.2");
    });

    it("6. Search mode with global retainedMatchingCount=120 and 1 search result must not render '1 loaded of 120 matching'", async () => {
      const searchItem = createClosedSession("search-1", "2026-09-19T10:00:00.000Z");

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [],
            recentClosedSessions: [],
            searchResults: [searchItem],
            selectedSessionId: "search-1",
            onSelectSession: vi.fn(),
            retainedMatchingCount: 120,
            retainedLoadedCount: 1,
            retainedCountStatus: "authoritative",
            onSearch: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      await act(async () => {
        trigger.click();
      });

      // Type a search query into input
      const searchInput = container.querySelector('input[type="text"]') as HTMLInputElement;
      expect(searchInput).not.toBeNull();
      expect(searchInput.placeholder).toBe("Search IP, session ID, or current/last CWD...");
      expect(searchInput.placeholder).not.toContain("or path");
      await act(async () => {
        fireInputChange(searchInput, "test");
      });

      expect(container.textContent).not.toContain("1 loaded of 120 matching");
      expect(container.textContent).toContain("Retained search results (1 loaded)");
    });

    it("7. Non-search mode with retainedMatchingCount=120 and retainedLoadedCount=25 renders '25 loaded of 120 matching'", async () => {
      const loaded: FilesystemClosedSession[] = [];
      for (let i = 0; i < 25; i++) {
        loaded.push(createClosedSession(`c-${i}`, "2026-09-19T10:00:00.000Z"));
      }

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [],
            recentClosedSessions: loaded,
            selectedSessionId: "c-0",
            onSelectSession: vi.fn(),
            retainedMatchingCount: 120,
            retainedLoadedCount: 25,
            retainedCountStatus: "authoritative",
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      await act(async () => {
        trigger.click();
      });

      expect(container.textContent).toContain("25 loaded of 120 matching");
    });

    it("8. Exact matchingCount > 0 but filteredClosedSessions=[] and active sessions exist: no Switch to match selects active session", () => {
      const activeSession = createActiveSession("act-1", "2026-09-20T10:00:00.000Z");
      const handleUserSelect = vi.fn();

      act(() => {
        root.render(
          createElement(AuditNoticeRegion, {
            expiredSessionId: null,
            allSessions: [activeSession],
            setExpiredSessionId: vi.fn(),
            handleUserSelectSession: handleUserSelect,
            switchViewMode: vi.fn(),
            hasActiveFilters: true,
            isSelectedFilteredOut: true,
            filteredSessionsCount: 1,
            totalSessionsCount: 10,
            targetPathFilter: "/var/log",
            hideHomeOnly: false,
            selectedSession: activeSession,
            filteredActiveSessions: [activeSession],
            filteredClosedSessions: [],
            handleResetAuditFilters: vi.fn(),
            handleClearSelection: vi.fn(),
            retainedMatchingCount: 10,
            retainedLoadedCount: 0,
            retainedCountStatus: "authoritative",
          }),
        );
      });

      // "Switch to match" button must not exist when 0 closed matches are loaded
      const buttons = Array.from(container.querySelectorAll("button"));
      const switchBtn = buttons.find((b) => b.textContent?.includes("Switch to match"));
      expect(switchBtn).toBeUndefined();
      expect(handleUserSelect).not.toHaveBeenCalled();
    });

    it("9. Complete directory with a path/home filter and no summary sets matching=loaded and total=null", () => {
      const c1 = createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"] });
      const c2 = createClosedSession("c-2", "2026-09-19T11:00:00.000Z", { paths: ["/var/log"] });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [c1, c2],
        snapshotRecentClosedSessions: [],
        isDirectoryComplete: true,
        targetPathFilter: "/var/log",
        summary: null,
      });

      expect(metrics.retainedMatchingCount).toBe(2);
      expect(metrics.retainedTotalCount).toBeNull();
      expect(metrics.retainedCountStatus).toBe("authoritative");
    });

    it("10. Complete unfiltered directory sets matching=loaded and total=loaded", () => {
      const c1 = createClosedSession("c-1", "2026-09-19T10:00:00.000Z");
      const c2 = createClosedSession("c-2", "2026-09-19T11:00:00.000Z");

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [c1, c2],
        snapshotRecentClosedSessions: [],
        isDirectoryComplete: true,
        targetPathFilter: null,
        hideHomeOnly: false,
        timeRange: "all",
        summary: null,
      });

      expect(metrics.retainedMatchingCount).toBe(2);
      expect(metrics.retainedTotalCount).toBe(2);
      expect(metrics.retainedCountStatus).toBe("authoritative");
    });

    it("11. Contradictory totalSessions < retainedLoadedCount sets totalCount to null and status to loaded-only", () => {
      const loaded: FilesystemClosedSession[] = [];
      for (let i = 0; i < 5; i++) {
        loaded.push(createClosedSession(`c-${i}`, "2026-09-19T10:00:00.000Z"));
      }

      const summary: AuditDirectorySummary = {
        totalSessions: 2, // Contradiction: 2 < 5 loaded
        homeOnlyCount: 0,
      };

      const scopeKey = createAuditScopeKey({ hideHome: false, targetPath: null });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
      });

      expect(metrics.retainedTotalCount).toBeNull();
      expect(metrics.retainedMatchingCount).toBeNull();
      expect(metrics.retainedCountStatus).toBe("loaded-only");
    });
  });

  describe("G. Retained count fail-closed invariants and cross-field validation", () => {
    it("A. target-path summary: matchingCount > totalSessions fails closed to loaded-only", () => {
      const loaded = [createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"] })];
      const summary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 2,
        matchingCount: 20, // Contradiction: 20 > 10
      };
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

      expect(metrics.retainedMatchingCount).toBeNull();
      expect(metrics.retainedTotalCount).toBeNull();
      expect(metrics.retainedCountStatus).toBe("loaded-only");
    });

    it("B. invalid home-only summaries: homeOnlyCount < 0 or > totalSessions fails closed without Math.max clamping", () => {
      const loaded = [createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"] })];
      const scopeKey = createAuditScopeKey({ hideHome: true, targetPath: null });

      // Case 1: homeOnlyCount < 0
      const summaryNegHome: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: -2,
      };

      const metricsNeg = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary: summaryNegHome,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: true,
      });

      expect(metricsNeg.retainedMatchingCount).toBeNull();
      expect(metricsNeg.retainedTotalCount).toBeNull();
      expect(metricsNeg.retainedCountStatus).toBe("loaded-only");

      // Case 2: homeOnlyCount > totalSessions (must not clamp with Math.max(0, total - home))
      const summaryExcessHome: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 12,
      };

      const metricsExcess = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary: summaryExcessHome,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: true,
      });

      expect(metricsExcess.retainedMatchingCount).toBeNull();
      expect(metricsExcess.retainedTotalCount).toBeNull();
      expect(metricsExcess.retainedCountStatus).toBe("loaded-only");
    });

    it("C. invalid required counts: negative, fractional, non-finite, and unsafe integers fail closed", () => {
      const loaded = [createClosedSession("c-1", "2026-09-19T10:00:00.000Z")];
      const scopeKey = createAuditScopeKey({ hideHome: false, targetPath: null });

      // Fractional totalSessions
      const fractionalSummary = {
        totalSessions: 10.5,
        homeOnlyCount: 2,
      } as unknown as AuditDirectorySummary;

      const metricsFrac = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary: fractionalSummary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
      });

      expect(metricsFrac.retainedMatchingCount).toBeNull();
      expect(metricsFrac.retainedTotalCount).toBeNull();
      expect(metricsFrac.retainedCountStatus).toBe("loaded-only");

      // Non-finite totalSessions (NaN)
      const nanSummary = {
        totalSessions: Number.NaN,
        homeOnlyCount: 0,
      } as unknown as AuditDirectorySummary;

      const metricsNaN = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary: nanSummary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
      });

      expect(metricsNaN.retainedMatchingCount).toBeNull();
      expect(metricsNaN.retainedTotalCount).toBeNull();
      expect(metricsNaN.retainedCountStatus).toBe("loaded-only");

      // Unsafe integer
      const unsafeSummary = {
        totalSessions: Number.MAX_SAFE_INTEGER + 1000,
        homeOnlyCount: 0,
      } as unknown as AuditDirectorySummary;

      const metricsUnsafe = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary: unsafeSummary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
      });

      expect(metricsUnsafe.retainedMatchingCount).toBeNull();
      expect(metricsUnsafe.retainedTotalCount).toBeNull();
      expect(metricsUnsafe.retainedCountStatus).toBe("loaded-only");
    });

    it("D. invalid total with otherwise valid matchingCount must not trust matchingCount alone", () => {
      const loaded = [createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"] })];
      const scopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/var/log" });

      const invalidTotalSummary: AuditDirectorySummary = {
        totalSessions: -1, // invalid
        homeOnlyCount: 0,
        matchingCount: 5,  // seemingly valid, but cannot be trusted from a corrupt summary
      };

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary: invalidTotalSummary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        targetPathFilter: "/var/log",
      });

      expect(metrics.retainedMatchingCount).toBeNull();
      expect(metrics.retainedTotalCount).toBeNull();
      expect(metrics.retainedCountStatus).toBe("loaded-only");
    });

    it("E. valid boundaries remain accepted", () => {
      const scopeKey = createAuditScopeKey({ hideHome: false, targetPath: null });

      // Boundary 1: totalSessions=0, homeOnlyCount=0
      const summaryZero: AuditDirectorySummary = {
        totalSessions: 0,
        homeOnlyCount: 0,
        matchingCount: 0,
      };

      const metricsZero = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [],
        snapshotRecentClosedSessions: [],
        summary: summaryZero,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
      });

      expect(metricsZero.retainedMatchingCount).toBe(0);
      expect(metricsZero.retainedTotalCount).toBe(0);
      expect(metricsZero.retainedCountStatus).toBe("authoritative");

      // Boundary 2: matchingCount === totalSessions
      const loadedFive: FilesystemClosedSession[] = [];
      for (let i = 0; i < 5; i++) {
        loadedFive.push(createClosedSession(`c-${i}`, "2026-09-19T10:00:00.000Z", { paths: ["/var/log"] }));
      }
      const pathScopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/var/log" });
      const summaryAllMatch: AuditDirectorySummary = {
        totalSessions: 5,
        homeOnlyCount: 0,
        matchingCount: 5,
      };

      const metricsAllMatch = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loadedFive,
        snapshotRecentClosedSessions: [],
        summary: summaryAllMatch,
        summaryScopeKey: pathScopeKey,
        currentScopeKey: pathScopeKey,
        summaryStatus: "success",
        targetPathFilter: "/var/log",
      });

      expect(metricsAllMatch.retainedMatchingCount).toBe(5);
      expect(metricsAllMatch.retainedTotalCount).toBe(5);
      expect(metricsAllMatch.retainedCountStatus).toBe("authoritative");

      // Boundary 3: homeOnlyCount === totalSessions on hideHomeOnly scope (matching count is exactly 0)
      const hideScopeKey = createAuditScopeKey({ hideHome: true, targetPath: null });
      const summaryAllHome: AuditDirectorySummary = {
        totalSessions: 8,
        homeOnlyCount: 8,
      };

      const metricsAllHome = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [],
        snapshotRecentClosedSessions: [],
        summary: summaryAllHome,
        summaryScopeKey: hideScopeKey,
        currentScopeKey: hideScopeKey,
        summaryStatus: "success",
        hideHomeOnly: true,
      });

      expect(metricsAllHome.retainedMatchingCount).toBe(0);
      expect(metricsAllHome.retainedTotalCount).toBe(8);
      expect(metricsAllHome.retainedCountStatus).toBe("authoritative");
    });

    it("F. public homeOnlyCount falls back to locally loaded evidence when summary count evidence is invalid", () => {
      const homeSession = createClosedSession("c-home", "2026-09-19T10:00:00.000Z", {
        paths: ["/home", "/home/user"],
        homeOnly: true,
      });
      const outsideSession = createClosedSession("c-outside", "2026-09-19T11:00:00.000Z", {
        paths: ["/var/log"],
        homeOnly: false,
      });

      const malformedSummary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: -5, // invalid negative homeOnlyCount
      };
      const scopeKey = createAuditScopeKey({ hideHome: false, targetPath: null });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [homeSession, outsideSession],
        snapshotRecentClosedSessions: [],
        summary: malformedSummary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
      });

      // Must not be negative or contaminated by -5; must fall back to the 1 loaded home-only session
      expect(metrics.homeOnlyCount).toBe(1);
    });
  });

  describe("H. Scope-specific count coherence and cross-field invariants", () => {
    it("1. Hide-home-only contradiction: total=10, homeOnly=2, matching=3 fails closed", () => {
      const loaded = [
        createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"], homeOnly: false }),
      ];
      const summary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 2,
        matchingCount: 3, // Contradiction: 10 - 2 = 8, not 3
      };
      const scopeKey = createAuditScopeKey({ hideHome: true, targetPath: null });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: true,
      });

      expect(metrics.retainedMatchingCount).toBeNull();
      expect(metrics.retainedTotalCount).toBeNull();
      expect(metrics.retainedCountStatus).toBe("loaded-only");
    });

    it("2. Valid hide-home-only agreement: total=10, homeOnly=2, matching=8 reports authoritative", () => {
      const loaded = [
        createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"], homeOnly: false }),
      ];
      const summary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 2,
        matchingCount: 8, // Exact agreement with 10 - 2
      };
      const scopeKey = createAuditScopeKey({ hideHome: true, targetPath: null });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: true,
      });

      expect(metrics.retainedMatchingCount).toBe(8);
      expect(metrics.retainedTotalCount).toBe(10);
      expect(metrics.retainedCountStatus).toBe("authoritative");
    });

    it("3. Hide-home-only with matchingCount omitted: total=10, homeOnly=2 derives authoritative matching=8", () => {
      const loaded = [
        createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"], homeOnly: false }),
      ];
      const summary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 2,
      };
      const scopeKey = createAuditScopeKey({ hideHome: true, targetPath: null });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: true,
      });

      expect(metrics.retainedMatchingCount).toBe(8);
      expect(metrics.retainedTotalCount).toBe(10);
      expect(metrics.retainedCountStatus).toBe("authoritative");
    });

    it("4. Combined hide-home and target-path contradiction: total=10, homeOnly=8, matching=5 fails closed", () => {
      const loaded = [
        createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"], homeOnly: false }),
      ];
      const summary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 8,
        matchingCount: 5, // Contradiction: max non-home is 10 - 8 = 2, 5 > 2 is impossible
      };
      const scopeKey = createAuditScopeKey({ hideHome: true, targetPath: "/var/log" });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: true,
        targetPathFilter: "/var/log",
      });

      expect(metrics.retainedMatchingCount).toBeNull();
      expect(metrics.retainedTotalCount).toBeNull();
      expect(metrics.retainedCountStatus).toBe("loaded-only");
    });

    it("5. Valid combined hide-home and target-path: total=10, homeOnly=8, matching=2 reports authoritative", () => {
      const loaded = [
        createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"], homeOnly: false }),
      ];
      const summary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 8,
        matchingCount: 2, // Valid: 2 <= 10 - 8
      };
      const scopeKey = createAuditScopeKey({ hideHome: true, targetPath: "/var/log" });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: true,
        targetPathFilter: "/var/log",
      });

      expect(metrics.retainedMatchingCount).toBe(2);
      expect(metrics.retainedTotalCount).toBe(10);
      expect(metrics.retainedCountStatus).toBe("authoritative");
    });

    it("6. Unfiltered/time-only contradiction: total=10, matchingCount=3 fails closed", () => {
      const loaded = [
        createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"] }),
      ];
      const summary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 2,
        matchingCount: 3, // Contradiction: unfiltered scope must equal totalSessions (10)
      };
      const scopeKey = createAuditScopeKey({ hideHome: false, targetPath: null });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: false,
        targetPathFilter: null,
      });

      expect(metrics.retainedMatchingCount).toBeNull();
      expect(metrics.retainedTotalCount).toBeNull();
      expect(metrics.retainedCountStatus).toBe("loaded-only");
    });

    it("7. Valid unfiltered redundancy: total=10, matchingCount=10 reports authoritative", () => {
      const loaded = [
        createClosedSession("c-1", "2026-09-19T10:00:00.000Z", { paths: ["/var/log"] }),
      ];
      const summary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 2,
        matchingCount: 10, // Exact agreement with totalSessions
      };
      const scopeKey = createAuditScopeKey({ hideHome: false, targetPath: null });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loaded,
        snapshotRecentClosedSessions: [],
        summary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: false,
        targetPathFilter: null,
      });

      expect(metrics.retainedMatchingCount).toBe(10);
      expect(metrics.retainedTotalCount).toBe(10);
      expect(metrics.retainedCountStatus).toBe("authoritative");
    });

    it("8. Malformed scope-specific evidence causes homeOnlyCount to fall back to locally loaded evidence", () => {
      const homeSession = createClosedSession("c-home", "2026-09-19T10:00:00.000Z", {
        paths: ["/home", "/home/user"],
        homeOnly: true,
      });
      const outsideSession = createClosedSession("c-outside", "2026-09-19T11:00:00.000Z", {
        paths: ["/var/log"],
        homeOnly: false,
      });

      const contradictorySummary: AuditDirectorySummary = {
        totalSessions: 10,
        homeOnlyCount: 2,
        matchingCount: 3, // Contradiction for hideHomeOnly scope (10 - 2 = 8 !== 3)
      };
      const scopeKey = createAuditScopeKey({ hideHome: true, targetPath: null });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [homeSession, outsideSession],
        snapshotRecentClosedSessions: [],
        summary: contradictorySummary,
        summaryScopeKey: scopeKey,
        currentScopeKey: scopeKey,
        summaryStatus: "success",
        hideHomeOnly: true,
        targetPathFilter: null,
      });

      // Must not use contaminated server homeOnlyCount (2); must fall back to the 1 loaded home-only session
      expect(metrics.homeOnlyCount).toBe(1);
    });
  });

  describe("I. Explicit summary scope attribution", () => {
    const contradictorySummary: AuditDirectorySummary = {
      totalSessions: 120,
      homeOnlyCount: 40,
      matchingCount: 1,
    };

    it("1. never disables scope coherence through the legacy explicit-scope flag", () => {
      const legacyOptions = {
        summary: contradictorySummary,
        hideHomeOnly: true,
        targetPathFilter: null,
        hasExplicitScopeKey: false,
        retainedLoadedCount: 1,
      };

      expect(evaluateScopeAwareSummaryCounts(legacyOptions)).toEqual({
        isValid: false,
        derivedMatching: null,
      });
    });

    it("2. rejects coherent exact summary evidence when summaryScopeKey is omitted", () => {
      const homeSession = createClosedSession("home", "2026-09-19T10:00:00.000Z", {
        paths: ["/home/user"],
        homeOnly: true,
      });
      const outsideSession = createClosedSession("outside", "2026-09-19T11:00:00.000Z", {
        paths: ["/var/log"],
      });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [homeSession, outsideSession],
        snapshotRecentClosedSessions: [],
        summary: {
          totalSessions: 10,
          homeOnlyCount: 2,
          matchingCount: 8,
        },
        summaryStatus: "success",
        hideHomeOnly: true,
      });

      expect(metrics.retainedMatchingCount).toBeNull();
      expect(metrics.retainedTotalCount).toBeNull();
      expect(metrics.retainedCountStatus).toBe("loaded-only");
      expect(metrics.homeOnlyCount).toBe(1);
    });

    it.each([
      { label: "unfiltered", hideHomeOnly: false },
      { label: "hide-home", hideHomeOnly: true },
    ])(
      "3. rejects omitted-scope contradictory evidence for $label scope",
      ({ hideHomeOnly }) => {
        const metrics = deriveAuthoritativeAuditMetrics({
          viewMode: "audit",
          activeSessions: [],
          authoritativeClosedSessions: [
            createClosedSession("outside", "2026-09-19T11:00:00.000Z", {
              paths: ["/var/log"],
            }),
          ],
          snapshotRecentClosedSessions: [],
          summary: contradictorySummary,
          summaryStatus: "success",
          hideHomeOnly,
          targetPathFilter: null,
        });

        expect(metrics.retainedMatchingCount).toBeNull();
        expect(metrics.retainedTotalCount).toBeNull();
        expect(metrics.retainedCountStatus).toBe("loaded-only");
      },
    );

    it("4. does not promote missing or mismatched scope evidence through directory completion", () => {
      const loaded = [createClosedSession("outside", "2026-09-19T11:00:00.000Z")];
      const currentScopeKey = createAuditScopeKey({ hideHome: false, targetPath: null });
      const staleScopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/etc" });

      for (const summaryScopeKey of [undefined, staleScopeKey]) {
        const metrics = deriveAuthoritativeAuditMetrics({
          viewMode: "audit",
          activeSessions: [],
          authoritativeClosedSessions: loaded,
          snapshotRecentClosedSessions: [],
          summary: {
            totalSessions: 1,
            homeOnlyCount: 0,
            matchingCount: 1,
          },
          summaryScopeKey,
          currentScopeKey,
          summaryStatus: "success",
          isDirectoryComplete: true,
        });

        expect(metrics.retainedMatchingCount).toBeNull();
        expect(metrics.retainedTotalCount).toBeNull();
        expect(metrics.retainedCountStatus).toBe("loaded-only");
      }
    });
  });
});
