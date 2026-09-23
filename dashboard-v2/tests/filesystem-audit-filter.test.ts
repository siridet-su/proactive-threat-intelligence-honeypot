import { describe, expect, it } from "vitest";

import {
  buildAuditUrlSearch,
  getDistinctSessionPaths,
  getHistoryWindowMetrics,
  isHistoryPage,
  isHomeOnlySession,
  parseAuditUrlParams,
  resolveSessionSelection,
  sessionTouchesPath,
} from "../src/components/filesystem/filesystemUtils";
import { buildAuditProjectionSummaryPipeline } from "../src/lib/filesystem-data";
import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
} from "../src/lib/dashboardTypes";

function session(
  sessionId: string,
  currentPath: string,
  visitedPaths: string[],
  homeOnly: boolean,
): FilesystemTopologySession {
  return {
    sessionId,
    sourceIp: "10.58.33.209",
    cwdState: {
      path: currentPath,
      status: "confirmed",
      observedAt: "2026-09-15T00:00:00.000Z",
      sourceEventId: `event-${sessionId}`,
    },
    auditSummary: {
      visitedPaths,
      homeOnly,
      eventCount: visitedPaths.length,
    },
  };
}

describe("filesystem audit filters", () => {
  it("binds the hide-home summary expression to each projected visited path", () => {
    const pipeline = buildAuditProjectionSummaryPipeline({ hideHome: true });
    const serialized = JSON.stringify(pipeline);

    expect(serialized).toContain('"input":"$$path"');
    expect(serialized).not.toContain('"input":"$path"');
  });

  it("does not classify a returned-home session as home-only", () => {
    const returnedHome = session(
      "returned-home",
      "/home/arch",
      ["/", "/etc", "/etc/profile.d", "/home/arch"],
      false,
    );

    expect(isHomeOnlySession(returnedHome)).toBe(false);
  });

  it("matches paths observed earlier in the session and their parent filter", () => {
    const returnedHome = session(
      "returned-home",
      "/home/arch",
      ["/", "/etc/profile.d", "/home/arch"],
      false,
    );

    expect(sessionTouchesPath(returnedHome, "/etc/profile.d")).toBe(true);
    expect(sessionTouchesPath(returnedHome, "/etc")).toBe(true);
    expect(sessionTouchesPath(returnedHome, "/var")).toBe(false);
  });

  it("builds path choices from complete active and retained closed-session summaries", () => {
    const active = session("active", "/home/arch", ["/home/arch", "/etc"], false);
    const closed: FilesystemClosedSession = {
      ...session("closed", "/var/tmp", ["/etc", "/var/tmp"], false),
      lifecycle: { startedAt: null, closedAt: "2026-09-15T00:01:00.000Z" },
    };

    expect(getDistinctSessionPaths([active], [closed])).toEqual([
      { path: "/etc", sessionCount: 2 },
      { path: "/home/arch", sessionCount: 1 },
      { path: "/var/tmp", sessionCount: 1 },
    ]);
  });
});

describe("filesystem history completeness", () => {
  it("rejects history payloads that omit completeness metadata", () => {
    expect(isHistoryPage({ items: [], nextCursor: null })).toBe(false);
    expect(isHistoryPage({
      items: [],
      nextCursor: null,
      totalItems: 12,
      totalSuccessfulItems: 10,
      complete: true,
    })).toBe(true);
  });

  it("keeps an event's absolute hop number stable as older pages are loaded", () => {
    const firstPage = getHistoryWindowMetrics(50, 120, 10);
    const secondPage = getHistoryWindowMetrics(100, 120, 60);

    expect(firstPage.selectedNumber).toBe(81);
    expect(secondPage.selectedNumber).toBe(81);
    expect(firstPage.unloadedItems).toBe(70);
    expect(secondPage.unloadedItems).toBe(20);
  });

  it("never reports a total smaller than the loaded window", () => {
    expect(getHistoryWindowMetrics(4, 2, 3)).toEqual({
      totalItems: 4,
      loadedItems: 4,
      unloadedItems: 0,
      indexOffset: 0,
      selectedNumber: 4,
    });
  });
});

describe("filtered selection and 0/N empty state semantics", () => {
  it("returns an empty audit snapshot when no session is selected", async () => {
    const { buildAuditSnapshot } = await import("../src/components/filesystem/filesystemUtils");
    const snapshot = buildAuditSnapshot(null, null, []);
    expect(snapshot.nodes).toEqual([]);
    expect(snapshot.sessions).toEqual([]);
    expect(snapshot.truncated).toBe(false);
  });

  it("identifies when a selected session lies outside active filter criteria", () => {
    const homeSession = session("home-only", "/home/user", ["/home/user"], true);
    const etcSession = session("etc-touch", "/etc", ["/etc", "/etc/profile.d"], false);

    // Filter by /var -> neither session matches (0/2 matches)
    expect(sessionTouchesPath(homeSession, "/var")).toBe(false);
    expect(sessionTouchesPath(etcSession, "/var")).toBe(false);

    // When hideHomeOnly is true, home-only session is filtered out
    expect(isHomeOnlySession(homeSession)).toBe(true);
    expect(isHomeOnlySession(etcSession)).toBe(false);
  });

  it("correctly classifies 0/N matching sessions when filter criteria eliminates all candidates", () => {
    const s1 = session("s1", "/home/a", ["/home/a"], true);
    const s2 = session("s2", "/home/b", ["/home/b"], true);
    const all = [s1, s2];

    const nonHome = all.filter((s) => !isHomeOnlySession(s));
    expect(nonHome.length).toBe(0);

    const pathMatches = all.filter((s) => sessionTouchesPath(s, "/etc"));
    expect(pathMatches.length).toBe(0);
  });
});

describe("audit URL state synchronization and session expiration", () => {
  it("parses empty search as default live view with no audit parameters", () => {
    const parsed = parseAuditUrlParams("");
    expect(parsed).toEqual({
      view: "live",
      sessionId: null,
      hideHome: false,
      targetPath: null,
      hop: null,
      timeRange: null,
      timeFrom: null,
      timeTo: null,
    });
  });

  it("parses audit view and all associated query parameters", () => {
    const parsed = parseAuditUrlParams("?view=audit&sessionId=sess-xyz&hideHome=1&targetPath=%2Fetc%2Fnginx&hop=evt-007");
    expect(parsed).toEqual({
      view: "audit",
      sessionId: "sess-xyz",
      hideHome: true,
      targetPath: "/etc/nginx",
      hop: "evt-007",
      timeRange: null,
      timeFrom: null,
      timeTo: null,
    });
  });

  it("builds a clean URL string when in live view", () => {
    const search = buildAuditUrlSearch({
      view: "live",
      sessionId: "sess-xyz",
      hideHome: true,
      targetPath: "/etc",
      hop: "evt-001",
      timeRange: null,
      timeFrom: null,
      timeTo: null,
    });
    expect(search).toBe("");
  });

  it("builds query string containing audit view, session, filters, and hop", () => {
    const search = buildAuditUrlSearch({
      view: "audit",
      sessionId: "sess-xyz",
      hideHome: true,
      targetPath: "/etc",
      hop: "evt-001",
      timeRange: null,
      timeFrom: null,
      timeTo: null,
    });
    expect(search).toBe("?view=audit&sessionId=sess-xyz&hideHome=1&targetPath=%2Fetc&hop=evt-001");

    // Verify roundtrip fidelity
    const parsed = parseAuditUrlParams(search);
    expect(parsed).toEqual({
      view: "audit",
      sessionId: "sess-xyz",
      hideHome: true,
      targetPath: "/etc",
      hop: "evt-001",
      timeRange: null,
      timeFrom: null,
      timeTo: null,
    });
  });

  it("resolves existing session candidate successfully", () => {
    const known = [{ sessionId: "sess-live" }, { sessionId: "sess-closed" }];
    const result = resolveSessionSelection("sess-live", null, known, true);
    expect(result).toEqual({
      sessionId: "sess-live",
      expiredSessionId: null,
    });
  });

  it("flags expiredSessionId in audit mode without silently choosing another session", () => {
    const known = [{ sessionId: "sess-live" }, { sessionId: "sess-closed" }];
    const result = resolveSessionSelection("sess-expired-999", null, known, true);
    expect(result).toEqual({
      sessionId: null,
      expiredSessionId: "sess-expired-999",
    });
  });

  it("flags expiredSessionId when session was explicitly requested via URL even in live mode", () => {
    const known = [{ sessionId: "sess-live" }];
    const result = resolveSessionSelection("sess-missing", null, known, false);
    expect(result).toEqual({
      sessionId: null,
      expiredSessionId: "sess-missing",
    });
  });

  it("falls back gracefully to available live session when disconnected live session was not explicitly requested", () => {
    const known = [{ sessionId: "sess-active-2" }];
    const result = resolveSessionSelection(null, "sess-active-1-disconnected", known, false);
    expect(result).toEqual({
      sessionId: "sess-active-2",
      expiredSessionId: null,
    });
  });

  it("handles empty session telemetry safely", () => {
    const result = resolveSessionSelection("sess-any", null, [], true);
    expect(result).toEqual({
      sessionId: null,
      expiredSessionId: "sess-any",
    });

    const fallbackResult = resolveSessionSelection(null, null, [], false);
    expect(fallbackResult).toEqual({
      sessionId: null,
      expiredSessionId: null,
    });
  });
});
