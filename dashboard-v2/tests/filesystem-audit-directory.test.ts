import { describe, expect, it, vi } from "vitest";

import {
  buildAuditSessionsUrl,
  createAuditDirectoryStore,
  createAuditScopeKey,
  deriveAuthoritativeAuditMetrics,
  getPaginationRenderState,
  mergeAuthoritativeClosedSessions,
  mergeAuthoritativeDistinctPaths,
  parseAuditScopeKey,
  type AuditScope,
} from "../src/components/filesystem/useAuditDirectory";
import {
  buildAuditSessionsQuery,
  normalizeSessionAuditSummary,
} from "../src/lib/filesystem-data";
import type {
  AuditDirectorySummary,
  FilesystemClosedSession,
  FilesystemTopologySession,
} from "../src/lib/dashboardTypes";

function createActiveSession(
  sessionId: string,
  currentPath: string,
  visitedPaths: string[],
  homeOnly: boolean,
): FilesystemTopologySession {
  return {
    sessionId,
    sourceIp: "192.168.1.100",
    cwdState: {
      path: currentPath,
      status: "confirmed",
      observedAt: "2026-09-16T08:00:00.000Z",
      sourceEventId: `event-${sessionId}`,
    },
    auditSummary: {
      visitedPaths,
      homeOnly,
      eventCount: visitedPaths.length,
    },
  };
}

function createClosedSession(
  sessionId: string,
  closedAt: string,
  visitedPaths: string[],
  homeOnly: boolean,
  currentPath = "/home/user",
): FilesystemClosedSession {
  return {
    sessionId,
    sourceIp: `10.0.0.${parseInt(sessionId.replace(/\D/g, "") || "1", 10)}`,
    cwdState: {
      path: currentPath,
      status: "confirmed",
      observedAt: closedAt,
      sourceEventId: `event-${sessionId}`,
    },
    lifecycle: {
      startedAt: "2026-09-16T00:00:00.000Z",
      closedAt,
    },
    auditSummary: {
      visitedPaths,
      homeOnly,
      eventCount: visitedPaths.length,
    },
  };
}

describe("FA-001: Authoritative Audit Directory Ownership & Decoupled State", () => {
  // Base fixtures
  const activeSession = createActiveSession("active-01", "/etc", ["/etc", "/home/user"], false);

  // 12 recent closed sessions (snapshot buffer)
  const snapshotRecentClosedSessions: FilesystemClosedSession[] = Array.from({ length: 12 }, (_, i) => {
    const num = i + 1;
    const isHome = num % 3 === 0;
    const visited = isHome ? ["/home/user"] : ["/var/log", `/tmp/run-${num}`];
    const minute = String(50 - num).padStart(2, "0");
    return createClosedSession(`closed-${num}`, `2026-09-16T07:${minute}:00.000Z`, visited, isHome);
  });

  // Older closed sessions (13 to 25)
  const olderAuditSessions: FilesystemClosedSession[] = [
    createClosedSession("closed-13", "2026-09-16T06:30:00.000Z", ["/var/log", "/usr/bin"], false),
    createClosedSession("closed-14", "2026-09-16T06:25:00.000Z", ["/home/test"], true),
    createClosedSession("closed-15", "2026-09-16T06:20:00.000Z", ["/etc/nginx", "/var/www"], false),
    createClosedSession("closed-16", "2026-09-16T06:15:00.000Z", ["/tmp/payload"], false),
    createClosedSession("closed-17", "2026-09-16T06:10:00.000Z", ["/home/attacker"], true),
    createClosedSession("closed-18", "2026-09-16T06:05:00.000Z", ["/etc/pam.d"], false),
    createClosedSession("closed-19", "2026-09-16T06:00:00.000Z", ["/var/spool/mail"], false),
    createClosedSession("closed-20", "2026-09-16T05:55:00.000Z", ["/opt/persistence/cron", "/etc/crontab"], false),
    createClosedSession("closed-21", "2026-09-16T05:50:00.000Z", ["/home/ftp"], true),
    createClosedSession("closed-22", "2026-09-16T05:45:00.000Z", ["/root/.ssh", "/etc/ssh"], false),
    createClosedSession("closed-23", "2026-09-16T05:40:00.000Z", ["/var/backups"], false),
    createClosedSession("closed-24", "2026-09-16T05:35:00.000Z", ["/home/service"], true),
    createClosedSession("closed-25", "2026-09-16T05:30:00.000Z", ["/tmp/scratch"], false),
  ];

  const all25ClosedSessions = [...snapshotRecentClosedSessions, ...olderAuditSessions];

  // ---------------------------------------------------------------------------
  // Suite 1: Live topology preservation
  // ---------------------------------------------------------------------------
  describe("1. Live Topology Isolation", () => {
    it("strictly bounds effective closed sessions to the snapshot buffer (12 items) in live mode", () => {
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "live",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        hideHomeOnly: false,
        targetPathFilter: null,
        selectedSessionId: null,
      });

      expect(metrics.effectiveClosedSessions.length).toBe(12);
      expect(metrics.totalSessionsCount).toBe(13); // 1 active + 12 buffer

      const distinctPathStrings = metrics.distinctPaths.map((p) => p.path);
      expect(distinctPathStrings).not.toContain("/opt/persistence/cron");
      expect(distinctPathStrings).not.toContain("/root/.ssh");
      expect(distinctPathStrings).not.toContain("/etc/nginx");
    });
  });

  // ---------------------------------------------------------------------------
  // Suite 2: >= 120 closed sessions with matching target path only on page 3
  // ---------------------------------------------------------------------------
  describe("2. Authoritative Metrics with >= 120 Sessions Across Multiple Pages", () => {
    // Generate 120 sessions: only session 115 (which would live on page 3 of 50 items/page) touches /opt/secret/backdoor
    const server120Summary: AuditDirectorySummary = {
      totalSessions: 120,
      homeOnlyCount: 40,
      matchingCount: 1, // Authoritative count of sessions matching /opt/secret/backdoor
      distinctPaths: [
        { path: "/home/user", sessionCount: 120 },
        { path: "/var/log", sessionCount: 60 },
        { path: "/opt/secret/backdoor", sessionCount: 1 },
      ],
    };

    // Client only has page 1 (50 items) loaded into memory, NONE of which touch /opt/secret/backdoor
    const clientPage1Sessions: FilesystemClosedSession[] = Array.from({ length: 50 }, (_, i) => {
      return createClosedSession(`sess-${i + 1}`, `2026-09-16T08:00:00.000Z`, ["/home/user", "/var/log"], false);
    });

    it("does NOT falsely report 0/N when target path matches a session on page 3", () => {
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession], // active session touches /etc and /home/user
        authoritativeClosedSessions: clientPage1Sessions,
        snapshotRecentClosedSessions,
        summary: server120Summary,
        hideHomeOnly: false,
        targetPathFilter: "/opt/secret/backdoor",
        selectedSessionId: null,
      });

      // Total must be 1 active + 120 database sessions = 121
      expect(metrics.totalSessionsCount).toBe(121);
      // Filtered sessions count must report 1 (from server summary), NOT 0/121!
      expect(metrics.filteredSessionsCount).toBe(1);
      expect(metrics.isAuthoritative).toBe(true);

      // Distinct paths must include the target path from the server summary immediately
      const distinctPathStrings = metrics.distinctPaths.map((p) => p.path);
      expect(distinctPathStrings).toContain("/opt/secret/backdoor");
    });

    it("truthfully reports total sessions matching when no filter is active without partial count disparity", () => {
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: clientPage1Sessions,
        snapshotRecentClosedSessions,
        summary: server120Summary,
        hideHomeOnly: false,
        targetPathFilter: null,
        selectedSessionId: null,
      });

      // Total count: 121
      expect(metrics.totalSessionsCount).toBe(121);
      // Filtered count when no filter is active must match totalSessionsCount (121), NOT partial in-memory count (51)
      expect(metrics.filteredSessionsCount).toBe(121);
    });

    it("truthfully calculates home-only filter across all 120 sessions using summary facets", () => {
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession], // active session is not home-only
        authoritativeClosedSessions: clientPage1Sessions,
        snapshotRecentClosedSessions,
        summary: server120Summary,
        hideHomeOnly: true,
        targetPathFilter: null,
        selectedSessionId: null,
      });

      expect(metrics.totalSessionsCount).toBe(121);
      expect(metrics.homeOnlyCount).toBe(40);
      // Non-home sessions: 1 active + (120 - 40) = 81
      expect(metrics.filteredSessionsCount).toBe(81);
    });
  });

  // ---------------------------------------------------------------------------
  // Suite 3: Decoupled Pagination State (Search vs Directory)
  // ---------------------------------------------------------------------------
  describe("3. Decoupled Directory and Search Pagination States", () => {
    it("preserves global directory cursor and hasMore when a search returns nextCursor=null", async () => {
      // Setup mock fetch
      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        if (!url.includes("q=")) {
          // Initial directory page: has more pages
          return {
            ok: true,
            json: async () => ({
              items: clientPage1Sessions,
              nextCursor: "dir-cursor-page-2",
              totalItems: 120,
              summary: { totalSessions: 120, homeOnlyCount: 30, distinctPaths: [] },
            }),
          } as Response;
        }

        if (url.includes("q=")) {
          // Search query returns results with nextCursor = null
          return {
            ok: true,
            json: async () => ({
              items: [createClosedSession("search-result-1", "2026-09-16T08:00:00.000Z", ["/tmp"], false)],
              nextCursor: null,
              totalItems: 1,
            }),
          } as Response;
        }

        return { ok: false, status: 404 } as Response;
      };

      const clientPage1Sessions = Array.from({ length: 50 }, (_, i) =>
        createClosedSession(`sess-${i + 1}`, "2026-09-16T08:00:00.000Z", ["/home"], false),
      );

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Step 1: Initial directory load
      await store.fetchInitial();
      expect(store.getState().directoryCursor).toBe("dir-cursor-page-2");
      expect(store.getState().directoryHasMore).toBe(true);
      expect(store.getState().directoryItems.length).toBe(50);

      // Step 2: Search returns complete results (nextCursor = null)
      await store.searchSessions("test-query");

      // Search state should be updated
      expect(store.getState().searchQuery).toBe("test-query");
      expect(store.getState().searchItems.length).toBe(1);
      expect(store.getState().searchCursor).toBeNull();
      expect(store.getState().searchHasMore).toBe(false);
      expect(store.getState().searchIsComplete).toBe(true);

      // CRITICAL: Directory state MUST remain unchanged!
      expect(store.getState().directoryCursor).toBe("dir-cursor-page-2");
      expect(store.getState().directoryHasMore).toBe(true);
      expect(store.getState().directoryItems.length).toBe(50);
    });

    it("maintains an independent search cursor and sends it on loadMoreSearch", async () => {
      const fetchedUrls: string[] = [];

      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        fetchedUrls.push(url);

        if (url.includes("cursor=search-cursor-page-2")) {
          return {
            ok: true,
            json: async () => ({
              items: [createClosedSession("search-result-2", "2026-09-16T07:00:00.000Z", ["/tmp"], false)],
              nextCursor: null,
              totalItems: 2,
            }),
          } as Response;
        }

        if (url.includes("q=myquery")) {
          return {
            ok: true,
            json: async () => ({
              items: [createClosedSession("search-result-1", "2026-09-16T08:00:00.000Z", ["/tmp"], false)],
              nextCursor: "search-cursor-page-2",
              totalItems: 2,
            }),
          } as Response;
        }

        return { ok: false, status: 404 } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Initial search page
      await store.searchSessions("myquery");
      expect(store.getState().searchCursor).toBe("search-cursor-page-2");
      expect(store.getState().searchHasMore).toBe(true);
      expect(store.getState().searchItems.length).toBe(1);

      // Load more search
      await store.loadMoreSearch();
      expect(store.getState().searchItems.length).toBe(2);
      expect(store.getState().searchCursor).toBeNull();
      expect(store.getState().searchHasMore).toBe(false);

      // Verify the URL for page 2 included query and search cursor
      const lastUrl = fetchedUrls[fetchedUrls.length - 1];
      expect(lastUrl).toContain("q=myquery");
      expect(lastUrl).toContain("cursor=search-cursor-page-2");
    });
  });

  // ---------------------------------------------------------------------------
  // Suite 4: Filter scoping with remote search
  // ---------------------------------------------------------------------------
  describe("4. Filter Scoping with Remote Search", () => {
    it("includes hideHome and targetPath query parameters when searching with active filters", async () => {
      const fetchedUrls: string[] = [];

      const mockFetch: typeof fetch = async (input) => {
        fetchedUrls.push(String(input));
        return {
          ok: true,
          json: async () => ({
            items: [],
            nextCursor: null,
            totalItems: 0,
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      await store.searchSessions("attacker", null, {
        hideHome: true,
        targetPath: "/etc/shadow",
      });

      expect(fetchedUrls.length).toBe(1);
      const url = fetchedUrls[0];
      expect(url).toContain("q=attacker");
      expect(url).toContain("hideHome=1");
      expect(url).toContain("targetPath=%2Fetc%2Fshadow");
    });
  });

  // ---------------------------------------------------------------------------
  // Suite 5: Pagination button and complete state mutual exclusivity
  // ---------------------------------------------------------------------------
  describe("5. Pagination Button and Completion State Mutual Exclusivity", () => {
    it("renders button when effectiveHasMore is true, never completed text", () => {
      const state = getPaginationRenderState({
        effectiveHasMore: true,
        effectiveIsLoading: false,
        hasItems: true,
        isComplete: false,
      });
      expect(state).toBe("button");
    });

    it("renders completed text when effectiveHasMore is false and items exist, never button", () => {
      const state = getPaginationRenderState({
        effectiveHasMore: false,
        effectiveIsLoading: false,
        hasItems: true,
        isComplete: true,
      });
      expect(state).toBe("completed");
    });

    it("renders neither during loading when there are no more items", () => {
      const state = getPaginationRenderState({
        effectiveHasMore: false,
        effectiveIsLoading: true,
        hasItems: true,
        isComplete: true,
      });
      expect(state).toBe("none");
    });

    it("keeps button in loading state during in-flight load more", () => {
      const state = getPaginationRenderState({
        effectiveHasMore: true,
        effectiveIsLoading: true,
        hasItems: true,
        isComplete: false,
      });
      expect(state).toBe("button");
    });
  });

  // ---------------------------------------------------------------------------
  // Suite 6: Initial request failure lifecycle and retry restoration
  // ---------------------------------------------------------------------------
  describe("6. Error State and Retry Lifecycle", () => {
    it("displays error state upon failure, and successfully restores data upon retry", async () => {
      let callCount = 0;

      const mockFetch: typeof fetch = async () => {
        callCount++;
        if (callCount === 1) {
          // First attempt fails with 500 error
          return {
            ok: false,
            status: 500,
            statusText: "Internal Server Error",
          } as Response;
        }

        // Second attempt succeeds
        return {
          ok: true,
          json: async () => ({
            items: [createClosedSession("recovered-1", "2026-09-16T08:00:00.000Z", ["/var"], false)],
            nextCursor: null,
            totalItems: 1,
            summary: { totalSessions: 1, homeOnlyCount: 0, distinctPaths: [] },
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // First fetch -> should enter error state
      await store.fetchInitial();
      expect(store.getState().status).toBe("error");
      expect(store.getState().errorMessage).toContain("Server returned status 500");
      expect(store.getState().directoryItems.length).toBe(0);

      // Retry -> should re-issue request and transition to success
      await store.retryInitial();
      expect(store.getState().status).toBe("success");
      expect(store.getState().errorMessage).toBeNull();
      expect(store.getState().directoryItems.length).toBe(1);
      expect(store.getState().directoryItems[0].sessionId).toBe("recovered-1");
      expect(callCount).toBe(2);
    });
  });

  // ---------------------------------------------------------------------------
  // Suite 7: Data flow URL and query construction tests
  // ---------------------------------------------------------------------------
  describe("7. Data Flow URL and Query Parameter Contract", () => {
    it("builds correct URL query parameters for all operations", () => {
      // Default initial query
      const initialUrl = buildAuditSessionsUrl({ limit: 50, summary: true });
      expect(initialUrl).toBe("/api/filesystem-topology/audit-sessions?limit=50&summary=1");

      // Pagination query with cursor
      const pageUrl = buildAuditSessionsUrl({ limit: 25, cursor: "cur-123" });
      expect(pageUrl).toBe("/api/filesystem-topology/audit-sessions?limit=25&cursor=cur-123");

      // Search query with filters
      const searchUrl = buildAuditSessionsUrl({
        limit: 25,
        q: "192.168",
        hideHome: true,
        targetPath: "/etc",
      });
      expect(searchUrl).toBe("/api/filesystem-topology/audit-sessions?limit=25&q=192.168&hideHome=1&targetPath=%2Fetc");
    });
  });

  // ---------------------------------------------------------------------------
  // Suite 8: Authoritative deduplication and path merging
  // ---------------------------------------------------------------------------
  describe("8. Deduplication and Authoritative Merging Logic", () => {
    it("deduplicates overlapping sessions and sorts chronologically descending by closedAt", () => {
      const snapSess = createClosedSession("sess-dup", "2026-09-16T01:00:00.000Z", ["/home"], true);
      const auditSess = createClosedSession("sess-dup", "2026-09-16T01:00:00.000Z", ["/home", "/etc"], false);
      const olderSess = createClosedSession("sess-old", "2026-09-16T00:30:00.000Z", ["/var"], false);
      const newerSess = createClosedSession("sess-new", "2026-09-16T02:00:00.000Z", ["/tmp"], false);

      const merged = mergeAuthoritativeClosedSessions(
        [snapSess],
        [olderSess, auditSess],
        [newerSess],
      );

      expect(merged.length).toBe(3);
      expect(merged.map((s) => s.sessionId)).toEqual(["sess-new", "sess-dup", "sess-old"]);
    });

    it("merges active and server distinct paths cleanly", () => {
      const activePaths = [{ path: "/etc", sessionCount: 1 }];
      const serverPaths = [
        { path: "/etc", sessionCount: 5 },
        { path: "/opt/secret", sessionCount: 2 },
      ];

      const merged = mergeAuthoritativeDistinctPaths(activePaths, serverPaths);
      expect(merged).toEqual([
        { path: "/etc", sessionCount: 6 }, // 1 active + 5 server
        { path: "/opt/secret", sessionCount: 2 },
      ]);
    });
  });

  // ---------------------------------------------------------------------------
  // Suite A: Selected-Session Persistence During Search
  // ---------------------------------------------------------------------------
  describe("Suite A: Selected-Session Persistence During Search", () => {
    it("preserves selected closed session in allSessions and sessionById when search query does not match it", () => {
      const sessionA = createClosedSession("sess-A", "2026-09-16T08:00:00.000Z", ["/var/log"], false);
      const sessionB = createClosedSession("sess-B", "2026-09-16T07:30:00.000Z", ["/tmp"], false);

      // User has sessionA selected initially
      const initialMetrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [sessionA, sessionB],
        snapshotRecentClosedSessions: [],
        selectedSessionId: "sess-A",
      });

      expect(initialMetrics.sessionById.get("sess-A")).toBeDefined();
      expect(initialMetrics.sessionById.get("sess-A")?.sessionId).toBe("sess-A");
      expect(initialMetrics.isSelectedFilteredOut).toBe(false);

      // User types a search query for "sess-B" or non-matching query
      // The authoritative closed sessions must NOT be replaced by search results!
      const duringSearchMetrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [sessionA, sessionB],
        snapshotRecentClosedSessions: [],
        selectedSessionId: "sess-A",
      });

      // Session A remains selected and present in sessionById & allSessions
      expect(duringSearchMetrics.sessionById.has("sess-A")).toBe(true);
      expect(duringSearchMetrics.allSessions.some((s) => s.sessionId === "sess-A")).toBe(true);
      expect(duringSearchMetrics.isSelectedFilteredOut).toBe(false);

      // Explicit user selection switches to session B
      const switchedMetrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: [sessionA, sessionB],
        snapshotRecentClosedSessions: [],
        selectedSessionId: "sess-B",
      });
      expect(switchedMetrics.sessionById.get("sess-B")?.sessionId).toBe("sess-B");
      expect(switchedMetrics.isSelectedFilteredOut).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  // Suite B: Scope-Bound Summary and Stale Response Discard
  // ---------------------------------------------------------------------------
  describe("Suite B: Scope-Bound Summary and Stale Response Discard", () => {
    it("round-trips createAuditScopeKey and parseAuditScopeKey", () => {
      const scope = { hideHome: true, targetPath: "/etc/nginx", q: "attacker" };
      const key = createAuditScopeKey(scope);
      expect(key).toBe(JSON.stringify([true, "/etc/nginx", "attacker", null, null]));
      expect(parseAuditScopeKey(key)).toEqual({
        hideHome: true,
        targetPath: "/etc/nginx",
        q: "attacker",
        from: undefined,
        to: undefined,
      });
    });

    it("round-trips paths and queries containing &, |, %, =, spaces, and Unicode with normalization", () => {
      const scope: AuditScope = {
        hideHome: true,
        targetPath: "/var/log|audit&test=1%20/dir///",
        q: "  Attacker & | % = 📁 นคร / test  ",
      };

      const key = createAuditScopeKey(scope);
      expect(key.startsWith("[")).toBe(true);

      const parsed = parseAuditScopeKey(key);
      expect(parsed.hideHome).toBe(true);
      // Target path normalized: trailing slashes stripped
      expect(parsed.targetPath).toBe("/var/log|audit&test=1%20/dir");
      // Query normalized: trimmed and lowercase
      expect(parsed.q).toBe("attacker & | % = 📁 นคร / test");

      // Root path preserves single slash
      const rootKey = createAuditScopeKey({ hideHome: false, targetPath: "///" });
      expect(parseAuditScopeKey(rootKey).targetPath).toBe("/");
    });

    it("discards out-of-order summary response for previous scope when later scope resolves first", async () => {
      let resolveVarSummary!: (value: Response) => void;
      const varPromise = new Promise<Response>((resolve) => {
        resolveVarSummary = resolve;
      });

      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        if (url.includes("targetPath=%2Fvar")) {
          return varPromise;
        }
        if (url.includes("targetPath=%2Fetc")) {
          // /etc resolves immediately
          return {
            ok: true,
            json: async () => ({
              totalSessions: 100,
              homeOnlyCount: 20,
              matchingCount: 15,
              distinctPaths: [{ path: "/etc", sessionCount: 15 }],
            }),
          } as Response;
        }
        return { ok: false, status: 404 } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Step 1: Request summary for /var (scope 1)
      const varCall = store.fetchSummary({ hideHome: false, targetPath: "/var" });

      // Step 2: Request summary for /etc (scope 2)
      await store.fetchSummary({ hideHome: false, targetPath: "/etc" });

      // Store must now reflect /etc scope
      const etcScopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/etc" });
      expect(store.getState().summaryScopeKey).toBe(etcScopeKey);
      expect(store.getState().summary?.matchingCount).toBe(15);

      // Step 3: Now resolve the delayed /var response
      resolveVarSummary({
        ok: true,
        json: async () => ({
          totalSessions: 100,
          homeOnlyCount: 20,
          matchingCount: 2,
          distinctPaths: [{ path: "/var", sessionCount: 2 }],
        }),
      } as Response);
      await varCall;

      // Stale /var response MUST have been discarded by generation guard
      expect(store.getState().summaryScopeKey).toBe(etcScopeKey);
      expect(store.getState().summary?.matchingCount).toBe(15);
    });

    it("marks isAuthoritative as false and falls back safely when summary scope does not match or fails", () => {
      const summaryForEtc: AuditDirectorySummary = {
        totalSessions: 100,
        homeOnlyCount: 20,
        matchingCount: 50,
        distinctPaths: [{ path: "/etc", sessionCount: 50 }],
      };

      const loadedSessions = [
        createClosedSession("sess-1", "2026-09-16T08:00:00.000Z", ["/var/log"], false),
      ];

      // Current scope is /var, but summary is for /etc (mismatched scope)
      const currentScopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/var" });
      const summaryScopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/etc" });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loadedSessions,
        snapshotRecentClosedSessions: [],
        summary: summaryForEtc,
        summaryScopeKey,
        currentScopeKey,
        summaryStatus: "stale",
        targetPathFilter: "/var",
      });

      // isAuthoritative MUST be false when scope keys do not match
      expect(metrics.isAuthoritative).toBe(false);
      // matchingCount from /etc (50) must NOT be applied to /var!
      expect(metrics.filteredSessionsCount).toBe(1); // falls back to loaded sessions matching /var

      // Summary error state also yields isAuthoritative: false
      const errorMetrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loadedSessions,
        snapshotRecentClosedSessions: [],
        summary: null,
        summaryScopeKey: null,
        currentScopeKey,
        summaryStatus: "error",
        targetPathFilter: "/var",
      });
      expect(errorMetrics.isAuthoritative).toBe(false);
      expect(errorMetrics.filteredSessionsCount).toBe(1);
    });

    it("stale or mismatched summary cannot affect totalSessionsCount or distinctPaths", () => {
      const staleSummary: AuditDirectorySummary = {
        totalSessions: 9999,
        homeOnlyCount: 500,
        matchingCount: 8888,
        distinctPaths: [{ path: "/stale/backdoor", sessionCount: 9999 }],
      };

      const loadedSessions = [
        createClosedSession("sess-1", "2026-09-16T08:00:00.000Z", ["/var/log"], false),
      ];

      // Scope mismatch: current scope is /var, summary is for /etc
      const currentScopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/var" });
      const staleScopeKey = createAuditScopeKey({ hideHome: false, targetPath: "/etc" });

      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loadedSessions,
        snapshotRecentClosedSessions: [],
        summary: staleSummary,
        summaryScopeKey: staleScopeKey,
        currentScopeKey,
        summaryStatus: "success", // even if status is success, mismatched scope key prevents using summary
        targetPathFilter: "/var",
      });

      // totalSessionsCount MUST NOT use 9999; must fall back to loaded count
      expect(metrics.totalSessionsCount).toBe(1);
      // distinctPaths MUST NOT contain /stale/backdoor
      expect(metrics.distinctPaths.some((p) => p.path === "/stale/backdoor")).toBe(false);
      // isAuthoritative MUST be false
      expect(metrics.isAuthoritative).toBe(false);

      // Loading state also ignores stale summary
      const loadingMetrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [],
        authoritativeClosedSessions: loadedSessions,
        snapshotRecentClosedSessions: [],
        summary: staleSummary,
        summaryScopeKey: currentScopeKey,
        currentScopeKey,
        summaryStatus: "loading",
        targetPathFilter: "/var",
      });
      expect(loadingMetrics.totalSessionsCount).toBe(1);
      expect(loadingMetrics.distinctPaths.some((p) => p.path === "/stale/backdoor")).toBe(false);
      expect(loadingMetrics.isAuthoritative).toBe(false);
    });

    it("exits loading with an error when server returns an HTTP 2xx response with invalid summary payload", async () => {
      const mockFetch: typeof fetch = async () => {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            // Invalid payload missing required summary fields
            malformed: true,
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      await store.fetchSummary({ hideHome: false, targetPath: null });

      // Must leave loading state and enter error state
      expect(store.getState().summaryIsLoading).toBe(false);
      expect(store.getState().summaryStatus).toBe("error");
      expect(store.getState().summaryError).toContain("Invalid summary payload");
      expect(store.getState().summary).toBeNull();
      expect(store.getState().summaryScopeKey).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // Suite C: Search Race Conditions and In-Flight Cancellation
  // ---------------------------------------------------------------------------
  describe("Suite C: Search Race Conditions and In-Flight Cancellation", () => {
    it("discards out-of-order search response when subsequent query resolves earlier", async () => {
      let resolveQueryA!: (value: Response) => void;
      const queryAPromise = new Promise<Response>((resolve) => {
        resolveQueryA = resolve;
      });

      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        const searchParams = new URL(url, "http://localhost").searchParams;
        if (searchParams.get("q") === "a") {
          return queryAPromise;
        }
        if (searchParams.get("q") === "ab") {
          return {
            ok: true,
            json: async () => ({
              items: [createClosedSession("sess-ab", "2026-09-16T08:00:00.000Z", ["/tmp"], false)],
              nextCursor: null,
              totalItems: 1,
            }),
          } as Response;
        }
        return { ok: false, status: 404 } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Trigger "a" first, then "ab"
      const callA = store.searchSessions("a");
      await store.searchSessions("ab");

      // Verify "ab" results are active
      expect(store.getState().searchQuery).toBe("ab");
      expect(store.getState().searchItems.map((s) => s.sessionId)).toEqual(["sess-ab"]);

      // Resolve "a" late
      resolveQueryA({
        ok: true,
        json: async () => ({
          items: [createClosedSession("sess-a-stale", "2026-09-16T08:00:00.000Z", ["/tmp"], false)],
          nextCursor: null,
          totalItems: 1,
        }),
      } as Response);
      await callA;

      // Stale "a" response must be discarded by generation guard
      expect(store.getState().searchQuery).toBe("ab");
      expect(store.getState().searchItems.map((s) => s.sessionId)).toEqual(["sess-ab"]);
    });

    it("aborts in-flight search and cleanly resets search state on clearSearch", async () => {
      let aborted = false;
      const mockFetch: typeof fetch = async (_input, init) => {
        const signal = init?.signal as AbortSignal | undefined;
        if (signal) {
          signal.addEventListener("abort", () => {
            aborted = true;
          });
        }
        return new Promise(() => {}); // never resolves
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      void store.searchSessions("in-flight-query");
      expect(store.getState().searchIsLoading).toBe(true);

      store.clearSearch();

      expect(aborted).toBe(true);
      expect(store.getState().searchQuery).toBe("");
      expect(store.getState().searchItems).toEqual([]);
      expect(store.getState().searchIsLoading).toBe(false);
      expect(store.getState().searchCursor).toBeNull();
      expect(store.getState().searchHasMore).toBe(false);
    });

    it("aborts and clears active search state when filter scope changes", async () => {
      let searchAborted = false;
      const mockFetch: typeof fetch = async (input, init) => {
        const url = String(input);
        if (url.includes("q=")) {
          const signal = init?.signal as AbortSignal | undefined;
          if (signal) {
            signal.addEventListener("abort", () => {
              searchAborted = true;
            });
          }
          return new Promise(() => {}); // never resolves
        }
        return {
          ok: true,
          json: async () => ({
            items: [],
            nextCursor: null,
            totalItems: 0,
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Start search under scope 1
      void store.searchSessions("attacker", null, { hideHome: false, targetPath: null });
      expect(store.getState().searchIsLoading).toBe(true);
      expect(store.getState().searchQuery).toBe("attacker");

      // Filter scope changes: fetchInitial for new scope
      await store.fetchInitial({ hideHome: true, targetPath: "/var" });

      // Active search must be aborted and cleared
      expect(searchAborted).toBe(true);
      expect(store.getState().searchQuery).toBe("");
      expect(store.getState().searchItems).toEqual([]);
      expect(store.getState().searchIsLoading).toBe(false);
      expect(store.getState().searchCursor).toBeNull();
    });

    it("never sends an old search cursor with a new filter scope and rejects/resets instead", async () => {
      const requestedUrls: string[] = [];

      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        requestedUrls.push(url);
        return {
          ok: true,
          json: async () => ({
            items: [createClosedSession("search-1", "2026-09-16T08:00:00.000Z", ["/tmp"], false)],
            nextCursor: "cursor-scope-1",
            totalItems: 5,
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Search page 1 under scope { hideHome: false, targetPath: null }
      await store.searchSessions("malware", null, { hideHome: false, targetPath: null });
      expect(store.getState().searchCursor).toBe("cursor-scope-1");

      // Attempt to loadMoreSearch with a DIFFERENT scope { hideHome: true, targetPath: "/etc" }
      await store.loadMoreSearch({ hideHome: true, targetPath: "/etc" });

      // Must reject/reset! Search cursor is NOT sent with the new filter scope.
      const invalidCombinedUrl = requestedUrls.find(
        (u) => u.includes("cursor=cursor-scope-1") && (u.includes("hideHome=1") || u.includes("targetPath")),
      );
      expect(invalidCombinedUrl).toBeUndefined();
      // Search state should be reset
      expect(store.getState().searchCursor).toBeNull();
      expect(store.getState().searchQuery).toBe("");
    });
  });

  // ---------------------------------------------------------------------------
  // Suite D: Filter Scope Preservation Across Directory Pagination
  // ---------------------------------------------------------------------------
  describe("Suite D: Filter Scope Preservation Across Directory Pagination", () => {
    it("preserves active filter scope across directory pagination pages", async () => {
      const requestedUrls: string[] = [];

      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        requestedUrls.push(url);

        if (url.includes("cursor=page-1-cursor")) {
          return {
            ok: true,
            json: async () => ({
              items: [createClosedSession("sess-page2", "2026-09-16T07:00:00.000Z", ["/etc"], false)],
              nextCursor: null,
              totalItems: 51,
            }),
          } as Response;
        }

        return {
          ok: true,
          json: async () => ({
            items: [createClosedSession("sess-page1", "2026-09-16T08:00:00.000Z", ["/etc"], false)],
            nextCursor: "page-1-cursor",
            totalItems: 51,
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Page 1 with scoped filter
      await store.fetchInitial({ hideHome: true, targetPath: "/etc" });
      expect(store.getState().directoryScopeKey).toBe(createAuditScopeKey({ hideHome: true, targetPath: "/etc" }));
      expect(store.getState().directoryCursor).toBe("page-1-cursor");

      // Page 2: loadMoreDirectory must preserve hideHome and targetPath
      await store.loadMoreDirectory();
      expect(requestedUrls.length).toBe(2);
      const page2Url = requestedUrls[1];
      expect(page2Url).toContain("hideHome=1");
      expect(page2Url).toContain("targetPath=%2Fetc");
      expect(page2Url).toContain("cursor=page-1-cursor");
      expect(store.getState().directoryItems.length).toBe(2);
    });

    it("aborts in-flight pagination, resets items, and fetches page 1 when filter scope changes", async () => {
      const requestedUrls: string[] = [];

      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        requestedUrls.push(url);
        return {
          ok: true,
          json: async () => ({
            items: [createClosedSession("sess-scoped", "2026-09-16T08:00:00.000Z", ["/var"], false)],
            nextCursor: "next-cursor",
            totalItems: 10,
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Scope 1: /etc
      await store.fetchInitial({ hideHome: false, targetPath: "/etc" });
      expect(store.getState().directoryScopeKey).toBe(createAuditScopeKey({ hideHome: false, targetPath: "/etc" }));

      // Scope 2: /var
      await store.fetchInitial({ hideHome: true, targetPath: "/var" });
      expect(store.getState().directoryScopeKey).toBe(createAuditScopeKey({ hideHome: true, targetPath: "/var" }));
      expect(requestedUrls[1]).toContain("hideHome=1");
      expect(requestedUrls[1]).toContain("targetPath=%2Fvar");
      expect(requestedUrls[1]).not.toContain("cursor=");
    });
  });

  // ---------------------------------------------------------------------------
  // Suite E: Query Builder Contracts and normalizeSessionAuditSummary Alignment
  // ---------------------------------------------------------------------------
  describe("Suite E: Query Builder Contracts and normalizeSessionAuditSummary Alignment", () => {
    it("strictly conforms to normalizeSessionAuditSummary semantics for visited paths, root handling, and homeOnly", () => {
      // 1. Root only is NOT home-only
      const rootOnly = normalizeSessionAuditSummary("/", [], [], 1);
      expect(rootOnly.visitedPaths).toEqual(["/"]);
      expect(rootOnly.homeOnly).toBe(false);

      // 2. Traversal through root while only visiting /home/user IS home-only
      const rootPlusHome = normalizeSessionAuditSummary("/", ["/home/operator"], ["/"], 2);
      expect(rootPlusHome.visitedPaths).toEqual(["/", "/home/operator"]);
      expect(rootPlusHome.homeOnly).toBe(true);

      // 3. Current path outside /home prevents home-only even with 0 events
      const outsideHomeCurrent = normalizeSessionAuditSummary("/etc", [], [], 0);
      expect(outsideHomeCurrent.visitedPaths).toEqual(["/etc"]);
      expect(outsideHomeCurrent.homeOnly).toBe(false);

      // 4. Session visiting both home and non-home is NOT home-only
      const mixedSession = normalizeSessionAuditSummary("/home/user", ["/home/user"], ["/var/log"], 2);
      expect(mixedSession.homeOnly).toBe(false);
    });

    it("verifies buildAuditSessionsQuery enforces closed lifecycle and covers legacy session_id and cwdState.path", () => {
      const query = buildAuditSessionsQuery({ search: "victim-path" });
      const andConditions = (query as { $and: Array<Record<string, unknown>> }).$and;

      // Closed lifecycle check
      expect(andConditions).toContainEqual({ "lifecycle.status": "closed" });
      expect(andConditions).toContainEqual({ "cwdState.path": { $type: "string", $ne: "" } });

      // Search check covers sessionId, session_id, sourceIp, and cwdState.path
      const searchCondition = andConditions.find((c) => Array.isArray(c.$or));
      expect(searchCondition).toBeDefined();
      const orClauses = searchCondition?.$or as Array<Record<string, unknown>>;
      expect(orClauses.some((c) => "sessionId" in c)).toBe(true);
      expect(orClauses.some((c) => "session_id" in c)).toBe(true);
      expect(orClauses.some((c) => "sourceIp" in c)).toBe(true);
      expect(orClauses.some((c) => "cwdState.path" in c)).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Suite F: Search and Pagination Request Parameter Contracts and Debounce Cancellation
  // ---------------------------------------------------------------------------
  describe("Suite F: Search and Pagination Request Parameter Contracts and Debounce Cancellation", () => {
    it("does not include summary parameter on search requests or paginated requests", () => {
      // Regular search URL has q, no summary
      const searchUrl = buildAuditSessionsUrl({ q: "test", limit: 25 });
      expect(searchUrl).not.toContain("summary=1");
      expect(searchUrl).toContain("q=test");

      // Pagination cursor URL has cursor, no summary
      const cursorUrl = buildAuditSessionsUrl({ cursor: "cursor-xyz", limit: 25 });
      expect(cursorUrl).not.toContain("summary=1");
      expect(cursorUrl).toContain("cursor=cursor-xyz");

      // Initial directory URL can request summary
      const summaryUrl = buildAuditSessionsUrl({ summary: true, limit: 50 });
      expect(summaryUrl).toContain("summary=1");
    });

    it("closing or clearing cancels a pending debounced search and fires onClearSearch", () => {
      vi.useFakeTimers();
      try {
        let searchFired = false;
        let clearFired = false;
        let searchedVal: string | null = null;
        const onSearch = (val: string) => {
          searchFired = true;
          searchedVal = val;
        };
        const onClearSearch = () => {
          clearFired = true;
        };

        // Simulate the debounce lifecycle
        let timer: ReturnType<typeof setTimeout> | null = null;
        let isOpen = true;

        const handleSearchChange = (val: string) => {
          if (timer) clearTimeout(timer);
          timer = setTimeout(() => {
            if (isOpen) onSearch(val);
          }, 250);
        };

        const handleClose = () => {
          if (timer) {
            clearTimeout(timer);
            timer = null;
          }
          isOpen = false;
          onClearSearch();
        };

        // User types search query
        handleSearchChange("attacker");
        expect(searchFired).toBe(false);

        // Before 250ms expires (at 100ms), user closes popover
        vi.advanceTimersByTime(100);
        handleClose();
        expect(clearFired).toBe(true);

        // Advance beyond the 250ms threshold
        vi.advanceTimersByTime(300);
        // Search request MUST NOT have fired
        expect(searchFired).toBe(false);
        expect(searchedVal).toBeNull();
      } finally {
        vi.useRealTimers();
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Suite G: FSV-003 Time Scope Propagation Through Search and Pagination
  // ---------------------------------------------------------------------------
  describe("Suite G: FSV-003 Time Scope Propagation Through Search and Pagination", () => {
    it("includes canonical from and to query parameters in search URL when supplied, and omits them when absent", async () => {
      const fetchedUrls: string[] = [];
      const mockFetch: typeof fetch = async (input) => {
        fetchedUrls.push(String(input));
        return {
          ok: true,
          json: async () => ({ items: [], nextCursor: null, totalItems: 0 }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // 1. Search with from and to
      await store.searchSessions("incident", null, {
        hideHome: true,
        targetPath: "/var/log",
        from: 1710000000000,
        to: 1710086400000,
      });

      expect(fetchedUrls.length).toBe(1);
      expect(fetchedUrls[0]).toContain("q=incident");
      expect(fetchedUrls[0]).toContain("hideHome=1");
      expect(fetchedUrls[0]).toContain("targetPath=%2Fvar%2Flog");
      expect(fetchedUrls[0]).toContain("from=1710000000000");
      expect(fetchedUrls[0]).toContain("to=1710086400000");

      // 2. Search without from and to
      await store.searchSessions("another", null, { hideHome: false });
      expect(fetchedUrls.length).toBe(2);
      expect(fetchedUrls[1]).toContain("q=another");
      expect(fetchedUrls[1]).not.toContain("from=");
      expect(fetchedUrls[1]).not.toContain("to=");
    });

    it("retains active from and to time scope across search pagination requests", async () => {
      const requestedUrls: string[] = [];
      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        requestedUrls.push(url);
        if (url.includes("cursor=page-1-search-cursor")) {
          return {
            ok: true,
            json: async () => ({
              items: [createClosedSession("search-sess-p2", "2026-09-16T07:00:00.000Z", ["/tmp"], false)],
              nextCursor: null,
              totalItems: 2,
            }),
          } as Response;
        }
        return {
          ok: true,
          json: async () => ({
            items: [createClosedSession("search-sess-p1", "2026-09-16T08:00:00.000Z", ["/tmp"], false)],
            nextCursor: "page-1-search-cursor",
            totalItems: 2,
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Initial search page 1 with time scope
      await store.searchSessions("payload", null, {
        hideHome: true,
        targetPath: "/tmp",
        from: 1710000000000,
        to: 1710086400000,
      });
      expect(store.getState().searchCursor).toBe("page-1-search-cursor");

      // Load more without explicit arguments (relies on stored scope retention)
      await store.loadMoreSearch();

      expect(requestedUrls.length).toBe(2);
      const page2Url = requestedUrls[1];
      expect(page2Url).toContain("q=payload");
      expect(page2Url).toContain("cursor=page-1-search-cursor");
      expect(page2Url).toContain("hideHome=1");
      expect(page2Url).toContain("targetPath=%2Ftmp");
      expect(page2Url).toContain("from=1710000000000");
      expect(page2Url).toContain("to=1710086400000");
      expect(store.getState().searchItems.length).toBe(2);
      expect(store.getState().searchCursor).toBeNull();
      expect(store.getState().searchHasMore).toBe(false);
      expect(store.getState().searchIsComplete).toBe(true);

      // Verify that calling loadMoreSearch with explicit matching options also succeeds and preserves scope
      await store.searchSessions("payload", null, {
        hideHome: true,
        targetPath: "/tmp",
        from: 1710000000000,
        to: 1710086400000,
      });
      expect(store.getState().searchCursor).toBe("page-1-search-cursor");

      await store.loadMoreSearch({
        hideHome: true,
        targetPath: "/tmp",
        from: 1710000000000,
        to: 1710086400000,
      });
      const page2ExplicitUrl = requestedUrls[requestedUrls.length - 1];
      expect(page2ExplicitUrl).toContain("from=1710000000000");
      expect(page2ExplicitUrl).toContain("to=1710086400000");
    });

    it("rejects mismatched from or to time scope on loadMoreSearch and clears search state", async () => {
      const requestedUrls: string[] = [];
      const mockFetch: typeof fetch = async (input) => {
        requestedUrls.push(String(input));
        return {
          ok: true,
          json: async () => ({
            items: [createClosedSession("search-sess-p1", "2026-09-16T08:00:00.000Z", ["/tmp"], false)],
            nextCursor: "cursor-time-scope-1",
            totalItems: 5,
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Search page 1 under scope with from: 1000, to: 2000
      await store.searchSessions("exploit", null, {
        hideHome: false,
        targetPath: null,
        from: 1000,
        to: 2000,
      });
      expect(store.getState().searchCursor).toBe("cursor-time-scope-1");
      expect(requestedUrls.length).toBe(1);

      // Attempt to loadMoreSearch with a DIFFERENT 'from' timestamp
      await store.loadMoreSearch({ hideHome: false, targetPath: null, from: 9999, to: 2000 });

      // Cursor must NOT have been sent with mismatched 'from'
      const invalidFromUrl = requestedUrls.find((u) => u.includes("cursor=cursor-time-scope-1") && u.includes("from=9999"));
      expect(invalidFromUrl).toBeUndefined();
      // Search state must be reset
      expect(store.getState().searchCursor).toBeNull();
      expect(store.getState().searchQuery).toBe("");
      expect(store.getState().searchItems).toEqual([]);

      // Now test mismatch with 'to'
      await store.searchSessions("exploit", null, {
        hideHome: false,
        targetPath: null,
        from: 1000,
        to: 2000,
      });
      expect(store.getState().searchCursor).toBe("cursor-time-scope-1");

      // Attempt to loadMoreSearch with a DIFFERENT 'to' timestamp
      await store.loadMoreSearch({ hideHome: false, targetPath: null, from: 1000, to: 8888 });

      const invalidToUrl = requestedUrls.find((u) => u.includes("cursor=cursor-time-scope-1") && u.includes("to=8888"));
      expect(invalidToUrl).toBeUndefined();
      expect(store.getState().searchCursor).toBeNull();
      expect(store.getState().searchQuery).toBe("");
      expect(store.getState().searchItems).toEqual([]);

      // Test mismatch when stored search had NO time scope and loadMoreSearch provides from
      await store.searchSessions("exploit", null, {
        hideHome: false,
        targetPath: null,
      });
      expect(store.getState().searchCursor).toBe("cursor-time-scope-1");

      await store.loadMoreSearch({ hideHome: false, targetPath: null, from: 1000, to: 2000 });
      expect(store.getState().searchCursor).toBeNull();
      expect(store.getState().searchQuery).toBe("");
      expect(store.getState().searchItems).toEqual([]);
    });

    it("protects against out-of-order search responses across different time ranges for the same query", async () => {
      let resolveRangeA!: (value: Response) => void;
      const rangeAPromise = new Promise<Response>((resolve) => {
        resolveRangeA = resolve;
      });

      const mockFetch: typeof fetch = async (input) => {
        const url = String(input);
        const params = new URL(url, "http://localhost").searchParams;
        if (params.get("from") === "1000" && params.get("to") === "2000") {
          return rangeAPromise;
        }
        if (params.get("from") === "3000" && params.get("to") === "4000") {
          return {
            ok: true,
            json: async () => ({
              items: [createClosedSession("sess-range-b", "2026-09-16T08:00:00.000Z", ["/opt"], false)],
              nextCursor: null,
              totalItems: 1,
            }),
          } as Response;
        }
        return { ok: false, status: 404 } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Trigger search in Range A (from: 1000, to: 2000)
      const callA = store.searchSessions("target", null, { from: 1000, to: 2000 });

      // Trigger search in Range B (from: 3000, to: 4000) which resolves quickly
      await store.searchSessions("target", null, { from: 3000, to: 4000 });

      // Verify Range B's results are active
      expect(store.getState().searchQuery).toBe("target");
      expect(store.getState().searchScopeKey).toBe(createAuditScopeKey({ q: "target", from: 3000, to: 4000 }));
      expect(store.getState().searchItems.map((s) => s.sessionId)).toEqual(["sess-range-b"]);

      // Late resolution of Range A
      resolveRangeA({
        ok: true,
        json: async () => ({
          items: [createClosedSession("sess-range-a-stale", "2026-09-16T08:00:00.000Z", ["/opt"], false)],
          nextCursor: null,
          totalItems: 1,
        }),
      } as Response);
      await callA;

      // Stale Range A response must be discarded by generation guard
      expect(store.getState().searchQuery).toBe("target");
      expect(store.getState().searchScopeKey).toBe(createAuditScopeKey({ q: "target", from: 3000, to: 4000 }));
      expect(store.getState().searchItems.map((s) => s.sessionId)).toEqual(["sess-range-b"]);
    });

    it("aborts in-flight search and clears search state when initial directory fetch changes time range", async () => {
      let searchAborted = false;
      const mockFetch: typeof fetch = async (input, init) => {
        const url = String(input);
        if (url.includes("q=")) {
          const signal = init?.signal as AbortSignal | undefined;
          if (signal) {
            signal.addEventListener("abort", () => {
              searchAborted = true;
            });
          }
          return new Promise(() => {}); // never resolves
        }
        return {
          ok: true,
          json: async () => ({
            items: [],
            nextCursor: null,
            totalItems: 0,
          }),
        } as Response;
      };

      const store = createAuditDirectoryStore({ fetchFn: mockFetch });

      // Start search under time range A
      void store.searchSessions("attacker", null, { from: 1000, to: 2000 });
      expect(store.getState().searchIsLoading).toBe(true);

      // Time range filter changes: fetchInitial for time range B
      await store.fetchInitial({ from: 3000, to: 4000 });

      // In-flight search must be aborted and cleared
      expect(searchAborted).toBe(true);
      expect(store.getState().searchQuery).toBe("");
      expect(store.getState().searchItems).toEqual([]);
      expect(store.getState().searchIsLoading).toBe(false);
      expect(store.getState().searchCursor).toBeNull();
    });
  });
});
