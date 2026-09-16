import { describe, expect, it } from "vitest";

import {
  buildAuditSessionsUrl,
  createAuditDirectoryStore,
  deriveAuthoritativeAuditMetrics,
  getPaginationRenderState,
  mergeAuthoritativeClosedSessions,
  mergeAuthoritativeDistinctPaths,
} from "../src/components/filesystem/useAuditDirectory";
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
        if (url.includes("summary=1")) {
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
});
