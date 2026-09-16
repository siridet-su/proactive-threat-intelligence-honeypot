import { describe, expect, it } from "vitest";

import {
  deriveAuthoritativeAuditMetrics,
  mergeAuthoritativeClosedSessions,
} from "../src/components/filesystem/useAuditDirectory";
import type {
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

describe("FA-001: Authoritative Audit Directory filtering, totals, and path options", () => {
  // Setup fixture with 1 active session and 25 closed sessions (> 12 closed sessions)
  const activeSession = createActiveSession("active-01", "/etc", ["/etc", "/home/user"], false);

  // 12 recent closed sessions (present in the live snapshot buffer)
  const snapshotRecentClosedSessions: FilesystemClosedSession[] = Array.from({ length: 12 }, (_, i) => {
    const num = i + 1;
    const isHome = num % 3 === 0;
    const visited = isHome ? ["/home/user"] : ["/var/log", `/tmp/run-${num}`];
    const minute = String(50 - num).padStart(2, "0");
    return createClosedSession(`closed-${num}`, `2026-09-16T07:${minute}:00.000Z`, visited, isHome);
  });

  // Older closed sessions (13 to 25) that are retained in MongoDB but outside the 12-item snapshot buffer
  const olderAuditSessions: FilesystemClosedSession[] = [
    createClosedSession("closed-13", "2026-09-16T06:30:00.000Z", ["/var/log", "/usr/bin"], false),
    createClosedSession("closed-14", "2026-09-16T06:25:00.000Z", ["/home/test"], true),
    createClosedSession("closed-15", "2026-09-16T06:20:00.000Z", ["/etc/nginx", "/var/www"], false),
    createClosedSession("closed-16", "2026-09-16T06:15:00.000Z", ["/tmp/payload"], false),
    createClosedSession("closed-17", "2026-09-16T06:10:00.000Z", ["/home/attacker"], true),
    createClosedSession("closed-18", "2026-09-16T06:05:00.000Z", ["/etc/pam.d"], false),
    createClosedSession("closed-19", "2026-09-16T06:00:00.000Z", ["/var/spool/mail"], false),
    // Session 20: specifically touches /opt/persistence/cron and /etc/crontab
    createClosedSession("closed-20", "2026-09-16T05:55:00.000Z", ["/opt/persistence/cron", "/etc/crontab"], false),
    createClosedSession("closed-21", "2026-09-16T05:50:00.000Z", ["/home/ftp"], true),
    // Session 22: specifically touches /root/.ssh
    createClosedSession("closed-22", "2026-09-16T05:45:00.000Z", ["/root/.ssh", "/etc/ssh"], false),
    createClosedSession("closed-23", "2026-09-16T05:40:00.000Z", ["/var/backups"], false),
    createClosedSession("closed-24", "2026-09-16T05:35:00.000Z", ["/home/service"], true),
    createClosedSession("closed-25", "2026-09-16T05:30:00.000Z", ["/tmp/scratch"], false),
  ];

  const all25ClosedSessions = [...snapshotRecentClosedSessions, ...olderAuditSessions];

  describe("Live Mode Topology Preservation", () => {
    it("strictly bounds effective closed sessions to the snapshot buffer (12 items) in live mode", () => {
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "live",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 25,
        hideHomeOnly: false,
        targetPathFilter: null,
        selectedSessionId: null,
      });

      // In live mode, effective closed sessions must equal snapshotRecentClosedSessions (12 items)
      expect(metrics.effectiveClosedSessions.length).toBe(12);
      expect(metrics.totalSessionsCount).toBe(13); // 1 active + 12 buffer

      // Paths that were visited ONLY by sessions #13-#25 must NOT appear in live mode distinct paths
      const distinctPathStrings = metrics.distinctPaths.map((p) => p.path);
      expect(distinctPathStrings).not.toContain("/opt/persistence/cron");
      expect(distinctPathStrings).not.toContain("/root/.ssh");
      expect(distinctPathStrings).not.toContain("/etc/nginx");
    });
  });

  describe("Audit Mode Authoritative Metrics with > 12 Sessions", () => {
    it("includes the complete retained closed-session directory (> 12) in audit mode", () => {
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 25,
        hideHomeOnly: false,
        targetPathFilter: null,
        selectedSessionId: null,
      });

      // In audit mode, all 25 closed sessions must be included
      expect(metrics.effectiveClosedSessions.length).toBe(25);
      expect(metrics.totalSessionsCount).toBe(26); // 1 active + 25 closed
      expect(metrics.filteredSessionsCount).toBe(26);

      // Paths visited only by sessions > 12 must now be included in distinctPaths
      const distinctPathStrings = metrics.distinctPaths.map((p) => p.path);
      expect(distinctPathStrings).toContain("/opt/persistence/cron");
      expect(distinctPathStrings).toContain("/root/.ssh");
      expect(distinctPathStrings).toContain("/etc/nginx");
      expect(distinctPathStrings).toContain("/etc/crontab");

      // Verify accurate session count aggregation
      const optPath = metrics.distinctPaths.find((p) => p.path === "/opt/persistence/cron");
      expect(optPath?.sessionCount).toBe(1);

      const etcPath = metrics.distinctPaths.find((p) => p.path === "/etc");
      // activeSession visited /etc
      expect(etcPath?.sessionCount).toBe(1);
    });

    it("evaluates path filters against the complete audit directory, avoiding false 0/12 counts", () => {
      // Filter for /opt/persistence/cron, which only session 20 visited
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 25,
        hideHomeOnly: false,
        targetPathFilter: "/opt/persistence/cron",
        selectedSessionId: null,
      });

      // active-01 did not touch /opt/persistence/cron
      expect(metrics.filteredActiveSessions.length).toBe(0);

      // closed-20 touched /opt/persistence/cron
      expect(metrics.filteredClosedSessions.length).toBe(1);
      expect(metrics.filteredClosedSessions[0].sessionId).toBe("closed-20");

      // Filtered count must be 1 out of 26 total sessions, NOT 0/12
      expect(metrics.filteredSessionsCount).toBe(1);
      expect(metrics.totalSessionsCount).toBe(26);
    });

    it("correctly produces 0/N where N is the full directory count when no session matches", () => {
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 25,
        hideHomeOnly: false,
        targetPathFilter: "/non/existent/path",
        selectedSessionId: null,
      });

      expect(metrics.filteredSessionsCount).toBe(0);
      expect(metrics.totalSessionsCount).toBe(26); // Truthfully 0/26, not 0/12
      expect(metrics.filteredActiveSessions.length).toBe(0);
      expect(metrics.filteredClosedSessions.length).toBe(0);
    });

    it("truthfully accounts for total sessions when auditDirectoryTotalCount exceeds in-memory buffer", () => {
      // Suppose server reports 100 closed sessions in database, but only 25 are currently loaded into memory
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 100,
        hideHomeOnly: false,
        targetPathFilter: null,
        selectedSessionId: null,
      });

      // Total count must be 1 active + 100 directory sessions = 101
      expect(metrics.totalSessionsCount).toBe(101);
      // Filtered count is the number of loaded matching items
      expect(metrics.filteredSessionsCount).toBe(26);
    });

    it("correctly counts and filters home-only sessions across the full directory", () => {
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 25,
        hideHomeOnly: true,
        targetPathFilter: null,
        selectedSessionId: null,
      });

      // Active session is not home-only
      expect(metrics.filteredActiveSessions.length).toBe(1);

      // Verify no home-only sessions are in filteredClosedSessions
      for (const s of metrics.filteredClosedSessions) {
        expect(s.auditSummary.homeOnly).toBe(false);
      }

      // Total sessions count remains 26
      expect(metrics.totalSessionsCount).toBe(26);
      expect(metrics.homeOnlyCount).toBeGreaterThan(0);
      expect(metrics.filteredSessionsCount).toBe(26 - metrics.homeOnlyCount);
    });
  });

  describe("Selected and Pinned Session Semantics Consistency", () => {
    it("identifies a matching session as NOT pinned outside filter", () => {
      // closed-20 visited /opt/persistence/cron
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 25,
        hideHomeOnly: false,
        targetPathFilter: "/opt/persistence/cron",
        selectedSessionId: "closed-20",
      });

      expect(metrics.isSelectedFilteredOut).toBe(false);
    });

    it("flags an older session (> 12) as pinned outside filter when it does not match active path filter", () => {
      // closed-22 did NOT visit /opt/persistence/cron
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 25,
        hideHomeOnly: false,
        targetPathFilter: "/opt/persistence/cron",
        selectedSessionId: "closed-22",
      });

      expect(metrics.isSelectedFilteredOut).toBe(true);
    });

    it("flags a home-only session as pinned outside filter when hideHomeOnly is enabled", () => {
      // closed-14 is home-only
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 25,
        hideHomeOnly: true,
        targetPathFilter: null,
        selectedSessionId: "closed-14",
      });

      expect(metrics.isSelectedFilteredOut).toBe(true);
    });

    it("does not flag a non-home session when hideHomeOnly is enabled", () => {
      // closed-22 is not home-only
      const metrics = deriveAuthoritativeAuditMetrics({
        viewMode: "audit",
        activeSessions: [activeSession],
        authoritativeClosedSessions: all25ClosedSessions,
        snapshotRecentClosedSessions,
        auditDirectoryTotalCount: 25,
        hideHomeOnly: true,
        targetPathFilter: null,
        selectedSessionId: "closed-22",
      });

      expect(metrics.isSelectedFilteredOut).toBe(false);
    });
  });

  describe("mergeAuthoritativeClosedSessions", () => {
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

    it("promotes remote pages from Map or Array without mutating original collections", () => {
      const map = new Map<string, FilesystemClosedSession>([
        ["s1", createClosedSession("s1", "2026-09-16T01:00:00.000Z", ["/tmp"], false)],
      ]);

      const merged = mergeAuthoritativeClosedSessions([], map);
      expect(merged.length).toBe(1);
      expect(merged[0].sessionId).toBe("s1");
    });
  });
});
