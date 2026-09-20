import { describe, expect, it } from "vitest";

import { buildAuditSnapshot } from "../src/components/filesystem/filesystemUtils";
import { getFreshnessState } from "../src/lib/filesystem-freshness";
import type {
  FilesystemClosedSession,
  SessionCwdHistoryEvent,
} from "../src/lib/dashboardTypes";

const closedSession: FilesystemClosedSession = {
  sessionId: "closed-session-1",
  sourceIp: "192.0.2.44",
  cwdState: {
    path: "/home/root/tools",
    status: "confirmed",
    observedAt: "2026-09-17T11:45:00.000Z",
    sourceEventId: "event-current",
  },
  auditSummary: {
    visitedPaths: ["/home/root", "/etc/nginx", "/var/log", "/home/root/tools"],
    homeOnly: false,
    eventCount: 4,
  },
  lifecycle: {
    startedAt: "2026-09-17T11:39:55.000Z",
    closedAt: "2026-09-17T11:46:00.000Z",
  },
};

const completeHistory: SessionCwdHistoryEvent[] = [
  {
    id: "event-entry",
    sessionId: closedSession.sessionId,
    sequence: "1",
    at: "2026-09-17T11:39:55.000Z",
    fromPath: null,
    toPath: "/home/root",
    action: "entered",
    status: "confirmed",
    sourceEventId: "source-entry",
  },
  {
    id: "event-etc",
    sessionId: closedSession.sessionId,
    sequence: "2",
    at: "2026-09-17T11:40:14.000Z",
    fromPath: "/home/root",
    toPath: "/etc/nginx",
    action: "changed",
    status: "confirmed",
    sourceEventId: "source-etc",
  },
  {
    id: "event-failed-typo",
    sessionId: closedSession.sessionId,
    sequence: "3",
    at: "2026-09-17T11:41:00.000Z",
    fromPath: "/etc/nginx",
    toPath: "/ect/ngnix",
    action: "failed_change",
    status: "conditional_candidate",
    sourceEventId: "source-failed",
  },
  {
    id: "event-var",
    sessionId: closedSession.sessionId,
    sequence: "4",
    at: "2026-09-17T11:42:00.000Z",
    fromPath: "/etc/nginx",
    toPath: "/var/log",
    action: "changed",
    status: "confirmed",
    sourceEventId: "source-var",
  },
];

describe("Filesystem Activity Phase 0 semantic baseline", () => {
  it("materializes every verified historical branch and excludes failed destination typo nodes", () => {
    const snapshot = buildAuditSnapshot(null, closedSession, completeHistory);

    expect(snapshot.nodes.map((node) => node.path)).toEqual([
      "/",
      "/etc",
      "/etc/nginx",
      "/home",
      "/home/root",
      "/home/root/tools",
      "/var",
      "/var/log",
    ]);
    expect(snapshot.nodes.find((node) => node.path === "/etc/nginx")).toMatchObject({
      parentPath: "/etc",
      depth: 2,
      sessionIds: [closedSession.sessionId],
    });
    expect(snapshot.nodes.some((node) => node.path === "/ect")).toBe(false);
    expect(snapshot.nodes.some((node) => node.path === "/ect/ngnix")).toBe(false);
  });

  it("preserves the retained lifecycle on the source model while characterizing the canvas adapter lane", () => {
    const snapshot = buildAuditSnapshot(null, closedSession, completeHistory);

    expect(closedSession.lifecycle).toEqual({
      startedAt: "2026-09-17T11:39:55.000Z",
      closedAt: "2026-09-17T11:46:00.000Z",
    });
    expect(snapshot.sessions).toHaveLength(1);
    expect(snapshot.sessions[0]).toMatchObject({
      sessionId: closedSession.sessionId,
      sourceIp: closedSession.sourceIp,
    });
    expect(snapshot.sessions[0]).not.toHaveProperty("lifecycle");
    expect(snapshot.recentClosedSessions).toEqual([]);
  });

  it("keeps transport connection and telemetry age as independent input dimensions", () => {
    const connectedWithStaleTelemetry = getFreshnessState({
      streamState: "live",
      regionStatus: "ready",
      hasSnapshot: true,
      telemetryAgeMs: 90_000,
      telemetryStatus: "valid",
      snapshotReceiptAgeMs: 2_000,
      staleThresholdMs: 30_000,
    });
    const disconnectedWithFreshTelemetry = getFreshnessState({
      streamState: "stale",
      regionStatus: "ready",
      hasSnapshot: true,
      telemetryAgeMs: 5_000,
      telemetryStatus: "valid",
      snapshotReceiptAgeMs: 2_000,
      staleThresholdMs: 30_000,
    });

    expect(connectedWithStaleTelemetry).toMatchObject({
      classification: "stale",
      isDegraded: false,
      isStale: true,
      telemetryAgeMs: 90_000,
    });
    expect(disconnectedWithFreshTelemetry).toMatchObject({
      classification: "degraded",
      isDegraded: true,
      isStale: false,
      telemetryAgeMs: 5_000,
    });
  });
});
