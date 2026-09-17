import { describe, expect, it } from "vitest";

import type { FilesystemTopologySnapshot } from "../src/lib/dashboardTypes";
import {
  calculateTelemetryAge,
  DEFAULT_STALE_THRESHOLD_MS,
  deriveLatestTelemetryAt,
  getFreshnessState,
  isSnapshot,
} from "../src/components/filesystem/filesystemUtils";

describe("Filesystem Freshness Semantics (FA-006 / FS-012)", () => {
  const baseEmptySnapshot: FilesystemTopologySnapshot = {
    nodes: [],
    sessions: [],
    recentClosedSessions: [],
    truncated: false,
    generatedAt: "2026-09-17T10:00:00.000Z",
    latestTelemetryAt: null,
  };

  describe("deriveLatestTelemetryAt", () => {
    it("returns null for null, undefined, or empty snapshot", () => {
      expect(deriveLatestTelemetryAt(null)).toBeNull();
      expect(deriveLatestTelemetryAt(undefined)).toBeNull();
      expect(deriveLatestTelemetryAt({ sessions: [], recentClosedSessions: [] })).toBeNull();
      expect(deriveLatestTelemetryAt(baseEmptySnapshot)).toBeNull();
    });

    it("extracts active session cwdState.observedAt", () => {
      const snapshot = {
        sessions: [
          {
            sessionId: "sess-1",
            cwdState: { observedAt: "2026-09-17T09:45:00.000Z" },
          },
        ],
        recentClosedSessions: [],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBe("2026-09-17T09:45:00.000Z");
    });

    it("extracts recent closed session cwdState.observedAt", () => {
      const snapshot = {
        sessions: [],
        recentClosedSessions: [
          {
            sessionId: "sess-closed-1",
            cwdState: { observedAt: "2026-09-17T09:50:00.000Z" },
            lifecycle: { closedAt: null },
          },
        ],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBe("2026-09-17T09:50:00.000Z");
    });

    it("extracts lifecycle.closedAt when it represents newer telemetry than cwdState.observedAt", () => {
      const snapshot = {
        sessions: [],
        recentClosedSessions: [
          {
            sessionId: "sess-closed-2",
            cwdState: { observedAt: "2026-09-17T09:40:00.000Z" },
            lifecycle: { closedAt: "2026-09-17T09:55:00.000Z" },
          },
        ],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBe("2026-09-17T09:55:00.000Z");
    });

    it("preserves cwdState.observedAt when it is newer than lifecycle.closedAt", () => {
      const snapshot = {
        sessions: [],
        recentClosedSessions: [
          {
            sessionId: "sess-closed-3",
            cwdState: { observedAt: "2026-09-17T09:58:00.000Z" },
            lifecycle: { closedAt: "2026-09-17T09:50:00.000Z" },
          },
        ],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBe("2026-09-17T09:58:00.000Z");
    });

    it("picks the latest timestamp across multiple active and closed sessions", () => {
      const snapshot = {
        sessions: [
          { sessionId: "sess-1", cwdState: { observedAt: "2026-09-17T09:30:00.000Z" } },
          { sessionId: "sess-2", cwdState: { observedAt: "2026-09-17T09:59:00.000Z" } },
        ],
        recentClosedSessions: [
          {
            sessionId: "sess-c1",
            cwdState: { observedAt: "2026-09-17T09:45:00.000Z" },
            lifecycle: { closedAt: "2026-09-17T09:48:00.000Z" },
          },
        ],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBe("2026-09-17T09:59:00.000Z");
    });

    it("ignores null, empty strings, and invalid date formats", () => {
      const snapshot = {
        sessions: [
          { sessionId: "sess-invalid", cwdState: { observedAt: "not-a-valid-date" } },
          { sessionId: "sess-empty", cwdState: { observedAt: "" } },
          { sessionId: "sess-null", cwdState: { observedAt: null } },
        ],
        recentClosedSessions: [
          { sessionId: "sess-c-invalid", cwdState: null, lifecycle: { closedAt: "bogus" } },
        ],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBeNull();
    });

    it("does NOT consider generatedAt as telemetry", () => {
      // Even if generatedAt is much newer, telemetryAt must only reflect session telemetry
      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:00.000Z",
        sessions: [
          {
            sessionId: "s1",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: "2026-09-17T09:00:00.000Z", status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBe("2026-09-17T09:00:00.000Z");
      expect(deriveLatestTelemetryAt(snapshot)).not.toBe("2026-09-17T12:00:00.000Z");
    });
  });

  describe("calculateTelemetryAge", () => {
    const fixedNow = Date.parse("2026-09-17T10:00:30.000Z");

    it("handles null snapshot safely", () => {
      const metrics = calculateTelemetryAge({ snapshot: null, now: fixedNow });
      expect(metrics.telemetryAt).toBeNull();
      expect(metrics.telemetryAgeMs).toBeNull();
      expect(metrics.retrievalAgeMs).toBe(0);
      expect(metrics.hasTelemetry).toBe(false);
    });

    it("uses authoritative snapshot.latestTelemetryAt when present", () => {
      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:00:20.000Z", // 10s retrieval age
        latestTelemetryAt: "2026-09-17T10:00:15.000Z", // 15s telemetry age
        sessions: [
          {
            sessionId: "s1",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: "2026-09-17T10:00:15.000Z", status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };
      const metrics = calculateTelemetryAge({ snapshot, now: fixedNow });
      expect(metrics.telemetryAt).toBe("2026-09-17T10:00:15.000Z");
      expect(metrics.telemetryAgeMs).toBe(15_000);
      expect(metrics.retrievalAgeMs).toBe(10_000);
      expect(metrics.hasTelemetry).toBe(true);
    });

    it("falls back to deriveLatestTelemetryAt if latestTelemetryAt is omitted", () => {
      const legacySnapshot: FilesystemTopologySnapshot = {
        nodes: [],
        truncated: false,
        generatedAt: "2026-09-17T10:00:20.000Z",
        recentClosedSessions: [],
        sessions: [
          {
            sessionId: "s1",
            auditSummary: { visitedPaths: ["/bin"], homeOnly: false, eventCount: 2 },
            cwdState: { path: "/bin", observedAt: "2026-09-17T10:00:10.000Z", status: "confirmed" },
            sourceIp: "10.0.0.2",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/bin"],
          },
        ],
      };
      const metrics = calculateTelemetryAge({ snapshot: legacySnapshot, now: fixedNow });
      expect(metrics.telemetryAt).toBe("2026-09-17T10:00:10.000Z");
      expect(metrics.telemetryAgeMs).toBe(20_000);
      expect(metrics.retrievalAgeMs).toBe(10_000);
      expect(metrics.hasTelemetry).toBe(true);
    });

    it("clamps future telemetry timestamps safely against client clock skew", () => {
      const futureTimestamp = "2026-09-17T10:05:00.000Z"; // 4.5 minutes in the future
      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:00:00.000Z",
        latestTelemetryAt: futureTimestamp,
        sessions: [
          {
            sessionId: "s1",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: futureTimestamp, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };
      const metrics = calculateTelemetryAge({ snapshot, now: fixedNow });
      // Clamped against now: age must be 0, not negative
      expect(metrics.telemetryAgeMs).toBe(0);
      expect(metrics.telemetryAt).toBe(futureTimestamp);
    });

    it("distinguishes empty snapshots (hasTelemetry = false) from session snapshots with missing timestamps", () => {
      const emptyMetrics = calculateTelemetryAge({ snapshot: baseEmptySnapshot, now: fixedNow });
      expect(emptyMetrics.hasTelemetry).toBe(false);
      expect(emptyMetrics.telemetryAgeMs).toBeNull();

      const snapshotWithNoTimestamps: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        sessions: [
          {
            sessionId: "s-unobserved",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: null, status: "unknown" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };
      const sessionMetrics = calculateTelemetryAge({ snapshot: snapshotWithNoTimestamps, now: fixedNow });
      expect(sessionMetrics.hasTelemetry).toBe(true);
      expect(sessionMetrics.telemetryAgeMs).toBeNull();
    });
  });

  describe("getFreshnessState Truthful Classification", () => {
    it("classifies valid empty snapshot + live transport as 'Live · No activity' (fresh, not offline)", () => {
      const state = getFreshnessState({
        telemetryAgeMs: null,
        retrievalAgeMs: 5_000,
        hasTelemetry: false,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("fresh");
      expect(state.label).toBe("Live · No activity");
      expect(state.detail).toBe("Live stream active · no session activity recorded.");
      expect(state.isDegraded).toBe(false);
      expect(state.isStale).toBe(false);
    });

    it("classifies valid empty snapshot + degraded transport as 'Degraded'", () => {
      const state = getFreshnessState({
        telemetryAgeMs: null,
        retrievalAgeMs: 8_000,
        hasTelemetry: false,
        streamState: "stale",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("degraded");
      expect(state.label).toBe("Degraded");
      expect(state.isDegraded).toBe(true);
      expect(state.detail).toContain("retained snapshot from 8s ago");
    });

    it("classifies valid empty snapshot + region error as 'Degraded'", () => {
      const state = getFreshnessState({
        telemetryAgeMs: null,
        retrievalAgeMs: 12_000,
        hasTelemetry: false,
        streamState: "live",
        regionStatus: "error",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("degraded");
      expect(state.label).toBe("Degraded");
      expect(state.isDegraded).toBe(true);
    });

    it("classifies no snapshot + connecting transport as 'Connecting'", () => {
      const state = getFreshnessState({
        telemetryAgeMs: null,
        retrievalAgeMs: 0,
        hasTelemetry: false,
        streamState: "connecting",
        regionStatus: "loading",
        hasSnapshot: false,
      });

      expect(state.classification).toBe("offline");
      expect(state.label).toBe("Connecting");
      expect(state.isDegraded).toBe(false);
      expect(state.isStale).toBe(false);
    });

    it("classifies no snapshot + failed transport as 'Offline'", () => {
      const state = getFreshnessState({
        telemetryAgeMs: null,
        retrievalAgeMs: 0,
        hasTelemetry: false,
        streamState: "stale",
        regionStatus: "error",
        hasSnapshot: false,
      });

      expect(state.classification).toBe("offline");
      expect(state.label).toBe("Offline");
      expect(state.isDegraded).toBe(true);
      expect(state.isStale).toBe(true);
    });

    it("classifies live transport + recent telemetry as 'Live & Fresh'", () => {
      const state = getFreshnessState({
        telemetryAgeMs: 12_000,
        retrievalAgeMs: 2_000,
        hasTelemetry: true,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
        staleThresholdMs: DEFAULT_STALE_THRESHOLD_MS, // 30s
      });

      expect(state.classification).toBe("fresh");
      expect(state.label).toBe("Live & Fresh");
      expect(state.detail).toContain("telemetry observed 12s ago");
      expect(state.isDegraded).toBe(false);
      expect(state.isStale).toBe(false);
    });

    it("classifies live transport + old telemetry as 'Stale'", () => {
      const state = getFreshnessState({
        telemetryAgeMs: 45_000,
        retrievalAgeMs: 1_000, // Snapshot was just fetched!
        hasTelemetry: true,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
        staleThresholdMs: DEFAULT_STALE_THRESHOLD_MS,
      });

      expect(state.classification).toBe("stale");
      expect(state.label).toBe("Stale");
      expect(state.detail).toContain("no new telemetry for 45s ago");
      expect(state.isDegraded).toBe(false);
      expect(state.isStale).toBe(true);
    });

    it("retained snapshot + disconnected transport classifies as 'Degraded'", () => {
      const state = getFreshnessState({
        telemetryAgeMs: 15_000,
        retrievalAgeMs: 10_000,
        hasTelemetry: true,
        streamState: "stale",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("degraded");
      expect(state.label).toBe("Degraded");
      expect(state.isDegraded).toBe(true);
    });

    it("provides deterministic fallback to 'Stale' when sessions exist without valid timestamps", () => {
      const state = getFreshnessState({
        telemetryAgeMs: null,
        retrievalAgeMs: 3_000,
        hasTelemetry: true,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("stale");
      expect(state.label).toBe("Stale");
      expect(state.detail).toContain("telemetry timestamps are unavailable or invalid");
      expect(state.isStale).toBe(true);
      expect(state.isDegraded).toBe(false);
    });

    it("safely normalizes negative telemetry age from clock skew to zero", () => {
      const state = getFreshnessState({
        telemetryAgeMs: -5_000,
        retrievalAgeMs: 0,
        hasTelemetry: true,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("fresh");
      expect(state.label).toBe("Live & Fresh");
      expect(state.telemetryAgeMs).toBe(0);
    });
  });

  describe("Manual Refresh Independence (FA-006 Core Fix)", () => {
    it("preserves telemetry age when a manual refresh updates retrieval time without new telemetry", () => {
      const now = Date.parse("2026-09-17T11:00:00.000Z");

      // Snapshot 1: Telemetry is 50 seconds old (stale)
      const staleTelemetryTime = "2026-09-17T10:59:10.000Z";
      const initialSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:59:20.000Z",
        latestTelemetryAt: staleTelemetryTime,
        sessions: [
          {
            sessionId: "s1",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: staleTelemetryTime, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };

      const metricsBefore = calculateTelemetryAge({ snapshot: initialSnapshot, now });
      const stateBefore = getFreshnessState({
        telemetryAgeMs: metricsBefore.telemetryAgeMs,
        retrievalAgeMs: metricsBefore.retrievalAgeMs,
        hasTelemetry: metricsBefore.hasTelemetry,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(metricsBefore.telemetryAgeMs).toBe(50_000);
      expect(stateBefore.classification).toBe("stale");
      expect(stateBefore.isStale).toBe(true);

      // User triggers refresh: Server generates snapshot at current time (now),
      // but no new telemetry occurred in the honeypot DB!
      const refreshedSnapshot: FilesystemTopologySnapshot = {
        ...initialSnapshot,
        generatedAt: new Date(now).toISOString(), // Snapshot retrieval time is now 0s old
        latestTelemetryAt: staleTelemetryTime,     // Telemetry observation time is STILL 50s old
      };

      const metricsAfter = calculateTelemetryAge({ snapshot: refreshedSnapshot, now });
      const stateAfter = getFreshnessState({
        telemetryAgeMs: metricsAfter.telemetryAgeMs,
        retrievalAgeMs: metricsAfter.retrievalAgeMs,
        hasTelemetry: metricsAfter.hasTelemetry,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      // Retrieval age is now 0s (fresh retrieval)
      expect(metricsAfter.retrievalAgeMs).toBe(0);
      // Telemetry age is STILL 50s (telemetry is NOT made falsely fresh)
      expect(metricsAfter.telemetryAgeMs).toBe(50_000);
      expect(stateAfter.classification).toBe("stale");
      expect(stateAfter.isStale).toBe(true);
      expect(stateAfter.detail).toContain("no new telemetry for 50s ago");
    });
  });

  describe("isSnapshot Validator", () => {
    it("accepts snapshots with null latestTelemetryAt", () => {
      expect(isSnapshot(baseEmptySnapshot)).toBe(true);
    });

    it("accepts snapshots with valid string latestTelemetryAt", () => {
      const withTelemetry: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        latestTelemetryAt: "2026-09-17T10:00:00.000Z",
      };
      expect(isSnapshot(withTelemetry)).toBe(true);
    });

    it("rejects snapshots with invalid latestTelemetryAt types", () => {
      const invalid = {
        ...baseEmptySnapshot,
        latestTelemetryAt: 12345,
      };
      expect(isSnapshot(invalid)).toBe(false);
    });
  });
});
