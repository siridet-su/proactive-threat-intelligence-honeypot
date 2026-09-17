import { describe, expect, it } from "vitest";

import type { FilesystemTopologySnapshot } from "../src/lib/dashboardTypes";
import {
  calculateTelemetryAge,
  DEFAULT_STALE_THRESHOLD_MS,
  deriveLatestTelemetryAt,
  formatUpdateAge,
  getFreshnessState,
  MAX_FUTURE_TELEMETRY_SKEW_MS,
} from "../src/lib/filesystem-freshness";
import { isSnapshot } from "../src/components/filesystem/filesystemUtils";

describe("Filesystem Freshness Semantics (FA-006 / FS-012)", () => {
  const baseEmptySnapshot: FilesystemTopologySnapshot = {
    nodes: [],
    sessions: [],
    recentClosedSessions: [],
    truncated: false,
    generatedAt: "2026-09-17T10:00:00.000Z",
    latestTelemetryAt: null,
  };

  describe("deriveLatestTelemetryAt (Neutral Lib Helper)", () => {
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

  describe("Twelve Deterministic Regression Requirements", () => {
    // 1. Snapshot generated 30s ago but received by client now -> receipt age is 0, server generation remains 30s old.
    it("1. Snapshot generated 30s ago but received now has 0s receipt age and 30s server generation age", () => {
      const now = Date.parse("2026-09-17T10:00:30.000Z");
      const clientReceivedAtMs = now; // Client received snapshot just now
      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:00:00.000Z", // Server generated 30s ago
      };

      const metrics = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: clientReceivedAtMs,
        now,
      });

      expect(metrics.snapshotReceiptAgeMs).toBe(0);
      expect(metrics.serverGenerationAgeMs).toBe(30_000);
      expect(metrics.retrievalAgeMs).toBe(0); // alias matches receipt age
    });

    // 2. Advancing client time increases receipt age from the captured receipt time.
    it("2. Advancing client time increases receipt age from the captured receipt time", () => {
      const receiptTime = Date.parse("2026-09-17T10:00:00.000Z");
      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T09:59:50.000Z",
      };

      // 10 seconds later
      const metricsAt10s = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: receiptTime,
        now: receiptTime + 10_000,
      });
      expect(metricsAt10s.snapshotReceiptAgeMs).toBe(10_000);

      // 25 seconds later
      const metricsAt25s = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: receiptTime,
        now: receiptTime + 25_000,
      });
      expect(metricsAt25s.snapshotReceiptAgeMs).toBe(25_000);
    });

    // 3. Rejected out-of-order snapshot does not reset receipt time.
    it("3. Rejected out-of-order snapshot does not reset receipt time in snapshot state transition", () => {
      let latestSnapshotAt = 0;
      let envelope = {
        snapshot: null as FilesystemTopologySnapshot | null,
        snapshotReceivedAtMs: null as number | null,
      };

      const apply = (data: FilesystemTopologySnapshot, receivedAt: number): boolean => {
        const timestamp = Date.parse(data.generatedAt) || 0;
        if (timestamp && timestamp < latestSnapshotAt) return false;
        latestSnapshotAt = Math.max(latestSnapshotAt, timestamp);
        envelope = { snapshot: data, snapshotReceivedAtMs: receivedAt };
        return true;
      };

      const initialReceivedAt = Date.parse("2026-09-17T10:00:05.000Z");
      const newerSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:00:00.000Z",
      };
      expect(apply(newerSnapshot, initialReceivedAt)).toBe(true);
      expect(envelope.snapshotReceivedAtMs).toBe(initialReceivedAt);

      // A late/stale out-of-order snapshot arrives with generatedAt in the past
      const olderSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T09:59:00.000Z",
      };
      const lateArrivalTime = Date.parse("2026-09-17T10:00:10.000Z");
      const accepted = apply(olderSnapshot, lateArrivalTime);

      expect(accepted).toBe(false);
      // Receipt timestamp must NOT be reset by the out-of-order snapshot
      expect(envelope.snapshotReceivedAtMs).toBe(initialReceivedAt);
      expect(envelope.snapshot?.generatedAt).toBe("2026-09-17T10:00:00.000Z");
    });

    // 4. Manual refresh resets receipt age but unchanged old telemetry remains stale.
    it("4. Manual refresh resets receipt age but unchanged old telemetry remains stale", () => {
      const now = Date.parse("2026-09-17T11:00:00.000Z");
      const oldTelemetryTime = "2026-09-17T10:59:00.000Z"; // 60s old (> 30s threshold)

      const initialSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:59:20.000Z",
        latestTelemetryAt: oldTelemetryTime,
        sessions: [
          {
            sessionId: "s1",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: oldTelemetryTime, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };

      const metricsBefore = calculateTelemetryAge({
        snapshot: initialSnapshot,
        snapshotReceivedAtMs: now - 40_000, // Received 40s ago
        now,
      });
      const stateBefore = getFreshnessState({
        telemetryAgeMs: metricsBefore.telemetryAgeMs,
        telemetryStatus: metricsBefore.telemetryStatus,
        snapshotReceiptAgeMs: metricsBefore.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(metricsBefore.snapshotReceiptAgeMs).toBe(40_000);
      expect(metricsBefore.telemetryAgeMs).toBe(60_000);
      expect(stateBefore.classification).toBe("stale");
      expect(stateBefore.isStale).toBe(true);

      // Manual refresh completes now: receipt age resets to 0s, but DB telemetry did not advance!
      const refreshedSnapshot: FilesystemTopologySnapshot = {
        ...initialSnapshot,
        generatedAt: new Date(now).toISOString(),
        latestTelemetryAt: oldTelemetryTime,
      };
      const metricsAfter = calculateTelemetryAge({
        snapshot: refreshedSnapshot,
        snapshotReceivedAtMs: now, // Newly received snapshot
        now,
      });
      const stateAfter = getFreshnessState({
        telemetryAgeMs: metricsAfter.telemetryAgeMs,
        telemetryStatus: metricsAfter.telemetryStatus,
        snapshotReceiptAgeMs: metricsAfter.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      // Receipt age reset to 0
      expect(metricsAfter.snapshotReceiptAgeMs).toBe(0);
      // Telemetry age remains 60s (NOT reset!)
      expect(metricsAfter.telemetryAgeMs).toBe(60_000);
      // State remains truthfully stale
      expect(stateAfter.classification).toBe("stale");
      expect(stateAfter.isStale).toBe(true);
      expect(stateAfter.detail).toContain("no new telemetry for 1m ago");
    });

    // 5. Future telemetry inside tolerance follows the documented policy.
    it("5. Future telemetry inside tolerance (<= 5s) normalizes to age 0 and valid status", () => {
      const now = Date.parse("2026-09-17T12:00:00.000Z");
      const futureTimeWithinTolerance = "2026-09-17T12:00:04.000Z"; // 4s in future (< 5s tolerance)

      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        latestTelemetryAt: futureTimeWithinTolerance,
        sessions: [
          {
            sessionId: "s-skew",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: futureTimeWithinTolerance, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };

      const metrics = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: now,
        now,
        futureSkewToleranceMs: MAX_FUTURE_TELEMETRY_SKEW_MS,
      });

      expect(metrics.telemetryStatus).toBe("valid");
      expect(metrics.telemetryAgeMs).toBe(0);

      const state = getFreshnessState({
        telemetryAgeMs: metrics.telemetryAgeMs,
        telemetryStatus: metrics.telemetryStatus,
        snapshotReceiptAgeMs: metrics.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("fresh");
      expect(state.label).toBe("Live & Fresh");
      expect(state.isStale).toBe(false);
    });

    // 6. Telemetry several minutes in the future is invalid/untrusted and never Fresh.
    it("6. Telemetry several minutes in the future is invalid/untrusted and classifies as Stale, never Fresh", () => {
      const now = Date.parse("2026-09-17T12:00:00.000Z");
      const excessiveFutureTime = "2026-09-17T12:05:00.000Z"; // 5 minutes in future

      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        latestTelemetryAt: excessiveFutureTime,
        sessions: [
          {
            sessionId: "s-bad-skew",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: excessiveFutureTime, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };

      const metrics = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: now,
        now,
        futureSkewToleranceMs: MAX_FUTURE_TELEMETRY_SKEW_MS,
      });

      expect(metrics.telemetryStatus).toBe("future_skew");
      expect(metrics.telemetryAgeMs).toBeNull(); // Untrusted: age is null

      const state = getFreshnessState({
        telemetryAgeMs: metrics.telemetryAgeMs,
        telemetryStatus: metrics.telemetryStatus,
        snapshotReceiptAgeMs: metrics.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("stale");
      expect(state.label).toBe("Stale");
      expect(state.isStale).toBe(true);
      expect(state.detail).toContain("clock skew detected");
    });

    // 7. Re-evaluating that future timestamp at multiple client times does not falsely refresh it.
    it("7. Re-evaluating excessive future timestamp at multiple client ticks never falsely makes it fresh", () => {
      const startTime = Date.parse("2026-09-17T12:00:00.000Z");
      const excessiveFutureTime = "2026-09-17T12:10:00.000Z"; // 10 minutes ahead

      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        latestTelemetryAt: excessiveFutureTime,
        sessions: [
          {
            sessionId: "s-future",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: excessiveFutureTime, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };

      // Ticks from 0s to 120s: future timestamp remains > 5s in the future
      const tickOffsets = [0, 1_000, 5_000, 30_000, 60_000, 120_000];
      for (const offset of tickOffsets) {
        const tickNow = startTime + offset;
        const metrics = calculateTelemetryAge({
          snapshot,
          snapshotReceivedAtMs: startTime,
          now: tickNow,
        });

        expect(metrics.telemetryStatus).toBe("future_skew");
        expect(metrics.telemetryAgeMs).toBeNull();

        const state = getFreshnessState({
          telemetryAgeMs: metrics.telemetryAgeMs,
          telemetryStatus: metrics.telemetryStatus,
          snapshotReceiptAgeMs: metrics.snapshotReceiptAgeMs,
          streamState: "live",
          regionStatus: "ready",
          hasSnapshot: true,
        });

        expect(state.classification).toBe("stale");
        expect(state.isStale).toBe(true);
      }
    });

    // 8. Sessions with null/invalid/future telemetry show Stale without substituting receipt age in UI display formatting.
    it("8. Sessions with null/invalid/future telemetry show Stale without substituting receipt age", () => {
      const now = Date.parse("2026-09-17T12:00:00.000Z");
      const snapshotReceivedAtMs = now - 2_000; // Snapshot arrived 2 seconds ago

      // Subcase A: Sessions exist but telemetry timestamp is null
      const stateNullTelemetry = getFreshnessState({
        telemetryAgeMs: null,
        telemetryStatus: "invalid",
        snapshotReceiptAgeMs: now - snapshotReceivedAtMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(stateNullTelemetry.classification).toBe("stale");
      expect(stateNullTelemetry.label).toBe("Stale");
      expect(stateNullTelemetry.telemetryAgeMs).toBeNull();
      // Ensure receipt age (2s) is NOT returned as telemetryAgeMs
      expect(stateNullTelemetry.telemetryAgeMs).not.toBe(2_000);

      // Subcase B: Sessions exist with excessive future clock skew
      const stateFutureSkew = getFreshnessState({
        telemetryAgeMs: null,
        telemetryStatus: "future_skew",
        snapshotReceiptAgeMs: now - snapshotReceivedAtMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(stateFutureSkew.classification).toBe("stale");
      expect(stateFutureSkew.label).toBe("Stale");
      expect(stateFutureSkew.telemetryAgeMs).toBeNull();
      expect(stateFutureSkew.telemetryAgeMs).not.toBe(2_000);
    });

    // 9. Empty valid snapshot remains Live · No activity.
    it("9. Empty valid snapshot remains Live · No activity (fresh, not offline or stale)", () => {
      const state = getFreshnessState({
        telemetryAgeMs: null,
        telemetryStatus: "none",
        snapshotReceiptAgeMs: 4_000,
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

    // 10. Degraded empty snapshot remains Degraded and may report explicitly labelled snapshot receipt age.
    it("10. Degraded empty snapshot remains Degraded and explicitly reports snapshot receipt age", () => {
      const state = getFreshnessState({
        telemetryAgeMs: null,
        telemetryStatus: "none",
        snapshotReceiptAgeMs: 14_000,
        hasTelemetry: false,
        streamState: "stale", // Stream disconnected
        regionStatus: "ready",
        hasSnapshot: true,
      });

      expect(state.classification).toBe("degraded");
      expect(state.label).toBe("Degraded");
      expect(state.isDegraded).toBe(true);
      expect(state.detail).toContain("retained snapshot from 14s ago");
    });

    // 11. New valid telemetry after recovery becomes Fresh.
    it("11. New valid telemetry after recovery transitions truthfully to Fresh", () => {
      const now = Date.parse("2026-09-17T13:00:00.000Z");
      const freshTelemetryTime = "2026-09-17T12:59:55.000Z"; // 5s ago

      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        latestTelemetryAt: freshTelemetryTime,
        sessions: [
          {
            sessionId: "s-recovered",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: freshTelemetryTime, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };

      const metrics = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: now - 1_000, // 1s receipt age
        now,
      });

      const state = getFreshnessState({
        telemetryAgeMs: metrics.telemetryAgeMs,
        telemetryStatus: metrics.telemetryStatus,
        snapshotReceiptAgeMs: metrics.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
        staleThresholdMs: DEFAULT_STALE_THRESHOLD_MS,
      });

      expect(metrics.telemetryStatus).toBe("valid");
      expect(metrics.telemetryAgeMs).toBe(5_000);
      expect(state.classification).toBe("fresh");
      expect(state.label).toBe("Live & Fresh");
      expect(state.isDegraded).toBe(false);
      expect(state.isStale).toBe(false);
      expect(state.detail).toContain("telemetry observed 5s ago");
    });

    // 12. Page and TopologyCanvas use the same classification and display-age semantics.
    it("12. Page badge and TopologyCanvas consume the exact same authoritative FreshnessState", () => {
      const now = Date.parse("2026-09-17T14:00:00.000Z");
      const telemetryTime = "2026-09-17T13:59:40.000Z"; // 20s ago

      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        latestTelemetryAt: telemetryTime,
        sessions: [
          {
            sessionId: "s1",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: telemetryTime, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };

      const metrics = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: now - 3_000, // 3s receipt age
        now,
      });

      const state = getFreshnessState({
        telemetryAgeMs: metrics.telemetryAgeMs,
        telemetryStatus: metrics.telemetryStatus,
        snapshotReceiptAgeMs: metrics.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });

      // Page Badge formatting logic simulation
      const pageBadgeDisplay = state.telemetryStatus === "valid" && state.telemetryAgeMs !== null
        ? `${state.label} · ${formatUpdateAge(state.telemetryAgeMs)}`
        : state.label;

      // Topology Canvas footer formatting logic simulation
      const canvasFooterDisplay = state.isStale
        ? `Stale (telemetry ${formatUpdateAge(state.telemetryAgeMs ?? 0)})`
        : `Telemetry ${formatUpdateAge(state.telemetryAgeMs ?? 0)}`;

      expect(pageBadgeDisplay).toBe("Live & Fresh · 20s ago");
      expect(canvasFooterDisplay).toBe("Telemetry 20s ago");
      expect(state.snapshotReceiptAgeMs).toBe(3_000);
      expect(state.telemetryAgeMs).toBe(20_000);
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
