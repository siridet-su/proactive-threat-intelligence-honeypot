import { describe, expect, it, vi } from "vitest";

import type { FilesystemTopologySnapshot } from "../src/lib/dashboardTypes";
import {
  calculateTelemetryAge,
  deriveLatestTelemetryAt,
  evaluateTelemetryTrust,
  formatPageBadgeText,
  getFreshnessState,
  MAX_FUTURE_TELEMETRY_SKEW_MS,
  processSnapshotTransition,
  SnapshotIngestionCoordinator,
  TelemetryFreshnessTracker,
  type FilesystemRegionStatus,
  type SnapshotTransitionState,
  type TelemetryTrustMarker,
} from "../src/lib/filesystem-freshness";
import {
  FilesystemStreamLifecycleManager,
} from "../src/components/filesystem/filesystemStreamManager";
import {
  FilesystemRefreshLifecycleManager,
} from "../src/components/filesystem/filesystemRefreshManager";
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
            sessionId: "sess-closed-1",
            cwdState: { observedAt: "2026-09-17T09:40:00.000Z" },
            lifecycle: { closedAt: "2026-09-17T09:55:00.000Z" },
          },
        ],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBe("2026-09-17T09:55:00.000Z");
    });

    it("picks the latest timestamp across multiple active and closed sessions", () => {
      const snapshot = {
        sessions: [
          {
            sessionId: "active-1",
            cwdState: { observedAt: "2026-09-17T09:30:00.000Z" },
          },
          {
            sessionId: "active-2",
            cwdState: { observedAt: "2026-09-17T09:58:00.000Z" },
          },
        ],
        recentClosedSessions: [
          {
            sessionId: "closed-1",
            cwdState: { observedAt: "2026-09-17T09:52:00.000Z" },
            lifecycle: { closedAt: "2026-09-17T09:59:30.000Z" }, // This is the latest!
          },
        ],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBe("2026-09-17T09:59:30.000Z");
    });

    it("ignores malformed or non-string date values gracefully", () => {
      const snapshot = {
        sessions: [
          {
            sessionId: "s1",
            cwdState: { observedAt: "not-a-valid-iso-date" },
          },
          {
            sessionId: "s2",
            cwdState: { observedAt: null },
          },
          {
            sessionId: "s3",
            cwdState: null,
          },
        ],
      };
      expect(deriveLatestTelemetryAt(snapshot)).toBeNull();
    });
  });

  describe("Production processSnapshotTransition (Hook Transition Helper)", () => {
    it("accepts in-order snapshot and sets snapshot and snapshotReceivedAtMs atomically", () => {
      const initialReceivedAt = Date.parse("2026-09-17T10:00:05.000Z");
      const initialState: SnapshotTransitionState = {
        envelope: { snapshot: null, snapshotReceivedAtMs: null },
        latestSnapshotAt: 0,
      };

      const newerSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:00:00.000Z",
      };

      const result = processSnapshotTransition(initialState, newerSnapshot, initialReceivedAt);

      expect(result.accepted).toBe(true);
      expect(result.state.envelope.snapshot).toBe(newerSnapshot);
      expect(result.state.envelope.snapshotReceivedAtMs).toBe(initialReceivedAt);
      expect(result.state.latestSnapshotAt).toBe(Date.parse("2026-09-17T10:00:00.000Z"));
    });

    it("rejects out-of-order snapshot without mutating existing snapshot or snapshotReceivedAtMs", () => {
      const initialReceivedAt = Date.parse("2026-09-17T10:00:05.000Z");
      const acceptedSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:00:00.000Z",
      };

      const currentState: SnapshotTransitionState = {
        envelope: { snapshot: acceptedSnapshot, snapshotReceivedAtMs: initialReceivedAt },
        latestSnapshotAt: Date.parse("2026-09-17T10:00:00.000Z"),
      };

      // Stale out-of-order snapshot arriving later
      const staleSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T09:59:00.000Z", // older than latestSnapshotAt
      };
      const lateArrivalTime = Date.parse("2026-09-17T10:00:15.000Z");

      const result = processSnapshotTransition(currentState, staleSnapshot, lateArrivalTime);

      expect(result.accepted).toBe(false);
      // Envelope and received timestamp remain completely untouched
      expect(result.state.envelope.snapshot).toBe(acceptedSnapshot);
      expect(result.state.envelope.snapshotReceivedAtMs).toBe(initialReceivedAt);
      expect(result.state.latestSnapshotAt).toBe(Date.parse("2026-09-17T10:00:00.000Z"));
    });
  });

  describe("FilesystemStreamLifecycleManager (Stream Resilience & Stability)", () => {
    class MockEventSource {
      public url: string;
      public listeners: Record<string, EventListener[]> = {};
      public onopen: (() => void) | null = null;
      public onerror: (() => void) | null = null;
      public closed = false;

      constructor(url: string) {
        this.url = url;
      }

      addEventListener(type: string, listener: EventListener): void {
        if (!this.listeners[type]) this.listeners[type] = [];
        this.listeners[type].push(listener);
      }

      close(): void {
        this.closed = true;
      }
    }

    it("establishes single EventSource connection on connect and does not recreate on state changes", () => {
      const createdSources: MockEventSource[] = [];
      const streamStates: string[] = [];
      let hydrated = false;

      const manager = new FilesystemStreamLifecycleManager({
        createEventSource: (url) => {
          const s = new MockEventSource(url);
          createdSources.push(s);
          return s as unknown as EventSource;
        },
        onSnapshot: vi.fn(),
        onStreamState: (st) => streamStates.push(st),
        onHydrated: () => { hydrated = true; },
      });

      // Initial connect
      manager.connect();
      expect(createdSources.length).toBe(1);
      expect(manager.getConnectionCount()).toBe(1);
      expect(streamStates).toEqual(["connecting"]);

      // Connecting -> Live transition (e.g. source.onopen triggers)
      const activeSource = createdSources[0];
      activeSource.onopen?.();

      expect(hydrated).toBe(true);
      expect(streamStates).toEqual(["connecting", "live"]);
      // Crucial invariant: connecting -> live MUST NOT create a new connection or clean up
      expect(createdSources.length).toBe(1);
      expect(manager.getConnectionCount()).toBe(1);
      expect(manager.getCleanupCount()).toBe(0);
      expect(activeSource.closed).toBe(false);

      // Explicit reconnect cleanly closes prior source and opens exactly one new source
      manager.reconnect();
      expect(createdSources.length).toBe(2);
      expect(manager.getConnectionCount()).toBe(2);
      expect(manager.getCleanupCount()).toBe(1);
      expect(createdSources[0].closed).toBe(true);
      expect(createdSources[1].closed).toBe(false);

      // Disposal cleanly closes the active connection
      manager.dispose();
      expect(manager.isDisposed()).toBe(true);
      expect(createdSources[1].closed).toBe(true);
      expect(manager.getCleanupCount()).toBe(2);
    });

    it("scopes connection lifecycle by generation, ignoring callbacks from superseded connections", () => {
      const createdSources: MockEventSource[] = [];
      const streamStates: string[] = [];
      const snapshots: FilesystemTopologySnapshot[] = [];

      const manager = new FilesystemStreamLifecycleManager({
        createEventSource: (url) => {
          const s = new MockEventSource(url);
          createdSources.push(s);
          return s as unknown as EventSource;
        },
        onSnapshot: (snap) => snapshots.push(snap),
        onStreamState: (st) => streamStates.push(st),
        onHydrated: vi.fn(),
      });

      manager.connect();
      expect(manager.getCurrentGeneration()).toBe(1);
      const sourceGen1 = createdSources[0];

      // Reconnect increments generation to 2
      manager.reconnect();
      expect(manager.getCurrentGeneration()).toBe(2);
      const sourceGen2 = createdSources[1];
      expect(manager.getActiveSource()).toBe(sourceGen2 as unknown as EventSource);

      // Now stale callback from superseded generation 1 fires
      sourceGen1.onerror?.();

      // Generation 2 must remain completely intact!
      expect(manager.getActiveSource()).toBe(sourceGen2 as unknown as EventSource);
      expect(sourceGen2.closed).toBe(false);
      // streamStates should NOT have added "stale" from the old source
      expect(streamStates).toEqual(["connecting", "connecting"]);

      // Old message from superseded generation 1 is also ignored
      const oldEvent = {
        data: JSON.stringify({
          data: {
            ...baseEmptySnapshot,
            generatedAt: "2026-09-17T10:00:00.000Z",
          },
        }),
      } as MessageEvent<string>;
      sourceGen1.listeners["snapshot"]?.forEach((l) => l(oldEvent));
      expect(snapshots.length).toBe(0);

      // Valid message from current generation 2 is processed
      const currentEvent = {
        data: JSON.stringify({
          data: {
            ...baseEmptySnapshot,
            generatedAt: "2026-09-17T10:05:00.000Z",
          },
        }),
      } as MessageEvent<string>;
      sourceGen2.listeners["snapshot"]?.forEach((l) => l(currentEvent));
      expect(snapshots.length).toBe(1);
      expect(snapshots[0].generatedAt).toBe("2026-09-17T10:05:00.000Z");

      manager.dispose();
    });

    it("aborts in-flight fallback fetch when reconnected or disposed", () => {
      const createdSources: MockEventSource[] = [];
      const abortedSignals: boolean[] = [];

      let resolveFetch: ((res: Response) => void) | null = null;
      const fetchFallback = vi.fn((_url: string, init?: RequestInit) => {
        if (init?.signal) {
          init.signal.addEventListener("abort", () => {
            abortedSignals.push(true);
          });
        }
        return new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        });
      });

      const manager = new FilesystemStreamLifecycleManager({
        createEventSource: (url) => {
          const s = new MockEventSource(url);
          createdSources.push(s);
          return s as unknown as EventSource;
        },
        fetchFallback,
        onSnapshot: vi.fn(),
        onStreamState: vi.fn(),
        onHydrated: vi.fn(),
      });

      manager.connect();
      const source1 = createdSources[0];

      // Trigger error to start fallback fetch
      source1.onerror?.();
      expect(fetchFallback).toHaveBeenCalledTimes(1);

      // Reconnect immediately while fetch is in-flight
      manager.reconnect();
      expect(abortedSignals.length).toBe(1);
      expect(abortedSignals[0]).toBe(true);

      // Resolving the late fetch after abort must not throw or affect manager
      if (resolveFetch) {
        (resolveFetch as (res: Response) => void)(new Response(JSON.stringify({ data: baseEmptySnapshot })));
      }

      manager.dispose();
    });
  });

  describe("SnapshotIngestionCoordinator (Synchronous & Deterministic Acceptance)", () => {
    it("synchronously commits accepted snapshot, receivedAtMs, and trust marker atomically", () => {
      const coordinator = new SnapshotIngestionCoordinator();
      const initialTime = Date.parse("2026-09-17T10:00:00.000Z");
      const snap1: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:00:00.000Z",
      };

      const res1 = coordinator.ingest(snap1, initialTime);
      expect(res1.accepted).toBe(true);
      expect(coordinator.getState().envelope.snapshot).toBe(snap1);
      expect(coordinator.getState().envelope.snapshotReceivedAtMs).toBe(initialTime);
      expect(coordinator.getState().latestSnapshotAt).toBe(initialTime);

      // Out-of-order snapshot arrives synchronously
      const staleTime = Date.parse("2026-09-17T10:00:05.000Z");
      const snapOld: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T09:55:00.000Z",
      };
      const resOld = coordinator.ingest(snapOld, staleTime);
      expect(resOld.accepted).toBe(false);
      // State remains completely unchanged
      expect(coordinator.getState().envelope.snapshot).toBe(snap1);
      expect(coordinator.getState().envelope.snapshotReceivedAtMs).toBe(initialTime);
      expect(coordinator.getState().latestSnapshotAt).toBe(initialTime);

      // Rapid newer snapshot arrives
      const snapNewer: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T10:02:00.000Z",
      };
      const newerTime = Date.parse("2026-09-17T10:02:01.000Z");
      const resNewer = coordinator.ingest(snapNewer, newerTime);
      expect(resNewer.accepted).toBe(true);
      expect(coordinator.getState().envelope.snapshot).toBe(snapNewer);
      expect(coordinator.getState().envelope.snapshotReceivedAtMs).toBe(newerTime);
      expect(coordinator.getState().latestSnapshotAt).toBe(Date.parse("2026-09-17T10:02:00.000Z"));
    });

    it("evaluates trust marker atomically on ingestion and keeps state bounded O(1)", () => {
      const coordinator = new SnapshotIngestionCoordinator();
      const receivedAt = Date.parse("2026-09-17T12:00:00.000Z");
      const futureTime = "2026-09-17T12:00:20.000Z"; // 20s in future (> 5s tolerance)

      const skewedSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:00.000Z",
        latestTelemetryAt: futureTime,
      };

      const res = coordinator.ingest(skewedSnapshot, receivedAt);
      expect(res.accepted).toBe(true);
      expect(res.state.trustMarker).toEqual({
        telemetryAt: futureTime,
        isFutureSkew: true,
      });

      // Manual refresh with same telemetryAt preserves future_skew
      const refreshedSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:10.000Z",
        latestTelemetryAt: futureTime,
      };
      const resRefresh = coordinator.ingest(refreshedSnapshot, receivedAt + 10_000);
      expect(resRefresh.accepted).toBe(true);
      expect(resRefresh.state.trustMarker).toEqual({
        telemetryAt: futureTime,
        isFutureSkew: true,
      });

      // Valid new timestamp replaces the marker
      const validTime = "2026-09-17T12:00:12.000Z";
      const validSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:15.000Z",
        latestTelemetryAt: validTime,
      };
      const resValid = coordinator.ingest(validSnapshot, receivedAt + 15_000);
      expect(resValid.accepted).toBe(true);
      expect(resValid.state.trustMarker).toEqual({
        telemetryAt: validTime,
        isFutureSkew: false,
      });
    });
  });

  describe("Pure Freshness Calculation (Zero Mutation During Render)", () => {
    it("is strictly pure and idempotent during React render", () => {
      const now = Date.parse("2026-09-17T12:00:00.000Z");
      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:00.000Z",
        latestTelemetryAt: "2026-09-17T12:00:20.000Z",
        sessions: [
          {
            sessionId: "s1",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: "2026-09-17T12:00:20.000Z", status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };

      const trustMarker: TelemetryTrustMarker = {
        telemetryAt: "2026-09-17T12:00:20.000Z",
        isFutureSkew: true,
      };

      const snapshotCopy = JSON.parse(JSON.stringify(snapshot));
      const markerCopy = { ...trustMarker };

      const res1 = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: now,
        now,
        trustMarker,
      });

      const res2 = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: now,
        now,
        trustMarker,
      });

      expect(res1).toEqual(res2);
      expect(snapshot).toEqual(snapshotCopy);
      expect(trustMarker).toEqual(markerCopy);
    });

    it("evaluates telemetry trust purely with evaluateTelemetryTrust and TelemetryFreshnessTracker", () => {
      const now = Date.parse("2026-09-17T12:00:00.000Z");
      const futureTime = "2026-09-17T12:00:15.000Z";

      // Null / empty input
      expect(evaluateTelemetryTrust(null, null, now)).toBeNull();
      expect(evaluateTelemetryTrust(null, "", now)).toBeNull();
      expect(evaluateTelemetryTrust(null, "invalid-date", now)).toBeNull();

      // Excessive future skew
      const skewed = evaluateTelemetryTrust(null, futureTime, now, 5_000);
      expect(skewed).toEqual({
        telemetryAt: futureTime,
        isFutureSkew: true,
      });

      // Preserve trust if same timestamp
      const preserved = evaluateTelemetryTrust(skewed, futureTime, now + 10_000, 5_000);
      expect(preserved).toBe(skewed);

      // Tracker wrapper
      const tracker = new TelemetryFreshnessTracker();
      expect(tracker.getTrustMarker()).toBeNull();
      tracker.ingestObservation(futureTime, now);
      expect(tracker.isKnownSkewed(futureTime)).toBe(true);
      expect(tracker.isSkewed(futureTime)).toBe(true);
      expect(tracker.isSkewed("other-time")).toBe(false);

      tracker.clear();
      expect(tracker.getTrustMarker()).toBeNull();
      expect(tracker.isSkewed(futureTime)).toBe(false);
    });
  });

  describe("Persistent Excessive Future-Skew Timeline & Trust Invariants", () => {
    it("preserves future_skew classification across clock catch-up, timestamp arrival, stale expiry, and manual refresh", () => {
      const baseReceiptTime = Date.parse("2026-09-17T12:00:00.000Z");
      // Excessive future telemetry: 20 seconds in future (> 5s tolerance)
      const excessiveFutureTime = "2026-09-17T12:00:20.000Z";

      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:00.000Z",
        latestTelemetryAt: excessiveFutureTime,
        sessions: [
          {
            sessionId: "s-skewed",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: excessiveFutureTime, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };

      const coordinator = new SnapshotIngestionCoordinator();
      const transition1 = coordinator.ingest(snapshot, baseReceiptTime);
      expect(transition1.accepted).toBe(true);
      expect(transition1.state.trustMarker?.isFutureSkew).toBe(true);
      expect(transition1.state.trustMarker?.telemetryAt).toBe(excessiveFutureTime);

      // Stage 1: Initial receipt at t = 12:00:00 (skew is 20s > 5s tolerance)
      const metrics1 = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: baseReceiptTime,
        now: baseReceiptTime,
        trustMarker: transition1.state.trustMarker,
      });
      const state1 = getFreshnessState({
        telemetryAgeMs: metrics1.telemetryAgeMs,
        telemetryStatus: metrics1.telemetryStatus,
        snapshotReceiptAgeMs: metrics1.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(metrics1.telemetryStatus).toBe("future_skew");
      expect(metrics1.telemetryAgeMs).toBeNull();
      expect(state1.classification).toBe("stale");
      expect(state1.label).toBe("Stale");
      expect(formatPageBadgeText(state1)).toBe("Stale · Clock skew");

      // Stage 2: Before entering tolerance window at t = 12:00:10 (skew is 10s > 5s tolerance)
      const nowStage2 = Date.parse("2026-09-17T12:00:10.000Z");
      const metrics2 = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: baseReceiptTime,
        now: nowStage2,
        trustMarker: transition1.state.trustMarker,
      });
      const state2 = getFreshnessState({
        telemetryAgeMs: metrics2.telemetryAgeMs,
        telemetryStatus: metrics2.telemetryStatus,
        snapshotReceiptAgeMs: metrics2.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(metrics2.telemetryStatus).toBe("future_skew");
      expect(state2.classification).toBe("stale");
      expect(formatPageBadgeText(state2)).toBe("Stale · Clock skew");

      // Stage 3: Inside tolerance window at t = 12:00:17 (skew would be 3s <= 5s tolerance)
      // INVARIANT: Unchanged observation must NEVER become valid/fresh merely because client clock caught up!
      const nowStage3 = Date.parse("2026-09-17T12:00:17.000Z");
      const metrics3 = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: baseReceiptTime,
        now: nowStage3,
        trustMarker: transition1.state.trustMarker,
      });
      const state3 = getFreshnessState({
        telemetryAgeMs: metrics3.telemetryAgeMs,
        telemetryStatus: metrics3.telemetryStatus,
        snapshotReceiptAgeMs: metrics3.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(metrics3.telemetryStatus).toBe("future_skew");
      expect(metrics3.telemetryAgeMs).toBeNull();
      expect(state3.classification).toBe("stale");
      expect(state3.isStale).toBe(true);
      expect(formatPageBadgeText(state3)).toBe("Stale · Clock skew");

      // Stage 4: At the telemetry timestamp at t = 12:00:20 (skew is 0s)
      // INVARIANT: Unchanged observation must remain untrusted
      const nowStage4 = Date.parse("2026-09-17T12:00:20.000Z");
      const metrics4 = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: baseReceiptTime,
        now: nowStage4,
        trustMarker: transition1.state.trustMarker,
      });
      const state4 = getFreshnessState({
        telemetryAgeMs: metrics4.telemetryAgeMs,
        telemetryStatus: metrics4.telemetryStatus,
        snapshotReceiptAgeMs: metrics4.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(metrics4.telemetryStatus).toBe("future_skew");
      expect(state4.classification).toBe("stale");
      expect(formatPageBadgeText(state4)).toBe("Stale · Clock skew");

      // Stage 5: After timestamp and beyond stale threshold at t = 12:01:00 (40s past timestamp > 30s threshold)
      const nowStage5 = Date.parse("2026-09-17T12:01:00.000Z");
      const metrics5 = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: baseReceiptTime,
        now: nowStage5,
        trustMarker: transition1.state.trustMarker,
      });
      const state5 = getFreshnessState({
        telemetryAgeMs: metrics5.telemetryAgeMs,
        telemetryStatus: metrics5.telemetryStatus,
        snapshotReceiptAgeMs: metrics5.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(metrics5.telemetryStatus).toBe("future_skew");
      expect(state5.classification).toBe("stale");
      expect(formatPageBadgeText(state5)).toBe("Stale · Clock skew");

      // Stage 6: Manual refresh with the SAME latestTelemetryAt value preserves future_skew classification
      const nowStage6 = Date.parse("2026-09-17T12:01:05.000Z");
      const refreshedSameSnapshot: FilesystemTopologySnapshot = {
        ...snapshot,
        generatedAt: "2026-09-17T12:01:05.000Z", // Server generated newly
        latestTelemetryAt: excessiveFutureTime,     // Telemetry timestamp is UNCHANGED
      };
      const transition6 = coordinator.ingest(refreshedSameSnapshot, nowStage6);
      expect(transition6.accepted).toBe(true);
      expect(transition6.state.trustMarker?.isFutureSkew).toBe(true);

      const metrics6 = calculateTelemetryAge({
        snapshot: refreshedSameSnapshot,
        snapshotReceivedAtMs: nowStage6,
        now: nowStage6,
        trustMarker: transition6.state.trustMarker,
      });
      const state6 = getFreshnessState({
        telemetryAgeMs: metrics6.telemetryAgeMs,
        telemetryStatus: metrics6.telemetryStatus,
        snapshotReceiptAgeMs: metrics6.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(metrics6.telemetryStatus).toBe("future_skew");
      expect(metrics6.telemetryAgeMs).toBeNull();
      expect(state6.classification).toBe("stale");
      expect(formatPageBadgeText(state6)).toBe("Stale · Clock skew");

      // Stage 7: A genuinely different, valid telemetry timestamp recovers state to Fresh!
      const nowStage7 = Date.parse("2026-09-17T12:01:10.000Z");
      const newValidTelemetryTime = "2026-09-17T12:01:05.000Z"; // 5s ago
      const recoveredSnapshot: FilesystemTopologySnapshot = {
        ...snapshot,
        generatedAt: "2026-09-17T12:01:10.000Z",
        latestTelemetryAt: newValidTelemetryTime,
        sessions: [
          {
            sessionId: "s-new",
            auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
            cwdState: { path: "/", observedAt: newValidTelemetryTime, status: "confirmed" },
            sourceIp: "10.0.0.1",
            sourceGeo: null,
            lifecycle: { status: "active", startedAt: null, closedAt: null },
            nodeIds: ["/"],
          },
        ],
      };
      const transition7 = coordinator.ingest(recoveredSnapshot, nowStage7);
      expect(transition7.accepted).toBe(true);
      expect(transition7.state.trustMarker?.isFutureSkew).toBe(false);

      const metrics7 = calculateTelemetryAge({
        snapshot: recoveredSnapshot,
        snapshotReceivedAtMs: nowStage7,
        now: nowStage7,
        trustMarker: transition7.state.trustMarker,
      });
      const state7 = getFreshnessState({
        telemetryAgeMs: metrics7.telemetryAgeMs,
        telemetryStatus: metrics7.telemetryStatus,
        snapshotReceiptAgeMs: metrics7.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(metrics7.telemetryStatus).toBe("valid");
      expect(metrics7.telemetryAgeMs).toBe(5_000);
      expect(state7.classification).toBe("fresh");
      expect(state7.label).toBe("Live & Fresh");
      expect(state7.isStale).toBe(false);
      expect(formatPageBadgeText(state7)).toBe("Live & Fresh · 5s ago");
    });
  });

  describe("Page Badge Precedence & Truthful Labels", () => {
    it("renders Degraded · Retained snapshot when transport is degraded, regardless of telemetry status", () => {
      // Case A: Degraded transport with future-skewed telemetry
      const stateDegradedSkew = getFreshnessState({
        telemetryAgeMs: null,
        telemetryStatus: "future_skew",
        snapshotReceiptAgeMs: 5_000,
        streamState: "stale", // Stream disconnected
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(formatPageBadgeText(stateDegradedSkew)).toBe("Degraded · Retained snapshot");

      // Case B: Degraded transport with missing/invalid telemetry
      const stateDegradedInvalid = getFreshnessState({
        telemetryAgeMs: null,
        telemetryStatus: "invalid",
        snapshotReceiptAgeMs: 8_000,
        streamState: "stale",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(formatPageBadgeText(stateDegradedInvalid)).toBe("Degraded · Retained snapshot");

      // Case C: Degraded transport with valid past telemetry
      const stateDegradedValid = getFreshnessState({
        telemetryAgeMs: 12_000,
        telemetryStatus: "valid",
        snapshotReceiptAgeMs: 4_000,
        streamState: "stale",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(formatPageBadgeText(stateDegradedValid)).toBe("Degraded · Retained snapshot");
    });

    it("renders telemetry sub-statuses truthfully for live transport classified as Stale", () => {
      // Live transport with future clock skew -> Stale · Clock skew
      const stateSkew = getFreshnessState({
        telemetryAgeMs: null,
        telemetryStatus: "future_skew",
        snapshotReceiptAgeMs: 2_000,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(formatPageBadgeText(stateSkew)).toBe("Stale · Clock skew");

      // Live transport with missing timestamp -> Stale · No timestamp
      const stateNoTime = getFreshnessState({
        telemetryAgeMs: null,
        telemetryStatus: "invalid",
        snapshotReceiptAgeMs: 2_000,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(formatPageBadgeText(stateNoTime)).toBe("Stale · No timestamp");

      // Live transport with valid stale telemetry -> Stale · 45s ago
      const stateStaleValid = getFreshnessState({
        telemetryAgeMs: 45_000,
        telemetryStatus: "valid",
        snapshotReceiptAgeMs: 2_000,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(formatPageBadgeText(stateStaleValid)).toBe("Stale · 45s ago");
    });

    it("renders truthful labels for live fresh and empty snapshots", () => {
      // Live fresh with valid telemetry -> Live & Fresh · 10s ago
      const stateFresh = getFreshnessState({
        telemetryAgeMs: 10_000,
        telemetryStatus: "valid",
        snapshotReceiptAgeMs: 1_000,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(formatPageBadgeText(stateFresh)).toBe("Live & Fresh · 10s ago");

      // Live empty snapshot -> Live · No activity
      const stateEmpty = getFreshnessState({
        telemetryAgeMs: null,
        telemetryStatus: "none",
        snapshotReceiptAgeMs: 1_000,
        streamState: "live",
        regionStatus: "ready",
        hasSnapshot: true,
      });
      expect(formatPageBadgeText(stateEmpty)).toBe("Live · No activity");
    });
  });

  describe("Snapshot Receipt Age Independence & Server Build Time", () => {
    it("derives snapshot receipt age from snapshotReceivedAtMs, never generatedAt", () => {
      const now = Date.parse("2026-09-17T12:00:10.000Z");
      const clientReceivedAt = Date.parse("2026-09-17T12:00:08.000Z"); // 2s ago
      const serverGeneratedAt = "2026-09-17T11:59:00.000Z";           // 70s ago

      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: serverGeneratedAt,
      };

      const metrics = calculateTelemetryAge({
        snapshot,
        snapshotReceivedAtMs: clientReceivedAt,
        now,
      });

      // Receipt age must reflect the 2s client receipt time, NOT the 70s server generation time
      expect(metrics.snapshotReceiptAgeMs).toBe(2_000);
      expect(metrics.serverGenerationAgeMs).toBe(70_000);
    });

    it("manual refresh resets receipt age but unchanged old telemetry remains stale", () => {
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
        snapshotReceivedAtMs: now - 40_000,
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
  });

  describe("Tolerance Window Policy (Within 5s Skew)", () => {
    it("future telemetry within 5s skew tolerance normalizes to age 0 and valid status", () => {
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

  describe("FilesystemRefreshLifecycleManager & Transport Ownership Separation", () => {
    it("live SSE + retained snapshot + failed manual refresh remains live/fresh or live/stale according to telemetry, never Degraded solely because HTTP failed", async () => {
      const coordinator = new SnapshotIngestionCoordinator();
      const now = Date.parse("2026-09-17T12:00:10.000Z");
      const telemetryTime = "2026-09-17T12:00:05.000Z"; // 5s ago (fresh)
      const snapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:05.000Z",
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

      // Ingest initial snapshot
      coordinator.ingest(snapshot, now - 5_000);

      let regionStatus: FilesystemRegionStatus = "ready";
      const refreshManager = new FilesystemRefreshLifecycleManager({
        hasSnapshot: () => Boolean(coordinator.getState().envelope.snapshot),
        applySnapshot: (s) => coordinator.ingest(s, now).accepted,
        fetchSnapshot: () => Promise.reject(new Error("Network connection refused")),
        onRegionStatus: (st) => { regionStatus = st; },
      });

      // Execute failed manual refresh
      const result = await refreshManager.refresh();
      expect(result).toBe(false);
      expect(refreshManager.getRefreshStatus()).toBe("error");
      expect(refreshManager.getRefreshError()?.message).toBe("Network connection refused");

      // Invariant 1: regionStatus remains "ready" because an accepted snapshot is present
      expect(regionStatus).toBe("ready");

      // Invariant 2: SSE transport is "live", so freshness is evaluated strictly from telemetry!
      const metrics = calculateTelemetryAge({
        snapshot: coordinator.getState().envelope.snapshot,
        snapshotReceivedAtMs: coordinator.getState().envelope.snapshotReceivedAtMs,
        now,
        trustMarker: coordinator.getState().trustMarker,
      });

      const freshness = getFreshnessState({
        telemetryAgeMs: metrics.telemetryAgeMs,
        telemetryStatus: metrics.telemetryStatus,
        snapshotReceiptAgeMs: metrics.snapshotReceiptAgeMs,
        streamState: "live", // SSE stream is live
        regionStatus,
        hasSnapshot: true,
      });

      // Must be Fresh, NOT Degraded!
      expect(freshness.classification).toBe("fresh");
      expect(freshness.label).toBe("Live & Fresh");
      expect(freshness.isDegraded).toBe(false);
      expect(formatPageBadgeText(freshness)).toBe("Live & Fresh · 5s ago");

      // Case B: Same scenario but telemetry is stale (45s ago)
      const staleTelemetryTime = "2026-09-17T11:59:25.000Z";
      const staleSnapshot: FilesystemTopologySnapshot = {
        ...snapshot,
        latestTelemetryAt: staleTelemetryTime,
        sessions: [
          {
            ...snapshot.sessions![0],
            cwdState: { path: "/", observedAt: staleTelemetryTime, status: "confirmed" },
          },
        ],
      };
      coordinator.ingest(staleSnapshot, now - 5_000);

      const metricsStale = calculateTelemetryAge({
        snapshot: coordinator.getState().envelope.snapshot,
        snapshotReceivedAtMs: coordinator.getState().envelope.snapshotReceivedAtMs,
        now,
        trustMarker: coordinator.getState().trustMarker,
      });
      const freshnessStale = getFreshnessState({
        telemetryAgeMs: metricsStale.telemetryAgeMs,
        telemetryStatus: metricsStale.telemetryStatus,
        snapshotReceiptAgeMs: metricsStale.snapshotReceiptAgeMs,
        streamState: "live",
        regionStatus,
        hasSnapshot: true,
      });

      // Must be Stale (Xs ago), NEVER Degraded!
      expect(freshnessStale.classification).toBe("stale");
      expect(freshnessStale.label).toBe("Stale");
      expect(freshnessStale.isDegraded).toBe(false);
      expect(formatPageBadgeText(freshnessStale)).toBe("Stale · 45s ago");
    });

    it("refresh A pending, SSE snapshot B accepted, refresh A fails late: B remains authoritative and transport remains live", async () => {
      const coordinator = new SnapshotIngestionCoordinator();
      const timeA = Date.parse("2026-09-17T12:00:00.000Z");
      const timeB = Date.parse("2026-09-17T12:00:05.000Z");

      const snapshotA: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:00.000Z",
      };
      coordinator.ingest(snapshotA, timeA);

      let rejectRefreshA: ((err: Error) => void) | null = null;
      let regionStatus: FilesystemRegionStatus = "ready";
      const refreshManager = new FilesystemRefreshLifecycleManager({
        hasSnapshot: () => Boolean(coordinator.getState().envelope.snapshot),
        applySnapshot: (s) => coordinator.ingest(s, Date.now()).accepted,
        fetchSnapshot: () => new Promise<Response>((_, reject) => {
          rejectRefreshA = reject;
        }),
        onRegionStatus: (st) => { regionStatus = st; },
      });

      // Start refresh A
      const refreshPromise = refreshManager.refresh();
      expect(regionStatus).toBe("refreshing");

      // While refresh A is pending, SSE snapshot B arrives and is accepted!
      const snapshotB: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:05.000Z",
      };
      const sseAccepted = coordinator.ingest(snapshotB, timeB);
      expect(sseAccepted.accepted).toBe(true);
      expect(coordinator.getState().envelope.snapshot).toBe(snapshotB);
      expect(coordinator.getState().envelope.snapshotReceivedAtMs).toBe(timeB);

      // Now refresh A fails late
      rejectRefreshA!(new Error("Gateway Timeout 504"));
      const refreshResult = await refreshPromise;
      expect(refreshResult).toBe(false);

      // Snapshot B remains completely authoritative!
      expect(coordinator.getState().envelope.snapshot).toBe(snapshotB);
      expect(coordinator.getState().envelope.snapshotReceivedAtMs).toBe(timeB);
      // Region status is restored to "ready" because snapshot B exists
      expect(regionStatus).toBe("ready");

      // Freshness remains based on snapshot B and live stream
      const freshness = getFreshnessState({
        streamState: "live",
        regionStatus,
        hasSnapshot: true,
      });
      expect(freshness.classification).not.toBe("degraded");
      expect(freshness.classification).not.toBe("offline");
    });

    it("refresh A superseded by refresh B: A is aborted and cannot mutate status", async () => {
      const coordinator = new SnapshotIngestionCoordinator();
      const signals: boolean[] = [];
      let resolveRefreshB: ((res: Response) => void) | null = null;

      const refreshManager = new FilesystemRefreshLifecycleManager({
        hasSnapshot: () => Boolean(coordinator.getState().envelope.snapshot),
        applySnapshot: (s) => coordinator.ingest(s, Date.now()).accepted,
        fetchSnapshot: (_url, init) => {
          if (refreshManager.getCurrentGeneration() === 1) {
            return new Promise<Response>((_, reject) => {
              init?.signal?.addEventListener("abort", () => {
                signals.push(true);
                reject(new DOMException("The operation was aborted.", "AbortError"));
              });
            });
          }
          // Request B
          return new Promise<Response>((resolve) => {
            resolveRefreshB = resolve;
          });
        },
      });

      // Start refresh A (gen 1)
      const promiseA = refreshManager.refresh();
      expect(refreshManager.getCurrentGeneration()).toBe(1);

      // Start refresh B (gen 2) before A finishes
      const promiseB = refreshManager.refresh();
      expect(refreshManager.getCurrentGeneration()).toBe(2);

      // Refresh A must have been aborted!
      expect(signals.length).toBe(1);
      expect(signals[0]).toBe(true);

      const snapshotB: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:10.000Z",
      };
      resolveRefreshB!(new Response(JSON.stringify(snapshotB)));

      const resultB = await promiseB;
      expect(resultB).toBe(true);
      expect(refreshManager.getRefreshStatus()).toBe("idle");
      expect(coordinator.getState().envelope.snapshot).toEqual(snapshotB);

      const resultA = await promiseA;
      expect(resultA).toBe(false);
    });

    it("refresh A returns an out-of-order snapshot: snapshot and receipt timestamp remain unchanged without false degradation", async () => {
      const coordinator = new SnapshotIngestionCoordinator();
      const acceptedTime = Date.parse("2026-09-17T12:00:10.000Z");
      const currentSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T12:00:10.000Z",
      };
      coordinator.ingest(currentSnapshot, acceptedTime);

      let regionStatus = "ready";
      // Refresh returns older snapshot (out of order)
      const staleSnapshot: FilesystemTopologySnapshot = {
        ...baseEmptySnapshot,
        generatedAt: "2026-09-17T11:50:00.000Z",
      };

      const refreshManager = new FilesystemRefreshLifecycleManager({
        hasSnapshot: () => Boolean(coordinator.getState().envelope.snapshot),
        applySnapshot: (s) => coordinator.ingest(s, Date.now()).accepted,
        fetchSnapshot: () => Promise.resolve(new Response(JSON.stringify(staleSnapshot))),
        onRegionStatus: (st) => { regionStatus = st; },
      });

      const result = await refreshManager.refresh();
      expect(result).toBe(false);
      expect(refreshManager.getRefreshStatus()).toBe("idle");
      expect(refreshManager.getRefreshError()).toBeNull();

      // Current snapshot is preserved, receipt time is NOT reset
      expect(coordinator.getState().envelope.snapshot).toBe(currentSnapshot);
      expect(coordinator.getState().envelope.snapshotReceivedAtMs).toBe(acceptedTime);
      // Region status is restored to "ready" without false degradation
      expect(regionStatus).toBe("ready");
    });

    it("unmount aborts the active refresh and prevents late state updates", async () => {
      const coordinator = new SnapshotIngestionCoordinator();
      let aborted = false;
      let resolveFetch: ((res: Response) => void) | null = null;
      const regionStatusUpdates: string[] = [];

      const refreshManager = new FilesystemRefreshLifecycleManager({
        hasSnapshot: () => Boolean(coordinator.getState().envelope.snapshot),
        applySnapshot: (s) => coordinator.ingest(s, Date.now()).accepted,
        fetchSnapshot: (_url, init) => {
          init?.signal?.addEventListener("abort", () => { aborted = true; });
          return new Promise<Response>((resolve) => {
            resolveFetch = resolve;
          });
        },
        onRegionStatus: (st) => { regionStatusUpdates.push(st); },
      });

      const promise = refreshManager.refresh();
      expect(regionStatusUpdates).toEqual(["loading"]);

      // Unmount / dispose
      refreshManager.dispose();
      expect(aborted).toBe(true);
      expect(refreshManager.isDisposed()).toBe(true);

      // Late resolution after unmount
      resolveFetch!(new Response(JSON.stringify(baseEmptySnapshot)));
      const result = await promise;
      expect(result).toBe(false);

      // No new state updates dispatched
      expect(regionStatusUpdates).toEqual(["loading"]);
    });

    it("streamState=\"stale\" with retained snapshot still classifies as Degraded", () => {
      const state = getFreshnessState({
        streamState: "stale",
        regionStatus: "ready",
        hasSnapshot: true,
        snapshotReceiptAgeMs: 5_000,
        telemetryStatus: "valid",
        telemetryAgeMs: 5_000,
      });

      expect(state.classification).toBe("degraded");
      expect(state.label).toBe("Degraded");
      expect(state.isDegraded).toBe(true);
      expect(formatPageBadgeText(state)).toBe("Degraded · Retained snapshot");
    });

    it("no snapshot plus unavailable transport still classifies as Offline", () => {
      // Transport disconnected with no snapshot
      const state1 = getFreshnessState({
        streamState: "stale",
        regionStatus: "ready",
        hasSnapshot: false,
      });
      expect(state1.classification).toBe("offline");
      expect(state1.label).toBe("Offline");
      expect(state1.isDegraded).toBe(true);

      // Error region status with no snapshot
      const state2 = getFreshnessState({
        streamState: "stale",
        regionStatus: "error",
        hasSnapshot: false,
      });
      expect(state2.classification).toBe("offline");
      expect(state2.label).toBe("Offline");

      // Connecting stream state with no snapshot
      const stateConnecting = getFreshnessState({
        streamState: "connecting",
        regionStatus: "loading",
        hasSnapshot: false,
      });
      expect(stateConnecting.classification).toBe("offline");
      expect(stateConnecting.label).toBe("Connecting");
      expect(stateConnecting.isDegraded).toBe(false);
    });
  });
});
