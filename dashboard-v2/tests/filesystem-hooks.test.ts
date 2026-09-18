import { describe, expect, it } from "vitest";

import type { SessionCwdHistoryEvent } from "../src/lib/dashboardTypes";
import {
  calculateNextHistoryEventId,
  deriveActiveHopRoute,
  deriveChronologicalHistory,
  filterDisplayedHistory,
  getNextPacingMode,
  getNextPlaybackSpeed,
} from "../src/components/filesystem/useAuditReplay";
import {
  buildReplayTimeline,
  calculateHistoryTimeMetrics,
  calculateReplayPacingDelay,
  formatElapsedTime,
  formatTimeDelta,
  getHistoryWindowMetrics,
  mapReplayTimelineValueToIndex,
} from "../src/components/filesystem/filesystemUtils";

describe("useAuditReplay pure replay helpers (FS-016)", () => {
  const mockEvents: SessionCwdHistoryEvent[] = [
    {
      id: "ev-3",
      sessionId: "sess-1",
      fromPath: "/var/log",
      toPath: "/var/log/nginx",
      command: "cd nginx",
      action: "change",
      status: "confirmed",
      at: "2026-09-15T10:02:00.000Z",
    },
    {
      id: "ev-2",
      sessionId: "sess-1",
      fromPath: "/var",
      toPath: "/var/log",
      command: "cd log",
      action: "change",
      status: "confirmed",
      at: "2026-09-15T10:01:00.000Z",
    },
    {
      id: "ev-1",
      sessionId: "sess-1",
      fromPath: "/",
      toPath: "/var",
      command: "cd /var",
      action: "change",
      status: "confirmed",
      at: "2026-09-15T10:00:00.000Z",
    },
  ];

  it("reverses incoming events to chronological order", () => {
    const chronological = deriveChronologicalHistory(mockEvents);
    expect(chronological.map((e) => e.id)).toEqual(["ev-1", "ev-2", "ev-3"]);
  });

  it("filters failed attempts when showFailedAttempts is false", () => {
    const eventsWithFailure: SessionCwdHistoryEvent[] = [
      ...mockEvents,
      {
        id: "ev-fail",
        sessionId: "sess-1",
        fromPath: "/var",
        toPath: "/root",
        command: "cd /root",
        action: "failed_change",
        status: "failed",
        at: "2026-09-15T10:01:30.000Z",
      },
    ];

    const withFailures = filterDisplayedHistory(eventsWithFailure, true);
    expect(withFailures.some((e) => e.id === "ev-fail")).toBe(true);

    const withoutFailures = filterDisplayedHistory(eventsWithFailure, false);
    expect(withoutFailures.some((e) => e.id === "ev-fail")).toBe(false);
  });

  it("computes active hop route metadata accurately", () => {
    const chronological = deriveChronologicalHistory(mockEvents);
    const metrics = getHistoryWindowMetrics(chronological.length, 3, 1);
    const hop = deriveActiveHopRoute(chronological, 1, metrics);

    expect(hop).not.toBeNull();
    expect(hop?.eventId).toBe("ev-2");
    expect(hop?.fromPath).toBe("/var");
    expect(hop?.toPath).toBe("/var/log");
    expect(hop?.stepIndex).toBe(1);
    expect(hop?.totalSteps).toBe(3);
    expect(hop?.isFailedAttempt).toBe(false);
    expect(hop?.visitedPaths).toContain("/var");
    expect(hop?.visitedPaths).toContain("/var/log");
  });

  it("computes failed attempt hop route staying at fromPath", () => {
    const eventsWithFailure: SessionCwdHistoryEvent[] = [
      {
        id: "ev-fail",
        sessionId: "sess-1",
        fromPath: "/var",
        toPath: "/root",
        command: "cd /root",
        action: "failed_change",
        status: "failed",
        at: "2026-09-15T10:01:30.000Z",
      },
    ];
    const metrics = getHistoryWindowMetrics(1, 1, 0);
    const hop = deriveActiveHopRoute(eventsWithFailure, 0, metrics);

    expect(hop).not.toBeNull();
    expect(hop?.isFailedAttempt).toBe(true);
    expect(hop?.toPath).toBe("/var"); // Stayed at /var
  });

  it("navigates next and previous hops sequentially", () => {
    const chronological = deriveChronologicalHistory(mockEvents);
    // from index 1: next should be ev-3, prev should be ev-1
    expect(calculateNextHistoryEventId(chronological, 1, "next")).toBe("ev-3");
    expect(calculateNextHistoryEventId(chronological, 1, "prev")).toBe("ev-1");

    // at end (index 2): next is null, loop returns ev-1
    expect(calculateNextHistoryEventId(chronological, 2, "next")).toBeNull();
    expect(calculateNextHistoryEventId(chronological, 2, "loop")).toBe("ev-1");

    // at start (index 0): prev is null
    expect(calculateNextHistoryEventId(chronological, 0, "prev")).toBeNull();
  });

  it("toggles playback speed between 1400ms and 700ms", () => {
    expect(getNextPlaybackSpeed(1400)).toBe(700);
    expect(getNextPlaybackSpeed(700)).toBe(1400);
  });
});

describe("useTopologyViewport pure helpers (FS-016)", () => {
  it("clamps zoom within allowed MAP boundaries", async () => {
    const { clampZoom } = await import("../src/components/filesystem/useTopologyViewport");
    expect(clampZoom(0.01)).toBe(0.35); // MAP_MIN_ZOOM
    expect(clampZoom(50)).toBe(2.75); // MAP_MAX_ZOOM
    expect(clampZoom(1.23456)).toBe(1.235);
  });

  it("calculates focal pan correctly during zoom adjustments", async () => {
    const { calculateFocalPan } = await import("../src/components/filesystem/useTopologyViewport");
    const currentPan = { x: 100, y: 50 };
    // without focal point, pan is preserved
    expect(calculateFocalPan(currentPan, 1.0, 1.5)).toEqual({ x: 100, y: 50 });

    // with focal point at center (200, 150)
    const focalPoint = { x: 200, y: 150 };
    const nextPan = calculateFocalPan(currentPan, 1.0, 2.0, focalPoint);
    // x: 200 - ((200 - 100) / 1) * 2 = 200 - 200 = 0
    // y: 150 - ((150 - 50) / 1) * 2 = 150 - 200 = -50
    expect(nextPan).toEqual({ x: 0, y: -50 });
  });

  it("calculates keyboard navigation pan steps", async () => {
    const { calculateKeyPanStep } = await import("../src/components/filesystem/useTopologyViewport");
    const pan = { x: 0, y: 0 };
    expect(calculateKeyPanStep(pan, "ArrowLeft", 40)).toEqual({ x: 40, y: 0 });
    expect(calculateKeyPanStep(pan, "ArrowRight", 40)).toEqual({ x: -40, y: 0 });
    expect(calculateKeyPanStep(pan, "ArrowUp", 40)).toEqual({ x: 0, y: 40 });
    expect(calculateKeyPanStep(pan, "ArrowDown", 40)).toEqual({ x: 0, y: -40 });
  });
});

describe("useTopologyArrange pure helpers (FS-016)", () => {
  it("clamps node coordinates within NODE_WORKSPACE_LIMIT", async () => {
    const { unrestrictedNodeCoordinate } = await import("../src/components/filesystem/useTopologyArrange");
    expect(unrestrictedNodeCoordinate(500)).toBe(400);
    expect(unrestrictedNodeCoordinate(-500)).toBe(-400);
    expect(unrestrictedNodeCoordinate(120)).toBe(120);
  });

  it("calculates relative drag delta accurately", async () => {
    const { calculateRelativeDragDelta } = await import("../src/components/filesystem/useTopologyArrange");
    // moved 50px across a 1000px plane = +5%
    expect(calculateRelativeDragDelta(150, 100, 1000)).toBe(5);
    // dimensionSize 0 returns 0
    expect(calculateRelativeDragDelta(150, 100, 0)).toBe(0);
  });

  it("applies drag offset and clamps result", async () => {
    const { applyDragOffset } = await import("../src/components/filesystem/useTopologyArrange");
    const origin = { x: 50, y: 50 };
    expect(applyDragOffset(origin, 10, -20)).toEqual({ x: 60, y: 30 });
    expect(applyDragOffset(origin, 400, 0)).toEqual({ x: 400, y: 50 }); // Clamped to 400
  });
});

describe("time-based replay scrubber pure helpers (FS-019)", () => {
  const unevenEvents: SessionCwdHistoryEvent[] = [
    {
      id: "ev-1",
      sessionId: "sess-1",
      fromPath: "/",
      toPath: "/home/cowrie",
      command: "cd ~",
      action: "change",
      status: "confirmed",
      at: "2026-09-15T12:00:00.000Z",
    },
    {
      id: "ev-2",
      sessionId: "sess-1",
      fromPath: "/home/cowrie",
      toPath: "/tmp",
      command: "cd /tmp",
      action: "change",
      status: "confirmed",
      at: "2026-09-15T12:00:05.000Z",
    },
    {
      id: "ev-3",
      sessionId: "sess-1",
      fromPath: "/tmp",
      toPath: "/etc",
      command: "cd /etc",
      action: "change",
      status: "confirmed",
      at: "2026-09-15T12:30:05.000Z",
    },
  ];

  it("uses uneven elapsed positions and maps 5 seconds to the five-second hop", () => {
    const timeline = buildReplayTimeline(unevenEvents, 1, true);
    expect(timeline.scaleMode).toBe("time");
    expect(timeline.maxValue).toBe(1_805_000);
    expect(timeline.hopMetrics.map((metric) => metric.positionValue)).toEqual([0, 5_000, 1_805_000]);
    expect(timeline.hopMetrics[1].timeProgressPercent).toBeCloseTo(0.277, 2);
    expect(mapReplayTimelineValueToIndex(timeline, 5_000)).toBe(1);
  });

  it("maps mid-gap ties to the earliest chronological hop", () => {
    const timeline = buildReplayTimeline(unevenEvents, 0, true);
    expect(mapReplayTimelineValueToIndex(timeline, 905_000)).toBe(1);
    expect(mapReplayTimelineValueToIndex(timeline, 900_000)).toBe(1);
  });

  it("allows equal timestamps to share a time position while stepping remains index-based", () => {
    const events = [unevenEvents[0], { ...unevenEvents[1], at: unevenEvents[0].at }, unevenEvents[2]];
    const timeline = buildReplayTimeline(events, 1, true);
    expect(timeline.scaleMode).toBe("time");
    expect(timeline.hopMetrics[0].positionValue).toBe(timeline.hopMetrics[1].positionValue);
    expect(timeline.hopMetrics[1].positionValue).toBe(0);
    expect(mapReplayTimelineValueToIndex(timeline, 0)).toBe(0);
    expect(calculateNextHistoryEventId(events, 0, "next")).toBe(events[1].id);
  });

  it("keeps a single event on a stable zero-duration time scale", () => {
    const timeline = buildReplayTimeline([unevenEvents[0]], 0, true);
    expect(timeline.scaleMode).toBe("time");
    expect(timeline.timingStatus).toBe("single-event");
    expect(timeline.minValue).toBe(0);
    expect(timeline.maxValue).toBe(0);
    expect(timeline.value).toBe(0);
  });

  it.each([
    ["all equal", [unevenEvents[0], { ...unevenEvents[1], at: unevenEvents[0].at }, { ...unevenEvents[2], at: unevenEvents[0].at }], "all-equal", "Timing unavailable"],
    ["missing", [{ ...unevenEvents[0], at: null }, unevenEvents[1]], "missing", "Timing unavailable"],
    ["invalid", [{ ...unevenEvents[0], at: "not-a-timestamp" }, unevenEvents[1]], "invalid", "Timing unavailable"],
    ["non-monotonic", [unevenEvents[1], unevenEvents[0]], "non-monotonic", "Timing unavailable"],
  ] as const)("fails closed for %s timestamps with an explicit index fallback", (_name, events, status, label) => {
    const timeline = buildReplayTimeline(events, 0, true);
    expect(timeline.scaleMode).toBe("index");
    expect(timeline.timingStatus).toBe(status);
    expect(timeline.durationLabel).toContain(label);
    expect(timeline.maxValue).toBe(events.length - 1);
  });

  it("labels partial and complete durations without overstating loaded history", () => {
    const partial = buildReplayTimeline(unevenEvents, 1, false);
    const complete = buildReplayTimeline(unevenEvents, 1, true);
    expect(partial.durationLabel).toBe("Partial · loaded span 30m 05s");
    expect(complete.durationLabel).toBe("Complete retained duration 30m 05s");
  });

  it("recomputes the loaded origin while preserving the selected event identity", () => {
    const laterWindow = buildReplayTimeline(unevenEvents.slice(1), 0, false);
    const earlierEvent = { ...unevenEvents[0], at: "2026-09-15T11:59:50.000Z" };
    const expandedWindow = buildReplayTimeline([earlierEvent, ...unevenEvents.slice(1)], 1, false);
    expect(laterWindow.selectedEventId).toBe("ev-2");
    expect(expandedWindow.selectedEventId).toBe("ev-2");
    expect(expandedWindow.value).toBe(15_000);
  });

  it("builds a truthful scale from the filtered displayed event set", () => {
    const withFailure = [
      unevenEvents[0],
      { ...unevenEvents[1], id: "ev-failed", action: "failed_change" as const, status: "failed" },
      unevenEvents[2],
    ];
    const filtered = filterDisplayedHistory(withFailure, false);
    const timeline = buildReplayTimeline(filtered, 1, true);
    expect(filtered.map((event) => event.id)).toEqual(["ev-1", "ev-3"]);
    expect(timeline.maxValue).toBe(1_805_000);
    expect(timeline.selectedEventId).toBe("ev-3");
  });

  it("formats forensic time deltas concisely across orders of magnitude", () => {
    expect(formatTimeDelta(0)).toBe("0s");
    expect(formatTimeDelta(-100)).toBe("0s");
    expect(formatTimeDelta(NaN)).toBe("0s");
    expect(formatTimeDelta(450)).toBe("<1s");
    expect(formatTimeDelta(14000)).toBe("14s");
    expect(formatTimeDelta(125000)).toBe("2m 05s");
    expect(formatTimeDelta(3720000)).toBe("1h 02m");
    expect(formatTimeDelta(90000000)).toBe("1d 01h");
  });

  it("formats relative elapsed session time cleanly", () => {
    expect(formatElapsedTime(0)).toBe("+00:00");
    expect(formatElapsedTime(-500)).toBe("+00:00");
    expect(formatElapsedTime(NaN)).toBe("+00:00");
    expect(formatElapsedTime(15000)).toBe("+00:15");
    expect(formatElapsedTime(125000)).toBe("+02:05");
    expect(formatElapsedTime(3725000)).toBe("+01:02:05");
  });

  it("calculates history time metrics and gaps accurately without assuming uniform cadence", () => {
    const events: SessionCwdHistoryEvent[] = [
      {
        id: "ev-1",
        sessionId: "sess-1",
        fromPath: "/",
        toPath: "/home/cowrie",
        command: "cd ~",
        action: "change",
        status: "confirmed",
        at: "2026-09-15T12:00:00.000Z",
      },
      {
        id: "ev-2",
        sessionId: "sess-1",
        fromPath: "/home/cowrie",
        toPath: "/tmp",
        command: "cd /tmp",
        action: "change",
        status: "confirmed",
        at: "2026-09-15T12:00:05.000Z", // 5s burst
      },
      {
        id: "ev-3",
        sessionId: "sess-1",
        fromPath: "/tmp",
        toPath: "/etc",
        command: "cd /etc",
        action: "change",
        status: "confirmed",
        at: "2026-09-15T12:30:05.000Z", // 30m idle pause
      },
    ];

    const { hopMetrics, summary } = calculateHistoryTimeMetrics(events, 1);

    expect(hopMetrics).toHaveLength(3);

    // First hop (entry)
    expect(hopMetrics[0].deltaMs).toBe(0);
    expect(hopMetrics[0].elapsedMs).toBe(0);
    expect(hopMetrics[0].formattedDelta).toBe("0s");
    expect(hopMetrics[0].formattedElapsed).toBe("+00:00");
    expect(hopMetrics[0].timeProgressPercent).toBe(0);

    // Second hop (5s dwell)
    expect(hopMetrics[1].deltaMs).toBe(5000);
    expect(hopMetrics[1].elapsedMs).toBe(5000);
    expect(hopMetrics[1].formattedDelta).toBe("5s");
    expect(hopMetrics[1].formattedElapsed).toBe("+00:05");
    // 5s out of 1805s total is ~0.27% of session duration, not 50%!
    expect(hopMetrics[1].timeProgressPercent).toBeLessThan(1);

    // Third hop (30m dwell)
    expect(hopMetrics[2].deltaMs).toBe(1800000);
    expect(hopMetrics[2].elapsedMs).toBe(1805000);
    expect(hopMetrics[2].formattedDelta).toBe("30m 00s");
    expect(hopMetrics[2].formattedElapsed).toBe("+30:05");
    expect(hopMetrics[2].timeProgressPercent).toBe(100);

    // Summary reflects selected hop (index 1) and total session
    expect(summary.totalDurationMs).toBe(1805000);
    expect(summary.currentElapsedMs).toBe(5000);
    expect(summary.currentDeltaMs).toBe(5000);
    expect(summary.formattedCurrentElapsed).toBe("+00:05");
    expect(summary.formattedCurrentDelta).toBe("5s");
  });

  it("handles empty or invalid timestamp history gracefully", () => {
    const empty = calculateHistoryTimeMetrics([], 0);
    expect(empty.hopMetrics).toEqual([]);
    expect(empty.summary.totalDurationMs).toBe(0);

    const invalidEvents: SessionCwdHistoryEvent[] = [
      {
        id: "ev-bad",
        sessionId: "sess-1",
        fromPath: "/",
        toPath: "/tmp",
        command: "cd /tmp",
        action: "change",
        status: "confirmed",
        at: null,
      },
    ];
    const invalid = calculateHistoryTimeMetrics(invalidEvents, 0);
    expect(invalid.hopMetrics[0].deltaMs).toBe(0);
    expect(invalid.hopMetrics[0].elapsedMs).toBe(0);
    expect(invalid.summary.totalDurationMs).toBe(0);
  });

  it("calculates realistic vs uniform playback delay", () => {
    // Uniform mode always returns playbackSpeed
    expect(calculateReplayPacingDelay(500, 1400, "uniform")).toBe(1400);
    expect(calculateReplayPacingDelay(60000, 1400, "uniform")).toBe(1400);
    expect(calculateReplayPacingDelay(60000, 700, "uniform")).toBe(700);

    // Realistic mode: fast dwell (<1s) -> fast snappy transition
    const quick1x = calculateReplayPacingDelay(400, 1400, "realistic");
    expect(quick1x).toBe(600);

    // Realistic mode: 2x speed cuts delay in half
    const quick2x = calculateReplayPacingDelay(400, 700, "realistic");
    expect(quick2x).toBe(300);

    // Realistic mode: medium dwell (5s) -> noticeable hesitation
    const med1x = calculateReplayPacingDelay(5000, 1400, "realistic");
    expect(med1x).toBeGreaterThan(quick1x);
    expect(med1x).toBeLessThan(1500);

    // Realistic mode: huge pause (15m) -> clamped to reasonable max (never stalls browser)
    const long1x = calculateReplayPacingDelay(900000, 1400, "realistic");
    expect(long1x).toBeGreaterThanOrEqual(2500);
    expect(long1x).toBeLessThanOrEqual(3200);
  });

  it("toggles replay pacing mode between realistic and uniform", () => {
    expect(getNextPacingMode("realistic")).toBe("uniform");
    expect(getNextPacingMode("uniform")).toBe("realistic");
  });
});
