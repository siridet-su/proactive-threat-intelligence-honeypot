import { describe, expect, it } from "vitest";

import type {
  FilesystemTopologySession,
  SessionCwdHistoryEvent,
} from "../src/lib/dashboardTypes";
import {
  buildAuditUrlSearch,
  calculateTwoDimensionalFit,
  calculateWorldBounds,
  clampTimelineSidebarWidth,
  getDistinctSessionPaths,
  getMotionDuration,
  isHomeOnlySession,
  MAP_MAX_ZOOM,
  MAP_MIN_ZOOM,
  MAX_TIMELINE_SIDEBAR_WIDTH,
  MIN_TIMELINE_SIDEBAR_WIDTH,
  parseAuditUrlParams,
  resolveSessionSelection,
  sessionTouchesPath,
  type GraphCallout,
  type GraphNode,
} from "../src/components/filesystem/filesystemUtils";
import {
  calculateNextHistoryEventId,
  deriveActiveHopRoute,
  filterDisplayedHistory,
} from "../src/components/filesystem/useAuditReplay";
import {
  calculateKeyPanStep,
  calculateTouchPinchZoom,
  clampZoom,
} from "../src/components/filesystem/useTopologyViewport";
import { terminateCapabilityFrom } from "../src/components/filesystem/useResponseAction";

function makeSession(
  sessionId: string,
  sourceIp: string,
  visitedPaths: string[],
  homeOnly: boolean,
): FilesystemTopologySession {
  return {
    sessionId,
    sourceIp,
    targetPath: visitedPaths[visitedPaths.length - 1] ?? "/",
    observedAt: "2026-09-16T10:00:00Z",
    auditSummary: {
      visitedPaths,
      homeOnly,
      eventCount: visitedPaths.length,
    },
  };
}

describe("Automated Coverage Expansion (FS-018)", () => {
  describe("Filter Truth & Session Path Semantics", () => {
    it("evaluates isHomeOnlySession accurately from audit summary", () => {
      const homeSession = makeSession("s-1", "1.1.1.1", ["/home/cowrie", "/root"], true);
      const systemSession = makeSession("s-2", "2.2.2.2", ["/home/cowrie", "/etc/nginx"], false);

      expect(isHomeOnlySession(homeSession)).toBe(true);
      expect(isHomeOnlySession(systemSession)).toBe(false);
    });

    it("evaluates sessionTouchesPath for exact, descendant, and non-matching paths", () => {
      const session = makeSession("s-1", "1.1.1.1", ["/var/log", "/var/log/nginx/access.log"], false);

      // Exact match
      expect(sessionTouchesPath(session, "/var/log")).toBe(true);
      // Descendant path match
      expect(sessionTouchesPath(session, "/var")).toBe(true);
      // Root matches everything
      expect(sessionTouchesPath(session, "/")).toBe(true);
      // Non-matching sibling path
      expect(sessionTouchesPath(session, "/var/mail")).toBe(false);
      expect(sessionTouchesPath(session, "/etc")).toBe(false);
      // Null or empty target path
      expect(sessionTouchesPath(session, null)).toBe(true);
    });

    it("extracts and sorts distinct session paths without duplicates or empty values", () => {
      const sessions = [
        makeSession("s-1", "1.1.1.1", ["/var/log", "/etc/passwd"], false),
        makeSession("s-2", "2.2.2.2", ["/etc/passwd", "/tmp", "/var/log"], false),
      ];

      const distinct = getDistinctSessionPaths(sessions);
      expect(distinct.map((p) => p.path)).toEqual(["/etc/passwd", "/var/log", "/tmp"]);
    });

    it("resolves session selection without silent hijacking", () => {
      const active1 = makeSession("active-1", "1.1.1.1", ["/"], true);

      // Known session resolves successfully
      expect(resolveSessionSelection("active-1", null, [active1], false)).toEqual({
        sessionId: "active-1",
        expiredSessionId: null,
      });

      // Missing session in audit mode marks expiredSessionId without silent hijacking
      expect(resolveSessionSelection("expired-sess", null, [active1], true)).toEqual({
        sessionId: null,
        expiredSessionId: "expired-sess",
      });

      // Default fallback in live mode when no specific session requested
      expect(resolveSessionSelection(null, null, [active1], false)).toEqual({
        sessionId: "active-1",
        expiredSessionId: null,
      });
    });
  });

  describe("Pagination Completeness & Replay Navigation", () => {
    const mockEvents: SessionCwdHistoryEvent[] = [
      { id: "e-1", sessionId: "s", fromPath: "/", toPath: "/etc", command: "cd /etc", action: "change", status: "confirmed", at: "2026-09-16T10:00:00Z" },
      { id: "e-2", sessionId: "s", fromPath: "/etc", toPath: "/etc/nginx", command: "cd nginx", action: "change", status: "confirmed", at: "2026-09-16T10:01:00Z" },
      { id: "e-3", sessionId: "s", fromPath: "/etc/nginx", toPath: "/var", command: "cd /var", action: "change", status: "confirmed", at: "2026-09-16T10:02:00Z" },
    ];

    it("navigates sequential next and previous history events with boundary clamping", () => {
      // Step forward
      expect(calculateNextHistoryEventId(mockEvents, 0, "next")).toBe("e-2");
      expect(calculateNextHistoryEventId(mockEvents, 1, "next")).toBe("e-3");
      // Clamped at end
      expect(calculateNextHistoryEventId(mockEvents, 2, "next")).toBeNull();

      // Step backward
      expect(calculateNextHistoryEventId(mockEvents, 2, "prev")).toBe("e-2");
      expect(calculateNextHistoryEventId(mockEvents, 1, "prev")).toBe("e-1");
      // Clamped at start
      expect(calculateNextHistoryEventId(mockEvents, 0, "prev")).toBeNull();

      // Loop wraps to beginning
      expect(calculateNextHistoryEventId(mockEvents, 2, "loop")).toBe("e-1");
    });

    it("filters failed attempts conditionally without altering valid transitions", () => {
      const mixed: SessionCwdHistoryEvent[] = [
        ...mockEvents,
        { id: "e-fail", sessionId: "s", fromPath: "/var", toPath: "/secret", command: "cd /secret", action: "failed_change", status: "denied", at: "2026-09-16T10:03:00Z" },
      ];

      const withFailed = filterDisplayedHistory(mixed, true);
      expect(withFailed.length).toBe(4);

      const withoutFailed = filterDisplayedHistory(mixed, false);
      expect(withoutFailed.length).toBe(3);
      expect(withoutFailed.map((e) => e.id)).toEqual(["e-1", "e-2", "e-3"]);
    });

    it("derives active hop route accurately for transitions and failures", () => {
      const metrics = { totalItems: 3, selectedNumber: 2, indexOffset: 0 };
      const successRoute = deriveActiveHopRoute(mockEvents, 1, metrics);
      expect(successRoute).toEqual({
        eventId: "e-2",
        fromPath: "/etc",
        toPath: "/etc/nginx",
        action: "change",
        status: "confirmed",
        at: "2026-09-16T10:01:00Z",
        stepIndex: 1,
        totalSteps: 3,
        visitedPaths: ["/etc", "/etc/nginx"],
        visitedStepMap: { "/etc": 1, "/etc/nginx": 2 },
        isFailedAttempt: false,
      });

      const failureEvents: SessionCwdHistoryEvent[] = [
        {
          id: "e-fail",
          sessionId: "s",
          fromPath: "/home",
          toPath: "/root",
          command: "cd /root",
          action: "failed_change",
          status: "denied",
          at: "2026-09-16T10:04:00Z",
        },
      ];

      const failRoute = deriveActiveHopRoute(failureEvents, 0, { totalItems: 1, selectedNumber: 1, indexOffset: 0 });
      expect(failRoute?.isFailedAttempt).toBe(true);
      expect(failRoute?.fromPath).toBe("/home");
      expect(failRoute?.toPath).toBe("/home"); // Failed attempt keeps active hop anchored at fromPath
    });
  });

  describe("Empty-History Response Capabilities", () => {
    it("determines response termination capability regardless of history presence", () => {
      expect(terminateCapabilityFrom({ available: true, authorized: true, configured: true })).toBe("available");
      expect(terminateCapabilityFrom({ available: false, authorized: false })).toBe("forbidden");
      expect(terminateCapabilityFrom({ available: false, authorized: true, configured: false })).toBe("unconfigured");
      expect(terminateCapabilityFrom({ available: false, authorized: true, configured: true })).toBe("error");
      expect(terminateCapabilityFrom({})).toBe("forbidden");
    });
  });

  describe("URL Restoration & Deep-Linking", () => {
    it("round-trips URL search params without loss or corruption", () => {
      const initial = {
        view: "audit" as const,
        sessionId: "sess-abc-123",
        hideHome: true,
        targetPath: "/var/log/audit",
        hop: "evt-999",
      };

      const search = buildAuditUrlSearch(initial);
      const parsed = parseAuditUrlParams(search);

      expect(parsed.view).toBe("audit");
      expect(parsed.sessionId).toBe("sess-abc-123");
      expect(parsed.hideHome).toBe(true);
      expect(parsed.targetPath).toBe("/var/log/audit");
      expect(parsed.hop).toBe("evt-999");
    });

    it("safely falls back to live defaults on malformed or malicious query parameters", () => {
      const malformed = "?view=exploit_payload&hideHome=not_a_boolean&sessionId=&targetPath=";
      const parsed = parseAuditUrlParams(malformed);

      expect(parsed.view).toBe("live");
      expect(parsed.hideHome).toBe(false);
      expect(parsed.sessionId).toBeNull();
      expect(parsed.targetPath).toBeNull();
    });
  });

  describe("2D World Bounds & Viewport Fit", () => {
    it("includes manually positioned nodes located outside 0..100 range in 2D bounds", () => {
      const nodes: GraphNode[] = [
        { path: "/", parentPath: null, depth: 0, sessionIds: [], observedAt: null, x: 50, y: 50 },
      ];
      const callouts: GraphCallout[] = [];
      const overrideNodes = {
        "/": { x: -80, y: 250 }, // Coordinates well outside standard 0..100 space
      };

      const bounds = calculateWorldBounds(nodes, callouts, overrideNodes, {}, {}, {}, {});
      expect(bounds.minX).toBeLessThanOrEqual(-80);
      expect(bounds.maxY).toBeGreaterThanOrEqual(250);
    });

    it("calculates 2D fit viewport considering minimap clearance and surface dimensions", () => {
      const bounds = { minX: 0, maxX: 100, minY: 0, maxY: 100, width: 100, height: 100, centerX: 50, centerY: 50 };
      const fitWithMinimap = calculateTwoDimensionalFit(bounds, {
        surfaceWidth: 1200,
        surfaceHeight: 800,
        planeWidth: 860,
        planeHeight: 500,
        planeOffsetLeft: 0,
        planeOffsetTop: 0,
        hasMinimap: true,
        isMinimapCollapsed: false,
        minPadding: 24,
      });

      const fitWithoutMinimap = calculateTwoDimensionalFit(bounds, {
        surfaceWidth: 1200,
        surfaceHeight: 800,
        planeWidth: 860,
        planeHeight: 500,
        planeOffsetLeft: 0,
        planeOffsetTop: 0,
        hasMinimap: false,
        isMinimapCollapsed: true,
        minPadding: 24,
      });

      expect(fitWithMinimap.zoom).toBeGreaterThanOrEqual(MAP_MIN_ZOOM);
      expect(fitWithMinimap.zoom).toBeLessThanOrEqual(MAP_MAX_ZOOM);
      expect(fitWithoutMinimap.zoom).toBeGreaterThanOrEqual(MAP_MIN_ZOOM);
      // Viewport without minimap has slightly more horizontal clearance
      expect(fitWithoutMinimap.zoom).toBeGreaterThanOrEqual(fitWithMinimap.zoom);
    });
  });

  describe("Sidebar Sizing & Responsive Constraints", () => {
    it("clamps sidebar width within min (360) and max (760) boundaries", () => {
      expect(clampTimelineSidebarWidth(200)).toBe(MIN_TIMELINE_SIDEBAR_WIDTH);
      expect(clampTimelineSidebarWidth(9999)).toBe(MAX_TIMELINE_SIDEBAR_WIDTH);
      expect(clampTimelineSidebarWidth(500)).toBe(500);
    });

    it("clamps sidebar width to maximum 65% of viewport on narrow screens", () => {
      const narrowViewport = 800; // 65% of 800 is 520
      expect(clampTimelineSidebarWidth(650, narrowViewport)).toBe(520);
    });

    it("handles non-finite or invalid numbers safely by falling back to default", () => {
      expect(clampTimelineSidebarWidth(NaN)).toBe(420);
      expect(clampTimelineSidebarWidth(-Infinity)).toBe(420);
    });
  });

  describe("Keyboard Navigation", () => {
    it("calculates key pan steps for all four arrow keys", () => {
      const origin = { x: 100, y: 100 };
      expect(calculateKeyPanStep(origin, "ArrowLeft", 50)).toEqual({ x: 150, y: 100 });
      expect(calculateKeyPanStep(origin, "ArrowRight", 50)).toEqual({ x: 50, y: 100 });
      expect(calculateKeyPanStep(origin, "ArrowUp", 50)).toEqual({ x: 100, y: 150 });
      expect(calculateKeyPanStep(origin, "ArrowDown", 50)).toEqual({ x: 100, y: 50 });
      expect(calculateKeyPanStep(origin, "OtherKey", 50)).toEqual(origin);
    });
  });

  describe("Touch Pinch Gestures", () => {
    it("scales zoom proportionally during touch pinch and clamps within limits", () => {
      // Pinch out (distance doubles: 100px -> 200px)
      expect(calculateTouchPinchZoom(1.0, 100, 200)).toBe(2.0);
      // Pinch in (distance halves: 100px -> 50px)
      expect(calculateTouchPinchZoom(1.0, 100, 50)).toBe(0.5);
      // Clamped to max zoom (2.75)
      expect(calculateTouchPinchZoom(2.0, 100, 300)).toBe(clampZoom(6.0));
      expect(calculateTouchPinchZoom(2.0, 100, 300)).toBe(MAP_MAX_ZOOM);
      // Clamped to min zoom (0.35)
      expect(calculateTouchPinchZoom(0.5, 100, 20)).toBe(MAP_MIN_ZOOM);
    });

    it("safely handles zero or negative distance inputs", () => {
      expect(calculateTouchPinchZoom(1.5, 0, 100)).toBe(1.5);
      expect(calculateTouchPinchZoom(1.5, 100, -10)).toBe(1.5);
      expect(calculateTouchPinchZoom(1.5, NaN, 100)).toBe(1.5);
    });
  });

  describe("Reduced Motion Support", () => {
    it("suppresses animation duration when reduced motion is requested", () => {
      expect(getMotionDuration(true)).toBe(0);
      expect(getMotionDuration(true, 1.2)).toBe(0);
      expect(getMotionDuration(false, 0.55)).toBe(0.55);
    });
  });
});
