"use client";

import { AnimatePresence, motion, useReducedMotion, type Transition } from "framer-motion";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  Folder,
  FolderOpen,
  HardDrive,
  Move,
  RotateCcw,
  Route,
  ScanLine,
  ShieldAlert,
  Undo2,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
} from "@/lib/dashboardTypes";
import { TopologyToolbar } from "./TopologyToolbar";
import { TopologySummaryBar } from "./TopologySummaryBar";
import { TopologyMinimap } from "./TopologyMinimap";
import {
  TransitionLegend,
  TransitionOverlay,
  type TransitionDisplayMode,
} from "./TransitionOverlay";
import type { VerifiedCwdTransition } from "./filesystemTransitions";
import {
  deriveMinimapVisibility,
  deriveTransitionEndpointCoverage,
  requiredTransitionEndpointPaths,
  topologyExceedsMinimapDensityThreshold,
  type MinimapVisibilityPreference,
} from "./topologyDensity";
import {
  analyzeTopologyDensity,
  calloutsForGraph,
  classifyRuleBasedPathInterest,
  clearAutomaticCalloutCollisions,
  compactDirectoryPath,
  DEFAULT_DENSITY_THRESHOLDS,
  deriveActiveHopCanvasSemantics,
  directorySegment,
  estimateExpandedCalloutDisclosureHeight,
  formatUpdateAge,
  formatFailedChangeMessage,
  formatRuleBasedPathInterestDescription,
  GRAPH_CALLOUT_LIMIT,
  GRAPH_NODE_LIMIT,
  leaderEndpoints,
  pointForGraph,
  resolveCalloutPositions,
  sourceRailPositions,
  type ActiveHopRoute,
  type FreshnessState,
  type GraphCallout,
  type GraphElementBounds,
  type LabelPosition,
  type Pan,
  type StreamState,
  type TopologyDensityMode,
  type TopologyDensityPreference,
} from "./filesystemUtils";
import { useTopologyViewport } from "./useTopologyViewport";
import { useTopologyArrange } from "./useTopologyArrange";
import { getLayoutStorageKeys } from "./layoutPersistence";
import { TopologyCanvasHeader } from "./TopologyCanvasHeader";

const TOPOLOGY_TRANSITION: Transition = { duration: 0.55, ease: [0.22, 1, 0.36, 1] };
// Fixed SVG viewBox units; this does not represent physical distance or filesystem scale.
const LIVE_RADAR_CANVAS_SIZE = 1000;

function sameElementBounds(
  left: Record<string, GraphElementBounds>,
  right: Record<string, GraphElementBounds>,
) {
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  return leftKeys.length === rightKeys.length && leftKeys.every((key) => {
    const next = right[key];
    const current = left[key];
    return next && current &&
      Math.abs(next.x - current.x) < 0.01 &&
      Math.abs(next.y - current.y) < 0.01 &&
      Math.abs(next.width - current.width) < 0.01 &&
      Math.abs(next.height - current.height) < 0.01 &&
      Math.abs((next.anchorOffsetX ?? 0) - (current.anchorOffsetX ?? 0)) < 0.01 &&
      Math.abs((next.anchorOffsetY ?? 0) - (current.anchorOffsetY ?? 0)) < 0.01;
  });
}

type LiveTopologyStandbyMode = "loading" | "listening" | "reconnecting";

function LiveRadarOverlay({
  showGrid = true,
  reducedMotion = false,
}: {
  showGrid?: boolean;
  reducedMotion?: boolean;
}) {
  const sweepGradientId = `live-radar-sweep-${useId().replace(/:/g, "")}`;
  const radarOverlayRef = useRef<HTMLDivElement>(null);
  const [radarViewportSize, setRadarViewportSize] = useState({
    width: LIVE_RADAR_CANVAS_SIZE,
    height: LIVE_RADAR_CANVAS_SIZE,
  });

  useLayoutEffect(() => {
    const overlay = radarOverlayRef.current;
    if (!overlay) return;

    const updateViewportSize = () => {
      const bounds = overlay.getBoundingClientRect();
      const width = Math.round(bounds.width);
      const height = Math.round(bounds.height);
      if (width <= 0 || height <= 0) return;

      setRadarViewportSize((current) =>
        current.width === width && current.height === height
          ? current
          : { width, height },
      );
    };

    updateViewportSize();
    const observer = new ResizeObserver(updateViewportSize);
    observer.observe(overlay);
    return () => observer.disconnect();
  }, []);

  const sweepCenterX = radarViewportSize.width / 2;
  const sweepCenterY = radarViewportSize.height / 2;
  const sweepRadius = Math.hypot(radarViewportSize.width, radarViewportSize.height) / 2 + 12;
  const beamEndX = sweepCenterX;
  const beamEndY = sweepCenterY - sweepRadius;
  const trailingEdgeAngle = (-138 * Math.PI) / 180;
  const trailEndX = sweepCenterX + Math.cos(trailingEdgeAngle) * sweepRadius;
  const trailEndY = sweepCenterY + Math.sin(trailingEdgeAngle) * sweepRadius;

  return (
    <div
      ref={radarOverlayRef}
      className="pointer-events-none absolute inset-0 overflow-hidden"
      data-testid="live-radar-overlay"
      data-radar-canvas-size={`${LIVE_RADAR_CANVAS_SIZE}x${LIVE_RADAR_CANVAS_SIZE}`}
      aria-hidden="true"
    >
      {showGrid && <div className="pti-live-radar-grid absolute inset-0" />}
      <svg
        className="absolute inset-0 h-full w-full"
        viewBox={`0 0 ${LIVE_RADAR_CANVAS_SIZE} ${LIVE_RADAR_CANVAS_SIZE}`}
        preserveAspectRatio="xMidYMid meet"
      >
        <rect className="pti-live-radar-range is-outer" x="38" y="38" width="924" height="924" />
        <rect className="pti-live-radar-range" x="168" y="168" width="664" height="664" />
        <rect className="pti-live-radar-range" x="298" y="298" width="404" height="404" />
        <rect className="pti-live-radar-range is-inner" x="428" y="428" width="144" height="144" />
        <path className="pti-live-radar-axis" d="M500 38V962 M38 500H962" />
        <rect className="pti-live-radar-origin" x="486" y="486" width="28" height="28" />
      </svg>

      {!reducedMotion && (
        <svg
          className="absolute inset-0 h-full w-full"
          viewBox={`0 0 ${radarViewportSize.width} ${radarViewportSize.height}`}
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          <defs>
            <linearGradient
              id={sweepGradientId}
              x1={trailEndX}
              y1={trailEndY}
              x2={beamEndX}
              y2={beamEndY}
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0%" stopColor="var(--pti-radar-accent)" stopOpacity="0" />
              <stop offset="58%" stopColor="var(--pti-radar-accent)" stopOpacity="0.04" />
              <stop offset="100%" stopColor="var(--pti-radar-accent)" stopOpacity="0.48" />
            </linearGradient>
          </defs>
          <g className="pti-live-radar-sweep-rotation">
            <path
              className="pti-live-radar-sweep-wedge"
              d={`M ${sweepCenterX} ${sweepCenterY} L ${beamEndX} ${beamEndY} A ${sweepRadius} ${sweepRadius} 0 0 0 ${trailEndX} ${trailEndY} Z`}
              fill={`url(#${sweepGradientId})`}
            />
            <path
              className="pti-live-radar-sweep-beam"
              d={`M ${sweepCenterX} ${sweepCenterY} L ${beamEndX} ${beamEndY}`}
            />
          </g>
        </svg>
      )}

      <span className="pti-live-radar-edge-tick is-top" />
      <span className="pti-live-radar-edge-tick is-right" />
      <span className="pti-live-radar-edge-tick is-bottom" />
      <span className="pti-live-radar-edge-tick is-left" />

      <div className="pti-live-radar-readout absolute left-4 top-4 sm:left-5 sm:top-5">
        <span>LIVE SENSOR</span>
        <span className="opacity-60">CWD TELEMETRY</span>
      </div>
      <div className="pti-live-radar-readout absolute bottom-4 left-4 sm:bottom-5 sm:left-5">
        <span>RADAR PLANE</span>
        <span className="opacity-60">{LIVE_RADAR_CANVAS_SIZE} × {LIVE_RADAR_CANVAS_SIZE}</span>
      </div>
    </div>
  );
}

function LiveTopologyStandby({
  mode,
  closedSessionCount,
  onOpenRetainedSessions,
  onReconnect,
  reducedMotion,
}: {
  mode: LiveTopologyStandbyMode;
  closedSessionCount: number;
  onOpenRetainedSessions?: () => void;
  onReconnect?: () => void;
  reducedMotion: boolean;
}) {
  const isListening = mode === "listening";
  const isReconnecting = mode === "reconnecting";
  const retainedLabel = closedSessionCount === 1 ? "View 1 retained session" : `View ${closedSessionCount} retained sessions`;
  const title =
    mode === "loading"
      ? "Opening live topology"
      : isListening
        ? "Listening for sessions"
        : "Restoring live stream";
  const status =
    mode === "loading"
      ? "Snapshot + SSE connecting"
      : isListening
        ? "SSE connected"
        : "Last snapshot preserved";

  return (
    <section
      className="pti-live-radar relative isolate flex min-h-[25rem] flex-1 items-center justify-center overflow-hidden rounded-xl border border-border px-5 py-10 sm:px-8"
      aria-label="Live honeypot activity"
    >
      <LiveRadarOverlay reducedMotion={reducedMotion} />
      <div className="pti-live-radar-status relative z-10 mx-auto flex max-w-lg flex-col items-center px-6 py-5 text-center sm:px-8">
        <div className={`pti-live-radar-hub is-${mode} relative mb-5 grid h-16 w-16 place-items-center`} aria-hidden="true">
          <HardDrive className="h-6 w-6" />
        </div>

        <div role="status" aria-live="polite">
          <h3 className="text-lg font-semibold text-text">{title}</h3>
          <p className={`pti-live-radar-status-line is-${mode} mt-2 flex items-center justify-center gap-2 text-sm`}>
            <span className="pti-listening-status-dot h-2 w-2 rounded-full" aria-hidden="true" />
            {status}
          </p>
        </div>

        {(closedSessionCount > 0 || (isReconnecting && onReconnect)) && (
          <div className="mt-5 flex flex-wrap justify-center gap-2">
            {closedSessionCount > 0 && onOpenRetainedSessions && (
              <button
                type="button"
                onClick={onOpenRetainedSessions}
                className="pti-live-radar-action rounded-lg border px-3 py-2 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              >
                {retainedLabel}
              </button>
            )}
            {isReconnecting && onReconnect && (
              <button
                type="button"
                onClick={onReconnect}
                className="pti-live-radar-action is-warning rounded-lg border px-3 py-2 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              >
                Reconnect stream
              </button>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

export type TopologyPresentationContext =
  | {
      mode: "live";
    }
  | {
      mode: "audit";
      session: {
        lifecycle: "active" | "retained";
        observedAt: string | null;
        startedAt: string | null;
        closedAt: string | null;
      } | null;
    };

function isFilesystemClosedSession(
  session: FilesystemTopologySession | FilesystemClosedSession,
): session is FilesystemClosedSession {
  return "lifecycle" in session && Boolean(session.lifecycle);
}

export function deriveTopologyPresentationContext(
  mode: "live" | "audit",
  selectedSession?: FilesystemTopologySession | FilesystemClosedSession | null,
): TopologyPresentationContext {
  if (mode === "live") {
    return { mode: "live" };
  }

  if (!selectedSession) {
    return {
      mode: "audit",
      session: null,
    };
  }

  if (isFilesystemClosedSession(selectedSession)) {
    return {
      mode: "audit",
      session: {
        lifecycle: "retained",
        observedAt: selectedSession.cwdState?.observedAt ?? null,
        startedAt: selectedSession.lifecycle.startedAt ?? null,
        closedAt: selectedSession.lifecycle.closedAt ?? null,
      },
    };
  }

  return {
    mode: "audit",
    session: {
      lifecycle: "active",
      observedAt: selectedSession.cwdState?.observedAt ?? null,
      startedAt: null,
      closedAt: null,
    },
  };
}

export interface TopologyCanvasProps {
  snapshot: FilesystemTopologySnapshot | null;
  regionStatus: RegionStatus;
  streamState: StreamState;
  freshnessState: FreshnessState;
  selectedSessionId: string | null;
  selectedPath: string | null;
  activeHop?: ActiveHopRoute | null;
  displayedTransitions?: readonly VerifiedCwdTransition[];
  currentTransition?: VerifiedCwdTransition | null;
  hopDurationMs?: number;
  title?: string;
  subtitle?: string;
  onSelectSession: (sessionId: string) => void;
  onSelectPath: (path: string | null) => void;
  isExpanded?: boolean;
  onToggleExpand?: () => void;
  onRefresh?: () => void;
  onReconnect?: () => void;
  onOpenRetainedSessions?: () => void;
  staleThresholdMs: number;
  presentationContext: TopologyPresentationContext;
  isResizingContainer?: boolean;
  className?: string;
}

export function TopologyCanvas({
  snapshot,
  regionStatus,
  streamState,
  freshnessState,
  selectedSessionId,
  selectedPath,
  activeHop,
  displayedTransitions = [],
  currentTransition = null,
  hopDurationMs = 1400,
  title,
  subtitle,
  onSelectSession,
  onSelectPath,
  isExpanded: controlledIsExpanded,
  onToggleExpand,
  onRefresh,
  onReconnect,
  onOpenRetainedSessions,
  staleThresholdMs,
  presentationContext,
  isResizingContainer = false,
  className,
}: TopologyCanvasProps) {
  const isAuditMode = presentationContext.mode === "audit";
  const activeHopCanvasSemantics = deriveActiveHopCanvasSemantics(activeHop);
  const isFailedHop = activeHop?.isFailedAttempt === true || activeHop?.action === "failed_change";
  const failedHopMessage = isFailedHop
    ? formatFailedChangeMessage(activeHop?.fromPath)
    : null;
  const reducedMotion = useReducedMotion();
  const [internalIsTopologyExpanded, setInternalIsTopologyExpanded] = useState(false);
  const isTopologyExpanded = controlledIsExpanded !== undefined ? controlledIsExpanded : internalIsTopologyExpanded;
  const isControlledExpansion = onToggleExpand !== undefined;
  const isStandaloneExpanded = isTopologyExpanded && !isControlledExpansion;

  const handleToggleExpand = useCallback(() => {
    if (onToggleExpand) {
      onToggleExpand();
    } else {
      setInternalIsTopologyExpanded((prev) => !prev);
    }
  }, [onToggleExpand]);

  // Scope layout persistence so audit session inspection never overrides live global topology
  const { labelStorageKey, nodeStorageKey } = useMemo(
    () => getLayoutStorageKeys(isAuditMode, selectedSessionId),
    [isAuditMode, selectedSessionId],
  );

  const [nodeElementBounds, setNodeElementBounds] = useState<Record<string, GraphElementBounds>>({});
  const [calloutElementBounds, setCalloutElementBounds] = useState<Record<string, GraphElementBounds>>({});
  const [calloutAnchorBounds, setCalloutAnchorBounds] = useState<Record<string, GraphElementBounds>>({});
  const [calloutLayoutBounds, setCalloutLayoutBounds] = useState<Record<string, GraphElementBounds>>({});

  const mapSurfaceRef = useRef<HTMLDivElement>(null);
  const graphPlaneRef = useRef<HTMLDivElement>(null);
  const nodeElementRefs = useRef(new Map<string, HTMLButtonElement>());
  const calloutElementRefs = useRef(new Map<string, HTMLElement>());
  const calloutAnchorElementRefs = useRef(new Map<string, HTMLButtonElement>());
  const clusterSessionRefs = useRef(new Map<string, HTMLButtonElement>());
  const [userCollapsedIps, setUserCollapsedIps] = useState<Set<string>>(new Set());
  const [userExpandedIps, setUserExpandedIps] = useState<Set<string>>(new Set());
  const [showGrid, setShowGrid] = useState(true);

  const isClusterExpanded = useCallback(
    (callout: GraphCallout) => {
      if (callout.sessions.length <= 1) return false;
      if (userCollapsedIps.has(callout.sourceIp)) return false;
      if (userExpandedIps.has(callout.sourceIp)) return true;
      return callout.sessionIds.includes(selectedSessionId ?? "");
    },
    [selectedSessionId, userCollapsedIps, userExpandedIps],
  );

  const getViewportSnapshotRef = useRef<(() => { pan: Pan; zoom: number }) | null>(null);
  const restoreViewportRef = useRef<((snapshot: { pan: Pan; zoom: number }) => void) | null>(null);
  const resetViewportRef = useRef<((overrideLabels?: Record<string, LabelPosition>, overrideNodes?: Record<string, LabelPosition>) => void) | null>(null);

  // TopologyCanvas is the sole mounted owner of arrangement state for this
  // topology instance. Presentational header/scene/overlay children receive
  // focused values and callbacks; they never call viewport or arrangement hooks.
  const {
    isArrangeMode,
    setIsArrangeMode,
    labelPositions,
    nodePositions,
    draggedCalloutIp,
    draggedNodePath,
    canUndoLayout,
    undoLayoutChange,
    autoArrangeTopology,
    resetMapWorkspace,
    onCalloutPointerDown,
    onCalloutPointerMove,
    onCalloutPointerEnd,
    consumeCalloutClickSuppression,
    onNodePointerDown,
    onNodePointerMove,
    onNodePointerEnd,
    consumeNodeClickSuppression,
  } = useTopologyArrange({
    labelStorageKey,
    nodeStorageKey,
    graphPlaneRef,
    onCaptureViewport: () => getViewportSnapshotRef.current?.() ?? { pan: { x: 0, y: 0 }, zoom: 1 },
    onRestoreViewport: (snapshot) => restoreViewportRef.current?.(snapshot),
    onResetViewport: (labels, nodes) => resetViewportRef.current?.(labels, nodes),
    onClearElementBounds: () => {
      setNodeElementBounds({});
      setCalloutElementBounds({});
      setCalloutAnchorBounds({});
      setCalloutLayoutBounds({});
    },
  });

  const [densityPreference, setDensityPreference] = useState<TopologyDensityPreference>("auto");
  const [minimapPreference, setMinimapPreference] = useState<MinimapVisibilityPreference>("auto");
  const [transitionDisplayMode, setTransitionDisplayMode] = useState<TransitionDisplayMode>("current");

  // Render limits state
  const [isSourcesExpanded, setIsSourcesExpanded] = useState(false);

  // Derived graph layout
  const effectiveDensityMode: TopologyDensityMode = useMemo(() => {
    if (densityPreference !== "auto") return densityPreference;
    const totalNodes = snapshot?.nodes.length ?? 0;
    const uniqueSources = new Set((snapshot?.sessions ?? []).map((s) => s.sourceIp)).size;
    if (
      totalNodes <= DEFAULT_DENSITY_THRESHOLDS.detailedMaxNodes &&
      uniqueSources <= DEFAULT_DENSITY_THRESHOLDS.detailedMaxSources
    ) {
      return "detailed";
    }
    if (
      totalNodes <= DEFAULT_DENSITY_THRESHOLDS.clusteredMaxNodes &&
      uniqueSources <= DEFAULT_DENSITY_THRESHOLDS.clusteredMaxSources
    ) {
      return "clustered";
    }
    return "aggregated";
  }, [densityPreference, snapshot?.nodes.length, snapshot?.sessions]);

  const focusedGraphPath = selectedPath ?? activeHopCanvasSemantics.layoutFocusPath;
  const transitionEndpointPaths = useMemo(
    () => requiredTransitionEndpointPaths(currentTransition),
    [currentTransition],
  );

  const automaticGraphNodes = useMemo(
    () =>
      pointForGraph(
        snapshot?.nodes ?? [],
        snapshot?.sessions ?? [],
        selectedPath,
        isAuditMode,
        {
          nodeLimit: densityPreference === "detailed" || isAuditMode ? null : GRAPH_NODE_LIMIT,
          selectedSessionId,
          densityMode: effectiveDensityMode,
          focusedPath: focusedGraphPath,
          requiredPaths: transitionEndpointPaths,
        },
      ),
    [
      effectiveDensityMode,
      focusedGraphPath,
      isAuditMode,
      densityPreference,
      selectedPath,
      selectedSessionId,
      snapshot?.nodes,
      snapshot?.sessions,
      transitionEndpointPaths,
    ],
  );
  const graphNodes = useMemo(
    () => automaticGraphNodes.map((node) => ({ ...node, ...(nodePositions[node.path] ?? {}) })),
    [automaticGraphNodes, nodePositions],
  );
  const graphNodeByPath = useMemo(() => new Map(graphNodes.map((node) => [node.path, node])), [graphNodes]);
  const transitionEndpointCoverage = useMemo(
    () => deriveTransitionEndpointCoverage(
      transitionEndpointPaths,
      snapshot?.nodes ?? [],
      graphNodes,
    ),
    [graphNodes, snapshot?.nodes, transitionEndpointPaths],
  );
  const obscuredTransitionEndpoints = useMemo(
    () => transitionEndpointCoverage.filter((endpoint) => endpoint.status !== "visible"),
    [transitionEndpointCoverage],
  );
  const failedAnnotationNode = activeHopCanvasSemantics.failedAnnotationPath
    ? graphNodeByPath.get(activeHopCanvasSemantics.failedAnnotationPath) ?? null
    : null;
  const graphPlaneHeight = useMemo(
    () => Math.max(440, 144 + Math.max(0, ...graphNodes.map((node) => node.depth)) * 64),
    [graphNodes],
  );
  const effectiveSessions = useMemo(() => {
    if (!activeHopCanvasSemantics.replayContextPath || !selectedSessionId) return snapshot?.sessions ?? [];
    return (snapshot?.sessions ?? []).map((session) => {
      if (session.sessionId === selectedSessionId) {
        return {
          ...session,
          cwdState: {
            ...session.cwdState,
            path: activeHopCanvasSemantics.replayContextPath,
          },
        };
      }
      return session;
    });
  }, [activeHopCanvasSemantics.replayContextPath, selectedSessionId, snapshot?.sessions]);

  const automaticGraphNodeByPath = useMemo(
    () => new Map(automaticGraphNodes.map((node) => [node.path, node])),
    [automaticGraphNodes],
  );

  const graphCallouts = useMemo(
    () =>
      calloutsForGraph(effectiveSessions, automaticGraphNodeByPath, {
        calloutLimit: isSourcesExpanded || densityPreference === "detailed" || isAuditMode ? null : GRAPH_CALLOUT_LIMIT,
        selectedSessionId,
        densityMode: effectiveDensityMode,
      }),
    [
      effectiveSessions,
      automaticGraphNodeByPath,
      isSourcesExpanded,
      densityPreference,
      isAuditMode,
      selectedSessionId,
      effectiveDensityMode,
    ],
  );
  const allSourceClusters = useMemo(
    () =>
      calloutsForGraph(effectiveSessions, automaticGraphNodeByPath, {
        calloutLimit: null,
        selectedSessionId,
      }),
    [effectiveSessions, automaticGraphNodeByPath, selectedSessionId],
  );

  const densityAnalysis = useMemo(
    () =>
      analyzeTopologyDensity(
        snapshot?.nodes ?? [],
        snapshot?.sessions ?? [],
        densityPreference,
        focusedGraphPath,
        graphNodes,
        graphCallouts,
      ),
    [snapshot?.nodes, snapshot?.sessions, densityPreference, focusedGraphPath, graphNodes, graphCallouts],
  );
  const sourceRailCalloutPositions = useMemo(
    () => sourceRailPositions(graphCallouts, automaticGraphNodeByPath, isAuditMode),
    [graphCallouts, automaticGraphNodeByPath, isAuditMode],
  );
  // Rail assignment happens before cards are measurable. Once the DOM reports
  // their true dimensions, clear automatic cards from directory cards. Manual
  // label positions remain intentionally untouched by this pass.
  const automaticCalloutPositions = useMemo(
    () => clearAutomaticCalloutCollisions(
      graphNodes,
      graphCallouts,
      sourceRailCalloutPositions,
      nodeElementBounds,
      calloutLayoutBounds,
    ),
    [calloutLayoutBounds, graphCallouts, graphNodes, nodeElementBounds, sourceRailCalloutPositions],
  );
  const effectiveCalloutPositions = useMemo(
    () => resolveCalloutPositions(graphCallouts, automaticCalloutPositions, labelPositions),
    [graphCallouts, automaticCalloutPositions, labelPositions],
  );
  const positionForCallout = useCallback(
    (callout: GraphCallout, _index: number): LabelPosition =>
      effectiveCalloutPositions.get(callout.sourceIp) ??
      automaticCalloutPositions.get(callout.sourceIp) ??
      { x: _index % 2 === 0 ? 10 : 90, y: 50 },
    [automaticCalloutPositions, effectiveCalloutPositions],
  );
  const liveSessionById = useMemo(
    () => new Map(effectiveSessions.map((session) => [session.sessionId, session])),
    [effectiveSessions],
  );
  const selectedGraphCallout = useMemo(
    () => graphCallouts.find((callout) => callout.sessionIds.includes(selectedSessionId ?? "")) ?? null,
    [graphCallouts, selectedSessionId],
  );
  const liveSourceCount = useMemo(
    () => new Set(effectiveSessions.map((session) => session.sourceIp)).size,
    [effectiveSessions],
  );
  const exactSessionCountByPath = useMemo(() => {
    const counts = new Map<string, number>();
    for (const session of effectiveSessions) {
      const p = session.cwdState.path;
      if (p) {
        counts.set(p, (counts.get(p) ?? 0) + 1);
      }
    }
    return counts;
  }, [effectiveSessions]);

  const totalLiveSources = liveSourceCount;
  const renderedSourcesCount = graphCallouts.length;



  const measureElementBounds = useCallback(() => {
    const plane = graphPlaneRef.current;
    if (!plane?.offsetWidth || !plane.offsetHeight) return;
    const planeBounds = plane.getBoundingClientRect();
    if (!planeBounds.width || !planeBounds.height) return;
    const toRelativeBounds = (element: HTMLElement): GraphElementBounds => {
      const bounds = element.getBoundingClientRect();
      return {
        x: ((bounds.left + bounds.width / 2 - planeBounds.left) / planeBounds.width) * 100,
        y: ((bounds.top + bounds.height / 2 - planeBounds.top) / planeBounds.height) * 100,
        width: (bounds.width / planeBounds.width) * 100,
        height: (bounds.height / planeBounds.height) * 100,
      };
    };
    const measuredNodes = Object.fromEntries(
      [...nodeElementRefs.current.entries()].map(([path, element]) => [path, toRelativeBounds(element)]),
    );
    const measuredCallouts = Object.fromEntries(
      [...calloutElementRefs.current.entries()].map(([sourceIp, element]) => [sourceIp, toRelativeBounds(element)]),
    );
    const calloutBySourceIp = new Map(graphCallouts.map((callout) => [callout.sourceIp, callout]));
    const measuredCalloutAnchors: Record<string, GraphElementBounds> = Object.fromEntries(
      [...calloutAnchorElementRefs.current.entries()].map(([sourceIp, element]) => [sourceIp, toRelativeBounds(element)]),
    );
    const measuredCalloutLayouts: Record<string, GraphElementBounds> = Object.fromEntries(
      Object.entries(measuredCalloutAnchors).map(([sourceIp, anchorBounds]) => {
        const callout = calloutBySourceIp.get(sourceIp);
        const reservedDisclosureHeight = estimateExpandedCalloutDisclosureHeight(callout?.sessions.length ?? 1);
        const reservedDisclosurePercent = (reservedDisclosureHeight / plane.offsetHeight) * 100;
        const visibleHeight = measuredCallouts[sourceIp]?.height ?? anchorBounds.height;
        const fullHeight = Math.max(anchorBounds.height + reservedDisclosurePercent, visibleHeight);
        const disclosureHeight = Math.max(0, fullHeight - anchorBounds.height);
        return [sourceIp, {
          ...anchorBounds,
          height: fullHeight,
          anchorOffsetY: disclosureHeight / 2,
        }];
      }),
    );
    setNodeElementBounds((current) => sameElementBounds(current, measuredNodes) ? current : measuredNodes);
    setCalloutElementBounds((current) => sameElementBounds(current, measuredCallouts) ? current : measuredCallouts);
    setCalloutAnchorBounds((current) => sameElementBounds(current, measuredCalloutAnchors) ? current : measuredCalloutAnchors);
    setCalloutLayoutBounds((current) => sameElementBounds(current, measuredCalloutLayouts) ? current : measuredCalloutLayouts);
  }, [graphCallouts]);

  // Source connectors use the stable header bounds. The full-card bounds remain
  // separate for overlap detection, while layout bounds reserve disclosure space.
  useLayoutEffect(() => {
    measureElementBounds();
    const plane = graphPlaneRef.current;
    if (!plane) return;
    const observer = new ResizeObserver(measureElementBounds);
    observer.observe(plane);
    for (const element of nodeElementRefs.current.values()) {
      observer.observe(element);
    }
    for (const element of calloutElementRefs.current.values()) {
      observer.observe(element);
    }
    for (const element of calloutAnchorElementRefs.current.values()) {
      observer.observe(element);
    }
    return () => observer.disconnect();
  }, [graphCallouts, graphNodes, isTopologyExpanded, labelPositions, measureElementBounds, nodePositions]);

  // Overlap detection: Identify any directory nodes or IP callouts that overlap each other
  const { overlappingNodePaths, overlappingCalloutIps } = useMemo(() => {
    const overlappingNodes = new Set<string>();
    const overlappingCallouts = new Set<string>();

    type BoundingBox = { id: string; type: "node" | "callout"; x: number; y: number; hw: number; hh: number };
    const boxes: BoundingBox[] = [];

    // Collect directory nodes
    for (const node of graphNodes) {
      const bounds = nodeElementBounds[node.path];
      const hw = bounds?.width ? bounds.width / 2 : 7.5;
      const hh = bounds?.height ? bounds.height / 2 : 4.0;
      boxes.push({ id: node.path, type: "node", x: node.x, y: node.y, hw, hh });
    }

    // Collect callouts
    for (const [index, callout] of graphCallouts.entries()) {
      const pos = positionForCallout(callout, index);
      const bounds = calloutElementBounds[callout.sourceIp];
      const hw = bounds?.width ? bounds.width / 2 : 8.35;
      const hh = bounds?.height ? bounds.height / 2 : 5.2;
      boxes.push({
        id: callout.sourceIp,
        type: "callout",
        x: bounds?.x ?? pos.x,
        y: bounds?.y ?? pos.y,
        hw,
        hh,
      });
    }

    // Compare all pairs for AABB intersection
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i];
        const b = boxes[j];

        // An overlap occurs when both X and Y center distances are smaller than the sum of their half-sizes (with small tolerance)
        const overlapX = Math.abs(a.x - b.x) < a.hw + b.hw - 0.4;
        const overlapY = Math.abs(a.y - b.y) < a.hh + b.hh - 0.4;

        if (overlapX && overlapY) {
          if (a.type === "node") overlappingNodes.add(a.id);
          else overlappingCallouts.add(a.id);

          if (b.type === "node") overlappingNodes.add(b.id);
          else overlappingCallouts.add(b.id);
        }
      }
    }

    return { overlappingNodePaths: overlappingNodes, overlappingCalloutIps: overlappingCallouts };
  }, [calloutElementBounds, graphCallouts, graphNodes, nodeElementBounds, positionForCallout]);

  const totalOverlaps = overlappingNodePaths.size + overlappingCalloutIps.size;
  const reserveMinimapSpace = minimapPreference === "show" || (
    minimapPreference === "auto" &&
    topologyExceedsMinimapDensityThreshold(densityAnalysis.totalNodes, densityAnalysis.totalSources)
  );

  const {
    pan,
    setPan,
    zoom,
    setZoom,
    fitZoom,
    panRef,
    zoomRef,
    isDraggingSurface,
    mapMetrics,
    zoomIn,
    zoomOut,
    markUserAdjusted,
    holdViewportSteady,
    centerMapOn,
    resetViewport,
    fitTopology,
    onPointerDown,
    onPointerMove,
    onPointerEnd,
    onSurfaceKeyDown,
  } = useTopologyViewport({
    mapSurfaceRef,
    graphPlaneRef,
    isTopologyExpanded,
    reserveMinimapSpace,
    automaticGraphNodes,
    graphCallouts,
    nodePositions,
    labelPositions,
    automaticCalloutPositions,
    nodeElementBounds,
    calloutElementBounds: calloutLayoutBounds,
    nodesCount: snapshot?.nodes.length ?? 0,
  });
  const toggleClusterExpand = useCallback((sourceIp: string, isCurrentlyExpanded: boolean) => {
    // Disclosure is an explicit viewport interaction. Keep the current camera while
    // ResizeObserver updates connector geometry and the disclosure animates.
    holdViewportSteady();
    if (isCurrentlyExpanded) {
      setUserCollapsedIps((prev) => new Set(prev).add(sourceIp));
      setUserExpandedIps((prev) => {
        const next = new Set(prev);
        next.delete(sourceIp);
        return next;
      });
    } else {
      setUserExpandedIps((prev) => new Set(prev).add(sourceIp));
      setUserCollapsedIps((prev) => {
        const next = new Set(prev);
        next.delete(sourceIp);
        return next;
      });
    }
  }, [holdViewportSteady]);
  const showMinimap = deriveMinimapVisibility({
    preference: minimapPreference,
    totalNodes: densityAnalysis.totalNodes,
    totalSources: densityAnalysis.totalSources,
    currentZoom: zoom,
    fitZoom,
  });

  useEffect(() => {
    getViewportSnapshotRef.current = () => ({ pan: panRef.current, zoom: zoomRef.current });
    restoreViewportRef.current = (snapshot) => {
      markUserAdjusted();
      panRef.current = snapshot.pan;
      zoomRef.current = snapshot.zoom;
      setPan(snapshot.pan);
      setZoom(snapshot.zoom);
    };
    resetViewportRef.current = resetViewport;
  }, [markUserAdjusted, panRef, resetViewport, setPan, setZoom, zoomRef]);

  const centerSelectedSource = useCallback(() => {
    if (!selectedGraphCallout) return;
    const index = graphCallouts.findIndex((callout) => callout.sourceIp === selectedGraphCallout.sourceIp);
    if (index < 0) return;
    centerMapOn(positionForCallout(selectedGraphCallout, index));
  }, [centerMapOn, graphCallouts, positionForCallout, selectedGraphCallout]);

  // Keep camera steady; only bring a verified destination into view when a hop changes.
  const lastProcessedHopEventId = useRef<string | null>(null);
  useEffect(() => {
    const currentHopEventId = activeHop?.eventId ?? null;
    const isNewHopEvent = currentHopEventId !== lastProcessedHopEventId.current;
    lastProcessedHopEventId.current = currentHopEventId;

    const autoCenterPath = activeHopCanvasSemantics.autoCenterPath;
    if (!isNewHopEvent || !autoCenterPath) return;

    // Never auto-center while user is actively dragging or interacting with the canvas
    if (draggedNodePath || draggedCalloutIp || isDraggingSurface) return;

    const targetNode = graphNodeByPath.get(autoCenterPath);
    if (!targetNode) return;

    const surface = mapSurfaceRef.current;
    const plane = graphPlaneRef.current;
    if (!surface || !plane) return;

    const screenX = plane.offsetLeft + panRef.current.x + ((plane.offsetWidth * targetNode.x) / 100) * zoomRef.current;
    const screenY = plane.offsetTop + panRef.current.y + ((plane.offsetHeight * targetNode.y) / 100) * zoomRef.current;

    const margin = 60;
    const isVisible =
      screenX >= margin &&
      screenX <= surface.clientWidth - margin &&
      screenY >= margin &&
      screenY <= surface.clientHeight - margin;

    if (!isVisible) {
      centerMapOn(targetNode);
    }
  }, [
    activeHop?.eventId,
    activeHopCanvasSemantics.autoCenterPath,
    centerMapOn,
    graphNodeByPath,
    isDraggingSurface,
    draggedNodePath,
    draggedCalloutIp,
    panRef,
    zoomRef,
  ]);

  // Minimap viewport box calculation
  const minimapViewport = useMemo(() => {
    if (!mapMetrics || !mapMetrics.planeWidth || !mapMetrics.planeHeight) return null;
    const rawLeft = ((-mapMetrics.planeLeft - pan.x) / (zoom * mapMetrics.planeWidth)) * 100;
    const rawTop = ((-mapMetrics.planeTop - pan.y) / (zoom * mapMetrics.planeHeight)) * 100;
    const rawRight = rawLeft + (mapMetrics.surfaceWidth / (zoom * mapMetrics.planeWidth)) * 100;
    const rawBottom = rawTop + (mapMetrics.surfaceHeight / (zoom * mapMetrics.planeHeight)) * 100;
    return {
      x: rawLeft,
      y: rawTop,
      width: Math.max(2, rawRight - rawLeft),
      height: Math.max(2, rawBottom - rawTop),
    };
  }, [mapMetrics, pan, zoom]);

  // Escape key exits expanded workspace (when running standalone)
  useEffect(() => {
    if (!isStandaloneExpanded) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setInternalIsTopologyExpanded(false);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [isStandaloneExpanded]);

  return (
    <div
      className={`ui-panel overflow-hidden flex flex-col ${
        isStandaloneExpanded ? "fixed inset-3 z-50 bg-surface" : ""
      } ${className ?? ""}`}
      aria-busy={regionStatus === "loading"}
    >
      <TopologyCanvasHeader title={title} subtitle={subtitle}>
        <TopologyToolbar
          zoom={zoom}
          zoomIn={zoomIn}
          zoomOut={zoomOut}
          fitTopology={fitTopology}
          selectedGraphCallout={selectedGraphCallout}
          markUserAdjusted={markUserAdjusted}
          centerSelectedSource={centerSelectedSource}
          isArrangeMode={isArrangeMode}
          setIsArrangeMode={setIsArrangeMode}
          canUndoLayout={canUndoLayout}
          undoLayoutChange={undoLayoutChange}
          totalOverlaps={totalOverlaps}
          autoArrangeTopology={autoArrangeTopology}
          resetMapWorkspace={resetMapWorkspace}
          densityPreference={densityPreference}
          setDensityPreference={setDensityPreference}
          minimapPreference={minimapPreference}
          setMinimapPreference={setMinimapPreference}
          minimapVisible={showMinimap}
          showGrid={showGrid}
          setShowGrid={setShowGrid}
          effectiveDensityMode={effectiveDensityMode}
          densityAnalysisHiddenNodes={densityAnalysis.hiddenNodes}
          isTopologyExpanded={isTopologyExpanded}
          isAuditMode={isAuditMode}
          transitionDisplayMode={transitionDisplayMode}
          setTransitionDisplayMode={setTransitionDisplayMode}
          handleToggleExpand={handleToggleExpand}
        />
      </TopologyCanvasHeader>

      {regionStatus === "error" && !snapshot ? (
        <div className={isAuditMode ? "p-5" : "flex min-h-0 flex-1 flex-col p-5"}>
          <RegionState
            kind="error"
            title="Filesystem activity unavailable"
            description="The topology could not be loaded. Other dashboard views remain available."
          />
        </div>
      ) : regionStatus === "loading" && !snapshot ? (
        <div className={isAuditMode ? "p-5" : "flex min-h-0 flex-1 flex-col p-5"}>
          {isAuditMode ? (
            <RegionState
              kind="loading"
              title="Loading audit topology..."
              description="Preparing retained filesystem evidence for replay."
              variant="topology"
            />
          ) : (
            <LiveTopologyStandby
              mode="loading"
              closedSessionCount={0}
              onReconnect={onReconnect}
              reducedMotion={Boolean(reducedMotion)}
            />
          )}
        </div>
      ) : !snapshot?.nodes.length ? (
        <div className={isAuditMode ? "p-5" : "flex min-h-0 flex-1 flex-col p-5"}>
          {failedHopMessage && (
            <div
              role="status"
              data-testid="failed-change-canvas-status"
              aria-label={failedHopMessage}
              className="mb-4 flex items-start gap-2 rounded-lg border border-warning-border bg-warning-subtle px-3 py-2 text-xs text-warning"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{failedHopMessage}</span>
            </div>
          )}
          {!isAuditMode && freshnessState.isDegraded && (
            <div role="status" className="mb-4 rounded-lg border border-warning-border bg-surface-raised px-3 py-2 text-xs text-text">
              <strong className="font-semibold text-warning">Degraded connection:</strong>{" "}
              Showing retained snapshot.
            </div>
          )}
          {!isAuditMode && snapshot && snapshot.sessions.length === 0 ? (
            <LiveTopologyStandby
              mode={
                streamState === "live"
                  ? "listening"
                  : streamState === "connecting"
                    ? "loading"
                    : "reconnecting"
              }
              closedSessionCount={snapshot.recentClosedSessions.length}
              onOpenRetainedSessions={onOpenRetainedSessions}
              onReconnect={onReconnect}
              reducedMotion={Boolean(reducedMotion)}
            />
          ) : (
            <RegionState
              kind="empty"
              title={isAuditMode ? "No session selected for audit" : "No verified working directory data yet"}
              description={
                isAuditMode
                  ? "Choose a session from the dropdown above or reset active filters."
                  : "An attacker is connected, but verified CWD telemetry has not been recorded yet."
              }
            />
          )}
        </div>
      ) : (
        <>
          <div
            className={
              isStandaloneExpanded
                ? "grid min-h-0 flex-1 lg:grid-cols-[minmax(0,1fr)_20rem]"
                : "flex min-h-0 flex-1 flex-col"
            }
          >
            <div className="flex min-h-0 min-w-0 flex-1 flex-col">
              {/* Global override during dragging to prevent text selection and force cursor */}
              {(isDraggingSurface || draggedNodePath || draggedCalloutIp) && (
                <style>{`
                  body { user-select: none !important; -webkit-user-select: none !important; }
                  body * { cursor: grabbing !important; }
                `}</style>
              )}
              <div
                ref={mapSurfaceRef}
                tabIndex={0}
                role="region"
                aria-label="Filesystem topology map workspace. Use arrow keys to pan, scroll or pinch to zoom."
                onKeyDown={onSurfaceKeyDown}
                className={`relative min-h-[380px] flex-1 overflow-hidden p-5 sm:p-8 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${isAuditMode ? "bg-surface-subtle" : "pti-live-radar"}`}
                onPointerDown={onPointerDown}
                onPointerMove={onPointerMove}
                onPointerUp={onPointerEnd}
                onPointerCancel={onPointerEnd}
              >
                {isAuditMode ? (
                  <div
                    className={`pointer-events-none absolute inset-0 transition-opacity duration-300 [background-image:linear-gradient(var(--border)_1px,transparent_1px),linear-gradient(90deg,var(--border)_1px,transparent_1px)] [background-size:28px_28px] ${showGrid ? "opacity-50" : "opacity-0"}`}
                    aria-hidden="true"
                  />
                ) : (
                  <LiveRadarOverlay showGrid={showGrid} reducedMotion={Boolean(reducedMotion)} />
                )}

                <AnimatePresence initial={false}>
                  {!isAuditMode && freshnessState.isDegraded && (
                    <motion.div
                      key="degraded-banner"
                      role="status"
                      initial={reducedMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -6 }}
                      transition={{ duration: reducedMotion ? 0 : 0.15, ease: "easeOut" }}
                      className="absolute left-1/2 top-4 z-50 flex -translate-x-1/2 items-center gap-2.5 rounded-lg border border-warning-border bg-surface-raised/95 px-3 py-1.5 text-xs text-text shadow-md backdrop-blur-xs"
                    >
                      <AlertTriangle className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                      <span>
                        <strong className="font-semibold text-warning">Degraded connection:</strong> Showing retained snapshot (received{" "}
                        {formatUpdateAge(freshnessState.snapshotReceiptAgeMs)}).
                      </span>
                      <span className="hidden sm:inline text-text-subtle text-xs">
                        (Threshold: {Math.round(staleThresholdMs / 1000)}s)
                      </span>
                      {isStandaloneExpanded && onRefresh && (
                        <button
                          type="button"
                          onClick={onRefresh}
                          className="ml-1 rounded border border-border bg-surface px-2 py-0.5 text-xs font-semibold text-text hover:bg-surface-hover transition-colors"
                        >
                          Refresh snapshot
                        </button>
                      )}
                      {isStandaloneExpanded && onReconnect && (
                        <button
                          type="button"
                          onClick={onReconnect}
                          className="ml-1 rounded border border-warning-border bg-warning-subtle px-2 py-0.5 text-xs font-semibold text-warning hover:bg-warning/20 transition-colors"
                        >
                          Reconnect now
                        </button>
                      )}
                    </motion.div>
                  )}
                  {isArrangeMode && (
                    <motion.div
                      key="arrange-mode-banner"
                      role="status"
                      initial={reducedMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -6 }}
                      transition={{ duration: reducedMotion ? 0 : 0.15, ease: "easeOut" }}
                      className="pointer-events-none absolute left-4 top-4 z-50 flex min-h-9 items-center gap-2 rounded-lg border border-primary-border bg-surface-raised px-3 text-xs text-text shadow-sm sm:left-5 sm:top-5"
                    >
                      <Move className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
                      <strong className="font-semibold text-primary">Arrange mode</strong>
                      <span className="text-text-muted">Drag nodes</span>
                      <span className="text-border" aria-hidden="true">·</span>
                      <kbd className="rounded border border-border bg-surface-subtle px-1.5 py-0.5 font-mono text-xs">Esc</kbd>
                      <span className="text-text-muted">to finish</span>
                    </motion.div>
                  )}
                  {activeHopCanvasSemantics.verifiedTargetPath && selectedPath && selectedPath !== activeHopCanvasSemantics.verifiedTargetPath && (
                    <motion.div
                      key="inspection-context-banner"
                      role="status"
                      initial={reducedMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, y: -6 }}
                      transition={{ duration: reducedMotion ? 0 : 0.15, ease: "easeOut" }}
                      className="pointer-events-none absolute left-1/2 top-4 z-50 flex min-h-9 -translate-x-1/2 items-center gap-2 rounded-lg border border-primary-border bg-surface-raised px-3 text-xs text-text shadow-sm"
                    >
                      <ScanLine className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
                      <strong className="font-semibold text-primary">Inspecting directory</strong>
                      <span className="text-border" aria-hidden="true">·</span>
                      <button
                        type="button"
                        onClick={() => onSelectPath(activeHopCanvasSemantics.verifiedTargetPath)}
                        className="pointer-events-auto rounded border border-border bg-surface-subtle px-2 py-0.5 font-semibold text-text hover:bg-surface hover:text-text transition-colors shadow-2xs"
                      >
                        Return to current hop
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>

                {failedHopMessage && !failedAnnotationNode && (
                  <div
                    role="status"
                    data-testid="failed-change-canvas-status"
                    aria-label={failedHopMessage}
                    className="pointer-events-none absolute left-1/2 top-4 z-40 flex max-w-[min(32rem,calc(100%-2rem))] -translate-x-1/2 items-start gap-2 rounded-lg border border-warning-border bg-warning-subtle px-3 py-2 text-xs text-warning shadow-sm"
                  >
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                    <span>{failedHopMessage}</span>
                  </div>
                )}

                {obscuredTransitionEndpoints.length > 0 && (
                  <div
                    role="status"
                    data-testid="transition-endpoint-coverage"
                    className="pointer-events-none absolute right-4 top-16 z-40 max-w-[min(30rem,calc(100%-2rem))] rounded-lg border border-border bg-surface-raised/95 px-3 py-2 text-xs text-text-muted shadow-sm"
                  >
                    {obscuredTransitionEndpoints.map((endpoint) => (
                      <div key={endpoint.path} data-transition-endpoint-status={endpoint.status}>
                        {endpoint.status === "aggregated" ? (
                          <>Current transition endpoint <span className="font-mono text-text">{endpoint.path}</span> is represented by aggregate <span className="font-mono text-text">{endpoint.aggregatePath}</span>.</>
                        ) : (
                          <>Current transition endpoint <span className="font-mono text-text">{endpoint.path}</span> is unavailable in the loaded topology.</>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {(displayedTransitions.length > 0 || currentTransition) && (
                  <TransitionLegend displayMode={transitionDisplayMode} />
                )}

                <motion.div
                  ref={graphPlaneRef}
                  className={`absolute origin-top-left overflow-visible ${isAuditMode ? "" : "z-10"}`}
                  animate={reducedMotion ? undefined : { x: pan.x, y: pan.y, scale: zoom }}
                  style={
                    reducedMotion
                      ? {
                          minHeight: graphPlaneHeight,
                          minWidth: 860,
                          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
                        }
                      : { minHeight: graphPlaneHeight, minWidth: 860 }
                  }
                  transition={
                    reducedMotion || isDraggingSurface || isResizingContainer
                      ? { duration: 0 }
                      : { type: "spring", stiffness: 260, damping: 28 }
                  }
                >
                  <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute h-full w-full overflow-visible" aria-hidden="true">
                    <AnimatePresence initial={false}>
                      {graphNodes.map((node) => {
                        const parent = node.parentPath ? graphNodeByPath.get(node.parentPath) : null;
                        if (!parent) return null;
                        const cpOffset = Math.min(25, Math.max(8, Math.abs(node.y - parent.y) * 0.5));
                        const cp1Y = parent.y <= node.y ? parent.y + cpOffset : parent.y - cpOffset;
                        const cp2Y = parent.y <= node.y ? node.y - cpOffset : node.y + cpOffset;
                        const filesystemRoute = `M ${parent.x} ${parent.y} C ${parent.x} ${cp1Y}, ${node.x} ${cp2Y}, ${node.x} ${node.y}`;

                        return (
                          <motion.g
                            key={`${parent.path}-${node.path}`}
                            initial={reducedMotion ? false : { opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={reducedMotion ? undefined : { opacity: 0 }}
                            transition={reducedMotion ? { duration: 0 } : { duration: 0.3, ease: "easeOut" }}
                          >
                            <motion.path
                              initial={false}
                              animate={{ d: filesystemRoute }}
                              transition={
                                reducedMotion || Boolean(draggedNodePath)
                                  ? { duration: 0 }
                                  : TOPOLOGY_TRANSITION
                              }
                              fill="none"
                              stroke="var(--border-strong)"
                              strokeWidth="0.35"
                              strokeOpacity="0.4"
                              strokeDasharray="none"
                              data-edge-kind="hierarchy"
                              data-parent-path={parent.path}
                              data-child-path={node.path}
                            />
                          </motion.g>
                        );
                      })}
                    </AnimatePresence>
                  </svg>
                  <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute z-0 h-full w-full overflow-visible" aria-hidden="true">
                    <AnimatePresence initial={false}>
                      {graphCallouts.map((callout, index) => {
                        const position = positionForCallout(callout, index);
                        const selectedSource = callout.sessionIds.includes(selectedSessionId ?? "");
                        const selectedSessionPath = selectedSessionId
                          ? callout.sessions?.find((s) => s.sessionId === selectedSessionId)?.path ?? liveSessionById.get(selectedSessionId)?.cwdState.path
                          : null;
                        const targetPaths = callout.targetPaths?.length
                          ? callout.targetPaths
                          : [callout.path];
                        return (
                          <motion.g
                            key={`leader-${callout.sourceIp}`}
                            initial={reducedMotion ? false : { opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={reducedMotion ? undefined : { opacity: 0 }}
                            transition={reducedMotion ? { duration: 0 } : { duration: 0.3, ease: "easeOut" }}
                          >
                            {targetPaths.map((path, routeIndex) => {
                              const node = graphNodeByPath.get(path);
                              if (!node) return null;
                              const isPrimarySelected = selectedSource && (path === selectedSessionPath || (!selectedSessionPath && path === callout.path));
                              const isClusterSelected = selectedSource;
                              const endpoint = leaderEndpoints(
                                node,
                                position,
                                nodeElementBounds[node.path],
                                calloutAnchorBounds[callout.sourceIp],
                              );
                              const controlX = (endpoint.startX + endpoint.endX) / 2;
                              const routePath = `M ${endpoint.startX} ${endpoint.startY} C ${controlX} ${endpoint.startY}, ${controlX} ${endpoint.endY}, ${endpoint.endX} ${endpoint.endY}`;
                              return (
                                <g key={`${callout.sourceIp}-route-${path}-${routeIndex}`}>
                                  <motion.path
                                    initial={false}
                                    animate={{ d: routePath }}
                                    transition={
                                      reducedMotion || Boolean(draggedNodePath || draggedCalloutIp)
                                        ? { duration: 0 }
                                        : TOPOLOGY_TRANSITION
                                    }
                                    fill="none"
                                    stroke={isPrimarySelected ? "var(--primary)" : isClusterSelected ? "var(--primary)" : "var(--border-strong)"}
                                    strokeOpacity={isAuditMode && currentTransition
                                      ? isPrimarySelected ? 0.32 : isClusterSelected ? 0.24 : 0.18
                                      : isPrimarySelected ? 1 : isClusterSelected ? 0.68 : 0.45}
                                    strokeWidth={isAuditMode && currentTransition
                                      ? isPrimarySelected ? "0.24" : "0.18"
                                      : isPrimarySelected ? "0.42" : isClusterSelected ? "0.28" : "0.2"}
                                    strokeDasharray={isPrimarySelected ? "none" : isClusterSelected ? "1.5 1.5" : "0.75 1.6"}
                                    data-source-connection={callout.sourceIp}
                                    data-source-target-path={path}
                                  />
                                  <motion.circle
                                    initial={false}
                                    animate={{ cx: endpoint.startX, cy: endpoint.startY }}
                                    transition={
                                      reducedMotion || Boolean(draggedNodePath || draggedCalloutIp)
                                        ? { duration: 0 }
                                        : TOPOLOGY_TRANSITION
                                    }
                                    r={isPrimarySelected ? "0.8" : isClusterSelected ? "0.6" : "0.45"}
                                    fill={isPrimarySelected ? "var(--primary)" : isClusterSelected ? "var(--primary)" : "var(--border-strong)"}
                                    fillOpacity={isPrimarySelected ? 1 : isClusterSelected ? 0.7 : 0.45}
                                  />
                                </g>
                              );
                            })}
                          </motion.g>
                        );
                      })}
                    </AnimatePresence>
                  </svg>
                  {(displayedTransitions.length > 0 || currentTransition) && (
                    <TransitionOverlay
                      transitions={displayedTransitions}
                      currentTransition={currentTransition}
                      nodes={graphNodes}
                      nodeBounds={nodeElementBounds}
                      durationMs={hopDurationMs}
                      reducedMotion={Boolean(reducedMotion)}
                      layoutTransition={
                        reducedMotion || Boolean(draggedNodePath)
                          ? { duration: 0 }
                          : TOPOLOGY_TRANSITION
                      }
                      showLegend={false}
                      displayMode={transitionDisplayMode}
                    />
                  )}
                  {failedHopMessage && failedAnnotationNode && (
                    <div
                      role="status"
                      data-testid="failed-change-annotation"
                      data-failed-change-origin={activeHopCanvasSemantics.failedAnnotationPath ?? undefined}
                      aria-label={failedHopMessage}
                      className="pointer-events-none absolute z-30 flex max-w-[min(32rem,calc(100%-2rem))] items-start gap-2 rounded-lg border border-warning-border bg-warning-subtle px-3 py-2 text-xs text-warning shadow-sm"
                      style={{
                        left: `${failedAnnotationNode.x}%`,
                        top: `${failedAnnotationNode.y}%`,
                        transform: "translate(-50%, calc(-100% - 0.75rem))",
                      }}
                    >
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                      <span>{failedHopMessage}</span>
                    </div>
                  )}
                  <AnimatePresence initial={false}>
                    {graphNodes.map((node) => {
                      const isSelected = node.path === selectedPath;
                      const isRoot = node.path === "/";
                      const pathInterest = classifyRuleBasedPathInterest(node.path);
                      const pathInterestAccessibleText = pathInterest
                        ? formatRuleBasedPathInterestDescription(pathInterest)
                        : null;
                      const isHopTarget = activeHopCanvasSemantics.verifiedTargetPath === node.path;
                      const isHopVisited = Boolean(activeHop?.visitedPaths.includes(node.path));
                      const visitedStep = activeHop?.visitedStepMap[node.path];
                      const isOverlapping = overlappingNodePaths.has(node.path);
                      const exactCount = exactSessionCountByPath.get(node.path) ?? 0;
                      const branchCount = node.sessionIds.length;
                      const descendantCount = Math.max(0, branchCount - exactCount);

                      return (
                        <motion.button
                          key={node.path}
                          ref={(element) => {
                            if (element) nodeElementRefs.current.set(node.path, element);
                            else nodeElementRefs.current.delete(node.path);
                          }}
                          initial={reducedMotion ? false : { opacity: 0, scale: 0.92 }}
                          animate={{ left: `${node.x}%`, top: `${node.y}%`, opacity: 1, scale: 1 }}
                          exit={reducedMotion ? undefined : { opacity: 0, scale: 0.94 }}
                          transition={
                            reducedMotion || draggedNodePath === node.path
                              ? { duration: 0 }
                              : {
                                  left: TOPOLOGY_TRANSITION,
                                  top: TOPOLOGY_TRANSITION,
                                  opacity: { duration: 0.3, ease: "easeOut" },
                                  scale: { duration: 0.3, ease: "easeOut" },
                              }
                          }
                          // Framer Motion changes left/top with transforms; a
                          // ResizeObserver on the plane does not report those
                          // child-position changes. Re-measure at the settled
                          // position so the collision pass receives real bounds.
                          onAnimationComplete={measureElementBounds}
                          type="button"
                          aria-pressed={isSelected}
                          aria-label={`Inspect directory ${node.path}${
                            exactCount > 0 && descendantCount > 0
                              ? ` (${exactCount} at exact path, ${descendantCount} in child directories)`
                              : exactCount > 0
                                ? ` (${exactCount} active ${exactCount === 1 ? "session" : "sessions"})`
                                : descendantCount > 0
                                  ? ` (${descendantCount} active ${descendantCount === 1 ? "session" : "sessions"} in child directories)`
                                  : ""
                          }${
                            (node.hiddenChildCount ?? 0) > 0
                              ? ` (${node.hiddenChildCount} child directories aggregated, click to expand)`
                              : ""
                          }${pathInterestAccessibleText ? ` (${pathInterestAccessibleText})` : ""}${
                            isHopTarget && activeHop ? ` (active hop target ${activeHop.stepIndex + 1} of ${activeHop.totalSteps})` : ""
                          }`}
                          title={
                            (node.hiddenChildCount ?? 0) > 0
                              ? `${node.path} (${node.hiddenChildCount} child directories aggregated, click to expand branch)`
                              : exactCount > 0 && descendantCount > 0
                                ? `${node.path} (${exactCount} at exact path, ${descendantCount} in child directories)`
                                : exactCount > 0
                                  ? `${node.path} (${exactCount} active)`
                                  : descendantCount > 0
                                    ? `${node.path} (${descendantCount} in child directories)`
                                    : node.path
                          }
                          onPointerDown={(event) => onNodePointerDown(event, node.path, node)}
                          onPointerMove={onNodePointerMove}
                          onPointerUp={onNodePointerEnd}
                          onPointerCancel={onNodePointerEnd}
                          onClick={() => {
                            if (consumeNodeClickSuppression()) return;
                            if (isArrangeMode) return;
                            onSelectPath(node.path);
                          }}
                          className={`absolute flex max-w-56 -translate-x-1/2 -translate-y-1/2 touch-none items-center gap-1.5 rounded-lg border px-2 py-1.5 text-left shadow-sm transition-colors duration-200 ${isArrangeMode ? "cursor-grab active:cursor-grabbing" : "cursor-pointer"} ${
                            isOverlapping
                              ? "z-30 border-warning bg-warning-subtle/50 text-text ring-2 ring-warning/80 shadow-md shadow-warning/20"
                              : isHopTarget
                                  ? "z-20 border-primary bg-primary-subtle text-text"
                                  : isSelected
                                    ? "z-10 border-primary-border bg-primary-subtle text-text ring-1 ring-primary/40"
                                    : isHopVisited
                                      ? "z-10 border-primary/40 bg-surface text-text hover:border-primary/70 hover:bg-surface-hover"
                                      : pathInterest
                                        ? "z-10 border-warning-border/80 bg-surface text-text hover:border-warning hover:bg-surface-hover"
                                        : "z-10 border-border bg-surface text-text hover:border-border-strong hover:bg-surface-hover"
                          }`}
                        >
                          {isOverlapping && (
                            <span
                              className="pointer-events-none absolute -top-1.5 -right-1.5 z-40 flex h-4 w-4 items-center justify-center rounded-full bg-warning text-surface shadow ring-1 ring-surface"
                              title="Overlapping position with another node"
                              aria-label="Overlapping position with another node"
                            >
                              <AlertTriangle className="h-2.5 w-2.5 stroke-[2.5]" aria-hidden="true" />
                            </span>
                          )}
                          {isRoot ? (
                            <HardDrive
                              className={`h-3.5 w-3.5 shrink-0 ${isSelected || isHopTarget ? "text-primary" : "text-text-subtle"}`}
                              aria-hidden="true"
                            />
                          ) : isSelected || isHopTarget ? (
                            <FolderOpen className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
                          ) : (
                            <Folder
                              className={`h-3.5 w-3.5 shrink-0 ${pathInterest ? "text-warning" : isHopVisited ? "text-primary/80" : "text-text-subtle"}`}
                              aria-hidden="true"
                            />
                          )}
                          <span className="truncate font-mono text-xs">{directorySegment(node.path)}</span>
                          {pathInterest && (
                            <span
                              data-testid="rule-based-path-interest"
                              data-rule-based-path-interest-root={pathInterest.matchedRoot}
                              role="img"
                              aria-label={pathInterestAccessibleText ?? pathInterest.label}
                              title={pathInterestAccessibleText ?? pathInterest.label}
                              className="flex h-4 w-4 shrink-0 items-center justify-center text-warning"
                            >
                              <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                              <span className="sr-only">{pathInterestAccessibleText}</span>
                            </span>
                          )}
                          {isHopTarget && activeHop ? (
                            <span
                              data-testid="active-hop-target-badge"
                              className="flex shrink-0 items-center gap-0.5 rounded bg-primary px-1.5 py-0.5 font-mono text-xs font-bold text-surface shadow-xs"
                              title={`Current hop target (${activeHop.stepIndex + 1}/${activeHop.totalSteps})`}
                            >
                              <Route className="h-2.5 w-2.5" aria-hidden="true" />
                              <span>Hop {activeHop.stepIndex + 1}</span>
                            </span>
                          ) : isHopVisited && visitedStep !== undefined ? (
                            <span
                              className="shrink-0 rounded border border-primary/30 bg-primary/10 px-1 py-0.5 font-mono text-xs font-semibold text-primary"
                              title={`Route step ${visitedStep}`}
                            >
                              #{visitedStep}
                            </span>
                          ) : null}
                          {(node.hiddenChildCount ?? 0) > 0 && (
                            <span
                              data-testid="topology-aggregate-indicator"
                              data-aggregate-path={node.path}
                              className="shrink-0 rounded-full border border-primary/40 bg-primary/10 px-1.5 py-0.5 font-mono text-xs font-bold text-primary"
                              title={`${node.hiddenChildCount} child ${node.hiddenChildCount === 1 ? "directory" : "directories"} aggregated under this path. Click to expand.`}
                            >
                              +{node.hiddenChildCount}
                            </span>
                          )}
                          {!isAuditMode && (
                            <span
                              className="rounded-full border border-border bg-surface-subtle px-1.5 text-xs font-semibold text-text-subtle"
                              title={`${exactCount} at exact path, ${descendantCount} in child directories (${branchCount} across branch)`}
                            >
                              {exactCount > 0 && descendantCount > 0
                                ? `${exactCount} (${branchCount})`
                                : exactCount > 0
                                  ? exactCount
                                  : descendantCount > 0
                                    ? `↳${branchCount}`
                                    : 0}
                            </span>
                          )}
                        </motion.button>
                      );
                    })}
                  </AnimatePresence>
                  <AnimatePresence initial={false}>
                    {graphCallouts.map((callout, index) => {
                      const position = positionForCallout(callout, index);
                      const isClusterSelected = callout.sessionIds.includes(selectedSessionId ?? "");
                      const isOverlapping = overlappingCalloutIps.has(callout.sourceIp);
                      const isMulti = callout.sessions?.length > 1;
                      const expanded = isClusterExpanded(callout);

                      return (
                        <motion.div
                          key={`callout-${callout.sourceIp}`}
                          ref={(element) => {
                            if (element) calloutElementRefs.current.set(callout.sourceIp, element);
                            else calloutElementRefs.current.delete(callout.sourceIp);
                          }}
                          initial={reducedMotion ? false : { opacity: 0, scale: 0.94 }}
                          animate={{ left: `${position.x}%`, top: `${position.y}%`, opacity: 1, scale: 1 }}
                          exit={reducedMotion ? undefined : { opacity: 0, scale: 0.94 }}
                          transition={
                            reducedMotion || draggedCalloutIp === callout.sourceIp
                              ? { duration: 0 }
                              : {
                                  left: TOPOLOGY_TRANSITION,
                                  top: TOPOLOGY_TRANSITION,
                                  opacity: { duration: 0.3, ease: "easeOut" },
                                  scale: { duration: 0.3, ease: "easeOut" },
                              }
                          }
                          onAnimationComplete={measureElementBounds}
                          onPointerDown={(event) => onCalloutPointerDown(event, callout.sourceIp, position)}
                          onPointerMove={onCalloutPointerMove}
                          onPointerUp={onCalloutPointerEnd}
                          onPointerCancel={onCalloutPointerEnd}
                          className={`absolute z-40 flex flex-col -translate-x-1/2 -translate-y-6 touch-none rounded-xl border text-left shadow-sm transition-colors duration-200 ${
                            isMulti ? "w-44 sm:w-52" : "w-36"
                          } ${isArrangeMode ? "cursor-grab active:cursor-grabbing" : ""} ${
                            isOverlapping
                              ? "border-warning bg-warning-subtle/60 text-text ring-2 ring-warning/80 shadow-md shadow-warning/20"
                              : isClusterSelected
                                ? "border-primary-border bg-surface ring-1 ring-primary/40 shadow-md"
                                : "border-border bg-surface hover:border-border-strong hover:bg-surface-hover"
                          }`}
                        >
                          {isOverlapping && (
                            <span
                              className="pointer-events-none absolute -top-1.5 -right-1.5 z-50 flex h-4 w-4 items-center justify-center rounded-full bg-warning text-surface shadow ring-1 ring-surface"
                              title="Overlapping position with another node"
                              aria-label="Overlapping position with another node"
                            >
                              <AlertTriangle className="h-2.5 w-2.5 stroke-[2.5]" aria-hidden="true" />
                            </span>
                          )}

                          {/* Main Callout Trigger */}
                          <button
                            ref={(element) => {
                              if (element) calloutAnchorElementRefs.current.set(callout.sourceIp, element);
                              else calloutAnchorElementRefs.current.delete(callout.sourceIp);
                            }}
                            type="button"
                            aria-pressed={isClusterSelected}
                            aria-expanded={isMulti ? expanded : undefined}
                            aria-haspopup={isMulti ? "listbox" : undefined}
                            aria-label={`Source ${callout.sourceIp}; ${callout.sessionIds.length} ${
                              callout.sessionIds.length === 1 ? "session" : "sessions"
                            }${isMulti ? (expanded ? "; cluster expanded" : "; click to expand sessions") : ""}`}
                            onClick={() => {
                              if (consumeCalloutClickSuppression()) return;
                              if (isArrangeMode) return;
                              if (!isMulti) {
                                onSelectSession(callout.sessionIds[0]);
                              } else {
                                if (!isClusterSelected) {
                                  holdViewportSteady();
                                  onSelectSession(callout.sessions[0].sessionId);
                                  setUserCollapsedIps((prev) => {
                                    const next = new Set(prev);
                                    next.delete(callout.sourceIp);
                                    return next;
                                  });
                                  setUserExpandedIps((prev) => new Set(prev).add(callout.sourceIp));
                                } else {
                                  toggleClusterExpand(callout.sourceIp, expanded);
                                }
                              }
                            }}
                            onKeyDown={(event) => {
                              if (isMulti && event.key === "ArrowDown") {
                                event.preventDefault();
                                if (!expanded) {
                                  toggleClusterExpand(callout.sourceIp, false);
                                }
                                const firstId = callout.sessions[0]?.sessionId;
                                if (firstId) {
                                  window.requestAnimationFrame(() => {
                                    clusterSessionRefs.current.get(`${callout.sourceIp}:${firstId}`)?.focus();
                                  });
                                }
                              }
                            }}
                            className={`flex w-full items-center justify-between gap-1.5 p-2 rounded-xl text-left cursor-pointer transition-colors ${
                              isClusterSelected && !isMulti ? "bg-primary-subtle" : ""
                            }`}
                          >
                            <div className="flex items-center gap-1.5 min-w-0">
                              <span
                                className={`h-2 w-2 shrink-0 rounded-full ${
                                  streamState === "live" ? "bg-success" : "bg-warning"
                                }`}
                                aria-hidden="true"
                              />
                              <div className="min-w-0">
                                <span className="block truncate font-mono text-xs font-semibold text-text" title={callout.sourceIp}>
                                  {callout.sourceIp}
                                </span>
                                <span className="mt-0.5 flex items-center gap-1 text-xs text-text-subtle">
                                  <span>
                                    {callout.sessionIds.length} {callout.sessionIds.length === 1 ? "session" : "sessions"}
                                  </span>
                                  {isMulti && (
                                    <>
                                      <span>·</span>
                                      <span className="font-semibold text-text-muted">
                                        {callout.targetPaths.length} {callout.targetPaths.length === 1 ? "path" : "paths"}
                                      </span>
                                    </>
                                  )}
                                </span>
                              </div>
                            </div>
                            {isMulti && (
                              <ChevronDown
                                className={`h-3.5 w-3.5 text-text-subtle shrink-0 transition-transform duration-200 ${
                                  expanded ? "rotate-180 text-primary" : ""
                                }`}
                                aria-hidden="true"
                              />
                            )}
                          </button>

                          {/* Multi-Session Cluster Disclosure Panel */}
                          <AnimatePresence initial={false}>
                            {isMulti && expanded && (
                              <motion.div
                                initial={reducedMotion ? { opacity: 0 } : { height: 0, opacity: 0 }}
                                animate={reducedMotion ? { opacity: 1 } : { height: "auto", opacity: 1 }}
                                exit={reducedMotion ? { opacity: 0 } : { height: 0, opacity: 0 }}
                                transition={{ duration: reducedMotion ? 0 : 0.2, ease: "easeOut" }}
                                role="listbox"
                                aria-label={`Active sessions for ${callout.sourceIp}`}
                                className="border-t border-border/70 bg-surface-subtle/60 rounded-b-xl overflow-hidden origin-top"
                              >
                                <div className="p-1.5 space-y-1 max-h-48 overflow-y-auto overscroll-contain">
                              {callout.sessions.map((sess, sIdx) => {
                                const isSessSelected = sess.sessionId === selectedSessionId;
                                return (
                                  <button
                                    key={sess.sessionId}
                                    ref={(el) => {
                                      if (el) clusterSessionRefs.current.set(`${callout.sourceIp}:${sess.sessionId}`, el);
                                      else clusterSessionRefs.current.delete(`${callout.sourceIp}:${sess.sessionId}`);
                                    }}
                                    type="button"
                                    role="option"
                                    aria-selected={isSessSelected}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      if (isArrangeMode) return;
                                      onSelectSession(sess.sessionId);
                                    }}
                                    onKeyDown={(e) => {
                                      if (e.key === "ArrowDown") {
                                        e.preventDefault();
                                        const nextIdx = (sIdx + 1) % callout.sessions.length;
                                        const nextId = callout.sessions[nextIdx].sessionId;
                                        clusterSessionRefs.current.get(`${callout.sourceIp}:${nextId}`)?.focus();
                                      } else if (e.key === "ArrowUp") {
                                        e.preventDefault();
                                        if (sIdx === 0) {
                                          calloutElementRefs.current.get(callout.sourceIp)?.querySelector("button")?.focus();
                                        } else {
                                          const prevId = callout.sessions[sIdx - 1].sessionId;
                                          clusterSessionRefs.current.get(`${callout.sourceIp}:${prevId}`)?.focus();
                                        }
                                      } else if (e.key === "Escape") {
                                        e.preventDefault();
                                        toggleClusterExpand(callout.sourceIp, true);
                                        calloutElementRefs.current.get(callout.sourceIp)?.querySelector("button")?.focus();
                                      }
                                    }}
                                    className={`flex w-full items-center justify-between gap-1.5 rounded-lg px-2 py-1 text-left text-xs font-mono transition-colors cursor-pointer ${
                                      isSessSelected
                                        ? "bg-primary-subtle text-primary font-semibold border border-primary-border/60 shadow-2xs"
                                        : "text-text hover:bg-surface-hover hover:text-text border border-transparent"
                                    }`}
                                  >
                                    <div className="flex items-center gap-1.5 truncate min-w-0">
                                      <span
                                        className={`h-1.5 w-1.5 rounded-full shrink-0 ${
                                          isSessSelected ? "bg-primary animate-pulse" : "bg-text-subtle/50"
                                        }`}
                                      />
                                      <span className="truncate text-text-muted">{sess.sessionId.slice(0, 8)}…</span>
                                      <span
                                        className={`truncate px-1 py-0.2 rounded text-xs border ${
                                          isSessSelected
                                            ? "bg-surface text-primary border-primary-border"
                                            : "bg-surface text-text-subtle border-border/50"
                                        }`}
                                        title={sess.path}
                                      >
                                        {compactDirectoryPath(sess.path)}
                                      </span>
                                    </div>
                                    {isSessSelected && (
                                      <Check className="h-3 w-3 text-primary shrink-0" aria-hidden="true" />
                                    )}
                                  </button>
                                );
                              })}
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </motion.div>
                      );
                    })}
                  </AnimatePresence>
                </motion.div>

                <AnimatePresence>
                  {showMinimap && (
                    <TopologyMinimap
                      graphNodes={graphNodes}
                      graphNodeByPath={graphNodeByPath}
                      graphCallouts={graphCallouts}
                      selectedPath={selectedPath}
                      selectedSessionId={selectedSessionId}
                      minimapViewport={minimapViewport}
                      positionForCallout={positionForCallout}
                      onFit={fitTopology}
                    />
                  )}
                </AnimatePresence>
              </div>

              <TopologySummaryBar
                densityAnalysisHiddenNodes={densityAnalysis.hiddenNodes}
                densityAnalysisRenderedNodes={densityAnalysis.renderedNodes}
                densityAnalysisTotalNodes={densityAnalysis.totalNodes}
                densityPreference={densityPreference}
                effectiveSessionsLength={effectiveSessions.length}
                isSourcesTruncated={totalLiveSources > renderedSourcesCount}
                renderedSourcesCount={renderedSourcesCount}
                totalLiveSources={totalLiveSources}
                isSourcesExpanded={isSourcesExpanded}
                setIsSourcesExpanded={setIsSourcesExpanded}
                totalOverlaps={totalOverlaps}
                {...(presentationContext.mode === "live"
                  ? {
                      presentationContext,
                      snapshotGeneratedAt: snapshot.generatedAt,
                      freshnessState,
                      staleThresholdMs,
                    }
                  : {
                      presentationContext,
                    })}
              />
              {snapshot.truncated && (
                <div className="flex shrink-0 gap-2 border-t border-warning-border bg-warning-subtle px-5 py-3 text-xs text-text-muted">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                  <p>
                    Showing the latest {snapshot.sessions.length} observed sessions. Live stream reached server limit (500). Older sessions are retained in Audit history.
                  </p>
                </div>
              )}
            </div>

            {isStandaloneExpanded && (
              <aside
                className="min-h-0 overflow-y-auto border-t border-border bg-surface p-5 lg:border-l lg:border-t-0"
                aria-label="Expanded map controls"
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.12em] text-primary">Map controls</p>
                    <h3 className="mt-1 font-semibold text-text">
                      Live source clusters ({graphCallouts.length}/{allSourceClusters.length} on map)
                    </h3>
                  </div>
                  <span
                    className={`ui-badge ${
                      streamState === "live"
                        ? "border-success-border bg-success-subtle text-success"
                        : "border-warning-border bg-warning-subtle text-warning"
                    }`}
                  >
                    {streamState === "live" ? "Live" : "Reconnecting"}
                  </span>
                </div>
                <p className="mt-3 text-xs text-text-subtle">
                  Choose an IP to fan its leader line out to every current verified path. Switch to Arrange to drag
                  directories and IP labels. Auto arrange rebuilds the subtree layout, returns sources to their rails,
                  and recenters the camera; undo restores this workspace. Press Escape to exit this workspace.
                </p>
                <button type="button" className="ui-button mt-4 w-full" onClick={autoArrangeTopology}>
                  <ScanLine className="h-4 w-4" />
                  Auto arrange topology
                </button>
                {canUndoLayout && (
                  <button type="button" className="ui-button mt-2 w-full" onClick={undoLayoutChange}>
                    <Undo2 className="h-4 w-4" />
                    Undo layout change
                  </button>
                )}
                <button type="button" className="ui-button mt-2 w-full" onClick={resetMapWorkspace}>
                  <RotateCcw className="h-4 w-4" />
                  Restore default workspace
                </button>
                {allSourceClusters.length > GRAPH_CALLOUT_LIMIT && (
                  <div className="mt-4 flex items-center justify-between rounded-lg border border-border bg-surface-subtle p-2.5 text-xs">
                    <span className="text-text-muted">
                      {isSourcesExpanded
                        ? `All ${allSourceClusters.length} sources rendered on map`
                        : `Showing top ${graphCallouts.length} of ${allSourceClusters.length} sources`}
                    </span>
                    <button
                      type="button"
                      onClick={() => setIsSourcesExpanded((prev) => !prev)}
                      className="rounded border border-primary-border bg-primary-subtle px-2 py-1 text-xs font-medium text-primary hover:bg-primary/20 transition-colors"
                    >
                      {isSourcesExpanded ? `Limit to ${GRAPH_CALLOUT_LIMIT}` : "Show all on map"}
                    </button>
                  </div>
                )}
                <div className="mt-4 space-y-2">
                  {allSourceClusters.map((callout) => {
                    const isRendered = graphCallouts.some((c) => c.sourceIp === callout.sourceIp);
                    const selected = callout === selectedGraphCallout;
                    return (
                      <button
                        key={`control-${callout.sourceIp}`}
                        type="button"
                        aria-pressed={selected}
                        onClick={() => onSelectSession(callout.sessionIds[0])}
                        className={`w-full rounded-lg border px-3 py-3 text-left transition-colors duration-150 ${
                          selected
                            ? "border-primary-border bg-primary-subtle"
                            : "border-border hover:border-border-strong hover:bg-surface-hover"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-mono text-xs text-text">{callout.sourceIp}</span>
                          <div className="flex items-center gap-1.5">
                            {!isRendered && (
                              <span className="ui-badge border-warning-border bg-warning-subtle text-xs text-warning">
                                Omitted (limit)
                              </span>
                            )}
                            <span className="ui-badge border-info-border bg-info-subtle text-info">
                              {callout.sessionIds.length}
                            </span>
                          </div>
                        </div>
                        <p className="mt-1 truncate font-mono text-xs text-text-muted">Latest: {callout.path}</p>
                      </button>
                    );
                  })}
                </div>
                {selectedGraphCallout && (
                  <div className="mt-5 border-t border-border pt-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">Selected IP paths</p>
                    <div className="mt-3 space-y-2">
                      {selectedGraphCallout.sessionIds.map((sessionId) => {
                        const session = liveSessionById.get(sessionId);
                        return (
                          <button
                            key={sessionId}
                            type="button"
                            onClick={() => onSelectSession(sessionId)}
                            className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left transition-colors duration-150 ${
                              sessionId === selectedSessionId
                                ? "border-primary-border bg-primary-subtle"
                                : "border-border hover:bg-surface-hover"
                            }`}
                          >
                            <span className="min-w-0">
                              <span className="block truncate font-mono text-xs text-text">
                                {session?.cwdState.path ?? "Unknown"}
                              </span>
                              <span className="mt-0.5 block truncate font-mono text-xs text-text-subtle">
                                {sessionId}
                              </span>
                            </span>
                            <ChevronRight className="h-4 w-4 shrink-0 text-text-subtle" />
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </aside>
            )}
          </div>
        </>
      )}
    </div>
  );
}
