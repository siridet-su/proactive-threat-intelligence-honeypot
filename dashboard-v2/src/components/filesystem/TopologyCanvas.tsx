"use client";

import { motion, useReducedMotion } from "framer-motion";
import {
  ChevronRight,
  Crosshair,
  Grip,
  LocateFixed,
  Maximize2,
  Minimize2,
  MousePointer2,
  Route,
  ScanLine,
  ShieldAlert,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
} from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import { TopologyMinimap } from "./TopologyMinimap";
import {
  calloutsForGraph,
  calloutSlot,
  formatTimestamp,
  leaderEndpoints,
  MAP_MAX_ZOOM,
  MAP_MIN_ZOOM,
  pointForGraph,
  snapLabelPosition,
  type GraphCallout,
  type LabelDrag,
  type LabelPosition,
  type MapMetrics,
  type Pan,
  type StreamState,
} from "./filesystemUtils";

const LABEL_LAYOUT_STORAGE_KEY = "pti-filesystem-label-layout-v1";

interface TopologyCanvasProps {
  snapshot: FilesystemTopologySnapshot | null;
  regionStatus: RegionStatus;
  streamState: StreamState;
  selectedSessionId: string | null;
  selectedPath: string | null;
  onSelectSession: (sessionId: string) => void;
  onSelectPath: (path: string | null) => void;
}

export function TopologyCanvas({
  snapshot,
  regionStatus,
  streamState,
  selectedSessionId,
  selectedPath,
  onSelectSession,
  onSelectPath,
}: TopologyCanvasProps) {
  const reducedMotion = useReducedMotion();
  const [pan, setPan] = useState<Pan>({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [isDraggingSurface, setIsDraggingSurface] = useState(false);
  const [isTopologyExpanded, setIsTopologyExpanded] = useState(false);
  const [labelPositions, setLabelPositions] = useState<Record<string, LabelPosition>>({});
  const [mapMetrics, setMapMetrics] = useState<MapMetrics | null>(null);

  const dragStart = useRef<{ x: number; y: number; pan: Pan } | null>(null);
  const panRef = useRef<Pan>({ x: 0, y: 0 });
  const zoomRef = useRef(1);
  const mapSurfaceRef = useRef<HTMLDivElement>(null);
  const graphPlaneRef = useRef<HTMLDivElement>(null);
  const labelDrag = useRef<LabelDrag | null>(null);
  const suppressCalloutClick = useRef(false);
  const labelLayoutReady = useRef(false);

  // Restore label layout from localStorage
  useEffect(() => {
    const restore = window.setTimeout(() => {
      try {
        const raw = window.localStorage.getItem(LABEL_LAYOUT_STORAGE_KEY);
        const parsed: unknown = raw ? JSON.parse(raw) : {};
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          const restored = Object.fromEntries(
            Object.entries(parsed).flatMap(([sourceIp, position]) => {
              if (!position || typeof position !== "object" || Array.isArray(position)) return [];
              const candidate = position as Partial<LabelPosition>;
              return typeof candidate.x === "number" && typeof candidate.y === "number"
                ? [[sourceIp, snapLabelPosition({ x: candidate.x, y: candidate.y })]]
                : [];
            }),
          );
          setLabelPositions(restored);
        }
      } catch {
        window.localStorage.removeItem(LABEL_LAYOUT_STORAGE_KEY);
      } finally {
        labelLayoutReady.current = true;
      }
    }, 0);
    return () => window.clearTimeout(restore);
  }, []);

  // Save label layout to localStorage
  useEffect(() => {
    if (!labelLayoutReady.current) return;
    window.localStorage.setItem(LABEL_LAYOUT_STORAGE_KEY, JSON.stringify(labelPositions));
  }, [labelPositions]);

  // Derived graph layout
  const graphNodes = useMemo(
    () => pointForGraph(snapshot?.nodes ?? [], snapshot?.sessions ?? [], selectedPath),
    [selectedPath, snapshot?.nodes, snapshot?.sessions],
  );
  const graphNodeByPath = useMemo(() => new Map(graphNodes.map((node) => [node.path, node])), [graphNodes]);
  const graphCallouts = useMemo(
    () => calloutsForGraph(snapshot?.sessions ?? [], graphNodeByPath, selectedSessionId),
    [graphNodeByPath, selectedSessionId, snapshot?.sessions],
  );
  const liveSessionById = useMemo(
    () => new Map((snapshot?.sessions ?? []).map((session) => [session.sessionId, session])),
    [snapshot?.sessions],
  );
  const selectedGraphCallout = useMemo(
    () => graphCallouts.find((callout) => callout.sessionIds.includes(selectedSessionId ?? "")) ?? null,
    [graphCallouts, selectedSessionId],
  );
  const liveSourceCount = useMemo(
    () => new Set((snapshot?.sessions ?? []).map((session) => session.sourceIp)).size,
    [snapshot?.sessions],
  );

  const setMapZoom = useCallback((value: number, focalPoint?: Pan) => {
    const nextZoom = Math.min(MAP_MAX_ZOOM, Math.max(MAP_MIN_ZOOM, Number(value.toFixed(3))));
    const currentZoom = zoomRef.current;
    const currentPan = panRef.current;
    const nextPan = focalPoint
      ? {
          x: focalPoint.x - ((focalPoint.x - currentPan.x) / currentZoom) * nextZoom,
          y: focalPoint.y - ((focalPoint.y - currentPan.y) / currentZoom) * nextZoom,
        }
      : currentPan;
    zoomRef.current = nextZoom;
    panRef.current = nextPan;
    setZoom(nextZoom);
    setPan(nextPan);
  }, []);

  const resetViewport = () => {
    panRef.current = { x: 0, y: 0 };
    zoomRef.current = 1;
    setPan(panRef.current);
    setZoom(zoomRef.current);
  };

  const resetLabelLayout = () => {
    setLabelPositions({});
    window.localStorage.removeItem(LABEL_LAYOUT_STORAGE_KEY);
  };

  const resetMapWorkspace = () => {
    resetViewport();
    resetLabelLayout();
  };

  const fitTopology = () => resetViewport();

  const positionForCallout = useCallback(
    (callout: GraphCallout, index: number): LabelPosition =>
      labelPositions[callout.sourceIp] ?? calloutSlot(index, graphCallouts.length),
    [graphCallouts.length, labelPositions],
  );

  const centerMapOn = (position: LabelPosition) => {
    const surface = mapSurfaceRef.current;
    const plane = graphPlaneRef.current;
    if (!surface || !plane) return;
    const nextPan = {
      x: surface.clientWidth / 2 - plane.offsetLeft - ((plane.offsetWidth * position.x) / 100) * zoomRef.current,
      y: surface.clientHeight / 2 - plane.offsetTop - ((plane.offsetHeight * position.y) / 100) * zoomRef.current,
    };
    panRef.current = nextPan;
    setPan(nextPan);
  };

  const centerSelectedSource = () => {
    if (!selectedGraphCallout) return;
    const index = graphCallouts.findIndex((callout) => callout.sourceIp === selectedGraphCallout.sourceIp);
    if (index < 0) return;
    centerMapOn(positionForCallout(selectedGraphCallout, index));
  };

  // Label dragging handlers
  const onCalloutPointerDown = (event: ReactPointerEvent<HTMLButtonElement>, sourceIp: string, origin: LabelPosition) => {
    event.stopPropagation();
    event.currentTarget.focus();
    suppressCalloutClick.current = false;
    event.currentTarget.setPointerCapture(event.pointerId);
    labelDrag.current = { sourceIp, startX: event.clientX, startY: event.clientY, origin };
  };

  const onCalloutPointerMove = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const dragging = labelDrag.current;
    const plane = graphPlaneRef.current;
    if (!dragging || !plane) return;
    const rect = plane.getBoundingClientRect();
    if (!rect.width || !rect.height) return;
    const deltaX = ((event.clientX - dragging.startX) / rect.width) * 100;
    const deltaY = ((event.clientY - dragging.startY) / rect.height) * 100;
    if (Math.abs(deltaX) > 0.25 || Math.abs(deltaY) > 0.25) suppressCalloutClick.current = true;
    setLabelPositions((current) => ({
      ...current,
      [dragging.sourceIp]: {
        x: Math.min(94, Math.max(6, dragging.origin.x + deltaX)),
        y: Math.min(94, Math.max(6, dragging.origin.y + deltaY)),
      },
    }));
  };

  const onCalloutPointerEnd = (event: ReactPointerEvent<HTMLButtonElement>) => {
    const dragging = labelDrag.current;
    if (dragging) {
      setLabelPositions((current) => ({
        ...current,
        [dragging.sourceIp]: snapLabelPosition(current[dragging.sourceIp] ?? dragging.origin),
      }));
    }
    labelDrag.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  // Surface pan handlers
  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest("button")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    dragStart.current = { x: event.clientX, y: event.clientY, pan: panRef.current };
    setIsDraggingSurface(true);
  };

  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!dragStart.current) return;
    const nextPan = {
      x: dragStart.current.pan.x + event.clientX - dragStart.current.x,
      y: dragStart.current.pan.y + event.clientY - dragStart.current.y,
    };
    panRef.current = nextPan;
    setPan(nextPan);
  };

  const onPointerEnd = (event: ReactPointerEvent<HTMLDivElement>) => {
    dragStart.current = null;
    setIsDraggingSurface(false);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  // Keyboard navigation
  const onSurfaceKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(event.key)) {
      event.preventDefault();
      const step = 40;
      setPan((current) => {
        const next = {
          x: event.key === "ArrowLeft" ? current.x + step : event.key === "ArrowRight" ? current.x - step : current.x,
          y: event.key === "ArrowUp" ? current.y + step : event.key === "ArrowDown" ? current.y - step : current.y,
        };
        panRef.current = next;
        return next;
      });
    }
  };

  // Wheel zoom
  useEffect(() => {
    const surface = mapSurfaceRef.current;
    if (!surface) return;
    const onWheel = (event: WheelEvent) => {
      const plane = graphPlaneRef.current;
      if (!plane) return;
      event.preventDefault();
      const bounds = surface.getBoundingClientRect();
      setMapZoom(zoomRef.current * Math.exp(-event.deltaY * 0.0015), {
        x: event.clientX - bounds.left - plane.offsetLeft,
        y: event.clientY - bounds.top - plane.offsetTop,
      });
    };
    surface.addEventListener("wheel", onWheel, { passive: false });
    return () => surface.removeEventListener("wheel", onWheel);
  }, [isTopologyExpanded, setMapZoom, snapshot?.nodes.length]);

  // Touch pinch zoom
  useEffect(() => {
    const surface = mapSurfaceRef.current;
    if (!surface) return;
    let initialDistance: number | null = null;
    let initialZoom = 1;

    const onTouchStart = (e: TouchEvent) => {
      if (e.touches.length === 2) {
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        initialDistance = Math.hypot(dx, dy);
        initialZoom = zoomRef.current;
      }
    };

    const onTouchMove = (e: TouchEvent) => {
      if (e.touches.length === 2 && initialDistance) {
        e.preventDefault();
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        const currentDistance = Math.hypot(dx, dy);
        const factor = currentDistance / initialDistance;
        setMapZoom(initialZoom * factor);
      }
    };

    const onTouchEnd = (e: TouchEvent) => {
      if (e.touches.length < 2) initialDistance = null;
    };

    surface.addEventListener("touchstart", onTouchStart, { passive: true });
    surface.addEventListener("touchmove", onTouchMove, { passive: false });
    surface.addEventListener("touchend", onTouchEnd, { passive: true });

    return () => {
      surface.removeEventListener("touchstart", onTouchStart);
      surface.removeEventListener("touchmove", onTouchMove);
      surface.removeEventListener("touchend", onTouchEnd);
    };
  }, [setMapZoom]);

  // ResizeObserver for metrics
  useEffect(() => {
    const surface = mapSurfaceRef.current;
    const plane = graphPlaneRef.current;
    if (!surface || !plane) return;
    const measure = () => {
      setMapMetrics({
        surfaceWidth: surface.clientWidth,
        surfaceHeight: surface.clientHeight,
        planeWidth: plane.offsetWidth,
        planeHeight: plane.offsetHeight,
        planeLeft: plane.offsetLeft,
        planeTop: plane.offsetTop,
      });
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(surface);
    observer.observe(plane);
    return () => observer.disconnect();
  }, [isTopologyExpanded, snapshot?.nodes.length]);

  // Minimap viewport box calculation
  const minimapViewport = useMemo(() => {
    if (!mapMetrics || !mapMetrics.planeWidth || !mapMetrics.planeHeight) return null;
    const rawLeft = ((-mapMetrics.planeLeft - pan.x) / (zoom * mapMetrics.planeWidth)) * 100;
    const rawTop = ((-mapMetrics.planeTop - pan.y) / (zoom * mapMetrics.planeHeight)) * 100;
    const rawRight = rawLeft + (mapMetrics.surfaceWidth / (zoom * mapMetrics.planeWidth)) * 100;
    const rawBottom = rawTop + (mapMetrics.surfaceHeight / (zoom * mapMetrics.planeHeight)) * 100;
    const left = Math.min(100, Math.max(0, rawLeft));
    const top = Math.min(100, Math.max(0, rawTop));
    const right = Math.min(100, Math.max(0, rawRight));
    const bottom = Math.min(100, Math.max(0, rawBottom));
    return {
      x: left === right ? Math.min(98, left) : left,
      y: top === bottom ? Math.min(98, top) : top,
      width: Math.max(2, right - left),
      height: Math.max(2, bottom - top),
    };
  }, [mapMetrics, pan, zoom]);

  // Escape key exits expanded workspace
  useEffect(() => {
    if (!isTopologyExpanded) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setIsTopologyExpanded(false);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [isTopologyExpanded]);

  return (
    <div
      className={`ui-panel overflow-hidden ${
        isTopologyExpanded ? "fixed inset-3 z-50 flex flex-col bg-surface" : ""
      }`}
      aria-busy={regionStatus === "loading"}
    >
      <div className="flex flex-col gap-3 border-b border-border p-5 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Route className="h-4 w-4 text-primary" aria-hidden="true" />
            <h2 className="font-semibold text-text">Live filesystem topology</h2>
          </div>
          <p className="mt-1 text-xs text-text-subtle">
            Observed paths form the topology; compact source-IP clusters point to their most recently verified location.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <button
            type="button"
            className="ui-button h-9 min-h-9 w-9 p-0"
            title="Zoom out"
            aria-label="Zoom out"
            onClick={() => setMapZoom(zoomRef.current - 0.1)}
          >
            <ZoomOut className="h-4 w-4" />
          </button>
          <span
            className="ui-badge h-9 min-w-12 justify-center font-mono tabular-nums"
            aria-live="polite"
            aria-label={`Zoom ${Math.round(zoom * 100)} percent`}
          >
            {Math.round(zoom * 100)}%
          </span>
          <button
            type="button"
            className="ui-button h-9 min-h-9 w-9 p-0"
            title="Zoom in"
            aria-label="Zoom in"
            onClick={() => setMapZoom(zoomRef.current + 0.1)}
          >
            <ZoomIn className="h-4 w-4" />
          </button>
          <button
            type="button"
            className="ui-button h-9 min-h-9 w-9 p-0"
            title="Fit topology"
            aria-label="Fit topology in view"
            onClick={fitTopology}
          >
            <ScanLine className="h-4 w-4" />
          </button>
          <button
            type="button"
            className="ui-button h-9 min-h-9 w-9 p-0"
            title="Center selected IP"
            aria-label="Center selected IP"
            disabled={!selectedGraphCallout}
            onClick={centerSelectedSource}
          >
            <LocateFixed className="h-4 w-4" />
          </button>
          <button
            type="button"
            className="ui-button h-9 min-h-9 w-9 p-0"
            title="Reset map and label layout"
            aria-label="Reset map view and label layout"
            onClick={resetMapWorkspace}
          >
            <MousePointer2 className="h-4 w-4" />
          </button>
          <button
            type="button"
            className="ui-button h-9 min-h-9 w-9 p-0"
            title={isTopologyExpanded ? "Exit expanded map" : "Expand map workspace"}
            aria-label={isTopologyExpanded ? "Exit expanded map" : "Expand map workspace"}
            aria-pressed={isTopologyExpanded}
            onClick={() => setIsTopologyExpanded((expanded) => !expanded)}
          >
            {isTopologyExpanded ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {regionStatus === "error" ? (
        <div className="p-5">
          <RegionState
            kind="error"
            title="Filesystem activity unavailable"
            description="The topology could not be loaded. Other dashboard views remain available."
          />
        </div>
      ) : regionStatus === "loading" && !snapshot ? (
        <div className="p-5">
          <RegionState kind="loading" title="Loading filesystem activity" />
        </div>
      ) : !snapshot?.nodes.length ? (
        <div className="p-5">
          <RegionState
            kind="empty"
            title="No observed working directories yet"
            description="The live view will populate after verified CWD telemetry is recorded."
          />
        </div>
      ) : (
        <>
          <div className={isTopologyExpanded ? "grid min-h-0 flex-1 lg:grid-cols-[minmax(0,1fr)_20rem]" : ""}>
            <div className={isTopologyExpanded ? "flex min-h-0 min-w-0 flex-col" : ""}>
              <div
                ref={mapSurfaceRef}
                tabIndex={0}
                role="region"
                aria-label="Filesystem topology map workspace. Use arrow keys to pan, scroll or pinch to zoom."
                onKeyDown={onSurfaceKeyDown}
                className={`relative overflow-hidden bg-surface-subtle p-5 sm:p-8 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${
                  isTopologyExpanded ? "min-h-[540px] flex-1" : "min-h-[540px]"
                }`}
                onPointerDown={onPointerDown}
                onPointerMove={onPointerMove}
                onPointerUp={onPointerEnd}
                onPointerCancel={onPointerEnd}
              >
                <div
                  className="pointer-events-none absolute inset-0 opacity-50 [background-image:linear-gradient(var(--border)_1px,transparent_1px),linear-gradient(90deg,var(--border)_1px,transparent_1px)] [background-size:28px_28px]"
                  aria-hidden="true"
                />
                <div className="pointer-events-none absolute left-5 top-5 flex items-center gap-2 text-xs text-text-subtle">
                  <Grip className="h-3.5 w-3.5" aria-hidden="true" />
                  Drag surface to pan · Scroll or pinch to zoom · Drag IP labels freely
                </div>
                <motion.div
                  ref={graphPlaneRef}
                  className={`relative origin-top-left ${isTopologyExpanded ? "h-full min-h-[500px]" : "h-[500px]"}`}
                  animate={reducedMotion ? undefined : { x: pan.x, y: pan.y, scale: zoom }}
                  style={reducedMotion ? { transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})` } : undefined}
                  transition={
                    reducedMotion || isDraggingSurface ? { duration: 0 } : { type: "spring", stiffness: 260, damping: 28 }
                  }
                >
                  <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 h-full w-full" aria-hidden="true">
                    {graphNodes.map((node) => {
                      const parent = node.parentPath ? graphNodeByPath.get(node.parentPath) : null;
                      if (!parent) return null;
                      return (
                        <path
                          key={`${parent.path}-${node.path}`}
                          d={`M ${parent.x} ${parent.y} C ${parent.x} ${(parent.y + node.y) / 2}, ${node.x} ${(parent.y + node.y) / 2}, ${node.x} ${node.y}`}
                          fill="none"
                          stroke="var(--border-strong)"
                          strokeWidth="0.35"
                        />
                      );
                    })}
                  </svg>
                  <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 z-30 h-full w-full overflow-visible" aria-hidden="true">
                    {graphCallouts.map((callout, index) => {
                      const position = positionForCallout(callout, index);
                      const selected = callout.sessionIds.includes(selectedSessionId ?? "");
                      const targetPaths = selected
                        ? [...new Set(callout.sessionIds.map((sessionId) => liveSessionById.get(sessionId)?.cwdState.path).filter((path): path is string => Boolean(path)))]
                        : [callout.path];
                      return (
                        <g key={`leader-${callout.sourceIp}`}>
                          {targetPaths.map((path) => {
                            const node = graphNodeByPath.get(path);
                            if (!node) return null;
                            const endpoint = leaderEndpoints(node, position);
                            const controlX = (endpoint.startX + endpoint.endX) / 2;
                            return (
                              <g key={path}>
                                <path
                                  d={`M ${endpoint.startX} ${endpoint.startY} C ${controlX} ${endpoint.startY}, ${controlX} ${endpoint.endY}, ${endpoint.endX} ${endpoint.endY}`}
                                  fill="none"
                                  stroke="var(--primary)"
                                  strokeWidth={selected ? "0.42" : "0.32"}
                                  strokeDasharray={selected ? "none" : "1.1 1.4"}
                                />
                                <circle
                                  cx={endpoint.startX}
                                  cy={endpoint.startY}
                                  r="1.15"
                                  fill="var(--surface)"
                                  stroke="var(--primary)"
                                  strokeWidth="0.48"
                                />
                              </g>
                            );
                          })}
                        </g>
                      );
                    })}
                  </svg>
                  {graphNodes.map((node) => (
                    <button
                      key={node.path}
                      type="button"
                      aria-pressed={node.path === selectedPath}
                      onClick={() => onSelectPath(node.path)}
                      style={{ left: `${node.x}%`, top: `${node.y}%` }}
                      className={`absolute z-10 flex max-w-40 -translate-x-1/2 -translate-y-1/2 items-center gap-2 rounded-lg border px-2.5 py-1.5 text-left shadow-sm transition-colors duration-150 ${
                        node.path === selectedPath
                          ? "border-primary-border bg-primary-subtle text-text"
                          : "border-border bg-surface text-text hover:border-border-strong hover:bg-surface-hover"
                      }`}
                    >
                      <Crosshair className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
                      <span className="truncate font-mono text-xs">{node.path}</span>
                      <span className="rounded-full bg-info-subtle px-1.5 text-xs font-semibold text-info">
                        {node.sessionIds.length}
                      </span>
                    </button>
                  ))}
                  {graphCallouts.map((callout, index) => {
                    const position = positionForCallout(callout, index);
                    const selected = callout.sessionIds.includes(selectedSessionId ?? "");
                    return (
                      <button
                        key={`callout-${callout.sourceIp}`}
                        type="button"
                        aria-pressed={selected}
                        onPointerDown={(event) => onCalloutPointerDown(event, callout.sourceIp, position)}
                        onPointerMove={onCalloutPointerMove}
                        onPointerUp={onCalloutPointerEnd}
                        onPointerCancel={onCalloutPointerEnd}
                        onClick={() => {
                          if (suppressCalloutClick.current) {
                            suppressCalloutClick.current = false;
                            return;
                          }
                          onSelectSession(callout.sessionIds[0]);
                        }}
                        style={{ left: `${position.x}%`, top: `${position.y}%` }}
                        className={`absolute z-40 flex w-44 -translate-x-1/2 -translate-y-1/2 touch-none items-center gap-2 rounded-lg border px-2.5 py-2 text-left shadow-sm transition-colors duration-150 ${
                          selected
                            ? "border-primary-border bg-primary-subtle"
                            : "border-border bg-surface hover:border-border-strong hover:bg-surface-hover"
                        }`}
                      >
                        <span
                          className={`h-2 w-2 shrink-0 rounded-full ${
                            streamState === "live" ? "bg-success" : "bg-warning"
                          }`}
                          aria-hidden="true"
                        />
                        <span className="min-w-0">
                          <span className="block truncate font-mono text-xs text-text">{callout.sourceIp}</span>
                          <span className="mt-0.5 flex items-center gap-1 text-[11px] text-text-subtle">
                            <span>
                              {callout.sessionIds.length} {callout.sessionIds.length === 1 ? "session" : "sessions"}
                            </span>
                            <span aria-hidden="true">·</span>
                            <span className="truncate font-mono">{callout.path}</span>
                          </span>
                        </span>
                      </button>
                    );
                  })}
                </motion.div>

                <div className="pointer-events-none absolute bottom-3 left-5 z-20 rounded-full border border-border bg-surface px-3 py-1.5 text-xs text-text-muted shadow-sm">
                  <span className="font-semibold text-text">{graphNodes.length}</span> paths mapped ·{" "}
                  <span className="font-semibold text-text">{graphCallouts.length}</span> of {liveSourceCount} IP labels
                </div>

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
              </div>

              <div className="flex flex-wrap gap-x-5 gap-y-2 border-t border-border px-5 py-3 text-xs text-text-muted">
                <span>
                  <strong className="text-text">{snapshot.nodes.length}</strong> observed paths
                </span>
                <span>
                  <strong className="text-text">{snapshot.sessions.length}</strong> sessions with a known CWD
                </span>
                <span>Snapshot {formatTimestamp(snapshot.generatedAt)}</span>
              </div>
              {snapshot.truncated && (
                <div className="flex gap-2 border-t border-warning-border bg-warning-subtle px-5 py-3 text-xs text-text-muted">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                  <p>
                    Showing the latest {snapshot.sessions.length} observed sessions. Older sessions are not included in
                    this live topology.
                  </p>
                </div>
              )}
            </div>

            {isTopologyExpanded && (
              <aside
                className="min-h-0 overflow-y-auto border-t border-border bg-surface p-5 lg:border-l lg:border-t-0"
                aria-label="Expanded map controls"
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.12em] text-primary">Map controls</p>
                    <h3 className="mt-1 font-semibold text-text">Live source clusters</h3>
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
                  Choose an IP to fan its leader line out to every current verified path. Drag labels on the map to
                  arrange them. Press Escape to exit this workspace.
                </p>
                <button type="button" className="ui-button mt-4 w-full" onClick={resetLabelLayout}>
                  <MousePointer2 className="h-4 w-4" />
                  Auto arrange labels
                </button>
                <div className="mt-5 space-y-2">
                  {graphCallouts.map((callout) => {
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
                          <span className="ui-badge border-info-border bg-info-subtle text-info">
                            {callout.sessionIds.length}
                          </span>
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
                              <span className="mt-0.5 block truncate font-mono text-[11px] text-text-subtle">
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
