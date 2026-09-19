"use client";

import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";

import {
  calculateTwoDimensionalFit,
  calculateWorldBounds,
  MAP_MAX_ZOOM,
  MAP_MIN_ZOOM,
  type GraphCallout,
  type GraphElementBounds,
  type GraphNode,
  type LabelPosition,
  type MapMetrics,
  type Pan,
} from "./filesystemUtils";

export function clampZoom(value: number): number {
  return Math.min(MAP_MAX_ZOOM, Math.max(MAP_MIN_ZOOM, Number(value.toFixed(3))));
}

export function calculateFocalPan(
  currentPan: Pan,
  currentZoom: number,
  nextZoom: number,
  focalPoint?: Pan,
): Pan {
  if (!focalPoint) return currentPan;
  return {
    x: focalPoint.x - ((focalPoint.x - currentPan.x) / currentZoom) * nextZoom,
    y: focalPoint.y - ((focalPoint.y - currentPan.y) / currentZoom) * nextZoom,
  };
}

export function calculateKeyPanStep(currentPan: Pan, key: string, step = 40): Pan {
  return {
    x: key === "ArrowLeft" ? currentPan.x + step : key === "ArrowRight" ? currentPan.x - step : currentPan.x,
    y: key === "ArrowUp" ? currentPan.y + step : key === "ArrowDown" ? currentPan.y - step : currentPan.y,
  };
}

export function calculateTouchPinchZoom(
  initialZoom: number,
  initialDistance: number,
  currentDistance: number,
): number {
  if (
    initialDistance <= 0 ||
    currentDistance <= 0 ||
    !Number.isFinite(initialDistance) ||
    !Number.isFinite(currentDistance)
  ) {
    return initialZoom;
  }
  const factor = currentDistance / initialDistance;
  return clampZoom(initialZoom * factor);
}

export interface UseTopologyViewportOptions {
  mapSurfaceRef: React.RefObject<HTMLDivElement | null>;
  graphPlaneRef: React.RefObject<HTMLDivElement | null>;
  isTopologyExpanded: boolean;
  showMinimap: boolean;
  automaticGraphNodes: GraphNode[];
  graphCallouts: GraphCallout[];
  nodePositions: Record<string, LabelPosition>;
  labelPositions: Record<string, LabelPosition>;
  automaticCalloutPositions: Map<string, LabelPosition>;
  nodeElementBounds: Record<string, GraphElementBounds>;
  calloutElementBounds: Record<string, GraphElementBounds>;
  nodesCount: number;
}

export interface UseTopologyViewportReturn {
  pan: Pan;
  setPan: React.Dispatch<React.SetStateAction<Pan>>;
  zoom: number;
  setZoom: React.Dispatch<React.SetStateAction<number>>;
  panRef: React.MutableRefObject<Pan>;
  zoomRef: React.MutableRefObject<number>;
  isDraggingSurface: boolean;
  mapMetrics: MapMetrics | null;
  hasUserManuallyAdjustedViewRef: React.MutableRefObject<boolean>;
  setMapZoom: (value: number, focalPoint?: Pan) => void;
  zoomIn: (delta?: number) => void;
  zoomOut: (delta?: number) => void;
  markUserAdjusted: () => void;
  centerMapOn: (position: LabelPosition) => void;
  calculateFitViewport: (
    surface: HTMLDivElement,
    plane: HTMLDivElement,
    overrideLabels?: Record<string, LabelPosition>,
    overrideNodes?: Record<string, LabelPosition>,
  ) => { pan: Pan; zoom: number } | null;
  resetViewport: (
    overrideLabels?: Record<string, LabelPosition>,
    overrideNodes?: Record<string, LabelPosition>,
  ) => void;
  fitTopology: () => void;
  onPointerDown: (event: ReactPointerEvent<HTMLDivElement>) => void;
  onPointerMove: (event: ReactPointerEvent<HTMLDivElement>) => void;
  onPointerEnd: (event: ReactPointerEvent<HTMLDivElement>) => void;
  onSurfaceKeyDown: (event: React.KeyboardEvent<HTMLDivElement>) => void;
}

export function useTopologyViewport(options: UseTopologyViewportOptions): UseTopologyViewportReturn {
  const {
    mapSurfaceRef,
    graphPlaneRef,
    isTopologyExpanded,
    showMinimap,
    automaticGraphNodes,
    graphCallouts,
    nodePositions,
    labelPositions,
    automaticCalloutPositions,
    nodeElementBounds,
    calloutElementBounds,
    nodesCount,
  } = options;

  const [pan, setPan] = useState<Pan>({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [isDraggingSurface, setIsDraggingSurface] = useState(false);
  const [mapMetrics, setMapMetrics] = useState<MapMetrics | null>(null);

  const panRef = useRef<Pan>({ x: 0, y: 0 });
  const zoomRef = useRef(1);
  const dragStart = useRef<{ x: number; y: number; pan: Pan } | null>(null);
  const hasUserManuallyAdjustedViewRef = useRef(false);

  const setMapZoom = useCallback((value: number, focalPoint?: Pan) => {
    const nextZoom = clampZoom(value);
    const currentZoom = zoomRef.current;
    const currentPan = panRef.current;
    const nextPan = calculateFocalPan(currentPan, currentZoom, nextZoom, focalPoint);
    zoomRef.current = nextZoom;
    panRef.current = nextPan;
    setZoom(nextZoom);
    setPan(nextPan);
  }, []);

  const markUserAdjusted = useCallback(() => {
    hasUserManuallyAdjustedViewRef.current = true;
  }, []);

  const zoomIn = useCallback((delta = 0.1) => {
    hasUserManuallyAdjustedViewRef.current = true;
    setMapZoom(zoomRef.current + delta);
  }, [setMapZoom]);

  const zoomOut = useCallback((delta = 0.1) => {
    hasUserManuallyAdjustedViewRef.current = true;
    setMapZoom(zoomRef.current - delta);
  }, [setMapZoom]);

  const calculateFitViewport = useCallback(
    (
      surface: HTMLDivElement,
      plane: HTMLDivElement,
      overrideLabels?: Record<string, LabelPosition>,
      overrideNodes?: Record<string, LabelPosition>,
    ) => {
      const surfaceWidth = surface.clientWidth;
      const surfaceHeight = surface.clientHeight;
      if (!surfaceWidth || !surfaceHeight) return null;

      const baseWidth = plane.offsetWidth || 860;
      const baseHeight = plane.offsetHeight || 500;
      const effectiveNodes = overrideNodes ?? nodePositions;
      const effectiveLabels = overrideLabels ?? labelPositions;

      const bounds = calculateWorldBounds(
        automaticGraphNodes,
        graphCallouts,
        effectiveNodes,
        effectiveLabels,
        automaticCalloutPositions,
        nodeElementBounds,
        calloutElementBounds,
      );

      return calculateTwoDimensionalFit(bounds, {
        surfaceWidth,
        surfaceHeight,
        planeWidth: baseWidth,
        planeHeight: baseHeight,
        planeOffsetLeft: plane.offsetLeft,
        planeOffsetTop: plane.offsetTop,
        hasMinimap: showMinimap,
        isMinimapCollapsed: false,
        minPadding: 24,
      });
    },
    [
      automaticCalloutPositions,
      automaticGraphNodes,
      calloutElementBounds,
      graphCallouts,
      labelPositions,
      nodeElementBounds,
      nodePositions,
      showMinimap,
    ],
  );

  const resetViewport = useCallback(
    (overrideLabels?: Record<string, LabelPosition>, overrideNodes?: Record<string, LabelPosition>) => {
      hasUserManuallyAdjustedViewRef.current = false;
      const surface = mapSurfaceRef.current;
      const plane = graphPlaneRef.current;
      if (surface && plane) {
        const fit = calculateFitViewport(surface, plane, overrideLabels, overrideNodes);
        if (fit) {
          panRef.current = fit.pan;
          zoomRef.current = fit.zoom;
          setPan(fit.pan);
          setZoom(fit.zoom);
          return;
        }
      }
      panRef.current = { x: 0, y: 0 };
      zoomRef.current = 1;
      setPan(panRef.current);
      setZoom(zoomRef.current);
    },
    [calculateFitViewport, graphPlaneRef, mapSurfaceRef],
  );

  const fitTopology = useCallback(() => {
    hasUserManuallyAdjustedViewRef.current = false;
    resetViewport();
  }, [resetViewport]);

  const centerMapOn = useCallback(
    (position: LabelPosition) => {
      const surface = mapSurfaceRef.current;
      const plane = graphPlaneRef.current;
      if (!surface || !plane) return;
      const nextPan = {
        x: surface.clientWidth / 2 - plane.offsetLeft - ((plane.offsetWidth * position.x) / 100) * zoomRef.current,
        y: surface.clientHeight / 2 - plane.offsetTop - ((plane.offsetHeight * position.y) / 100) * zoomRef.current,
      };
      panRef.current = nextPan;
      setPan(nextPan);
    },
    [graphPlaneRef, mapSurfaceRef],
  );

  // Surface pan handlers
  const onPointerDown = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).closest("button")) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    dragStart.current = { x: event.clientX, y: event.clientY, pan: panRef.current };
    setIsDraggingSurface(true);
  }, []);

  const onPointerMove = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    if (!dragStart.current) return;
    const deltaX = event.clientX - dragStart.current.x;
    const deltaY = event.clientY - dragStart.current.y;
    if (Math.abs(deltaX) > 3 || Math.abs(deltaY) > 3) {
      hasUserManuallyAdjustedViewRef.current = true;
    }
    const nextPan = {
      x: dragStart.current.pan.x + deltaX,
      y: dragStart.current.pan.y + deltaY,
    };
    panRef.current = nextPan;
    setPan(nextPan);
  }, []);

  const onPointerEnd = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    dragStart.current = null;
    setIsDraggingSurface(false);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }, []);

  // Keyboard navigation
  const onSurfaceKeyDown = useCallback((event: React.KeyboardEvent<HTMLDivElement>) => {
    if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(event.key)) {
      event.preventDefault();
      hasUserManuallyAdjustedViewRef.current = true;
      setPan((current) => {
        const next = calculateKeyPanStep(current, event.key, 40);
        panRef.current = next;
        return next;
      });
    }
  }, []);

  // Wheel zoom
  useEffect(() => {
    const surface = mapSurfaceRef.current;
    if (!surface) return;
    const onWheel = (event: WheelEvent) => {
      const plane = graphPlaneRef.current;
      if (!plane) return;
      event.preventDefault();
      hasUserManuallyAdjustedViewRef.current = true;
      const bounds = surface.getBoundingClientRect();
      setMapZoom(zoomRef.current * Math.exp(-event.deltaY * 0.0015), {
        x: event.clientX - bounds.left - plane.offsetLeft,
        y: event.clientY - bounds.top - plane.offsetTop,
      });
    };
    surface.addEventListener("wheel", onWheel, { passive: false });
    return () => surface.removeEventListener("wheel", onWheel);
  }, [graphPlaneRef, isTopologyExpanded, mapSurfaceRef, nodesCount, setMapZoom]);

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
        hasUserManuallyAdjustedViewRef.current = true;
        const dx = e.touches[0].clientX - e.touches[1].clientX;
        const dy = e.touches[0].clientY - e.touches[1].clientY;
        const currentDistance = Math.hypot(dx, dy);
        setMapZoom(calculateTouchPinchZoom(initialZoom, initialDistance, currentDistance));
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
  }, [mapSurfaceRef, setMapZoom]);

  // ResizeObserver for metrics and responsive auto-fit viewport
  useEffect(() => {
    const surface = mapSurfaceRef.current;
    const plane = graphPlaneRef.current;
    if (!surface || !plane) return;
    const handleResize = () => {
      setMapMetrics({
        surfaceWidth: surface.clientWidth,
        surfaceHeight: surface.clientHeight,
        planeWidth: plane.offsetWidth,
        planeHeight: plane.offsetHeight,
        planeLeft: plane.offsetLeft,
        planeTop: plane.offsetTop,
      });

      if (!hasUserManuallyAdjustedViewRef.current) {
        const fit = calculateFitViewport(surface, plane);
        if (fit) {
          if (
            Math.abs(panRef.current.x - fit.pan.x) > 1 ||
            Math.abs(panRef.current.y - fit.pan.y) > 1 ||
            Math.abs(zoomRef.current - fit.zoom) > 0.005
          ) {
            panRef.current = fit.pan;
            zoomRef.current = fit.zoom;
            setPan(fit.pan);
            setZoom(fit.zoom);
          }
        }
      }
    };
    handleResize();
    const observer = new ResizeObserver(handleResize);
    observer.observe(surface);
    return () => observer.disconnect();
  }, [calculateFitViewport, graphPlaneRef, mapSurfaceRef]);

  return {
    pan,
    setPan,
    zoom,
    setZoom,
    panRef,
    zoomRef,
    isDraggingSurface,
    mapMetrics,
    hasUserManuallyAdjustedViewRef,
    setMapZoom,
    zoomIn,
    zoomOut,
    markUserAdjusted,
    centerMapOn,
    calculateFitViewport,
    resetViewport,
    fitTopology,
    onPointerDown,
    onPointerMove,
    onPointerEnd,
    onSurfaceKeyDown,
  };
}
