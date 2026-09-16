"use client";

import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";

import type { LabelDrag, LabelPosition, NodeDrag, Pan } from "./filesystemUtils";
import {
  loadLayoutFromStorage,
  pruneStaleAuditLayouts,
  removeLayoutFromStorage,
  saveLayoutToStorage,
} from "./layoutPersistence";

export const NODE_WORKSPACE_LIMIT = 400;

export function unrestrictedNodeCoordinate(value: number): number {
  return Math.min(NODE_WORKSPACE_LIMIT, Math.max(-NODE_WORKSPACE_LIMIT, value));
}

export function calculateRelativeDragDelta(currentCoord: number, startCoord: number, dimensionSize: number): number {
  if (!dimensionSize) return 0;
  return ((currentCoord - startCoord) / dimensionSize) * 100;
}

export function applyDragOffset(origin: LabelPosition, deltaX: number, deltaY: number): LabelPosition {
  return {
    x: unrestrictedNodeCoordinate(origin.x + deltaX),
    y: unrestrictedNodeCoordinate(origin.y + deltaY),
  };
}

export function readStoredLabelLayout(storageKey: string): Record<string, LabelPosition> {
  return loadLayoutFromStorage(storageKey);
}

export function readStoredNodeLayout(storageKey: string): Record<string, LabelPosition> {
  return loadLayoutFromStorage(storageKey);
}

export interface WorkspaceLayoutSnapshot {
  labelPositions: Record<string, LabelPosition>;
  nodePositions: Record<string, LabelPosition>;
  pan: Pan;
  zoom: number;
}

export interface UseTopologyArrangeOptions {
  labelStorageKey: string;
  nodeStorageKey: string;
  graphPlaneRef: React.RefObject<HTMLDivElement | null>;
  onCaptureViewport?: () => { pan: Pan; zoom: number };
  onRestoreViewport?: (snapshot: { pan: Pan; zoom: number }) => void;
  onResetViewport?: (
    overrideLabels?: Record<string, LabelPosition>,
    overrideNodes?: Record<string, LabelPosition>,
  ) => void;
  onClearElementBounds?: () => void;
}

export interface UseTopologyArrangeReturn {
  isArrangeMode: boolean;
  setIsArrangeMode: React.Dispatch<React.SetStateAction<boolean>>;
  labelPositions: Record<string, LabelPosition>;
  setLabelPositions: React.Dispatch<React.SetStateAction<Record<string, LabelPosition>>>;
  nodePositions: Record<string, LabelPosition>;
  setNodePositions: React.Dispatch<React.SetStateAction<Record<string, LabelPosition>>>;
  draggedCalloutIp: string | null;
  draggedNodePath: string | null;
  canUndoLayout: boolean;
  layoutUndo: React.MutableRefObject<WorkspaceLayoutSnapshot | null>;
  undoLayoutChange: () => void;
  autoArrangeTopology: () => void;
  resetMapWorkspace: () => void;
  resetLabelLayout: () => void;
  resetNodeLayout: () => void;
  onCalloutPointerDown: (event: ReactPointerEvent<HTMLElement>, sourceIp: string, origin: LabelPosition) => void;
  onCalloutPointerMove: (event: ReactPointerEvent<HTMLElement>) => void;
  onCalloutPointerEnd: (event: ReactPointerEvent<HTMLElement>) => void;
  consumeCalloutClickSuppression: () => boolean;
  onNodePointerDown: (event: ReactPointerEvent<HTMLButtonElement>, path: string, origin: LabelPosition) => void;
  onNodePointerMove: (event: ReactPointerEvent<HTMLButtonElement>) => void;
  onNodePointerEnd: (event: ReactPointerEvent<HTMLButtonElement>) => void;
  consumeNodeClickSuppression: () => boolean;
}

export function useTopologyArrange(options: UseTopologyArrangeOptions): UseTopologyArrangeReturn {
  const {
    labelStorageKey,
    nodeStorageKey,
    graphPlaneRef,
    onCaptureViewport,
    onRestoreViewport,
    onResetViewport,
    onClearElementBounds,
  } = options;

  const [labelPositions, setLabelPositions] = useState<Record<string, LabelPosition>>(() =>
    readStoredLabelLayout(labelStorageKey),
  );
  const [nodePositions, setNodePositions] = useState<Record<string, LabelPosition>>(() =>
    readStoredNodeLayout(nodeStorageKey),
  );

  const [prevLabelStorageKey, setPrevLabelStorageKey] = useState(labelStorageKey);
  if (prevLabelStorageKey !== labelStorageKey) {
    setPrevLabelStorageKey(labelStorageKey);
    setLabelPositions(readStoredLabelLayout(labelStorageKey));
  }

  const [prevNodeStorageKey, setPrevNodeStorageKey] = useState(nodeStorageKey);
  if (prevNodeStorageKey !== nodeStorageKey) {
    setPrevNodeStorageKey(nodeStorageKey);
    setNodePositions(readStoredNodeLayout(nodeStorageKey));
  }

  const [isArrangeMode, setIsArrangeMode] = useState(false);
  const [draggedCalloutIp, setDraggedCalloutIp] = useState<string | null>(null);
  const [draggedNodePath, setDraggedNodePath] = useState<string | null>(null);
  const [canUndoLayout, setCanUndoLayout] = useState(false);

  const labelDrag = useRef<LabelDrag | null>(null);
  const nodeDrag = useRef<NodeDrag | null>(null);
  const suppressCalloutClick = useRef(false);
  const suppressNodeClick = useRef(false);
  const layoutUndo = useRef<WorkspaceLayoutSnapshot | null>(null);
  const pendingDragUndo = useRef<WorkspaceLayoutSnapshot | null>(null);

  // Prune stale or excess audit layout keys on mount / key change
  useEffect(() => {
    pruneStaleAuditLayouts({ retainKeys: [labelStorageKey, nodeStorageKey] });
  }, [labelStorageKey, nodeStorageKey]);

  // Save label layout to localStorage
  useEffect(() => {
    saveLayoutToStorage(labelStorageKey, labelPositions);
  }, [labelPositions, labelStorageKey]);

  // Directory layout is a workspace preference, independent from source-IP labels.
  useEffect(() => {
    saveLayoutToStorage(nodeStorageKey, nodePositions);
  }, [nodePositions, nodeStorageKey]);

  const captureDragUndo = useCallback(() => {
    const vp = onCaptureViewport?.() ?? { pan: { x: 0, y: 0 }, zoom: 1 };
    pendingDragUndo.current = {
      labelPositions: { ...labelPositions },
      nodePositions: { ...nodePositions },
      pan: vp.pan,
      zoom: vp.zoom,
    };
  }, [labelPositions, nodePositions, onCaptureViewport]);

  const commitDragUndo = useCallback(() => {
    if (!pendingDragUndo.current) return;
    layoutUndo.current = pendingDragUndo.current;
    pendingDragUndo.current = null;
  }, []);

  const resetLabelLayout = useCallback(() => {
    labelDrag.current = null;
    setDraggedCalloutIp(null);
    setLabelPositions({});
    removeLayoutFromStorage(labelStorageKey);
  }, [labelStorageKey]);

  const resetNodeLayout = useCallback(() => {
    nodeDrag.current = null;
    setDraggedNodePath(null);
    setNodePositions({});
    removeLayoutFromStorage(nodeStorageKey);
  }, [nodeStorageKey]);

  const resetMapWorkspace = useCallback(() => {
    resetLabelLayout();
    resetNodeLayout();
    onClearElementBounds?.();
    onResetViewport?.({}, {});
    layoutUndo.current = null;
    pendingDragUndo.current = null;
    setCanUndoLayout(false);
  }, [onClearElementBounds, onResetViewport, resetLabelLayout, resetNodeLayout]);

  const autoArrangeTopology = useCallback(() => {
    const vp = onCaptureViewport?.() ?? { pan: { x: 0, y: 0 }, zoom: 1 };
    layoutUndo.current = {
      labelPositions: { ...labelPositions },
      nodePositions: { ...nodePositions },
      pan: vp.pan,
      zoom: vp.zoom,
    };
    setCanUndoLayout(true);
    resetLabelLayout();
    resetNodeLayout();
    onClearElementBounds?.();
    onResetViewport?.({}, {});
  }, [labelPositions, nodePositions, onCaptureViewport, onClearElementBounds, onResetViewport, resetLabelLayout, resetNodeLayout]);

  const undoLayoutChange = useCallback(() => {
    const previous = layoutUndo.current;
    if (!previous) return;
    setLabelPositions(previous.labelPositions);
    setNodePositions(previous.nodePositions);
    onRestoreViewport?.({ pan: previous.pan, zoom: previous.zoom });
    layoutUndo.current = null;
    pendingDragUndo.current = null;
    setCanUndoLayout(false);
  }, [onRestoreViewport]);

  // Label dragging handlers
  const onCalloutPointerDown = useCallback(
    (event: ReactPointerEvent<HTMLElement>, sourceIp: string, origin: LabelPosition) => {
      event.stopPropagation();
      event.currentTarget.focus();
      if (!isArrangeMode) return;
      suppressCalloutClick.current = false;
      event.currentTarget.setPointerCapture(event.pointerId);
      labelDrag.current = { sourceIp, startX: event.clientX, startY: event.clientY, origin };
      captureDragUndo();
      setDraggedCalloutIp(sourceIp);
    },
    [captureDragUndo, isArrangeMode],
  );

  const onCalloutPointerMove = useCallback(
    (event: ReactPointerEvent<HTMLElement>) => {
      const dragging = labelDrag.current;
      const plane = graphPlaneRef.current;
      if (!dragging || !plane) return;
      const rect = plane.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      const deltaX = calculateRelativeDragDelta(event.clientX, dragging.startX, rect.width);
      const deltaY = calculateRelativeDragDelta(event.clientY, dragging.startY, rect.height);
      if (Math.abs(deltaX) > 0.25 || Math.abs(deltaY) > 0.25) {
        if (!suppressCalloutClick.current) commitDragUndo();
        suppressCalloutClick.current = true;
      }
      setLabelPositions((current) => ({
        ...current,
        [dragging.sourceIp]: applyDragOffset(dragging.origin, deltaX, deltaY),
      }));
    },
    [commitDragUndo, graphPlaneRef],
  );

  const onCalloutPointerEnd = useCallback((event: ReactPointerEvent<HTMLElement>) => {
    const dragging = labelDrag.current;
    if (dragging) {
      setLabelPositions((current) => ({
        ...current,
        [dragging.sourceIp]: current[dragging.sourceIp] ?? dragging.origin,
      }));
    }
    labelDrag.current = null;
    pendingDragUndo.current = null;
    setDraggedCalloutIp(null);
    if (suppressCalloutClick.current) setCanUndoLayout(true);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }, []);

  // Manual node placement handlers
  const onNodePointerDown = useCallback(
    (event: ReactPointerEvent<HTMLButtonElement>, path: string, origin: LabelPosition) => {
      event.stopPropagation();
      event.currentTarget.focus();
      if (!isArrangeMode) return;
      suppressNodeClick.current = false;
      event.currentTarget.setPointerCapture(event.pointerId);
      nodeDrag.current = { path, startX: event.clientX, startY: event.clientY, origin };
      captureDragUndo();
      setDraggedNodePath(path);
    },
    [captureDragUndo, isArrangeMode],
  );

  const onNodePointerMove = useCallback(
    (event: ReactPointerEvent<HTMLButtonElement>) => {
      const dragging = nodeDrag.current;
      const plane = graphPlaneRef.current;
      if (!dragging || !plane) return;
      const rect = plane.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      const deltaX = calculateRelativeDragDelta(event.clientX, dragging.startX, rect.width);
      const deltaY = calculateRelativeDragDelta(event.clientY, dragging.startY, rect.height);
      if (Math.abs(deltaX) > 0.2 || Math.abs(deltaY) > 0.2) {
        if (!suppressNodeClick.current) commitDragUndo();
        suppressNodeClick.current = true;
      }
      setNodePositions((current) => ({
        ...current,
        [dragging.path]: applyDragOffset(dragging.origin, deltaX, deltaY),
      }));
    },
    [commitDragUndo, graphPlaneRef],
  );

  const onNodePointerEnd = useCallback((event: ReactPointerEvent<HTMLButtonElement>) => {
    nodeDrag.current = null;
    pendingDragUndo.current = null;
    setDraggedNodePath(null);
    if (suppressNodeClick.current) setCanUndoLayout(true);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }, []);

  const consumeNodeClickSuppression = useCallback(() => {
    if (suppressNodeClick.current) {
      suppressNodeClick.current = false;
      return true;
    }
    return false;
  }, []);

  const consumeCalloutClickSuppression = useCallback(() => {
    if (suppressCalloutClick.current) {
      suppressCalloutClick.current = false;
      return true;
    }
    return false;
  }, []);

  return {
    isArrangeMode,
    setIsArrangeMode,
    labelPositions,
    setLabelPositions,
    nodePositions,
    setNodePositions,
    draggedCalloutIp,
    draggedNodePath,
    canUndoLayout,
    layoutUndo,
    undoLayoutChange,
    autoArrangeTopology,
    resetMapWorkspace,
    resetLabelLayout,
    resetNodeLayout,
    onCalloutPointerDown,
    onCalloutPointerMove,
    onCalloutPointerEnd,
    consumeCalloutClickSuppression,
    onNodePointerDown,
    onNodePointerMove,
    onNodePointerEnd,
    consumeNodeClickSuppression,
  };
}
