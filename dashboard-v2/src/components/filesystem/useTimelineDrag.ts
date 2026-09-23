import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import {
  DEFAULT_TIMELINE_SIDEBAR_WIDTH,
  MAX_TIMELINE_SIDEBAR_WIDTH,
  MIN_TIMELINE_SIDEBAR_WIDTH,
  TIMELINE_SIDEBAR_STORAGE_KEY,
  clampTimelineSidebarWidth,
} from "./filesystemUtils";

function readStoredTimelineWidth(): number | null {
  if (typeof window === "undefined") return null;
  try {
    const saved = localStorage.getItem(TIMELINE_SIDEBAR_STORAGE_KEY);
    if (!saved) return null;
    const parsed = parseInt(saved, 10);
    return Number.isFinite(parsed) ? clampTimelineSidebarWidth(parsed, window.innerWidth) : null;
  } catch {
    return null;
  }
}

export function useTimelineDrag() {
  const persistedTimelineWidth = useSyncExternalStore(
    useCallback(() => () => {}, []),
    readStoredTimelineWidth,
    () => null,
  );

  const [timelineWidthOverride, setTimelineWidthOverride] = useState<number | null>(null);
  const timelineWidth = timelineWidthOverride ?? persistedTimelineWidth ?? DEFAULT_TIMELINE_SIDEBAR_WIDTH;

  const setTimelineWidth = useCallback((next: number | ((current: number) => number)) => {
    setTimelineWidthOverride((currentOverride) => {
      const current = currentOverride ?? persistedTimelineWidth ?? DEFAULT_TIMELINE_SIDEBAR_WIDTH;
      return typeof next === "function" ? next(current) : next;
    });
  }, [persistedTimelineWidth]);

  const [isDraggingTimeline, setIsDraggingTimeline] = useState(false);
  const activePointerRef = useRef<{
    pointerId: number;
    startX: number;
    startWidth: number;
    target: HTMLElement;
  } | null>(null);

  useEffect(() => {
    if (typeof window !== "undefined" && (persistedTimelineWidth !== null || timelineWidthOverride !== null)) {
      try {
        localStorage.setItem(TIMELINE_SIDEBAR_STORAGE_KEY, String(timelineWidth));
      } catch {
        // ignore
      }
    }
  }, [persistedTimelineWidth, timelineWidth, timelineWidthOverride]);

  useEffect(() => {
    if (isDraggingTimeline) {
      document.body.style.userSelect = "none";
      document.body.style.cursor = "col-resize";
    } else {
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    }
    return () => {
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
    };
  }, [isDraggingTimeline]);

  const releaseActivePointer = useCallback((pointerId?: number, updateState = true) => {
    const active = activePointerRef.current;
    if (!active || (pointerId !== undefined && active.pointerId !== pointerId)) return;
    activePointerRef.current = null;
    try {
      active.target.releasePointerCapture?.(active.pointerId);
    } catch {
      // Capture may already have been released by the browser.
    }
    if (updateState) setIsDraggingTimeline(false);
  }, []);

  useEffect(() => {
    return () => {
      releaseActivePointer(undefined, false);
    };
  }, [releaseActivePointer]);

  const handleSplitterPointerDown = useCallback((event: React.PointerEvent<HTMLElement>) => {
    if (event.isPrimary === false) return;
    if (event.pointerType === "mouse" && event.button !== 0) return;
    event.preventDefault();
    activePointerRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startWidth: timelineWidth,
      target: event.currentTarget,
    };
    try {
      event.currentTarget.setPointerCapture?.(event.pointerId);
    } catch {
      // The drag remains safe if a browser cannot capture the pointer.
    }
    setIsDraggingTimeline(true);
  }, [timelineWidth]);

  const handleSplitterPointerMove = useCallback((event: React.PointerEvent<HTMLElement>) => {
    const active = activePointerRef.current;
    if (!active || active.pointerId !== event.pointerId) return;
    event.preventDefault();
    const deltaX = active.startX - event.clientX;
    setTimelineWidth(clampTimelineSidebarWidth(active.startWidth + deltaX, window.innerWidth));
  }, [setTimelineWidth]);

  const handleSplitterPointerUp = useCallback((event: React.PointerEvent<HTMLElement>) => {
    releaseActivePointer(event.pointerId);
  }, [releaseActivePointer]);

  const handleSplitterPointerCancel = useCallback((event: React.PointerEvent<HTMLElement>) => {
    releaseActivePointer(event.pointerId);
  }, [releaseActivePointer]);

  const handleResetTimelineWidth = useCallback(() => {
    setTimelineWidth(DEFAULT_TIMELINE_SIDEBAR_WIDTH);
  }, [setTimelineWidth]);

  const handleSplitterKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowLeft") {
      e.preventDefault();
      e.stopPropagation();
      setTimelineWidth((curr) => clampTimelineSidebarWidth(curr + 24, window.innerWidth));
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      e.stopPropagation();
      setTimelineWidth((curr) => clampTimelineSidebarWidth(curr - 24, window.innerWidth));
    } else if (e.key === "Home") {
      e.preventDefault();
      e.stopPropagation();
      setTimelineWidth(MIN_TIMELINE_SIDEBAR_WIDTH);
    } else if (e.key === "End") {
      e.preventDefault();
      e.stopPropagation();
      setTimelineWidth(MAX_TIMELINE_SIDEBAR_WIDTH);
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      e.stopPropagation();
      setTimelineWidth(DEFAULT_TIMELINE_SIDEBAR_WIDTH);
    }
  }, [setTimelineWidth]);

  return {
    timelineWidth,
    isDraggingTimeline,
    handleSplitterPointerDown,
    handleSplitterPointerMove,
    handleSplitterPointerUp,
    handleSplitterPointerCancel,
    handleResetTimelineWidth,
    handleSplitterKeyDown,
  };
}
