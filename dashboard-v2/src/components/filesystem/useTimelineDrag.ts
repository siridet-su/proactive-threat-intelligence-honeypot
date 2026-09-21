import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import {
  DEFAULT_TIMELINE_SIDEBAR_WIDTH,
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

  const handleSplitterMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsDraggingTimeline(true);
    const startX = e.clientX;
    const startWidth = timelineWidth;

    const onMouseMove = (moveEvent: MouseEvent) => {
      const deltaX = startX - moveEvent.clientX;
      setTimelineWidth(clampTimelineSidebarWidth(startWidth + deltaX, window.innerWidth));
    };

    const onMouseUp = () => {
      setIsDraggingTimeline(false);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };

    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
  }, [setTimelineWidth, timelineWidth]);

  const handleResetTimelineWidth = useCallback(() => {
    setTimelineWidth(DEFAULT_TIMELINE_SIDEBAR_WIDTH);
  }, [setTimelineWidth]);

  const handleSplitterKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowLeft") {
      e.preventDefault();
      setTimelineWidth((curr) => clampTimelineSidebarWidth(curr + 24, window.innerWidth));
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      setTimelineWidth((curr) => clampTimelineSidebarWidth(curr - 24, window.innerWidth));
    } else if (e.key === "Enter" || e.key === " " || e.key === "Home") {
      e.preventDefault();
      setTimelineWidth(DEFAULT_TIMELINE_SIDEBAR_WIDTH);
    }
  }, [setTimelineWidth]);

  return {
    timelineWidth,
    isDraggingTimeline,
    handleSplitterMouseDown,
    handleResetTimelineWidth,
    handleSplitterKeyDown,
  };
}
