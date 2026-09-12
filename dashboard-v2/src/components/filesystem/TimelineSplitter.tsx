"use client";

import { memo } from "react";
import {
  MAX_TIMELINE_SIDEBAR_WIDTH,
  MIN_TIMELINE_SIDEBAR_WIDTH,
} from "./filesystemUtils";

interface TimelineSplitterProps {
  isDragging: boolean;
  width: number;
  onMouseDown: (e: React.MouseEvent) => void;
  onDoubleClick?: () => void;
  onKeyDown?: (e: React.KeyboardEvent) => void;
  className?: string;
}

export const TimelineSplitter = memo(function TimelineSplitter({
  isDragging,
  width,
  onMouseDown,
  onDoubleClick,
  onKeyDown,
  className = "",
}: TimelineSplitterProps) {
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-valuenow={width}
      aria-valuemin={MIN_TIMELINE_SIDEBAR_WIDTH}
      aria-valuemax={MAX_TIMELINE_SIDEBAR_WIDTH}
      aria-label="Resize timeline panel. Drag left/right, double click to reset."
      tabIndex={0}
      title="Drag to resize timeline (Double-click to reset)"
      onMouseDown={onMouseDown}
      onDoubleClick={onDoubleClick}
      onKeyDown={onKeyDown}
      className={`relative z-20 flex items-center justify-center w-3 -mr-1.5 cursor-col-resize select-none group touch-none shrink-0 ${
        isDragging ? "pointer-events-auto" : ""
      } ${className}`}
    >
      {/* Visual Splitter Line */}
      <div
        className={`h-full w-1 rounded-full transition-colors duration-150 ${
          isDragging
            ? "bg-primary shadow-[0_0_8px_rgba(59,130,246,0.6)]"
            : "bg-border/60 group-hover:bg-primary/70"
        }`}
      />

      {/* Grip Indicator Badge */}
      <div
        className={`absolute top-1/2 -translate-y-1/2 flex flex-col gap-1 rounded bg-surface border border-border px-0.5 py-1.5 shadow-xs transition-opacity duration-150 ${
          isDragging ? "opacity-100 border-primary" : "opacity-0 group-hover:opacity-100"
        }`}
      >
        <div className="w-0.5 h-0.5 rounded-full bg-text-subtle" />
        <div className="w-0.5 h-0.5 rounded-full bg-text-subtle" />
        <div className="w-0.5 h-0.5 rounded-full bg-text-subtle" />
      </div>
    </div>
  );
});
