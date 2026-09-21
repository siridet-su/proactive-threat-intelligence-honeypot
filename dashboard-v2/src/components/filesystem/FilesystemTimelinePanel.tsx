"use client";

import type { CSSProperties } from "react";
import { CwdRouteHistory, type CwdRouteHistoryProps } from "./CwdRouteHistory";

export interface FilesystemTimelinePanelProps extends Omit<CwdRouteHistoryProps, "layout"> {
  collapsed: boolean;
  isDragging: boolean;
  width: number;
  variant: "fullscreen" | "page";
}

/**
 * Shared page composition for the single mounted forensic history panel.
 * Layout variants change only presentation; they never mount a second replay,
 * response, history, or timer owner.
 */
export function FilesystemTimelinePanel({
  collapsed,
  isDragging,
  width,
  variant,
  ...historyProps
}: FilesystemTimelinePanelProps) {
  const isFullscreen = variant === "fullscreen";
  const outerStyle: CSSProperties = isFullscreen
    ? { width: collapsed ? 0 : width }
    : { width: collapsed ? 0 : undefined, ["--timeline-width" as string]: `${width}px` };
  const innerStyle: CSSProperties = isFullscreen
    ? { width }
    : {};

  return (
    <div
      inert={collapsed ? true : undefined}
      aria-hidden={collapsed}
      style={outerStyle}
      className={`${isFullscreen ? "h-full" : ""} flex flex-col shrink-0 overflow-hidden ${
        isDragging ? "transition-none" : isFullscreen ? "transition-[width,opacity,margin] duration-300 ease-in-out motion-reduce:transition-none" : "transition-[width,opacity,margin,max-height] duration-300 ease-in-out motion-reduce:transition-none"
      } ${
        collapsed
          ? isFullscreen
            ? "opacity-0 pointer-events-none ml-0"
            : "max-h-0 lg:max-h-none lg:w-0 opacity-0 pointer-events-none mt-0 lg:mt-0 lg:ml-0"
          : isFullscreen
            ? "opacity-100 ml-2 sm:ml-2.5"
            : "max-h-[800px] lg:max-h-none w-full lg:w-[var(--timeline-width)] opacity-100 mt-4 lg:mt-0 lg:ml-2.5"
      }`}
    >
      <div
        style={innerStyle}
        className={isFullscreen ? "h-full flex flex-col min-h-0" : "w-full lg:w-[var(--timeline-width)] h-full flex flex-col min-h-0"}
      >
        <CwdRouteHistory {...historyProps} layout="sidebar" isDragging={isDragging} />
      </div>
    </div>
  );
}
