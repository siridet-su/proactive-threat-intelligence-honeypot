"use client";

import { Route } from "lucide-react";
import type { ReactNode } from "react";

export interface TopologyCanvasHeaderProps {
  title?: string;
  subtitle?: string;
  children: ReactNode;
}

/** Presentational shell for topology identity and its focused control groups. */
export function TopologyCanvasHeader({ title, subtitle, children }: TopologyCanvasHeaderProps) {
  return (
    <div className="relative z-40 flex shrink-0 flex-col gap-2.5 overflow-visible border-b border-border px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0 flex-1 pr-3">
        <div className="flex items-center gap-2">
          <Route className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
          <h2 className="truncate font-semibold text-text text-sm sm:text-base">{title ?? "Live filesystem topology"}</h2>
        </div>
        <p className="mt-0.5 truncate text-xs text-text-subtle">
          {subtitle ?? "Observed paths form the topology; compact source-IP clusters point to their most recently verified location."}
        </p>
      </div>
      {children}
    </div>
  );
}
