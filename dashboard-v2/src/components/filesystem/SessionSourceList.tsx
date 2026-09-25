"use client";

import { ChevronRight } from "lucide-react";
import { useMemo } from "react";

import type { FilesystemTopologySession } from "@/lib/dashboardTypes";
import { compactDirectoryPath } from "./filesystemUtils";

interface SessionSourceListProps {
  embedded?: boolean;
  sessions: FilesystemTopologySession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
}

export function SessionSourceList({
  embedded = false,
  sessions,
  selectedSessionId,
  onSelectSession,
}: SessionSourceListProps) {
  const liveSources = useMemo(() => {
    const grouped = new Map<string, FilesystemTopologySession[]>();
    for (const session of sessions) {
      const group = grouped.get(session.sourceIp) ?? [];
      group.push(session);
      grouped.set(session.sourceIp, group);
    }

    return [...grouped.entries()]
      .map(([sourceIp, group]) => {
        const ordered = [...group].sort((left, right) => {
          const leftObservedAt = Date.parse(left.cwdState.observedAt ?? "") || 0;
          const rightObservedAt = Date.parse(right.cwdState.observedAt ?? "") || 0;
          return rightObservedAt - leftObservedAt;
        });
        const distinctPaths = new Set(
          ordered.map((session) => session.cwdState.path).filter(Boolean),
        );

        return {
          sourceIp,
          sessions: ordered,
          latest: ordered[0],
          distinctPathCount: distinctPaths.size,
        };
      })
      .sort((left, right) => {
        const leftObservedAt = Date.parse(left.latest.cwdState.observedAt ?? "") || 0;
        const rightObservedAt = Date.parse(right.latest.cwdState.observedAt ?? "") || 0;
        return rightObservedAt - leftObservedAt;
      });
  }, [sessions]);

  return (
    <div className={embedded ? "" : "ui-panel h-fit p-5"}>
      <p className="text-xs text-text-subtle">
        Select an active source to inspect its latest session and focus it on the topology.
      </p>

      <div
        className="mt-3 max-h-[22rem] space-y-2 overflow-y-auto overscroll-contain pr-1"
        role="list"
        aria-label="Active source navigator"
      >
        {liveSources.map((source) => {
          const isSelected = source.sessions.some(
            (session) => session.sessionId === selectedSessionId,
          );
          const latestPath = source.latest.cwdState.path;
          const sessionLabel = `${source.sessions.length} ${
            source.sessions.length === 1 ? "session" : "sessions"
          }`;
          const pathLabel = `${source.distinctPathCount} ${
            source.distinctPathCount === 1 ? "path" : "paths"
          }`;

          return (
            <div key={source.sourceIp} role="listitem">
              <button
                type="button"
                aria-pressed={isSelected}
                aria-label={`Inspect active source ${source.sourceIp}; ${sessionLabel}; ${pathLabel}; latest path ${latestPath ?? "unknown"}`}
                onClick={() => onSelectSession(source.latest.sessionId)}
                className={`flex w-full min-w-0 items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${
                  isSelected
                    ? "border-primary-border bg-primary-subtle"
                    : "border-border hover:border-border-strong hover:bg-surface-hover"
                }`}
              >
                <span className="min-w-0">
                  <span className="block truncate font-mono text-xs font-semibold text-text">
                    {source.sourceIp}
                  </span>
                  <span className="mt-0.5 block text-xs text-text-subtle">
                    {sessionLabel} · {pathLabel}
                  </span>
                  <span className="mt-1 block truncate font-mono text-xs text-text-muted">
                    Latest: {latestPath ? compactDirectoryPath(latestPath) : "Unknown path"}
                  </span>
                </span>

                <span className="shrink-0">
                  {isSelected ? (
                    <span className="text-xs font-semibold text-primary">Selected</span>
                  ) : (
                    <ChevronRight className="h-4 w-4 text-text-subtle" aria-hidden="true" />
                  )}
                </span>
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
