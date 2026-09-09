"use client";

import { ChevronRight, Radio } from "lucide-react";
import { useMemo } from "react";

import type { FilesystemTopologySession } from "@/lib/dashboardTypes";
import { compactDirectoryPath } from "./filesystemUtils";

interface LiveSourcesProps {
  sessions: FilesystemTopologySession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
}

export function LiveSources({ sessions, selectedSessionId, onSelectSession }: LiveSourcesProps) {
  const sources = useMemo(() => {
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
        return { sourceIp, sessions: ordered, latest: ordered[0] };
      })
      .sort((left, right) => {
        const leftObservedAt = Date.parse(left.latest.cwdState.observedAt ?? "") || 0;
        const rightObservedAt = Date.parse(right.latest.cwdState.observedAt ?? "") || 0;
        return rightObservedAt - leftObservedAt;
      });
  }, [sessions]);

  return (
    <div className="ui-panel h-fit p-5">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Radio className="h-4 w-4 text-success" aria-hidden="true" />
          <h2 className="font-semibold">Live sources</h2>
        </div>
        <span className="ui-badge border-success-border bg-success-subtle text-success">{sources.length}</span>
      </div>
      <p className="mt-2 text-xs text-text-subtle">Choose a source to inspect its latest recorded session and route.</p>
      {sources.length ? (
        <div className="mt-4 max-h-[22rem] space-y-2 overflow-y-auto overscroll-contain pr-1" aria-label="Live sources">
          {sources.map((source) => {
            const selected = source.sessions.some((session) => session.sessionId === selectedSessionId);
            const latestPath = source.latest.cwdState.path;
            return (
              <button
                key={source.sourceIp}
                type="button"
                aria-pressed={selected}
                aria-label={`Inspect source ${source.sourceIp}; ${source.sessions.length} ${
                  source.sessions.length === 1 ? "session" : "sessions"
                }; latest verified path ${latestPath ?? "unknown"}`}
                onClick={() => onSelectSession(source.latest.sessionId)}
                className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors duration-150 ${
                  selected
                    ? "border-primary-border bg-primary-subtle"
                    : "border-border hover:border-border-strong hover:bg-surface-hover"
                }`}
              >
                <span className="min-w-0">
                  <span className="block truncate font-mono text-xs text-text">{source.sourceIp}</span>
                  <span className="mt-0.5 block text-xs text-text-subtle">
                    {source.sessions.length} {source.sessions.length === 1 ? "session" : "sessions"} · latest
                  </span>
                  <span className="mt-1 block truncate font-mono text-xs text-text-muted" title={latestPath ?? "Unknown path"}>
                    {latestPath ? compactDirectoryPath(latestPath) : "Unknown path"}
                  </span>
                </span>
                {selected ? (
                  <span className="shrink-0 text-xs font-semibold text-primary">Auditing</span>
                ) : (
                  <ChevronRight className="h-4 w-4 shrink-0 text-text-subtle" aria-hidden="true" />
                )}
              </button>
            );
          })}
        </div>
      ) : (
        <p className="mt-4 text-sm text-text-muted">No live sources have a known working directory yet.</p>
      )}
    </div>
  );
}
