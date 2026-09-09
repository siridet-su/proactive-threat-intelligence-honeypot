"use client";

import { CircleDot } from "lucide-react";
import { useMemo, useState } from "react";

import type { FilesystemTopologyNode, FilesystemTopologySession } from "@/lib/dashboardTypes";
import { compactDirectoryPath, formatTimestamp } from "./filesystemUtils";

interface PathInspectorProps {
  selectedNode: FilesystemTopologyNode | null;
  sessions: FilesystemTopologySession[];
  liveSessionCount: number;
}

type DirectoryView = "recent" | "all";

function DirectorySessionRow({ session }: { session: FilesystemTopologySession }) {
  const path = session.cwdState.path;
  return (
    <div className="flex items-start justify-between gap-3 py-2.5">
      <span className="min-w-0">
        <span className="block truncate font-mono text-xs text-text">{session.sourceIp}</span>
        <span className="mt-0.5 block truncate font-mono text-xs text-text-muted" title={path ?? "Unknown path"}>
          {path ? compactDirectoryPath(path) : "Unknown path"}
        </span>
      </span>
      <time className="shrink-0 text-right text-xs text-text-subtle">{formatTimestamp(session.cwdState.observedAt)}</time>
    </div>
  );
}

export function PathInspector({ selectedNode, sessions, liveSessionCount }: PathInspectorProps) {
  const [view, setView] = useState<DirectoryView>("recent");
  const branchSessions = useMemo(() => {
    if (!selectedNode) return [];
    const sessionIds = new Set(selectedNode.sessionIds);
    return sessions
      .filter((session) => sessionIds.has(session.sessionId))
      .sort((left, right) => (Date.parse(right.cwdState.observedAt ?? "") || 0) - (Date.parse(left.cwdState.observedAt ?? "") || 0));
  }, [selectedNode, sessions]);
  const sourceGroups = useMemo(() => {
    const grouped = new Map<string, FilesystemTopologySession[]>();
    for (const session of branchSessions) {
      const group = grouped.get(session.sourceIp) ?? [];
      group.push(session);
      grouped.set(session.sourceIp, group);
    }
    return [...grouped.entries()].map(([sourceIp, sourceSessions]) => ({ sourceIp, sessions: sourceSessions }));
  }, [branchSessions]);

  return (
    <div className="ui-panel h-fit p-5">
      <div className="flex items-center gap-2">
        <CircleDot className="h-4 w-4 text-primary" aria-hidden="true" />
        <h2 className="font-semibold">Directory inspector</h2>
      </div>
      {selectedNode ? (
        <>
          <p className="mt-5 break-all font-mono text-sm text-text">{selectedNode.path}</p>
          <dl className="mt-5 grid gap-4 text-sm sm:grid-cols-2 xl:grid-cols-1">
            <div>
              <dt className="text-xs text-text-subtle">Parent directory</dt>
              <dd className="mt-1 break-all font-mono text-text">{selectedNode.parentPath ?? "Filesystem root"}</dd>
            </div>
            <div>
              <dt className="text-xs text-text-subtle">Depth</dt>
              <dd className="mt-1 font-mono text-text">{selectedNode.depth}</dd>
            </div>
            <div>
              <dt className="text-xs text-text-subtle">Live sessions here</dt>
              <dd className="mt-1 font-semibold text-text">{liveSessionCount}</dd>
            </div>
            <div>
              <dt className="text-xs text-text-subtle">Sessions in branch</dt>
              <dd className="mt-1 font-semibold text-text">{branchSessions.length}</dd>
            </div>
            <div>
              <dt className="text-xs text-text-subtle">Latest observation</dt>
              <dd className="mt-1 text-text-muted">{formatTimestamp(selectedNode.observedAt)}</dd>
            </div>
          </dl>
          <div className="mt-5 border-t border-border pt-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">Directory activity</p>
              <div className="flex rounded-lg border border-border bg-surface-subtle p-0.5" role="tablist" aria-label="Directory activity view">
                {([
                  ["recent", "Recent"],
                  ["all", "All"],
                ] as const).map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    role="tab"
                    aria-selected={view === value}
                    onClick={() => setView(value)}
                    className={`rounded-md px-2.5 py-1 text-xs font-semibold transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-offset-2 focus-visible:ring-offset-surface ${
                      view === value ? "bg-surface text-text shadow-sm" : "text-text-subtle hover:bg-surface-hover hover:text-text"
                    }`}
                  >
                    {label} <span className="font-mono">{value === "recent" ? Math.min(5, branchSessions.length) : branchSessions.length}</span>
                  </button>
                ))}
              </div>
            </div>

            {branchSessions.length ? (
              view === "recent" ? (
                <div className="mt-3 divide-y divide-border" role="tabpanel" aria-label="Recent directory activity">
                  {branchSessions.slice(0, 5).map((session) => (
                    <DirectorySessionRow key={session.sessionId} session={session} />
                  ))}
                </div>
              ) : (
                <div className="mt-3 max-h-80 space-y-2 overflow-y-auto overscroll-contain pr-1" role="tabpanel" aria-label="All directory activity grouped by source">
                  {sourceGroups.map((source) => (
                    <details key={source.sourceIp} className="rounded-lg border border-border bg-surface-subtle">
                      <summary className="cursor-pointer list-none px-3 py-2.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring focus-visible:ring-inset [&::-webkit-details-marker]:hidden">
                        <span className="flex items-center justify-between gap-3">
                          <span className="min-w-0">
                            <span className="block truncate font-mono text-xs text-text">{source.sourceIp}</span>
                            <span className="mt-0.5 block text-xs text-text-subtle">
                              {source.sessions.length} {source.sessions.length === 1 ? "session" : "sessions"}
                            </span>
                          </span>
                          <time className="shrink-0 text-right text-xs text-text-subtle">{formatTimestamp(source.sessions[0]?.cwdState.observedAt ?? null)}</time>
                        </span>
                      </summary>
                      <div className="divide-y divide-border border-t border-border bg-surface px-3">
                        {source.sessions.map((session) => (
                          <DirectorySessionRow key={session.sessionId} session={session} />
                        ))}
                      </div>
                    </details>
                  ))}
                </div>
              )
            ) : (
              <p className="mt-3 text-sm text-text-muted">No live sessions are currently mapped to this directory branch.</p>
            )}
          </div>
        </>
      ) : (
        <p className="mt-5 text-sm text-text-muted">Select a live directory to inspect its observed metadata.</p>
      )}
    </div>
  );
}
