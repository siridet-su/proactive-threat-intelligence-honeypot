"use client";

import { ChevronLeft, ChevronRight, CircleDot, Search } from "lucide-react";
import { useMemo, useState } from "react";

import type { FilesystemTopologyNode, FilesystemTopologySession } from "@/lib/dashboardTypes";
import { formatTimestamp, INSPECTOR_PAGE_SIZE } from "./filesystemUtils";

interface PathInspectorProps {
  selectedNode: FilesystemTopologyNode | null;
  sessionById: Map<string, FilesystemTopologySession>;
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
}

export function PathInspector({
  selectedNode,
  sessionById,
  selectedSessionId,
  onSelectSession,
}: PathInspectorProps) {
  const [pathSessionQuery, setPathSessionQuery] = useState("");
  const [pathSessionPage, setPathSessionPage] = useState(0);

  const matchingPathSessionIds = useMemo(() => {
    const query = pathSessionQuery.trim().toLowerCase();
    const sessionIds = selectedNode?.sessionIds ?? [];
    if (!query) return sessionIds;
    return sessionIds.filter((id) => {
      const session = sessionById.get(id);
      return id.toLowerCase().includes(query) || session?.sourceIp.toLowerCase().includes(query);
    });
  }, [pathSessionQuery, selectedNode?.sessionIds, sessionById]);

  const pathSessionPageCount = Math.max(1, Math.ceil(matchingPathSessionIds.length / INSPECTOR_PAGE_SIZE));
  const safePathSessionPage = Math.min(pathSessionPage, pathSessionPageCount - 1);
  const visiblePathSessionIds = matchingPathSessionIds.slice(
    safePathSessionPage * INSPECTOR_PAGE_SIZE,
    (safePathSessionPage + 1) * INSPECTOR_PAGE_SIZE,
  );

  return (
    <div className="ui-panel h-fit p-5">
      <div className="flex items-center gap-2">
        <CircleDot className="h-4 w-4 text-primary" aria-hidden="true" />
        <h2 className="font-semibold">Path inspector</h2>
      </div>
      {selectedNode ? (
        <>
          <p className="mt-5 break-all font-mono text-sm text-text">{selectedNode.path}</p>
          <dl className="mt-5 space-y-3 text-sm">
            <div className="flex justify-between gap-4">
              <dt className="text-text-subtle">Observed sessions</dt>
              <dd className="font-semibold text-text">{selectedNode.sessionIds.length}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt className="text-text-subtle">Latest observation</dt>
              <dd className="text-right text-text-muted">{formatTimestamp(selectedNode.observedAt)}</dd>
            </div>
          </dl>
          <div className="mt-6 border-t border-border pt-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">Sessions at this path</p>
              <span className="text-xs text-text-subtle">{matchingPathSessionIds.length}</span>
            </div>
            <label className="relative block">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-subtle" aria-hidden="true" />
              <span className="sr-only">Filter sessions at this path</span>
              <input
                type="search"
                value={pathSessionQuery}
                onChange={(event) => {
                  setPathSessionQuery(event.target.value);
                  setPathSessionPage(0);
                }}
                className="ui-field h-9 min-h-9 pl-9 text-xs"
                placeholder="Find session or source IP"
              />
            </label>
            <div className="mt-3 space-y-2">
              {visiblePathSessionIds.map((id) => {
                const session = sessionById.get(id);
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => onSelectSession(id)}
                    className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2 text-left transition-colors ${
                      id === selectedSessionId ? "border-primary-border bg-primary-subtle" : "border-border hover:bg-surface-hover"
                    }`}
                  >
                    <span className="min-w-0">
                      <span className="block truncate font-mono text-xs text-text">{id}</span>
                      <span className="mt-0.5 block font-mono text-xs text-text-subtle">{session?.sourceIp ?? "Unknown"}</span>
                    </span>
                    <ChevronRight className="h-4 w-4 shrink-0 text-text-subtle" />
                  </button>
                );
              })}
            </div>
            {matchingPathSessionIds.length === 0 && (
              <p className="mt-3 text-xs text-text-subtle">No sessions match this filter.</p>
            )}
            {pathSessionPageCount > 1 && (
              <div className="mt-3 flex items-center justify-between gap-2">
                <button
                  type="button"
                  className="ui-button h-8 min-h-8 px-2 text-xs"
                  disabled={safePathSessionPage === 0}
                  onClick={() => setPathSessionPage((page) => Math.max(0, page - 1))}
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                  Previous
                </button>
                <span className="text-xs text-text-subtle">
                  {safePathSessionPage + 1} / {pathSessionPageCount}
                </span>
                <button
                  type="button"
                  className="ui-button h-8 min-h-8 px-2 text-xs"
                  disabled={safePathSessionPage >= pathSessionPageCount - 1}
                  onClick={() => setPathSessionPage((page) => Math.min(pathSessionPageCount - 1, page + 1))}
                >
                  Next
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            )}
          </div>
        </>
      ) : (
        <p className="mt-5 text-sm text-text-muted">Select a live directory to inspect the sessions observed there.</p>
      )}
    </div>
  );
}
