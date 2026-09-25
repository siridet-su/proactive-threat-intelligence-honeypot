"use client";

import { ChevronDown, ListTree } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type {
  FilesystemClosedSession,
  FilesystemTopologyNode,
  FilesystemTopologySession,
} from "@/lib/dashboardTypes";
import { FilesystemInspector } from "./FilesystemInspector";
import { SessionSourceList } from "./SessionSourceList";

interface FilesystemContextPanelProps {
  selectedSession: FilesystemTopologySession | null;
  selectedClosedSession: FilesystemClosedSession | null;
  selectedNode: FilesystemTopologyNode | null;
  sessions: FilesystemTopologySession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  onSelectPath: (path: string) => void;
  onOpenAudit: (sessionId: string) => void;
}

export function FilesystemContextPanel({
  selectedSession,
  selectedClosedSession,
  selectedNode,
  sessions,
  selectedSessionId,
  onSelectSession,
  onSelectPath,
  onOpenAudit,
}: FilesystemContextPanelProps) {
  const sourceCount = useMemo(() => new Set(sessions.map((session) => session.sourceIp)).size, [sessions]);
  const [sourceBrowserOpen, setSourceBrowserOpen] = useState(false);
  const userToggledSourceBrowser = useRef(false);

  useEffect(() => {
    if (userToggledSourceBrowser.current) return;
    setSourceBrowserOpen(sourceCount > 1);
  }, [sourceCount]);

  return (
    <aside className="ui-panel min-w-0 overflow-hidden p-5" aria-label="Filesystem selection and sources">
      <FilesystemInspector
        embedded
        selectedSession={selectedSession}
        selectedClosedSession={selectedClosedSession}
        selectedNode={selectedNode}
        sessions={sessions}
        selectedSessionId={selectedSessionId}
        onSelectSession={onSelectSession}
        onSelectPath={onSelectPath}
        onOpenAudit={onOpenAudit}
      />

      {sourceCount > 1 && (
        <div className="mt-5 border-t border-border pt-4">
          <button
            type="button"
            aria-expanded={sourceBrowserOpen}
            aria-controls="filesystem-source-browser"
            onClick={() => {
              userToggledSourceBrowser.current = true;
              setSourceBrowserOpen((current) => !current);
            }}
            className="flex min-h-9 w-full items-center justify-between gap-3 rounded-lg px-2 text-left text-sm font-semibold text-text transition-colors hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            <span className="flex items-center gap-2">
              <ListTree className="h-4 w-4 text-primary" aria-hidden="true" />
              Source navigator
              <span className="ui-badge text-xs">{sourceCount}</span>
            </span>
            <ChevronDown
              className={`h-4 w-4 text-text-subtle transition-transform duration-150 ${sourceBrowserOpen ? "rotate-180" : ""}`}
              aria-hidden="true"
            />
          </button>
          {sourceBrowserOpen && (
            <div id="filesystem-source-browser" className="mt-3">
              <SessionSourceList
                embedded
                sessions={sessions}
                selectedSessionId={selectedSessionId}
                onSelectSession={onSelectSession}
              />
            </div>
          )}
        </div>
      )}
    </aside>
  );
}
