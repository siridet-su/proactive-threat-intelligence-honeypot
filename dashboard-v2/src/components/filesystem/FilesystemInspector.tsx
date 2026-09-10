"use client";

import {
  ChevronDown,
  ChevronRight,
  FolderOpen,
  Route,
  ShieldAlert,
  Terminal,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import type {
  FilesystemClosedSession,
  FilesystemTopologyNode,
  FilesystemTopologySession,
} from "@/lib/dashboardTypes";
import {
  compactDirectoryPath,
  formatTimestamp,
  isSensitiveDirectory,
  pathBreadcrumbs,
  statusBadgeClass,
  statusLabel,
} from "./filesystemUtils";

interface FilesystemInspectorProps {
  selectedSession: FilesystemTopologySession | null;
  selectedClosedSession: FilesystemClosedSession | null;
  selectedNode: FilesystemTopologyNode | null;
  sessions: FilesystemTopologySession[];
  liveSessionCount: number;
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  onSelectPath: (path: string) => void;
  onOpenAudit?: (sessionId: string) => void;
}

type InspectorTab = "session" | "directory";
type DirectoryView = "recent" | "all";

interface DirectorySessionRowProps {
  session: FilesystemTopologySession;
  selected: boolean;
  onSelect?: () => void;
}

function DirectorySessionRow({ session, selected, onSelect }: DirectorySessionRowProps) {
  const path = session.cwdState.path;
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={`flex w-full items-start justify-between gap-3 rounded-lg px-2.5 py-2 text-left transition-colors duration-150 ${
        selected
          ? "border border-primary-border bg-primary-subtle text-text"
          : "border border-transparent hover:border-border hover:bg-surface-hover text-text"
      }`}
    >
      <span className="min-w-0">
        <span className="block truncate font-mono text-xs text-text">{session.sourceIp}</span>
        <span className="mt-0.5 block truncate font-mono text-xs text-text-muted" title={path ?? "Unknown path"}>
          {path ? compactDirectoryPath(path) : "Unknown path"}
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-2">
        <time className="text-right text-xs text-text-subtle">{formatTimestamp(session.cwdState.observedAt)}</time>
        {selected ? (
          <span className="rounded bg-surface px-1.5 py-0.5 text-[10px] font-semibold text-primary shadow-xs">
            Auditing
          </span>
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-text-subtle" aria-hidden="true" />
        )}
      </span>
    </button>
  );
}

export function FilesystemInspector({
  selectedSession,
  selectedClosedSession,
  selectedNode,
  sessions,
  liveSessionCount,
  selectedSessionId,
  onSelectSession,
  onSelectPath,
  onOpenAudit,
}: FilesystemInspectorProps) {
  const [activeTab, setActiveTab] = useState<InspectorTab>("session");
  const [directoryView, setDirectoryView] = useState<DirectoryView>("recent");

  const lastSelectedPath = useRef<string | null>(selectedNode?.path ?? null);
  const lastSelectedSession = useRef<string | null>(selectedSessionId);

  // Auto-switch to directory tab when a directory node is clicked
  useEffect(() => {
    if (selectedNode?.path && selectedNode.path !== lastSelectedPath.current) {
      lastSelectedPath.current = selectedNode.path;
      if (selectedSession && selectedNode.path === selectedSession.cwdState.path) {
        return;
      }
      const timer = window.setTimeout(() => {
        setActiveTab("directory");
      }, 0);
      return () => window.clearTimeout(timer);
    }
    lastSelectedPath.current = selectedNode?.path ?? null;
  }, [selectedNode?.path, selectedSession]);

  // Auto-switch to session tab when a session is selected
  useEffect(() => {
    if (selectedSessionId && selectedSessionId !== lastSelectedSession.current) {
      lastSelectedSession.current = selectedSessionId;
      const timer = window.setTimeout(() => {
        setActiveTab("session");
      }, 0);
      return () => window.clearTimeout(timer);
    }
    lastSelectedSession.current = selectedSessionId;
  }, [selectedSessionId]);

  const breadcrumbs = useMemo(
    () => (selectedNode ? pathBreadcrumbs(selectedNode.path) : []),
    [selectedNode],
  );

  const branchSessions = useMemo(() => {
    if (!selectedNode) return [];
    const sessionIds = new Set(selectedNode.sessionIds);
    return sessions
      .filter((session) => sessionIds.has(session.sessionId))
      .sort(
        (left, right) =>
          (Date.parse(right.cwdState.observedAt ?? "") || 0) - (Date.parse(left.cwdState.observedAt ?? "") || 0),
      );
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
      {/* Inspector Tabs */}
      <div className="flex items-center justify-between border-b border-border pb-3" role="tablist" aria-label="Inspector mode">
        <div className="flex items-center gap-1.5">
          <button
            id="tab-inspector-session"
            type="button"
            role="tab"
            aria-selected={activeTab === "session"}
            aria-controls="panel-inspector-session"
            onClick={() => setActiveTab("session")}
            className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors duration-150 ${
              activeTab === "session"
                ? "bg-primary-subtle text-primary shadow-xs"
                : "text-text-muted hover:bg-surface-hover hover:text-text"
            }`}
          >
            <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
            Session
            {selectedSession && (
              <span className="rounded-full bg-surface px-1.5 py-0.2 text-[10px] font-mono font-bold text-primary">
                .{selectedSession.sourceIp.split(".").pop()}
              </span>
            )}
          </button>

          <button
            id="tab-inspector-directory"
            type="button"
            role="tab"
            aria-selected={activeTab === "directory"}
            aria-controls="panel-inspector-directory"
            onClick={() => setActiveTab("directory")}
            className={`flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors duration-150 ${
              activeTab === "directory"
                ? "bg-primary-subtle text-primary shadow-xs"
                : "text-text-muted hover:bg-surface-hover hover:text-text"
            }`}
          >
            <FolderOpen className="h-3.5 w-3.5" aria-hidden="true" />
            Directory
            {selectedNode && (
              <span className="rounded-full bg-surface px-1.5 py-0.2 text-[10px] font-mono font-bold text-primary">
                {liveSessionCount}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* Tab Panel: Session Context */}
      {activeTab === "session" ? (
        <div id="panel-inspector-session" role="tabpanel" aria-labelledby="tab-inspector-session" className="mt-4">
          {selectedSession ? (
            <dl className="space-y-3 text-sm">
              <div className="flex items-center justify-between gap-2">
                <dt className="text-xs text-text-subtle">Source IP</dt>
                <dd className="font-mono text-xs font-semibold text-text">{selectedSession.sourceIp}</dd>
              </div>

              <div className="flex items-start justify-between gap-2">
                <dt className="text-xs text-text-subtle">
                  {selectedClosedSession ? "Last observed path" : "Current path"}
                </dt>
                <dd className="max-w-[14rem] text-right font-mono text-xs text-text break-all">
                  {selectedSession.cwdState.path ?? "Unknown"}
                </dd>
              </div>

              <div className="flex items-center justify-between gap-2">
                <dt className="text-xs text-text-subtle">Confidence</dt>
                <dd>
                  <span className={`ui-badge ${statusBadgeClass(selectedSession.cwdState.status)} text-[11px]`}>
                    {statusLabel(selectedSession.cwdState.status)}
                  </span>
                </dd>
              </div>

              <div className="flex items-center justify-between gap-2">
                <dt className="text-xs text-text-subtle">Observed at</dt>
                <dd className="text-xs text-text-muted">{formatTimestamp(selectedSession.cwdState.observedAt)}</dd>
              </div>

              {selectedClosedSession && (
                <>
                  <div className="flex items-center justify-between gap-2 border-t border-border pt-2.5">
                    <dt className="text-xs text-text-subtle">Connection state</dt>
                    <dd>
                      <span className="ui-badge border-warning-border bg-warning-subtle text-warning text-[11px]">
                        Closed
                      </span>
                    </dd>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <dt className="text-xs text-text-subtle">Closed at</dt>
                    <dd className="text-xs text-text-muted">
                      {formatTimestamp(selectedClosedSession.lifecycle.closedAt)}
                    </dd>
                  </div>
                </>
              )}

              <div className="mt-4 flex gap-2 rounded-lg border border-warning-border bg-warning-subtle p-2.5 text-xs text-text-muted">
                <ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                <p className="text-[11px] leading-relaxed">
                  Unknown paths remain unknown. This view never fills a missing directory with a guessed Linux path.
                </p>
              </div>

              {onOpenAudit && (
                <button
                  type="button"
                  onClick={() => onOpenAudit(selectedSession.sessionId)}
                  className="mt-3.5 flex w-full items-center justify-center gap-2 rounded-lg border border-primary-border bg-primary px-3 py-2 text-xs font-semibold text-surface transition-all hover:bg-primary/90 shadow-sm"
                >
                  <Route className="h-3.5 w-3.5" aria-hidden="true" />
                  Open Session Forensics & Replay ➜
                </button>
              )}
            </dl>
          ) : (
            <p className="py-4 text-center text-sm text-text-muted">
              Select a session from the list below or topology to inspect details.
            </p>
          )}
        </div>
      ) : (
        /* Tab Panel: Directory Details */
        <div id="panel-inspector-directory" role="tabpanel" aria-labelledby="tab-inspector-directory" className="mt-4">
          {selectedNode ? (
            <>
              <div>
                <div className="flex flex-wrap items-center gap-1 font-mono text-xs" aria-label="Directory breadcrumbs">
                  {breadcrumbs.map((segment, index) => {
                    const isLast = index === breadcrumbs.length - 1;
                    return (
                      <span key={segment.path} className="inline-flex items-center gap-1">
                        {index > 0 && <span className="text-text-subtle/50" aria-hidden="true">/</span>}
                        {isLast ? (
                          <span className="rounded bg-primary-subtle px-1.5 py-0.5 font-semibold text-primary">
                            {segment.name}
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => onSelectPath(segment.path)}
                            className="rounded px-1.5 py-0.5 text-text-muted transition-colors hover:bg-surface-hover hover:text-text"
                            title={`Navigate to ${segment.path}`}
                          >
                            {segment.name}
                          </button>
                        )}
                      </span>
                    );
                  })}
                </div>
                {isSensitiveDirectory(selectedNode.path) && (
                  <div className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-warning-border bg-warning-subtle px-2 py-0.5 text-[11px] font-semibold text-warning">
                    <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                    Sensitive target / Drop directory
                  </div>
                )}
              </div>

              <div className="mt-4">
                <div className="flex items-center justify-between gap-2 border-b border-border pb-2 text-xs">
                  <span className="font-semibold text-text">Live sessions</span>
                  <div className="flex items-center gap-1" role="tablist" aria-label="Directory session grouping">
                    <button
                      type="button"
                      role="tab"
                      aria-selected={directoryView === "recent"}
                      onClick={() => setDirectoryView("recent")}
                      className={`rounded px-2 py-0.5 text-[11px] font-medium transition-colors ${
                        directoryView === "recent"
                          ? "bg-surface-hover font-semibold text-text"
                          : "text-text-subtle hover:text-text"
                      }`}
                    >
                      Recent ({branchSessions.length})
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={directoryView === "all"}
                      onClick={() => setDirectoryView("all")}
                      className={`rounded px-2 py-0.5 text-[11px] font-medium transition-colors ${
                        directoryView === "all"
                          ? "bg-surface-hover font-semibold text-text"
                          : "text-text-subtle hover:text-text"
                      }`}
                    >
                      By IP ({sourceGroups.length})
                    </button>
                  </div>
                </div>

                {branchSessions.length ? (
                  directoryView === "recent" ? (
                    <div className="mt-2.5 max-h-60 space-y-1.5 overflow-y-auto overscroll-contain pr-1" role="tabpanel" aria-label="Recent directory activity">
                      {branchSessions.map((session) => (
                        <DirectorySessionRow
                          key={session.sessionId}
                          session={session}
                          selected={session.sessionId === selectedSessionId}
                          onSelect={() => onSelectSession(session.sessionId)}
                        />
                      ))}
                    </div>
                  ) : (
                    <div className="mt-2.5 max-h-60 space-y-1.5 overflow-y-auto overscroll-contain pr-1" role="tabpanel" aria-label="All directory activity grouped by source">
                      {sourceGroups.map((source) => (
                        <details key={source.sourceIp} className="group rounded-lg border border-border bg-surface-subtle overflow-hidden">
                          <summary className="cursor-pointer list-none px-3 py-2 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring [&::-webkit-details-marker]:hidden">
                            <span className="flex items-center justify-between gap-3">
                              <span className="min-w-0">
                                <span className="block truncate font-mono text-xs text-text">{source.sourceIp}</span>
                                <span className="mt-0.5 block text-[11px] text-text-subtle">
                                  {source.sessions.length} {source.sessions.length === 1 ? "session" : "sessions"}
                                </span>
                              </span>
                              <span className="flex items-center gap-1.5">
                                <time className="shrink-0 text-right text-[11px] text-text-subtle">
                                  {formatTimestamp(source.sessions[0]?.cwdState.observedAt ?? null)}
                                </time>
                                <ChevronDown className="h-3.5 w-3.5 shrink-0 text-text-subtle transition-transform duration-200 group-open:rotate-180" aria-hidden="true" />
                              </span>
                            </span>
                          </summary>
                          <div className="border-t border-border bg-surface p-1 space-y-1">
                            {source.sessions.map((session) => (
                              <DirectorySessionRow
                                key={session.sessionId}
                                session={session}
                                selected={session.sessionId === selectedSessionId}
                                onSelect={() => onSelectSession(session.sessionId)}
                              />
                            ))}
                          </div>
                        </details>
                      ))}
                    </div>
                  )
                ) : (
                  <p className="mt-3 text-xs text-text-muted">No live sessions are mapped to this directory branch.</p>
                )}
              </div>
            </>
          ) : (
            <p className="py-4 text-center text-sm text-text-muted">
              Select a live directory node on the topology to inspect its observed metadata.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
