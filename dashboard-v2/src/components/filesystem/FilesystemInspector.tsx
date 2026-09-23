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
  classifyRuleBasedPathInterest,
  compactDirectoryPath,
  formatTimestamp,
  formatRuleBasedPathInterestDescription,
  getDirectorySessionCounts,
  pathBreadcrumbs,
  statusBadgeClass,
  statusLabel,
} from "./filesystemUtils";

interface FilesystemInspectorProps {
  embedded?: boolean;
  selectedSession: FilesystemTopologySession | null;
  selectedClosedSession: FilesystemClosedSession | null;
  selectedNode: FilesystemTopologyNode | null;
  sessions: FilesystemTopologySession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  onSelectPath: (path: string) => void;
  onOpenAudit?: (sessionId: string) => void;
}

type InspectorTab = "session" | "directory";
type DirectoryView = "all" | "exact" | "sources";

interface DirectorySessionRowProps {
  session: FilesystemTopologySession;
  selected: boolean;
  onSelect?: () => void;
  isExact?: boolean;
}

function DirectorySessionRow({ session, selected, onSelect, isExact }: DirectorySessionRowProps) {
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
        <span className="flex items-center gap-1.5 font-mono text-xs text-text truncate">
          <span>{session.sourceIp}</span>
          {isExact !== undefined && (
            <span
              className={`rounded px-1.5 py-0.2 text-[10px] font-semibold ${
                isExact
                  ? "bg-primary-subtle text-primary border border-primary-border/50"
                  : "bg-surface-subtle text-text-subtle border border-border"
              }`}
            >
              {isExact ? "Exact" : "Subdir"}
            </span>
          )}
        </span>
        <span className="mt-0.5 block truncate font-mono text-xs text-text-muted" title={path ?? "Unknown path"}>
          {path ? compactDirectoryPath(path) : "Unknown path"}
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-2">
        <time className="text-right text-xs text-text-subtle">{formatTimestamp(session.cwdState.observedAt)}</time>
        {selected ? (
          <span className="rounded bg-surface px-1.5 py-0.5 text-xs font-semibold text-primary shadow-xs">
            Selected
          </span>
        ) : (
          <ChevronRight className="h-3.5 w-3.5 text-text-subtle" aria-hidden="true" />
        )}
      </span>
    </button>
  );
}

export function FilesystemInspector({
  embedded = false,
  selectedSession,
  selectedClosedSession,
  selectedNode,
  sessions,
  selectedSessionId,
  onSelectSession,
  onSelectPath,
  onOpenAudit,
}: FilesystemInspectorProps) {
  const [activeTab, setActiveTab] = useState<InspectorTab>("session");
  const [directoryView, setDirectoryView] = useState<DirectoryView>("all");

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
  const pathInterest = selectedNode ? classifyRuleBasedPathInterest(selectedNode.path) : null;

  const nodeCounts = useMemo(() => {
    if (!selectedNode) return { exactCount: 0, descendantCount: 0, branchCount: 0, uniqueSourcesCount: 0 };
    return getDirectorySessionCounts(selectedNode.path, selectedNode.sessionIds, sessions);
  }, [selectedNode, sessions]);

  const exactSessions = useMemo(() => {
    if (!selectedNode) return [];
    return sessions
      .filter((s) => s.cwdState.path === selectedNode.path)
      .sort(
        (a, b) =>
          (Date.parse(b.cwdState.observedAt ?? "") || 0) - (Date.parse(a.cwdState.observedAt ?? "") || 0),
      );
  }, [selectedNode, sessions]);

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

  const siblingSessions = useMemo(() => {
    if (!selectedSession) return [];
    return sessions
      .filter((s) => s.sourceIp === selectedSession.sourceIp && s.sessionId !== selectedSession.sessionId)
      .sort(
        (left, right) =>
          (Date.parse(right.cwdState.observedAt ?? "") || 0) - (Date.parse(left.cwdState.observedAt ?? "") || 0),
      );
  }, [selectedSession, sessions]);

  const sourceGroups = useMemo(() => {
    const listToGroup = directoryView === "exact" ? exactSessions : branchSessions;
    const grouped = new Map<string, FilesystemTopologySession[]>();
    for (const session of listToGroup) {
      const group = grouped.get(session.sourceIp) ?? [];
      group.push(session);
      grouped.set(session.sourceIp, group);
    }
    return [...grouped.entries()].map(([sourceIp, sourceSessions]) => ({ sourceIp, sessions: sourceSessions }));
  }, [branchSessions, directoryView, exactSessions]);

  return (
    <div className={embedded ? "" : "ui-panel h-fit p-5"}>
      {/* Inspector Tabs */}
      <div className="flex items-center justify-between border-b border-border pb-3" role="tablist" aria-label="Inspector mode">
        <div className="flex items-center gap-1.5">
          <button
            id="tab-inspector-session"
            type="button"
            role="tab"
            aria-selected={activeTab === "session"}
            aria-controls="panel-inspector-session"
            tabIndex={activeTab === "session" ? 0 : -1}
            onClick={() => setActiveTab("session")}
            onKeyDown={(event) => {
              if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
              event.preventDefault();
              setActiveTab("directory");
              document.getElementById("tab-inspector-directory")?.focus();
            }}
            className={`flex min-h-9 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors duration-150 ${
              activeTab === "session"
                ? "bg-primary-subtle text-primary shadow-xs"
                : "text-text-muted hover:bg-surface-hover hover:text-text"
            }`}
          >
            <Terminal className="h-3.5 w-3.5" aria-hidden="true" />
            Session
            {selectedSession && (
              <span className="rounded-full bg-surface px-1.5 py-0.2 text-xs font-mono font-bold text-primary">
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
            tabIndex={activeTab === "directory" ? 0 : -1}
            onClick={() => setActiveTab("directory")}
            onKeyDown={(event) => {
              if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
              event.preventDefault();
              setActiveTab("session");
              document.getElementById("tab-inspector-session")?.focus();
            }}
            className={`flex min-h-9 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors duration-150 ${
              activeTab === "directory"
                ? "bg-primary-subtle text-primary shadow-xs"
                : "text-text-muted hover:bg-surface-hover hover:text-text"
            }`}
          >
            <FolderOpen className="h-3.5 w-3.5" aria-hidden="true" />
            Directory
            {selectedNode && (
              <span
                className="rounded-full bg-surface px-1.5 py-0.2 text-xs font-mono font-bold text-primary"
                title={`${nodeCounts.exactCount} at exact path, ${nodeCounts.descendantCount} in child directories (${nodeCounts.branchCount} total across branch)`}
              >
                {nodeCounts.branchCount}
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
                  <span className={`ui-badge ${statusBadgeClass(selectedSession.cwdState.status)} text-xs`}>
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
                      <span className="ui-badge border-warning-border bg-warning-subtle text-warning text-xs">
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

              {siblingSessions.length > 0 && (
                <div className="border-t border-border pt-3">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-xs font-semibold text-text">
                      Other active sessions from this IP ({siblingSessions.length})
                    </span>
                    <span className="text-[11px] text-text-subtle">Concurrent routes</span>
                  </div>
                  <div className="space-y-1.5 max-h-40 overflow-y-auto overscroll-contain pr-1">
                    {siblingSessions.map((sibling) => (
                      <div
                        key={sibling.sessionId}
                        className="flex items-center justify-between gap-2 rounded-lg border border-border bg-surface-subtle/50 px-2.5 py-1.5 transition-colors hover:border-border-strong hover:bg-surface-hover"
                      >
                        <button
                          type="button"
                          onClick={() => onSelectSession(sibling.sessionId)}
                          className="flex min-w-0 flex-1 items-center justify-between gap-2 text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-focus-ring rounded"
                          aria-label={`Switch to session ${sibling.sessionId}; path ${sibling.cwdState.path ?? "unknown"}`}
                        >
                          <div className="min-w-0">
                            <span className="block font-mono text-xs text-text truncate">
                              {sibling.sessionId.slice(0, 10)}…
                            </span>
                            <span
                              className="block font-mono text-xs text-text-muted truncate"
                              title={sibling.cwdState.path ?? "Unknown path"}
                            >
                              {sibling.cwdState.path ? compactDirectoryPath(sibling.cwdState.path) : "Unknown path"}
                            </span>
                          </div>
                          <span className="text-[10px] text-text-subtle shrink-0">
                            {formatTimestamp(sibling.cwdState.observedAt)}
                          </span>
                        </button>
                        {onOpenAudit && (
                          <button
                            type="button"
                            title={`Audit sibling session ${sibling.sessionId}`}
                            aria-label={`Audit sibling session ${sibling.sessionId}`}
                            onClick={() => onOpenAudit(sibling.sessionId)}
                            className="flex h-6 w-6 shrink-0 items-center justify-center rounded text-primary hover:bg-primary-subtle transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-focus-ring"
                          >
                            <Route className="h-3.5 w-3.5" aria-hidden="true" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="mt-4 flex gap-2 rounded-lg border border-warning-border bg-warning-subtle p-2.5 text-xs text-text-muted">
                <ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                <p className="text-xs leading-relaxed">
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
                {pathInterest && (
                  <aside
                    data-testid="rule-based-path-interest"
                    role="note"
                    aria-label={formatRuleBasedPathInterestDescription(pathInterest)}
                    className="mt-3 flex items-start gap-2 rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-text"
                  >
                    <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
                    <div className="min-w-0 space-y-1">
                      <p className="font-semibold text-text">{pathInterest.label}</p>
                      <p>
                        <span className="font-medium">Category:</span> {pathInterest.categoryLabel}
                      </p>
                      <p>
                        <span className="font-medium">Matched rule:</span> {pathInterest.ruleDescription}
                      </p>
                      <p>
                        <span className="font-medium">Matched root:</span>{" "}
                        <code className="font-mono">{pathInterest.matchedRoot}</code>
                      </p>
                      <p data-testid="rule-based-path-interest-explanation" className="leading-relaxed text-text-muted">
                        {pathInterest.explanation}
                      </p>
                    </div>
                  </aside>
                )}
              </div>

              <div className="mt-3 grid grid-cols-3 gap-2 text-center text-xs select-none">
                <div className="rounded-lg border border-border bg-surface-subtle/60 p-2">
                  <div className="text-[10px] font-medium uppercase tracking-wider text-text-subtle">Exact path</div>
                  <div className="mt-0.5 font-mono text-sm font-semibold text-text">{nodeCounts.exactCount}</div>
                </div>
                <div className="rounded-lg border border-border bg-surface-subtle/60 p-2">
                  <div className="text-[10px] font-medium uppercase tracking-wider text-text-subtle">In subdirs</div>
                  <div className="mt-0.5 font-mono text-sm font-semibold text-text">{nodeCounts.descendantCount}</div>
                </div>
                <div className="rounded-lg border border-border bg-surface-subtle/60 p-2">
                  <div className="text-[10px] font-medium uppercase tracking-wider text-text-subtle">Unique sources</div>
                  <div className="mt-0.5 font-mono text-sm font-semibold text-text">{nodeCounts.uniqueSourcesCount}</div>
                </div>
              </div>

              <div className="mt-6">
                <div className="mb-2 text-sm font-semibold text-text">Directory sessions</div>
                <div
                  className="mb-4 grid w-full grid-cols-3 gap-1 rounded-lg border border-border bg-surface-subtle p-1 text-xs"
                  role="tablist"
                  aria-label="Directory session grouping"
                >
                  <button
                    type="button"
                    role="tab"
                    aria-selected={directoryView === "all"}
                    onClick={() => setDirectoryView("all")}
                    className={`flex h-8 items-center justify-center gap-1 rounded-md px-1 font-medium transition-colors ${
                      directoryView === "all"
                        ? "bg-surface text-text shadow-xs border border-border/50"
                        : "text-text-subtle hover:bg-surface-hover hover:text-text border border-transparent"
                    }`}
                    title={`All sessions in this branch (${nodeCounts.branchCount})`}
                  >
                    <span className="truncate">Branch</span>
                    <span className="opacity-60 shrink-0">({nodeCounts.branchCount})</span>
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={directoryView === "exact"}
                    onClick={() => setDirectoryView("exact")}
                    className={`flex h-8 items-center justify-center gap-1 rounded-md px-1 font-medium transition-colors ${
                      directoryView === "exact"
                        ? "bg-surface text-text shadow-xs border border-border/50"
                        : "text-text-subtle hover:bg-surface-hover hover:text-text border border-transparent"
                    }`}
                    title={`Sessions ending exactly here (${nodeCounts.exactCount})`}
                  >
                    <span className="truncate">Exact</span>
                    <span className="opacity-60 shrink-0">({nodeCounts.exactCount})</span>
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={directoryView === "sources"}
                    onClick={() => setDirectoryView("sources")}
                    className={`flex h-8 items-center justify-center gap-1 rounded-md px-1 font-medium transition-colors ${
                      directoryView === "sources"
                        ? "bg-surface text-text shadow-xs border border-border/50"
                        : "text-text-subtle hover:bg-surface-hover hover:text-text border border-transparent"
                    }`}
                    title={`Grouped by source IP (${sourceGroups.length})`}
                  >
                    <span className="truncate">Sources</span>
                    <span className="opacity-60 shrink-0">({sourceGroups.length})</span>
                  </button>
                </div>

                {directoryView === "all" ? (
                  branchSessions.length ? (
                    <div className="mt-2.5 max-h-60 space-y-1.5 overflow-y-auto overscroll-contain pr-1" role="tabpanel" aria-label="All directory sessions in branch">
                      {branchSessions.map((session) => (
                        <DirectorySessionRow
                          key={session.sessionId}
                          session={session}
                          selected={session.sessionId === selectedSessionId}
                          isExact={session.cwdState.path === selectedNode.path}
                          onSelect={() => onSelectSession(session.sessionId)}
                        />
                      ))}
                    </div>
                  ) : (
                    <p className="mt-3 text-xs text-text-muted">No live sessions are mapped to this directory branch.</p>
                  )
                ) : directoryView === "exact" ? (
                  exactSessions.length ? (
                    <div className="mt-2.5 max-h-60 space-y-1.5 overflow-y-auto overscroll-contain pr-1" role="tabpanel" aria-label="Exact path directory sessions">
                      {exactSessions.map((session) => (
                        <DirectorySessionRow
                          key={session.sessionId}
                          session={session}
                          selected={session.sessionId === selectedSessionId}
                          isExact={true}
                          onSelect={() => onSelectSession(session.sessionId)}
                        />
                      ))}
                    </div>
                  ) : (
                    <p className="mt-3 text-xs text-text-muted">
                      No active sessions are directly located in <code className="font-mono text-text">{selectedNode.path}</code>.
                      {nodeCounts.descendantCount > 0 ? ` All ${nodeCounts.descendantCount} active sessions in this branch are inside subdirectories.` : ""}
                    </p>
                  )
                ) : (
                  sourceGroups.length ? (
                    <div className="mt-2.5 max-h-60 space-y-1.5 overflow-y-auto overscroll-contain pr-1" role="tabpanel" aria-label="Directory activity grouped by source">
                      {sourceGroups.map((source) => (
                        <details key={source.sourceIp} className="group rounded-lg border border-border bg-surface-subtle overflow-hidden">
                          <summary className="cursor-pointer list-none px-3 py-2 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring [&::-webkit-details-marker]:hidden">
                            <span className="flex items-center justify-between gap-3">
                              <span className="min-w-0">
                                <span className="block truncate font-mono text-xs text-text">{source.sourceIp}</span>
                                <span className="mt-0.5 block text-xs text-text-subtle">
                                  {source.sessions.length} {source.sessions.length === 1 ? "session" : "sessions"}
                                </span>
                              </span>
                              <span className="flex items-center gap-1.5">
                                <time className="shrink-0 text-right text-xs text-text-subtle">
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
                                isExact={session.cwdState.path === selectedNode.path}
                                onSelect={() => onSelectSession(session.sessionId)}
                              />
                            ))}
                          </div>
                        </details>
                      ))}
                    </div>
                  ) : (
                    <p className="mt-3 text-xs text-text-muted">No sources are mapped to this directory branch.</p>
                  )
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
