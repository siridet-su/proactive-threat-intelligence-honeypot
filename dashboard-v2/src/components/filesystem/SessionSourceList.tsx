"use client";

import { ChevronDown, ChevronRight, History, Radio, Route } from "lucide-react";
import { useMemo, useState } from "react";

import type { FilesystemClosedSession, FilesystemTopologySession } from "@/lib/dashboardTypes";
import { compactDirectoryPath, formatTimestamp } from "./filesystemUtils";
import { handleRovingTabKey } from "./tabSemantics";

interface SessionSourceListProps {
  embedded?: boolean;
  sessions: FilesystemTopologySession[];
  recentClosedSessions: FilesystemClosedSession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  onAuditSession?: (sessionId: string) => void;
}

type TabKey = "live" | "closed";

const SOURCE_TABS = ["live", "closed"] as const;

export function SessionSourceList({
  embedded = false,
  sessions,
  recentClosedSessions,
  selectedSessionId,
  onSelectSession,
  onAuditSession,
}: SessionSourceListProps) {
  const [userCollapsedIps, setUserCollapsedIps] = useState<Set<string>>(new Set());
  const [userExpandedIps, setUserExpandedIps] = useState<Set<string>>(new Set());

  const isSelectedClosed = useMemo(
    () => recentClosedSessions.some((s) => s.sessionId === selectedSessionId),
    [recentClosedSessions, selectedSessionId],
  );

  const [userTabChoice, setUserTabChoice] = useState<{ sessionId: string | null; tab: TabKey } | null>(null);

  const activeTab: TabKey =
    userTabChoice && userTabChoice.sessionId === selectedSessionId
      ? userTabChoice.tab
      : isSelectedClosed
        ? "closed"
        : "live";

  const selectTab = (tab: TabKey) => {
    setUserTabChoice({ sessionId: selectedSessionId, tab });
  };

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
        const distinctPaths = Array.from(
          new Set(ordered.map((s) => s.cwdState.path).filter((p): p is string => Boolean(p))),
        );
        return { sourceIp, sessions: ordered, latest: ordered[0], distinctPaths };
      })
      .sort((left, right) => {
        const leftObservedAt = Date.parse(left.latest.cwdState.observedAt ?? "") || 0;
        const rightObservedAt = Date.parse(right.latest.cwdState.observedAt ?? "") || 0;
        return rightObservedAt - leftObservedAt;
      });
  }, [sessions]);

  const isSourceExpanded = (source: { sourceIp: string; sessions: FilesystemTopologySession[] }) => {
    if (source.sessions.length <= 1) return false;
    if (userCollapsedIps.has(source.sourceIp)) return false;
    if (userExpandedIps.has(source.sourceIp)) return true;
    return source.sessions.some((s) => s.sessionId === selectedSessionId);
  };

  const toggleSourceExpand = (sourceIp: string, isCurrentlyExpanded: boolean) => {
    if (isCurrentlyExpanded) {
      setUserCollapsedIps((prev) => new Set(prev).add(sourceIp));
      setUserExpandedIps((prev) => {
        const next = new Set(prev);
        next.delete(sourceIp);
        return next;
      });
    } else {
      setUserExpandedIps((prev) => new Set(prev).add(sourceIp));
      setUserCollapsedIps((prev) => {
        const next = new Set(prev);
        next.delete(sourceIp);
        return next;
      });
    }
  };

  return (
    <div className={embedded ? "" : "ui-panel h-fit p-5"}>
      {/* Tab Switcher Header */}
      <div className="flex items-center justify-between gap-2 border-b border-border pb-3" role="tablist" aria-label="Session telemetry views">
        <div className="flex items-center gap-1.5">
          <button
            id="tab-source-live"
            type="button"
            role="tab"
            aria-selected={activeTab === "live"}
            aria-controls="panel-source-live"
            tabIndex={activeTab === "live" ? 0 : -1}
            onClick={() => selectTab("live")}
            onKeyDown={(event) => handleRovingTabKey({
              event,
              tabs: SOURCE_TABS,
              currentTab: "live",
              onSelect: selectTab,
              tabId: (tab) => `tab-source-${tab}`,
            })}
            className={`flex min-h-9 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors duration-150 ${
              activeTab === "live"
                ? "bg-success-subtle text-success shadow-xs"
                : "text-text-muted hover:bg-surface-hover hover:text-text"
            }`}
          >
            <Radio className="h-3.5 w-3.5" aria-hidden="true" />
            Live sources
            <span
              className={`rounded-full px-1.5 py-0.2 text-xs font-bold ${
                activeTab === "live" ? "bg-surface text-success" : "bg-surface-subtle text-text-subtle"
              }`}
            >
              {liveSources.length}
            </span>
          </button>

          <button
            id="tab-source-closed"
            type="button"
            role="tab"
            aria-selected={activeTab === "closed"}
            aria-controls="panel-source-closed"
            tabIndex={activeTab === "closed" ? 0 : -1}
            onClick={() => selectTab("closed")}
            onKeyDown={(event) => handleRovingTabKey({
              event,
              tabs: SOURCE_TABS,
              currentTab: "closed",
              onSelect: selectTab,
              tabId: (tab) => `tab-source-${tab}`,
            })}
            className={`flex min-h-9 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors duration-150 ${
              activeTab === "closed"
                ? "bg-warning-subtle text-warning shadow-xs"
                : "text-text-muted hover:bg-surface-hover hover:text-text"
            }`}
          >
            <History className="h-3.5 w-3.5" aria-hidden="true" />
            Closed
            <span
              className={`rounded-full px-1.5 py-0.2 text-xs font-bold ${
                activeTab === "closed" ? "bg-surface text-warning" : "bg-surface-subtle text-text-subtle"
              }`}
            >
              {recentClosedSessions.length}
            </span>
          </button>
        </div>
      </div>

      <p className="mt-2 text-xs text-text-subtle">
        {activeTab === "live"
          ? "Choose an active source cluster to inspect its sessions and routes."
          : "Closed connections remain audit-ready until telemetry retention expires."}
      </p>

      {/* Tab Panels */}
      {activeTab === "live" ? (
        <div id="panel-source-live" role="tabpanel" aria-labelledby="tab-source-live" className="mt-3">
          {liveSources.length ? (
            <div className="max-h-[22rem] space-y-2 overflow-y-auto overscroll-contain pr-1">
              {liveSources.map((source) => {
                const isMulti = source.sessions.length > 1;
                const isExpanded = isSourceExpanded(source);
                const isClusterActive = source.sessions.some((s) => s.sessionId === selectedSessionId);
                const distinctPaths = source.distinctPaths;
                const latestPath = source.latest.cwdState.path;

                if (!isMulti) {
                  return (
                    <div
                      key={source.sourceIp}
                      className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors duration-150 ${
                        isClusterActive
                          ? "border-primary-border bg-primary-subtle"
                          : "border-border hover:border-border-strong hover:bg-surface-hover"
                      }`}
                    >
                      <button
                        type="button"
                        aria-pressed={isClusterActive}
                        aria-label={`Inspect source ${source.sourceIp}; 1 session; path ${latestPath ?? "unknown"}`}
                        onClick={() => onSelectSession(source.latest.sessionId)}
                        className="flex min-w-0 flex-1 items-center justify-between gap-3 rounded-md text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                      >
                        <span className="min-w-0">
                          <span className="block truncate font-mono text-xs text-text">{source.sourceIp}</span>
                          <span className="mt-0.5 block text-xs text-text-subtle">
                            1 session · live
                          </span>
                          <span
                            className="mt-1 block truncate font-mono text-xs text-text-muted"
                            title={latestPath ?? "Unknown path"}
                          >
                            {latestPath ? compactDirectoryPath(latestPath) : "Unknown path"}
                          </span>
                        </span>
                        <span className="shrink-0">
                          {isClusterActive ? (
                            <span className="text-xs font-semibold text-primary">Selected</span>
                          ) : (
                            <ChevronRight className="h-4 w-4 text-text-subtle" aria-hidden="true" />
                          )}
                        </span>
                      </button>
                      {onAuditSession && (
                        <button
                          type="button"
                          title="Open in Session Forensics & Replay"
                          aria-label={`Open ${source.sourceIp} in Session Forensics and Replay`}
                          onClick={() => onAuditSession(source.latest.sessionId)}
                          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-surface text-primary transition-colors hover:border-primary-border hover:bg-primary-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                        >
                          <Route className="h-4 w-4" aria-hidden="true" />
                        </button>
                      )}
                    </div>
                  );
                }

                return (
                  <div
                    key={source.sourceIp}
                    className={`w-full rounded-lg border transition-colors duration-150 overflow-hidden ${
                      isClusterActive
                        ? "border-primary-border bg-surface shadow-2xs"
                        : "border-border bg-surface hover:border-border-strong"
                    }`}
                  >
                    <div
                      className={`flex items-center justify-between gap-2 px-3 py-2.5 transition-colors ${
                        isClusterActive ? "bg-primary-subtle/50" : "hover:bg-surface-hover"
                      }`}
                    >
                      <button
                        type="button"
                        aria-expanded={isExpanded}
                        aria-controls={`cluster-sessions-${source.sourceIp}`}
                        onClick={() => toggleSourceExpand(source.sourceIp, isExpanded)}
                        className="flex min-w-0 flex-1 items-center justify-between gap-2 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring rounded-md"
                      >
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-semibold text-text truncate">
                              {source.sourceIp}
                            </span>
                            <span className="rounded-full bg-surface px-1.5 py-0.2 text-[10px] font-bold text-primary border border-primary-border/40">
                              {source.sessions.length} sessions
                            </span>
                          </div>
                          <div className="mt-0.5 text-xs text-text-subtle">
                            Across {distinctPaths.length} {distinctPaths.length === 1 ? "path" : "paths"} · latest:{" "}
                            <span className="font-mono text-text-muted">
                              {latestPath ? compactDirectoryPath(latestPath) : "Unknown"}
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <span className="text-[11px] font-medium text-text-muted">
                            {isExpanded ? "Collapse" : "Expand"}
                          </span>
                          <ChevronDown
                            className={`h-4 w-4 text-text-subtle transition-transform duration-200 ${
                              isExpanded ? "rotate-180 text-primary" : ""
                            }`}
                            aria-hidden="true"
                          />
                        </div>
                      </button>
                    </div>

                    {isExpanded && (
                      <div
                        id={`cluster-sessions-${source.sourceIp}`}
                        role="list"
                        aria-label={`Active sessions for ${source.sourceIp}`}
                        className="border-t border-border divide-y divide-border/60 bg-surface-subtle/40"
                      >
                        {source.sessions.map((session) => {
                          const isSelected = session.sessionId === selectedSessionId;
                          const sessionPath = session.cwdState.path;
                          return (
                            <div
                              key={session.sessionId}
                              role="listitem"
                              className={`flex items-center justify-between gap-2 px-3 py-2 transition-colors ${
                                isSelected ? "bg-primary-subtle" : "hover:bg-surface-hover"
                              }`}
                            >
                              <button
                                type="button"
                                aria-pressed={isSelected}
                                onClick={() => onSelectSession(session.sessionId)}
                                className="flex min-w-0 flex-1 items-center justify-between gap-2 text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-focus-ring rounded"
                              >
                                <div className="min-w-0">
                                  <div className="flex items-center gap-1.5">
                                    <span
                                      className={`h-1.5 w-1.5 rounded-full shrink-0 ${
                                        isSelected ? "bg-primary animate-pulse" : "bg-text-subtle/50"
                                      }`}
                                    />
                                    <span className="font-mono text-xs text-text truncate">
                                      {session.sessionId.slice(0, 10)}…
                                    </span>
                                  </div>
                                  <div
                                    className="mt-0.5 font-mono text-xs text-text-muted truncate"
                                    title={sessionPath ?? "Unknown path"}
                                  >
                                    {sessionPath ? compactDirectoryPath(sessionPath) : "Unknown path"}
                                  </div>
                                </div>
                                <div className="text-right shrink-0">
                                  {isSelected ? (
                                    <span className="text-[11px] font-bold text-primary">Selected</span>
                                  ) : (
                                    <span className="text-[10px] text-text-subtle">
                                      {formatTimestamp(session.cwdState.observedAt)}
                                    </span>
                                  )}
                                </div>
                              </button>
                              {onAuditSession && (
                                <button
                                  type="button"
                                  title={`Open session ${session.sessionId} in Forensics & Replay`}
                                  aria-label={`Open session ${session.sessionId} in Forensics & Replay`}
                                  onClick={() => onAuditSession(session.sessionId)}
                                  className="flex h-7 w-7 shrink-0 items-center justify-center rounded border border-border bg-surface text-primary transition-colors hover:border-primary-border hover:bg-primary-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                                >
                                  <Route className="h-3.5 w-3.5" aria-hidden="true" />
                                </button>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="mt-3 text-sm text-text-muted">No live sources have a known working directory yet.</p>
          )}
        </div>
      ) : (
        <div id="panel-source-closed" role="tabpanel" aria-labelledby="tab-source-closed" className="mt-3">
          {recentClosedSessions.length ? (
            <div className="max-h-[22rem] space-y-2 overflow-y-auto overscroll-contain pr-1">
              {recentClosedSessions.map((session) => (
                <div
                  key={session.sessionId}
                  className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors duration-150 ${
                    session.sessionId === selectedSessionId
                      ? "border-warning-border bg-warning-subtle"
                      : "border-border hover:border-border-strong hover:bg-surface-hover"
                  }`}
                >
                  <button
                    type="button"
                    aria-pressed={session.sessionId === selectedSessionId}
                    onClick={() => onSelectSession(session.sessionId)}
                    className="flex min-w-0 flex-1 items-center justify-between gap-3 rounded-md text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                  >
                    <span className="min-w-0">
                      <span className="block truncate font-mono text-xs text-text">{session.sourceIp}</span>
                      <span className="mt-0.5 block truncate font-mono text-xs text-text-subtle">
                        {session.sessionId}
                      </span>
                      <span
                        className="mt-1 block truncate font-mono text-xs text-text-muted"
                        title={session.cwdState.path ?? "Unknown path"}
                      >
                        {session.cwdState.path ? compactDirectoryPath(session.cwdState.path) : "Unknown path"}
                      </span>
                    </span>
                    <span className="shrink-0 text-right">
                      <span className="block text-xs font-medium text-warning">Closed</span>
                      <span className="mt-0.5 block text-xs text-text-subtle">
                        {formatTimestamp(session.lifecycle.closedAt)}
                      </span>
                    </span>
                  </button>
                  {onAuditSession && (
                    <button
                      type="button"
                      title="Open in Session Forensics & Replay"
                      aria-label={`Open ${session.sourceIp} in Session Forensics and Replay`}
                      onClick={() => onAuditSession(session.sessionId)}
                      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-surface text-primary transition-colors hover:border-primary-border hover:bg-primary-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                    >
                      <Route className="h-4 w-4" aria-hidden="true" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="mt-3 text-sm text-text-muted">No closed sessions are retained yet.</p>
          )}
        </div>
      )}
    </div>
  );
}
