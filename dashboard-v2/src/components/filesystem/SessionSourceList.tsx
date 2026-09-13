"use client";

import { ChevronRight, History, Radio, Route } from "lucide-react";
import { useMemo, useState } from "react";

import type { FilesystemClosedSession, FilesystemTopologySession } from "@/lib/dashboardTypes";
import { compactDirectoryPath, formatTimestamp } from "./filesystemUtils";

interface SessionSourceListProps {
  embedded?: boolean;
  sessions: FilesystemTopologySession[];
  recentClosedSessions: FilesystemClosedSession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  onAuditSession?: (sessionId: string) => void;
}

type TabKey = "live" | "closed";

export function SessionSourceList({
  embedded = false,
  sessions,
  recentClosedSessions,
  selectedSessionId,
  onSelectSession,
  onAuditSession,
}: SessionSourceListProps) {
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
        return { sourceIp, sessions: ordered, latest: ordered[0] };
      })
      .sort((left, right) => {
        const leftObservedAt = Date.parse(left.latest.cwdState.observedAt ?? "") || 0;
        const rightObservedAt = Date.parse(right.latest.cwdState.observedAt ?? "") || 0;
        return rightObservedAt - leftObservedAt;
      });
  }, [sessions]);

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
            onKeyDown={(event) => {
              if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
              event.preventDefault();
              selectTab("closed");
              document.getElementById("tab-source-closed")?.focus();
            }}
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
            onKeyDown={(event) => {
              if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
              event.preventDefault();
              selectTab("live");
              document.getElementById("tab-source-live")?.focus();
            }}
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
          ? "Choose an active source cluster to inspect its latest session and route."
          : "Closed connections remain audit-ready until telemetry retention expires."}
      </p>

      {/* Tab Panels */}
      {activeTab === "live" ? (
        <div id="panel-source-live" role="tabpanel" aria-labelledby="tab-source-live" className="mt-3">
          {liveSources.length ? (
            <div className="max-h-[22rem] space-y-2 overflow-y-auto overscroll-contain pr-1">
              {liveSources.map((source) => {
                const selected = source.sessions.some((session) => session.sessionId === selectedSessionId);
                const latestPath = source.latest.cwdState.path;
                return (
                  <div
                    key={source.sourceIp}
                    className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors duration-150 ${
                      selected
                        ? "border-primary-border bg-primary-subtle"
                        : "border-border hover:border-border-strong hover:bg-surface-hover"
                    }`}
                  >
                    <button
                      type="button"
                      aria-pressed={selected}
                      aria-label={`Inspect source ${source.sourceIp}; ${source.sessions.length} ${
                        source.sessions.length === 1 ? "session" : "sessions"
                      }; latest verified path ${latestPath ?? "unknown"}`}
                      onClick={() => onSelectSession(source.latest.sessionId)}
                      className="flex min-w-0 flex-1 items-center justify-between gap-3 rounded-md text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                    >
                      <span className="min-w-0">
                        <span className="block truncate font-mono text-xs text-text">{source.sourceIp}</span>
                        <span className="mt-0.5 block text-xs text-text-subtle">
                          {source.sessions.length} {source.sessions.length === 1 ? "session" : "sessions"} · latest
                        </span>
                        <span
                          className="mt-1 block truncate font-mono text-xs text-text-muted"
                          title={latestPath ?? "Unknown path"}
                        >
                          {latestPath ? compactDirectoryPath(latestPath) : "Unknown path"}
                        </span>
                      </span>
                      <span className="shrink-0">
                        {selected ? (
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
