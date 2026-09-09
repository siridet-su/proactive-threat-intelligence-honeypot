"use client";

import { History } from "lucide-react";

import type { FilesystemClosedSession } from "@/lib/dashboardTypes";
import { formatTimestamp } from "./filesystemUtils";

interface RecentClosedSessionsProps {
  recentClosedSessions: FilesystemClosedSession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
}

export function RecentClosedSessions({
  recentClosedSessions,
  selectedSessionId,
  onSelectSession,
}: RecentClosedSessionsProps) {
  return (
    <div className="ui-panel h-fit p-5">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <History className="h-4 w-4 text-warning" aria-hidden="true" />
          <h2 className="font-semibold">Recent closed sessions</h2>
        </div>
        <span className="ui-badge border-warning-border bg-warning-subtle text-warning">
          {recentClosedSessions.length}
        </span>
      </div>
      <p className="mt-2 text-xs text-text-subtle">
        Closed connections remain audit-ready until telemetry retention expires.
      </p>
      {recentClosedSessions.length ? (
        <div className="mt-4 max-h-[34rem] space-y-2 overflow-y-auto overscroll-contain pr-1" aria-label="Recent closed sessions">
          {recentClosedSessions.map((session) => (
            <button
              key={session.sessionId}
              type="button"
              onClick={() => onSelectSession(session.sessionId)}
              className={`flex w-full items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-left transition-colors duration-150 ${
                session.sessionId === selectedSessionId
                  ? "border-warning-border bg-warning-subtle"
                  : "border-border hover:border-border-strong hover:bg-surface-hover"
              }`}
            >
              <span className="min-w-0">
                <span className="block truncate font-mono text-xs text-text">{session.sourceIp}</span>
                <span className="mt-0.5 block truncate font-mono text-[11px] text-text-subtle">{session.sessionId}</span>
                <span className="mt-1 block truncate font-mono text-[11px] text-text-muted">
                  {session.cwdState.path ?? "Unknown path"}
                </span>
              </span>
              <span className="shrink-0 text-right">
                <span className="block text-xs font-medium text-warning">Closed</span>
                <span className="mt-0.5 block text-[11px] text-text-subtle">
                  {formatTimestamp(session.lifecycle.closedAt)}
                </span>
              </span>
            </button>
          ))}
        </div>
      ) : (
        <p className="mt-4 text-sm text-text-muted">No closed sessions are retained yet.</p>
      )}
    </div>
  );
}
