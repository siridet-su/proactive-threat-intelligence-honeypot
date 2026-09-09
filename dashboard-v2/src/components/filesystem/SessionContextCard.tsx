"use client";

import { ShieldAlert, Terminal } from "lucide-react";

import type { FilesystemClosedSession, FilesystemTopologySession } from "@/lib/dashboardTypes";
import { formatTimestamp, statusBadgeClass, statusLabel } from "./filesystemUtils";

interface SessionContextCardProps {
  selectedSession: FilesystemTopologySession | null;
  selectedClosedSession: FilesystemClosedSession | null;
}

export function SessionContextCard({
  selectedSession,
  selectedClosedSession,
}: SessionContextCardProps) {
  return (
    <aside className="ui-panel h-fit p-5">
      <div className="flex items-center gap-2">
        <Terminal className="h-4 w-4 text-primary" aria-hidden="true" />
        <h2 className="font-semibold">Session context</h2>
      </div>
      {selectedSession ? (
        <dl className="mt-5 space-y-4 text-sm">
          <div>
            <dt className="text-xs text-text-subtle">Source IP</dt>
            <dd className="mt-1 font-mono text-text">{selectedSession.sourceIp}</dd>
          </div>
          <div>
            <dt className="text-xs text-text-subtle">
              {selectedClosedSession ? "Last observed path" : "Current observed path"}
            </dt>
            <dd className="mt-1 break-all font-mono text-text">{selectedSession.cwdState.path ?? "Unknown"}</dd>
          </div>
          <div>
            <dt className="text-xs text-text-subtle">Confidence</dt>
            <dd className="mt-1">
              <span className={`ui-badge ${statusBadgeClass(selectedSession.cwdState.status)}`}>
                {statusLabel(selectedSession.cwdState.status)}
              </span>
            </dd>
          </div>
          <div>
            <dt className="text-xs text-text-subtle">Observed at</dt>
            <dd className="mt-1 text-text-muted">{formatTimestamp(selectedSession.cwdState.observedAt)}</dd>
          </div>
          {selectedClosedSession && (
            <>
              <div>
                <dt className="text-xs text-text-subtle">Connection state</dt>
                <dd className="mt-1">
                  <span className="ui-badge border-warning-border bg-warning-subtle text-warning">Closed</span>
                </dd>
              </div>
              <div>
                <dt className="text-xs text-text-subtle">Closed at</dt>
                <dd className="mt-1 text-text-muted">{formatTimestamp(selectedClosedSession.lifecycle.closedAt)}</dd>
              </div>
            </>
          )}
        </dl>
      ) : (
        <p className="mt-5 text-sm text-text-muted">No session is selected.</p>
      )}
      <div className="mt-6 flex gap-2 rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-text-muted">
        <ShieldAlert className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
        <p>Unknown paths remain unknown. This view never fills a missing directory with a guessed Linux path.</p>
      </div>
    </aside>
  );
}
