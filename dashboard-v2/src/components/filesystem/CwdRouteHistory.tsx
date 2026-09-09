"use client";

import { ChevronLeft, ChevronRight, FastForward, History, Plus, RefreshCw } from "lucide-react";
import { useMemo } from "react";

import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySession, SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import { actionLabel, formatTimestamp, statusLabel } from "./filesystemUtils";

interface CwdRouteHistoryProps {
  selectedSession: FilesystemTopologySession | null;
  history: SessionCwdHistoryEvent[];
  historyStatus: RegionStatus;
  historyCursor: string | null;
  selectedHistoryEventId: string | null;
  onSelectHistoryEventId: (eventId: string | null) => void;
  onLoadEarlier: () => void;
}

export function CwdRouteHistory({
  selectedSession,
  history,
  historyStatus,
  historyCursor,
  selectedHistoryEventId,
  onSelectHistoryEventId,
  onLoadEarlier,
}: CwdRouteHistoryProps) {
  const chronologicalHistory = useMemo(() => [...history].reverse(), [history]);

  const selectedHistoryIndex = useMemo(() => {
    if (!chronologicalHistory.length) return -1;
    const index = chronologicalHistory.findIndex((event) => event.id === selectedHistoryEventId);
    return index >= 0 ? index : chronologicalHistory.length - 1;
  }, [chronologicalHistory, selectedHistoryEventId]);

  const selectedHistoryEvent = selectedHistoryIndex >= 0 ? chronologicalHistory[selectedHistoryIndex] : null;
  const activeHistoryEventId = selectedHistoryEvent?.id ?? null;

  return (
    <div className="ui-panel overflow-hidden">
      <div className="flex flex-col gap-3 border-b border-border p-5 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-primary" aria-hidden="true" />
            <h2 className="font-semibold">Verified CWD route</h2>
          </div>
          <p className="mt-1 text-xs text-text-subtle">
            Step through Cowrie-confirmed directory transitions. Command text never creates a guessed path.
          </p>
        </div>
        {selectedSession && <span className="ui-badge font-mono text-xs">{selectedSession.sessionId}</span>}
      </div>

      <div className="p-5">
        {!selectedSession ? (
          <RegionState
            kind="empty"
            title="Select a session to inspect its path history"
            description="Choose a session from the topology or inspector."
          />
        ) : historyStatus === "error" && !history.length ? (
          <RegionState
            kind="error"
            title="Session history unavailable"
            description="The selected CWD history could not be loaded."
          />
        ) : historyStatus === "loading" && !history.length ? (
          <RegionState kind="loading" title="Loading session history" />
        ) : !history.length ? (
          <RegionState
            kind="empty"
            title="No verified directory transitions"
            description="This session has a known observed path, but Cowrie has not recorded a successful directory move. It may have ended after a non-interactive probe."
          />
        ) : (
          <>
            <div className="rounded-xl border border-border bg-surface-subtle p-3 sm:p-4" aria-live="polite">
              <div className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-stretch gap-2 sm:gap-3">
                <button
                  type="button"
                  className="ui-button h-auto min-h-0 w-10 shrink-0 p-0 sm:w-auto sm:px-3"
                  aria-label="Show previous verified directory move"
                  disabled={selectedHistoryIndex <= 0}
                  onClick={() => onSelectHistoryEventId(chronologicalHistory[selectedHistoryIndex - 1]?.id ?? null)}
                >
                  <ChevronLeft className="h-4 w-4" />
                  <span className="hidden sm:inline">Previous</span>
                </button>
                <div className="min-w-0 rounded-lg border border-primary-border bg-primary-subtle px-3 py-2.5 text-center sm:px-5">
                  <p className="text-xs font-semibold uppercase tracking-[0.12em] text-primary">
                    Checkpoint {selectedHistoryIndex + 1} of {chronologicalHistory.length}
                  </p>
                  <p className="mt-1 font-medium text-text">
                    {selectedHistoryEvent ? actionLabel(selectedHistoryEvent) : "Loading checkpoint"}
                  </p>
                  <p className="mt-1 truncate font-mono text-xs text-text-muted">
                    {selectedHistoryEvent?.fromPath ?? "Unknown"}
                    <span className="px-1.5 text-primary">→</span>
                    {selectedHistoryEvent?.toPath ?? "Unknown"}
                  </p>
                </div>
                <button
                  type="button"
                  className="ui-button h-auto min-h-0 w-10 shrink-0 p-0 sm:w-auto sm:px-3"
                  aria-label="Show next verified directory move"
                  disabled={selectedHistoryIndex < 0 || selectedHistoryIndex >= chronologicalHistory.length - 1}
                  onClick={() => onSelectHistoryEventId(chronologicalHistory[selectedHistoryIndex + 1]?.id ?? null)}
                >
                  <span className="hidden sm:inline">Next</span>
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-text-subtle">
                <time className="font-mono">{selectedHistoryEvent ? formatTimestamp(selectedHistoryEvent.at) : ""}</time>
                <button
                  type="button"
                  className="ui-button h-8 min-h-8 px-2.5 text-xs"
                  disabled={selectedHistoryIndex === chronologicalHistory.length - 1}
                  onClick={() => onSelectHistoryEventId(chronologicalHistory.at(-1)?.id ?? null)}
                >
                  <FastForward className="h-3.5 w-3.5" />
                  Latest recorded move
                </button>
              </div>
            </div>

            {historyCursor && (
              <button
                type="button"
                className="ui-button mt-4"
                onClick={onLoadEarlier}
                disabled={historyStatus === "refreshing"}
              >
                {historyStatus === "refreshing" ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <Plus className="h-4 w-4" />
                )}
                Load earlier moves
              </button>
            )}

            <ol className="relative mt-5 space-y-0 border-l border-border pl-6" aria-label="Verified directory route">
              {chronologicalHistory.map((event, index) => (
                <li key={event.id} className="relative pb-5 last:pb-0">
                  <span
                    className={`absolute -left-[31px] top-3 flex h-3 w-3 rounded-full border-2 border-surface ${
                      event.action === "failed_change"
                        ? "bg-danger"
                        : event.id === activeHistoryEventId
                          ? "bg-primary"
                          : "bg-info"
                    }`}
                    aria-hidden="true"
                  />
                  <button
                    type="button"
                    aria-current={event.id === activeHistoryEventId ? "step" : undefined}
                    onClick={() => onSelectHistoryEventId(event.id)}
                    className={`w-full rounded-lg border px-3 py-3 text-left transition-colors duration-150 ${
                      event.id === activeHistoryEventId
                        ? "border-primary-border bg-primary-subtle"
                        : "border-transparent hover:border-border hover:bg-surface-hover"
                    }`}
                  >
                    <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                      <p className="font-medium text-text">
                        <span className="mr-2 font-mono text-xs text-text-subtle">
                          {String(index + 1).padStart(2, "0")}
                        </span>
                        {actionLabel(event)}
                      </p>
                      <time className="font-mono text-xs text-text-subtle">{formatTimestamp(event.at)}</time>
                    </div>
                    <p className="mt-2 break-all font-mono text-xs text-text-muted">
                      <span>{event.fromPath ?? "Unknown"}</span>
                      <span className="px-2 text-primary">→</span>
                      <span>{event.toPath ?? "Unknown"}</span>
                    </p>
                    <p className="mt-1 flex items-center gap-1.5 text-xs text-text-subtle">
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          event.status === "confirmed"
                            ? "bg-success"
                            : event.status === "conditional_candidate"
                              ? "bg-warning"
                              : "bg-info"
                        }`}
                        aria-hidden="true"
                      />
                      <span>{statusLabel(event.status)}</span>
                      {event.sequence !== null ? <span>· event {event.sequence}</span> : null}
                    </p>
                  </button>
                </li>
              ))}
            </ol>
          </>
        )}
      </div>
    </div>
  );
}
