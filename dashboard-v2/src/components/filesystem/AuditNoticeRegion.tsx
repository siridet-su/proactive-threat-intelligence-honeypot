import { AlertTriangle } from "lucide-react";
import type { FilesystemTopologySession, FilesystemClosedSession } from "@/lib/dashboardTypes";

export interface AuditNoticeRegionProps {
  expiredSessionId: string | null;
  allSessions: (FilesystemTopologySession | FilesystemClosedSession)[];
  setExpiredSessionId: (id: string | null) => void;
  handleUserSelectSession: (id: string) => void;
  switchViewMode: (mode: "live" | "audit") => void;
  hasActiveFilters: boolean;
  isSelectedFilteredOut: boolean;
  filteredSessionsCount: number;
  totalSessionsCount: number;
  targetPathFilter: string | null;
  hideHomeOnly: boolean;
  selectedSession: FilesystemTopologySession | FilesystemClosedSession | null;
  filteredActiveSessions: FilesystemTopologySession[];
  filteredClosedSessions: FilesystemClosedSession[];
  handleResetAuditFilters: () => void;
  handleClearSelection: () => void;

  // Retained semantics (FSV-004)
  retainedMatchingCount?: number | null;
  retainedLoadedCount?: number;
  retainedTotalCount?: number | null;
}

export function AuditNoticeRegion({
  expiredSessionId,
  allSessions,
  setExpiredSessionId,
  handleUserSelectSession,
  switchViewMode,
  hasActiveFilters,
  isSelectedFilteredOut,
  filteredSessionsCount,
  targetPathFilter,
  hideHomeOnly,
  selectedSession,
  filteredActiveSessions,
  filteredClosedSessions,
  handleResetAuditFilters,
  handleClearSelection,
  retainedMatchingCount,
}: AuditNoticeRegionProps) {
  if (expiredSessionId) {
    return (
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-danger-border bg-danger-subtle px-3 py-2 text-xs text-text">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-danger" aria-hidden="true" />
          <span>
            <strong>Requested audit session is no longer available:</strong> Session{" "}
            <span className="font-mono font-semibold text-text">{expiredSessionId}</span> has expired or was not found in retained telemetry.
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {allSessions.length > 0 && (
            <button
              type="button"
              onClick={() => {
                const first = allSessions[0];
                setExpiredSessionId(null);
                if (first) {
                  handleUserSelectSession(first.sessionId);
                }
              }}
              className="rounded border border-primary-border bg-primary px-2 py-0.5 text-xs font-semibold text-surface hover:bg-primary/90 transition-colors"
            >
              View latest available session
            </button>
          )}
          <button
            type="button"
            onClick={() => {
              setExpiredSessionId(null);
              switchViewMode("live");
            }}
            className="rounded border border-border bg-surface px-2 py-0.5 text-xs font-medium text-text-muted hover:text-text hover:bg-surface-hover transition-colors"
          >
            Return to live view
          </button>
        </div>
      </div>
    );
  }

  const effectiveMatchingCount =
    typeof retainedMatchingCount === "number"
      ? retainedMatchingCount
      : filteredClosedSessions.length > 0
        ? filteredClosedSessions.length
        : filteredSessionsCount;

  if (hasActiveFilters && (isSelectedFilteredOut || effectiveMatchingCount === 0)) {
    const isSelectedActive = Boolean(
      selectedSession &&
        (!("lifecycle" in selectedSession) ||
          !selectedSession.lifecycle ||
          !selectedSession.lifecycle.closedAt),
    );

    return (
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-warning-border bg-warning-subtle px-3 py-2 text-xs text-text">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
          <span>
            {effectiveMatchingCount === 0 ? (
              <>
                <strong>0 retained sessions match filter</strong>
                {targetPathFilter ? ` ("${targetPathFilter}")` : ""}
                {hideHomeOnly ? " [excluding /home]" : ""}.
                {selectedSession ? (
                  <span className="text-text-muted ml-1">
                    Showing previously selected session <span className="font-mono font-semibold text-text">{selectedSession.sourceIp}</span> which {isSelectedActive ? "is active" : "is retained"} but falls outside the active filters.
                  </span>
                ) : null}
              </>
            ) : (
              <>
                <strong>Pinned outside filter:</strong> {isSelectedActive ? "Active session " : "Retained session "}<span className="font-mono font-semibold text-text">{selectedSession?.sourceIp}</span> falls outside the active filter criteria. {effectiveMatchingCount} other {effectiveMatchingCount === 1 ? "retained session matches" : "retained sessions match"}.
              </>
            )}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {effectiveMatchingCount > 0 && (
            <button
              type="button"
              onClick={() => {
                const first = filteredClosedSessions[0] ?? filteredActiveSessions[0];
                if (first) handleUserSelectSession(first.sessionId);
              }}
              className="rounded border border-primary-border bg-primary-subtle px-2 py-0.5 text-xs font-semibold text-primary hover:bg-primary/20 transition-colors"
            >
              Switch to match
            </button>
          )}
          <button
            type="button"
            onClick={handleResetAuditFilters}
            className="rounded border border-border bg-surface px-2 py-0.5 text-xs font-medium text-text-muted hover:text-text hover:bg-surface-hover transition-colors"
          >
            Reset filters
          </button>
          {selectedSession && effectiveMatchingCount === 0 && (
            <button
              type="button"
              onClick={handleClearSelection}
              className="rounded border border-border bg-surface px-2 py-0.5 text-xs text-text-muted hover:text-text hover:bg-surface-hover transition-colors"
            >
              Clear selection
            </button>
          )}
        </div>
      </div>
    );
  }

  return null;
}
