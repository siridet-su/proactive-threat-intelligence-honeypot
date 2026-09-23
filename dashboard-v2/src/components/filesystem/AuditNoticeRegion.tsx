import { AlertTriangle } from "lucide-react";
import type { FilesystemTopologySession, FilesystemClosedSession } from "@/lib/dashboardTypes";
import type { RetainedCountStatus } from "./useAuditDirectory";

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
  retainedCountStatus?: RetainedCountStatus;
}

export function AuditNoticeRegion({
  expiredSessionId,
  allSessions,
  setExpiredSessionId,
  handleUserSelectSession,
  switchViewMode,
  hasActiveFilters,
  isSelectedFilteredOut,
  targetPathFilter,
  hideHomeOnly,
  selectedSession,
  filteredClosedSessions,
  handleResetAuditFilters,
  handleClearSelection,
  retainedMatchingCount,
  retainedLoadedCount,
  retainedCountStatus,
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

  const effectiveStatus = retainedCountStatus ?? (typeof retainedMatchingCount === "number" ? "authoritative" : "loaded-only");
  const isExactZero = retainedMatchingCount === 0 && effectiveStatus === "authoritative";
  const loadedCount = retainedLoadedCount ?? filteredClosedSessions.length;

  if (hasActiveFilters && (isSelectedFilteredOut || isExactZero)) {
    const isSelectedRetained = Boolean(
      selectedSession &&
        "lifecycle" in selectedSession &&
        Boolean(selectedSession.lifecycle),
    );
    const isSelectedActive = !isSelectedRetained;

    return (
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-warning-border bg-warning-subtle px-3 py-2 text-xs text-text">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-warning" aria-hidden="true" />
          <span>
            {isExactZero ? (
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
                <strong>Pinned outside filter:</strong> {isSelectedActive ? "Active session " : "Retained session "}<span className="font-mono font-semibold text-text">{selectedSession?.sourceIp}</span> falls outside the active filter criteria.{" "}
                {typeof retainedMatchingCount === "number" && effectiveStatus === "authoritative" ? (
                  loadedCount < retainedMatchingCount ? (
                    `${retainedMatchingCount} other ${retainedMatchingCount === 1 ? "retained session matches" : "retained sessions match"} (${loadedCount} loaded).`
                  ) : (
                    `${retainedMatchingCount} other ${retainedMatchingCount === 1 ? "retained session matches" : "retained sessions match"}.`
                  )
                ) : effectiveStatus === "loading" ? (
                  `${loadedCount} retained session${loadedCount === 1 ? "" : "s"} loaded; exact match count loading.`
                ) : (
                  `${loadedCount} retained session${loadedCount === 1 ? "" : "s"} loaded; exact match count unavailable.`
                )}
              </>
            )}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {filteredClosedSessions.length > 0 && (
            <button
              type="button"
              onClick={() => {
                const first = filteredClosedSessions[0];
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
          {selectedSession && isExactZero && (
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
