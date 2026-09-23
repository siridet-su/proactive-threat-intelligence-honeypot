"use client";

import { Check, ChevronDown, Loader2, RotateCcw } from "lucide-react";
import React, {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
} from "react";

import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
} from "@/lib/dashboardTypes";
import {
  AuditSessionSearchManager,
  type CloseReason,
} from "./auditSessionSearchManager";
import {
  ComboboxPopover,
  ComboboxSearchInput,
  useComboboxNavigation,
} from "./ComboboxPopover";
import { getPaginationRenderState, type RetainedCountStatus } from "./useAuditDirectory";
import { deriveForensicTimestamp } from "./filesystemUtils";

import type { TimeRangeFilter } from "./AuditFilterControls";

const useIsomorphicLayoutEffect =
  typeof window !== "undefined" ? React.useLayoutEffect : React.useEffect;

export function getSessionOptionKey(
  session: FilesystemTopologySession | FilesystemClosedSession,
): string {
  return session.sessionId;
}

export function getSessionOptionLabel(
  s: FilesystemTopologySession | FilesystemClosedSession,
): string {
  return `${s.sourceIp} ${s.sessionId} ${s.cwdState?.path ?? ""}`;
}

export function formatSessionMetadata(s: FilesystemTopologySession | FilesystemClosedSession): { timeStr: string; eventsStr: string } {
  const count = s.auditSummary?.eventCount ?? 0;
  const eventsStr = `${count} ${count === 1 ? 'event' : 'events'}`;

  const isClosed = "lifecycle" in s && Boolean(s.lifecycle);
  const rawDateStr = isClosed ? s.lifecycle?.closedAt : s.cwdState?.observedAt;
  const label = isClosed ? "Closed" : "Observed";
  const timestamp = deriveForensicTimestamp(label, rawDateStr);
  const timeStr = timestamp.available
    ? `${label} ${timestamp.absolute}`
    : `${label} time unavailable`;

  return { timeStr, eventsStr };
}

export interface AuditSessionSelectProps {
  sessions: readonly FilesystemTopologySession[];
  recentClosedSessions: readonly FilesystemClosedSession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string, session?: FilesystemTopologySession | FilesystemClosedSession) => void;
  className?: string;
  totalCount?: number;
  hasActiveFilters?: boolean;
  onResetFilters?: () => void;
  allSessionsList?: readonly (FilesystemTopologySession | FilesystemClosedSession)[];

  // Directory pagination
  directoryHasMore?: boolean;
  directoryIsLoading?: boolean;
  directoryIsComplete?: boolean;
  onLoadMoreDirectory?: () => Promise<void> | void;

  // Search pagination & callbacks
  searchResults?: readonly FilesystemClosedSession[];
  searchHasMore?: boolean;
  searchIsLoading?: boolean;
  searchIsComplete?: boolean;
  onSearch?: (query: string) => Promise<void> | void;
  onLoadMoreSearch?: () => Promise<void> | void;
  onClearSearch?: () => void;

  // Active filters for scoped searching
  hideHomeOnly?: boolean;
  targetPathFilter?: string | null;
  timeRange?: TimeRangeFilter;

  // Retained semantics (FSV-004)
  retainedMatchingCount?: number | null;
  retainedLoadedCount?: number;
  retainedCountStatus?: RetainedCountStatus;

  // Error and retry state
  status?: "idle" | "loading" | "success" | "ready" | "stale" | "error";
  errorMessage?: string | null;
  onRetry?: () => void;
}

export function AuditSessionSelect({
  sessions,
  recentClosedSessions,
  selectedSessionId,
  onSelectSession,
  className = "",
  totalCount,
  hasActiveFilters,
  onResetFilters,
  allSessionsList,
  hideHomeOnly = false,
  targetPathFilter = null,
  timeRange,
  retainedMatchingCount,
  retainedLoadedCount,
  retainedCountStatus = "loaded-only",
  status = "idle",
  onSearch,
  onClearSearch,
  onLoadMoreSearch,
  onLoadMoreDirectory,
  directoryHasMore,
  directoryIsLoading,
  directoryIsComplete,
  searchResults,
  searchHasMore,
  searchIsLoading,
  searchIsComplete,
  errorMessage,
  onRetry,
}: AuditSessionSelectProps) {
  const triggerRef = useRef<HTMLButtonElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const generatedId = useId();
  const triggerId = `audit-session-select-${generatedId}`;
  const popupId = `${triggerId}-popup`;
  const listboxId = `${triggerId}-listbox`;

  // Authoritative lifecycle owner for search, debounce, requests, and close idempotency
  const [manager] = useState(
    () =>
      new AuditSessionSearchManager({
        onSearch,
        onClearSearch,
        onLoadMoreSearch,
        onLoadMoreDirectory,
        hideHomeOnly,
        targetPathFilter,
      }),
  );

  // Keep manager options fresh with latest props to prevent stale closures
  useIsomorphicLayoutEffect(() => {
    manager.updateOptions({
      onSearch,
      onClearSearch,
      onLoadMoreSearch,
      onLoadMoreDirectory,
      hideHomeOnly,
      targetPathFilter,
    });
  }, [manager, onSearch, onClearSearch, onLoadMoreSearch, onLoadMoreDirectory, hideHomeOnly, targetPathFilter]);

  // Clean up timers, abort in-flight requests on unmount
  useEffect(() => {
    return () => {
      manager.dispose();
    };
  }, [manager]);

  // Subscribe to search manager state via useSyncExternalStore
  const searchState = useSyncExternalStore(manager.subscribe, manager.getSnapshot);
  const open = searchState.isOpen;
  const searchQuery = searchState.searchQuery;
  const remoteSessions = searchState.remoteSessions;
  const hasMoreRemote = searchState.hasMoreRemote;
  const isLoadingRemote = searchState.isLoadingRemote;
  const searchErrorMessage = searchState.errorMessage;

  const isSearchActive = Boolean(searchQuery.trim());
  const isParentSearch = typeof onSearch === "function";
  const isParentDirectory = typeof onLoadMoreDirectory === "function";

  const effectiveHasMore = isSearchActive
    ? isParentSearch
      ? Boolean(searchHasMore)
      : hasMoreRemote
    : isParentDirectory
      ? Boolean(directoryHasMore)
      : false;

  const effectiveIsLoading = isSearchActive
    ? isParentSearch
      ? Boolean(searchIsLoading)
      : isLoadingRemote
    : isParentDirectory
      ? Boolean(directoryIsLoading)
      : false;

  const effectiveIsComplete = isSearchActive
    ? isParentSearch
      ? Boolean(searchIsComplete)
      : (!hasMoreRemote && !isLoadingRemote && remoteSessions.length > 0)
    : isParentDirectory
      ? Boolean(directoryIsComplete)
      : true;

  const handleClearSearch = useCallback(() => {
    manager.clearSearch();
    searchInputRef.current?.focus();
  }, [manager]);

  const handleSearchChange = useCallback((value: string) => {
    manager.setSearchQuery(value);
  }, [manager]);

  const handleLoadMore = useCallback(() => {
    void manager.loadMore();
  }, [manager]);

  // Combined closed sessions:
  // - In search mode: parent searchResults if parent-controlled, otherwise manager remoteSessions
  // - In non-search mode: recentClosedSessions from topology/directory
  const combinedClosedSessions = useMemo(() => {
    if (isSearchActive) {
      if (isParentSearch) {
        return searchResults ?? [];
      }
      return remoteSessions;
    }
    return recentClosedSessions;
  }, [isSearchActive, isParentSearch, searchResults, remoteSessions, recentClosedSessions]);

  // Filter active sessions locally using query
  const filteredActiveSessions = useMemo(() => {
    if (!searchQuery.trim()) return sessions;
    const query = searchQuery.trim().toLowerCase();
    return sessions.filter((s) => {
      const ipMatch = s.sourceIp.toLowerCase().includes(query);
      const idMatch = s.sessionId.toLowerCase().includes(query);
      const pathMatch = s.cwdState?.path?.toLowerCase().includes(query);
      const auditPathMatch = s.auditSummary?.visitedPaths.some((p) =>
        p.toLowerCase().includes(query),
      );
      return ipMatch || idMatch || pathMatch || auditPathMatch;
    });
  }, [sessions, searchQuery]);

  const filteredClosedSessions = useMemo(() => {
    if (isSearchActive) {
      if (isParentSearch) {
        return searchResults ?? [];
      }
      return remoteSessions;
    }
    return combinedClosedSessions;
  }, [isSearchActive, isParentSearch, searchResults, remoteSessions, combinedClosedSessions]);

  const allDisplaySessions = useMemo(
    () => [...filteredActiveSessions, ...filteredClosedSessions],
    [filteredActiveSessions, filteredClosedSessions],
  );

  const selectedIndex = useMemo(() => {
    if (!selectedSessionId) return -1;
    return allDisplaySessions.findIndex((s) => s.sessionId === selectedSessionId);
  }, [allDisplaySessions, selectedSessionId]);

  const selectedSession = useMemo(() => {
    if (!selectedSessionId) return null;
    const active = sessions.find((s) => s.sessionId === selectedSessionId);
    if (active) return active;
    const closed = combinedClosedSessions.find((s) => s.sessionId === selectedSessionId);
    if (closed) return closed;
    if (allSessionsList) {
      return allSessionsList.find((s) => s.sessionId === selectedSessionId) ?? null;
    }
    return null;
  }, [selectedSessionId, sessions, combinedClosedSessions, allSessionsList]);

  const isSelectedClosed = useMemo(() => {
    if (!selectedSession) return false;
    return "lifecycle" in selectedSession && Boolean(selectedSession.lifecycle);
  }, [selectedSession]);

  const retainedGroupLabel = useMemo(() => {
    const loaded = isSearchActive ? filteredClosedSessions.length : (retainedLoadedCount ?? filteredClosedSessions.length);
    if (isSearchActive) {
      return `Retained search results (${loaded} loaded)`;
    }

    if (
      retainedMatchingCount !== null &&
      typeof retainedMatchingCount === "number" &&
      retainedCountStatus === "authoritative"
    ) {
      if (loaded < retainedMatchingCount) {
        return `Retained sessions (${loaded} loaded of ${retainedMatchingCount} matching)`;
      }
      return `Retained sessions (${retainedMatchingCount} matching)`;
    }

    if (retainedCountStatus === "loading") {
      return `Retained sessions (${loaded} loaded · exact match count loading)`;
    }

    if (retainedMatchingCount === null && retainedCountStatus !== "authoritative") {
      return `Retained sessions (${loaded} loaded · exact match count unavailable)`;
    }

    return `Retained sessions (${loaded})`;
  }, [isSearchActive, filteredClosedSessions.length, retainedMatchingCount, retainedLoadedCount, retainedCountStatus]);

  const isSelectedFilteredOut = useMemo(
    () =>
      Boolean(
        selectedSession &&
          hasActiveFilters &&
          !allDisplaySessions.some((s) => s.sessionId === selectedSessionId),
      ),
    [selectedSession, hasActiveFilters, allDisplaySessions, selectedSessionId],
  );

  const closeMenu = useCallback(
    (reason: CloseReason = "escape") => {
      const didClose = manager.close(reason);
      if (didClose && reason !== "outside") {
        triggerRef.current?.focus();
      }
    },
    [manager],
  );

  const handleSelect = useCallback(
    (sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession) => {
      onSelectSession(sessionId, sessionObj);
      closeMenu("select");
    },
    [onSelectSession, closeMenu],
  );

  const {
    activeIndex,
    registerOptionRef,
    openWithFocus,
    handleTriggerKeyDown,
    handleInputKeyDown,
    handleOptionKeyDown,
    handleSearchInputFocus,
    handleOptionFocus,
  } = useComboboxNavigation<FilesystemTopologySession | FilesystemClosedSession>({
    isOpen: open,
    onOpen: () => manager.open(),
    onClose: (reason) => closeMenu(reason),
    items: allDisplaySessions,
    getLabel: getSessionOptionLabel,
    getKey: getSessionOptionKey,
    onSelect: (s) => handleSelect(s.sessionId, s),
    triggerRef,
    searchInputRef,
    selectedIndex,
  });

  const handleToggleOpen = useCallback(() => {
    if (open) {
      closeMenu("toggle");
    } else {
      manager.open();
      openWithFocus("search");
    }
  }, [open, closeMenu, manager, openWithFocus]);

  return (
    <div className={`relative inline-block text-left ${className ?? ""}`}>
      {/* Trigger Button */}
      <button
        ref={triggerRef}
        id={triggerId}
        type="button"
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listboxId}
        onClick={handleToggleOpen}
        onKeyDown={handleTriggerKeyDown}
        className={`h-9 min-h-9 max-w-[280px] sm:max-w-[320px] flex items-center justify-between gap-2 rounded-lg border border-border bg-surface px-2.5 py-1 font-mono text-xs text-text transition-colors cursor-pointer select-none ${
          open
            ? "border-primary ring-2 ring-primary/30 bg-surface"
            : "hover:bg-surface-hover hover:border-border-strong"
        }`}
        title={
          selectedSession
            ? `${selectedSession.sourceIp} · ${selectedSession.sessionId} (${
                isSelectedClosed ? "Closed" : selectedSession.cwdState.path ?? "/"
              })`
            : "Select session to audit"
        }
      >
        <div className="flex items-center gap-1.5 truncate">
          <span
            className={`h-2 w-2 rounded-full shrink-0 ${
              isSelectedClosed
                ? "bg-text-subtle/60"
                : selectedSession
                  ? "bg-success animate-pulse"
                  : "bg-text-subtle/40"
            }`}
            aria-hidden="true"
          />
          {selectedSession ? (
            <>
              <span className="font-semibold text-text">{selectedSession.sourceIp}</span>
              <span className="text-text-subtle">·</span>
              {(() => {
                 const meta = formatSessionMetadata(selectedSession);
                 return (
                   <>
                     {meta.timeStr && <span className="text-text-subtle hidden sm:inline">{meta.timeStr}</span>}
                     {meta.timeStr && <span className="text-text-subtle hidden sm:inline">·</span>}
                     <span className="text-text-subtle">{meta.eventsStr}</span>
                   </>
                 );
              })()}
              <span className="truncate text-text-muted hidden sm:inline">
                ({isSelectedClosed ? "closed" : selectedSession.cwdState?.path ?? "/"})
              </span>
            </>
          ) : (
            <span className="text-text-subtle">Select session…</span>
          )}
        </div>
        <ChevronDown
          className={`h-3.5 w-3.5 text-text-subtle shrink-0 transition-transform ${
            open ? "rotate-180" : ""
          }`}
          aria-hidden="true"
        />
      </button>

      {/* Popover Menu using ComboboxPopover */}
      <ComboboxPopover
        id={popupId}
        isOpen={open}
        onClose={closeMenu}
        triggerRef={triggerRef}
        ariaLabel="Select session to audit"
        totalCount={allDisplaySessions.length}
        className="min-w-[320px] sm:min-w-[440px] max-w-[90vw] sm:max-w-[500px] max-h-96 overflow-y-auto overscroll-contain"
      >
        {/* Search Input inside Session Dropdown (outside listbox) */}
        <ComboboxSearchInput
          inputRef={searchInputRef}
          value={searchQuery}
          onChange={handleSearchChange}
          onClear={handleClearSearch}
          onKeyDown={handleInputKeyDown}
          onFocus={handleSearchInputFocus}
          placeholder="Search IP, session ID, or current/last CWD..."
          isLoading={effectiveIsLoading}
          ariaControls={listboxId}
        />

        {/* Error banner if directory fetch or search failed (outside listbox) */}
        {(status === "error" || searchErrorMessage) && (
          <div className="mx-2 mb-2 p-2 rounded-lg border border-danger-border bg-danger-subtle text-xs font-mono flex items-center justify-between gap-2">
            <span className="text-danger truncate">
              {searchErrorMessage ?? errorMessage ?? "Failed to load audit directory"}
            </span>
            {onRetry && (
              <button
                type="button"
                onClick={onRetry}
                className="px-2 py-1 rounded bg-danger text-white hover:bg-danger-hover transition-colors shrink-0 text-xs font-sans font-semibold cursor-pointer"
              >
                Retry
              </button>
            )}
          </div>
        )}

        {/* Callout if currently audited session is hidden by active filter (outside listbox) */}
        {isSelectedFilteredOut && selectedSession && (
          <div className="mx-1 mb-2 rounded-lg border border-primary-border bg-primary-subtle p-2 text-xs">
            <div className="text-xs font-semibold uppercase tracking-wider text-primary">
              Selected session (hidden by active filter):
            </div>
            <div className="mt-1 flex items-center justify-between font-mono text-xs">
              <div className="flex items-center gap-1.5 truncate">
                <span className="h-1.5 w-1.5 rounded-full bg-text-subtle/60 shrink-0" />
                <strong className="text-text">{selectedSession.sourceIp}</strong>
                <span className="text-text-subtle">{selectedSession.sessionId.slice(0, 8)}…</span>
              </div>
              <span className="px-1.5 py-0.2 rounded bg-surface border border-border/60 text-text-muted text-xs shrink-0">
                {selectedSession.cwdState?.path ?? "/"}
              </span>
            </div>
          </div>
        )}

        {/* Dedicated listbox for session options (always rendered when open) */}
        <div
          role="listbox"
          id={listboxId}
          aria-label="Select session to audit"
          tabIndex={-1}
        >
          {/* Active Sessions Group */}
          {filteredActiveSessions.length > 0 && (
            <div
              role="group"
              aria-label={
                timeRange && timeRange !== "all"
                  ? `Active Sessions (${filteredActiveSessions.length}) · Outside Closed-at filter`
                  : `Active Sessions (${filteredActiveSessions.length})`
              }
            >
              <div
                className="px-2.5 py-1.5 text-xs font-semibold text-text-subtle uppercase tracking-wider flex items-center justify-between select-none"
                aria-hidden="true"
              >
                <div className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-success" />
                  Active Sessions ({filteredActiveSessions.length})
                </div>
                {timeRange && timeRange !== "all" ? (
                  <span className="text-xs font-sans font-normal text-text-subtle normal-case">
                    Not filtered by Closed at
                  </span>
                ) : (
                  totalCount !== undefined &&
                  totalCount > allDisplaySessions.length && (
                    <span className="text-xs font-mono text-primary/80 lowercase">
                      filtered
                    </span>
                  )
                )}
              </div>
              <div className="space-y-0.5">
                {filteredActiveSessions.map((s, idx) => {
                  const isSelected = s.sessionId === selectedSessionId;
                  const globalIndex = idx;
                  const isOptionTabStop =
                    activeIndex === globalIndex || (activeIndex === -1 && globalIndex === 0);
                  const isOutsideHome =
                    s.cwdState?.path &&
                    s.cwdState.path !== "/" &&
                    s.cwdState.path !== "/home" &&
                    !s.cwdState.path.startsWith("/home/");

                  return (
                    <button
                      key={s.sessionId}
                      ref={registerOptionRef(globalIndex, s.sessionId)}
                      type="button"
                      role="option"
                      id={`${listboxId}-opt-${globalIndex}`}
                      aria-selected={isSelected}
                      tabIndex={isOptionTabStop ? 0 : -1}
                      onFocus={() => handleOptionFocus(globalIndex, s.sessionId)}
                      onClick={() => handleSelect(s.sessionId, s)}
                      onKeyDown={(e) => handleOptionKeyDown(e, globalIndex)}
                      className={`w-full flex items-center justify-between gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-xs font-mono transition-colors cursor-pointer ${
                        isSelected
                          ? "bg-primary-subtle text-primary border border-primary-border/50"
                          : activeIndex === globalIndex
                            ? "bg-surface-hover text-text border border-border/50"
                            : "text-text-muted hover:bg-surface-hover hover:text-text border border-transparent"
                      }`}
                    >
                      <div className="flex items-center gap-1.5 truncate">
                        <span className="h-1.5 w-1.5 rounded-full bg-success shrink-0" />
                        <strong className={isSelected ? "text-primary" : "text-text"}>
                          {s.sourceIp}
                        </strong>
                        <span className="text-text-subtle">·</span>
                        {(() => {
                           const meta = formatSessionMetadata(s);
                           return (
                             <>
                               {meta.timeStr && <span className="text-text-subtle whitespace-nowrap">{meta.timeStr}</span>}
                               {meta.timeStr && <span className="text-text-subtle">·</span>}
                               <span className="text-text-subtle whitespace-nowrap">{meta.eventsStr}</span>
                             </>
                           );
                        })()}
                        {s.cwdState?.path && (
                          <span
                            className={`truncate px-1.5 py-0.2 rounded text-xs border ${
                              isOutsideHome
                                ? "bg-primary/10 text-primary border-primary/30 font-semibold"
                                : "bg-surface-subtle text-text-subtle border-border/50"
                            }`}
                          >
                            {s.cwdState.path}
                          </span>
                        )}
                      </div>
                      {isSelected && (
                        <Check className="h-3.5 w-3.5 text-primary shrink-0" aria-hidden="true" />
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Retained Sessions Group */}
          {filteredClosedSessions.length > 0 && (
            <div
              role="group"
              aria-label={retainedGroupLabel}
              className={filteredActiveSessions.length > 0 ? "mt-2 pt-2 border-t border-border/60" : ""}
            >
              <div
                className="px-2.5 py-1.5 text-xs font-semibold text-text-subtle uppercase tracking-wider flex items-center gap-1.5 select-none"
                aria-hidden="true"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-text-subtle/50" />
                {retainedGroupLabel}
              </div>
              <div className="space-y-0.5">
                {filteredClosedSessions.map((s, idx) => {
                  const isSelected = s.sessionId === selectedSessionId;
                  const globalIndex = filteredActiveSessions.length + idx;
                  const isOptionTabStop =
                    activeIndex === globalIndex || (activeIndex === -1 && globalIndex === 0);
                  const isOutsideHome =
                    s.cwdState?.path &&
                    s.cwdState.path !== "/" &&
                    s.cwdState.path !== "/home" &&
                    !s.cwdState.path.startsWith("/home/");

                  return (
                    <button
                      key={s.sessionId}
                      ref={registerOptionRef(globalIndex, s.sessionId)}
                      type="button"
                      role="option"
                      id={`${listboxId}-opt-${globalIndex}`}
                      aria-selected={isSelected}
                      tabIndex={isOptionTabStop ? 0 : -1}
                      onFocus={() => handleOptionFocus(globalIndex, s.sessionId)}
                      onClick={() => handleSelect(s.sessionId, s)}
                      onKeyDown={(e) => handleOptionKeyDown(e, globalIndex)}
                      className={`w-full flex items-center justify-between gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-xs font-mono transition-colors cursor-pointer ${
                        isSelected
                          ? "bg-primary-subtle text-primary border border-primary-border/50"
                          : activeIndex === globalIndex
                            ? "bg-surface-hover text-text border border-border/50"
                            : "text-text-muted hover:bg-surface-hover hover:text-text border border-transparent"
                      }`}
                    >
                      <div className="flex items-center gap-1.5 truncate">
                        <span className="h-1.5 w-1.5 rounded-full bg-text-subtle/60 shrink-0" />
                        <strong className={isSelected ? "text-primary" : "text-text"}>
                          {s.sourceIp}
                        </strong>
                        <span className="text-text-subtle">·</span>
                        {(() => {
                           const meta = formatSessionMetadata(s);
                           return (
                             <>
                               {meta.timeStr && <span className="text-text-subtle whitespace-nowrap">{meta.timeStr}</span>}
                               {meta.timeStr && <span className="text-text-subtle">·</span>}
                               <span className="text-text-subtle whitespace-nowrap">{meta.eventsStr}</span>
                             </>
                           );
                        })()}
                        {s.cwdState?.path && (
                          <span
                            className={`truncate px-1.5 py-0.2 rounded text-xs border ${
                              isOutsideHome
                                ? "bg-primary/10 text-primary border-primary/30 font-semibold"
                                : "bg-surface-subtle text-text-subtle border-border/50"
                            }`}
                          >
                            {s.cwdState.path}
                          </span>
                        )}
                      </div>
                      {isSelected && (
                        <Check className="h-3.5 w-3.5 text-primary shrink-0" aria-hidden="true" />
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Pagination / Remote Directory Retrieval (outside listbox) */}
        {(() => {
          const paginationState = getPaginationRenderState({
            effectiveHasMore,
            effectiveIsLoading,
            hasItems: combinedClosedSessions.length > 0,
            isComplete: effectiveIsComplete,
          });

          if (paginationState === "button") {
            return (
              <div className="pt-2 px-1">
                <button
                  type="button"
                  onClick={handleLoadMore}
                  disabled={effectiveIsLoading}
                  className="w-full flex items-center justify-center gap-1.5 rounded-lg border border-border/80 bg-surface-subtle/70 px-2 py-1.5 text-xs font-mono text-text-muted hover:bg-surface-hover hover:text-text hover:border-primary/40 transition-colors cursor-pointer disabled:opacity-50"
                >
                  {effectiveIsLoading ? (
                    <>
                      <Loader2 className="h-3 w-3 animate-spin text-primary" />
                      <span>{isSearchActive ? "Loading search results…" : "Loading audit directory…"}</span>
                    </>
                  ) : (
                    <>
                      <span>{isSearchActive ? "Load more matching sessions" : "Load older closed sessions"}</span>
                      <ChevronDown className="h-3 w-3 text-text-subtle" />
                    </>
                  )}
                </button>
              </div>
            );
          }

          if (paginationState === "completed") {
            return (
              <div className="pt-2 pb-1 text-center font-mono text-xs text-text-subtle">
                {isSearchActive
                  ? `All matching search results loaded (${filteredClosedSessions.length})`
                  : `All matching directory sessions loaded (${filteredClosedSessions.length})`}
              </div>
            );
          }

          return null;
        })()}

        {/* Empty State (outside listbox) */}
        {allDisplaySessions.length === 0 && (
          <div className="px-3 py-4 text-center text-xs text-text-subtle font-mono">
            {effectiveIsLoading ? (
              <div className="flex items-center justify-center gap-1.5 text-text-subtle">
                <Loader2 className="h-3 w-3 animate-spin text-primary" />
                <span>Searching sessions…</span>
              </div>
            ) : searchQuery ? (
              <div>No sessions match &ldquo;{searchQuery}&rdquo;</div>
            ) : hasActiveFilters ? (
              <div className="space-y-2">
                <div>No sessions match current audit filters.</div>
                {onResetFilters && (
                  <button
                    type="button"
                    onClick={() => {
                      onResetFilters();
                      handleClearSearch();
                    }}
                    className="inline-flex items-center gap-1 rounded-md border border-border bg-surface-subtle px-2 py-1 text-xs text-primary hover:bg-surface-hover hover:border-primary/40 transition-colors cursor-pointer"
                  >
                    <RotateCcw className="h-3 w-3" />
                    Reset audit filters
                  </button>
                )}
              </div>
            ) : (
              <div>No sessions available for audit</div>
            )}
          </div>
        )}
      </ComboboxPopover>
    </div>
  );
}
