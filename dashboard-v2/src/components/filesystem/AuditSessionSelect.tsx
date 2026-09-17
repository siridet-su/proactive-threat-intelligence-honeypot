"use client";

import { Check, ChevronDown, Loader2, RotateCcw } from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

import type {
  AuditSessionsPage,
  FilesystemClosedSession,
  FilesystemTopologySession,
} from "@/lib/dashboardTypes";
import {
  ComboboxPopover,
  ComboboxSearchInput,
  useComboboxNavigation,
} from "./ComboboxPopover";

import { sessionTouchesPath } from "./filesystemUtils";
import { getPaginationRenderState } from "./useAuditDirectory";

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
  onLoadMoreDirectory?: () => void;

  // Search pagination & callbacks
  searchResults?: readonly FilesystemClosedSession[];
  searchHasMore?: boolean;
  searchIsLoading?: boolean;
  searchIsComplete?: boolean;
  onSearch?: (query: string) => void;
  onLoadMoreSearch?: () => void;
  onClearSearch?: () => void;

  // Active filters for scoped searching
  hideHomeOnly?: boolean;
  targetPathFilter?: string | null;

  // Error and retry state
  status?: "idle" | "loading" | "success" | "error";
  errorMessage?: string | null;
  onRetry?: () => void;
}

export function AuditSessionSelect({
  sessions,
  recentClosedSessions,
  selectedSessionId,
  onSelectSession,
  className,
  totalCount,
  hasActiveFilters,
  onResetFilters,
  allSessionsList,
  directoryHasMore,
  directoryIsLoading,
  directoryIsComplete,
  onLoadMoreDirectory,
  searchResults,
  searchHasMore,
  searchIsLoading,
  searchIsComplete,
  onSearch,
  onLoadMoreSearch,
  onClearSearch,
  hideHomeOnly = false,
  targetPathFilter = null,
  status,
  errorMessage,
  onRetry,
}: AuditSessionSelectProps) {
  const [open, setOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [remoteSessions, setRemoteSessions] = useState<FilesystemClosedSession[]>([]);
  const [remoteCursor, setRemoteCursor] = useState<string | null>(null);
  const [hasMoreRemote, setHasMoreRemote] = useState(false);
  const [isLoadingRemote, setIsLoadingRemote] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const searchGenerationRef = useRef(0);
  const generatedId = useId();
  const triggerId = `audit-session-select-${generatedId}`;
  const popupId = `${triggerId}-popup`;
  const listboxId = `${triggerId}-listbox`;
  const openRef = useRef(open);
  useEffect(() => {
    openRef.current = open;
  }, [open]);

  const isSearchActive = Boolean(searchQuery.trim());

  const effectiveHasMore = isSearchActive
    ? searchHasMore !== undefined
      ? searchHasMore
      : hasMoreRemote
    : directoryHasMore !== undefined
      ? directoryHasMore
      : hasMoreRemote;

  const effectiveIsLoading = isSearchActive
    ? searchIsLoading !== undefined
      ? searchIsLoading
      : isLoadingRemote
    : directoryIsLoading !== undefined
      ? directoryIsLoading
      : isLoadingRemote;

  const handleClearSearch = useCallback(() => {
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = null;
    }
    searchGenerationRef.current++;
    setSearchQuery("");
    setRemoteSessions([]);
    setRemoteCursor(null);
    setHasMoreRemote(false);
    setIsLoadingRemote(false);
    onClearSearch?.();
    searchInputRef.current?.focus();
  }, [onClearSearch]);

  const handleSearchChange = useCallback((value: string) => {
    setSearchQuery(value);
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = null;
    }
    const trimmed = value.trim();
    if (!trimmed) {
      searchGenerationRef.current++;
      setRemoteSessions([]);
      setRemoteCursor(null);
      setHasMoreRemote(false);
      setIsLoadingRemote(false);
      onClearSearch?.();
    } else if (onSearch && openRef.current) {
      const currentGen = ++searchGenerationRef.current;
      debounceTimerRef.current = setTimeout(() => {
        if (openRef.current && searchGenerationRef.current === currentGen) {
          onSearch(trimmed);
        }
      }, 250);
    }
  }, [onSearch, onClearSearch]);

  useEffect(() => {
    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
        debounceTimerRef.current = null;
      }
    };
  }, []);


  // Standalone fallback: Query remote audit directory when searching without parent onSearch
  useEffect(() => {
    if (!open) return;
    if (onSearch) return; // parent handles search
    const query = searchQuery.trim();
    if (!query) return;

    const timer = setTimeout(async () => {
      if (!openRef.current) return;
      setIsLoadingRemote(true);
      try {
        const params = new URLSearchParams();
        params.set("q", query);
        params.set("limit", "25");
        if (hideHomeOnly) params.set("hideHome", "1");
        if (targetPathFilter) params.set("targetPath", targetPathFilter);

        const response = await fetch(
          `/api/filesystem-topology/audit-sessions?${params.toString()}`,
          { cache: "no-store" },
        );
        if (!response.ok) return;
        const data: unknown = await response.json();
        const page = data as Partial<AuditSessionsPage>;
        if (Array.isArray(page.items)) {
          setRemoteSessions(page.items);
          setRemoteCursor(page.nextCursor ?? null);
          setHasMoreRemote(Boolean(page.nextCursor));
        }
      } catch {
        // preserve local results
      } finally {
        setIsLoadingRemote(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [open, searchQuery, onSearch, hideHomeOnly, targetPathFilter]);

  const handleLoadMore = useCallback(async () => {
    if (effectiveIsLoading) return;
    if (isSearchActive) {
      if (onLoadMoreSearch) {
        onLoadMoreSearch();
        return;
      }
    } else {
      if (onLoadMoreDirectory) {
        onLoadMoreDirectory();
        return;
      }
    }

    // Standalone fallback
    setIsLoadingRemote(true);
    try {
      const q = searchQuery.trim();
      const params = new URLSearchParams();
      if (q) params.set("q", q);
      if (remoteCursor) params.set("cursor", remoteCursor);
      params.set("limit", "25");
      if (hideHomeOnly) params.set("hideHome", "1");
      if (targetPathFilter) params.set("targetPath", targetPathFilter);

      const response = await fetch(
        `/api/filesystem-topology/audit-sessions?${params.toString()}`,
        { cache: "no-store" },
      );
      if (!response.ok) return;
      const data: unknown = await response.json();
      const page = data as Partial<AuditSessionsPage>;
      if (Array.isArray(page.items)) {
        setRemoteSessions((prev) => {
          const seen = new Set(prev.map((s) => s.sessionId));
          const additions = page.items?.filter((s) => !seen.has(s.sessionId)) ?? [];
          return [...prev, ...additions];
        });
        setRemoteCursor(page.nextCursor ?? null);
        setHasMoreRemote(Boolean(page.nextCursor));
      }
    } catch {
      // ignore
    } finally {
      setIsLoadingRemote(false);
    }
  }, [
    effectiveIsLoading,
    isSearchActive,
    onLoadMoreSearch,
    onLoadMoreDirectory,
    searchQuery,
    remoteCursor,
    hideHomeOnly,
    targetPathFilter,
  ]);

  const combinedClosedSessions = useMemo(() => {
    if (isSearchActive) {
      const base = searchResults ?? remoteSessions;
      return base.filter((s) => {
        if (hasActiveFilters && hideHomeOnly && s.auditSummary?.homeOnly) return false;
        if (hasActiveFilters && targetPathFilter && !sessionTouchesPath(s, targetPathFilter)) return false;
        return true;
      });
    }
    return recentClosedSessions as FilesystemClosedSession[];
  }, [
    isSearchActive,
    searchResults,
    remoteSessions,
    hasActiveFilters,
    hideHomeOnly,
    targetPathFilter,
    recentClosedSessions,
  ]);

  const effectiveAllSessions = useMemo(
    () => allSessionsList ?? [...sessions, ...combinedClosedSessions],
    [allSessionsList, sessions, combinedClosedSessions],
  );

  const selectedSession = useMemo(
    () =>
      effectiveAllSessions.find((s) => s.sessionId === selectedSessionId) ??
      [...sessions, ...combinedClosedSessions].find((s) => s.sessionId === selectedSessionId) ??
      null,
    [effectiveAllSessions, sessions, combinedClosedSessions, selectedSessionId],
  );

  const isSelectedClosed = useMemo(
    () =>
      selectedSession
        ? "lifecycle" in selectedSession && Boolean(selectedSession.lifecycle)
        : combinedClosedSessions.some((s) => s.sessionId === selectedSessionId),
    [selectedSession, combinedClosedSessions, selectedSessionId],
  );

  const normalizedQuery = searchQuery.trim().toLowerCase();

  const filteredActiveSessions = useMemo(() => {
    if (!normalizedQuery) return sessions;
    return sessions.filter(
      (s) =>
        s.sourceIp.toLowerCase().includes(normalizedQuery) ||
        s.sessionId.toLowerCase().includes(normalizedQuery) ||
        (s.cwdState?.path && s.cwdState.path.toLowerCase().includes(normalizedQuery)),
    );
  }, [sessions, normalizedQuery]);

  const filteredClosedSessions = useMemo(() => {
    if (!normalizedQuery) return combinedClosedSessions;
    return combinedClosedSessions.filter(
      (s) =>
        s.sourceIp.toLowerCase().includes(normalizedQuery) ||
        s.sessionId.toLowerCase().includes(normalizedQuery) ||
        (s.cwdState?.path && s.cwdState.path.toLowerCase().includes(normalizedQuery)),
    );
  }, [combinedClosedSessions, normalizedQuery]);

  const allDisplaySessions = useMemo(
    () => [...filteredActiveSessions, ...filteredClosedSessions],
    [filteredActiveSessions, filteredClosedSessions],
  );

  const selectedIndex = useMemo(
    () => allDisplaySessions.findIndex((s) => s.sessionId === selectedSessionId),
    [allDisplaySessions, selectedSessionId],
  );

  const isSelectedFilteredOut = useMemo(
    () =>
      Boolean(
        selectedSession &&
          hasActiveFilters &&
          !allDisplaySessions.some((s) => s.sessionId === selectedSessionId),
      ),
    [selectedSession, hasActiveFilters, allDisplaySessions, selectedSessionId],
  );

  const closeMenu = useCallback(() => {
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = null;
    }
    searchGenerationRef.current++;
    setOpen(false);
    setSearchQuery("");
    setRemoteSessions([]);
    setRemoteCursor(null);
    setHasMoreRemote(false);
    setIsLoadingRemote(false);
    onClearSearch?.();
  }, [onClearSearch]);

  const handleSelect = useCallback(
    (sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession) => {
      onSelectSession(sessionId, sessionObj);
      closeMenu();
      triggerRef.current?.focus();
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
  } = useComboboxNavigation<FilesystemTopologySession | FilesystemClosedSession>({
    isOpen: open,
    onOpen: () => setOpen(true),
    onClose: closeMenu,
    items: allDisplaySessions,
    getLabel: (s) => `${s.sourceIp} ${s.sessionId} ${s.cwdState?.path ?? ""}`,
    onSelect: (s) => handleSelect(s.sessionId, s),
    triggerRef,
    searchInputRef,
    selectedIndex,
  });

  const handleToggleOpen = useCallback(() => {
    if (open) {
      closeMenu();
    } else {
      openWithFocus("search");
      setOpen(true);
    }
  }, [open, closeMenu, openWithFocus]);


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
        className={`h-9 min-h-9 max-w-[280px] sm:max-w-md flex items-center justify-between gap-2 rounded-lg border border-border bg-surface px-2.5 py-1 font-mono text-xs text-text transition-colors cursor-pointer select-none ${
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
              <span className="text-text-subtle">{selectedSession.sessionId.slice(0, 8)}…</span>
              <span className="truncate text-text-muted hidden sm:inline">
                ({isSelectedClosed ? "Closed" : selectedSession.cwdState.path ?? "/"})
              </span>
              {isSelectedFilteredOut && (
                <span
                  className="h-[18px] rounded-full border border-warning-border bg-warning-subtle px-1.5 font-sans text-[10px] font-semibold leading-4 text-warning shadow-2xs inline"
                  title="This session is pinned outside the active filter criteria"
                >
                  Outside filter
                </span>
              )}
            </>
          ) : (
            <span className="text-text-muted">Select Session…</span>
          )}
        </div>
        <ChevronDown
          className={`h-3.5 w-3.5 shrink-0 text-text-subtle transition-transform duration-200 ${
            open ? "rotate-180 text-primary" : ""
          }`}
          aria-hidden="true"
        />
      </button>

      {/* Animated Dropdown Menu using ComboboxPopover */}
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
          placeholder="Search IP, session ID, or path..."
          isLoading={effectiveIsLoading}
          ariaControls={listboxId}
        />

        {/* Error banner if directory fetch failed (outside listbox) */}
        {status === "error" && (
          <div className="mx-2 mb-2 p-2 rounded-lg border border-danger-border bg-danger-subtle text-xs font-mono flex items-center justify-between gap-2">
            <span className="text-danger truncate">{errorMessage ?? "Failed to load audit directory"}</span>
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

        {/* Dedicated listbox for session options */}
        {(filteredActiveSessions.length > 0 || filteredClosedSessions.length > 0) && (
          <div
            role="listbox"
            id={listboxId}
            aria-label="Select session to audit"
            tabIndex={-1}
          >
            {/* Active Sessions Group */}
            {filteredActiveSessions.length > 0 && (
              <div role="group" aria-label={`Active Sessions (${filteredActiveSessions.length})`}>
                <div
                  className="px-2.5 py-1.5 text-xs font-semibold text-text-subtle uppercase tracking-wider flex items-center justify-between select-none"
                  aria-hidden="true"
                >
                  <div className="flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-success" />
                    Active Sessions ({filteredActiveSessions.length})
                  </div>
                  {totalCount !== undefined && totalCount > allDisplaySessions.length && (
                    <span className="text-xs font-mono text-primary/80 lowercase">
                      filtered
                    </span>
                  )}
                </div>
                <div className="space-y-0.5">
                  {filteredActiveSessions.map((s, idx) => {
                    const isSelected = s.sessionId === selectedSessionId;
                    const globalIndex = idx;
                    const isOutsideHome =
                      s.cwdState?.path &&
                      s.cwdState.path !== "/" &&
                      s.cwdState.path !== "/home" &&
                      !s.cwdState.path.startsWith("/home/");

                    return (
                      <button
                        key={s.sessionId}
                        ref={registerOptionRef(globalIndex)}
                        type="button"
                        role="option"
                        id={`${listboxId}-opt-${globalIndex}`}
                        aria-selected={isSelected}
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
                          <span className="text-text-subtle">{s.sessionId.slice(0, 8)}…</span>
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

            {/* Closed Sessions Group */}
            {filteredClosedSessions.length > 0 && (
              <div
                role="group"
                aria-label={`Closed Sessions (${filteredClosedSessions.length})`}
                className={filteredActiveSessions.length > 0 ? "mt-2 pt-2 border-t border-border/60" : ""}
              >
                <div
                  className="px-2.5 py-1.5 text-xs font-semibold text-text-subtle uppercase tracking-wider flex items-center gap-1.5 select-none"
                  aria-hidden="true"
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-text-subtle/50" />
                  Closed Sessions ({filteredClosedSessions.length})
                </div>
                <div className="space-y-0.5">
                  {filteredClosedSessions.map((s, idx) => {
                    const isSelected = s.sessionId === selectedSessionId;
                    const globalIndex = filteredActiveSessions.length + idx;
                    const isOutsideHome =
                      s.cwdState?.path &&
                      s.cwdState.path !== "/" &&
                      s.cwdState.path !== "/home" &&
                      !s.cwdState.path.startsWith("/home/");

                    return (
                      <button
                        key={s.sessionId}
                        ref={registerOptionRef(globalIndex)}
                        type="button"
                        role="option"
                        id={`${listboxId}-opt-${globalIndex}`}
                        aria-selected={isSelected}
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
                          <span className="h-1.5 w-1.5 rounded-full bg-text-subtle/50 shrink-0" />
                          <strong className={isSelected ? "text-primary" : "text-text"}>
                            {s.sourceIp}
                          </strong>
                          <span className="text-text-subtle">·</span>
                          <span className="text-text-subtle">{s.sessionId.slice(0, 8)}…</span>
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
                          <span className="text-xs text-text-subtle font-sans px-1 rounded bg-surface-subtle border border-border shrink-0">
                            Closed
                          </span>
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
        )}

        {/* Pagination / Remote Directory Retrieval (outside listbox) */}
        {(() => {
          const paginationState = getPaginationRenderState({
            effectiveHasMore,
            effectiveIsLoading,
            hasItems: combinedClosedSessions.length > 0,
            isComplete: isSearchActive ? Boolean(searchIsComplete) : Boolean(directoryIsComplete),
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
              <div className="pt-2 pb-1 text-center font-mono text-[11px] text-text-subtle">
                {isSearchActive
                  ? `All matching search results loaded (${combinedClosedSessions.length})`
                  : `All matching directory sessions loaded (${combinedClosedSessions.length})`}
              </div>
            );
          }

          return null;
        })()}

            {/* Empty State */}
            {allDisplaySessions.length === 0 && (
              <div className="px-3 py-4 text-center text-xs text-text-subtle font-mono">
                {searchQuery ? (
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
