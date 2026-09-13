"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Check, ChevronDown, RotateCcw, Search, X } from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";

import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
} from "@/lib/dashboardTypes";

export interface AuditSessionSelectProps {
  sessions: readonly FilesystemTopologySession[];
  recentClosedSessions: readonly FilesystemClosedSession[];
  selectedSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  className?: string;
  totalCount?: number;
  hasActiveFilters?: boolean;
  onResetFilters?: () => void;
  allSessionsList?: readonly (FilesystemTopologySession | FilesystemClosedSession)[];
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
}: AuditSessionSelectProps) {
  const [open, setOpen] = useState(false);
  const reducedMotion = useReducedMotion();
  const [searchQuery, setSearchQuery] = useState("");
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const generatedId = useId();
  const triggerId = `audit-session-select-${generatedId}`;
  const menuId = `${triggerId}-menu`;

  const effectiveAllSessions = useMemo(
    () => allSessionsList ?? [...sessions, ...recentClosedSessions],
    [allSessionsList, sessions, recentClosedSessions],
  );

  const selectedSession = useMemo(
    () =>
      effectiveAllSessions.find((s) => s.sessionId === selectedSessionId) ??
      [...sessions, ...recentClosedSessions].find((s) => s.sessionId === selectedSessionId) ??
      null,
    [effectiveAllSessions, sessions, recentClosedSessions, selectedSessionId],
  );

  const isSelectedClosed = useMemo(
    () =>
      selectedSession
        ? "lifecycle" in selectedSession && Boolean(selectedSession.lifecycle)
        : recentClosedSessions.some((s) => s.sessionId === selectedSessionId),
    [selectedSession, recentClosedSessions, selectedSessionId],
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
    if (!normalizedQuery) return recentClosedSessions;
    return recentClosedSessions.filter(
      (s) =>
        s.sourceIp.toLowerCase().includes(normalizedQuery) ||
        s.sessionId.toLowerCase().includes(normalizedQuery) ||
        (s.cwdState?.path && s.cwdState.path.toLowerCase().includes(normalizedQuery)),
    );
  }, [recentClosedSessions, normalizedQuery]);

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
    setOpen(false);
    setSearchQuery("");
  }, []);

  // Close on click outside or Escape
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        closeMenu();
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeMenu();
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open, closeMenu]);

  // Focus search input when opened
  useEffect(() => {
    if (!open) return;
    const timer = setTimeout(() => searchInputRef.current?.focus(), 50);
    return () => clearTimeout(timer);
  }, [open]);

  // Scroll active option into view when opened
  useEffect(() => {
    if (!open) return;
    if (selectedIndex >= 0 && optionRefs.current[selectedIndex]) {
      optionRefs.current[selectedIndex]?.scrollIntoView({ block: "nearest" });
    }
  }, [open, selectedIndex]);

  const handleSelect = useCallback(
    (sessionId: string) => {
      onSelectSession(sessionId);
      closeMenu();
      triggerRef.current?.focus();
    },
    [onSelectSession, closeMenu],
  );

  const focusOption = (index: number) => {
    if (!allDisplaySessions.length) return;
    const nextIndex = (index + allDisplaySessions.length) % allDisplaySessions.length;
    optionRefs.current[nextIndex]?.focus();
  };

  const handleTriggerKeyDown = (event: ReactKeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      setOpen(true);
      focusOption(event.key === "ArrowDown" ? selectedIndex + 1 : selectedIndex - 1);
    }
  };

  const handleOptionKeyDown = (event: ReactKeyboardEvent<HTMLButtonElement>, index: number) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      focusOption(event.key === "ArrowDown" ? index + 1 : index - 1);
    } else if (event.key === "Home") {
      event.preventDefault();
      focusOption(0);
    } else if (event.key === "End") {
      event.preventDefault();
      focusOption(allDisplaySessions.length - 1);
    }
  };

  return (
    <div ref={rootRef} className={`relative inline-block text-left ${className ?? ""}`}>
      {/* Trigger Button */}
      <button
        ref={triggerRef}
        id={triggerId}
        type="button"
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => setOpen((prev) => !prev)}
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
                <span className="hidden h-[18px] rounded-full border border-primary-border bg-surface px-1.5 font-sans text-xs font-semibold leading-4 text-primary shadow-2xs md:inline">
                  Filtered
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

      {/* Animated Dropdown Menu */}
      <AnimatePresence>
        {open && (
          <motion.div
            id={menuId}
            role="listbox"
            aria-labelledby={triggerId}
            initial={reducedMotion ? false : { opacity: 0, y: -6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={reducedMotion ? undefined : { opacity: 0, y: -6, scale: 0.98 }}
            transition={reducedMotion ? { duration: 0 } : { duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            className="absolute left-0 top-[calc(100%+6px)] z-50 min-w-[320px] sm:min-w-[440px] max-w-[90vw] sm:max-w-[500px] max-h-96 overflow-y-auto overscroll-contain rounded-xl border border-border bg-surface-raised p-1.5 shadow-lg"
          >
            {/* Search Input inside Session Dropdown */}
            <div className="relative mb-1.5 px-1 pt-1">
              <Search className="absolute left-3 top-3 h-3.5 w-3.5 text-text-subtle" />
              <input
                ref={searchInputRef}
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search IP, session ID, or path..."
                className="w-full rounded-lg border border-border bg-surface-subtle pl-8 pr-7 py-1.5 text-xs font-mono text-text placeholder:text-text-subtle focus:border-primary focus:outline-hidden focus:ring-1 focus:ring-primary/40"
              />
              {searchQuery && (
                <button
                type="button"
                onClick={() => setSearchQuery("")}
                aria-label="Clear session search"
                className="absolute right-3 top-3 text-text-subtle hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>

            {/* Callout if currently audited session is hidden by active filter */}
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

            {/* Active Sessions */}
            {filteredActiveSessions.length > 0 && (
              <div>
                <div className="px-2.5 py-1.5 text-xs font-semibold text-text-subtle uppercase tracking-wider flex items-center justify-between select-none">
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
                        ref={(el) => {
                          optionRefs.current[globalIndex] = el;
                        }}
                        type="button"
                        role="option"
                        aria-selected={isSelected}
                        onClick={() => handleSelect(s.sessionId)}
                        onKeyDown={(e) => handleOptionKeyDown(e, globalIndex)}
                        className={`w-full flex items-center justify-between gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-xs font-mono transition-colors ${
                          isSelected
                            ? "bg-primary-subtle text-primary border border-primary-border/50"
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

            {/* Closed Sessions */}
            {filteredClosedSessions.length > 0 && (
              <div className={filteredActiveSessions.length > 0 ? "mt-2 pt-2 border-t border-border/60" : ""}>
                <div className="px-2.5 py-1.5 text-xs font-semibold text-text-subtle uppercase tracking-wider flex items-center gap-1.5 select-none">
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
                        ref={(el) => {
                          optionRefs.current[globalIndex] = el;
                        }}
                        type="button"
                        role="option"
                        aria-selected={isSelected}
                        onClick={() => handleSelect(s.sessionId)}
                        onKeyDown={(e) => handleOptionKeyDown(e, globalIndex)}
                        className={`w-full flex items-center justify-between gap-2.5 rounded-lg px-2.5 py-1.5 text-left text-xs font-mono transition-colors ${
                          isSelected
                            ? "bg-primary-subtle text-primary border border-primary-border/50"
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
                          setSearchQuery("");
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
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
