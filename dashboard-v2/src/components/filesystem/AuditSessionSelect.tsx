"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Check, ChevronDown } from "lucide-react";
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
}

export function AuditSessionSelect({
  sessions,
  recentClosedSessions,
  selectedSessionId,
  onSelectSession,
  className,
}: AuditSessionSelectProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const generatedId = useId();
  const triggerId = `audit-session-select-${generatedId}`;
  const menuId = `${triggerId}-menu`;

  const allSessions = useMemo(
    () => [...sessions, ...recentClosedSessions],
    [sessions, recentClosedSessions],
  );

  const selectedSession = useMemo(
    () => allSessions.find((s) => s.sessionId === selectedSessionId) ?? null,
    [allSessions, selectedSessionId],
  );

  const isSelectedClosed = useMemo(
    () => recentClosedSessions.some((s) => s.sessionId === selectedSessionId),
    [recentClosedSessions, selectedSessionId],
  );

  const selectedIndex = useMemo(
    () => allSessions.findIndex((s) => s.sessionId === selectedSessionId),
    [allSessions, selectedSessionId],
  );

  // Close on click outside or Escape
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
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
      setOpen(false);
      triggerRef.current?.focus();
    },
    [onSelectSession],
  );

  const focusOption = (index: number) => {
    if (!allSessions.length) return;
    const nextIndex = (index + allSessions.length) % allSessions.length;
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
      focusOption(allSessions.length - 1);
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
        className={`h-8 min-h-8 max-w-[280px] sm:max-w-md flex items-center justify-between gap-2 rounded-lg border border-border bg-surface-subtle px-2.5 py-1 font-mono text-xs text-text transition-all cursor-pointer select-none ${
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
            initial={{ opacity: 0, y: -6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.98 }}
            transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            className="absolute left-0 top-[calc(100%+6px)] z-50 min-w-[300px] sm:min-w-[420px] max-w-[90vw] sm:max-w-[480px] max-h-80 overflow-y-auto overscroll-contain rounded-xl border border-border bg-surface p-1.5 shadow-2xl backdrop-blur-md"
          >
            {/* Active Sessions */}
            {sessions.length > 0 && (
              <div>
                <div className="px-2.5 py-1.5 text-[11px] font-semibold text-text-subtle uppercase tracking-wider flex items-center gap-1.5 select-none">
                  <span className="h-1.5 w-1.5 rounded-full bg-success" />
                  Active Sessions ({sessions.length})
                </div>
                <div className="space-y-0.5">
                  {sessions.map((s, idx) => {
                    const isSelected = s.sessionId === selectedSessionId;
                    const globalIndex = idx;
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
                            <span className="truncate text-text-subtle">
                              ({s.cwdState.path})
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
            {recentClosedSessions.length > 0 && (
              <div className={sessions.length > 0 ? "mt-2 pt-2 border-t border-border/60" : ""}>
                <div className="px-2.5 py-1.5 text-[11px] font-semibold text-text-subtle uppercase tracking-wider flex items-center gap-1.5 select-none">
                  <span className="h-1.5 w-1.5 rounded-full bg-text-subtle/50" />
                  Closed Sessions ({recentClosedSessions.length})
                </div>
                <div className="space-y-0.5">
                  {recentClosedSessions.map((s, idx) => {
                    const isSelected = s.sessionId === selectedSessionId;
                    const globalIndex = sessions.length + idx;
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
                          <span className="text-[10px] text-text-subtle font-sans px-1 rounded bg-surface-subtle border border-border shrink-0">
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
            {sessions.length === 0 && recentClosedSessions.length === 0 && (
              <div className="px-3 py-4 text-center text-xs text-text-subtle font-mono">
                No sessions available for audit
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
