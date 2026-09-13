"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
  Check,
  ChevronDown,
  Folder,
  FolderSearch,
  Home,
  RotateCcw,
  Search,
  X,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

import type { DistinctPathOption } from "./filesystemUtils";

export interface AuditFilterControlsProps {
  hideHomeOnly: boolean;
  onToggleHideHomeOnly: () => void;
  targetPath: string | null;
  onSelectTargetPath: (path: string | null) => void;
  distinctPaths: readonly DistinctPathOption[];
  homeOnlyCount: number;
  filteredCount: number;
  totalCount: number;
  onResetFilters: () => void;
  selectedCanvasPath?: string | null;
  className?: string;
}

export function AuditFilterControls({
  hideHomeOnly,
  onToggleHideHomeOnly,
  targetPath,
  onSelectTargetPath,
  distinctPaths,
  homeOnlyCount,
  filteredCount,
  totalCount,
  onResetFilters,
  selectedCanvasPath,
  className,
}: AuditFilterControlsProps) {
  const [pathDropdownOpen, setPathDropdownOpen] = useState(false);
  const reducedMotion = useReducedMotion();
  const [pathSearchQuery, setPathSearchQuery] = useState("");
  const pathMenuRef = useRef<HTMLDivElement>(null);
  const pathTriggerRef = useRef<HTMLButtonElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const generatedId = useId();
  const pathMenuId = `audit-path-filter-menu-${generatedId}`;
  const pathTriggerId = `audit-path-filter-trigger-${generatedId}`;

  const hasActiveFilters = hideHomeOnly || targetPath !== null;

  // Filter distinct paths based on search input
  const filteredPaths = useMemo(() => {
    if (!pathSearchQuery.trim()) return distinctPaths;
    const query = pathSearchQuery.trim().toLowerCase();
    return distinctPaths.filter((item) => item.path.toLowerCase().includes(query));
  }, [distinctPaths, pathSearchQuery]);

  const closeDropdown = useCallback(() => {
    setPathDropdownOpen(false);
    setPathSearchQuery("");
  }, []);

  // Close path dropdown on click outside or Escape
  useEffect(() => {
    if (!pathDropdownOpen) return;
    const onPointerDown = (event: PointerEvent) => {
      if (pathMenuRef.current && !pathMenuRef.current.contains(event.target as Node)) {
        closeDropdown();
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeDropdown();
        pathTriggerRef.current?.focus();
      }
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [pathDropdownOpen, closeDropdown]);

  // Focus search input when dropdown opens
  useEffect(() => {
    if (!pathDropdownOpen) return;
    const timer = setTimeout(() => searchInputRef.current?.focus(), 50);
    return () => clearTimeout(timer);
  }, [pathDropdownOpen]);

  const handleSelectPath = useCallback(
    (path: string | null) => {
      onSelectTargetPath(path);
      closeDropdown();
      pathTriggerRef.current?.focus();
    },
    [onSelectTargetPath, closeDropdown],
  );

  return (
    <div className={`flex flex-wrap items-center gap-1.5 ${className ?? ""}`}>
      {/* 1. Toggle: Hide /home Only */}
      <button
        type="button"
        aria-pressed={hideHomeOnly}
        onClick={onToggleHideHomeOnly}
        title={
          hideHomeOnly
            ? `Excluding ${homeOnlyCount} home-only session${homeOnlyCount === 1 ? "" : "s"}. Click to include them.`
            : "Exclude sessions that stayed in /home and never traversed into system directories"
        }
        className={`h-9 min-h-9 flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-mono transition-colors cursor-pointer select-none ${
          hideHomeOnly
            ? "border-primary-border bg-primary-subtle text-primary shadow-xs hover:bg-primary-subtle/80"
            : "border-border bg-surface text-text-muted hover:border-border-strong hover:bg-surface-hover hover:text-text"
        }`}
      >
        <Home
          className={`h-3.5 w-3.5 shrink-0 ${
            hideHomeOnly ? "text-primary" : "text-text-subtle"
          }`}
        />
        <span className="font-sans font-medium text-xs">
          Exclude home-only
        </span>
        {homeOnlyCount > 0 && (
          <span
            className={`rounded-full px-1.5 py-0.2 text-xs font-mono font-semibold transition-colors ${
              hideHomeOnly
                ? "bg-surface text-primary border border-primary-border shadow-2xs"
                : "bg-surface-subtle text-text-subtle border border-border"
            }`}
          >
            {homeOnlyCount}
          </span>
        )}
      </button>

      {/* 2. Target Path Selector Dropdown */}
      <div ref={pathMenuRef} className="relative inline-block text-left">
        <div className="flex items-center">
          <button
            ref={pathTriggerRef}
            id={pathTriggerId}
            type="button"
            role="combobox"
            aria-haspopup="listbox"
            aria-expanded={pathDropdownOpen}
            aria-controls={pathMenuId}
            onClick={() => setPathDropdownOpen((prev) => !prev)}
            className={`h-9 min-h-9 max-w-[220px] sm:max-w-xs flex items-center justify-between gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-mono transition-colors cursor-pointer select-none ${
              targetPath
                ? "border-primary-border bg-primary-subtle text-primary shadow-xs"
                : pathDropdownOpen
                  ? "border-primary ring-2 ring-primary/20 bg-surface text-text"
                  : "border-border bg-surface text-text-muted hover:border-border-strong hover:bg-surface-hover hover:text-text"
            }`}
            title={targetPath ? `Filtering sessions that visited: ${targetPath}` : "Filter sessions by path of interest"}
          >
            <div className="flex items-center gap-1.5 truncate">
              <FolderSearch
                className={`h-3.5 w-3.5 shrink-0 ${targetPath ? "text-primary" : "text-text-subtle"}`}
              />
              <span className="hidden font-sans text-xs font-medium text-text-subtle sm:inline">
                Path:
              </span>
              <span className={`truncate ${targetPath ? "font-bold text-primary" : "text-text"}`}>
                {targetPath ? targetPath : "All paths"}
              </span>
            </div>
            <ChevronDown
              className={`h-3 w-3 shrink-0 text-text-subtle transition-transform duration-200 ${
                pathDropdownOpen ? "rotate-180 text-primary" : ""
              }`}
            />
          </button>

          {/* Quick Clear Path Button */}
          {targetPath && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onSelectTargetPath(null);
              }}
              title="Clear path filter"
              aria-label="Clear path filter"
              className="ml-1 flex h-9 w-9 items-center justify-center rounded-md border border-border bg-surface text-text-subtle hover:text-text hover:bg-surface-hover transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* Path Popover Menu */}
        <AnimatePresence>
          {pathDropdownOpen && (
            <motion.div
              id={pathMenuId}
              role="listbox"
              aria-labelledby={pathTriggerId}
              initial={reducedMotion ? false : { opacity: 0, y: -6, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={reducedMotion ? undefined : { opacity: 0, y: -6, scale: 0.98 }}
              transition={reducedMotion ? { duration: 0 } : { duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
              className="absolute left-0 top-[calc(100%+6px)] z-50 min-w-[260px] sm:min-w-[320px] max-w-[90vw] sm:max-w-sm max-h-80 overflow-y-auto overscroll-contain rounded-xl border border-border bg-surface-raised p-1.5 shadow-lg"
            >
              {/* Search Box */}
              <div className="relative mb-1.5 px-1 pt-1">
                <Search className="absolute left-3 top-3 h-3.5 w-3.5 text-text-subtle" />
                <input
                  ref={searchInputRef}
                  type="text"
                  value={pathSearchQuery}
                  onChange={(e) => setPathSearchQuery(e.target.value)}
                  placeholder="Search directory path..."
                  className="w-full rounded-lg border border-border bg-surface-subtle pl-8 pr-7 py-1.5 text-xs font-mono text-text placeholder:text-text-subtle focus:border-primary focus:outline-hidden focus:ring-1 focus:ring-primary/40"
                />
                {pathSearchQuery && (
                  <button
                  type="button"
                  onClick={() => setPathSearchQuery("")}
                  aria-label="Clear directory search"
                  className="absolute right-3 top-3 text-text-subtle hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>

              {/* Quick option: All paths (reset) */}
              <button
                type="button"
                role="option"
                aria-selected={targetPath === null}
                onClick={() => handleSelectPath(null)}
                className={`w-full flex items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-left text-xs font-mono transition-colors ${
                  targetPath === null
                    ? "bg-primary-subtle text-primary border border-primary-border/50"
                    : "text-text-muted hover:bg-surface-hover hover:text-text border border-transparent"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Folder className="h-3.5 w-3.5 text-text-subtle" />
                  <span className="font-sans font-medium">All paths</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <span className="text-xs text-text-subtle">({totalCount} sessions)</span>
                  {targetPath === null && <Check className="h-3.5 w-3.5 text-primary" />}
                </div>
              </button>

              {/* Quick shortcut if user clicked a node on canvas */}
              {selectedCanvasPath &&
                selectedCanvasPath !== "/" &&
                selectedCanvasPath !== targetPath && (
                  <div className="mt-1 mb-1 px-1">
                    <button
                      type="button"
                      onClick={() => handleSelectPath(selectedCanvasPath)}
                      className="w-full flex items-center justify-between gap-2 rounded-lg border border-primary/30 bg-primary/10 px-2 py-1.5 text-left text-xs font-mono text-primary hover:bg-primary/20 transition-colors"
                    >
                      <div className="flex items-center gap-1.5 truncate">
                        <span className="text-xs font-sans font-semibold uppercase tracking-wider text-primary/80">
                          Canvas Selection:
                        </span>
                        <strong className="truncate">{selectedCanvasPath}</strong>
                      </div>
                      <span className="text-xs underline font-sans shrink-0">Filter</span>
                    </button>
                  </div>
                )}

              {/* Distinct Paths List */}
              <div className="mt-1 pt-1 border-t border-border/60">
                <div className="px-2 py-1 text-xs font-semibold text-text-subtle uppercase tracking-wider">
                  Observed Directories ({filteredPaths.length})
                </div>
                <div className="space-y-0.5">
                  {filteredPaths.map((item) => {
                    const isSelected = targetPath === item.path;
                    return (
                      <button
                        key={item.path}
                        type="button"
                        role="option"
                        aria-selected={isSelected}
                        onClick={() => handleSelectPath(item.path)}
                        className={`w-full flex items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-left text-xs font-mono transition-colors ${
                          isSelected
                            ? "bg-primary-subtle text-primary border border-primary-border/50"
                            : "text-text-muted hover:bg-surface-hover hover:text-text border border-transparent"
                        }`}
                      >
                        <div className="flex items-center gap-2 truncate">
                          <Folder className={`h-3.5 w-3.5 shrink-0 ${isSelected ? "text-primary" : "text-text-subtle"}`} />
                          <span className={`truncate ${isSelected ? "font-bold text-primary" : "text-text"}`}>
                            {item.path}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <span className="rounded bg-surface-subtle border border-border/60 px-1 py-0.2 text-xs text-text-subtle">
                            {item.sessionCount} {item.sessionCount === 1 ? "session" : "sessions"}
                          </span>
                          {isSelected && <Check className="h-3.5 w-3.5 text-primary" />}
                        </div>
                      </button>
                    );
                  })}

                  {filteredPaths.length === 0 && (
                    <div className="px-3 py-3 text-center text-xs text-text-subtle font-mono">
                      No paths match &ldquo;{pathSearchQuery}&rdquo;
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* 3. Filter Result Summary & Quick Reset */}
      {hasActiveFilters && (
        <div className="flex items-center gap-1.5 rounded-lg border border-border bg-surface px-2 py-1 text-xs">
          <span className="font-mono text-xs text-text-muted">
            Filtered:{" "}
            <strong
              className={
                filteredCount === 0
                  ? "text-danger font-semibold"
                  : "text-primary font-semibold"
              }
            >
              {filteredCount}
            </strong>
            /{totalCount}
          </span>
          <button
            type="button"
            onClick={onResetFilters}
            title="Reset all audit filters"
            aria-label="Reset all audit filters"
            className="ml-0.5 h-9 px-2 flex items-center gap-1 rounded-md border border-border bg-surface text-xs font-sans text-text-muted hover:text-text hover:bg-surface-hover hover:border-border-strong transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
          >
            <RotateCcw className="h-2.5 w-2.5" />
            <span>Reset</span>
          </button>
        </div>
      )}
    </div>
  );
}
