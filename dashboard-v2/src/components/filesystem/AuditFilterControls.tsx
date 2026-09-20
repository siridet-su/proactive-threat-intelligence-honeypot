"use client";

import {
  Check,
  ChevronDown,
  Clock,
  Folder,
  FolderSearch,
  Home,
  RotateCcw,
  X,
} from "lucide-react";
import {
  useCallback,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";

import { ComboboxPopover, ComboboxSearchInput, useComboboxNavigation } from "./ComboboxPopover";
import { Calendar } from "./Calendar";
import { TimePicker } from "./TimePicker";
import type { DateRange } from "react-day-picker";

import type { CloseReason } from "./auditSessionSearchManager";
import type { DistinctPathOption } from "./filesystemUtils";

export type TimeRangeFilter = "all" | "24h" | "7d" | "30d" | "custom";

export interface AuditFilterControlsProps {
  hideHomeOnly: boolean;
  onToggleHideHomeOnly: () => void;
  targetPath: string | null;
  onSelectTargetPath: (path: string | null) => void;
  timeRange: TimeRangeFilter;
  onSelectTimeRange: (range: TimeRangeFilter) => void;
  customDateRange?: DateRange;
  onSelectCustomDateRange?: (range: DateRange | undefined) => void;
  distinctPaths: readonly DistinctPathOption[];
  homeOnlyCount: number;
  filteredCount: number;
  totalCount: number;
  onResetFilters: () => void;
  selectedCanvasPath?: string | null;
  className?: string;
}

export type PathOptionItem = {
  type: "all" | "canvas" | "path";
  path: string | null;
  label: string;
  count?: number;
};

export function getPathOptionItemKey(item: PathOptionItem): string {
  return `${item.type}:${item.path ?? ""}`;
}

export function getPathOptionItemLabel(item: PathOptionItem): string {
  return item.label;
}

export function AuditFilterControls({
  hideHomeOnly,
  onToggleHideHomeOnly,
  targetPath,
  onSelectTargetPath,
  timeRange,
  onSelectTimeRange,
  customDateRange,
  onSelectCustomDateRange,
  distinctPaths,
  homeOnlyCount,
  filteredCount,
  totalCount,
  onResetFilters,
  selectedCanvasPath,
  className,
}: AuditFilterControlsProps) {
  const [pathDropdownOpen, setPathDropdownOpen] = useState(false);
  const [pathSearchQuery, setPathSearchQuery] = useState("");
  const pathTriggerRef = useRef<HTMLButtonElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const generatedId = useId();
  const pathTriggerId = `audit-path-filter-trigger-${generatedId}`;
  const pathPopupId = `${pathTriggerId}-popup`;
  const pathListboxId = `${pathTriggerId}-listbox`;

  const [timeDropdownOpen, setTimeDropdownOpen] = useState(false);
  const timeTriggerRef = useRef<HTMLButtonElement>(null);
  const timeTriggerId = `audit-time-filter-trigger-${generatedId}`;
  const timePopupId = `${timeTriggerId}-popup`;
  const timeListboxId = `${timeTriggerId}-listbox`;

  const timeOptions: { value: TimeRangeFilter; label: string }[] = useMemo(() => [
    { value: "all", label: "All time" },
    { value: "24h", label: "Last 24 hours" },
    { value: "7d", label: "Last 7 days" },
    { value: "30d", label: "Last 30 days" },
    { value: "custom", label: "Custom range..." },
  ], []);

  const selectedTimeIndex = timeOptions.findIndex(o => o.value === timeRange);

  const {
    activeIndex: timeActiveIndex,
    registerOptionRef: registerTimeOptionRef,
    openWithFocus: openTimeWithFocus,
    handleTriggerKeyDown: handleTimeTriggerKeyDown,
    handleOptionKeyDown: handleTimeOptionKeyDown,
    handleOptionFocus: handleTimeOptionFocus,
  } = useComboboxNavigation<{ value: TimeRangeFilter; label: string }>({
    isOpen: timeDropdownOpen,
    onOpen: () => setTimeDropdownOpen(true),
    onClose: (reason) => {
      setTimeDropdownOpen(false);
      if (reason !== "outside") {
        timeTriggerRef.current?.focus();
      }
    },
    items: timeOptions,
    getLabel: (item) => item.label,
    getKey: (item) => item.value,
    onSelect: (item) => {
      onSelectTimeRange(item.value);
      setTimeDropdownOpen(false);
      timeTriggerRef.current?.focus();
    },
    triggerRef: timeTriggerRef,
    selectedIndex: selectedTimeIndex,
  });

  const handleToggleTimeDropdown = useCallback(() => {
    if (timeDropdownOpen) {
      setTimeDropdownOpen(false);
      timeTriggerRef.current?.focus();
    } else {
      openTimeWithFocus("first");
      setTimeDropdownOpen(true);
    }
  }, [timeDropdownOpen, openTimeWithFocus]);

  const hasActiveFilters = hideHomeOnly || targetPath !== null;

  // Filter distinct paths based on search input
  const filteredPaths = useMemo(() => {
    if (!pathSearchQuery.trim()) return distinctPaths;
    const query = pathSearchQuery.trim().toLowerCase();
    return distinctPaths.filter((item) => item.path.toLowerCase().includes(query));
  }, [distinctPaths, pathSearchQuery]);

  const closeDropdown = useCallback((reason: CloseReason = "escape") => {
    setPathDropdownOpen(false);
    setPathSearchQuery("");
    if (reason !== "outside") {
      pathTriggerRef.current?.focus();
    }
  }, []);

  const handleSelectPath = useCallback(
    (path: string | null) => {
      onSelectTargetPath(path);
      closeDropdown("select");
    },
    [onSelectTargetPath, closeDropdown],
  );

  const pathItems = useMemo<PathOptionItem[]>(() => {
    const list: PathOptionItem[] = [
      {
        type: "all",
        path: null,
        label: "All paths",
        count: totalCount,
      },
    ];

    if (
      selectedCanvasPath &&
      selectedCanvasPath !== "/" &&
      selectedCanvasPath !== targetPath
    ) {
      list.push({
        type: "canvas",
        path: selectedCanvasPath,
        label: selectedCanvasPath,
      });
    }

    for (const item of filteredPaths) {
      list.push({
        type: "path",
        path: item.path,
        label: item.path,
        count: item.sessionCount,
      });
    }

    return list;
  }, [totalCount, selectedCanvasPath, targetPath, filteredPaths]);

  const selectedPathIndex = useMemo(() => {
    return pathItems.findIndex((item) => item.path === targetPath);
  }, [pathItems, targetPath]);

  const {
    activeIndex,
    registerOptionRef,
    openWithFocus,
    handleTriggerKeyDown,
    handleInputKeyDown,
    handleOptionKeyDown,
    handleSearchInputFocus,
    handleOptionFocus,
  } = useComboboxNavigation<PathOptionItem>({
    isOpen: pathDropdownOpen,
    onOpen: () => setPathDropdownOpen(true),
    onClose: (reason) => closeDropdown(reason),
    items: pathItems,
    getLabel: getPathOptionItemLabel,
    getKey: getPathOptionItemKey,
    onSelect: (item) => handleSelectPath(item.path),
    triggerRef: pathTriggerRef,
    searchInputRef,
    selectedIndex: selectedPathIndex,
  });

  const handleToggleDropdown = useCallback(() => {
    if (pathDropdownOpen) {
      closeDropdown("toggle");
    } else {
      openWithFocus("search");
      setPathDropdownOpen(true);
    }
  }, [pathDropdownOpen, closeDropdown, openWithFocus]);


  return (
    <div className={`flex flex-wrap items-center gap-1.5 ${className ?? ""}`}>
      {/* 0. Time Range Selector Dropdown */}
      <div className="relative inline-block text-left">
        <div className="flex items-center">
          <button
            ref={timeTriggerRef}
            id={timeTriggerId}
            type="button"
            role="combobox"
            aria-haspopup="listbox"
            aria-expanded={timeDropdownOpen}
            aria-controls={timeListboxId}
            onClick={handleToggleTimeDropdown}
            onKeyDown={handleTimeTriggerKeyDown}
            title="Filter sessions by time range"
            className={`h-9 min-h-9 flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-mono transition-colors cursor-pointer select-none ${
              timeRange !== "all"
                ? "border-primary-border bg-primary-subtle text-primary shadow-xs hover:bg-primary-subtle/80"
                : "border-border bg-surface text-text-muted hover:border-border-strong hover:bg-surface-hover hover:text-text"
            }`}
          >
            <Clock
              className={`h-3.5 w-3.5 shrink-0 ${
                timeRange !== "all" ? "text-primary" : "text-text-subtle"
              }`}
            />
            <span className="font-sans font-medium text-xs">
              Time: {timeRange === "custom" && customDateRange?.from
                ? `${customDateRange.from.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}${customDateRange.to ? ` - ${customDateRange.to.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}` : ''}`
                : timeOptions.find(o => o.value === timeRange)?.label.replace("Last ", "") ?? "All time"}
            </span>
            <ChevronDown
              className={`h-3.5 w-3.5 text-text-subtle shrink-0 transition-transform ${
                timeDropdownOpen ? "rotate-180" : ""
              }`}
            />
          </button>
        </div>

        <ComboboxPopover
          id={timePopupId}
          isOpen={timeDropdownOpen}
          onClose={() => setTimeDropdownOpen(false)}
          triggerRef={timeTriggerRef}
          ariaLabel="Filter sessions by time range"
          className="min-w-[200px] p-1.5"
        >
          {timeRange === "custom" ? (
            <div className="flex flex-col p-1 w-[280px]">
              <div className="flex items-center justify-between px-2 pb-2 mb-1 border-b border-border">
                <span className="text-xs font-semibold text-text">Custom Range</span>
                <button
                  onClick={() => onSelectTimeRange("all")}
                  className="text-xs text-text-subtle hover:text-text cursor-pointer transition-colors"
                >
                  Presets
                </button>
              </div>
              <Calendar
                mode="range"
                selected={customDateRange}
                onSelect={(range) => {
                  onSelectCustomDateRange?.(range);
                  // Do not auto-close so the user can edit time
                }}
                numberOfMonths={1}
                className="pointer-events-auto flex justify-center"
              />
              
              {customDateRange?.from && (
                <div className="flex flex-col gap-2 px-3 pt-3 pb-1 mt-1 border-t border-border">
                  <TimePicker 
                    label="Start Time" 
                    date={customDateRange.from} 
                    onChange={(newDate) => onSelectCustomDateRange?.({ ...customDateRange, from: newDate })} 
                  />
                  {customDateRange?.to && (
                    <TimePicker 
                      label="End Time" 
                      date={customDateRange.to} 
                      onChange={(newDate) => onSelectCustomDateRange?.({ ...customDateRange, to: newDate })} 
                    />
                  )}
                  
                  <button
                    onClick={() => {
                      setTimeDropdownOpen(false);
                      timeTriggerRef.current?.focus();
                    }}
                    disabled={!customDateRange?.from || !customDateRange?.to}
                    className="mt-3 w-full bg-primary text-primary-content rounded-md py-1.5 text-xs font-medium hover:bg-primary-action transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Apply Range
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div
              role="listbox"
              id={timeListboxId}
              aria-label="Filter sessions by time range"
              tabIndex={-1}
            >
              {timeOptions.map((item, index) => {
                const isSelected = item.value === timeRange;
                return (
                  <button
                    key={item.value}
                    ref={registerTimeOptionRef(index, item.value)}
                    type="button"
                    role="option"
                    id={`${timeListboxId}-opt-${index}`}
                    aria-selected={isSelected}
                    tabIndex={timeActiveIndex === index || (timeActiveIndex === -1 && index === 0) ? 0 : -1}
                    onFocus={() => handleTimeOptionFocus(index, item.value)}
                    onClick={() => {
                      onSelectTimeRange(item.value);
                      if (item.value !== "custom") {
                        setTimeDropdownOpen(false);
                        timeTriggerRef.current?.focus();
                      }
                    }}
                    onKeyDown={(e) => handleTimeOptionKeyDown(e, index)}
                    className={`w-full flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-left text-xs font-mono transition-colors cursor-pointer ${
                      isSelected
                        ? "bg-primary-subtle text-primary"
                        : timeActiveIndex === index
                          ? "bg-surface-hover text-text"
                          : "text-text-muted hover:bg-surface-hover hover:text-text"
                    }`}
                  >
                    <span className="flex-1">{item.label}</span>
                    {isSelected && (
                      <Check className="h-3.5 w-3.5 text-primary shrink-0" aria-hidden="true" />
                    )}
                  </button>
                );
              })}
            </div>
          )}
        </ComboboxPopover>
      </div>
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
      <div className="relative inline-block text-left">
        <div className="flex items-center">
          <button
            ref={pathTriggerRef}
            id={pathTriggerId}
            type="button"
            role="combobox"
            aria-haspopup="listbox"
            aria-expanded={pathDropdownOpen}
            aria-controls={pathListboxId}
            onClick={handleToggleDropdown}
            onKeyDown={handleTriggerKeyDown}
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
        <ComboboxPopover
          id={pathPopupId}
          isOpen={pathDropdownOpen}
          onClose={closeDropdown}
          triggerRef={pathTriggerRef}
          ariaLabel="Filter sessions by path"
          totalCount={pathItems.length}
          className="min-w-[260px] sm:min-w-[320px] max-w-[90vw] sm:max-w-sm max-h-80 overflow-y-auto overscroll-contain"
        >
          {/* Search Box (outside listbox) */}
          <ComboboxSearchInput
            inputRef={searchInputRef}
            value={pathSearchQuery}
            onChange={setPathSearchQuery}
            onClear={() => setPathSearchQuery("")}
            onKeyDown={handleInputKeyDown}
            onFocus={handleSearchInputFocus}
            placeholder="Search directory path..."
            ariaControls={pathListboxId}
          />


          {/* Dedicated listbox for path options */}
          <div
            role="listbox"
            id={pathListboxId}
            aria-label="Filter sessions by path"
            tabIndex={-1}
          >
            {/* Quick option: All paths (reset) */}
            <button
              ref={registerOptionRef(0, "all:")}
              type="button"
              role="option"
              id={`${pathListboxId}-opt-0`}
              aria-selected={targetPath === null}
              tabIndex={activeIndex === 0 || activeIndex === -1 ? 0 : -1}
              onFocus={() => handleOptionFocus(0, "all:")}
              onClick={() => handleSelectPath(null)}
              onKeyDown={(e) => handleOptionKeyDown(e, 0)}
              className={`w-full flex items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-left text-xs font-mono transition-colors cursor-pointer ${
                targetPath === null
                  ? "bg-primary-subtle text-primary border border-primary-border/50"
                  : activeIndex === 0
                    ? "bg-surface-hover text-text border border-border/50"
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
                    ref={registerOptionRef(1, `canvas:${selectedCanvasPath}`)}
                    type="button"
                    role="option"
                    id={`${pathListboxId}-opt-1`}
                    aria-selected={targetPath === selectedCanvasPath}
                    tabIndex={activeIndex === 1 ? 0 : -1}
                    onFocus={() => handleOptionFocus(1, `canvas:${selectedCanvasPath}`)}
                    onClick={() => handleSelectPath(selectedCanvasPath)}
                    onKeyDown={(e) => handleOptionKeyDown(e, 1)}
                    className={`w-full flex items-center justify-between gap-2 rounded-lg border border-primary/30 bg-primary/10 px-2 py-1.5 text-left text-xs font-mono text-primary hover:bg-primary/20 transition-colors cursor-pointer ${
                      activeIndex === 1 ? "ring-2 ring-primary/40" : ""
                    }`}
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

            {/* Distinct Paths List Group */}
            {filteredPaths.length > 0 && (
              <div
                role="group"
                aria-label={`Observed Directories (${filteredPaths.length})`}
                className="mt-1 pt-1 border-t border-border/60"
              >
                <div
                  className="px-2 py-1 text-xs font-semibold text-text-subtle uppercase tracking-wider select-none"
                  aria-hidden="true"
                >
                  Observed Directories ({filteredPaths.length})
                </div>
                <div className="space-y-0.5">
                  {filteredPaths.map((item, idx) => {
                    const isSelected = targetPath === item.path;
                    const canvasOffset =
                      selectedCanvasPath &&
                      selectedCanvasPath !== "/" &&
                      selectedCanvasPath !== targetPath
                        ? 2
                        : 1;
                    const globalIndex = canvasOffset + idx;
                    const isActive = activeIndex === globalIndex;

                    return (
                      <button
                        key={item.path}
                        ref={registerOptionRef(globalIndex, `path:${item.path}`)}
                        type="button"
                        role="option"
                        id={`${pathListboxId}-opt-${globalIndex}`}
                        aria-selected={isSelected}
                        tabIndex={isActive ? 0 : -1}
                        onFocus={() => handleOptionFocus(globalIndex, `path:${item.path}`)}
                        onClick={() => handleSelectPath(item.path)}
                        onKeyDown={(e) => handleOptionKeyDown(e, globalIndex)}
                        className={`w-full flex items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-left text-xs font-mono transition-colors cursor-pointer ${
                          isSelected
                            ? "bg-primary-subtle text-primary border border-primary-border/50"
                            : isActive
                              ? "bg-surface-hover text-text border border-border/50"
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
                </div>
              </div>
            )}
          </div>

          {/* Empty state when 0 paths match (outside listbox) */}
          {filteredPaths.length === 0 && (
            <div className="px-3 py-3 text-center text-xs text-text-subtle font-mono">
              No paths match &ldquo;{pathSearchQuery}&rdquo;
            </div>
          )}
        </ComboboxPopover>
      </div>

      {/* 3. Filter Result Summary & Quick Reset */}
      {hasActiveFilters && (
        <div className="flex h-9 min-h-9 items-stretch overflow-hidden rounded-lg border border-border bg-surface text-xs">
          <span className="flex items-center px-2 font-mono text-xs text-text-muted">
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
            className="flex min-w-14 items-center justify-center gap-1 border-l border-border px-2 font-sans text-xs text-text-muted transition-colors hover:bg-surface-hover hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus-ring"
          >
            <RotateCcw className="h-3 w-3" />
            <span>Reset</span>
          </button>
        </div>
      )}
    </div>
  );
}
