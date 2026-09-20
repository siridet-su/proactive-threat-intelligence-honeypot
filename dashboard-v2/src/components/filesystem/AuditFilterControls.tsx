"use client";

import {
  ArrowRight,
  Calendar as CalendarIcon,
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
import { motion, AnimatePresence, useReducedMotion } from "framer-motion";

import { ComboboxPopover, ComboboxSearchInput, useComboboxNavigation } from "./ComboboxPopover";
import { Calendar } from "./Calendar";
import { TimePicker } from "./TimePicker";
import type { DateRange } from "react-day-picker";
import { format, isSameDay } from "date-fns";

import type { CloseReason } from "./auditSessionSearchManager";
import type { DistinctPathOption } from "./filesystemUtils";

export type TimeRangeFilter =
  | "all"
  | "15m"
  | "1h"
  | "6h"
  | "24h"
  | "7d"
  | "30d"
  | "today"
  | "yesterday"
  | "custom";

export const PRESET_OPTIONS: { value: TimeRangeFilter; label: string; shortLabel: string }[] = [
  { value: "all", label: "All time", shortLabel: "All time" },
  { value: "15m", label: "Last 15 minutes", shortLabel: "Last 15m" },
  { value: "1h", label: "Last 1 hour", shortLabel: "Last 1h" },
  { value: "6h", label: "Last 6 hours", shortLabel: "Last 6h" },
  { value: "24h", label: "Last 24 hours", shortLabel: "Last 24h" },
  { value: "7d", label: "Last 7 days", shortLabel: "Last 7d" },
  { value: "30d", label: "Last 30 days", shortLabel: "Last 30d" },
  { value: "today", label: "Today", shortLabel: "Today" },
  { value: "yesterday", label: "Yesterday", shortLabel: "Yesterday" },
];

export function getPresetDateRange(preset: TimeRangeFilter): DateRange | undefined {
  const now = new Date();
  switch (preset) {
    case "15m":
      return { from: new Date(now.getTime() - 15 * 60 * 1000), to: now };
    case "1h":
      return { from: new Date(now.getTime() - 60 * 60 * 1000), to: now };
    case "6h":
      return { from: new Date(now.getTime() - 6 * 3600 * 1000), to: now };
    case "24h":
      return { from: new Date(now.getTime() - 24 * 3600 * 1000), to: now };
    case "7d":
      return { from: new Date(now.getTime() - 7 * 86400 * 1000), to: now };
    case "30d":
      return { from: new Date(now.getTime() - 30 * 86400 * 1000), to: now };
    case "today": {
      const start = new Date(now);
      start.setHours(0, 0, 0, 0);
      return { from: start, to: now };
    }
    case "yesterday": {
      const yesterday = new Date(now.getTime() - 86400 * 1000);
      const start = new Date(yesterday);
      start.setHours(0, 0, 0, 0);
      const end = new Date(yesterday);
      end.setHours(23, 59, 59, 999);
      return { from: start, to: end };
    }
    default:
      return undefined;
  }
}

export function formatTimeFilterLabel(timeRange: TimeRangeFilter, customDateRange?: DateRange): string {
  if (timeRange === "all") return "All time";
  if (timeRange === "custom" && customDateRange?.from) {
    const fromStr = format(customDateRange.from, "MMM d, HH:mm");
    if (!customDateRange.to) return `From ${fromStr}`;
    const toStr = isSameDay(customDateRange.from, customDateRange.to)
      ? format(customDateRange.to, "HH:mm")
      : format(customDateRange.to, "MMM d, HH:mm");
    return `${fromStr} - ${toStr}`;
  }
  const found = PRESET_OPTIONS.find((p) => p.value === timeRange);
  return found?.shortLabel ?? timeRange;
}

export function formatDuration(from?: Date, to?: Date): string {
  if (!from || !to) return "";
  const diffMs = Math.max(0, to.getTime() - from.getTime());
  const totalMins = Math.floor(diffMs / (60 * 1000));
  const days = Math.floor(totalMins / (24 * 60));
  const hours = Math.floor((totalMins % (24 * 60)) / 60);
  const mins = totalMins % 60;
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

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

const STEP_TAB_COLUMN: Record<"date" | "time", number> = {
  date: 1,
  time: 2,
};

const STEP_CONTENT_VARIANTS = {
  enter: (direction: number) => ({ opacity: direction === 0 ? 1 : 0, x: direction * 10 }),
  center: { opacity: 1, x: 0 },
  exit: (direction: number) => ({ opacity: direction === 0 ? 1 : 0, x: direction * -6 }),
};

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

  const [activeStep, setActiveStep] = useState<"date" | "time">("date");
  const [stepDirection, setStepDirection] = useState(1);
  const shouldReduceMotion = useReducedMotion();

  const handleStepChange = useCallback((nextStep: "date" | "time") => {
    setActiveStep((currentStep) => {
      if (nextStep !== currentStep) {
        setStepDirection(STEP_TAB_COLUMN[nextStep] > STEP_TAB_COLUMN[currentStep] ? 1 : -1);
      }
      return nextStep;
    });
  }, []);
  const [draftTimeRange, setDraftTimeRange] = useState<TimeRangeFilter>(timeRange);
  const [draftRange, setDraftRange] = useState<DateRange | undefined>(customDateRange);
  const [hasCustomTime, setHasCustomTime] = useState<boolean>(false);
  const [isSelecting, setIsSelecting] = useState<boolean>(false);
  const [selectionStart, setSelectionStart] = useState<Date | null>(null);

  const handleToggleTimeDropdown = useCallback(() => {
    if (timeDropdownOpen) {
      setTimeDropdownOpen(false);
      setIsSelecting(false);
      setSelectionStart(null);
      timeTriggerRef.current?.focus();
    } else {
      handleStepChange("date");
      setIsSelecting(false);
      setSelectionStart(null);
      if (customDateRange?.from && customDateRange?.to) {
        setDraftTimeRange(timeRange);
        setDraftRange(customDateRange);
        const isFullDay =
          customDateRange.from.getHours() === 0 &&
          customDateRange.from.getMinutes() === 0 &&
          customDateRange.to.getHours() === 23 &&
          customDateRange.to.getMinutes() === 59;
        setHasCustomTime(!isFullDay);
      } else if (timeRange !== "all" && timeRange !== "custom") {
        setDraftTimeRange(timeRange);
        setDraftRange(getPresetDateRange(timeRange));
        setHasCustomTime(false);
      } else {
        // Default to Today: from 00:00 to current time (Now)
        const now = new Date();
        const start = new Date(now);
        start.setHours(0, 0, 0, 0);
        setDraftRange({ from: start, to: now });
        setDraftTimeRange("today");
        setHasCustomTime(false);
      }
      setTimeDropdownOpen(true);
    }
  }, [timeDropdownOpen, timeRange, customDateRange, handleStepChange]);

  const handleSelectPreset = useCallback((preset: TimeRangeFilter) => {
    setIsSelecting(false);
    setSelectionStart(null);
    setDraftTimeRange(preset);
    setHasCustomTime(false);
    if (preset === "all") {
      setDraftRange(undefined);
    } else {
      setDraftRange(getPresetDateRange(preset));
    }
  }, []);

  const handleCustomRangeSelect = useCallback(
    (_newRange: DateRange | undefined, selectedDay?: Date) => {
      setDraftTimeRange("custom");
      setHasCustomTime(false);
      const now = new Date();
      const clickedDay = selectedDay ?? _newRange?.from ?? now;

      if (!isSelecting || !selectionStart) {
        // First click: select this day as a single day
        setIsSelecting(true);
        setSelectionStart(clickedDay);

        const start = new Date(clickedDay);
        start.setHours(0, 0, 0, 0);

        let end: Date;
        if (isSameDay(clickedDay, now)) {
          // If Today: default to current time (Now)
          end = new Date(now);
        } else {
          // If other date: default to all time (23:59:59.999)
          end = new Date(clickedDay);
          end.setHours(23, 59, 59, 999);
        }

        setDraftRange({ from: start, to: end });
      } else {
        // Second click: complete range from selectionStart to clickedDay
        setIsSelecting(false);
        setSelectionStart(null);

        const startDay = clickedDay < selectionStart ? clickedDay : selectionStart;
        const endDay = clickedDay < selectionStart ? selectionStart : clickedDay;

        const start = new Date(startDay);
        start.setHours(0, 0, 0, 0);

        const end = new Date(endDay);
        if (isSameDay(startDay, endDay) && isSameDay(endDay, now)) {
          // If both start and end are Today: current time
          end.setHours(now.getHours(), now.getMinutes(), now.getSeconds(), now.getMilliseconds());
        } else {
          // Range or single day on other date: all time (23:59:59.999)
          end.setHours(23, 59, 59, 999);
        }

        setDraftRange({ from: start, to: end });
      }
    },
    [isSelecting, selectionStart],
  );

  const handleApplyTimeFilter = useCallback(() => {
    const now = new Date();
    let finalRange = draftRange;
    if (finalRange?.from && !finalRange?.to) {
      if (isSameDay(finalRange.from, now)) {
        finalRange = { from: finalRange.from, to: now };
      } else {
        const endOfDay = new Date(finalRange.from);
        if (hasCustomTime) {
          endOfDay.setHours(finalRange.from.getHours(), finalRange.from.getMinutes(), 59, 999);
        } else {
          endOfDay.setHours(23, 59, 59, 999);
        }
        finalRange = { from: finalRange.from, to: endOfDay };
      }
    }
    setIsSelecting(false);
    setSelectionStart(null);
    onSelectTimeRange(draftTimeRange);
    onSelectCustomDateRange?.(finalRange);
    setTimeDropdownOpen(false);
    timeTriggerRef.current?.focus();
  }, [draftTimeRange, draftRange, hasCustomTime, onSelectTimeRange, onSelectCustomDateRange]);

  const handleSwitchToTime = useCallback(() => {
    const now = new Date();
    if (!draftRange?.from) {
      const start = new Date(now);
      start.setHours(0, 0, 0, 0);
      setDraftRange({ from: start, to: now });
      setDraftTimeRange("today");
    } else if (!draftRange.to) {
      if (isSameDay(draftRange.from, now)) {
        setDraftRange({ from: draftRange.from, to: now });
      } else {
        const endOfDay = new Date(draftRange.from);
        endOfDay.setHours(23, 59, 59, 999);
        setDraftRange({ from: draftRange.from, to: endOfDay });
      }
    }
    setIsSelecting(false);
    setSelectionStart(null);
    handleStepChange("time");
  }, [draftRange, handleStepChange]);

  const handleClearTimeFilter = useCallback(() => {
    setIsSelecting(false);
    setSelectionStart(null);
    onSelectTimeRange("all");
    onSelectCustomDateRange?.(undefined);
  }, [onSelectTimeRange, onSelectCustomDateRange]);

  const hasActiveFilters = hideHomeOnly || targetPath !== null || timeRange !== "all";

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
            aria-haspopup="dialog"
            aria-expanded={timeDropdownOpen}
            aria-controls={timePopupId}
            onClick={handleToggleTimeDropdown}
            title="Filter sessions by time range"
            className={`h-9 min-h-9 flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-mono transition-colors cursor-pointer select-none ${
              timeRange !== "all"
                ? "border-primary-border bg-primary-subtle text-primary shadow-xs hover:bg-primary-subtle/80"
                : timeDropdownOpen
                  ? "border-primary ring-2 ring-primary/20 bg-surface text-text"
                  : "border-border bg-surface text-text-muted hover:border-border-strong hover:bg-surface-hover hover:text-text"
            }`}
          >
            <Clock
              className={`h-3.5 w-3.5 shrink-0 ${
                timeRange !== "all" ? "text-primary" : "text-text-subtle"
              }`}
            />
            <span className="font-sans font-medium text-xs">
              Time: {formatTimeFilterLabel(timeRange, customDateRange)}
            </span>
            <ChevronDown
              className={`h-3.5 w-3.5 shrink-0 transition-transform duration-150 ${
                timeDropdownOpen ? "rotate-180 text-primary" : "text-text-subtle"
              }`}
            />
          </button>

          {/* Quick Clear Time Filter Button */}
          {timeRange !== "all" && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                handleClearTimeFilter();
              }}
              title="Clear time filter"
              aria-label="Clear time filter"
              className="ml-1 flex h-9 w-9 items-center justify-center rounded-md border border-border bg-surface text-text-subtle hover:text-danger hover:bg-danger-subtle hover:border-danger-border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <ComboboxPopover
          id={timePopupId}
          isOpen={timeDropdownOpen}
          onClose={() => setTimeDropdownOpen(false)}
          triggerRef={timeTriggerRef}
          ariaLabel="Filter sessions by time range"
          className="w-[336px] max-w-[340px] p-0 overflow-hidden shadow-2xl border-border bg-surface-raised rounded-2xl"
        >
          <div className="flex flex-col text-text">
            {/* Top Segmented Step Tabs */}
            <div className="p-2 border-b border-border/60 bg-surface-subtle/40">
              <div 
                className="relative isolate grid w-full grid-cols-2 gap-1 rounded-xl border border-border/60 bg-surface-subtle p-1 text-xs"
                role="tablist"
              >
                <div aria-hidden="true" className="pointer-events-none absolute inset-1 grid grid-cols-2 gap-1">
                  <motion.span
                    layout="position"
                    className="rounded-lg border border-border/50 bg-surface shadow-xs"
                    style={{ gridColumnStart: STEP_TAB_COLUMN[activeStep] }}
                    transition={
                      shouldReduceMotion
                        ? { duration: 0 }
                        : { duration: 0.28, ease: [0.4, 0, 0.2, 1] }
                    }
                  />
                </div>
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeStep === "date"}
                  onClick={() => handleStepChange("date")}
                  className={`relative z-10 h-8 flex items-center justify-center gap-1.5 rounded-lg text-xs font-sans transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus-ring ${
                    activeStep === "date"
                      ? "text-text font-semibold"
                      : "text-text-muted hover:text-text font-medium"
                  }`}
                >
                  <CalendarIcon className={`h-3.5 w-3.5 ${activeStep === "date" ? "text-primary" : "text-text-subtle"}`} />
                  <span>Date Range</span>
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeStep === "time"}
                  onClick={handleSwitchToTime}
                  className={`relative z-10 h-8 flex items-center justify-center gap-1.5 rounded-lg text-xs font-sans transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus-ring ${
                    activeStep === "time"
                      ? "text-text font-semibold"
                      : "text-text-muted hover:text-text font-medium"
                  }`}
                >
                  <Clock className={`h-3.5 w-3.5 ${activeStep === "time" ? "text-primary" : "text-text-subtle"}`} />
                  <span>Time Range</span>
                </button>
              </div>
            </div>

            <div className="relative overflow-hidden">
              <AnimatePresence initial={false} mode="popLayout" custom={stepDirection}>
                <motion.div
                  key={activeStep}
                  custom={stepDirection}
                  variants={STEP_CONTENT_VARIANTS}
                  initial="enter"
                  animate="center"
                  exit="exit"
                  transition={
                    shouldReduceMotion
                      ? { duration: 0 }
                      : { duration: 0.18, ease: [0.4, 0, 0.2, 1] }
                  }
                  className="flex flex-col w-full"
                >
                  {activeStep === "date" ? (
                    <div className="flex flex-col">
                      {/* Quick Presets row */}
                      <div className="grid grid-cols-5 gap-1.5 px-3 pt-3 pb-2">
                        {[
                          { key: "all", label: "All" },
                          { key: "today", label: "Today" },
                          { key: "yesterday", label: "Yesterday" },
                          { key: "24h", label: "24h" },
                          { key: "7d", label: "7d" },
                        ].map((p) => {
                          const isSelected = draftTimeRange === p.key;
                          return (
                            <button
                              key={p.key}
                              type="button"
                              onClick={() => handleSelectPreset(p.key as TimeRangeFilter)}
                              className={`h-7 flex items-center justify-center rounded-md text-[11px] font-sans transition-all cursor-pointer text-center tracking-tight ${
                                isSelected
                                  ? "bg-primary-subtle text-primary border border-primary/40 font-semibold shadow-2xs"
                                  : "bg-surface hover:bg-surface-hover text-text-muted hover:text-text border border-border/70 font-medium"
                              }`}
                            >
                              {p.label}
                            </button>
                          );
                        })}
                      </div>

                      {/* Calendar */}
                      <div className="px-1 py-0.5 flex justify-center">
                        <Calendar
                          mode="range"
                          captionLayout="dropdown-buttons"
                          fromYear={2020}
                          toYear={new Date().getFullYear()}
                          selected={
                            isSelecting && selectionStart
                              ? { from: selectionStart, to: undefined }
                              : draftRange
                          }
                          onSelect={handleCustomRangeSelect}
                          numberOfMonths={1}
                          className="pointer-events-auto"
                        />
                      </div>

                      {/* Selected Date Summary */}
                      <div className="px-3 py-1.5 flex items-center justify-center text-[11px] font-mono text-text-muted border-t border-border/40 bg-surface-subtle/30">
                        {draftTimeRange === "all" ? (
                          <span className="text-text-subtle">All time</span>
                        ) : draftRange?.from ? (
                          <span className="flex items-center gap-1.5">
                            <strong className="text-text font-semibold">{format(draftRange.from, "MMM d, yyyy")}</strong>
                            {draftRange.to && !isSameDay(draftRange.from, draftRange.to) && (
                              <>
                                <ArrowRight className="h-3 w-3 text-primary/70" />
                                <strong className="text-text font-semibold">{format(draftRange.to, "MMM d, yyyy")}</strong>
                              </>
                            )}
                          </span>
                        ) : (
                          <span className="text-text-subtle">Select a date</span>
                        )}
                      </div>
                    </div>
                  ) : (
                    /* Step 2: Time Range Precision View */
                    <div className="flex flex-col">
                      {/* Header info */}
                      <div className="flex items-center justify-between px-3.5 pt-2.5 pb-1">
                        <div className="flex items-center gap-1.5">
                          <CalendarIcon className="h-3.5 w-3.5 text-primary" />
                          <span className="flex items-center gap-1.5 text-xs font-mono font-semibold text-text">
                            {draftRange?.from ? (
                              <>
                                <span>{format(draftRange.from, "MMM d")}</span>
                                {draftRange.to && !isSameDay(draftRange.from, draftRange.to) && (
                                  <>
                                    <ArrowRight className="h-3 w-3 text-primary/70" />
                                    <span>{format(draftRange.to, "MMM d")}</span>
                                  </>
                                )}
                              </>
                            ) : (
                              <span>Today</span>
                            )}
                          </span>
                        </div>
                        {formatDuration(draftRange?.from, draftRange?.to) && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-surface-subtle border border-border/70 text-text-muted">
                            {formatDuration(draftRange?.from, draftRange?.to)}
                          </span>
                        )}
                      </div>

                      {/* Time Pickers (Stacked cleanly) */}
                      <div className="p-3 flex flex-col gap-2.5">
                        <TimePicker
                          label="Start Time"
                          variant="start"
                          date={draftRange?.from}
                          onChange={(newDate) => {
                            setHasCustomTime(true);
                            setDraftTimeRange("custom");
                            setDraftRange((prev) => ({
                              from: newDate,
                              to: prev?.to ?? newDate,
                            }));
                          }}
                        />
                        <TimePicker
                          label="End Time"
                          variant="end"
                          date={draftRange?.to ?? draftRange?.from}
                          onChange={(newDate) => {
                            setHasCustomTime(true);
                            setDraftTimeRange("custom");
                            setDraftRange((prev) => ({
                              from: prev?.from ?? newDate,
                              to: newDate,
                            }));
                          }}
                        />
                      </div>
                    </div>
                  )}
                </motion.div>
              </AnimatePresence>
            </div>

            {/* Unified Popover Footer: Cancel & Apply */}
            <div className="grid grid-cols-2 gap-2.5 p-3 bg-surface-subtle/50 border-t border-border/60">
              <button
                type="button"
                onClick={() => {
                  setTimeDropdownOpen(false);
                  timeTriggerRef.current?.focus();
                }}
                className="h-9 w-full flex items-center justify-center rounded-xl text-xs font-sans font-medium text-text-muted hover:text-text bg-surface hover:bg-surface-hover border border-border/80 shadow-2xs cursor-pointer transition-all active:scale-[0.98]"
              >
                Cancel
              </button>

              <button
                type="button"
                onClick={handleApplyTimeFilter}
                className="h-9 w-full flex items-center justify-center gap-1.5 rounded-xl text-xs font-sans font-semibold bg-primary-subtle text-primary border border-primary/40 hover:bg-primary-subtle/80 hover:text-primary-hover shadow-xs cursor-pointer transition-all active:scale-[0.98]"
              >
                <Check className="h-4 w-4" />
                <span>Apply</span>
              </button>
            </div>
          </div>
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
              className="ml-1 flex h-9 w-9 items-center justify-center rounded-md border border-border bg-surface text-text-subtle hover:text-danger hover:bg-danger-subtle hover:border-danger-border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger"
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
            className="flex min-w-14 items-center justify-center gap-1 border-l border-border px-2 font-sans text-xs text-text-muted transition-colors hover:bg-danger-subtle hover:text-danger focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-danger"
          >
            <RotateCcw className="h-3 w-3" />
            <span>Reset</span>
          </button>
        </div>
      )}
    </div>
  );
}
