"use client";

import { useEffect, useRef, useState } from "react";
import { CalendarDays, Check, ChevronDown, Clock, X } from "lucide-react";
import { format } from "date-fns";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import type { DateRange } from "react-day-picker";

import { Calendar } from "@/components/filesystem/Calendar";
import { TimePicker } from "@/components/filesystem/TimePicker";

export type HardwareHistoryPreset = "1h" | "6h" | "24h" | "7d" | "30d";
export type HardwareHistoryRange = HardwareHistoryPreset | "custom";

export interface HardwareHistoryCustomRange {
  from: Date;
  to: Date;
}

interface HardwareHistoryRangePickerProps {
  range: HardwareHistoryRange;
  customRange: HardwareHistoryCustomRange | null;
  loading: boolean;
  onPresetChange: (range: HardwareHistoryPreset) => void;
  onCustomApply: (range: HardwareHistoryCustomRange) => void;
}

const PRESETS: { value: HardwareHistoryPreset; label: string }[] = [
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
];

const MAX_CUSTOM_RANGE_MS = 30 * 24 * 60 * 60 * 1_000;

function cloneRange(range: HardwareHistoryCustomRange): HardwareHistoryCustomRange {
  return { from: new Date(range.from), to: new Date(range.to) };
}

function defaultRange(): HardwareHistoryCustomRange {
  const to = new Date();
  to.setSeconds(0, 0);
  return { from: new Date(to.getTime() - 24 * 60 * 60 * 1_000), to };
}

function presetRange(preset: HardwareHistoryPreset): HardwareHistoryCustomRange {
  const hours = { "1h": 1, "6h": 6, "24h": 24, "7d": 24 * 7, "30d": 24 * 30 }[preset];
  const to = new Date();
  to.setSeconds(0, 0);
  return { from: new Date(to.getTime() - hours * 60 * 60 * 1_000), to };
}

function withTime(day: Date, source: Date | undefined, fallbackHour: number, fallbackMinute: number) {
  const result = new Date(day);
  result.setHours(source?.getHours() ?? fallbackHour, source?.getMinutes() ?? fallbackMinute, 0, 0);
  return result;
}

function validateRange(range: Partial<HardwareHistoryCustomRange> | undefined): string | null {
  if (!range?.from || !range.to) return "Select a start and end date.";
  if (range.to.getTime() <= range.from.getTime()) return "End time must be after start time.";
  if (range.to.getTime() - range.from.getTime() > MAX_CUSTOM_RANGE_MS) return "Custom range is limited to 30 days.";
  if (range.to.getTime() > Date.now()) return "End time cannot be in the future.";
  return null;
}

export function HardwareHistoryRangePicker({
  range,
  customRange,
  loading,
  onPresetChange,
  onCustomApply,
}: HardwareHistoryRangePickerProps) {
  const rootRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [draftRange, setDraftRange] = useState<Partial<HardwareHistoryCustomRange> | undefined>();
  const shouldReduceMotion = useReducedMotion();

  useEffect(() => {
    if (!open) return;
    const closeOnOutside = (event: PointerEvent) => {
      if (event.target instanceof Node && !rootRef.current?.contains(event.target)) setOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", closeOnOutside);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutside);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [open]);

  const openCustomPicker = () => {
    if (open) {
      setOpen(false);
      return;
    }
    if (customRange && range === "custom") {
      setDraftRange(cloneRange(customRange));
    } else {
      setDraftRange(range === "custom" ? defaultRange() : presetRange(range));
    }
    setOpen(true);
  };

  const handleDateSelect = (selected: DateRange | undefined) => {
    if (!selected?.from) {
      setDraftRange(undefined);
      return;
    }
    const from = withTime(selected.from, draftRange?.from, 0, 0);
    const to = selected.to
      ? withTime(selected.to, draftRange?.to, 23, 59)
      : undefined;
    setDraftRange({ from, to });
  };

  const handleApply = () => {
    const error = validateRange(draftRange);
    if (error || !draftRange?.from || !draftRange.to) return;
    onCustomApply(cloneRange({ from: draftRange.from, to: draftRange.to }));
    setOpen(false);
  };

  const validationError = validateRange(draftRange);
  const customLabel = customRange
    ? `${format(customRange.from, "MMM d, HH:mm")} → ${format(customRange.to, "MMM d, HH:mm")}`
    : "Custom";

  return (
    <div ref={rootRef} className="relative flex items-center gap-1 rounded-md border border-border bg-surface-subtle p-1" role="group" aria-label="Hardware history range">
      {PRESETS.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={range === option.value}
          onClick={() => {
            setOpen(false);
            onPresetChange(option.value);
          }}
          disabled={loading}
          className={`min-h-8 rounded px-2 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring disabled:cursor-not-allowed disabled:opacity-50 ${range === option.value ? "bg-primary-subtle text-primary" : "text-text-muted hover:bg-surface-hover hover:text-text"}`}
        >
          {option.label}
        </button>
      ))}
      <button
        type="button"
        aria-pressed={range === "custom"}
        aria-expanded={open}
        onClick={openCustomPicker}
        disabled={loading}
        className={`flex min-h-8 items-center gap-1 rounded px-2 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring disabled:cursor-not-allowed disabled:opacity-50 ${range === "custom" || open ? "bg-primary-subtle text-primary" : "text-text-muted hover:bg-surface-hover hover:text-text"}`}
        title={range === "custom" ? customLabel : "Choose a custom date and time range"}
      >
        <CalendarDays className="h-3.5 w-3.5" aria-hidden="true" />
        <span>Custom</span>
        <ChevronDown className={`h-3 w-3 transition-transform ${open ? "rotate-180" : ""}`} aria-hidden="true" />
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -6, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.98 }}
            transition={shouldReduceMotion ? { duration: 0 } : { duration: 0.18, ease: [0.4, 0, 0.2, 1] }}
            className="absolute right-0 top-[calc(100%+8px)] z-[80] flex max-h-[calc(100vh-1rem)] w-[min(94vw,368px)] flex-col overflow-hidden rounded-xl border border-border bg-surface-raised shadow-[var(--shadow-raised)]"
          >
            <div className="min-h-0 overflow-y-auto overscroll-contain">
              <div className="flex items-center justify-between border-b border-border/60 px-3 py-2.5">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-xs font-semibold text-text">
                    <CalendarDays className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden="true" />
                    Custom range
                  </div>
                  <p className="mt-0.5 truncate text-[10px] text-text-subtle">Up to 30 days of retained history · local time</p>
                </div>
                <button type="button" onClick={() => setOpen(false)} className="rounded-md p-1 text-text-subtle hover:bg-surface-hover hover:text-text" aria-label="Close custom history range">
                  <X className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>

              <div className="w-full px-3 pb-2 pt-1">
                <Calendar
                  mode="range"
                  captionLayout="dropdown-buttons"
                  fromYear={2020}
                  toYear={new Date().getFullYear()}
                  selected={draftRange ? { from: draftRange.from, to: draftRange.to } : undefined}
                  onSelect={handleDateSelect}
                  disabled={{ after: new Date() }}
                  numberOfMonths={1}
                  className="!w-full !p-0"
                  classNames={{
                    months: "flex w-full flex-col",
                    month: "w-full space-y-2",
                    caption: "relative mb-1 flex h-7 w-full items-center justify-center",
                    caption_dropdowns: "relative z-10 flex h-full items-center justify-center gap-1",
                    nav_button: "h-7 w-7 rounded-md border border-border/50 bg-surface-subtle/40 p-0 text-text-subtle hover:border-border-strong hover:bg-surface-hover hover:text-text",
                    table: "w-full border-collapse",
                    head_row: "flex w-full justify-between",
                    head_cell: "flex-1 text-center font-mono text-[10px] font-semibold uppercase text-text-subtle",
                    row: "mt-0.5 flex w-full justify-between",
                    cell: "relative h-8 flex-1 p-0 text-center",
                    // Let range modifiers fill the entire cell so adjacent days form one continuous band.
                    day: "mx-0 h-8 w-full rounded-md p-0 font-mono text-[11px] text-text hover:bg-surface-hover hover:text-text",
                  }}
                />
              </div>

              <div className="border-t border-border/60 px-3 pb-3 pt-2">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-text-subtle">
                    <Clock className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
                    Time precision
                  </div>
                  <span className="text-[10px] text-text-subtle">24-hour clock</span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <TimePicker
                    label="Start"
                    variant="start"
                    compact
                    date={draftRange?.from}
                    onChange={(date) => setDraftRange((current) => ({ from: date, to: current?.to ?? date }))}
                  />
                  <TimePicker
                    label="End"
                    variant="end"
                    compact
                    date={draftRange?.to ?? draftRange?.from}
                    onChange={(date) => setDraftRange((current) => ({ from: current?.from ?? date, to: date }))}
                  />
                </div>
                {validationError && <p className="mt-2 text-[11px] text-warning">{validationError}</p>}
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-border/60 bg-surface-subtle/50 px-3 py-2.5">
              <button type="button" onClick={() => setOpen(false)} className="ui-button min-h-8 px-3 text-xs">
                Cancel
              </button>
              <button type="button" onClick={handleApply} disabled={Boolean(validationError)} className="ui-button min-h-8 gap-1.5 border-primary-border bg-primary-subtle px-3 text-xs text-primary disabled:cursor-not-allowed disabled:opacity-50">
                <Check className="h-3.5 w-3.5" aria-hidden="true" />
                Apply range
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
