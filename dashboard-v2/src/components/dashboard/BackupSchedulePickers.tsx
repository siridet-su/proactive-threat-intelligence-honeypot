"use client";

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { CalendarDays, ChevronDown, ChevronLeft, ChevronRight } from "lucide-react";

const popoverMotion = {
  initial: { opacity: 0, y: -6, scale: 0.98 },
  animate: { opacity: 1, y: 0, scale: 1 },
  exit: { opacity: 0, y: -4, scale: 0.98 },
};

function useOutsideClose(open: boolean, close: () => void, root: React.RefObject<HTMLDivElement | null>) {
  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: PointerEvent) {
      if (event.target instanceof Node && !root.current?.contains(event.target)) close();
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") close();
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open, close, root]);
}

export function ScheduleNumberPicker({ label, value, values, onChange, disabled }: {
  label: string;
  value: string;
  values: string[];
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  const root = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const reducedMotion = useReducedMotion();
  useOutsideClose(open, () => setOpen(false), root);

  function handleKeyDown(event: React.KeyboardEvent<HTMLButtonElement>) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      const next = Math.min(values.length - 1, Math.max(0, values.indexOf(value) + step));
      onChange(values[next]);
      setOpen(true);
    } else if (event.key === "Escape") {
      setOpen(false);
    }
  }

  return <div ref={root} className="relative min-w-0 flex-1">
    <span className="text-xs text-text-muted">{label}</span>
    <button type="button" disabled={disabled} aria-label={`${label}: ${value}`} aria-haspopup="listbox" aria-expanded={open}
      onClick={() => setOpen((current) => !current)} onKeyDown={handleKeyDown}
      className="ui-field mt-1 flex cursor-pointer items-center justify-between font-mono text-base font-semibold disabled:cursor-not-allowed disabled:opacity-60">
      <span>{value}</span><ChevronDown className={`h-4 w-4 text-text-muted transition-transform duration-150 ${open ? "rotate-180" : ""}`} aria-hidden="true" />
    </button>
    <AnimatePresence initial={false}>
      {open && !disabled && <motion.div {...popoverMotion} transition={reducedMotion ? { duration: 0 } : { duration: 0.16 }}
        role="listbox" aria-label={label}
        className="absolute left-0 right-0 top-[calc(100%+4px)] z-50 max-h-52 overflow-y-auto overscroll-contain rounded-lg border border-border bg-surface-raised p-1 shadow-[var(--shadow-raised)]">
        {values.map((option) => <button key={option} type="button" role="option" aria-selected={option === value}
          onClick={() => { onChange(option); setOpen(false); }}
          className={`flex w-full rounded-md px-3 py-1.5 text-left font-mono text-sm transition-colors ${option === value ? "bg-primary-subtle font-semibold text-primary" : "text-text hover:bg-surface-hover"}`}>{option}</button>)}
      </motion.div>}
    </AnimatePresence>
  </div>;
}

const DAY_MS = 86_400_000;
const PAGE_DAYS = 35;
const WEEKDAYS = ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"];

function utcDay(day: string): Date {
  return new Date(`${day}T00:00:00Z`);
}

function dateLabel(date: Date): string {
  return date.toLocaleDateString("en-GB", { timeZone: "UTC", day: "numeric", month: "short", year: "numeric" });
}

export function ScheduleRangePicker({ startDate, durationDays, today, onChange, disabled }: {
  startDate: string;
  durationDays: number;
  today: string;
  onChange: (startDate: string, durationDays: number) => void;
  disabled: boolean;
}) {
  const root = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [page, setPage] = useState(0);
  const [draftStart, setDraftStart] = useState(startDate || today);
  const [draftEnd, setDraftEnd] = useState<string | null>(null);
  const [choosingEnd, setChoosingEnd] = useState(false);
  const [hoveredDay, setHoveredDay] = useState<string | null>(null);
  const reducedMotion = useReducedMotion();
  useOutsideClose(open, () => setOpen(false), root);
  const todayDate = utcDay(today);
  const lastStartDate = new Date(todayDate.getTime() + 365 * DAY_MS);
  const weekStart = todayDate.getTime() - todayDate.getUTCDay() * DAY_MS;
  const selectedPage = startDate ? Math.max(0, Math.floor((utcDay(startDate).getTime() - weekStart) / (PAGE_DAYS * DAY_MS))) : 0;
  const pageStart = weekStart + page * PAGE_DAYS * DAY_MS;
  const days = Array.from({ length: PAGE_DAYS }, (_, index) => new Date(pageStart + index * DAY_MS));
  const lastDay = days[PAGE_DAYS - 1];
  const savedEnd = new Date(utcDay(startDate || today).getTime() + (durationDays - 1) * DAY_MS);
  const label = `${dateLabel(utcDay(startDate || today))} – ${dateLabel(savedEnd)}`;
  const lastEndDate = new Date(utcDay(draftStart).getTime() + 89 * DAY_MS);
  const navigationLimit = choosingEnd ? lastEndDate : new Date(Math.max(lastStartDate.getTime(), savedEnd.getTime()));
  const endPreview = choosingEnd ? hoveredDay && hoveredDay >= draftStart && utcDay(hoveredDay) <= lastEndDate ? hoveredDay : draftStart : draftEnd;

  function openPicker() {
    if (open) { setOpen(false); return; }
    setDraftStart(startDate || today);
    setDraftEnd(savedEnd.toISOString().slice(0, 10));
    setChoosingEnd(false);
    setHoveredDay(null);
    setPage(selectedPage);
    setOpen(true);
  }

  function selectDay(day: string) {
    if (!choosingEnd || day < draftStart) {
      setDraftStart(day);
      setDraftEnd(null);
      setChoosingEnd(true);
      setHoveredDay(null);
      return;
    }
    const selectedDays = Math.round((utcDay(day).getTime() - utcDay(draftStart).getTime()) / DAY_MS) + 1;
    if (selectedDays < 1 || selectedDays > 90) return;
    onChange(draftStart, selectedDays);
    setOpen(false);
  }

  function quickDuration(selectedDays: number) {
    onChange(draftStart, selectedDays);
    setOpen(false);
  }

  return <div ref={root} className="relative min-w-0">
    <span className="text-xs text-text-muted">Date range · first and last backup day</span>
    <button type="button" disabled={disabled} aria-label={`Backup date range: ${label}, ${durationDays} days`} aria-haspopup="dialog" aria-expanded={open}
      onClick={openPicker}
      className="ui-field mt-1 flex cursor-pointer items-center justify-between text-left disabled:cursor-not-allowed disabled:opacity-60">
      <span className="truncate">{label} <span className="text-text-muted">· {durationDays} day{durationDays === 1 ? "" : "s"}</span></span><CalendarDays className="ml-2 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
    </button>
    <AnimatePresence initial={false}>
      {open && !disabled && <motion.div {...popoverMotion} transition={reducedMotion ? { duration: 0 } : { duration: 0.18 }}
        role="dialog" aria-label="Choose backup date range"
        className="absolute left-0 top-[calc(100%+6px)] z-50 w-[min(92vw,336px)] rounded-xl border border-border bg-surface-raised p-3 shadow-[var(--shadow-raised)]">
        <div className="flex items-center justify-between gap-2">
          <button type="button" disabled={page === 0} onClick={() => setPage((current) => current - 1)} aria-label="Previous five weeks"
            className="grid h-8 w-8 place-items-center rounded-md border border-border text-text-muted hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-35"><ChevronLeft className="h-4 w-4" aria-hidden="true" /></button>
          <div className="text-center"><p className="text-xs font-semibold text-text">{choosingEnd ? "Choose last backup day" : "Choose first backup day"}</p><p className="mt-0.5 text-[11px] text-text-muted">{dateLabel(days[0])} – {dateLabel(lastDay)}</p></div>
          <button type="button" disabled={lastDay >= navigationLimit} onClick={() => setPage((current) => current + 1)} aria-label="Next five weeks"
            className="grid h-8 w-8 place-items-center rounded-md border border-border text-text-muted hover:bg-surface-hover disabled:cursor-not-allowed disabled:opacity-35"><ChevronRight className="h-4 w-4" aria-hidden="true" /></button>
        </div>
        <div className="mt-3 grid grid-cols-7 gap-1 text-center text-[10px] font-semibold uppercase tracking-wide text-text-muted" aria-hidden="true">
          {WEEKDAYS.map((weekday) => <span key={weekday}>{weekday}</span>)}
        </div>
        <AnimatePresence initial={false} mode="wait">
          <motion.div key={page} initial={{ opacity: 0, x: reducedMotion ? 0 : 8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: reducedMotion ? 0 : -8 }} transition={reducedMotion ? { duration: 0 } : { duration: 0.14 }} className="mt-1 grid grid-cols-7 gap-1">
            {days.map((date) => {
              const day = date.toISOString().slice(0, 10);
              const unavailable = date < todayDate || date > (choosingEnd ? lastEndDate : lastStartDate);
              const boundary = day === draftStart || day === endPreview;
              const inRange = endPreview && day > draftStart && day < endPreview;
              return <button key={day} type="button" disabled={unavailable} aria-label={dateLabel(date)} aria-pressed={Boolean(boundary || inRange)} aria-current={day === today ? "date" : undefined}
                onMouseEnter={() => setHoveredDay(day)} onFocus={() => setHoveredDay(day)} onClick={() => selectDay(day)}
                className={`h-9 rounded-md text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${boundary ? "bg-primary font-semibold text-on-primary" : inRange ? "bg-primary-subtle text-primary" : unavailable ? "cursor-not-allowed bg-surface-subtle text-text-muted opacity-65" : day === today ? "border border-primary-border bg-primary-subtle text-primary hover:bg-surface-hover" : "text-text hover:bg-surface-hover"}`}>
                {date.getUTCDate()}
              </button>;
            })}
          </motion.div>
        </AnimatePresence>
        <div className="mt-3 border-t border-border pt-3">
          <p className="text-[11px] text-text-muted">{choosingEnd ? `Start: ${dateLabel(utcDay(draftStart))} · select the last day (90 days max)` : "Click a start date, then the last day. Both dates are included."}</p>
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[10px] text-text-muted">From {dateLabel(utcDay(draftStart))}</span>
            {[1, 7, 30].map((quickDays) => <button key={quickDays} type="button" onClick={() => quickDuration(quickDays)} className="rounded-md border border-border px-2 py-1 text-xs text-text hover:border-primary-border hover:bg-primary-subtle">{quickDays} day{quickDays === 1 ? "" : "s"}</button>)}
          </div>
        </div>
      </motion.div>}
    </AnimatePresence>
  </div>;
}
