"use client";

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { CalendarDays, ChevronDown } from "lucide-react";

import { Calendar } from "@/components/filesystem/Calendar";

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

function dateFromLocalDay(day: string): Date {
  const [year, month, date] = day.split("-").map(Number);
  return new Date(year, month - 1, date);
}

function localDayFromDate(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

export function ScheduleDatePicker({ value, today, onChange, disabled }: {
  value: string;
  today: string;
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  const root = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const reducedMotion = useReducedMotion();
  useOutsideClose(open, () => setOpen(false), root);
  const minDate = dateFromLocalDay(today);
  const maxDate = new Date(minDate.getFullYear(), minDate.getMonth(), minDate.getDate() + 365);
  const selectedDate = value ? dateFromLocalDay(value) : undefined;
  const label = selectedDate ? selectedDate.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" }) : "Select start date";

  return <div ref={root} className="relative min-w-0">
    <span className="text-xs text-text-muted">Start date</span>
    <button type="button" disabled={disabled} aria-label={`Start date: ${label}`} aria-haspopup="dialog" aria-expanded={open}
      onClick={() => setOpen((current) => !current)}
      className="ui-field mt-1 flex cursor-pointer items-center justify-between text-left disabled:cursor-not-allowed disabled:opacity-60">
      <span>{label}</span><CalendarDays className="h-4 w-4 text-primary" aria-hidden="true" />
    </button>
    <AnimatePresence initial={false}>
      {open && !disabled && <motion.div {...popoverMotion} transition={reducedMotion ? { duration: 0 } : { duration: 0.18 }}
        role="dialog" aria-label="Choose backup start date"
        className="absolute left-0 top-[calc(100%+6px)] z-50 w-[min(92vw,320px)] rounded-xl border border-border bg-surface-raised p-2 shadow-[var(--shadow-raised)]">
        <Calendar mode="single" selected={selectedDate} defaultMonth={selectedDate ?? minDate}
          fromDate={minDate} toDate={maxDate} disabled={{ before: minDate, after: maxDate }}
          onSelect={(date) => { if (date) { onChange(localDayFromDate(date)); setOpen(false); } }}
          className="!p-1" classNames={{ day_selected: "!bg-primary !text-on-primary font-semibold rounded-md" }} />
      </motion.div>}
    </AnimatePresence>
  </div>;
}
