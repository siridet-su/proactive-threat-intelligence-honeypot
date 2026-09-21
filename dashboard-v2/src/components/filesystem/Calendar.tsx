"use client";

import * as React from "react";
import { ChevronDown, ChevronLeft, ChevronRight } from "lucide-react";
import { DayPicker } from "react-day-picker";
import { isSameDay, isAfter, isBefore, startOfDay } from "date-fns";
import { motion, AnimatePresence } from "framer-motion";

export type CalendarProps = React.ComponentProps<typeof DayPicker>;

function CalendarSelectMenu({ value, options, onChange }: { value: string, options: {value: string; label: string}[], onChange: (val: string) => void }) {
  const root = React.useRef<HTMLDivElement>(null);
  const [open, setOpen] = React.useState(false);
  const selectedOption = options.find((o) => o.value === value);

  React.useEffect(() => {
    const closeOnOutside = (e: PointerEvent) => {
      if (e.target instanceof Node && !root.current?.contains(e.target)) setOpen(false);
    };
    document.addEventListener("pointerdown", closeOnOutside);
    return () => document.removeEventListener("pointerdown", closeOnOutside);
  }, []);

  return (
    <div ref={root} className="relative z-50">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={`h-7 px-2.5 flex items-center gap-1.5 rounded-md border transition-all font-mono text-[11px] font-semibold ${
          open
            ? "border-primary ring-2 ring-primary/20 bg-surface text-text shadow-sm"
            : "border-border/40 bg-surface-subtle/40 hover:bg-surface-hover hover:border-border/60 text-text"
        }`}
      >
        <span>{selectedOption?.label ?? value}</span>
        <ChevronDown className={`h-3 w-3 transition-transform duration-150 ${open ? "rotate-180 text-primary" : "text-text-subtle"}`} />
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -4, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.98 }}
            transition={{ duration: 0.15, ease: "easeOut" }}
            className="absolute top-[calc(100%+4px)] left-1/2 -translate-x-1/2 w-32 max-h-56 overflow-y-auto overscroll-contain rounded-lg border border-border bg-surface-raised p-1 shadow-2xl flex flex-col z-[60]"
          >
            {options.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => {
                  onChange(opt.value);
                  setOpen(false);
                }}
                className={`text-left px-2.5 py-1.5 rounded-md text-[11px] font-mono transition-colors ${
                  opt.value === value
                    ? "bg-primary-subtle text-primary border border-primary/40 font-semibold shadow-2xs"
                    : "text-text-muted hover:bg-surface-hover hover:text-text border border-transparent"
                }`}
              >
                {opt.label}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

import { DropdownProps } from "react-day-picker";

const CalendarIconLeft = () => <ChevronLeft className="h-3.5 w-3.5" />;
const CalendarIconRight = () => <ChevronRight className="h-3.5 w-3.5" />;
const CalendarCustomDropdown = ({ value, onChange, children }: DropdownProps) => {
  const options: { value: string; label: string }[] = [];
  React.Children.forEach(children, (child: React.ReactNode) => {
    if (React.isValidElement<any>(child) && (child as React.ReactElement<any>).props.value !== undefined) {
      options.push({
        value: String((child as React.ReactElement<any>).props.value),
        label: String((child as React.ReactElement<any>).props.children),
      });
    }
  });

  return (
    <CalendarSelectMenu
      value={String(value)}
      options={options}
      onChange={(newVal: string) => {
        if (onChange) onChange({ target: { value: newVal } } as unknown as React.ChangeEvent<HTMLSelectElement>);
      }}
    />
  );
};

function Calendar({
  className,
  classNames,
  showOutsideDays = true,
  ...props
}: CalendarProps) {
  const [hoveredDate, setHoveredDate] = React.useState<Date | null>(null);

  // Extract selection if in range mode
  const selectedRange =
    props.mode === "range"
      ? (props.selected as { from?: Date; to?: Date } | undefined)
      : undefined;

  return (
    <DayPicker
      onDayMouseEnter={(day) => setHoveredDate(day)}
      onDayMouseLeave={() => setHoveredDate(null)}
      modifiers={{
        range_start: (day) => {
          if (props.mode === "range" && selectedRange?.from) {
            return isSameDay(day, selectedRange.from);
          }
          return false;
        },
        range_end: (day) => {
          if (props.mode === "range" && selectedRange?.to) {
            return isSameDay(day, selectedRange.to);
          }
          return false;
        },
        range_middle: (day) => {
          if (props.mode === "range" && selectedRange?.from && selectedRange?.to) {
            if (!isSameDay(selectedRange.from, selectedRange.to)) {
              const start = startOfDay(isBefore(selectedRange.from, selectedRange.to)
                ? selectedRange.from
                : selectedRange.to);
              const end = startOfDay(isBefore(selectedRange.from, selectedRange.to)
                ? selectedRange.to
                : selectedRange.from);
              return isAfter(day, start) && isBefore(day, end);
            }
          }
          return false;
        },
        range_hover: (day) => {
          if (props.mode === "range" && selectedRange?.from && !selectedRange?.to && hoveredDate) {
            const startDay = startOfDay(selectedRange.from);
            const hoverDay = startOfDay(hoveredDate);
            if (isAfter(day, startDay) && isBefore(day, hoverDay)) return true;
            if (isBefore(day, startDay) && isAfter(day, hoverDay)) return true;
          }
          return false;
        },
        range_hover_start: (day) => {
          if (props.mode === "range" && selectedRange?.from && !selectedRange?.to && hoveredDate) {
            if (isBefore(hoveredDate, selectedRange.from)) {
              return isSameDay(day, hoveredDate);
            }
          }
          return false;
        },
        range_hover_end: (day) => {
          if (props.mode === "range" && selectedRange?.from && !selectedRange?.to && hoveredDate) {
            if (isAfter(hoveredDate, selectedRange.from)) {
              return isSameDay(day, hoveredDate);
            }
          }
          return false;
        },
        range_preview_anchor_end: (day) => {
          if (props.mode === "range" && selectedRange?.from && !selectedRange?.to && hoveredDate) {
            if (isBefore(hoveredDate, selectedRange.from)) {
              return isSameDay(day, selectedRange.from);
            }
          }
          return false;
        },
        range_single: (day) => {
          if (props.mode === "range" && selectedRange?.from) {
            if (selectedRange.to) {
              if (isSameDay(selectedRange.from, selectedRange.to)) {
                return isSameDay(day, selectedRange.from);
              }
            } else {
              // Selection in progress: if not hovering another day, show as solid single-day pill
              if (!hoveredDate || isSameDay(hoveredDate, selectedRange.from)) {
                return isSameDay(day, selectedRange.from);
              }
            }
          }
          return false;
        },
      }}
      modifiersClassNames={{
        range_start:
          "!bg-primary !text-on-primary font-semibold hover:!bg-primary-action hover:!text-on-primary !rounded-l-md !rounded-r-none shadow-2xs",
        range_end:
          "!bg-primary !text-on-primary font-semibold hover:!bg-primary-action hover:!text-on-primary !rounded-r-md !rounded-l-none shadow-2xs",
        range_middle:
          "!bg-primary/15 !text-primary font-medium !rounded-none hover:!bg-primary/25",
        range_hover: "!bg-primary/15 !text-primary !rounded-none",
        range_hover_start: "!bg-primary/30 !text-primary font-semibold !rounded-l-md !rounded-r-none",
        range_hover_end: "!bg-primary/30 !text-primary font-semibold !rounded-r-md !rounded-l-none",
        range_preview_anchor_end: "!bg-primary !text-on-primary font-semibold !rounded-r-md !rounded-l-none",
        range_single:
          "!rounded-md !bg-primary !text-on-primary font-semibold hover:!bg-primary-action hover:!text-on-primary shadow-2xs",
      }}
      showOutsideDays={showOutsideDays}
      className={`p-2.5 ${className ?? ""}`}
      classNames={{
        months: "flex flex-col sm:flex-row space-y-3 sm:space-x-3 sm:space-y-0",
        month: "space-y-3",
        caption: "flex justify-center relative items-center h-7 mb-3",
        caption_label: "caption-label-text text-xs font-mono font-semibold text-text group-hover:text-primary tracking-wide uppercase transition-colors",
        caption_dropdowns: "flex justify-center gap-1.5 relative items-center h-full z-10 [&_.caption-label-text]:hidden",
        dropdown_month: "relative flex items-center group h-full",
        dropdown_year: "relative flex items-center group h-full",
        dropdown: "hidden", // We use SelectMenu now, so native select can be completely hidden just in case
        dropdown_icon: "hidden",
        nav: "space-x-1 flex items-center z-0",
        nav_button:
          "h-7 w-7 bg-surface-subtle/40 p-0 text-text-subtle hover:text-text hover:bg-surface-hover flex justify-center items-center rounded-md border border-border/40 hover:border-border/60 transition-colors cursor-pointer",
        nav_button_previous: "absolute left-0 top-1/2 -translate-y-1/2",
        nav_button_next: "absolute right-0 top-1/2 -translate-y-1/2",
        table: "w-full border-collapse space-y-1",
        head_row: "flex justify-between",
        head_cell: "text-text-subtle w-8 sm:w-8.5 font-mono text-[10px] uppercase font-semibold text-center select-none",
        row: "flex w-full mt-1 justify-between",
        cell: "h-8 w-8 sm:h-8.5 sm:w-8.5 text-center text-xs p-0 relative focus-within:relative focus-within:z-20",
        day: "h-8 w-8 sm:h-8.5 sm:w-8.5 p-0 font-mono text-xs font-normal text-text hover:bg-surface-hover hover:text-text rounded-md flex justify-center items-center cursor-pointer transition-colors select-none",
        day_selected:
          "font-semibold focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-focus-ring shadow-2xs",
        day_range_start:
          "day-range-start !rounded-l-md !rounded-r-none !bg-primary !text-on-primary font-bold hover:!bg-primary-action hover:!text-on-primary",
        day_range_middle:
          "!bg-primary/15 !text-text font-medium !rounded-none hover:!bg-primary/25",
        day_range_end:
          "day-range-end !rounded-r-md !rounded-l-none !bg-primary !text-on-primary font-bold hover:!bg-primary-action hover:!text-on-primary",
        day_today:
          "font-semibold text-primary relative after:content-[''] after:absolute after:bottom-0.5 after:left-1/2 after:-translate-x-1/2 after:h-1 after:w-1 after:rounded-full after:bg-primary aria-selected:after:hidden aria-selected:text-inherit",
        day_outside: "text-text-subtle/40 opacity-40 hover:opacity-80",
        day_disabled: "text-text-subtle/30 opacity-30 cursor-not-allowed hover:bg-transparent",
        day_hidden: "invisible",
        vhidden: "sr-only",
        ...classNames,
      }}
      components={{
        IconLeft: CalendarIconLeft,
        IconRight: CalendarIconRight,
        Dropdown: CalendarCustomDropdown,
      }}
      {...props}
    />
  );
}
Calendar.displayName = "Calendar";

export { Calendar };
