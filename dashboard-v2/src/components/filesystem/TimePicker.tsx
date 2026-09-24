"use client";

import * as React from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import { isSameDay } from "date-fns";

export interface TimePickerProps {
  date?: Date;
  onChange: (date: Date) => void;
  label: string;
  variant?: "start" | "end";
  compact?: boolean;
}

export function TimePicker({ date, onChange, label, variant = "start", compact = false }: TimePickerProps) {
  const hourInputRef = React.useRef<HTMLInputElement>(null);
  const minuteInputRef = React.useRef<HTMLInputElement>(null);

  const selectedHour = date ? date.getHours() : 0;
  const selectedMinute = date ? date.getMinutes() : 0;

  const [isEditingHour, setIsEditingHour] = React.useState(false);
  const [hourInputVal, setHourInputVal] = React.useState("");

  const [isEditingMinute, setIsEditingMinute] = React.useState(false);
  const [minuteInputVal, setMinuteInputVal] = React.useState("");

  const displayHour = isEditingHour ? hourInputVal : selectedHour.toString().padStart(2, "0");
  const displayMinute = isEditingMinute ? minuteInputVal : selectedMinute.toString().padStart(2, "0");

  const commitTime = React.useCallback(
    (newHour: number, newMinute: number) => {
      const base = date ? new Date(date) : new Date();
      const clampedH = Math.max(0, Math.min(23, Math.floor(newHour)));
      const clampedM = Math.max(0, Math.min(59, Math.floor(newMinute)));
      base.setHours(clampedH, clampedM, 0, 0);
      onChange(base);
    },
    [date, onChange],
  );

  const handleHourFocus = (e: React.FocusEvent<HTMLInputElement>) => {
    setIsEditingHour(true);
    setHourInputVal(selectedHour.toString().padStart(2, "0"));
    e.currentTarget.select();
  };

  const handleHourChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value.replace(/\D/g, "").slice(0, 2);
    setHourInputVal(val);
    if (val.length === 2) {
      const num = parseInt(val, 10);
      if (!Number.isNaN(num) && num >= 0 && num <= 23) {
        commitTime(num, selectedMinute);
        setIsEditingHour(false);
        minuteInputRef.current?.focus();
        minuteInputRef.current?.select();
      }
    }
  };

  const handleHourBlur = () => {
    setIsEditingHour(false);
    const num = parseInt(hourInputVal, 10);
    if (!Number.isNaN(num)) {
      const clamped = Math.max(0, Math.min(23, num));
      commitTime(clamped, selectedMinute);
    }
  };

  const handleMinuteFocus = (e: React.FocusEvent<HTMLInputElement>) => {
    setIsEditingMinute(true);
    setMinuteInputVal(selectedMinute.toString().padStart(2, "0"));
    e.currentTarget.select();
  };

  const handleMinuteChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value.replace(/\D/g, "").slice(0, 2);
    setMinuteInputVal(val);
    if (val.length === 2) {
      const num = parseInt(val, 10);
      if (!Number.isNaN(num) && num >= 0 && num <= 59) {
        commitTime(selectedHour, num);
        setIsEditingMinute(false);
      }
    }
  };

  const handleMinuteBlur = () => {
    setIsEditingMinute(false);
    const num = parseInt(minuteInputVal, 10);
    if (!Number.isNaN(num)) {
      const clamped = Math.max(0, Math.min(59, num));
      commitTime(selectedHour, clamped);
    }
  };

  const stepHour = (delta: number) => {
    const nextH = (selectedHour + delta + 24) % 24;
    commitTime(nextH, selectedMinute);
  };

  const stepMinute = (delta: number) => {
    const nextM = (selectedMinute + delta + 60) % 60;
    commitTime(selectedHour, nextM);
  };

  const handleHourKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      stepHour(1);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      stepHour(-1);
    } else if (e.key === "ArrowRight" && e.currentTarget.selectionStart === e.currentTarget.value.length) {
      minuteInputRef.current?.focus();
      minuteInputRef.current?.select();
    }
  };

  const handleMinuteKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      stepMinute(1);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      stepMinute(-1);
    } else if (e.key === "PageUp") {
      e.preventDefault();
      stepMinute(5);
    } else if (e.key === "PageDown") {
      e.preventDefault();
      stepMinute(-5);
    } else if (e.key === "ArrowLeft" && e.currentTarget.selectionStart === 0) {
      hourInputRef.current?.focus();
      hourInputRef.current?.select();
    }
  };

  const isStart = variant === "start";

  const quickPresets = isStart
    ? [
        { label: "00:00", h: 0, m: 0 },
        { label: "12:00", h: 12, m: 0 },
      ]
    : [
        { label: "23:59", h: 23, m: 59 },
      ];

  const handleSetNow = () => {
    const now = new Date();
    commitTime(now.getHours(), now.getMinutes());
  };

  const isNow =
    !isStart &&
    Boolean(date) &&
    (() => {
      const now = new Date();
      return (
        isSameDay(date!, now) &&
        date!.getHours() === now.getHours() &&
        Math.abs(date!.getMinutes() - now.getMinutes()) <= 1
      );
    })();

  return (
    <div className={`flex flex-col rounded-xl bg-surface border border-border/70 transition-colors hover:border-border-strong ${compact ? "gap-1.5 p-2" : "gap-2 p-2.5 shadow-2xs"}`}>
      {/* Row with Label and Digital Input */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span
            className={`h-2 w-2 rounded-full ${
              isStart
                ? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.4)]"
                : "bg-primary shadow-[0_0_6px_rgba(217,119,6,0.4)]"
            }`}
          />
          <span className="text-xs font-sans font-medium text-text">
            {label}
          </span>
        </div>

        {/* Digital LCD Time Box */}
        <div className={`flex items-center bg-surface-subtle border border-border/80 focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/20 rounded-lg shadow-2xs transition-all ${compact ? "px-1.5 py-0" : "px-2 py-0.5"}`}>
          <input
            ref={hourInputRef}
            type="text"
            inputMode="numeric"
            value={displayHour}
            onFocus={handleHourFocus}
            onChange={handleHourChange}
            onBlur={handleHourBlur}
            onKeyDown={handleHourKeyDown}
            className={`${compact ? "w-5 text-xs" : "w-6 text-sm"} text-center font-mono font-bold text-text bg-transparent outline-hidden`}
            aria-label={`${label} hour`}
          />
          <span className="text-text-subtle font-mono text-xs font-bold select-none px-0.5">:</span>
          <input
            ref={minuteInputRef}
            type="text"
            inputMode="numeric"
            value={displayMinute}
            onFocus={handleMinuteFocus}
            onChange={handleMinuteChange}
            onBlur={handleMinuteBlur}
            onKeyDown={handleMinuteKeyDown}
            className={`${compact ? "w-5 text-xs" : "w-6 text-sm"} text-center font-mono font-bold text-text bg-transparent outline-hidden`}
            aria-label={`${label} minute`}
          />

          <div className="flex flex-col ml-1 pl-1 border-l border-border/60">
            <button
              type="button"
              onClick={() => stepMinute(1)}
              className="p-0.5 text-text-subtle hover:text-text hover:bg-surface-hover rounded cursor-pointer transition-colors"
              title="Increase (+1m)"
            >
              <ChevronUp className="h-2.5 w-2.5" />
            </button>
            <button
              type="button"
              onClick={() => stepMinute(-1)}
              className="p-0.5 text-text-subtle hover:text-text hover:bg-surface-hover rounded cursor-pointer transition-colors"
              title="Decrease (-1m)"
            >
              <ChevronDown className="h-2.5 w-2.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Quick Chips below */}
      <div className={`grid grid-cols-2 ${compact ? "gap-1 pt-0.5" : "gap-2 pt-1"}`}>
        {!isStart && (
          <button
            type="button"
            onClick={handleSetNow}
            className={`${compact ? "h-7 rounded-md text-xs" : "h-8 rounded-lg text-xs"} flex items-center justify-center font-mono cursor-pointer transition-all ${
              isNow
                ? "bg-primary-subtle text-primary border border-primary/40 font-semibold shadow-2xs"
                : "bg-surface-subtle hover:bg-surface-hover text-text-muted hover:text-text border border-border/70 font-medium"
            }`}
          >
            Now
          </button>
        )}
        {quickPresets.map((qp) => {
          const isSelected = selectedHour === qp.h && selectedMinute === qp.m && !isNow;
          return (
            <button
              key={qp.label}
              type="button"
              onClick={() => commitTime(qp.h, qp.m)}
              className={`${compact ? "h-7 rounded-md text-xs" : "h-8 rounded-lg text-xs"} flex items-center justify-center font-mono cursor-pointer transition-all ${
                isSelected
                  ? "bg-primary-subtle text-primary border border-primary/40 font-semibold shadow-2xs"
                  : "bg-surface-subtle hover:bg-surface-hover text-text-muted hover:text-text border border-border/70 font-medium"
              }`}
            >
              {qp.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
