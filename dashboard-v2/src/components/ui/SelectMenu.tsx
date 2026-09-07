"use client";

import { Check, ChevronDown } from "lucide-react";
import { useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";

import { cn } from "@/lib/utils";

export type SelectMenuOption = string | { value: string; label: string };

interface SelectMenuProps {
  id?: string;
  value: string;
  options: readonly SelectMenuOption[];
  onValueChange: (value: string) => void;
  disabled?: boolean;
  className?: string;
  leadingIcon?: ReactNode;
}

function normalizeOption(option: SelectMenuOption) {
  return typeof option === "string" ? { value: option, label: option } : option;
}

export function SelectMenu({ id, value, options, onValueChange, disabled = false, className, leadingIcon }: SelectMenuProps) {
  const root = useRef<HTMLDivElement>(null);
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const generatedId = useId();
  const triggerId = id ?? `pti-select-${generatedId}`;
  const menuId = `${triggerId}-options`;
  const normalizedOptions = options.map(normalizeOption);
  const selectedIndex = Math.max(0, normalizedOptions.findIndex((option) => option.value === value));
  const selectedOption = normalizedOptions[selectedIndex];
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (event.target instanceof Node && !root.current?.contains(event.target)) setOpen(false);
    };
    const closeOnEscape = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  const focusOption = (index: number) => {
    const nextIndex = (index + normalizedOptions.length) % normalizedOptions.length;
    window.requestAnimationFrame(() => optionRefs.current[nextIndex]?.focus());
  };
  const chooseOption = (nextValue: string) => {
    onValueChange(nextValue);
    setOpen(false);
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
    }
    if (event.key === "Home") {
      event.preventDefault();
      focusOption(0);
    }
    if (event.key === "End") {
      event.preventDefault();
      focusOption(normalizedOptions.length - 1);
    }
  };

  return (
    <div ref={root} className={cn("relative", className)}>
      <button
        id={triggerId}
        type="button"
        disabled={disabled}
        className={cn("ui-field ui-select-trigger", leadingIcon && "pl-10")}
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => setOpen((isOpen) => !isOpen)}
        onKeyDown={handleTriggerKeyDown}
      >
        {leadingIcon && <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-text-subtle" aria-hidden="true">{leadingIcon}</span>}
        <span className="min-w-0 flex-1 truncate">{selectedOption?.label ?? value}</span>
        <ChevronDown className={cn("h-4 w-4 shrink-0 text-text-subtle transition-transform duration-150", open && "rotate-180")} aria-hidden="true" />
      </button>
      <div id={menuId} data-open={open && !disabled} className="ui-dropdown-menu absolute inset-x-0 top-[calc(100%+6px)] z-[60] max-h-60 overflow-auto rounded-lg border border-border bg-surface-raised p-1 shadow-[var(--shadow-raised)]" role="listbox" aria-labelledby={triggerId}>
        {normalizedOptions.map((option, index) => {
          const selected = option.value === value;
          return (
            <button
              key={option.value}
              ref={(element) => { optionRefs.current[index] = element; }}
              type="button"
              role="option"
              aria-selected={selected}
              className={cn("flex w-full items-center justify-between gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors duration-150", selected ? "bg-primary-subtle text-primary" : "text-text-muted hover:bg-surface-hover hover:text-text")}
              onClick={() => chooseOption(option.value)}
              onKeyDown={(event) => handleOptionKeyDown(event, index)}
            >
              <span className="truncate">{option.label}</span>
              {selected && <Check className="h-4 w-4 shrink-0" aria-hidden="true" />}
            </button>
          );
        })}
      </div>
    </div>
  );
}
