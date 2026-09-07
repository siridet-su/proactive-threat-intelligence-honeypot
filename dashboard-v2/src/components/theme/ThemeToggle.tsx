"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Check, ChevronDown, Monitor, Moon, Sun } from "lucide-react";

import { useThemePreference } from "./ThemeProvider";
import { setThemePreference, type ThemePreference } from "@/lib/theme";

const themeOptions: Array<{
  value: ThemePreference;
  label: string;
  description: string;
  icon: typeof Monitor;
}> = [
  { value: "system", label: "System", description: "Use device setting", icon: Monitor },
  { value: "light", label: "Light", description: "Use light interface", icon: Sun },
  { value: "dark", label: "Dark", description: "Use dark interface", icon: Moon },
];

interface ThemeToggleProps {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export default function ThemeToggle({ open, onOpenChange }: ThemeToggleProps) {
  const preference = useThemePreference();
  const menu = useRef<HTMLDetailsElement>(null);
  const [uncontrolledOpen, setUncontrolledOpen] = useState(false);
  const selectedTheme = themeOptions.find((option) => option.value === preference) ?? themeOptions[0];
  const SelectedIcon = selectedTheme.icon;
  const isControlled = open !== undefined;
  const isOpen = isControlled ? open : uncontrolledOpen;
  const setMenuOpen = useCallback((nextOpen: boolean) => {
    if (isControlled) onOpenChange?.(nextOpen);
    else setUncontrolledOpen(nextOpen);
  }, [isControlled, onOpenChange]);

  useEffect(() => {
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (!isOpen) return;
      if (event.target instanceof Node && !menu.current?.contains(event.target)) setMenuOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (isOpen && event.key === "Escape") setMenuOpen(false);
    };

    document.addEventListener("pointerdown", closeOnOutsidePointer);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [isOpen, setMenuOpen]);

  return (
    <details
      ref={menu}
      open={isOpen}
      className="relative shrink-0"
    >
      <summary
        className="ui-button h-9 min-h-9 list-none gap-2 px-2.5 text-xs [&::-webkit-details-marker]:hidden"
        aria-label={`Theme: ${selectedTheme.label}`}
        onClick={(event) => {
          event.preventDefault();
          setMenuOpen(!isOpen);
        }}
      >
        <SelectedIcon className="h-4 w-4 text-primary" aria-hidden="true" />
        <span className="hidden sm:inline">{selectedTheme.label}</span>
        <ChevronDown className="h-3.5 w-3.5 text-text-subtle" aria-hidden="true" />
      </summary>
      <div className="absolute right-0 top-[calc(100%+8px)] z-50 w-56 rounded-xl border border-border bg-surface-raised p-1.5 shadow-[var(--shadow-raised)]" role="menu" aria-label="Theme preference">
        <p className="px-2.5 pb-1.5 pt-1 text-xs font-medium text-text-subtle">Appearance</p>
        {themeOptions.map(({ value, label, description, icon: Icon }) => {
          const selected = value === preference;
          return (
            <button
              key={value}
              type="button"
              role="menuitemradio"
              aria-checked={selected}
              onClick={() => {
                setThemePreference(value);
                setMenuOpen(false);
              }}
              className="flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left text-sm text-text-muted transition-colors duration-150 hover:bg-surface-hover hover:text-text"
            >
              <Icon className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
              <span className="min-w-0 flex-1">
                <span className="block font-medium text-text">{label}</span>
                <span className="block text-xs text-text-subtle">{description}</span>
              </span>
              {selected && <Check className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />}
            </button>
          );
        })}
      </div>
    </details>
  );
}
