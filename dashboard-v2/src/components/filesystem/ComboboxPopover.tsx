"use client";

import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Loader2, Search, X } from "lucide-react";
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";


/**
 * Pure calculation for next focused option index in combobox/listbox navigation.
 * Returns -1 if allowInputFocus is true and user navigated up from index 0.
 */
export function calculateNextComboboxIndex(
  currentIndex: number,
  delta: number | "home" | "end",
  totalCount: number,
  options: { loop?: boolean; allowInputFocus?: boolean } = {},
): number {
  const { loop = true, allowInputFocus = false } = options;
  if (totalCount <= 0) return allowInputFocus ? -1 : 0;

  if (delta === "home") return 0;
  if (delta === "end") return totalCount - 1;

  if (delta > 0) {
    if (currentIndex < 0) return 0;
    const next = currentIndex + delta;
    if (next >= totalCount) {
      return loop ? 0 : totalCount - 1;
    }
    return next;
  }

  if (delta < 0) {
    if (currentIndex === 0 && allowInputFocus) {
      return -1;
    }
    if (currentIndex < 0) {
      return totalCount - 1;
    }
    const prev = currentIndex + delta;
    if (prev < 0) {
      return loop ? totalCount - 1 : 0;
    }
    return prev;
  }

  return currentIndex;
}

/**
 * Pure typeahead matcher for combobox options.
 * Searches from (startIndex + 1) through the end, then wraps from 0 to startIndex.
 */
export function findTypeaheadIndex<T>(
  items: readonly T[],
  getLabel: (item: T) => string,
  rawQuery: string,
  startIndex = 0,
): number {
  if (!items.length || !rawQuery) return -1;
  const query = rawQuery.trim().toLowerCase();
  if (!query) return -1;

  // Search forward from next item
  for (let i = startIndex + 1; i < items.length; i++) {
    const item = items[i];
    if (item !== undefined && getLabel(item).toLowerCase().startsWith(query)) {
      return i;
    }
  }

  // Wrap around from beginning
  for (let i = 0; i <= startIndex && i < items.length; i++) {
    const item = items[i];
    if (item !== undefined && getLabel(item).toLowerCase().startsWith(query)) {
      return i;
    }
  }

  return -1;
}

export type ComboboxFocusTarget = "first" | "last" | "search";

/**
 * Pure calculation to determine initial focus target when opening from closed trigger.
 */
export function determineFocusTarget(
  triggerKey: string,
  isOpen: boolean,
): ComboboxFocusTarget | null {
  if (isOpen) return null;
  if (triggerKey === "ArrowDown") return "first";
  if (triggerKey === "ArrowUp") return "last";
  if (triggerKey === "Enter" || triggerKey === " ") return "search";
  return null;
}

export interface UseComboboxNavigationOptions<T> {
  isOpen: boolean;
  onOpen: (focusTarget?: ComboboxFocusTarget) => void;
  onClose: () => void;
  items: readonly T[];
  getLabel: (item: T) => string;
  onSelect: (item: T, index: number) => void;
  triggerRef: React.RefObject<HTMLElement | null>;
  searchInputRef?: React.RefObject<HTMLInputElement | null>;
  selectedIndex?: number;
}

export function useComboboxNavigation<T>({
  isOpen,
  onOpen,
  onClose,
  items,
  getLabel,
  onSelect,
  triggerRef,
  searchInputRef,
  selectedIndex = -1,
}: UseComboboxNavigationOptions<T>) {
  const [navigatedIndex, setNavigatedIndex] = useState<number | null>(null);
  const pendingFocusTargetRef = useRef<ComboboxFocusTarget | null>(null);
  const optionRefs = useRef<Array<HTMLElement | null>>([]);
  const typeaheadBuffer = useRef("");
  const typeaheadTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Compute activeIndex with safe bounds clamping
  const activeIndex = useMemo(() => {
    if (items.length === 0) return -1;
    if (navigatedIndex !== null) {
      return Math.max(0, Math.min(navigatedIndex, items.length - 1));
    }
    if (selectedIndex >= 0 && selectedIndex < items.length) {
      return selectedIndex;
    }
    return 0;
  }, [items.length, navigatedIndex, selectedIndex]);

  // Truncate optionRefs to eliminate stale refs
  useEffect(() => {
    if (optionRefs.current.length > items.length) {
      optionRefs.current.length = items.length;
    }
  }, [items.length]);


  const registerOptionRef = useCallback((index: number) => {
    return (el: HTMLElement | null) => {
      optionRefs.current[index] = el;
    };
  }, []);

  const openWithFocus = useCallback(
    (focusTarget: ComboboxFocusTarget = "search") => {
      pendingFocusTargetRef.current = focusTarget;
      onOpen(focusTarget);
    },
    [onOpen],
  );

  // Focus active option or scroll it into view
  const focusOption = useCallback((index: number) => {
    if (index === -1) {
      setNavigatedIndex(-1);
      searchInputRef?.current?.focus();
      return;
    }
    if (index >= 0 && index < optionRefs.current.length) {
      setNavigatedIndex(index);
      const el = optionRefs.current[index];
      el?.focus();
      el?.scrollIntoView({ block: "nearest" });
    }
  }, [searchInputRef]);

  // Apply pending focus synchronously once mounted
  useEffect(() => {
    if (!isOpen) {
      pendingFocusTargetRef.current = null;
      return;
    }

    const target = pendingFocusTargetRef.current;
    if (!target) return;
    pendingFocusTargetRef.current = null;

    if (target === "first") {
      if (items.length > 0 && optionRefs.current[0]) {
        setNavigatedIndex(0);
        optionRefs.current[0]?.focus();
        optionRefs.current[0]?.scrollIntoView({ block: "nearest" });
        return;
      }
    } else if (target === "last") {
      const lastIdx = items.length - 1;
      if (lastIdx >= 0 && optionRefs.current[lastIdx]) {
        setNavigatedIndex(lastIdx);
        optionRefs.current[lastIdx]?.focus();
        optionRefs.current[lastIdx]?.scrollIntoView({ block: "nearest" });
        return;
      }
    }

    // Default "search" target or empty-list fallback
    if (searchInputRef?.current) {
      setNavigatedIndex(-1);
      searchInputRef.current.focus();
    } else if (items.length > 0 && optionRefs.current[0]) {
      setNavigatedIndex(0);
      optionRefs.current[0]?.focus();
      optionRefs.current[0]?.scrollIntoView({ block: "nearest" });
    }
  }, [isOpen, items.length, searchInputRef]);

  // Handle trigger keydown (ArrowDown/Up/Enter/Space to open or navigate)
  const handleTriggerKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLElement>) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        if (!isOpen) {
          openWithFocus("first");
        } else {
          const next = calculateNextComboboxIndex(activeIndex, 1, items.length);
          focusOption(next);
        }
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        if (!isOpen) {
          openWithFocus("last");
        } else {
          const prev = calculateNextComboboxIndex(activeIndex, -1, items.length);
          focusOption(prev);
        }
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        if (!isOpen) {
          openWithFocus("search");
        } else {
          onClose();
          triggerRef.current?.focus();
        }
      } else if (event.key === "Escape" && isOpen) {
        event.preventDefault();
        onClose();
        triggerRef.current?.focus();
      }
    },
    [isOpen, openWithFocus, onClose, activeIndex, items.length, focusOption, triggerRef],
  );

  // Handle search input keydown
  const handleInputKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLInputElement>) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        if (items.length > 0) {
          focusOption(0);
        }
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        if (items.length > 0) {
          focusOption(items.length - 1);
        }
      } else if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        triggerRef.current?.focus();
      } else if (event.key === "Enter") {
        if (activeIndex >= 0 && activeIndex < items.length) {
          event.preventDefault();
          const targetItem = items[activeIndex];
          if (targetItem !== undefined) {
            onSelect(targetItem, activeIndex);
          }
          onClose();
          triggerRef.current?.focus();
        }
      }
    },
    [activeIndex, focusOption, items, onClose, onSelect, triggerRef],
  );

  // Handle option keydown
  const handleOptionKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLElement>, index: number) => {
      if (event.key === "ArrowDown") {
        event.preventDefault();
        const next = calculateNextComboboxIndex(index, 1, items.length);
        focusOption(next);
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        const prev = calculateNextComboboxIndex(index, -1, items.length, {
          allowInputFocus: Boolean(searchInputRef?.current),
        });
        focusOption(prev);
      } else if (event.key === "Home") {
        event.preventDefault();
        if (items.length > 0) {
          focusOption(0);
        }
      } else if (event.key === "End") {
        event.preventDefault();
        if (items.length > 0) {
          focusOption(items.length - 1);
        }
      } else if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        triggerRef.current?.focus();
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        const targetItem = items[index];
        if (targetItem !== undefined) {
          onSelect(targetItem, index);
        }
        onClose();
        triggerRef.current?.focus();
      } else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
        // Typeahead jump
        if (typeaheadTimer.current) clearTimeout(typeaheadTimer.current);
        typeaheadBuffer.current += event.key;
        typeaheadTimer.current = setTimeout(() => {
          typeaheadBuffer.current = "";
        }, 500);

        const match = findTypeaheadIndex(items, getLabel, typeaheadBuffer.current, index);
        if (match >= 0) {
          event.preventDefault();
          focusOption(match);
        }
      }
    },
    [focusOption, getLabel, items, onClose, onSelect, searchInputRef, triggerRef],
  );

  return {
    activeIndex,
    registerOptionRef,
    focusOption,
    openWithFocus,
    handleTriggerKeyDown,
    handleInputKeyDown,
    handleOptionKeyDown,
  };
}

export interface ComboboxPopoverProps {
  id: string;
  isOpen: boolean;
  onClose: () => void;
  triggerRef: React.RefObject<HTMLElement | null>;
  ariaLabel: string;
  children: React.ReactNode;
  className?: string;
  totalCount?: number;
}

export function ComboboxPopover({
  id,
  isOpen,
  onClose,
  triggerRef,
  ariaLabel,
  children,
  className = "",
  totalCount,
}: ComboboxPopoverProps) {
  const popoverRef = useRef<HTMLDivElement>(null);
  const reducedMotion = useReducedMotion();

  // Outside click & global Escape handling
  useEffect(() => {
    if (!isOpen) return;

    const handlePointerDown = (e: PointerEvent) => {
      const target = e.target as Node | null;
      if (
        popoverRef.current &&
        !popoverRef.current.contains(target) &&
        triggerRef.current &&
        !triggerRef.current.contains(target)
      ) {
        onClose();
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        onClose();
        triggerRef.current?.focus();
      }
    };

    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen, onClose, triggerRef]);

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          ref={popoverRef}
          id={id}
          role="dialog"
          aria-modal="false"
          aria-label={ariaLabel}
          tabIndex={-1}
          initial={reducedMotion ? false : { opacity: 0, y: -6, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={reducedMotion ? undefined : { opacity: 0, y: -6, scale: 0.98 }}
          transition={reducedMotion ? { duration: 0 } : { duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
          className={`absolute left-0 top-[calc(100%+6px)] z-50 rounded-xl border border-border bg-surface-raised p-1.5 shadow-lg ${className}`}
        >
          {/* Screen reader live region announcing item counts */}
          <div role="status" aria-live="polite" className="sr-only">
            {totalCount !== undefined ? `${totalCount} options available` : `${ariaLabel} opened`}
          </div>
          {children}
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export interface ComboboxSearchInputProps {
  inputRef: React.RefObject<HTMLInputElement | null>;
  value: string;
  onChange: (value: string) => void;
  onClear: () => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  placeholder?: string;
  isLoading?: boolean;
  ariaControls?: string;
  className?: string;
}

export function ComboboxSearchInput({
  inputRef,
  value,
  onChange,
  onClear,
  onKeyDown,
  placeholder = "Search...",
  isLoading = false,
  ariaControls,
  className = "",
}: ComboboxSearchInputProps) {
  return (
    <div className={`relative mb-1.5 px-1 pt-1 ${className}`}>
      <Search className="absolute left-3 top-3 h-3.5 w-3.5 text-text-subtle" aria-hidden="true" />
      <input
        ref={inputRef}
        type="text"
        role="searchbox"
        aria-controls={ariaControls}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={onKeyDown}
        placeholder={placeholder}
        className="w-full rounded-lg border border-border bg-surface-subtle pl-8 pr-7 py-1.5 text-xs font-mono text-text placeholder:text-text-subtle focus:border-primary focus:outline-hidden focus:ring-1 focus:ring-primary/40"
      />
      {isLoading ? (
        <Loader2 className="absolute right-3 top-3 h-3.5 w-3.5 animate-spin text-primary" aria-label="Loading results" />
      ) : value ? (
        <button
          type="button"
          onClick={onClear}
          aria-label="Clear search text"
          className="absolute right-3 top-3 text-text-subtle hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
        >
          <X className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      ) : null}
    </div>
  );
}
