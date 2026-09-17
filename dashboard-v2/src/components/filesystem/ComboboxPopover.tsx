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

import type { CloseReason } from "./auditSessionSearchManager";

const useIsomorphicLayoutEffect =
  typeof window !== "undefined" ? React.useLayoutEffect : React.useEffect;

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
  onClose: (reason?: CloseReason) => void;
  items: readonly T[];
  getLabel: (item: T) => string;
  getKey?: (item: T, index: number) => string;
  onSelect: (item: T, index: number) => void;
  triggerRef: React.RefObject<HTMLElement | null>;
  searchInputRef?: React.RefObject<HTMLInputElement | null>;
  selectedIndex?: number;
}

function defaultGetKey<T>(item: T, index: number): string {
  if (item && typeof item === "object") {
    if ("sessionId" in item && typeof (item as { sessionId: unknown }).sessionId === "string") {
      return (item as { sessionId: string }).sessionId;
    }
    if ("path" in item && typeof (item as { path: unknown }).path === "string") {
      const type =
        "type" in item && typeof (item as { type: unknown }).type === "string"
          ? (item as { type: string }).type
          : "path";
      return `${type}:${(item as { path: string }).path}`;
    }
    if ("id" in item && typeof (item as { id: unknown }).id === "string") {
      return (item as { id: string }).id;
    }
    if ("key" in item && typeof (item as { key: unknown }).key === "string") {
      return (item as { key: string }).key;
    }
  }
  return String(index);
}

export function useComboboxNavigation<T>({
  isOpen,
  onOpen,
  onClose,
  items,
  getLabel,
  getKey,
  onSelect,
  triggerRef,
  searchInputRef,
  selectedIndex = -1,
}: UseComboboxNavigationOptions<T>) {
  const [navigatedIndex, setNavigatedIndex] = useState<number | null>(null);
  const [navigatedKey, setNavigatedKey] = useState<string | null>(null);
  const pendingFocusTargetRef = useRef<ComboboxFocusTarget | null>(null);
  const optionKeyRefs = useRef<Map<string, HTMLElement>>(new Map());
  const optionIndexRefs = useRef<Array<HTMLElement | null>>([]);
  const typeaheadBuffer = useRef("");
  const typeaheadTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const effectiveGetKey = useCallback(
    (item: T, index: number): string => {
      if (getKey) return getKey(item, index);
      return defaultGetKey(item, index);
    },
    [getKey],
  );

  // Compute activeIndex with safe bounds clamping; return -1 when search input is active
  const activeIndex = useMemo(() => {
    if (items.length === 0) return -1;
    if (navigatedKey === "__search__" || navigatedIndex === -1) return -1;
    if (navigatedKey !== null) {
      const idx = items.findIndex((item, i) => effectiveGetKey(item, i) === navigatedKey);
      if (idx !== -1) return idx;
    }
    if (navigatedIndex !== null && navigatedIndex >= 0 && navigatedIndex < items.length) {
      return navigatedIndex;
    }
    if (selectedIndex >= 0 && selectedIndex < items.length) {
      return selectedIndex;
    }
    return -1;
  }, [items, effectiveGetKey, navigatedKey, navigatedIndex, selectedIndex]);

  // Truncate optionIndexRefs to eliminate stale refs
  useEffect(() => {
    if (optionIndexRefs.current.length > items.length) {
      optionIndexRefs.current.length = items.length;
    }
  }, [items.length]);

  const registerOptionRef = useCallback(
    (index: number, explicitKey?: string) => {
      return (el: HTMLElement | null) => {
        const item = items[index];
        const key = explicitKey ?? (item !== undefined ? effectiveGetKey(item, index) : String(index));
        if (el) {
          optionKeyRefs.current.set(key, el);
        } else {
          optionKeyRefs.current.delete(key);
        }
        optionIndexRefs.current[index] = el;
      };
    },
    [items, effectiveGetKey],
  );

  const openWithFocus = useCallback(
    (focusTarget: ComboboxFocusTarget = "search") => {
      pendingFocusTargetRef.current = focusTarget;
      onOpen(focusTarget);
    },
    [onOpen],
  );

  // Focus active option or search input
  const focusOption = useCallback(
    (index: number) => {
      if (index === -1) {
        setNavigatedIndex(-1);
        setNavigatedKey("__search__");
        searchInputRef?.current?.focus();
        return;
      }
      if (index >= 0 && index < items.length) {
        const item = items[index];
        const key = effectiveGetKey(item, index);
        setNavigatedIndex(index);
        setNavigatedKey(key);
        const el = optionKeyRefs.current.get(key) ?? optionIndexRefs.current[index];
        el?.focus();
        el?.scrollIntoView({ block: "nearest" });
      }
    },
    [items, effectiveGetKey, searchInputRef],
  );

  // Apply pending focus synchronously once mounted in layout phase
  useIsomorphicLayoutEffect(() => {
    if (!isOpen) {
      pendingFocusTargetRef.current = null;
      return;
    }

    const target = pendingFocusTargetRef.current;
    if (!target) return;
    pendingFocusTargetRef.current = null;

    if (target === "first") {
      if (items.length > 0) {
        const item = items[0];
        const key = effectiveGetKey(item, 0);
        setNavigatedIndex(0);
        setNavigatedKey(key);
        const el = optionKeyRefs.current.get(key) ?? optionIndexRefs.current[0];
        el?.focus();
        el?.scrollIntoView({ block: "nearest" });
        return;
      }
    } else if (target === "last") {
      const lastIdx = items.length - 1;
      if (lastIdx >= 0) {
        const item = items[lastIdx];
        const key = effectiveGetKey(item, lastIdx);
        setNavigatedIndex(lastIdx);
        setNavigatedKey(key);
        const el = optionKeyRefs.current.get(key) ?? optionIndexRefs.current[lastIdx];
        el?.focus();
        el?.scrollIntoView({ block: "nearest" });
        return;
      }
    }

    // Default "search" target or empty-list fallback
    if (searchInputRef?.current) {
      setNavigatedIndex(-1);
      setNavigatedKey("__search__");
      searchInputRef.current.focus();
    } else if (items.length > 0) {
      const item = items[0];
      const key = effectiveGetKey(item, 0);
      setNavigatedIndex(0);
      setNavigatedKey(key);
      const el = optionKeyRefs.current.get(key) ?? optionIndexRefs.current[0];
      el?.focus();
      el?.scrollIntoView({ block: "nearest" });
    }
  }, [isOpen, items, effectiveGetKey, searchInputRef]);

  // Identity-aware focus preservation & deterministic fallback on list change (FA-007)
  useIsomorphicLayoutEffect(() => {
    if (!isOpen) {
      setNavigatedIndex(null);
      setNavigatedKey(null);
      optionKeyRefs.current.clear();
      optionIndexRefs.current.length = 0;
      return;
    }

    // If search input is focused, retain focus there
    if (navigatedKey === "__search__" || navigatedIndex === -1) {
      return;
    }

    // If an option was actively navigated:
    if (navigatedKey !== null) {
      const newIndex = items.findIndex((item, idx) => effectiveGetKey(item, idx) === navigatedKey);

      if (newIndex !== -1) {
        // Option STILL EXISTS by identity after list reorder/update
        if (newIndex !== navigatedIndex) {
          setNavigatedIndex(newIndex);
        }
        const el = optionKeyRefs.current.get(navigatedKey);
        if (el && document.activeElement !== el) {
          el.focus();
        }
        return;
      }

      // Option DISAPPEARED (filtered out, replaced with different items, etc.)
      // Deterministic fallback:
      if (searchInputRef?.current) {
        // Fallback to search input
        setNavigatedIndex(-1);
        setNavigatedKey("__search__");
        searchInputRef.current.focus();
      } else if (items.length > 0) {
        // Fallback to nearest valid neighbor
        const fallbackIdx = Math.max(0, Math.min(navigatedIndex ?? 0, items.length - 1));
        const fallbackItem = items[fallbackIdx];
        const fallbackKey = effectiveGetKey(fallbackItem, fallbackIdx);
        setNavigatedIndex(fallbackIdx);
        setNavigatedKey(fallbackKey);
        const fallbackEl = optionKeyRefs.current.get(fallbackKey) ?? optionIndexRefs.current[fallbackIdx];
        fallbackEl?.focus();
      } else {
        // List is completely empty with no search input
        setNavigatedIndex(-1);
        setNavigatedKey(null);
        triggerRef.current?.focus();
      }
    }
  }, [isOpen, items, effectiveGetKey, navigatedKey, navigatedIndex, searchInputRef, triggerRef]);

  // Clear typeahead timer on close and unmount
  useEffect(() => {
    if (!isOpen) {
      if (typeaheadTimer.current) {
        clearTimeout(typeaheadTimer.current);
        typeaheadTimer.current = null;
      }
      typeaheadBuffer.current = "";
    }
  }, [isOpen]);

  useEffect(() => {
    return () => {
      if (typeaheadTimer.current) {
        clearTimeout(typeaheadTimer.current);
        typeaheadTimer.current = null;
      }
      typeaheadBuffer.current = "";
    };
  }, []);

  // Handle trigger keydown (using determineFocusTarget)
  const handleTriggerKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLElement>) => {
      const focusTarget = determineFocusTarget(event.key, isOpen);
      if (focusTarget) {
        event.preventDefault();
        openWithFocus(focusTarget);
        return;
      }
      if (isOpen) {
        if (event.key === "ArrowDown") {
          event.preventDefault();
          const next = calculateNextComboboxIndex(activeIndex, 1, items.length);
          focusOption(next);
        } else if (event.key === "ArrowUp") {
          event.preventDefault();
          const prev = calculateNextComboboxIndex(activeIndex, -1, items.length);
          focusOption(prev);
        } else if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onClose("escape");
          triggerRef.current?.focus();
        } else if (event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
          onClose("escape");
          triggerRef.current?.focus();
        }
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
        event.stopPropagation();
        onClose("escape");
        triggerRef.current?.focus();
      } else if (event.key === "Enter") {
        // Only select if user actively navigated to an option (navigatedIndex !== -1)
        if (navigatedIndex !== -1 && activeIndex >= 0 && activeIndex < items.length) {
          event.preventDefault();
          const targetItem = items[activeIndex];
          if (targetItem !== undefined) {
            onSelect(targetItem, activeIndex);
          }
        }
      }
    },
    [activeIndex, focusOption, items, navigatedIndex, onClose, onSelect, triggerRef],
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
        event.stopPropagation();
        onClose("escape");
        triggerRef.current?.focus();
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        const targetItem = items[index];
        if (targetItem !== undefined) {
          onSelect(targetItem, index);
        }
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

  const handleSearchInputFocus = useCallback(() => {
    setNavigatedIndex(-1);
    setNavigatedKey("__search__");
  }, []);

  return {
    activeIndex,
    registerOptionRef,
    focusOption,
    openWithFocus,
    handleTriggerKeyDown,
    handleInputKeyDown,
    handleOptionKeyDown,
    handleSearchInputFocus,
  };
}

export interface ComboboxPopoverProps {
  id: string;
  isOpen: boolean;
  onClose: (reason?: CloseReason) => void;
  triggerRef: React.RefObject<HTMLElement | null>;
  ariaLabel?: string;
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
        onClose("outside");
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        onClose("escape");
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
          tabIndex={-1}
          initial={reducedMotion ? false : { opacity: 0, y: -6, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={reducedMotion ? undefined : { opacity: 0, y: -6, scale: 0.98 }}
          transition={reducedMotion ? { duration: 0 } : { duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
          className={`absolute left-0 top-[calc(100%+6px)] z-50 rounded-xl border border-border bg-surface-raised p-1.5 shadow-lg ${className}`}
        >
          {/* Screen reader live region announcing item counts */}
          <div role="status" aria-live="polite" className="sr-only">
            {totalCount !== undefined
              ? `${totalCount} options available`
              : ariaLabel
                ? `${ariaLabel} opened`
                : "Options opened"}
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
  onFocus?: () => void;
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
  onFocus,
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
        onFocus={onFocus}
        placeholder={placeholder}
        className="w-full rounded-lg border border-border bg-surface-subtle pl-8 pr-7 py-1.5 text-xs font-mono text-text placeholder:text-text-subtle focus:border-primary focus:outline-hidden focus:ring-1 focus:ring-primary/40"
      />
      {isLoading ? (
        <Loader2 className="absolute right-3 top-3 h-3.5 w-3.5 animate-spin text-primary" aria-label="Loading results" />
      ) : value ? (
        <button
          type="button"
          onClick={() => {
            onClear();
            inputRef?.current?.focus();
          }}
          aria-label="Clear search input"
          className="absolute right-2.5 top-2.5 rounded p-0.5 text-text-subtle hover:text-text hover:bg-surface-hover focus-visible:outline-hidden focus-visible:ring-1 focus-visible:ring-focus-ring"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      ) : null}
    </div>
  );
}
