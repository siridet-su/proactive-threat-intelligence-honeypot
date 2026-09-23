import type { KeyboardEvent } from "react";

export type TabOrientation = "horizontal" | "vertical";

export function resolveRovingTabIndex(
  key: string,
  currentIndex: number,
  tabCount: number,
  orientation: TabOrientation = "horizontal",
): number | null {
  if (tabCount <= 0 || currentIndex < 0 || currentIndex >= tabCount) return null;
  if (key === "Home") return 0;
  if (key === "End") return tabCount - 1;

  const previousKey = orientation === "horizontal" ? "ArrowLeft" : "ArrowUp";
  const nextKey = orientation === "horizontal" ? "ArrowRight" : "ArrowDown";
  if (key === previousKey) return (currentIndex - 1 + tabCount) % tabCount;
  if (key === nextKey) return (currentIndex + 1) % tabCount;
  return null;
}

interface HandleRovingTabKeyOptions<T extends string> {
  event: KeyboardEvent<HTMLElement>;
  tabs: readonly T[];
  currentTab: T;
  onSelect: (tab: T) => void;
  tabId: (tab: T) => string;
  orientation?: TabOrientation;
}

export function handleRovingTabKey<T extends string>({
  event,
  tabs,
  currentTab,
  onSelect,
  tabId,
  orientation = "horizontal",
}: HandleRovingTabKeyOptions<T>): boolean {
  const currentIndex = tabs.indexOf(currentTab);
  const nextIndex = resolveRovingTabIndex(event.key, currentIndex, tabs.length, orientation);
  if (nextIndex === null) return false;
  const nextTab = tabs[nextIndex];
  if (!nextTab) return false;

  event.preventDefault();
  event.stopPropagation();
  onSelect(nextTab);
  document.getElementById(tabId(nextTab))?.focus();
  return true;
}
