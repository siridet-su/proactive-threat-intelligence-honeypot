"use client";

import { createContext, useContext, useEffect, useRef, useState, useSyncExternalStore } from "react";
import {
  applyTheme,
  parseTheme,
  setThemePreference,
  THEME_CHANGE_EVENT,
  THEME_STORAGE_KEY,
  THEME_TRANSITION_REQUEST_EVENT,
  type ResolvedTheme,
  type ThemeTransitionRequest,
} from "@/lib/theme";
import ThemeTransition from "./ThemeTransition";

const ThemeContext = createContext<ResolvedTheme>("light");
type ThemeSwitch = { previous: ResolvedTheme; resolved: ResolvedTheme };
const THEME_HANDOFF_DELAY_MS = 760;
const THEME_TRANSITION_DURATION_MS = 1360;
function subscribe(onChange: () => void) {
  const onStorage = (event: StorageEvent) => {
    if (event.key === THEME_STORAGE_KEY || event.key === null) {
      applyTheme(parseTheme(event.newValue));
      onChange();
    }
  };
  window.addEventListener(THEME_CHANGE_EVENT, onChange);
  window.addEventListener("storage", onStorage);
  return () => {
    window.removeEventListener(THEME_CHANGE_EVENT, onChange);
    window.removeEventListener("storage", onStorage);
  };
}
const getSnapshot = (): ResolvedTheme => document.documentElement.dataset.theme === "dark" ? "dark" : "light";
const getServerSnapshot = (): ResolvedTheme => "light";

export default function ThemeProvider({ children }: { children: React.ReactNode }) {
  const resolvedTheme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const themeApplyTimer = useRef<number | null>(null);
  const transitionDismissTimer = useRef<number | null>(null);
  const [themeSwitch, setThemeSwitch] = useState<ThemeSwitch | null>(null);

  useEffect(() => {
    // Read the bootstrapped preference too: hydration initially uses the server snapshot.
    const preference = parseTheme(document.documentElement.dataset.themePreference);
    applyTheme(preference);
    if (preference !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => {
      applyTheme("system");
      window.dispatchEvent(new Event(THEME_CHANGE_EVENT));
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [resolvedTheme]);

  useEffect(() => {
    const clearTimers = () => {
      if (themeApplyTimer.current !== null) window.clearTimeout(themeApplyTimer.current);
      if (transitionDismissTimer.current !== null) window.clearTimeout(transitionDismissTimer.current);
    };
    const onThemeTransitionRequest = (event: Event) => {
      const request = (event as CustomEvent<ThemeTransitionRequest>).detail;
      if (!request) return;

      const previous = document.documentElement.dataset.theme === "dark" ? "dark" : "light";
      if (previous === request.theme) {
        setThemePreference(request.theme);
        return;
      }

      clearTimers();
      setThemeSwitch({ previous, resolved: request.theme });
      // Keep the current theme visible through the outgoing icon. The actual
      // token swap happens while the overlay covers the hand-off in the rail.
      themeApplyTimer.current = window.setTimeout(() => setThemePreference(request.theme), THEME_HANDOFF_DELAY_MS);
      transitionDismissTimer.current = window.setTimeout(() => setThemeSwitch(null), THEME_TRANSITION_DURATION_MS);
    };

    window.addEventListener(THEME_TRANSITION_REQUEST_EVENT, onThemeTransitionRequest);
    return () => {
      clearTimers();
      window.removeEventListener(THEME_TRANSITION_REQUEST_EVENT, onThemeTransitionRequest);
    };
  }, []);

  return (
    <ThemeContext value={resolvedTheme}>
      {children}
      {themeSwitch && <ThemeTransition {...themeSwitch} />}
    </ThemeContext>
  );
}

export const useResolvedTheme = () => useContext(ThemeContext);
