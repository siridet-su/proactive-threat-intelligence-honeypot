"use client";

import { createContext, useContext, useEffect, useRef, useState, useSyncExternalStore } from "react";
import {
  applyTheme,
  parseTheme,
  resolveTheme,
  setThemePreference,
  THEME_CHANGE_EVENT,
  THEME_STORAGE_KEY,
  THEME_TRANSITION_REQUEST_EVENT,
  type ResolvedTheme,
  type ThemePreference,
  type ThemeTransitionRequest,
} from "@/lib/theme";
import ThemeTransition from "./ThemeTransition";

const ThemeContext = createContext<ThemePreference>("system");
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
const getSnapshot = () => parseTheme(document.documentElement.dataset.themePreference);
const getServerSnapshot = (): ThemePreference => "system";

export default function ThemeProvider({ children }: { children: React.ReactNode }) {
  const preference = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const themeApplyTimer = useRef<number | null>(null);
  const transitionDismissTimer = useRef<number | null>(null);
  const [themeSwitch, setThemeSwitch] = useState<ThemeSwitch | null>(null);

  useEffect(() => {
    // Read the bootstrapped preference too: hydration initially uses the server snapshot.
    const current = getSnapshot();
    applyTheme(current);
    if (current !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyTheme("system");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [preference]);

  useEffect(() => {
    const clearTimers = () => {
      if (themeApplyTimer.current !== null) window.clearTimeout(themeApplyTimer.current);
      if (transitionDismissTimer.current !== null) window.clearTimeout(transitionDismissTimer.current);
    };
    const onThemeTransitionRequest = (event: Event) => {
      const request = (event as CustomEvent<ThemeTransitionRequest>).detail;
      if (!request) return;

      const previous = document.documentElement.dataset.theme === "dark" ? "dark" : "light";
      const resolved = resolveTheme(request.preference);
      if (previous === resolved) {
        setThemePreference(request.preference);
        return;
      }

      clearTimers();
      setThemeSwitch({ previous, resolved });
      // Keep the current theme visible through the outgoing icon. The actual
      // token swap happens while the overlay covers the hand-off in the rail.
      themeApplyTimer.current = window.setTimeout(() => setThemePreference(request.preference), THEME_HANDOFF_DELAY_MS);
      transitionDismissTimer.current = window.setTimeout(() => setThemeSwitch(null), THEME_TRANSITION_DURATION_MS);
    };

    window.addEventListener(THEME_TRANSITION_REQUEST_EVENT, onThemeTransitionRequest);
    return () => {
      clearTimers();
      window.removeEventListener(THEME_TRANSITION_REQUEST_EVENT, onThemeTransitionRequest);
    };
  }, []);

  return (
    <ThemeContext value={preference}>
      {children}
      {themeSwitch && <ThemeTransition {...themeSwitch} />}
    </ThemeContext>
  );
}

export const useThemePreference = () => useContext(ThemeContext);
