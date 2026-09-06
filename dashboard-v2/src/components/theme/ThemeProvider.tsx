"use client";

import { createContext, useContext, useEffect, useSyncExternalStore } from "react";
import { applyTheme, parseTheme, THEME_CHANGE_EVENT, THEME_STORAGE_KEY, type ThemePreference } from "@/lib/theme";

const ThemeContext = createContext<ThemePreference>("system");
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
  return <ThemeContext value={preference}>{children}</ThemeContext>;
}

export const useThemePreference = () => useContext(ThemeContext);
