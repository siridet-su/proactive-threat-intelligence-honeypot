export type ThemePreference = "system" | "light" | "dark";
export const THEME_STORAGE_KEY = "pti-theme";
export const THEME_CHANGE_EVENT = "pti-theme-change";

export function parseTheme(value: string | null | undefined): ThemePreference {
  return value === "light" || value === "dark" ? value : "system";
}

export function applyTheme(preference: ThemePreference) {
  const resolved = preference === "system"
    ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : preference;
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themePreference = preference;
  document.documentElement.style.colorScheme = resolved;
}

export function setThemePreference(preference: ThemePreference) {
  try { localStorage.setItem(THEME_STORAGE_KEY, preference); } catch { /* Retain the in-page preference when storage is unavailable. */ }
  applyTheme(preference);
  window.dispatchEvent(new Event(THEME_CHANGE_EVENT));
}

// Static synchronous head script: resolves the theme before body content can paint.
export const themeBootstrap = `(${function () {
  let preference = "system";
  try {
    const stored = localStorage.getItem("pti-theme");
    if (stored === "light" || stored === "dark") preference = stored;
  } catch {}
  const resolved = preference === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : preference;
  const root = document.documentElement;
  root.dataset.theme = resolved;
  root.dataset.themePreference = preference;
  root.style.colorScheme = resolved;
}.toString()})();`;
