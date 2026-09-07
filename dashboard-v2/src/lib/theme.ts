export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = Exclude<ThemePreference, "system">;
export type ThemeTransitionRequest = { preference: ThemePreference };
export const THEME_STORAGE_KEY = "pti-theme";
export const THEME_CHANGE_EVENT = "pti-theme-change";
export const THEME_TRANSITION_REQUEST_EVENT = "pti-theme-transition-request";

export function parseTheme(value: string | null | undefined): ThemePreference {
  return value === "light" || value === "dark" ? value : "system";
}

export function resolveTheme(preference: ThemePreference): ResolvedTheme {
  return preference === "system"
    ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")
    : preference;
}

export function applyTheme(preference: ThemePreference) {
  const resolved = resolveTheme(preference);
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themePreference = preference;
  document.documentElement.style.colorScheme = resolved;
}

export function setThemePreference(preference: ThemePreference) {
  try { localStorage.setItem(THEME_STORAGE_KEY, preference); } catch { /* Retain the in-page preference when storage is unavailable. */ }
  applyTheme(preference);
  window.dispatchEvent(new Event(THEME_CHANGE_EVENT));
}

export function requestThemePreference(preference: ThemePreference) {
  window.dispatchEvent(new CustomEvent<ThemeTransitionRequest>(THEME_TRANSITION_REQUEST_EVENT, {
    detail: { preference },
  }));
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
