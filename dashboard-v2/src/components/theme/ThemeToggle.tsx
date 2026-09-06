"use client";

import { useThemePreference } from "./ThemeProvider";
import { parseTheme, setThemePreference } from "@/lib/theme";

export default function ThemeToggle() {
  const preference = useThemePreference();
  return (
    <label className="flex shrink-0 items-center gap-2 text-xs font-medium text-text-muted">
      <span>Theme</span>
      <select className="ui-field w-auto text-xs" value={preference} onChange={event => setThemePreference(parseTheme(event.target.value))}>
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
    </label>
  );
}
