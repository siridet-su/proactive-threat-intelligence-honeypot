"use client";

import { Moon, Sun } from "lucide-react";

import { useResolvedTheme } from "./ThemeProvider";
import { requestThemePreference } from "@/lib/theme";

export default function ThemeToggle() {
  const theme = useResolvedTheme();
  const targetTheme = theme === "dark" ? "light" : "dark";
  const ToggleIcon = targetTheme === "dark" ? Moon : Sun;

  return (
    <button
      type="button"
      className="pti-theme-toggle ui-button h-9 min-h-9 w-10 shrink-0 p-0"
      aria-label={`Switch to ${targetTheme} mode`}
      title={`Switch to ${targetTheme} mode`}
      onClick={() => requestThemePreference(targetTheme)}
    >
      <span className="pti-theme-toggle-spark pti-theme-toggle-spark-one" aria-hidden="true" />
      <span className="pti-theme-toggle-spark pti-theme-toggle-spark-two" aria-hidden="true" />
      <span className="pti-theme-toggle-spark pti-theme-toggle-spark-three" aria-hidden="true" />
      <ToggleIcon className="pti-theme-toggle-glyph h-5 w-5 text-primary" aria-hidden="true" />
      <span className="sr-only">Switch to {targetTheme} mode</span>
    </button>
  );
}
