"use client";

import { useSyncExternalStore } from "react";
import { Moon, Sun } from "lucide-react";

import type { ResolvedTheme } from "@/lib/theme";

interface ThemeTransitionProps {
  previous: ResolvedTheme;
  resolved: ResolvedTheme;
}

const subscribeToHydration = () => () => {};
const getClientHydrationState = () => true;
const getServerHydrationState = () => false;

export default function ThemeTransition({ previous, resolved }: ThemeTransitionProps) {
  const hydrated = useSyncExternalStore(subscribeToHydration, getClientHydrationState, getServerHydrationState);

  // The transition is deliberately client-only so an in-flight Fast Refresh
  // state can never produce markup that differs from the server response.
  if (!hydrated) return null;

  const FromIcon = previous === "dark" ? Moon : Sun;
  const ToIcon = resolved === "dark" ? Moon : Sun;
  const nextLabel = resolved === "dark" ? "dark" : "light";

  return (
    <div className="pti-theme-transition" role="status" aria-live="polite" aria-atomic="true">
      <div className="pti-theme-transition-card">
        <div className="pti-theme-transition-icons" aria-hidden="true">
          <span className="pti-theme-transition-icon pti-theme-transition-icon-from">
            <FromIcon className="h-5 w-5" strokeWidth={1.8} />
          </span>
          <span className="pti-theme-transition-rail"><span /></span>
          <span className="pti-theme-transition-icon pti-theme-transition-icon-to">
            <ToIcon className="h-5 w-5" strokeWidth={1.8} />
          </span>
        </div>
        <span className="text-sm font-medium text-text">Switching to {nextLabel} mode</span>
      </div>
    </div>
  );
}
