import {
  Check,
  ChevronDown,

  LayoutGrid,
  LocateFixed,
  Maximize2,
  Minimize2,
  MousePointer2,
  Move,
  RotateCcw,
  ScanLine,
  Settings2,
  Undo2,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import type { GraphCallout, TopologyDensityMode, TopologyDensityPreference } from "./filesystemUtils";
import type { MinimapVisibilityPreference } from "./topologyDensity";

interface TopologyToolbarProps {
  zoom: number;
  zoomIn: () => void;
  zoomOut: () => void;
  fitTopology: () => void;
  selectedGraphCallout: GraphCallout | null;
  markUserAdjusted: () => void;
  centerSelectedSource: () => void;
  isArrangeMode: boolean;
  setIsArrangeMode: (mode: boolean) => void;
  canUndoLayout: boolean;
  undoLayoutChange: () => void;
  totalOverlaps: number;
  autoArrangeTopology: () => void;
  resetMapWorkspace: () => void;
  densityPreference: TopologyDensityPreference;
  setDensityPreference: (pref: TopologyDensityPreference) => void;
  minimapPreference: MinimapVisibilityPreference;
  setMinimapPreference: (pref: MinimapVisibilityPreference) => void;
  minimapVisible: boolean;
  showGrid: boolean;
  setShowGrid: (show: boolean) => void;
  effectiveDensityMode: TopologyDensityMode;
  densityAnalysisHiddenNodes: number;
  isTopologyExpanded: boolean;
  isAuditMode: boolean;
  handleToggleExpand: () => void;
}

export function TopologyToolbar({
  zoom,
  zoomIn,
  zoomOut,
  fitTopology,
  selectedGraphCallout,
  markUserAdjusted,
  centerSelectedSource,
  isArrangeMode,
  setIsArrangeMode,
  canUndoLayout,
  undoLayoutChange,
  totalOverlaps,
  autoArrangeTopology,
  resetMapWorkspace,
  densityPreference,
  setDensityPreference,
  minimapPreference,
  setMinimapPreference,
  minimapVisible,
  showGrid,
  setShowGrid,
  effectiveDensityMode,
  densityAnalysisHiddenNodes,
  isTopologyExpanded,
  isAuditMode,
  handleToggleExpand,
}: TopologyToolbarProps) {
  const viewMenuRef = useRef<HTMLDivElement>(null);
  const [viewMenuOpen, setViewMenuOpen] = useState(false);
  useEffect(() => {
    if (!viewMenuOpen) return;
    const closeViewMenu = (event: PointerEvent) => {
      if (!viewMenuRef.current?.contains(event.target as Node)) setViewMenuOpen(false);
    };
    const closeViewMenuOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        setViewMenuOpen(false);
        viewMenuRef.current?.querySelector<HTMLButtonElement>("button")?.focus();
      }
    };
    document.addEventListener("pointerdown", closeViewMenu);
    document.addEventListener("keydown", closeViewMenuOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeViewMenu);
      document.removeEventListener("keydown", closeViewMenuOnEscape);
    };
  }, [viewMenuOpen]);

  // Handle escape for arrange mode in toolbar so we don't have to duplicate layoutMenuOpen state
  useEffect(() => {
    if (!isArrangeMode) return;
    const exitArrangeMode = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || viewMenuOpen) return;
      event.preventDefault();
      event.stopPropagation();
      setIsArrangeMode(false);
    };
    document.addEventListener("keydown", exitArrangeMode);
    return () => document.removeEventListener("keydown", exitArrangeMode);
  }, [isArrangeMode, viewMenuOpen, setIsArrangeMode]);

  return (
    <div
      className="flex shrink-0 flex-wrap items-center justify-start sm:justify-end gap-2"
      role="toolbar"
      aria-label="Topology canvas controls"
    >
      <div
        className="flex items-center gap-0.5 rounded-lg border border-border/80 bg-surface-subtle/80 p-0.5 shadow-2xs shrink-0 flex-nowrap"
        role="group"
        aria-label="Canvas navigation"
      >
        <button
          type="button"
          className="ui-button h-8 min-h-8 w-8 p-0"
          title="Zoom out"
          aria-label="Zoom out"
          data-keyboard-tooltip
          onClick={() => zoomOut()}
        >
          <ZoomOut className="h-3.5 w-3.5" />
        </button>
        <span
          className="ui-badge h-8 min-w-11 justify-center border-none bg-surface/80 px-1 font-mono text-xs tabular-nums"
          aria-live="polite"
          aria-label={`Zoom ${Math.round(zoom * 100)} percent`}
        >
          {Math.round(zoom * 100)}%
        </span>
        <button
          type="button"
          className="ui-button h-8 min-h-8 w-8 p-0"
          title="Zoom in"
          aria-label="Zoom in"
          data-keyboard-tooltip
          onClick={() => zoomIn()}
        >
          <ZoomIn className="h-3.5 w-3.5" />
        </button>

        <div className="mx-0.5 h-4 w-px bg-border/80 shrink-0" aria-hidden="true" />

        <button
          type="button"
          className="ui-button h-8 min-h-8 w-8 p-0"
          title="Fit topology in view"
          aria-label="Fit topology in view"
          data-keyboard-tooltip
          onClick={fitTopology}
        >
          <ScanLine className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          className="ui-button h-8 min-h-8 w-8 p-0"
          title="Center selected IP"
          aria-label="Center selected IP"
          data-keyboard-tooltip
          onClick={() => {
            // Selection is supplied by the live client stream and can differ
            // from the SSR snapshot. The callback is already a safe no-op
            // without a selected source, so keep this attribute deterministic.
            if (!selectedGraphCallout) return;
            markUserAdjusted();
            centerSelectedSource();
          }}
        >
          <LocateFixed className="h-3.5 w-3.5" />
        </button>
      </div>

      <div ref={viewMenuRef} className="relative shrink-0">
        <button
          type="button"
          className={`h-9 min-h-9 flex items-center justify-between gap-1.5 rounded-lg border px-2.5 py-1 text-xs transition-colors cursor-pointer select-none shadow-2xs ${
            totalOverlaps > 0
              ? "border-warning-border bg-warning-subtle text-warning shadow-xs"
              : viewMenuOpen
                ? "border-primary ring-2 ring-primary/20 bg-surface text-text"
                : "border-border bg-surface text-text hover:border-border-strong hover:bg-surface-hover hover:text-text"
          }`}
          title="View settings"
          aria-label="View settings"
          aria-expanded={viewMenuOpen}
          aria-controls="topology-view-settings"
          onClick={() => setViewMenuOpen((current) => !current)}
        >
          <div className="flex items-center gap-1.5">
            <Settings2 className={`h-3.5 w-3.5 shrink-0 ${viewMenuOpen ? "text-primary" : "text-text-muted"}`} aria-hidden="true" />
            <span className={`hidden font-sans font-medium sm:inline ${viewMenuOpen ? "text-text" : "text-text"}`}>View</span>
          </div>
          <ChevronDown className={`h-3 w-3 shrink-0 transition-transform duration-200 ${viewMenuOpen ? "rotate-180 text-primary" : "text-text-muted"}`} aria-hidden="true" />
          {totalOverlaps > 0 && (
            <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-warning ring-1 ring-surface" />
          )}
        </button>
          <AnimatePresence>
            {viewMenuOpen && (
              <motion.div
                initial={{ opacity: 0, y: -4, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -4, scale: 0.98 }}
                transition={{ duration: 0.15, ease: "easeOut" }}
                id="topology-view-settings"
                aria-label="View settings"
                className="absolute right-0 top-[calc(100%+6px)] z-50 w-64 origin-top-right rounded-xl border border-border bg-surface-raised p-1.5 text-xs shadow-lg"
              >
              <div className="px-2 py-1 text-xs font-medium text-text-muted">
                Interaction Mode
              </div>
              <div className="flex p-1 gap-1">
                <button
                  type="button"
                  aria-pressed={!isArrangeMode}
                  onClick={() => { setIsArrangeMode(false); setViewMenuOpen(false); }}
                  className={`flex-1 flex h-8 items-center justify-center gap-1.5 rounded-md px-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${
                    !isArrangeMode
                      ? "border border-border bg-surface font-semibold text-text shadow-2xs"
                      : "border border-transparent text-text-muted hover:bg-surface-hover hover:text-text"
                  }`}
                >
                  <MousePointer2 className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Explore</span>
                </button>
                <button
                  type="button"
                  aria-pressed={isArrangeMode}
                  onClick={() => { setIsArrangeMode(true); setViewMenuOpen(false); }}
                  className={`flex-1 flex h-8 items-center justify-center gap-1.5 rounded-md px-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${
                    isArrangeMode
                      ? "border border-primary-border bg-primary-subtle font-semibold text-primary shadow-2xs"
                      : "border border-transparent text-text-muted hover:bg-surface-hover hover:text-text"
                  }`}
                >
                  <Move className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Arrange</span>
                </button>
              </div>

              <div className="my-1 h-px bg-border" aria-hidden="true" />
              <div className="px-2 py-1 text-xs font-medium text-text-muted">
                Density Mode
              </div>
              {(["auto", "detailed", "clustered", "aggregated"] as const).map((pref) => {
                const isSelected = densityPreference === pref;
                return (
                  <button
                    key={pref}
                    type="button"
                    onClick={() => {
                      setDensityPreference(pref);
                    }}
                    className={`flex min-h-8 w-full items-center justify-between rounded-lg px-2.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${
                      isSelected
                        ? "bg-primary-subtle text-primary font-medium"
                        : "text-text hover:bg-surface-hover"
                    }`}
                  >
                    <span className="capitalize">
                      {pref === "auto" ? `Auto (${effectiveDensityMode})` : pref}
                    </span>
                    {isSelected && <Check className="h-3.5 w-3.5 text-primary" aria-hidden="true" />}
                  </button>
                );
              })}
              {densityAnalysisHiddenNodes > 0 && (
                <div className="mt-1 border-t border-border pt-1 px-2 py-1 text-xs text-text-subtle">
                  {densityAnalysisHiddenNodes} {densityAnalysisHiddenNodes === 1 ? "path" : "paths"} aggregated
                </div>
              )}

              <div className="my-1 h-px bg-border" aria-hidden="true" />
              <div className="px-2 py-1 text-xs font-medium text-text-muted">
                Appearance
              </div>
              <div className="px-2.5 pb-1 pt-0.5 text-xs text-text-subtle">
                Minimap {minimapVisible ? "visible" : "hidden"}
              </div>
              <div
                role="group"
                aria-label="Minimap visibility"
                className="grid grid-cols-3 gap-1 px-1 pb-1"
              >
                {(["auto", "show", "hide"] as const).map((preference) => {
                  const selected = minimapPreference === preference;
                  return (
                    <button
                      key={preference}
                      type="button"
                      aria-pressed={selected}
                      onClick={() => setMinimapPreference(preference)}
                      className={`min-h-8 rounded-md px-2 text-xs font-medium capitalize transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${
                        selected
                          ? "border border-primary-border bg-primary-subtle text-primary"
                          : "border border-transparent text-text-muted hover:bg-surface-hover hover:text-text"
                      }`}
                    >
                      {preference}
                    </button>
                  );
                })}
              </div>
              <button
                type="button"
                onClick={() => setShowGrid(!showGrid)}
                className="flex min-h-8 w-full items-center justify-between rounded-lg px-2.5 text-left text-text transition-colors hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              >
                <span>Show background grid</span>
                {showGrid && <Check className="h-3.5 w-3.5 text-primary" aria-hidden="true" />}
              </button>

              <div className="my-1 h-px bg-border" aria-hidden="true" />
              <div className="px-2 py-1 text-xs font-medium text-text-muted">
                Layout Actions
              </div>
              {canUndoLayout && (
                <button
                  type="button"
                  onClick={undoLayoutChange}
                  className="flex min-h-9 w-full items-center gap-2 rounded-lg px-2.5 text-left text-text transition-colors hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                >
                  <Undo2 className="h-4 w-4" aria-hidden="true" />
                  Undo layout change
                </button>
              )}
              <button
                type="button"
                onClick={() => {
                  autoArrangeTopology();
                  setViewMenuOpen(false);
                }}
                className="flex min-h-9 w-full items-center gap-2 rounded-lg px-2.5 text-left text-text transition-colors hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              >
                <LayoutGrid className="h-4 w-4 text-primary" aria-hidden="true" />
                <span className="flex-1">Auto arrange</span>
                {totalOverlaps > 0 && <span className="text-warning">{totalOverlaps} overlapping</span>}
              </button>
              <button
                type="button"
                onClick={() => {
                  resetMapWorkspace();
                  setIsArrangeMode(false);
                  setViewMenuOpen(false);
                }}
                className="flex min-h-9 w-full items-center gap-2 rounded-lg px-2.5 text-left text-text transition-colors hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              >
                <RotateCcw className="h-4 w-4" aria-hidden="true" />
                Restore default layout
              </button>
            </motion.div>
          )}
          </AnimatePresence>
        </div>

      <div className="flex items-center shrink-0">
        <button
          type="button"
          className="ui-button h-9 min-h-9 w-9 p-0"
          title={
            isTopologyExpanded
              ? isAuditMode
                ? "Exit fullscreen audit studio"
                : "Exit expanded map"
              : isAuditMode
                ? "Open fullscreen audit studio"
                : "Expand map workspace"
          }
          aria-label={
            isTopologyExpanded
              ? isAuditMode
                ? "Exit fullscreen audit studio"
                : "Exit expanded map"
              : isAuditMode
                ? "Open fullscreen audit studio"
                : "Expand map workspace"
          }
          aria-pressed={isTopologyExpanded}
          data-keyboard-tooltip
          onClick={handleToggleExpand}
        >
          {isTopologyExpanded ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
        </button>
      </div>
    </div>
  );
}
