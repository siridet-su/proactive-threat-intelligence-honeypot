import {
  Check,
  ChevronDown,
  Layers,
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
import type { GraphCallout, TopologyDensityMode, TopologyDensityPreference } from "./filesystemUtils";

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
  effectiveDensityMode,
  densityAnalysisHiddenNodes,
  isTopologyExpanded,
  isAuditMode,
  handleToggleExpand,
}: TopologyToolbarProps) {
  const layoutMenuRef = useRef<HTMLDivElement>(null);
  const [layoutMenuOpen, setLayoutMenuOpen] = useState(false);

  useEffect(() => {
    if (!layoutMenuOpen) return;
    const closeLayoutMenu = (event: PointerEvent) => {
      if (!layoutMenuRef.current?.contains(event.target as Node)) setLayoutMenuOpen(false);
    };
    const closeLayoutMenuOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        setLayoutMenuOpen(false);
        layoutMenuRef.current?.querySelector<HTMLButtonElement>("button")?.focus();
      }
    };
    document.addEventListener("pointerdown", closeLayoutMenu);
    document.addEventListener("keydown", closeLayoutMenuOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeLayoutMenu);
      document.removeEventListener("keydown", closeLayoutMenuOnEscape);
    };
  }, [layoutMenuOpen]);

  const [densityMenuOpen, setDensityMenuOpen] = useState(false);
  const densityMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!densityMenuOpen) return;
    const closeDensityMenu = (event: PointerEvent) => {
      if (!densityMenuRef.current?.contains(event.target as Node)) setDensityMenuOpen(false);
    };
    const closeDensityMenuOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        setDensityMenuOpen(false);
        densityMenuRef.current?.querySelector<HTMLButtonElement>("button")?.focus();
      }
    };
    document.addEventListener("pointerdown", closeDensityMenu);
    document.addEventListener("keydown", closeDensityMenuOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeDensityMenu);
      document.removeEventListener("keydown", closeDensityMenuOnEscape);
    };
  }, [densityMenuOpen]);

  // Handle escape for arrange mode in toolbar so we don't have to duplicate layoutMenuOpen state
  useEffect(() => {
    if (!isArrangeMode) return;
    const exitArrangeMode = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || layoutMenuOpen) return;
      event.preventDefault();
      event.stopPropagation();
      setIsArrangeMode(false);
    };
    document.addEventListener("keydown", exitArrangeMode);
    return () => document.removeEventListener("keydown", exitArrangeMode);
  }, [isArrangeMode, layoutMenuOpen, setIsArrangeMode]);

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
          onClick={fitTopology}
        >
          <ScanLine className="h-3.5 w-3.5" />
        </button>
        <button
          type="button"
          className="ui-button h-8 min-h-8 w-8 p-0"
          title="Center selected IP"
          aria-label="Center selected IP"
          disabled={!selectedGraphCallout}
          onClick={() => {
            markUserAdjusted();
            centerSelectedSource();
          }}
        >
          <LocateFixed className="h-3.5 w-3.5" />
        </button>
      </div>

      <div
        className="flex items-center gap-0.5 rounded-lg border border-border/80 bg-surface-subtle/80 p-0.5 shadow-2xs shrink-0 flex-nowrap"
        role="group"
        aria-label="Layout editing"
      >
        <div
          className="flex items-center"
          role="group"
          aria-label="Interaction mode"
        >
          <button
            type="button"
            aria-pressed={!isArrangeMode}
            onClick={() => setIsArrangeMode(false)}
            className={`flex h-8 items-center gap-1.5 rounded-md px-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${
              !isArrangeMode
                ? "border border-border bg-surface font-semibold text-text shadow-2xs"
                : "border border-transparent text-text-muted hover:bg-surface-hover hover:text-text"
            }`}
          >
            <MousePointer2 className="h-3.5 w-3.5" aria-hidden="true" />
            <span className="hidden sm:inline">Explore</span>
          </button>
          <button
            type="button"
            aria-pressed={isArrangeMode}
            onClick={() => setIsArrangeMode(true)}
            className={`flex h-8 items-center gap-1.5 rounded-md px-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring ${
              isArrangeMode
                ? "border border-primary-border bg-primary-subtle font-semibold text-primary shadow-2xs"
                : "border border-transparent text-text-muted hover:bg-surface-hover hover:text-text"
            }`}
          >
            <Move className="h-3.5 w-3.5" aria-hidden="true" />
            <span className="hidden sm:inline">Arrange</span>
          </button>
        </div>

        {canUndoLayout && (
          <>
            <div className="mx-0.5 h-4 w-px bg-border/80 shrink-0" aria-hidden="true" />
            <button
              type="button"
              className="ui-button h-8 min-h-8 px-2 text-xs"
              title="Undo last layout change"
              aria-label="Undo last layout change"
              onClick={undoLayoutChange}
            >
              <Undo2 className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="hidden xl:inline">Undo</span>
            </button>
          </>
        )}

        <div className="mx-0.5 h-4 w-px bg-border/80 shrink-0" aria-hidden="true" />

        <div ref={layoutMenuRef} className="relative">
          <button
            type="button"
            className={`ui-button relative h-8 min-h-8 w-8 p-0 ${
              totalOverlaps > 0 ? "border-warning/70 text-warning" : ""
            }`}
            title="Layout options"
            aria-label="Open topology layout options"
            aria-expanded={layoutMenuOpen}
            aria-controls="topology-layout-options"
            onClick={() => setLayoutMenuOpen((current) => !current)}
          >
            <Settings2 className="h-3.5 w-3.5" />
            {totalOverlaps > 0 && (
              <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-warning ring-1 ring-surface" />
            )}
          </button>
          {layoutMenuOpen && (
            <div
              id="topology-layout-options"
              aria-label="Topology layout options"
              className="absolute right-0 top-[calc(100%+6px)] z-50 w-56 rounded-xl border border-border bg-surface-raised p-1.5 text-xs shadow-lg"
            >
              <button
                type="button"
                onClick={() => {
                  autoArrangeTopology();
                  setLayoutMenuOpen(false);
                }}
                className="flex min-h-9 w-full items-center gap-2 rounded-lg px-2.5 text-left text-text transition-colors hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              >
                <LayoutGrid className="h-4 w-4 text-primary" aria-hidden="true" />
                <span className="flex-1">Auto arrange</span>
                {totalOverlaps > 0 && <span className="text-warning">{totalOverlaps} overlapping</span>}
              </button>
              <div className="my-1 h-px bg-border" aria-hidden="true" />
              <button
                type="button"
                onClick={() => {
                  resetMapWorkspace();
                  setIsArrangeMode(false);
                  setLayoutMenuOpen(false);
                }}
                className="flex min-h-9 w-full items-center gap-2 rounded-lg px-2.5 text-left text-text transition-colors hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
              >
                <RotateCcw className="h-4 w-4" aria-hidden="true" />
                Restore default layout
              </button>
            </div>
          )}
        </div>
      </div>

      <div
        className="flex items-center gap-0.5 rounded-lg border border-border/80 bg-surface-subtle/80 p-0.5 shadow-2xs shrink-0 flex-nowrap"
        role="group"
        aria-label="Density mode"
      >
        <div ref={densityMenuRef} className="relative">
          <button
            type="button"
            className="ui-button h-8 min-h-8 px-2 text-xs flex items-center gap-1.5"
            title="Adjust map density mode"
            aria-label={`Density mode: ${densityPreference === "auto" ? `Auto (${effectiveDensityMode})` : densityPreference}`}
            aria-expanded={densityMenuOpen}
            aria-controls="topology-density-options"
            onClick={() => setDensityMenuOpen((current) => !current)}
          >
            <Layers className="h-3.5 w-3.5 text-text-subtle" aria-hidden="true" />
            <span className="font-medium capitalize hidden sm:inline">
              {densityPreference === "auto" ? `Auto (${effectiveDensityMode})` : densityPreference}
            </span>
            <ChevronDown className="h-3 w-3 opacity-60" aria-hidden="true" />
          </button>
          {densityMenuOpen && (
            <div
              id="topology-density-options"
              aria-label="Density options"
              className="absolute right-0 top-[calc(100%+6px)] z-50 w-56 rounded-xl border border-border bg-surface-raised p-1.5 text-xs shadow-lg"
            >
              <div className="px-2 py-1 text-[11px] font-medium text-text-muted">
                Density mode
              </div>
              {(["auto", "detailed", "clustered", "aggregated"] as const).map((pref) => {
                const isSelected = densityPreference === pref;
                return (
                  <button
                    key={pref}
                    type="button"
                    onClick={() => {
                      setDensityPreference(pref);
                      setDensityMenuOpen(false);
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
                <div className="mt-1 border-t border-border pt-1 px-2 py-1 text-[11px] text-text-subtle">
                  {densityAnalysisHiddenNodes} {densityAnalysisHiddenNodes === 1 ? "path" : "paths"} aggregated in branches
                </div>
              )}
            </div>
          )}
        </div>
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
          onClick={handleToggleExpand}
        >
          {isTopologyExpanded ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
        </button>
      </div>
    </div>
  );
}
