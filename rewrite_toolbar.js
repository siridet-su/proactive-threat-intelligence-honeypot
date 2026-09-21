const fs = require('fs');
const path = './dashboard-v2/src/components/filesystem/TopologyToolbar.tsx';
let code = fs.readFileSync(path, 'utf8');

// Replace state
code = code.replace(
  /const layoutMenuRef = useRef<HTMLDivElement>\(null\);\s+const \[layoutMenuOpen, setLayoutMenuOpen\] = useState\(false\);[\s\S]*?const \[densityMenuOpen, setDensityMenuOpen\] = useState\(false\);\s+const densityMenuRef = useRef<HTMLDivElement>\(null\);[\s\S]*?\}\, \[densityMenuOpen\]\);/g,
  `const viewMenuRef = useRef<HTMLDivElement>(null);
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
  }, [viewMenuOpen]);`
);

// Replace layoutMenuOpen in useEffect for Arrange Mode
code = code.replace(
  /\|\| layoutMenuOpen/g,
  `|| viewMenuOpen`
);
code = code.replace(
  /\[isArrangeMode, layoutMenuOpen, setIsArrangeMode\]/g,
  `[isArrangeMode, viewMenuOpen, setIsArrangeMode]`
);

// Replace the two toolbar groups
const toolbarRegex = /<div\s+className="flex items-center gap-0\.5 rounded-lg border border-border\/80 bg-surface-subtle\/80 p-0\.5 shadow-2xs shrink-0 flex-nowrap"\s+role="group"\s+aria-label="Layout editing"[\s\S]*?<\/div>\s*<\/div>\s*<\/div>/g;

const replacement = `<div
        className="flex items-center gap-0.5 rounded-lg border border-border/80 bg-surface-subtle/80 p-0.5 shadow-2xs shrink-0 flex-nowrap"
        role="group"
        aria-label="View settings"
      >
        <div ref={viewMenuRef} className="relative">
          <button
            type="button"
            className={\`ui-button h-8 min-h-8 px-2 text-xs flex items-center gap-1.5 \${totalOverlaps > 0 ? "border-warning/70 text-warning" : ""}\`}
            title="View settings"
            aria-label="View settings"
            aria-expanded={viewMenuOpen}
            aria-controls="topology-view-settings"
            onClick={() => setViewMenuOpen((current) => !current)}
          >
            <Settings2 className="h-3.5 w-3.5 text-text-subtle" aria-hidden="true" />
            <span className="font-medium capitalize hidden sm:inline">View</span>
            <ChevronDown className="h-3 w-3 opacity-60" aria-hidden="true" />
            {totalOverlaps > 0 && (
              <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-warning ring-1 ring-surface" />
            )}
          </button>
          {viewMenuOpen && (
            <div
              id="topology-view-settings"
              aria-label="View settings"
              className="absolute right-0 top-[calc(100%+6px)] z-50 w-64 rounded-xl border border-border bg-surface-raised p-1.5 text-xs shadow-lg"
            >
              <div className="px-2 py-1 text-[11px] font-medium text-text-muted">
                Interaction Mode
              </div>
              <div className="flex p-1 gap-1">
                <button
                  type="button"
                  aria-pressed={!isArrangeMode}
                  onClick={() => { setIsArrangeMode(false); setViewMenuOpen(false); }}
                  className={\`flex-1 flex h-8 items-center justify-center gap-1.5 rounded-md px-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring \${
                    !isArrangeMode
                      ? "border border-border bg-surface font-semibold text-text shadow-2xs"
                      : "border border-transparent text-text-muted hover:bg-surface-hover hover:text-text"
                  }\`}
                >
                  <MousePointer2 className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Explore</span>
                </button>
                <button
                  type="button"
                  aria-pressed={isArrangeMode}
                  onClick={() => { setIsArrangeMode(true); setViewMenuOpen(false); }}
                  className={\`flex-1 flex h-8 items-center justify-center gap-1.5 rounded-md px-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring \${
                    isArrangeMode
                      ? "border border-primary-border bg-primary-subtle font-semibold text-primary shadow-2xs"
                      : "border border-transparent text-text-muted hover:bg-surface-hover hover:text-text"
                  }\`}
                >
                  <Move className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>Arrange</span>
                </button>
              </div>

              <div className="my-1 h-px bg-border" aria-hidden="true" />
              <div className="px-2 py-1 text-[11px] font-medium text-text-muted">
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
                    className={\`flex min-h-8 w-full items-center justify-between rounded-lg px-2.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring \${
                      isSelected
                        ? "bg-primary-subtle text-primary font-medium"
                        : "text-text hover:bg-surface-hover"
                    }\`}
                  >
                    <span className="capitalize">
                      {pref === "auto" ? \`Auto (\${effectiveDensityMode})\` : pref}
                    </span>
                    {isSelected && <Check className="h-3.5 w-3.5 text-primary" aria-hidden="true" />}
                  </button>
                );
              })}
              {densityAnalysisHiddenNodes > 0 && (
                <div className="mt-1 border-t border-border pt-1 px-2 py-1 text-[11px] text-text-subtle">
                  {densityAnalysisHiddenNodes} {densityAnalysisHiddenNodes === 1 ? "path" : "paths"} aggregated
                </div>
              )}

              <div className="my-1 h-px bg-border" aria-hidden="true" />
              <div className="px-2 py-1 text-[11px] font-medium text-text-muted">
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
            </div>
          )}
        </div>
      </div>`;

code = code.replace(toolbarRegex, replacement);

fs.writeFileSync(path, code);
