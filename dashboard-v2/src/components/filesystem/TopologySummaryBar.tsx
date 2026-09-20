import { AlertTriangle } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { formatTimestamp, formatUpdateAge, GRAPH_CALLOUT_LIMIT } from "./filesystemUtils";
import type { FreshnessState, TopologyDensityPreference } from "./filesystemUtils";

interface TopologySummaryBarProps {
  densityAnalysisHiddenNodes: number;
  densityAnalysisRenderedNodes: number;
  densityAnalysisTotalNodes: number;
  densityPreference: TopologyDensityPreference;
  setDensityPreference: (pref: TopologyDensityPreference) => void;
  setIsPathsExpanded: (val: boolean) => void;
  effectiveSessionsLength: number;
  isSourcesTruncated: boolean;
  renderedSourcesCount: number;
  totalLiveSources: number;
  isSourcesExpanded: boolean;
  setIsSourcesExpanded: (val: boolean | ((prev: boolean) => boolean)) => void;
  snapshotGeneratedAt: string;
  freshnessState: FreshnessState;
  staleThresholdMs: number;
  totalOverlaps: number;
  autoArrangeTopology: () => void;
  reducedMotion: boolean | null;
  isAuditMode?: boolean;
}

export function TopologySummaryBar({
  densityAnalysisHiddenNodes,
  densityAnalysisRenderedNodes,
  densityAnalysisTotalNodes,
  densityPreference,
  setDensityPreference,
  setIsPathsExpanded,
  effectiveSessionsLength,
  isSourcesTruncated,
  renderedSourcesCount,
  totalLiveSources,
  isSourcesExpanded,
  setIsSourcesExpanded,
  snapshotGeneratedAt,
  freshnessState,
  staleThresholdMs,
  totalOverlaps,
  autoArrangeTopology,
  reducedMotion,
  isAuditMode = false,
}: TopologySummaryBarProps) {
  return (
    <div className="flex min-h-11 shrink-0 flex-col items-start justify-between gap-2 border-t border-border px-4 py-3 text-xs text-text-muted select-none sm:h-11 sm:flex-row sm:items-center sm:px-5 sm:py-0">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1 text-xs sm:flex-nowrap sm:gap-3">
        {densityAnalysisHiddenNodes > 0 ? (
          <span className="shrink-0 flex items-center gap-1.5">
            <span>
              <strong className="font-medium text-text">{densityAnalysisRenderedNodes}</strong> of{" "}
              <strong className="font-medium text-text">{densityAnalysisTotalNodes}</strong> paths{" "}
              <span className="text-text-subtle font-normal">
                ({densityAnalysisHiddenNodes} aggregated in branches)
              </span>
            </span>
            {densityPreference !== "detailed" ? (
              <button
                type="button"
                onClick={() => {
                  setDensityPreference("detailed");
                  setIsPathsExpanded(true);
                }}
                className="rounded border border-primary-border bg-primary-subtle px-1.5 py-0.5 text-[10px] font-semibold text-primary hover:bg-primary/20 transition-colors"
                title="Switch to detailed density mode to render all paths"
              >
                Expand all
              </button>
            ) : (
              <button
                type="button"
                onClick={() => {
                  setDensityPreference("auto");
                  setIsPathsExpanded(false);
                }}
                className="rounded border border-border bg-surface px-1.5 py-0.5 text-[10px] text-text-muted hover:text-text transition-colors"
                title="Reset density mode to Auto"
              >
                Reset to auto
              </button>
            )}
          </span>
        ) : densityPreference !== "auto" ? (
          <span className="shrink-0 flex items-center gap-1.5">
            <span>
              All <strong className="font-medium text-text">{densityAnalysisRenderedNodes}</strong> paths rendered
              <span className="text-text-subtle font-normal"> ({densityPreference} mode)</span>
            </span>
            <button
              type="button"
              onClick={() => {
                setDensityPreference("auto");
                setIsPathsExpanded(false);
              }}
              className="rounded border border-border bg-surface px-1.5 py-0.5 text-[10px] text-text-muted hover:text-text transition-colors"
              title="Reset density mode to Auto"
            >
              Reset to auto
            </button>
          </span>
        ) : (
          <span className="shrink-0">
            <strong className="font-medium text-text">{densityAnalysisTotalNodes}</strong> observed paths
          </span>
        )}
        <span className="shrink-0 text-border" aria-hidden="true">·</span>
        <span className="shrink-0">
          <strong className="font-medium text-text">{effectiveSessionsLength}</strong> {isAuditMode ? "retained" : "active"} {effectiveSessionsLength === 1 ? "session" : "sessions"}
          <span className="hidden xl:inline"> with a known CWD</span>
        </span>
        <span className="shrink-0 text-border" aria-hidden="true">·</span>
        {isSourcesTruncated ? (
          <span className="shrink-0 flex items-center gap-1.5">
            <span>
              <strong className="font-medium text-text">{renderedSourcesCount}</strong> of{" "}
              <strong className="font-medium text-text">{totalLiveSources}</strong> unique {totalLiveSources === 1 ? "source" : "sources"} on map
            </span>
            <button
              type="button"
              onClick={() => setIsSourcesExpanded(true)}
              className="rounded border border-primary-border bg-primary-subtle px-1.5 py-0.5 text-[10px] font-semibold text-primary hover:bg-primary/20 transition-colors"
              title="Show all live source callouts on the map"
            >
              Show all
            </button>
          </span>
        ) : isSourcesExpanded && totalLiveSources > GRAPH_CALLOUT_LIMIT ? (
          <span className="shrink-0 flex items-center gap-1.5">
            <span>
              All <strong className="font-medium text-text">{renderedSourcesCount}</strong> unique {renderedSourcesCount === 1 ? "source" : "sources"} on map
            </span>
            <button
              type="button"
              onClick={() => setIsSourcesExpanded(false)}
              className="rounded border border-border bg-surface px-1.5 py-0.5 text-[10px] text-text-muted hover:text-text transition-colors"
              title={`Limit to ${GRAPH_CALLOUT_LIMIT} source callouts`}
            >
              Compact ({GRAPH_CALLOUT_LIMIT})
            </button>
          </span>
        ) : (
          <span className="shrink-0">
            <strong className="font-medium text-text">{totalLiveSources}</strong> unique {totalLiveSources === 1 ? "source" : "sources"}
          </span>
        )}
        <span className="hidden 2xl:inline shrink-0 text-border" aria-hidden="true">·</span>
        {isAuditMode ? (
          <span className="hidden 2xl:inline truncate text-text-subtle font-medium text-primary">
            Historical audit data
          </span>
        ) : (
          <span
            className="hidden 2xl:inline truncate text-text-subtle"
            title={`Snapshot generated at ${formatTimestamp(snapshotGeneratedAt)}, received ${formatUpdateAge(freshnessState.snapshotReceiptAgeMs)} (stale threshold: ${Math.round(staleThresholdMs / 1000)}s)`}
          >
            {freshnessState.isStale ? (
              <span className="font-medium text-warning">
                {freshnessState.telemetryStatus === "valid" && freshnessState.telemetryAgeMs !== null ? (
                  <>Stale (telemetry {formatUpdateAge(freshnessState.telemetryAgeMs)}) · Snapshot {formatTimestamp(snapshotGeneratedAt)}</>
                ) : freshnessState.telemetryStatus === "future_skew" ? (
                  <>Stale (telemetry clock skew) · Snapshot {formatTimestamp(snapshotGeneratedAt)}</>
                ) : (
                  <>Stale (telemetry unavailable) · Snapshot {formatTimestamp(snapshotGeneratedAt)}</>
                )}
              </span>
            ) : freshnessState.label === "Live · No activity" ? (
              <span>
                Live (no activity) · Snapshot {formatTimestamp(snapshotGeneratedAt)}
              </span>
            ) : (
              <span>
                Telemetry {formatUpdateAge(freshnessState.telemetryAgeMs ?? 0)} · Snapshot {formatTimestamp(snapshotGeneratedAt)}
              </span>
            )}
          </span>
        )}
      </div>

      <div className="flex max-w-full shrink-0 flex-wrap items-center gap-3.5">
        <AnimatePresence>
          {totalOverlaps > 0 && (
            <motion.div
              key="overlap-badge-group"
              initial={reducedMotion ? false : { opacity: 0, scale: 0.92, x: 8 }}
              animate={{ opacity: 1, scale: 1, x: 0 }}
              exit={reducedMotion ? undefined : { opacity: 0, scale: 0.92, x: 8 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              className="flex items-center gap-3"
            >
              <button
                type="button"
                onClick={autoArrangeTopology}
                className="flex items-center gap-1.5 rounded-md border border-warning-border bg-warning-subtle px-2.5 py-1 text-xs font-medium text-warning transition-all hover:border-warning/60 hover:bg-warning/20 active:scale-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-warning"
                title="Click to automatically arrange overlapping elements"
                aria-label={`${totalOverlaps} elements overlapping. Click to auto arrange.`}
              >
                <AlertTriangle className="h-3 w-3 shrink-0 text-warning" aria-hidden="true" />
                <span>{totalOverlaps} overlapping · Auto arrange</span>
              </button>
              <div className="hidden h-3.5 w-px bg-border sm:block" aria-hidden="true" />
            </motion.div>
          )}
        </AnimatePresence>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1" aria-label="Topology map legend">
          <span className="flex items-center gap-1.5">
            <span className="h-px w-3 bg-border-strong" aria-hidden="true" />
            <span>Filesystem route</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-3 rounded-full bg-primary" aria-hidden="true" />
            <span>Selected source route</span>
          </span>
        </div>
      </div>
    </div>
  );
}
