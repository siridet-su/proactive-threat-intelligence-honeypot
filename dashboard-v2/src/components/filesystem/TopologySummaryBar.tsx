import { AlertTriangle } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { formatTimestamp, formatUpdateAge, GRAPH_CALLOUT_LIMIT } from "./filesystemUtils";
import type { FreshnessState, TopologyDensityPreference } from "./filesystemUtils";
import type { TopologyPresentationContext } from "./TopologyCanvas";

interface BaseTopologySummaryBarProps {
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
  totalOverlaps: number;
  autoArrangeTopology: () => void;
  reducedMotion: boolean | null;
}

export type TopologySummaryBarProps = BaseTopologySummaryBarProps & (
  | {
      presentationContext: Extract<TopologyPresentationContext, { mode: "live" }>;
      snapshotGeneratedAt: string;
      freshnessState: FreshnessState;
      staleThresholdMs: number;
    }
  | {
      presentationContext: Extract<TopologyPresentationContext, { mode: "audit" }>;
      snapshotGeneratedAt?: never;
      freshnessState?: never;
      staleThresholdMs?: never;
    }
);

function isLiveSummaryBarProps(
  props: TopologySummaryBarProps,
): props is BaseTopologySummaryBarProps & {
  presentationContext: Extract<TopologyPresentationContext, { mode: "live" }>;
  snapshotGeneratedAt: string;
  freshnessState: FreshnessState;
  staleThresholdMs: number;
} {
  return props.presentationContext.mode === "live";
}

export function TopologySummaryBar(props: TopologySummaryBarProps) {
  const {
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
    totalOverlaps,
    autoArrangeTopology,
    reducedMotion,
    presentationContext,
  } = props;
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
          <strong className="font-medium text-text">{effectiveSessionsLength}</strong>{" "}
          {presentationContext.mode === "live"
            ? `active ${effectiveSessionsLength === 1 ? "session" : "sessions"}`
            : presentationContext.session?.lifecycle === "retained"
              ? `retained ${effectiveSessionsLength === 1 ? "session" : "sessions"}`
              : presentationContext.session?.lifecycle === "active"
                ? `${effectiveSessionsLength === 1 ? "session" : "sessions"} (active session investigation)`
                : `${effectiveSessionsLength === 1 ? "session" : "sessions"}`}
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
        {isLiveSummaryBarProps(props) ? (
          <span
            className="hidden 2xl:inline truncate text-text-subtle"
            title={`Snapshot generated at ${formatTimestamp(props.snapshotGeneratedAt)}, received ${formatUpdateAge(props.freshnessState.snapshotReceiptAgeMs)} (stale threshold: ${Math.round(props.staleThresholdMs / 1000)}s)`}
          >
            {props.freshnessState.isStale ? (
              <span className="font-medium text-warning">
                {props.freshnessState.telemetryStatus === "valid" && props.freshnessState.telemetryAgeMs !== null ? (
                  <>Stale (telemetry {formatUpdateAge(props.freshnessState.telemetryAgeMs)}) · Snapshot {formatTimestamp(props.snapshotGeneratedAt)}</>
                ) : props.freshnessState.telemetryStatus === "future_skew" ? (
                  <>Stale (telemetry clock skew) · Snapshot {formatTimestamp(props.snapshotGeneratedAt)}</>
                ) : (
                  <>Stale (telemetry unavailable) · Snapshot {formatTimestamp(props.snapshotGeneratedAt)}</>
                )}
              </span>
            ) : props.freshnessState.label === "Live · No activity" ? (
              <span>
                Live (no activity) · Snapshot {formatTimestamp(props.snapshotGeneratedAt)}
              </span>
            ) : (
              <span>
                Telemetry {formatUpdateAge(props.freshnessState.telemetryAgeMs ?? 0)} · Snapshot {formatTimestamp(props.snapshotGeneratedAt)}
              </span>
            )}
          </span>
        ) : (
          <span className="hidden 2xl:inline truncate text-text-subtle font-medium text-primary">
            {props.presentationContext.session?.lifecycle === "retained" ? (
              <>
                {props.presentationContext.session.observedAt ? `Observed ${formatTimestamp(props.presentationContext.session.observedAt)}` : null}
                {props.presentationContext.session.observedAt && props.presentationContext.session.closedAt ? " · " : null}
                {props.presentationContext.session.closedAt ? `Closed ${formatTimestamp(props.presentationContext.session.closedAt)}` : null}
                {!props.presentationContext.session.observedAt && !props.presentationContext.session.closedAt ? "Historical audit data" : null}
              </>
            ) : props.presentationContext.session?.lifecycle === "active" ? (
              <>
                {props.presentationContext.session.observedAt ? (
                  <>Observed {formatTimestamp(props.presentationContext.session.observedAt)} · Active investigation</>
                ) : (
                  <>Active investigation</>
                )}
              </>
            ) : (
              "Historical audit data"
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
            <span>Hierarchy edge</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-3 rounded-full bg-primary" aria-hidden="true" />
            <span>Attacker transition</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />
            <span>Entry points</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="flex h-3.5 w-3.5 items-center justify-center rounded bg-primary font-mono text-[8px] font-bold text-surface shadow-xs" aria-hidden="true">H</span>
            <span>Current hop</span>
          </span>
        </div>
      </div>
    </div>
  );
}
