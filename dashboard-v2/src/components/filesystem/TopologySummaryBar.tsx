import { formatTimestamp, formatUpdateAge, GRAPH_CALLOUT_LIMIT } from "./filesystemUtils";
import type { FreshnessState, TopologyDensityPreference } from "./filesystemUtils";
import type { TopologyPresentationContext } from "./TopologyCanvas";

interface BaseTopologySummaryBarProps {
  densityAnalysisHiddenNodes: number;
  densityAnalysisRenderedNodes: number;
  densityAnalysisTotalNodes: number;
  densityPreference: TopologyDensityPreference;
  effectiveSessionsLength: number;
  isSourcesTruncated: boolean;
  renderedSourcesCount: number;
  totalLiveSources: number;
  isSourcesExpanded: boolean;
  setIsSourcesExpanded: (val: boolean | ((prev: boolean) => boolean)) => void;
  totalOverlaps: number;
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

function formatEvidenceTimestamp(value: string | null | undefined): string {
  if (!value || typeof value !== "string" || !value.trim()) return "unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "unavailable";
  return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

export function TopologySummaryBar(props: TopologySummaryBarProps) {
  const {
    densityAnalysisHiddenNodes,
    densityAnalysisRenderedNodes,
    densityAnalysisTotalNodes,
    densityPreference,
    effectiveSessionsLength,
    isSourcesTruncated,
    renderedSourcesCount,
    totalLiveSources,
    isSourcesExpanded,
    setIsSourcesExpanded,
    totalOverlaps,
    presentationContext,
  } = props;
  return (
    <div className="flex min-h-11 shrink-0 flex-col items-start justify-between gap-2 border-t border-border px-4 py-3 text-xs text-text-muted select-none sm:min-h-11 sm:h-auto 2xl:h-11 sm:flex-row sm:items-center sm:px-5 sm:py-2 2xl:py-0">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1 text-xs 2xl:flex-nowrap sm:gap-3">
        {densityAnalysisHiddenNodes > 0 ? (
          <span className="shrink-0">
            <strong className="font-medium text-text">{densityAnalysisRenderedNodes}</strong> of{" "}
            <strong className="font-medium text-text">{densityAnalysisTotalNodes}</strong> paths{" "}
            <span className="text-text-subtle font-normal">
              ({densityAnalysisHiddenNodes} aggregated in branches; change density under View)
            </span>
          </span>
        ) : densityPreference !== "auto" ? (
          <span className="shrink-0">
            All <strong className="font-medium text-text">{densityAnalysisRenderedNodes}</strong> paths rendered
            <span className="text-text-subtle font-normal"> ({densityPreference} mode)</span>
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
              className="rounded border border-primary-border bg-primary-subtle px-1.5 py-0.5 text-xs font-semibold text-primary hover:bg-primary/20 transition-colors"
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
              className="rounded border border-border bg-surface px-1.5 py-0.5 text-xs text-text-muted hover:text-text transition-colors"
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
        {isLiveSummaryBarProps(props) ? (
          <>
            <span className="hidden 2xl:inline shrink-0 text-border" aria-hidden="true">·</span>
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
          </>
        ) : (
          <>
            <span className="shrink-0 text-border" aria-hidden="true">·</span>
            <span
              className="min-w-0 max-w-full whitespace-normal break-words text-text-subtle font-medium text-primary"
              aria-label="Audit evidence timestamps"
            >
              {props.presentationContext.session?.lifecycle === "retained" ? (
                <>
                  Observed {formatEvidenceTimestamp(props.presentationContext.session.observedAt)} · Closed {formatEvidenceTimestamp(props.presentationContext.session.closedAt)}
                </>
              ) : props.presentationContext.session?.lifecycle === "active" ? (
                <>
                  Observed {formatEvidenceTimestamp(props.presentationContext.session.observedAt)} · Active investigation
                </>
              ) : (
                "Historical audit data"
              )}
            </span>
          </>
        )}
      </div>

      <div className="flex max-w-full shrink-0 flex-wrap items-center gap-3.5">
        {totalOverlaps > 0 && (
          <span role="status" className="text-warning">
            {totalOverlaps} overlapping · use View → Auto arrange
          </span>
        )}

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1" aria-label="Topology map legend">
          <span className="flex items-center gap-1.5">
            <span className="h-px w-3 bg-border-strong" aria-hidden="true" />
            <span>Hierarchy edge</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-1.5 w-3 rounded-full bg-primary" aria-hidden="true" />
            <span>Source connection</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />
            <span>Active source</span>
          </span>
        </div>
      </div>
    </div>
  );
}
