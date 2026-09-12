"use client";

import { use, useCallback, useMemo, useState } from "react";
import { Activity, Check, ChevronRight, Copy, MapPin, Printer, Terminal } from "lucide-react";
import Link from "next/link";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";

import { SessionAnalysisPanels, type SessionAnalysisLoadState } from "@/components/threat/SessionAnalysisPanels";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { RegionState } from "@/components/ui/RegionState";
import {
  authoritativeEventTimestamp,
  chronologicalRecords,
  sessionLifecycleStatus,
} from "@/lib/session-analysis-semantics";
import { analystCommandText } from "@/lib/session-intelligence";
import { cn } from "@/lib/utils";

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

type DetailRecord = Record<string, unknown>;
type NextDistinctResult = {
  data: DetailRecord;
  state: SessionAnalysisLoadState;
  reason: string;
};
type BoundNextDistinctResult = NextDistinctResult & { sessionId: string };

function recordValue(value: unknown): DetailRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as DetailRecord
    : {};
}

function textValue(value: unknown, fallback = "Unavailable"): string {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return fallback;
}

function numberValue(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function commandInput(value: unknown): string | null {
  return analystCommandText(value);
}

function commandTimestamp(value: unknown): string {
  const item = recordValue(value);
  const timestamp = authoritativeEventTimestamp(item);
  if (typeof timestamp === "string" && timestamp.trim()) return timestamp;
  if (typeof timestamp === "number" && Number.isFinite(timestamp)) return String(timestamp);
  return "Not recorded";
}

function commandEventId(value: unknown): string {
  const item = recordValue(value);
  const eventId = item.event_id || item.eventid;
  return typeof eventId === "string" && eventId.trim() ? eventId : "event unavailable";
}

function nextDistinctState(result: NextDistinctResult): {
  label: string;
  tactic: string;
  context: string;
  updatedAt: string;
  source: string;
} {
  const data = recordValue(result.data);
  const freshness = recordValue(data.freshness);
  const rawState = textValue(data.state || data.status, result.state === "unavailable" ? "UNAVAILABLE" : "EMPTY_VALID").toUpperCase();
  const freshnessState = textValue(freshness.state, "").toUpperCase();
  const predictionStatus = textValue(data.prediction_status, "").toUpperCase();
  const reason = textValue(data.prediction_status_reason, "");
  const hasPrediction = typeof data.next_distinct_tactic === "string" && data.next_distinct_tactic.trim().length > 0;
  const isEnded = rawState === "SESSION_ENDED" || data.session_ended === true || data.is_ended === true;
  const isUnavailable = result.state === "unavailable" || rawState === "UNAVAILABLE" || freshnessState === "UNAVAILABLE";
  const isStale = rawState === "STALE" || predictionStatus === "STALE" || ["STALE", "EXPIRED", "TI_STALE", "TI_EXPIRED"].includes(freshnessState);
  const isInsufficient = !hasPrediction && (
    ["EMPTY_VALID", "WAITING_FOR_EVIDENCE", "NO_DATA"].includes(rawState)
    || predictionStatus.includes("INSUFFICIENT")
    || predictionStatus.includes("NO_TRUSTED_HISTORY")
    || reason.toLowerCase().includes("history")
  );
  const label = result.state === "loading"
    ? "LOADING"
    : isEnded
      ? "SESSION_ENDED"
    : isUnavailable
      ? "UNAVAILABLE"
      : isStale
        ? "STALE"
        : hasPrediction
          ? "PREDICTION"
          : isInsufficient
            ? "WAITING_FOR_EVIDENCE"
            : rawState;
  const tactic = result.state === "loading"
    ? "Reading Next-Distinct projection…"
    : isEnded
      ? "No session-end prediction"
    : hasPrediction
      ? textValue(data.next_distinct_tactic, "Prediction unavailable")
      : isUnavailable
        ? "Next-Distinct unavailable"
        : isStale
          ? "Prediction stale"
          : "WAITING_FOR_EVIDENCE";
  const context = reason || (isInsufficient
    ? "No trusted distinct-tactic progression is available yet."
    : isEnded
      ? "The final observed path is authoritative for this closed session; no session-end class is emitted."
      : "Read-only Next-Distinct PoC projection; no fallback inference path is used.");
  const updatedAt = textValue(
    data.timestamp || data.generated_at || data.updated_at || freshness.as_of || freshness.updated_at,
    "Not recorded",
  );
  return {
    label,
    tactic,
    context,
    updatedAt,
    source: textValue(data.source, "NEXT_DISTINCT_POC"),
  };
}

function PriorityNextTactic({ result, detail }: { result: NextDistinctResult; detail: DetailRecord }) {
  const view = nextDistinctState(result);
  const observedPath = Array.isArray(detail.observed_tactic_path)
    ? detail.observed_tactic_path.map(recordValue).filter((item) => textValue(item.tactic, ""))
    : [];
  const ended = sessionLifecycleStatus(detail) === "Closed" || view.label === "SESSION_ENDED";
  const stateClass = view.label === "PREDICTION"
    ? "border-success-border bg-success-subtle text-success"
    : view.label === "STALE"
      ? "border-warning-border bg-warning-subtle text-warning"
      : view.label === "UNAVAILABLE"
        ? "border-danger-border bg-danger-subtle text-danger"
        : "border-border bg-surface-subtle text-text-muted";

  return (
    <article className="ui-panel flex flex-col overflow-hidden">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border bg-surface px-5 py-4 sm:px-6">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
            <Activity className="h-4 w-4" aria-hidden="true" />
            Forecast / advisory
          </div>
          <h2 className="mt-1 text-base font-semibold sm:text-lg">Real-time Next Tactic</h2>
        </div>
        <span className={`ui-badge text-[11px] ${stateClass}`}>{view.label}</span>
      </div>
      <div className="flex flex-1 flex-col justify-between gap-5 p-5 sm:p-6">
        <div>
          <div className="mb-4 rounded-lg border border-border bg-surface-subtle p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-subtle">{ended ? "Final observed tactic path" : "Observed tactic path"}</p>
              <span className="ui-badge text-[11px]">{ended ? "SESSION ENDED" : "TRUSTED OBSERVATIONS"}</span>
            </div>
            {observedPath.length > 0 ? (
              <ol className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                {observedPath.map((phase, index) => (
                  <li key={`${index}-${textValue(phase.tactic, "phase")}`} className="flex items-center gap-2">
                    {index > 0 && <span className="text-text-subtle" aria-hidden="true">→</span>}
                    <span className="rounded border border-primary-border bg-primary-subtle px-2 py-1 font-medium text-text">{textValue(phase.tactic)}</span>
                  </li>
                ))}
              </ol>
            ) : <p className="mt-2 text-xs font-medium text-text-muted">WAITING_FOR_EVIDENCE</p>}
          </div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-text-subtle">Next distinct tactic / technique</p>
          <p className="mt-2 text-xl font-semibold tracking-tight text-text sm:text-2xl">{view.tactic}</p>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-text-muted">{view.context}</p>
        </div>
        <dl className="grid gap-3 border-t border-border pt-4 text-xs sm:grid-cols-3">
          <div>
            <dt className="font-semibold uppercase tracking-[0.1em] text-text-subtle">Prediction status</dt>
            <dd className="mt-1 text-text">{view.label}</dd>
          </div>
          <div>
            <dt className="font-semibold uppercase tracking-[0.1em] text-text-subtle">Source</dt>
            <dd className="mt-1 font-mono text-text">{view.source}</dd>
          </div>
          <div>
            <dt className="font-semibold uppercase tracking-[0.1em] text-text-subtle">Last updated</dt>
            <dd className="mt-1 font-mono text-text">{view.updatedAt}</dd>
          </div>
        </dl>
        <p className="text-[11px] text-text-subtle">NON-AUTHORITATIVE · Next-Distinct PoC only · not confirmed ATT&amp;CK truth</p>
      </div>
    </article>
  );
}

function SourceLocationPanel({
  originIp,
  country,
  city,
  lat,
  lon,
}: {
  originIp: string;
  country: string;
  city: string;
  lat: number;
  lon: number;
}) {
  const hasCoordinates = lat !== 0 && lon !== 0;
  const locationLabel = city !== "Unknown" && country !== "Unknown"
    ? `${city}, ${country}`
    : city !== "Unknown"
      ? city
      : country !== "Unknown"
        ? country
        : "Location unavailable";
  const resolutionLabel = hasCoordinates
    ? "Approximate location · contextual only"
    : country !== "Unknown"
      ? "Country / region context only"
      : "No usable coordinates are stored";

  return (
    <article className="ui-panel flex flex-col overflow-hidden">
      <div className="border-b border-border bg-surface px-5 py-4 sm:px-6">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
          <MapPin className="h-4 w-4" aria-hidden="true" />
          Contextual geography
        </div>
        <h2 className="mt-1 text-base font-semibold sm:text-lg">Source location</h2>
      </div>
      <div className="flex flex-1 flex-col p-4 sm:p-5">
        <div className="relative aspect-[16/8] min-h-28 max-h-40 overflow-hidden rounded-lg border border-border bg-surface-subtle" aria-label="Compact source location map">
          {hasCoordinates ? (
            <ComposableMap
              projection="geoMercator"
              projectionConfig={{ scale: 420, center: [lon, lat] }}
              style={{ width: "100%", height: "100%" }}
            >
              <Geographies geography={geoUrl}>
                {({ geographies }) => geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill="var(--map-land)"
                    stroke="var(--map-border)"
                    strokeWidth={0.5}
                    style={{
                      default: { outline: "none" },
                      hover: { fill: "var(--map-hover)", outline: "none" },
                      pressed: { fill: "var(--map-hover)", outline: "none" },
                    }}
                  />
                ))}
              </Geographies>
              <Marker coordinates={[lon, lat]}>
                <title>{`Approximate source location · ${locationLabel}`}</title>
                <circle r={5} fill="var(--primary)" stroke="var(--surface)" strokeWidth={2} />
              </Marker>
            </ComposableMap>
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 p-4 text-center">
              <MapPin className="h-5 w-5 text-text-subtle" aria-hidden="true" />
              <p className="text-sm font-medium text-text">Location unavailable</p>
              <p className="text-xs text-text-muted">{resolutionLabel}</p>
            </div>
          )}
        </div>
        <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-2">
          <div>
            <dt className="font-semibold uppercase tracking-[0.1em] text-text-subtle">Source IP</dt>
            <dd className="mt-1 break-all font-mono text-text">{originIp}</dd>
          </div>
          <div>
            <dt className="font-semibold uppercase tracking-[0.1em] text-text-subtle">Resolution</dt>
            <dd className="mt-1 text-text">{locationLabel}</dd>
          </div>
        </dl>
        <p className="mt-3 text-[11px] text-text-subtle">{resolutionLabel}. Location does not identify the attacker or explain the prediction.</p>
      </div>
    </article>
  );
}

export default function SessionDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const sessionId = resolvedParams.id;
  const { threats } = useThreatFeed();
  const threatData = useMemo(() => threats.find((threat) => threat.id === sessionId) ?? null, [sessionId, threats]);
  const [detailData, setDetailData] = useState<DetailRecord>({});
  const [liveCommands, setLiveCommands] = useState<unknown[]>([]);
  const [liveActive, setLiveActive] = useState(false);
  const [nextDistinct, setNextDistinct] = useState<BoundNextDistinctResult>({ sessionId, data: {}, state: "loading", reason: "" });
  const [copiedPayload, setCopiedPayload] = useState(false);
  const handleDetail = useCallback((data: DetailRecord) => {
    setDetailData(data);
  }, []);
  const handleLiveInteraction = useCallback((commands: unknown[], active: boolean) => {
    setLiveCommands(chronologicalRecords(commands));
    setLiveActive(active);
  }, []);
  const handleNextDistinct = useCallback((data: DetailRecord, state: SessionAnalysisLoadState, reason: string) => {
    setNextDistinct({ sessionId, data, state, reason });
  }, [sessionId]);

  const handleCopyPayload = async (text: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      setCopiedPayload(true);
      window.setTimeout(() => setCopiedPayload(false), 2000);
    } catch {
      setCopiedPayload(false);
    }
  };

  const detailOverview = recordValue(detailData.overview);
  const detailGeo = recordValue(detailOverview.geo);
  const originIp = threatData?.sourceIp || textValue(detailOverview.src_ip, "Unknown");
  const country = threatData?.geo.country || textValue(detailGeo.country, "Unknown");
  const city = threatData?.geo.city || textValue(detailGeo.city, "Unknown");
  const lat = threatData?.geo.lat ?? numberValue(detailGeo.lat);
  const lon = threatData?.geo.lon ?? numberValue(detailGeo.lon);
  const protocol = threatData?.protocol || textValue(detailOverview.protocol);
  const sensor = threatData?.sensor || textValue(detailOverview.sensor);
  const durationCandidate = textValue(detailOverview.duration || threatData?.duration);
  const capturedAt = threatData ? threatData.date + " " + threatData.time : textValue(detailOverview.start_time);
  const endTime = textValue(detailOverview.end_time, sessionLifecycleStatus(detailData) === "Active" ? "Active" : "Not recorded");
  const observedDurationSeconds = Math.max(0, Math.round(
    (Date.parse(textValue(detailOverview.end_time, "")) - Date.parse(textValue(detailOverview.start_time, ""))) / 1000,
  ));
  const duration = ["Active", "Closed"].includes(durationCandidate)
    ? (Number.isFinite(observedDurationSeconds) && observedDurationSeconds > 0 ? `${observedDurationSeconds}s` : "Not recorded")
    : durationCandidate;
  const sourcePort = textValue(detailOverview.src_port, "Not recorded");
  const destination = textValue(detailOverview.dst_ip || detailOverview.destination, sensor);
  const eventCount = textValue(detailOverview.event_count, String((Array.isArray(detailData.events) ? detailData.events : []).length));
  const sessionStatus = sessionLifecycleStatus(detailData);
  const payloadItems = liveCommands.map(commandInput).filter((value): value is string => Boolean(value));
  const fallbackPayload = analystCommandText(threatData?.payloadPreview) || "";
  const displayCommands = payloadItems.length > 0 ? payloadItems : (fallbackPayload ? [fallbackPayload] : []);
  const payload = displayCommands.join("\n");
  const hasCommandEvents = liveCommands.length > 0;
  const hasPayload = Boolean(payload);
  const commandTimestamps = liveCommands.map(commandTimestamp);
  const readableLiveCommands = liveCommands.map(commandInput).filter((value): value is string => Boolean(value));

  return (
    <div className="space-y-5 pb-10">
      {/* Print only banner */}
      <div className="hidden border-b-2 border-border pb-4 print:block">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-widest text-primary">Proactive Threat Intelligence Honeypot</p>
            <h1 className="mt-1 text-xl font-bold text-text">Forensic Incident Investigation Report</h1>
          </div>
          <div className="text-right font-mono text-xs text-text-muted">
            <div>Session ID: {sessionId}</div>
            <div>Generated: {capturedAt}</div>
          </div>
        </div>
      </div>

      <header className="flex flex-col gap-5 border-b border-border pb-6 print:hidden">
        <div className="flex flex-wrap items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">
          <Link href="/dashboard" className="text-primary hover:text-primary-action-hover">Session analysis</Link>
          <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
          <span className="font-mono text-text-subtle">{sessionId.substring(0, 12)}{sessionId.length > 12 ? "…" : ""}</span>
        </div>
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div>
            <h1 className="text-2xl font-semibold leading-8 tracking-tight sm:text-[28px] sm:leading-9">Session analysis</h1>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <span
                className={cn(
                  "ui-badge text-xs",
                  sessionStatus === "Closed" && "border-success-border bg-success-subtle text-success",
                  sessionStatus === "Active" && "border-primary-border bg-primary-subtle text-primary",
                )}
                aria-label={`Session lifecycle status: ${sessionStatus}`}
              >
                {sessionStatus}
              </span>
              <span className="text-sm text-text-muted">Observed session</span>
              <span className="font-mono text-xs text-text-subtle">ID {sessionId}</span>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => window.print()}
              className="ui-button ui-button-primary min-h-9 px-3 text-xs sm:text-sm"
              title="Print forensic incident report or save as PDF"
              aria-label="Print or export session forensic report"
            >
              <Printer className="h-4 w-4" aria-hidden="true" />
              Print / Export report
            </button>
          </div>
        </div>
      </header>

      <section aria-label="Session overview">
        <article className="ui-panel flex flex-col overflow-hidden">
          <div className="border-b border-border bg-surface px-5 py-4 sm:px-6">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
              <MapPin className="h-4 w-4" aria-hidden="true" />
              Session context
            </div>
            <h2 className="mt-1 text-base font-semibold sm:text-lg">Forensic target metadata</h2>
          </div>
          <div className="flex flex-1 flex-col p-5 sm:p-6">
            <dl className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Origin IP</dt>
                <dd className="mt-1 break-all font-mono text-base font-medium text-primary">{originIp}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Source port</dt>
                <dd className="mt-1 font-mono text-sm text-text">{sourcePort}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Protocol</dt>
                <dd className="mt-1 font-mono text-sm text-text">{protocol !== "Unavailable" ? protocol.toUpperCase() : "Unavailable"}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Capture sensor</dt>
                <dd className="mt-1 truncate font-mono text-sm text-text" title={sensor !== "Unavailable" ? sensor : undefined}>{sensor}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Destination / sensor</dt>
                <dd className="mt-1 truncate font-mono text-sm text-text" title={destination !== "Unavailable" ? destination : undefined}>{destination}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Start time</dt>
                <dd className="mt-1 font-mono text-sm text-text">{capturedAt}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">End time</dt>
                <dd className="mt-1 font-mono text-sm text-text">{endTime}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Duration</dt>
                <dd className="mt-1 font-mono text-sm text-text">{duration}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Observed evidence</dt>
                <dd className="mt-1 font-mono text-sm text-text">{eventCount} events · {liveCommands.length} commands</dd>
              </div>
            </dl>
          </div>
        </article>
      </section>

      <section className="grid grid-cols-1 items-start gap-5 xl:grid-cols-[minmax(0,7fr)_minmax(220px,3fr)] xl:gap-6" aria-label="Priority session context">
        <PriorityNextTactic detail={detailData} result={nextDistinct.sessionId === sessionId ? nextDistinct : { sessionId, data: {}, state: "loading", reason: "" }} />
        <SourceLocationPanel originIp={originIp} country={country} city={city} lat={lat} lon={lon} />
      </section>

      <section aria-label="Command evidence">
        <article className="ui-panel flex flex-col overflow-hidden">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-3 sm:px-5">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
                <Terminal className="h-4 w-4" aria-hidden="true" />
                Evidence stream
              </div>
              <h2 className="mt-1 text-base font-semibold sm:text-lg">Command activity</h2>
            </div>
            {hasCommandEvents || hasPayload ? (
              <div className="flex items-center gap-2">
                <span className="ui-badge border-success-border bg-success-subtle text-success text-xs">
                  {liveActive ? "Live stream" : "Persisted commands"}
                </span>
                {hasPayload && (
                  <button
                    type="button"
                    onClick={() => void handleCopyPayload(payload)}
                    className="ui-button min-h-8 px-2.5 text-xs"
                    title="Copy captured command evidence"
                    aria-label="Copy captured command evidence"
                  >
                    {copiedPayload ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
                    {copiedPayload ? "Copied" : "Copy commands"}
                  </button>
                )}
              </div>
            ) : (
              <span className="ui-badge">{liveActive ? "Waiting for commands" : "No command stream"}</span>
            )}
          </div>
          {hasCommandEvents || hasPayload ? (
            <div className="flex flex-1 flex-col overflow-hidden bg-surface-subtle/60 p-4 sm:p-5">
              <div className="flex select-none items-center gap-2 border-b border-border pb-3 text-xs text-text-subtle">
                <span className={liveActive ? "h-2 w-2 rounded-full bg-success" : "h-2 w-2 rounded-full bg-text-subtle"} aria-hidden="true" />
                <span>{sensor !== "Unavailable" ? "Capture sensor · " + sensor : "Captured command evidence"}</span>
              </div>
              <dl className="mt-4 grid gap-x-5 gap-y-3 border-b border-border pb-4 sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <dt className="text-[11px] uppercase tracking-[0.1em] text-text-subtle">Command events</dt>
                  <dd className="mt-1 font-mono text-sm text-text">{liveCommands.length || (payload ? 1 : 0)}</dd>
                </div>
                <div>
                  <dt className="text-[11px] uppercase tracking-[0.1em] text-text-subtle">Text availability</dt>
                  <dd className="mt-1 text-sm text-text">{readableLiveCommands.length > 0 ? `${readableLiveCommands.length} readable` : "Unavailable after pre-persistence redaction"}</dd>
                </div>
                <div>
                  <dt className="text-[11px] uppercase tracking-[0.1em] text-text-subtle">Activity</dt>
                  <dd className="mt-1 text-sm text-text">{liveActive ? "Session active" : "Session closed or idle"}</dd>
                </div>
                <div>
                  <dt className="text-[11px] uppercase tracking-[0.1em] text-text-subtle">Observed interval</dt>
                  <dd className="mt-1 font-mono text-xs text-text">{commandTimestamps.find((value) => value !== "Not recorded") || "Not recorded"} → {[...commandTimestamps].reverse().find((value) => value !== "Not recorded") || "Not recorded"}</dd>
                </div>
              </dl>
              {liveCommands.length > 0 ? (
                <ol className="mt-3 divide-y divide-border">
                  {liveCommands.map((command, index) => {
                    const text = commandInput(command);
                    const classificationTechnique = textValue(recordValue(command).classification_technique, "");
                    return (
                      <li key={`${index}-${commandEventId(command)}`} className="py-3 text-xs text-text first:pt-0 last:pb-0">
                        <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-text-subtle">
                          <span className="font-semibold uppercase tracking-[0.08em]">#{index + 1} · {commandEventId(command)}</span>
                          <span className="font-mono">{commandTimestamp(command)}</span>
                        </div>
                        <p className="mt-2 font-mono">{text || "Command text unavailable after pre-persistence privacy redaction."}</p>
                        {classificationTechnique && <p className="mt-2 text-[11px] text-text-muted">ATT&amp;CK mapping: <span className="font-mono text-text">{classificationTechnique}</span></p>}
                      </li>
                    );
                  })}
                </ol>
              ) : displayCommands.length > 0 ? (
                <ol className="mt-3 divide-y divide-border">
                  {displayCommands.map((command, index) => <li key={`${index}-${command}`} className="py-3 font-mono text-xs text-text first:pt-0 last:pb-0"><span className="mr-2 text-text-subtle">#{index + 1}</span>{command}</li>)}
                </ol>
              ) : (
                <p className="mt-4 rounded-lg border border-warning-border bg-warning-subtle p-4 text-sm text-warning">
                  Command records are present for this exact session, but the original text was removed before persistence. No text is being reconstructed or inferred.
                </p>
              )}
            </div>
          ) : (
            <div className="flex flex-1 items-center p-5 sm:p-6">
              <RegionState kind="empty" title="Interaction evidence unavailable" description="No persisted command events are available for this exact session." />
            </div>
          )}
        </article>

      </section>

      <SessionAnalysisPanels
        key={sessionId}
        sessionId={sessionId}
        onDetail={handleDetail}
        onLiveInteraction={handleLiveInteraction}
        onNextDistinct={handleNextDistinct}
      />
    </div>
  );
}
