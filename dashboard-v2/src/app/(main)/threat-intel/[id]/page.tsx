"use client";

import { use, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Check,
  ChevronRight,
  Copy,
  Download,
  Ghost,
  Lock,
  MapPin,
  Printer,
  Terminal,
  X,
  Globe,
  Server,
  Clock,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";

import { SessionAnalysisPanels, type SessionAnalysisLoadState } from "@/components/threat/SessionAnalysisPanels";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { RegionState } from "@/components/ui/RegionState";
import { TerminalStreamLoader } from "@/components/ui/loaders";
import { isDeceptionDecision, type DeceptionDecision, type DeceptionLure } from "@/lib/dashboardTypes";
import { useModalFocusTrap } from "@/lib/useModalFocusTrap";
import {
  authoritativeEventTimestamp,
  chronologicalRecords,
  sessionLifecycleStatus,
} from "@/lib/session-analysis-semantics";
import { analystCommandText } from "@/lib/session-intelligence";
import { hasValidHistoricalNextDistinct } from "@/lib/next-distinct-projection";
import { buildNextTacticChain } from "@/lib/next-tactic-chain";
import { cn } from "@/lib/utils";

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

type DetailRecord = Record<string, unknown>;
type NextDistinctResult = {
  sessionId: string;
  data: DetailRecord;
  state: SessionAnalysisLoadState;
  reason: string;
};
type BoundNextDistinctResult = NextDistinctResult;
type BoundCommandView = {
  sessionId: string;
  state: SessionAnalysisLoadState;
  reason: string;
  sensitive: true;
};

function recordValue(value: unknown): DetailRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as DetailRecord)
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
  historical: boolean;
} {
  const data = recordValue(result.data);
  const freshness = recordValue(data.freshness);
  const rawState = textValue(
    data.state || data.status,
    result.state === "unavailable" ? "UNAVAILABLE" : "EMPTY_VALID"
  ).toUpperCase();
  const freshnessState = textValue(freshness.state, "").toUpperCase();
  const predictionStatus = textValue(data.prediction_status, "").toUpperCase();
  const reason = textValue(data.prediction_status_reason, "");
  const isEnded = rawState === "SESSION_ENDED" || data.session_ended === true || data.is_ended === true;
  const isUnavailable = result.state === "unavailable" || rawState === "UNAVAILABLE" || freshnessState === "UNAVAILABLE";
  const isStale = rawState === "STALE" || predictionStatus === "STALE" || ["STALE", "EXPIRED", "TI_STALE", "TI_EXPIRED"].includes(freshnessState);
  const hasPrediction = !isEnded
    && typeof data.next_distinct_tactic === "string"
    && data.next_distinct_tactic.trim().length > 0;
  const hasHistoricalPrediction = isEnded
    && !isUnavailable
    && !isStale
    && hasValidHistoricalNextDistinct(data, result.sessionId);
  const isInsufficient = !hasPrediction && (
    ["EMPTY_VALID", "WAITING_FOR_EVIDENCE", "NO_DATA"].includes(rawState)
    || predictionStatus.includes("INSUFFICIENT")
    || predictionStatus.includes("NO_TRUSTED_HISTORY")
    || reason.toLowerCase().includes("history")
  );
  const label = result.state === "loading"
    ? "LOADING"
    : isUnavailable
      ? "UNAVAILABLE"
      : isStale
        ? "STALE"
        : isEnded
          ? "SESSION_ENDED"
        : hasPrediction
          ? "PREDICTION"
          : isInsufficient
            ? "WAITING_FOR_EVIDENCE"
            : rawState;
  const tactic = result.state === "loading"
    ? "Reading Next-Distinct projection…"
    : isUnavailable
      ? "Next-Distinct unavailable"
      : isStale
        ? "Prediction stale"
        : isEnded
          ? hasHistoricalPrediction
            ? textValue(data.stored_next_distinct_tactic, "No valid stored prediction")
            : "No valid stored prediction"
          : hasPrediction
            ? textValue(data.next_distinct_tactic, "Prediction unavailable")
            : "WAITING_FOR_EVIDENCE";
  const context = hasHistoricalPrediction
    ? "Historical advisory from the final, manifest-matched Next-Distinct sidecar result. The final observed tactic path remains authoritative; no session-end prediction is emitted."
    : reason || (isInsufficient
    ? "No trusted distinct-tactic progression is available yet."
    : isEnded
      ? "The final observed path is authoritative for this closed session; no session-end class is emitted."
      : "Read-only Next-Distinct PoC projection; no fallback inference path is used.");
  const updatedAt = textValue(
    data.timestamp || data.generated_at || data.updated_at || freshness.as_of || freshness.updated_at,
    "Not recorded"
  );

  return {
    label,
    tactic,
    context,
    updatedAt,
    source: textValue(data.source, "NEXT_DISTINCT_POC"),
    historical: hasHistoricalPrediction,
  };
}

function PriorityNextTactic({ result, detail }: { result: NextDistinctResult; detail: DetailRecord }) {
  const view = nextDistinctState(result);
  const observedPath = Array.isArray(detail.observed_tactic_path)
    ? detail.observed_tactic_path.map(recordValue).filter((item) => textValue(item.tactic, ""))
    : [];
  const ended = sessionLifecycleStatus(detail) === "Closed" || view.label === "SESSION_ENDED";
  const hasForecast = view.label === "PREDICTION" || view.historical;
  const tacticChain = buildNextTacticChain(
    observedPath,
    hasForecast ? { tactic: view.tactic, historical: view.historical } : null,
  );
  
  const stateClass =
    view.label === "PREDICTION"
      ? "text-emerald-600 bg-emerald-50 border-emerald-200"
      : view.label === "STALE"
      ? "text-orange-600 bg-orange-50 border-orange-200"
      : view.label === "UNAVAILABLE"
      ? "text-rose-600 bg-rose-50 border-rose-200"
      : "text-slate-500 bg-slate-100 border-slate-200";

  return (
    <article className="bg-white border border-slate-200 rounded-xl shadow-xs flex flex-col overflow-hidden h-full">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-6 py-4">
        <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-slate-800">
          <Activity className="h-3.5 w-3.5 text-blue-500" aria-hidden="true" />
          Priority Context — Forecast &amp; Advisory
        </div>
        <span className={cn("px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border", stateClass)}>
          {view.label}
        </span>
      </div>
      
      <div className="flex flex-col p-6 space-y-6 flex-1">
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
          <div className="flex items-center justify-between text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3">
            <span>Tactic chain</span>
            <span className="font-mono text-[9px] bg-white border border-slate-200 px-1.5 py-0.5 rounded">{ended ? "SESSION ENDED" : "OBSERVED → NEXT"}</span>
          </div>
          {tacticChain.length > 0 ? (
            <ol aria-label="Observed tactic chain and next tactic" className="flex flex-wrap items-center gap-2">
              {tacticChain.map((step, index) => (
                <li key={`${index}-${step.kind}-${step.tactic}`} className="flex items-center gap-1.5 text-[11px]">
                  {index > 0 && <span className="text-slate-400" aria-hidden="true">→</span>}
                  <span className={cn(
                    "rounded bg-white border px-2 py-1 font-bold shadow-sm",
                    step.kind === "observed" ? "border-slate-200 text-slate-700" : "border-emerald-200 bg-emerald-50 text-emerald-700"
                  )}>
                    {step.tactic}
                    <span className="ml-1.5 text-[9px] font-normal uppercase tracking-widest text-slate-400">({step.kind})</span>
                  </span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-[11px] text-slate-400 font-mono italic">WAITING_FOR_EVIDENCE</p>
          )}
          {tacticChain.length > 0 && !hasForecast && <p className="mt-2 text-[10px] text-slate-500">Observed chain only; no valid next-tactic prediction is stored.</p>}
          {hasForecast && observedPath.length === 0 && <p className="mt-2 text-[10px] text-slate-500">No trusted preceding tactic is recorded; the final node is advisory only.</p>}
        </div>

        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
              {view.historical ? "Last Recorded Next Tactic" : "Predicted Next Tactic"}
            </span>
            {view.historical && <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-orange-50 text-orange-600 border border-orange-200">Historical</span>}
          </div>
          <p className="text-2xl font-bold tracking-tight text-slate-800 sm:text-3xl">{view.tactic}</p>
          <p className="mt-3 text-xs leading-relaxed text-slate-500 border-l-2 border-orange-400 pl-3">
            {view.context}
          </p>
        </div>

        <div className="border-t border-slate-100 pt-4">
          <dl className="grid grid-cols-3 gap-4 text-[11px]">
            <div>
              <dt className="text-slate-400 font-bold uppercase tracking-wider mb-1">Status</dt>
              <dd className="font-bold text-slate-700">{view.label}</dd>
            </div>
            <div>
              <dt className="text-slate-400 font-bold uppercase tracking-wider mb-1">Model Source</dt>
              <dd className="font-mono text-slate-600 truncate">{view.source}</dd>
            </div>
            <div>
              <dt className="text-slate-400 font-bold uppercase tracking-wider mb-1">Updated</dt>
              <dd className="font-mono text-slate-500 truncate">{view.updatedAt}</dd>
            </div>
          </dl>
        </div>
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
  const locationLabel =
    city !== "Unknown" && country !== "Unknown"
      ? `${city}, ${country}`
      : city !== "Unknown"
      ? city
      : country !== "Unknown"
      ? country
      : "Location unavailable";
  const resolutionLabel = hasCoordinates
    ? "Approximate geolocation"
    : country !== "Unknown"
    ? "Country context only"
    : "No coordinates stored";

  return (
    <article className="bg-white border border-slate-200 rounded-xl shadow-xs flex flex-col overflow-hidden h-full">
      <div className="flex items-center justify-between border-b border-slate-100 px-6 py-4">
        <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-slate-800">
          <MapPin className="h-3.5 w-3.5 text-blue-500" aria-hidden="true" />
          Origin Geography
        </div>
        <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-slate-100 text-slate-500 border border-slate-200">
          {resolutionLabel}
        </span>
      </div>
      <div className="flex flex-1 flex-col p-6">
        <div
          className="relative h-44 w-full overflow-hidden rounded-lg border border-slate-200 bg-slate-50"
          aria-label="Compact source location map"
        >
          {hasCoordinates ? (
            <ComposableMap
              projection="geoMercator"
              projectionConfig={{ scale: 380, center: [lon, lat] }}
              style={{ width: "100%", height: "100%" }}
            >
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill="#E2E8F0"
                      stroke="#CBD5E1"
                      strokeWidth={0.5}
                      className="outline-none"
                    />
                  ))
                }
              </Geographies>
              <Marker coordinates={[lon, lat]}>
                <title>{`Source location: ${locationLabel}`}</title>
                <circle r={8} fill="#F97316" opacity={0.3} className="animate-ping" />
                <circle r={5} fill="#F97316" stroke="#FFFFFF" strokeWidth={2} />
              </Marker>
            </ComposableMap>
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 p-4 text-center">
              <MapPin className="h-6 w-6 text-slate-300" aria-hidden="true" />
              <p className="text-xs font-bold text-slate-600">Coordinates Unavailable</p>
              <p className="text-[10px] text-slate-400">{resolutionLabel}</p>
            </div>
          )}
        </div>
        <dl className="mt-5 grid grid-cols-2 gap-4 border-t border-slate-100 pt-4 text-[11px]">
          <div>
            <dt className="text-slate-400 font-bold uppercase tracking-wider mb-1">Attacker IP</dt>
            <dd className="font-mono font-bold text-orange-600 truncate">{originIp}</dd>
          </div>
          <div>
            <dt className="text-slate-400 font-bold uppercase tracking-wider mb-1">Location</dt>
            <dd className="font-bold text-slate-700 truncate">{locationLabel}</dd>
          </div>
        </dl>
      </div>
    </article>
  );
}

type DeceptionLoadState = "loading" | "ready" | "empty" | "unavailable";
interface DeceptionResult {
  state: DeceptionLoadState;
  data: DeceptionDecision | null;
  reason: string;
}

const DECEPTION_TIMEOUT_MS = 7_000;
const DECEPTION_POLL_MS = 15_000;

async function fetchDeceptionDecision(ip: string): Promise<DeceptionResult> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), DECEPTION_TIMEOUT_MS);
  try {
    const response = await fetch(`/api/deception?ip=${encodeURIComponent(ip)}`, {
      cache: "no-store",
      signal: controller.signal,
    });
    if (response.status === 404) {
      return { state: "empty", data: null, reason: "No deception decision recorded for this origin IP." };
    }
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      return { state: "unavailable", data: null, reason: "Deception service returned a non-JSON response" };
    }
    if (!response.ok) {
      return {
        state: "unavailable",
        data: null,
        reason: textValue(recordValue(parsed).error, `HTTP ${response.status}`),
      };
    }
    if (!isDeceptionDecision(parsed)) {
      return { state: "unavailable", data: null, reason: "Deception response did not match the expected shape" };
    }
    return { state: "ready", data: parsed, reason: "" };
  } catch (error: unknown) {
    const aborted = error instanceof Error && error.name === "AbortError";
    return {
      state: "unavailable",
      data: null,
      reason: aborted ? "Deception panel request timed out" : "Local BFF unavailable",
    };
  } finally {
    window.clearTimeout(timeout);
  }
}

function DeceptionStateFetcher({ ip }: { ip: string }) {
  const [result, setResult] = useState<DeceptionResult>({ state: "loading", data: null, reason: "" });

  useEffect(() => {
    let cancelled = false;

    const load = () => {
      void fetchDeceptionDecision(ip).then((value) => {
        if (!cancelled) setResult(value);
      });
    };

    load();
    // Pi syncs Track B decisions into Mongo on its own cron (currently every 1 minute);
    // poll faster than that so the panel picks up a new sync within one interval without
    // a full page reload.
    const intervalId = window.setInterval(load, DECEPTION_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [ip]);

  return <DeceptionPanel result={result} />;
}

function LureDetailModal({ lure, onClose }: { lure: DeceptionLure | null; onClose: () => void }) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const open = lure !== null;
  useModalFocusTrap(open, dialogRef);

  useEffect(() => {
    if (!open) return;
    const oldOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = oldOverflow;
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onClose]);

  if (!lure) return null;

  return (
    <div
      data-open="true"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
      className="pti-modal-overlay fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4 backdrop-blur-sm"
      role="presentation"
    >
      <div
        ref={dialogRef}
        data-open="true"
        className="pti-modal-panel max-h-[85vh] w-full max-w-lg overflow-y-auto rounded-xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="lure-detail-title"
        tabIndex={-1}
      >
        <header className="flex items-start justify-between gap-4 border-b border-slate-100 bg-slate-50 px-6 py-4">
          <div className="min-w-0">
            <h3 id="lure-detail-title" className="truncate text-sm font-bold text-slate-800">
              {lure.target}
            </h3>
            <p className="mt-1 text-[10px] text-slate-500 font-mono uppercase">Served to attacker at {lure.at}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded bg-white border border-slate-200 p-1 text-slate-400 hover:text-slate-600 hover:bg-slate-50"
            aria-label="Close lure detail"
            data-autofocus
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </header>
        <div className="p-6">
          <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-slate-200 bg-slate-50 p-4 font-mono text-[11px] text-slate-700 leading-relaxed">
            {lure.content}
          </pre>
        </div>
      </div>
    </div>
  );
}

const PHASE_LABELS: Record<string, string> = {
  Reconnaissance: "Reconnaissance (scanning/probing)",
  Weaponization: "Weaponization",
  Delivery: "File delivery",
  Exploitation: "Exploitation",
  Installation: "Installation",
  Command_and_Control: "Command & control",
  Actions_on_Objectives: "Objective execution",
};

function phaseLabel(phase: string): string {
  return PHASE_LABELS[phase] ?? phase.replace(/_/g, " ");
}

const ACTION_LABELS: Record<string, string> = {
  deceive: "Served decoy content to attacker",
  observe: "Observed only (passive monitoring)",
};

function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action.replace(/_/g, " ");
}

function DeceptionPanel({ result }: { result: DeceptionResult }) {
  const { state, data, reason } = result;
  const [selectedLure, setSelectedLure] = useState<DeceptionLure | null>(null);

  // Each lure is pre-generated in both "deceive" and "normal" variants ahead of the
  // decision; only the one matching the latest recorded action was actually served.
  // Mirrors get_content_mode() in colab_upload/3_serve/session_prompt_builder.py:
  // action "deceive" -> content_type "deceive"; any other action (e.g. "lure", "delay")
  // -> content_type "normal". The action string itself is NOT a content_type.
  const latestAction = data && data.actions.length > 0 ? data.actions[data.actions.length - 1].action : null;
  const servedContentType = latestAction === null ? null : latestAction === "deceive" ? "deceive" : "normal";
  const servedLures = data ? data.lures.filter((lure) => !servedContentType || lure.content_type === servedContentType) : [];

  return (
    <article className="bg-white border border-slate-200 rounded-xl shadow-xs flex flex-col overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-6 py-4">
        <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-slate-800">
          <Ghost className="h-4 w-4 text-orange-500" aria-hidden="true" />
          Active Deception Engine
        </div>
        {state === "ready" && data && (
          <span
            className={cn(
              "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border",
              data.attacker_type === "APT" ? "bg-rose-50 text-rose-600 border-rose-200" :
              data.attacker_type === "Bot" ? "bg-slate-100 text-slate-500 border-slate-200" :
              "bg-orange-50 text-orange-600 border-orange-200"
            )}
          >
            {data.attacker_type}
            {data.attacker_type_locked && <Lock className="ml-1 inline h-3 w-3" aria-hidden="true" />}
          </span>
        )}
      </div>
      <div className="flex flex-1 flex-col p-6">
        {state === "loading" && <RegionState kind="loading" title="Loading deception state…" />}
        {state === "empty" && (
          <RegionState kind="empty" title="No deception decision recorded" description={reason} />
        )}
        {state === "unavailable" && (
          <RegionState kind="error" title="Deception state unavailable" description={reason} />
        )}
        {state === "ready" && data && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[11px] font-bold text-slate-500 uppercase tracking-widest border-b border-slate-100 pb-4">
              <span className="flex items-center gap-2">
                <Activity className="h-3.5 w-3.5 text-blue-500" />
                Phase: <span className="text-slate-800">{data.phase}</span>
              </span>
              <span className="flex items-center gap-2">
                <Terminal className="h-3.5 w-3.5 text-slate-400" />
                Commands: <span className="font-mono text-slate-700">{data.command_count}</span>
              </span>
            </div>

            <div className="grid items-start gap-6 sm:grid-cols-2">
              <div className="border border-slate-200 rounded-xl bg-slate-50 p-4 shadow-sm">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3 flex items-center gap-1.5">
                  <Terminal className="h-3.5 w-3.5" />
                  System Decisions ({data.actions.length})
                </p>
                {data.actions.length > 0 ? (
                  <ol className="ui-scroll-region max-h-52 divide-y divide-slate-200/50 overflow-y-auto pr-2">
                    {data.actions.map((action, index) => (
                      <li key={`${index}-${action.at}`} className="py-2.5 text-xs">
                        <div className="flex items-start justify-between gap-2 mb-1">
                          <span className="font-bold text-slate-700">{phaseLabel(action.phase)}</span>
                          <span className="font-mono text-slate-400 text-[10px]">{action.at.slice(11, 19)}</span>
                        </div>
                        <p className="text-slate-500">{actionLabel(action.action)}</p>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p className="text-[11px] text-slate-400 font-mono p-2 bg-white rounded text-center border border-dashed border-slate-200">No decisions recorded.</p>
                )}
              </div>

              <div className="border border-slate-200 rounded-xl bg-slate-50 p-4 shadow-sm">
                <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-3 flex items-center gap-1.5">
                  <Ghost className="h-3.5 w-3.5" />
                  Decoy content prepared for this attacker ({servedLures.length})
                </p>
                {servedLures.length > 0 ? (
                  <ol className="ui-scroll-region max-h-52 divide-y divide-slate-200/50 overflow-y-auto pr-2">
                    {servedLures.map((lure, index) => (
                      <li key={`${index}-${lure.at}`} className="py-1">
                        <button
                          type="button"
                          onClick={() => setSelectedLure(lure)}
                          className="flex w-full items-center justify-between gap-3 rounded px-2 py-2 text-left text-xs transition-colors hover:bg-white"
                        >
                          <span className="truncate font-bold text-slate-700">
                            {lure.target}{" "}
                            <span className="text-slate-400 font-normal font-mono text-[9px] uppercase tracking-wider ml-1 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200">
                              {lure.content_type}
                            </span>
                          </span>
                          <span className="font-mono text-slate-400 text-[10px] shrink-0">{lure.at.slice(11, 19)}</span>
                        </button>
                      </li>
                    ))}
                  </ol>
                ) : !data.attacker_type_locked ? (
                  <p className="text-[11px] text-slate-500 p-2 bg-white rounded border border-dashed border-slate-200">
                    Still in Part 1 (attacker type not locked yet) — Part 2 decoy files will start preparing automatically once classification locks.
                  </p>
                ) : (
                  <p className="text-[11px] text-slate-400 font-mono p-2 bg-white rounded text-center border border-dashed border-slate-200">None prepared yet.</p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
      <LureDetailModal lure={selectedLure} onClose={() => setSelectedLure(null)} />
    </article>
  );
}

// ----------------------------------------------------------------------
// MAIN PAGE COMPONENT
// ----------------------------------------------------------------------

const IN_PAGE_TABS = [
  { key: "session-overview", selector: "#session-overview", label: "Metadata" },
  { key: "priority-context", selector: "#priority-context", label: "Forecast & Location" },
  { key: "command-evidence", selector: "#command-evidence", label: "Command Stream" },
  { key: "deception-state", selector: "#deception-state", label: "Deception" },
  { key: "session-evidence", selector: 'section[aria-label="Session evidence"]', label: "Activity Evidence" },
  { key: "classification", selector: 'section[aria-label="Classification evidence"]', label: "Trusted Observations" },
  { key: "ensemble", selector: 'section[aria-label="Model ensemble evidence"]', label: "Shadow Corroboration" },
  { key: "analyst-assessment", selector: 'section[aria-label="Analyst assessment"]', label: "Analyst Assessment" },
  { key: "ti-context", selector: 'section[aria-label="Threat intelligence context"]', label: "TI Context" },
  { key: "evidence-ledger", selector: 'section[aria-label="Evidence ledger"]', label: "Evidence Ledger" },
];

export default function SessionDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const sessionId = resolvedParams.id;
  const { threats } = useThreatFeed();
  const threatData = useMemo(() => threats.find((threat) => threat.id === sessionId) ?? null, [sessionId, threats]);

  const [boundDetail, setBoundDetail] = useState<{ sessionId: string; data: DetailRecord }>(() => ({ sessionId, data: {} }));
  const [liveCommandState, setLiveCommandState] = useState<{ sessionId: string; commands: unknown[]; active: boolean }>(
    () => ({ sessionId, commands: [], active: false }),
  );
  const [commandView, setCommandView] = useState<BoundCommandView>(() => ({ sessionId, state: "loading", reason: "", sensitive: true }));
  const [nextDistinct, setNextDistinct] = useState<BoundNextDistinctResult>({ sessionId, data: {}, state: "loading", reason: "" });
  const [copiedPayload, setCopiedPayload] = useState(false);

  const [activeTab, setActiveTab] = useState("session-overview");

  const detailData = boundDetail.sessionId === sessionId ? boundDetail.data : {};
  const currentLiveCommandState = liveCommandState.sessionId === sessionId
    ? liveCommandState
    : { sessionId, commands: [], active: false };

  const handleDetail = useCallback((data: DetailRecord) => {
    setBoundDetail({ sessionId, data });
  }, [sessionId]);
  
  const handleLiveInteraction = useCallback((commands: unknown[], active: boolean, view: Omit<BoundCommandView, "sessionId">) => {
    setLiveCommandState({ sessionId, commands: chronologicalRecords(commands), active });
    setCommandView({ sessionId, ...view });
  }, [sessionId]);

  const handleNextDistinct = useCallback(
    (data: DetailRecord, state: SessionAnalysisLoadState, reason: string) => {
      setNextDistinct({ sessionId, data, state, reason });
    },
    [sessionId]
  );

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

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const matchedTab = IN_PAGE_TABS.find(
              (tab) =>
                (entry.target.id && `#${entry.target.id}` === tab.selector) ||
                (entry.target.getAttribute("aria-label") &&
                  `section[aria-label="${entry.target.getAttribute("aria-label")}"]` === tab.selector)
            );
            if (matchedTab) {
              setActiveTab(matchedTab.key);
              const navElement = document.getElementById("sticky-nav-scroll");
              const activeTabElement = document.getElementById(`tab-${matchedTab.key}`);
              if (navElement && activeTabElement) {
                const navRect = navElement.getBoundingClientRect();
                const tabRect = activeTabElement.getBoundingClientRect();
                if (tabRect.left < navRect.left || tabRect.right > navRect.right) {
                  activeTabElement.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
                }
              }
            }
          }
        });
      },
      { rootMargin: "-120px 0px -60% 0px", threshold: 0 }
    );

    const attachObserver = () => {
      IN_PAGE_TABS.forEach((tab) => {
        const el = document.querySelector(tab.selector);
        if (el) observer.observe(el);
      });
    };

    attachObserver();
    const interval = setInterval(attachObserver, 1000);
    const timeout = setTimeout(() => clearInterval(interval), 10000);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
      observer.disconnect();
    };
  }, [detailData]);

  const scrollToSection = (e: React.MouseEvent<HTMLAnchorElement>, selector: string) => {
    e.preventDefault();
    const el = document.querySelector(selector);
    if (el) {
      const y = el.getBoundingClientRect().top + window.scrollY - 130;
      window.scrollTo({ top: y, behavior: "smooth" });
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
  const endTime = textValue(
    detailOverview.end_time,
    sessionLifecycleStatus(detailData) === "Active" ? "Active" : "Not recorded"
  );
  const observedDurationSeconds = Math.max(
    0,
    Math.round(
      (Date.parse(textValue(detailOverview.end_time, "")) - Date.parse(textValue(detailOverview.start_time, ""))) / 1000
    )
  );
  const duration = ["Active", "Closed"].includes(durationCandidate)
    ? Number.isFinite(observedDurationSeconds) && observedDurationSeconds > 0
      ? `${observedDurationSeconds}s`
      : "Not recorded"
    : durationCandidate;
  const sourcePort = textValue(detailOverview.src_port, "Not recorded");
  const destination = textValue(detailOverview.dst_ip || detailOverview.destination, sensor);
  const eventCount = textValue(
    detailOverview.event_count,
    String((Array.isArray(detailData.events) ? detailData.events : []).length)
  );
  const sessionStatus = sessionLifecycleStatus(detailData);
  
  const currentCommandView = commandView.sessionId === sessionId
    ? commandView
    : { sessionId, state: "loading" as const, reason: "", sensitive: true as const };
  const publicEvents = Array.isArray(detailData.events)
    ? detailData.events
    : Array.isArray(detailData.events_table_rows) ? detailData.events_table_rows : [];
  const publicCommandCount = publicEvents.filter((value) => recordValue(value).command_event === true).length;
  const sessionCommands = currentLiveCommandState.commands.filter((value) => recordValue(value).session_id === sessionId);
  const liveActive = currentLiveCommandState.active;
  const hasCommandEvents = sessionCommands.length > 0 || publicCommandCount > 0;
  const commandCount = sessionCommands.length || publicCommandCount;
  const commandTimestamps = sessionCommands.map(commandTimestamp);
  const readableLiveCommands = sessionCommands.map(commandInput).filter((value): value is string => Boolean(value));
  
  const textAvailability = readableLiveCommands.length > 0
    ? `${readableLiveCommands.length} readable`
    : currentCommandView.state === "unavailable" || currentCommandView.state === "limited"
      ? currentCommandView.reason
      : currentCommandView.state === "empty"
        ? "No retained command input"
        : currentCommandView.state === "ready"
          ? "No command input stored"
          : "Loading Admin-only command evidence";
          
  const payload = readableLiveCommands.join("\n");
  const hasPayload = Boolean(payload);

  const hasStoredReport = Array.isArray(detailData.reports) && detailData.reports.length > 0;
  const reportDownloadHref = `/api/session-report?session_id=${encodeURIComponent(sessionId)}`;

  return (
    <div className="space-y-6 pb-12 font-sans bg-[#F9FAFB] min-h-screen text-[#1E293B] relative -mx-4 px-4 sm:-mx-6 sm:px-6 py-6 lg:-mx-8 lg:px-8">
      <style dangerouslySetInnerHTML={{ __html: `
        #sticky-nav-scroll::-webkit-scrollbar { display: none; }
      `}} />

      {/* Print only banner */}
      <div className="hidden border-b-2 border-slate-200 pb-4 print:block">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">PTI-Honeypot</p>
            <h1 className="mt-1 text-xl font-bold text-slate-800">Forensic Incident Investigation Report</h1>
          </div>
          <div className="text-right font-mono text-[10px] text-slate-500">
            <div>Session ID: {sessionId}</div>
            <div>Generated: {capturedAt}</div>
          </div>
        </div>
      </div>

      <header className="flex flex-col gap-4 pb-2 print:hidden">
        <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest text-slate-400">
          <Link href="/dashboard" className="text-blue-600 hover:underline">
            Dashboard
          </Link>
          <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
          <Link href="/threat-intel" className="text-blue-600 hover:underline">
            Threat Intelligence
          </Link>
          <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
          <span className="font-mono text-slate-500 bg-slate-200/50 px-1.5 py-0.5 rounded border border-slate-200">
            {sessionId.slice(0, 14)}...
          </span>
        </div>

        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-800 sm:text-3xl">Session Analysis</h1>
            <div className="mt-2.5 flex flex-wrap items-center gap-3">
              <span
                className={cn(
                  "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border",
                  sessionStatus === "Closed" ? "bg-emerald-50 text-emerald-600 border-emerald-200" : "bg-blue-50 text-blue-600 border-blue-200 animate-pulse"
                )}
              >
                {sessionStatus}
              </span>
              <span className="text-[11px] font-bold uppercase tracking-widest text-slate-500">Exact Session ID:</span>
              <span className="font-mono text-[11px] bg-white px-2 py-0.5 rounded border border-slate-200 text-slate-700 font-medium shadow-xs">{sessionId}</span>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={() => window.print()}
              className="flex items-center gap-1.5 rounded-md border border-orange-600 bg-orange-500 px-3 py-1.5 text-xs font-bold text-white shadow-xs hover:bg-orange-600 transition-all"
              title="Print report or save as PDF"
            >
              <Printer className="h-3.5 w-3.5" aria-hidden="true" />
              PRINT REPORT
            </button>
            <a
              href={hasStoredReport ? reportDownloadHref : undefined}
              download="session-threat-report.pdf"
              aria-disabled={!hasStoredReport}
              className={cn(
                "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-bold shadow-xs transition-all border",
                hasStoredReport
                  ? "bg-orange-500 text-white border-orange-600 hover:bg-orange-600"
                  : "pointer-events-none opacity-50 bg-slate-100 text-slate-400 border-slate-200"
              )}
            >
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              DOWNLOAD PDF
            </a>
          </div>
        </div>
      </header>

      {/* STICKY NAV */}
      <nav
        id="sticky-nav-scroll"
        className="sticky top-16 z-30 bg-white/95 backdrop-blur-md border border-slate-200 rounded-lg print:hidden flex gap-1 p-1.5 overflow-x-auto shadow-sm"
        style={{ scrollbarWidth: "none", msOverflowStyle: "none" }}
        aria-label="In-page navigation"
      >
        {IN_PAGE_TABS.map((tab) => (
          <a
            key={tab.key}
            id={`tab-${tab.key}`}
            href={tab.selector.startsWith("#") ? tab.selector : `#${tab.key}`}
            onClick={(e) => scrollToSection(e, tab.selector)}
            className={cn(
              "whitespace-nowrap rounded-md px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider transition-colors select-none",
              activeTab === tab.key
                ? "bg-orange-500 text-white shadow-sm"
                : "text-slate-500 hover:bg-slate-100 hover:text-slate-800"
            )}
          >
            {tab.label}
          </a>
        ))}
      </nav>

      {/* Target Metadata Section: 3-Column Design จากรูปเป๊ะๆ */}
      <section id="session-overview" aria-label="Session overview" className="scroll-mt-32">
        <article className="bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
          <div className="border-b border-slate-100 px-6 py-4">
            <h2 className="text-[11px] font-bold uppercase tracking-widest text-slate-500 flex items-center gap-2">
              <Activity className="h-3.5 w-3.5 text-blue-500" />
              FORENSIC SESSION METADATA
            </h2>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-slate-100 gap-6 md:gap-0">
              {/* Group 1: Network Origin */}
              <div className="md:pr-8">
                <span className="text-[10px] font-bold text-slate-800 uppercase tracking-widest flex items-center gap-2 mb-4">
                  <Globe className="h-3.5 w-3.5 text-slate-500" /> NETWORK ORIGIN
                </span>
                <dl className="space-y-4 text-[11px]">
                  <div className="flex justify-between items-center">
                    <dt className="text-slate-500 font-medium">Origin IP</dt>
                    <dd className="font-mono font-bold text-orange-600 bg-orange-50 px-2 py-0.5 rounded border border-orange-100">
                      {originIp}
                    </dd>
                  </div>
                  <div className="flex justify-between items-center">
                    <dt className="text-slate-500 font-medium">Source Port</dt>
                    <dd className="font-mono text-slate-800">{sourcePort}</dd>
                  </div>
                  <div className="flex justify-between items-center">
                    <dt className="text-slate-500 font-medium">Protocol</dt>
                    <dd className="font-mono font-bold text-slate-800 uppercase">{protocol}</dd>
                  </div>
                </dl>
              </div>

              {/* Group 2: Target & Sensor */}
              <div className="md:px-8">
                <span className="text-[10px] font-bold text-slate-800 uppercase tracking-widest flex items-center gap-2 mb-4">
                  <Server className="h-3.5 w-3.5 text-slate-500" /> HONEYPOT SENSOR
                </span>
                <dl className="space-y-4 text-[11px]">
                  <div className="flex justify-between items-center">
                    <dt className="text-slate-500 font-medium">Decoy Sensor</dt>
                    <dd className="font-bold text-slate-800 truncate max-w-[150px]" title={sensor}>{sensor}</dd>
                  </div>
                  <div className="flex justify-between items-center">
                    <dt className="text-slate-500 font-medium">Destination</dt>
                    <dd className="font-mono text-slate-800 truncate max-w-[150px]">{destination}</dd>
                  </div>
                  <div className="flex justify-between items-center">
                    <dt className="text-slate-500 font-medium">Captured Evidence</dt>
                    <dd className="font-medium text-slate-800 bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
                      {eventCount} events · {commandCount} commands
                    </dd>
                  </div>
                </dl>
              </div>

              {/* Group 3: Observation Timeline */}
              <div className="md:pl-8">
                <span className="text-[10px] font-bold text-slate-800 uppercase tracking-widest flex items-center gap-2 mb-4">
                  <Clock className="h-3.5 w-3.5 text-slate-500" /> TIMELINE &amp; DURATION
                </span>
                <dl className="space-y-4 text-[11px]">
                  <div className="flex justify-between items-center">
                    <dt className="text-slate-500 font-medium">Started At</dt>
                    <dd className="font-mono text-slate-800">{capturedAt}</dd>
                  </div>
                  <div className="flex justify-between items-center">
                    <dt className="text-slate-500 font-medium">Ended At</dt>
                    <dd className="font-mono text-slate-800">{endTime}</dd>
                  </div>
                  <div className="flex justify-between items-center">
                    <dt className="text-slate-500 font-medium">Active Dwell Time</dt>
                    <dd className="font-mono font-bold text-slate-800 bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
                      {duration}
                    </dd>
                  </div>
                </dl>
              </div>
            </div>
          </div>
        </article>
      </section>

      {/* Row: Real-Time Next Tactic & Geographic Origin */}
      <section id="priority-context" className="grid grid-cols-1 gap-6 lg:grid-cols-12 lg:items-stretch scroll-mt-32" aria-label="Priority session context">
        <div className="lg:col-span-8">
          <PriorityNextTactic
            detail={detailData}
            result={nextDistinct.sessionId === sessionId ? nextDistinct : { sessionId, data: {}, state: "loading", reason: "" }}
          />
        </div>
        <div className="lg:col-span-4">
          <SourceLocationPanel originIp={originIp} country={country} city={city} lat={lat} lon={lon} />
        </div>
      </section>

      {/* Command Activity Stream: Terminal Style */}
      <section id="command-evidence" aria-label="Command evidence" className="scroll-mt-32 print:hidden">
        <article className="bg-white border border-slate-200 rounded-xl shadow-xs flex flex-col overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 px-6 py-4">
            <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-slate-800">
              <Terminal className="h-3.5 w-3.5 text-blue-500" aria-hidden="true" />
              COMMAND EVIDENCE — Command Activity
            </div>
            <div className="flex items-center gap-3">
              <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-slate-100 text-slate-500 border border-slate-200">
                {liveActive ? "Active Session Stream" : "Persisted Log"}
              </span>
              {hasPayload && (
                <button
                  type="button"
                  onClick={() => void handleCopyPayload(payload)}
                  className="flex items-center gap-1.5 rounded bg-slate-100 border border-slate-200 px-2 py-1 text-[10px] font-bold text-slate-600 hover:bg-slate-200 transition-colors"
                >
                  {copiedPayload ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copiedPayload ? "COPIED" : "COPY"}</span>
                </button>
              )}
            </div>
          </div>

          {hasCommandEvents || hasPayload ? (
            <div className="p-6">
              
              <div className="flex select-none items-center gap-2 border-b border-slate-100 pb-3 text-xs text-slate-500 mb-4">
                <span className={liveActive ? "h-2 w-2 rounded-full bg-emerald-500" : "h-2 w-2 rounded-full bg-slate-400"} aria-hidden="true" />
                <span className="font-bold">{sensor !== "Unavailable" ? "Capture sensor · " + sensor : "Captured command evidence"}</span>
              </div>
              <dl className="grid gap-x-5 gap-y-3 border-b border-slate-100 pb-4 sm:grid-cols-2 lg:grid-cols-4 mb-4">
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Command events</dt>
                  <dd className="mt-1 font-mono text-sm text-slate-700">{commandCount}</dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Text availability</dt>
                  <dd className="mt-1 text-sm text-slate-700 font-semibold">{textAvailability}</dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Activity</dt>
                  <dd className="mt-1 text-sm text-slate-700 font-semibold">{liveActive ? "Session active" : "Session closed or idle"}</dd>
                </div>
                <div>
                  <dt className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Observed interval</dt>
                  <dd className="mt-1 font-mono text-xs text-slate-500">{commandTimestamps.find((value) => value !== "Not recorded") || "Not recorded"} → {[...commandTimestamps].reverse().find((value) => value !== "Not recorded") || "Not recorded"}</dd>
                </div>
              </dl>

              {/* Terminal Block */}
              {sessionCommands.length > 0 ? (
                <div className="rounded-xl border border-slate-800 bg-[#0B1220] shadow-xl overflow-hidden mt-4">
                  <div className="flex items-center justify-between border-b border-slate-800/80 bg-[#141d2d] px-4 py-3">
                    <div className="flex items-center gap-4">
                      <div className="flex gap-1.5">
                        <span className="h-3 w-3 rounded-full bg-rose-500"></span>
                        <span className="h-3 w-3 rounded-full bg-amber-500"></span>
                        <span className="h-3 w-3 rounded-full bg-emerald-500"></span>
                      </div>
                      <span className="font-mono text-[11px] text-slate-400">
                        attacker@honeypot:~#
                      </span>
                    </div>
                    <span className="font-mono text-[10px] text-slate-500 hidden sm:inline">
                      {commandTimestamps[0]} → {commandTimestamps[commandTimestamps.length - 1]}
                    </span>
                  </div>
                  <ol className="divide-y divide-slate-800/50 p-4 font-mono text-[13px] max-h-80 overflow-y-auto">
                    {sessionCommands.map((command, index) => {
                      const text = commandInput(command);
                      const classificationTechnique = textValue(recordValue(command).classification_technique, "");
                      return (
                        <li key={`${index}-${commandEventId(command)}`} className="py-2 flex items-start gap-4 hover:bg-white/5 transition-colors -mx-4 px-4">
                          <div className="text-slate-500 select-none mt-0.5 text-right w-6 shrink-0">${index + 1}</div>
                          <div className="flex-1">
                            <p className="text-slate-200 font-semibold break-all">
                              {text || <span className="text-slate-500 italic font-normal">Command text redacted</span>}
                            </p>
                            {classificationTechnique && (
                              <div className="mt-2">
                                <span className="inline-block rounded border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-[10px] font-sans font-bold text-orange-400">
                                  MITRE: {classificationTechnique}
                                </span>
                              </div>
                            )}
                          </div>
                          <div className="text-[10px] text-slate-500 shrink-0 mt-1 whitespace-nowrap">
                            {commandTimestamp(command).split(" ")[1]}
                          </div>
                        </li>
                      );
                    })}
                  </ol>
                </div>
              ) : currentCommandView.state === "loading" ? (
                <div className="mt-4">
                  <TerminalStreamLoader
                    title="Decrypting Admin-only Command Stream..."
                    subtitle="Intercepting and decoding attacker commands against MITRE ATT&CK database"
                  />
                </div>
              ) : (
                <div className="rounded-lg border border-orange-200 bg-orange-50 p-4 text-[11px] text-orange-800 font-medium flex items-center gap-2 mt-4">
                  <ShieldAlert className="h-4 w-4 text-orange-500 shrink-0" />
                  {textAvailability}{currentCommandView.state === "ready" || currentCommandView.reason.toLowerCase().includes("redacted")
                    ? ". Command text redacted before persistence cannot be recovered."
                    : "."}
                </div>
              )}
              
              <p className="mt-4 rounded-md border border-orange-200 bg-orange-50/50 p-3 text-xs text-orange-700">
                Sensitive Admin-only evidence: command input may contain attacker-entered usernames, passwords, tokens, or other secrets. It is excluded from print/export reports and is not copied automatically.
              </p>
            </div>
          ) : (
            <div className="p-10 text-center">
              <RegionState kind="empty" title="No interactive commands detected" description="Attacker did not execute shell commands in this session." />
            </div>
          )}
        </article>
      </section>

      {/* Active Deception Engine State */}
      <section id="deception-state" aria-label="Deception state" className="scroll-mt-32">
        {originIp === "Unknown" ? (
          <article className="bg-white border border-slate-200 rounded-xl shadow-xs p-10 text-center">
            <RegionState kind="empty" title="No deception decision recorded" description="No origin IP resolved for this session yet." />
          </article>
        ) : (
          <DeceptionStateFetcher key={originIp} ip={originIp} />
        )}
      </section>

      {/* Analysis Panels (Native Components) */}
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
