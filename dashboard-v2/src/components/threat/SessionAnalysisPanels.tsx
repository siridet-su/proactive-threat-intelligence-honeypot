"use client";

import {
  Activity,
  AlertCircle,
  Bot,
  BrainCircuit,
  ChevronDown,
  FileSearch,
  FileText,
  Fingerprint,
  Inbox,
  ListTree,
  Network,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";

import {
  chronologicalRecords,
  sessionLifecycleStatus,
} from "@/lib/session-analysis-semantics";
import {
  analystAttackerUsername,
  analystCommandText,
  selectedProviderFields,
} from "@/lib/session-intelligence";
import {
  externalTiFreshness,
  providerLookupExecuted,
  sourceIpCacheFreshness,
} from "@/lib/external-ti-presentation";
import { projectAdminCommandRecords } from "@/lib/session-command-projection";
import { projectContextualHypotheses } from "@/lib/contextual-hypothesis-presentation";
import { hasBoundModel2, model1TechniqueName, rankTtpRecommendations } from "@/lib/model-ttp-ranking";

type JsonRecord = Record<string, unknown>;
type LoadState = "loading" | "ready" | "limited" | "empty" | "not_applicable" | "unavailable";
export type SessionAnalysisLoadState = LoadState;

interface CapabilityResult {
  state: LoadState;
  status: number;
  data: JsonRecord;
  reason: string;
}

const initialResult: CapabilityResult = {
  state: "loading",
  status: 0,
  data: {},
  reason: "",
};

function terminalResult(
  state: Exclude<LoadState, "loading">,
  reason = "",
  data: JsonRecord = {},
  status = 0,
): CapabilityResult {
  return { state, status, data, reason };
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown): JsonRecord {
  return isRecord(value) ? value : {};
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function label(value: unknown, fallback = "Unavailable"): string {
  if (typeof value === "string" && value.trim()) return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function display(value: unknown, fallback = "Unavailable"): string {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function ContentPanel({ title, count, children, className = "" }: { title: string; count?: number; children: ReactNode; className?: string }) {
  return (
    <section className={`overflow-hidden rounded-xl border border-border bg-surface ${className}`}>
      <div className="flex items-center justify-between gap-3 border-b border-border bg-surface-subtle px-3.5 py-2.5">
        <h3 className="text-xs font-semibold text-text">{title}</h3>
        {count !== undefined && <span className="ui-badge text-[10px]">{count}</span>}
      </div>
      <div className="space-y-2 p-3">
        {children}
      </div>
    </section>
  );
}

function MoreDetails({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="group rounded-lg border border-border bg-surface">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-sm font-semibold text-text marker:text-primary"><span className="ui-badge text-[9px]">Technical details</span><span>{title}</span><ChevronDown className="ml-auto h-4 w-4 shrink-0 text-text-muted transition-transform group-open:rotate-180" aria-hidden="true" /></summary>
      <div className="space-y-3 border-t border-border px-4 py-3">{children}</div>
    </details>
  );
}

function readableCode(value: unknown): string {
  return label(value, "not recorded").replaceAll("_", " ").toLowerCase();
}

function timestampMillis(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const numeric = typeof value === "number" || (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim()));
  const numericValue = numeric ? Number(value) : Number.NaN;
  const timestamp = numeric
    ? (Math.abs(numericValue) < 1_000_000_000_000 ? numericValue * 1000 : numericValue)
    : Date.parse(String(value));
  if (Number.isFinite(timestamp)) return timestamp;
  const legacyUtc = String(value).trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})[ ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(UTC|GMT)$/i);
  if (!legacyUtc) return null;
  return Date.UTC(Number(legacyUtc[3]), Number(legacyUtc[2]) - 1, Number(legacyUtc[1]), Number(legacyUtc[4]), Number(legacyUtc[5]), Number(legacyUtc[6] || 0));
}

function thailandTimestamp(value: unknown): string {
  if (!hasMeaningfulValue(value)) return "Not recorded";
  if (["not recorded", "not available", "unavailable", "unknown", "n/a"].includes(String(value).trim().toLowerCase())) return "Not recorded";
  const timestamp = timestampMillis(value);
  if (timestamp === null) return "Not calculable";
  const formatted = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Bangkok",
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(timestamp);
  return `${formatted} ICT (UTC+7)`;
}

// Allow the bounded server projection to finish over the local SSH tunnel.
// The previous 2.5/7-second client cutoffs hid healthy session evidence.
const CLIENT_TIMEOUT_MS = 45_000;
const DETAIL_CLIENT_TIMEOUT_MS = 75_000;
const SESSION_TI_CLIENT_TIMEOUT_MS = 75_000;

async function fetchCapability(
  capability: string,
  sessionId: string,
  extra: Record<string, string> = {},
): Promise<CapabilityResult> {
  const query = new URLSearchParams({ session_id: sessionId, ...extra });
  const controller = new AbortController();
  const timeout = window.setTimeout(
    () => controller.abort(),
    capability === "detail" || capability === "commands"
      ? DETAIL_CLIENT_TIMEOUT_MS
      : capability === "session-ti"
        ? SESSION_TI_CLIENT_TIMEOUT_MS
        : CLIENT_TIMEOUT_MS,
  );
  try {
    const endpoint = capability === "commands"
      ? `/api/sessions/${encodeURIComponent(sessionId)}/commands`
      : `/api/session-analysis/${capability}?${query.toString()}`;
    const response = await fetch(endpoint, {
      cache: "no-store",
      signal: controller.signal,
    });
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > 1_000_000) {
      return {
        state: "unavailable",
        status: response.status,
        data: { error: "Bounded monitor response exceeded" },
        reason: "Bounded monitor response exceeded",
      };
    }
    let value: unknown;
    try {
      value = text ? JSON.parse(text) : {};
    } catch {
      return {
        state: "unavailable",
        status: response.status,
        data: { error: "Monitor returned a non-JSON response", error_code: "monitor_non_json" },
        reason: "Monitor returned a non-JSON response",
      };
    }
    const data = record(value);
    if (!response.ok) {
      return {
        state: "unavailable",
        status: response.status,
        data,
        reason: response.status === 404
          ? label(data.error, "Capability is not deployed for this release")
          : label(data.error, "HTTP " + response.status),
      };
    }
    if (data.ok === false) {
      return {
        state: "unavailable",
        status: response.status,
        data,
        reason: label(data.error, "The exact-session projection was unavailable"),
      };
    }
    return { state: "ready", status: response.status, data, reason: "" };
  } catch (error: unknown) {
    const aborted = error instanceof Error && error.name === "AbortError";
    return {
      state: "unavailable",
      status: 0,
      data: {},
      reason: aborted ? "Panel request timed out" : "Local BFF unavailable",
    };
  } finally {
    window.clearTimeout(timeout);
  }
}

function sessionIsActive(detail: JsonRecord): boolean {
  return sessionLifecycleStatus(detail) === "Active";
}

function hasItems(data: JsonRecord, keys: readonly string[]): boolean {
  return keys.some((key) => {
    const value = data[key];
    return Array.isArray(value) ? value.length > 0 : isRecord(value) && Object.keys(value).length > 0;
  });
}

function hasMeaningfulValue(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value.trim().length > 0;
  if (typeof value === "number" || typeof value === "boolean") return true;
  if (Array.isArray(value)) return value.some(hasMeaningfulValue);
  if (isRecord(value)) return Object.values(value).some(hasMeaningfulValue);
  return false;
}

function hasMeaningfulRecord(value: unknown): boolean {
  return isRecord(value) && hasMeaningfulValue(value);
}

export function hasClassificationEvidence(
  classificationEvents: unknown[],
  trustedMappings: unknown[],
): boolean {
  return classificationEvents.length > 0 || trustedMappings.length > 0;
}

function countOf(value: unknown, fallback = 0): string {
  const numeric = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numeric) ? String(numeric) : String(fallback);
}

function summaryValue(value: unknown, fallback = "Unavailable"): string {
  if (!hasMeaningfulValue(value)) return fallback;
  return display(value, fallback);
}

function commandText(value: unknown): string | null {
  return analystCommandText(value);
}

function normalizePanelResult(capability: string, result: CapabilityResult): CapabilityResult {
  if (result.state !== "ready") return result;

  const { data } = result;
  let hasEvidence = true;
  switch (capability) {
    case "commands":
      {
        const commandItems = list(data.commands);
        hasEvidence = commandItems.length > 0;
        if (hasEvidence && commandItems.every((item) => commandText(item) === null)) {
          const redacted = commandItems.some((item) => {
            const command = record(item);
            return typeof command.input === "string" && command.input.trim().toUpperCase() === "[REDACTED]";
          });
          return terminalResult(
            "limited",
            redacted
              ? "Command events are stored, but their input was redacted before persistence; the original text cannot be reconstructed."
              : "Command events are stored, but no command input text is present in the retained records.",
            { ...data, command_text_available: false, historical_originals: "unrecoverable_if_redacted_before_persistence" },
            result.status,
          );
        }
      }
      break;
    case "next-distinct":
      if (data.state === "UNAVAILABLE" || data.status === "UNAVAILABLE") {
        return terminalResult(
          "unavailable",
          label(data.prediction_status_reason, "The Next-Distinct read model is unavailable."),
          data,
          result.status,
        );
      }
      if (["WAITING_FOR_EVIDENCE", "SESSION_ENDED", "STALE"].includes(label(data.state || data.status, "").toUpperCase())) {
        return result;
      }
      hasEvidence = (data.state === "DATA" || data.status === "DATA")
        && data.next_distinct_tactic !== null
        && data.next_distinct_tactic !== undefined;
      break;
    case "session-ti":
      {
        const evidence = list(data.evidence).map(record);
        const cache = list(data.source_ip_cache).map(record);
        const usable = [...evidence, ...cache].some((item) => ["OK", "NOT_FOUND"].includes(label(item.lookup_status || item.status, "").toUpperCase()));
        const reason = label(data.status_reason, "").toUpperCase();
        if (!usable && reason === "POLICY_BLOCKED") return terminalResult("limited", summaryValue(data.status_reason_text, "Provider lookup is blocked by policy; stored status records are audit context only."), data, result.status);
        if (!usable && reason === "NO_ELIGIBLE_OBSERVABLE") return terminalResult("not_applicable", summaryValue(data.status_reason_text, "No policy-eligible observable is available for provider lookup."), data, result.status);
      }
      hasEvidence = hasItems(data, ["evidence", "shared_entities", "source_ip_cache"])
        || Number(record(data.counts).evidence_returned || 0) > 0
        || Number(record(data.counts).records_found || 0) > 0;
      break;
    case "source-ip-pivot":
      hasEvidence = hasItems(data, ["sessions", "source_ip_cache"]);
      break;
    case "observable-ti":
      hasEvidence = hasItems(data, ["evidence", "sightings", "sessions", "source_ip_cache"])
        || Number(record(data.counts).evidence_returned || 0) > 0
        || Number(record(data.counts).records_found || 0) > 0;
      break;
    case "hypothesis":
      {
        const reportSummary = record(data.report_summary);
        hasEvidence = hasItems(data, ["correlated_ttp_hypotheses", "hypothesis_sets", "session_hypothesis_assessment"])
          || hasMeaningfulValue(reportSummary.hypothesis);
      }
      break;
    case "recommendations":
      {
        const guidance = record(data.response_guidance);
        const guidanceStatus = label(guidance.status, "").toLowerCase();
        const validationStatus = label(record(guidance.validation).status, "").toLowerCase();
        if (["unavailable", "rejected", "invalid", "error"].some((state) => guidanceStatus.includes(state))
          || ["rejected", "invalid", "error"].some((state) => validationStatus.includes(state))) {
          return terminalResult(
            "unavailable",
            label(record(guidance.validation).error, "Stored response guidance is unavailable or failed validation."),
            data,
            result.status,
          );
        }
        const actions = list(guidance.advisory_actions);
        const guidanceState = label(guidance.guidance_state, "").toLowerCase();
        hasEvidence = actions.length > 0
          && !["no_applicable_grounded_action", "abstain", "empty_valid"].includes(guidanceState);
      }
      break;
    case "ai-advisory":
      {
        const advisory = record(data.advisory);
        const validated = record(advisory.validated_advisory);
        const status = label(data.status, "").toLowerCase();
        if (["unavailable", "not_available", "failed", "superseded"].includes(status)) {
          return terminalResult(
            "empty",
            "No accepted provider advisory is stored for this exact session.",
            data,
            result.status,
          );
        }
        if (status === "accepted" && validated.abstained === true) return terminalResult("limited", "The AI provider response was accepted and validated, but it abstained from selecting evidence or actions.", data, result.status);
        hasEvidence = status === "accepted" && hasMeaningfulRecord(advisory);
      }
      break;
    case "related":
      hasEvidence = hasItems(data, ["session_links", "campaigns", "related_observable_sightings"]);
      break;
    case "feedback":
      hasEvidence = list(data.analyst_feedback).length > 0;
      break;
    case "reports":
      hasEvidence = list(data.reports).length > 0 || hasMeaningfulRecord(data.report_summary);
      break;
    default:
      break;
  }
  return hasEvidence
    ? result
    : terminalResult(
        "empty",
        capability === "recommendations"
          ? "No policy-valid, evidence-linked response guidance is stored for this exact session; no response action is inferred."
          : "No stored evidence is available for this exact session.",
        data,
        result.status,
      );
}

function detailPanelResult(
  result: CapabilityResult,
  hasEvidence: boolean,
  reason: string,
): CapabilityResult {
  if (result.state !== "ready" && result.state !== "empty") return result;
  return hasEvidence
    ? result
    : terminalResult("empty", reason, result.data, result.status);
}

function combinedPanelResult(results: CapabilityResult[], emptyReason: string): CapabilityResult {
  if (results.some((result) => result.state === "loading")) return initialResult;
  const ready = results.find((result) => result.state === "ready");
  const limited = results.find((result) => result.state === "limited");
  const unavailable = results.filter((result) => result.state === "unavailable");
  if (ready && (limited || unavailable.length > 0)) {
    return terminalResult("limited", "Some evidence in this section is unavailable or partial.", ready.data, ready.status);
  }
  if (ready) return ready;
  if (limited) return limited;
  if (unavailable.length === results.length && unavailable[0]) return unavailable[0];
  if (unavailable.length > 0) {
    return terminalResult("limited", "Some evidence in this section is unavailable.", unavailable[0].data, unavailable[0].status);
  }
  return terminalResult("empty", emptyReason, results[0]?.data || {});
}

const DERIVED_CAPABILITIES = [
  "hypothesis",
  "recommendations",
  "ai-advisory",
  "related",
  "feedback",
  "reports",
] as const;

function derivedEntries(detailResult: CapabilityResult): Array<readonly [string, CapabilityResult]> {
  const detail = detailResult.data;
  const base = {
    ok: detail.ok,
    session_id: detail.session_id,
    timestamp: detail.timestamp,
  };
  const projections: Record<string, JsonRecord> = {
    hypothesis: {
      ...base,
      authority: "CONTEXTUAL_NON_AUTHORITATIVE",
      report_summary: detail.report_summary || {},
      report_recommendations: detail.report_recommendations || {},
      correlated_ttp_hypotheses: detail.correlated_ttp_hypotheses || [],
      hypothesis_sets: detail.hypothesis_sets || [],
      session_hypothesis_assessment: detail.session_hypothesis_assessment || {},
      reports: detail.reports || [],
      non_claims: [
        "does not establish attacker identity or intent",
        "cannot alter trusted ATT&CK mappings or authorize response",
      ],
    },
    recommendations: {
      ...base,
      response_guidance: detail.response_guidance || {},
      report_recommendations: detail.report_recommendations || {},
      requires_manual_approval: true,
      safe_to_auto_execute: false,
    },
    related: {
      ...base,
      authority: "CONTEXTUAL_NON_AUTHORITATIVE",
      session_links: detail.session_links || [],
      campaigns: detail.campaigns || [],
      related_observable_sightings: detail.related_observable_sightings || [],
    },
    feedback: {
      ...base,
      analyst_feedback: detail.analyst_feedback || [],
      write_enabled: false,
    },
    reports: {
      ...base,
      reports: detail.reports || [],
      report_summary: detail.report_summary || {},
    },
  };
  return DERIVED_CAPABILITIES.map((capability) => [
    capability,
    {
      ...detailResult,
      data: projections[capability] || base,
    },
  ] as const);
}

function Panel({
  eyebrow,
  title,
  icon,
  result,
  children,
  className = "",
  variant = "card",
  renderEmptyContent = false,
  compactUnavailable = false,
}: {
  eyebrow: string;
  title: string;
  icon: ReactNode;
  result: CapabilityResult;
  children: ReactNode;
  className?: string;
  variant?: "card" | "embedded" | "flat" | "module";
  renderEmptyContent?: boolean;
  compactUnavailable?: boolean;
}) {
  const stateCopy = result.state === "loading"
    ? {
        icon: <RefreshCw className="h-4 w-4 animate-spin text-primary" aria-hidden="true" />,
        title: `Loading ${title.toLowerCase()}`,
        description: "Reading the bounded exact-session projection.",
        className: "border-primary/20 bg-primary/5",
      }
    : result.state === "unavailable"
      ? {
          icon: <AlertCircle className="h-4 w-4 text-warning" aria-hidden="true" />,
          title: `${title} unavailable`,
          description: result.reason || "No eligible stored evidence is available.",
          className: "border-warning-border bg-warning-subtle",
        }
      : result.state === "not_applicable"
        ? {
            icon: <Inbox className="h-4 w-4 text-text-subtle" aria-hidden="true" />,
            title: `${title} not applicable`,
            description: result.reason || "This session has no eligible evidence for this panel.",
            className: "border-border bg-surface-subtle",
          }
        : {
            icon: <Inbox className="h-4 w-4 text-text-subtle" aria-hidden="true" />,
            title: `${title} has no stored evidence`,
            description: result.reason || "No stored evidence is available for this exact session.",
            className: "border-border bg-surface-subtle",
          };

  const embedded = variant === "embedded";
  const flat = variant === "flat";
  const isModule = variant === "module";

  return (
    <article className={`${embedded || flat ? "min-w-0" : "ui-panel flex min-w-0 flex-col overflow-hidden"} ${className}`}>
      <div className={`flex flex-wrap items-center justify-between gap-3 ${isModule ? "border-b border-border bg-surface px-4 py-3 sm:px-5" : embedded ? "border-b border-border pb-3" : flat ? "pb-2" : "border-b border-border bg-surface px-4 py-3 sm:px-5"}`}>
        {isModule ? (
          <h2 className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.12em] text-primary-navy sm:text-xs">
            {icon}
            {title}
          </h2>
        ) : (
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary-navy">
              {icon}
              {eyebrow}
            </div>
            <h3 className="mt-1 text-base font-semibold sm:text-lg">{title}</h3>
          </div>
        )}
        <span className="ui-badge">
          {result.state === "ready" && "PASS_WITH_DATA"}
          {result.state === "limited" && "LIMITED"}
          {result.state === "empty" && "EMPTY_VALID"}
          {result.state === "not_applicable" && "EMPTY_VALID"}
          {result.state === "loading" && "Loading"}
          {result.state === "unavailable" && "UNAVAILABLE"}
        </span>
      </div>
      <div className={isModule ? "p-4 sm:p-5" : embedded ? "pt-4" : flat ? "pt-1" : "p-4 sm:p-5"}>
        {result.state === "loading" ? (
          <div role="status" aria-busy="true" className={`flex items-start gap-3 rounded-lg border p-3.5 ${stateCopy.className}`}>
            {stateCopy.icon}
            <div className="min-w-0">
              <p className="text-sm font-semibold text-text">{stateCopy.title}</p>
              <p className="mt-1 text-xs leading-5 text-text-muted">{stateCopy.description}</p>
            </div>
          </div>
        ) : result.state === "unavailable" && compactUnavailable ? (
          <div role="alert" className="flex items-center gap-2 rounded-lg border border-warning-border bg-warning-subtle/60 px-3 py-2.5">
            {stateCopy.icon}
            <div className="min-w-0">
              <p className="text-xs font-semibold text-text">{stateCopy.title}</p>
              <p className="mt-0.5 text-[11px] leading-4 text-text-muted">{stateCopy.description}</p>
            </div>
          </div>
        ) : (result.state === "empty" || result.state === "not_applicable") && renderEmptyContent ? (
          children
        ) : result.state === "empty" || result.state === "not_applicable" || result.state === "unavailable" ? (
          <div role={result.state === "unavailable" ? "alert" : "status"} className={`flex items-start gap-3 rounded-lg border p-3.5 ${stateCopy.className}`}>
            {stateCopy.icon}
            <div className="min-w-0">
              <p className="text-sm font-semibold text-text">{stateCopy.title}</p>
              <p className="mt-1 text-xs leading-5 text-text-muted">{stateCopy.description}</p>
            </div>
          </div>
        ) : children}
      </div>
    </article>
  );
}

export function TimelineList({ items }: { items: unknown[] }) {
  const orderedItems = chronologicalRecords(items).filter((item) => item.command_event !== true);
  const [filter, setFilter] = useState("all");
  const category = (item: JsonRecord) => {
    const eventName = String(item.eventid || item.event_id || item.event_type || "").toLowerCase();
    if (/login|auth|password|client\.kex/.test(eventName)) return "Authentication";
    if (/session|connect|disconnect|close/.test(eventName)) return "Session";
    return "Other";
  };
  const visibleItems = orderedItems.filter((item) => filter === "all" || category(item) === filter);
  const timelineItems = visibleItems.slice(-100);
  const accessCount = orderedItems.filter((item) => category(item) === "Authentication").length;
  const sessionCount = orderedItems.filter((item) => category(item) === "Session").length;
  const otherCount = orderedItems.length - accessCount - sessionCount;
  const filters = [
    ["all", "All events", orderedItems.length],
    ["Authentication", "Access", orderedItems.filter((item) => category(item) === "Authentication").length],
    ["Session", "Session", orderedItems.filter((item) => category(item) === "Session").length],
    ["Other", "Other", orderedItems.filter((item) => category(item) === "Other").length],
  ] as const;
  return (
    <div className="space-y-2.5">
      <dl className="grid grid-cols-4 divide-x divide-border rounded-lg border border-border bg-surface-subtle">
        {[["Events", orderedItems.length], ["Access", accessCount], ["Session", sessionCount], ["Other", otherCount]].map(([name, count]) => <div key={name} className="min-w-0 px-2.5 py-2 text-center sm:px-3">
          <dt className="text-[9px] font-semibold uppercase tracking-[0.1em] text-text-subtle sm:text-[10px]">{name}</dt>
          <dd className="mt-0.5 text-sm font-semibold text-primary-navy">{count}</dd>
        </div>)}
      </dl>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-text-subtle">Bound event chain <span className="ml-1 font-normal normal-case tracking-normal">· oldest to newest</span></p>
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter timeline events">
          {filters.map(([key, title, count]) => <button key={key} type="button" aria-pressed={filter === key} onClick={() => setFilter(key)} className={`rounded-full border px-2.5 py-1 text-[10px] font-medium transition-colors ${filter === key ? "border-primary-border bg-primary-subtle text-primary" : "border-border bg-surface text-text-muted hover:border-primary-border hover:text-text"}`}>
            {title}<span className="ml-1 opacity-70">{count}</span>
          </button>)}
        </div>
      </div>
      {timelineItems.length > 0 ? <div className="h-[min(65vh,28rem)] overflow-y-auto overscroll-contain rounded-lg border border-border bg-surface px-3 py-3" aria-label="Bounded event timeline" tabIndex={0}>
        <ol className="space-y-0">
        {timelineItems.map((event, index) => {
          const eventName = summaryValue(event.eventid || event.event_id || event.event_type, "event");
          const timestampValue = event.timestamp || event.received_at;
          const readableEvent = eventName.replace(/^cowrie\./i, "").replaceAll(".", " ");
          const eventCategory = category(event);
          const isLatest = index === timelineItems.length - 1;
          const EventIcon = eventCategory === "Authentication" ? Fingerprint : eventCategory === "Session" ? Network : Activity;
          const endpoint = [event.src_ip && `src ${display(event.src_ip)}`, event.dst_ip && `dst ${display(event.dst_ip)}`].filter(Boolean).join(" · ");
        return (
          <li key={`${index}-${eventName}-${String(timestampValue || "unknown")}`} className="relative grid grid-cols-[1rem_minmax(0,1fr)] gap-x-3 pb-3 last:pb-0">
            {index < timelineItems.length - 1 && <span className="absolute -bottom-2.5 left-[0.4375rem] top-4 w-px bg-primary-navy-line" aria-hidden="true" />}
            <span className={`relative z-10 mt-0.5 grid h-4 w-4 place-items-center rounded-full border bg-surface ${isLatest ? "border-orange-500 text-orange-600" : "border-primary-navy-line text-primary-navy"}`}>
              <EventIcon className="h-2.5 w-2.5" aria-hidden="true" />
            </span>
            <div className="min-w-0 pb-1">
              <div className="grid grid-cols-[minmax(0,1fr)_9.5rem_3.5rem] items-start gap-x-2 sm:grid-cols-[minmax(0,1fr)_15rem_4rem] sm:gap-x-3" data-testid="timeline-event-row">
                <div className="min-w-0">
                <p className="text-xs font-semibold capitalize leading-5 text-text">{readableEvent}</p>
                  <p className="mt-0.5 text-[10px] text-text-subtle">{eventCategory} · {summaryValue(event.sensor_id || event.sensor, "Sensor unavailable")}</p>
                  {endpoint && <p className="mt-0.5 break-all font-mono text-[10px] text-text-muted">{endpoint}</p>}
                  {event.processed === false && <span className="mt-1 inline-flex rounded-full border border-border bg-surface-subtle px-2 py-0.5 text-[9px] font-medium text-text-muted">Processing pending</span>}
                </div>
                <time className="min-w-0 break-words pt-0.5 text-right font-mono text-[9px] text-text-muted sm:text-[10px]" dateTime={hasMeaningfulValue(timestampValue) ? String(timestampValue) : undefined}>{hasMeaningfulValue(timestampValue) ? thailandTimestamp(timestampValue) : "Timestamp unavailable"}</time>
                <span className={`w-14 justify-self-end pt-0.5 text-right text-[9px] font-semibold uppercase tracking-wide ${isLatest ? "text-orange-600" : "text-transparent"}`} aria-label={isLatest ? "Latest event" : undefined} aria-hidden={!isLatest} data-testid="timeline-state-slot">{isLatest ? "LATEST" : "\u00a0"}</span>
              </div>
            </div>
          </li>
        );
        })}
        </ol>
      </div> : <p className="rounded-lg border border-border bg-surface-subtle px-3 py-2.5 text-xs text-text-muted">No persisted timeline events are available.</p>}
    </div>
  );
}

export function ClassificationList({ items, trustedMappings }: { items: unknown[]; trustedMappings: unknown[] }) {
  const classificationRecords = items.map(record);
  if (!classificationRecords.length && !trustedMappings.length) {
    return <p className="rounded-lg border border-border bg-surface-subtle px-3 py-2.5 text-xs text-text-muted">No trusted observation or classification evidence recorded.</p>;
  }
  const classifiedCommandKeys = new Set(
    classificationRecords
      .map((mapping) => {
        const durableOrder = record(mapping.durable_evidence_order);
        for (const candidate of [
          durableOrder.event_id,
          mapping.command_event_id,
          mapping.event_id,
          mapping.event_timestamp,
          mapping.timestamp,
        ]) {
          if (hasMeaningfulValue(candidate)) return display(candidate, "");
        }
        return null;
      })
      .filter((value): value is string => Boolean(value)),
  );
  const uniqueAttackTechniques = new Set(trustedMappings.map((item) => {
    const mapping = record(item);
    return display(mapping.technique_id || mapping.ttp, "");
  }).filter(Boolean));
  const evidenceReferenceCount = trustedMappings.reduce<number>((total, item) => {
    const mapping = record(item);
    return total + Number(mapping.evidence_ref_count || list(mapping.evidence_refs).length || 0);
  }, 0);
  const classificationByTechnique = new Map(classificationRecords.map((item) => [
    display(item.technique_id || item.ttp, ""),
    item,
  ]));
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-primary-navy">Observed behavior &amp; ATT&amp;CK mapping</h3>
        <span className="ui-badge text-[10px]">Observed · not model suggestions</span>
      </div>
      <dl className="grid grid-cols-3 divide-x divide-border rounded-lg border border-border bg-surface-subtle">
        {[["Trusted TTPs", String(uniqueAttackTechniques.size)], ["Linked evidence", String(evidenceReferenceCount)], ["Classified events", String(classifiedCommandKeys.size)]].map(([name, value]) => <div key={name} className="min-w-0 px-2.5 py-2.5 text-center sm:px-3">
          <dt className="text-[9px] font-semibold uppercase tracking-[0.1em] text-text-subtle sm:text-[10px]">{name}</dt>
          <dd className="mt-0.5 text-base font-semibold text-primary-navy">{value}</dd>
        </div>)}
      </dl>
      <p className="text-[11px] text-text-muted">Counts describe different things: trusted TTPs are distinct observed ATT&amp;CK techniques; classified events are command-event records. One technique can be linked to several events, and a classified event does not automatically become a trusted mapping.</p>
      <div className="grid gap-4 xl:grid-cols-12">
        <section className="xl:col-span-4">
          <h3 className="text-xs font-semibold uppercase tracking-[0.1em] text-primary-navy">Observed behavior</h3>
          <dl className="mt-3 divide-y divide-border rounded-lg border border-border">
            <div className="flex items-center justify-between gap-3 px-3 py-2.5 text-xs"><dt className="text-text-muted">Trusted mappings</dt><dd className="font-semibold text-text">{trustedMappings.length}</dd></div>
            <div className="flex items-center justify-between gap-3 px-3 py-2.5 text-xs"><dt className="text-text-muted">Distinct ATT&amp;CK techniques</dt><dd className="font-semibold text-text">{uniqueAttackTechniques.size}</dd></div>
            <div className="flex items-center justify-between gap-3 px-3 py-2.5 text-xs"><dt className="text-text-muted">Classifier records</dt><dd className="font-semibold text-text">{classificationRecords.length}</dd></div>
          </dl>
          {trustedMappings.length === 0 && <p className="mt-2 text-xs text-text-muted">No trusted ATT&amp;CK mapping was established.</p>}
        </section>
        <section className="min-w-0 xl:col-span-8">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-[0.1em] text-primary-navy">MITRE ATT&amp;CK</h3>
            <span className="ui-badge text-[10px]">Observed · not model suggestions</span>
          </div>
          {trustedMappings.length ? <div className="mt-2 max-h-[28rem] overflow-auto overscroll-contain rounded-lg border border-border">
            <table className="w-full min-w-[620px] text-left text-xs">
              <thead className="bg-primary-navy-soft text-[10px] uppercase tracking-[0.08em] text-primary-navy"><tr><th className="px-3 py-2 font-semibold">Technique</th><th className="px-3 py-2 font-semibold">Tactic</th><th className="px-3 py-2 font-semibold">Evidence</th><th className="px-3 py-2 font-semibold">Authority</th></tr></thead>
              <tbody className="divide-y divide-border">
                {trustedMappings.slice(0, 30).map((item, index) => {
                  const mapping = record(item);
                  const techniqueId = display(mapping.technique_id || mapping.ttp, "Technique unavailable");
                  const classifier = classificationByTechnique.get(techniqueId) || {};
                  const tactics = list(mapping.tactics).map((value) => display(value)).filter(Boolean).join(", ") || display(mapping.tactic, "Not recorded");
                  const refs = Number(mapping.evidence_ref_count || list(mapping.evidence_refs).length || 0);
                  return <tr key={`${index}-${techniqueId}`} className="align-top">
                    <td className="px-3 py-2.5"><span className="font-mono font-semibold text-primary-navy">{techniqueId}</span><span className="mt-0.5 block text-text-muted">{summaryValue(mapping.name || classifier.name, "Technique name not recorded")}</span></td>
                    <td className="px-3 py-2.5 text-text-muted">{tactics}</td>
                    <td className="px-3 py-2.5 text-text-muted">{countOf(refs)} linked reference{refs === 1 ? "" : "s"}<div className="mt-1"><TrustedTraceability mapping={mapping} /></div></td>
                    <td className="px-3 py-2.5"><span className="ui-badge text-[10px]">{readableCode(mapping.trust_tier || mapping.authority || "not recorded")}</span><span className="mt-1 block text-[10px] text-text-subtle">{readableCode(mapping.mapping_semantics || "not recorded")}</span></td>
                  </tr>;
                })}
              </tbody>
            </table>
          </div> : <p className="mt-2 rounded-lg border border-border bg-surface-subtle px-3 py-2.5 text-xs text-text-muted">No ATT&amp;CK mapping to display.</p>}
        </section>
      </div>

      {classificationRecords.length > 0 && <details className="group rounded-lg border border-border bg-surface">
        <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-2 px-4 py-3">
          <span>
            <span className="block text-sm font-semibold text-text">Command classification details</span>
            <span className="mt-0.5 block text-xs text-text-muted">Review the command, predicted technique, and decision record.</span>
          </span>
          <span className="flex items-center gap-2"><span className="ui-badge">{classificationRecords.length} records</span><ChevronDown className="h-4 w-4 text-text-muted transition-transform group-open:rotate-180" aria-hidden="true" /></span>
        </summary>
        <ol className="grid gap-2 border-t border-border p-3 sm:grid-cols-2">
          {classificationRecords.slice(0, 50).map((mapping, index) => {
            const authority = record(mapping.authority_decision);
            const advisory = record(mapping.s1_advisory);
            const technique = mapping.ttp || mapping.technique_id || "NO_TECHNIQUE_ASSIGNED";
            const sourceCommand = commandText(mapping.source_command || mapping.command || mapping.original_command);
            return (
              <li key={`${index}-${String(mapping.evidence_id || technique)}`} className="min-w-0 rounded-lg border border-border bg-surface-subtle p-3 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-text">{summaryValue(technique)}</span>
                  <span className="ui-badge text-[10px]">{summaryValue(authority.decision || mapping.evidence_tier, "advisory")}</span>
                </div>
                <p className="mt-1 text-text-muted">{summaryValue(mapping.name, "Technique not assigned")} · {summaryValue(mapping.tactic, "Tactic not recorded")}</p>
                {sourceCommand && <p className="mt-2 break-words rounded-md border border-border bg-surface px-2.5 py-2 font-mono text-[11px] text-text">{sourceCommand}</p>}
                {hasMeaningfulValue(advisory.predicted_technique) && <p className="mt-2 font-mono text-text-muted">Model1 advisory: {summaryValue(advisory.predicted_technique)}</p>}
                <ClassificationTraceability mapping={mapping} />
              </li>
            );
          })}
        </ol>
      </details>}
    </div>
  );
}

function ObservableList({ items, empty = "No file or observable evidence is available." }: { items: unknown[]; empty?: string }) {
  if (!items.length) {
    return <p className="text-xs text-text-muted">{empty}</p>;
  }
  const records = items.slice(0, 100).map(record);
  const groups = Array.from(records.reduce((grouped, observable) => {
    const type = summaryValue(observable.type || observable.observable_type || observable.role, "observable");
    const value = summaryValue(observable.value || observable.observable_value, "Value unavailable");
    const key = `${type}\u0000${value}`;
    const current = grouped.get(key);
    if (current) {
      current.items.push(observable);
    } else {
      grouped.set(key, { type, value, items: [observable] });
    }
    return grouped;
  }, new Map<string, { type: string; value: string; items: JsonRecord[] }>()).values());
  const sessionIds = new Set(records.map((item) => String(item.session_id || "").trim()).filter(Boolean));
  const sightingIds = new Set(records.map((item) => String(item.sighting_id || "").trim()).filter(Boolean));
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-3 divide-x divide-border rounded-lg border border-border bg-surface-subtle">
        {[["Observables", String(groups.length)], ["Sightings", sightingIds.size ? String(sightingIds.size) : "Not recorded"], ["Sessions", sessionIds.size ? String(sessionIds.size) : "Not recorded"]].map(([name, value]) => <div key={name} className="px-2.5 py-2 text-center sm:px-3"><dt className="text-[9px] font-semibold uppercase tracking-[0.1em] text-text-subtle sm:text-[10px]">{name}</dt><dd className="mt-0.5 text-sm font-semibold text-primary-navy">{value}</dd></div>)}
      </dl>
      <div className="max-h-[28rem] overflow-auto overscroll-contain rounded-lg border border-border">
        <table className="w-full min-w-[660px] text-left text-xs">
          <thead className="sticky top-0 z-10 bg-primary-navy-soft text-[10px] uppercase tracking-[0.08em] text-primary-navy"><tr><th scope="col" className="px-3 py-2 font-semibold">Observable</th><th scope="col" className="px-3 py-2 font-semibold">Sightings</th><th scope="col" className="px-3 py-2 font-semibold">First / last seen</th><th scope="col" className="px-3 py-2 font-semibold">Source</th></tr></thead>
          <tbody className="divide-y divide-border">
            {groups.map((group, index) => {
              const first = group.items[0];
              const groupSightingIds = new Set(group.items.map((item) => String(item.sighting_id || "").trim()).filter(Boolean));
              const sortedTimes = group.items.map((item) => item.timestamp || item.first_seen).filter(hasMeaningfulValue).sort((a, b) => (timestampMillis(a) ?? 0) - (timestampMillis(b) ?? 0));
              const firstSeen = sortedTimes[0];
              const lastSeen = sortedTimes[sortedTimes.length - 1];
              return <tr key={`${index}-${group.type}-${group.value}`} className="align-top">
                <td className="px-3 py-2.5"><span className="ui-badge text-[10px]">{group.type}</span><span className="mt-1 block max-w-[320px] break-all font-mono text-xs text-text">{group.value}</span></td>
                <td className="px-3 py-2.5 text-text">{groupSightingIds.size ? groupSightingIds.size : "Not recorded"}</td>
                <td className="px-3 py-2.5 text-[11px] text-text-muted"><span className="block">{hasMeaningfulValue(firstSeen) ? thailandTimestamp(firstSeen) : "Not recorded"}</span>{hasMeaningfulValue(lastSeen) && lastSeen !== firstSeen && <span className="mt-0.5 block">→ {thailandTimestamp(lastSeen)}</span>}</td>
                <td className="px-3 py-2.5 text-text-muted">{summaryValue(first.source || first.sensor_id || first.eventid, "Not recorded")}<details className="mt-1"><summary className="cursor-pointer text-[10px] font-medium text-primary">Inspect provenance</summary><div className="min-w-[260px] pt-1"><ol className="space-y-1.5">{group.items.map((observable, occurrenceIndex) => <li key={`${occurrenceIndex}-${summaryValue(observable.sighting_id, "occurrence")}`} className="rounded border border-border bg-surface-subtle p-2"><p className="break-all font-mono text-[10px] text-text">Session: {summaryValue(observable.session_id, "Not recorded")}</p><p className="mt-1 text-[10px] text-text-muted">{thailandTimestamp(observable.timestamp || observable.first_seen)} · {summaryValue(observable.source || observable.sensor_id, "Source not recorded")}</p><p className="mt-1 break-all font-mono text-[10px] text-text-subtle">Event: {summaryValue(observable.event_id || observable.eventid, "Not linked")} · Sighting: {summaryValue(observable.sighting_id, "Not recorded")}</p></li>)}</ol></div></details></td>
              </tr>;
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RecordList({ items, empty }: { items: unknown[]; empty: string }) {
  if (!items.length) {
    return <p className="text-xs text-text-muted">{empty}</p>;
  }
  return (
    <ol className="divide-y divide-border rounded-lg border border-border">
      {items.slice(0, 50).map((item, index) => {
        const entry = record(item);
        const primary = entry.title || entry.name || entry.rule_id || entry.report_id || entry.feedback_id || entry.status || entry.type;
        const secondary = entry.reason || entry.summary || entry.message || entry.description;
        return (
          <li key={`${index}-${String(primary || "record")}`} className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 px-3 py-2.5">
            <div className="min-w-0 flex-1">
              <p className="break-all font-mono text-[11px] font-semibold text-text">{summaryValue(primary, "Stored report")}</p>
              {hasMeaningfulValue(secondary) && <p className="mt-0.5 line-clamp-2 text-[11px] text-text-muted">{summaryValue(secondary)}</p>}
            </div>
            <div className="flex shrink-0 items-center gap-2"><time className="text-[10px] text-text-subtle">{thailandTimestamp(entry.generated_at || entry.created_at || entry.updated_at)}</time>{entry.status !== undefined && <span className="ui-badge text-[10px]">{readableCode(entry.status)}</span>}</div>
          </li>
        );
      })}
    </ol>
  );
}

function isEmptyTechnicalValue(value: string): boolean {
  const normalized = value.trim().toLowerCase().replaceAll("_", " ").replaceAll(/\s+/g, " ");
  return normalized === "" || [
    "not recorded", "not available", "unavailable", "unknown", "n/a", "na", "not reported",
    "not calculable", "not linked", "not assessed", "empty", "none",
  ].includes(normalized) || /^0+(?:\.0+)?$/.test(normalized);
}

function TechnicalFieldGrid({ fields, empty = "No additional technical values were recorded." }: { fields: Array<readonly [string, string]>; empty?: string }) {
  const populatedFields = fields.filter(([, value]) => !isEmptyTechnicalValue(value));
  if (populatedFields.length === 0) return <p role="status" className="rounded-md bg-surface-subtle px-3 py-2 text-xs text-text-muted">{empty}{fields.length > 0 ? ` (${fields.length} fields are empty, unavailable, or zero.)` : ""}</p>;
  const mostlyEmpty = fields.length > 0 && fields.length - populatedFields.length > fields.length / 2;
  if (mostlyEmpty) {
    return <div className="space-y-2">
      <p className="text-[11px] text-text-muted">Limited technical detail · {populatedFields.length} of {fields.length} fields recorded.</p>
      <dl className="divide-y divide-border rounded-md border border-border px-3">
        {populatedFields.map(([name, value]) => <div key={name} className="grid gap-1 py-2 sm:grid-cols-[minmax(9rem,0.8fr)_minmax(0,1.2fr)] sm:gap-3">
          <dt className="text-[10px] font-medium uppercase tracking-[0.08em] text-text-subtle">{name}</dt>
          <dd className="break-words font-mono text-[11px] text-text">{value}</dd>
        </div>)}
      </dl>
    </div>;
  }
  return <dl className="grid gap-2 sm:grid-cols-2">
    {fields.map(([name, value]) => <div key={name} className="min-w-0 rounded-md border border-border bg-surface-subtle p-2">
      <dt className="text-[10px] font-medium uppercase tracking-[0.08em] text-text-subtle">{name}</dt>
      <dd className="mt-1 break-words font-mono text-[11px] text-text">{value}</dd>
    </div>)}
  </dl>;
}

function SummaryGrid({ fields }: { fields: Array<readonly [string, string]> }) {
  return (
    <TechnicalFieldGrid fields={fields} />
  );
}

function traceList(value: unknown, fallback = "Not recorded"): string {
  const values = list(value)
    .map((item) => (typeof item === "string" || typeof item === "number" || typeof item === "boolean" ? String(item) : ""))
    .filter(Boolean);
  return values.length ? values.join(", ") : summaryValue(value, fallback);
}

function TraceabilityDetails({
  title,
  fields,
  empty = "Traceability is not recorded for this item.",
}: {
  title: string;
  fields: Array<readonly [string, string]>;
  empty?: string;
}) {
  return (
    <details className="mt-3 rounded-lg border border-border bg-surface px-3 py-2 text-xs">
      <summary className="flex cursor-pointer list-none items-center gap-2 font-semibold text-text"><span className="ui-badge text-[9px]">Technical details</span><span>{title}</span></summary>
      <div className="mt-3"><TechnicalFieldGrid fields={fields} empty={empty} /></div>
    </details>
  );
}

function guidancePolicyRuleLabel(value: unknown): string {
  const policyRule = record(value);
  const parts = [
    policyRule.rule_id,
    policyRule.policy_rule_id,
    policyRule.behavior_policy_rule_id,
    policyRule.policy_id,
    policyRule.policy_version,
  ]
    .map((item) => (typeof item === "string" || typeof item === "number" ? String(item) : ""))
    .filter(Boolean);
  return parts.length ? Array.from(new Set(parts)).join(" · ") : "Not recorded";
}

function predicateTraceLabel(value: unknown): string {
  const trace = record(value);
  const predicate = summaryValue(trace.predicate, "predicate");
  const result = trace.result === true ? "matched" : trace.result === false ? "not matched" : "result unavailable";
  const expected = hasMeaningfulValue(trace.expected) ? `expected=${traceList(trace.expected)}` : "";
  const matched = hasMeaningfulValue(trace.matched) ? `matched=${traceList(trace.matched)}` : "";
  const refs = hasMeaningfulValue(trace.evidence_references) ? `evidence=${traceList(trace.evidence_references)}` : "";
  return [predicate, result, expected, matched, refs].filter(Boolean).join(" · ");
}

function GuidanceTraceability({ action, guidance }: { action: JsonRecord; guidance: JsonRecord }) {
  const trace = record(action.traceability);
  const predicates = list(trace.matched_predicates).length > 0
    ? list(trace.matched_predicates)
    : list(action.matched_predicates);
  const evidenceReferences = hasMeaningfulValue(trace.evidence_references)
    ? traceList(trace.evidence_references)
    : traceList(action.evidence_refs);
  const sessionId = summaryValue(trace.session_id || guidance.session_id || record(guidance.binding).session_id, "Not recorded");
  return (
    <div className="mt-2 space-y-1.5">
      <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-text-subtle">Selection and source binding · technical details</p>
      <TechnicalFieldGrid fields={[
        ["Action ID", summaryValue(trace.action_id || action.action_id, "Not recorded")],
        ["Policy / rule", guidancePolicyRuleLabel(trace.policy_rule || { rule_id: action.rule_id })],
        ["Matched predicates", predicates.length ? predicates.map(predicateTraceLabel).join(" | ") : "Not recorded"],
        ["Evidence references", evidenceReferences],
        ["Source event IDs", traceList(trace.source_event_ids)],
        ["Source command IDs", traceList(trace.source_command_ids)],
        ["Exact session", sessionId],
      ]} empty="No additional action-selection trace was recorded." />
    </div>
  );
}

function ClassificationTraceability({ mapping }: { mapping: JsonRecord }) {
  const trace = record(mapping.traceability);
  const sourceEvent = record(trace.source_event);
  const durableOrder = record(mapping.durable_evidence_order);
  return (
    <div className="mt-2 space-y-1.5">
      <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-text-subtle">Evidence trace · technical details</p>
      <TechnicalFieldGrid fields={[
        ["Source event", summaryValue(sourceEvent.cowrie_eventid || sourceEvent.event_type || mapping.cowrie_eventid, "Not recorded")],
        ["Event ID", summaryValue(trace.event_id || durableOrder.event_id || mapping.evidence_id, "Not recorded")],
        ["Procedure / evidence anchor", summaryValue(trace.procedure_anchor, "Not recorded")],
        ["Evidence references", traceList(trace.evidence_references || mapping.evidence_id)],
        ["Policy / rule", guidancePolicyRuleLabel(trace.policy_or_rule_identifier)],
        ["Model source", summaryValue(trace.model_source || mapping.source, "Not recorded")],
      ]} empty="No additional classification evidence trace was recorded." />
    </div>
  );
}

function TrustedTraceability({ mapping }: { mapping: JsonRecord }) {
  const trace = record(mapping.traceability);
  return (
    <TraceabilityDetails
      title="Evidence trace"
      fields={[
        ["Source command", traceList(trace.source_commands)],
        ["Evidence references", traceList(trace.evidence_references)],
        ["Policy / rule", guidancePolicyRuleLabel(trace.policy_or_rule_identifier)],
      ]}
    />
  );
}

function tiLookupState(value: JsonRecord, freshnessOverride?: unknown): string {
  const lookup = String(value.lookup_status || value.status || "").trim().toUpperCase();
  if (["PROVIDER_ERROR", "ERROR", "RATE_LIMITED", "AUTH_FAILED", "REQUEST_FAILED"].includes(lookup)) return "ERROR";
  if (!providerLookupExecuted(value)) return "UNAVAILABLE";
  const freshness = String(freshnessOverride ?? value.freshness_state ?? "").trim().toUpperCase();
  if (freshness === "STALE" || freshness === "EXPIRED" || freshness === "TI_EXPIRED" || freshness === "TI_STALE") return "STALE";
  if (["OK", "CACHED", "AVAILABLE"].includes(lookup)) return "DATA";
  if (["NOT_FOUND", "NO_DATA"].includes(lookup)) return "NO_DATA";
  if (["DISABLED", "UNAVAILABLE", "AUTH_DISABLED", "BUDGET_EXHAUSTED", "INVALID_OBSERVABLE", "PENDING"].includes(lookup)) return "UNAVAILABLE";
  return "UNAVAILABLE";
}

function providerRecordFreshness(value: JsonRecord): string {
  return providerLookupExecuted(value) ? freshnessLabel(value.freshness_state) : "NOT APPLICABLE";
}

function freshnessLabel(value: unknown): string {
  const normalized = String(value || "").trim().toUpperCase();
  if (["FRESH", "TI_FRESH"].includes(normalized)) return "FRESH";
  if (["STALE", "TI_STALE"].includes(normalized)) return "STALE";
  if (["EXPIRED", "TI_EXPIRED"].includes(normalized)) return "STALE (expired)";
  return summaryValue(value, "Not recorded");
}

function dataAge(value: unknown): string {
  if (!hasMeaningfulValue(value)) return "Not recorded";
  const timestamp = timestampMillis(value);
  if (timestamp === null) return "Not calculable";
  const ageSeconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (ageSeconds < 60) return `${ageSeconds}s`;
  if (ageSeconds < 3_600) return `${Math.floor(ageSeconds / 60)}m`;
  if (ageSeconds < 86_400) return `${Math.floor(ageSeconds / 3_600)}h`;
  return `${Math.floor(ageSeconds / 86_400)}d`;
}

function tiTimestampLabel(value: unknown): string {
  return thailandTimestamp(value);
}

function providerName(value: unknown): string {
  const name = String(value || "").toLowerCase();
  return ({ abuseipdb: "AbuseIPDB", otx: "AlienVault OTX", shodan_official: "Shodan" } as Record<string, string>)[name] || readableCode(value);
}

function providerContextNote(provider: unknown): string {
  const name = String(provider || "").toLowerCase();
  if (name === "abuseipdb") return "Third-party IP reputation and community reports; not model confidence or proof of this session’s behavior.";
  if (name === "otx") return "Third-party pulse context; a match does not confirm behavior in this session.";
  if (name === "shodan_official") return "Provider-observed internet host attributes; listed ports were not necessarily observed in this Cowrie session.";
  return "External provider context only; it does not establish session behavior, actor identity, or attribution.";
}

function providerStateLabel(state: string): string {
  return ({
    DATA: "Data",
    NO_DATA: "No data",
    ERROR: "Provider error",
    UNAVAILABLE: "Unavailable",
    STALE: "Stale",
  } as Record<string, string>)[state] || readableCode(state);
}

function providerLookupStatusLabel(value: unknown, state: string): string {
  const code = String(value || "").trim().toUpperCase();
  const labels: Record<string, string> = {
    OK: "Available",
    CACHED: "Available",
    AVAILABLE: "Available",
    NOT_FOUND: "No data",
    NO_DATA: "No data",
    PROVIDER_ERROR: "Provider error",
    ERROR: "Provider error",
    RATE_LIMITED: "Rate limited",
    AUTH_FAILED: "Authentication failed",
    REQUEST_FAILED: "Request failed",
    DISABLED: "Disabled",
    AUTH_DISABLED: "Authentication disabled",
    BUDGET_EXHAUSTED: "Budget exhausted",
    INVALID_OBSERVABLE: "Invalid observable",
    PENDING: "Pending",
    POLICY_BLOCKED: "Policy blocked",
    SKIPPED: "Skipped",
  };
  return labels[code] || (code ? readableCode(code) : providerStateLabel(state));
}

function providerFieldValue(value: unknown): string {
  if (Array.isArray(value)) {
    return value
      .filter(hasMeaningfulValue)
      .slice(0, 12)
      .map((item) => display(item))
      .join(" · ");
  }
  return display(value, "Not reported");
}

function ProviderMetadataGrid({ fields }: { fields: Array<readonly [string, string]> }) {
  return (
    <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border">
      {fields.map(([name, value]) => (
        <div key={name} className="min-w-0 bg-surface px-2.5 py-2">
          <dt className="text-[9px] font-semibold uppercase tracking-[0.08em] text-text-subtle">{name}</dt>
          <dd className="mt-0.5 break-words text-xs font-semibold text-primary-navy">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function normalizedProviderKey(value: unknown): string {
  const key = String(value || "").trim().toLowerCase();
  if (key.includes("abuseipdb")) return "abuseipdb";
  if (key === "otx" || key.includes("alienvault")) return "otx";
  if (key.includes("shodan")) return "shodan_official";
  return key || "unknown_provider";
}

function latestProviderRecord(items: JsonRecord[], timestampField: string): JsonRecord | null {
  return [...items].sort((left, right) => {
    return (timestampMillis(right[timestampField]) ?? 0) - (timestampMillis(left[timestampField]) ?? 0);
  })[0] ?? null;
}

function ProviderContextRows({
  evidence,
  cache,
  providerStatus,
  observable,
  asOf,
}: {
  evidence: JsonRecord[];
  cache: JsonRecord[];
  providerStatus: JsonRecord;
  observable: JsonRecord;
  asOf: number | null;
}) {
  const providerGroups = new Map<string, { provider: string; status: JsonRecord | null; evidence: JsonRecord[]; cache: JsonRecord[] }>();
  const getGroup = (provider: unknown) => {
    const key = normalizedProviderKey(provider);
    let group = providerGroups.get(key);
    if (!group) {
      group = { provider: key, status: null, evidence: [], cache: [] };
      providerGroups.set(key, group);
    }
    return group;
  };
  for (const [provider, value] of Object.entries(providerStatus)) {
    const status = record(value);
    if (Number(status.record_count || 0) > 0 || hasMeaningfulValue(status.lookup_status)) {
      getGroup(provider).status = status;
    }
  }
  for (const item of evidence) getGroup(item.provider).evidence.push(item);
  for (const item of cache) getGroup(item.provider).cache.push(item);
  const groups = Array.from(providerGroups.values()).sort((left, right) => {
    const order = ["abuseipdb", "otx", "shodan_official"];
    const leftOrder = order.indexOf(left.provider);
    const rightOrder = order.indexOf(right.provider);
    if (leftOrder !== rightOrder) return (leftOrder < 0 ? order.length : leftOrder) - (rightOrder < 0 ? order.length : rightOrder);
    return providerName(left.provider).localeCompare(providerName(right.provider));
  });
  if (groups.length === 0) return <p className="border-l-2 border-border pl-3 text-xs text-text-muted">No provider status, lookup result, or linked finding was returned for this observable.</p>;
  return (
    <div className="space-y-3">
      <p className="text-xs text-text-muted">Each panel separates lookup state, provider-specific intelligence, and findings linked to this session.</p>
      <div className="max-h-[620px] overflow-y-auto overscroll-contain pr-1" aria-label="Provider intelligence results">
      <ol className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {groups.slice(0, 12).map((group) => {
          const latestCache = latestProviderRecord(group.cache, "lookup_at");
          const latestEvidence = latestProviderRecord(group.evidence, "retrieved_at");
          const status = group.status;
          const provider = group.provider;
          const latestCacheWasQueried = Boolean(latestCache && providerLookupExecuted(latestCache));
          const source = (latestCache && hasMeaningfulValue(latestCache.lookup_status || latestCache.status) ? latestCache : null) || latestEvidence || status || latestCache || {};
          const lookupWasExecuted = latestCacheWasQueried
            || Boolean(latestEvidence && providerLookupExecuted(latestEvidence))
            || Boolean(status && hasMeaningfulValue(status.lookup_status) && providerLookupExecuted(status));
          const rawLookupState = String(source.lookup_status || source.status || "").trim().toUpperCase();
          const lookupFailed = ["PROVIDER_ERROR", "ERROR", "RATE_LIMITED", "AUTH_FAILED", "REQUEST_FAILED"].includes(rawLookupState);
          const lookupNotRun = ["DISABLED", "AUTH_DISABLED", "BUDGET_EXHAUSTED", "INVALID_OBSERVABLE", "PENDING", "POLICY_BLOCKED", "SKIPPED"].includes(rawLookupState);
          const normalized = record(latestCacheWasQueried ? latestCache?.normalized_context : undefined);
          const cacheFreshness = latestCacheWasQueried && latestCache ? sourceIpCacheFreshness(latestCache, asOf) : undefined;
          const freshness = latestCacheWasQueried ? freshnessLabel(cacheFreshness) : latestEvidence ? providerRecordFreshness(latestEvidence) : latestCache ? "NOT APPLICABLE" : providerRecordFreshness(status || {});
          const lookupState = latestCache
            ? tiLookupState(latestCache, cacheFreshness)
            : latestEvidence
              ? tiLookupState(latestEvidence)
              : status
                ? tiLookupState(status)
                : "UNAVAILABLE";
          const pulses = list(normalized.pulses).map(record);
          const summarizedProviderKeys = new Set(["pulses", "pulse_count", "abuse_confidence_score", "total_reports", "ports", "asn"]);
          const supplementalMap = new Map<string, readonly [string, string]>();
          for (const [key, value] of [
            ...selectedProviderFields(normalized),
            ...(latestEvidence ? selectedProviderFields(latestEvidence.normalized_extension) : []),
          ]) {
            if (!summarizedProviderKeys.has(key.toLowerCase())) supplementalMap.set(key.toLowerCase(), [key, value]);
          }
          const supplemental = Array.from(supplementalMap.values());
          const providerSpecificFields: Array<readonly [string, string]> = [];
          if (provider === "abuseipdb") {
            if (hasMeaningfulValue(normalized.abuse_confidence_score)) providerSpecificFields.push(["Abuse score", `${display(normalized.abuse_confidence_score)} / 100`]);
            if (hasMeaningfulValue(normalized.total_reports)) providerSpecificFields.push(["Community reports", display(normalized.total_reports)]);
          } else if (provider === "otx") {
            if (hasMeaningfulValue(normalized.pulse_count)) providerSpecificFields.push(["Pulse matches", display(normalized.pulse_count)]);
            else if (pulses.length > 0) providerSpecificFields.push(["Pulse matches", String(pulses.length)]);
            const pulseNames = pulses.map((pulse) => summaryValue(pulse.name, "")).filter(Boolean).slice(0, 2);
            if (pulseNames.length > 0) providerSpecificFields.push(["Pulse examples", pulseNames.join(" · ").slice(0, 140)]);
          } else if (provider === "shodan_official") {
            if (hasMeaningfulValue(normalized.ports)) providerSpecificFields.push(["Ports", providerFieldValue(normalized.ports)]);
            if (hasMeaningfulValue(normalized.asn)) providerSpecificFields.push(["ASN", display(normalized.asn)]);
          }
          const visibleSupplementalCount = Math.max(0, 6 - providerSpecificFields.length);
          const visibleProviderFields = [...providerSpecificFields, ...supplemental.slice(0, visibleSupplementalCount)];
          const technicalProviderFields = supplemental.slice(visibleSupplementalCount);
          const reportedAt = latestCache?.lookup_at || latestEvidence?.retrieved_at || status?.retrieved_at || status?.lookup_at;
          const expiresAt = (latestCacheWasQueried ? latestCache?.expires_at : undefined) || latestEvidence?.expires_at || status?.expires_at;
          const lookupStatus = hasMeaningfulValue(source.lookup_status || source.status)
            ? providerLookupStatusLabel(source.lookup_status || source.status, lookupState)
            : providerStateLabel(lookupState);
          const linkedFindings = group.evidence.length > 0
            ? `${group.evidence.length}${latestEvidence ? ` · ${readableCode(latestEvidence.finding_state || "state not recorded")}` : ""}`
            : "None";
          const providerRecords = hasMeaningfulValue(status?.record_count) ? countOf(status?.record_count) : "Not recorded";
          const checkedAt = hasMeaningfulValue(reportedAt) ? tiTimestampLabel(reportedAt) : lookupWasExecuted || lookupFailed ? "Not recorded" : "Not queried";
          const validUntil = hasMeaningfulValue(expiresAt) ? tiTimestampLabel(expiresAt) : lookupWasExecuted ? "Not recorded" : "Not applicable";
          const resultNote = lookupFailed
            ? `Provider lookup returned ${lookupStatus}; no normalized result is available.`
            : lookupNotRun
              ? `No provider lookup was executed. State: ${lookupStatus}.`
              : latestEvidence
              ? summaryValue(latestEvidence.summary, "A linked provider finding is stored.")
              : lookupWasExecuted
                ? "The lookup ran, but no normalized provider result is available."
                : hasMeaningfulValue(source.lookup_status || source.status)
                  ? `No provider result is available. State: ${lookupStatus}.`
                  : "Lookup state was not reported and no normalized provider result was returned.";
          return (
            <li key={provider} className="min-w-0 self-start overflow-hidden rounded-xl border border-border bg-surface">
              <div className="flex flex-wrap items-start justify-between gap-2 border-b border-border bg-surface-subtle px-3 py-2.5">
                <div className="min-w-0">
                  <h4 className="text-xs font-bold uppercase tracking-[0.08em] text-primary-navy">{providerName(provider)}</h4>
                  <p className="mt-0.5 text-[10px] text-text-muted">{latestCacheWasQueried ? "Source-IP lookup" : latestEvidence ? "Linked provider finding" : "Provider status"}</p>
                </div>
                <div className="flex flex-wrap justify-end gap-1.5">
                  <span className={`ui-badge text-[9px] uppercase ${lookupState === "ERROR" || lookupState === "UNAVAILABLE" ? "border-warning-border bg-warning-subtle text-warning" : ""}`}>{providerStateLabel(lookupState)}</span>
                  <span className="ui-badge text-[9px] uppercase">{readableCode(freshness)}</span>
                </div>
              </div>

              <div className="space-y-3 p-3">
                <ProviderMetadataGrid fields={[
                  ["Lookup status", lookupStatus],
                  ["Freshness", readableCode(freshness)],
                  ["Provider records", providerRecords],
                  ["Linked findings", linkedFindings],
                  ["Checked at", checkedAt],
                  ["Valid until", validUntil],
                ]} />

                <section className="border-t border-border pt-2.5" aria-label={`${providerName(provider)} provider-specific intelligence`}>
                  <h5 className="mb-2 text-[9px] font-semibold uppercase tracking-[0.08em] text-text-subtle">Provider-specific intelligence</h5>
                  {visibleProviderFields.length > 0
                    ? <ProviderMetadataGrid fields={visibleProviderFields.map(([key, value]) => [readableCode(key), value] as const)} />
                    : <p className="rounded-md bg-surface-subtle px-2.5 py-2 text-[11px] text-text-muted">No provider-specific fields were returned.</p>}
                </section>

                <p className="border-l-2 border-primary-border pl-2.5 text-[10px] leading-4 text-text-muted">{providerContextNote(provider)}</p>
                {!latestCacheWasQueried && <p className={`text-[10px] leading-4 ${lookupFailed ? "text-warning" : "text-text-muted"}`}>{resultNote}</p>}

                <details className="border-t border-border pt-2.5 text-xs">
                  <summary className="flex cursor-pointer list-none items-center gap-2 font-semibold text-text">
                    <span className="ui-badge text-[9px]">Technical details</span>
                    <span>Provenance and additional fields</span>
                  </summary>
                  <div className="mt-3 space-y-3">
                    <TechnicalFieldGrid fields={[
                      ["Observable type", summaryValue(latestCache?.observable_type || latestEvidence?.observable_type || status?.observable_type || observable.type, "source_ip")],
                      ["Observable role", summaryValue(latestCache?.observable_role || latestEvidence?.observable_role || status?.observable_role || "source_ip", "Not recorded")],
                      ["Provider observed at", thailandTimestamp(latestCache?.provider_observed_at || latestEvidence?.provider_observed_at || status?.provider_observed_at)],
                      ["Data age", dataAge(reportedAt)],
                      ["Session binding", summaryValue(latestEvidence?.session_id || latestCache?.session_id, "Not recorded")],
                      ...technicalProviderFields.map(([key, value]) => [readableCode(key), value] as const),
                    ]} />
                    {group.evidence.length > 1 && (
                      <section>
                        <h6 className="mb-2 text-[10px] font-semibold uppercase tracking-wide text-text-subtle">Other linked findings · {group.evidence.length - 1}</h6>
                        <ol className="divide-y divide-border rounded-md border border-border">
                          {group.evidence.filter((item) => item !== latestEvidence).slice(0, 10).map((item, index) => <li key={`${index}-${label(item.evidence_id, "finding")}`} className="px-2.5 py-2">
                            <p className="font-semibold text-text">{readableCode(item.finding_state || "not recorded")}</p>
                            <p className="mt-1 text-text-muted">{summaryValue(item.summary, "No provider finding summary stored.")}</p>
                            <p className="mt-1 text-[10px] text-text-subtle">{thailandTimestamp(item.retrieved_at)} · evidence {summaryValue(item.evidence_id, "not linked")}</p>
                          </li>)}
                        </ol>
                      </section>
                    )}
                  </div>
                </details>
              </div>
            </li>
          );
        })}
      </ol>
      </div>
    </div>
  );
}

function AuthenticationSummary({ data }: { data: JsonRecord }) {
  const attempts = list(data.attempts).map(record);
  const storedCounts = [data.attempt_count, data.success_count, data.failure_count].some(hasMeaningfulValue);
  const visibleUsernames = Array.from(new Set(
    attempts.map(analystAttackerUsername).filter((value): value is string => Boolean(value)),
  ));
  return (
    <div className="space-y-2.5">
      <dl className="grid grid-cols-3 divide-x divide-border rounded-lg border border-border bg-surface-subtle py-1">
        {[["Attempts", data.attempt_count], ["Succeeded", data.success_count], ["Failed", data.failure_count]].map(([name, value]) => <div key={String(name)} className="min-w-0 px-2 py-2 text-center"><dt className="text-[9px] font-semibold uppercase tracking-[0.08em] text-text-subtle">{String(name)}</dt><dd className="mt-0.5 text-sm font-semibold text-primary-navy">{hasMeaningfulValue(value) ? countOf(value) : "Not recorded"}</dd></div>)}
      </dl>
      {attempts.length > 0 && <p className="text-[11px] text-text-muted">{visibleUsernames.length ? `Observed account: ${visibleUsernames.join(", ")}.` : "Account name not retained."} Authentication records are not proof of identity.</p>}
      {attempts.length > 0 ? (
        <section className="max-h-[28rem] overflow-y-auto overscroll-contain rounded-lg border border-border" aria-label="Authentication attempts">
        <div className="sticky top-0 z-10 border-b border-border bg-surface-subtle px-3 py-2 text-xs font-semibold text-primary-navy">Login activity · {attempts.length}</div>
        <ol className="divide-y divide-border">
          {attempts.slice(0, 20).map((attempt, index) => (
            <li key={`${index}-${summaryValue(attempt.timestamp, "attempt")}`} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2.5 text-[11px]">
              <span className="font-medium text-text">{readableCode(attempt.outcome || "login attempt")} · {analystAttackerUsername(attempt) || summaryValue(attempt.username_visibility, "Account not retained")}{hasMeaningfulValue(attempt.method) ? ` · ${readableCode(attempt.method)}` : ""}</span>
              <time className="font-mono text-text-muted" dateTime={String(attempt.timestamp || "")}>{thailandTimestamp(attempt.timestamp)}</time>
            </li>
          ))}
        </ol>
        </section>
      ) : <p className="rounded-lg border border-border bg-surface-subtle px-3 py-2.5 text-[11px] text-text-muted">{Number(data.attempt_count) === 0 ? "No authentication attempts recorded." : storedCounts ? "No authentication attempt records are available." : "Authentication attempt details were not retained."}</p>}
      {hasMeaningfulValue(data.first_attempt_at) || hasMeaningfulValue(data.last_attempt_at) ? <p className="text-[10px] text-text-subtle">First: {thailandTimestamp(data.first_attempt_at)} · Last: {thailandTimestamp(data.last_attempt_at)}</p> : null}
    </div>
  );
}

export function SourcePivotSummary({ data }: { data: JsonRecord }) {
  const counts = record(data.counts);
  const sessions = list(data.sessions).map(record);
  const sourceIp = summaryValue(record(data.observable).value, "Source IP not recorded");
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-border pb-2">
        <p className="break-all font-mono text-base font-semibold text-primary-navy">{sourceIp}</p>
        <span className="ui-badge text-[10px]">Recurrence context · not attribution</span>
      </div>
      <dl className="grid grid-cols-3 divide-x divide-border rounded-lg border border-border bg-surface-subtle">
        {[["Related sessions", hasMeaningfulValue(counts.sessions_found) ? countOf(counts.sessions_found) : "Not recorded"], ["Sightings examined", hasMeaningfulValue(counts.sightings_examined) ? countOf(counts.sightings_examined) : "Not recorded"], ["Provider calls", data.provider_calls === false ? "No" : data.provider_calls === true ? "Yes" : "Not reported"]].map(([name, value]) => <div key={String(name)} className="min-w-0 px-2 py-2 text-center"><dt className="text-[9px] font-semibold uppercase tracking-[0.08em] text-text-subtle">{name}</dt><dd className="mt-0.5 text-sm font-semibold text-primary-navy">{value}</dd></div>)}
      </dl>
      {sessions.length > 0 ? <div className="max-h-[28rem] overflow-auto overscroll-contain rounded-lg border border-border">
        <table className="w-full min-w-[560px] text-left text-xs">
          <thead className="sticky top-0 z-10 bg-primary-navy-soft text-[10px] uppercase tracking-[0.08em] text-primary-navy"><tr><th scope="col" className="px-3 py-2 font-semibold">Session</th><th scope="col" className="px-3 py-2 font-semibold">First seen (ICT)</th><th scope="col" className="px-3 py-2 font-semibold">Last seen (ICT)</th><th scope="col" className="px-3 py-2 text-right font-semibold">Sightings</th></tr></thead>
          <tbody className="divide-y divide-border">
            {sessions.slice(0, 50).map((session, index) => <tr key={`${index}-${summaryValue(session.session_id, "session")}`}>
              <td className="px-3 py-2.5"><details className="group"><summary className="max-w-[240px] cursor-pointer break-all font-mono text-[11px] font-semibold text-primary-navy">{summaryValue(session.session_id, "Session unavailable")}</summary><div className="mt-2 rounded-md bg-surface-subtle p-2"><p className="mb-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-text-subtle">Technical details</p><TechnicalFieldGrid fields={[["Observable role", traceList(session.roles, "source_ip")], ["Sources", traceList(session.sources)], ["Sensor IDs", traceList(session.sensor_ids)]]} empty="No additional session-source details were recorded." /></div></details></td>
              <td className="whitespace-nowrap px-3 py-2.5 font-mono text-[10px] text-text-muted">{thailandTimestamp(session.first_seen)}</td>
              <td className="whitespace-nowrap px-3 py-2.5 font-mono text-[10px] text-text-muted">{thailandTimestamp(session.last_seen)}</td>
              <td className="px-3 py-2.5 text-right font-semibold text-primary-navy">{countOf(session.sighting_count)}</td>
            </tr>)}
          </tbody>
        </table>
      </div> : <p className="text-xs text-text-muted">No related session records were returned for this source IP.</p>}
      <p className="text-[10px] leading-4 text-text-subtle">Repeated source-IP activity indicates recurrence only, not shared identity, intent, or attribution.</p>
    </div>
  );
}

export function ExternalTiSummary({ sessionData, observableData }: { sessionData: JsonRecord; observableData: JsonRecord }) {
  const sessionCounts = record(sessionData.counts);
  const summary = { ...record(sessionData.external_ti_summary), ...record(observableData.external_ti_summary) };
  const entities = list(sessionData.shared_entities).map(record);
  const evidence = Array.from(new Map(
    [...list(sessionData.evidence), ...list(observableData.evidence)]
      .map(record)
      .map((item) => {
        const identity = label(
          item.evidence_id,
          [item.provider, item.observable_value, item.retrieved_at, item.finding_state, item.summary].map((value) => label(value, "")).join(":"),
        );
        return [identity, item] as const;
      }),
  ).values());
  const cache = Array.from(new Map(
    [...list(sessionData.source_ip_cache), ...list(observableData.source_ip_cache)]
      .map(record)
      .map((item) => [`${label(item.provider)}:${label(item.cache_key)}:${label(item.lookup_at)}`, item] as const),
  ).values());
  const providerStatus = { ...record(sessionData.provider_status), ...record(observableData.provider_status) };
  const jobSummary = record(sessionData.enrichment_job_summary);
  const jobStatusCounts = record(jobSummary.status_counts);
  const freshness = record(sessionData.freshness);
  const observable = record(observableData.observable);
  const [asOf, setAsOf] = useState<number | null>(null);
  useEffect(() => {
    const timer = window.setTimeout(() => setAsOf(Date.now()), 0);
    const interval = window.setInterval(() => setAsOf(Date.now()), 60_000);
    return () => {
      window.clearTimeout(timer);
      window.clearInterval(interval);
    };
  }, [sessionData, observableData]);
  const tiState = externalTiFreshness({
    rawState: freshness.state,
    freshness,
    summary,
    evidence,
    cache,
    providerStatus,
    asOf,
  });
  const executedCache = cache.filter(providerLookupExecuted);
  const availableEvidence = evidence.filter(providerLookupExecuted);
  const providersWithLookupResults = new Set([...executedCache, ...availableEvidence].map((item) => normalizedProviderKey(item.provider))).size;
  const providerCount = new Set([
    ...evidence.map((item) => normalizedProviderKey(item.provider)),
    ...cache.map((item) => normalizedProviderKey(item.provider)),
    ...Object.keys(providerStatus).filter((provider) => hasMeaningfulRecord(record(providerStatus[provider]))).map(normalizedProviderKey),
  ]).size;
  const lookupRecords = [...evidence, ...cache, ...Object.values(providerStatus).map(record)];
  const explicitNoLookupStatus = lookupRecords.some((item) => [
    "DISABLED", "AUTH_DISABLED", "BUDGET_EXHAUSTED", "INVALID_OBSERVABLE", "PENDING", "POLICY_BLOCKED", "SKIPPED",
  ].includes(String(item.lookup_status || item.status || "").trim().toUpperCase()));
  const noLookupReasonRecorded = String(sessionData.status_reason_text || "").toLowerCase().includes("no provider lookup");
  const noLookupExecuted = executedCache.length === 0 && availableEvidence.length === 0 && (explicitNoLookupStatus || noLookupReasonRecorded);
  const metrics: Array<readonly [string, string]> = [
    ["Eligible observables", hasMeaningfulValue(sessionCounts.eligible_observables) ? countOf(sessionCounts.eligible_observables) : "Not recorded"],
    ["Providers with results", String(providersWithLookupResults)],
    ["Provider evidence records", String(evidence.length)],
    ["Fresh / stale", `${countOf(tiState.freshCacheCount)} / ${countOf(tiState.staleCacheCount + tiState.staleEvidenceCount)}`],
    ["Last lookup", noLookupExecuted ? "Not executed" : tiState.state === "UNAVAILABLE" ? "Unavailable" : tiTimestampLabel(tiState.latestRetrievedAt)],
  ];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-text-muted">{summaryValue(observable.value, "Observable not recorded")} · provider intelligence is contextual, not attribution or behavioral proof.</p>
        <span className={`ui-badge text-[10px] ${tiState.state === "FRESH" ? "border-primary-border bg-primary-subtle text-primary" : tiState.state === "UNAVAILABLE" ? "border-warning-border bg-warning-subtle text-warning" : ""}`}>{readableCode(tiState.state)}</span>
      </div>
      <dl className="grid grid-cols-2 divide-x divide-y divide-border border-y border-border sm:grid-cols-3 sm:divide-y-0 xl:grid-cols-5">
        {metrics.map(([name, value]) => <div key={name} className="min-w-0 px-2.5 py-2"><dt className="text-[9px] font-semibold uppercase tracking-[0.08em] text-text-subtle">{name}</dt><dd className="mt-0.5 break-words text-[11px] font-semibold text-text">{value}</dd></div>)}
      </dl>
      {executedCache.length > 0 ? <p className="text-[10px] text-text-muted">{executedCache.length} source-IP provider lookup result{executedCache.length === 1 ? "" : "s"}. Provider intelligence is contextual—not evidence of this session’s behavior, actor identity, or response authority.</p> : noLookupExecuted ? <p className="text-[10px] text-text-muted">No provider lookup was executed for this session. Last lookup: Not executed. {summaryValue(sessionData.status_reason_text, "No usable provider result is linked.")}</p> : <p className="text-[10px] text-text-muted">No source-IP cache result is stored; provider evidence records are displayed separately.</p>}
      {jobSummary.pending === true && (
        <p className="rounded-md border border-warning-border bg-warning-subtle/60 px-3 py-2 text-[11px] text-text-muted">
          {summaryValue(sessionData.status_reason_text, "An eligible provider lookup is awaiting the enrichment worker.")}
          {Object.keys(jobStatusCounts).length > 0 && ` Queue state: ${Object.entries(jobStatusCounts).map(([state, count]) => `${state}=${count}`).join(", ")}.`}
        </p>
      )}
      {tiState.state === "MIXED" && (
        <p className="rounded-md border border-warning-border bg-warning-subtle/60 px-3 py-2 text-[11px] text-text-muted">
          Fresh source-IP cache data is available ({tiState.freshCacheCount} provider result{tiState.freshCacheCount === 1 ? "" : "s"}); older stored provider evidence is stale ({tiState.staleEvidenceCount} record{tiState.staleEvidenceCount === 1 ? "" : "s"}). Freshness is shown per record below.
        </p>
      )}
      {entities.length > 0 && <ContentPanel title="Related observables and sightings" count={entities.length}><ObservableList items={entities} empty="No shared entities are recorded." /></ContentPanel>}
      {providerCount > 0 ? <div className="space-y-2">
        <div className="flex items-center justify-between gap-2"><h3 className="text-xs font-semibold uppercase tracking-[0.08em] text-primary-navy">Provider Intelligence</h3><span className="ui-badge text-[10px]">{providerCount} provider{providerCount === 1 ? "" : "s"} · state per panel</span></div>
        <ProviderContextRows evidence={evidence} cache={cache} providerStatus={providerStatus} observable={observable} asOf={asOf} />
      </div> : <p className="border-l-2 border-border pl-3 text-xs text-text-muted">No provider result or lookup state is stored. {readableCode(summary.uncertainty || sessionData.status || "context only")}.</p>}
    </div>
  );
}

function hypothesisGateExplanation(value: unknown): string {
  const code = String(value || "");
  return ({
    effect_status_not_eligible: "The observed command did not confirm the required effect.",
    outcome_not_eligible: "The recorded outcome did not confirm success.",
    additional_operation_not_activated: "A required follow-up operation was not observed.",
    no_fact_for_activated_family: "No matching behavior fact was recorded.",
    canonical_finding_not_emitted_after_match: "A selector matched but no canonical finding was emitted; review the assessment pipeline.",
    typed_semantic_evaluation_unavailable: "The typed behavior check was unavailable.",
    semantic_selector_error: "The behavior selector failed; review processing logs.",
  } as Record<string, string>)[code] || readableCode(code);
}

export function HypothesisSummary({ data }: { data: JsonRecord }) {
  const counts = record(data.counts);
  const reportSummary = record(data.report_summary);
  const hypotheses = list(data.correlated_ttp_hypotheses);
  const contextualHypotheses = projectContextualHypotheses(hypotheses);
  const hypothesisSets = list(data.hypothesis_sets).map(record);
  const sessionAssessment = record(data.session_hypothesis_assessment);
  const sessionFamilies = list(sessionAssessment.semantic_families).map(record);
  const sessionGraph = record(sessionAssessment.evidence_graph);
  const followOnAssessment = record(sessionAssessment.follow_on_hypothesis);
  const reports = list(data.reports);
  const canonicalCount = list(sessionAssessment.canonical_finding_ids).length;
  const assessmentOutcome = hypothesisSets.length > 0
    ? `${hypothesisSets.length} evidence-bounded hypothesis set${hypothesisSets.length === 1 ? "" : "s"} recorded`
    : canonicalCount > 0
      ? `${canonicalCount} canonical behavioral finding${canonicalCount === 1 ? "" : "s"} established`
      : "No threat hypothesis or canonical finding established";
  const relationshipCount = Number(sessionGraph.relationship_edges || 0);
  const missingEvidence = list(sessionAssessment.missing_evidence).slice(0, 4);
  return (
    <div className="space-y-3">
      <div className="border-l-2 border-primary-border pl-3">
        <p className="text-[9px] font-semibold uppercase tracking-[0.12em] text-text-subtle">Assessment outcome</p>
        <p className="mt-0.5 text-sm font-semibold text-text">{assessmentOutcome}</p>
        <p className="mt-0.5 text-[11px] text-text-muted">Analyst interpretation only · not response authority</p>
      </div>
      <dl className="grid grid-cols-3 divide-x divide-border rounded-lg border border-border bg-surface-subtle">
        {[["Hypothesis sets", String(hypothesisSets.length)], ["Canonical findings", String(canonicalCount)], ["Related TTP context", String(contextualHypotheses.length)]].map(([name, value]) => <div key={name} className="min-w-0 px-2.5 py-2.5 text-center sm:px-3"><dt className="text-[9px] font-semibold uppercase tracking-[0.1em] text-text-subtle sm:text-[10px]">{name}</dt><dd className="mt-0.5 text-base font-semibold text-text">{value}</dd></div>)}
      </dl>
      {hypothesisSets.length === 0 && missingEvidence.length > 0 && <details className="rounded-lg border border-border bg-surface-subtle px-3 py-2 text-xs">
        <summary className="cursor-pointer font-semibold text-text">Why no hypothesis was established · {missingEvidence.length} gate{missingEvidence.length === 1 ? "" : "s"}</summary>
        <ul className="mt-2 list-inside list-disc space-y-1 text-text-muted">{missingEvidence.map((reason, index) => <li key={`${String(reason)}-${index}`}>{hypothesisGateExplanation(reason)}</li>)}</ul>
        <p className="mt-2 text-[10px] text-text-subtle">An observed command is not proof that its effect succeeded.</p>
      </details>}
      {sessionFamilies.length > 0 && (
        <details className="group rounded-lg border border-border">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3 py-2.5 text-xs"><span className="font-semibold text-text">Behavior gate checks</span><span className="flex items-center gap-2"><span className="ui-badge text-[10px]">{sessionFamilies.length}</span><ChevronDown className="h-3.5 w-3.5 text-text-muted transition-transform group-open:rotate-180" aria-hidden="true" /></span></summary>
          <ul className="divide-y divide-border border-t border-border">
            {sessionFamilies.map((family, index) => <li key={`${summaryValue(family.semantic_family, "family")}-${index}`} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-xs">
              <span className="font-medium text-text">{readableCode(family.semantic_family || "behavior not recorded")}</span><span className="text-text-muted">{countOf(family.observed_fact_count)} observations · {countOf(list(family.finding_ids).length)} findings</span><span className="ui-badge text-[10px]">{readableCode(family.status || "not evaluated")}</span>
              {list(family.missing_evidence).length > 0 && <p className="basis-full text-[11px] text-text-subtle">Gate: {list(family.missing_evidence).map(hypothesisGateExplanation).join(" ")}</p>}
            </li>)}
          </ul>
        </details>
      )}
      {contextualHypotheses.length > 0 && (
        <details className="rounded-lg border border-border px-3 py-2">
          <summary className="cursor-pointer text-xs font-semibold text-text">Related ATT&amp;CK context · not confirmed behavior <span className="ui-badge ml-1 text-[10px]">{contextualHypotheses.length}</span></summary>
          <ol className="mt-2 divide-y divide-border border-t border-border">
            {contextualHypotheses.map((hypothesis) => <li key={hypothesis.key} className="py-2 text-xs">
              <div className="flex flex-wrap items-center gap-2"><span className="font-mono font-semibold text-text">{hypothesis.techniqueId || "Technique unavailable"}</span>{hypothesis.techniqueName && <span className="text-text-muted">{hypothesis.techniqueName}</span>}{hypothesis.tactic && <span className="ui-badge text-[10px]">{readableCode(hypothesis.tactic)}</span>}</div>
              {hypothesis.matchedConditions.length > 0 && <p className="mt-1 text-[11px] text-text-muted">Related evidence: {hypothesis.matchedConditions.map((condition) => condition.description || readableCode(condition.type || "observation")).join(" · ")}</p>}
            </li>)}
          </ol>
        </details>
      )}
      {hypothesisSets.length > 0 && (
        <ContentPanel title="Evidence-bounded hypothesis sets" count={hypothesisSets.length}>
        <ol className="space-y-2">
          {hypothesisSets.slice(0, 50).map((hypothesisSet, index) => (
            <li key={`${index}-${summaryValue(hypothesisSet.hypothesis_set_id, "hypothesis-set")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs">
              <p className="font-semibold text-text">{summaryValue(hypothesisSet.question, "Bounded hypothesis set")}</p>
              {list(hypothesisSet.hypotheses).map(record).slice(0, 8).map((hypothesis, hypothesisIndex) => (
                <div key={`${hypothesisIndex}-${summaryValue(hypothesis.hypothesis_id, "hypothesis")}`} className="mt-2 rounded border border-border bg-surface px-2.5 py-2">
                  <p className="text-text">{summaryValue(hypothesis.statement, "Hypothesis statement unavailable")}</p>
                  {list(hypothesis.artifact_paths).length > 0 && <p className="mt-1 text-text-muted">Artifact/path: {list(hypothesis.artifact_paths).map((value) => display(value)).join(", ")}</p>}
                  {list(hypothesis.falsification_conditions).length > 0 && <p className="mt-1 text-text-muted">Falsifiers: {list(hypothesis.falsification_conditions).map((value) => display(value)).join(" ")}</p>}
                </div>
              ))}
            </li>
          ))}
        </ol>
        </ContentPanel>
      )}
      {hypotheses.length === 0 && hypothesisSets.length === 0 && <p className="text-[11px] text-text-subtle">No session-correlated ATT&amp;CK context was recorded.</p>}
      <MoreDetails title="Assessment method and report notes">
        <SummaryGrid fields={[
          ["Authority", summaryValue(data.authority, "Contextual only")],
          ["Correlation records", countOf(hypotheses.length || counts.correlations)],
          ["Evidence strength", readableCode(reportSummary.evidence_strength || reportSummary.analytical_evidence_strength || "not recorded")],
          ["Analysis mode", readableCode(reportSummary.analysis_mode || "not recorded")],
          ["Campaign", summaryValue(reportSummary.campaign_name, "Not recorded")],
          ["Follow-on assessment", readableCode(followOnAssessment.status || "not assessed")],
          ["Evidence nodes", countOf(sessionGraph.evidence_nodes)],
          ["Relationship links", countOf(relationshipCount)],
          ["Reports", countOf(reports.length)],
        ]} />
        {hasMeaningfulValue(reportSummary.summary) && <p className="mt-3 rounded-lg border border-border bg-surface-subtle p-3 text-sm text-text">{summaryValue(reportSummary.summary)}</p>}
        {hasMeaningfulValue(reportSummary.evidence_strength_reason) && <p className="mt-2 text-xs text-text-muted">Assessment note: {summaryValue(reportSummary.evidence_strength_reason)}</p>}
        <p className="mt-3 text-[11px] text-text-subtle">Context does not confirm behavior or attacker intent.</p>
      </MoreDetails>
    </div>
  );
}

function GuidanceSummary({ data }: { data: JsonRecord }) {
  const guidance = record(data.response_guidance);
  const recommendations = record(data.report_recommendations);
  const actions = list(guidance.advisory_actions).map(record).length > 0
    ? list(guidance.advisory_actions).map(record)
    : list(recommendations.recommended_actions_structured).map(record);
  const validation = record(guidance.validation);
  const findingCount = Number(guidance.finding_count || 0);
  const boundFindingIds = new Set(actions.flatMap((action) => list(action.finding_ids).map((id) => label(id, "")).filter(Boolean)));
  const hasFindingBindings = actions.some((action) => Array.isArray(action.finding_ids));
  const unmatchedFindingCount = hasFindingBindings ? Math.max(0, findingCount - boundFindingIds.size) : null;
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-3 divide-x divide-border rounded-lg border border-border bg-surface-subtle">
        {[["Findings", countOf(findingCount)], ["Reviewed actions", String(actions.length)], ["Approval", guidance.requires_manual_approval === false ? "Not required" : "Required"]].map(([name, value]) => <div key={name} className="min-w-0 px-2 py-2.5 text-center"><dt className="text-[9px] font-semibold uppercase tracking-[0.08em] text-text-subtle">{name}</dt><dd className="mt-0.5 break-words text-xs font-semibold text-text">{value}</dd></div>)}
      </dl>
      <p className="text-[11px] text-text-muted">Policy-matched guidance for analyst review; no response is executed automatically.</p>
      {actions.length > 0 ? (
        <section className="overflow-hidden rounded-lg border border-border">
        <div className="flex items-center justify-between gap-2 bg-surface-subtle px-3 py-2"><h3 className="text-xs font-semibold text-text">Suggested analyst actions</h3><span className="ui-badge text-[10px]">{actions.length}</span></div>
        <ol className="divide-y divide-border">
          {actions.slice(0, 20).map((action, index) => (
            <li key={`${index}-${summaryValue(action.action_id, "action")}`} className="px-3 py-2.5 text-xs">
              <div className="flex flex-wrap items-start justify-between gap-2"><p className="font-semibold text-text">{summaryValue(action.description || action.action_id, "Stored analyst action")}</p><span className="ui-badge text-[10px]">{action.requires_manual_approval === false ? "Review not required" : "Human review required"}</span></div>
              <details className="mt-1.5">
                <summary className="cursor-pointer text-[10px] font-medium text-primary">Rationale, checks &amp; traceability</summary>
                <div className="mt-2 rounded-md bg-surface-subtle p-2.5">
                  <p className="leading-5 text-text-muted">{summaryValue(action.rationale, "No rationale recorded.")}</p>
                  {list(action.preconditions).length > 0 && <p className="mt-1.5 text-text-muted"><span className="font-semibold text-text">Before:</span> {list(action.preconditions).map((value) => display(value)).join(" ")}</p>}
                  {list(action.verification_steps).length > 0 && <p className="mt-1 text-text-muted"><span className="font-semibold text-text">Verify:</span> {list(action.verification_steps).map((value) => display(value)).join(" ")}</p>}
                  <span className="mt-2 inline-flex ui-badge text-[10px]">{action.safe_to_auto_execute === true ? "Automatic execution allowed by policy" : "No automatic action"}</span>
                  <GuidanceTraceability action={action} guidance={guidance} />
                </div>
              </details>
            </li>
          ))}
        </ol>
        </section>
      ) : <p className="rounded-md border border-border bg-surface-subtle px-3 py-2.5 text-xs text-text-muted">No policy-approved response action is available for the current evidence.</p>}
      {unmatchedFindingCount !== null && unmatchedFindingCount > 0 && (
        <p className="mt-3 rounded-lg border border-border bg-surface-subtle p-3 text-xs text-text-muted">
          {unmatchedFindingCount} evidence finding{unmatchedFindingCount === 1 ? " does" : "s do"} not select a distinct reviewed action playbook. Actions are policy-matched and deduplicated; findings are not converted into recommendations automatically.
        </p>
      )}
      <MoreDetails title="Guidance policy and validation">
        <SummaryGrid fields={[["Validation", summaryValue(validation.status, "Not recorded")], ["Authority", summaryValue(guidance.authority, "Not recorded")]]} />
        {hasMeaningfulValue(validation.error) && <p className="mt-2 text-xs text-warning">{summaryValue(validation.error)}</p>}
      </MoreDetails>
    </div>
  );
}

function booleanLabel(value: unknown): string {
  if (value === true) return "YES";
  if (value === false) return "NO";
  return "Not reported";
}

export function Model2EnsembleSummary({ data }: { data: JsonRecord }) {
  const ensemble = record(data.ensemble_evidence);
  const model1 = record(ensemble.model1);
  const model2 = record(ensemble.model2);
  const binding = record(model2.binding);
  const unavailableHeads = Object.entries(record(model2.unavailable_heads));
  const results = list(ensemble.results).map(record);
  const model2OnlyPredictions = hasBoundAvailableModel2(data)
    ? results.filter((item) => item.model2_relation === "MODEL2_ONLY" && item.model2_result === "PRESENT")
    : [];
  const recommendations = rankTtpRecommendations(data);
  const rrf = record(record(data.session_ttp_advisory).rrf_recommendation);
  const weighted = record(record(data.session_ttp_advisory).weighted_voting_recommendation);
  const weightedRows = new Map(list(weighted.rows).map(record).map((item) => [label(item.technique_id, ""), item]));
  const recommendedTechnique = recommendations[0] || null;
  const otherTechniques = recommendations.slice(1).sort((a, b) => a.techniqueId.localeCompare(b.techniqueId));
  const displayedTechniques = recommendedTechnique ? [recommendedTechnique, ...otherTechniques] : [];
  const weightedTopRecommendation = list(weighted.recommendation_order)[0];
  const rrfTopRecommendation = list(rrf.recommendation_order)[0];
  const weightedReady = weighted.schema_version === "session_ttp_weighted_voting_advisory.v1"
    && weighted.session_id === data.session_id
    && recommendations.some((item) => item.rankingScore !== null);
  const techniqueNames = new Map<string, string>();
  [...list(data.classification_events), ...list(data.observed_trusted_ttps), ...results].map(record).forEach((item) => {
    const id = display(item.technique_id || item.ttp, "");
    const name = display(item.name || item.technique_name, "");
    if (id && name) techniqueNames.set(id, name);
  });

  if (!hasMeaningfulRecord(ensemble) && recommendations.length === 0) {
    return <p className="text-xs text-text-muted">No stored Model1 + Model2 evidence is available for this session.</p>;
  }

  const architecture = model2.one_model === true
    ? "UNIFIED_ONE_MODEL"
    : model2.one_model === false
      ? "NOT_UNIFIED"
      : "Not reported";

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-text-muted">One Model1 candidate is highlighted for analyst review; exact-bound Model2 support may affect that recommendation, but never creates a TTP or finding.</p>
        <span className="ui-badge text-[10px]">{weightedReady ? "Gated weighted voting · PoC" : "Model1 recommendation"}</span>
      </div>
      <dl className="grid grid-cols-3 divide-x divide-border rounded-lg border border-border bg-surface-subtle">
        {[["Model 1", model1.applicable === true || recommendations.length > 0 ? `${recommendations.length} candidates` : model1.applicable === false ? "Not applicable" : "Not reported"], ["Model 2", hasBoundAvailableModel2(data) ? model2.availability === "PARTIAL" ? "Partial binding" : "Exact binding" : "Unavailable"], ["Techniques compared", String(results.length)]].map(([name, value]) => <div key={name} className="min-w-0 px-2.5 py-2.5 text-center sm:px-3"><dt className="text-[9px] font-semibold uppercase tracking-[0.1em] text-text-subtle sm:text-[10px]">{name}</dt><dd className="mt-0.5 text-sm font-semibold text-text">{value}</dd></div>)}
      </dl>
      {!hasBoundAvailableModel2(data) && <p className="text-[10px] text-text-muted">No session-bound Model2 result is available (status: {readableCode(model2.status || "not reported")}); it did not corroborate or change the Model1 recommendation.</p>}
      {model2OnlyPredictions.length > 0 && <p className="rounded-md border border-border bg-surface-subtle px-3 py-2 text-[11px] text-text-muted">{model2OnlyPredictions.map((item) => `Experimental Model2-only prediction for ${summaryValue(item.technique_id, "unknown technique")}`).join("; ")}: not a confirmed observed behavior, canonical finding, or response decision. Excluded from the Model1-led recommendation list.</p>}
      {model2.availability === "PARTIAL" && unavailableHeads.length > 0 && <details className="rounded-xl border border-warning-border bg-warning-subtle/50">
      <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-text">Why Model2 is partial · unavailable heads <span className="ui-badge ml-2">{unavailableHeads.length}</span></summary>
        <ul className="space-y-2 border-t border-warning-border px-4 py-3 text-sm text-text">{unavailableHeads.map(([technique, reason]) => <li key={technique}><span className="font-mono font-semibold">{technique}</span>: {reason === "t1046_unbound_sensor_context" ? "Nearby sensor traffic shares the source IP and time window, but it is not bound to this Cowrie session. It cannot corroborate T1046." : reason === "t1046_not_observed" || reason === "t1046_multiservice_scan_evidence_missing" ? "No exact-bound multiservice scan observation was recorded. A Cowrie SSH session alone does not establish T1046." : reason === "t1046_scan_evidence_invalid" ? "The scan observation did not pass exact PCAP/Zeek measurement binding checks." : readableCode(reason)}</li>)}</ul>
      </details>}
      {displayedTechniques.length > 0 ? <section className="overflow-hidden rounded-lg border border-border">
        <div className="flex flex-wrap items-start justify-between gap-2 bg-surface-subtle px-3 py-2.5">
          <div>
            <h3 className="text-xs font-semibold text-text">TTP candidates</h3>
            <p className="mt-0.5 text-[10px] text-text-muted">Only the highlighted candidate is recommended; the remaining Model1 TTPs are listed without a priority label.</p>
          </div>
          <span className="ui-badge text-[10px]">Advisory only · not findings</span>
        </div>
        <ul className="divide-y divide-border">
          {displayedTechniques.map((item, index) => <li key={item.techniqueId} className={`grid gap-1.5 px-3 py-2.5 text-xs sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:items-center ${index === 0 ? "bg-primary-subtle/20" : ""}`}>
            {index === 0 ? <span className="ui-badge w-fit border-primary-border bg-surface text-[10px] font-bold uppercase text-primary-navy">Recommend</span> : <span aria-hidden="true" />}
            <div className="min-w-0"><p className="font-mono font-semibold text-text">{item.techniqueId}<span className="ml-2 font-sans font-medium text-text-muted">{techniqueNames.get(item.techniqueId) || model1TechniqueName(item.techniqueId) || "Technique name unavailable"}</span></p><p className="mt-0.5 text-[10px] text-text-muted">{item.supportingCommandEvents} of {item.assessedCommandEvents} assessed command events support Model1{index === 0 && item.evidenceRefs.length ? ` · Command refs: ${item.evidenceRefs.slice(0, 4).map((ref) => ref.commandRef).join(", ")}${item.evidenceRefs.length > 4 ? "…" : ""}` : ""}</p></div>
            {index === 0 && item.model2SupportAdded ? <span className="ui-badge w-fit text-[10px]">Model1 + Model2 support</span> : null}
          </li>)}
        </ul>
      </section> : <p className="rounded-md border border-border bg-surface-subtle px-3 py-2 text-xs text-text-muted">No deduplicated command-level Model1 advisory is available. Stable command references may be absent in older snapshots.</p>}
      {weighted.schema_version === "session_ttp_weighted_voting_advisory.v1" && <details className="rounded-xl border border-border bg-surface">
        <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-text">Compare ranking formulas <span className="ui-badge ml-2">PoC</span></summary>
        <div className="grid gap-3 border-t border-border p-3 md:grid-cols-2">
          <div className="rounded-lg border border-primary-border bg-primary-subtle/40 p-3 text-xs">
            <p className="font-semibold text-text">Formula used for the PoC recommendation: gated weighted voting</p>
            <p className="mt-1 break-words font-mono text-[10px] text-text-muted">{summaryValue(weighted.formula, "Formula not reported")}</p>
            <p className="mt-1 text-text-muted">Top recommendation: {summaryValue(weightedTopRecommendation, "Unavailable")}</p>
          </div>
          <div className="rounded-lg border border-border bg-surface-subtle p-3 text-xs">
            <p className="font-semibold text-text">Comparator: reciprocal-rank</p>
            <p className="mt-1 text-text-muted">Top recommendation: {summaryValue(rrfTopRecommendation, "Unavailable")}</p>
          </div>
          <p className="text-xs leading-5 text-text-muted md:col-span-2">The controlled synthetic comparison favored weighted voting; field accuracy and superiority are not established. This PoC result is not a real-world performance claim.</p>
        </div>
      </details>}
      {results.length > 0 && <details className="rounded-xl border border-border bg-surface">
        <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-text">Per-technique model results <span className="ui-badge ml-2">{results.length}</span></summary>
        <ol className="grid gap-2 border-t border-border p-3 sm:grid-cols-2">
          {results.map((item, index) => {
            const qualified = record(weightedRows.get(label(item.technique_id, "")));
            const rawAgreementOnly = item.evidence_state === "AGREE" && qualified.model2_support_added !== true;
            return <li key={`${index}-${summaryValue(item.technique_id, "technique")}`} className="min-w-0 rounded-lg border border-border bg-surface-subtle p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono font-semibold text-text">{summaryValue(item.technique_id, "Technique unavailable")}</span>
                <span className="ui-badge text-[11px]">{rawAgreementOnly ? "RAW AGREE · NO VOTE" : summaryValue(item.evidence_state, "UNAVAILABLE")}</span>
              </div>
              <div className="mt-2 grid gap-1 text-text-muted sm:grid-cols-2">
                <span>Model1: <span className="font-medium text-text">{readableCode(item.model1_result || "not applicable")}</span>{item.model1_margin !== null && item.model1_margin !== undefined ? ` · margin ${display(item.model1_margin)}` : ""}</span>
                <span>Model2: <span className="font-medium text-text">{readableCode(item.model2_result || "unavailable")}</span>{item.model2_score !== null && item.model2_score !== undefined ? ` · score ${display(item.model2_score)}` : ""}</span>
              </div>
              <p className="mt-1 text-text-muted">{readableCode(item.model2_relation || "comparison not recorded")} · primary source: {readableCode(item.primary_source || "none")}</p>
              {rawAgreementOnly && <p className="mt-1 text-warning">Raw predictions agree, but Model2 did not pass the evidence gate for this technique{hasMeaningfulValue(qualified.exclusion_reason) ? `: ${readableCode(qualified.exclusion_reason)}` : ""}. It did not vote or change the recommendation.</p>}
            </li>;
          })}
        </ol>
      </details>}
      <MoreDetails title="Technical model and session-binding details">
      <SummaryGrid fields={[
        ["Authority", summaryValue(ensemble.ensemble_authority, "ADVISORY_ONLY")],
        ["Model2 status", summaryValue(model2.status, "Unavailable")],
        ["Model2 architecture", architecture],
        ["One inference call", booleanLabel(model2.one_inference_call)],
        ["Independent binary heads", booleanLabel(model2.independent_binary_heads)],
        ["Model2 version", summaryValue(model2.model_version || model2.artifact_id, "Not reported")],
        ["Run ID", summaryValue(ensemble.run_id, "Not reported")],
        ["Measurement ID", summaryValue(model2.measurement_id || binding.measurement_id, "Not reported")],
        ["Episode ID", summaryValue(model2.episode_id || binding.episode_id, "Not reported")],
        ["Score-level model ensemble", ensemble.fused_score === null ? "NONE (fused_score=null)" : display(ensemble.fused_score)],
        ["Computed at", thailandTimestamp(ensemble.ensemble_computed_at)],
      ]} />
      </MoreDetails>
    </div>
  );
}

export function hasBoundAvailableModel2(data: JsonRecord): boolean {
  return hasBoundModel2(data);
}

export function shouldPollExternalTi(data: JsonRecord): boolean {
  return label(data.status, "").toUpperCase() === "TI_PENDING"
    && label(data.status_reason, "").toUpperCase() === "PROVIDER_RESULT_PENDING"
    && record(data.enrichment_job_summary).pending === true;
}

export function AiAdvisorySummary({ data, guidanceData, behavioralFindings = [], canonicalFindingIds = [] }: { data: JsonRecord; guidanceData: JsonRecord; behavioralFindings?: unknown[]; canonicalFindingIds?: unknown[] }) {
  const advisory = record(data.advisory);
  const validation = record(advisory.validation);
  const provenance = record(advisory.provenance);
  const safety = record(advisory.safety);
  const rendered = record(advisory.rendered_advisory);
  const presentation = record(advisory.presentation);
  const storedParagraphs = list(rendered.paragraphs).map(record);
  const displayParagraphs = list(presentation.paragraphs).map(record);
  const paragraphs = displayParagraphs.length > 0 ? displayParagraphs : storedParagraphs;
  const validated = record(advisory.validated_advisory);
  const guidance = record(guidanceData.response_guidance);
  const guidanceFindings = list(guidance.findings).map(record);
  const canonicalFindings = behavioralFindings.map(record);
  const knownCanonicalIds = new Set(canonicalFindings.map((item) => label(item.finding_id, "")));
  for (const value of canonicalFindingIds) {
    const id = label(value, "");
    if (id && !knownCanonicalIds.has(id)) {
      canonicalFindings.push({ finding_id: id, statement: "Canonical behavioral finding recorded in the immutable assessment; see the report for its full statement." });
      knownCanonicalIds.add(id);
    }
  }
  const guidanceActions = list(guidance.advisory_actions).map(record);
  // Provider selections are validated and stored independently of the optional
  // rendered policy templates. Empty paragraphs must not erase those choices.
  const selectedFindingIds = new Set([
    ...list(validated.selected_finding_ids),
    ...paragraphs.flatMap((item) => list(item.finding_ids)),
  ].map((id) => label(id, "")).filter(Boolean));
  const selectedActionIds = new Set([
    ...list(validated.ranked_action_ids),
    ...paragraphs.flatMap((item) => list(item.action_ids)),
  ].map((id) => label(id, "")).filter(Boolean));
  const selectedRelationshipCount = list(validated.selected_relationship_ids).length;
  const selectedFindings = [...canonicalFindings, ...guidanceFindings].filter((item) => selectedFindingIds.has(label(item.finding_id, "")));
  const selectedActions = guidanceActions.filter((item) => selectedActionIds.has(label(item.action_id, "")));
  const inaccurateStoredNarrative = selectedFindings.length > 0 && storedParagraphs.some((item) => label(item.text, "").includes("canonical finding"));
  const hasSelection = selectedFindingIds.size > 0 || selectedActionIds.size > 0;
  const abstained = validated.abstained === true;
  return (
    <div className="space-y-3">
      <p className="text-xs leading-5 text-text-muted">{hasSelection ? `AI selected ${selectedFindingIds.size} existing evidence item${selectedFindingIds.size === 1 ? "" : "s"} and ${selectedActionIds.size} existing manual action${selectedActionIds.size === 1 ? "" : "s"} for review${selectedRelationshipCount ? `, with ${selectedRelationshipCount} relationship${selectedRelationshipCount === 1 ? "" : "s"}` : ""}.` : abstained ? "The AI response was accepted and validated, but it abstained from selecting evidence or actions." : "No AI evidence or action selection is stored for this session."} AI does not create trusted findings or execute responses.</p>
      {hasSelection && paragraphs.length === 0 && <p className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-warning">The AI selection is stored, but no rendered narrative was recorded. The linked evidence and actions below come from the verified guidance record.</p>}
      {hasSelection && <ContentPanel title="Evidence and advice AI selected" count={selectedFindingIds.size + selectedActionIds.size}>
        {selectedFindings.map((item) => <article key={label(item.finding_id)} className="rounded-lg border border-border bg-surface-subtle p-3 text-sm text-text">
          <div className="mb-1.5 flex flex-wrap items-center gap-2"><span className="ui-badge text-[10px]">Observed evidence</span><span className="text-[10px] text-text-subtle">{canonicalFindings.includes(item) ? "Canonical behavioral finding" : "Response-guidance finding"}</span></div>
          {summaryValue(item.statement, "Statement unavailable")}
          {!hasMeaningfulValue(item.finding_type) && canonicalFindings.includes(item) && <p className="mt-1 font-mono text-[10px] text-text-muted">ID: {label(item.finding_id)}</p>}
        </article>)}
        {selectedActions.map((item) => <article key={label(item.action_id)} className="rounded-lg border border-primary-border bg-primary-subtle/50 p-3 text-sm text-text">
          <div className="mb-1.5 flex items-center gap-2"><span className="ui-badge text-[10px]">Existing action selected for review</span><span className="text-[10px] text-text-subtle">For analyst review</span></div>
          <p className="font-semibold">{summaryValue(item.description, "Action description unavailable")}</p>
          {hasMeaningfulValue(item.rationale) && <p className="mt-1 text-xs leading-5 text-text-muted">{summaryValue(item.rationale)}</p>}
        </article>)}
      </ContentPanel>}
      {(selectedFindingIds.size > selectedFindings.length || selectedActionIds.size > selectedActions.length) && <p className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-warning">Some AI selections could not be matched to the stored evidence or action details.</p>}
      {inaccurateStoredNarrative && displayParagraphs.length === 0 && <p className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-warning">The stored text calls this a canonical finding, but its selected ID belongs to response guidance. The item shown above comes from the verified guidance record.</p>}
      <MoreDetails title="AI provider, validation and original response">
        <SummaryGrid fields={[
          ["Status", summaryValue(data.status, "Unavailable")],
          ["Authority", summaryValue(advisory.authority, "Non-authoritative")],
          ["Validation", summaryValue(validation.status, "Not recorded")],
          ["Provider", summaryValue(provenance.provider_id, "Not recorded")],
          ["Model", summaryValue(provenance.model_id, "Not recorded")],
          ["Manual approval", safety.requires_manual_approval === false ? "No" : "Required"],
        ]} />
        {paragraphs.map((paragraph, index) => <p key={`${index}-${label(paragraph.template_id)}`} className="mt-2 text-xs text-text-muted">{summaryValue(paragraph.text, "No advisory narrative")}</p>)}
      </MoreDetails>
    </div>
  );
}

function PolicyGapSummary({ data }: { data: JsonRecord }) {
  const gap = record(data.policy_gap);
  const proposals = list(gap.proposals).map(record);
  if (proposals.length === 0) {
    return <div className="space-y-2 border-l-2 border-border pl-3 text-xs text-text-muted">
      <p>Policy-gap review: no candidate pattern was recorded.</p>
      <MoreDetails title="Policy proposal safeguards">
        <SummaryGrid fields={[["Mode", summaryValue(gap.mode, "Read-only")], ["Authority", summaryValue(gap.authority, "PROPOSED_UNVALIDATED")], ["Review", gap.requires_review === false ? "Not required" : "REQUIRES_REVIEW"], ["Policy mutation", gap.automatic_policy_mutation === true ? "Enabled" : "Disabled"]]} />
        <p className="mt-3 text-xs text-text-subtle">Candidates are for review. Policy updates and automatic execution remain disabled.</p>
      </MoreDetails>
    </div>;
  }
  return (
    <article className="rounded-lg border border-warning-border bg-warning-subtle p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.1em] text-warning">AI proposal for review</p>
        <span className="ui-badge text-[11px]">Not approved policy</span>
      </div>
      <p className="mt-2 text-sm text-text">AI proposed {proposals.length} possible pattern{proposals.length === 1 ? "" : "s"} to investigate. These are not verified findings or new response actions.</p>
      <ContentPanel title="Candidate patterns to review" count={proposals.length}>
        <ol className="space-y-2">
          {proposals.slice(0, 8).map((proposal, index) => {
            const predicates = record(proposal.predicates);
            const evidence = list(proposal.supporting_evidence_references);
            const missingEvidence = list(proposal.missing_evidence).length ? list(proposal.missing_evidence) : list(proposal.limitations);
            const falsifiers = list(proposal.falsifiers);
            const tests = list(proposal.proposed_validation_tests);
            return <li key={`${index}-${label(proposal.proposal_id)}`} className="rounded-lg border border-warning-border bg-surface p-3 text-sm text-text transition-colors hover:shadow-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-semibold capitalize">{readableCode(proposal.candidate_type)}</p>
                <span className="ui-badge text-[10px]">Review required</span>
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                <span className="rounded-full border border-border bg-surface-subtle px-2.5 py-1 text-[10px] text-text-muted">{readableCode(proposal.scope || "current session")}</span>
                <span className="rounded-full border border-border bg-surface-subtle px-2.5 py-1 text-[10px] text-text-muted">{evidence.length} supporting reference{evidence.length === 1 ? "" : "s"}</span>
              </div>
              <p className="mt-2 text-xs text-text-muted"><span className="font-semibold text-text">Still missing / limits:</span> {missingEvidence.length ? missingEvidence.map(readableCode).join(", ") : "none recorded"}</p>
              {Object.keys(predicates).length > 0 && <p className="mt-1 text-xs text-text-muted"><span className="font-semibold text-text">Conditions:</span> {Object.values(predicates).flatMap((value) => Array.isArray(value) ? value : [value]).map(readableCode).join(" · ")}</p>}
              {falsifiers.length > 0 && <p className="mt-1 text-xs text-text-muted"><span className="font-semibold text-text">What would disprove it:</span> {falsifiers.map(readableCode).join(" · ")}</p>}
              {tests.length > 0 && <p className="mt-1 text-xs text-text-muted"><span className="font-semibold text-text">Suggested validation:</span> {tests.map(readableCode).join(" · ")}</p>}
              {evidence.length > 0 && <TraceabilityDetails title="See supporting evidence references" fields={evidence.map((reference, refIndex) => [`Evidence ${refIndex + 1}`, display(reference)] as const)} />}
            </li>;
          })}
        </ol>
      </ContentPanel>
      <MoreDetails title="Policy proposal safeguards">
      <SummaryGrid fields={[
        ["Mode", summaryValue(gap.mode, "Read-only")],
        ["Authority", summaryValue(gap.authority, "PROPOSED_UNVALIDATED")],
        ["Review", gap.requires_review === false ? "Not required" : "REQUIRES_REVIEW"],
        ["Policy mutation", gap.automatic_policy_mutation === true ? "Enabled" : "Disabled"],
      ]} />
      <p className="mt-3 text-xs text-text-subtle">Candidates are for review. Policy updates and automatic execution remain disabled.</p>
      </MoreDetails>
    </article>
  );
}

export function ProvenanceSummary({ value }: { value: JsonRecord }) {
  const reportSummary = record(value.report_summary);
  const errors = record(value.errors);
  const nonEmptyErrors = Object.values(errors).filter(hasMeaningfulValue).length;
  const currentAiStatus = summaryValue(reportSummary.current_ai_advisory_status, "Not available");
  const immutableEnrichmentCopy = reportSummary.ai_enriched === false || reportSummary.ai_enriched === "false"
    ? "immutable assessment was generated without AI enrichment."
    : hasMeaningfulValue(reportSummary.ai_enriched)
      ? `immutable assessment AI enrichment: ${readableCode(reportSummary.ai_enriched)}.`
      : "immutable assessment AI enrichment was not recorded.";
  return (
    <div className="space-y-2">
      <dl className="grid grid-cols-2 divide-x divide-border rounded-lg border border-border bg-surface-subtle sm:grid-cols-4">
        {[["Analysis jobs", countOf(list(value.analysis_jobs).length)], ["Report summary", hasMeaningfulRecord(reportSummary) ? "Stored" : "None"], ["Processing errors", countOf(nonEmptyErrors)], ["AI advisory", readableCode(currentAiStatus)]].map(([name, result]) => <div key={name} className="min-w-0 border-b border-border px-2 py-2 last:border-b-0 sm:border-b-0 sm:px-2.5"><dt className="text-[9px] font-semibold uppercase tracking-[0.08em] text-text-subtle">{name}</dt><dd className={`mt-0.5 break-words text-[11px] font-semibold ${nonEmptyErrors > 0 && name === "Processing errors" ? "text-warning" : "text-text"}`}>{result}</dd></div>)}
      </dl>
      {hasMeaningfulRecord(reportSummary) && <p className="text-[10px] leading-4 text-text-muted">{immutableEnrichmentCopy} Current AI advisory: {readableCode(currentAiStatus)}. The current advisory is stored separately and does not rewrite the original assessment.</p>}
      <MoreDetails title="Schema and processing-error detail">
      <SummaryGrid fields={[
        ["Schema", summaryValue(value.schema_version, "Not recorded")],
      ]} />
      {nonEmptyErrors > 0 && <SummaryGrid fields={Object.entries(errors).filter(([, error]) => hasMeaningfulValue(error)).map(([name, error]) => [readableCode(name), summaryValue(error)] as const)} />}
      </MoreDetails>
    </div>
  );
}

export function SessionAnalysisPanels({
  sessionId,
  onDetail,
  onLiveInteraction,
  onNextDistinct,
}: {
  sessionId: string;
  onDetail?: (data: JsonRecord) => void;
  onLiveInteraction?: (
    commands: unknown[],
    active: boolean,
    view: { state: LoadState; reason: string; sensitive: true },
  ) => void;
  onNextDistinct?: (data: JsonRecord, state: LoadState, reason: string) => void;
}) {
  const [results, setResults] = useState<Record<string, CapabilityResult>>({});

  useEffect(() => {
    let cancelled = false;
    let pollTimer: number | undefined;
    let analysisPollTimer: number | undefined;
    let analysisPollInFlight = false;
    let analysisPollAttempts = 0;
    let tiPollTimer: number | undefined;
    let tiPollInFlight = false;
    let tiPollAttempts = 0;
    let pollInFlight = false;
    let lastDetail: JsonRecord = {};
    const allCapabilities = [
      "detail",
      "commands",
      "next-distinct",
      "session-ti",
      "source-ip-pivot",
      "observable-ti",
      "hypothesis",
      "recommendations",
      "related",
      "feedback",
      "reports",
      "ai-advisory",
    ] as const;
    const primaryCapabilities = ["detail", "commands", "next-distinct", "session-ti"] as const;
    const pollCapabilities = ["detail", "commands", "next-distinct"] as const;

    const analysisComplete = (detail: JsonRecord, ai: CapabilityResult): boolean => (
      list(detail.reports).length > 0 &&
      ai.state === "ready" &&
      label(ai.data.status, "").toLowerCase() === "accepted"
    );
    const stopAnalysisPoll = () => {
      if (analysisPollTimer !== undefined) window.clearInterval(analysisPollTimer);
      analysisPollTimer = undefined;
    };

    const stopTiPoll = () => {
      if (tiPollTimer !== undefined) window.clearInterval(tiPollTimer);
      tiPollTimer = undefined;
    };
    const startTiPoll = (initial: CapabilityResult | undefined) => {
      if (!shouldPollExternalTi(initial?.data || {})) return;
      tiPollTimer = window.setInterval(async () => {
        if (cancelled || tiPollInFlight) return;
        tiPollInFlight = true;
        try {
          const refreshed = await fetchCapability("session-ti", sessionId);
          if (cancelled) return;
          apply([["session-ti", refreshed]]);
          tiPollAttempts += 1;
          if (!shouldPollExternalTi(refreshed.data) || tiPollAttempts >= 12) {
            stopTiPoll();
          }
        } finally {
          tiPollInFlight = false;
        }
      }, 5_000);
    };

    const unavailable = (reason: string): CapabilityResult => terminalResult("unavailable", reason);
    const notApplicable = (reason: string): CapabilityResult => terminalResult("not_applicable", reason);

    const apply = (entries: readonly (readonly [string, CapabilityResult])[]) => {
      if (cancelled) return;
      const normalizedEntries = entries.map(([capability, result]) => (
        [capability, normalizePanelResult(capability, result)] as const
      ));
      setResults((previous) => ({ ...previous, ...Object.fromEntries(normalizedEntries) }));
      const nextDistinctEntry = normalizedEntries.find(([capability]) => capability === "next-distinct");
      if (nextDistinctEntry) {
        onNextDistinct?.(nextDistinctEntry[1].data, nextDistinctEntry[1].state, nextDistinctEntry[1].reason);
      }
      const detailEntry = normalizedEntries.find(([capability]) => capability === "detail");
      if (detailEntry?.[1].state === "ready") {
        lastDetail = detailEntry[1].data;
        onDetail?.(detailEntry[1].data);
      }
      const commandEntry = normalizedEntries.find(([capability]) => capability === "commands");
      if (commandEntry) {
        const detail = detailEntry?.[1].state === "ready" ? detailEntry[1].data : lastDetail;
        const commandData = commandEntry[1].state === "ready" || commandEntry[1].state === "limited"
          ? commandEntry[1].data
          : {};
        onLiveInteraction?.(
          projectAdminCommandRecords(sessionId, detail, commandData),
          sessionIsActive(detail),
          { state: commandEntry[1].state, reason: commandEntry[1].reason, sensitive: true },
        );
      }
    };

    const settle = (
      capabilities: readonly string[],
      settled: PromiseSettledResult<readonly [string, CapabilityResult]>[],
    ): Array<readonly [string, CapabilityResult]> => settled.map((result, index) => (
      result.status === "fulfilled"
        ? result.value
        : [capabilities[index], unavailable("Panel request failed")] as const
    ));

    const poll = async () => {
      if (cancelled || pollInFlight) return;
      pollInFlight = true;
      const settled = await Promise.allSettled(
        pollCapabilities.map(async (capability) => [capability, await fetchCapability(capability, sessionId)] as const),
      );
      const entries = settle(pollCapabilities, settled);
      apply(entries);
      const detailEntry = entries.find(([capability]) => capability === "detail");
      if (detailEntry?.[1].state === "ready" && !sessionIsActive(detailEntry[1].data) && pollTimer !== undefined) {
        window.clearInterval(pollTimer);
        pollTimer = undefined;
      }
      pollInFlight = false;
    };

    const startAnalysisPoll = (detail: JsonRecord, ai: CapabilityResult) => {
      if (analysisComplete(detail, ai)) return;
      // Reports and AI are produced after the session closes. Keep checking for a
      // bounded period so an already-open page does not freeze its initial snapshot.
      analysisPollTimer = window.setInterval(async () => {
        if (cancelled || analysisPollInFlight) return;
        analysisPollInFlight = true;
        try {
          const [detailResult, aiResult] = await Promise.all([
            fetchCapability("detail", sessionId),
            fetchCapability("ai-advisory", sessionId),
          ]);
          if (cancelled) return;
          apply([["detail", detailResult]]);
          if (detailResult.state === "ready") {
            apply(derivedEntries(detailResult).filter(([capability]) => capability !== "ai-advisory"));
          }
          apply([["ai-advisory", aiResult]]);
          analysisPollAttempts += 1;
          if (
            (detailResult.state === "ready" && analysisComplete(detailResult.data, aiResult)) ||
            analysisPollAttempts >= 24
          ) stopAnalysisPoll();
        } finally {
          analysisPollInFlight = false;
        }
      }, 5_000);
    };

    const load = async () => {
      const settled = await Promise.allSettled(
        primaryCapabilities.map(async (capability) => [capability, await fetchCapability(capability, sessionId)] as const),
      );
      const entries = settle(primaryCapabilities, settled);
      if (!cancelled) {
        setResults(Object.fromEntries(allCapabilities.map((capability) => [capability, { ...initialResult }])));
      }
      apply(entries);
      startTiPoll(entries.find(([capability]) => capability === "session-ti")?.[1]);
      const detailEntry = entries.find(([capability]) => capability === "detail");
      if (!detailEntry || detailEntry[1].state !== "ready") {
        const detailReason = detailEntry?.[1].reason || "The exact-session detail projection failed";
        apply([
          ...DERIVED_CAPABILITIES.map((capability) => [capability, unavailable(`Depends on session detail: ${detailReason}`)] as const),
          ["source-ip-pivot", unavailable(`Depends on session detail: ${detailReason}`)] as const,
          ["observable-ti", unavailable(`Depends on session detail: ${detailReason}`)] as const,
        ]);
        return;
      }

      apply(derivedEntries(detailEntry[1]));
      const detail = detailEntry[1].data;
      // Independent context must not wait for the optional source-IP/TI lookups.
      const aiRequest = fetchCapability("ai-advisory", sessionId).then((aiResult) => {
        apply([["ai-advisory", aiResult]]);
        if (!cancelled) startAnalysisPoll(detail, aiResult);
      });
      if (!cancelled && sessionIsActive(detail)) {
        pollTimer = window.setInterval(() => {
          void poll();
        }, 1_000);
      }
      const overview = record(detail.overview);
      const sourceIp = label(overview.src_ip || record(detail.session).src_ip, "");
      const observables = list(detail.observables).filter(isRecord);
      const firstSupported = observables.find((item) => item.type === "ip" || item.type === "hash");
      const optionalRequests: Array<Promise<readonly [string, CapabilityResult]>> = [];
      if (sourceIp) {
        optionalRequests.push(
          fetchCapability("source-ip-pivot", sessionId, { source_ip: sourceIp })
            .then((value) => ["source-ip-pivot", value] as const),
        );
      }
      if (firstSupported) {
        optionalRequests.push(
          fetchCapability("observable-ti", sessionId, {
            observable_type: label(firstSupported.type, ""),
            observable_value: label(firstSupported.value, ""),
          }).then((value) => ["observable-ti", value] as const),
        );
      }
      if (optionalRequests.length) {
        const optionalSettled = await Promise.allSettled(optionalRequests);
        apply(optionalSettled.map((result, index) => (
          result.status === "fulfilled"
            ? result.value
            : [index === 0 && sourceIp ? "source-ip-pivot" : "observable-ti", unavailable("Optional panel request failed")] as const
        )));
      } else {
        apply([
          ["source-ip-pivot", sourceIp ? unavailable("Source-IP pivot request was not started") : notApplicable("No source IP is stored for this exact session.")] as const,
          ["observable-ti", firstSupported ? unavailable("Observable-TI request was not started") : notApplicable("No supported IP or hash observable is stored for this exact session.")] as const,
        ]);
      }
      await aiRequest;
    };

    void load();
    return () => {
      cancelled = true;
      if (pollTimer !== undefined) window.clearInterval(pollTimer);
      stopAnalysisPoll();
      stopTiPoll();
    };
  }, [sessionId, onDetail, onLiveInteraction, onNextDistinct]);

  const get = (key: string) => results[key] || initialResult;
  const detail = get("detail").data;
  const detailResult = get("detail");
  const overview = record(detail.overview);
  const events = list(detail.events || detail.events_table_rows);
  const classificationEvents = list(detail.classification_events);
  const trustedTtps = list(detail.observed_trusted_ttps);
  const sessionTi = get("session-ti").data;
  const sourcePivot = get("source-ip-pivot");
  const observableTi = get("observable-ti");
  const hypothesis = get("hypothesis").data;
  const reports = list(get("reports").data.reports);
  const observables = list(detail.observables);
  const observableSightings = list(detail.observable_sightings);
  const analystObservables = observableSightings.length ? observableSightings : observables;
  const authentication = record(detail.authentication_activity);
  const provenance = {
    schema_version: detail.schema_version,
    session_id: detail.session_id,
    analysis_jobs: detail.analysis_jobs,
    report_summary: detail.report_summary,
    errors: detail.errors,
  };
  const timelineResult = detailPanelResult(detailResult, events.length > 0, "No persisted timeline events are available.");
  const authenticationResult = detailPanelResult(
    detailResult,
    Number(authentication.attempt_count || 0) > 0,
    "No Cowrie authentication attempts were recorded.",
  );
  const classificationResult = detailPanelResult(
    detailResult,
    hasClassificationEvidence(classificationEvents, trustedTtps),
    "No classification evidence was established.",
  );
  const baseEnsembleResult = detailPanelResult(detailResult, hasMeaningfulRecord(detail.ensemble_evidence), "No stored Model1 + Model2 ensemble evidence is available.");
  const ensembleResult = baseEnsembleResult.state === "ready" && !hasBoundAvailableModel2(detail)
    ? terminalResult(
        "limited",
        "Model1 or ensemble metadata is present, but no exact-session Model2 artifact and run binding is available.",
        detail,
        baseEnsembleResult.status,
      )
    : baseEnsembleResult;
  const filesResult = detailPanelResult(detailResult, analystObservables.length > 0, "No file or observable evidence is available.");
  const provenanceResult = detailPanelResult(detailResult, Object.values(provenance).some(hasMeaningfulValue), "No provenance record is available.");
  const aiAdvisory = get("ai-advisory");
  const etiBaseResult = get("session-ti").state === "ready" || get("session-ti").state === "loading"
    ? get("session-ti")
    : observableTi;
  const etiHasEvidence = hasItems(sessionTi, ["evidence", "source_ip_cache"])
    || hasItems(observableTi.data, ["evidence", "source_ip_cache"])
    || Number(record(sessionTi.counts).evidence_returned || 0) > 0
    || Number(record(observableTi.data.counts).evidence_returned || 0) > 0;
  const sourceScope = label(overview.src_ip_scope, "").toLowerCase();
  const sourceIpIneligible = ["private", "loopback", "link_local", "documentation", "reserved"].includes(sourceScope);
  const etiResult = etiBaseResult.state === "loading"
    ? etiBaseResult
    : sourceIpIneligible && !etiHasEvidence
      ? terminalResult(
          "not_applicable",
          `The source IP scope is ${sourceScope || "non-public"}; public source-IP provider lookup is not eligible for this session.`,
          etiBaseResult.data,
          etiBaseResult.status,
        )
      : detailPanelResult(
          etiBaseResult,
          etiHasEvidence,
          "No provider finding is linked to this exact session. No external intelligence is inferred.",
        );

  const activityResult = combinedPanelResult([timelineResult, authenticationResult], "No activity or authentication evidence is stored.");
  const analystResult = combinedPanelResult([get("hypothesis"), get("recommendations")], "No analyst assessment or response guidance is stored.");
  const tiSectionResult = combinedPanelResult([etiResult, sourcePivot], "No threat-intelligence context is stored.");
  const evidenceSectionResult = combinedPanelResult([filesResult, provenanceResult, get("reports")], "No evidence inventory or durable report is stored.");

  return (
    <div className="space-y-5">
      <section aria-label="Activity evidence">
        <Panel eyebrow="" title="Activity evidence" icon={<Activity className="h-4 w-4" aria-hidden="true" />} result={activityResult} variant="module" renderEmptyContent compactUnavailable>
          <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-[minmax(0,7fr)_minmax(18rem,3fr)]">
            <Panel eyebrow="Bound event chain · oldest → newest" title="Bounded event timeline" icon={<ListTree className="h-4 w-4" aria-hidden="true" />} result={timelineResult} variant="embedded" renderEmptyContent compactUnavailable>
              <TimelineList items={events} />
            </Panel>
            <Panel eyebrow="Session access" title="Authentication activity" icon={<Fingerprint className="h-4 w-4" aria-hidden="true" />} result={authenticationResult} className="xl:border-l xl:border-border xl:pl-4" variant="flat" renderEmptyContent compactUnavailable>
              <AuthenticationSummary data={authentication} />
            </Panel>
          </div>
        </Panel>
      </section>

      <section aria-label="Trusted observations">
        <Panel eyebrow="" title="Trusted observations" icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />} result={classificationResult} variant="module" renderEmptyContent compactUnavailable>
          <ClassificationList items={classificationEvents} trustedMappings={trustedTtps} />
        </Panel>
      </section>

      <section aria-label="TTP recommendation">
        <Panel eyebrow="" title="TTP recommendation" icon={<Network className="h-4 w-4" aria-hidden="true" />} result={ensembleResult} variant="module" renderEmptyContent compactUnavailable>
          <Model2EnsembleSummary data={detail} />
        </Panel>
      </section>

      <section aria-label="Analyst assessment">
        <Panel eyebrow="" title="Analyst assessment" icon={<BrainCircuit className="h-4 w-4" aria-hidden="true" />} result={analystResult} variant="module" renderEmptyContent compactUnavailable>
          <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-[minmax(0,7fr)_minmax(18rem,3fr)]">
            <Panel eyebrow="Assessment outcome" title="Threat hypothesis" icon={<BrainCircuit className="h-4 w-4" aria-hidden="true" />} result={get("hypothesis")} variant="embedded" renderEmptyContent compactUnavailable>
              <HypothesisSummary data={hypothesis} />
            </Panel>
            <Panel eyebrow="Manual review" title="Response guidance" icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />} result={get("recommendations")} className="xl:border-l xl:border-border xl:pl-4" variant="flat" renderEmptyContent compactUnavailable>
              <GuidanceSummary data={get("recommendations").data} />
            </Panel>
          </div>
        </Panel>
      </section>

      <section aria-label="AI advisory">
        <Panel eyebrow="" title="AI advisory" icon={<Bot className="h-4 w-4" aria-hidden="true" />} result={aiAdvisory} variant="module" renderEmptyContent compactUnavailable>
          <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-12">
            <div className="min-w-0 xl:col-span-8">
              <AiAdvisorySummary data={aiAdvisory.data} guidanceData={get("recommendations").data} behavioralFindings={list(detail.behavioral_findings)} canonicalFindingIds={list(record(detail.session_hypothesis_assessment).canonical_finding_ids)} />
            </div>
            <aside className="min-w-0 xl:col-span-4 xl:border-l xl:border-border xl:pl-4" aria-label="Policy gap review">
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.12em] text-primary-navy">Policy-gap review</p>
              {aiAdvisory.state === "ready" || aiAdvisory.state === "limited"
                ? <PolicyGapSummary data={aiAdvisory.data} />
                : <p className="text-xs text-text-muted">Unavailable: no accepted AI advisory is stored.</p>}
            </aside>
          </div>
        </Panel>
      </section>

      <section aria-label="Threat intelligence context">
        <Panel eyebrow="" title="Threat intelligence context" icon={<Network className="h-4 w-4" aria-hidden="true" />} result={tiSectionResult} variant="module" renderEmptyContent compactUnavailable>
          <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-[minmax(20rem,5fr)_minmax(0,7fr)]">
            <Panel eyebrow="Provider results" title="External Threat Intelligence" icon={<Network className="h-4 w-4" aria-hidden="true" />} result={etiResult} variant="embedded" renderEmptyContent compactUnavailable>
              <ExternalTiSummary sessionData={sessionTi} observableData={observableTi.data} />
            </Panel>
            <Panel eyebrow="Recurrence · not attribution" title="Source-IP recurrence" icon={<Fingerprint className="h-4 w-4" aria-hidden="true" />} result={sourcePivot} className="xl:border-l xl:border-border xl:pl-4" variant="flat" renderEmptyContent compactUnavailable>
              <SourcePivotSummary data={sourcePivot.data} />
            </Panel>
          </div>
        </Panel>
      </section>

      <section aria-label="Evidence ledger">
        <Panel eyebrow="" title="Evidence ledger" icon={<FileSearch className="h-4 w-4" aria-hidden="true" />} result={evidenceSectionResult} variant="module" renderEmptyContent compactUnavailable>
          <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-[minmax(0,8fr)_minmax(18rem,4fr)]">
            <Panel eyebrow="Evidence inventory" title="Artifacts and observables" icon={<FileSearch className="h-4 w-4" aria-hidden="true" />} result={filesResult} variant="embedded" renderEmptyContent compactUnavailable>
              <ObservableList items={analystObservables} />
            </Panel>
            <aside className="min-w-0 divide-y divide-border xl:border-l xl:border-border xl:pl-4">
              <Panel eyebrow="Processing trace" title="Evidence and provenance" icon={<Fingerprint className="h-4 w-4" aria-hidden="true" />} result={provenanceResult} className="pb-4" variant="flat" renderEmptyContent compactUnavailable>
                <ProvenanceSummary value={provenance} />
              </Panel>
              <Panel eyebrow="Durable output" title="Reports" icon={<FileText className="h-4 w-4" aria-hidden="true" />} result={get("reports")} className="pt-4" variant="flat" renderEmptyContent compactUnavailable>
                <RecordList items={reports} empty="No stored report is available." />
              </Panel>
            </aside>
          </div>
        </Panel>
      </section>
    </div>
  );
}
