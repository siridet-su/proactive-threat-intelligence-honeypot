"use client";

import {
  AlertCircle,
  Bot,
  BrainCircuit,
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
  sourceIpCacheFreshness,
} from "@/lib/external-ti-presentation";
import { projectAdminCommandRecords } from "@/lib/session-command-projection";
import { projectContextualHypotheses } from "@/lib/contextual-hypothesis-presentation";
import { hasBoundModel2, rankTtpRecommendations } from "@/lib/model-ttp-ranking";

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

function Insight({ title, children, tone = "primary" }: { title: string; children: ReactNode; tone?: "primary" | "warning" }) {
  return (
    <div className={`rounded-xl border p-4 ${tone === "warning" ? "border-warning-border bg-warning-subtle" : "border-primary-border bg-primary-subtle"}`}>
      <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-primary">{title}</p>
      <div className="mt-1 text-sm leading-6 text-text">{children}</div>
    </div>
  );
}

function ScrollPanel({ title, count, children, className = "", height = "max-h-72" }: { title: string; count?: number; children: ReactNode; className?: string; height?: string }) {
  return (
    <section className={`overflow-hidden rounded-xl border border-border bg-surface ${className}`}>
      <div className="flex items-center justify-between gap-3 border-b border-border bg-surface-subtle px-3.5 py-2.5">
        <h3 className="text-xs font-semibold text-text">{title}</h3>
        {count !== undefined && <span className="ui-badge text-[10px]">{count}</span>}
      </div>
      <div role="region" aria-label={title} tabIndex={0} className={`ui-scroll-region ${height} space-y-2 overflow-y-auto overscroll-contain scroll-smooth p-2.5 pr-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-primary`} style={{ scrollbarColor: "var(--border-strong) transparent", scrollbarWidth: "thin" }}>
        {children}
      </div>
    </section>
  );
}

function MoreDetails({ title, children }: { title: string; children: ReactNode }) {
  return (
    <details className="group rounded-lg border border-border bg-surface">
      <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-text marker:text-primary">{title}</summary>
      <div className="border-t border-border px-4 py-4">{children}</div>
    </details>
  );
}

function readableCode(value: unknown): string {
  return label(value, "not recorded").replaceAll("_", " ").toLowerCase();
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
        const status = label(data.status, "").toLowerCase();
        if (["unavailable", "not_available", "failed", "superseded"].includes(status)) {
          return terminalResult(
            "empty",
            "No accepted provider advisory is stored for this exact session.",
            data,
            result.status,
          );
        }
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
}: {
  eyebrow: string;
  title: string;
  icon: ReactNode;
  result: CapabilityResult;
  children: ReactNode;
  className?: string;
  variant?: "card" | "embedded";
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

  return (
    <article className={`${embedded ? "min-w-0 overflow-hidden" : "ui-panel flex flex-col overflow-hidden"} ${className}`}>
      <div className={`flex flex-wrap items-start justify-between gap-3 ${embedded ? "border-b border-border pb-3" : "border-b border-border bg-surface px-4 py-3 sm:px-5"}`}>
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
            {icon}
            {eyebrow}
          </div>
          <h2 className="mt-1 text-base font-semibold sm:text-lg">{title}</h2>
        </div>
        <span className="ui-badge">
          {result.state === "ready" && "PASS_WITH_DATA"}
          {result.state === "limited" && "LIMITED"}
          {result.state === "empty" && "EMPTY_VALID"}
          {result.state === "not_applicable" && "EMPTY_VALID"}
          {result.state === "loading" && "Loading"}
          {result.state === "unavailable" && "UNAVAILABLE"}
        </span>
      </div>
      <div className={embedded ? "pt-4" : "p-4 sm:p-5"}>
        {result.state === "loading" ? (
          <div role="status" aria-busy="true" className={`flex items-start gap-3 rounded-lg border p-3.5 ${stateCopy.className}`}>
            {stateCopy.icon}
            <div className="min-w-0">
              <p className="text-sm font-semibold text-text">{stateCopy.title}</p>
              <p className="mt-1 text-xs leading-5 text-text-muted">{stateCopy.description}</p>
            </div>
          </div>
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

function TimelineList({ items }: { items: unknown[] }) {
  const orderedItems = chronologicalRecords(items).filter((item) => item.command_event !== true);
  const [filter, setFilter] = useState("all");
  const category = (item: JsonRecord) => {
    const eventName = String(item.eventid || item.event_id || item.event_type || "").toLowerCase();
    if (/login|auth|password|client\.kex/.test(eventName)) return "Authentication";
    if (/session|connect|disconnect|close/.test(eventName)) return "Session";
    return "Other";
  };
  const visibleItems = orderedItems.filter((item) => filter === "all" || category(item) === filter);
  const filters = [
    ["all", "All events", orderedItems.length],
    ["Authentication", "Access", orderedItems.filter((item) => category(item) === "Authentication").length],
    ["Session", "Session", orderedItems.filter((item) => category(item) === "Session").length],
    ["Other", "Other", orderedItems.filter((item) => category(item) === "Other").length],
  ] as const;
  if (!orderedItems.length) {
    return <p className="rounded-lg border border-border bg-surface-subtle p-4 text-sm text-text-muted">No persisted timeline events are available.</p>;
  }
  return (
    <div className="space-y-3">
      <Insight title="Activity at a glance">{orderedItems.length} connection, authentication, or lifecycle event{orderedItems.length === 1 ? "" : "s"} were recorded. Commands are shown separately in Command activity.</Insight>
      <div className="flex flex-wrap gap-2" role="group" aria-label="Filter timeline events">
        {filters.map(([key, title, count]) => <button key={key} type="button" aria-pressed={filter === key} onClick={() => setFilter(key)} className={`rounded-full border px-3 py-1.5 text-xs font-medium transition-colors ${filter === key ? "border-primary bg-primary text-white shadow-sm" : "border-border bg-surface text-text-muted hover:border-primary-border hover:bg-primary-subtle hover:text-text"}`}>
          {title}<span className="ml-1.5 opacity-70">{count}</span>
        </button>)}
      </div>
      <ScrollPanel title={`Session timeline · ${filter === "all" ? "all activity" : filter.toLowerCase()}`} count={visibleItems.length} height="max-h-80">
      <ol className="relative space-y-2 border-l border-primary-border pl-4">
        {visibleItems.slice(0, 100).map((event, index) => {
        const eventName = summaryValue(event.eventid || event.event_id || event.event_type, "event");
        const timestamp = summaryValue(event.timestamp || event.received_at, "Timestamp unavailable");
        const shortTime = timestamp.includes("T") ? `${timestamp.split("T")[1].slice(0, 8)} UTC` : timestamp;
        const readableEvent = eventName.replace(/^cowrie\./i, "").replaceAll(".", " ");
        return (
          <li key={`${index}-${eventName}-${timestamp}`} className="group relative rounded-lg border border-border bg-surface-subtle px-3 py-2.5 transition duration-150 hover:border-primary-border hover:bg-primary-subtle/40 hover:shadow-sm">
            <span className="absolute -left-[21px] top-4 h-2.5 w-2.5 rounded-full border-2 border-surface bg-primary shadow-[0_0_0_2px_var(--primary-subtle)]" aria-hidden="true" />
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-sm font-semibold capitalize text-text">{readableEvent}</span>
              <time className="rounded-full bg-surface px-2 py-1 font-mono text-[10px] text-text-muted" dateTime={timestamp}>{shortTime}</time>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-text-muted">
              <span className="rounded bg-surface px-2 py-0.5">{category(event)}</span>
              <span>{summaryValue(event.sensor_id || event.sensor, "Sensor unavailable")}</span>
              {event.processed === false && <span className="rounded bg-warning-subtle px-2 py-0.5 text-warning">Needs review</span>}
            </div>
          </li>
        );
        })}
      </ol>
      </ScrollPanel>
    </div>
  );
}

export function ClassificationList({ items, trustedMappings }: { items: unknown[]; trustedMappings: unknown[] }) {
  const classificationRecords = items.map(record);
  if (!classificationRecords.length && !trustedMappings.length) {
    return <p className="rounded-lg border border-border bg-surface-subtle p-4 text-sm text-text-muted">No classification evidence is available for this exact session.</p>;
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
  const uniqueAttackTechniques = new Set(
    trustedMappings
      .map((item) => {
        const mapping = record(item);
        return display(mapping.technique_id || mapping.ttp, "");
      })
      .filter(Boolean),
  );
  return (
    <div className="space-y-3">
      <Insight title="Trusted classification">{trustedMappings.length} trusted mapping{trustedMappings.length === 1 ? "" : "s"} across {uniqueAttackTechniques.size} ATT&amp;CK technique{uniqueAttackTechniques.size === 1 ? "" : "s"}, from {classificationRecords.length} command-level record{classificationRecords.length === 1 ? "" : "s"}. Model1 is advisory; Model2 has its own panel.</Insight>
      {uniqueAttackTechniques.size > 0 && <div className="flex flex-wrap gap-2">{[...uniqueAttackTechniques].map((technique) => <span key={technique} className="rounded-md border border-primary-border bg-primary-subtle px-2.5 py-1 font-mono text-xs text-text transition-transform hover:-translate-y-0.5">{technique}</span>)}</div>}
      <MetricStrip fields={[
        ["Classification records", String(classificationRecords.length)],
        ["Classified command events", String(classifiedCommandKeys.size)],
        ["Trusted ATT&CK", String(uniqueAttackTechniques.size)],
      ]} />
      {classificationRecords.length > 0 && <p className="text-xs text-text-muted">Command-level classification is shown with its evidence. Model1 scores are advisory.</p>}
      {classificationRecords.length > 0 && <ScrollPanel title="Classified activity" count={classificationRecords.length} height="max-h-96">
      <ol className="space-y-2">
        {classificationRecords.slice(0, 50).map((mapping, index) => {
          const authority = record(mapping.authority_decision);
          const advisory = record(mapping.s1_advisory);
          const technique = mapping.ttp || mapping.technique_id || "NO_TECHNIQUE_ASSIGNED";
          const sourceCommand = commandText(mapping.source_command || mapping.command || mapping.original_command);
          return (
            <li key={`${index}-${String(mapping.evidence_id || technique)}`} className="rounded-lg border border-border bg-surface-subtle px-3 py-3 transition-colors hover:border-primary-border hover:bg-primary-subtle/30">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-semibold text-text">{summaryValue(technique)}</span>
                  <span className="text-xs text-text-muted">{summaryValue(mapping.name, "Technique not assigned")}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  <span className="ui-badge text-[11px]">{summaryValue(authority.decision || mapping.evidence_tier, "advisory")}</span>
                </div>
              </div>
              {sourceCommand && <p className="mt-2 rounded border border-border bg-surface px-2.5 py-2 font-mono text-xs text-text">{sourceCommand}</p>}
              <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
                <span className="rounded-full border border-border bg-surface px-2.5 py-1 text-text-muted">{summaryValue(mapping.tactic, "Tactic not recorded")}</span>
                <span className="rounded-full border border-border bg-surface px-2.5 py-1 text-text-muted">{summaryValue(authority.decision || mapping.authority, "Advisory only")}</span>
                {hasMeaningfulValue(advisory.predicted_technique) && <span className="rounded-full border border-primary-border bg-primary-subtle px-2.5 py-1 text-text">Model1: {summaryValue(advisory.predicted_technique)}</span>}
              </div>
              <ClassificationTraceability mapping={mapping} sourceCommand={sourceCommand} />
            </li>
          );
        })}
      </ol></ScrollPanel>}
      <div className="rounded-xl border border-primary-border bg-primary-subtle/50 p-3">
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs font-semibold text-primary">Trusted ATT&amp;CK mapping details</p>
          <span className="ui-badge text-[10px]">{trustedMappings.length}</span>
        </div>
        {trustedMappings.length ? (
          <ol className="ui-scroll-region mt-2 max-h-64 space-y-2 overflow-y-auto pr-2">
            {trustedMappings.slice(0, 20).map((item, index) => {
              const mapping = record(item);
              const tactics = list(mapping.tactics).map((value) => display(value)).filter(Boolean).join(", ");
              return (
                <li key={`${index}-${summaryValue(mapping.technique_id, "mapping")}`} className="rounded border border-primary-border bg-surface px-3 py-2 text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono font-semibold text-text">{summaryValue(mapping.technique_id, "Technique unavailable")}</span>
                    <span className="ui-badge text-[11px]">{summaryValue(mapping.trust_tier || mapping.authority, "trusted_observation")}</span>
                  </div>
                  <p className="mt-1 text-text-muted">{tactics || "Tactic unavailable"} · {summaryValue(mapping.mapping_semantics, "Observed command evidence")}</p>
                  <p className="mt-1 text-text-muted">{countOf(mapping.evidence_ref_count || list(mapping.evidence_refs).length)} evidence reference{Number(mapping.evidence_ref_count || list(mapping.evidence_refs).length) === 1 ? "" : "s"}</p>
                  <TrustedTraceability mapping={mapping} />
                </li>
              );
            })}
          </ol>
        ) : <p className="mt-2 text-xs text-text-muted">No trusted mapping was established.</p>}
      </div>
    </div>
  );
}

function ObservableList({ items, empty = "No file or observable evidence is available." }: { items: unknown[]; empty?: string }) {
  if (!items.length) {
    return <p className="rounded-lg border border-border bg-surface-subtle p-4 text-sm text-text-muted">{empty}</p>;
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
  const timestamps = records
    .map((item) => String(item.timestamp || item.first_seen || "").trim())
    .filter(Boolean)
    .sort();
  const sessionIds = new Set(records.map((item) => String(item.session_id || "").trim()).filter(Boolean));
  const sightingIds = records.map((item) => String(item.sighting_id || "").trim()).filter(Boolean);
  const hasSightingMetadata = timestamps.length > 0 || sessionIds.size > 0 || sightingIds.length > 0;
  return (
    <>
      {hasSightingMetadata && <SummaryGrid fields={[
        ["Returned sightings", sightingIds.length ? String(sightingIds.length) : String(records.length)],
        ["Unique observables", String(groups.length)],
        ["Distinct sessions", sessionIds.size ? String(sessionIds.size) : "Not recorded"],
        ["First seen", timestamps[0] || "Not recorded"],
        ["Last seen", timestamps[timestamps.length - 1] || "Not recorded"],
      ]} />}
      <ol className="mt-3 grid gap-2 xl:grid-cols-2">
        {groups.map((group, index) => {
          const first = group.items[0];
          return (
            <li key={`${index}-${group.type}-${group.value}`} className="rounded-lg border border-border bg-surface-subtle px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="ui-badge text-[11px]">{group.type}</span>
                <span className="min-w-0 flex-1 break-all font-mono text-xs text-text">{group.value}</span>
                {group.items.length > 1 && <span className="ui-badge text-[11px]">{group.items.length} sightings</span>}
              </div>
              {(hasMeaningfulValue(first.source) || hasMeaningfulValue(first.eventid) || hasMeaningfulValue(first.event_id)) && <p className="mt-1 text-[11px] text-text-muted">source: {summaryValue(first.eventid || first.source, "observed event")} · event {summaryValue(first.event_id, "not linked")}</p>}
              <details className="mt-2 rounded-lg border border-border bg-surface px-3 py-2 text-xs">
                <summary className="cursor-pointer select-none font-semibold text-text">Observable context · {group.items.length} {group.items.length === 1 ? "sighting" : "sightings"}</summary>
                <ol className="mt-3 space-y-2">
                  {group.items.map((observable, occurrenceIndex) => (
                    <li key={`${occurrenceIndex}-${summaryValue(observable.sighting_id, "occurrence")}`} className="rounded border border-border bg-surface-subtle p-2">
                      <dl className="grid gap-2 sm:grid-cols-2">
                        <div>
                          <dt className="text-[10px] uppercase tracking-[0.1em] text-text-subtle">Session</dt>
                          <dd className="mt-1 break-all font-mono text-[11px] text-text">{summaryValue(observable.session_id, "Not recorded")}</dd>
                        </div>
                        <div>
                          <dt className="text-[10px] uppercase tracking-[0.1em] text-text-subtle">Timestamp</dt>
                          <dd className="mt-1 break-all font-mono text-[11px] text-text">{summaryValue(observable.timestamp || observable.first_seen, "Not recorded")}</dd>
                        </div>
                        <div>
                          <dt className="text-[10px] uppercase tracking-[0.1em] text-text-subtle">Source / event</dt>
                          <dd className="mt-1 break-words text-[11px] text-text">{summaryValue(observable.source || observable.sensor_id, "Not recorded")} · {summaryValue(observable.event_id || observable.eventid, "not linked")}</dd>
                        </div>
                        <div>
                          <dt className="text-[10px] uppercase tracking-[0.1em] text-text-subtle">Sighting ID</dt>
                          <dd className="mt-1 break-all font-mono text-[11px] text-text">{summaryValue(observable.sighting_id, "Not recorded")}</dd>
                        </div>
                      </dl>
                    </li>
                  ))}
                </ol>
              </details>
            </li>
          );
        })}
      </ol>
    </>
  );
}

function RecordList({ items, empty }: { items: unknown[]; empty: string }) {
  if (!items.length) {
    return <p className="rounded-lg border border-border bg-surface-subtle p-4 text-sm text-text-muted">{empty}</p>;
  }
  return (
    <ol className="space-y-2">
      {items.slice(0, 50).map((item, index) => {
        const entry = record(item);
        const primary = entry.title || entry.name || entry.rule_id || entry.report_id || entry.feedback_id || entry.status || entry.type;
        const secondary = entry.reason || entry.summary || entry.message || entry.description;
        return (
          <li key={`${index}-${String(primary || "record")}`} className="rounded-lg border border-border bg-surface-subtle px-3 py-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-xs font-semibold text-text">{summaryValue(primary, "Stored record")}</span>
              {entry.status !== undefined && <span className="ui-badge text-[11px]">{summaryValue(entry.status)}</span>}
            </div>
            {hasMeaningfulValue(secondary) && <p className="mt-1 text-xs text-text-muted">{summaryValue(secondary)}</p>}
          </li>
        );
      })}
    </ol>
  );
}

function SummaryGrid({ fields }: { fields: Array<readonly [string, string]> }) {
  return (
    <dl className="grid gap-3 sm:grid-cols-2">
      {fields.map(([name, value]) => (
        <div key={name} className="rounded-lg border border-border bg-surface-subtle p-3">
          <dt className="text-[11px] font-medium uppercase tracking-[0.1em] text-text-subtle">{name}</dt>
          <dd className="mt-1 break-words font-mono text-xs text-text">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function MetricStrip({ fields }: { fields: Array<readonly [string, string]> }) {
  return (
    <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3">
      {fields.map(([name, value], index) => (
        <div key={name} className={`rounded-lg border px-3 py-2.5 transition-colors hover:border-primary-border ${index === 0 ? "border-primary-border bg-primary-subtle/50" : "border-border bg-surface-subtle"}`}>
          <dt className="text-[10px] font-semibold uppercase tracking-[0.1em] text-text-subtle">{name}</dt>
          <dd className="mt-0.5 break-words text-lg font-semibold leading-6 text-text">{value}</dd>
        </div>
      ))}
    </dl>
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
  const hasValue = fields.some(([, value]) => value !== "Not recorded" && value !== "Unavailable" && value !== "");
  return (
    <details className="mt-3 rounded-lg border border-border bg-surface px-3 py-2 text-xs">
      <summary className="cursor-pointer select-none font-semibold text-text">{title}</summary>
      {hasValue ? (
        <dl className="mt-3 grid gap-2 sm:grid-cols-2">
          {fields.map(([name, value]) => (
            <div key={name} className="rounded border border-border bg-surface-subtle p-2">
              <dt className="text-[10px] uppercase tracking-[0.1em] text-text-subtle">{name}</dt>
              <dd className="mt-1 break-words font-mono text-[11px] text-text">{value}</dd>
            </div>
          ))}
        </dl>
      ) : <p className="mt-2 text-text-muted">{empty}</p>}
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
    <TraceabilityDetails
      title="Why this guidance was selected"
      fields={[
        ["Action ID", summaryValue(trace.action_id || action.action_id, "Not recorded")],
        ["Policy / rule", guidancePolicyRuleLabel(trace.policy_rule || { rule_id: action.rule_id })],
        ["Matched predicates", predicates.length ? predicates.map(predicateTraceLabel).join(" | ") : "Not recorded"],
        ["Evidence references", evidenceReferences],
        ["Source event IDs", traceList(trace.source_event_ids)],
        ["Source command IDs", traceList(trace.source_command_ids)],
        ["Exact session", sessionId],
      ]}
    />
  );
}

function ClassificationTraceability({ mapping, sourceCommand }: { mapping: JsonRecord; sourceCommand: string | null }) {
  const trace = record(mapping.traceability);
  const sourceEvent = record(trace.source_event);
  const durableOrder = record(mapping.durable_evidence_order);
  return (
    <TraceabilityDetails
      title="Why this technique is shown"
      fields={[
        ["Technique", summaryValue(mapping.ttp || mapping.technique_id, "Not recorded")],
        ["Technique name", summaryValue(mapping.name, "Not recorded")],
        ["Source command", sourceCommand || "Not recorded"],
        ["Source event", summaryValue(sourceEvent.cowrie_eventid || sourceEvent.event_type || mapping.cowrie_eventid, "Not recorded")],
        ["Event ID", summaryValue(trace.event_id || durableOrder.event_id || mapping.evidence_id, "Not recorded")],
        ["Procedure / evidence anchor", summaryValue(trace.procedure_anchor, "Not recorded")],
        ["Evidence references", traceList(trace.evidence_references || mapping.evidence_id)],
        ["Policy / rule", guidancePolicyRuleLabel(trace.policy_or_rule_identifier)],
        ["Model source", summaryValue(trace.model_source || mapping.source, "Not recorded")],
        ["Authority state", summaryValue(trace.authority_state, "Not recorded")],
        ["Evidence tier", summaryValue(trace.evidence_tier || mapping.evidence_tier, "Not recorded")],
      ]}
    />
  );
}

function TrustedTraceability({ mapping }: { mapping: JsonRecord }) {
  const trace = record(mapping.traceability);
  return (
    <TraceabilityDetails
      title="Trusted evidence anchors"
      fields={[
        ["Technique", summaryValue(mapping.technique_id || mapping.ttp, "Not recorded")],
        ["Source command", traceList(trace.source_commands)],
        ["Evidence references", traceList(trace.evidence_references)],
        ["Policy / rule", guidancePolicyRuleLabel(trace.policy_or_rule_identifier)],
        ["Authority state", summaryValue(trace.authority_state || mapping.authority, "trusted_observation")],
        ["Evidence tier", summaryValue(trace.evidence_tier || mapping.evidence_tier, "Not recorded")],
      ]}
    />
  );
}

function tiLookupState(value: JsonRecord, freshnessOverride?: unknown): string {
  const freshness = String(freshnessOverride ?? value.freshness_state ?? "").trim().toUpperCase();
  if (freshness === "STALE" || freshness === "EXPIRED" || freshness === "TI_EXPIRED" || freshness === "TI_STALE") return "STALE";
  const lookup = String(value.lookup_status || value.status || "").trim().toUpperCase();
  if (["OK", "CACHED", "AVAILABLE"].includes(lookup)) return "DATA";
  if (["NOT_FOUND", "NO_DATA"].includes(lookup)) return "NO_DATA";
  if (["PROVIDER_ERROR", "ERROR", "RATE_LIMITED", "AUTH_FAILED", "REQUEST_FAILED"].includes(lookup)) return "ERROR";
  if (["DISABLED", "UNAVAILABLE", "AUTH_DISABLED", "BUDGET_EXHAUSTED", "INVALID_OBSERVABLE", "PENDING"].includes(lookup)) return "UNAVAILABLE";
  return "UNAVAILABLE";
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
  const timestamp = Date.parse(String(value));
  if (!Number.isFinite(timestamp)) return "Not calculable";
  const ageSeconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (ageSeconds < 60) return `${ageSeconds}s`;
  if (ageSeconds < 3_600) return `${Math.floor(ageSeconds / 60)}m`;
  if (ageSeconds < 86_400) return `${Math.floor(ageSeconds / 3_600)}h`;
  return `${Math.floor(ageSeconds / 86_400)}d`;
}

function tiTimestampLabel(value: unknown): string {
  if (!hasMeaningfulValue(value)) return "Not recorded";
  const timestamp = Date.parse(String(value));
  if (!Number.isFinite(timestamp)) return "Not calculable";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(timestamp);
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
  const statuses = Object.entries(providerStatus)
    .map(([provider, value]) => [provider, record(value)] as const)
    .filter(([, value]) => Number(value.record_count || 0) > 0 || hasMeaningfulValue(value.lookup_status));
  if (evidence.length === 0 && cache.length === 0 && statuses.length === 0) return null;
  return (
    <div className="mt-3 space-y-2">
      <p className="text-xs font-semibold uppercase tracking-[0.1em] text-text-subtle">Stored provider context · non-authoritative</p>
      {statuses.length > 0 && (
        <ol className="space-y-2">
          {statuses.slice(0, 12).map(([provider, status]) => (
            <li key={provider} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono font-semibold text-text">{provider}</span>
                <span className="ui-badge text-[11px]">{tiLookupState(status)}</span>
              </div>
              <p className="mt-1 text-text-muted">
                finding: {summaryValue(status.finding_state, "not recorded")} · freshness: {summaryValue(status.freshness_state, "not recorded")} · records: {countOf(status.record_count)}
              </p>
              <TraceabilityDetails
                title="Provider state details"
                fields={[
                  ["Provider", provider],
                  ["Observable", summaryValue(status.observable_value || observable.value, "Not recorded")],
                  ["Observable type", summaryValue(status.observable_type || observable.type, "Not recorded")],
                  ["Observable role", summaryValue(status.observable_role || observable.role, "Not recorded")],
                  ["Lookup state", tiLookupState(status)],
                  ["Freshness", freshnessLabel(status.freshness_state)],
                  ["Retrieved at", summaryValue(status.retrieved_at || status.lookup_at, "Not recorded")],
                  ["Provider observed at", summaryValue(status.provider_observed_at, "Not recorded")],
                  ["Expires at", summaryValue(status.expires_at, "Not recorded")],
                  ["Data age", dataAge(status.retrieved_at || status.lookup_at)],
                ]}
              />
            </li>
          ))}
        </ol>
      )}
      {evidence.slice(0, 20).map((item, index) => {
        const extension = selectedProviderFields(item.normalized_extension);
        return (
          <div key={`evidence-${index}-${summaryValue(item.evidence_id, "provider")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono font-semibold text-text">{summaryValue(item.provider, "provider unavailable")}</span>
              <span className="ui-badge text-[11px]">{tiLookupState(item)}</span>
            </div>
            <p className="mt-1 text-text-muted">
              finding: {summaryValue(item.finding_state, "not recorded")} · freshness: {summaryValue(item.freshness_state, "not recorded")}
            </p>
            <p className="mt-1 text-text-muted">summary: {summaryValue(item.summary, "No provider finding summary stored.")}</p>
            <p className="mt-1 text-text-muted">
              retrieved: {summaryValue(item.retrieved_at, "Not recorded")} · expires: {summaryValue(item.expires_at, "Not recorded")}
            </p>
            <TraceabilityDetails
              title="Provider and observable traceability"
              fields={[
                ["Provider", summaryValue(item.provider, "Not recorded")],
                ["Observable", summaryValue(item.observable_value || record(item.safe_observable_reference).display_value || observable.value, "Not recorded")],
                ["Observable type", summaryValue(item.observable_type || observable.type, "Not recorded")],
                ["Observable role", summaryValue(item.observable_role || observable.role, "Not recorded")],
                ["Lookup state", tiLookupState(item)],
                ["Freshness", freshnessLabel(item.freshness_state)],
                ["Retrieved at", summaryValue(item.retrieved_at, "Not recorded")],
                ["Provider observed at", summaryValue(item.provider_observed_at, "Not recorded")],
                ["Expires at", summaryValue(item.expires_at, "Not recorded")],
                ["Data age", dataAge(item.retrieved_at)],
                ["Session binding", summaryValue(item.session_id, "Not recorded")],
              ]}
            />
            {extension.length > 0 && (
              <dl className="mt-2 grid gap-2 sm:grid-cols-2">
                {extension.map(([key, value]) => (
                  <div key={key} className="rounded border border-border bg-surface p-2">
                    <dt className="text-[10px] uppercase tracking-[0.1em] text-text-subtle">{key.replaceAll("_", " ")}</dt>
                    <dd className="mt-1 break-words font-mono text-[11px] text-text">{value}</dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        );
      })}
      {cache.slice(0, 20).map((item, index) => {
        const context = selectedProviderFields(item.normalized_context);
        const freshness = sourceIpCacheFreshness(item, asOf);
        return (
          <div key={`cache-${index}-${summaryValue(item.provider, "provider")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono font-semibold text-text">{summaryValue(item.provider, "provider unavailable")} cache</span>
              <span className="ui-badge text-[11px]">{tiLookupState(item, freshness)}</span>
            </div>
            <p className="mt-1 text-text-muted">lookup: {summaryValue(item.lookup_at, "Not recorded")} · expires: {summaryValue(item.expires_at, "Not recorded")} · freshness: {freshnessLabel(freshness)}</p>
            <TraceabilityDetails
              title="Cached provider and observable details"
              fields={[
                ["Provider", summaryValue(item.provider, "Not recorded")],
                ["Observable", summaryValue(item.observable_value || observable.value, "Not recorded")],
                ["Observable type", summaryValue(item.observable_type || observable.type, "source_ip")],
                ["Observable role", summaryValue(item.observable_role || "source_ip", "Not recorded")],
                ["Lookup state", tiLookupState(item, freshness)],
                ["Freshness", freshnessLabel(freshness)],
                ["Retrieved at", summaryValue(item.lookup_at, "Not recorded")],
                ["Provider observed at", summaryValue(item.provider_observed_at, "Not recorded")],
                ["Expires at", summaryValue(item.expires_at, "Not recorded")],
                ["Data age", dataAge(item.lookup_at)],
              ]}
            />
            {context.length > 0 && <p className="mt-1 text-text-muted">normalized context: {context.map(([key, value]) => `${key.replaceAll("_", " ")}=${value}`).join(" · ")}</p>}
          </div>
        );
      })}
    </div>
  );
}

function AuthenticationSummary({ data }: { data: JsonRecord }) {
  const attempts = list(data.attempts).map(record);
  const visibleUsernames = Array.from(new Set(
    attempts.map(analystAttackerUsername).filter((value): value is string => Boolean(value)),
  ));
  return (
    <div className="space-y-3">
      <Insight title="Observed access">{countOf(data.attempt_count)} login attempt{Number(data.attempt_count) === 1 ? "" : "s"}; {countOf(data.success_count)} succeeded and {countOf(data.failure_count)} failed. {visibleUsernames.length ? `Observed account: ${visibleUsernames.join(", ")}.` : "The account name was not retained."}</Insight>
      <MetricStrip fields={[
        ["Attempts", countOf(data.attempt_count)],
        ["Successful", countOf(data.success_count)],
        ["Failed", countOf(data.failure_count)],
      ]} />
      {attempts.length > 0 && (
        <ScrollPanel title="Login activity" count={attempts.length} height="max-h-64">
        <ol className="space-y-2">
          {attempts.slice(0, 20).map((attempt, index) => (
            <li key={`${index}-${summaryValue(attempt.timestamp, "attempt")}`} className="flex items-start gap-3 rounded-lg border border-border bg-surface-subtle p-3 text-xs transition-colors hover:border-primary-border">
              <span className={`mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full ${String(attempt.outcome).toLowerCase().includes("success") ? "bg-primary-subtle text-primary" : "bg-warning-subtle text-warning"}`} aria-hidden="true">
                <Fingerprint className="h-3.5 w-3.5" />
              </span>
              <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold capitalize text-text">{readableCode(attempt.outcome || "login attempt")}</span>
                <span className="font-mono text-text-muted">{summaryValue(attempt.timestamp, "Timestamp unavailable")}</span>
              </div>
              <p className="mt-1 text-text-muted">Account: <span className="font-mono text-text">{analystAttackerUsername(attempt) || summaryValue(attempt.username_visibility, "Not retained")}</span>{hasMeaningfulValue(attempt.method) ? ` · method: ${readableCode(attempt.method)}` : ""}</p>
              </div>
            </li>
          ))}
        </ol>
        </ScrollPanel>
      )}
      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-text-muted">
        <span>First seen: {summaryValue(data.first_attempt_at, "Not recorded")}</span>
        <span>Last seen: {summaryValue(data.last_attempt_at, "Not recorded")}</span>
      </div>
    </div>
  );
}

function SourcePivotSummary({ data }: { data: JsonRecord }) {
  const counts = record(data.counts);
  const sessions = list(data.sessions).map(record);
  return (
    <div className="space-y-3">
      <Insight title="Source-IP recurrence">{summaryValue(record(data.observable).value, "This source")} appears in {countOf(counts.sessions_found)} recorded session{Number(counts.sessions_found) === 1 ? "" : "s"}. This is repeated source context, not attribution.</Insight>
      <MetricStrip fields={[
        ["Sessions found", countOf(counts.sessions_found)],
        ["Sightings examined", countOf(counts.sightings_examined)],
        ["Provider calls", data.provider_calls === false ? "0" : "Not reported"],
      ]} />
      {sessions.length > 0 && (
        <ScrollPanel title="Related sessions" count={sessions.length} height="max-h-80">
        <ol className="space-y-2">
          {sessions.slice(0, 20).map((session, index) => (
            <li key={`${index}-${summaryValue(session.session_id, "session")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs transition-colors hover:border-primary-border hover:bg-primary-subtle/30">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono font-semibold text-text">{summaryValue(session.session_id, "Session unavailable")}</span>
                <span className="ui-badge text-[11px]">{countOf(session.sighting_count)} sightings</span>
              </div>
              <p className="mt-1 text-text-muted"><time>{summaryValue(session.first_seen, "First seen unavailable")}</time> <span aria-hidden="true">→</span> <time>{summaryValue(session.last_seen, "Last seen unavailable")}</time></p>
              <TraceabilityDetails
                title="Observable recurrence details"
                fields={[
                  ["Observable role", traceList(session.roles, "source_ip")],
                  ["Sources", traceList(session.sources)],
                  ["Sensor IDs", traceList(session.sensor_ids)],
                  ["Sighting count", countOf(session.sighting_count)],
                  ["First seen", summaryValue(session.first_seen, "Not recorded")],
                  ["Last seen", summaryValue(session.last_seen, "Not recorded")],
                ]}
              />
            </li>
          ))}
        </ol>
        </ScrollPanel>
      )}
      <p className="text-xs text-text-subtle">Repeated source context does not establish attribution, intent, or classification.</p>
    </div>
  );
}

function ExternalTiSummary({ sessionData, observableData }: { sessionData: JsonRecord; observableData: JsonRecord }) {
  const sessionCounts = record(sessionData.counts);
  const observableCounts = record(observableData.counts);
  const summary = { ...record(sessionData.external_ti_summary), ...record(observableData.external_ti_summary) };
  const entities = list(sessionData.shared_entities).map(record);
  const evidence = [...list(sessionData.evidence), ...list(observableData.evidence)].map(record);
  const cache = [...list(sessionData.source_ip_cache), ...list(observableData.source_ip_cache)].map(record);
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
  return (
    <>
      <Insight title="External threat intelligence" tone={tiState.state === "FRESH" && (evidence.length > 0 || cache.length > 0) ? "primary" : "warning"}>
        {evidence.length || cache.length ? `${evidence.length} stored provider finding${evidence.length === 1 ? "" : "s"} and ${cache.length} source-IP cache result${cache.length === 1 ? "" : "s"}. Check freshness before using this context.` : summaryValue(sessionData.status_reason_text, "No provider finding is linked to this session; no external intelligence is inferred.")}
      </Insight>
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded-full border px-3 py-1.5 text-xs font-semibold ${tiState.state === "FRESH" ? "border-primary-border bg-primary-subtle text-primary" : "border-warning-border bg-warning-subtle text-warning"}`}>{readableCode(tiState.state)}</span>
        <span className="rounded-full border border-border bg-surface px-3 py-1.5 text-xs text-text-muted">Observable: {summaryValue(observable.value, "Not available")}</span>
        <span className="rounded-full border border-border bg-surface px-3 py-1.5 text-xs text-text-muted">Last lookup: {tiTimestampLabel(tiState.latestRetrievedAt)}</span>
      </div>
      <MetricStrip fields={[
        ["Eligible observables", countOf(sessionCounts.eligible_observables)],
        ["Provider findings", countOf(evidence.length || Number(sessionCounts.evidence_returned || 0) + Number(observableCounts.evidence_returned || 0))],
        ["Cached results", countOf(cache.length)],
        ["Sightings examined", countOf(observableCounts.sightings_examined || sessionCounts.sightings_examined)],
      ]} />
      {jobSummary.pending === true && (
        <p className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-text-muted">
          {summaryValue(sessionData.status_reason_text, "An eligible provider lookup is awaiting the enrichment worker.")}
          {Object.keys(jobStatusCounts).length > 0 && ` Queue state: ${Object.entries(jobStatusCounts).map(([state, count]) => `${state}=${count}`).join(", ")}.`}
        </p>
      )}
      {tiState.state === "MIXED" && (
        <p className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-text-muted">
          Fresh source-IP cache data is available ({tiState.freshCacheCount} provider result{tiState.freshCacheCount === 1 ? "" : "s"}); older stored provider evidence is stale ({tiState.staleEvidenceCount} record{tiState.staleEvidenceCount === 1 ? "" : "s"}). Freshness is shown per record below.
        </p>
      )}
      {entities.length > 0 && <ScrollPanel title="Shared entities" count={entities.length} height="max-h-64"><ObservableList items={entities} empty="No shared entities are recorded." /></ScrollPanel>}
      <ScrollPanel title="Provider results and freshness" count={evidence.length + cache.length} height="max-h-96">
        <ProviderContextRows evidence={evidence} cache={cache} providerStatus={providerStatus} observable={observable} asOf={asOf} />
      </ScrollPanel>
      {entities.length === 0 && evidence.length === 0 && cache.length === 0 && (
        <p className="rounded-lg border border-border bg-surface-subtle p-3 text-xs text-text-muted">No provider finding is linked to this session. Read state: {readableCode(summary.uncertainty || sessionData.status || "context only")}.</p>
      )}
      <p className="text-xs text-text-subtle">Provider results are attributed context; they do not establish classification or authorize response.</p>
    </>
  );
}

function HypothesisSummary({ data }: { data: JsonRecord }) {
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
  const relationshipCount = Number(sessionGraph.relationship_edges || 0);
  return (
    <div className="space-y-3">
      <Insight title="Assessment outcome" tone={hypothesisSets.length ? "primary" : "warning"}>
        {hypothesisSets.length ? `${hypothesisSets.length} evidence-bounded hypothesis set${hypothesisSets.length === 1 ? "" : "s"} recorded.` : "No evidence-bounded hypothesis was established for this session."} {contextualHypotheses.length} TTP correlation{contextualHypotheses.length === 1 ? " is" : "s are"} context only, not validated findings.
      </Insight>
      <MetricStrip fields={[
        ["Hypothesis sets", String(hypothesisSets.length)],
        ["Canonical findings", String(canonicalCount)],
        ["TTP context", String(contextualHypotheses.length)],
      ]} />
      {sessionFamilies.length > 0 && (
        <ScrollPanel title="Behavior checks across this session" count={sessionFamilies.length} height="max-h-80">
          <p className="mb-2 px-1 text-[11px] text-text-muted">Each behavior family shows whether observed evidence passed its review gate.</p>
          <ul className="grid gap-2 sm:grid-cols-2">
            {sessionFamilies.map((family, index) => (
              <li key={`${summaryValue(family.semantic_family, "family")}-${index}`} className="rounded-lg border border-border bg-surface p-3 text-xs transition-colors hover:border-primary-border">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold capitalize text-text">{readableCode(family.semantic_family || "behavior not recorded")}</span>
                  <span className={`ui-badge ${list(family.finding_ids).length ? "border-primary-border bg-primary-subtle text-primary" : ""}`}>{readableCode(family.status || "not evaluated")}</span>
                </div>
                <div className="mt-2 flex gap-3 text-text-muted"><span>{countOf(family.observed_fact_count)} observations</span><span>{countOf(list(family.finding_ids).length)} findings</span></div>
                {list(family.missing_evidence).length > 0 && <p className="mt-2 rounded-md bg-warning-subtle px-2.5 py-1.5 text-warning">Still needed: {list(family.missing_evidence).map(readableCode).join(", ")}</p>}
              </li>
            ))}
          </ul>
        </ScrollPanel>
      )}
      {contextualHypotheses.length > 0 && (
        <section className="rounded-xl border border-warning-border bg-warning-subtle/30 p-3" aria-label="Related ATT&CK context">
          <div className="mb-2 flex items-center justify-between gap-2">
            <h3 className="text-xs font-semibold text-text">Related ATT&amp;CK context · not confirmed behavior</h3>
            <span className="ui-badge text-[10px]">{contextualHypotheses.length}</span>
          </div>
          <ol className="grid gap-2 sm:grid-cols-2">
            {contextualHypotheses.map((hypothesis) => (
              <li key={hypothesis.key} className="rounded-lg border border-warning-border bg-warning-subtle/40 p-3 text-xs transition-colors hover:bg-warning-subtle">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="rounded-md bg-surface px-2 py-1 font-mono font-semibold text-text">{hypothesis.techniqueId || "Technique unavailable"}</span>
                  {hypothesis.techniqueName && <span className="font-medium text-text">{hypothesis.techniqueName}</span>}
                  <span className="ml-auto ui-badge">Context only</span>
                </div>
                {hypothesis.tactic && <p className="mt-2 text-text-muted">Related tactic: {readableCode(hypothesis.tactic)}</p>}
                {hypothesis.matchedConditions.length > 0 && <p className="mt-1 text-text-muted">Related evidence: {hypothesis.matchedConditions.map((condition) => condition.description || readableCode(condition.type || "observation")).join(" · ")}</p>}
              </li>
            ))}
          </ol>
        </section>
      )}
      {hypothesisSets.length > 0 && (
        <ScrollPanel title="Evidence-bounded hypothesis sets" count={hypothesisSets.length} height="max-h-80">
        <ol className="space-y-2">
          {hypothesisSets.slice(0, 10).map((hypothesisSet, index) => (
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
        </ScrollPanel>
      )}
      {hypotheses.length === 0 && hypothesisSets.length === 0 && <div className="rounded-lg border border-border bg-surface-subtle p-3 text-sm text-text-muted">No session-correlated ATT&amp;CK context was recorded.</div>}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-2 text-[11px] text-text-subtle">
        <span>Evidence nodes: {countOf(sessionGraph.evidence_nodes)} · links: {relationshipCount} · reports: {reports.length}</span>
        <span>Context does not confirm behavior or attacker intent.</span>
      </div>
      <MoreDetails title="Assessment method and report notes">
        <SummaryGrid fields={[
          ["Authority", summaryValue(data.authority, "Contextual only")],
          ["Correlation records", countOf(hypotheses.length || counts.correlations)],
          ["Evidence strength", readableCode(reportSummary.evidence_strength || reportSummary.analytical_evidence_strength || "not recorded")],
          ["Analysis mode", readableCode(reportSummary.analysis_mode || "not recorded")],
          ["Campaign", summaryValue(reportSummary.campaign_name, "Not recorded")],
          ["Follow-on assessment", readableCode(followOnAssessment.status || "not assessed")],
        ]} />
        {hasMeaningfulValue(reportSummary.summary) && <p className="mt-3 rounded-lg border border-border bg-surface-subtle p-3 text-sm text-text">{summaryValue(reportSummary.summary)}</p>}
        {hasMeaningfulValue(reportSummary.evidence_strength_reason) && <p className="mt-2 text-xs text-text-muted">Assessment note: {summaryValue(reportSummary.evidence_strength_reason)}</p>}
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
  const safety = record(guidance.safety);
  const findingCount = Number(guidance.finding_count || 0);
  const boundFindingIds = new Set(actions.flatMap((action) => list(action.finding_ids).map((id) => label(id, "")).filter(Boolean)));
  const hasFindingBindings = actions.some((action) => Array.isArray(action.finding_ids));
  const unmatchedFindingCount = hasFindingBindings ? Math.max(0, findingCount - boundFindingIds.size) : null;
  return (
    <>
      <Insight title="What an analyst can do">{actions.length ? `${actions.length} manual action${actions.length === 1 ? " is" : "s are"} available from reviewed policy. AI did not invent or execute ${actions.length === 1 ? "it" : "them"}.` : "No policy-approved response action is available for this evidence."}</Insight>
      <div className="flex flex-wrap gap-2">
        <span className="rounded-full border border-border bg-surface-subtle px-3 py-1.5 text-xs text-text-muted">{countOf(findingCount)} evidence finding{findingCount === 1 ? "" : "s"}</span>
        <span className="rounded-full border border-primary-border bg-primary-subtle px-3 py-1.5 text-xs font-medium text-primary">{actions.length} reviewed action{actions.length === 1 ? "" : "s"}</span>
        <span className="rounded-full border border-warning-border bg-warning-subtle px-3 py-1.5 text-xs text-warning">{guidance.requires_manual_approval === false ? "Manual approval not required" : "Manual approval required"}</span>
      </div>
      {actions.length > 0 ? (
        <ScrollPanel title="Suggested analyst actions" count={actions.length} height="max-h-80">
        <ol className="space-y-2">
          {actions.slice(0, 20).map((action, index) => (
            <li key={`${index}-${summaryValue(action.action_id, "action")}`} className="rounded-lg border border-primary-border bg-primary-subtle/30 p-3 text-sm transition-colors hover:bg-primary-subtle/60">
              <p className="font-semibold text-text">{summaryValue(action.description || action.action_id, "Stored analyst action")}</p>
              <p className="mt-1 text-xs leading-5 text-text-muted">{summaryValue(action.rationale, "Review the cited evidence before acting.")}</p>
              {list(action.preconditions).length > 0 && <p className="mt-2 text-xs text-text-muted"><span className="font-semibold text-text">Before:</span> {list(action.preconditions).map((value) => display(value)).join(" ")}</p>}
              {list(action.verification_steps).length > 0 && <p className="mt-1 text-xs text-text-muted"><span className="font-semibold text-text">Check:</span> {list(action.verification_steps).map((value) => display(value)).join(" ")}</p>}
              <div className="mt-2">
                <span className="ui-badge text-[10px]">{action.requires_manual_approval === false ? "Review not required" : "Human review required"} · {action.safe_to_auto_execute === true ? "automatic execution allowed" : "no automatic action"}</span>
                <GuidanceTraceability action={action} guidance={guidance} />
              </div>
            </li>
          ))}
        </ol>
        </ScrollPanel>
      ) : <p className="mt-3 text-xs text-text-muted">No stored recommendation content is available.</p>}
      {unmatchedFindingCount !== null && unmatchedFindingCount > 0 && (
        <p className="mt-3 rounded-lg border border-border bg-surface-subtle p-3 text-xs text-text-muted">
          {unmatchedFindingCount} evidence finding{unmatchedFindingCount === 1 ? " does" : "s do"} not select a distinct reviewed action playbook. Actions are policy-matched and deduplicated; findings are not converted into recommendations automatically.
        </p>
      )}
      {hasMeaningfulValue(validation.error) && <p className="mt-3 text-xs text-warning">{summaryValue(validation.error)}</p>}
      <p className="mt-3 text-xs text-text-subtle">Manual-only. safe_to_auto_execute={String(safety.automatic_execution === true ? true : false)}.</p>
    </>
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
  const results = list(ensemble.results).map(record);
  const model1Only = list(ensemble.model1_only_labels).map(record);
  const recommendations = rankTtpRecommendations(data);

  if (!hasMeaningfulRecord(ensemble) && recommendations.length === 0) {
    return <p className="rounded-lg border border-border bg-surface-subtle p-4 text-sm text-text-muted">No stored Model1 + Model2 ensemble evidence is available for this exact session.</p>;
  }

  const architecture = model2.one_model === true
    ? "UNIFIED_ONE_MODEL"
    : model2.one_model === false
      ? "NOT_UNIFIED"
      : "Not reported";

  return (
    <div className="space-y-3">
      <Insight title="Model corroboration" tone={hasBoundAvailableModel2(data) ? "primary" : "warning"}>
        {hasBoundAvailableModel2(data) ? "A session-bound Model2 result is available for comparison with Model1." : "No session-bound Model2 result is available. Model1 remains primary; no ensemble corroboration or combined score is claimed."}
      </Insight>
      <MetricStrip fields={[
        ["Model1", model1.applicable === true || recommendations.length > 0 ? "Ready" : model1.applicable === false ? "N/A" : "Unknown"],
        ["Model2", hasBoundAvailableModel2(data) ? "Bound" : "Unavailable"],
        ["Comparisons", String(results.length)],
      ]} />
      <p className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs leading-5 text-warning">Model1 remains the primary classifier. Model2 adds advisory corroboration only when fully bound to this session. Native model scores are never added or treated as probabilities.</p>
      {recommendations.length > 0 ? <section className="rounded-xl border border-primary-border bg-primary-subtle p-3.5">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-text">TTPs to investigate first</h3>
            <p className="mt-1 text-xs leading-5 text-text-muted">Model1's selected TTP per command, grouped by distinct command event. More supporting commands appear first. This is not a confidence percentage, trusted finding, or response authorization.</p>
          </div>
          <span className="ui-badge text-[10px]">Command evidence · advisory only</span>
        </div>
        <ol className="mt-3 grid gap-2 sm:grid-cols-2">
          {recommendations.map((item) => <li key={item.techniqueId} className="rounded-lg border border-border bg-surface p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-semibold text-text">#{item.rank} <span className="font-mono">{item.techniqueId}</span></span>
              <span className="ui-badge text-[10px]">{item.model2Support === "corroborates" ? "Model2 supports" : item.model2Support === "does_not_support" ? "Model2 does not support" : item.model2Support === "not_supported" ? "Model2 does not cover this TTP" : "Model2 unavailable"}</span>
            </div>
            <p className="mt-1 text-xs text-text-muted">{item.supportingCommandEvents} of {item.assessedCommandEvents} assessed command events support this Model1 suggestion.</p>
            {item.evidenceRefs.length > 0 && <p className="mt-1 text-[11px] text-text-subtle">Command refs: {item.evidenceRefs.slice(0, 8).map((ref) => ref.commandRef).join(", ")}{item.evidenceRefs.length > 8 ? " …" : ""}</p>}
            {item.model2Support === "does_not_support" && <p className="mt-1 text-xs text-warning">Model2 reported ABSENT for its independent head; review before drawing a conclusion.</p>}
          </li>)}
        </ol>
        <p className="mt-2 text-[11px] text-text-subtle">Method: count distinct command events by selected Model1 TTP. Repeated classifications for one command count once. Model2 is a separate bound-session comparison; no RRF or score fusion is applied.</p>
      </section> : <p className="rounded-lg border border-border bg-surface-subtle p-3 text-xs text-text-muted">No deduplicated command-level Model1 advisory is available for this session. Older snapshots may lack stable command references.</p>}
      {results.length > 0 && <ScrollPanel title="Technique-by-technique comparison" count={results.length} height="max-h-80">
        <ol className="space-y-2">
          {results.map((item, index) => (
            <li key={`${index}-${summaryValue(item.technique_id, "technique")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs transition-colors hover:border-primary-border">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono font-semibold text-text">{summaryValue(item.technique_id, "Technique unavailable")}</span>
                <span className="ui-badge text-[11px]">{readableCode(item.evidence_state || "comparison unavailable")}</span>
              </div>
              <div className="mt-2 grid gap-1 text-text-muted sm:grid-cols-2">
                <span>Model1: <span className="font-medium text-text">{readableCode(item.model1_result || "not applicable")}</span>{item.model1_margin !== null && item.model1_margin !== undefined ? ` · margin ${display(item.model1_margin)}` : ""}</span>
                <span>Model2: <span className="font-medium text-text">{readableCode(item.model2_result || "unavailable")}</span>{item.model2_score !== null && item.model2_score !== undefined ? ` · score ${display(item.model2_score)}` : ""}</span>
              </div>
              <p className="mt-1 text-text-muted">{readableCode(item.model2_relation || "comparison not recorded")} · primary source: {readableCode(item.primary_source || "none")}</p>
            </li>
          ))}
        </ol>
      </ScrollPanel>}
      {model1Only.length > 0 && <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-text-muted">Model1 only:</span>
        {model1Only.map((item) => <span key={summaryValue(item.technique_id, "unknown")} className="ui-badge font-mono text-[10px]">{summaryValue(item.technique_id, "unknown")}</span>)}
      </div>}
      <MoreDetails title="Model artifact and run information">
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
        ["Numeric score fusion", ensemble.fused_score === null ? "NONE" : display(ensemble.fused_score)],
        ["Computed at", summaryValue(ensemble.ensemble_computed_at, "Not reported")],
      ]} />
      </MoreDetails>
    </div>
  );
}

export function hasBoundAvailableModel2(data: JsonRecord): boolean {
  return hasBoundModel2(data);
}

export function AiAdvisorySummary({ data, guidanceData }: { data: JsonRecord; guidanceData: JsonRecord }) {
  const advisory = record(data.advisory);
  const validation = record(advisory.validation);
  const provenance = record(advisory.provenance);
  const safety = record(advisory.safety);
  const rendered = record(advisory.rendered_advisory);
  const paragraphs = list(rendered.paragraphs).map(record);
  const validated = record(advisory.validated_advisory);
  const guidance = record(guidanceData.response_guidance);
  const guidanceFindings = list(guidance.findings).map(record);
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
  const selectedFindings = guidanceFindings.filter((item) => selectedFindingIds.has(label(item.finding_id, "")));
  const selectedActions = guidanceActions.filter((item) => selectedActionIds.has(label(item.action_id, "")));
  const inaccurateNarrative = selectedFindings.length > 0 && paragraphs.some((item) => label(item.text, "").includes("canonical finding"));
  const hasSelection = selectedFindingIds.size > 0 || selectedActionIds.size > 0;
  return (
    <div className="space-y-3">
      <Insight title="What AI actually did" tone={hasSelection ? "primary" : "warning"}>
        {hasSelection ? `AI selected ${selectedFindingIds.size} existing evidence item${selectedFindingIds.size === 1 ? "" : "s"} and ${selectedActionIds.size} existing manual action${selectedActionIds.size === 1 ? "" : "s"} for review${selectedRelationshipCount ? `, with ${selectedRelationshipCount} relationship${selectedRelationshipCount === 1 ? "" : "s"}` : ""}.` : "No selected evidence or action is recorded in this advisory."} It did not create a trusted finding or execute a response.
      </Insight>
      {hasSelection && paragraphs.length === 0 && <p className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-warning">The AI selection is stored, but no rendered narrative was recorded. The linked evidence and actions below come from the verified guidance record.</p>}
      {hasSelection && <ScrollPanel title="Evidence and advice AI selected" count={selectedFindingIds.size + selectedActionIds.size} height="max-h-72">
        {selectedFindings.map((item) => <article key={label(item.finding_id)} className="rounded-lg border border-border bg-surface-subtle p-3 text-sm text-text">
          <div className="mb-1.5 flex flex-wrap items-center gap-2"><span className="ui-badge text-[10px]">Observed evidence</span><span className="text-[10px] text-text-subtle">{label(item.finding_type, "Response-guidance finding")}</span></div>
          {summaryValue(item.statement, "Statement unavailable")}
        </article>)}
        {selectedActions.map((item) => <article key={label(item.action_id)} className="rounded-lg border border-primary-border bg-primary-subtle/50 p-3 text-sm text-text">
          <div className="mb-1.5 flex items-center gap-2"><span className="ui-badge text-[10px]">Existing manual action</span><span className="text-[10px] text-text-subtle">For analyst review</span></div>
          <p className="font-semibold">{summaryValue(item.description, "Action description unavailable")}</p>
          {hasMeaningfulValue(item.rationale) && <p className="mt-1 text-xs leading-5 text-text-muted">{summaryValue(item.rationale)}</p>}
        </article>)}
      </ScrollPanel>}
      {(selectedFindingIds.size > selectedFindings.length || selectedActionIds.size > selectedActions.length) && <p className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-warning">Some AI selections could not be matched to the stored evidence or action details.</p>}
      {inaccurateNarrative && <p className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-xs text-warning">The stored text calls this a canonical finding, but the linked evidence is a response-guidance finding. The item shown above comes from the verified guidance record.</p>}
      <MoreDetails title="AI provider, validation and original response">
        <SummaryGrid fields={[
          ["Status", summaryValue(data.status, "Unavailable")],
          ["Authority", summaryValue(advisory.authority, "Non-authoritative")],
          ["Validation", summaryValue(validation.status, "Not recorded")],
          ["Provider", summaryValue(provenance.provider_id, "Not recorded")],
          ["Model", summaryValue(provenance.model_id, "Not recorded")],
          ["Manual approval", safety.requires_manual_approval === false ? "No" : "Required"],
        ]} />
        {paragraphs.map((paragraph, index) => <p key={`${index}-${label(paragraph.template_id)}`} className="mt-2 text-xs text-text-muted">{summaryValue(paragraph.text, "No stored narrative")}</p>)}
      </MoreDetails>
    </div>
  );
}

function PolicyGapSummary({ data }: { data: JsonRecord }) {
  const gap = record(data.policy_gap);
  const proposals = list(gap.proposals).map(record);
  return (
    <article className="rounded-lg border border-warning-border bg-warning-subtle p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.1em] text-warning">AI proposal for review</p>
        <span className="ui-badge text-[11px]">Not approved policy</span>
      </div>
      <p className="mt-2 text-sm text-text">{proposals.length ? `AI proposed ${proposals.length} possible pattern${proposals.length === 1 ? "" : "s"} to investigate. These are not verified findings or new response actions.` : "AI did not propose a new pattern for this session."}</p>
      {proposals.length > 0 && <ScrollPanel title="Candidate patterns to review" count={proposals.length} height="max-h-96">
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
      </ScrollPanel>}
      {proposals.length === 0 && <p className="mt-3 rounded-lg border border-border bg-surface p-3 text-sm text-text-muted">No policy-gap candidate was proposed for this session.</p>}
      <MoreDetails title="Policy proposal safeguards">
      <SummaryGrid fields={[
        ["Mode", summaryValue(gap.mode, "Read-only")],
        ["Proposals", countOf(proposals.length)],
        ["Authority", summaryValue(gap.authority, "PROPOSED_UNVALIDATED")],
        ["Review", gap.requires_review === false ? "Not required" : "REQUIRES_REVIEW"],
        ["Policy mutation", gap.automatic_policy_mutation === true ? "Enabled" : "Disabled"],
      ]} />
      <p className="mt-3 text-xs text-text-subtle">Candidates are for review. Policy updates and automatic execution remain disabled.</p>
      </MoreDetails>
    </article>
  );
}

function ProvenanceSummary({ value }: { value: JsonRecord }) {
  const reportSummary = record(value.report_summary);
  const errors = record(value.errors);
  const nonEmptyErrors = Object.values(errors).filter(hasMeaningfulValue).length;
  return (
    <>
      <Insight title="Evidence trail" tone={nonEmptyErrors ? "warning" : "primary"}>
        {list(value.analysis_jobs).length} analysis job{list(value.analysis_jobs).length === 1 ? "" : "s"} recorded; {hasMeaningfulRecord(reportSummary) ? "a report summary is available" : "no report summary is stored"}. {nonEmptyErrors ? `${nonEmptyErrors} error field${nonEmptyErrors === 1 ? " needs" : "s need"} review.` : "No stored error is reported."}
      </Insight>
      <MetricStrip fields={[
        ["Analysis jobs", countOf(list(value.analysis_jobs).length)],
        ["Report summary", hasMeaningfulRecord(reportSummary) ? "Ready" : "Empty"],
        ["Processing errors", countOf(nonEmptyErrors)],
      ]} />
      <div className="mt-3"><MoreDetails title="Schema, session ID and processing details">
      <SummaryGrid fields={[
        ["Schema", summaryValue(value.schema_version, "Not recorded")],
        ["Session", summaryValue(value.session_id, "Unknown")],
        ["Analysis jobs", countOf(list(value.analysis_jobs).length)],
        ["Report summary", hasMeaningfulRecord(reportSummary) ? "Present" : "Empty"],
        ["Errors", countOf(nonEmptyErrors)],
      ]} />
      </MoreDetails></div>
    </>
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

    const load = async () => {
      const settled = await Promise.allSettled(
        primaryCapabilities.map(async (capability) => [capability, await fetchCapability(capability, sessionId)] as const),
      );
      const entries = settle(primaryCapabilities, settled);
      if (!cancelled) {
        setResults(Object.fromEntries(allCapabilities.map((capability) => [capability, { ...initialResult }])));
      }
      apply(entries);
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
      const aiResult = await fetchCapability("ai-advisory", sessionId);
      apply([["ai-advisory", aiResult]]);
      if (!cancelled && sessionIsActive(detailEntry[1].data)) {
        pollTimer = window.setInterval(() => {
          void poll();
        }, 1_000);
      }
    };

    void load();
    return () => {
      cancelled = true;
      if (pollTimer !== undefined) window.clearInterval(pollTimer);
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

  return (
    <div className="space-y-5">
      <section aria-label="Session evidence">
        <div className="mb-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">Evidence &amp; activity</p>
          <p className="mt-1 text-xs text-text-muted">Chronology, observed access, and trusted classification for this exact session.</p>
        </div>
        <div className="ui-panel overflow-hidden p-4 sm:p-5">
          <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-12">
          <Panel eyebrow="Chronology" title="Bounded event timeline" icon={<ListTree className="h-4 w-4" aria-hidden="true" />} result={timelineResult} variant="embedded" className="xl:col-span-8">
            <TimelineList items={events} />
          </Panel>
          <Panel eyebrow="Observed access" title="Authentication activity" icon={<Fingerprint className="h-4 w-4" aria-hidden="true" />} result={authenticationResult} variant="embedded" className="border-t border-border pt-5 xl:col-span-4 xl:border-l xl:border-t-0 xl:pl-5 xl:pt-0">
            <AuthenticationSummary data={authentication} />
          </Panel>
          </div>
        </div>
      </section>

      <section aria-label="Classification evidence">
        <div className="mb-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">Trusted observations</p>
          <p className="mt-1 text-xs text-text-muted">Classification and ATT&amp;CK mappings remain separate from advisory analysis.</p>
        </div>
        <Panel eyebrow="Trusted observations" title="Classification and ATT&CK mappings" icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />} result={classificationResult}>
          <ClassificationList items={classificationEvents} trustedMappings={trustedTtps} />
        </Panel>
      </section>

      <section aria-label="Model ensemble evidence">
        <div className="mb-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">Shadow corroboration</p>
          <p className="mt-1 text-xs text-text-muted">The stored late-fusion evidence is read-only; Model1 remains primary and Model2 never authorizes response.</p>
        </div>
        <Panel eyebrow="Model evidence" title="Model1 + Model2 ensemble" icon={<Network className="h-4 w-4" aria-hidden="true" />} result={ensembleResult}>
          <Model2EnsembleSummary data={detail} />
        </Panel>
      </section>

      <section aria-label="Analyst assessment">
        <div className="mb-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">Analyst assessment</p>
          <p className="mt-1 text-xs text-text-muted">Evidence-bounded interpretation, manual corroboration, and review-only advisory context.</p>
        </div>
        <div className="ui-panel overflow-hidden p-4 sm:p-5">
          <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-2">
            <Panel eyebrow="Evidence-bounded analysis" title="Threat hypothesis" icon={<BrainCircuit className="h-4 w-4" aria-hidden="true" />} result={get("hypothesis")} variant="embedded">
              <HypothesisSummary data={hypothesis} />
            </Panel>
            <Panel eyebrow="Manual corroboration" title="Response guidance" icon={<ShieldCheck className="h-4 w-4" aria-hidden="true" />} result={get("recommendations")} variant="embedded" className="border-t border-border pt-5 xl:border-l xl:border-t-0 xl:pl-5 xl:pt-0">
              <GuidanceSummary data={get("recommendations").data} />
            </Panel>
          </div>

          <div className="mt-5 grid grid-cols-1 items-start gap-5 border-t border-border pt-5 xl:grid-cols-2">
            <Panel eyebrow="Stored AI advisory" title="AI advisory" icon={<Bot className="h-4 w-4" aria-hidden="true" />} result={aiAdvisory} variant="embedded">
              <AiAdvisorySummary data={aiAdvisory.data} guidanceData={get("recommendations").data} />
            </Panel>
            {aiAdvisory.state === "ready" || aiAdvisory.state === "limited" ? (
              <PolicyGapSummary data={aiAdvisory.data} />
            ) : (
              <div className="rounded-lg border border-border bg-surface-subtle p-4 text-sm text-text-muted">
                Policy-gap analysis is unavailable because no accepted AI advisory capability is deployed for this local runtime.
              </div>
            )}
          </div>
        </div>
      </section>

      <section aria-label="Threat intelligence context">
        <div className="mb-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">Threat intelligence context</p>
          <p className="mt-1 text-xs text-text-muted">Contextual provider state and exact source identity; neither establishes attribution.</p>
        </div>
        <div className="ui-panel overflow-hidden p-4 sm:p-5">
          <Panel eyebrow="Non-authoritative context" title="External TI context" icon={<Network className="h-4 w-4" aria-hidden="true" />} result={etiResult} variant="embedded">
            <ExternalTiSummary sessionData={sessionTi} observableData={observableTi.data} />
          </Panel>
          <Panel eyebrow="Exact source identity" title="Source-IP pivot" icon={<Fingerprint className="h-4 w-4" aria-hidden="true" />} result={sourcePivot} variant="embedded" className="mt-5 border-t border-border pt-5">
            <SourcePivotSummary data={sourcePivot.data} />
          </Panel>
        </div>
      </section>

      <section aria-label="Evidence ledger">
        <div className="mb-3">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary">Evidence ledger</p>
          <p className="mt-1 text-xs text-text-muted">Artifacts stay dense and inspectable while provenance and durable output remain compact.</p>
        </div>
        <div className="ui-panel overflow-hidden p-4 sm:p-5">
          <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-12">
          <Panel eyebrow="Artifacts" title="Files and observables" icon={<FileSearch className="h-4 w-4" aria-hidden="true" />} result={filesResult} variant="embedded" className="xl:col-span-8">
            <ObservableList items={analystObservables} />
          </Panel>
          <div className="space-y-5 border-t border-border pt-5 xl:col-span-4 xl:border-l xl:border-t-0 xl:pl-5 xl:pt-0">
            <Panel eyebrow="Traceability" title="Evidence and provenance" icon={<Fingerprint className="h-4 w-4" aria-hidden="true" />} result={provenanceResult} variant="embedded">
              <ProvenanceSummary value={provenance} />
            </Panel>
            <Panel eyebrow="Durable output" title="Reports" icon={<FileText className="h-4 w-4" aria-hidden="true" />} result={get("reports")} variant="embedded" className="border-t border-border pt-5">
              <RecordList items={reports} empty="No stored report is available." />
            </Panel>
          </div>
          </div>
        </div>
      </section>
    </div>
  );
}
