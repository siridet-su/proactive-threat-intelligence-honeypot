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
  authoritativeEventTimestamp,
  chronologicalRecords,
  sessionLifecycleStatus,
} from "@/lib/session-analysis-semantics";
import {
  analystAttackerUsername,
  analystCommandText,
  ensembleEvidenceState,
  selectedProviderFields,
} from "@/lib/session-intelligence";

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

const CLIENT_TIMEOUT_MS = 2_500;
const DETAIL_CLIENT_TIMEOUT_MS = 7_000;

async function fetchCapability(
  capability: string,
  sessionId: string,
  extra: Record<string, string> = {},
): Promise<CapabilityResult> {
  const query = new URLSearchParams({ session_id: sessionId, ...extra });
  const controller = new AbortController();
  const timeout = window.setTimeout(
    () => controller.abort(),
    capability === "detail" ? DETAIL_CLIENT_TIMEOUT_MS : CLIENT_TIMEOUT_MS,
  );
  try {
    const response = await fetch(`/api/session-analysis/${capability}?${query.toString()}`, {
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

function buildCommandRecords(detail: JsonRecord): JsonRecord[] {
  const events = chronologicalRecords(
    list(detail.events || detail.events_table_rows)
      .map(record)
      .filter((event) => event.command_event === true),
  );
  const storedCommands = list(detail.commands);
  const classifications = list(detail.classification_events).map(record);
  return events.map((event, index) => {
    const eventId = event.event_id || event.eventid;
    const timestamp = authoritativeEventTimestamp(event);
    const classification = classifications.find((item) => {
      const order = record(item.durable_evidence_order);
      return order.event_id === eventId || item.event_timestamp === timestamp;
    });
    const rawCommand = storedCommands[index];
    const text = commandText(event) || commandText(rawCommand) || commandText(classification);
    return {
      sequence: index + 1,
      event_id: eventId,
      eventid: event.eventid,
      timestamp,
      received_at: event.received_at,
      session_id: event.session_id || detail.session_id,
      sensor_id: event.sensor_id,
      command_event: true,
      ...(text ? { input: text, command_text_available: true } : {
        command_text_available: false,
        command_text_unavailable_reason: "unrecoverable_after_pre_persistence_redaction",
      }),
      classification_event_id: classification?.evidence_id,
      classification_technique: classification?.ttp || null,
    };
  });
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
          return terminalResult(
            "limited",
            "Exact-session command records are present, but their text was removed before persistence and cannot be recovered by the Dashboard.",
            { ...data, command_text_available: false },
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
        hasEvidence = hasItems(data, ["correlated_ttp_hypotheses", "hypothesis_sets"])
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
    : terminalResult("empty", "No stored evidence is available for this exact session.", data, result.status);
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
  "commands",
  "hypothesis",
  "recommendations",
  "ai-advisory",
  "related",
  "feedback",
  "reports",
] as const;

function derivedEntries(detailResult: CapabilityResult): Array<readonly [string, CapabilityResult]> {
  const detail = detailResult.data;
  const commandRecords = buildCommandRecords(detail);
  const base = {
    ok: detail.ok,
    session_id: detail.session_id,
    timestamp: detail.timestamp,
  };
  const projections: Record<string, JsonRecord> = {
    commands: {
      ...base,
      commands: commandRecords,
      command_text_available: commandRecords.some((item) => item.command_text_available === true),
    },
    hypothesis: {
      ...base,
      authority: "CONTEXTUAL_NON_AUTHORITATIVE",
      report_summary: detail.report_summary || {},
      report_recommendations: detail.report_recommendations || {},
      correlated_ttp_hypotheses: detail.correlated_ttp_hypotheses || [],
      hypothesis_sets: detail.hypothesis_sets || [],
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
  if (!orderedItems.length) {
    return <p className="rounded-lg border border-border bg-surface-subtle p-4 text-sm text-text-muted">No persisted timeline events are available.</p>;
  }
  return (
    <div className="space-y-3">
      <p className="text-xs text-text-muted">Transport, authentication, and lifecycle events. Command input is shown once in Command activity.</p>
      <ol className="space-y-2">
        {orderedItems.slice(0, 100).map((event, index) => {
        const eventName = summaryValue(event.eventid || event.event_id || event.event_type, "event");
        const timestamp = summaryValue(event.timestamp || event.received_at, "Timestamp unavailable");
        const session = summaryValue(event.session_id || event.session, "Exact session unavailable");
        return (
          <li key={`${index}-${eventName}-${timestamp}`} className="rounded-lg border border-border bg-surface-subtle px-3 py-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-xs font-semibold text-text">{eventName}</span>
              <span className="ui-badge text-[11px]">Observed event</span>
            </div>
            <div className="mt-2 grid gap-1 text-[11px] text-text-muted sm:grid-cols-2">
              <span>time: <span className="font-mono text-text">{timestamp}</span></span>
              <span>session: <span className="font-mono text-text">{session}</span></span>
              <span>processed: <span className="font-mono text-text">{label(event.processed, "unknown")}</span></span>
              <span>source: <span className="font-mono text-text">{summaryValue(event.sensor_id || event.sensor, "unknown")}</span></span>
            </div>
          </li>
        );
        })}
      </ol>
    </div>
  );
}

function ClassificationList({ items, trustedMappings }: { items: unknown[]; trustedMappings: unknown[] }) {
  if (!items.length) {
    return <p className="rounded-lg border border-border bg-surface-subtle p-4 text-sm text-text-muted">No classification evidence is available for this exact session.</p>;
  }
  const classificationRecords = items.map(record);
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
  const ensembleCounts = classificationRecords.reduce<Record<string, number>>((counts, item) => {
    const state = ensembleEvidenceState(item);
    counts[state] = (counts[state] || 0) + 1;
    return counts;
  }, {});
  return (
    <div className="space-y-3">
      <SummaryGrid fields={[
        ["Classification records", String(classificationRecords.length)],
        ["Classified command events", String(classifiedCommandKeys.size)],
        ["Trusted ATT&CK mappings", `${trustedMappings.length} records · ${uniqueAttackTechniques.size} techniques`],
      ]} />
      <p className="text-xs text-text-muted">Model1 signed decision margin is not a calibrated probability. Model2 remains research/shadow evidence; scores are not combined and neither model authorizes response.</p>
      <ol className="space-y-2">
        {classificationRecords.slice(0, 50).map((mapping, index) => {
          const authority = record(mapping.authority_decision);
          const advisory = record(mapping.s1_advisory);
          const shadow = record(mapping.shadow_model);
          const technique = mapping.ttp || mapping.technique_id || "NO_TECHNIQUE_ASSIGNED";
          const sourceCommand = commandText(mapping.source_command || mapping.command || mapping.original_command);
          const evidenceState = ensembleEvidenceState(mapping);
          return (
            <li key={`${index}-${String(mapping.evidence_id || technique)}`} className="rounded-lg border border-border bg-surface-subtle px-3 py-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-semibold text-text">{summaryValue(technique)}</span>
                  <span className="text-xs text-text-muted">{summaryValue(mapping.name, "Technique not assigned")}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  <span className="ui-badge text-[11px]">{evidenceState}</span>
                  <span className="ui-badge text-[11px]">{summaryValue(authority.decision || mapping.evidence_tier, "advisory")}</span>
                </div>
              </div>
              {sourceCommand && <p className="mt-2 rounded border border-border bg-surface px-2.5 py-2 font-mono text-xs text-text">{sourceCommand}</p>}
              <SummaryGrid fields={[
                ["Tactic", summaryValue(mapping.tactic, "Not recorded")],
                ["Evidence / authority", `${summaryValue(mapping.evidence_type || mapping.evidence_tier, "observed event")} · ${summaryValue(authority.decision || mapping.authority, "advisory")}`],
                ["Model1 advisory", advisory.decision_score === undefined ? "Not recorded" : `${summaryValue(advisory.predicted_technique, "unassigned")} · margin ${display(advisory.decision_score)}`],
                ["Model2 shadow", `${summaryValue(shadow.technique_id, "no usable output")} · ${summaryValue(shadow.status, "unavailable")}`],
              ]} />
              <ClassificationTraceability mapping={mapping} sourceCommand={sourceCommand} />
              <p className="mt-2 text-[11px] text-text-muted">source: {summaryValue(mapping.source || mapping.rule_id, "reviewed classifier")} · event <span className="font-mono text-text">{summaryValue(record(mapping.durable_evidence_order).event_id || mapping.evidence_id, "Unavailable")}</span> · {summaryValue(mapping.event_timestamp, "Timestamp unavailable")}</p>
            </li>
          );
        })}
      </ol>
      <div className="rounded-lg border border-primary-border bg-primary-subtle p-3">
        <p className="text-xs font-semibold uppercase tracking-[0.1em] text-primary">Trusted ATT&amp;CK mappings</p>
        {trustedMappings.length ? (
          <ol className="mt-2 space-y-2">
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
                  <p className="mt-1 text-text-muted">evidence refs: {countOf(mapping.evidence_ref_count || list(mapping.evidence_refs).length)} · evidence semantics: {summaryValue(mapping.confidence_semantics, "evidence strength; not probability")}</p>
                  <TrustedTraceability mapping={mapping} />
                </li>
              );
            })}
          </ol>
        ) : <p className="mt-2 text-xs text-text-muted">No trusted mapping was established.</p>}
      </div>
      <div className="rounded-lg border border-border bg-surface-subtle p-3">
        <p className="text-xs font-semibold uppercase tracking-[0.1em] text-text-subtle">Model evidence states</p>
        <div className="mt-2 flex flex-wrap gap-2">
          {Object.entries(ensembleCounts).map(([state, count]) => (
            <span key={state} className="ui-badge text-[11px]">{state} · {count}</span>
          ))}
        </div>
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

function tiLookupState(value: JsonRecord): string {
  const freshness = String(value.freshness_state || "").trim().toUpperCase();
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

function ProviderContextRows({
  evidence,
  cache,
  providerStatus,
  observable,
}: {
  evidence: JsonRecord[];
  cache: JsonRecord[];
  providerStatus: JsonRecord;
  observable: JsonRecord;
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
        return (
          <div key={`cache-${index}-${summaryValue(item.provider, "provider")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono font-semibold text-text">{summaryValue(item.provider, "provider unavailable")} cache</span>
              <span className="ui-badge text-[11px]">{tiLookupState(item)}</span>
            </div>
            <p className="mt-1 text-text-muted">lookup: {summaryValue(item.lookup_at, "Not recorded")} · expires: {summaryValue(item.expires_at, "Not recorded")}</p>
            <TraceabilityDetails
              title="Cached provider and observable details"
              fields={[
                ["Provider", summaryValue(item.provider, "Not recorded")],
                ["Observable", summaryValue(item.observable_value || observable.value, "Not recorded")],
                ["Observable type", summaryValue(item.observable_type || observable.type, "source_ip")],
                ["Observable role", summaryValue(item.observable_role || "source_ip", "Not recorded")],
                ["Lookup state", tiLookupState(item)],
                ["Freshness", freshnessLabel(item.freshness_state)],
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
    <>
      <SummaryGrid fields={[
        ["Attempts", countOf(data.attempt_count)],
        ["Successful", countOf(data.success_count)],
        ["Failed", countOf(data.failure_count)],
        ["Attacker usernames", visibleUsernames.length ? visibleUsernames.join(", ") : summaryValue(data.username_visibility, "Not persisted")],
        ["First attempt", summaryValue(data.first_attempt_at, "Not recorded")],
        ["Last attempt", summaryValue(data.last_attempt_at, "Not recorded")],
      ]} />
      {attempts.length > 0 && (
        <ol className="mt-3 space-y-2">
          {attempts.slice(0, 20).map((attempt, index) => (
            <li key={`${index}-${summaryValue(attempt.timestamp, "attempt")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-text">{summaryValue(attempt.outcome, "attempt")}</span>
                <span className="font-mono text-text-muted">{summaryValue(attempt.timestamp, "Timestamp unavailable")}</span>
              </div>
              <p className="mt-1 text-text-muted">Username: <span className="font-mono text-text">{analystAttackerUsername(attempt) || summaryValue(attempt.username_visibility, "Not persisted")}</span>{hasMeaningfulValue(attempt.method) ? ` · method: ${summaryValue(attempt.method)}` : ""}</p>
            </li>
          ))}
        </ol>
      )}
      <p className="mt-3 text-xs text-text-subtle">Attacker-entered usernames are shown only when safely retained. Password values are never projected or rendered.</p>
    </>
  );
}

function SourcePivotSummary({ data }: { data: JsonRecord }) {
  const counts = record(data.counts);
  const sessions = list(data.sessions).map(record);
  return (
    <>
      <SummaryGrid fields={[
        ["Authority", summaryValue(data.authority, "Contextual only")],
        ["Observable", summaryValue(record(data.observable).value, "Source IP unavailable")],
        ["Observable type", summaryValue(record(data.observable).type, "ip")],
        ["Observable role", "source_ip"],
        ["Sessions found", countOf(counts.sessions_found)],
        ["Sessions returned", countOf(counts.sessions_returned)],
        ["Distinct sessions", countOf(counts.sessions_returned)],
        ["Sightings examined", countOf(counts.sightings_examined)],
        ["Provider calls", data.provider_calls === false ? "0" : "Not reported"],
      ]} />
      {sessions.length > 0 && (
        <ol className="mt-3 space-y-2">
          {sessions.slice(0, 20).map((session, index) => (
            <li key={`${index}-${summaryValue(session.session_id, "session")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono font-semibold text-text">{summaryValue(session.session_id, "Session unavailable")}</span>
                <span className="ui-badge text-[11px]">{countOf(session.sighting_count)} sightings</span>
              </div>
              <p className="mt-1 text-text-muted">{summaryValue(session.first_seen, "First seen unavailable")} → {summaryValue(session.last_seen, "Last seen unavailable")}</p>
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
      )}
      <p className="mt-3 text-xs text-text-subtle">Contextual source repetition only; it does not establish attribution, intent, or classification.</p>
    </>
  );
}

function ExternalTiSummary({ sessionData, observableData }: { sessionData: JsonRecord; observableData: JsonRecord }) {
  const sessionCounts = record(sessionData.counts);
  const observableCounts = record(observableData.counts);
  const summary = record(sessionData.external_ti_summary);
  const entities = list(sessionData.shared_entities).map(record);
  const evidence = [...list(sessionData.evidence), ...list(observableData.evidence)].map(record);
  const cache = [...list(sessionData.source_ip_cache), ...list(observableData.source_ip_cache)].map(record);
  const providerStatus = { ...record(sessionData.provider_status), ...record(observableData.provider_status) };
  const freshness = record(sessionData.freshness);
  const observable = record(observableData.observable);
  return (
    <>
      <SummaryGrid fields={[
        ["Status", summaryValue(sessionData.status || freshness.state, "TI_PENDING")],
        ["Observable", summaryValue(observable.value, "No eligible observable")],
        ["Freshness", summaryValue(freshness.state, "TI_PENDING")],
        ["Eligible observables", countOf(sessionCounts.eligible_observables)],
        ["Stored provider evidence", countOf(Number(sessionCounts.evidence_returned || 0) + Number(observableCounts.evidence_returned || 0))],
        ["Sightings examined", countOf(observableCounts.sightings_examined || sessionCounts.sightings_examined)],
        ["Provider calls", sessionData.provider_calls === false || observableData.provider_calls === false ? "0 (stored-only read)" : "Not reported"],
      ]} />
      {entities.length > 0 && <ObservableList items={entities} empty="No shared entities are recorded." />}
      <ProviderContextRows evidence={evidence} cache={cache} providerStatus={providerStatus} observable={observable} />
      {entities.length === 0 && evidence.length === 0 && (
        <p className="mt-3 rounded-lg border border-border bg-surface-subtle p-3 text-xs text-text-muted">No provider finding is linked to this exact session. The read model is {summaryValue(summary.uncertainty, "context-only")}; unavailable evidence is not inferred.</p>
      )}
      <p className="mt-3 text-xs font-medium text-text-subtle">NON_AUTHORITATIVE_CONTEXT_ONLY · provider claims remain attributed and never authorize classification or response.</p>
    </>
  );
}

function HypothesisSummary({ data }: { data: JsonRecord }) {
  const counts = record(data.counts);
  const reportSummary = record(data.report_summary);
  const hypotheses = list(data.correlated_ttp_hypotheses);
  const hypothesisSets = list(data.hypothesis_sets).map(record);
  const reports = list(data.reports);
  return (
    <>
      <SummaryGrid fields={[
        ["Authority", summaryValue(data.authority, "Contextual only")],
        ["Correlated hypotheses", countOf(hypotheses.length || counts.correlations)],
        ["Bounded hypothesis sets", countOf(hypothesisSets.length)],
        ["Reports", countOf(reports.length)],
        ["Evidence strength", summaryValue(reportSummary.evidence_strength || reportSummary.analytical_evidence_strength, "Not recorded")],
        ["Analysis mode", summaryValue(reportSummary.analysis_mode, "Not recorded")],
        ["Campaign", summaryValue(reportSummary.campaign_name, "Not recorded")],
      ]} />
      {hasMeaningfulValue(reportSummary.summary) && <p className="mt-3 rounded-lg border border-border bg-surface-subtle p-3 text-sm text-text">{summaryValue(reportSummary.summary)}</p>}
      {hasMeaningfulValue(reportSummary.evidence_strength_reason) && <p className="mt-2 text-xs text-text-muted">Evidence note: {summaryValue(reportSummary.evidence_strength_reason)}</p>}
      {hypothesisSets.length > 0 && (
        <ol className="mt-3 space-y-2">
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
      )}
      {hypotheses.length === 0 && hypothesisSets.length === 0 && <p className="mt-3 rounded-lg border border-border bg-surface-subtle p-3 text-xs font-semibold text-text-muted">NO_CORRELATED_HYPOTHESIS</p>}
      <p className="mt-3 text-xs text-text-subtle">Evidence-bounded context only; no attacker identity, intent, or authoritative TTP promotion is inferred.</p>
    </>
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
  return (
    <>
      <SummaryGrid fields={[
        ["Status", summaryValue(guidance.status, "Unavailable")],
        ["Authority", summaryValue(guidance.authority, "Policy-bounded")],
        ["Guidance state", summaryValue(guidance.guidance_state, "Not recorded")],
        ["Findings", countOf(guidance.finding_count || guidance.advisory_action_count)],
        ["Validation", summaryValue(validation.status, "Not recorded")],
        ["Manual approval", guidance.requires_manual_approval === false ? "No" : "Required"],
      ]} />
      {actions.length > 0 ? (
        <ol className="mt-3 space-y-2">
          {actions.slice(0, 20).map((action, index) => (
            <li key={`${index}-${summaryValue(action.action_id, "action")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-xs">
              <p className="font-semibold text-text">{summaryValue(action.description || action.action_id, "Stored analyst action")}</p>
              {hasMeaningfulValue(action.rationale) && <p className="mt-1 text-text-muted">Rationale: {summaryValue(action.rationale)}</p>}
              {list(action.preconditions).length > 0 && <p className="mt-1 text-text-muted">Preconditions: {list(action.preconditions).map((value) => display(value)).join(" ")}</p>}
              {list(action.verification_steps).length > 0 && <p className="mt-1 text-text-muted">Verification: {list(action.verification_steps).map((value) => display(value)).join(" ")}</p>}
              <p className="mt-1 text-text-muted">Manual approval: {action.requires_manual_approval === false ? "not required" : "required"} · automatic execution: {action.safe_to_auto_execute === true ? "allowed" : "disabled"}</p>
              <GuidanceTraceability action={action} guidance={guidance} />
            </li>
          ))}
        </ol>
      ) : <p className="mt-3 text-xs text-text-muted">No stored recommendation content is available.</p>}
      {hasMeaningfulValue(validation.error) && <p className="mt-3 text-xs text-warning">{summaryValue(validation.error)}</p>}
      <p className="mt-3 text-xs text-text-subtle">Manual-only. safe_to_auto_execute={String(safety.automatic_execution === true ? true : false)}.</p>
    </>
  );
}

function AiAdvisorySummary({ data }: { data: JsonRecord }) {
  const advisory = record(data.advisory);
  const validation = record(advisory.validation);
  const provenance = record(advisory.provenance);
  const safety = record(advisory.safety);
  const rendered = record(advisory.rendered_advisory);
  const paragraphs = list(rendered.paragraphs).map(record);
  return (
    <>
      <SummaryGrid fields={[
        ["Status", summaryValue(data.status, "Unavailable")],
        ["Authority", summaryValue(advisory.authority, "Non-authoritative")],
        ["Validation", summaryValue(validation.status, "Not recorded")],
        ["Provider", summaryValue(provenance.provider_id, "Not recorded")],
        ["Model", summaryValue(provenance.model_id, "Not recorded")],
        ["Manual approval", safety.requires_manual_approval === false ? "No" : "Required"],
      ]} />
      {paragraphs.length > 0 ? (
        <ol className="mt-3 space-y-2">
          {paragraphs.slice(0, 8).map((paragraph, index) => (
            <li key={`${index}-${summaryValue(paragraph.template_id, "advisory")}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-sm text-text">
              {summaryValue(paragraph.text, "No policy-authored advisory text stored.")}
            </li>
          ))}
        </ol>
      ) : <p className="mt-3 rounded-lg border border-border bg-surface-subtle p-3 text-xs text-text-muted">No policy-authored advisory text is stored.</p>}
      <p className="mt-3 text-xs font-semibold text-text">AI ADVISORY · ADVISORY_ONLY · NON_AUTHORITATIVE</p>
      <p className="mt-1 text-xs text-text-subtle">This explanation can select existing evidence for review. It cannot create canonical findings, overwrite trusted mappings, select authoritative response actions, or execute a response.</p>
    </>
  );
}

function PolicyGapSummary({ data }: { data: JsonRecord }) {
  const gap = record(data.policy_gap);
  const proposals = list(gap.proposals).map(record);
  return (
    <article className="rounded-lg border border-warning-border bg-warning-subtle p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.1em] text-warning">AI proposed analysis · Policy gap proposal</p>
        <span className="ui-badge text-[11px]">{summaryValue(gap.status, "IMPLEMENTATION_GAP")}</span>
      </div>
      <SummaryGrid fields={[
        ["Mode", summaryValue(gap.mode, "Read-only")],
        ["Proposals", countOf(proposals.length)],
        ["Authority", summaryValue(gap.authority, "PROPOSED_UNVALIDATED")],
        ["Review", gap.requires_review === false ? "Not required" : "REQUIRES_REVIEW"],
        ["Policy mutation", gap.automatic_policy_mutation === true ? "Enabled" : "Disabled"],
      ]} />
      {proposals.length > 0 ? (
        <ol className="mt-3 space-y-2">
          {proposals.slice(0, 8).map((proposal, index) => {
            const predicates = record(proposal.predicates);
            const evidence = list(proposal.supporting_evidence_references);
            const limitations = list(proposal.limitations);
            const falsifiers = list(proposal.falsifiers);
            const tests = list(proposal.proposed_validation_tests);
            return (
              <li key={`${index}-${summaryValue(proposal.proposal_id, "proposal")}`} className="rounded-lg border border-warning-border bg-surface p-3 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="font-semibold text-text">{summaryValue(proposal.candidate_type, "Structured candidate")}</p>
                  <span className="ui-badge text-[11px]">PROPOSED_UNVALIDATED</span>
                </div>
                <p className="mt-1 text-text-muted">Scope: {summaryValue(proposal.scope, "current_session_only")} · REQUIRES_REVIEW</p>
                <p className="mt-1 text-text-muted">Supporting evidence: {evidence.length > 0 ? evidence.map((value) => display(value)).join(", ") : "Not supplied"}</p>
                <p className="mt-1 text-text-muted">Conditions: {Object.values(predicates).flatMap((value) => list(value)).map((value) => display(value)).join(", ") || "Not supplied"}</p>
                <p className="mt-1 text-text-muted">Limitations / missing evidence: {limitations.length > 0 ? limitations.map((value) => display(value)).join(", ") : "None identified"}</p>
                <p className="mt-1 text-text-muted">Falsifiers: {falsifiers.length > 0 ? falsifiers.map((value) => display(value)).join(", ") : "Not supplied"}</p>
                <p className="mt-1 text-text-muted">Proposed validation tests: {tests.length > 0 ? tests.map((value) => display(value)).join(", ") : "Not supplied"}</p>
              </li>
            );
          })}
        </ol>
      ) : <p className="mt-3 text-xs text-text-muted">No policy-gap candidate was proposed for this session.</p>}
      <p className="mt-3 text-xs text-text-subtle">Review-only candidate namespace. Policy writes, trusted promotion, response selection, and automatic execution are disabled.</p>
    </article>
  );
}

function ObservedTacticPath({ items, ended }: { items: unknown[]; ended: boolean }) {
  const phases = items.map(record).filter((item) => hasMeaningfulValue(item.tactic));
  return (
    <div className="rounded-lg border border-border bg-surface-subtle p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-primary">Observed tactic path</p>
          <p className="mt-1 text-xs text-text-muted">Trusted canonical observations only; this is actual session history, not a forecast.</p>
        </div>
        <span className="ui-badge text-[11px]">{ended ? "SESSION ENDED" : "OBSERVED"}</span>
      </div>
      {phases.length > 0 ? (
        <ol className="mt-3 flex flex-wrap items-center gap-2 text-sm">
          {phases.map((phase, index) => (
            <li key={`${index}-${summaryValue(phase.tactic, "phase")}`} className="flex items-center gap-2">
              {index > 0 && <span className="text-text-subtle" aria-hidden="true">→</span>}
              <span className="rounded-md border border-primary-border bg-primary-subtle px-2.5 py-1 font-medium text-text">{summaryValue(phase.tactic)}</span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="mt-3 text-xs font-medium text-text-muted">WAITING_FOR_EVIDENCE</p>
      )}
    </div>
  );
}

function ProvenanceSummary({ value }: { value: JsonRecord }) {
  const reportSummary = record(value.report_summary);
  const errors = record(value.errors);
  const nonEmptyErrors = Object.values(errors).filter(hasMeaningfulValue).length;
  return (
    <>
      <SummaryGrid fields={[
        ["Schema", summaryValue(value.schema_version, "Not recorded")],
        ["Session", summaryValue(value.session_id, "Unknown")],
        ["Analysis jobs", countOf(list(value.analysis_jobs).length)],
        ["Report summary", hasMeaningfulRecord(reportSummary) ? "Present" : "Empty"],
        ["Errors", countOf(nonEmptyErrors)],
      ]} />
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
  onLiveInteraction?: (commands: unknown[], active: boolean) => void;
  onNextDistinct?: (data: JsonRecord, state: LoadState, reason: string) => void;
}) {
  const [results, setResults] = useState<Record<string, CapabilityResult>>({});

  useEffect(() => {
    let cancelled = false;
    let pollTimer: number | undefined;
    let pollInFlight = false;
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
    const primaryCapabilities = ["detail", "next-distinct", "session-ti"] as const;
    const pollCapabilities = ["detail", "next-distinct"] as const;

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
        onDetail?.(detailEntry[1].data);
        onLiveInteraction?.(buildCommandRecords(detailEntry[1].data), sessionIsActive(detailEntry[1].data));
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
  const classificationResult = detailPanelResult(detailResult, classificationEvents.length > 0, "No classification evidence was established.");
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
  const etiResult = detailPanelResult(
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
          <ObservedTacticPath items={list(detail.observed_tactic_path)} ended={!sessionIsActive(detail)} />
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
              <AiAdvisorySummary data={aiAdvisory.data} />
            </Panel>
            <PolicyGapSummary data={aiAdvisory.data} />
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
