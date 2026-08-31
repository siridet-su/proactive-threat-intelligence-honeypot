"use client";

import Link from "next/link";
import { use, useEffect, useMemo, useState } from "react";
import { ArrowLeft, Brain, CheckCircle2, CircleAlert, Database, GitBranch, ShieldCheck } from "lucide-react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiErrorMessage, apiQuery, fetchDashboardJson } from "@/lib/api";
import { formatTimestamp, listRows, safeLabel, sessionStatus, text } from "@/lib/dashboardData";
import type { AiAdvisoryResponse, EventView, JsonRecord, PredictionResponse, SessionDetail } from "@/lib/dashboardTypes";

interface DetailState {
  detail: SessionDetail | null;
  prediction: PredictionResponse | null;
  advisory: AiAdvisoryResponse | null;
  errors: string[];
}

const EMPTY_STATE: DetailState = { detail: null, prediction: null, advisory: null, errors: [] };
const EMPTY_EVENTS: EventView[] = [];

export default function SessionIntelligencePage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const sessionId = decodeURIComponent(resolvedParams.id);
  const [state, setState] = useState<DetailState>(EMPTY_STATE);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      const results = await Promise.allSettled([
        fetchDashboardJson<SessionDetail>(apiQuery("/api/session", { session_id: sessionId }), controller.signal),
        fetchDashboardJson<PredictionResponse>(apiQuery("/api/predictions/current", { session_id: sessionId }), controller.signal),
        fetchDashboardJson<AiAdvisoryResponse>(apiQuery("/api/ai-advisory", { session_id: sessionId }), controller.signal),
      ]);
      if (controller.signal.aborted) return;
      const errors = results
        .filter((result): result is PromiseRejectedResult => result.status === "rejected")
        .map((result) => apiErrorMessage(result.reason));
      setState({
        detail: results[0].status === "fulfilled" ? results[0].value : null,
        prediction: results[1].status === "fulfilled" ? results[1].value : null,
        advisory: results[2].status === "fulfilled" ? results[2].value : null,
        errors: [...new Set(errors)],
      });
      setLoading(false);
    }
    void load();
    return () => controller.abort();
  }, [sessionId]);

  const detail = state.detail;
  const overview = detail?.overview || {};
  const events = listRows<EventView>(detail?.events) || EMPTY_EVENTS;
  const status = sessionStatus(overview);
  const timeline = useMemo(() => buildTimeline(events), [events]);
  const trusted = Array.isArray(detail?.observed_trusted_ttps) ? detail.observed_trusted_ttps : [];
  const correlations = Array.isArray(detail?.correlated_ttp_hypotheses)
    ? detail.correlated_ttp_hypotheses
    : Array.isArray(detail?.session_ttp_correlations) ? detail.session_ttp_correlations : [];
  const modelPrediction = state.prediction?.current_prediction || null;
  const ranking = predictionRanking(modelPrediction);
  const reportSummary = detail?.report_summary || {};

  return (
    <div className="flex flex-col gap-6 pb-10">
      <div className="flex flex-wrap items-center gap-4">
        <Link href="/threat-intel" className="p-2 bg-slate-900/50 hover:bg-slate-800 border border-slate-800 rounded-full transition-colors text-slate-400 hover:text-white" title="Back to Threat Intelligence">
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <h2 className="text-2xl font-bold text-white">Session Intelligence Detail</h2>
        <span className="bg-slate-800 text-purple-300 font-mono px-3 py-1 rounded text-xs border border-purple-900/30 truncate max-w-full">
          SESSION: {sessionId || "unknown"}
        </span>
      </div>

      <p className="text-sm text-slate-400">Bounded, redacted evidence from the existing monitor API. No actor attribution is inferred from this record.</p>

      {state.errors.length > 0 && (
        <div className="bg-amber-950/20 border border-amber-900/50 rounded-xl px-5 py-4 text-xs text-amber-200">
          <p className="font-semibold tracking-wide">DETAIL DATA PARTIALLY UNAVAILABLE</p>
          <p className="mt-1 text-amber-300/70">{state.errors.join(" · ")}</p>
        </div>
      )}

      {!loading && !detail && (
        <div className="bg-[#111116] border border-red-900/50 p-8 rounded-xl text-center">
          <CircleAlert className="w-6 h-6 text-red-400 mx-auto mb-3" />
          <p className="text-sm text-red-200">This session could not be loaded from the production API.</p>
          <Link href="/threat-intel" className="inline-block mt-4 text-xs text-purple-300 hover:text-white">Return to Threat Intelligence</Link>
        </div>
      )}

      {detail && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <DetailMetric label="SOURCE" value={text(overview.src_ip, "unavailable")} detail={text(overview.src_ip_scope, "scope unavailable")} icon={<Database className="w-4 h-4 text-purple-400" />} />
            <DetailMetric label="ANALYSIS STATUS" value={status} detail={text(overview.job_status || overview.analysis_status, "not recorded")} icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />} tone={status === "failed" ? "red" : "normal"} />
            <DetailMetric label="COMMAND EVENTS" value={String(overview.command_count ?? "—")} detail="Text remains redacted by API boundary" icon={<GitBranch className="w-4 h-4 text-amber-400" />} tone="amber" />
            <DetailMetric label="SESSION START" value={formatTimestamp(overview.start_time)} detail={`Updated ${formatTimestamp(overview.updated_at)}`} icon={<CheckCircle2 className="w-4 h-4 text-slate-300" />} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-[#111116] border border-slate-800/50 p-6 rounded-xl h-[400px]">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h3 className="text-base font-semibold text-white">Event Sequence</h3>
                  <p className="text-[10px] text-slate-500 mt-1">Bounded event count over the selected session · not a model confidence trend</p>
                </div>
                <span className="text-[10px] font-mono text-slate-500">{events.length} shown</span>
              </div>
              {timeline.length > 0 ? (
                <ResponsiveContainer width="100%" height="82%">
                  <LineChart data={timeline}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                    <YAxis stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
                    <Tooltip contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #334155", color: "#e2e8f0" }} />
                    <Line type="monotone" dataKey="events" name="events shown" stroke="#a855f7" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              ) : <EmptyState text="No bounded event rows were returned for this session." />}
            </div>

            <div className="bg-[#111116] border border-slate-800/50 p-6 rounded-xl">
              <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-4">Canonical report record</p>
              <h4 className="text-slate-400 text-sm mb-2">Report status</h4>
              <div className="text-purple-300 text-xl font-bold mb-4">{listRows(detail.reports).length ? "AVAILABLE" : "NOT RECORDED"}</div>
              <div className="space-y-3 border-t border-slate-800 pt-5 text-xs">
                <KeyValue label="report id" value={text(overview.report_id, "not recorded")} />
                <KeyValue label="summary fields" value={Object.keys(reportSummary).length ? String(Object.keys(reportSummary).length) : "not recorded"} />
                <KeyValue label="api timestamp" value={formatTimestamp(detail.timestamp)} />
              </div>
              <p className="text-[10px] text-slate-600 mt-6 leading-relaxed">Report content is displayed only through the API’s bounded public projection.</p>
            </div>
          </div>

          <EvidenceLanes detail={detail} trusted={trusted} ranking={ranking} correlations={correlations} advisory={state.advisory} />

          <div className="bg-[#0f0f13] border border-slate-800/50 rounded-xl p-6 font-mono text-xs">
            <div className="flex gap-2 mb-4 items-center">
              <div className="w-2 h-2 rounded-full bg-red-500" />
              <div className="w-2 h-2 rounded-full bg-yellow-500" />
              <div className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-slate-500 ml-2">BOUNDED EVENT METADATA</span>
            </div>
            {events.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-[11px]">
                  <thead className="text-slate-500 uppercase border-b border-slate-800"><tr><th className="py-3 pr-4">Timestamp</th><th className="py-3 pr-4">Event</th><th className="py-3 pr-4">Sensor</th><th className="py-3 pr-4">Source</th><th className="py-3">Command event</th></tr></thead>
                  <tbody>{events.slice(0, 100).map((event, index) => <EventRow key={event.event_id || `${event.timestamp}-${index}`} event={event} />)}</tbody>
                </table>
              </div>
            ) : <EmptyState text="No event metadata available." />}
          </div>
        </>
      )}
    </div>
  );
}

function EvidenceLanes({
  detail,
  trusted,
  ranking,
  correlations,
  advisory,
}: {
  detail: SessionDetail;
  trusted: unknown[];
  ranking: JsonRecord[];
  correlations: JsonRecord[];
  advisory: AiAdvisoryResponse | null;
}) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <EvidencePanel
        title="Trusted ATT&CK observations"
        subtitle="Reviewed/traceable evidence; not actor attribution or response authority."
        icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
        tone="emerald"
      >
        {trusted.length ? trusted.slice(0, 50).map((item, index) => <EvidenceRow key={`trusted-${index}`} item={item} />) : <EmptyState text="No trusted observation records returned." />}
      </EvidencePanel>

      <EvidencePanel
        title="Model advisory predictions"
        subtitle="Candidate ranking and score fields remain model output; scores are not calibrated probabilities."
        icon={<Brain className="w-4 h-4 text-amber-400" />}
        tone="amber"
      >
        {ranking.length ? ranking.slice(0, 8).map((item, index) => <PredictionRow key={`prediction-${index}`} item={item} />) : <EmptyState text="No current prediction snapshot returned." />}
        {detail.response_guidance && <p className="text-[10px] text-slate-600 mt-3">Response guidance is kept as a separate stored-policy record.</p>}
      </EvidencePanel>

      <EvidencePanel
        title="Correlation hypotheses"
        subtitle="Project-local heuristic context; strength is not probability and cannot promote evidence."
        icon={<GitBranch className="w-4 h-4 text-purple-400" />}
        tone="purple"
      >
        {correlations.length ? correlations.slice(0, 20).map((item, index) => <CorrelationRow key={`correlation-${index}`} item={item} />) : <EmptyState text="No correlation hypothesis records returned." />}
        <div className="border-t border-slate-800/60 mt-4 pt-4 text-[10px] text-slate-600">{text(detail.session_ttp_correlation_summary?.confidence_semantics, "correlation semantics unavailable")}</div>
      </EvidencePanel>

      <div className="lg:col-span-3 bg-[#111116] border border-slate-800/50 p-5 rounded-xl">
        <div className="flex items-start gap-3">
          <CircleAlert className="w-4 h-4 text-slate-400 mt-0.5 shrink-0" />
          <div>
            <h4 className="text-[11px] font-bold text-white uppercase tracking-wider">Separate advisory record</h4>
            <p className="text-[11px] text-slate-400 mt-2">AI advisory status: <span className="text-slate-200">{text(advisory?.status, "not requested or unavailable")}</span>. Only validated rendered advisory content is eligible for presentation; shadow candidates are not rendered as actions.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function EvidencePanel({ title, subtitle, icon, tone, children }: { title: string; subtitle: string; icon: React.ReactNode; tone: "emerald" | "amber" | "purple"; children: React.ReactNode }) {
  const border = tone === "emerald" ? "border-emerald-900/40" : tone === "amber" ? "border-amber-900/40" : "border-purple-900/40";
  return (
    <div className={`bg-[#111116] border ${border} p-5 rounded-xl min-h-[220px]`}>
      <div className="flex items-start gap-3 mb-4"><span className="mt-0.5">{icon}</span><div><h3 className="text-sm font-semibold text-white">{title}</h3><p className="text-[10px] text-slate-500 mt-1 leading-relaxed">{subtitle}</p></div></div>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

function EvidenceRow({ item }: { item: unknown }) {
  const record = asRecord(item);
  return <div className="bg-[#18181b] border border-slate-800/60 rounded px-3 py-2"><div className="text-xs text-emerald-200">{safeLabel(item)}</div><div className="text-[10px] text-slate-500 mt-1">{text(record.tactic || record.source || record.evidence_tier, "trace metadata unavailable")}</div></div>;
}

function PredictionRow({ item }: { item: JsonRecord }) {
  const score = item.score ?? item.weighted_score;
  return <div className="bg-[#18181b] border border-slate-800/60 rounded px-3 py-2"><div className="flex justify-between gap-3 text-xs text-amber-200"><span>{safeLabel(item)}</span>{score !== undefined && <span className="font-mono text-amber-300/80">score {String(score)}</span>}</div><div className="text-[10px] text-slate-500 mt-1">{text(item.source_types || item.sources, "model source metadata unavailable")}</div></div>;
}

function CorrelationRow({ item }: { item: JsonRecord }) {
  const strength = item.strength ?? item.confidence;
  return <div className="bg-[#18181b] border border-slate-800/60 rounded px-3 py-2"><div className="flex justify-between gap-3 text-xs text-purple-200"><span>{safeLabel(item)}</span>{strength !== undefined && <span className="font-mono text-purple-300/80">strength {String(strength)}</span>}</div><div className="text-[10px] text-slate-500 mt-1">{text(item.confidence_semantics, "developer-defined heuristic")}</div></div>;
}

function EventRow({ event }: { event: EventView }) {
  return <tr className="border-b border-slate-800/60"><td className="py-3 pr-4 text-slate-400">{formatTimestamp(event.timestamp || event.received_at)}</td><td className="py-3 pr-4 text-purple-300">{text(event.eventid || event.event_id, "unknown")}</td><td className="py-3 pr-4 text-slate-400">{text(event.sensor_id || event.sensor, "unknown")}</td><td className="py-3 pr-4 text-slate-400">{text(event.src_ip, "unavailable")}</td><td className="py-3 text-slate-500">{event.command_event ? "yes · text redacted" : "no"}</td></tr>;
}

function DetailMetric({ label, value, detail, icon, tone = "normal" }: { label: string; value: string; detail: string; icon: React.ReactNode; tone?: "normal" | "amber" | "red" }) {
  const valueColor = tone === "red" ? "text-[#fca5a5]" : tone === "amber" ? "text-amber-300" : "text-white";
  return <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl min-h-[132px]"><div className="flex items-center justify-between"><span className="text-[10px] text-slate-500 tracking-wider">{label}</span>{icon}</div><div className={`text-lg font-bold mt-3 ${valueColor} truncate`}>{value}</div><div className="text-[10px] text-slate-500 mt-2 truncate">{detail}</div></div>;
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return <div className="flex justify-between gap-4"><span className="text-slate-500">{label}</span><span className="text-slate-300 text-right truncate">{value}</span></div>;
}

function EmptyState({ text: message }: { text: string }) {
  return <div className="text-[11px] text-slate-500 text-center py-6">{message}</div>;
}

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
}

function predictionRanking(prediction: JsonRecord | null): JsonRecord[] {
  if (!prediction) return [];
  const ranking = prediction.final_ranking || prediction.prediction;
  return Array.isArray(ranking) ? ranking.filter((item): item is JsonRecord => Boolean(item && typeof item === "object" && !Array.isArray(item))) : [];
}

function buildTimeline(events: EventView[]) {
  return events.slice(0, 50).reverse().map((event, index) => ({
    time: shortTime(event.timestamp || event.received_at, index),
    events: index + 1,
  }));
}

function shortTime(value: unknown, fallback: number): string {
  const parsed = new Date(text(value, "")).getTime();
  if (!Number.isFinite(parsed)) return `#${fallback + 1}`;
  return new Date(parsed).toISOString().slice(11, 19);
}
