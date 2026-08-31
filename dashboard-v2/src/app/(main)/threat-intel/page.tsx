"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Brain, Clock3, Database, MapPin, ShieldAlert } from "lucide-react";
import TargetLandscapeChart, { type LandscapeDatum } from "@/components/threat-intel/TargetLandscapeChart";
import { apiErrorMessage, fetchDashboardJson } from "@/lib/api";
import {
  ageLabel,
  asStringList,
  buildStatusData,
  buildTacticData,
  formatTimestamp,
  isFresh,
  listRows,
  sessionStatus,
  statusTextColor,
  text,
} from "@/lib/dashboardData";
import type { AlertRow, SessionOverview, SessionsResponse, TableResponse } from "@/lib/dashboardTypes";

interface ThreatIntelState {
  sessions: SessionsResponse | null;
  alerts: TableResponse<AlertRow> | null;
  predictions: TableResponse | null;
  errors: string[];
}

const EMPTY_STATE: ThreatIntelState = { sessions: null, alerts: null, predictions: null, errors: [] };
const EMPTY_SESSIONS: SessionOverview[] = [];

export default function ThreatIntelPage() {
  const [state, setState] = useState<ThreatIntelState>(EMPTY_STATE);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      const results = await Promise.allSettled([
        fetchDashboardJson<SessionsResponse>("/api/sessions?limit=100&offset=0", controller.signal),
        fetchDashboardJson<TableResponse<AlertRow>>("/api/alerts?limit=100", controller.signal),
        fetchDashboardJson<TableResponse>("/api/prediction-snapshots?limit=100", controller.signal),
      ]);
      if (controller.signal.aborted) return;
      const errors = results
        .filter((result): result is PromiseRejectedResult => result.status === "rejected")
        .map((result) => apiErrorMessage(result.reason));
      setState({
        sessions: results[0].status === "fulfilled" ? results[0].value : null,
        alerts: results[1].status === "fulfilled" ? results[1].value : null,
        predictions: results[2].status === "fulfilled" ? results[2].value : null,
        errors: [...new Set(errors)],
      });
      setLoading(false);
    }
    void load();
    return () => controller.abort();
  }, []);

  const sessions = listRows<SessionOverview>(state.sessions?.sessions) || EMPTY_SESSIONS;
  const summary = state.sessions?.summary || {};
  const asOf = state.sessions?.timestamp;
  const statusData = useMemo((): LandscapeDatum[] => buildStatusData(sessions).map((entry) => ({
    name: capitalize(entry.name),
    value: entry.value,
    color: entry.color,
  })), [sessions]);
  const tacticData = useMemo(() => buildTacticData(sessions), [sessions]);
  const latestObserved = latestSessionTimestamp(sessions);
  const freshness = isFresh(latestObserved, asOf);
  const criticalAlerts = listRows<AlertRow>(state.alerts?.items).filter(
    (alert) => text(alert.severity, "").toLowerCase() === "critical",
  ).length;
  const totalSessions = typeof summary.total_sessions === "number" ? summary.total_sessions : sessions.length;
  const predictionCount = listRows(state.predictions?.items).length;

  return (
    <div className="space-y-8 animate-in fade-in duration-500 pb-10">
      {state.errors.length > 0 && (
        <div className="bg-amber-950/20 border border-amber-900/50 rounded-xl px-5 py-4 text-xs text-amber-200">
          <p className="font-semibold tracking-wide">THREAT INTELLIGENCE BACKEND PARTIALLY UNAVAILABLE</p>
          <p className="mt-1 text-amber-300/70">{state.errors.join(" · ")}</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <MetricCard label="TOTAL SESSIONS" value={totalSessions.toLocaleString()} detail={`${sessions.length.toLocaleString()} shown from canonical API`} icon={<Database className="w-4 h-4 text-purple-400" />} />
        <MetricCard label="PREDICTION SNAPSHOTS" value={predictionCount.toLocaleString()} detail="Bounded rows · model output" icon={<Brain className="w-4 h-4 text-amber-400" />} tone="amber" />
        <MetricCard label="LATEST OBSERVATION" value={latestObserved ? ageLabel(latestObserved, asOf) : "—"} detail={formatTimestamp(latestObserved)} icon={<Clock3 className="w-4 h-4 text-slate-300" />} />
        <MetricCard label="HISTORICAL CRITICAL ALERTS" value={criticalAlerts.toLocaleString()} detail="Legacy alert authority only" icon={<ShieldAlert className="w-4 h-4 text-red-400" />} tone="red" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-[#111116] border border-slate-800/50 p-6 rounded-xl flex flex-col">
          <div className="flex justify-between items-center mb-8">
            <div>
              <h3 className="text-base font-semibold text-white">Observed Session Status</h3>
              <p className="text-[10px] text-slate-500 mt-1">Derived from returned analysis status fields</p>
            </div>
            <span className="text-slate-500 text-sm" title="No actor attribution is inferred">ⓘ</span>
          </div>
          <div className="flex-1 flex flex-col items-center justify-center">
            <div className="relative w-full max-w-[200px] mb-8">
              <div className="absolute inset-0 bg-[#1e1e2d]/40 rounded-xl border border-slate-800/50 scale-90" />
              <TargetLandscapeChart data={statusData} totalLabel={sessions.length.toLocaleString()} />
            </div>
            <div className="grid grid-cols-2 gap-y-3 gap-x-6 w-full text-xs font-mono text-slate-300 px-4">
              {statusData.map((entry) => (
                <div key={entry.name} className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: entry.color }} />
                  {entry.name} ({entry.value})
                </div>
              ))}
              {statusData.length === 0 && <span className="col-span-2 text-center text-slate-500">No status data returned.</span>}
            </div>
          </div>
        </div>

        <div className="lg:col-span-2 bg-[#111116] border border-slate-800/50 rounded-xl flex flex-col overflow-hidden">
          <div className="p-6 border-b border-slate-800/50 flex justify-between items-start">
            <div>
              <h3 className="text-base font-semibold text-white mb-1">Observed Session Log</h3>
              <p className="text-xs text-slate-500">Canonical session records · source labels are not actor attribution</p>
            </div>
            <span className={`text-[10px] font-mono uppercase ${freshness === false ? "text-amber-400" : freshness === true ? "text-emerald-400" : "text-slate-500"}`}>
              {freshness === false ? "STALE DATA" : freshness === true ? "CURRENT DATA" : "FRESHNESS UNKNOWN"}
            </span>
          </div>
          <div className="flex-1 overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-300">
              <thead className="text-[10px] uppercase text-slate-500 font-mono border-b border-slate-800/50">
                <tr>
                  <th className="px-6 py-4 font-normal">TIMESTAMP</th>
                  <th className="px-6 py-4 font-normal">SOURCE</th>
                  <th className="px-6 py-4 font-normal">ANALYSIS STATUS</th>
                  <th className="px-6 py-4 font-normal text-right">ACTION</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((session, index) => {
                  const id = text(session.session_id, "");
                  const status = sessionStatus(session);
                  return (
                    <tr key={id || index} className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                      <td className="px-6 py-4 font-mono text-[11px] text-slate-400">
                        <div>{formatTimestamp(session.updated_at || session.start_time)}</div>
                        <div className="text-slate-600">{text(session.sensor_id || session.sensor, "sensor unavailable")}</div>
                      </td>
                      <td className="px-6 py-4 font-mono text-purple-300 text-xs">
                        <div>{text(session.src_ip, "source unavailable")}</div>
                        <div className="text-[10px] text-slate-600 mt-1">{session.src_ip_scope || "scope unavailable"}</div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-2 py-1 text-[9px] font-bold border rounded-sm ${statusBadge(status)}`}>
                          {status.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        {id ? <Link href={`/threat-intel/${encodeURIComponent(id)}`} className="border border-slate-700 bg-slate-900/50 text-slate-400 px-3 py-1.5 rounded text-[10px] hover:text-white transition">View Details ›</Link> : <span className="text-slate-600 text-[10px]">Unavailable</span>}
                      </td>
                    </tr>
                  );
                })}
                {!loading && sessions.length === 0 && (
                  <tr><td colSpan={4} className="px-6 py-12 text-center text-[11px] text-slate-500">No canonical sessions were returned.</td></tr>
                )}
                {loading && (
                  <tr><td colSpan={4} className="px-6 py-12 text-center text-[11px] text-slate-500">Reading canonical session telemetry…</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-2">
        <InfoCard title="Top recorded tactic" desc={tacticData[0] ? `${tacticData[0].label} · ${tacticData[0].count} shown` : "Not recorded"} icon={<Brain className="w-4 h-4 text-purple-400" />} />
        <InfoCard title="TTP field coverage" desc={`${sessions.filter((session) => asStringList(session.ttps).length > 0).length} shown sessions with TTP fields`} icon={<ShieldAlert className="w-4 h-4 text-amber-500" />} highlight />
        <InfoCard title="Public map coverage" desc={`${sessions.filter((session) => session.geo?.latitude !== undefined || session.source_geo?.latitude !== undefined).length} shown sessions with map fields`} icon={<MapPin className="w-4 h-4 text-purple-400" />} />
        <InfoCard title="Canonical data freshness" desc={freshness === false ? "Data present but stale" : freshness === true ? "Within 24 hours" : "Timestamp unavailable"} icon={<Clock3 className="w-4 h-4 text-slate-300" />} />
      </div>

      <div className="bg-[#111116] border border-purple-900/30 p-5 rounded-xl">
        <div className="flex items-start gap-3">
          <Brain className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
          <div>
            <h4 className="text-[11px] font-bold text-white uppercase tracking-wider">Evidence lanes</h4>
            <p className="text-[11px] text-slate-400 mt-2 leading-relaxed">
              Trusted ATT&amp;CK observations, model advisory predictions, and correlation hypotheses are separate API namespaces. A correlation strength is a developer-defined heuristic, not a probability; a model score is not promoted to actor attribution or response authority.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function latestSessionTimestamp(sessions: SessionOverview[]): string {
  return sessions.map((session) => text(session.updated_at || session.start_time, "")).filter(Boolean).sort().at(-1) || "";
}

function capitalize(value: string): string {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : "Unknown";
}

function statusBadge(status: string): string {
  switch (status) {
    case "completed": return "text-purple-200 bg-purple-950/40 border-purple-900/50";
    case "running": return "text-emerald-200 bg-emerald-950/40 border-emerald-900/50";
    case "failed": return "text-red-200 bg-red-950/40 border-red-900/50";
    case "queued": return "text-slate-300 bg-slate-800/50 border-slate-700";
    default: return `${statusTextColor(status)} bg-slate-900/80 border-slate-700/50`;
  }
}

function MetricCard({
  label,
  value,
  detail,
  icon,
  tone = "normal",
}: {
  label: string;
  value: string;
  detail: string;
  icon: React.ReactNode;
  tone?: "normal" | "amber" | "red";
}) {
  const valueColor = tone === "red" ? "text-[#fca5a5]" : tone === "amber" ? "text-amber-300" : "text-white";
  return (
    <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl flex flex-col justify-between min-h-[132px]">
      <div className="flex items-center justify-between"><span className="text-[10px] text-slate-500 tracking-wider">{label}</span><span>{icon}</span></div>
      <div className="flex items-baseline gap-2 mt-3"><span className={`text-2xl font-bold ${valueColor}`}>{value}</span></div>
      <span className="text-[10px] text-slate-500 mt-2">{detail}</span>
    </div>
  );
}

function InfoCard({ title, desc, icon, highlight = false }: { title: string; desc: string; icon: React.ReactNode; highlight?: boolean }) {
  return (
    <div className="bg-[#111116] border border-slate-800/50 p-4 rounded-xl flex items-center gap-4 relative overflow-hidden group">
      <div className="w-10 h-10 rounded-lg bg-[#1e1e2d] border border-slate-700/50 flex items-center justify-center shrink-0">{icon}</div>
      <div><h4 className="text-[11px] font-bold text-white mb-0.5">{title}</h4><p className={`text-[10px] font-mono ${highlight ? "text-amber-500/80" : "text-slate-400"}`}>{desc}</p></div>
    </div>
  );
}
