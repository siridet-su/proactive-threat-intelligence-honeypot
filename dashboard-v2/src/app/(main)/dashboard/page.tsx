"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";
import AttackRateChart from "@/components/dashboard/AttackRateChart";
import RegionalMap, { type RegionalMarker } from "@/components/dashboard/RegionalMap";
import { apiErrorMessage, fetchDashboardJson } from "@/lib/api";
import {
  ageLabel,
  asStringList,
  buildActivityData,
  buildStatusData,
  buildTacticData,
  CHART_COLORS,
  formatTimestamp,
  geoPoint,
  isFresh,
  listRows,
  sessionStatus,
  statusColor,
  statusTextColor,
  text,
  timestampOf,
} from "@/lib/dashboardData";
import type {
  AlertRow,
  EventView,
  EventsResponse,
  HealthResponse,
  JobRow,
  SessionOverview,
  SessionsResponse,
  TableResponse,
} from "@/lib/dashboardTypes";

interface DashboardState {
  sessions: SessionsResponse | null;
  events: EventsResponse | null;
  alerts: TableResponse<AlertRow> | null;
  jobs: TableResponse<JobRow> | null;
  health: HealthResponse | null;
  errors: string[];
}

const EMPTY_STATE: DashboardState = {
  sessions: null,
  events: null,
  alerts: null,
  jobs: null,
  health: null,
  errors: [],
};

const EMPTY_SESSIONS: SessionOverview[] = [];

export default function DashboardPage() {
  const [state, setState] = useState<DashboardState>(EMPTY_STATE);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();
    async function load() {
      const results = await Promise.allSettled([
        fetchDashboardJson<SessionsResponse>("/api/sessions?limit=100&offset=0", controller.signal),
        fetchDashboardJson<EventsResponse>("/api/events", controller.signal),
        fetchDashboardJson<TableResponse<AlertRow>>("/api/alerts?limit=100", controller.signal),
        fetchDashboardJson<TableResponse<JobRow>>("/api/jobs?limit=100", controller.signal),
        fetchDashboardJson<HealthResponse>("/api/health", controller.signal),
      ]);
      if (controller.signal.aborted) return;

      const valueAt = <T,>(index: number): T | null => {
        const result = results[index];
        return result.status === "fulfilled" ? (result.value as T) : null;
      };
      const errors = results
        .filter((result): result is PromiseRejectedResult => result.status === "rejected")
        .map((result) => apiErrorMessage(result.reason));

      setState({
        sessions: valueAt<SessionsResponse>(0),
        events: valueAt<EventsResponse>(1),
        alerts: valueAt<TableResponse<AlertRow>>(2),
        jobs: valueAt<TableResponse<JobRow>>(3),
        health: valueAt<HealthResponse>(4),
        errors: [...new Set(errors)],
      });
      setLoading(false);
    }
    void load();
    return () => controller.abort();
  }, []);

  const sessions = listRows<SessionOverview>(state.sessions?.sessions) || EMPTY_SESSIONS;
  const events = listRows<EventView>(state.events?.events);
  const summary = state.sessions?.summary || {};
  const asOf = state.sessions?.timestamp || state.events?.timestamp;
  const statusData = useMemo(() => buildStatusData(sessions), [sessions]);
  const tacticData = useMemo(() => buildTacticData(sessions), [sessions]);
  const activityData = useMemo(() => buildActivityData(sessions, asOf), [sessions, asOf]);
  const markers = useMemo(() => buildRegionalMarkers(sessions), [sessions]);
  const latestObserved = latestTimestamp(
    events.map((event) => text(event.timestamp || event.received_at, "")),
    sessions.map(timestampOf),
  );
  const freshness = isFresh(latestObserved, asOf);
  const criticalAlerts = listRows<AlertRow>(state.alerts?.items).filter(
    (alert) => text(alert.severity, "").toLowerCase() === "critical",
  ).length;
  const totalSessions = typeof summary.total_sessions === "number" ? summary.total_sessions : sessions.length;
  const shownSessions = typeof summary.shown_sessions === "number" ? summary.shown_sessions : sessions.length;

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {state.errors.length > 0 && (
        <div className="bg-amber-950/20 border border-amber-900/50 rounded-xl px-5 py-4 text-xs text-amber-200">
          <p className="font-semibold tracking-wide">BACKEND DATA PARTIALLY UNAVAILABLE</p>
          <p className="mt-1 text-amber-300/70">{state.errors.join(" · ")}</p>
        </div>
      )}

      <div className="bg-[#111116] border border-slate-800/80 rounded-xl px-5 py-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.16em] text-slate-500">Production observation window</p>
          <p className="text-xs text-slate-300 mt-1">
            {loading ? "Loading backend telemetry…" : `Backend as of ${formatTimestamp(asOf)}`}
          </p>
        </div>
        <div className="flex items-center gap-3 text-[10px] font-mono uppercase tracking-wider">
          <span className={`w-2 h-2 rounded-full ${freshness === true ? "bg-emerald-400" : freshness === false ? "bg-amber-400" : "bg-slate-500"}`} />
          <span className={freshness === true ? "text-emerald-300" : freshness === false ? "text-amber-300" : "text-slate-400"}>
            {freshness === true ? "Current data" : freshness === false ? "Data stale" : "Freshness unknown"}
          </span>
          <span className="text-slate-600">{latestObserved ? ageLabel(latestObserved, asOf) : "timestamp unavailable"}</span>
        </div>
      </div>

      <div className="bg-[#111116] border border-slate-800/80 rounded-xl hover:border-purple-900/50 transition-colors flex flex-col overflow-hidden">
        <div className="px-6 py-5 border-b border-slate-800/80 flex flex-col xl:flex-row xl:justify-between xl:items-center gap-4 bg-[#111116] z-10">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">Global Activity Matrix</h2>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Public geolocation derived from the bounded session response · {totalSessions.toLocaleString()} total · {shownSessions.toLocaleString()} shown
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-400">
            {statusData.slice(0, 4).map((status) => (
              <span key={status.name} className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: status.color }} />
                {capitalize(status.name)}
              </span>
            ))}
            {statusData.length === 0 && <span>No session statuses returned</span>}
          </div>
        </div>
        <div className="h-[400px] w-full bg-[#09090b]">
          <RegionalMap markers={markers} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-5 lg:col-span-5 flex flex-col hover:border-purple-900/50 transition-colors">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Session Activity (24H)</h3>
            <span className="text-[10px] text-slate-600 font-mono">OBSERVED SESSIONS / 4H</span>
          </div>
          <div className="flex-1 min-h-[180px]">
            <AttackRateChart data={activityData} />
          </div>
        </div>

        <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-5 lg:col-span-3 flex flex-col hover:border-purple-900/50 transition-colors">
          <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-4">Status Split</h3>
          <div className="flex-1 flex flex-col items-center justify-center">
            {statusData.length > 0 ? (
              <>
                <div className="h-32 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={statusData} innerRadius={40} outerRadius={55} paddingAngle={4} dataKey="value" stroke="none">
                        {statusData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-2 w-full mt-4">
                  {statusData.map((entry) => (
                    <div key={entry.name} className="flex justify-between items-center bg-[#18181b] px-2 py-1 rounded text-[10px] gap-2">
                      <span className="text-slate-400 truncate">{capitalize(entry.name)}</span>
                      <span className="text-white font-mono">{entry.percentage}%</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <p className="text-[11px] text-slate-500 text-center">No status data returned.</p>
            )}
          </div>
        </div>

        <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-5 lg:col-span-4 flex flex-col hover:border-purple-900/50 transition-colors">
          <h3 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-4">Observed Tactic Frequency</h3>
          <div className="flex flex-col gap-3 flex-1 justify-center">
            {tacticData.length > 0 ? tacticData.map((tactic, index) => (
              <TacticBar key={tactic.label} label={tactic.label} count={tactic.count} max={tacticData[0].count} color={CHART_COLORS[index % CHART_COLORS.length]} />
            )) : <p className="text-[11px] text-slate-500 text-center">No tactic fields returned.</p>}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard label="TOTAL SESSIONS" value={totalSessions.toLocaleString()} detail={`${shownSessions.toLocaleString()} returned by bounded API page`} />
        <MetricCard label="QUEUED / RUNNING JOBS" value={text(summary.queued_jobs, "—")} detail="Canonical analysis summary" tone="amber" />
        <MetricCard label="HISTORICAL CRITICAL ALERTS" value={criticalAlerts.toLocaleString()} detail="Bounded alert rows · legacy authority" tone="red" />
      </div>

      <div className="bg-[#111116] border border-slate-800/80 rounded-xl overflow-hidden hover:border-purple-900/50 transition-colors">
        <div className="px-6 py-5 border-b border-slate-800/80 flex flex-col sm:flex-row justify-between sm:items-center gap-4">
          <div>
            <h3 className="text-sm font-semibold text-white tracking-tight">Sessions</h3>
            <p className="text-[11px] text-slate-500 mt-0.5">Canonical session rows · click a row for bounded intelligence detail</p>
          </div>
          <span className="text-[10px] text-slate-600 font-mono">{formatTimestamp(latestObserved)} latest observed</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-[#09090b] border-b border-slate-800/80">
              <tr className="text-slate-500 text-[10px] uppercase tracking-widest font-semibold">
                <th className="px-6 py-3">Session ID / Source</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3">Observed Tactics</th>
                <th className="px-6 py-3 text-right">Commands</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session, index) => {
                const id = text(session.session_id, "");
                const status = sessionStatus(session);
                return (
                  <tr key={id || index} className="border-b border-slate-800/40 hover:bg-slate-800/30 transition-colors group">
                    <td className="px-6 py-3.5">
                      {id ? (
                        <Link href={`/threat-intel/${encodeURIComponent(id)}`} className="font-mono text-xs text-purple-300 hover:text-white">
                          {id}
                        </Link>
                      ) : <span className="font-mono text-xs text-slate-500">unknown session</span>}
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5">{text(session.src_ip, "source unavailable")}</div>
                    </td>
                    <td className="px-6 py-3.5">
                      <span className={`flex items-center gap-1.5 text-[11px] ${statusTextColor(status)}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${statusColor(status)}`} />
                        {capitalize(status)}
                      </span>
                    </td>
                    <td className="px-6 py-3.5">
                      <span className="bg-[#18181b] border border-slate-700/50 px-2 py-0.5 rounded text-[10px] text-slate-400">
                        {asStringList(session.tactics).slice(0, 2).join(" · ") || "not recorded"}
                      </span>
                    </td>
                    <td className="px-6 py-3.5 text-right font-mono text-xs text-slate-400">
                      {typeof session.command_count === "number" ? session.command_count : "—"}
                    </td>
                  </tr>
                );
              })}
              {!loading && sessions.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-[11px] text-slate-500">No session rows were returned by the production API.</td>
                </tr>
              )}
              {loading && (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-[11px] text-slate-500">Reading canonical session telemetry…</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function buildRegionalMarkers(sessions: SessionOverview[]): RegionalMarker[] {
  const grouped = new Map<string, RegionalMarker>();
  for (const session of sessions) {
    const geo = geoPoint(session);
    if (!geo) continue;
    const key = `${geo.latitude?.toFixed(3)}:${geo.longitude?.toFixed(3)}`;
    const name = [text(geo.city, ""), text(geo.country, "")].filter(Boolean).join(", ") || "Public source location";
    const current = grouped.get(key);
    if (current) {
      current.count += 1;
      if (sessionStatus(session) === "running") current.status = "running";
    } else {
      grouped.set(key, {
        name,
        coordinates: [geo.longitude as number, geo.latitude as number],
        status: sessionStatus(session),
        count: 1,
      });
    }
  }
  return [...grouped.values()];
}

function latestTimestamp(...groups: string[][]): string {
  return groups.flat().filter(Boolean).sort().at(-1) || "";
}

function capitalize(value: string): string {
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : "Unknown";
}

function MetricCard({
  label,
  value,
  detail,
  tone = "purple",
}: {
  label: string;
  value: string;
  detail: string;
  tone?: "purple" | "amber" | "red";
}) {
  const toneClass = tone === "red" ? "text-[#fca5a5]" : tone === "amber" ? "text-amber-300" : "text-white";
  return (
    <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl flex flex-col justify-between">
      <span className="text-[10px] text-slate-500 tracking-wider mb-2">{label}</span>
      <div className="flex items-baseline gap-2">
        <span className={`text-3xl font-bold ${toneClass}`}>{value}</span>
      </div>
      <span className="text-[10px] text-slate-500 mt-2">{detail}</span>
    </div>
  );
}

function TacticBar({ label, count, max, color }: { label: string; count: number; max: number; color: string }) {
  const percentage = max > 0 ? Math.min(100, (count / max) * 100) : 0;
  return (
    <div className="flex items-center gap-3">
      <div className="w-28 text-right text-[10px] font-mono text-slate-400 truncate">{label}</div>
      <div className="flex-1 h-2 bg-[#18181b] rounded-full overflow-hidden flex">
        <div className="h-full rounded-full" style={{ width: `${percentage}%`, backgroundColor: color }} />
      </div>
      <div className="w-6 text-left text-[10px] font-mono text-slate-300">{count}</div>
    </div>
  );
}
