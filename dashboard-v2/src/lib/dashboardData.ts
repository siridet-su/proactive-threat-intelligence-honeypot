import type { GeoPoint, SessionOverview } from "@/lib/dashboardTypes";

export const CHART_COLORS = ["#a855f7", "#d946ef", "#64748b", "#d97706", "#34d399"];

export function listRows<T>(value: unknown): T[] {
  return Array.isArray(value) ? value.filter((item) => item !== null && item !== undefined) as T[] : [];
}

export function text(value: unknown, fallback = "—"): string {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

export function numberValue(value: unknown, fallback = 0): number {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => text(item, "")).filter(Boolean);
}

export function sessionStatus(session: SessionOverview): string {
  const raw = text(session.analysis_status || session.job_status, "unknown").toLowerCase();
  if (raw === "succeeded" || raw === "completed" || raw === "complete") return "completed";
  if (raw === "running" || raw === "retry") return "running";
  if (raw === "queued") return "queued";
  if (raw === "failed" || raw === "error") return "failed";
  if (raw === "skipped") return "skipped";
  return raw || "unknown";
}

export function statusColor(status: string): string {
  switch (status) {
    case "completed":
      return "bg-purple-500";
    case "running":
      return "bg-emerald-400";
    case "failed":
      return "bg-red-400";
    case "queued":
      return "bg-slate-500";
    case "skipped":
      return "bg-amber-500";
    default:
      return "bg-slate-600";
  }
}

export function statusTextColor(status: string): string {
  switch (status) {
    case "completed":
      return "text-purple-300";
    case "running":
      return "text-emerald-300";
    case "failed":
      return "text-red-300";
    case "queued":
      return "text-slate-300";
    case "skipped":
      return "text-amber-300";
    default:
      return "text-slate-400";
  }
}

export function timestampOf(session: SessionOverview): string {
  return text(session.updated_at || session.start_time, "");
}

export function formatTimestamp(value: unknown): string {
  const raw = text(value, "");
  if (!raw) return "—";
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return raw;
  return parsed.toISOString().replace("T", " ").replace(".000Z", "Z");
}

export function ageLabel(value: unknown, nowValue?: unknown): string {
  const timestamp = new Date(text(value, "")).getTime();
  const now = nowValue ? new Date(text(nowValue, "")).getTime() : Date.now();
  if (!Number.isFinite(timestamp) || !Number.isFinite(now)) return "timestamp unavailable";
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < 60) return `${seconds}s old`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m old`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h old`;
  return `${Math.floor(seconds / 86400)}d old`;
}

export function isFresh(value: unknown, nowValue?: unknown): boolean | null {
  const timestamp = new Date(text(value, "")).getTime();
  const now = nowValue ? new Date(text(nowValue, "")).getTime() : Date.now();
  if (!Number.isFinite(timestamp) || !Number.isFinite(now)) return null;
  return now - timestamp <= 24 * 60 * 60 * 1000;
}

export function buildStatusData(sessions: SessionOverview[]) {
  const counts = new Map<string, number>();
  for (const session of sessions) {
    const status = sessionStatus(session);
    counts.set(status, (counts.get(status) || 0) + 1);
  }
  const order = ["completed", "running", "failed", "queued", "skipped", "unknown"];
  const total = sessions.length;
  return order
    .filter((name) => counts.has(name))
    .map((name, index) => ({
      name,
      value: counts.get(name) || 0,
      percentage: total ? Math.round(((counts.get(name) || 0) / total) * 100) : 0,
      color: CHART_COLORS[index % CHART_COLORS.length],
    }));
}

export function buildTacticData(sessions: SessionOverview[]) {
  const counts = new Map<string, number>();
  for (const session of sessions) {
    for (const tactic of asStringList(session.tactics)) {
      counts.set(tactic, (counts.get(tactic) || 0) + 1);
    }
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([label, count]) => ({ label, count }));
}

export function buildActivityData(sessions: SessionOverview[], asOf?: string) {
  const now = new Date(asOf || Date.now());
  if (Number.isNaN(now.getTime())) return [];
  const buckets = Array.from({ length: 6 }, (_, index) => {
    const start = new Date(now.getTime() - (5 - index) * 4 * 60 * 60 * 1000);
    return { start, label: `${String(start.getUTCHours()).padStart(2, "0")}Z`, rate: 0 };
  });
  for (const session of sessions) {
    const time = new Date(timestampOf(session)).getTime();
    if (!Number.isFinite(time)) continue;
    const bucket = buckets.find((candidate, index) => {
      const end = index === buckets.length - 1 ? now.getTime() + 1 : buckets[index + 1].start.getTime();
      return time >= candidate.start.getTime() && time < end;
    });
    if (bucket) bucket.rate += 1;
  }
  return buckets.map(({ label, rate }) => ({ time: label, rate }));
}

export function geoPoint(session: SessionOverview): GeoPoint | null {
  const geo = session.geo || session.source_geo;
  if (!geo || typeof geo !== "object") return null;
  const latitude = numberValue(geo.latitude, Number.NaN);
  const longitude = numberValue(geo.longitude, Number.NaN);
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return null;
  if (Math.abs(latitude) > 90 || Math.abs(longitude) > 180) return null;
  return { ...geo, latitude, longitude };
}

export function safeLabel(value: unknown): string {
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return text(record.ttp || record.technique || record.tactic || record.label, "recorded evidence");
  }
  return "recorded evidence";
}
