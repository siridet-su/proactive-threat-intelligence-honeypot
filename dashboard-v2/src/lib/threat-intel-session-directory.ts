import type { DashboardThreatEvent } from "@/lib/dashboardTypes";
import type { WebHttpSession } from "@/lib/web-http-intel";

export type SessionProtocolFilter = "all" | "ssh" | "http";
export type SessionAttackerTypeFilter = "All" | "APT" | "Bot" | "ScriptKiddie";
export type SessionAttackerType = Exclude<SessionAttackerTypeFilter, "All"> | "Unclassified";

/** Values accepted by the existing threat-directory backend. */
export const SESSION_ATTACKER_TYPE_OPTIONS: ReadonlyArray<{
  value: Exclude<SessionAttackerTypeFilter, "All">;
  label: string;
}> = [
  { value: "APT", label: "APT" },
  { value: "Bot", label: "Bot" },
  { value: "ScriptKiddie", label: "Script Kiddie" },
];

/** Attacker classification belongs only to the SSH directory/API query. */
export function attackerTypeQueryValue(
  protocol: SessionProtocolFilter,
  attackerType: SessionAttackerTypeFilter,
): Exclude<SessionAttackerTypeFilter, "All"> | null {
  return protocol === "ssh" && attackerType !== "All" ? attackerType : null;
}

export type SessionDirectoryRow = {
  key: string;
  id: string;
  href: string;
  protocol: "SSH" | "HTTP";
  attackerType: SessionAttackerType | null;
  sensor: string;
  origin: string;
  originDetail: string;
  startedAt: string;
  startedLabel: string;
  activity: string;
  dwellTime: string;
  status: "Active" | "Closed" | "Observed";
  sortTimestamp: number;
  searchText: string;
};

function timestamp(value: unknown): number | null {
  if (typeof value !== "string" && typeof value !== "number" && !(value instanceof Date)) return null;
  const parsed = value instanceof Date ? value.getTime() : Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function startedLabel(value: string): string {
  const parsed = timestamp(value);
  if (parsed === null) return "Not recorded";
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(parsed);
}

function secondsLabel(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
}

function sshDwellTime(session: DashboardThreatEvent, status: "Active" | "Closed"): string {
  if (status === "Active") return "Active";
  const started = timestamp(session.timestamp);
  const ended = timestamp(session.end_time);
  if (started !== null && ended !== null && ended >= started) {
    return secondsLabel(Math.round((ended - started) / 1_000));
  }
  if (typeof session.duration === "number" && Number.isFinite(session.duration) && session.duration >= 0) {
    return secondsLabel(Math.round(session.duration));
  }
  return "Not recorded";
}

function sshRow(session: DashboardThreatEvent): SessionDirectoryRow {
  const status: "Active" | "Closed" = session.session_status === "active" || session.duration === "Active"
    ? "Active"
    : "Closed";
  const startedAt = String(session.timestamp ?? "");
  const country = session.geo?.country && session.geo.country !== "Unknown"
    ? session.geo.country
    : "Country unavailable";
  const sensor = session.sensor || "Cowrie";
  const attackerType = normalizeAttackerType(session.classification);

  return {
    key: `ssh:${session.id}`,
    id: session.id,
    href: `/threat-intel/${encodeURIComponent(session.id)}`,
    protocol: "SSH",
    attackerType,
    sensor,
    origin: session.sourceIp || "Origin unavailable",
    originDetail: country === "Country unavailable" ? country : `Approximate · ${country}`,
    startedAt,
    startedLabel: startedLabel(startedAt),
    // The directory contract does not include a session-bound command count.
    activity: "Command activity",
    dwellTime: sshDwellTime(session, status),
    status,
    sortTimestamp: timestamp(startedAt) ?? 0,
    searchText: [session.id, session.sourceIp, session.sensor, country, attackerType, "ssh cowrie"].join(" ").toLowerCase(),
  };
}

function httpRow(session: WebHttpSession & { id: string }): SessionDirectoryRow {
  const startedAt = session.firstObservedAt;
  const first = timestamp(session.firstObservedAt);
  const last = timestamp(session.lastObservedAt);
  const observedSpan = first !== null && last !== null && last > first
    ? `${secondsLabel(Math.round((last - first) / 1_000))} observed`
    : "—";
  const hintCount = session.events.filter((event) => event.signals.length > 0).length;
  const requestLabel = `${session.events.length} request${session.events.length === 1 ? "" : "s"}`;
  const activity = hintCount
    ? `${requestLabel} · ${hintCount} injection hint${hintCount === 1 ? "" : "s"}`
    : requestLabel;
  const origin = session.sourceIps[0] ?? "Origin unavailable";
  const originDetail = session.sourceIps.length > 1
    ? `${session.sourceIps.length} observed IPs · location unavailable`
    : "Location unavailable";

  return {
    key: `http:${session.id}`,
    id: session.id,
    href: `/threat-intel/http/${encodeURIComponent(session.id)}`,
    protocol: "HTTP",
    attackerType: null,
    sensor: "web-corp",
    origin,
    originDetail,
    startedAt,
    startedLabel: startedLabel(startedAt),
    activity,
    dwellTime: observedSpan,
    // Cookie continuity groups requests; it is not a verified live-session state.
    status: "Observed",
    sortTimestamp: first ?? 0,
    searchText: [
      session.id,
      ...session.sourceIps,
      "http web-corp",
      ...session.events.flatMap((event) => [event.method, event.path, ...event.signals]),
    ].join(" ").toLowerCase(),
  };
}

export function normalizeAttackerType(value: unknown): SessionAttackerType {
  if (value === "APT" || value === "Bot" || value === "ScriptKiddie") return value;
  return "Unclassified";
}

export function buildSessionDirectoryRows(
  sshSessions: readonly DashboardThreatEvent[],
  httpSessions: readonly WebHttpSession[],
  protocol: SessionProtocolFilter,
  search = "",
): SessionDirectoryRow[] {
  const normalizedSearch = search.trim().toLowerCase();
  const rows: SessionDirectoryRow[] = [];

  if (protocol !== "http") rows.push(...sshSessions.map(sshRow));
  if (protocol !== "ssh") {
    rows.push(...httpSessions
      .filter((session): session is WebHttpSession & { id: string } => typeof session.id === "string")
      .map(httpRow));
  }

  return rows
    .filter((row) => !normalizedSearch || row.searchText.includes(normalizedSearch))
    .sort((a, b) => b.sortTimestamp - a.sortTimestamp || a.key.localeCompare(b.key));
}
