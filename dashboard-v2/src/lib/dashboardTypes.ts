export type JsonRecord = Record<string, unknown>;

export interface DashboardThreatGeo {
  lat: number;
  lon: number;
  country: string;
  city: string;
}

/** Stable fields emitted by the current /api/threats route. */
export interface DashboardThreatEvent extends JsonRecord {
  id: string;
  timestamp: string | number;
  date: string;
  time: string;
  sensor: string;
  src_ip: string;
  sourceIp: string;
  severity: string;
  classification: string;
  typeColor: string;
  duration: string;
  geo: DashboardThreatGeo;
  ip?: string;
  event_type?: string;
  protocol?: string;
  payloadPreview?: string;
  abuseipdb?: { abuseConfidenceScore?: number; isp?: string | null } | null;
  virustotal?: {
    attributes?: {
      meaningful_name?: string | null;
      stats?: { malicious?: number; undetected?: number } | null;
    } | null;
  } | null;
}

export type ThreatSeverityFilter = "All" | "Critical" | "High" | "Medium" | "Low";

export interface ThreatDirectoryPage {
  items: DashboardThreatEvent[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface ThreatDashboardSummary {
  windowHours: number;
  sessions: number;
  uniqueSources: number;
  prioritySessions: number;
}

export interface AttackerSummary {
  ip: string;
  country: string;
  asn: string;
  mainTechnique: string;
  attackCount: number;
  riskScore: number;
  status: string;
}

export interface DashboardChartDatum {
  name: string;
  value: number;
  color: string;
}

export interface HardwareTelemetry extends JsonRecord {
  timestamp?: string | number | Date;
  cpu_percent?: number | string | null;
  mem_percent?: number | string | null;
  disk_percent?: number | string | null;
  temperature?: number | string | null;
  net_wlan0_rx_mbps?: number | string | null;
  net_wlan0_tx_mbps?: number | string | null;
}

export interface HardwareChartRecord extends HardwareTelemetry {
  time: string;
  timestampEpoch: number;
}

export type HardwareStreamMessage =
  | { type: "initial"; data: HardwareTelemetry[] }
  | { type: "update"; data: HardwareTelemetry };

/** Messages emitted by the shared live threat feed. */
export type ThreatStreamMessage =
  | { type: "snapshot"; data: DashboardThreatEvent[] }
  | { type: "threat.upsert"; data: DashboardThreatEvent }
  | { type: "heartbeat"; data: { at: string } };

export interface DashboardUser extends JsonRecord {
  operatorId: string;
  fullName: string;
  email: string;
  position: string;
  role: string;
  status: string;
  createdAt?: string | number | Date;
}

export type DashboardProfile = DashboardUser;

export type CwdObservationStatus = "observed" | "confirmed" | "conditional_candidate" | "unknown";

/** Canonical, server-derived working-directory state for a Cowrie session. */
export interface SessionCwdState {
  path: string | null;
  status: CwdObservationStatus;
  observedAt: string | null;
  sourceEventId: string | null;
}

export interface FilesystemTopologyNode {
  path: string;
  parentPath: string | null;
  depth: number;
  sessionIds: string[];
  observedAt: string | null;
}

export interface FilesystemTopologySession {
  sessionId: string;
  sourceIp: string;
  cwdState: SessionCwdState;
}

/** A session that is no longer live but remains available for CWD audit retention. */
export interface FilesystemClosedSession extends FilesystemTopologySession {
  lifecycle: {
    startedAt: string | null;
    closedAt: string | null;
  };
}

export interface FilesystemTopologySnapshot {
  nodes: FilesystemTopologyNode[];
  sessions: FilesystemTopologySession[];
  /** Most recently closed, audit-ready sessions. They never appear in the live graph. */
  recentClosedSessions: FilesystemClosedSession[];
  /** True when a bounded live snapshot contains only the most recently observed sessions. */
  truncated: boolean;
  generatedAt: string;
}

export interface SessionCwdHistoryEvent {
  id: string;
  sessionId: string;
  /** Lossless decimal representation of the MongoDB Int64/Unix nanoseconds. */
  sequence: string | null;
  at: string;
  fromPath: string | null;
  toPath: string | null;
  action: "entered" | "changed" | "failed_change";
  status: CwdObservationStatus;
  sourceEventId: string | null;
}

export interface SessionCwdHistoryPage {
  items: SessionCwdHistoryEvent[];
  nextCursor: string | null;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringOrNumber(value: unknown): value is string | number {
  return typeof value === "string" || typeof value === "number";
}

function isGeo(value: unknown): value is DashboardThreatGeo {
  if (!isRecord(value)) return false;
  return typeof value.lat === "number" && typeof value.lon === "number" &&
    typeof value.country === "string" && typeof value.city === "string";
}

function isAbuseIpdb(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (!isRecord(value)) return false;
  return value.abuseConfidenceScore === undefined || typeof value.abuseConfidenceScore === "number";
}

function isVirusTotal(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (!isRecord(value)) return false;
  const attributes = value.attributes;
  if (attributes === undefined || attributes === null) return true;
  if (!isRecord(attributes)) return false;
  const stats = attributes.stats;
  if (stats === undefined || stats === null) return true;
  if (!isRecord(stats)) return false;
  return (stats.malicious === undefined || typeof stats.malicious === "number") &&
    (stats.undetected === undefined || typeof stats.undetected === "number");
}

export function isDashboardThreatEvent(value: unknown): value is DashboardThreatEvent {
  if (!isRecord(value)) return false;
  return typeof value.id === "string" && isStringOrNumber(value.timestamp) &&
    typeof value.date === "string" && typeof value.time === "string" &&
    typeof value.sensor === "string" && typeof value.src_ip === "string" &&
    typeof value.sourceIp === "string" && typeof value.severity === "string" &&
    typeof value.classification === "string" && typeof value.typeColor === "string" &&
    typeof value.duration === "string" && isGeo(value.geo) &&
    isAbuseIpdb(value.abuseipdb) && isVirusTotal(value.virustotal);
}

function hardwareTimestampEpoch(value: unknown): number | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.getTime() : null;
  if (typeof value === "number") return Number.isFinite(value) ? new Date(value).getTime() : null;
  if (typeof value === "string" && value.trim()) {
    const timestamp = new Date(value).getTime();
    return Number.isFinite(timestamp) ? timestamp : null;
  }
  return null;
}

function isHardwareMetric(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value === "number") return Number.isFinite(value);
  return typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value));
}

export function isHardwareTelemetry(value: unknown): value is HardwareTelemetry {
  if (!isRecord(value)) return false;
  return hardwareTimestampEpoch(value.timestamp) !== null && isHardwareMetric(value.cpu_percent) &&
    isHardwareMetric(value.mem_percent) && isHardwareMetric(value.disk_percent) &&
    isHardwareMetric(value.temperature) && isHardwareMetric(value.net_wlan0_rx_mbps) &&
    isHardwareMetric(value.net_wlan0_tx_mbps);
}

export function parseHardwareStreamMessage(value: unknown): HardwareStreamMessage | null {
  if (!isRecord(value) || (value.type !== "initial" && value.type !== "update")) return null;
  if (value.type === "initial") {
    if (!Array.isArray(value.data)) return null;
    return { type: "initial", data: value.data.filter(isHardwareTelemetry) };
  }
  return isHardwareTelemetry(value.data) ? { type: "update", data: value.data } : null;
}

export function parseThreatStreamMessage(value: unknown): ThreatStreamMessage | null {
  if (!isRecord(value) || typeof value.type !== "string") return null;

  if (value.type === "snapshot") {
    if (!Array.isArray(value.data)) return null;
    return { type: "snapshot", data: value.data.filter(isDashboardThreatEvent) };
  }

  if (value.type === "threat.upsert") {
    return isDashboardThreatEvent(value.data) ? { type: "threat.upsert", data: value.data } : null;
  }

  if (value.type === "heartbeat" && isRecord(value.data) && typeof value.data.at === "string") {
    return { type: "heartbeat", data: { at: value.data.at } };
  }

  return null;
}

export function formatHardwareMetric(metric: HardwareTelemetry): HardwareChartRecord {
  const timestampEpoch = hardwareTimestampEpoch(metric.timestamp) ?? 0;
  const date = new Date(timestampEpoch);
  return {
    ...metric,
    cpu_percent: numericHardwareMetric(metric.cpu_percent),
    mem_percent: numericHardwareMetric(metric.mem_percent),
    disk_percent: numericHardwareMetric(metric.disk_percent),
    temperature: numericHardwareMetric(metric.temperature),
    net_wlan0_rx_mbps: numericHardwareMetric(metric.net_wlan0_rx_mbps),
    net_wlan0_tx_mbps: numericHardwareMetric(metric.net_wlan0_tx_mbps),
    timestampEpoch,
    time: `${date.getHours()}:${date.getMinutes().toString().padStart(2, "0")}:${date.getSeconds().toString().padStart(2, "0")}`,
  };
}

export function numericHardwareMetric(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  const numberValue = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numberValue) ? numberValue : null;
}

export function isDashboardUser(value: unknown): value is DashboardUser {
  if (!isRecord(value)) return false;
  return typeof value.operatorId === "string" && typeof value.fullName === "string" &&
    typeof value.email === "string" && typeof value.position === "string" &&
    typeof value.role === "string" && typeof value.status === "string";
}
