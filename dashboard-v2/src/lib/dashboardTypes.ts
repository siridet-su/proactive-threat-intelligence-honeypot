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
}

export type HardwareStreamMessage =
  | { type: "initial"; data: HardwareTelemetry[] }
  | { type: "update"; data: HardwareTelemetry };

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

function isMetric(value: unknown): boolean {
  return value === undefined || value === null || value instanceof Date || isStringOrNumber(value);
}

export function isHardwareTelemetry(value: unknown): value is HardwareTelemetry {
  if (!isRecord(value)) return false;
  return isMetric(value.timestamp) && isMetric(value.cpu_percent) &&
    isMetric(value.mem_percent) && isMetric(value.disk_percent) &&
    isMetric(value.temperature) && isMetric(value.net_wlan0_rx_mbps) &&
    isMetric(value.net_wlan0_tx_mbps);
}

export function parseHardwareStreamMessage(value: unknown): HardwareStreamMessage | null {
  if (!isRecord(value) || (value.type !== "initial" && value.type !== "update")) return null;
  if (value.type === "initial") {
    if (!Array.isArray(value.data)) return null;
    return { type: "initial", data: value.data.filter(isHardwareTelemetry) };
  }
  return isHardwareTelemetry(value.data) ? { type: "update", data: value.data } : null;
}

export function formatHardwareMetric(metric: HardwareTelemetry): HardwareChartRecord {
  const date = metric.timestamp instanceof Date ? metric.timestamp : new Date(metric.timestamp ?? "");
  return {
    ...metric,
    time: `${date.getHours()}:${date.getMinutes().toString().padStart(2, "0")}:${date.getSeconds().toString().padStart(2, "0")}`,
  };
}

export function isDashboardUser(value: unknown): value is DashboardUser {
  if (!isRecord(value)) return false;
  return typeof value.operatorId === "string" && typeof value.fullName === "string" &&
    typeof value.email === "string" && typeof value.position === "string" &&
    typeof value.role === "string" && typeof value.status === "string";
}
