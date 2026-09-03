export type JsonRecord = Record<string, unknown>;

export interface DashboardAbuseIpdbSummary {
  abuseConfidenceScore?: number;
  isp?: string | null;
}

export interface DashboardVirusTotalSummary {
  attributes?: {
    meaningful_name?: string | null;
    stats?: {
      malicious?: number;
      undetected?: number;
    };
  };
}

export interface DashboardThreatGeo {
  lat: number;
  lon: number;
  country: string;
  city: string;
}

/** The stable response shape emitted by /api/threats for dashboard clients. */
export interface DashboardThreatEvent {
  id: string;
  timestamp: string | number;
  sensor: string;
  event_type: string;
  src_ip: string;
  sourceIp: string;
  protocol: string;
  payloadPreview: string;
  severity: string;
  abuseipdb?: DashboardAbuseIpdbSummary | null;
  virustotal?: DashboardVirusTotalSummary | null;
  geo: DashboardThreatGeo;
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

/** Raw hardware documents retain additional agent-specific metrics. */
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

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringOrNumber(value: unknown): value is string | number {
  return typeof value === "string" || typeof value === "number";
}

function isOptionalNumber(value: unknown): boolean {
  return value === undefined || typeof value === "number";
}

function isOptionalString(value: unknown): boolean {
  return value === undefined || value === null || typeof value === "string";
}

function isOptionalMetricValue(value: unknown): boolean {
  return value === undefined || value === null || isStringOrNumber(value) || value instanceof Date;
}

function isValidThreatGeo(value: unknown): value is DashboardThreatGeo {
  if (!isRecord(value)) return false;
  return (
    typeof value.lat === "number" &&
    typeof value.lon === "number" &&
    typeof value.country === "string" &&
    typeof value.city === "string"
  );
}

function isValidAbuseIpdb(value: unknown): value is DashboardAbuseIpdbSummary {
  if (!isRecord(value)) return false;
  return isOptionalNumber(value.abuseConfidenceScore) && isOptionalString(value.isp);
}

function isValidVirusTotal(value: unknown): value is DashboardVirusTotalSummary {
  if (!isRecord(value)) return false;
  if (value.attributes === undefined || value.attributes === null) return true;
  if (!isRecord(value.attributes)) return false;
  if (!isOptionalString(value.attributes.meaningful_name)) return false;
  if (value.attributes.stats === undefined || value.attributes.stats === null) return true;
  if (!isRecord(value.attributes.stats)) return false;
  return (
    isOptionalNumber(value.attributes.stats.malicious) &&
    isOptionalNumber(value.attributes.stats.undetected)
  );
}

export function isDashboardThreatEvent(value: unknown): value is DashboardThreatEvent {
  if (!isRecord(value)) return false;
  return (
    typeof value.id === "string" &&
    isStringOrNumber(value.timestamp) &&
    typeof value.sensor === "string" &&
    typeof value.event_type === "string" &&
    typeof value.src_ip === "string" &&
    typeof value.sourceIp === "string" &&
    typeof value.protocol === "string" &&
    typeof value.payloadPreview === "string" &&
    typeof value.severity === "string" &&
    isValidThreatGeo(value.geo) &&
    (value.abuseipdb === undefined || value.abuseipdb === null || isValidAbuseIpdb(value.abuseipdb)) &&
    (value.virustotal === undefined || value.virustotal === null || isValidVirusTotal(value.virustotal))
  );
}

export function isHardwareTelemetry(value: unknown): value is HardwareTelemetry {
  if (!isRecord(value)) return false;
  return (
    isOptionalMetricValue(value.timestamp) &&
    isOptionalMetricValue(value.cpu_percent) &&
    isOptionalMetricValue(value.mem_percent) &&
    isOptionalMetricValue(value.disk_percent) &&
    isOptionalMetricValue(value.temperature) &&
    isOptionalMetricValue(value.net_wlan0_rx_mbps) &&
    isOptionalMetricValue(value.net_wlan0_tx_mbps)
  );
}

export function parseHardwareStreamMessage(value: unknown): HardwareStreamMessage | null {
  if (!isRecord(value) || (value.type !== "initial" && value.type !== "update")) return null;
  if (value.type === "initial") {
    if (!Array.isArray(value.data)) return null;
    return {
      type: "initial",
      data: value.data.filter(isHardwareTelemetry),
    };
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

export interface GeoPoint {
  latitude?: number;
  longitude?: number;
  city?: string;
  country?: string;
  country_code?: string;
  [key: string]: unknown;
}

export interface SessionOverview {
  session_id?: string;
  sensor?: string;
  sensor_id?: string;
  src_ip?: string;
  src_ip_is_public?: boolean;
  src_ip_scope?: string;
  geo?: GeoPoint;
  source_geo?: GeoPoint;
  start_time?: string;
  updated_at?: string;
  duration?: string | number;
  ended?: boolean;
  is_ended?: boolean;
  command_count?: number;
  tactics?: string[];
  ttps?: string[];
  analysis_status?: string;
  job_status?: string;
  report_id?: string;
  [key: string]: unknown;
}

export interface SessionsSummary {
  total_sessions?: number;
  shown_sessions?: number;
  session_limit?: number;
  session_offset?: number;
  active_sessions?: number;
  queued_jobs?: number;
  succeeded_reports?: number;
  skipped_no_command_sessions?: number;
  latest_updated?: string;
  [key: string]: unknown;
}

export interface SessionsResponse {
  ok?: boolean;
  timestamp?: string;
  summary?: SessionsSummary;
  sessions?: SessionOverview[];
  selected_session_id?: string | null;
  error?: string;
}

export interface EventView {
  timestamp?: string;
  received_at?: string;
  event_id?: string;
  eventid?: string;
  session?: string;
  session_id?: string;
  sensor?: string;
  sensor_id?: string;
  src_ip?: string;
  src_ip_is_public?: boolean;
  command_event?: boolean;
  [key: string]: unknown;
}

export interface EventsResponse {
  ok?: boolean;
  timestamp?: string;
  events?: EventView[];
  error?: string;
}

export interface TableResponse<T extends JsonRecord = JsonRecord> {
  items?: T[];
  limit?: number;
  table?: string;
  timestamp?: string;
  error?: string;
}

export interface AlertRow extends JsonRecord {
  severity?: string;
  created_at?: string;
  updated_at?: string;
  authority_display?: string;
}

export interface JobRow extends JsonRecord {
  status?: string;
  updated_at?: string;
  created_at?: string;
}

export interface SessionDetail {
  ok?: boolean;
  timestamp?: string;
  session_id?: string;
  overview?: SessionOverview;
  source_geo?: GeoPoint;
  source_geo_context?: JsonRecord;
  observables?: Array<{ type?: string; value?: string }>;
  commands?: unknown[];
  classification_events?: JsonRecord[];
  observed_trusted_ttps?: unknown[];
  correlated_ttp_hypotheses?: JsonRecord[];
  session_ttp_correlations?: JsonRecord[];
  session_ttp_correlation_summary?: JsonRecord;
  tactics?: string[];
  ttps?: string[];
  prediction_snapshots?: JsonRecord[];
  latest_prediction_snapshot?: JsonRecord;
  analyst_feedback?: JsonRecord[];
  analysis_jobs?: JsonRecord[];
  reports?: JsonRecord[];
  report_summary?: JsonRecord;
  response_guidance?: JsonRecord;
  errors?: JsonRecord;
  session?: JsonRecord;
  events?: EventView[];
  error?: string;
}

export interface PredictionResponse {
  item?: JsonRecord;
  current_prediction?: JsonRecord;
  response_guidance?: JsonRecord;
  session_id?: string;
  timestamp?: string;
  error?: string;
}

export interface AiAdvisoryResponse {
  ok?: boolean;
  status?: string;
  session_id?: string;
  advisory?: JsonRecord;
  metrics?: JsonRecord;
  timestamp?: string;
  error?: string;
}

export interface HealthResponse {
  ok?: boolean;
  service?: string;
  timestamp?: string;
  error?: string;
}
