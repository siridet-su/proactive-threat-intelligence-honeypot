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
  /** Explicit lifecycle signals used by the dashboard status renderer. */
  is_ended?: boolean;
  ended?: boolean;
  end_time?: string | number | null;
  session_status?: string;
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
  /** Current percentage per logical CPU, ordered by core index. */
  cpu_core_percent?: number[] | null;
  /** Canonical memory pressure percentage: (total - available) / total. */
  mem_pressure_percent?: number | string | null;
  /** @deprecated Kept only so older hardware_live.v2 documents remain readable. */
  mem_percent?: number | string | null;
  mem_total_bytes?: number | string | null;
  mem_available_bytes?: number | string | null;
  /** @deprecated Kept only so older hardware_live.v2 documents remain readable. */
  mem_used_bytes?: number | string | null;
  disk_percent?: number | string | null;
  disk_total_bytes?: number | string | null;
  disk_free_bytes?: number | string | null;
  /** @deprecated Derived from disk_total_bytes - disk_free_bytes in new live data. */
  disk_used_bytes?: number | string | null;
  temperature?: number | string | null;
  net_wlan0_rx_mbps?: number | string | null;
  net_wlan0_tx_mbps?: number | string | null;
}

export const hardwareHistoryMetricNames = [
  "cpu_percent",
  "mem_pressure_percent",
  "disk_percent",
  "temperature",
  "net_wlan0_rx_mbps",
  "net_wlan0_tx_mbps",
] as const;

export type HardwareHistoryMetricName = typeof hardwareHistoryMetricNames[number];

export interface HardwareHistoryMetric {
  min: number;
  avg: number;
  max: number;
}

export type HardwareHistoryMetrics = Partial<Record<HardwareHistoryMetricName, HardwareHistoryMetric>>;

export interface HardwareHistoryPoint {
  timestamp: string;
  sample_count: number;
  metrics: HardwareHistoryMetrics;
}

export interface HardwareHistorySeries {
  sensor_id: string;
  points: HardwareHistoryPoint[];
}

export interface HardwareHistoryResponse {
  from: string;
  to: string;
  bucket_seconds: number;
  series: HardwareHistorySeries[];
}

export type HardwareBackupDayStatus = "success" | "failed" | "running" | "missing";

export interface HardwareBackupDay {
  day: string;
  status: HardwareBackupDayStatus;
  document_count: number | null;
  archive_bytes: number | null;
  started_at: string | null;
  completed_at: string | null;
  object_name: string | null;
  error: string | null;
}

export type HardwareBackupRequestAction = "run_missing" | "retry_failed";
export type HardwareBackupRequestStatus = "pending" | "running" | "success" | "failed";

export interface HardwareBackupRequestProgress {
  total_days: number;
  completed_days: number;
  successful_days: number;
  failed_days: number;
  current_day: string | null;
  percent: number;
}

export interface HardwareBackupRequestView {
  id: string;
  source: string;
  action: HardwareBackupRequestAction;
  requested_by: string;
  status: HardwareBackupRequestStatus;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  heartbeat_at: string | null;
  progress: HardwareBackupRequestProgress;
  error: string | null;
}

export interface HardwareBackupStorageStatus {
  source: string;
  bucket: string;
  storage_bytes: number;
  file_versions: number;
  checked_at: string;
}

export interface HardwareBackupStatus {
  can_control: boolean;
  collection: string;
  generated_at: string;
  expected_window: { from: string; to: string; days: number };
  summary: {
    expected_days: number;
    successful_days: number;
    failed_days: number;
    running_days: number;
    missing_days: number;
    archived_documents: number;
    archive_bytes: number;
    latest_success_day: string | null;
    last_started_at: string | null;
    last_completed_at: string | null;
    latest_run_status: HardwareBackupDayStatus | null;
  };
  days: HardwareBackupDay[];
  request: HardwareBackupRequestView | null;
  storage: HardwareBackupStorageStatus | null;
}

function isNullableNumber(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && Number.isFinite(value));
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isHardwareBackupDay(value: unknown): value is HardwareBackupDay {
  if (!isRecord(value)) return false;
  return typeof value.day === "string" &&
    (value.status === "success" || value.status === "failed" || value.status === "running" || value.status === "missing") &&
    isNullableNumber(value.document_count) && isNullableNumber(value.archive_bytes) &&
    isNullableString(value.started_at) && isNullableString(value.completed_at) &&
    isNullableString(value.object_name) && isNullableString(value.error);
}

function isHardwareBackupRequestProgress(value: unknown): value is HardwareBackupRequestProgress {
  if (!isRecord(value)) return false;
  return ["total_days", "completed_days", "successful_days", "failed_days", "percent"].every((key) => (
    typeof value[key] === "number" && Number.isFinite(value[key])
  )) && isNullableString(value.current_day);
}

function isHardwareBackupRequest(value: unknown): value is HardwareBackupRequestView {
  if (!isRecord(value)) return false;
  return typeof value.id === "string" &&
    typeof value.source === "string" &&
    (value.action === "run_missing" || value.action === "retry_failed") &&
    typeof value.requested_by === "string" &&
    (value.status === "pending" || value.status === "running" || value.status === "success" || value.status === "failed") &&
    typeof value.created_at === "string" &&
    isNullableString(value.started_at) &&
    isNullableString(value.completed_at) &&
    isNullableString(value.heartbeat_at) &&
    isHardwareBackupRequestProgress(value.progress) &&
    isNullableString(value.error);
}

function isHardwareBackupStorageStatus(value: unknown): value is HardwareBackupStorageStatus {
  if (!isRecord(value)) return false;
  return typeof value.source === "string" &&
    typeof value.bucket === "string" &&
    typeof value.storage_bytes === "number" && Number.isFinite(value.storage_bytes) &&
    typeof value.file_versions === "number" && Number.isFinite(value.file_versions) &&
    typeof value.checked_at === "string";
}

export function isHardwareBackupStatus(value: unknown): value is HardwareBackupStatus {
  if (!isRecord(value) || typeof value.can_control !== "boolean" || typeof value.collection !== "string" || typeof value.generated_at !== "string" || !isRecord(value.expected_window) || !isRecord(value.summary) || !Array.isArray(value.days)) {
    return false;
  }
  const expectedWindow = value.expected_window;
  const summary = value.summary;
  return typeof expectedWindow.from === "string" && typeof expectedWindow.to === "string" &&
    typeof expectedWindow.days === "number" && Number.isFinite(expectedWindow.days) &&
    typeof summary.expected_days === "number" && Number.isFinite(summary.expected_days) &&
    typeof summary.successful_days === "number" && Number.isFinite(summary.successful_days) &&
    typeof summary.failed_days === "number" && Number.isFinite(summary.failed_days) &&
    typeof summary.running_days === "number" && Number.isFinite(summary.running_days) &&
    typeof summary.missing_days === "number" && Number.isFinite(summary.missing_days) &&
    typeof summary.archived_documents === "number" && Number.isFinite(summary.archived_documents) &&
    typeof summary.archive_bytes === "number" && Number.isFinite(summary.archive_bytes) &&
    isNullableString(summary.latest_success_day) && isNullableString(summary.last_started_at) &&
    isNullableString(summary.last_completed_at) &&
    (summary.latest_run_status === null || summary.latest_run_status === "success" || summary.latest_run_status === "failed" || summary.latest_run_status === "running" || summary.latest_run_status === "missing") &&
    value.days.every(isHardwareBackupDay) &&
    (value.request === null || isHardwareBackupRequest(value.request)) &&
    (value.storage === null || isHardwareBackupStorageStatus(value.storage));
}

function isHardwareHistoryMetric(value: unknown): value is HardwareHistoryMetric {
  if (!isRecord(value)) return false;
  return ["min", "avg", "max"].every((key) => (
    typeof value[key] === "number" && Number.isFinite(value[key])
  ));
}

export function isHardwareHistoryResponse(value: unknown): value is HardwareHistoryResponse {
  if (!isRecord(value)) return false;
  if (
    typeof value.from !== "string" ||
    typeof value.to !== "string" ||
    typeof value.bucket_seconds !== "number" ||
    !Number.isFinite(value.bucket_seconds) ||
    !Array.isArray(value.series)
  ) {
    return false;
  }

  return value.series.every((series) => {
    if (!isRecord(series) || typeof series.sensor_id !== "string" || !Array.isArray(series.points)) {
      return false;
    }
    return series.points.every((point) => {
      if (
        !isRecord(point) ||
        typeof point.timestamp !== "string" ||
        typeof point.sample_count !== "number" ||
        !Number.isFinite(point.sample_count) ||
        !isRecord(point.metrics)
      ) {
        return false;
      }
      return Object.values(point.metrics).every(isHardwareHistoryMetric);
    });
  });
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

/** Complete, server-derived path facts used by Audit filters and counts. */
export interface FilesystemSessionAuditSummary {
  visitedPaths: string[];
  homeOnly: boolean;
  eventCount: number;
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
  auditSummary: FilesystemSessionAuditSummary;
}

/** A session that is no longer live but remains available for CWD audit retention. */
export interface FilesystemClosedSession extends FilesystemTopologySession {
  lifecycle: {
    startedAt: string | null;
    closedAt: string | null;
  };
}

export interface AuditDirectorySummary {
  totalSessions: number;
  homeOnlyCount: number;
  distinctPaths: { path: string; sessionCount: number }[];
  matchingCount?: number;
}

export interface AuditSessionsPage {
  items: FilesystemClosedSession[];
  nextCursor: string | null;
  totalItems: number;
  summary?: AuditDirectorySummary;
}

export interface FilesystemTopologySnapshot {
  nodes: FilesystemTopologyNode[];
  sessions: FilesystemTopologySession[];
  /** Most recently closed, audit-ready sessions. They never appear in the live graph. */
  recentClosedSessions: FilesystemClosedSession[];
  /** True when a bounded live snapshot contains only the most recently observed sessions. */
  truncated: boolean;
  generatedAt: string;
  /**
   * Authoritative timestamp of the latest session observation or closure in this snapshot,
   * or null if no session telemetry has been observed.
   */
  latestTelemetryAt?: string | null;
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
  /** 1-based chronological index within the complete retained session route. */
  hopNumber?: number;
  /** 1-based chronological index excluding failed_change attempts. */
  successfulHopNumber?: number;
}

export interface SessionCwdHistoryPage {
  items: SessionCwdHistoryEvent[];
  nextCursor: string | null;
  /** Total retained CWD events for this session, independent of pagination. */
  totalItems: number;
  /** Retained events excluding failed directory-change attempts. */
  totalSuccessfulItems: number;
  /** True when this response reaches the oldest retained event. */
  complete: boolean;
}

/** One sampled action for a (session, phase, attacker_type) — see deception-core `session_action`. */
export interface DeceptionAction {
  phase: string;
  attacker_type: string;
  action: string;
  at: string;
}

/** One decoy file served to the attacker and the fake content injected into it. */
export interface DeceptionLure {
  door: string;
  target: string;
  tier: number;
  content_type: string;
  content: string;
  at: string;
}

/** One document per attacker IP, synced from Pi SQLite deception-core into `honeypot_db.deception_decisions`. */
export interface DeceptionDecision {
  ip: string;
  session_id: string;
  attacker_type: string;
  attacker_type_locked: boolean;
  phase: string;
  command_count: number;
  first_seen: string;
  last_seen: string;
  actions: DeceptionAction[];
  lures: DeceptionLure[];
  synced_at: string;
}

// ============================================================================
// Type Guards & Utility Functions
// ============================================================================

/**
 * ตรวจสอบว่าค่าที่รับมาเป็น Object พื้นฐาน (Record) หรือไม่
 * โดยต้องไม่เป็น null และไม่ใช่ Array
 * 
 * @param {unknown} value - ค่าที่ต้องการตรวจสอบ
 * @returns {boolean} - true หากเป็น Record
 */
function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * ตรวจสอบว่าค่าที่รับมาเป็นประเภท String หรือ Number
 * 
 * @param {unknown} value - ค่าที่ต้องการตรวจสอบ
 * @returns {boolean} - true หากเป็น string หรือ number
 */
function isStringOrNumber(value: unknown): value is string | number {
  return typeof value === "string" || typeof value === "number";
}

/**
 * ตรวจสอบโครงสร้างข้อมูลพิกัดภูมิศาสตร์ (Geo)
 * 
 * @param {unknown} value - ข้อมูลที่คาดว่าเป็น DashboardThreatGeo
 * @returns {boolean} - true หากมีโครงสร้างที่ถูกต้อง
 */
function isGeo(value: unknown): value is DashboardThreatGeo {
  if (!isRecord(value)) return false;
  return typeof value.lat === "number" && typeof value.lon === "number" &&
    typeof value.country === "string" && typeof value.city === "string";
}

/**
 * ตรวจสอบข้อมูลความน่าเชื่อถือของ IP จาก AbuseIPDB
 * 
 * @param {unknown} value - ข้อมูล AbuseIPDB
 * @returns {boolean} - true หากข้อมูลถูกต้องหรือเป็น optional (ว่างเปล่า)
 */
function isAbuseIpdb(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (!isRecord(value)) return false;
  return value.abuseConfidenceScore === undefined || typeof value.abuseConfidenceScore === "number";
}

/**
 * ตรวจสอบข้อมูลสถิติจาก VirusTotal
 * 
 * @param {unknown} value - ข้อมูล VirusTotal
 * @returns {boolean} - true หากข้อมูลถูกต้องหรือเป็น optional (ว่างเปล่า)
 */
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

/**
 * ตรวจสอบโครงสร้างของข้อมูลภัยคุกคาม (DashboardThreatEvent) ว่าครบถ้วนหรือไม่
 * 
 * @param {unknown} value - ข้อมูลที่ต้องการตรวจสอบ
 * @returns {boolean} - true หากเป็น DashboardThreatEvent ที่สมบูรณ์
 */
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

/**
 * แปลงข้อมูลเวลาของ Hardware เป็น Epoch timestamp (ตัวเลขมิลลิวินาที)
 * 
 * @param {unknown} value - วันที่ (Date, number, หรือ string)
 * @returns {number | null} - Epoch timestamp หรือ null หากแปลงไม่ได้
 */
function hardwareTimestampEpoch(value: unknown): number | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.getTime() : null;
  if (typeof value === "number") return Number.isFinite(value) ? new Date(value).getTime() : null;
  if (typeof value === "string" && value.trim()) {
    const timestamp = new Date(value).getTime();
    return Number.isFinite(timestamp) ? timestamp : null;
  }
  return null;
}

/**
 * ตรวจสอบว่าค่า Metric ของ Hardware เป็นตัวเลขที่ใช้งานได้หรือไม่
 * 
 * @param {unknown} value - ค่า Metric
 * @returns {boolean} - true หากเป็นตัวเลขหรือแปลงเป็นตัวเลขได้
 */
function isHardwareMetric(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value === "number") return Number.isFinite(value);
  return typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value));
}

function isHardwareMetricList(value: unknown): boolean {
  return value === undefined || value === null || (Array.isArray(value) && value.length > 0 && value.every(isHardwareMetric));
}

/**
 * ตรวจสอบโครงสร้างข้อมูล Telemetry ของ Hardware (เช่น CPU, RAM)
 * 
 * @param {unknown} value - ข้อมูลที่ต้องการตรวจสอบ
 * @returns {boolean} - true หากโครงสร้างถูกต้อง
 */
export function isHardwareTelemetry(value: unknown): value is HardwareTelemetry {
  if (!isRecord(value)) return false;
  return hardwareTimestampEpoch(value.timestamp) !== null && isHardwareMetric(value.cpu_percent) &&
    isHardwareMetricList(value.cpu_core_percent) &&
    isHardwareMetric(value.mem_pressure_percent) &&
    isHardwareMetric(value.mem_percent) && isHardwareMetric(value.disk_percent) &&
    isHardwareMetric(value.mem_total_bytes) && isHardwareMetric(value.mem_available_bytes) && isHardwareMetric(value.mem_used_bytes) &&
    isHardwareMetric(value.disk_total_bytes) && isHardwareMetric(value.disk_free_bytes) && isHardwareMetric(value.disk_used_bytes) &&
    isHardwareMetric(value.temperature) && isHardwareMetric(value.net_wlan0_rx_mbps) &&
    isHardwareMetric(value.net_wlan0_tx_mbps);
}

/**
 * ตรวจสอบและแยกประเภท Message ที่ได้จาก Hardware Stream (Initial หรือ Update)
 * 
 * @param {unknown} value - Message ดิบจาก Stream
 * @returns {HardwareStreamMessage | null} - Message ที่ถูกจัดประเภทแล้ว หรือ null หากผิดพลาด
 */
export function parseHardwareStreamMessage(value: unknown): HardwareStreamMessage | null {
  if (!isRecord(value) || (value.type !== "initial" && value.type !== "update")) return null;
  if (value.type === "initial") {
    if (!Array.isArray(value.data)) return null;
    return { type: "initial", data: value.data.filter(isHardwareTelemetry) };
  }
  return isHardwareTelemetry(value.data) ? { type: "update", data: value.data } : null;
}

/**
 * ตรวจสอบและแยกประเภท Message ที่ได้จาก Threat Stream
 * 
 * @param {unknown} value - Message ดิบจาก Stream
 * @returns {ThreatStreamMessage | null} - Message ที่ถูกต้อง หรือ null
 */
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

/**
 * จัดรูปแบบข้อมูล Hardware Metric ให้พร้อมสำหรับการนำไปแสดงผลบน Chart
 * 
 * @param {HardwareTelemetry} metric - ข้อมูล Telemetry ต้นฉบับ
 * @returns {HardwareChartRecord} - ข้อมูลที่จัดรูปแบบเวลาและแปลงเป็นตัวเลขแล้ว
 */
export function formatHardwareMetric(metric: HardwareTelemetry): HardwareChartRecord {
  const timestampEpoch = hardwareTimestampEpoch(metric.timestamp) ?? 0;
  const date = new Date(timestampEpoch);
  return {
    ...metric,
    cpu_percent: numericHardwareMetric(metric.cpu_percent),
    cpu_core_percent: numericHardwareMetricList(metric.cpu_core_percent),
    mem_pressure_percent: numericHardwareMetric(metric.mem_pressure_percent),
    mem_percent: numericHardwareMetric(metric.mem_percent),
    mem_total_bytes: numericHardwareMetric(metric.mem_total_bytes),
    mem_available_bytes: numericHardwareMetric(metric.mem_available_bytes),
    mem_used_bytes: numericHardwareMetric(metric.mem_used_bytes),
    disk_percent: numericHardwareMetric(metric.disk_percent),
    disk_total_bytes: numericHardwareMetric(metric.disk_total_bytes),
    disk_free_bytes: numericHardwareMetric(metric.disk_free_bytes),
    disk_used_bytes: numericHardwareMetric(metric.disk_used_bytes),
    temperature: numericHardwareMetric(metric.temperature),
    net_wlan0_rx_mbps: numericHardwareMetric(metric.net_wlan0_rx_mbps),
    net_wlan0_tx_mbps: numericHardwareMetric(metric.net_wlan0_tx_mbps),
    timestampEpoch,
    time: `${date.getHours()}:${date.getMinutes().toString().padStart(2, "0")}:${date.getSeconds().toString().padStart(2, "0")}`,
  };
}

/**
 * แปลงค่าที่คาดว่าจะเป็นตัวเลขให้เป็น Number
 * 
 * @param {unknown} value - ค่าที่ต้องการแปลง
 * @returns {number | null} - ตัวเลข หรือ null หากไม่ใช่ตัวเลขที่ใช้งานได้
 */
export function numericHardwareMetric(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  // ดักจับสตริงว่างหรือช่องว่างเปล่าๆ ป้องกัน JavaScript แปลงค่า "" เป็น 0
  if (typeof value === "string" && value.trim() === "") return null;
  
  const numberValue = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numberValue) ? numberValue : null;
}

export function numericHardwareMetricList(value: unknown): number[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const metrics = value.map(numericHardwareMetric);
  return metrics.every((metric): metric is number => metric !== null) ? metrics : null;
}

/**
 * ตรวจสอบโครงสร้างข้อมูลของ DashboardUser (ผู้ดูแลระบบ)
 * 
 * @param {unknown} value - ข้อมูลที่ต้องการตรวจสอบ
 * @returns {boolean} - true หากมีโครงสร้างที่ถูกต้อง
 */
export function isDashboardUser(value: unknown): value is DashboardUser {
  if (!isRecord(value)) return false;
  return typeof value.operatorId === "string" && typeof value.fullName === "string" &&
    typeof value.email === "string" && typeof value.position === "string" &&
    typeof value.role === "string" && typeof value.status === "string";
}

function isDeceptionAction(value: unknown): value is DeceptionAction {
  if (!isRecord(value)) return false;
  return typeof value.phase === "string" && typeof value.attacker_type === "string" &&
    typeof value.action === "string" && typeof value.at === "string";
}

function isDeceptionLure(value: unknown): value is DeceptionLure {
  if (!isRecord(value)) return false;
  return typeof value.door === "string" && typeof value.target === "string" &&
    typeof value.tier === "number" && typeof value.content_type === "string" &&
    typeof value.content === "string" && typeof value.at === "string";
}

export function isDeceptionDecision(value: unknown): value is DeceptionDecision {
  if (!isRecord(value)) return false;
  return typeof value.ip === "string" && typeof value.session_id === "string" &&
    typeof value.attacker_type === "string" && typeof value.attacker_type_locked === "boolean" &&
    typeof value.phase === "string" && typeof value.command_count === "number" &&
    typeof value.first_seen === "string" && typeof value.last_seen === "string" &&
    typeof value.synced_at === "string" &&
    Array.isArray(value.actions) && value.actions.every(isDeceptionAction) &&
    Array.isArray(value.lures) && value.lures.every(isDeceptionLure);
}
