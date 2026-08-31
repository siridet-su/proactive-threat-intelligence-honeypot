export type JsonRecord = Record<string, unknown>;

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
