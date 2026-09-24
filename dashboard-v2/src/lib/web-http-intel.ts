/** Read-side, non-authoritative HTTP hints for the web-corp event lane. */
export type WebHttpRuleMatch = {
  signal: "sqli" | "xss";
  field: "database" | "login" | "password" | "redirect" | "query" | "path";
  ruleId: string;
};
export type WebHttpHint = {
  eventId: string;
  sessionId: string | null;
  eventType: "web_login_attempt" | "web_http_request";
  observedAt: string;
  sourceIp: string;
  method: string;
  path: string;
  statusCode: number | null;
  outcome: "rejected" | "unknown";
  signals: Array<"sqli" | "xss">;
  ruleIds: string[];
  matches: WebHttpRuleMatch[];
  ttpCandidate: "T1190" | null;
  authority: "contextual_rule_hint_only";
  modelPrediction: false;
  exploitConfirmed: false;
};

const SQLI_RULES = new Set([
  "sql_comment", "union_select", "boolean_tautology", "time_delay",
  "database_metadata", "stacked_statement", "sql_keyword",
]);

const XSS_RULES = new Set(["script_tag", "event_handler", "javascript_scheme", "svg_script"]);
const FIELDS = new Set(["database", "login", "password", "redirect", "query", "path"]);

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

function boundedString(value: unknown, limit: number): string {
  return typeof value === "string" ? value.slice(0, limit) : "";
}

export function projectWebHttpEvent(value: unknown): WebHttpHint | null {
  const event = record(value);
  if (event.source !== "web-corp" ||
      (event.event_type !== "web_login_attempt" && event.event_type !== "web_http_request")) return null;
  const id = boundedString(event.event_id, 128);
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id)) return null;
  const analysis = record(event.analysis);
  const sqli = record(record(analysis.sqli).indicators);
  const xss = record(record(analysis.xss).indicators);
  const matches: WebHttpRuleMatch[] = [];
  for (const [signal, indicators, allowed] of [
    ["sqli", sqli, SQLI_RULES], ["xss", xss, XSS_RULES],
  ] as const) {
    for (const [field, values] of Object.entries(indicators)) {
      if (!FIELDS.has(field) || !Array.isArray(values)) continue;
      for (const name of values) {
        if (typeof name === "string" && allowed.has(name)) {
          const candidate = { signal, field: field as WebHttpRuleMatch["field"], ruleId: name };
          if (!matches.some((item) => item.signal === signal && item.field === field && item.ruleId === name)) matches.push(candidate);
        }
      }
    }
  }
  matches.sort((a, b) => `${a.signal}.${a.field}.${a.ruleId}`.localeCompare(`${b.signal}.${b.field}.${b.ruleId}`));
  const http = record(event.http);
  // Trust only sensor-computed rule names. Never read submitted values, URL
  // query, cookies, or raw payloads in the dashboard read path.
  const ruleIds = [...new Set(matches.map((item) => `${item.signal}_${item.ruleId}`))].sort();
  const signals: WebHttpHint["signals"] = [];
  if (ruleIds.some((name) => name.startsWith("sqli_"))) signals.push("sqli");
  if (ruleIds.some((name) => name.startsWith("xss_"))) signals.push("xss");
  const network = record(event.network);
  const sourceIp = boundedString(network.src_ip, 45);
  const method = boundedString(http.method, 8).toUpperCase();
  const rawPath = boundedString(http.path, 128);
  const path = /^\/[A-Za-z0-9_./-]{0,127}$/.test(rawPath) ? rawPath : "[redacted-path]";
  const rawStatus = http.status_code;
  const statusCode = typeof rawStatus === "number" && Number.isInteger(rawStatus) && rawStatus >= 100 && rawStatus <= 599 ? rawStatus : null;
  const sessionId = boundedString(record(event.correlation).web_session_id, 32);
  const timestamp = event.timestamp;
  return {
    eventId: id,
    sessionId: /^[a-f0-9]{32}$/.test(sessionId) ? sessionId : null,
    eventType: event.event_type,
    observedAt: timestamp instanceof Date ? timestamp.toISOString() : boundedString(timestamp, 40),
    sourceIp: /^[0-9a-fA-F:.]{2,45}$/.test(sourceIp) ? sourceIp : "unavailable",
    method: /^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(method) ? method : "UNKNOWN",
    path,
    statusCode,
    outcome: event.outcome === "rejected" ? "rejected" : "unknown",
    signals,
    ruleIds,
    matches,
    ttpCandidate: signals.length ? "T1190" : null,
    authority: "contextual_rule_hint_only",
    modelPrediction: false,
    exploitConfirmed: false,
  };
}

export type WebHttpSession = {
  id: string | null;
  events: WebHttpHint[];
  firstObservedAt: string;
  lastObservedAt: string;
  sourceIps: string[];
};

export function groupWebHttpSessions(items: WebHttpHint[]): WebHttpSession[] {
  const groups = new Map<string, WebHttpHint[]>();
  for (const item of items) {
    // A legacy event with no sensor-issued session ID must stay separate;
    // never infer a join from IP, username, or User-Agent.
    const key = item.sessionId ?? `unlinked:${item.eventId}`;
    groups.set(key, [...(groups.get(key) ?? []), item]);
  }
  return [...groups.entries()].map(([key, events]) => {
    events.sort((a, b) => a.observedAt.localeCompare(b.observedAt) || a.eventId.localeCompare(b.eventId));
    return {
      id: key.startsWith("unlinked:") ? null : key,
      events,
      firstObservedAt: events[0]?.observedAt ?? "",
      lastObservedAt: events.at(-1)?.observedAt ?? "",
      sourceIps: [...new Set(events.map((item) => item.sourceIp))].sort(),
    };
  }).sort((a, b) => b.lastObservedAt.localeCompare(a.lastObservedAt));
}
