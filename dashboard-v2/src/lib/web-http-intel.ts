/** Read-side, non-authoritative HTTP hints for the existing web-corp login lane. */
export type WebHttpHint = {
  eventId: string;
  observedAt: string;
  sourceIp: string;
  method: string;
  outcome: "rejected" | "unknown";
  signals: Array<"sqli" | "xss">;
  ruleIds: string[];
  ttpCandidate: "T1190" | null;
  authority: "contextual_rule_hint_only";
  modelPrediction: false;
  exploitConfirmed: false;
};

const SQLI_RULES = new Set([
  "sql_comment", "union_select", "boolean_tautology", "time_delay",
  "database_metadata", "stacked_statement", "sql_keyword",
]);

const XSS_PATTERNS: ReadonlyArray<[string, RegExp]> = [
  ["xss_script_tag", /<\s*script\b/i],
  ["xss_event_handler", /<\s*[a-z][^>]{0,128}\bon(?:error|load|click|focus)\s*=/i],
  ["xss_javascript_scheme", /\bjavascript\s*:/i],
];

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

function boundedString(value: unknown, limit: number): string {
  return typeof value === "string" ? value.slice(0, limit) : "";
}

function decodedOnce(value: string): string {
  try { return decodeURIComponent(value.replace(/\+/g, " ")); }
  catch { return value; }
}

export function projectWebHttpEvent(value: unknown): WebHttpHint | null {
  const event = record(value);
  if (event.source !== "web-corp" || event.event_type !== "web_login_attempt") return null;
  const id = boundedString(event.event_id, 128);
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id)) return null;
  const analysis = record(event.analysis);
  const sqli = record(record(analysis.sqli).indicators);
  const matched = new Set<string>();
  for (const value of Object.values(sqli)) {
    if (!Array.isArray(value)) continue;
    for (const name of value) if (typeof name === "string" && SQLI_RULES.has(name)) matched.add(`sqli_${name}`);
  }
  const http = record(event.http);
  // Only URL components are read for XSS hints. Never inspect or return login
  // values, raw payloads, cookies, query strings, or submitted passwords.
  const urlText = decodedOnce(`${boundedString(http.path, 512)} ${boundedString(http.query, 512)}`);
  for (const [name, pattern] of XSS_PATTERNS) if (pattern.test(urlText)) matched.add(name);
  const ruleIds = [...matched].sort();
  const signals: WebHttpHint["signals"] = [];
  if (ruleIds.some((name) => name.startsWith("sqli_"))) signals.push("sqli");
  if (ruleIds.some((name) => name.startsWith("xss_"))) signals.push("xss");
  const network = record(event.network);
  const sourceIp = boundedString(network.src_ip, 45);
  const method = boundedString(http.method, 8).toUpperCase();
  const timestamp = event.timestamp;
  return {
    eventId: id,
    observedAt: timestamp instanceof Date ? timestamp.toISOString() : boundedString(timestamp, 40),
    sourceIp: /^[0-9a-fA-F:.]{2,45}$/.test(sourceIp) ? sourceIp : "unavailable",
    method: /^(GET|POST|PUT|PATCH|DELETE)$/.test(method) ? method : "UNKNOWN",
    outcome: event.outcome === "rejected" ? "rejected" : "unknown",
    signals,
    ruleIds,
    ttpCandidate: signals.length ? "T1190" : null,
    authority: "contextual_rule_hint_only",
    modelPrediction: false,
    exploitConfirmed: false,
  };
}
