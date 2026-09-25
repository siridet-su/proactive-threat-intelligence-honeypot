import "server-only";

import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import type { Document } from "mongodb";

import {
  authenticatedSensorSessionAlias,
  CANONICAL_SESSION_ID_PATTERN,
  isValidSensorSessionIdentifier,
  parseStoredCanonicalEvent,
} from "@/lib/sensor-session-identity";
import { getMongoClient } from "@/lib/mongodb";

const MAX_TOKEN_BYTES = 4_096;
const MAX_UPSTREAM_BYTES = 1_000_000;
const MAX_COMMANDS = 100;
const MAX_COMMAND_INPUT_BYTES = 4_096;
const UPSTREAM_TIMEOUT_MS = 4_000;
const IDENTITY_LOOKUP_TIMEOUT_MS = 20_000;
const CANONICAL_EVENT_SCHEMA = "mongodb_canonical_event.v1";
const COMMAND_EVENT_IDS = new Set([
  "cowrie.command.failed",
  "cowrie.command.input",
  "cowrie.command.success",
]);
const SESSION_IDENTITY_EVENT_IDS = [
  "cowrie.session.closed",
  "cowrie.session.connect",
  "cowrie.session.cwd",
  "cowrie.session.params",
];

type JsonRecord = Record<string, unknown>;

export interface AdminCowrieCommand {
  event_id: string;
  eventid: string;
  timestamp: string | null;
  input: string;
  command_text_available: boolean;
  input_truncated: boolean;
  classification: Array<{
    evidence_id?: string;
    ttp?: string;
    tactic?: string;
    source?: string;
    command_outcome?: string;
    evidence_tier?: string;
  }>;
}

export interface AdminCowrieCommandProjection {
  ok: true;
  schema_version: "dashboard.admin_cowrie_commands.v1";
  session_id: string;
  sensitive: true;
  content_scope: "administrator_only_cowrie_command_input";
  historical_originals: "unrecoverable_if_redacted_before_persistence";
  commands: AdminCowrieCommand[];
  truncated: boolean;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Resolve a Filesystem Activity sensor-local ID to its canonical identity.
 * Only canonical event rows with an authenticated identity binding can establish
 * the alias; missing or ambiguous mappings fail closed.
 */
export async function resolveCanonicalSessionIdForCommandEvidence(sessionId: string): Promise<string | null> {
  if (CANONICAL_SESSION_ID_PATTERN.test(sessionId)) return sessionId;
  if (!isValidSensorSessionIdentifier(sessionId)) return null;

  // Match the JSON-encoded value exactly. Search only session metadata event
  // types so the identity lookup never loads command-input event payloads.
  const jsonValue = JSON.stringify(sessionId).slice(1, -1);
  const sensorAliasPattern = new RegExp(`"sensor_session_id"\\s*:\\s*"${escapeRegExp(jsonValue)}"`);
  const client = await getMongoClient();
  const candidates = await client.db("honeypot_canonical_v1").collection<Document>("events")
    .aggregate<Document>([
      {
        $match: {
          schema_version: CANONICAL_EVENT_SCHEMA,
          session_id: { $regex: CANONICAL_SESSION_ID_PATTERN.source },
          eventid: { $in: SESSION_IDENTITY_EVENT_IDS },
          payload_json: { $regex: sensorAliasPattern },
        },
      },
      {
        $group: {
          _id: "$session_id",
          sensor_id: { $first: "$sensor_id" },
          payload_json: { $first: "$payload_json" },
        },
      },
      { $limit: 2 },
    ], { maxTimeMS: IDENTITY_LOOKUP_TIMEOUT_MS })
    .toArray();

  if (candidates.length !== 1) return null;
  const candidate = candidates[0];
  const canonicalSessionId = candidate?._id;
  if (typeof canonicalSessionId !== "string" || !CANONICAL_SESSION_ID_PATTERN.test(canonicalSessionId)) {
    return null;
  }

  const event = parseStoredCanonicalEvent(candidate.payload_json);
  return authenticatedSensorSessionAlias(canonicalSessionId, event, candidate.sensor_id) === sessionId
    ? canonicalSessionId
    : null;
}

function tokenFromPrivateFile(configuredPath: string): string | null {
  const tokenPath = configuredPath.trim();
  if (!tokenPath || !isAbsolute(tokenPath)) return null;
  try {
    const stat = lstatSync(/* turbopackIgnore: true */ tokenPath);
    if (!stat.isFile() || stat.isSymbolicLink() || (process.platform !== "win32" && (stat.mode & 0o077) !== 0) || stat.size > MAX_TOKEN_BYTES) return null;
    const token = readFileSync(/* turbopackIgnore: true */ tokenPath, { encoding: "utf8", flag: "r" }).trim();
    if (token.length < 32 || Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES || /[\s\u0000-\u001f\u007f]/u.test(token)) return null;
    return token;
  } catch {
    return null;
  }
}

function monitorCommandsEndpoint(): URL {
  const configured = process.env.DASHBOARD_MONITOR_BASE_URL?.trim() || "http://127.0.0.1:8090";
  const base = new URL(configured);
  if (
    base.protocol !== "http:"
    || base.hostname !== "127.0.0.1"
    || base.username
    || base.password
    || base.search
    || base.hash
  ) {
    throw new Error("private monitor endpoint is not loopback-only");
  }
  return new URL("/api/internal/session-commands", base);
}

function boundedText(value: unknown, maximum = 256): string | undefined {
  return typeof value === "string" && value.length > 0 && value.length <= maximum
    ? value
    : undefined;
}

function boundedInput(value: unknown): { input: string; truncated: boolean } | null {
  if (typeof value !== "string") return null;
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength <= MAX_COMMAND_INPUT_BYTES) return { input: value, truncated: false };

  const decoder = new TextDecoder("utf-8", { fatal: true });
  let end = MAX_COMMAND_INPUT_BYTES;
  while (end > 0) {
    try {
      return {
        input: `${decoder.decode(bytes.subarray(0, end))}\n...[truncated at ${MAX_COMMAND_INPUT_BYTES} UTF-8 bytes]`,
        truncated: true,
      };
    } catch {
      end -= 1;
    }
  }
  return { input: `...[truncated at ${MAX_COMMAND_INPUT_BYTES} UTF-8 bytes]`, truncated: true };
}

function projectUpstreamCommands(sessionId: string, payload: JsonRecord): AdminCowrieCommandProjection {
  if (
    payload.ok !== true
    || payload.schema_version !== "monitor.internal_command_view.v1"
    || payload.sensitive !== true
    || payload.session_id !== sessionId
    || !Array.isArray(payload.commands)
  ) {
    throw new Error("private monitor response failed its closed contract");
  }

  const seenEventIds = new Set<string>();
  const commands: AdminCowrieCommand[] = [];
  let truncated = payload.truncated === true;
  for (const candidate of payload.commands) {
    if (!isRecord(candidate)) throw new Error("private monitor command record is invalid");
    const event_id = boundedText(candidate.event_id);
    const eventid = typeof candidate.eventid === "string" ? candidate.eventid.toLowerCase() : "";
    const input = boundedInput(candidate.input);
    if (
      !event_id
      || seenEventIds.has(event_id)
      || !COMMAND_EVENT_IDS.has(eventid)
      || input === null
    ) {
      throw new Error("private monitor command identity is invalid");
    }
    seenEventIds.add(event_id);
    truncated = truncated || input.truncated;

    const classifications = Array.isArray(candidate.classification)
      ? candidate.classification.slice(0, 8).filter(isRecord).map((item) => ({
          ...(boundedText(item.evidence_id) ? { evidence_id: boundedText(item.evidence_id) } : {}),
          ...(boundedText(item.ttp, 64) ? { ttp: boundedText(item.ttp, 64) } : {}),
          ...(boundedText(item.tactic, 64) ? { tactic: boundedText(item.tactic, 64) } : {}),
          ...(boundedText(item.source, 64) ? { source: boundedText(item.source, 64) } : {}),
          ...(boundedText(item.command_outcome, 64) ? { command_outcome: boundedText(item.command_outcome, 64) } : {}),
          ...(boundedText(item.evidence_tier, 64) ? { evidence_tier: boundedText(item.evidence_tier, 64) } : {}),
        }))
      : [];
    const timestamp = typeof candidate.timestamp === "string" && candidate.timestamp.length <= 64
      ? candidate.timestamp
      : null;
    commands.push({
      event_id,
      eventid,
      timestamp,
      input: input.input,
      command_text_available: input.input.trim().length > 0 && input.input.trim() !== "[REDACTED]",
      input_truncated: input.truncated,
      classification: classifications,
    });
  }

  return {
    ok: true,
    schema_version: "dashboard.admin_cowrie_commands.v1",
    session_id: sessionId,
    sensitive: true,
    content_scope: "administrator_only_cowrie_command_input",
    historical_originals: "unrecoverable_if_redacted_before_persistence",
    commands: commands.slice(0, MAX_COMMANDS),
    truncated: truncated || commands.length > MAX_COMMANDS,
  };
}

/** Fetch a narrow raw-command projection through the monitor's loopback-only credential gate. */
export async function loadAdminCowrieCommands(sessionId: string): Promise<AdminCowrieCommandProjection> {
  if (!CANONICAL_SESSION_ID_PATTERN.test(sessionId)) throw new TypeError("invalid canonical session identifier");
  const tokenFile = process.env.MONITOR_RAW_COMMANDS_TOKEN_FILE;
  const token = tokenFile ? tokenFromPrivateFile(tokenFile) : null;
  if (!token) throw new Error("private command credential is unavailable");

  const endpoint = monitorCommandsEndpoint();
  endpoint.searchParams.set("session_id", sessionId);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > MAX_UPSTREAM_BYTES || !response.ok) {
      throw new Error("private monitor command request failed");
    }
    let payload: unknown;
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      throw new Error("private monitor command response is not JSON");
    }
    if (!isRecord(payload)) throw new Error("private monitor command response is invalid");
    return projectUpstreamCommands(sessionId, payload);
  } finally {
    clearTimeout(timeout);
  }
}

/** Local development only: exact-session, Admin-gated command review from canonical Mongo. */
export async function loadLocalAdminCowrieCommands(sessionId: string): Promise<AdminCowrieCommandProjection> {
  if (!CANONICAL_SESSION_ID_PATTERN.test(sessionId)) throw new TypeError("invalid canonical session identifier");
  if (process.env.NODE_ENV !== "development" || process.env.PTI_LOCAL_ADMIN_COMMANDS_FROM_MONGO !== "true") {
    throw new Error("local command review is disabled");
  }
  const client = await getMongoClient();
  const rows = await client.db("honeypot_canonical_v1").collection("events")
    .find(
      { session_id: sessionId, eventid: { $in: [...COMMAND_EVENT_IDS] } },
      { projection: { _id: 0, event_id: 1, eventid: 1, timestamp: 1, payload_json: 1 } },
    )
    .sort({ timestamp: 1, event_id: 1 })
    .limit(MAX_COMMANDS + 1)
    .maxTimeMS(20_000)
    .toArray();
  const commands = rows.map((row) => {
    if (typeof row.payload_json !== "string" || Buffer.byteLength(row.payload_json, "utf8") > MAX_UPSTREAM_BYTES) {
      throw new Error("canonical command payload is unavailable");
    }
    let payload: unknown;
    try {
      payload = JSON.parse(row.payload_json);
    } catch {
      throw new Error("canonical command payload is invalid");
    }
    if (!isRecord(payload) || typeof payload.input !== "string") {
      throw new Error("canonical command input is unavailable");
    }
    return {
      event_id: row.event_id,
      eventid: row.eventid,
      timestamp: row.timestamp,
      input: payload.input,
    };
  });
  return projectUpstreamCommands(sessionId, {
    ok: true,
    schema_version: "monitor.internal_command_view.v1",
    sensitive: true,
    session_id: sessionId,
    commands,
    truncated: rows.length > MAX_COMMANDS,
  });
}
