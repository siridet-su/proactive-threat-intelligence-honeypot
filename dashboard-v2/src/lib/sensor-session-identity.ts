import "server-only";

import { createHash } from "node:crypto";

export const SENSOR_SESSION_IDENTITY_SCHEMA = "authenticated_sensor_session.v1";
export const CANONICAL_SESSION_ID_PATTERN = /^session_v1_[0-9a-f]{32}$/;
const MAX_SENSOR_ID_LENGTH = 256;
const MAX_SENSOR_SESSION_ID_LENGTH = 256;

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validIdentityText(value: unknown, maximumLength: number): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximumLength
    && !/[\x00-\x1f\x7f]/.test(value);
}

/**
 * Verify the authenticated sensor/session binding embedded at ingestion and
 * return its sensor-local Cowrie ID. This mirrors the Python canonical-ID
 * contract; an unverified alias must never be used to read session evidence.
 */
export function authenticatedSensorSessionAlias(
  canonicalSessionId: string,
  eventValue: unknown,
  storedSensorId: unknown,
): string | null {
  if (!CANONICAL_SESSION_ID_PATTERN.test(canonicalSessionId) || !isRecord(eventValue)) return null;

  const identity = eventValue._honeypot_identity;
  if (!isRecord(identity)) return null;
  const sensorId = identity.sensor_id;
  const sensorSessionId = identity.sensor_session_id;
  if (
    identity.schema_version !== SENSOR_SESSION_IDENTITY_SCHEMA
    || identity.canonical_session_id !== canonicalSessionId
    || eventValue.session !== canonicalSessionId
    || !validIdentityText(sensorId, MAX_SENSOR_ID_LENGTH)
    || sensorId !== storedSensorId
    || !validIdentityText(sensorSessionId, MAX_SENSOR_SESSION_ID_LENGTH)
  ) {
    return null;
  }

  // Python uses json.dumps(..., ensure_ascii=False, sort_keys=True,
  // separators=(",", ":")). Keep the explicit key order byte-identical.
  const canonicalMaterial = JSON.stringify({
    schema_version: SENSOR_SESSION_IDENTITY_SCHEMA,
    sensor_id: sensorId,
    sensor_session_id: sensorSessionId,
  });
  const expectedSessionId = `session_v1_${createHash("sha256").update(canonicalMaterial, "utf8").digest("hex").slice(0, 32)}`;
  return expectedSessionId === canonicalSessionId ? sensorSessionId : null;
}

/** Parse the exact event JSON stored in a canonical Mongo event row. */
export function parseStoredCanonicalEvent(value: unknown): JsonRecord | null {
  if (typeof value !== "string" || value.length > 1_000_000) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
