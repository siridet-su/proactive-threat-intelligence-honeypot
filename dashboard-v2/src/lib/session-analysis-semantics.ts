export type SessionAnalysisRecord = Record<string, unknown>;
export type SessionLifecycleStatus = "Active" | "Closed" | "Unknown";

function record(value: unknown): SessionAnalysisRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as SessionAnalysisRecord
    : {};
}

function meaningful(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value.trim().length > 0;
  return true;
}

function timestampMillis(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string" || !value.trim()) return null;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function sequenceNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string" || !value.trim()) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export function authoritativeEventTimestamp(value: SessionAnalysisRecord): unknown {
  return value.timestamp ?? value.event_timestamp ?? value.received_at ?? value.updated_at;
}

function authoritativeEventSequence(value: SessionAnalysisRecord): number | null {
  const durableOrder = record(value.durable_evidence_order);
  for (const candidate of [
    value.sequence,
    value.sequence_index,
    value.event_sequence,
    durableOrder.sequence,
    durableOrder.sequence_index,
  ]) {
    const parsed = sequenceNumber(candidate);
    if (parsed !== null) return parsed;
  }
  return null;
}

/**
 * Sort persisted records by their authoritative event timestamp. Timestamps
 * are the primary order; an explicit event sequence is the deterministic tie
 * breaker, followed by the source order when no sequence was persisted.
 */
export function chronologicalRecords(items: unknown[]): SessionAnalysisRecord[] {
  return items
    .map((value, index) => {
      const item = record(value);
      return {
        item,
        index,
        timestamp: timestampMillis(authoritativeEventTimestamp(item)),
        sequence: authoritativeEventSequence(item),
      };
    })
    .sort((left, right) => {
      if (left.timestamp !== null && right.timestamp !== null && left.timestamp !== right.timestamp) {
        return left.timestamp - right.timestamp;
      }
      if (left.timestamp === null && right.timestamp !== null) return 1;
      if (left.timestamp !== null && right.timestamp === null) return -1;
      if (left.sequence !== null && right.sequence !== null && left.sequence !== right.sequence) {
        return left.sequence - right.sequence;
      }
      if (left.sequence === null && right.sequence !== null) return 1;
      if (left.sequence !== null && right.sequence === null) return -1;
      return left.index - right.index;
    })
    .map(({ item }) => item);
}

function statusText(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

/**
 * Resolve lifecycle state only from explicit persisted lifecycle signals.
 * Inactivity, missing polling, and analysis status are deliberately ignored.
 */
export function sessionLifecycleStatus(detail: SessionAnalysisRecord): SessionLifecycleStatus {
  const sources = [
    record(detail.session),
    record(detail.overview),
    record(detail.session_payload),
    detail,
  ];
  let sawActive = false;

  for (const source of sources) {
    if (source.is_ended === true || source.ended === true) return "Closed";
    if (meaningful(source.end_time) || meaningful(source.ended_at) || meaningful(source.closed_at)) {
      return "Closed";
    }
    const statuses = [source.status, source.session_status, source.lifecycle_status]
      .map(statusText)
      .filter(Boolean);
    if (statuses.some((value) => ["closed", "ended", "complete", "completed", "terminated", "disconnected"].includes(value))) {
      return "Closed";
    }
    if (source.is_ended === false || source.ended === false || statuses.some((value) => ["active", "open", "connected", "running"].includes(value))) {
      sawActive = true;
    }
  }

  return sawActive ? "Active" : "Unknown";
}
