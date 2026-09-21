type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validText(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * Ended sessions may retain a final, manifest-bound sidecar result. The
 * adapter calls that freshness state FINAL (not FRESH); it remains historical
 * advisory evidence, never a prediction of session end.
 */
export function hasValidHistoricalNextDistinct(payload: unknown, expectedSessionId: string): boolean {
  if (!isRecord(payload)) return false;
  const sourceSessionId = payload.session_id || payload.sequence_id;
  const freshness = isRecord(payload.freshness) ? payload.freshness : {};
  const state = String(payload.state || payload.status || "").toUpperCase();
  const sessionEnded = state === "SESSION_ENDED"
    || payload.session_ended === true
    || payload.is_ended === true;
  const freshnessState = String(freshness.state || "").toUpperCase();
  const freshnessBoundToEndedSession = freshnessState === "FINAL"
    && freshness.session_ended === true;

  return sourceSessionId === expectedSessionId
    && sessionEnded
    && String(payload.prediction_status || "").toUpperCase() === "PREDICTED"
    && freshnessBoundToEndedSession
    && freshness.history_manifest_match === true
    && validText(payload.stored_next_distinct_tactic);
}

export function projectNextDistinct(payload: JsonRecord, sessionId: string): JsonRecord {
  const nextDistinct = payload.next_distinct_tactic ?? payload.top1 ?? null;
  const freshness = isRecord(payload.freshness) ? payload.freshness : {};
  const predictionStatus = String(payload.prediction_status || "").toUpperCase();
  const freshnessState = String(freshness.state || "").toUpperCase();
  const unavailable = predictionStatus === "UNAVAILABLE" || freshnessState === "UNAVAILABLE";
  const rawState = String(payload.state || payload.status || "").toUpperCase();
  const sourceSessionId = payload.session_id || payload.sequence_id;
  const sessionBound = sourceSessionId === sessionId;
  const sessionEnded = rawState === "SESSION_ENDED"
    || payload.session_ended === true
    || payload.is_ended === true;
  const stale = predictionStatus === "STALE" || ["STALE", "EXPIRED"].includes(freshnessState);
  const hasCurrentData = sessionBound && nextDistinct !== null && nextDistinct !== undefined && nextDistinct !== "";
  const hasHistoricalData = sessionBound && hasValidHistoricalNextDistinct(payload, sessionId);
  const state = !sessionBound
    ? "UNAVAILABLE"
    : sessionEnded
    ? "SESSION_ENDED"
    : unavailable
      ? "UNAVAILABLE"
      : stale
        ? "STALE"
        : hasCurrentData
          ? "DATA"
          : "WAITING_FOR_EVIDENCE";
  return {
    ...payload,
    ok: true,
    session_id: sessionId,
    source: "NEXT_DISTINCT_POC",
    dashboard_source: "NEXT_DISTINCT_POC",
    read_only: true,
    advisory_only: true,
    state,
    status: state,
    availability: state === "DATA" ? "AVAILABLE" : state,
    next_distinct_tactic: state === "DATA" ? nextDistinct : null,
    stored_next_distinct_tactic: hasHistoricalData ? payload.stored_next_distinct_tactic : null,
    ...(state === "SESSION_ENDED"
      ? {
        prediction_status_reason: hasHistoricalData
          ? "session ended; no session-end prediction is emitted; the last manifest-matched sidecar result is shown as a historical advisory"
          : stale
            ? "session ended; the stored sidecar result is stale or history-mismatched; no session-end prediction is emitted"
            : "session ended; no valid stored prediction is available; no session-end prediction is emitted",
      }
      : {}),
    ...(!sessionBound
      ? { prediction_status_reason: "sidecar session identity did not match the requested session" }
      : {}),
  };
}
