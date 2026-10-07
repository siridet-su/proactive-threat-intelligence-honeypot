export type DeceptionSessionQuery = {
  ip: string;
  session_id: string;
};

/** Build the only supported session-detail lookup: both bindings are mandatory. */
export function buildDeceptionSessionQuery(ip: string, sessionId: string): DeceptionSessionQuery | null {
  const boundIp = ip.trim();
  const boundSessionId = sessionId.trim();
  if (!boundIp || !boundSessionId) return null;
  return { ip: boundIp, session_id: boundSessionId };
}

/** Fail closed if an API response is not bound to the requested IP and session. */
export function matchesDeceptionSessionBinding(
  value: unknown,
  ip: string,
  sessionId: string,
): boolean {
  const query = buildDeceptionSessionQuery(ip, sessionId);
  if (!query || typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record.ip === query.ip && record.session_id === query.session_id;
}
