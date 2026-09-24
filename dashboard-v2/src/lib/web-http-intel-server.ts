import "server-only";

import { getMongoClient, getMongoDatabaseName } from "@/lib/mongodb";
import { projectWebHttpEvent, type WebHttpHint } from "@/lib/web-http-intel";

const HTTP_EVENT_PROJECTION = {
  _id: 0, source: 1, event_type: 1, event_id: 1, timestamp: 1,
  "network.src_ip": 1, "network.src_port": 1,
  "network.dst_ip": 1, "network.dst_port": 1,
  "http.method": 1, "http.path": 1, "http.status_code": 1,
  "analysis.sqli.indicators": 1, "analysis.xss.indicators": 1,
  "correlation.web_session_id": 1, outcome: 1,
} as const;

export async function getWebHttpHints(limit = 50): Promise<{ items: WebHttpHint[]; coverage: string }> {
  const safeLimit = Math.max(1, Math.min(100, Math.trunc(limit)));
  const client = await getMongoClient();
  const rows = await client.db(getMongoDatabaseName()).collection("events")
    .find({ source: "web-corp", event_type: { $in: ["web_login_attempt", "web_http_request"] } }, {
      maxTimeMS: 5_000,
      // Explicit allowlist: the Mongo row also contains plaintext password
      // under web_login and raw.payload. They must never reach this read path.
      projection: HTTP_EVENT_PROJECTION,
    })
    .sort({ timestamp: -1, event_id: -1 })
    .limit(safeLimit)
    .toArray();
  return {
    items: rows.map(projectWebHttpEvent).filter((item): item is WebHttpHint => item !== null),
    coverage: "Stored web-corp HTTP requests and login attempts only; legacy events without a session ID remain ungrouped.",
  };
}

/** Exact sensor-issued browser-continuity ID only. Never join by IP or username. */
export async function getWebHttpSession(sessionId: string): Promise<WebHttpHint[] | null> {
  if (!/^[a-f0-9]{32}$/.test(sessionId)) return null;
  const client = await getMongoClient();
  const rows = await client.db(getMongoDatabaseName()).collection("events")
    .find({ source: "web-corp", event_type: { $in: ["web_login_attempt", "web_http_request"] }, "correlation.web_session_id": sessionId }, {
      maxTimeMS: 5_000,
      projection: HTTP_EVENT_PROJECTION,
    })
    .sort({ timestamp: 1, event_id: 1 })
    .limit(501)
    .toArray();
  // Do not silently claim a complete chronology when the safe cap is reached.
  if (rows.length > 500) throw new Error("HTTP session exceeds the bounded detail limit");
  const items = rows.map(projectWebHttpEvent).filter((item): item is WebHttpHint => item?.sessionId === sessionId);
  return items.length ? items : null;
}
