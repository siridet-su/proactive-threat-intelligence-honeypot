import "server-only";

import { getMongoClient, getMongoDatabaseName } from "@/lib/mongodb";
import { projectWebHttpEvent, type WebHttpHint } from "@/lib/web-http-intel";

export async function getWebHttpHints(limit = 50): Promise<{ items: WebHttpHint[]; coverage: string }> {
  const safeLimit = Math.max(1, Math.min(100, Math.trunc(limit)));
  const client = await getMongoClient();
  const rows = await client.db(getMongoDatabaseName()).collection("events")
    .find({ source: "web-corp", event_type: { $in: ["web_login_attempt", "web_http_request"] } }, {
      maxTimeMS: 5_000,
      // Explicit allowlist: the Mongo row also contains plaintext password
      // under web_login and raw.payload. They must never reach this read path.
      projection: {
        _id: 0, source: 1, event_type: 1, event_id: 1, timestamp: 1,
        "network.src_ip": 1, "http.method": 1, "http.path": 1,
        "http.status_code": 1, "analysis.sqli.indicators": 1,
        "analysis.xss.indicators": 1, "correlation.web_session_id": 1,
        outcome: 1,
      },
    })
    .sort({ timestamp: -1, event_id: -1 })
    .limit(safeLimit)
    .toArray();
  return {
    items: rows.map(projectWebHttpEvent).filter((item): item is WebHttpHint => item !== null),
    coverage: "Stored web-corp HTTP requests and login attempts only; legacy events without a session ID remain ungrouped.",
  };
}
