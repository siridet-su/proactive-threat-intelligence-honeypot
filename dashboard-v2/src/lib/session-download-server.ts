import "server-only";

import { getMongoClient } from "@/lib/mongodb";
import { normalizeSha256 } from "@/lib/artifact-server";
import { CANONICAL_SESSION_ID_PATTERN, parseStoredCanonicalEvent } from "@/lib/sensor-session-identity";

const MAX_DOWNLOADS = 100;

export interface SessionDownloadEvidence {
  event_id: string;
  timestamp: string | null;
  sha256: string | null;
  kind: "network_download" | "local_redirection" | "unverified";
}

function eventKind(payload: Record<string, unknown>): SessionDownloadEvidence["kind"] {
  if (typeof payload.url === "string" && payload.url.length <= 4096) {
    try {
      const url = new URL(payload.url);
      if (["http:", "https:", "ftp:", "sftp:"].includes(url.protocol) && url.hostname) return "network_download";
    } catch { /* A malformed URL is not evidence of a network download. */ }
  }
  if (typeof payload.destfile === "string" && payload.destfile.length > 0
    && typeof payload.message === "string" && payload.message.startsWith("Saved redir contents")) {
    return "local_redirection";
  }
  return "unverified";
}

/** Bounded, hash-only projection of Cowrie file artifact events for one verified session. */
export async function loadSessionDownloads(sessionId: string): Promise<{ downloads: SessionDownloadEvidence[]; truncated: boolean }> {
  if (!CANONICAL_SESSION_ID_PATTERN.test(sessionId)) throw new TypeError("invalid canonical session identifier");
  const client = await getMongoClient();
  const rows = await client.db("honeypot_canonical_v1").collection("events")
    .find(
      { schema_version: "mongodb_canonical_event.v1", session_id: sessionId, eventid: "cowrie.session.file_download" },
      { projection: { _id: 0, event_id: 1, timestamp: 1, payload_json: 1 } },
    )
    .sort({ timestamp: -1, event_id: -1 })
    .limit(MAX_DOWNLOADS + 1)
    .maxTimeMS(20_000)
    .toArray();

  const downloads = rows.slice(0, MAX_DOWNLOADS).flatMap((row) => {
    if (typeof row.event_id !== "string" || row.event_id.length === 0 || row.event_id.length > 256) return [];
    const payload = parseStoredCanonicalEvent(row.payload_json);
    if (!payload) return [];
    const timestamp = row.timestamp instanceof Date ? row.timestamp.toISOString() : row.timestamp;
    return [{
      event_id: row.event_id,
      timestamp: typeof timestamp === "string" && timestamp.length <= 64 ? timestamp : null,
      sha256: normalizeSha256(payload.shasum ?? payload.sha256),
      kind: eventKind(payload),
    }];
  });
  return { downloads, truncated: rows.length > MAX_DOWNLOADS };
}
