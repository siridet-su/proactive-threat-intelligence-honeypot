import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
vi.mock("@/lib/mongodb", () => ({ getMongoClient: vi.fn() }));

import { getMongoClient } from "@/lib/mongodb";
import { loadSessionDownloads } from "@/lib/session-download-server";

const SESSION_ID = "session_v1_0123456789abcdef0123456789abcdef";

describe("canonical session file download projection", () => {
  it("queries one canonical session and returns only bounded hash metadata", async () => {
    const find = vi.fn(() => ({
      sort: () => ({ limit: () => ({ maxTimeMS: () => ({ toArray: async () => [
        { event_id: "event-1", timestamp: "2026-09-27T00:00:00Z", payload_json: JSON.stringify({ shasum: "A".repeat(64), url: "https://example.invalid/?token=private", destfile: "/tmp/private" }) },
      ] }) }) }),
    }));
    vi.mocked(getMongoClient).mockResolvedValue({ db: () => ({ collection: () => ({ find }) }) } as never);
    const result = await loadSessionDownloads(SESSION_ID);
    expect(find).toHaveBeenCalledWith(
      { schema_version: "mongodb_canonical_event.v1", session_id: SESSION_ID, eventid: "cowrie.session.file_download" },
      { projection: { _id: 0, event_id: 1, timestamp: 1, payload_json: 1 } },
    );
    expect(result.downloads).toEqual([{ event_id: "event-1", timestamp: "2026-09-27T00:00:00Z", sha256: "a".repeat(64), kind: "network_download" }]);
    expect(JSON.stringify(result)).not.toContain("private");
  });

  it("does not present Cowrie shell redirection as a network download", async () => {
    vi.mocked(getMongoClient).mockResolvedValue({ db: () => ({ collection: () => ({ find: () => ({
      sort: () => ({ limit: () => ({ maxTimeMS: () => ({ toArray: async () => [{
        event_id: "redir-1", timestamp: "2026-09-28T12:46:18Z",
        payload_json: JSON.stringify({ eventid: "cowrie.session.file_download", destfile: "/tmp/private", message: "Saved redir contents with SHA-256", shasum: "a".repeat(64) }),
      }] }) }) }),
    }) }) }) } as never);
    const result = await loadSessionDownloads(SESSION_ID);
    expect(result.downloads[0].kind).toBe("local_redirection");
    expect(JSON.stringify(result)).not.toContain("/tmp/private");
  });
});
