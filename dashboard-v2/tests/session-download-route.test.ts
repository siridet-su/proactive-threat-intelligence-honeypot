import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { GET } from "@/app/api/sessions/[id]/file-downloads/route";
import * as authSession from "@/lib/auth/session";
import * as commandServer from "@/lib/session-command-server";
import * as downloadServer from "@/lib/session-download-server";

const SESSION_ID = "session_v1_0123456789abcdef0123456789abcdef";
const HASH = "a".repeat(64);
const operator = (role: "admin" | "analyst") => ({
  sessionId: "operator-session", operatorId: "operator-1", role,
  mustChangePassword: false, expiresAt: new Date(Date.now() + 60_000),
});
const callRoute = (id = SESSION_ID) => GET(new Request(`http://dashboard.local/api/sessions/${id}/file-downloads`), { params: Promise.resolve({ id }) });

describe("session-scoped file download evidence route", () => {
  afterEach(() => vi.restoreAllMocks());

  it("denies unauthenticated and non-admin requests before querying evidence", async () => {
    const load = vi.spyOn(downloadServer, "loadSessionDownloads");
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValueOnce(null).mockResolvedValueOnce(operator("analyst"));
    vi.spyOn(authSession, "isAdmin").mockReturnValue(false);
    expect((await callRoute()).status).toBe(401);
    expect((await callRoute()).status).toBe(403);
    expect(load).not.toHaveBeenCalled();
  });

  it("rejects an unverified sensor-local identity", async () => {
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue(operator("admin"));
    vi.spyOn(authSession, "isAdmin").mockReturnValue(true);
    vi.spyOn(commandServer, "resolveCanonicalSessionIdForCommandEvidence").mockResolvedValue(null);
    const load = vi.spyOn(downloadServer, "loadSessionDownloads");
    expect((await callRoute("sensor-session")).status).toBe(400);
    expect(load).not.toHaveBeenCalled();
  });

  it("returns only bounded hash metadata for the verified canonical session", async () => {
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue(operator("admin"));
    vi.spyOn(authSession, "isAdmin").mockReturnValue(true);
    vi.spyOn(commandServer, "resolveCanonicalSessionIdForCommandEvidence").mockResolvedValue(SESSION_ID);
    const load = vi.spyOn(downloadServer, "loadSessionDownloads").mockResolvedValue({
      downloads: [{ event_id: "event-1", timestamp: "2026-09-27T00:00:00Z", sha256: HASH, kind: "network_download" }], truncated: false,
    });
    const response = await callRoute();
    const body = await response.json();
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(load).toHaveBeenCalledWith(SESSION_ID);
    expect(body).toMatchObject({ requested_session_id: SESSION_ID, session_id: SESSION_ID, downloads: [{ sha256: HASH }] });
    expect(JSON.stringify(body)).not.toContain("payload_json");
  });
});
