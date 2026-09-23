import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { GET } from "@/app/api/sessions/[id]/commands/route";
import * as authSession from "@/lib/auth/session";
import * as commandServer from "@/lib/session-command-server";

const SESSION_ID = "session_v1_0123456789abcdef0123456789abcdef";

function operator(role: "admin" | "analyst", mustChangePassword = false) {
  return {
    sessionId: "operator-session",
    operatorId: "operator-1",
    role,
    mustChangePassword,
    expiresAt: new Date(Date.now() + 60_000),
  };
}

async function callRoute(id = SESSION_ID) {
  return GET(
    new Request(`http://dashboard.local/api/sessions/${encodeURIComponent(id)}/commands`),
    { params: Promise.resolve({ id }) },
  );
}

describe("Admin-only Cowrie command evidence route", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  it("requires an authenticated session and does not query command storage for anonymous users", async () => {
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue(null);
    const loadCommands = vi.spyOn(commandServer, "loadAdminCowrieCommands").mockResolvedValue({
      ok: true,
      schema_version: "dashboard.admin_cowrie_commands.v1",
      session_id: SESSION_ID,
      sensitive: true,
      content_scope: "administrator_only_cowrie_command_input",
      historical_originals: "unrecoverable_if_redacted_before_persistence",
      commands: [],
      truncated: false,
    });

    const response = await callRoute();

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(loadCommands).not.toHaveBeenCalled();
  });

  it.each([
    ["analyst role", operator("analyst")],
    ["password rotation required", operator("admin", true)],
  ])("denies %s before raw-command lookup", async (_label, session) => {
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue(session);
    vi.spyOn(authSession, "isAdmin").mockReturnValue(session.role === "admin");
    const loadCommands = vi.spyOn(commandServer, "loadAdminCowrieCommands");

    const response = await callRoute();

    expect(response.status).toBe(403);
    expect(loadCommands).not.toHaveBeenCalled();
  });

  it("returns raw command input only for an authenticated Admin and never caches it", async () => {
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue(operator("admin"));
    vi.spyOn(authSession, "isAdmin").mockReturnValue(true);
    const loadCommands = vi.spyOn(commandServer, "loadAdminCowrieCommands").mockResolvedValue({
      ok: true,
      schema_version: "dashboard.admin_cowrie_commands.v1",
      session_id: SESSION_ID,
      sensitive: true,
      content_scope: "administrator_only_cowrie_command_input",
      historical_originals: "unrecoverable_if_redacted_before_persistence",
      commands: [{
        event_id: "event-1",
        eventid: "cowrie.command.input",
        timestamp: "2026-09-21T13:36:14Z",
        input: "curl -u attacker:synthetic-password https://example.invalid/",
        command_text_available: true,
        input_truncated: false,
        classification: [],
      }],
      truncated: false,
    });

    const response = await callRoute();
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("vary")).toContain("Cookie");
    expect(loadCommands).toHaveBeenCalledWith(SESSION_ID);
    expect(body.commands[0].input).toContain("attacker:synthetic-password");
  });

  it("allows the explicit development Mongo path only on loopback", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("PTI_LOCAL_ADMIN_COMMANDS_FROM_MONGO", "true");
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue(operator("admin"));
    vi.spyOn(authSession, "isAdmin").mockReturnValue(true);
    const local = vi.spyOn(commandServer, "loadLocalAdminCowrieCommands").mockResolvedValue({
      ok: true,
      schema_version: "dashboard.admin_cowrie_commands.v1",
      session_id: SESSION_ID,
      sensitive: true,
      content_scope: "administrator_only_cowrie_command_input",
      historical_originals: "unrecoverable_if_redacted_before_persistence",
      commands: [],
      truncated: false,
    });
    const remoteResponse = await callRoute();
    expect(remoteResponse.status).toBe(403);
    expect(local).not.toHaveBeenCalled();

    const localResponse = await GET(
      new Request(`http://127.0.0.1:3187/api/sessions/${SESSION_ID}/commands`),
      { params: Promise.resolve({ id: SESSION_ID }) },
    );
    expect(localResponse.status).toBe(200);
    expect(local).toHaveBeenCalledWith(SESSION_ID);
  });

  it("rejects noncanonical session ids without calling the sensitive upstream", async () => {
    vi.spyOn(authSession, "getSessionFromRequest").mockResolvedValue(operator("admin"));
    vi.spyOn(authSession, "isAdmin").mockReturnValue(true);
    const loadCommands = vi.spyOn(commandServer, "loadAdminCowrieCommands");

    const response = await callRoute("session-safe");

    expect(response.status).toBe(400);
    expect(loadCommands).not.toHaveBeenCalled();
  });
});
