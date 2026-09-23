import { afterEach, describe, expect, it, vi } from "vitest";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

vi.mock("server-only", () => ({}));

import { loadAdminCowrieCommands } from "@/lib/session-command-server";

const SESSION_ID = "session_v1_0123456789abcdef0123456789abcdef";
const TOKEN = "synthetic-command-access-token-for-unit-tests";
const originalTokenFile = process.env.MONITOR_RAW_COMMANDS_TOKEN_FILE;
const originalMonitorBase = process.env.DASHBOARD_MONITOR_BASE_URL;

let testDirectory = "";

function configureTokenFile(mode = 0o600): string {
  testDirectory = mkdtempSync(join(tmpdir(), "admin-command-route-test-"));
  const tokenFile = join(testDirectory, "command-token");
  writeFileSync(tokenFile, `${TOKEN}\n`, { mode });
  chmodSync(tokenFile, mode);
  process.env.MONITOR_RAW_COMMANDS_TOKEN_FILE = tokenFile;
  process.env.DASHBOARD_MONITOR_BASE_URL = "http://127.0.0.1:8090";
  return tokenFile;
}

function upstreamBody(overrides: Record<string, unknown> = {}) {
  return {
    ok: true,
    schema_version: "monitor.internal_command_view.v1",
    sensitive: true,
    session_id: SESSION_ID,
    commands: [{
      event_id: "event-1",
      eventid: "cowrie.command.input",
      timestamp: "2026-09-21T13:36:14Z",
      input: "curl -u attacker:synthetic-password https://example.invalid/",
      classification: [{ ttp: "T1105", tactic: "command-and-control", extra: "not projected" }],
      password: "must-not-be-projected",
    }],
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  if (originalTokenFile === undefined) delete process.env.MONITOR_RAW_COMMANDS_TOKEN_FILE;
  else process.env.MONITOR_RAW_COMMANDS_TOKEN_FILE = originalTokenFile;
  if (originalMonitorBase === undefined) delete process.env.DASHBOARD_MONITOR_BASE_URL;
  else process.env.DASHBOARD_MONITOR_BASE_URL = originalMonitorBase;
  if (testDirectory) rmSync(testDirectory, { recursive: true, force: true });
  testDirectory = "";
});

describe("server-only raw command forwarding", () => {
  it("reads an owner-only token file and calls only the loopback monitor with a narrow projection", async () => {
    configureTokenFile();
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(upstreamBody()), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const result = await loadAdminCowrieCommands(SESSION_ID);

    expect(fetchSpy).toHaveBeenCalledOnce();
    const [target, init] = fetchSpy.mock.calls[0]!;
    expect(new URL(String(target)).origin).toBe("http://127.0.0.1:8090");
    expect(new URL(String(target)).pathname).toBe("/api/internal/session-commands");
    expect(new URL(String(target)).searchParams.get("session_id")).toBe(SESSION_ID);
    expect((init?.headers as Record<string, string>).Authorization).toBe(`Bearer ${TOKEN}`);
    expect(init).toMatchObject({ cache: "no-store", redirect: "error" });
    expect(result.commands).toEqual([expect.objectContaining({
      event_id: "event-1",
      eventid: "cowrie.command.input",
      input: "curl -u attacker:synthetic-password https://example.invalid/",
      classification: [{ ttp: "T1105", tactic: "command-and-control" }],
    })]);
    expect(JSON.stringify(result)).not.toContain("must-not-be-projected");
    expect(JSON.stringify(result)).not.toContain("not projected");
  });

  it("truncates command text to the byte bound and marks the projection", async () => {
    configureTokenFile();
    const oversized = "x".repeat(5_000);
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(upstreamBody({
        commands: [{ event_id: "event-1", eventid: "cowrie.command.input", input: oversized }],
      })), { status: 200 }),
    );

    const result = await loadAdminCowrieCommands(SESSION_ID);

    expect(Buffer.byteLength(result.commands[0]!.input, "utf8")).toBeLessThanOrEqual(4_096 + 64);
    expect(result.commands[0]!.input_truncated).toBe(true);
    expect(result.truncated).toBe(true);
  });

  it("fails closed when the upstream session identity does not match", async () => {
    configureTokenFile();
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(upstreamBody({ session_id: "session_v1_ffffffffffffffffffffffffffffffff" })), {
        status: 200,
      }),
    );

    await expect(loadAdminCowrieCommands(SESSION_ID)).rejects.toThrow("closed contract");
  });

  it.skipIf(process.platform === "win32")("does not make an upstream request when the credential file grants group/other access", async () => {
    configureTokenFile(0o644);
    const fetchSpy = vi.spyOn(globalThis, "fetch");

    await expect(loadAdminCowrieCommands(SESSION_ID)).rejects.toThrow("credential is unavailable");
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
