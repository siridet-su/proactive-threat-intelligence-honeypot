import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("server-only", () => ({}));

import {
  requestSessionTermination,
  resetResponseControlHealthCache,
  responseControlCachedHealth,
  responseControlConfigured,
  responseControlHealthy,
} from "../src/lib/response-control";

const originalURL = process.env.COWRIE_RESPONSE_AGENT_URL;
const originalToken = process.env.COWRIE_RESPONSE_AGENT_TOKEN;
const originalTokenFile = process.env.COWRIE_RESPONSE_AGENT_TOKEN_FILE;
const validActionID = "123e4567-e89b-12d3-a456-426614174000";
let fixtureDirectory: string;

describe("response control client", () => {
  beforeEach(() => {
    resetResponseControlHealthCache();
    fixtureDirectory = mkdtempSync(join(tmpdir(), "pti-response-control-"));
    process.env.COWRIE_RESPONSE_AGENT_URL = "http://100.118.43.30:8788";
    process.env.COWRIE_RESPONSE_AGENT_TOKEN = "01234567890123456789012345678901";
    delete process.env.COWRIE_RESPONSE_AGENT_TOKEN_FILE;
  });

  afterEach(() => {
    resetResponseControlHealthCache();
    vi.restoreAllMocks();
    if (originalURL === undefined) delete process.env.COWRIE_RESPONSE_AGENT_URL;
    else process.env.COWRIE_RESPONSE_AGENT_URL = originalURL;
    if (originalToken === undefined) delete process.env.COWRIE_RESPONSE_AGENT_TOKEN;
    else process.env.COWRIE_RESPONSE_AGENT_TOKEN = originalToken;
    if (originalTokenFile === undefined) delete process.env.COWRIE_RESPONSE_AGENT_TOKEN_FILE;
    else process.env.COWRIE_RESPONSE_AGENT_TOKEN_FILE = originalTokenFile;
    rmSync(fixtureDirectory, { recursive: true, force: true });
  });

  it("remains disabled unless endpoint and credential are both configured", async () => {
    delete process.env.COWRIE_RESPONSE_AGENT_TOKEN;
    expect(responseControlConfigured()).toBe(false);
    expect(await requestSessionTermination("abcdef123456", validActionID)).toEqual({ delivered: false, category: "unconfigured" });
  });

  it("sends only the exact session path and action identity", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
      JSON.stringify({ ok: true, status: "terminating" }),
      { status: 202, headers: { "Content-Type": "application/json" } },
    ));

    expect(await requestSessionTermination("abcdef123456", validActionID)).toEqual({ delivered: true, status: "terminating" });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://100.118.43.30:8788/v1/sessions/abcdef123456/terminate");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
    expect((init?.headers as Record<string, string>)["X-Action-ID"]).toBe(validActionID);
  });

  it("reports healthy only when the authenticated agent and Cowrie socket are ready", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
      JSON.stringify({ ok: true, status: "ready" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));

    expect(await responseControlHealthy()).toBe(true);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://100.118.43.30:8788/v1/health");
    expect(init?.method).toBe("GET");
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer 01234567890123456789012345678901");
  });

  it("reports unhealthy for an invalid health response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
      JSON.stringify({ ok: true, status: "starting" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));

    expect(await responseControlHealthy()).toBe(false);
  });

  it("caches healthy status within TTL to avoid repeated outbound pings", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(
      JSON.stringify({ ok: true, status: "ready" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));

    expect(await responseControlHealthy()).toBe(true);
    expect(await responseControlHealthy()).toBe(true);
    expect(await responseControlHealthy()).toBe(true);
    // Only 1 fetch call because subsequent calls hit the TTL cache
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(responseControlCachedHealth()).toBe(true);
  });

  it("forceRefresh bypasses the health cache", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(
      JSON.stringify({ ok: true, status: "ready" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ));

    expect(await responseControlHealthy()).toBe(true);
    expect(await responseControlHealthy(true)).toBe(true);
    // 2 fetch calls because forceRefresh was set
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("prefers a private absolute token file for deployed runtimes", async () => {
    const tokenPath = join(fixtureDirectory, "response-agent.token");
    const fileToken = "abcdef0123456789abcdef0123456789";
    writeFileSync(tokenPath, `${fileToken}\n`, { mode: 0o600 });
    process.env.COWRIE_RESPONSE_AGENT_TOKEN_FILE = tokenPath;
    delete process.env.COWRIE_RESPONSE_AGENT_TOKEN;
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
      JSON.stringify({ ok: true, status: "terminating" }),
      { status: 202, headers: { "Content-Type": "application/json" } },
    ));

    expect(responseControlConfigured()).toBe(true);
    expect(await requestSessionTermination("abcdef123456", validActionID)).toEqual({ delivered: true, status: "terminating" });
    const [, init] = fetchMock.mock.calls[0];
    expect((init?.headers as Record<string, string>).Authorization).toBe(`Bearer ${fileToken}`);
  });

  it("fails closed when a configured token file has unsafe permissions", async () => {
    const tokenPath = join(fixtureDirectory, "response-agent.token");
    writeFileSync(tokenPath, "abcdef0123456789abcdef0123456789\n", { mode: 0o600 });
    chmodSync(tokenPath, 0o640);
    process.env.COWRIE_RESPONSE_AGENT_TOKEN_FILE = tokenPath;
    const fetchMock = vi.spyOn(globalThis, "fetch");

    expect(responseControlConfigured()).toBe(false);
    expect(await requestSessionTermination("abcdef123456", validActionID)).toEqual({ delivered: false, category: "unconfigured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("does not follow a configured token-file symlink or fall back to an inline token", async () => {
    const tokenPath = join(fixtureDirectory, "response-agent.token");
    const linkPath = join(fixtureDirectory, "response-agent.link");
    writeFileSync(tokenPath, "abcdef0123456789abcdef0123456789\n", { mode: 0o600 });
    symlinkSync(tokenPath, linkPath);
    process.env.COWRIE_RESPONSE_AGENT_TOKEN_FILE = linkPath;

    expect(responseControlConfigured()).toBe(false);
    expect(await requestSessionTermination("abcdef123456", validActionID)).toEqual({ delivered: false, category: "unconfigured" });
  });

  it("fails closed for an invalid configured endpoint", async () => {
    process.env.COWRIE_RESPONSE_AGENT_URL = "file:///etc/passwd";
    expect(await requestSessionTermination("abcdef123456", validActionID)).toEqual({ delivered: false, category: "unconfigured" });
  });

  it("does not send a bearer token over public plaintext HTTP", async () => {
    process.env.COWRIE_RESPONSE_AGENT_URL = "http://203.0.113.10:8788";
    const fetchMock = vi.spyOn(globalThis, "fetch");
    expect(await requestSessionTermination("abcdef123456", validActionID)).toEqual({ delivered: false, category: "unconfigured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
