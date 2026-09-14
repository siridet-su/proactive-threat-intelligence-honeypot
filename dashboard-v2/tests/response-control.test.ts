import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { requestSessionTermination, responseControlConfigured } from "../src/lib/response-control";

const originalURL = process.env.COWRIE_RESPONSE_AGENT_URL;
const originalToken = process.env.COWRIE_RESPONSE_AGENT_TOKEN;
const validActionID = "123e4567-e89b-12d3-a456-426614174000";

describe("response control client", () => {
  beforeEach(() => {
    process.env.COWRIE_RESPONSE_AGENT_URL = "http://100.118.43.30:8788";
    process.env.COWRIE_RESPONSE_AGENT_TOKEN = "01234567890123456789012345678901";
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (originalURL === undefined) delete process.env.COWRIE_RESPONSE_AGENT_URL;
    else process.env.COWRIE_RESPONSE_AGENT_URL = originalURL;
    if (originalToken === undefined) delete process.env.COWRIE_RESPONSE_AGENT_TOKEN;
    else process.env.COWRIE_RESPONSE_AGENT_TOKEN = originalToken;
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
