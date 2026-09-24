import { beforeEach, describe, expect, it, vi } from "vitest";

const { getSessionFromRequest, getWebHttpHints } = vi.hoisted(() => ({
  getSessionFromRequest: vi.fn(), getWebHttpHints: vi.fn(),
}));
vi.mock("@/lib/auth/session", () => ({ getSessionFromRequest }));
vi.mock("@/lib/web-http-intel-server", () => ({ getWebHttpHints }));

import { GET } from "@/app/api/http-activity/route";

beforeEach(() => { vi.clearAllMocks(); });

describe("HTTP activity API", () => {
  it("does not read Mongo for unauthenticated users", async () => {
    getSessionFromRequest.mockResolvedValue(null);
    const response = await GET(new Request("http://localhost/api/http-activity"));
    expect(response.status).toBe(401);
    expect(getWebHttpHints).not.toHaveBeenCalled();
    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
  });

  it("returns only the projected feed for authenticated users", async () => {
    getSessionFromRequest.mockResolvedValue({ mustChangePassword: false });
    getWebHttpHints.mockResolvedValue({ items: [], coverage: "Stored web-corp login attempts only" });
    const response = await GET(new Request("http://localhost/api/http-activity"));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ items: [], coverage: "Stored web-corp login attempts only" });
  });

  it("fails closed without returning backend exception text", async () => {
    getSessionFromRequest.mockResolvedValue({ mustChangePassword: false });
    getWebHttpHints.mockRejectedValue(new Error("synthetic-sensitive-mongo-uri"));
    const response = await GET(new Request("http://localhost/api/http-activity"));
    expect(response.status).toBe(503);
    expect(JSON.stringify(await response.json())).not.toContain("synthetic-sensitive-mongo-uri");
  });
});
