import { beforeEach, describe, expect, it, vi } from "vitest";

const { getSessionFromRequest, getWebHttpSession } = vi.hoisted(() => ({
  getSessionFromRequest: vi.fn(), getWebHttpSession: vi.fn(),
}));
vi.mock("@/lib/auth/session", () => ({ getSessionFromRequest }));
vi.mock("@/lib/web-http-intel-server", () => ({ getWebHttpSession }));

import { GET } from "@/app/api/http-activity/session/[id]/route";

const id = "0123456789abcdef0123456789abcdef";
const request = () => new Request(`http://localhost/api/http-activity/session/${id}`);
const context = (value = id) => ({ params: Promise.resolve({ id: value }) });

beforeEach(() => vi.clearAllMocks());

describe("exact HTTP session API", () => {
  it("rejects unauthenticated and malformed IDs without querying Mongo", async () => {
    getSessionFromRequest.mockResolvedValue(null);
    expect((await GET(request(), context())).status).toBe(401);
    getSessionFromRequest.mockResolvedValue({ role: "Admin", mustChangePassword: false });
    expect((await GET(request(), context("bad"))).status).toBe(400);
    expect(getWebHttpSession).not.toHaveBeenCalled();
  });
  it("returns an exact bounded read with no-store headers", async () => {
    getSessionFromRequest.mockResolvedValue({ role: "Admin", mustChangePassword: false });
    getWebHttpSession.mockResolvedValue({ items: [{ eventId: "evt1", sessionId: id }], payloads: [{ eventId: "evt1", query: "q=test", form: null, truncatedFields: [] }] });
    const response = await GET(request(), context());
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    const body = await response.json();
    expect(body.items).toHaveLength(1);
    expect(body.payloads[0].query).toBe("q=test");
    expect(body.rawPayloadAccess).toBe(true);
    expect(getWebHttpSession).toHaveBeenCalledWith(id, true);
  });
  it("does not request credential-bearing fields for a Supporter", async () => {
    getSessionFromRequest.mockResolvedValue({ role: "Supporter", mustChangePassword: false });
    getWebHttpSession.mockResolvedValue({ items: [{ eventId: "evt1", sessionId: id }], payloads: [] });
    const response = await GET(request(), context());
    const body = await response.json();
    expect(body.rawPayloadAccess).toBe(false);
    expect(body.payloads).toEqual([]);
    expect(getWebHttpSession).toHaveBeenCalledWith(id, false);
  });
});
