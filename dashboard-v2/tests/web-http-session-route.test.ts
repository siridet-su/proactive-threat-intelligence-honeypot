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
    getSessionFromRequest.mockResolvedValue({ mustChangePassword: false });
    expect((await GET(request(), context("bad"))).status).toBe(400);
    expect(getWebHttpSession).not.toHaveBeenCalled();
  });
  it("returns an exact bounded read with no-store headers", async () => {
    getSessionFromRequest.mockResolvedValue({ mustChangePassword: false });
    getWebHttpSession.mockResolvedValue([{ eventId: "evt1", sessionId: id }]);
    const response = await GET(request(), context());
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect((await response.json()).items).toHaveLength(1);
    expect(getWebHttpSession).toHaveBeenCalledWith(id);
  });
});
