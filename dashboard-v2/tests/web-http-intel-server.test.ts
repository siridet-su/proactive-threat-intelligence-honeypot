import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

const { find, collection, db } = vi.hoisted(() => {
  const find = vi.fn();
  const collection = vi.fn(() => ({ find }));
  const db = vi.fn(() => ({ collection }));
  return { find, collection, db };
});
vi.mock("@/lib/mongodb", () => ({
  getMongoClient: async () => ({ db }),
  getMongoDatabaseName: () => "honeypot_db",
}));

import { getWebHttpHints, getWebHttpSession } from "@/lib/web-http-intel-server";

beforeEach(() => vi.clearAllMocks());

describe("HTTP Mongo read boundary", () => {
  it("queries only web-corp login events with a narrow projection and bounded result", async () => {
    const toArray = vi.fn().mockResolvedValue([{
      source: "web-corp", event_type: "web_login_attempt", event_id: "a123",
      network: { src_ip: "198.51.100.10" }, http: { method: "POST" },
      analysis: { sqli: { indicators: { password: ["sql_comment"] } } },
    }]);
    const limit = vi.fn(() => ({ toArray }));
    const sort = vi.fn(() => ({ limit }));
    find.mockReturnValue({ sort });

    const result = await getWebHttpHints(5000);

    expect(db).toHaveBeenCalledWith("honeypot_db");
    expect(collection).toHaveBeenCalledWith("events");
    expect(find).toHaveBeenCalledWith(
      { source: "web-corp", event_type: { $in: ["web_login_attempt", "web_http_request"] } },
      expect.objectContaining({ projection: expect.objectContaining({
        "analysis.sqli.indicators": 1, "analysis.xss.indicators": 1,
        "correlation.web_session_id": 1,
      }) }),
    );
    const projection = find.mock.calls[0]![1].projection as Record<string, number>;
    expect(Object.keys(projection)).not.toContain("web_login.password");
    expect(Object.keys(projection)).not.toContain("raw.payload");
    expect(Object.keys(projection)).not.toContain("http.query");
    expect(limit).toHaveBeenCalledWith(100);
    expect(result.items[0]?.ttpCandidate).toBe("T1190");
  });

  it("reads an exact HTTP session with the same safe projection", async () => {
    const id = "0123456789abcdef0123456789abcdef";
    const toArray = vi.fn().mockResolvedValue([{ source: "web-corp", event_type: "web_http_request", event_id: "evt1", correlation: { web_session_id: id }, network: { src_ip: "10.0.0.1", dst_port: 80 }, http: { method: "GET", path: "/login.html" } }]);
    const limit = vi.fn(() => ({ toArray }));
    const sort = vi.fn(() => ({ limit }));
    find.mockReturnValue({ sort });
    expect(await getWebHttpSession("invalid")).toBeNull();
    expect(find).not.toHaveBeenCalled();
    const items = await getWebHttpSession(id);
    expect(find).toHaveBeenCalledWith(expect.objectContaining({ "correlation.web_session_id": id }), expect.objectContaining({ projection: expect.any(Object) }));
    const projection = find.mock.calls[0]![1].projection as Record<string, number>;
    expect(projection["network.dst_port"]).toBe(1);
    expect(projection["web_login.password"]).toBeUndefined();
    expect(projection["raw.payload"]).toBeUndefined();
    expect(limit).toHaveBeenCalledWith(501);
    expect(items?.[0]?.destinationPort).toBe(80);
  });
});
