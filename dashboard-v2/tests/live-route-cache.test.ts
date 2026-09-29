import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getSessionFromRequest: vi.fn(),
  getThreatSnapshot: vi.fn(),
  getRecentHardwareMetrics: vi.fn(),
}));

vi.mock("@/lib/auth/session", () => ({
  getSessionFromRequest: mocks.getSessionFromRequest,
}));
vi.mock("@/lib/threat-server", () => ({
  getThreatSnapshot: mocks.getThreatSnapshot,
}));
vi.mock("@/lib/hardware-mongo", () => ({
  getRecentHardwareMetrics: mocks.getRecentHardwareMetrics,
}));

import { GET as getThreats } from "@/app/api/threats/route";
import { GET as getHardware } from "@/app/api/hardware/route";

describe("authenticated live snapshot cache policy", () => {
  beforeEach(() => {
    mocks.getSessionFromRequest.mockResolvedValue({
      sessionId: "operator-session", role: "Admin", mustChangePassword: false,
    });
    mocks.getThreatSnapshot.mockResolvedValue([]);
    mocks.getRecentHardwareMetrics.mockResolvedValue([]);
  });

  it("does not permit a proxy to cache the live threat snapshot", async () => {
    const response = await getThreats(new Request("http://localhost/api/threats"));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
  });

  it("does not permit a proxy to cache the live hardware snapshot", async () => {
    const response = await getHardware(new Request("http://localhost/api/hardware"));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("private, no-store");
  });
});
