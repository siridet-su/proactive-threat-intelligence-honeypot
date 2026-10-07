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

const request = (path: string) => new Request(`http://localhost${path}`);
const expectPrivateNoStore = (response: Response) => {
  expect(response.headers.get("cache-control")).toBe("private, no-store");
};

describe("authenticated live snapshot cache policy", () => {
  beforeEach(() => {
    mocks.getSessionFromRequest.mockResolvedValue({
      sessionId: "operator-session",
      role: "Admin",
      mustChangePassword: false,
    });
    mocks.getThreatSnapshot.mockResolvedValue([]);
    mocks.getRecentHardwareMetrics.mockResolvedValue([]);
  });

  it("does not cache successful threat snapshots in a browser or proxy", async () => {
    const response = await getThreats(request("/api/threats"));
    expect(response.status).toBe(200);
    expectPrivateNoStore(response);
  });

  it("does not cache unauthorized threat responses", async () => {
    mocks.getSessionFromRequest.mockResolvedValueOnce(null);
    const response = await getThreats(request("/api/threats"));
    expect(response.status).toBe(401);
    expectPrivateNoStore(response);
  });

  it("does not cache threat error responses", async () => {
    mocks.getThreatSnapshot.mockRejectedValueOnce(new Error("fixture failure"));
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await getThreats(request("/api/threats"));
    log.mockRestore();
    expect(response.status).toBe(500);
    expectPrivateNoStore(response);
  });

  it("does not cache successful hardware snapshots in a browser or proxy", async () => {
    const response = await getHardware(request("/api/hardware"));
    expect(response.status).toBe(200);
    expectPrivateNoStore(response);
  });

  it("does not cache unauthorized hardware responses", async () => {
    mocks.getSessionFromRequest.mockResolvedValueOnce(null);
    const response = await getHardware(request("/api/hardware"));
    expect(response.status).toBe(401);
    expectPrivateNoStore(response);
  });

  it("does not cache hardware error responses", async () => {
    mocks.getRecentHardwareMetrics.mockRejectedValueOnce(new Error("fixture failure"));
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await getHardware(request("/api/hardware"));
    log.mockRestore();
    expect(response.status).toBe(503);
    expectPrivateNoStore(response);
  });
});
