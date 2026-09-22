import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
const { getMongoClient } = vi.hoisted(() => ({ getMongoClient: vi.fn() }));
vi.mock("@/lib/mongodb", () => ({ getMongoClient }));

import { loadLocalAdminCowrieCommands } from "@/lib/session-command-server";

const SESSION_ID = "session_v1_0123456789abcdef0123456789abcdef";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetAllMocks();
});

describe("local-only Admin command projection", () => {
  it("fails closed unless explicitly enabled in development", async () => {
    await expect(loadLocalAdminCowrieCommands(SESSION_ID)).rejects.toThrow("disabled");
    expect(getMongoClient).not.toHaveBeenCalled();
  });

  it("reads only exact-session command events and omits credential fields", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("PTI_LOCAL_ADMIN_COMMANDS_FROM_MONGO", "true");
    const toArray = vi.fn().mockResolvedValue([{
      event_id: "event-1",
      eventid: "cowrie.command.input",
      timestamp: "2026-09-22T10:55:22Z",
      payload_json: JSON.stringify({ input: "whoami", username: "secret-user", password: "secret-pass" }),
    }]);
    const maxTimeMS = vi.fn().mockReturnValue({ toArray });
    const limit = vi.fn().mockReturnValue({ maxTimeMS });
    const sort = vi.fn().mockReturnValue({ limit });
    const find = vi.fn().mockReturnValue({ sort });
    const collection = vi.fn().mockReturnValue({ find });
    const db = vi.fn().mockReturnValue({ collection });
    getMongoClient.mockResolvedValue({ db });

    const result = await loadLocalAdminCowrieCommands(SESSION_ID);

    expect(db).toHaveBeenCalledWith("honeypot_canonical_v1");
    expect(find).toHaveBeenCalledWith(
      { session_id: SESSION_ID, eventid: { $in: expect.arrayContaining(["cowrie.command.input"]) } },
      { projection: { _id: 0, event_id: 1, eventid: 1, timestamp: 1, payload_json: 1 } },
    );
    expect(limit).toHaveBeenCalledWith(101);
    expect(result.commands[0]?.input).toBe("whoami");
    expect(JSON.stringify(result)).not.toContain("secret-user");
    expect(JSON.stringify(result)).not.toContain("secret-pass");
  });
});
