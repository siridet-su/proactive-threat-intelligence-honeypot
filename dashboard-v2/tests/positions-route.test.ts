import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getSessionFromRequest: vi.fn(),
  isAdmin: vi.fn(),
  getMongoClient: vi.fn(),
}));

vi.mock("@/lib/auth/session", () => ({
  getSessionFromRequest: mocks.getSessionFromRequest,
  isAdmin: mocks.isAdmin,
}));

vi.mock("@/lib/mongodb", () => ({
  getMongoClient: mocks.getMongoClient,
}));

import { GET, POST, PUT, DELETE } from "@/app/api/positions/route";

describe("Positions API Route (/api/positions)", () => {
  let mockPositionsColl: {
    countDocuments: ReturnType<typeof vi.fn>;
    insertMany: ReturnType<typeof vi.fn>;
    find: ReturnType<typeof vi.fn>;
    findOne: ReturnType<typeof vi.fn>;
    insertOne: ReturnType<typeof vi.fn>;
    updateOne: ReturnType<typeof vi.fn>;
    deleteOne: ReturnType<typeof vi.fn>;
  };
  let mockUsersColl: {
    aggregate: ReturnType<typeof vi.fn>;
    countDocuments: ReturnType<typeof vi.fn>;
    updateMany: ReturnType<typeof vi.fn>;
  };
  let mockDb: {
    collection: ReturnType<typeof vi.fn>;
  };
  let mockClient: {
    db: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.clearAllMocks();

    mockPositionsColl = {
      countDocuments: vi.fn().mockResolvedValue(4),
      insertMany: vi.fn().mockResolvedValue({ acknowledged: true }),
      find: vi.fn().mockReturnValue({
        sort: vi.fn().mockReturnValue({
          toArray: vi.fn().mockResolvedValue([
            { id: "POS-01", title: "Lead Sentinel", status: "ACTIVE", description: "Desc 1", iconName: "Shield" },
            { id: "POS-02", title: "Data Guardian", status: "ACTIVE", description: "Desc 2", iconName: "Database" },
          ]),
        }),
        toArray: vi.fn().mockResolvedValue([
          { id: "POS-01" },
          { id: "POS-02" },
        ]),
      }),
      findOne: vi.fn().mockResolvedValue(null),
      insertOne: vi.fn().mockResolvedValue({ acknowledged: true }),
      updateOne: vi.fn().mockResolvedValue({ acknowledged: true }),
      deleteOne: vi.fn().mockResolvedValue({ acknowledged: true }),
    };

    mockUsersColl = {
      aggregate: vi.fn().mockReturnValue({
        toArray: vi.fn().mockResolvedValue([
          { _id: "Lead Sentinel", count: 2 },
        ]),
      }),
      countDocuments: vi.fn().mockResolvedValue(0),
      updateMany: vi.fn().mockResolvedValue({ acknowledged: true }),
    };

    mockDb = {
      collection: vi.fn((name: string) => {
        if (name === "job_positions") return mockPositionsColl;
        if (name === "users") return mockUsersColl;
        return {};
      }),
    };

    mockClient = {
      db: vi.fn().mockReturnValue(mockDb),
    };

    mocks.getMongoClient.mockResolvedValue(mockClient);
    mocks.getSessionFromRequest.mockResolvedValue({ operatorId: "OP-01", role: "Admin", mustChangePassword: false });
    mocks.isAdmin.mockReturnValue(true);
  });

  describe("GET /api/positions", () => {
    it("returns 401 if unauthenticated", async () => {
      mocks.getSessionFromRequest.mockResolvedValueOnce(null);
      const req = new Request("http://localhost/api/positions");
      const res = await GET(req);
      expect(res.status).toBe(401);
    });

    it("seeds default positions if database collection is empty", async () => {
      mockPositionsColl.countDocuments.mockResolvedValueOnce(0);
      const req = new Request("http://localhost/api/positions");
      const res = await GET(req);
      expect(res.status).toBe(200);
      expect(mockPositionsColl.insertMany).toHaveBeenCalledTimes(1);
    });

    it("returns mapped positions with calculated userCount", async () => {
      const req = new Request("http://localhost/api/positions");
      const res = await GET(req);
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data).toHaveLength(2);
      expect(data[0]).toMatchObject({
        id: "POS-01",
        title: "Lead Sentinel",
        status: "ACTIVE",
        userCount: 2,
      });
      expect(data[1]).toMatchObject({
        id: "POS-02",
        title: "Data Guardian",
        status: "ACTIVE",
        userCount: 0,
      });
    });
  });

  describe("POST /api/positions", () => {
    it("returns 401 if unauthenticated", async () => {
      mocks.getSessionFromRequest.mockResolvedValueOnce(null);
      const req = new Request("http://localhost/api/positions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: "New Position" }),
      });
      const res = await POST(req);
      expect(res.status).toBe(401);
    });

    it("returns 403 if user is not Admin", async () => {
      mocks.isAdmin.mockReturnValueOnce(false);
      const req = new Request("http://localhost/api/positions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: "New Position" }),
      });
      const res = await POST(req);
      expect(res.status).toBe(403);
    });

    it("returns 400 for invalid title", async () => {
      const req = new Request("http://localhost/api/positions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: " " }),
      });
      const res = await POST(req);
      expect(res.status).toBe(400);
    });

    it("returns 409 if title already exists", async () => {
      mockPositionsColl.findOne.mockResolvedValueOnce({ id: "POS-01", title: "Lead Sentinel" });
      const req = new Request("http://localhost/api/positions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: "Lead Sentinel" }),
      });
      const res = await POST(req);
      expect(res.status).toBe(409);
    });

    it("allocates next POS-ID and inserts new position", async () => {
      const req = new Request("http://localhost/api/positions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: "Cloud Threat Lead",
          status: "ACTIVE",
          description: "Cloud analysis",
          iconName: "Shield",
        }),
      });
      const res = await POST(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(json.position.id).toBe("POS-03");
      expect(mockPositionsColl.insertOne).toHaveBeenCalledWith(
        expect.objectContaining({
          id: "POS-03",
          title: "Cloud Threat Lead",
          status: "ACTIVE",
        })
      );
    });
  });

  describe("PUT /api/positions", () => {
    it("returns 403 if user is not Admin", async () => {
      mocks.isAdmin.mockReturnValueOnce(false);
      const req = new Request("http://localhost/api/positions", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "POS-01", title: "Lead Sentinel Updated" }),
      });
      const res = await PUT(req);
      expect(res.status).toBe(403);
    });

    it("returns 404 if position does not exist", async () => {
      mockPositionsColl.findOne.mockResolvedValueOnce(null);
      const req = new Request("http://localhost/api/positions", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "POS-99", title: "Non-existent" }),
      });
      const res = await PUT(req);
      expect(res.status).toBe(404);
    });

    it("cascades title update to users collection when title changes", async () => {
      mockPositionsColl.findOne
        .mockResolvedValueOnce({ id: "POS-01", title: "Lead Sentinel" }) // current check
        .mockResolvedValueOnce(null); // title duplicate check

      const req = new Request("http://localhost/api/positions", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: "POS-01",
          title: "Principal Sentinel",
          status: "ACTIVE",
          description: "New scope",
          iconName: "Shield",
        }),
      });
      const res = await PUT(req);
      expect(res.status).toBe(200);
      expect(mockUsersColl.updateMany).toHaveBeenCalledWith(
        { position: "Lead Sentinel" },
        { $set: { position: "Principal Sentinel" } }
      );
      expect(mockPositionsColl.updateOne).toHaveBeenCalledTimes(1);
    });
  });

  describe("DELETE /api/positions", () => {
    it("returns 404 if position to delete does not exist", async () => {
      mockPositionsColl.findOne.mockResolvedValueOnce(null);
      const req = new Request("http://localhost/api/positions", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "POS-99" }),
      });
      const res = await DELETE(req);
      expect(res.status).toBe(404);
    });

    it("blocks deletion with 400 error when operators are assigned", async () => {
      mockPositionsColl.findOne.mockResolvedValueOnce({ id: "POS-01", title: "Lead Sentinel" });
      mockUsersColl.countDocuments.mockResolvedValueOnce(3); // 3 operators assigned

      const req = new Request("http://localhost/api/positions", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "POS-01" }),
      });
      const res = await DELETE(req);
      expect(res.status).toBe(400);
      const data = await res.json();
      expect(data.error).toContain("currently assigned to 3 operator(s)");
      expect(mockPositionsColl.deleteOne).not.toHaveBeenCalled();
    });

    it("deletes position when no operators are assigned", async () => {
      mockPositionsColl.findOne.mockResolvedValueOnce({ id: "POS-02", title: "Data Guardian" });
      mockUsersColl.countDocuments.mockResolvedValueOnce(0); // 0 operators

      const req = new Request("http://localhost/api/positions", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "POS-02" }),
      });
      const res = await DELETE(req);
      expect(res.status).toBe(200);
      expect(mockPositionsColl.deleteOne).toHaveBeenCalledWith({ id: "POS-02" });
    });
  });
});
