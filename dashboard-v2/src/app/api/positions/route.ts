import { NextResponse } from "next/server";
import { getMongoClient } from "@/lib/mongodb";
import { getSessionFromRequest, isAdmin } from "@/lib/auth/session";
import type { JobPosition } from "@/lib/dashboardTypes";

export const dynamic = "force-dynamic";

const DEFAULT_POSITIONS: Array<Omit<JobPosition, "userCount">> = [
  { id: "POS-01", title: "Lead Sentinel", status: "ACTIVE", description: "Directs threat analysis and tactical incident triage", iconName: "Shield" },
  { id: "POS-02", title: "Data Guardian", status: "ACTIVE", description: "Ensures evidence preservation, audit integrity, and telemetry retention", iconName: "Database" },
  { id: "POS-03", title: "Network Shield", status: "STANDBY", description: "Deploys honeynet deception topologies and monitors ingress routes", iconName: "Network" },
  { id: "POS-04", title: "Threat Hunter", status: "ACTIVE", description: "Performs adversarial TTP mapping and proactive behavioral profiling", iconName: "Target" },
];

function escapeRegex(text: string): string {
  return text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
}

function unauthorized() {
  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}

function forbidden() {
  return NextResponse.json({ error: "Forbidden" }, { status: 403 });
}

export async function GET(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return unauthorized();

  try {
    const client = await getMongoClient();
    const db = client.db("honeypot_db");
    const positionsColl = db.collection("job_positions");
    const usersColl = db.collection("users");

    // Seed defaults if collection is empty
    const count = await positionsColl.countDocuments({});
    if (count === 0) {
      const now = new Date();
      await positionsColl.insertMany(
        DEFAULT_POSITIONS.map((pos) => ({
          ...pos,
          createdAt: now,
          updatedAt: now,
        }))
      );
    }

    const docs = await positionsColl.find({}).sort({ id: 1 }).toArray();

    // Aggregate user counts per position
    const userCounts = await usersColl
      .aggregate<{ _id: string; count: number }>([
        { $group: { _id: "$position", count: { $sum: 1 } } },
      ])
      .toArray();

    const countMap = new Map<string, number>(
      userCounts.map((entry) => [String(entry._id), entry.count])
    );

    const positions: JobPosition[] = docs.map((doc) => ({
      id: String(doc.id),
      title: String(doc.title),
      status: doc.status === "STANDBY" ? "STANDBY" : "ACTIVE",
      description: typeof doc.description === "string" ? doc.description : "",
      iconName: typeof doc.iconName === "string" ? doc.iconName : "Briefcase",
      userCount: countMap.get(String(doc.title)) ?? 0,
      createdAt: doc.createdAt ? String(doc.createdAt) : undefined,
      updatedAt: doc.updatedAt ? String(doc.updatedAt) : undefined,
    }));

    return NextResponse.json(positions);
  } catch (error) {
    console.error("Failed to fetch positions:", error);
    return NextResponse.json({ error: "Failed to fetch positions" }, { status: 500 });
  }
}

export async function POST(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return unauthorized();
  if (!isAdmin(session)) return forbidden();

  try {
    const data: unknown = await request.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return NextResponse.json({ error: "Invalid position payload" }, { status: 400 });
    }

    const candidate = data as Record<string, unknown>;
    const title = typeof candidate.title === "string" ? candidate.title.trim() : "";
    const status = candidate.status === "STANDBY" ? "STANDBY" : "ACTIVE";
    const description = typeof candidate.description === "string" ? candidate.description.trim() : "";
    const iconName = typeof candidate.iconName === "string" ? candidate.iconName.trim() : "Briefcase";

    if (!title || title.length < 2) {
      return NextResponse.json({ error: "Position title must be at least 2 characters long" }, { status: 400 });
    }

    const client = await getMongoClient();
    const db = client.db("honeypot_db");
    const positionsColl = db.collection("job_positions");

    // Check duplicate title
    const existing = await positionsColl.findOne({
      title: { $regex: new RegExp(`^${escapeRegex(title)}$`, "i") },
    });
    if (existing) {
      return NextResponse.json({ error: `A position with title "${title}" already exists` }, { status: 409 });
    }

    // Allocate next ID
    const allPositions = await positionsColl.find({}, { projection: { id: 1 } }).toArray();
    let maxNum = 0;
    for (const p of allPositions) {
      const match = String(p.id).match(/^POS-(\d+)$/);
      if (match) {
        const num = parseInt(match[1], 10);
        if (num > maxNum) maxNum = num;
      }
    }
    const nextId = `POS-${String(maxNum + 1).padStart(2, "0")}`;

    const newPosition = {
      id: nextId,
      title,
      status,
      description,
      iconName,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    await positionsColl.insertOne(newPosition);
    return NextResponse.json({ success: true, position: { ...newPosition, userCount: 0 } });
  } catch (error) {
    console.error("Failed to create position:", error);
    return NextResponse.json({ error: "Failed to create position" }, { status: 500 });
  }
}

export async function PUT(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return unauthorized();
  if (!isAdmin(session)) return forbidden();

  try {
    const data: unknown = await request.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return NextResponse.json({ error: "Invalid position payload" }, { status: 400 });
    }

    const candidate = data as Record<string, unknown>;
    const id = typeof candidate.id === "string" ? candidate.id.trim() : "";
    const title = typeof candidate.title === "string" ? candidate.title.trim() : "";
    const status = candidate.status === "STANDBY" ? "STANDBY" : "ACTIVE";
    const description = typeof candidate.description === "string" ? candidate.description.trim() : "";
    const iconName = typeof candidate.iconName === "string" ? candidate.iconName.trim() : "Briefcase";

    if (!id) return NextResponse.json({ error: "Position ID is required" }, { status: 400 });
    if (!title || title.length < 2) {
      return NextResponse.json({ error: "Position title must be at least 2 characters long" }, { status: 400 });
    }

    const client = await getMongoClient();
    const db = client.db("honeypot_db");
    const positionsColl = db.collection("job_positions");
    const usersColl = db.collection("users");

    const current = await positionsColl.findOne({ id });
    if (!current) {
      return NextResponse.json({ error: "Position not found" }, { status: 404 });
    }

    // Check duplicate title with other positions
    const existingWithSameTitle = await positionsColl.findOne({
      id: { $ne: id },
      title: { $regex: new RegExp(`^${escapeRegex(title)}$`, "i") },
    });
    if (existingWithSameTitle) {
      return NextResponse.json({ error: `A position with title "${title}" already exists` }, { status: 409 });
    }

    // If title changed, propagate new title to assigned users
    const oldTitle = String(current.title);
    if (oldTitle !== title) {
      await usersColl.updateMany(
        { position: oldTitle },
        { $set: { position: title } }
      );
    }

    await positionsColl.updateOne(
      { id },
      {
        $set: {
          title,
          status,
          description,
          iconName,
          updatedAt: new Date(),
        },
      }
    );

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Failed to update position:", error);
    return NextResponse.json({ error: "Failed to update position" }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
  const session = await getSessionFromRequest(request);
  if (!session || session.mustChangePassword) return unauthorized();
  if (!isAdmin(session)) return forbidden();

  try {
    let id = "";
    if (request.headers.get("content-type")?.includes("application/json")) {
      const data: unknown = await request.json().catch(() => null);
      if (data && typeof data === "object" && "id" in data && typeof (data as { id: unknown }).id === "string") {
        id = (data as { id: string }).id.trim();
      }
    }
    if (!id) {
      const url = new URL(request.url);
      id = url.searchParams.get("id")?.trim() ?? "";
    }

    if (!id) {
      return NextResponse.json({ error: "Position ID is required" }, { status: 400 });
    }

    const client = await getMongoClient();
    const db = client.db("honeypot_db");
    const positionsColl = db.collection("job_positions");
    const usersColl = db.collection("users");

    const position = await positionsColl.findOne({ id });
    if (!position) {
      return NextResponse.json({ error: "Position not found" }, { status: 404 });
    }

    // Safety check: Prevent deletion if any operators are currently assigned to this position
    const assignedCount = await usersColl.countDocuments({ position: position.title });
    if (assignedCount > 0) {
      return NextResponse.json({
        error: `Cannot delete position "${position.title}" because it is currently assigned to ${assignedCount} operator(s). Please reassign operators before deleting.`,
      }, { status: 400 });
    }

    await positionsColl.deleteOne({ id });
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Failed to delete position:", error);
    return NextResponse.json({ error: "Failed to delete position" }, { status: 500 });
  }
}
