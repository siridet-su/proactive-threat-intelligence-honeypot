import "server-only";

import { getMongoClient } from "@/lib/mongodb";
import { isDeceptionDecision } from "@/lib/dashboardTypes";
import type { DeceptionDecision } from "@/lib/dashboardTypes";

const DATABASE_NAME = "honeypot_db";
const COLLECTION_NAME = "deception_decisions";
const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 500;

/** One document per attacker IP, synced from Pi SQLite deception-core (tools/deception_mongo_sync.py). */
export async function getDeceptionDecisions(limit = DEFAULT_LIMIT): Promise<DeceptionDecision[]> {
  const client = await getMongoClient();
  const documents = await client
    .db(DATABASE_NAME)
    .collection(COLLECTION_NAME)
    .find({})
    .sort({ last_seen: -1 })
    .limit(Math.max(1, Math.min(limit, MAX_LIMIT)))
    .toArray();

  return (documents as unknown[]).filter(isDeceptionDecision);
}

export async function getDeceptionDecisionByIp(ip: string): Promise<DeceptionDecision | null> {
  const client = await getMongoClient();
  const document = await client
    .db(DATABASE_NAME)
    .collection(COLLECTION_NAME)
    .findOne({ ip });

  return isDeceptionDecision(document) ? document : null;
}
