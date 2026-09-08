#!/usr/bin/env node

import { MongoClient } from "mongodb";

const uri = process.env.MONGODB_URI;
if (!uri) {
  throw new Error("MONGODB_URI is required to create the sessions start_time index.");
}

const client = new MongoClient(uri);

try {
  await client.connect();
  const sessions = client.db("honeypot_canonical_v1").collection("sessions");
  const indexName = await sessions.createIndex(
    { start_time: -1 },
    { name: "start_time_desc" },
  );
  const queryPlan = await sessions.find({})
    .sort({ start_time: -1 })
    .limit(1)
    .explain("queryPlanner");
  const usesExpectedIndex = JSON.stringify(queryPlan.queryPlanner.winningPlan).includes(indexName);
  if (!usesExpectedIndex) {
    throw new Error(`The session recency query is not using the ${indexName} index.`);
  }

  console.log(JSON.stringify({
    database: "honeypot_canonical_v1",
    collection: "sessions",
    index: indexName,
    queryPlan: "uses_index",
    status: "ready",
  }));
} finally {
  await client.close();
}
