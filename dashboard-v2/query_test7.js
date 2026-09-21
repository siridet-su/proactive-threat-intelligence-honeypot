async function test() {
  const from = new Date("2026-09-17T00:00:00+07:00").getTime();
  const to = new Date("2026-09-21T23:59:59+07:00").getTime();
  const { MongoClient } = require('mongodb');
  const client = new MongoClient("mongodb://localhost:27017");
  await client.connect();
  const db = client.db("ag_honeypot");
  const count = await db.collection("audit_projection").countDocuments({
    "lifecycle.closedAt": { $gte: new Date(from), $lte: new Date(to) },
    $or: [
      { auditVisitedPaths: { $exists: false } },
      { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
    ]
  });
  console.log("Matching items:", count);
  await client.close();
}
test();
