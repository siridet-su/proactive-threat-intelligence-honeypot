async function test() {
  const from = new Date("2026-09-17T00:00:00+07:00").getTime();
  const to = new Date("2026-09-21T23:59:59+07:00").getTime();
  const { MongoClient } = require('mongodb');
  const client = new MongoClient("mongodb://localhost:27017");
  await client.connect();
  const db = client.db("ag_honeypot");
  const docs = await db.collection("audit_projection").find({
    "lifecycle.closedAt": { $gte: new Date(from), $lte: new Date(to) }
  }).sort({ "lifecycle.closedAt": -1 }).limit(100).toArray();
  docs.forEach(d => {
    if (d.lifecycle.closedAt.toISOString().startsWith("2026-09-17T04:3")) {
      console.log(d.lifecycle.closedAt.toISOString() + " - " + d.cwdState?.path + " - " + d.auditHomeOnly + " - " + JSON.stringify(d.auditVisitedPaths));
    }
  });
  await client.close();
}
test();
