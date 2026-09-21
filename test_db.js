const { MongoClient } = require('mongodb');

async function test() {
  const uri = process.env.MONGODB_URI || "mongodb://localhost:27017";
  const client = new MongoClient(uri);
  try {
    await client.connect();
    const db = client.db("ag_honeypot");
    const count = await db.collection("audit_projection").countDocuments();
    console.log("Total documents in audit_projection:", count);

    const from = new Date("2026-09-17T00:00:00+07:00");
    const to = new Date("2026-09-21T23:59:59+07:00");
    console.log("From:", from, "To:", to);

    const matching = await db.collection("audit_projection").countDocuments({
      "lifecycle.closedAt": { $gte: from, $lte: to }
    });
    console.log("Matching date range:", matching);

    const matchingNonHome = await db.collection("audit_projection").countDocuments({
      "lifecycle.closedAt": { $gte: from, $lte: to },
      $or: [
        { auditHomeOnly: false },
        { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
      ]
    });
    console.log("Matching date range AND non-home:", matchingNonHome);

  } finally {
    await client.close();
  }
}
test();
