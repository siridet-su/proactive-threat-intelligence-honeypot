import { MongoClient } from 'mongodb';
import { buildAuditSessionsPipeline } from './dashboard-v2/src/lib/filesystem-data.ts';

async function test() {
  const from = new Date("2026-09-17T00:00:00+07:00").getTime();
  const to = new Date("2026-09-21T23:59:59+07:00").getTime();
  
  const options = {
    hideHome: true,
    from: from,
    to: to,
    limit: 25,
    historyCollectionName: 'cwd_events'
  };
  
  console.log("Options:", options);
  
  const pipeline = buildAuditSessionsPipeline(options);
  console.log("Pipeline:", JSON.stringify(pipeline, null, 2));
}

test();
