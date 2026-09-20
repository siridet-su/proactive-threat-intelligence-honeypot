const http = require('http');

async function test() {
  const from = new Date("2026-09-17T00:00:00+07:00").getTime();
  const to = new Date("2026-09-21T23:59:59+07:00").getTime();
  
  let url = `http://localhost:3000/api/filesystem-topology/audit-sessions?hideHome=1&from=${from}&to=${to}&limit=25`;
  
  console.log("Fetching: " + url);
  
  const res = await fetch(url);
  const data = await res.json();
  console.log(`Page 1: items=${data.items.length}, nextCursor=${data.nextCursor}`);
  
  if (data.nextCursor) {
    url = `http://localhost:3000/api/filesystem-topology/audit-sessions?hideHome=1&from=${from}&to=${to}&limit=25&cursor=${encodeURIComponent(data.nextCursor)}`;
    const res2 = await fetch(url);
    const data2 = await res2.json();
    console.log(`Page 2: items=${data2.items.length}, nextCursor=${data2.nextCursor}`);
  }
}

test();
