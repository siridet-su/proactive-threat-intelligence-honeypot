async function test() {
  const from = new Date("2026-09-17T00:00:00+07:00").getTime();
  const to = new Date("2026-09-21T23:59:59+07:00").getTime();
  let url = "http://localhost:3000/api/filesystem-topology/audit-sessions?hideHome=1&from=" + from + "&to=" + to + "&limit=25";
  let res = await fetch(url);
  let data = await res.json();
  console.log("PAGE 1:");
  console.log("items:", data.items ? data.items.length : 0);
  console.log("nextCursor:", !!data.nextCursor);
  
  if (data.nextCursor) {
    url = "http://localhost:3000/api/filesystem-topology/audit-sessions?hideHome=1&from=" + from + "&to=" + to + "&limit=25&cursor=" + encodeURIComponent(data.nextCursor);
    res = await fetch(url);
    data = await res.json();
    console.log("PAGE 2:");
    console.log("items:", data.items ? data.items.length : 0);
    console.log("nextCursor:", !!data.nextCursor);
  }
}
test();
