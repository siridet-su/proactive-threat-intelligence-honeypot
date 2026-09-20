async function test() {
  const from = new Date("2026-09-17T00:00:00+07:00").getTime();
  const to = new Date("2026-09-21T23:59:59+07:00").getTime();
  let url = "http://localhost:3000/api/filesystem-topology/audit-sessions?hideHome=0&from=" + from + "&to=" + to + "&limit=100";
  let res = await fetch(url);
  let data = await res.json();
  data.items.forEach(s => {
    if (s.lifecycle.closedAt.startsWith("2026-09-17T04:3") || s.lifecycle.closedAt.startsWith("2026-09-17T04:2")) {
      console.log(s.lifecycle.closedAt + " - " + s.cwdState?.path + " - homeOnly:" + s.auditSummary.homeOnly + " - paths: " + JSON.stringify(s.auditSummary.visitedPaths));
    }
  });
}
test();
