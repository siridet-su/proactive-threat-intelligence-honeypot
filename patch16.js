const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/app/api/filesystem-topology/audit-sessions/route.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /const page = await getAuditSessions\(/,
  `console.log("[API] /audit-sessions: from=" + from + ", to=" + to + ", cursor=" + cursor + ", hideHome=" + hideHome);
    const page = await getAuditSessions(`
);
code = code.replace(
  /return Response\.json\(page\);/,
  `console.log("[API] /audit-sessions returning: items=" + page.items.length + ", nextCursor=" + !!page.nextCursor);
    return Response.json(page);`
);

fs.writeFileSync(path, code);
