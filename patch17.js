const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/lib/filesystem-server.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /const pageDocs = rawItems\.slice\(0, limit\);/g,
  `console.log("[SERVER] rawItems.length=" + rawItems.length + ", limit=" + limit);
  const pageDocs = rawItems.slice(0, limit);`
);

fs.writeFileSync(path, code);
