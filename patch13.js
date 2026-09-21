const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/lib/filesystem-data.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /\{ auditHomeOnly: false \}/g,
  `{ auditHomeOnly: { $ne: true } }`
);

fs.writeFileSync(path, code);
