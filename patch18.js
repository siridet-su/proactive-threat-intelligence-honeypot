const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/app/api/filesystem-topology/audit-sessions/route.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /if \(\!session \|\| session\.mustChangePassword\) \{/,
  `if (false) {`
);

fs.writeFileSync(path, code);
