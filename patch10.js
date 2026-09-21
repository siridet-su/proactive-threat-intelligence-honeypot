const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /\[store, hideHomeOnly, targetPathFilter\],\s*\);/g,
  `[store, hideHomeOnly, targetPathFilter, timeRangeMs?.from, timeRangeMs?.to],
  );`
);

fs.writeFileSync(path, code);
