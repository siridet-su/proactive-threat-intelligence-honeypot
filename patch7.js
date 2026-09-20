const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /const scopeKey = createAuditScopeKey\(\{ hideHome, targetPath \}\);/g,
  `const scopeKey = createAuditScopeKey({ hideHome, targetPath, from: filterOptions?.from, to: filterOptions?.to });`
);

code = code.replace(
  /const scopeKey = createAuditScopeKey\(\{ hideHome, targetPath, q: trimmed \}\);/g,
  `const scopeKey = createAuditScopeKey({ hideHome, targetPath, q: trimmed, from: filterOptions?.from, to: filterOptions?.to });`
);

fs.writeFileSync(path, code);
