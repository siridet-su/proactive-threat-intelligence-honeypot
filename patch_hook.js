const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /const currentScopeKey = createAuditScopeKey\(\{ hideHome: hideHomeOnly, targetPath: targetPathFilter \}\);/g,
  `const currentScopeKey = createAuditScopeKey({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });`
);

code = code.replace(
  /void store\.fetchInitial\(\{ hideHome: hideHomeOnly, targetPath: targetPathFilter \}\);/g,
  `void store.fetchInitial({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });`
);
code = code.replace(
  /void store\.fetchSummary\(\{ hideHome: hideHomeOnly, targetPath: targetPathFilter \}\);/g,
  `void store.fetchSummary({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });`
);
code = code.replace(
  /await store\.searchSessions\(query, null, \{ hideHome: hideHomeOnly, targetPath: targetPathFilter \}\);/g,
  `await store.searchSessions(query, null, { hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });`
);
code = code.replace(
  /await store\.loadMoreSearch\(\{ hideHome: hideHomeOnly, targetPath: targetPathFilter \}\);/g,
  `await store.loadMoreSearch({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });`
);
code = code.replace(
  /await store\.retryInitial\(\{ hideHome: hideHomeOnly, targetPath: targetPathFilter \}\);/g,
  `await store.retryInitial({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });`
);
code = code.replace(
  /\[hideHomeOnly, targetPathFilter\]/g,
  `[hideHomeOnly, targetPathFilter, timeRangeMs?.from, timeRangeMs?.to]`
);
code = code.replace(
  /\[viewMode, hideHomeOnly, targetPathFilter, store\]/g,
  `[viewMode, hideHomeOnly, targetPathFilter, timeRangeMs?.from, timeRangeMs?.to, store]`
);

fs.writeFileSync(path, code);
