const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /currentScopeKey \?\? createAuditScopeKey\(\{ hideHome: hideHomeOnly, targetPath: targetPathFilter \}\);/g,
  `currentScopeKey ?? createAuditScopeKey({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: (function(){
      if (!timeRange || timeRange === "all") return undefined;
      if (timeRange === "custom") return customDateRange?.from?.getTime();
      return getPresetDateRange(timeRange)?.from?.getTime();
    })(), to: (function(){
      if (!timeRange || timeRange === "all") return undefined;
      if (timeRange === "custom") return customDateRange?.to?.getTime();
      return getPresetDateRange(timeRange)?.to?.getTime();
    })() });`
);

code = code.replace(
  /\(\) => createAuditScopeKey\(\{ hideHome: hideHomeOnly, targetPath: targetPathFilter \}\),/g,
  `() => createAuditScopeKey({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to }),`
);

fs.writeFileSync(path, code);
