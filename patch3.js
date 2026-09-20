const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /limit: defaultLimit,\n\s*hideHome,\n\s*targetPath,\n\s*\}\);/g,
  `limit: defaultLimit,\n        hideHome,\n        targetPath,\n        from: filterOptions?.from,\n        to: filterOptions?.to,\n      });`
);

code = code.replace(
  /hideHome: parsedScope.hideHome,\n\s*targetPath: parsedScope.targetPath,\n\s*\}\);/g,
  `hideHome: parsedScope.hideHome,\n        targetPath: parsedScope.targetPath,\n        from: parsedScope.from,\n        to: parsedScope.to,\n      });`
);

code = code.replace(
  /hideHome: parsedScope.hideHome,\n\s*targetPath: parsedScope.targetPath,\n\s*q: parsedScope.q \|\| undefined,\n\s*\}\);/g,
  `hideHome: parsedScope.hideHome,\n        targetPath: parsedScope.targetPath,\n        q: parsedScope.q || undefined,\n        from: parsedScope.from,\n        to: parsedScope.to,\n      });`
);

fs.writeFileSync(path, code);
