const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/components/filesystem/useAuditDirectory.ts';
let code = fs.readFileSync(path, 'utf8');

// replace getSessionTimestamp(s) with getSessionClosedTimestamp(s) in filterFn
code = code.replace(
  /const ts = getSessionTimestamp\(s\);/g,
  `let ts = 0;
      if ("lifecycle" in s && s.lifecycle?.closedAt) {
        ts = new Date(s.lifecycle.closedAt).getTime();
        if (Number.isNaN(ts)) ts = 0;
      }`
);

fs.writeFileSync(path, code);
