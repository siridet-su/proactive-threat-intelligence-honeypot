const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/lib/filesystem-data.ts';
let code = fs.readFileSync(path, 'utf8');

code = code.replace(
  /if \(options\.hideHome\) match\.auditHomeOnly = \{ \$ne: true \};/g,
  `if (options.hideHome) {
    match.$or = [
      { auditHomeOnly: false },
      { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
    ];
  }`
);

fs.writeFileSync(path, code);
