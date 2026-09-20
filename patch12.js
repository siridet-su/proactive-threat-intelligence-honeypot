const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/lib/filesystem-data.ts';
let code = fs.readFileSync(path, 'utf8');

const search = `  if (options.hideHome) {
    match.$or = [
      { auditHomeOnly: false },
      { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
    ];
  }`;
const replace = `  if (options.hideHome) {
    const hideHomeCond = {
      $or: [
        { auditHomeOnly: false },
        { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
      ]
    };
    if (match.$or) {
      match.$and = [{ $or: match.$or }, hideHomeCond];
      delete match.$or;
    } else {
      match.$or = hideHomeCond.$or;
    }
  }`;
code = code.replace(search, replace);
fs.writeFileSync(path, code);
