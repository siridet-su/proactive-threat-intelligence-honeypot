const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/lib/filesystem-data.ts';
let code = fs.readFileSync(path, 'utf8');

const search = `    const hideHomeCond = {
      $or: [
        { auditHomeOnly: { $ne: true } },
        { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
      ]
    };`;
const replace = `    const hideHomeCond = {
      $or: [
        { auditVisitedPaths: { $exists: false } },
        { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
      ]
    };`;

code = code.replace(search, replace);
fs.writeFileSync(path, code);
