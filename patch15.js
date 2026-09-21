const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/lib/filesystem-data.ts';
let code = fs.readFileSync(path, 'utf8');

const search = `  if (options.hideHome) clauses.push({ $ne: ["$auditHomeOnly", true] });`;
const replace = `  if (options.hideHome) {
    clauses.push({
      $or: [
        { $eq: [{ $type: "$auditVisitedPaths" }, "missing"] },
        {
          $anyElementTrue: {
            $map: {
              input: { $ifNull: ["$auditVisitedPaths", []] },
              as: "path",
              in: { $not: { $regexMatch: { input: "$$path", regex: "^/home(/|$)" } } }
            }
          }
        }
      ]
    });
  }`;

code = code.replace(search, replace);
fs.writeFileSync(path, code);
