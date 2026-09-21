const fs = require('fs');
const path = '/home/siridet/Projects/proactive-threat-intelligence-honeypot/dashboard-v2/src/lib/filesystem-data.ts';
let code = fs.readFileSync(path, 'utf8');

const search1 = `      $or: [
        { auditVisitedPaths: { $exists: false } },
        { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
      ]`;
const replace1 = `      $or: [
        {
          $and: [
            { auditVisitedPaths: { $exists: false } },
            { visitedPaths: { $exists: false } },
            { "cwdState.path": { $regex: "^(?!/home(/|$))" } }
          ]
        },
        {
          $and: [
            { auditVisitedPaths: { $exists: false } },
            { visitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
          ]
        },
        { auditVisitedPaths: { $elemMatch: { $regex: "^(?!/home(/|$))" } } }
      ]`;

code = code.replace(search1, replace1);

const search2 = `      $or: [
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
      ]`;
const replace2 = `      $or: [
        {
          $and: [
            { $eq: [{ $type: "$auditVisitedPaths" }, "missing"] },
            { $eq: [{ $type: "$visitedPaths" }, "missing"] },
            { $not: { $regexMatch: { input: { $ifNull: ["$cwdState.path", ""] }, regex: "^/home(/|$)" } } }
          ]
        },
        {
          $and: [
            { $eq: [{ $type: "$auditVisitedPaths" }, "missing"] },
            {
              $anyElementTrue: {
                $map: {
                  input: { $ifNull: ["$visitedPaths", []] },
                  as: "path",
                  in: { $not: { $regexMatch: { input: "$$path", regex: "^/home(/|$)" } } }
                }
              }
            }
          ]
        },
        {
          $anyElementTrue: {
            $map: {
              input: { $ifNull: ["$auditVisitedPaths", []] },
              as: "path",
              in: { $not: { $regexMatch: { input: "$$path", regex: "^/home(/|$)" } } }
            }
          }
        }
      ]`;

code = code.replace(search2, replace2);

fs.writeFileSync(path, code);
