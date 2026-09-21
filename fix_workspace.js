const fs = require('fs');
const path = './dashboard-v2/src/components/filesystem/AuditFilesystemWorkspace.tsx';
let code = fs.readFileSync(path, 'utf8');

// Replace the end of the file. Currently it ends with:
//       />
//     </div>
//   );
// }

code = code.replace(/      \/>\n    <\/div>\n  \);\n\}\n?$/, "      />\n      </div>\n    </div>\n    </div>\n  );\n}");

fs.writeFileSync(path, code);
