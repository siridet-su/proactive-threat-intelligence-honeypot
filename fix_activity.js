const fs = require('fs');
let code = fs.readFileSync('dashboard-v2/src/components/filesystem/FilesystemActivity.tsx', 'utf8');

code = code.replace(/\{\/\* eslint-disable-next-line @typescript-eslint\/no-explicit-any \*\/\}/, '');
code = code.replace(/return \(\n\s*<FilesystemContext\.Provider/, '// eslint-disable-next-line @typescript-eslint/no-explicit-any\n  return (\n    <FilesystemContext.Provider');

fs.writeFileSync('dashboard-v2/src/components/filesystem/FilesystemActivity.tsx', code);
