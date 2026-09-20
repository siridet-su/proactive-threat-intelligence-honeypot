const fs = require('fs');
let code = fs.readFileSync('dashboard-v2/src/components/filesystem/FilesystemContext.tsx', 'utf8');

// The issue is `any` disables all typechecking but apparently strict mode complains about accessing properties on `any`?
// No, `any` allows accessing properties. Wait! Maybe `FilesystemContextType` isn't `any`, but `unknown`?
// I will just use the exact interface props.
code = code.replace(/export type FilesystemContextType = any;/, `
export interface FilesystemContextType extends Record<string, any> {
  expiredSessionId: string | null;
  allSessions: any[];
  setExpiredSessionId: (id: string | null) => void;
  handleUserSelectSession: (id: string, sessionObj?: any) => void;
  // ... and other props will be allowed via Record<string, any>
}
`);
fs.writeFileSync('dashboard-v2/src/components/filesystem/FilesystemContext.tsx', code);
