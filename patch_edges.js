const fs = require('fs');
const path = './dashboard-v2/src/components/filesystem/TopologyCanvas.tsx';
let code = fs.readFileSync(path, 'utf8');

const svgStart = /<svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 h-full w-full overflow-visible" aria-hidden="true">/;

code = code.replace(svgStart, `<svg viewBox="0 0 100 100" preserveAspectRatio="none" className="pointer-events-none absolute inset-0 h-full w-full overflow-visible" aria-hidden="true">
                    <defs>
                      <marker id="arrowhead-primary" markerWidth="4" markerHeight="4" refX="2" refY="2" orient="auto">
                        <polygon points="0 0, 4 2, 0 4" fill="var(--primary)" opacity="0.6" />
                      </marker>
                    </defs>`);

const pathEndRegex = /strokeDasharray=\{\s*isActiveHopEdge\s*\?\s*"none"\s*:\s*isTrailEdge\s*\?\s*"1\.2 0\.8"\s*:\s*"none"\s*\}/;

const markerEndStr = `strokeDasharray={
                                isActiveHopEdge
                                  ? "none"
                                  : isTrailEdge
                                    ? "1.2 0.8"
                                    : "none"
                              }
                              markerEnd={isTrailEdge ? "url(#arrowhead-primary)" : undefined}`;

code = code.replace(pathEndRegex, markerEndStr);

fs.writeFileSync(path, code);
