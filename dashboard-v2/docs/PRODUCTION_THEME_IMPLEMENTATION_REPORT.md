# Production theme implementation — first slice

Implemented on `design/production-theme-system`, following the approved specification. Scope: theme foundations, shared UI patterns, authenticated shell, `/`, `/login`, and `/dashboard`.

- Added semantic foundation, state, chart, map, typography, and elevation tokens with Tailwind v4 utilities. Normal surfaces use flat backgrounds, neutral shadows, and restrained radii. The approved system font fallbacks are active; no font assets or dependencies were added.
- Added stored System / Light / Dark controls, synchronous theme resolution before body paint, native color-scheme, OS preference tracking, cross-tab updates, and storage-denied fallback.
- Added a 240 px desktop sidebar and modal mobile navigation drawer, visible keyboard focus, accessible controls, responsive search/time placement, and focus restoration.
- Moved dashboard context and existing metrics ahead of the map. Preserved every directory column and action in a scrollable table. Added fixed-height loading skeletons, distinct unavailable/empty states, refreshing indicators, and retained results with explicit failed-refresh labels.
- Converted the shared attack-rate chart to CSS-variable colors and a flat fill. Converted map land, boundaries, tooltip, markers, legend, and controls to theme tokens; markers use distinct shapes. Removed continuous map animation.

| Automated verification | Result |
| --- | --- |
| `npm run lint` | Pass; 15 existing unused-variable warnings |
| `npm run build` | Pass; final Turbopack build required sandbox escalation for its local CSS-worker port |
| Dashboard API integration and staging contract tests | 10 passed |
| Browser interaction assertions | 28 passed |
| Source comparison | API calls, polling intervals, metric assignments, authentication/navigation calls unchanged |
| `git diff --check` | Pass |

Visually reviewed all three migrated routes in light/dark at 1440 × 1000 and 390 × 844. Also checked 320 px reflow, a 200% zoom equivalent (720 × 500 CSS pixels at device scale 2), keyboard focus, navigation and map dialogs, reduced motion, hover/pressed controls, disabled zoom, loading, empty, error, refresh, and stale presentation. Sampled text token contrast is at least 4.55:1; map boundaries are 3.86:1 light and 5.48:1 dark. Both stored themes were correct on every sampled animation frame with body content.

[Open the 31-image screenshot gallery and verification receipts](/tmp/pti-theme-review/index.html).

Verification limits: local `MONGODB_URI` is not configured, so final dashboard screenshots show the actual unavailable response. Empty/refresh/stale checks used controlled empty HTTP responses and network failures, with no fabricated events or markers. Populated rows, pagination, live markers, chart series/tooltips, and successful authentication were not visually verified. The existing health calculation remains unchanged.

Other route interiors and their specialized components remain for subsequent migration slices; this report does not claim completion of the full specification’s route matrix. The pre-existing untracked specification was preserved. No commit or push was performed.
