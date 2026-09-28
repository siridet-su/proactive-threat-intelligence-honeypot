# PTI-Honeypot dashboard-v2

This is the fixed-theme threat-intelligence dashboard for the honeypot project. The dashboard reads the existing monitor/dashboard APIs through a same-origin, read-only Next.js BFF; browser code never connects directly to MongoDB Atlas.

## Local run

Install from the lockfile. The existing dependency set has a React 19 / `react-simple-maps` peer mismatch, so npm may require legacy peer resolution:

```bash
npm ci --legacy-peer-deps --ignore-scripts
npm run dev
```

The BFF defaults to `http://127.0.0.1:8090`, the existing `monitor_web` service. Configure these server-only variables before use:

```text
DASHBOARD_MONITOR_BASE_URL=http://127.0.0.1:8090
DASHBOARD_MONITOR_READ_TOKEN=<optional monitor read token, never a NEXT_PUBLIC variable>
PTI_ADMIN_PASSWORD=<deployment Admin password>
AUTH_SESSION_SECRET=<random server-only value, at least 32 characters>
MONGODB_URI=<server-only MongoDB connection string>
```

The production login endpoint requires MongoDB, the configured Admin password,
and the session secret. The staging deployment wrapper checks these required
env names before switching releases; the installer does not supply their
values.
Filesystem Activity is read-only: it provides Route Replay and Evidence views
and has no session-termination UI or API. No Pi response-agent URL or credential
is required. MongoDB credentials remain server-only and are never exposed
through a `NEXT_PUBLIC_*` variable. The sensitive monitor command-detail route
remains excluded from generic browser APIs and is not a control channel.

## Hosted production command evidence

The Admin-only Filesystem Activity Command events panel defaults to the
loopback `monitor_web` source. A hosted Dashboard such as Railway cannot use
the Pi monitor through its own `127.0.0.1`. For that deployment, set the
private server variable `PTI_ADMIN_COMMANDS_SOURCE=mongo` after confirming
the existing `MONGODB_URI` can read `honeypot_canonical_v1.events`. Do not set
this as a `NEXT_PUBLIC_*` value or put a URI in repository files. The route
still checks the Admin session and exact canonical session binding before
reading at most 101 command submissions. Responses are private and `no-store`.
An absent or different source value keeps the loopback monitor path; there is
no automatic fallback after a monitor error.

After the hosted service redeploys, sign in as an Admin and open Evidence for a
session already known to contain retained command submissions. Confirm the
Command events panel loads and the browser response to
`/api/sessions/{id}/commands` is 200. Confirm a non-Admin account receives 403
and the response has `Cache-Control: private, no-store`. Do not copy command
text into tickets, logs, or screenshots. Disable the setting to restore the
monitor-only source. See [ADR-0016](../docs/adr/ADR-0016-hosted-dashboard-command-evidence.md)
for the source boundary.

## API and data documentation

The source-backed API contract is maintained in [`docs/API.md`](/home/rubchek/Desktop/teammate-repo/dashboard-v2/docs/API.md), with a machine-readable inventory in [`docs/API_ENDPOINT_INVENTORY.csv`](/home/rubchek/Desktop/teammate-repo/dashboard-v2/docs/API_ENDPOINT_INVENTORY.csv) and a lightweight OpenAPI description in [`docs/openapi.yaml`](/home/rubchek/Desktop/teammate-repo/dashboard-v2/docs/openapi.yaml). Frontend consumers, trust boundaries, and freshness behavior are described in [`docs/FRONTEND_API_MAPPING.md`](/home/rubchek/Desktop/teammate-repo/dashboard-v2/docs/FRONTEND_API_MAPPING.md), [`docs/API_ARCHITECTURE.md`](/home/rubchek/Desktop/teammate-repo/dashboard-v2/docs/API_ARCHITECTURE.md), and [`docs/DATA_SEMANTICS.md`](/home/rubchek/Desktop/teammate-repo/dashboard-v2/docs/DATA_SEMANTICS.md).

The deterministic documentation check is [`docs/verify_endpoint_inventory.mjs`](/home/rubchek/Desktop/teammate-repo/dashboard-v2/docs/verify_endpoint_inventory.mjs). It verifies that the allowlisted source routes, CSV inventory, and API headings remain aligned.

## Verification

```bash
npm run lint
npx tsc --noEmit
npm run build
```

The implementation audit and runtime binding are recorded under `honeypot-analysis/evaluation/current_policy_remediation_20260827/dashboard_v2_threat_intel_api_integration/`. Production deployment is a separate authorized step and must wait for a current runtime preflight.
