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
DASHBOARD_API_ORIGIN=http://127.0.0.1:8090
DASHBOARD_API_READ_TOKEN=<monitor read token, never a NEXT_PUBLIC variable>
DASHBOARD_V2_OPERATOR_ID=<deployment operator id>
DASHBOARD_V2_ACCESS_KEY=<deployment dashboard access key>
DASHBOARD_V2_SESSION_SECRET=<deployment session secret>
```

The app fails closed when dashboard authentication is not configured. No Mongo URI or Mongo credential belongs in this application. The BFF exposes only allowlisted GET routes and excludes the sensitive monitor command route.

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
