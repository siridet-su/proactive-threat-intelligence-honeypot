# dashboard-v2 staging deployment

These files provision a separate staging frontend on the existing VM. They
are not a production deployment mechanism. The runtime namespace is
`/opt/honeypot-dashboard-v2-staging` and its `incoming/` directory is the only
artifact upload area accepted by the root deployment wrapper.

## One-time VM setup

Run as the existing authorized VM administrator from this directory:

```bash
sudo ./bootstrap-staging-runtime.sh
```

The script creates `/opt/honeypot-dashboard-v2-staging`, installs the staging
unit and root-owned deploy wrapper, creates a blank root-only staging env
file if absent, reloads systemd, and enables only the staging unit. It
does not start a service without a release and does not touch production,
backend services, Mongo, network rules, or Cloudflare.

Before deployment, fill `/etc/honeypot/services/dashboard-v2-staging.env`
with `sudoedit`: `MONGODB_URI`, `PTI_ADMIN_PASSWORD` (at least 12 characters),
and `AUTH_SESSION_SECRET` (at least 32 characters) are required. Keep the
file owned by root with mode `0600`. The staging wrapper checks required
names, shape, and permissions without printing values before switching a
release. Existing env files are preserved, including older files that need
manual migration from retired `DASHBOARD_V2_*` names. It does not test Mongo
connectivity or credentials until runtime; do not reuse production secrets.

After the wrapper is installed, a repository administrator can provision the
dedicated CI account with a public key:

```bash
sudo ./setup-deploy-identity.sh /path/to/dashboard-staging-deploy.pub
```

The private key is never supplied to this script. Store it only as the
GitHub `staging` Environment secret. The generated sudoers entry permits only
`/opt/honeypot-dashboard-v2-staging/bin/deploy-staging`.

## Deployment contract

The CI job uploads a file named
`/opt/honeypot-dashboard-v2-staging/incoming/dashboard-v2-staging-<full-commit-sha>.tar.gz`
and invokes:

```text
sudo -n /opt/honeypot-dashboard-v2-staging/bin/deploy-staging \
  --artifact /opt/honeypot-dashboard-v2-staging/incoming/dashboard-v2-staging-<full-commit-sha>.tar.gz \
  --sha256 <artifact-sha256> \
  --commit <full-commit-sha> \
  --tree <full-tree-sha> \
  --lock-sha256 <package-lock-sha256> \
  --run-id <github-run-id>
```

The wrapper accepts only the exact staging `incoming/` path shape, validates the
archive against traversal and unexpected top-level paths, verifies the
manifest identity, extracts into a new immutable release, atomically changes
the staging `current` symlink, restarts only
`honeypot-dashboard-v2-staging.service`, and performs health checks. A failed
candidate restores the previous healthy staging pointer. Failed candidates
remain available for bounded diagnostics until the explicit five-release
retention policy removes an old, inactive release.

## Expected manual health checks

```bash
systemctl status honeypot-dashboard-v2-staging.service
systemctl show honeypot-dashboard-v2-staging.service -p MainPID -p NRestarts
ss -ltn
curl --fail --silent --show-error http://127.0.0.1:3001/
```

The listener must be exactly `127.0.0.1:3001`; no firewall rule or public
listener is part of this setup. The page carries a visible `STAGING` marker
and a short build identity. The current explicit-route dashboard has no
legacy `/api/health` catch-all endpoint, so the wrapper probes `GET
/api/auth/login` and requires `405` (method not allowed) as a
backend-independent router check.

## Rollback

Rollback is automatic when the wrapper's post-restart health check fails. The
wrapper restores the previous symlink and restarts only staging. Production
continues using `/opt/honeypot-dashboard-v2/current` and
`honeypot-dashboard-v2.service` on port 3000.
