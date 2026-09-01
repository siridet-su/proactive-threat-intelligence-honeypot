from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboard-v2"
DEPLOYMENT = ROOT / "honeypot-analysis/deployment/dashboard-v2-staging"
WORKFLOW = ROOT / ".github/workflows/dashboard-v2-staging.yml"


def test_staging_workflow_is_scoped_to_dashboard_and_staging_pushes() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request:" in workflow
    assert "push:" in workflow
    assert "branches:" in workflow
    assert "- staging" in workflow
    assert "dashboard-v2/**" in workflow
    assert "honeypot-analysis/deployment/dashboard-v2-staging/**" in workflow
    assert "permissions: {}" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "if: github.event_name == 'push' && github.ref == 'refs/heads/staging'" in workflow
    assert "environment:" in workflow
    assert "name: staging" in workflow
    assert "StrictHostKeyChecking=no" not in workflow
    assert "ssh-keyscan" not in workflow
    assert "honeypot-dashboard-v2.service" not in workflow
    assert "MONGO_URI" not in workflow
    assert "CLOUDFLARE_API_TOKEN" not in workflow


def test_staging_bff_rejects_state_changing_methods_and_keeps_auth_local() -> None:
    proxy = (DASHBOARD / "src/app/api/[...path]/route.ts").read_text(encoding="utf-8")
    auth = (DASHBOARD / "src/app/api/auth/route.ts").read_text(encoding="utf-8")
    assert 'export async function GET' in proxy
    assert 'export async function HEAD' in proxy
    assert 'export async function POST' in proxy
    assert 'export async function PUT' in proxy
    assert 'export async function PATCH' in proxy
    assert 'export async function DELETE' in proxy
    assert 'method: "GET"' in proxy
    assert 'redirect: "error"' in proxy
    assert 'response.headers.set("allow", "GET, HEAD")' in proxy
    assert 'method: "POST"' not in proxy
    assert 'method: "PUT"' not in proxy
    assert 'method: "PATCH"' not in proxy
    assert 'method: "DELETE"' not in proxy
    assert "fetch(" not in auth


def test_staging_unit_is_non_root_and_loopback_only() -> None:
    unit = (DEPLOYMENT / "honeypot-dashboard-v2-staging.service").read_text(encoding="utf-8")
    assert "User=honeypot" in unit
    assert "Group=honeypot" in unit
    assert "EnvironmentFile=/etc/honeypot/services/dashboard-v2-staging.env" in unit
    assert "Environment=HOSTNAME=127.0.0.1" in unit
    assert "Environment=PORT=3001" in unit
    assert "ExecStart=/opt/honeypot-dashboard-v2/node-v24.18.0/bin/node /opt/honeypot-dashboard-v2-staging/current/server.js" in unit
    assert "0.0.0.0:3001" not in unit
    assert "honeypot-dashboard-v2.service" not in unit


def test_staging_wrapper_has_no_production_restart_or_unbounded_root_input() -> None:
    wrapper = (DEPLOYMENT / "deploy-staging").read_text(encoding="utf-8")
    assert 'SERVICE="honeypot-dashboard-v2-staging.service"' in wrapper
    assert 'RELEASE_ROOT="/opt/honeypot-dashboard-v2-staging"' in wrapper
    assert 'CURRENT="$RELEASE_ROOT/current"' in wrapper
    assert 'artifact" == "$INCOMING/dashboard-v2-staging-${commit}.tar.gz"' in wrapper
    assert 'DEPLOY_GROUP="dashboard-staging-deploy"' in wrapper
    assert 'staging incoming ownership/mode is unsafe' in wrapper
    assert 'switch_pointer "releases/$release_name"' in wrapper
    assert "for ((attempt = 0; attempt < 30; attempt++))" in wrapper
    assert "sleep 1" in wrapper
    assert "--no-same-owner" in wrapper
    assert "--no-same-permissions" in wrapper
    assert "mv -Tf" in wrapper
    assert '"$SYSTEMCTL" restart "$SERVICE"' in wrapper
    assert "honeypot-dashboard-v2.service" not in wrapper
    assert "/opt/honeypot-dashboard-v2/current" not in wrapper
    assert "0.0.0.0:3001" not in wrapper
    assert "rm -rf \"$RELEASE_ROOT" not in wrapper


def test_staging_artifact_contains_only_non_secret_identity_fields() -> None:
    package_script = (DASHBOARD / "scripts/package-staging.mjs").read_text(encoding="utf-8")
    env_example = (DEPLOYMENT / "dashboard-v2-staging.env.example").read_text(encoding="utf-8")
    assert "git_commit_sha" in package_script
    assert "git_tree_sha" in package_script
    assert "package_lock_sha256" in package_script
    assert "artifact_sha256" in package_script
    assert "DASHBOARD_V2_ACCESS_KEY=<generate-with-bootstrap-script>" in env_example
    assert "MONGO_URI" not in package_script
    assert "CLOUDFLARE_API_TOKEN" not in package_script
    assert package_script.index("await mkdir(outputRoot") < package_script.index("await runArchive")
    assert 'output.on("error", rejectArchive)' in package_script


def test_staging_deploy_identity_restricts_the_ci_ssh_key() -> None:
    identity = (DEPLOYMENT / "setup-deploy-identity.sh").read_text(encoding="utf-8")
    assert 'printf \'restrict %s\\n\' "$public_key_line"' in identity
    assert "sudo_scope=only root-owned staging deployment wrapper" in identity
    assert "docker" not in identity
    assert "sudo ALL" not in identity
