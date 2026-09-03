from __future__ import annotations

import io
from pathlib import Path
import subprocess
import tarfile


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


def test_staging_uses_explicit_direct_api_handlers_without_bff_proxy() -> None:
    api_root = DASHBOARD / "src/app/api"
    assert not (api_root / "[...path]/route.ts").exists()
    for relative in ("threats/route.ts", "hardware/route.ts", "malware/route.ts", "users/route.ts"):
        route = (api_root / relative).read_text(encoding="utf-8")
        assert "export async function GET" in route
        assert "clientPromise" in route


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


def test_staging_health_probe_matches_explicit_runtime_routes() -> None:
    wrapper = (DEPLOYMENT / "deploy-staging").read_text(encoding="utf-8")
    assert "http://127.0.0.1:3001/api/auth/login" in wrapper
    assert "route_status" in wrapper
    assert "route_status\" == '405'" in wrapper
    assert "http://127.0.0.1:3001/api/health" not in wrapper


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
    assert '"--use-compress-program=gzip -n -9"' in package_script
    assert '"--hard-dereference"' in package_script
    assert 'execFileSync("tar", tarArgs' in package_script
    assert 'spawn("tar"' not in package_script
    assert 'title=staging packaging failed' in package_script
    assert 'standalone copy failed' in package_script
    assert "symlink_count_before" in package_script
    assert (DASHBOARD / "scripts/staging-archive-policy.mjs").exists()


def test_staging_deploy_identity_restricts_the_ci_ssh_key() -> None:
    identity = (DEPLOYMENT / "setup-deploy-identity.sh").read_text(encoding="utf-8")
    assert 'printf \'restrict %s\\n\' "$public_key_line"' in identity
    assert "sudo_scope=only root-owned staging deployment wrapper" in identity
    assert "docker" not in identity
    assert "sudo ALL" not in identity


def _add_regular(archive: tarfile.TarFile, name: str, content: bytes = b"x") -> None:
    member = tarfile.TarInfo(name)
    member.mode = 0o644
    member.size = len(content)
    archive.addfile(member, io.BytesIO(content))


def _add_directory(archive: tarfile.TarFile, name: str) -> None:
    member = tarfile.TarInfo(name.rstrip("/") + "/")
    member.type = tarfile.DIRTYPE
    member.mode = 0o755
    archive.addfile(member)


def test_staging_archive_validator_rejects_symlinks_and_accepts_materialized_tree(
    tmp_path: Path,
) -> None:
    validator = DASHBOARD / "scripts/staging-archive-policy.mjs"
    symlink_archive = tmp_path / "contains-link.tar.gz"
    with tarfile.open(symlink_archive, "w:gz") as archive:
        _add_directory(archive, ".next")
        _add_directory(archive, "node_modules")
        _add_regular(archive, "server.js")
        _add_regular(archive, "build-metadata.json", b"{}")
        _add_regular(archive, "package.json", b"{}")
        link = tarfile.TarInfo(".next/node_modules/escaped")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    rejected = subprocess.run(
        ["node", str(validator), str(symlink_archive)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "unsupported member type" in rejected.stderr

    materialized_archive = tmp_path / "materialized.tar.gz"
    with tarfile.open(materialized_archive, "w:gz") as archive:
        _add_directory(archive, ".next")
        _add_directory(archive, "node_modules")
        _add_regular(archive, "server.js")
        _add_regular(archive, "build-metadata.json", b"{}")
        _add_regular(archive, "package.json", b"{}")
        _add_regular(archive, ".next/node_modules/materialized", b"dependency bytes")

    accepted = subprocess.run(
        ["node", str(validator), str(materialized_archive)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert accepted.returncode == 0, accepted.stderr
    assert '"archive_symlink_count":0' in accepted.stdout
