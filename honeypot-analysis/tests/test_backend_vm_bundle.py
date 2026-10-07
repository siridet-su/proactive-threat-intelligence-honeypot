"""Migration archive boundaries, using only temporary synthetic files."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[1] / "deployment/gcp/backend_vm.py"
SPEC = importlib.util.spec_from_file_location("backend_vm", MODULE)
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)


@pytest.fixture
def tmp_path():
    # The repository test configuration may put pytest temp files in a checkout;
    # private migration artifacts deliberately reject that destination.
    with tempfile.TemporaryDirectory(prefix="pti-vm-bundle-test-", dir="/tmp") as name:
        yield Path(name)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(root)], check=True)
    source = root / "honeypot-analysis/production"
    source.mkdir(parents=True)
    (source / "entrypoint.py").write_text("# synthetic immutable source\n")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture"], check=True)
    return root


@pytest.fixture
def bundle(repo, tmp_path):
    result = tmp_path / "backend.tar.gz"
    vm.build(repo, "HEAD", result, [])
    return result


def plan_file(tmp_path, assets, **extra):
    path = tmp_path / "private-plan.json"
    path.write_text(json.dumps({"schema_version": vm.PLAN_SCHEMA,
        "host": vm.os_identity(), "required_units": list(vm.CORE_UNITS),
        "assets": assets, **extra}))
    return path


def runtime_file(tmp_path, logical, content=b"synthetic runtime fixture\n"):
    root = tmp_path / "private-runtime"
    path = write_runtime_file(root, logical, content)
    return root, path


def write_runtime_file(root, logical, content=b"synthetic runtime fixture\n"):
    path = root / logical.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def complete_runtime_plan(tmp_path, *, omit_component=None, omit_unit=None,
                          directories=None):
    root = tmp_path / "complete-private-runtime"
    assets = []
    paths = {
        "configuration": "/etc/honeypot/production_config.json",
        "credentials": "/etc/credstore/mongodb-uri",
        "model1": "/opt/honeypot-model-bundles/fixture/model.bin",
        "model2": "/var/lib/model2-v7/fixture.bin",
        "next_distinct": "/opt/honeypot-shadow/fixture/bundle.json",
        "python_runtime": "/opt/honeypot-python-runtimes/fixture/bin/python",
        "feeds": "/var/lib/honeypot/feeds/fixture.json",
        "rollback_backup": "/var/backups/honeypot-external/rollback/receipt.json",
        "host_helpers": "/usr/local/libexec/honeypot-fixture-helper",
    }
    for component, logical in paths.items():
        if component == omit_component:
            continue
        write_runtime_file(root, logical)
        assets.append({"component": component, "source": logical})
    if omit_component != "systemd":
        for unit in vm.CORE_UNITS:
            if unit == omit_unit:
                continue
            logical = f"/etc/systemd/system/{unit}"
            write_runtime_file(root, logical)
            assets.append({"component": "systemd", "source": logical})
    plan = {"schema_version": vm.PLAN_SCHEMA, "host": vm.os_identity(),
            "required_units": list(vm.CORE_UNITS), "assets": assets}
    if directories is not None:
        plan["directories"] = directories
    path = tmp_path / "complete-private-plan.json"
    path.write_text(json.dumps(plan))
    return root, path


def rewritten(bundle, destination, mutate):
    with tarfile.open(bundle, "r:gz") as archive:
        values = {item.name: archive.extractfile(item).read() for item in archive}
    mutate(values)
    with tarfile.open(destination, "w:gz") as archive:
        for name, data in values.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    return destination


def test_dirty_changes_are_excluded(repo, tmp_path):
    (repo / "honeypot-analysis/production/entrypoint.py").write_text("# uncommitted change\n")
    (repo / "honeypot-analysis/private.env").write_text("synthetic private worktree input\n")
    package = tmp_path / "dirty.tar.gz"
    vm.build(repo, "HEAD", package, [])
    manifest = vm.verify(package)
    assert manifest["worktree_changes_excluded"] is True
    with tarfile.open(package, "r:gz") as archive:
        with tarfile.open(fileobj=io.BytesIO(archive.extractfile("sources/backend.tar.gz").read()), mode="r:gz") as source:
            assert source.extractfile("production/entrypoint.py").read() == b"# synthetic immutable source\n"
            assert "private.env" not in source.getnames()


def test_build_is_repeatable(repo, tmp_path):
    first, second = tmp_path / "a.tar.gz", tmp_path / "b.tar.gz"
    vm.build(repo, "HEAD", first, [])
    vm.build(repo, "HEAD", second, [])
    assert first.read_bytes() == second.read_bytes()
    assert first.stat().st_mode & 0o777 == 0o600


def test_source_only_does_not_claim_runtime_parity(bundle):
    manifest = vm.verify(bundle)
    assert manifest["missing_components"] == sorted(vm.COMPONENTS)
    assert manifest["runtime_inputs_complete"] is False
    assert manifest["source_host_health_passed"] is False
    assert manifest["destination_qualified"] is False
    assert manifest["activated"] is False


def test_exact_reference_source_is_included(repo, tmp_path):
    output = tmp_path / "refs.tar.gz"
    vm.build(repo, "HEAD", output, ["HEAD"])
    manifest = vm.verify(output)
    assert manifest["references"][0]["different"] is False
    assert len([v for v in manifest["files"] if v["path"].startswith("sources/")]) == 2


def test_refuses_package_inside_checkout(repo):
    with pytest.raises(ValueError, match="outside"):
        vm.build(repo, "HEAD", repo / "bundle.tar.gz", [])


def test_refuses_existing_package_without_modifying_it(repo, bundle):
    before = bundle.read_bytes()
    with pytest.raises(ValueError, match="overwrite"):
        vm.build(repo, "HEAD", bundle, [])
    assert bundle.read_bytes() == before


def test_stage_checks_external_package_digest_first(bundle, tmp_path):
    target = tmp_path / "new-vm"
    with pytest.raises(ValueError, match="SHA-256"):
        vm.stage(bundle, target, "0" * 64)
    assert not target.exists()


def test_stage_source_without_selecting_active_pointer(bundle, tmp_path):
    target = tmp_path / "new-vm"
    result = vm.stage(bundle, target, vm.file_digest(bundle))
    release = Path(result["release"])
    assert (release / "production/entrypoint.py").read_text() == "# synthetic immutable source\n"
    assert (release / "DEPLOYED_COMMIT").read_text().strip() == release.name
    assert not (target / "opt/honeypot").exists()
    assert result["activated"] is False
    with pytest.raises(ValueError, match="release already"):
        vm.stage(bundle, target, vm.file_digest(bundle))


def test_stage_rejects_existing_active_host(bundle, tmp_path):
    target = tmp_path / "existing-vm"
    (target / "opt/honeypot").mkdir(parents=True)
    with pytest.raises(ValueError, match="active backend"):
        vm.stage(bundle, target, vm.file_digest(bundle))
    assert not (target / "opt/honeypot-releases").exists()


def test_stage_rejects_symlink_parent(bundle, tmp_path):
    target = tmp_path / "new-vm"
    outside = tmp_path / "outside"
    outside.mkdir()
    target.mkdir()
    (target / "opt").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        vm.stage(bundle, target, vm.file_digest(bundle))
    assert list(outside.iterdir()) == []


def test_detects_modified_payload(bundle, tmp_path):
    def mutate(values):
        values["backend_vm.py"] += b"# changed\n"
    damaged = rewritten(bundle, tmp_path / "damaged.tar.gz", mutate)
    with pytest.raises(ValueError, match="size/hash|checksum"):
        vm.verify(damaged)


def test_rejects_undeclared_and_traversal_members(bundle, tmp_path):
    damaged = rewritten(bundle, tmp_path / "extra.tar.gz", lambda v: v.update({"../escape": b"x"}))
    with pytest.raises(ValueError, match="unsafe archive"):
        vm.verify(damaged)


def test_rejects_link_members(bundle, tmp_path):
    output = tmp_path / "linked.tar.gz"
    with tarfile.open(bundle, "r:gz") as source, tarfile.open(output, "w:gz") as dest:
        for item in source:
            dest.addfile(item, source.extractfile(item))
        item = tarfile.TarInfo("external-link")
        item.type = tarfile.SYMTYPE
        item.linkname = "/etc/passwd"
        dest.addfile(item)
    with pytest.raises(ValueError, match="link or special"):
        vm.verify(output)


def test_runtime_assets_are_pinned_and_staged(repo, tmp_path):
    logical = "/etc/honeypot/services/analysis-worker.env"
    root, original = runtime_file(tmp_path, logical)
    os.chmod(original.parent, 0o750)
    plan = plan_file(tmp_path, [{"component": "configuration", "source": logical}])
    output = tmp_path / "runtime.tar.gz"
    vm.build(repo, "HEAD", output, [], plan, root)
    receipt = vm.verify(output)
    assert receipt["contains_private_inputs"] is True
    assert "configuration" not in receipt["missing_components"]
    target = tmp_path / "new-vm"
    vm.stage(output, target, vm.file_digest(output))
    restored = target / logical.lstrip("/")
    assert restored.read_bytes() == original.read_bytes()
    assert restored.parent.stat().st_mode & 0o777 == 0o750


def test_runtime_partial_units_do_not_claim_systemd_complete(repo, tmp_path):
    logical = "/etc/systemd/system/honeypot-ingest-api.service"
    root, _ = runtime_file(tmp_path, logical)
    plan = plan_file(tmp_path, [{"component": "systemd", "source": logical}])
    output = tmp_path / "partial-units.tar.gz"
    vm.build(repo, "HEAD", output, [], plan, root)
    assert "systemd" in vm.verify(output)["missing_components"]


@pytest.mark.parametrize("logical", ["/etc/passwd", "/etc/honeypot/../shadow", "/", "/opt"])
def test_refuses_unscoped_runtime_paths(logical):
    with pytest.raises(ValueError):
        vm.target_path(logical)


@pytest.mark.parametrize("logical", [
    "/var/backups/honeypot-external/verified/receipt.json",
    "/var/lib/model2-v7/runtime.json", "/var/lib/honeypot/reports",
    "/opt/honeypot-releases/0f701f65e2574ba1b3fcf3225c33de15531a4fda",
    "/etc/haproxy/haproxy.cfg",
])
def test_scoped_migration_targets_are_allowed(logical):
    assert vm.target_path(logical) == logical


def test_empty_state_directories_require_directory_metadata_scope():
    for logical in ("/var/lib/honeypot", "/var/lib/honeypot-service-watchdog",
                    vm.EMPTY_CAPTURE_DIRECTORY):
        with pytest.raises(ValueError):
            vm.target_path(logical)
        assert vm.target_path(logical, allow_directory=True) == logical


@pytest.mark.parametrize("logical", [
    "/opt/honeypot-releases", "/opt/honeypot-releases/short",
    "/var/lib/model2-v7/pcap/capture.pcap", "/etc/honeypot/spool/item",
])
def test_scoped_migration_targets_stay_narrow(logical):
    with pytest.raises(ValueError):
        vm.target_path(logical)


def test_empty_runtime_directories_stage_without_component_coverage(repo, tmp_path):
    directory = {"target": "/var/lib/honeypot-service-watchdog",
                 "uid": os.getuid(), "gid": os.getgid(), "mode": 0o750}
    plan = plan_file(tmp_path, [], directories=[directory])
    output = tmp_path / "empty-directory.tar.gz"
    vm.build(repo, "HEAD", output, [], plan)
    manifest = vm.verify(output)
    assert manifest["runtime_assets"] == []
    assert manifest["missing_components"] == sorted(vm.COMPONENTS)
    assert manifest["runtime_directories"] == [directory]
    target = tmp_path / "fresh-root"
    vm.stage(output, target, vm.file_digest(output))
    restored = target / directory["target"].lstrip("/")
    assert restored.is_dir()
    assert restored.stat().st_mode & 0o777 == 0o750


def test_exact_empty_pcap_directory_can_be_restored_without_runtime_payload(repo, tmp_path):
    directory = {"target": vm.EMPTY_CAPTURE_DIRECTORY,
                 "uid": 992, "gid": 983, "mode": 0o750}
    plan = plan_file(tmp_path, [], directories=[directory])
    output = tmp_path / "empty-pcap-directory.tar.gz"
    vm.build(repo, "HEAD", output, [], plan)
    manifest = vm.verify(output)
    assert manifest["runtime_assets"] == []
    assert manifest["missing_components"] == sorted(vm.COMPONENTS)
    target = tmp_path / "fresh-root"
    vm.stage(output, target, vm.file_digest(output))
    restored = target / directory["target"].lstrip("/")
    assert restored.is_dir()
    assert restored.stat().st_mode & 0o777 == 0o750


def test_historic_release_directory_preserves_source_contents(tmp_path):
    revision = "0f701f65e2574ba1b3fcf3225c33de15531a4fda"
    root = tmp_path / "source-root"
    release = f"/opt/honeypot-releases/{revision}"
    write_runtime_file(root, release + "/configs/source.json", b"synthetic config\n")
    write_runtime_file(root, release + "/production/worker.py", b"synthetic worker\n")
    write_runtime_file(root, release + "/DEPLOYED_COMMIT", (revision + "\n").encode())
    plan = {"schema_version": vm.PLAN_SCHEMA,
            "assets": [{"component": "model2", "source": release}]}
    payloads, entries, _ = vm.asset_entries(plan, root, "3cf60ae69a1fcc3d60059c65076144c8ae02a58a")
    names = {value["target"] for value in entries if "target" in value}
    assert release + "/configs/source.json" in names
    assert release + "/production/worker.py" in names
    assert release + "/DEPLOYED_COMMIT" in names
    assert not any(".venv" in name for name in names)
    assert len(payloads) == 3


def test_refuses_runtime_source_parent_symlink(repo, tmp_path):
    root = tmp_path / "private-runtime"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "fixture.env").write_text("synthetic\n")
    (root / "etc").mkdir(parents=True)
    (root / "etc/honeypot").symlink_to(outside)
    plan = plan_file(tmp_path, [{"component": "configuration", "source": "/etc/honeypot/fixture.env"}])
    with pytest.raises(ValueError, match="symlink"):
        vm.build(repo, "HEAD", tmp_path / "bad.tar.gz", [], plan, root)


def test_refuses_unbound_runtime_symlink(repo, tmp_path):
    root, fixture = runtime_file(tmp_path, "/opt/honeypot-shadow/test/fixture.py")
    (fixture.parent / "other").symlink_to("/etc/passwd")
    plan = plan_file(tmp_path, [{"component": "next_distinct", "source": "/opt/honeypot-shadow/test"}])
    with pytest.raises(ValueError, match="symlink points outside"):
        vm.build(repo, "HEAD", tmp_path / "bad.tar.gz", [], plan, root)


def test_explicit_runtime_link_to_bundled_python_directory(repo, tmp_path):
    root, original = runtime_file(tmp_path, "/opt/honeypot-python-runtimes/test/bin/python", b"synthetic executable\n")
    plan = plan_file(tmp_path, [{"component": "python_runtime", "source": "/opt/honeypot-python-runtimes/test"}],
        links=[{"component": "python_runtime", "path": "/opt/honeypot-releases/{revision}/.venv",
                "target": "/opt/honeypot-python-runtimes/test"}])
    output = tmp_path / "python.tar.gz"
    vm.build(repo, "HEAD", output, [], plan, root)
    target = tmp_path / "new-vm"
    result = vm.stage(output, target, vm.file_digest(output))
    assert (Path(result["release"]) / ".venv/bin/python").read_bytes() == original.read_bytes()


def test_requires_matching_os_for_private_runtime_assets(repo, tmp_path):
    logical = "/etc/honeypot/fixture.env"
    root, _ = runtime_file(tmp_path, logical)
    plan = plan_file(tmp_path, [{"component": "configuration", "source": logical}], host={"id": "other"})
    output = tmp_path / "os.tar.gz"
    vm.build(repo, "HEAD", output, [], plan, root)
    target = tmp_path / "new-vm"
    with pytest.raises(ValueError, match="OS/version/architecture"):
        vm.stage(output, target, vm.file_digest(output))
    assert not target.exists()


def test_refuses_live_database_as_runtime_input(repo, tmp_path):
    logical = "/etc/honeypot/fixture.db"
    root, _ = runtime_file(tmp_path, logical)
    plan = plan_file(tmp_path, [{"component": "configuration", "source": logical}])
    with pytest.raises(ValueError, match="verified backup"):
        vm.build(repo, "HEAD", tmp_path / "live.tar.gz", [], plan, root)


def test_accepts_verified_external_rollback_database(repo, tmp_path):
    logical = "/var/backups/honeypot-external/fixture/mirror.db"
    root, dbpath = runtime_file(tmp_path, logical, b"")
    with sqlite3.connect(dbpath) as db:
        db.execute("CREATE TABLE fixture (id INTEGER)")
    plan = plan_file(tmp_path, [{"component": "rollback_backup", "source": logical}])
    output = tmp_path / "external-mirror.tar.gz"
    vm.build(repo, "HEAD", output, [], plan, root)
    assert "rollback_backup" not in vm.verify(output)["missing_components"]


def test_rejects_live_pcap_file(repo, tmp_path):
    logical = "/var/lib/model2-v7/capture.pcap"
    root, _ = runtime_file(tmp_path, logical, b"")
    plan = plan_file(tmp_path, [{"component": "model2", "source": logical}])
    with pytest.raises(ValueError, match="pcap/spool"):
        vm.build(repo, "HEAD", tmp_path / "pcap-file.tar.gz", [], plan, root)


def test_rejects_pcap_directory_instead_of_silently_omitting_it(repo, tmp_path):
    root, _ = runtime_file(tmp_path, "/var/lib/model2-v7/model.json")
    write_runtime_file(root, "/var/lib/model2-v7/pcap/capture.bin", b"")
    plan = plan_file(tmp_path, [{"component": "model2", "source": "/var/lib/model2-v7"}])
    output = tmp_path / "pcap-directory.tar.gz"
    with pytest.raises(ValueError, match="pcap/spool"):
        vm.build(repo, "HEAD", output, [], plan, root)
    assert not output.exists()


def test_only_verified_backup_can_restore_mirror(repo, tmp_path):
    logical = "/var/backups/honeypot/fixture/mirror.db"
    root, dbpath = runtime_file(tmp_path, logical, b"")
    with sqlite3.connect(dbpath) as db:
        db.execute("CREATE TABLE fixture (id INTEGER)")
    plan = plan_file(tmp_path, [{"component": "rollback_backup", "source": logical,
                               "target": "/var/lib/honeypot/mongodb_epoch_rollback.db"}])
    output = tmp_path / "mirror.tar.gz"
    vm.build(repo, "HEAD", output, [], plan, root)
    target = tmp_path / "new-vm"
    vm.stage(output, target, vm.file_digest(output))
    assert (target / "var/lib/honeypot/mongodb_epoch_rollback.db").read_bytes() == dbpath.read_bytes()


def test_runtime_file_conflict_stops_before_source_writes(repo, tmp_path):
    logical = "/etc/honeypot/fixture.env"
    root, _ = runtime_file(tmp_path, logical)
    plan = plan_file(tmp_path, [{"component": "configuration", "source": logical}])
    output = tmp_path / "runtime.tar.gz"
    vm.build(repo, "HEAD", output, [], plan, root)
    target = tmp_path / "new-vm"
    existing = target / logical.lstrip("/")
    existing.parent.mkdir(parents=True)
    existing.write_text("retained destination\n")
    with pytest.raises(ValueError, match="overwrite"):
        vm.stage(output, target, vm.file_digest(output))
    assert not (target / "opt").exists()
    assert existing.read_text() == "retained destination\n"


def test_snapshot_does_not_export_inline_environment_or_exec_secrets(tmp_path, monkeypatch):
    def fake(args, timeout=30):
        if "is-active" in args:
            return "active"
        if "show" in args:
            return "User=\nGroup=\nExecStart={ path=/opt/honeypot/.venv/bin/python ; argv[]=python --token=synthetic-sensitive-value ; }\nEnvironment=TOKEN=synthetic-sensitive-value"
        return ""
    monkeypatch.setattr(vm, "command", fake)
    monkeypatch.setattr(vm, "health", lambda units, **kwargs: {"passed": False})
    output = tmp_path / "snapshot.json"
    receipt = vm.snapshot(output)
    assert "synthetic-sensitive-value" not in output.read_text()
    assert receipt["private_file_contents_collected"] is False
    assert output.stat().st_mode & 0o777 == 0o600


def test_snapshot_includes_disabled_timer_companions_and_deployed_units(tmp_path, monkeypatch):
    seen = set()
    health_units = []

    def fake_command(args, timeout=30):
        if "list-unit-files" in args:
            return "honeypot-fixture.timer disabled\n"
        if "show" in args:
            seen.add(args[2])
            return "Type=oneshot\nActiveState=inactive\nUser=\nGroup=\n"
        raise AssertionError("unexpected command")

    def fake_health(units, probes=None, unit_metadata=None):
        health_units.extend(units)
        return {"passed": True, "units": [], "endpoints": []}

    monkeypatch.setattr(vm, "command", fake_command)
    monkeypatch.setattr(vm, "health", fake_health)
    receipt = vm.snapshot(tmp_path / "inventory.json")
    names = {entry["name"] for entry in receipt["units"]}
    assert "honeypot-fixture.timer" in names
    assert "honeypot-fixture.service" in names
    assert set(vm.DEPLOYED_COMPAT_UNITS).issubset(names)
    assert {unit[:-len(".timer")] + ".service" for unit in vm.CORE_UNITS
            if unit.endswith(".timer")}.issubset(names)
    assert "honeypot-fixture.service" not in health_units
    assert "honeypot-fixture.service" in seen


def test_health_failure_is_explicit(monkeypatch):
    def unavailable(*args, **kwargs):
        raise ValueError("unavailable")
    monkeypatch.setattr(vm, "command", unavailable)
    result = vm.health([vm.CORE_UNITS[0]], [])
    assert result["passed"] is False
    assert result["units"][0]["state"] == "inactive_or_unavailable"


def test_inactive_oneshot_is_not_unhealthy(monkeypatch):
    monkeypatch.setattr(vm, "command", lambda *args, **kwargs:
                        "Type=oneshot\nActiveState=inactive\nResult=success\n")
    result = vm.health(["honeypot-fixture.service"], [])
    assert result["passed"] is True
    assert result["units"] == [{"unit": "honeypot-fixture.service",
                                 "state": "inactive", "result": "success", "passed": True}]


def test_failed_inactive_oneshot_is_unhealthy(monkeypatch):
    monkeypatch.setattr(vm, "command", lambda *args, **kwargs:
                        "Type=oneshot\nActiveState=inactive\nResult=exit-code\n")
    result = vm.health(["honeypot-fixture.service"], [])
    assert result["passed"] is False
    assert result["units"][0]["result"] == "exit-code"


def coverage_commit(repo, *, behavior=("behavior-a",), rules=("guidance-a",),
                    actions=("action-a",), scopes=("bounded_cowrie_fixture",)):
    """Owned synthetic policies; never imports or executes a packaged backend."""
    config = repo / "honeypot-analysis/configs"
    config.mkdir(exist_ok=True)
    (config / "threat_hypothesis_behavior.trusted.json").write_text(json.dumps(
        {"policy": {"rules": [{"rule_id": name} for name in behavior]}}))
    (config / "response_guidance_policy.v3.json").write_text(json.dumps(
        {"rules": [{"rule_id": name} for name in rules],
         "actions": [{"action_id": name} for name in actions]}))
    source = repo / "honeypot-analysis/production/reporting"
    source.mkdir(exist_ok=True)
    (source / "session_assessment_v4.py").write_text(f"SCOPES = {scopes!r}\n")
    subprocess.run(["git", "-C", str(repo), "add", "honeypot-analysis"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "coverage"], check=True)
    return vm.command(["git", "-C", str(repo), "rev-parse", "HEAD"])


def test_preserved_coverage_floor_is_archived_and_recomputed(repo, tmp_path):
    floor = coverage_commit(repo)
    coverage_commit(repo, actions=("action-a", "action-b"))
    output = tmp_path / "preserved.tar.gz"
    vm.build(repo, "HEAD", output, [floor], coverage_baseline=floor)
    manifest = vm.verify(output)
    gate = manifest["rule_coverage"]
    assert gate["baseline_revision"] == floor
    assert gate["added"]["guidance_action_ids"] == ["action-b"]
    assert not any(gate["removed"].values())
    assert gate["static_presence_only"] is True
    assert gate["runtime_semantics_qualified"] is False
    assert len(manifest["references"]) == 1


@pytest.mark.parametrize("change", [
    {"behavior": ("behavior-b",)}, {"rules": ("guidance-b",)},
    {"actions": ("action-b",)}, {"scopes": ("bounded_cowrie_different",)},
])
def test_equal_counts_cannot_hide_lost_rule_identity(repo, tmp_path, change):
    floor = coverage_commit(repo)
    coverage_commit(repo, **change)
    output = tmp_path / "regressed.tar.gz"
    with pytest.raises(ValueError, match="coverage regressed"):
        vm.build(repo, "HEAD", output, [], coverage_baseline=floor)
    assert not output.exists()


def test_inventory_automatically_requires_actual_active_floor(repo, tmp_path):
    floor = coverage_commit(repo)
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"schema_version": "pti_backend_vm_inventory.v1",
                                    "active_revision": floor, "health": {"passed": False}}))
    coverage_commit(repo, actions=("action-a", "action-b"))
    output = tmp_path / "inventory-floor.tar.gz"
    vm.build(repo, "HEAD", output, [], inventory_path=inventory)
    assert vm.verify(output)["rule_coverage"]["baseline_revision"] == floor
    with pytest.raises(ValueError, match="differs from source-host"):
        vm.build(repo, "HEAD", tmp_path / "wrong-floor.tar.gz", [],
                 inventory_path=inventory, coverage_baseline="HEAD")


def test_verify_does_not_trust_rehashed_coverage_claim(repo, tmp_path):
    floor = coverage_commit(repo)
    package = tmp_path / "valid-floor.tar.gz"
    vm.build(repo, "HEAD", package, [], coverage_baseline=floor)

    def mutate(values):
        gate = json.loads(values["RULE_COVERAGE.json"])
        gate["candidate"]["guidance_action_ids"] = []
        values["RULE_COVERAGE.json"] = vm.encoded(gate)
        manifest = json.loads(values["BUNDLE_MANIFEST.json"])
        manifest["rule_coverage"] = gate
        for item in manifest["files"]:
            if item["path"] == "RULE_COVERAGE.json":
                item.update(sha256=vm.digest(values[item["path"]]), bytes=len(values[item["path"]]))
        values["BUNDLE_MANIFEST.json"] = vm.encoded(manifest)

    damaged = rewritten(package, tmp_path / "false-coverage.tar.gz", mutate)
    with pytest.raises(ValueError, match="coverage receipt is inconsistent"):
        vm.verify(damaged)


def test_verify_rejects_removed_inventory_floor_even_when_rehashed(repo, tmp_path):
    floor = coverage_commit(repo)
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps({"schema_version": "pti_backend_vm_inventory.v1",
                                    "active_revision": floor}))
    package = tmp_path / "with-inventory.tar.gz"
    vm.build(repo, "HEAD", package, [], inventory_path=inventory)

    def mutate(values):
        manifest = json.loads(values["BUNDLE_MANIFEST.json"])
        manifest["rule_coverage"] = None
        values["BUNDLE_MANIFEST.json"] = vm.encoded(manifest)

    damaged = rewritten(package, tmp_path / "missing-floor.tar.gz", mutate)
    with pytest.raises(ValueError, match="inventory requires"):
        vm.verify(damaged)


def test_cli_verifies_sha_pinned_source_kit(bundle, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["backend_vm.py", "verify", "--source-kit",
        str(bundle), "--sha256", vm.file_digest(bundle)])
    assert vm.main() == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


def test_complete_rejects_tampered_source_kit_before_output(repo, tmp_path):
    source_kit = tmp_path / "source-only.tar.gz"
    vm.build(repo, "HEAD", source_kit, [])
    root, plan = complete_runtime_plan(tmp_path)
    tampered = tmp_path / "tampered-source-only.tar.gz"
    tampered.write_bytes(source_kit.read_bytes() + b"tampered")
    output = tmp_path / "must-not-exist.tar.gz"
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        vm.assemble(tampered, vm.file_digest(source_kit), output, plan, root)
    assert not output.exists()


def test_complete_rejects_a_source_kit_that_already_has_runtime_assets(repo, tmp_path):
    root, _ = runtime_file(tmp_path, "/etc/honeypot/fixture.env")
    plan = plan_file(tmp_path, [{"component": "configuration",
                                 "source": "/etc/honeypot/fixture.env"}])
    source_kit = tmp_path / "not-source-only.tar.gz"
    vm.build(repo, "HEAD", source_kit, [], plan, root)
    with pytest.raises(ValueError, match="must not contain runtime assets"):
        vm.verify_source_kit(source_kit, vm.file_digest(source_kit))


@pytest.mark.parametrize("omit_component,omit_unit", [
    ("feeds", None), (None, vm.CORE_UNITS[0]),
])
def test_complete_missing_component_or_unit_stops_before_output(
        repo, tmp_path, omit_component, omit_unit):
    source_kit = tmp_path / "source-only.tar.gz"
    vm.build(repo, "HEAD", source_kit, [])
    root, plan = complete_runtime_plan(tmp_path, omit_component=omit_component,
                                       omit_unit=omit_unit)
    output = tmp_path / "incomplete-must-not-publish.tar.gz"
    with pytest.raises(ValueError, match="runtime plan is incomplete"):
        vm.assemble(source_kit, vm.file_digest(source_kit), output, plan, root)
    assert not output.exists()


def test_complete_cli_uses_source_sha256_option(repo, tmp_path, monkeypatch, capsys):
    source_kit = tmp_path / "source-only.tar.gz"
    vm.build(repo, "HEAD", source_kit, [])
    root, plan = complete_runtime_plan(tmp_path)
    output = tmp_path / "complete-cli.tar.gz"
    monkeypatch.setattr(sys, "argv", ["backend_vm.py", "complete",
        "--source-kit", str(source_kit), "--source-sha256", vm.file_digest(source_kit),
        "--runtime-plan", str(plan), "--runtime-root", str(root), "--output", str(output)])
    assert vm.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["runtime_inputs_complete"] is True
    assert vm.verify(output)["activated"] is False


def test_complete_requires_inventory_revision_to_match_source_coverage(repo, tmp_path):
    floor = coverage_commit(repo)
    coverage_commit(repo, actions=("action-a", "action-b"))
    source_kit = tmp_path / "source-only-with-floor.tar.gz"
    vm.build(repo, "HEAD", source_kit, [], coverage_baseline=floor)
    root, plan = complete_runtime_plan(tmp_path)
    inventory = tmp_path / "wrong-inventory.json"
    inventory.write_text(json.dumps({"schema_version": "pti_backend_vm_inventory.v1",
        "active_revision": "a" * 40, "health": {"passed": False}}))
    output = tmp_path / "wrong-inventory-must-not-publish.tar.gz"
    with pytest.raises(ValueError, match="differs from source-kit coverage baseline"):
        vm.assemble(source_kit, vm.file_digest(source_kit), output, plan, root, inventory)
    assert not output.exists()


def test_complete_without_git_preserves_static_archives_and_health(repo, tmp_path, monkeypatch):
    floor = coverage_commit(repo)
    coverage_commit(repo, actions=("action-a", "action-b"))
    old_inventory = tmp_path / "old-inventory.json"
    old_inventory.write_text(json.dumps({"schema_version": "pti_backend_vm_inventory.v1",
        "active_revision": floor, "health": {"passed": True}}))
    source_kit = tmp_path / "source-only-with-floor.tar.gz"
    vm.build(repo, "HEAD", source_kit, [], inventory_path=old_inventory)
    source_manifest = vm.verify_source_kit(source_kit, vm.file_digest(source_kit))
    root, plan = complete_runtime_plan(tmp_path)
    fresh_inventory = tmp_path / "fresh-inventory.json"
    fresh_inventory.write_text(json.dumps({"schema_version": "pti_backend_vm_inventory.v1",
        "active_revision": floor, "health": {"passed": False}}))

    def forbidden(*args, **kwargs):
        raise AssertionError("complete must not invoke Git")

    monkeypatch.setattr(vm, "git_archive", forbidden)
    monkeypatch.setattr(vm, "command", forbidden)
    output = tmp_path / "complete.tar.gz"
    result = vm.assemble(source_kit, vm.file_digest(source_kit), output, plan, root,
                         fresh_inventory)
    manifest = vm.verify(output, result["sha256"])
    assert manifest["primary_revision"] == source_manifest["primary_revision"]
    assert manifest["source_kit_sha256"] == vm.file_digest(source_kit)
    assert manifest["rule_coverage"] == source_manifest["rule_coverage"]
    assert manifest["missing_components"] == []
    assert manifest["runtime_inputs_complete"] is True
    assert manifest["source_host_health_passed"] is False
    assert manifest["destination_qualified"] is False
    assert manifest["activated"] is False
    assert output.stat().st_mode & 0o777 == 0o600
    old_files = {entry["path"]: entry["sha256"] for entry in source_manifest["files"]}
    new_files = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    preserved = [name for name in old_files if name.startswith(("sources/", "operator-docs/"))
                 or name == "RULE_COVERAGE.json"]
    assert all(new_files[name] == old_files[name] for name in preserved)
    assert new_files["backend_vm.py"] == vm.digest(Path(vm.__file__).read_bytes())
    with tarfile.open(output, "r:gz") as archive:
        assert json.load(archive.extractfile("inventory.json")) == json.loads(fresh_inventory.read_text())


def test_verify_rejects_unmapped_runtime_payload(repo, tmp_path):
    logical = "/etc/honeypot/fixture.env"
    root, _ = runtime_file(tmp_path, logical)
    plan = plan_file(tmp_path, [{"component": "configuration", "source": logical}])
    package = tmp_path / "runtime-package.tar.gz"
    vm.build(repo, "HEAD", package, [], plan, root)

    def mutate(values):
        values["runtime/unmapped"] = b"synthetic\n"
        manifest = json.loads(values["BUNDLE_MANIFEST.json"])
        manifest["files"].append({"path": "runtime/unmapped",
            "sha256": vm.digest(values["runtime/unmapped"]),
            "bytes": len(values["runtime/unmapped"])})
        values["BUNDLE_MANIFEST.json"] = vm.encoded(manifest)

    damaged = rewritten(package, tmp_path / "unmapped-runtime.tar.gz", mutate)
    with pytest.raises(ValueError, match="not mapped"):
        vm.verify(damaged)


def test_verify_rejects_asset_declared_as_both_file_and_symlink(repo, tmp_path):
    logical = "/etc/honeypot/fixture.env"
    root, _ = runtime_file(tmp_path, logical)
    plan = plan_file(tmp_path, [{"component": "configuration", "source": logical}])
    package = tmp_path / "runtime-package.tar.gz"
    vm.build(repo, "HEAD", package, [], plan, root)

    def mutate(values):
        manifest = json.loads(values["BUNDLE_MANIFEST.json"])
        manifest["runtime_assets"][0]["link_target"] = "/etc/passwd"
        values["BUNDLE_MANIFEST.json"] = vm.encoded(manifest)

    damaged = rewritten(package, tmp_path / "file-and-link.tar.gz", mutate)
    with pytest.raises(ValueError, match="exactly one file or symlink"):
        vm.verify(damaged)


def test_verify_validates_rehashed_runtime_plan_required_unit_names(repo, tmp_path):
    logical = "/etc/honeypot/fixture.env"
    root, _ = runtime_file(tmp_path, logical)
    plan = plan_file(tmp_path, [{"component": "configuration", "source": logical}])
    package = tmp_path / "runtime-package.tar.gz"
    vm.build(repo, "HEAD", package, [], plan, root)

    def mutate(values):
        plan_value = json.loads(values["runtime-plan.json"])
        plan_value["required_units"] = ["forged.service"]
        values["runtime-plan.json"] = vm.encoded(plan_value)
        manifest = json.loads(values["BUNDLE_MANIFEST.json"])
        for entry in manifest["files"]:
            if entry["path"] == "runtime-plan.json":
                entry["sha256"] = vm.digest(values["runtime-plan.json"])
                entry["bytes"] = len(values["runtime-plan.json"])
        values["BUNDLE_MANIFEST.json"] = vm.encoded(manifest)

    damaged = rewritten(package, tmp_path / "bad-units.tar.gz", mutate)
    with pytest.raises(ValueError, match="invalid required units"):
        vm.verify(damaged)
