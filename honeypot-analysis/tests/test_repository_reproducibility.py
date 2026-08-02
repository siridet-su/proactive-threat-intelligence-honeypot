from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_separates_runtime_and_optional_dependency_groups() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    extras = project["optional-dependencies"]

    assert project["requires-python"] == ">=3.11"
    assert project["dependencies"] == ["requests>=2.31,<3"]
    assert set(extras) == {
        "securebert",
        "training",
        "artifacts",
        "evaluation",
        "test",
    }
    assert any(item.startswith("reportlab") for item in extras["artifacts"])
    assert any(item.startswith("stix2-validator") for item in extras["artifacts"])
    assert any(item.startswith("torch") for item in extras["securebert"])
    assert any(item.startswith("scikit-learn") for item in extras["evaluation"])
    assert any(item.startswith("pytest") for item in extras["test"])


def test_requirement_files_match_documented_optional_groups() -> None:
    expected = {
        "requirements.txt": "requests>=2.31,<3",
        "requirements-dev.txt": "pytest>=8,<10",
        "requirements-securebert.txt": "transformers>=4.40,<5",
        "requirements-training.txt": "pandas>=2.2,<4",
        "requirements-artifacts.txt": "stix2-validator>=3.2,<4",
        "requirements-evaluation.txt": "scikit-learn>=1.4,<2",
    }
    for filename, dependency in expected.items():
        contents = (ROOT / filename).read_text(encoding="utf-8")
        assert dependency in contents, filename
    constraints = (ROOT / "constraints-core-test.txt").read_text(encoding="utf-8")
    assert "requests==" in constraints
    assert "pytest==" in constraints
    for archived in (
        "requirements-mongodb.txt",
        "requirements-postgresql.txt",
        "requirements-vertex.txt",
        "constraints-mongodb.txt",
    ):
        assert not (ROOT / archived).exists()


def test_core_environment_imports_every_production_module_in_isolation() -> None:
    script = f"""
import importlib
import json
import pkgutil
import sys
sys.path.insert(0, {str(ROOT)!r})
import production
failed = []
modules = [item.name for item in pkgutil.walk_packages(production.__path__, production.__name__ + '.')]
for name in modules:
    try:
        importlib.import_module(name)
    except Exception as exc:
        failed.append([name, type(exc).__name__])
print(json.dumps({{'modules': len(modules), 'failed': failed}}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd="/tmp",
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    report = json.loads(result.stdout)
    assert report["modules"] >= 100
    assert report["failed"] == []


def test_all_packaged_service_modules_have_working_help() -> None:
    modules = (
        "production.api.ingest_api",
        "production.api.dashboard_api",
        "production.api.monitor_web",
        "production.workers.session_worker",
        "production.workers.analysis_worker",
        "production.workers.enrichment_worker",
        "production.workers.sensor_forwarder",
        "production.workers.threat_hunt_worker",
        "production.workers.webhook_dispatcher",
        "production.enrichment.refresh_feeds",
    )
    for module in modules:
        result = subprocess.run(
            [sys.executable, "-m", module, "--help"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (module, result.stderr)
        assert "usage:" in result.stdout.lower(), module


def test_generated_and_sensitive_artifact_classes_are_ignored() -> None:
    generated = (
        "evaluation/transient-output.json",
        "evaluation/transient-output.csv",
        "data/feeds/cisa_kev_cache.json",
        "data/feeds/cisa_kev_cache.json.lock",
        "configs/example.generated.json",
        "CODEX_REMEDIATION_HANDOFF.md",
        "reports/report.json",
        "models/model.safetensors",
        "backup.db",
    )
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", *generated],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    ignored = set(result.stdout.splitlines())
    assert ignored == set(generated)
    assert subprocess.run(
        ["git", "check-ignore", "--no-index", "production/api/static/monitor.html"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        timeout=10,
    ).returncode == 1
def test_canonical_docs_cover_runtime_storage_and_artifacts() -> None:
    inventory = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "docs/SYSTEM_ARCHITECTURE.md",
            "docs/SECURITY_AND_PRIVACY.md",
            "docs/DEPLOYMENT_AND_RECOVERY.md",
            "docs/HISTORICAL_IMPLEMENTATION_RECORD.md",
            "docs/MODEL_AND_EVALUATION.md",
        )
    )
    for required in (
        "SQLite",
        "MongoDB",
        "Optional",
        "compatibility",
        "Transformer",
        "VOMM",
        "manual",
        "production/",
        "evaluation/",
        "data/feeds/",
    ):
        assert required in inventory
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "SQLite/Postgres storage adapter" not in readme
    assert "Python 3.10 or newer" not in readme
