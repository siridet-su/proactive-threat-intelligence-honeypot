"""Fresh sanitizer bundles must not silently change the legacy Pi contract."""

from pathlib import Path

from production.cowrie_output.runtime import DEPLOYMENT_CONTRACT, FRESH_DEPLOYMENT_CONTRACT, verify_bundle
from production.tools.cowrie_output_integration import build_bundle


def test_fresh_bundle_omits_legacy_forwarder_without_changing_legacy_contract(tmp_path):
    source = Path(__file__).resolve().parents[1]
    revision = "a" * 40
    fresh = tmp_path / "fresh"
    legacy = tmp_path / "legacy"
    build_bundle(source, fresh, revision, fresh=True)
    build_bundle(source, legacy, revision)
    fresh_manifest, _, _ = verify_bundle(fresh)
    legacy_manifest, _, _ = verify_bundle(legacy)
    assert fresh_manifest["deployment"] == FRESH_DEPLOYMENT_CONTRACT
    assert fresh_manifest["deployment"]["service_impact"]["must_remain_active"] == []
    assert legacy_manifest["deployment"] == DEPLOYMENT_CONTRACT
    assert legacy_manifest["deployment"]["service_impact"]["must_remain_active"] == ["honeypot-sensor-forwarder.service"]
    assert fresh_manifest["component_id"] != legacy_manifest["component_id"]
