#!/usr/bin/env python3
"""Isolated localhost-only Final POC shadow service.

This is deployment glue, not a change to the frozen model bundle.  It loads
only the content-addressed bundle supplied with --bundle, performs the bundle
and golden-fixture checks before opening a socket, and exposes a
non-authoritative prediction-only HTTP endpoint.  It has no production,
database, canonical, or provider imports.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


EXPECTED_CHECKPOINT = "16506e962432f9921d18a514c3a31686a20f9734385ec49439ad2651e4cdd283"
EXPECTED_TEMPERATURE = 0.6990670591704266
EXPECTED_TEMPERATURE_SHA = "e6465b3ed2d8711e2a2417bb49c103af18f3c21e19a5919164bdd67246cb6731"
EXPECTED_LABEL_SHA = "94d41ef0f1bcfd49e4f0968f730148aeb76c8035cefe723a426c38c93f874707"
EXPECTED_BINDING_SHA = "5141d0ec0b3f7ebee614eecf5d9168d76e099df478ece3f7e094d3bf533427a0"
EXPECTED_BUNDLE_SHA = "b1c16786422dc619e0f4815035ea798261275259018f184d951d1c87b4bc8d6c"
EXPECTED_CONFIG_SHA = "b8cc325262c5f3688b26c4d0b0b4e244fce45c4bba3b86161449c19e457675d2"
EXPECTED_LABELS = (
    "command-and-control",
    "credential-access",
    "defense-evasion",
    "discovery",
    "execution",
    "persistence",
    "privilege-escalation",
)


class StartupFailure(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def load_module(name: str, path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise StartupFailure(f"missing or symlinked module: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise StartupFailure(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bundle_payload_hash(bundle: Path, excluded: set[str]) -> tuple[str, dict[str, str]]:
    records: dict[str, str] = {}
    for path in sorted(bundle.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rel = str(path.relative_to(bundle))
            # Python may emit non-authoritative bytecode beside source files;
            # those diagnostics are never part of the frozen payload hash.
            if rel not in excluded and "__pycache__/" not in rel and not rel.endswith(".pyc"):
                records[rel] = sha256_file(path)
    return sha256_json(records), records


def _finite_vector(values: list[Any], expected: int) -> None:
    if len(values) != expected or any(not math.isfinite(float(v)) for v in values):
        raise StartupFailure("non-finite or wrong-sized vector")


def verify_bundle(bundle: Path) -> dict[str, Any]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise StartupFailure("bundle directory missing or symlinked")
    manifest_path = bundle / "final_poc_bundle_manifest.json"
    if sha256_file(manifest_path) != "8aa7986017a92500162d8d3980c4445b41367800ca1d16fda1d2c2a2a3b7519a":
        raise StartupFailure("bundle manifest SHA mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = manifest.get("files")
    if not isinstance(records, dict) or not records:
        raise StartupFailure("bundle manifest has no records")
    for rel, expected in records.items():
        path = bundle / rel
        if not path.is_file() or path.is_symlink() or sha256_file(path) != expected:
            raise StartupFailure(f"bundle file hash mismatch: {rel}")
    payload_hash, payload_records = bundle_payload_hash(
        bundle, {"final_poc_bundle_manifest.json", "deployment/final_poc_gcp_deployment_manifest.json"}
    )
    expected_payload_records = {
        str(k): str(v) for k, v in records.items() if k != "deployment/final_poc_gcp_deployment_manifest.json"
    }
    if payload_hash != EXPECTED_BUNDLE_SHA or payload_records != expected_payload_records:
        raise StartupFailure("bundle payload hash mismatch")

    old_checkpoint = bundle / "checkpoint/final_padding_study_transformer.pt"
    if old_checkpoint.exists():
        raise StartupFailure("excluded padding-study checkpoint present")
    binding_path = bundle / "final_poc_runtime_binding.json"
    if sha256_file(binding_path) != EXPECTED_BINDING_SHA:
        raise StartupFailure("runtime binding SHA mismatch")
    config_path = bundle / "config/final_model_config.json"
    temp_path = bundle / "config/final_retained_model_temperature.json"
    label_path = bundle / "config/runtime_label_binding.json"
    if sha256_file(config_path) != EXPECTED_CONFIG_SHA:
        raise StartupFailure("model config SHA mismatch")
    if sha256_file(temp_path) != EXPECTED_TEMPERATURE_SHA:
        raise StartupFailure("temperature artifact SHA mismatch")
    if sha256_file(label_path) != EXPECTED_LABEL_SHA:
        raise StartupFailure("label binding SHA mismatch")

    previous_cwd = Path.cwd()
    os.chdir(bundle)
    try:
        adapter = load_module("final_poc_shadow_adapter", bundle / "adapter/adapter.py")
        binding = adapter.load_runtime_binding(binding_path)
        if binding.get("checkpoint_sha256") != EXPECTED_CHECKPOINT:
            raise StartupFailure("retained checkpoint identity mismatch")
        if binding.get("temperature") != EXPECTED_TEMPERATURE:
            raise StartupFailure("retained temperature mismatch")
        if binding.get("label_order") != list(EXPECTED_LABELS):
            raise StartupFailure("label order mismatch")
        if binding.get("authority") != "non_authoritative" or binding.get("canonical_write_allowed") is not False:
            raise StartupFailure("authority boundary mismatch")
        temperature_artifact = json.loads(temp_path.read_text(encoding="utf-8"))
        if float(temperature_artifact.get("temperature_full_precision")) != EXPECTED_TEMPERATURE:
            raise StartupFailure("active temperature artifact mismatch")
        if temperature_artifact.get("selected_checkpoint_sha256") != EXPECTED_CHECKPOINT:
            raise StartupFailure("temperature checkpoint binding mismatch")
        loader = load_module("final_poc_shadow_loader", bundle / "runtime/model_loader.py")
        model = loader.load_checkpoint(Path(binding["checkpoint_path"]), EXPECTED_CHECKPOINT)
        if sum(int(p.numel()) for p in model.parameters()) != 2599:
            raise StartupFailure("parameter count mismatch")
        model.eval()
        golden = json.loads((bundle / "fixtures/golden_runtime_predictions.json").read_text(encoding="utf-8"))
        fixtures = golden.get("fixtures", [])
        if not fixtures:
            raise StartupFailure("golden fixtures missing")
        import torch
        import numpy as np
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        for fixture in fixtures:
            history = adapter.prepare_history(fixture["input_history"])
            tokens = loader.tokens_for_history(history["sequence"])
            with torch.no_grad():
                logits = model(tokens).detach().cpu().numpy()[0].astype(float).tolist()
            _finite_vector(logits, 7)
            if logits != fixture["raw_logits"] and not np.allclose(logits, fixture["raw_logits"], atol=0.0, rtol=0.0):
                raise StartupFailure(f"golden logits mismatch: {fixture['fixture_id']}")
            output = adapter.predict_from_logits(
                fixture["input_history"], logits, temperature=EXPECTED_TEMPERATURE,
                model_identifier="finalf_refined_v1_prediction_only", checkpoint_sha256=EXPECTED_CHECKPOINT,
            )
            if output["top3"] != fixture["calibrated_ranking"] or not np.allclose(
                output["probabilities"], fixture["calibrated_probabilities"], atol=0.0, rtol=0.0
            ):
                raise StartupFailure(f"golden calibrated mismatch: {fixture['fixture_id']}")
    finally:
        try:
            os.chdir(previous_cwd)
        except PermissionError:
            # A least-privilege caller may not be allowed back into its
            # invoking home directory; never let that mask bundle success.
            os.chdir("/")
    return {
        "status": "COMPLETE_VALID",
        "model_ready": True,
        "checkpoint_sha256": EXPECTED_CHECKPOINT,
        "temperature": EXPECTED_TEMPERATURE,
        "temperature_artifact_sha256": EXPECTED_TEMPERATURE_SHA,
        "label_binding_sha256": EXPECTED_LABEL_SHA,
        "runtime_binding_sha256": EXPECTED_BINDING_SHA,
        "bundle_sha256": EXPECTED_BUNDLE_SHA,
        "parameter_count": 2599,
        "golden_fixtures_replayed": len(fixtures),
        "authority": "non_authoritative",
        "canonical_write_allowed": False,
        "task": "next_observed_distinct_tactic",
        "max_history": 8,
    }, adapter, loader, model, binding


class ShadowHandler(BaseHTTPRequestHandler):
    server_version = "FinalFShadow/1.0"

    def _send(self, status: int, body: dict[str, Any]) -> None:
        data = (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._send(HTTPStatus.NOT_FOUND, {"status": "NOT_FOUND"})
            return
        self._send(HTTPStatus.OK, {**self.server.ready, "status": "READY"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/predict":
            self._send(HTTPStatus.NOT_FOUND, {"status": "NOT_FOUND"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > 1_000_000:
                raise ValueError("invalid content length")
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(body, dict) or "observations" not in body:
                raise ValueError("request must contain observations")
            observations = body["observations"]
            if not isinstance(observations, list):
                raise ValueError("observations must be a list")
            adapter = self.server.adapter
            loader = self.server.loader
            history = adapter.prepare_history(observations)
            tokens = loader.tokens_for_history(history["sequence"])
            with self.server.torch.no_grad():
                logits = self.server.model(tokens).detach().cpu().numpy()[0].astype(float).tolist()
            output = adapter.predict_from_logits(
                observations, logits, temperature=EXPECTED_TEMPERATURE,
                model_identifier="finalf_refined_v1_prediction_only", checkpoint_sha256=EXPECTED_CHECKPOINT,
            )
            output["raw_logits"] = logits
            self._send(HTTPStatus.OK, output)
        except Exception as exc:  # fail closed for malformed/unknown input
            self._send(HTTPStatus.BAD_REQUEST, {"status": "REJECTED", "error": str(exc)[:240]})

    def log_message(self, fmt: str, *args: Any) -> None:
        # Journald is the isolated service diagnostic sink; no canonical file is touched.
        sys.stderr.write((fmt % args) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args()
    if args.bind != "127.0.0.1" or args.port != 18082:
        print("refusing non-localhost/non-approved listener", file=sys.stderr)
        return 2
    try:
        ready, adapter, loader, model, binding = verify_bundle(args.bundle.resolve())
    except Exception as exc:
        print(f"STARTUP_FAIL_CLOSED: {exc}", file=sys.stderr)
        return 3
    import torch
    server = ThreadingHTTPServer((args.bind, args.port), ShadowHandler)
    server.daemon_threads = True
    server.ready = ready
    server.adapter = adapter
    server.loader = loader
    server.model = model
    server.binding = binding
    server.torch = torch
    print(json.dumps({"event": "READY", **ready}, sort_keys=True), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
