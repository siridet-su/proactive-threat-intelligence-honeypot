#!/usr/bin/env python3
"""MongoDB-backed, read-only production shadow feeder.

This is a versioned replacement for the 2026-08-23 SQLite feeder.  It reads
only the active canonical MongoDB ``sessions`` collection, accepts only
server-produced v3 trusted-history manifests from ``production_live`` rows,
and writes privacy-safe records below a separate shadow root.  No MongoDB
insert/update/delete operation is present or called by this module.

The activation cursor is seeded before the service starts.  Existing rows are
therefore never replayed; only rows with a strictly greater
``(updated_at, session_id, revision)`` cursor are considered after activation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional
from urllib import error as urlerror
from urllib import request as urlrequest

try:
    from pymongo import MongoClient
except ImportError:  # pragma: no cover - exercised only by unavailable runtimes
    MongoClient = None  # type: ignore[assignment]


LABEL_ORDER = (
    "command-and-control", "credential-access", "defense-evasion",
    "discovery", "execution", "persistence", "privilege-escalation",
)
TARGET_CONTRACT_ID = "next_distinct_trusted_behavior_phase_or_session_end.v2"
MANIFEST_SCHEMA = "prediction_trusted_history_manifest.v3"
EVIDENCE_CUTOFF_SCHEMA = "prediction_evidence_cutoff.v1"
SESSION_SOURCE = "production_live"
MAX_HISTORY = 8
SESSION_ID_RE = re.compile(r"^session_v1_[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_CHECKPOINT = "16506e962432f9921d18a514c3a31686a20f9734385ec49439ad2651e4cdd283"
EXPECTED_TEMPERATURE = 0.6990670591704266
EXPECTED_MODEL = "finalf_refined_v1_prediction_only"
STATE_SCHEMA = "gcp_cowrie_shadow_mongo_feeder_state.v1"
CONFIG_SCHEMA = "gcp_cowrie_shadow_mongo_feeder_config.v1"


class FeederReject(ValueError):
    """A source row or response failed a fail-closed contract."""


class PredictorFailure(FeederReject):
    """A transient predictor failure that must not advance the Mongo cursor."""


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _sha(value: Any, field: str) -> str:
    text = _text(value).lower()
    if not SHA256_RE.fullmatch(text):
        raise FeederReject(f"{field} is not a SHA-256 digest")
    return text


def _timestamp(value: Any, field: str) -> str:
    text = _text(value)
    if not text or "T" not in text or ("+" not in text and not text.endswith("Z")):
        raise FeederReject(f"{field} is not timezone-qualified")
    return text


def _sequence_id(value: Any) -> str:
    text = _text(value)
    if not SESSION_ID_RE.fullmatch(text):
        raise FeederReject("session identity is not canonical sensor-namespaced v1")
    return text


def _positive_int(value: Any, field: str, *, zero_ok: bool = False) -> int:
    if isinstance(value, bool):
        raise FeederReject(f"{field} is boolean")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise FeederReject(f"{field} is not an integer") from exc
    if number < (0 if zero_ok else 1):
        raise FeederReject(f"{field} is out of range")
    return number


def _require_cutoff(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"schema_version", "received_at", "event_id"}:
        raise FeederReject("evidence_cutoff is malformed")
    if value.get("schema_version") != EVIDENCE_CUTOFF_SCHEMA:
        raise FeederReject("evidence_cutoff schema differs")
    event_id = _text(value.get("event_id"))
    if not event_id:
        raise FeederReject("evidence_cutoff.event_id is empty")
    return {
        "schema_version": EVIDENCE_CUTOFF_SCHEMA,
        "received_at": _timestamp(value.get("received_at"), "evidence_cutoff.received_at"),
        "event_id": event_id,
    }


def _phase_hash(phase: Mapping[str, Any]) -> str:
    basis = dict(phase)
    basis.pop("phase_sha256", None)
    return digest(basis)


def _validate_manifest(manifest: Mapping[str, Any]) -> tuple[list[str], int, str]:
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise FeederReject("trusted-history manifest is not v3")
    if manifest.get("target_contract_id") != TARGET_CONTRACT_ID:
        raise FeederReject("trusted-history target contract differs")
    _require_cutoff(manifest.get("evidence_cutoff"))
    classifier_hash = _sha(manifest.get("classifier_environment_sha256"), "classifier_environment_sha256")
    del classifier_hash
    if manifest.get("maximum_trusted_phases") != MAX_HISTORY:
        raise FeederReject("maximum_trusted_phases differs")
    phases = manifest.get("ordered_trusted_phases")
    if not isinstance(phases, list) or not phases or len(phases) > MAX_HISTORY:
        raise FeederReject("ordered_trusted_phases is absent or out of bounds")
    if digest(phases) != _sha(manifest.get("ordered_trusted_phases_sha256"), "ordered_trusted_phases_sha256"):
        raise FeederReject("ordered phase hash mismatch")
    basis = dict(manifest)
    basis.pop("history_manifest_sha256", None)
    manifest_hash = _sha(manifest.get("history_manifest_sha256"), "history_manifest_sha256")
    if digest(basis) != manifest_hash:
        raise FeederReject("history manifest hash mismatch")
    original_count = _positive_int(manifest.get("original_distinct_phase_count"), "original_distinct_phase_count")
    selected_count = _positive_int(manifest.get("selected_distinct_phase_count"), "selected_distinct_phase_count")
    omitted_count = _positive_int(manifest.get("omitted_prefix_phase_count"), "omitted_prefix_phase_count", zero_ok=True)
    if selected_count != len(phases) or original_count != selected_count + omitted_count:
        raise FeederReject("manifest phase counts do not reconcile")
    if bool(manifest.get("truncated")) != bool(omitted_count):
        raise FeederReject("manifest truncation flag differs")
    observations: list[str] = []
    previous_end = -1
    for index, phase in enumerate(phases):
        if not isinstance(phase, Mapping):
            raise FeederReject("phase is not an object")
        if phase.get("phase_index") != index:
            raise FeederReject("phase index is not ordered")
        start = _positive_int(phase.get("start_command_index"), f"phase[{index}].start_command_index", zero_ok=True)
        end = _positive_int(phase.get("end_command_index"), f"phase[{index}].end_command_index", zero_ok=True)
        if end < start or start <= previous_end:
            raise FeederReject("phase command ordering is invalid")
        previous_end = end
        _timestamp(phase.get("start_timestamp"), f"phase[{index}].start_timestamp")
        _timestamp(phase.get("end_timestamp"), f"phase[{index}].end_timestamp")
        tactics = phase.get("tactics")
        if not isinstance(tactics, list) or len(tactics) != 1 or tactics[0] not in LABEL_ORDER:
            raise FeederReject("phase does not contain exactly one frozen tactic")
        labels = phase.get("labels")
        if not isinstance(labels, list) or not labels:
            raise FeederReject("phase labels are absent")
        for label in labels:
            if not isinstance(label, Mapping) or label.get("tactic") not in LABEL_ORDER:
                raise FeederReject("phase label tactic is invalid")
            if label.get("source") not in {"reviewed_rule", "rule_model_agreement"}:
                raise FeederReject("phase label source is not trusted")
            if label.get("agreement_status") in {"disagreed", "model_only", "unreviewed"}:
                raise FeederReject("phase label agreement is not trusted")
        if _phase_hash(phase) != _sha(phase.get("phase_sha256"), f"phase[{index}].phase_sha256"):
            raise FeederReject("phase hash mismatch")
        observations.append(str(tactics[0]))
    return observations, original_count, manifest_hash


def _read_uri(path: str) -> str:
    if not path:
        path = _text(os.environ.get("MONGODB_URI_FILE"))
    if not path:
        credential_dir = _text(os.environ.get("CREDENTIALS_DIRECTORY"))
        path = str(Path(credential_dir) / "mongodb-uri") if credential_dir else ""
    if not path:
        raise FeederReject("Mongo credential path is not configured")
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise FeederReject("Mongo credential is unreadable") from exc
    if not value or not value.startswith(("mongodb://", "mongodb+srv://")):
        raise FeederReject("Mongo credential is not a MongoDB URI")
    return value


def _cursor_from_doc(doc: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "updated_at": _timestamp(doc.get("updated_at"), "updated_at"),
        "session_id": _sequence_id(doc.get("session_id")),
        "revision": _positive_int(doc.get("revision"), "revision"),
    }


def _cursor_tuple(cursor: Mapping[str, Any]) -> tuple[str, str, int]:
    return (_text(cursor.get("updated_at")), _text(cursor.get("session_id")), int(cursor.get("revision") or 0))


def _after_query(cursor: Mapping[str, Any]) -> dict[str, Any]:
    timestamp, session_id, revision = _cursor_tuple(cursor)
    if not timestamp:
        return {}
    return {"$or": [
        {"updated_at": {"$gt": timestamp}},
        {"updated_at": timestamp, "session_id": {"$gt": session_id}},
        {"updated_at": timestamp, "session_id": session_id, "revision": {"$gt": revision}},
    ]}


def _request(endpoint: str, observations: list[str], timeout: float) -> dict[str, Any]:
    body = json.dumps({"observations": observations}, separators=(",", ":")).encode("utf-8")
    req = urlrequest.Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=timeout) as response:
            if int(response.status) != 200:
                raise PredictorFailure(f"predictor HTTP status {response.status}")
            value = json.loads(response.read().decode("utf-8"))
    except PredictorFailure:
        raise
    except (urlerror.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise PredictorFailure(f"predictor unavailable: {type(exc).__name__}") from exc
    if not isinstance(value, Mapping):
        raise PredictorFailure("predictor response is not an object")
    if value.get("authority") != "non_authoritative" or value.get("canonical_write_allowed") is not False:
        raise PredictorFailure("predictor authority contract failed")
    if value.get("task") != "next_observed_distinct_tactic" or value.get("model_identifier") != EXPECTED_MODEL:
        raise PredictorFailure("predictor task or model identity differs")
    if _text(value.get("checkpoint_sha256")).lower() != EXPECTED_CHECKPOINT:
        raise PredictorFailure("predictor checkpoint identity differs")
    probabilities = value.get("probabilities")
    if not isinstance(probabilities, list) or len(probabilities) != len(LABEL_ORDER) or any(
        not isinstance(item, (int, float)) or not math.isfinite(float(item)) or float(item) < 0 for item in probabilities
    ) or abs(sum(float(item) for item in probabilities) - 1.0) > 1e-5:
        raise PredictorFailure("predictor probability vector is invalid")
    ranked = sorted(range(len(LABEL_ORDER)), key=lambda index: (-float(probabilities[index]), index))
    if value.get("top1") != LABEL_ORDER[ranked[0]]:
        raise PredictorFailure("predictor top1 ranking is not deterministic")
    top3 = value.get("top3")
    if not isinstance(top3, list) or top3 != [LABEL_ORDER[index] for index in ranked[:len(top3)]]:
        raise PredictorFailure("predictor top3 ranking is not deterministic")
    calibration = value.get("calibration")
    try:
        temperature = float(calibration.get("temperature")) if isinstance(calibration, Mapping) else float("nan")
    except (TypeError, ValueError):
        temperature = float("nan")
    if not isinstance(calibration, Mapping) or calibration.get("method") != "temperature_scaled_softmax.v1" or temperature != EXPECTED_TEMPERATURE:
        raise PredictorFailure("predictor calibration binding differs")
    return dict(value)


class MongoShadowFeeder:
    def __init__(self, config: Mapping[str, Any]) -> None:
        if config.get("schema_version") != CONFIG_SCHEMA:
            raise FeederReject("feeder configuration schema differs")
        if config.get("endpoint") != "http://127.0.0.1:18082/predict":
            raise FeederReject("endpoint is not the approved localhost predictor")
        if _text(config.get("expected_checkpoint_sha256")).lower() != EXPECTED_CHECKPOINT:
            raise FeederReject("configured checkpoint binding differs")
        if float(config.get("expected_temperature")) != EXPECTED_TEMPERATURE:
            raise FeederReject("configured temperature binding differs")
        self.config = dict(config)
        self.deployment_id = _text(config.get("deployment_id"))
        if not self.deployment_id:
            raise FeederReject("deployment identity is missing")
        self.endpoint = str(config["endpoint"])
        self.database_name = _text(config.get("mongo_database")) or "honeypot_canonical_v1"
        self.collection_name = _text(config.get("mongo_collection")) or "sessions"
        self.credential_path = _text(config.get("mongo_uri_file"))
        self.shadow_root = Path(str(config.get("shadow_root") or ""))
        self.state_path = self.shadow_root / "state.json"
        self.records_path = self.shadow_root / "records.jsonl"
        self.metrics_path = self.shadow_root / "metrics.json"
        self.timeout = float(config.get("predict_timeout_seconds", 2.0))
        if not 0 < self.timeout <= 10:
            raise FeederReject("predict timeout is out of bounds")
        self.metrics: dict[str, int] = {
            "rows_seen": 0, "rows_eligible": 0, "predictions_emitted": 0,
            "duplicate_rows": 0, "rejected_rows": 0, "predictor_failures": 0,
            "cursor_advanced": 0, "transient_cursor_holds": 0,
        }
        self.state = self._load_state()

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            empty = {"updated_at": "", "session_id": "", "revision": 0}
            return {"schema_version": STATE_SCHEMA, "activation_watermark": empty, "cursor": dict(empty), "sessions": {}}
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FeederReject("shadow state is unreadable") from exc
        if not isinstance(value, Mapping) or value.get("schema_version") != STATE_SCHEMA:
            raise FeederReject("shadow state schema differs")
        if not isinstance(value.get("activation_watermark"), Mapping) or not isinstance(value.get("cursor"), Mapping):
            raise FeederReject("activation watermark or cursor is absent")
        return {"schema_version": STATE_SCHEMA, "activation_watermark": dict(value["activation_watermark"]), "cursor": dict(value["cursor"]), "sessions": dict(value.get("sessions") or {})}

    def _atomic_json(self, path: Path, value: Mapping[str, Any]) -> None:
        self.shadow_root.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=self.shadow_root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
                handle.write("\n")
                handle.flush(); os.fsync(handle.fileno())
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _write_state(self) -> None:
        self._atomic_json(self.state_path, self.state)

    def _write_metrics(self) -> None:
        self._atomic_json(self.metrics_path, self.metrics)

    def _append_record(self, value: Mapping[str, Any]) -> None:
        self.shadow_root.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.records_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            line = (stable_json(value) + "\n").encode("utf-8")
            os.write(fd, line); os.fsync(fd)
        finally:
            os.close(fd)

    def _client(self) -> Any:
        if MongoClient is None:
            raise FeederReject("pymongo is unavailable")
        uri = _read_uri(self.credential_path)
        client = MongoClient(uri, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000, socketTimeoutMS=5000)
        client.admin.command("ping")
        return client

    def _collection(self, client: Any) -> Any:
        return client[self.database_name][self.collection_name]

    @staticmethod
    def _projection() -> dict[str, int]:
        return {"_id": 0, "session_id": 1, "session_source": 1, "ended": 1, "updated_at": 1, "revision": 1, "payload_json": 1}

    def _highwater(self, collection: Any) -> Optional[dict[str, Any]]:
        cursor = collection.find(
            {"session_source": SESSION_SOURCE, "session_id": {"$regex": r"^session_v1_[0-9a-f]{32}$"}},
            projection=self._projection(),
            sort=[("updated_at", -1), ("session_id", -1), ("revision", -1)],
            limit=1,
        )
        doc = next(cursor, None)
        return _cursor_from_doc(doc) if doc is not None else None

    def initialize_watermark(self) -> dict[str, Any]:
        if self.state_path.exists():
            raise FeederReject("state already exists; refusing to reseed cursor")
        client = self._client()
        try:
            watermark = self._highwater(self._collection(client))
        finally:
            client.close()
        if watermark is None:
            watermark = {"updated_at": "", "session_id": "", "revision": 0}
        self.state = {"schema_version": STATE_SCHEMA, "activation_watermark": watermark, "cursor": dict(watermark), "sessions": {}}
        self._write_state(); self._write_metrics()
        return dict(watermark)

    def _rows(self, collection: Any) -> Iterable[dict[str, Any]]:
        cursor = self.state.get("cursor") or {"updated_at": "", "session_id": "", "revision": 0}
        query: dict[str, Any] = {"session_source": SESSION_SOURCE, "session_id": {"$regex": r"^session_v1_[0-9a-f]{32}$"}}
        after = _after_query(cursor)
        if after:
            query.update(after)
        for doc in collection.find(query, projection=self._projection(), sort=[("updated_at", 1), ("session_id", 1), ("revision", 1)], limit=int(self.config.get("poll_limit", 200))):
            yield doc

    def _row_payload(self, doc: Mapping[str, Any]) -> dict[str, Any]:
        value = doc.get("payload_json", doc.get("payload"))
        if isinstance(value, Mapping):
            return dict(value)
        if not isinstance(value, str):
            raise FeederReject("Mongo payload_json is not an object or JSON string")
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise FeederReject("Mongo payload_json is malformed") from exc
        if not isinstance(parsed, Mapping):
            raise FeederReject("Mongo payload_json is not an object")
        return dict(parsed)

    def process_row(self, doc: Mapping[str, Any], *, dry_run: bool = False) -> str:
        self.metrics["rows_seen"] += 1
        cursor = _cursor_from_doc(doc)
        sequence_id = cursor["session_id"]
        if doc.get("session_source") != SESSION_SOURCE:
            raise FeederReject("session source is not production_live")
        payload = self._row_payload(doc)
        manifest = payload.get("prediction_trusted_history_manifest")
        if not isinstance(manifest, Mapping):
            raise FeederReject("v3 trusted-history manifest is absent")
        observations, progression, manifest_hash = _validate_manifest(manifest)
        revision = _positive_int(payload.get("prediction_trusted_history_revision"), "prediction_trusted_history_revision")
        phase_count = _positive_int(payload.get("prediction_trusted_phase_count"), "prediction_trusted_phase_count")
        if revision != progression or phase_count != progression:
            raise FeederReject("session counters do not equal v3 progression")
        prior = self.state["sessions"].get(sequence_id)
        if prior and progression <= int(prior.get("last_progression", 0)):
            self.metrics["duplicate_rows"] += 1
            return "DUPLICATE"
        if dry_run:
            self.metrics["rows_eligible"] += 1
            return "ELIGIBLE_DRY_RUN"
        try:
            output = _request(self.endpoint, observations, self.timeout)
        except PredictorFailure:
            self.metrics["predictor_failures"] += 1
            raise
        prediction_id = hashlib.sha256(("shadow-next-distinct-v2\\0" + self.deployment_id + "\\0" + sequence_id + "\\0" + str(progression)).encode()).hexdigest()
        record = {
            "schema_version": "gcp_cowrie_shadow_prediction_record.v2",
            "prediction_id": prediction_id,
            "sequence_id": sequence_id,
            "progression_index": progression,
            "history": observations[-MAX_HISTORY:],
            "history_length": len(observations[-MAX_HISTORY:]),
            "session_ended": bool(doc.get("ended")),
            "updated_at": cursor["updated_at"],
            "revision": cursor["revision"],
            "evidence_cutoff_sha256": digest(manifest["evidence_cutoff"]),
            "history_manifest_sha256": manifest_hash,
            "predictor": {
                "task": output.get("task"), "authority": output.get("authority"),
                "canonical_write_allowed": output.get("canonical_write_allowed"),
                "model_identifier": output.get("model_identifier"),
                "checkpoint_sha256": output.get("checkpoint_sha256"),
                "calibrated": True, "top1": output.get("top1"), "top3": output.get("top3"),
                "probabilities": output.get("probabilities"), "calibration": output.get("calibration"),
            },
            "recorded_at": time.time(),
        }
        self._append_record(record)
        self.state["sessions"][sequence_id] = {"last_progression": progression, "last_cursor": cursor, "ended": bool(doc.get("ended")), "manifest_hash": manifest_hash}
        self.metrics["rows_eligible"] += 1
        self.metrics["predictions_emitted"] += 1
        return "EMITTED"

    def run_once(self, *, dry_run: bool = False) -> dict[str, int]:
        client = self._client()
        try:
            for doc in self._rows(self._collection(client)):
                cursor = _cursor_from_doc(doc)
                try:
                    result = self.process_row(doc, dry_run=dry_run)
                except PredictorFailure:
                    self.metrics["transient_cursor_holds"] += 1
                    break
                except FeederReject:
                    self.metrics["rejected_rows"] += 1
                    result = "REJECTED"
                if not dry_run:
                    self.state["cursor"] = cursor
                    self.metrics["cursor_advanced"] += 1
                    self._write_state()
                print(json.dumps({"status": result, "cursor": cursor}, sort_keys=True))
        finally:
            client.close()
        if not dry_run:
            self._write_metrics()
        return dict(self.metrics)

    def run_fixture(self, path: Path) -> dict[str, int]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FeederReject("fixture is unreadable") from exc
        rows = value if isinstance(value, list) else [value]
        for row in rows:
            if not isinstance(row, Mapping) or row.get("schema_version") != "gcp_cowrie_shadow_fixture.v1":
                raise FeederReject("fixture schema differs")
            payload = row.get("payload") if isinstance(row.get("payload"), Mapping) else {}
            manifest = payload.get("prediction_trusted_history_manifest") if isinstance(payload, Mapping) else {}
            cutoff = manifest.get("evidence_cutoff") if isinstance(manifest, Mapping) else {}
            fixture_row = dict(row)
            fixture_row.setdefault("updated_at", cutoff.get("received_at"))
            fixture_row.setdefault("revision", payload.get("prediction_trusted_history_revision"))
            self.process_row(fixture_row)
        self._write_state(); self._write_metrics()
        return dict(self.metrics)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--initialize-watermark", action="store_true")
    parser.add_argument("--fixture", type=Path)
    args = parser.parse_args()
    try:
        config = json.loads(args.config.read_text(encoding="utf-8"))
        feeder = MongoShadowFeeder(config)
        if args.initialize_watermark:
            print(json.dumps({"status": "INITIALIZED", "activation_watermark": feeder.initialize_watermark()}, sort_keys=True))
        elif args.fixture:
            print(json.dumps(feeder.run_fixture(args.fixture), sort_keys=True))
        elif args.once or args.dry_run:
            print(json.dumps(feeder.run_once(dry_run=args.dry_run), sort_keys=True))
        else:
            interval = float(config.get("poll_interval_seconds", 2.0))
            while True:
                feeder.run_once(); time.sleep(interval)
    except FeederReject as exc:
        print(json.dumps({"status": "FAILED_CLOSED", "reason": str(exc)}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
