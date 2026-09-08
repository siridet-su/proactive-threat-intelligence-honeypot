"""Frozen S1 command-to-ATT&CK advisory classifier.

The S1 package is deliberately isolated from the authoritative command
classifier.  It is a character/word TF-IDF ``LinearSVC`` model trained for the
offline command experiment.  Its decision margins are deterministic ranking
scores, not calibrated probabilities, and its output can never be promoted to
trusted or canonical ATT&CK evidence by this adapter.

The adapter verifies the content-addressed package before loading any
serialized estimator.  Optional scikit-learn/joblib dependencies are imported
only when a package is explicitly configured, so the default production path
and environments without the small-model extras remain unchanged.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


SCHEMA_VERSION = "s1_advisory_prediction.v1"
PACKAGE_SCHEMA_VERSION = "command_ttp_s1_model_package.v1"
SCORE_TYPE = "linear_svc_decision_margin"
AUTHORITY = "advisory_only"


class S1AdvisoryModelError(ValueError):
    """Raised when an S1 package is absent, malformed, or tampered."""


def _stable(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_bytes((_stable(value) + "\n").encode("utf-8"))


def _text(value: Any) -> str:
    return str(value or "").strip()


def _safe_component_name(value: Any) -> str:
    name = _text(value)
    path = Path(name)
    if (
        not name
        or path.is_absolute()
        or path.name != name
        or name in {".", ".."}
        or "\\" in name
    ):
        raise S1AdvisoryModelError("S1 package component path is unsafe")
    return name


class S1AdvisoryClassifier:
    """Load and run the frozen S1 package without granting authority."""

    score_type = SCORE_TYPE
    calibrated_probability = None
    authority = AUTHORITY

    def __init__(
        self,
        package_path: str | Path,
        *,
        repository_root: str | Path | None = None,
    ) -> None:
        raw_path = Path(package_path).expanduser()
        if not raw_path.is_absolute():
            root = (
                Path(repository_root).expanduser()
                if repository_root is not None
                else Path(__file__).resolve().parents[2]
            )
            raw_path = root / raw_path
        self.package_path = raw_path.resolve()
        if not self.package_path.is_dir() or self.package_path.is_symlink():
            raise S1AdvisoryModelError("S1 package directory is unavailable")

        manifest_path = self.package_path / "FINAL_MODEL_MANIFEST.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise S1AdvisoryModelError("S1 package manifest is unreadable") from exc
        if not isinstance(manifest, dict):
            raise S1AdvisoryModelError("S1 package manifest must be an object")
        if _text(manifest.get("schema_version")) != PACKAGE_SCHEMA_VERSION:
            raise S1AdvisoryModelError("S1 package schema is unsupported")

        components = manifest.get("components")
        if not isinstance(components, list) or not components:
            raise S1AdvisoryModelError("S1 package component manifest is invalid")
        normalized_components: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for item in components:
            if not isinstance(item, Mapping):
                raise S1AdvisoryModelError("S1 package component entry is invalid")
            name = _safe_component_name(item.get("path"))
            if name in seen:
                raise S1AdvisoryModelError("S1 package component is duplicated")
            seen.add(name)
            expected_hash = _text(item.get("sha256")).lower()
            if len(expected_hash) != 64 or any(
                character not in "0123456789abcdef" for character in expected_hash
            ):
                raise S1AdvisoryModelError("S1 package component hash is invalid")
            try:
                expected_size = int(item.get("size"))
            except (TypeError, ValueError) as exc:
                raise S1AdvisoryModelError("S1 package component size is invalid") from exc
            if expected_size < 0:
                raise S1AdvisoryModelError("S1 package component size is invalid")
            component_path = self.package_path / name
            if (
                not component_path.is_file()
                or component_path.is_symlink()
                or component_path.stat().st_size != expected_size
            ):
                raise S1AdvisoryModelError(
                    f"S1 package component is missing or size-mismatched: {name}"
                )
            actual_hash = _sha256_bytes(component_path.read_bytes())
            if actual_hash != expected_hash:
                raise S1AdvisoryModelError(
                    f"S1 package component SHA-256 mismatch: {name}"
                )
            normalized_components.append(
                {"path": name, "size": expected_size, "sha256": actual_hash}
            )

        if normalized_components != sorted(normalized_components, key=lambda item: item["path"]):
            raise S1AdvisoryModelError("S1 package components are not stably ordered")
        package_hash = _text(manifest.get("package_sha256")).lower()
        if len(package_hash) != 64 or _sha256_json(normalized_components) != package_hash:
            raise S1AdvisoryModelError("S1 package manifest identity mismatch")

        recipe = manifest.get("recipe")
        provenance = manifest.get("provenance")
        if not isinstance(recipe, Mapping) or not isinstance(provenance, Mapping):
            raise S1AdvisoryModelError("S1 package recipe/provenance is invalid")
        if _text(recipe.get("score_type")) != SCORE_TYPE:
            raise S1AdvisoryModelError("S1 package score semantics are unsupported")
        if recipe.get("calibrated_probability") is not None:
            raise S1AdvisoryModelError("S1 package unexpectedly claims calibration")
        if _text(recipe.get("authority")) != AUTHORITY:
            raise S1AdvisoryModelError("S1 package authority is unsupported")

        labels_path = self.package_path / "labels.json"
        bundle_path = self.package_path / "s1_tfidf_linearsvc.joblib"
        if "labels.json" not in seen or "s1_tfidf_linearsvc.joblib" not in seen:
            raise S1AdvisoryModelError("S1 package required components are missing")
        try:
            labels_document = json.loads(labels_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise S1AdvisoryModelError("S1 label mapping is unreadable") from exc
        labels = labels_document.get("labels") if isinstance(labels_document, dict) else None
        if (
            not isinstance(labels, list)
            or not labels
            or any(not isinstance(label, str) or not label.strip() for label in labels)
            or len(labels) != int(recipe.get("label_count", 0) or 0)
        ):
            raise S1AdvisoryModelError("S1 label mapping is invalid")
        label_order_hash = _text(recipe.get("label_order_sha256")).lower()
        if label_order_hash and _sha256_bytes(labels_path.read_bytes()) != _text(
            next(item["sha256"] for item in normalized_components if item["path"] == "labels.json")
        ):
            raise S1AdvisoryModelError("S1 label component identity is inconsistent")

        try:
            import joblib
        except ImportError as exc:
            raise S1AdvisoryModelError(
                "S1 advisory model requires the optional joblib/scikit-learn runtime"
            ) from exc
        try:
            bundle = joblib.load(bundle_path)
        except Exception as exc:
            raise S1AdvisoryModelError("S1 serialized model cannot be loaded") from exc
        if not isinstance(bundle, Mapping):
            raise S1AdvisoryModelError("S1 serialized model bundle is invalid")
        required = ("char", "word", "classifier", "labels")
        if any(key not in bundle for key in required):
            raise S1AdvisoryModelError("S1 serialized model bundle is incomplete")
        bundle_labels = list(bundle.get("labels") or [])
        if bundle_labels != labels:
            raise S1AdvisoryModelError("S1 serialized label order mismatch")
        classifier = bundle.get("classifier")
        raw_classes = getattr(classifier, "classes_", [])
        classes = list(raw_classes) if raw_classes is not None else []
        if classes != labels:
            raise S1AdvisoryModelError("S1 classifier label order mismatch")

        self.manifest = dict(manifest)
        self.package_id = _text(manifest.get("package_id"))
        self.package_sha256 = package_hash
        self.labels = labels
        self.recipe = dict(recipe)
        self.provenance = dict(provenance)
        self.char_vectorizer = bundle["char"]
        self.word_vectorizer = bundle["word"]
        self.classifier = classifier
        self._verified_components = normalized_components

    def metadata(self) -> Dict[str, Any]:
        """Return safe model identity and authority metadata."""

        return {
            "schema_version": SCHEMA_VERSION,
            "status": "loaded",
            "package_id": self.package_id,
            "package_sha256": self.package_sha256,
            "model_version": self.package_id,
            "model_family": self.recipe.get("model_family"),
            "label_count": len(self.labels),
            "label_order_sha256": self.recipe.get("label_order_sha256"),
            "training_provenance": dict(self.provenance),
            "score_type": SCORE_TYPE,
            "calibrated_probability": None,
            "authority": AUTHORITY,
            "trusted_eligible": False,
            "canonical_write_allowed": False,
            "response_authority": False,
        }

    def predict_topk(self, command: str, k: int = 3) -> List[Dict[str, Any]]:
        """Return ranked labels and raw decision margins for one command."""

        text = _text(command)
        if not text:
            return []
        try:
            import numpy as np
            from scipy.sparse import hstack

            matrix = hstack(
                [
                    self.char_vectorizer.transform([text]),
                    self.word_vectorizer.transform([text]),
                ],
                format="csr",
            )
            scores = self.classifier.decision_function(matrix)
            if getattr(scores, "ndim", 0) == 1:
                scores = np.column_stack([-scores, scores])
            row = np.asarray(scores[0], dtype=float)
            if row.shape[0] != len(self.labels) or not np.all(np.isfinite(row)):
                raise S1AdvisoryModelError("S1 decision-margin output is invalid")
            limit = max(1, min(int(k), len(self.labels)))
            order = np.argsort(-row, kind="stable")[:limit]
            return [
                {
                    "technique_id": self.labels[int(index)],
                    "decision_score": float(row[int(index)]),
                    "score_type": SCORE_TYPE,
                    "calibrated_probability": None,
                }
                for index in order
            ]
        except S1AdvisoryModelError:
            raise
        except Exception as exc:
            raise S1AdvisoryModelError("S1 inference failed") from exc

    def predict(self, command: str, *, top_k: int = 3) -> Dict[str, Any]:
        """Return one advisory prediction with explicit non-probability semantics."""

        ranked = self.predict_topk(command, k=top_k)
        if not ranked:
            return {
                **self.metadata(),
                "status": "empty_input_skipped",
                "predicted_technique": None,
                "topk": [],
                "decision_score": None,
            }
        best = ranked[0]
        return {
            **self.metadata(),
            "predicted_technique": best["technique_id"],
            "topk": ranked,
            "decision_score": best["decision_score"],
        }


__all__ = ["S1AdvisoryClassifier", "S1AdvisoryModelError"]
