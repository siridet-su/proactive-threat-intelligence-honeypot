"""Production SecureBERT command classifier adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional, Tuple

from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log
from production.utils.serialization import utc_now


class SecureBertCommandClassifier:
    """Loads a HuggingFace sequence classifier and returns `(ttp_id, confidence)`."""

    def __init__(
        self,
        model_path: str,
        checkpoint_path: str = "",
        device: str = "auto",
        max_length: int = 128,
    ) -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("SecureBERT requires torch and transformers in the runtime image.") from exc

        self.torch = torch
        self.max_length = max_length
        self.model_path = Path(model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"SecureBERT model path not found: {self.model_path}")

        if checkpoint_path:
            self.checkpoint_path = Path(checkpoint_path)
        else:
            default_checkpoint = self.model_path / "checkpoint-6765"
            self.checkpoint_path = default_checkpoint if default_checkpoint.exists() else self.model_path

        if not self.checkpoint_path.exists():
            raise FileNotFoundError(f"SecureBERT checkpoint path not found: {self.checkpoint_path}")

        if device == "auto":
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(self.checkpoint_path)).to(self.device)
        self.model.eval()

    def classify(self, command: str) -> Tuple[Optional[str], float]:
        command = (command or "").strip()
        if len(command) < 3:
            return None, 0.0

        inputs = self.tokenizer(
            command,
            return_tensors="pt",
            truncation=True,
            max_length=self.max_length,
            padding=True,
        ).to(self.device)

        with self.torch.no_grad():
            logits = self.model(**inputs).logits

        probs = self.torch.softmax(logits, dim=-1)
        idx = int(probs.argmax().item())
        confidence = float(probs[0][idx].item())
        id2label = getattr(self.model.config, "id2label", {}) or {}
        ttp_id = id2label.get(idx) or id2label.get(str(idx))
        return ttp_id, confidence

    def classify_batch(self, commands: List[str]) -> List[Tuple[Optional[str], float]]:
        if not commands:
            return []
        inputs = self.tokenizer(
            commands,
            return_tensors="pt",
            truncation=True,
            max_length=self.max_length,
            padding=True,
        ).to(self.device)
        with self.torch.no_grad():
            probs = self.torch.softmax(self.model(**inputs).logits, dim=-1)
        max_p, idx = self.torch.max(probs, dim=1)
        id2label = getattr(self.model.config, "id2label", {}) or {}
        return [
            (id2label.get(int(i)) or id2label.get(str(int(i))), float(p))
            for p, i in zip(max_p.tolist(), idx.tolist())
        ]

    def classify_topk(self, command: str, k: int = 3) -> List[Tuple[Optional[str], float]]:
        command = (command or "").strip()
        if not command:
            return []
        inputs = self.tokenizer(
            command,
            return_tensors="pt",
            truncation=True,
            max_length=max(self.max_length, 512),
            padding=True,
        ).to(self.device)
        with self.torch.no_grad():
            probs = self.torch.softmax(self.model(**inputs).logits, dim=-1)
        top_p, top_idx = self.torch.topk(probs, k=k, dim=1)
        id2label = getattr(self.model.config, "id2label", {}) or {}
        return [
            (id2label.get(int(i)) or id2label.get(str(int(i))), float(p))
            for p, i in zip(top_p[0].tolist(), top_idx[0].tolist())
        ]


def load_securebert_classifier(config: ProductionConfig):
    """Return a callable for `SessionMonitor(bert_fn=...)`, or None when unavailable."""
    if not config.enable_securebert:
        return None
    try:
        classifier = SecureBertCommandClassifier(
            model_path=config.securebert_model_path,
            checkpoint_path=config.securebert_checkpoint_path,
            device=config.securebert_device,
            max_length=config.securebert_max_length,
        )
        print(
            json.dumps(
                {
                    "service": "securebert_classifier",
                    "status": "loaded",
                    "model_path": str(classifier.model_path),
                    "checkpoint_path": str(classifier.checkpoint_path),
                    "device": str(classifier.device),
                    "timestamp": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return classifier.classify
    except Exception as exc:
        print(
            json.dumps(
                {
                    "service": "securebert_classifier",
                    "status": "unavailable",
                    "error": redact_exception_for_log(exc),
                    "timestamp": utc_now(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return None
