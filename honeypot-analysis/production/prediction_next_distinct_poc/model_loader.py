"""Self-contained loader for the retained Final F prediction-only POC model.

This file is included in the hash-bound offline bundle.  It intentionally has
no database, network, canonical-analysis, or production-runtime imports.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Sequence

import torch
from torch import nn

LABEL_ORDER = (
    "command-and-control",
    "credential-access",
    "defense-evasion",
    "discovery",
    "execution",
    "persistence",
    "privilege-escalation",
)
LABEL_TO_TOKEN = {name: i + 1 for i, name in enumerate(LABEL_ORDER)}
MAX_HISTORY = 8


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class RetainedTransformer(nn.Module):
    """Exact refined-v1 architecture: 2,599 parameters."""

    def __init__(self) -> None:
        super().__init__()
        self.embedding = nn.Embedding(8, 16, padding_idx=0)
        self.position = nn.Parameter(torch.zeros(1, MAX_HISTORY, 16))
        layer = nn.TransformerEncoderLayer(
            d_model=16,
            nhead=4,
            dim_feedforward=32,
            dropout=0.1,
            batch_first=True,
        )
        self.encoder = nn.TransformerEncoder(layer, num_layers=1)
        self.head = nn.Linear(16, 7)

    def forward(self, tokens: torch.Tensor) -> torch.Tensor:
        embedded = self.embedding(tokens) + self.position
        causal = torch.triu(
            torch.ones(MAX_HISTORY, MAX_HISTORY, device=tokens.device, dtype=torch.bool),
            diagonal=1,
        )
        encoded = self.encoder(embedded, mask=causal)
        return self.head(encoded[:, -1])


def tokens_for_history(history: Sequence[str]) -> torch.Tensor:
    values = list(history)
    if len(values) > MAX_HISTORY:
        values = values[-MAX_HISTORY:]
    unknown = [x for x in values if x not in LABEL_TO_TOKEN]
    if unknown:
        raise ValueError(f"unknown tactic labels: {unknown!r}")
    tokens = [0] * MAX_HISTORY
    if values:
        tokens[-len(values):] = [LABEL_TO_TOKEN[x] for x in values]
    return torch.tensor([tokens], dtype=torch.long)


def load_checkpoint(path: str | Path, expected_sha256: str) -> RetainedTransformer:
    checkpoint = Path(path)
    actual = sha256_file(checkpoint)
    if actual != expected_sha256:
        raise ValueError(f"checkpoint SHA mismatch: {actual}")
    model = RetainedTransformer()
    state = torch.load(checkpoint, map_location="cpu", weights_only=True)
    model.load_state_dict(state, strict=True)
    if sum(int(p.numel()) for p in model.parameters()) != 2599:
        raise ValueError("unexpected parameter count")
    model.eval()
    return model

