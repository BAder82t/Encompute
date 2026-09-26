"""Model factories training workers may build. A worker never unpickles a
model: it builds the architecture from a factory in code the training spec
binds (by digest) and loads the weights from the canonical tensor format.
Your own factory works the same way: a module-level function in an
importable module, named as ``"package.module:function"``."""

from __future__ import annotations

import importlib

import torch
from torch import nn


class TinyClassifier(nn.Module):
    """A small text classifier: token embeddings, one self-attention layer
    with q/k/v/out projections, a feed-forward block and a linear head."""

    def __init__(self, vocab: int = 64, dim: int = 16, classes: int = 2, seq: int = 8):
        super().__init__()
        self.embed = nn.Embedding(vocab, dim)
        self.q = nn.Linear(dim, dim)
        self.k = nn.Linear(dim, dim)
        self.v = nn.Linear(dim, dim)
        self.out = nn.Linear(dim, dim)
        self.ff = nn.Linear(dim, dim)
        self.head = nn.Linear(dim, classes)

    def forward(self, tokens: torch.Tensor) -> torch.Tensor:
        x = self.embed(tokens)
        a = torch.softmax(self.q(x) @ self.k(x).transpose(1, 2) / x.shape[-1] ** 0.5, dim=-1)
        x = x + self.out(a @ self.v(x))
        x = x + torch.relu(self.ff(x))
        return self.head(x.mean(dim=1))


def tiny_classifier(**kwargs) -> nn.Module:
    return TinyClassifier(**kwargs)


def build(factory: str, kwargs: dict) -> nn.Module:
    """Builds ``factory`` ("module:function") with ``kwargs``."""
    mod, _, fn = factory.partition(":")
    if not mod or not fn:
        raise ValueError(f"factory {factory!r}: expected 'package.module:function'")
    return getattr(importlib.import_module(mod), fn)(**kwargs)


def source_file(factory: str) -> str:
    """The file defining ``factory``: part of the training code digest."""
    return importlib.import_module(factory.partition(":")[0]).__file__
