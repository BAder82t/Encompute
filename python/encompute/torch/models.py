"""Model factories training workers may build. A worker never unpickles a
model: it builds the architecture from a factory the worker image ships,
in code the training spec binds (by digest), and loads the weights from
the canonical tensor format.

Only the factories in ``FACTORIES`` can be named, each with arguments of
its schema (checked natively, the same check the training spec validator
applies): a training spec cannot make a worker call any other code. A new
architecture is added to the worker image and to the allowlist, and
reviewed there."""

from __future__ import annotations

import importlib
import json

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


# The factories the worker image ships (the training spec validator's
# allowlist): the reference model, and Hugging Face models rebuilt from
# their package's own config.json.
FACTORIES = ("encompute.torch.models:tiny_classifier", "encompute.torch.hf:from_config")


def check(factory: str, kwargs: dict) -> None:
    """Refuses a factory outside ``FACTORIES``, or arguments outside its
    schema, before anything is imported."""
    from .. import _native

    try:
        _native.training_check_architecture(json.dumps({"factory": factory, "kwargs": kwargs}))
    except _native.NativeError as e:
        raise ValueError(e.args[1]) from None


def build(factory: str, kwargs: dict) -> nn.Module:
    """Builds ``factory`` ("module:function", one of ``FACTORIES``) with
    ``kwargs``."""
    check(factory, kwargs)
    mod, _, fn = factory.partition(":")
    return getattr(importlib.import_module(mod), fn)(**kwargs)


def source_file(factory: str) -> str:
    """The file defining ``factory``: part of the training code digest."""
    if factory not in FACTORIES:
        raise ValueError(f"factory {factory!r} is not one the worker image ships")
    return importlib.import_module(factory.partition(":")[0]).__file__
