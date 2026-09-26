"""Confidential PyTorch fine-tuning. PyTorch does the computation (forward,
backward, autograd, optimizers, kernels); Encompute controls who may hold
what, and proves it: ownership and policy, placement and attestation, key
release, gradient release (secure aggregation), differential privacy,
lineage and verification.

    model = encompute.torch.wrap_model("encompute.torch.models:tiny_classifier", vocab=64)
    data = encompute.torch.private_dataset(tokens, labels)
    base = project.model("base-model", owner="modelco", module=model)
    a = project.data("patients-a", owner="hospital-a", dataset=data)
    result = project.finetune(model=base, data=[a, b], privacy="strong",
                              verification="required", allow_development=True)

What protects what:
- The TEE (attested) keeps the base model and each dataset from the host,
  and from the other parties.
- Secure aggregation keeps each hospital's update from the coordinator.
- Differential privacy bounds what the released aggregate reveals about
  one participant (organization level, from the per-hospital update clip).
- PyTorch itself is not encrypted: it runs in plaintext inside the attested
  workload.
"""

from __future__ import annotations

from typing import Any

import torch

from .lora import LoRAConfig, apply_lora, get_flat, layout, layout_digest, set_flat
from .models import TinyClassifier, build

__all__ = [
    "LoRAConfig",
    "TinyClassifier",
    "apply_lora",
    "build",
    "get_flat",
    "layout",
    "layout_digest",
    "private_dataset",
    "set_flat",
    "wrap_model",
]


def wrap_model(factory: str, **kwargs: Any) -> torch.nn.Module:
    """Builds a model from a factory ("package.module:function") so training
    workers can rebuild it from bound code instead of unpickling it."""
    m = build(factory, kwargs)
    m.encompute_factory = factory
    m.encompute_kwargs = dict(kwargs)
    return m


def private_dataset(x: torch.Tensor, y: torch.Tensor) -> tuple:
    """A participant's dataset: inputs and labels. It is written only to
    its owner's worker directory; only its digest is shared."""
    if len(x) != len(y):
        raise ValueError("inputs and labels differ in length")
    return (x.detach().clone(), y.detach().clone())
