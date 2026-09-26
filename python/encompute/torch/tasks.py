"""What a model computes, and how training reads it: the task layer
between a dataset's named tensors and a model's outputs.

- ``classifier``: the reference models. ``model(x)`` returns logits.
- ``sequence-classification``: Hugging Face models. The model takes
  ``input_ids`` and ``attention_mask`` and returns a structured output; the
  logits are read from it.

The loss is always per record (cross-entropy, unreduced), so DP-SGD can sum
a privacy unit's records before clipping.

``build`` rebuilds the model a training spec names, the same way in every
worker, the inference workload and the model owner's process: the base
from its bound factory and sealed weights, then the bound adapter, then the
layout check.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Tuple

import torch

from . import lora, models, tensors

Batch = Dict[str, torch.Tensor]


@dataclass(frozen=True)
class Task:
    name: str
    inputs: Tuple[str, ...]
    label: str
    keyword: bool  # the model takes its inputs by name

    def call(self, batch: Batch) -> Tuple[tuple, dict]:
        """The model's positional and keyword arguments for ``batch``."""
        if self.keyword:
            return (), {k: batch[k] for k in self.inputs}
        return tuple(batch[k] for k in self.inputs), {}

    def logits(self, out) -> torch.Tensor:
        return out if isinstance(out, torch.Tensor) else out.logits

    def model_logits(self, model: torch.nn.Module, batch: Batch) -> torch.Tensor:
        a, k = self.call(batch)
        return self.logits(model(*a, **k))

    def losses(self, model: torch.nn.Module, batch: Batch) -> torch.Tensor:
        """One cross-entropy loss per record."""
        return torch.nn.functional.cross_entropy(self.model_logits(model, batch),
                                                 batch[self.label], reduction="none")


CLASSIFIER = Task("classifier", ("x",), "y", keyword=False)
SEQUENCE_CLASSIFICATION = Task("sequence-classification", ("input_ids", "attention_mask"),
                               "labels", keyword=True)


def of_spec(spec: dict) -> Task:
    return SEQUENCE_CLASSIFICATION if spec["config"]["method"] == "peft-lora" else CLASSIFIER


def records(batch: Batch) -> int:
    return len(next(iter(batch.values())))


def select(batch: Batch, idx: torch.Tensor) -> Batch:
    return {k: v[idx] for k, v in batch.items()}


def build(spec: dict, weights: bytes, seed: int) -> torch.nn.Module:
    """The model a training spec names, with its adapter; refuses another
    layout. ``weights`` are the opened sealed base weights."""
    base = spec["base_model"]
    arch = json.loads(base["architecture"])
    if spec["config"]["method"] == "peft-lora":
        from . import hf
        hf.check_versions(base["huggingface"])
    model = models.build(arch["factory"], arch["kwargs"])
    model.load_state_dict(tensors.loads(bytes(weights)))
    c = spec["config"]
    if c["method"] == "peft-lora":
        from . import hf
        model = hf.apply_peft(model, c["peft"], seed)
    else:
        lora.apply_lora(model, lora.LoRAConfig(rank=c["rank"], alpha=c["alpha"],
                                               target_modules=tuple(c["target_modules"]),
                                               seed=seed))
    if lora.layout_digest(model) != spec["layout_digest"]:
        raise ValueError("this worker's adapter layout is not the approved one")
    return model
