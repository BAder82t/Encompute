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
  one hospital (organization level: each hospital's update is clipped) or,
  with ``privacy="strong-patient"``, about one patient (DP-SGD: each
  patient's gradient is clipped, and patients are Poisson-sampled).
- PyTorch itself is not encrypted: it runs in plaintext inside the attested
  workload.
"""

from __future__ import annotations

from typing import Any, Optional

import torch

from .lora import LoRAConfig, apply_lora, get_flat, layout, layout_digest, set_flat
from .models import TinyClassifier, build


def __getattr__(name: str):
    # Hugging Face support loads transformers and peft only when used.
    if name in ("huggingface", "import_model"):
        from . import hf
        return getattr(hf, name)
    raise AttributeError(name)

__all__ = [
    "LoRAConfig",
    "TextDataset",
    "TinyClassifier",
    "apply_lora",
    "build",
    "get_flat",
    "huggingface",
    "import_model",
    "layout",
    "layout_digest",
    "private_dataset",
    "private_text_dataset",
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


def private_dataset(x: torch.Tensor, y: torch.Tensor,
                    unit_ids: Optional[torch.Tensor] = None) -> tuple:
    """A participant's dataset: inputs, labels and, for patient-level
    privacy, each record's patient (``unit_ids``, integers): a patient's
    records are grouped and clipped together. Without ``unit_ids`` each
    record is its own unit. The dataset is written only to its owner's
    worker directory; only its digest (covering the unit IDs) and its number
    of units are shared."""
    if len(x) != len(y):
        raise ValueError("inputs and labels differ in length")
    if unit_ids is None:
        return (x.detach().clone(), y.detach().clone())
    if len(unit_ids) != len(x) or unit_ids.dtype != torch.int64:
        raise ValueError("unit_ids needs one int64 ID per record")
    return (x.detach().clone(), y.detach().clone(), unit_ids.detach().clone())


class TextDataset:
    """A participant's tokenized text: ``input_ids``, ``attention_mask``,
    ``labels`` and ``unit_ids`` tensors, and how it was tokenized (bound
    into the training spec)."""

    def __init__(self, tensors: dict, preprocessing: dict):
        self.tensors = tensors
        self.preprocessing = preprocessing

    def __len__(self) -> int:
        return len(self.tensors["labels"])


def private_text_dataset(texts, labels, *, tokenizer, max_length: int = 64,
                         truncation: bool = True, stride: Optional[int] = None,
                         unit_ids=None) -> TextDataset:
    """Tokenizes a participant's texts with the model package's tokenizer
    (``model.encompute_tokenizer``), padding every record to
    ``max_length``.

    ``unit_ids`` names each text's privacy unit (its patient). With
    ``stride``, a long text is split into overlapping chunks, and every
    chunk keeps its text's unit: tokenization never turns one patient into
    several units. Without ``unit_ids``, each text is its own unit.
    """
    texts, labels = list(texts), torch.as_tensor(labels, dtype=torch.int64)
    if len(texts) != len(labels):
        raise ValueError("texts and labels differ in length")
    if unit_ids is not None:
        unit_ids = torch.as_tensor(unit_ids, dtype=torch.int64)
        if len(unit_ids) != len(texts):
            raise ValueError("unit_ids needs one ID per text")
    if not hasattr(tokenizer, "digest"):
        raise ValueError("tokenizer must be the model package's (model.encompute_tokenizer)")
    enc = tokenizer(texts, max_length=max_length, truncation=truncation, padding="max_length",
                    return_overflowing_tokens=stride is not None, stride=stride or 0,
                    return_tensors="pt")
    source = (enc["overflow_to_sample_mapping"] if stride is not None
              else torch.arange(len(texts)))
    t = {"input_ids": enc["input_ids"].to(torch.int64),
         "attention_mask": enc["attention_mask"].to(torch.int64),
         "labels": labels[source]}
    if unit_ids is not None:
        t["unit_ids"] = unit_ids[source]
    elif stride is not None:
        t["unit_ids"] = source.to(torch.int64)  # a text's chunks: one unit
    pre = {"tokenizer_digest": tokenizer.digest, "max_length": int(max_length),
           "truncation": bool(truncation), "padding": "max_length",
           "stride": None if stride is None else int(stride)}
    return TextDataset(t, pre)
