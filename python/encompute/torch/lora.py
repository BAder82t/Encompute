"""LoRA with plain PyTorch: frozen base weights, trainable low-rank
adapters on chosen ``nn.Linear`` modules, and a canonical parameter layout
(module, parameter, shape, offset, length, dtype) that fixes the order the
adapter is flattened in for secure aggregation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

import torch
from torch import nn


@dataclass(frozen=True)
class LoRAConfig:
    rank: int = 4
    alpha: int = 8
    target_modules: Sequence[str] = ("q", "v")
    optimizer: str = "sgd"
    learning_rate: float = 0.05
    update_clip: float = 0.5
    local_steps: int = 5
    batch_size: int = 16
    rounds: int = 2
    seed: int = 0


class LoRALinear(nn.Module):
    """``base(x) + (x A^T B^T) * alpha / rank``; only A and B train."""

    def __init__(self, base: nn.Linear, rank: int, alpha: int, generator: torch.Generator):
        super().__init__()
        self.base = base
        for p in self.base.parameters():
            p.requires_grad_(False)
        self.lora_A = nn.Parameter(
            torch.randn(rank, base.in_features, generator=generator) / rank
        )
        self.lora_B = nn.Parameter(torch.zeros(base.out_features, rank))
        self.scaling = alpha / rank

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.base(x) + (x @ self.lora_A.T @ self.lora_B.T) * self.scaling


def apply_lora(model: nn.Module, cfg: LoRAConfig) -> nn.Module:
    """Freezes every base parameter and adds adapters to ``cfg.target_modules``
    (deterministically, from ``cfg.seed``)."""
    for p in model.parameters():
        p.requires_grad_(False)
    g = torch.Generator().manual_seed(cfg.seed)
    for name in sorted(cfg.target_modules):
        parent, _, leaf = name.rpartition(".")
        owner = model.get_submodule(parent) if parent else model
        base = getattr(owner, leaf)
        if not isinstance(base, nn.Linear):
            raise ValueError(f"{name} is not an nn.Linear")
        setattr(owner, leaf, LoRALinear(base, cfg.rank, cfg.alpha, g))
    return model


LAYOUT_VERSION = 1


def adapter_parameters(model: nn.Module) -> Dict[str, nn.Parameter]:
    """The adapter's parameters in canonical order: by (module, parameter)."""
    ps = [(n.rpartition(".")[0], n.rpartition(".")[2], n, p)
          for n, p in model.named_parameters() if "lora_" in n]
    return {n: p for _, _, n, p in sorted(ps, key=lambda t: (t[0], t[1]))}


def layout(model: nn.Module) -> List[dict]:
    out, offset = [], 0
    for name, p in adapter_parameters(model).items():
        module, _, param = name.rpartition(".")
        n = p.numel()
        out.append({"module": module, "parameter": param, "shape": list(p.shape),
                    "offset": offset, "length": n, "dtype": str(p.dtype).replace("torch.", "")})
        offset += n
    return out


def layout_digest(model: nn.Module) -> str:
    """The layout's digest, computed (and the layout validated) natively."""
    from .. import _native

    return _native.layout_digest(json.dumps({"version": LAYOUT_VERSION,
                                             "entries": layout(model)}))


def get_flat(model: nn.Module) -> torch.Tensor:
    return torch.cat([p.detach().reshape(-1) for p in adapter_parameters(model).values()])


def set_flat(model: nn.Module, vec: torch.Tensor) -> None:
    with torch.no_grad():
        off = 0
        for p in adapter_parameters(model).values():
            n = p.numel()
            p.copy_(vec[off:off + n].reshape(p.shape).to(p.dtype))
            off += n


def base_state(model: nn.Module) -> Dict[str, torch.Tensor]:
    """The base weights (everything but the adapters), for commitments."""
    return {k: v for k, v in model.state_dict().items() if "lora_" not in k}
