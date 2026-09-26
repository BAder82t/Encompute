"""DP-SGD inside the attested training worker: per-example gradients of
the LoRA parameters only, grouped by privacy unit, clipped per unit, and
summed over a Poisson sample of the units.

One step, for one participant's dataset:

1. **Sample.** Each privacy unit (a patient, say) is included
   independently with probability ``q``, using the operating system's
   randomness. Nobody outside the worker chooses or sees the sample: the
   model owner's round seed does not influence it.
2. **Per-example gradients.** ``torch.func.vmap(grad(loss))`` over the
   sampled records, in microbatches, for the adapter parameters only (the
   base weights are constants).
3. **Group.** A unit's records are summed into one gradient per unit, so a
   patient with many records still has one clipped contribution.
4. **Clip.** Each unit's gradient is scaled to L2 norm at most ``clip``.
5. **Sum.** The clipped unit gradients are summed. That sum is the
   participant's contribution to secure aggregation; the coordinator adds
   the noise.

Adding or removing one unit changes the sum by at most ``clip``, whatever
the other units hold. That is the sensitivity the accountant charges.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import torch
from torch.func import functional_call, grad, vmap

from . import lora

# The codec scale and per-unit clip (in codec units) of DP-SGD
# aggregations: each unit's clipped gradient is rescaled to norm at most
# CODEC_CLIP, so the sum of many units stays inside the codec's [-1, 1]
# range while the rounding term (at most sqrt(d) codes) stays small next
# to CODEC_CLIP * CODEC_SCALE.
CODEC_SCALE = 65536
CODEC_CLIP = 0.015625


@dataclass(frozen=True)
class DpSgd:
    """A run's DP-SGD settings (all bound in the training spec)."""

    unit: str
    per_example_clip: float
    sampling_rate: float
    noise_multiplier: float
    delta: float
    grouping: str  # "unit_ids" or "none"
    expected_batch: float
    microbatch: int = 64  # memory only: never changes the result


def unit_index(unit_ids: Optional[torch.Tensor], n: int) -> Tuple[torch.Tensor, int]:
    """Each record's unit as 0..U-1 (in sorted unit-ID order), and U.
    Without unit IDs, each record is its own unit."""
    if unit_ids is None:
        return torch.arange(n), n
    uniq, inverse = torch.unique(unit_ids, sorted=True, return_inverse=True)
    return inverse, len(uniq)


def poisson_sample(n_units: int, q: float, generator: Optional[torch.Generator] = None
                   ) -> torch.Tensor:
    """The sampled units: each independently with probability ``q``. By
    default the randomness comes from the operating system (``os.urandom``),
    fresh every call, so no party can choose or replay the sample."""
    if generator is None:
        generator = torch.Generator().manual_seed(int.from_bytes(os.urandom(8), "little"))
    return torch.nonzero(torch.rand(n_units, generator=generator) < q).flatten()


def _loss_fn(model: torch.nn.Module, names: Tuple[str, ...]):
    def loss(adapter: Tuple[torch.Tensor, ...], x: torch.Tensor, y: torch.Tensor):
        out = functional_call(model, dict(zip(names, adapter)), (x.unsqueeze(0),))
        return torch.nn.functional.cross_entropy(out, y.unsqueeze(0))
    return loss


def per_example_grads(model: torch.nn.Module, x: torch.Tensor, y: torch.Tensor
                      ) -> torch.Tensor:
    """Per-example gradients of the adapter parameters, flattened in the
    canonical layout order: shape ``[len(x), d]``."""
    params: Dict[str, torch.nn.Parameter] = lora.adapter_parameters(model)
    names = tuple(params)
    adapter = tuple(p.detach() for p in params.values())
    g = vmap(grad(_loss_fn(model, names)), in_dims=(None, 0, 0))(adapter, x, y)
    return torch.cat([t.reshape(len(x), -1) for t in g], dim=1)


def clip_rows(g: torch.Tensor, clip: float) -> torch.Tensor:
    """Scales each row to L2 norm at most ``clip``."""
    norms = g.norm(dim=1, keepdim=True)
    return g * torch.clamp(clip / norms.clamp_min(1e-12), max=1.0)


def clipped_sum(model: torch.nn.Module, x: torch.Tensor, y: torch.Tensor,
                unit_of: torch.Tensor, sampled: torch.Tensor, clip: float,
                microbatch: int = 64) -> torch.Tensor:
    """The sum over ``sampled`` units of each unit's clipped gradient (the
    unit's gradient is the sum of its records' gradients). Microbatching
    bounds memory; the result does not depend on it."""
    d = lora.get_flat(model).numel()
    if len(sampled) == 0:
        return torch.zeros(d)
    slot = torch.full((int(unit_of.max()) + 1,), -1, dtype=torch.long)
    slot[sampled] = torch.arange(len(sampled))
    records = torch.nonzero(slot[unit_of] >= 0).flatten()
    per_unit = torch.zeros(len(sampled), d)
    for i in range(0, len(records), microbatch):
        r = records[i:i + microbatch]
        per_unit.index_add_(0, slot[unit_of[r]], per_example_grads(model, x[r], y[r]))
    return clip_rows(per_unit, clip).sum(dim=0)


def reference_clipped_sum(model: torch.nn.Module, x: torch.Tensor, y: torch.Tensor,
                          unit_of: torch.Tensor, sampled: torch.Tensor, clip: float
                          ) -> torch.Tensor:
    """The same sum, the slow way: ordinary autograd, one unit at a time
    (for the equivalence tests)."""
    params = list(lora.adapter_parameters(model).values())
    total = torch.zeros(sum(p.numel() for p in params))
    for u in sampled.tolist():
        g_unit = torch.zeros_like(total)
        for i in torch.nonzero(unit_of == u).flatten().tolist():
            model.zero_grad()
            loss = torch.nn.functional.cross_entropy(model(x[i:i + 1]), y[i:i + 1])
            gs = torch.autograd.grad(loss, params)
            g_unit += torch.cat([g.reshape(-1) for g in gs])
        n = float(g_unit.norm())
        total += g_unit * min(1.0, clip / max(n, 1e-12))
    return total
