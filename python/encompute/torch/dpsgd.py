"""DP-SGD inside the attested training worker: per-example gradients of
the LoRA parameters only, grouped by privacy unit, clipped per unit, and
summed over a Poisson sample of the units.

One step, for one participant's dataset:

1. **Sample.** Each privacy unit (a patient, say) is included
   independently with probability ``q``, using the operating system's
   randomness. Nobody outside the worker chooses or sees the sample: the
   model owner's round seed does not influence it.
2. **Per-example gradients.** For the adapter parameters only (the base
   weights are constants), on one of two paths with the same semantics:
   ``torch.func.vmap(grad(loss))`` over the sampled records in
   microbatches (fast), or one unit at a time with ordinary autograd
   (reference, for models whose code does not vectorize). A probe picks
   the path per model; if neither works, training fails closed.
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

from . import lora, tasks

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


class GradientsUnavailable(RuntimeError):
    """Neither path can produce per-unit gradients for this model:
    patient-level privacy cannot be satisfied, so training fails closed."""


def _params(model: torch.nn.Module):
    params: Dict[str, torch.nn.Parameter] = lora.adapter_parameters(model)
    return tuple(params), tuple(params.values())


def per_example_grads(model: torch.nn.Module, task: tasks.Task, batch: tasks.Batch
                      ) -> torch.Tensor:
    """FAST PATH: per-example gradients of the adapter parameters with
    ``vmap(grad(...))``, flattened in the canonical layout order: shape
    ``[records, d]``."""
    names, params = _params(model)
    adapter = tuple(p.detach() for p in params)

    def loss(adapter, one):
        b = {k: v.unsqueeze(0) for k, v in one.items()}
        a, k = task.call(b)
        out = functional_call(model, dict(zip(names, adapter)), a, k)
        return torch.nn.functional.cross_entropy(task.logits(out), b[task.label]).sum()

    g = vmap(grad(loss), in_dims=(None, 0), randomness="different")(adapter, batch)
    n = tasks.records(batch)
    return torch.cat([t.reshape(n, -1) for t in g], dim=1)


def unit_grad(model: torch.nn.Module, task: tasks.Task, batch: tasks.Batch) -> torch.Tensor:
    """REFERENCE PATH: the gradient of one unit's summed losses (all its
    records at once), with ordinary autograd."""
    _, params = _params(model)
    gs = torch.autograd.grad(task.losses(model, batch).sum(), params)
    return torch.cat([g.reshape(-1) for g in gs])


def clip_rows(g: torch.Tensor, clip: float) -> torch.Tensor:
    """Scales each row to L2 norm at most ``clip``."""
    norms = g.norm(dim=1, keepdim=True)
    return g * torch.clamp(clip / norms.clamp_min(1e-12), max=1.0)


def _sampled_records(unit_of: torch.Tensor, sampled: torch.Tensor):
    slot = torch.full((int(unit_of.max()) + 1,), -1, dtype=torch.long)
    slot[sampled] = torch.arange(len(sampled))
    return slot, torch.nonzero(slot[unit_of] >= 0).flatten()


def clipped_sum(model: torch.nn.Module, task: tasks.Task, batch: tasks.Batch,
                unit_of: torch.Tensor, sampled: torch.Tensor, clip: float,
                microbatch: int = 64, path: str = "vmap") -> torch.Tensor:
    """The sum over ``sampled`` units of each unit's clipped gradient (the
    unit's gradient is the sum of its records' gradients).

    ``path`` is ``vmap`` (per-example gradients, microbatched; the result
    does not depend on the microbatch size) or ``reference`` (one unit at a
    time). Both clip each unit once: the privacy semantics are identical.
    """
    d = lora.get_flat(model).numel()
    if len(sampled) == 0:
        return torch.zeros(d)
    slot, rows = _sampled_records(unit_of, sampled)
    per_unit = torch.zeros(len(sampled), d)
    if path == "vmap":
        for i in range(0, len(rows), microbatch):
            r = rows[i:i + microbatch]
            per_unit.index_add_(0, slot[unit_of[r]],
                                per_example_grads(model, task, tasks.select(batch, r)))
    elif path == "reference":
        for j, u in enumerate(sampled.tolist()):
            r = torch.nonzero(unit_of == u).flatten()
            per_unit[j] = unit_grad(model, task, tasks.select(batch, r))
    else:
        raise ValueError(f"unknown gradient path {path!r}")
    return clip_rows(per_unit, clip).sum(dim=0)


def select_path(model: torch.nn.Module, task: tasks.Task, batch: tasks.Batch) -> str:
    """Chooses the gradient path for a model, on a few of its records: the
    fast path if it runs and agrees with the reference, else the reference
    path. If no path yields per-unit gradients, raises
    :class:`GradientsUnavailable`: DP-SGD never falls back to ordinary
    (whole-batch) clipping."""
    probe = tasks.select(batch, torch.arange(min(3, tasks.records(batch))))
    was = model.training
    model.eval()  # no dropout: both paths must see the same function
    try:
        try:
            ref = torch.stack([unit_grad(model, task, tasks.select(probe, torch.tensor([i])))
                               for i in range(tasks.records(probe))])
        except Exception as e:
            raise GradientsUnavailable(
                f"per-example gradients are unavailable for this model ({type(e).__name__}: "
                f"{e}): patient-level privacy cannot be satisfied") from None
        try:
            fast = per_example_grads(model, task, probe)
            # Training runs in train mode (dropout), where some models'
            # code does not vectorize: it must run there too.
            model.train()
            per_example_grads(model, task, probe)
        except Exception:
            return "reference"
        return "vmap" if torch.allclose(fast, ref, atol=1e-5, rtol=1e-4) else "reference"
    finally:
        model.train(was)


def reference_clipped_sum(model: torch.nn.Module, task: tasks.Task, batch: tasks.Batch,
                          unit_of: torch.Tensor, sampled: torch.Tensor, clip: float
                          ) -> torch.Tensor:
    """The same sum, the slowest way: one autograd call per record (for the
    equivalence tests)."""
    _, params = _params(model)
    total = torch.zeros(sum(p.numel() for p in params))
    for u in sampled.tolist():
        g_unit = torch.zeros_like(total)
        for i in torch.nonzero(unit_of == u).flatten().tolist():
            one = tasks.select(batch, torch.tensor([i]))
            gs = torch.autograd.grad(task.losses(model, one).sum(), params)
            g_unit += torch.cat([g.reshape(-1) for g in gs])
        n = float(g_unit.norm())
        total += g_unit * min(1.0, clip / max(n, 1e-12))
    return total
