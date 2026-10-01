"""The confidential training worker: one per participant, inside the
placement the plan chose (an attested TEE).

    python -m encompute.torch.worker CONFIG.json

It attests to the model owner's key broker as the approved training spec's
workload and receives the base model's key. It opens the sealed model,
checks it is the committed version, and builds it from the bound factory
(never a pickle). It adds LoRA and checks the parameter layout is the
approved one. Then, per round, it trains locally on its owner's dataset and
contributes the clipped adapter update to secure aggregation (or, with
patient-level DP-SGD, one step's sum of Poisson-sampled, per-patient
clipped gradients; see dpsgd.py), through
`encompute aggregate join --values -`. The update goes only into that
process's stdin: it is never written to disk or sent anywhere else.

Commands arrive as JSON lines on stdin; replies go out as JSON lines on
stdout.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback
from typing import Optional, Tuple

import torch

from .. import _native
from . import dpsgd, lora, tasks, tensors

DP_FAILED = "the DP-SGD contribution failed"


def grouping(unit_ids: torch.Tensor, salt) -> dict:
    """What a dataset's grouping digest covers: its unit IDs and its salt."""
    g = {"unit_ids": unit_ids}
    if salt is not None:
        g[SALT] = salt
    return g


def development(record: str) -> bool:
    """Whether a worker's attestation is development (mock) evidence: the
    only case in which test hooks are honoured. Evidence from real
    hardware (Confidential Space) never enables them, whatever the
    environment says (review finding SC-5)."""
    try:
        return json.loads(record)["evidence"]["provider"] == "mock"
    except (ValueError, KeyError, TypeError):
        return False


def reply(**kw) -> None:
    print(json.dumps(kw), flush=True)


def check_code(spec: dict) -> None:
    """Refuses to run unless this worker's own training code is the code the
    training spec binds (its digest, computed here, over the installed
    files), before any key is requested: the attestation's artifact digest
    is then a fact about this workload, not a claim copied from the spec
    (review finding TR-1)."""
    from .finetune import code_digest
    factory = json.loads(spec["base_model"]["architecture"])["factory"]
    if code_digest(factory) != spec["code_digest"]:
        raise ValueError("this worker's training code is not the code the training spec binds")


def codec_clip(spec: dict, plan: str) -> float:
    """DP-SGD: the per-unit clip (codec units) this worker applies, read from
    the approved plan after checking it is the spec's plan and samples at
    the spec's rate, so each unit's contribution is bounded exactly as the
    accountant charges (review finding DP-3)."""
    try:
        clip = float(_native.training_plan_clip(json.dumps(spec), plan))
    except _native.NativeError as e:
        raise ValueError(e.args[1]) from None
    if not 0 < clip <= dpsgd.CODEC_CLIP:
        raise ValueError(f"the plan's per-unit clip {clip} is outside the codec's range")
    return clip


def lora_config(spec: dict, seed: int) -> lora.LoRAConfig:
    """The LoRA configuration: the training spec's, never a job's (review
    finding TR-2). Only the round's seed comes from outside."""
    c = spec["config"]
    peft = c.get("peft") or {}
    return lora.LoRAConfig(
        rank=c["rank"], alpha=c["alpha"], target_modules=tuple(c["target_modules"]),
        optimizer=c["optimizer"], learning_rate=float(c["learning_rate"]),
        update_clip=float(c["update_clip"]), local_steps=c["local_steps"],
        batch_size=c["batch_size"], rounds=c["rounds"], seed=int(seed),
        dropout=float(peft.get("lora_dropout", "0.0")),
    )


def load_dataset(cfg: dict) -> tuple:
    """The committed dataset's named tensors, its unit IDs (if any) and its
    commitment salt."""
    data = open(cfg["dataset"], "rb").read()
    if _native.sha256_hex(data) != cfg["dataset_digest"]:
        raise ValueError(f"{cfg['dataset_asset']} is not the dataset the training spec commits to")
    return split_dataset(tensors.loads(data))


def split_dataset(t: dict) -> tuple:
    """A committed dataset's records, unit IDs and salt."""
    unit_ids = t.pop("unit_ids", None)
    salt = t.pop(SALT, None)
    return t, unit_ids, salt


# The dataset's commitment salt (random, kept by its owner): the shared
# digests of the dataset and its grouping are hiding commitments.
SALT = "commitment_salt"


class Worker:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        spec = json.loads(cfg["spec"])
        self.spec = spec
        check_code(spec)
        clip = (codec_clip(spec, open(cfg["plan"]).read())
                if spec["config"].get("dp_sgd") else None)
        keys, record = _native.acquire_training_keys(
            cfg["spec"], cfg["broker"], [spec["base_model"]["asset_id"]],
            cfg["identity"], cfg["mock_seed"], cfg["image"],
        )
        self.record = record
        self.hooks = development(record)
        key = dict(keys)[spec["base_model"]["asset_id"]]
        sealed = open(cfg["model_sealed"], "rb").read()
        weights = _native.open_asset(
            key, sealed, spec["project"], spec["base_model"]["asset_id"],
            spec["base_model"]["weights_digest"],
        )
        del key
        # The model and its layout are built and checked before the dataset
        # is read.
        self._build(spec, weights, int(cfg["lora"]["seed"]), clip)
        data, unit_ids, salt = load_dataset(cfg)
        self._load(data, unit_ids, salt, cfg["dataset_asset"], int(cfg.get("microbatch", 64)))
        if self.dp is not None:
            # The coordinator accepts DP-SGD contributions only from an
            # attested worker running this training code.
            self.contribution_record = os.path.join(os.path.dirname(cfg["state"]),
                                                    "contribution-attestation.json")
            with open(self.contribution_record, "w") as f:
                f.write(_native.attest_contribution(
                    spec["plan_id"], None, spec["code_digest"], cfg["identity"],
                    cfg["mock_seed"], cfg["image"]))

    @classmethod
    def for_model(cls, spec: dict, weights: bytes, seed: int, clip: Optional[float],
                  hooks: bool = False) -> "Worker":
        """A worker for an already opened model (a confidential training job
        decrypts its assets itself): the same checks and the same training.
        The dataset follows with :meth:`load`, once the model is built."""
        w = cls.__new__(cls)
        w.cfg, w.spec, w.record, w.hooks = {}, spec, None, hooks
        w._build(spec, weights, seed, clip)
        return w

    def _build(self, spec: dict, weights: bytes, seed: int, clip: Optional[float]) -> None:
        self.lcfg = lora_config(spec, seed)
        # The bound base model (Hugging Face: the package's library versions
        # are checked first), the bound adapter, the approved layout.
        self.model = tasks.build(spec, weights, seed)
        self.task = tasks.of_spec(spec)
        self.versions = None
        if spec["base_model"].get("huggingface"):
            from . import hf
            self.versions = hf.exact_versions()
        if spec["config"].get("dp_sgd") and clip is None:
            raise ValueError("DP-SGD needs the approved plan's per-unit clip")
        self.codec_clip = clip

    def load(self, data: dict, unit_ids, salt, dataset_asset: str, microbatch: int = 64) -> None:
        """The opened dataset (its records, unit IDs and salt)."""
        self._load(data, unit_ids, salt, dataset_asset, microbatch)

    def _load(self, data: dict, unit_ids, salt, dataset_asset: str, microbatch: int) -> None:
        spec = self.spec
        self.data = data
        self.n = tasks.records(self.data)
        self.grad_path = None
        self.dp = None
        if not 1 <= int(microbatch) <= 4096:
            raise ValueError("the microbatch is between 1 and 4096 records")
        if spec["config"].get("dp_sgd"):
            d = spec["config"]["dp_sgd"]
            mine = next(x for x in spec["datasets"] if x["asset_id"] == dataset_asset)
            self.unit_of, n_units = dpsgd.unit_index(unit_ids, self.n)
            # The grouping must be the committed one.
            if (d["grouping"] == "unit_ids") != (unit_ids is not None):
                raise ValueError("this dataset's grouping is not the approved one")
            if unit_ids is not None and _native.sha256_hex(tensors.dumps(
                    grouping(unit_ids, salt))) != mine["grouping_digest"]:
                raise ValueError("this dataset's patient grouping is not the committed one")
            self.n_units = n_units
            self.dp = dpsgd.DpSgd(
                unit=d["privacy_unit"], per_example_clip=float(d["per_example_clip"]),
                sampling_rate=float(d["sampling_rate"]),
                noise_multiplier=float(d["noise_multiplier"]), delta=float(d["delta"]),
                grouping=d["grouping"], expected_batch=float(d["expected_batch"]),
                microbatch=int(microbatch))
            # Per-unit gradients, on the fast path if this model supports
            # it; never ordinary clipping (fails closed otherwise).
            self.grad_path = dpsgd.select_path(self.model, self.task, self.data)

    def train(self, adapter: list, seed: int) -> torch.Tensor:
        """Local LoRA training from `adapter`; returns the update."""
        start = torch.tensor(adapter, dtype=torch.float32)
        lora.set_flat(self.model, start)
        params = list(lora.adapter_parameters(self.model).values())
        opt = (torch.optim.SGD if self.lcfg.optimizer == "sgd" else torch.optim.Adam)(
            params, lr=self.lcfg.learning_rate
        )
        g = torch.Generator().manual_seed(seed)
        loss = torch.tensor(0.0)
        self.model.train()
        for _ in range(self.lcfg.local_steps):
            idx = torch.randint(0, self.n, (self.lcfg.batch_size,), generator=g)
            opt.zero_grad()
            loss = self.task.losses(self.model, tasks.select(self.data, idx)).mean()
            loss.backward()
            opt.step()
        self.loss = float(loss)
        return lora.get_flat(self.model) - start

    def dp_sgd_step(self, adapter: list) -> torch.Tensor:
        """DP-SGD: the sum of the Poisson-sampled units' clipped gradients,
        rescaled so each unit's is at most the plan's clip (codec units).
        The round's seed is not used: the sample comes from the operating
        system."""
        lora.set_flat(self.model, torch.tensor(adapter, dtype=torch.float32))
        sampled = dpsgd.poisson_sample(self.n_units, self.dp.sampling_rate)
        self.model.train()
        g = dpsgd.clipped_sum(self.model, self.task, self.data, self.unit_of, sampled,
                              self.dp.per_example_clip, self.dp.microbatch, self.grad_path)
        return g * (self.codec_clip / self.dp.per_example_clip)

    def contribution(self, adapter: list, seed: int) -> Tuple[torch.Tensor, float, float]:
        """One round's contribution, in the codec's range: DP-SGD's sum of
        clipped per-unit gradients, or the whole clipped update. Returns it
        with the update's norm and clip (organization mode)."""
        if self.dp is not None:
            self.loss = None
            return self.dp_sgd_step(adapter), 0.0, 1.0
        update = self.train(adapter, seed)
        c = self.lcfg.update_clip
        norm = float(update.norm())
        return update * min(1.0, c / max(norm, 1e-12)) / c, norm, c

    def _failpoint(self, name: str) -> None:
        """Crash injection for the assurance tests (see finetune.py):
        development attestation only."""
        if self.hooks and os.environ.get("ENCOMPUTE_TRAINING_FAILPOINT") == name:
            os._exit(137)

    def canary(self, v: torch.Tensor) -> None:
        """Test-only: the leakage tests plant a known value in the
        contribution and check it never appears outside the masked
        secure-aggregation message. Development attestation only: it
        overwrites coordinates after clipping."""
        value = os.environ.get("ENCOMPUTE_CANARY_UPDATE")
        if self.hooks and value:
            v[:4] = float(value)

    def contribute(self, msg: dict) -> dict:
        if self.dp is not None:
            v = self.dp_sgd_step(msg["adapter"])
            update, norm, c, self.loss = v, 0.0, 1.0, None
            self._failpoint("after-local-training")
        else:
            update = self.train(msg["adapter"], msg["seed"])
            self._failpoint("after-local-training")
            # Clip the whole update to update_clip (the sensitivity the
            # privacy accounting assumes), scaled into the codec's [-1, 1]
            # range.
            c = self.lcfg.update_clip
            norm = float(update.norm())
            v = update * min(1.0, c / max(norm, 1e-12)) / c
        self.canary(v)
        cfg = self.cfg
        attested = (["--coordinator-policy", cfg["coordinator_policy"],
                     "--mock-root", cfg["mock_root"]] if cfg["coordinator_policy"] else [])
        if cfg.get("contribution_policy"):
            attested += ["--attestation-policy", cfg["contribution_policy"],
                         "--attestation", self.contribution_record]
        p = subprocess.run(
            [cfg["cli"], "aggregate", "join", cfg["artifact"], "--parties", cfg["parties"],
             "--plan", cfg["plan"], *attested, "--coordinator", msg["coordinator"],
             "--party", cfg["party"], "--key", cfg["identity"], "--values", "-",
             "--state", cfg["state"], "--timeout", str(msg.get("timeout", 30))],
            input=json.dumps([float(x) for x in v]), capture_output=True, text=True,
        )
        del update, v
        self._failpoint("after-contribution")
        if self.dp is not None:
            # Nothing about the local data leaves except the masked
            # contribution: no loss, no clipping or sample statistics, and a
            # fixed error (review finding DP-5).
            ok = p.returncode == 0
            return {"ok": ok, "log": "" if ok else DP_FAILED}
        return {"ok": p.returncode == 0, "loss": self.loss, "clipped": norm > c,
                "log": (p.stdout + p.stderr)[-2000:]}


def main() -> None:
    cfg = json.load(open(sys.argv[1]))
    try:
        w = Worker(cfg)
    except Exception as e:  # reported to the orchestrator, then exit
        reply(ready=False, error=f"{type(e).__name__}: {e}")
        return
    reply(ready=True, record=w.record, grad_path=w.grad_path, versions=w.versions)
    for line in sys.stdin:
        msg = json.loads(line)
        if msg.get("cmd") == "exit":
            return
        try:
            reply(**w.contribute(msg))
        except Exception:
            # DP-SGD: whatever failed, the same message (an error that
            # depends on the data would leak outside the accounting).
            reply(ok=False, log=DP_FAILED if w.dp is not None else traceback.format_exc()[-2000:])


if __name__ == "__main__":
    main()
