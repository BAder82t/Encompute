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

import torch

from .. import _native
from . import dpsgd, lora, tasks, tensors


def _failpoint(name: str) -> None:
    """Crash injection for the assurance tests (see finetune.py)."""
    if os.environ.get("ENCOMPUTE_TRAINING_FAILPOINT") == name:
        os._exit(137)


def reply(**kw) -> None:
    print(json.dumps(kw), flush=True)


def load_dataset(cfg: dict) -> tuple:
    """The committed dataset's named tensors and its unit IDs (if any)."""
    data = open(cfg["dataset"], "rb").read()
    if _native.sha256_hex(data) != cfg["dataset_digest"]:
        raise ValueError(f"{cfg['dataset_asset']} is not the dataset the training spec commits to")
    t = tensors.loads(data)
    unit_ids = t.pop("unit_ids", None)
    return t, unit_ids


class Worker:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        spec = json.loads(cfg["spec"])
        self.spec = spec
        keys, record = _native.acquire_training_keys(
            cfg["spec"], cfg["broker"], [spec["base_model"]["asset_id"]],
            cfg["identity"], cfg["mock_seed"], cfg["image"],
        )
        self.record = record
        key = dict(keys)[spec["base_model"]["asset_id"]]
        sealed = open(cfg["model_sealed"], "rb").read()
        weights = _native.open_asset(
            key, sealed, spec["project"], spec["base_model"]["asset_id"],
            spec["base_model"]["weights_digest"],
        )
        del key
        c = cfg["lora"]
        self.lcfg = lora.LoRAConfig(
            rank=c["rank"], alpha=c["alpha"], target_modules=tuple(c["target_modules"]),
            optimizer=c["optimizer"], learning_rate=c["learning_rate"],
            update_clip=c["update_clip"], local_steps=c["local_steps"],
            batch_size=c["batch_size"], rounds=c["rounds"], seed=c["seed"],
        )
        # The bound base model (Hugging Face: the package's library versions
        # are checked first), the bound adapter, the approved layout.
        self.model = tasks.build(spec, weights, c["seed"])
        self.task = tasks.of_spec(spec)
        self.data, unit_ids = load_dataset(cfg)
        self.n = tasks.records(self.data)
        self.versions = None
        if spec["base_model"].get("huggingface"):
            from . import hf
            self.versions = hf.exact_versions()
        self.grad_path = None
        self.dp = None
        if spec["config"].get("dp_sgd"):
            d = spec["config"]["dp_sgd"]
            mine = next(x for x in spec["datasets"] if x["asset_id"] == cfg["dataset_asset"])
            self.unit_of, n_units = dpsgd.unit_index(unit_ids, self.n)
            # The grouping must be the committed one.
            if (d["grouping"] == "unit_ids") != (unit_ids is not None):
                raise ValueError("this dataset's grouping is not the approved one")
            if unit_ids is not None and _native.sha256_hex(
                    tensors.dumps({"unit_ids": unit_ids})) != mine["grouping_digest"]:
                raise ValueError("this dataset's patient grouping is not the committed one")
            if n_units != mine["privacy_units"]:
                raise ValueError("this dataset's number of privacy units is not the committed one")
            self.n_units = n_units
            self.dp = dpsgd.DpSgd(
                unit=d["privacy_unit"], per_example_clip=float(d["per_example_clip"]),
                sampling_rate=float(d["sampling_rate"]),
                noise_multiplier=float(d["noise_multiplier"]), delta=float(d["delta"]),
                grouping=d["grouping"], expected_batch=float(d["expected_batch"]),
                microbatch=int(cfg.get("microbatch", 64)))
            # Per-unit gradients, on the fast path if this model supports
            # it; never ordinary clipping (fails closed otherwise).
            self.grad_path = dpsgd.select_path(self.model, self.task, self.data)
            # The coordinator accepts DP-SGD contributions only from an
            # attested worker running this training code.
            self.contribution_record = os.path.join(os.path.dirname(cfg["state"]),
                                                    "contribution-attestation.json")
            with open(self.contribution_record, "w") as f:
                f.write(_native.attest_contribution(
                    spec["plan_id"], None, spec["code_digest"], cfg["identity"],
                    cfg["mock_seed"], cfg["image"]))

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
        rescaled so each unit's is at most CODEC_CLIP. The round's seed is
        not used: the sample comes from the operating system."""
        lora.set_flat(self.model, torch.tensor(adapter, dtype=torch.float32))
        sampled = dpsgd.poisson_sample(self.n_units, self.dp.sampling_rate)
        self.model.train()
        g = dpsgd.clipped_sum(self.model, self.task, self.data, self.unit_of, sampled,
                              self.dp.per_example_clip, self.dp.microbatch, self.grad_path)
        return g * (dpsgd.CODEC_CLIP / self.dp.per_example_clip)

    def contribute(self, msg: dict) -> dict:
        if self.dp is not None:
            v = self.dp_sgd_step(msg["adapter"])
            update, norm, c, self.loss = v, 0.0, 1.0, None
            _failpoint("after-local-training")
        else:
            update = self.train(msg["adapter"], msg["seed"])
            _failpoint("after-local-training")
            # Clip the whole update to update_clip (the sensitivity the
            # privacy accounting assumes), scaled into the codec's [-1, 1]
            # range.
            c = self.lcfg.update_clip
            norm = float(update.norm())
            v = update * min(1.0, c / max(norm, 1e-12)) / c
        # Test-only: the leakage tests plant a known value in the
        # contribution and check it never appears outside the masked
        # secure-aggregation message.
        canary = os.environ.get("ENCOMPUTE_CANARY_UPDATE")
        if canary:
            v[:4] = float(canary)
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
        _failpoint("after-contribution")
        if self.dp is not None:
            # Nothing about the local data leaves except the masked
            # contribution: no loss, no clipping or sample statistics.
            return {"ok": p.returncode == 0, "log": (p.stdout + p.stderr)[-2000:]}
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
            reply(ok=False, log=traceback.format_exc()[-2000:])


if __name__ == "__main__":
    main()
