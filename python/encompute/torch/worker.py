"""The confidential training worker: one per participant, inside the
placement the plan chose (an attested TEE).

    python -m encompute.torch.worker CONFIG.json

It attests to the model owner's key broker as the approved training spec's
workload and receives the base model's key. It opens the sealed model,
checks it is the committed version, and builds it from the bound factory
(never a pickle). It adds LoRA and checks the parameter layout is the
approved one. Then, per round, it trains locally on its owner's dataset and
contributes the clipped adapter update to secure aggregation, through
`encompute aggregate join --values -`. The update goes only into that
process's stdin: it is never written to disk or sent anywhere else.

Commands arrive as JSON lines on stdin; replies go out as JSON lines on
stdout.
"""

from __future__ import annotations

import json
import subprocess
import sys
import traceback

import torch

from .. import _native
from . import lora, models, tensors


def reply(**kw) -> None:
    print(json.dumps(kw), flush=True)


def load_dataset(cfg: dict) -> tuple:
    data = open(cfg["dataset"], "rb").read()
    if _native.sha256_hex(data) != cfg["dataset_digest"]:
        raise ValueError(f"{cfg['dataset_asset']} is not the dataset the training spec commits to")
    t = tensors.loads(data)
    return t["x"], t["y"]


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
        arch = json.loads(spec["base_model"]["architecture"])
        self.model = models.build(arch["factory"], arch["kwargs"])
        self.model.load_state_dict(tensors.loads(bytes(weights)))
        c = cfg["lora"]
        self.lcfg = lora.LoRAConfig(
            rank=c["rank"], alpha=c["alpha"], target_modules=tuple(c["target_modules"]),
            optimizer=c["optimizer"], learning_rate=c["learning_rate"],
            update_clip=c["update_clip"], local_steps=c["local_steps"],
            batch_size=c["batch_size"], rounds=c["rounds"], seed=c["seed"],
        )
        lora.apply_lora(self.model, self.lcfg)
        if lora.layout_digest(self.model) != spec["layout_digest"]:
            raise ValueError("this worker's adapter layout is not the approved one")
        self.x, self.y = load_dataset(cfg)

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
        for _ in range(self.lcfg.local_steps):
            idx = torch.randint(0, len(self.x), (self.lcfg.batch_size,), generator=g)
            opt.zero_grad()
            loss = torch.nn.functional.cross_entropy(self.model(self.x[idx]), self.y[idx])
            loss.backward()
            opt.step()
        self.loss = float(loss)
        return lora.get_flat(self.model) - start

    def contribute(self, msg: dict) -> dict:
        update = self.train(msg["adapter"], msg["seed"])
        # Clip the whole update to update_clip (the sensitivity the privacy
        # accounting assumes), scaled into the codec's [-1, 1] range.
        c = self.lcfg.update_clip
        norm = float(update.norm())
        v = update * min(1.0, c / max(norm, 1e-12)) / c
        cfg = self.cfg
        attested = (["--coordinator-policy", cfg["coordinator_policy"],
                     "--mock-root", cfg["mock_root"]] if cfg["coordinator_policy"] else [])
        p = subprocess.run(
            [cfg["cli"], "aggregate", "join", cfg["artifact"], "--parties", cfg["parties"],
             "--plan", cfg["plan"], *attested, "--coordinator", msg["coordinator"],
             "--party", cfg["party"], "--key", cfg["identity"], "--values", "-",
             "--state", cfg["state"], "--timeout", str(msg.get("timeout", 30))],
            input=json.dumps([float(x) for x in v]), capture_output=True, text=True,
        )
        del update, v
        return {"ok": p.returncode == 0, "loss": self.loss, "clipped": norm > c,
                "log": (p.stdout + p.stderr)[-2000:]}


def main() -> None:
    cfg = json.load(open(sys.argv[1]))
    try:
        w = Worker(cfg)
    except Exception as e:  # reported to the orchestrator, then exit
        reply(ready=False, error=f"{type(e).__name__}: {e}")
        return
    reply(ready=True, record=w.record)
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
