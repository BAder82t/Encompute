"""Attested inference with a private adapter:

    python -m encompute.torch.infer CONFIG.json

The workload attests to the model owner's key broker as the approved
training spec's workload, and receives the base model key and the adapter
key. It opens both, checking each is the committed version: the model
against the training spec, the adapter against its signed record. It then
returns the logits for the requester's inputs. Neither model asset leaves
the workload.
"""

from __future__ import annotations

import json
import sys

from .. import _native
import torch

from . import lora, tasks, tensors


def main() -> None:
    cfg = json.load(open(sys.argv[1]))
    try:
        spec = json.loads(cfg["spec"])
        base = spec["base_model"]
        keys, _ = _native.acquire_training_keys(
            cfg["spec"], cfg["broker"], [base["asset_id"], "adapters"],
            cfg["identity"], cfg["mock_seed"], cfg["image"])
        keys = dict(keys)
        weights = _native.open_asset(keys[base["asset_id"]], open(cfg["model_sealed"], "rb").read(),
                                     spec["project"], base["asset_id"], base["weights_digest"])
        model = tasks.build(spec, weights, cfg["lora"]["seed"])
        adapter = _native.open_asset(keys["adapters"], open(cfg["adapter_sealed"], "rb").read(),
                                     spec["project"], cfg["adapter"], cfg["adapter_digest"])
        lora.set_flat(model, tensors.loads(bytes(adapter))["adapter"])
        model.eval()
        batch = tensors.loads(bytes.fromhex(cfg["inputs"]))
        with torch.no_grad():
            logits = tasks.of_spec(spec).model_logits(model, batch).detach()
        print(json.dumps({"ok": True, "logits": tensors.dumps({"logits": logits}).hex()}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))


if __name__ == "__main__":
    main()
