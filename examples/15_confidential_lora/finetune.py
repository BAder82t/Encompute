"""15: confidential LoRA fine-tuning with PyTorch.

Two hospitals fine-tune ModelCo's private base model on their private
datasets. Neither hospital sees the model or the other's data, ModelCo sees
no data, and only a noised aggregate of the updates is ever released.
"""

import sys

import torch

import encompute
import encompute.torch as et


def patients(seed: int, n: int = 96):
    """A synthetic hospital dataset: token sequences and a label (the
    target depends on the first token). Stands in for private text."""
    g = torch.Generator().manual_seed(seed)
    x = torch.randint(0, 64, (n, 8), generator=g)
    return et.private_dataset(x, (x[:, 0] < 32).long())


project = encompute.Project(
    "medical-lora",
    parties=["hospital-a", "hospital-b", "modelco"],
    purpose="disease-training",
)

torch.manual_seed(0)
base = et.wrap_model("encompute.torch.models:tiny_classifier", vocab=64, dim=16, classes=2)
model = project.model("base-model", owner="modelco", policy="private-model", module=base)
a = project.data("patients-a", owner="hospital-a", policy="private-training", dataset=patients(1))
b = project.data("patients-b", owner="hospital-b", policy="private-training", dataset=patients(2))

adapter = project.finetune(
    model=model,
    data=[a, b],
    method="lora",
    privacy="standard",
    verification="required",
    config=et.LoRAConfig(rank=4, alpha=8, target_modules=("q", "v"), rounds=2,
                         local_steps=10, learning_rate=0.1),
    allow_development=True,            # mock attestation: this machine has no TEE
    workdir=sys.argv[1] if len(sys.argv) > 1 else None,
)

print("\n" + adapter.lineage())

print("Inference with the private adapter (in an attested workload)")
x = patients(9, 32)[0]
before, after = adapter.infer(x, adapter="adapter-0"), adapter.infer(x)
changed = int((before.argmax(1) != after.argmax(1)).sum())
print(f"  predictions changed by training   {changed} of {len(x)}")
print(f"  largest logit change              {float((before - after).abs().max()):.3f}")
print("ADAPTER USABLE" if float((before - after).abs().max()) > 1e-3 else "ADAPTER UNCHANGED")

print("\nExport")
print(adapter.export)

print("\nMeasured (seconds; development attestation, all parties on one machine)")
labels = {
    "plain_pytorch_local_training_s": "plain PyTorch, one party's local steps",
    "attestation_startup_s": "workers attest, receive the model key",
    "secure_aggregation_s": "rounds: local training + SecAgg + DP",
    "checkpoint_s": "sealed checkpoints and adapters",
    "trust_graph_s": "adapter records into the trust graph",
    "total_s": "total",
}
for k, v in adapter.timings.items():
    print(f"  {labels.get(k, k):<42}{v:.2f}")
adapter.close()
raise SystemExit(0 if adapter.satisfied else 1)
