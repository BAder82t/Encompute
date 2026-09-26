"""17: confidential fine-tuning of a Hugging Face model with PEFT LoRA and
patient-level differential privacy.

ModelCo imports a Transformers model into a content-addressed package
(immutable revision, safetensors only, no remote code). Two hospitals
tokenize their private clinical notes, keeping each note's patient.
Encompute fine-tunes the model with PEFT LoRA in attested workers, with
per-patient clipping, secure aggregation and differential privacy. The
adapter is verified, used for inference without leaving the protected
path, and, because every owner allowed it, exported as standard PEFT files
that load with plain Transformers and PEFT.

    python finetune.py WORKDIR

The model is a tiny BERT written locally (no download), standing in for a
repository; `encompute.torch.huggingface("org/model", revision=...)`
imports a real one the same way.
"""

import json
import sys
from pathlib import Path

import torch

import encompute
import encompute.torch as et
from encompute.torch import hf

W = Path(sys.argv[1])
W.mkdir(parents=True, exist_ok=True)
PATIENTS = 2000
RISK = hf.WORDS[13:]  # the hospitals' task: notes dominated by these words


def hospital_notes(seed: int, patients: int = PATIENTS):
    """Two notes per patient; one patient in fifty also has a long note,
    which is split into overlapping chunks (all of them that patient's)."""
    texts, labels = hf.synthetic_notes(seed, patients * 2, RISK)
    ids = [i // 2 for i in range(len(texts))]
    for p in range(0, patients, 50):
        long_note = " ".join([texts[2 * p]] * 5)
        texts.append(long_note)
        labels.append(labels[2 * p])
        ids.append(p)
    return texts, labels, ids


print("== ModelCo imports a Hugging Face model ==\n")
repo = hf.write_tiny_model(str(W / "repository"), "bert")
base = et.huggingface(str(repo), num_labels=2)
pkg = base.encompute_hf
tok = base.encompute_tokenizer
print(f"{'Model package':<24}enchf1:{pkg.id[:16]}...")
print(f"{'Class':<24}{pkg.manifest['model_class']}")
print(f"{'Resolved revision':<24}{pkg.manifest['revision'][:23]}...")
print(f"{'Files':<24}" + ", ".join(f["path"] for f in pkg.manifest["files"]))
print(f"{'Weights':<24}SAFETENSORS VERIFIED")
print(f"{'Remote code':<24}DISABLED\n")

print("== The hospitals tokenize their notes, keeping each note's patient ==\n")
project = encompute.Project("medical-text", parties=["hospital-a", "hospital-b", "modelco"],
                            purpose="disease-training")
# Every owner allows adapters derived from its asset to be shared, so the
# final adapter may be exported (still only if the trust report passes).
model = project.model("clinical-model", owner="modelco", policy="private-model", module=base,
                      adapters="public")
data = []
for i, owner in enumerate(("hospital-a", "hospital-b")):
    texts, labels, ids = hospital_notes(i + 1)
    d = et.private_text_dataset(texts, labels, tokenizer=tok, max_length=16, stride=4,
                                unit_ids=ids)
    units = len(torch.unique(d.tensors["unit_ids"]))
    print(f"{owner:<24}{len(texts)} notes -> {len(d)} tokenized records -> {units} patients")
    data.append(project.data(f"notes-{'ab'[i]}", owner=owner, dataset=d, adapters="public"))

print("\n== Confidential fine-tuning ==\n")
result = project.finetune(
    model=model, data=data, method="peft-lora", privacy="strong-patient",
    verification="required",
    config=et.LoRAConfig(rank=4, alpha=8, rounds=20, batch_size=100, learning_rate=3.0),
    allow_development=True, workdir=str(W / "run"))

print("\n== Inference, without exporting anything ==\n")
tt, tl = hf.synthetic_notes(99, 500, RISK)
test = et.private_text_dataset(tt, tl, tokenizer=tok, max_length=16)
labels = torch.tensor(tl)
before = float((result.infer(test, adapter="adapter-0").argmax(1) == labels).float().mean())
after = float((result.infer(test).argmax(1) == labels).float().mean())
print(f"{'Held-out accuracy':<24}{before:.3f} (base model) -> {after:.3f} (adapter)")

print("\n== Export as standard PEFT files, and load them without Encompute ==\n")
print(result.export_peft(str(W / "exported-adapter")))
from peft import PeftModel  # noqa: E402
from transformers import AutoModelForSequenceClassification  # noqa: E402

plain = AutoModelForSequenceClassification.from_pretrained(str(repo))
peft_model = PeftModel.from_pretrained(plain, str(W / "exported-adapter")).eval()
with torch.no_grad():
    outside = peft_model(input_ids=test.tensors["input_ids"],
                         attention_mask=test.tensors["attention_mask"]).logits
diff = float((outside - result.infer(test)).abs().max())
print(f"{'Files':<24}" + ", ".join(sorted(p.name for p in (W / 'exported-adapter').iterdir())))
print(f"{'PEFT vs Encompute':<24}max logit difference {diff:.1e}")
print("PEFT INTEROPERABLE" if diff < 1e-4 else "PEFT OUTPUT DIFFERS")
meta = json.loads((W / "exported-adapter" / "encompute-adapter.json").read_text())
print(f"{'Encompute identity':<24}{meta['adapter_id']} of {meta['model_package_id'][:24]}...")

print("\n" + result.lineage())

rows = result.rows
print("CONFIDENTIAL HUGGING FACE FINE-TUNING")
print("─" * 36)
for k, v in (("Framework", "Transformers"), ("PEFT", "LoRA"),
             ("Base model", pkg.manifest["repo_id"]),
             ("Weights", "SAFETENSORS VERIFIED"), ("Remote code", "DISABLED"),
             ("Participants", "2"), ("Privacy unit", result.privacy_unit),
             ("Per-patient clipping", "ACTIVE"),
             ("Secure aggregation", rows.get("Private aggregation")),
             ("Differential privacy", rows.get("Privacy budget")),
             ("Adapter lineage", rows.get("Lineage")),
             ("Trust report", "SATISFIED" if result.satisfied else "NOT SATISFIED")):
    print(f"{k:<24}{v}")
print("\nMeasured (seconds; development attestation, all parties on one machine)")
labels_t = {
    "plain_pytorch_local_training_s": "plain PyTorch + PEFT, one local step",
    "attestation_startup_s": "workers attest, load Transformers, pick the gradient path",
    "secure_aggregation_s": "20 rounds: per-patient gradients + SecAgg + DP",
    "checkpoint_s": "sealed checkpoints and adapters",
    "trust_graph_s": "adapter records into the trust graph",
    "total_s": "total",
}
for k, v in result.timings.items():
    print(f"  {labels_t.get(k, k):<58}{v:.2f}")
result.close()
ok = result.satisfied and after > before + 0.1 and diff < 1e-4
print("\nRESULT\n" + ("CONFIDENTIAL HUGGING FACE FINE-TUNING VERIFIED" if ok else "FAILED"))
sys.exit(0 if ok else 1)
