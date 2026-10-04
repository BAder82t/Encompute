# Confidential fine-tuning

LoRA and PEFT fine-tuning on several parties' private data.

PyTorch does the computation; Encompute decides who may hold what, and
proves it. One call fine-tunes a private model on several
parties' private data:

```python
import encompute.torch as et
base = project.model("base-model", owner="modelco",
                     module=et.wrap_model("encompute.torch.models:tiny_classifier"))
a = project.data("patients-a", owner="hospital-a", dataset=et.private_dataset(xa, ya))
b = project.data("patients-b", owner="hospital-b", dataset=et.private_dataset(xb, yb))
adapter = project.finetune(model=base, data=[a, b], method="lora",
                           privacy="standard", verification="required")
adapter.infer(x); adapter.lineage(); adapter.export_adapter()   # EXPORT DENIED
```

Each hospital's training worker attests before it receives the model key.
LoRA updates leave it only through secure aggregation with differential
privacy (organization-level: each hospital's clipped update). Adapters and
checkpoints are sealed; resuming can never roll back spent budget; every
adapter's lineage is signed and checked by the trust report. PyTorch runs
in plaintext inside the attested workload: the TEE, not PyTorch, protects
data in use. See [examples/15_confidential_lora](../../examples/15_confidential_lora/).

For patient-level privacy, pass each record's patient and ask for DP-SGD:

```python
a = project.data("patients-a", owner="hospital-a",
                 dataset=et.private_dataset(xa, ya, unit_ids=patient_ids_a))
adapter = project.finetune(model=base, data=[a, b], privacy="strong-patient")
```

Each worker clips every patient's gradient, with all of the patient's
records grouped, and samples patients at random. The coordinator adds
noise to the securely aggregated sum. A Rényi DP accountant, checked
against an independent reference, charges each hospital's budget. A run
that would exceed the budget is denied before training, and the trust
report refuses a patient-level claim from organization-level training. See
[examples/16_patient_private_lora](../../examples/16_patient_private_lora/).

## Hugging Face Transformers + PEFT

```python
base = et.huggingface("org/model", revision="<commit>")   # or a local directory
notes = et.private_text_dataset(texts, labels, tokenizer=base.encompute_tokenizer,
                                unit_ids=patient_ids)
model = project.model("clinical-model", owner="modelco", module=base)
adapter = project.finetune(model=model, data=[a, b], method="peft-lora",
                           privacy="strong-patient")
adapter.export_peft("adapter/")   # standard PEFT files, only if every owner permits
```

The model owner imports the model once into a content-addressed package:
- the revision is resolved to an immutable commit;
- only safetensors, configuration and tokenizer files are kept;
- remote code and pickled weights are refused;
- credentials are used for that download only.

Workers never download anything. They rebuild the Transformers-native
class, load the sealed weights, and add PEFT LoRA.

The training spec binds:
- the package (every file's digest);
- the tokenizer and each dataset's tokenization;
- the PEFT configuration and the adapter layout.

A patient's records keep their patient through tokenization and chunking.
Transformers supplies the architecture, PEFT the adapters and PyTorch the
training; Encompute supplies the confidentiality, privacy and evidence. See
[examples/17_huggingface_peft](../../examples/17_huggingface_peft/).
