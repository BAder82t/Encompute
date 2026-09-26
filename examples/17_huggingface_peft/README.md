# 17 — Hugging Face Transformers + PEFT, with patient-level privacy

## What this demonstrates

ModelCo owns a Transformers model. Two hospitals own private clinical
notes. They fine-tune the model together with standard PEFT LoRA:

```python
base = et.huggingface("org/clinical-bert", revision="<commit>")   # here: a local tiny BERT
tok = base.encompute_tokenizer
notes_a = et.private_text_dataset(texts_a, labels_a, tokenizer=tok, max_length=16,
                                  stride=4, unit_ids=patient_ids_a)
model = project.model("clinical-model", owner="modelco", module=base, adapters="public")
a = project.data("notes-a", owner="hospital-a", dataset=notes_a, adapters="public")
adapter = project.finetune(model=model, data=[a, b], method="peft-lora",
                           privacy="strong-patient", verification="required")
adapter.infer(test_notes)              # protected: nothing leaves the attested path
adapter.export_peft("exported-adapter")  # standard PEFT files, only if permitted
```

Each tool has its job:

| | Supplies |
|---|---|
| Hugging Face Transformers | the model architecture and tokenizer |
| PEFT | LoRA adapters and the portable adapter format |
| PyTorch | training |
| Encompute | ownership, policy, attestation, key release, secure aggregation, differential privacy, lineage and verification |

Hugging Face provides no confidentiality here. Encompute does.

The run:

1. **Import.** ModelCo imports the model once, into a content-addressed
   package:
   - the revision is resolved to an immutable commit (a local model gets
     its content digest);
   - only safetensors, configuration and tokenizer files are kept;
   - remote code and pickled weights are refused;
   - every file is hashed.
2. **Tokenize.** Each hospital tokenizes its notes with the package's
   tokenizer. Long notes are split into overlapping chunks, and every
   chunk keeps its note's patient. The output shows 4,040 notes becoming
   4,120 records, which are still 2,000 patients.
3. **Bind.** The training spec binds:
   - the package: its revision, every file's digest, the tokenizer and
     the library versions;
   - each dataset's tokenization;
   - the PEFT configuration (rank, alpha, dropout, target modules, bias,
     the fully trained head, initialization, adapter name);
   - the adapter layout;
   - the DP-SGD settings.
4. **Train.** Attested workers rebuild the Transformers-native class from
   its configuration, load the sealed weights and add PEFT LoRA. They never
   download anything. For each patient, a worker:
   - computes per-example gradients (vectorized when the model allows it,
     otherwise one patient at a time, with the same result);
   - groups the patient's records and clips once per patient;
   - samples patients at random.

   Secure aggregation sums the clipped gradients, and the coordinator adds
   noise.
5. **Verify.** The trust report and the lineage record the whole supply
   chain.
6. **Use.** Inference runs in an attested workload with the sealed model
   and adapter. The accuracy on ModelCo's held-out notes goes from about
   0.77 (the base model) to about 0.96.
7. **Export.** Every owner allowed adapters to be shared (`adapters="public"`)
   and the trust report is satisfied, so the adapter is exported as
   `adapter_config.json` and `adapter_model.safetensors`, plus
   `encompute-adapter.json` (its Encompute identity). Plain Transformers and
   `PeftModel.from_pretrained` load it and give the same predictions.

## Run it

```sh
pip install 'encompute[huggingface]'      # torch, transformers, peft
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/17_huggingface_peft/run.sh
```

It needs no network: the tiny model is written locally and briefly
pretrained on a related task, as a real base model would be. It takes
about a minute and a half.

## Expected output

```text
Model package           enchf1:...
Class                   BertForSequenceClassification
Weights                 SAFETENSORS VERIFIED
Remote code             DISABLED
hospital-a              4040 notes -> 4120 tokenized records -> 2000 patients
...
Per-patient gradients   ACTIVE (vectorized per-example gradients)
Round 20/20             COMPLETE
TRUST REQUIREMENTS SATISFIED
Held-out accuracy       0.772 (base model) -> 0.956 (adapter)
EXPORT PERMITTED: every parent of adapter-20 allows public release
PEFT vs Encompute       max logit difference 9.5e-07
PEFT INTEROPERABLE

CONFIDENTIAL HUGGING FACE FINE-TUNING
Framework               Transformers
PEFT                    LoRA
Privacy unit            patient
Per-patient clipping    ACTIVE
Trust report            SATISFIED
```

## Try breaking it

`attack.py` attacks the finished run:

| Attack | Boundary | Refusal |
|---|---|---|
| another model revision, or one swapped weight shard | the training spec binds the package, so the key broker refuses | ENC2002 |
| tampered sealed weights | authenticated encryption | ENC2502 |
| a dataset tokenized with a changed vocabulary | each dataset's tokenizer must be the package's | ENC2501 |
| a changed tokenizer configuration | the tokenizer digest covers it | ENC2504 |
| `trust_remote_code=True`, or custom code named in `config.json` | remote code never runs | ENC2504 |
| pickled weights (`pytorch_model.bin`) | only safetensors | ENC2504 |
| a shard index pointing outside the package (`../`, an absolute path) | an index may name only the package's safetensors files | ENC2504 |
| a mutable revision (`main`) | only a commit or a content digest | ENC2504 |
| other PEFT target modules, or a higher rank | the training spec binds the PEFT configuration | ENC2002 |
| a different adapter layout | the worker checks the layout digest | refused |
| the adapter with another base model | the adapter's training spec names its base | ENC2002 |
| the adapter moved into another project | the sealed adapter is bound to its project | ENC2501 |
| the private model outside the approved workload | only the attested image receives keys | ENC2002 |
| patient IDs changed after tokenization, or grouping dropped | the dataset digest covers the IDs | refused |
| less DP noise | the training spec binds it | ENC2002 |
| claim patient privacy without per-patient clipping | the planner refuses | ENC2401 |
| resume under another Transformers version | the package binds library versions | ENC2504 |
| export after a hospital revokes its data | export refuses revoked parents | EXPORT DENIED |

`python/tests/test_huggingface.py` also covers:
- the Hub path: `main` is resolved to its commit, and the token is never
  stored;
- both gradient paths against a one-record-at-a-time reference;
- a model with no per-patient gradients failing closed;
- export writing nothing when it is refused.

## What Encompute guarantees

- A run is bound to one immutable model package. Nothing downloaded, and
  no repository code, runs in a worker.
- Only safetensors weights enter the supported path.
- The adapter layout is identical for every participant, and every PEFT
  setting is bound.
- Patient-level DP-SGD holds for PEFT parameters exactly as for the
  reference model. Tokenization cannot split a patient into several units.
- A model that cannot produce per-patient gradients cannot claim
  patient-level privacy: training fails closed.
- An adapter leaves as PEFT files only when every owner permits it, no
  owner has revoked, and the trust report is satisfied.

## What Encompute does NOT guarantee

- **PyTorch and Transformers are not encrypted.** They run in plaintext
  inside the attested workload. Here attestation is a mock, which protects
  nothing.
- **Library code is trusted by version, not by digest.** The package binds
  the major.minor versions of Transformers, PEFT and PyTorch, and the run
  records the exact versions. The installed library code itself is
  covered only by the worker image's digest, as in any real deployment.
- **Only sequence classification with BERT, DistilBERT and RoBERTa** is
  supported. Causal language models, larger models, quantization and
  multi-GPU training are not covered yet.
- **The model configuration is shared** with the hospitals, as metadata.
  The weights are not.
- **Patient IDs must be right.** The digest makes them fixed and auditable,
  not correct.

## Relevant source modules

- `python/encompute/torch/hf.py`: import, packages, tokenizers, PEFT and
  the offline test model.
- `python/encompute/torch/tasks.py`: task adapters (structured outputs,
  per-record losses) and the shared model builder.
- `python/encompute/torch/dpsgd.py`: the fast and reference gradient
  paths, and the probe that picks one.
- `crates/encompute-training/src/hf.rs`: the model package format and its
  checks.
- `crates/encompute-training/src/spec.rs`: `PeftConfig` and
  `TextPreprocessing` in the training spec.
- Design notes: `docs/adr/0018-huggingface-peft.md`.
