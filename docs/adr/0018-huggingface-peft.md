# ADR-018 — Hugging Face Transformers and PEFT

Status: **Accepted** (2026-09-26)

## Context

Confidential fine-tuning ran a small reference classifier with a
hand-written LoRA. ML teams use Hugging Face Transformers models and PEFT
adapters. Encompute must train those without weakening any guarantee:
- confidentiality;
- attestation and key release;
- secure aggregation and patient-level DP;
- lineage, rollback resistance and export control.

## Decision

1. **The boundary.**
   - Transformers supplies the architecture and tokenizer.
   - PEFT supplies the LoRA adapters and the portable adapter format.
   - PyTorch trains.
   - Encompute supplies ownership, policy, attestation, key release,
     aggregation, privacy, lineage and verification.
   - The reference LoRA stays as the dependency-light backend and
     correctness oracle (`method="lora"`). Hugging Face models use
     `method="peft-lora"`.
2. **Model packages, never runtime downloads.**
   - The model owner imports a model once, outside any confidential
     workload.
   - A Hub revision is resolved to its immutable commit; a local model's
     revision is its content digest (`sha256:`). `main`, tags and `latest`
     are never bound.
   - Only configuration, tokenizer and `*.safetensors` files are kept,
     each hashed. `*.py`, pickled formats (`.bin`, `.pt`, `.pkl`, ...),
     unknown files, a `config.json` naming custom code (`auto_map`,
     `trust_remote_code`), a shard index (`model.safetensors.index.json`)
     naming anything but the package's own safetensors files, and
     unsupported architectures are refused (ENC2504).
   - Credentials are used for that download only, and never stored.
   - The package manifest (Rust-owned, validated, ID `enchf1:`) binds:
     - the repository and revision;
     - the class, task and labels;
     - every file's digest;
     - the configuration and tokenizer digests;
     - the library versions and the license.
3. **Rebuilding in workers.**
   - The base model is rebuilt from its configuration with the
     Transformers-native class (`from_config`, eager attention), then the
     sealed weights are loaded.
   - No remote code, no `from_pretrained` from a repository, no network.
   - The training spec's `base_model.huggingface` carries the whole
     package manifest, so the trust graph holds the supply chain and the
     lineage prints it.
4. **Library versions.**
   - The package binds major.minor versions of Transformers, PEFT and
     PyTorch. A worker with others refuses to run (ENC2504), including
     on resume.
   - Patch versions do not change the package. The run records exact
     versions (Transformers, PEFT, PyTorch, safetensors, tokenizers) in its
     provenance.
   - The library code itself is trusted through the worker image digest.
5. **PEFT.**
   - The official `peft` library adds LoRA (`get_peft_model`).
   - The spec's `PeftConfig` binds the type, rank, alpha, dropout, target
     modules, bias, the fully trained head, task type, initialization,
     adapter name and PEFT library version.
   - The adapter is every trainable parameter (the LoRA matrices and the
     head), in the canonical layout (sorted by module and parameter). Its
     digest is in the spec, so every participant aggregates the same
     layout.
6. **Text data.**
   - `private_text_dataset` tokenizes with the package's tokenizer and
     pads to a fixed length. With a stride, it splits long texts into
     overlapping chunks.
   - Every chunk keeps its text's privacy unit (`unit_ids`, or the text
     itself). Tokenization never splits a patient into several units.
   - Each dataset commitment binds its preprocessing: the tokenizer
     digest, the maximum length, truncation, padding and stride. The spec
     refuses a tokenizer other than the package's.
7. **Tasks.** A task adapter maps a dataset's named tensors to the model's
   arguments and reads logits from structured outputs. The loss is per
   record, so DP-SGD can sum a unit's records before clipping.
8. **Per-patient gradients.**
   - Two paths, with identical semantics:
     - the fast path: `vmap(grad)` per example;
     - the reference path: one unit at a time with autograd.
   - A probe on the worker's own records picks the fast path if it runs
     in training mode and agrees with the reference, else the reference
     path. With eager attention, BERT, DistilBERT and RoBERTa take the
     fast path; SDPA attention does not vectorize.
   - If no path yields per-unit gradients, the worker refuses: patient-level
     privacy is never downgraded to ordinary clipping.
9. **Export.**
   - `export_peft` writes `adapter_config.json`,
     `adapter_model.safetensors` and `encompute-adapter.json` (the adapter's
     Encompute identity). It does so only when every parent permits a
     public adapter, no parent is revoked, and the trust report is
     satisfied. Otherwise it writes nothing.
   - Owners permit public adapters explicitly, per asset
     (`adapters="public"`).
   - The protected path (attested inference with the sealed model and
     adapter) needs no export.
10. **Planning.** The training declaration names the framework
    (`pytorch-reference` or `huggingface-sequence-classification`). This is
    workload metadata; the mechanisms still follow from the policy.

## Consequences and limits

- One clean path: sequence classification with BERT, DistilBERT and
  RoBERTa.
- Not covered:
  - causal LMs;
  - `Trainer`, TRL and quantization;
  - multi-GPU training;
  - arbitrary remote-code models.
- The model configuration is shared with participants as metadata. The
  weights are not.
- CI uses a tiny model written locally, with no network. Real Hub models
  import the same way.
- A dependency set, `encompute[huggingface]`. CI pins Transformers 4.46
  and PEFT 0.12.
- Assurance: INV-136 to INV-142, `examples/17_huggingface_peft`.
