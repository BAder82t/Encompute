# 15 — Confidential LoRA fine-tuning

## What this demonstrates

A real PyTorch fine-tuning run, protected end to end. ModelCo owns a small
transformer classifier. Hospitals A and B each own a private dataset. The
developer writes:

```python
adapter = project.finetune(model=model, data=[a, b], method="lora",
                           privacy="standard", verification="required",
                           allow_development=True)
```

Encompute does the rest:

1. It **plans** the run. Training cannot run under FHE, and each side's
   assets must stay hidden from the other, so every training step goes into
   an attested confidential workload. The updates go through secure
   aggregation with differential privacy.
2. It **binds** the run to a training spec (`enctrain1:`) covering:
   - the plan, the base model's digest and the training code's digest;
   - the LoRA configuration and the adapter's tensor layout;
   - the datasets' digests, the participants, and the privacy and
     aggregation specs.
3. It **attests** each hospital's training worker. ModelCo's key broker
   releases the model key only to a workload bound to that spec.
4. It **trains** with PyTorch in each worker: base weights frozen, LoRA on
   `q` and `v`.
5. It **aggregates** each worker's clipped update through secure
   aggregation. The update goes only into the aggregation client's stdin:
   never to disk, never to ModelCo.
6. It **releases** the sum with discrete Gaussian noise, charged to each
   hospital's budget.
7. It **records** every round:
   - an immutable adapter (`adapter-0 → round 1 → adapter-1 → …`), sealed;
   - a sealed checkpoint bound to the privacy ledgers;
   - a signed adapter record in the trust bundle.
8. It **verifies** the whole run with one trust report, shows the adapter's
   lineage, refuses a public export, and runs **inference** with the adapter
   in an attested workload, showing that training changed the model's
   predictions.

**Privacy unit: organization.** Each hospital's whole update is clipped,
so the budget bounds what the adapter reveals about one hospital's
contribution. This run does not claim patient-level privacy. For that, use
DP-SGD (`privacy="strong-patient"`), shown in
[example 16](../16_patient_private_lora/).

**Crash safety.** A round is accepted only when its signed adapter record
enters the trust bundle. After a crash, `recover(workdir)` finalizes or
discards the round, and `finetune(resume=workdir)` continues. A released
but unaccepted round stays charged.

## Threat model

- The cloud host is untrusted.
- ModelCo must not see patient data.
- Neither hospital may obtain the base model or the other hospital's data.
- The aggregation coordinator (ModelCo) must not see an individual update.
- The TEE hardware is trusted. Here it is **development mock attestation**:
  every check runs, but there is **no hardware confidentiality**.
- Parties know each other's public keys out of band.

## Architecture

```text
 ModelCo                          hospital A worker (attested)   hospital B worker (attested)
 ───────                          ────────────────────────────   ────────────────────────────
 plan, training spec              attest ─► model key            attest ─► model key
 key broker ──sealed key──────►   open model (digest checked)    open model (digest checked)
 adapter-N ─────────────────────► LoRA train on patients-a        LoRA train on patients-b
                                  clip ─► aggregate join (stdin)  clip ─► aggregate join (stdin)
 coordinator: SecAgg + DP ◄───── masked contributions ───────────┘
 adapter-N+1, sealed checkpoint, signed adapter record ─► trust bundle ─► trust report
```

## Run it

```sh
pip install torch --index-url https://download.pytorch.org/whl/cpu
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/15_confidential_lora/run.sh
```

## Expected output

```text
Plan                    encplan1:...
DEVELOPMENT ATTESTATION: NO HARDWARE CONFIDENTIALITY
Training                LoRA (rank 4, 256 adapter parameters)
Workers                 2 attested, model key received
Round 1/2               COMPLETE (mean local loss 0.704)
Round 2/2               COMPLETE (mean local loss 0.797)

CONFIDENTIAL FINE-TUNING
────────────────────────
Model protection        SATISFIED
Dataset protection      SATISFIED
Gradient protection     SATISFIED
Privacy budget          SATISFIED
Workload identity       VERIFIED
Aggregation             VERIFIED
Checkpoint lineage      COMPLETE
Adapter lineage         COMPLETE

RESULT
TRUST REQUIREMENTS SATISFIED
```

The run then prints:
- the adapter's lineage (base model, data, LoRA rank, rounds, aggregation,
  ε used per hospital, adapter history, evidence verdicts);
- inference (`ADAPTER USABLE`);
- the export decision (`EXPORT DENIED`);
- timings: plain PyTorch against each stage of the confidential run.

## Try breaking it

`attack.py` attacks the finished run for real:

| Attack | Boundary | Refusal |
|---|---|---|
| train outside the approved workload (another image) | the key broker checks the attestation | ENC2002 |
| different training code, LoRA rank or plan | the TrainingSpecId binds them, so the broker refuses | ENC2002 |
| another model version, or a tampered sealed model | the sealed model must be the committed weights | ENC2501 / ENC2502 |
| a different tensor layout | the worker checks the layout digest | refused |
| an unauthorized dataset | the worker checks the dataset digest | refused |
| a sharp cut to the DP noise | the ledger charges the noise actually used | ENC2201 |
| a slight cut to the DP noise | each hospital checks the spec | ENC2102 |
| run without the approved plan | each hospital checks the PlanId | ENC2102 |
| lower the threshold to one party | the compiler refuses | ENC2106 |
| restore an older checkpoint (roll privacy back) | resume matches the privacy ledgers | ENC2502 |
| resume under another policy, or another project's checkpoint | resume checks the bindings | ENC2501 / ENC2502 |
| roll the privacy ledger back | resume: the ledger must extend the checkpoint | ENC2202 |
| modify the adapter after training | the sealed adapter's digest is in the signed record | ENC2502 |
| export the adapter publicly | the adapter inherits every parent's policy | EXPORT DENIED |

`python/tests/test_finetune.py` covers the same attacks, plus budget
exhaustion (training stops, and the denied round charges nothing) and a
tampered adapter record (the trust report fails).

## What Encompute guarantees

- The base model's key reaches only a workload attesting to the approved
  training spec: this code, this configuration, this plan, this image.
- A dataset is used only if it is the committed one. The control plane
  never receives samples, only digests.
- No individual update leaves a hospital except as a masked secure-
  aggregation contribution. Only the noised sum is released.
- Every release is charged to each hospital's budget. When the next round
  would exceed it, training stops.
- Checkpoints and adapters are sealed. Resuming refuses stale, foreign or
  rolled-back state.
- The adapter's lineage is recorded, and export follows every parent's
  policy.

## What Encompute does NOT guarantee

- **PyTorch is not encrypted.** It runs in plaintext inside the attested
  workload. Confidentiality of the model and the data in use rests on the
  TEE. Here the TEE is mock attestation, which protects nothing.
- **Privacy here is organization-level, not patient-level.** Each
  hospital's whole update is clipped, so the budget bounds what the adapter
  reveals about one hospital's contribution. The program declares the unit
  as `organization`, so no stronger claim is made. Patient-level DP-SGD is
  [example 16](../16_patient_private_lora/).
- **Verified training means attested workloads.** No execution proof covers
  general training, so `verification="required"` requires attestation. The
  plan says so.
- **All parties run on one machine here,** in separate directories and
  processes. In a deployment each runs on its own; the checks are the same.
- The adapter's quality is not the point: the model and data are tiny and
  synthetic.

## Relevant source modules

- `python/encompute/torch/`: LoRA, the canonical tensor format, the
  attested worker, the orchestrator and inference.
- `crates/encompute-training`: training specs, sealed assets, checkpoints,
  adapter records, export control.
- `crates/encompute-trust/src/lineage.rs`, and the report's Training row.
- Design notes: `docs/adr/0016-confidential-fine-tuning.md`.
