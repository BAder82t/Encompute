# ADR-016 — Confidential fine-tuning with PyTorch and LoRA

Status: **Accepted** (2026-09-26)

## Context

The collaboration flow worked end to end, with fixed update vectors:
policies, the plan, attested key release, secure aggregation, differential
privacy and the trust report. The missing step was a real learned update.
Encompute should protect a real PyTorch fine-tuning run without replacing
PyTorch.

## Decision

1. **The boundary.**
   - PyTorch does the computation: forward, backward, autograd, optimizers
     and kernels.
   - Encompute controls who may hold what, and proves it: ownership, policy,
     placement, attestation, key release, gradient release, privacy,
     lineage and verification.
   - PyTorch runs in plaintext inside the attested workload. We never say it
     is encrypted.
2. **LoRA first.**
   - Base weights are frozen; low-rank adapters on chosen `nn.Linear`
     modules train. This keeps updates, checkpoints and lineage small.
   - A canonical **parameter layout** (module, parameter, shape, offset,
     length, dtype) fixes the flattening order. Its digest is bound, so a
     participant with another layout is refused before aggregation.
3. **The training spec.**
   - `TrainingSpec` binds:
     - the project and purpose;
     - the plan, program and policies;
     - the aggregation spec (threshold, codec, noise, participants);
     - the base model's commitment: factory, arguments and weights digest;
     - each dataset's digest;
     - the training code's digest and the layout digest;
     - the LoRA and optimizer configuration and the round count.
   - Its ID is `enctrain1:`. Changing any of these changes it.
   - A `TrainingRunId` identifies one execution.
4. **No pickles.**
   - A worker rebuilds the model from a factory in the bound code, then
     loads the weights from a canonical tensor format and checks their
     digest.
   - A pickled model would let its owner run code inside a hospital's
     worker, next to the data.
5. **Attested workers and keys.**
   - Each participant's worker attests to the model owner's key broker. The
     attestation binds the TrainingSpecId (as its execution spec), the
     policy, the code digest (as its artifact) and the participant's
     identity key.
   - The broker releases the model key only under the training attestation
     policy. The keys for sealed checkpoints and adapters are released the
     same way.
6. **Updates.**
   - A worker trains locally, then clips its whole update to `update_clip`
     and scales it into the codec's range.
   - It passes the update only to `aggregate join --values -` on stdin: no
     file, no other channel.
   - The existing secure aggregation, DP, ledgers and receipts do the rest.
     There is no training-specific aggregation or accounting.
7. **Privacy unit: organization.**
   - The enforced bound is one hospital's clipped update, so the program
     declares `privacy unit "organization"`, and the accountant charges
     twice the per-contribution sensitivity.
   - Patient-level DP needs per-example clipping. DP-SGD provides it, as a
     separate mode ([ADR-017](0017-patient-level-dp.md)).
8. **Immutable adapters and sealed checkpoints.**
   - Each round creates `adapter-N`, sealed, with a coordinator-signed
     `AdapterRecord` naming its previous adapter, aggregation receipt, base
     model and datasets.
   - Each round's sealed checkpoint binds the project, spec, run, policies
     and each ledger's position.
   - Resume refuses:
     - another project, spec or policy;
     - a tampered checkpoint;
     - a checkpoint whose privacy state is behind the authoritative ledgers
       (so restoring it cannot restore spent budget);
     - a ledger rolled back behind it.
9. **Trust and export.**
   - The trust graph gains Training and Adapter nodes. The report's
     Training row checks:
     - the spec belongs to its plan and aggregation;
     - participants' keys and parent assets match;
     - each adapter is signed by a trusted coordinator, comes from a round
       of its spec, and extends an earlier adapter of its run.
   - `encompute lineage` explains an adapter.
   - `encompute export` is permitted only if every parent permits a public
     adapter (`derive [adapter public to []]`), else EXPORT DENIED.
10. **Interfaces.**
    - `Project.finetune(model=, data=, method="lora", privacy=,
      verification=)`, with `encompute.torch.wrap_model`, `private_dataset`
      and `LoRAConfig`.
    - `FineTuneResult` provides `summary`, `lineage`, `infer`, `resume` and
      `export_adapter`.
    - `encompute train project.py`.
    - Errors ENC2501 (training spec), ENC2502 (checkpoint or sealed
      artifact) and ENC2503 (export denied).

## Consequences and limits

- One call runs a real, verified, multi-party fine-tuning. The plan decides
  the placement, and training never falls back to ordinary execution when
  the plan cannot be satisfied.
- Training correctness has no execution proof. `verification="required"`
  means attested workloads.
- Development mode uses mock attestation, labelled "no hardware
  confidentiality". Real Confidential Space workers need a GCP project.
- On one machine, parties run as separate processes and directories. The
  orchestrator plays the model owner, which holds the adapter.
- Measured baselines (plain PyTorch against attestation, rounds,
  checkpoints and trust graph) are printed with every run. Nothing is
  optimized yet.
- Assurance: INV-120 to INV-127 ([assurance.md](../assurance.md)), and
  `examples/15_confidential_lora`.

## Addendum: release hardening

1. **One commit point per round.**
   - The adapter and checkpoint are written provisionally (atomically,
     into `pending/`).
   - The round is accepted when its coordinator-signed adapter record
     enters the trust bundle; only then do the files move into place.
   - `recover` finalizes rounds that reached the commit point and discards
     the rest.
   - A round that was released but not accepted is *lost*: its privacy
     stays spent in the ledgers. Resume accepts ledger entries after the
     last accepted checkpoint only if they belong to declared lost rounds.
     An older checkpoint whose later rounds were accepted is still stale.
   - Resume also checks the run ID, and refuses once any parent asset has
     been revoked.
2. **Rust owns every format.**
   - The training spec, checkpoint header, adapter record, sealed-asset
     header, adapter layout and canonical tensor file are versioned and
     validated in `encompute-training`. Unknown versions are refused.
   - Python only orchestrates. The contract fixtures
     (`crates/encompute-training/tests/fixtures`) are checked by the Rust
     tests and, through the bindings, by `test_training_contract.py`.
3. **Commitments.**
   - The dataset digest covers every sample and label *in order*:
     reordering a dataset is a different dataset.
   - The model commitment is the factory, its arguments and the weights
     digest.
   - The layout digest covers every adapter parameter's module, name,
     shape, offset, length and dtype.
4. **Export.** Export is denied unless:
   - every parent permits public adapters;
   - no parent has been revoked;
   - the run's trust report is satisfied.
5. **Release gate.** Every pull request runs, with example 15 required:
   - the fine-tuning end-to-end tests;
   - the commitment matrix;
   - canary leakage over the whole run directory and all output;
   - crash and kill recovery at ten points: worker after training and
     after contributing; coordinator killed; orchestrator after release,
     after the adapter write, before and during the checkpoint write, and
     before and after the commit point; broker killed;
   - the contract tests.

   `scripts/release-check.sh` runs the supported path from a clean
   checkout. INV-128 and INV-129 record the crash and leakage guarantees.
6. **Still open.** One real Confidential Space training worker. It needs a
   GCP project, and the release check reports it as SKIPPED until then.
