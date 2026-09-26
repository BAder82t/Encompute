# ADR-019 — Confidential training on Google Confidential Space

Status: **Accepted** (2026-09-26)

## Context

Fine-tuning ran real Hugging Face + PEFT training with patient-level
DP-SGD, but under development (mock) attestation. The existing Confidential
Space demo released only a test key to a mock evaluator. This milestone
connects the two: real protected model and dataset keys, released only to a
hardware-attested training worker.

## Decision

1. **A job, not a session.**
   - A confidential training job is one participant's training step. It
     is described by a job descriptor that carries public commitments
     only: the training spec, its IDs, the model package ID, the locations
     of the sealed assets, the broker and the output location.
   - The operator can edit the descriptor, but only to make the job fail:
     - the worker checks it against the spec it names;
     - the broker releases keys only for the approved spec.
2. **The worker (`encompute.torch.cs_worker`).**
   - It creates a session identity in memory, and attests once per broker
     through the Confidential Space launcher. The token binds the session
     keys, the training spec, the policy and the broker's challenge.
   - It receives the model, dataset, adapter and output keys sealed to
     that session. Keys and plaintext live only in memory.
   - It opens the assets, checking every digest, and rebuilds the model as
     every worker does:
     - the package, the library versions, the layout;
     - the dataset's grouping and unit count.
   - It runs one step of the bound training code (DP-SGD per the spec),
     seals the contribution under the participant's output key, and signs
     evidence with the attested key.
3. **Evidence (`WorkerEvidence`).**
   - Signed by the key the attestation record binds.
   - It names the run, spec, plan, policies, participant, round, model
     (package and weights digest), dataset (digest), layout, measured
     image, attestation record and session. It commits to the sealed
     output and, with a salt inside the sealed payload, to the plaintext
     step.
   - Verification needs no asset or key:
     - the signature;
     - the bindings to the spec and the record;
     - the record itself, against the spec's attestation policy and the
       provider's roots (Google's JWKS).
   - The trust graph holds it as a Worker node linked to its spec,
     attestation, model and dataset. The report's Training row verifies it
     and refuses two outputs for one participant and round.
4. **Production mode only.**
   - Jobs are planned for Intel TDX on Confidential Space. The policies
     are production policies: the image digest, no debugging, a supported
     TCB, no mock evidence.
   - The broker runs in production mode, with keys wrapped under a
     key-encryption key. The development file store is refused.
5. **A session acts for one participant.**
   - A job attests to the training spec scoped to its participant: an
     execution ID derived from the spec ID and the participant.
   - Each participant's policy releases:
     - the model and adapter, to that participant's jobs;
     - its dataset and output keys, only to them.
   - So one session never receives two participants' keys, and the
     evidence's participant is attested, not merely claimed. The report
     checks each record against the participant-scoped policy.
6. **One attestation per broker.** A workload attests once to each broker
   and receives all its grants in that session, instead of one attestation
   per key. The broker's per-address request limit is configurable; the
   default is still 60 a minute.
7. **Local rehearsal.**
   - A development-only launcher simulator (`encompute attest
     simulate-launcher`) serves Confidential Space tokens signed with a
     test key.
   - With the matching test JWKS, a production broker verifies every claim
     as in the cloud. Only the hardware and Google's signature are
     simulated.
   - `job.py container` runs the real image the same way. CI does both,
     with an approved and a tampered image.
8. **Deployment.**
   - `deploy/confidential-space-training` builds the pinned image on Cloud
     Build and resolves its digest.
   - It stages ciphertext in an input bucket and runs one TDX VM per
     participant. The launch policy lets the operator override only
     `JOB_URL`.
   - Outputs go to a separate bucket. The worker's service account may
     read inputs, write outputs, and attest; nothing else.
   - The production image holds the worker and its libraries only. A
     separate `rehearsal` target adds the CLI (for the simulated launcher)
     and is never deployed.
   - `approved`, `tampered` and `debug` variants; a manual live workflow;
     a release-check row that reports SKIPPED without GCP.
9. **Gradient-path probe tolerance.**
   - The probe that picks the vectorized path compares it with the
     reference at 1e-3 of the gradient's scale. That catches semantic
     failures, not kernel rounding.
   - On a Linux ARM64 PyTorch build it caught a 1.5% disagreement, and the
     worker used the reference path. Privacy never depends on it: clipping
     bounds whatever gradient is computed.

## Consequences and limits

- The training step is verified in isolation. Securely aggregating the
  sealed contributions across attested machines is the next milestone.
  Until then, the trust report's overall result is not satisfied, and the
  example reports "training step verified".
- **Where privacy is spent.** A sealed contribution releases nothing:
  privacy is charged when the aggregate is released with noise, by the
  ledgers. So an operator who reruns a participant's job for an extra round
  produces only another sealed output, which releases nothing by itself.
- **Evidence is submitted, not collected.** The report flags two outputs
  for one participant and round only when both are in the bundle. The
  aggregator (the next milestone) will accept exactly one attested output
  per participant and round.
- **The demo's broker is shared.** `deploy.sh` is a single-operator
  deployment: ModelCo's broker holds every owner's keys, under per-participant
  policies. In a multi-party deployment each hospital runs its own broker
  and protects its own dataset key there, so no other party can release it.
- The live run needs a GCP project. Until it runs, the cloud numbers in
  docs/benchmarks.md are pending.
- Assurance: INV-143 to INV-148, `examples/18_confidential_space_hf`.
