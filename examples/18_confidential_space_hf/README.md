# 18 — A Hugging Face training step in Google Confidential Space

## What this demonstrates

The training path of example 17 (Transformers, PEFT LoRA, patient-level
DP-SGD) runs inside a hardware-attested workload. Real protected assets are
released to it only after attestation.

| | LOCAL DEVELOPMENT (`--local`) | REAL CONFIDENTIAL SPACE (`--gcp-project`) |
|---|---|---|
| Where the worker runs | this machine (or the image, with `job.py container`) | a production Confidential Space VM, Intel TDX |
| Attestation token | a simulated launcher, signed with a test key | Google's attestation service |
| Broker | production mode: wrapped keys, no mock evidence, JWKS verification | the same |
| What it proves | the orchestration, the checks and every refusal | also the hardware and Google's signature |

The run:

1. **Prepare.** ModelCo imports a Transformers model (a tiny local BERT)
   into a sealed package. Two hospitals tokenize their notes, keeping each
   note's patient. The run is planned for Intel TDX on Confidential Space,
   and its attestation policy fixes:
   - the image digest and the training spec;
   - no debugging, a supported TCB, no mock evidence.

   A production broker receives the model, dataset, adapter and output keys,
   wrapped under a key-encryption key that stays with ModelCo. Each
   participant gets a **job descriptor** with public commitments only.
2. **Attest.** Each worker creates a session identity in memory and
   attests. The token binds the session, the training spec and the
   broker's fresh challenge. The broker verifies the token and releases the
   keys sealed to that session.
3. **Train.** The worker fetches the ciphertexts and opens them. It checks
   the model's weights and package, the dataset's digest, patient grouping
   and tokenization, and the adapter layout. It then runs one DP-SGD step
   with per-patient clipping: the same code as example 17.
4. **Seal.** It seals its contribution under a key only attested workloads
   receive, and signs evidence with the attested session key. The evidence
   binds the run, spec, plan, participant, round, model package, dataset,
   layout, image, attestation, and commitments to the output.
5. **Verify.** Anyone can verify from outside, with public evidence only:
   the attestation record, the evidence, the training policy and the
   JWKS. The trust report shows Workload ATTESTED and Training VERIFIED.

The trust report's overall result stays "not satisfied" until the
aggregation step runs: combining the sealed contributions across machines
is the next milestone. This example reports **TRAINING STEP VERIFIED**.

## Run it

```sh
pip install 'encompute[huggingface]'
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/18_confidential_space_hf/run.sh --local
# the built image, locally (needs docker):
docker build --target rehearsal -f deploy/confidential-space-training/Dockerfile \
  -t encompute-training:approved .
python examples/18_confidential_space_hf/job.py container /tmp/cs
# real Confidential Space (see deploy/confidential-space-training/README.md):
examples/18_confidential_space_hf/run.sh --gcp-project PROJECT --region us-central1 \
  --broker-url http://10.128.0.5:8760 approved
```

## Expected output (local)

```text
LOCAL REHEARSAL: SIMULATED CONFIDENTIAL SPACE LAUNCHER, TEST SIGNING KEY
CONFIDENTIAL TRAINING JOB
Attester                Google Confidential Space launcher
Attestation             VERIFIED BY THE BROKER
Model key               RELEASED TO ATTESTED SESSION
Dataset key             RELEASED TO ATTESTED SESSION
Per-patient clipping    ACTIVE (vectorized per-example gradients)
Training                COMPLETE
Output                  SEALED (contribution-hospital-a-r1, 4870 bytes)
Evidence                SIGNED BY THE ATTESTED SESSION
...
CONFIDENTIAL SPACE TRAINING (LOCAL REHEARSAL)
Provider                Google Confidential Space (SIMULATED)
Platform                Intel TDX (SIMULATED)
Debug mode              DISABLED
Attestation             VERIFIED
Privacy unit            patient
Output                  SEALED (hospital-a, hospital-b)
Evidence                VERIFIED
Raw model exposure      NONE DETECTED
Raw dataset exposure    NONE DETECTED
RESULT
TRAINING STEP VERIFIED
```

In the cloud, the summary says `HARDWARE ATTESTATION` and `GOOGLE
CONFIDENTIAL SPACE` instead.

## Try breaking it

| Attack | Boundary | Result |
|---|---|---|
| a modified image on genuine TDX | the broker: the attestation is valid, the image is not approved | KEY RELEASE DENIED |
| the approved image on a debug VM | the broker: debug never receives keys | KEY RELEASE DENIED |
| another LoRA rank (a new training spec) | the broker: keys are bound to the approved spec | KEY RELEASE DENIED |
| a weakened privacy configuration in the descriptor | the worker: the descriptor must be the approved spec | TRAINING SPEC MISMATCH |
| another model's ciphertext | the worker: authenticated decryption, digests | ASSET MISMATCH |
| hospital B's dataset in A's job | the worker: the dataset is bound to its participant | ASSET / DATASET ASSET MISMATCH |
| a replayed attestation token | the broker: challenges are single-use | refused |

`python/tests/test_confidential_job.py` also checks:
- mock evidence gets no production key;
- a substituted model package is refused;
- a second output for one round is flagged as a replay;
- no model weights, patient tokens, gradient values or asset keys appear
  in anything the operator can see (canary scan).

## What Encompute guarantees

- Model, dataset and output keys reach only a workload attesting to the
  approved image, on approved hardware, without debugging, for the
  approved training spec. They are sealed to that workload's in-memory
  session.
- The worker trains only on the committed model, dataset, tokenization and
  grouping, with the committed privacy settings. Per-patient clipping stays
  on.
- The output leaves only sealed, bound by signed evidence to its spec,
  participant, round, assets and attestation.
- A verifier needs no asset and no key.

## What Encompute does NOT guarantee

- **The hardware and Google are trusted.** The attestation proves which
  code ran where; it does not prove TDX or Google's infrastructure have no
  flaws.
- **The broker is ModelCo's.** In this demo one broker holds both
  hospitals' dataset keys. In a deployment each hospital runs its own, with
  its own policy.
- **Each session acts for one participant.** The attestation is scoped to
  it, so another participant's dataset and output keys are never released
  to it. But the demo's single broker is ModelCo's: in a multi-party
  deployment each hospital runs its own broker for its own dataset key.
- **Privacy is charged at release.** A sealed output releases nothing.
  The noised aggregate (the next milestone, with an attested aggregator
  that takes one output per participant and round) is what the ledgers
  charge.
- **The local rehearsal proves no hardware.** Its tokens are signed with a
  test key. The broker trusts that key only because it is given the
  matching JWKS.
- **The gradient path can differ by platform.** On one Linux ARM64 build of
  PyTorch, the vectorized gradients disagreed with the reference, so the
  worker used the one-patient-at-a-time path. It is slower, with the same
  privacy.

## Relevant source modules

- `python/encompute/torch/cs_worker.py`: the job worker inside the TEE.
- `python/encompute/torch/job.py`: preparing jobs, the local rehearsal and
  verification.
- `crates/encompute-training/src/worker.rs`: signed worker evidence.
- `crates/encompute-trust/src/report.rs`: the Training row's worker checks.
- `crates/encompute-cli/src/launcher_sim.rs`: the development-only
  simulated launcher.
- `deploy/confidential-space-training/`: the image and GCP deployment.
- Design notes: `docs/adr/0019-confidential-space-training.md`.
