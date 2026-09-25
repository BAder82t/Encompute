# ADR-011 — Attested confidential compute: policy-gated key release

Status: **Accepted** (2026-09-25)

## Context

ADR-010 lets a program state who owns each asset, who may learn what and
for which purpose, and binds that policy into the execution spec. It is a
requirement only: nothing stopped an operator from running a different
program on an owner's data. Owners need a reason to release an asset key to
a machine. The reason should be cryptographic: the machine proves, in
hardware, that it runs the exact approved Encompute artifact, under the
approved execution spec and policy, in an approved TEE, for a fresh session.

## Decision

1. **Provider-neutral attestation** (`encompute-attestation`, no FHE, no
   cloud SDK). A provider (`AttestationProvider`) verifies one kind of
   evidence (signature, and that it commits to the binding) and returns
   normalized `VerifiedWorkload` claims:
   - TEE kind (`IntelTdx`, `AmdSevSnp`, `AmdSev`, `NvidiaConfidentialGpu`,
     `Mock`, `Other`)
   - workload measurement and image digest
   - debug state
   - TCB status (`unknown < out_of_date < supported < current`)
   - evidence digest
   - issue and expiry times
   - optional GPU claims

   Nothing provider-specific leaves the provider. `VerifiedWorkload` carries
   `gpu: Option<VerifiedGpu>`, so CPU and GPU attestation can be composed
   later.

2. **The workload binding** is what evidence must commit to:
   ```text
   WorkloadBinding = { ExecutionSpecId, PolicyId, artifact digest,
                       evaluator receipt key, session key, challenge nonce }
   nonce in the evidence = SHA256("encompute.workload-binding.v1" || 0 || canonical JSON)
   ```
   - The artifact digest is the SHA-256 of `manifest.json`.
   - The session key is an X25519 HPKE key generated inside the TEE.
   - A host that swaps any field (its own session key or evaluator key,
     another spec) no longer matches the evidence.
   - The session ID is `SHA256("encompute.workload-session.v1" || 0 ||
     evaluator key || session key)`. It is stable across the brokers a
     session talks to.

3. **The attestation policy is separate from the confidentiality policy.**
   - The confidentiality policy says who owns data and how it may be
     released.
   - `AttestationPolicy` says where and what may run. It fixes the
     execution spec, `PolicyId` and artifact, and lists the allowed TEEs,
     the allowed image digests, the debug setting (forbidden by default),
     the minimum TCB, whether GPU attestation is required, and the maximum
     evidence age.
   - `allow_development` is false by default, and a policy naming the mock
     TEE without it is invalid.
   - `encompute attest policy` writes a policy from an artifact.

4. **Freshness.**
   - The broker issues a random 32-byte, single-use challenge that lives
     for 5 minutes, and the binding includes it.
   - A challenge is consumed on first presentation, whatever the outcome,
     so replayed evidence finds none.
   - Evidence must be issued after the challenge, must be younger than the
     policy's maximum age, and must not have expired.
   - TLS channel binding is not used. Grants are sealed to the attested
     session key, so an intercepted grant is useless.

5. **Key broker** (`encompute-keybroker`).
   - It holds `ProtectedSecret`s: an asset key per version, under an
     `AttestationPolicy`.
   - Operations: `challenge`, `verify_attestation` (opens an attested
     session for up to 10 minutes), `release_key` (per asset, rechecks the
     policy), `rotate_key` and `revoke`.
   - A grant (`EncryptedKeyGrant`) is the key sealed with HPKE (RFC 9180,
     base mode, X25519-HKDF-SHA256, ChaCha20-Poly1305) to the session key.
     The header is authenticated as associated data: asset, key version,
     `PolicyId`, `ExecutionSpecId`, session ID, binding hash, attestation
     digest and expiry.
   - There is no path that returns a key without attestation, and no HTTP
     endpoint that manages keys.
   - A production broker refuses development evidence regardless of
     policy.
   - A broker's audience is always its own ID. Its HTTP server allows 60
     requests per source address per minute, and it keeps at most 4096 open
     challenges and sessions.
   - The broker never sees asset data.

6. **Receipts bind the attested session.**
   - Receipt version 3 adds an optional `attestation` field with the
     attestation record ID and the workload session ID. The record itself
     (the evidence) is kept beside the receipts and served at
     `/v1/attestation`.
   - The evaluator refuses a record that binds another signing key.
   - A verifier checks the chain: the receipt names the record and its
     session; the record binds the receipt's signing key and execution
     spec; the evidence verifies (as history, without the expiry check);
     and the workload satisfies the policy.
   - The chain is: hardware attestation → workload measurement → evaluator
     signing key → receipt → execution proof.

7. **Providers.**
   - **Google Confidential Space** (`gcp-confidential-space`) is the first
     real provider.
     - The workload requests a custom OIDC token from the launcher
       (`POST /v1/token` on `/run/container_launcher/teeserver.sock`), with
       the broker ID as the audience and the binding hash as the nonce.
     - The broker verifies the token against Google's published JWKS: RS256
       only, key selected by `kid`, issuer
       `https://confidentialcomputing.googleapis.com`, its own audience, and
       expiry.
     - It requires `swname = CONFIDENTIAL_SPACE`, Secure Boot and a
       container image digest.
     - It maps `hwmodel` to a TEE kind, `dbgstat` to the debug state, and
       `support_attributes` to the TCB status: STABLE+LATEST is current,
       STABLE is supported, USABLE is out of date.
   - **Mock** (`mock`) is for development and CI.
     - An Ed25519 "hardware root" signs the claims.
     - It is always `DevelopmentOnly` and `TeeKind::Mock`.
     - Production policies and brokers refuse it.

## Consequences

- An asset key reaches only a workload that is running the approved image,
  under the approved execution spec and policy, and in an approved TEE with
  debugging off. The key is sealed to the workload's session. The cloud
  operator can relay requests but cannot open a grant.
- Trust moves to the TEE vendor and the attestation service (for
  Confidential Space: Google's attestation verifier and the launcher). A
  compromised TEE, or a wrong measurement from the attestation service,
  defeats this layer.
- The image digest is the measurement. Owners must review what the approved
  image does. Approval is by digest: every rebuild is a new policy.
- Kinds and policies are still the program's claims (ADR-010). Attestation
  proves which program runs, not that its policy declarations are honest.
- In this version, the workload tool (`encompute workload keys`) receives
  and opens keys, then exits. Using them to decrypt asset-encrypted inputs
  inside the evaluator is the next step. Evaluation itself is unchanged: it
  is FHE, or mock in the Confidential Space demo.
- The broker stores keys in a local file (mode 0600). A production broker
  would front a KMS or HSM. The interface does not change.
- `ReexecutionBackend` and receipts are unchanged. Attestation adds who ran
  the evaluation. It does not replace proofs of what the evaluation
  computed.

## Evidence

- `crates/encompute-attestation/tests/attestation.rs` covers the mock and
  Confidential Space providers, with tokens signed by a test key:
  - wrong audience, issuer, nonce, swname or Secure Boot state; a missing
    image;
  - a debug image, a disallowed TEE, a shielded VM, an experimental image;
  - expiry; an unknown key; a key substituted under Google's `kid`; a
    tampered payload; `alg: none` and HS256;
  - GPU claims;
  - binding substitution; freshness; history records.
- `crates/encompute-keybroker/tests/release.rs` covers every case in the
  milestone's list. Each receives no key:
  - wrong image, ExecutionSpecID or PolicyID
  - debug workload
  - stale or expired evidence; an expired challenge; a replayed nonce
  - wrong evaluator or session key
  - unacceptable TCB
  - tampered evidence; an unknown provider; a rogue root
  - a revoked key

  It also runs the two-party demo over HTTP: Hospital and ModelCo each run a
  broker, the approved workload receives both keys, and a modified image,
  another spec or a debug build receives none.
- `crates/encompute-runtime/tests/attested.rs`: receipts from an attested
  evaluator verify against the record and policy. Another record, another
  image or a rogue root fails, and so do an unattested evaluator's receipts.
- `crates/encompute-cli/tests/cli.rs` (`attestation_and_key_release`).
- `deploy/confidential-space/`: the image, entrypoint and deploy script for
  the real Confidential Space run.
