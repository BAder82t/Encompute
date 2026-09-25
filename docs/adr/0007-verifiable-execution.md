# ADR-007 — Verifiable execution: receipts before proofs

Status: **Accepted** (2026-09-25)

## Context

Encompute keeps inputs secret from the evaluator, but a client cannot tell
what the evaluator did. The goal is: *no valid execution proof, no trusted
result*. Proof systems for FHE execution are young; the statement they must
prove has to be fixed first, and fixed in a form that does not change when
the proof backend arrives.

## Decision

1. **Receipts precede proofs.** 0.4 V1 adds `ExecutionReceiptV1`: what the
   evaluator claims it executed, bound to the execution spec, the key, the
   exact request and response bytes, and the evaluator's identity, signed
   by the evaluator. Its `evidence` is `VerificationEvidence::None`. A later
   `ExecutionProof` (ZK, FHE verification, attestation) attaches to the same
   receipt without changing its statement. Nothing in V1 is called a proof.
2. **Reuse existing identities.** `program_id`, `parameter_set_id` and
   `key_id` are the IDs envelopes already carry. `plan_id` is SHA-256 of the
   artifact's `plan.json`, the same convention. `ExecutionSpec` adds plan
   kind and version, semantics, scheme, backend and backend version;
   `verification.json` in the artifact (format 4) records the spec for the
   target backend.
3. **Canonicalization.** Everything hashed or signed is canonical JSON:
   object keys sorted by UTF-8 bytes, no whitespace, serde_json string
   escaping, integers only (floats, NaN and infinities refused). For such
   values this equals RFC 8785 (JCS). Key order is imposed by our writer,
   not by `serde_json::Map`, so crate features cannot change it.
4. **Hash and domain separation.** SHA-256 with a distinct domain per object:
   `SHA256(domain || 0x00 || bytes)` with `encompute.execution-spec.v1`,
   `encompute.execution-request.v1`, `encompute.execution-output.v1`,
   `encompute.execution-receipt.v1`, `encompute.evaluator.v1`. The request
   and output commitments hash the exact envelope bytes, never decrypted or
   re-encoded data.
5. **Evaluator signing.** Ed25519 (`ed25519-dalek`, strict verification).
   `evaluator_id = SHA256(encompute.evaluator.v1 || 0x00 || public key)`.
   The signing key is unrelated to every FHE key; the evaluator still never
   holds a decryption key. `encompute-evaluator serve --identity FILE` keeps
   it; clients pin it on first use (`evaluator.pub` in the key directory)
   or take `--trust-evaluator`.
6. **Receipts are verified before decryption.** `ClientSession::
   decrypt_verified` returns a `VerifiedReceipt` only `verify_receipt` can
   build. Local runs and `run --remote` both go through it; the lower-level
   `decrypt` remains.
7. **Proof hook.** `ExecutionObserver` sees each step of an exact plan
   (index, instruction with its public constants, registers), never
   ciphertexts or plaintext. `VerificationBackend` fixes the prover
   interface; `NoProofBackend` never produces evidence.

## Why a signature is not a correctness proof

A signature shows which evaluator made a statement, not that the statement
is true. An evaluator can sign a receipt for a result it fabricated. The
receipt makes that lie attributable and bound to exact bytes; only an
execution proof can rule it out. The CLI prints `RECEIPT VERIFIED` and
`EXECUTION PROOF NOT PRESENT`, never "execution verified".

## Why the exact plan is the first proof target

Exact plans are straight-line programs over integers and Booleans with
exact semantics: every step has one correct result, so a transcript is a
clean statement/witness pair. CKKS results are approximate and carry noise,
which makes "correct" a tolerance, not an equality. Receipts cover both
schemes now; instruction-level observation starts with exact plans.

## Evidence

`crates/encompute-verification/tests/receipts.rs` (canonical form, stable
IDs, every field tampered, cross-execution and replay refused, malformed
receipts), `crates/encompute-runtime/tests/receipts.rs` (CKKS and exact,
local and remote), `crates/encompute-cli/tests/cli.rs`
(`run --remote`, `verify`, identity pinning).
