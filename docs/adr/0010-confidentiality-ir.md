# ADR-010 — Confidentiality IR: parties, assets and policies

Status: **Accepted** (2026-09-25)

## Context

Encompute knew "this value is secret". Multi-party confidential AI needs
more: who owns a value, who may learn it, what it may be used for, how it
may be released, and what may be derived from it: for raw data and for
gradients, embeddings, models and outputs alike. This ADR adds those
*requirements* to the IR. It adds no mechanism: nothing here chooses FHE,
MPC, secure aggregation or a TEE, and nothing changes how a program runs.

## Decision

1. **Declarations live in the IR**, so they survive tracing and are part of
   the program text and ID:
   ```text
   program step precision 0.01 purpose "disease-training"
   party "hospital-a" "Hospital A"
   asset "patients" dataset owners ["hospital-a"] readers ["hospital-a"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator"]]
   %0 = input "x" [-1.0, 1.0] asset "patients" : secret vector<4>
   derive %3 gradient aggregate_only
   output "gradient" = %3                  # sealed (default)
   output "score" = %4 to "hospital-a"     # revealed to a party
   output "count" = %5 public
   ```
   They are declarations and annotations, not IR operations: CKKS and exact
   lowering, transcripts and proofs are unchanged.
2. **Parties** are authorization principals (`hospital-a`), not hosts.
   **Assets** have a kind (dataset, model, gradient, embedding, …; descriptive
   only) and a policy: owners, readers, purposes, release, and derivation
   permissions. Owners are not readers unless listed: owning a model does
   not mean anyone else may see it, and ownership is not visibility.
3. **Release levels**, most to least restrictive: `never` (nobody),
   `owner_only`, `allowed_parties` (readers), `aggregate_only` (only as part
   of an aggregate, to readers), `public`.
4. **Join.** A computed value's policy is the join of its operands':
   owners union (everyone with a stake); audience (who may learn it)
   intersection; purposes intersection; release the most restrictive;
   derivation permissions the kinds every source allows, at the most
   restrictive release, to the recipients every source names. Public data
   is the identity. The result is at least as restrictive as every input,
   so neither of two owners gains visibility into the other's asset.
5. **Weakening only by permitted derivation.** `derive %N KIND RELEASE`
   may restrict freely; it may weaken (e.g. a gradient of `never` data
   becoming `aggregate_only`) only as far as every source asset's owners
   permit for that kind (`derive [gradient aggregate_only to [...]]`), and
   only to the parties they name. There is no other declassification.
6. **Checks** at compile time (the compiler runs them before lowering):
   ENC1901 confidential value to a public output; ENC1902 revealed to a
   party outside its audience; ENC1903 purpose not allowed by an input
   asset; ENC1904 derivation not permitted; ENC1905 aggregate-only value
   revealed without an aggregation boundary; ENC1906 malformed
   declarations (unknown party or asset, unbound secret input, …). Outputs
   are sealed (handed on encrypted, revealed to nobody here) unless
   declared otherwise.
7. **Identity.** `PolicyId = SHA256("encompute.confidentiality-policy.v1"
   || 0x00 || canonical declarations)` (`encpolicy1:`). It is part of the
   `ExecutionSpec` (only when declarations exist, so other specs are
   unchanged), so receipts and proofs bind the policy an execution ran
   under. Asset-definition IDs hash the program ID, node and policy;
   runtime instances (checkpoints) will need instance IDs later.
8. **Artifacts** (format 5) carry `policy.json`: declarations, policy ID,
   each asset's derived policy, flows, warnings. `encompute privacy
   explain` and `privacy graph --format dot` show the graph.

## Consequences

- A policy is a statement of what must be true, checked statically. Runtime
  enforcement (policy-gated key release, attestation, secure aggregation)
  comes later and must satisfy these policies; the planner will choose the
  mechanism.
- `verify` shows the policy binding: which policy the execution claims. It
  does not prove the policy was enforced.
- Programs without declarations behave exactly as before.
- Kinds are the program's claims. A derivation permission ("gradients may
  be released in aggregate") is consent for values the program labels that
  kind, so the checker stops the obvious abuses: a raw input cannot be
  weakened, a value that already has a kind cannot be relabelled, and a
  public permission cannot also name recipients. It cannot tell whether a
  computation really is a gradient. Owners must review and approve the
  program itself; binding that approval to the program ID is part of
  policy-gated key release.

## Evidence

`crates/encompute-analysis/tests/confidentiality.rs` (the training
scenario, lattice properties, every error), `crates/encompute-runtime/tests/
policy.rs` (policy IDs, spec binding, artifact round trip and tampering,
receipts), `python/tests/test_confidentiality.py`,
`crates/encompute-cli/tests/cli.rs` (`privacy explain`/`graph`),
`examples/confidential_training.py`.
