# ADR-014 — Trust graph: one verifiable record of a collaboration

Status: **Accepted** (2026-09-26)

## Context

By now each Encompute mechanism leaves its own evidence:

- confidentiality policies (ADR-010);
- attestation records and key grants (ADR-011);
- aggregation specs and receipts (ADR-012);
- privacy receipts and ledgers (ADR-013);
- execution receipts (ADR-007).

A data owner, auditor or regulator asks one question across all of it: can I
trust what happened to my data? Answering it means joining that evidence up.
Which program used which asset, and did its owner approve it? Which
aggregates were derived from it? Was it revoked, and what was derived after
that? Did the privacy spend stay within budget?

ADR-010 also left a gap. A program's kinds and derivations are its own
claims, so an owner has to approve the program itself, not only a policy.

## Decision

1. **One content-addressed graph** (`encompute-trust`).
   - **Nodes:** parties, assets, programs, policies, owner authorizations
     and revocations, aggregation specs and rounds, released aggregates,
     privacy releases, attestations and executions.
   - **Edges:** owns, uses, governed by, derived from, contributed,
     produced, charged to, released by, attested by, signed, authorizes,
     covers, revokes, and runs.
   - **Evidence:** the signed receipt, record or program text travels inside
     its node, so a bundle (`trust.json`) is checked offline.
   - **Bundle root:** `SHA256("encompute.trust-bundle.v1", canonical
     graph)`.
2. **Owners approve programs.**
   - An `Authorization` is an owner's Ed25519 signature over one program ID.
     It also names that program's policy ID, privacy policy ID and purpose,
     for one asset, with an optional expiry.
   - A `Revocation` withdraws an asset, or one authorization, from a given
     time on.
   - Every asset a program uses needs a valid authorization from each of its
     owners. An asset that is used but has no owner fails.
3. **The report trusts nothing the bundle says about itself.**
   - *Evidence decides the graph.* The report rebuilds the graph from the
     evidence alone:
     - owners, uses and governance come from the program text;
     - lineage, contributors and privacy releases come from the signed
       aggregation receipts;
     - execution and attestation links come from the execution receipts.
     The bundle's own edges, nodes and attributes are a cache. Any
     difference fails the report. The only exception is party keys, which
     are informational.
   - *Keys come from the verifier.* Signatures are checked only against
     `Anchors` the caller supplies out of band:
     - the consortium's party keys (`parties.json`);
     - trusted coordinator keys;
     - trusted evaluator keys. An evaluator whose attestation verifies
       needs no anchor.
     Evidence without an anchor is reported as *present, not checked*.
   - *Budgets come from the program.* A privacy release is compared with
     the ε and δ its asset *declares*, not the budget its receipt claims.
     A release of an undeclared asset, or with non-finite values, fails.
     Its signer must be a trusted coordinator, and for a round's release,
     that round's coordinator.
   - *Time comes from signatures.* A revocation is ordered against the
     round's `opened_at` from the signed aggregation receipt.
4. **The result is conservative.** Requirements are satisfied only when:
   - no row failed;
   - no row is unchecked;
   - a program is present;
   - every row the caller requires (`--require`) is present.

   An empty bundle is never satisfied. A revoked asset lists everything
   derived from it, to retrain or unlearn.
5. **CLI.** `encompute trust init | authorize | revoke | add | report |
   lineage | graph`. `aggregate serve --trust-bundle` records each finished
   round. `trust report` takes `--parties`, `--coordinator-key`,
   `--evaluator-key` and `--require`, and exits 1 unless the requirements
   are satisfied.
6. **Errors.**
   - ENC2301: evidence that is malformed or fails verification.
   - ENC2302: an authorization that is missing, invalid, expired or
     revoked.
   - ENC2303: an inconsistent graph.

## Consequences

- One command answers the owner's question, from evidence anyone can
  recheck. The answer is never better than the anchors supplied. Without
  keys obtained out of band, the report says so instead of trusting a
  bundle's self-description.
- The report checks what was recorded. A coordinator that never adds a
  round to the bundle leaves no trace. Owners still enforce budgets and
  ledgers at contribution time (ADR-013), and `--require` makes an absence
  explicit.
- Authorizations bind a program ID, so any program change needs fresh
  approvals, which is intended.
- The graph is the substrate for the planner: it records the parties,
  assets and policies that the planner will choose protections for.

## Assurance

INV-100 to INV-103 in [assurance.md](../assurance.md). Each finding of the
pre-merge review has a regression test in
`crates/encompute-runtime/tests/trust.rs`:

- self-referential keys;
- edges not derived from evidence;
- non-finite ε;
- the receipt's own budget used instead of the declared one;
- an unresolved signer;
- an empty bundle reported as satisfied;
- an unsigned timestamp.
