# ADR-012 — Multi-party secure aggregation

Status: **Accepted** (2026-09-25)

## Context

ADR-010 lets an asset be `release aggregate_only`: it may leave its owner
only as part of an aggregate over several parties. Until now that was a
compile-time requirement with no mechanism behind it. The compiler rejected
revealing such a value (ENC1905), and nothing could release the aggregate.
Several hospitals training one model need that mechanism: each contributes a
gradient, and the coordinator learns only the sum.

## Decision

1. **The aggregation boundary is declared in the IR**, and it is part of the
   policy and its `PolicyId`. The output must also name its recipient; the
   compiler checks it:
   ```text
   output "global_gradient" = %4 to "coordinator"
   aggregate "global_gradient" sum minimum 3 colluding 2 clip [-1.0, 1.0] scale 65536 modulus 32
   ```
   In Python this is `secure_aggregate(ga + gb + gc, to=coordinator,
   minimum=3, colluding=2, clip=(-1, 1), scale=65536, modulus_bits=32)`.
   `colluding` is required: the number of parties that may collude with the
   coordinator without learning another party's contribution. It is
   declared, never assumed.

2. **Lowering** (`encompute-analysis`) turns the declaration into an
   `AggregationBoundary`, or fails with ENC2106.
   - The output must be a sum of inputs, each used once.
   - Each input must be an asset with a single owner, and no party may own
     two of them.
   - `2 ≤ minimum ≤` the number of parties.
   - The contributions' release must allow an aggregate: `owner_only` and
     `never` fail with ENC1904.

   The aggregate gets a derived policy:
   - owners: the contributors;
   - purposes: the intersection of the contributions' purposes;
   - audience: the parties every contribution allows;
   - release: `allowed_parties`. It is never public unless every
     contribution is public.

   Revealing it to anyone outside the audience is ENC1902, and publishing it
   is ENC1901. An `aggregate_only` value outside a boundary is still ENC1905.

3. **Runtime enforcement.** An aggregation program never runs on one
   evaluator. That would put every party's contribution under one client's
   key. The evaluator refuses to load it, and a remote client refuses to send
   it (ENC1905). It runs only as secure aggregation (`encompute-secagg`).

4. **Protocol: Bonawitz et al., "Practical Secure Aggregation for
   Privacy-Preserving Machine Learning" (CCS 2017), active-adversary
   variant.** This is not new cryptography.
   - The five rounds are: advertise keys, share keys, masked input,
     consistency check and unmask.
   - Parties sign their messages with Ed25519 identity keys. The keys are
     fixed in the spec, which acts as the PKI.
   - Survivors sign the survivor set, and a party reveals shares only after
     at least t valid signatures on the same set.
   - A party never reveals both kinds of share for one party. Flower's
     SecAgg+ client does not check this; we do.
   - The primitives are X25519, a SHA-256 KDF bound to the round, the
     ChaCha20 keystream as the mask PRG, ChaCha20-Poly1305 share encryption,
     Shamir sharing over GF(2^8) (`vsss-rs`), and Ed25519.
   - The coordinator checks every reconstruction: a mask key against its
     advertised public key, and a self-mask seed against its commitment. A
     bad share aborts the round rather than producing a wrong aggregate.
   - The threshold is `t = max(minimum, ⌊(n + colluding)/2⌋ + 1)`, which
     keeps inputs private against a coordinator colluding with up to
     `colluding` parties. A bound the parties cannot meet (`t > n`, or
     `colluding ≥ n`) is ENC2106. Unanimity (`minimum = n`) tolerates n − 1
     colluders and no dropouts. `privacy explain` and `explain` show the
     threshold, the collusion bound and the dropout tolerance; receipts
     record them.
   - A security review found that the first version enforced only
     `t > n/2`. With n = 3 and t = 2, one colluding party let the coordinator
     split the survivor sets ({V, M} to one party, {W, M} to another) and
     collect both of V's secrets. The declared bound closes this; the test
     `collusion_bound_defeats_split_survivor_sets` covers it.
   - The implementation has Flower SecAgg+'s semantics (stages, clipping,
     quantization) but is not wire-compatible with it. It uses a complete
     graph. The SecAgg+ sparse graph is future work.

5. **Identities.**
   - The `AggregationSpec` (`encagg1:`) fixes the plan, the party identity
     keys, the protocol, the threshold, the optional training
     `ExecutionSpecId`, and an optional attestation policy. The plan fixes
     the program, `PolicyId`, participants, minimum, vector length, codec,
     function, recipient and derived policy.
   - Each party builds the spec from its own copy of the artifact and the
     consortium's `parties.json`. It joins only a round whose spec is
     identical; otherwise the error names the differing fields.
   - An `AggregationRound` (`encround1:`) is one execution: the spec ID, an
     increasing sequence number, a nonce and the coordinator key. The round ID
     enters every key derivation and signature, so nothing from one round
     works in another. Parties also refuse a round that is not newer than the
     last one they joined.

6. **Quantization is explicit.**
   - `FixedPointCodec` clips to `[clip_min, clip_max]`, then encodes
     `round((x − clip_min)·scale)`, which lies in `[0, levels]`.
   - The compiler refuses a codec whose sum over the parties could reach the
     modulus (ENC2105), and prints the bound.
   - Clipping, scale, modulus and rounding error appear in `privacy explain`,
     `explain`, the round manifest and the receipt. When an input's declared
     range exceeds the clip range, the compiler warns.
   - The aggregate is exactly `decode(Σ encode(xᵢ))`: within `n·0.5/scale`
     of the real sum for unclipped values. A mean divides by the actual
     contributor count.

7. **Outputs.**
   - The round produces an `AggregateAsset`: the values, the integer sum,
     the contributors, parent assets (contributors only) and the derived
     policy. It goes to the coordinator's process and is never served.
   - It also produces an `AggregationReceipt`, signed by the coordinator. The
     receipt holds:
     - the round, spec, `PolicyId`, training spec, codec, shape, function and
       protocol;
     - the eligible, advertised, contributing and dropped parties;
     - each contributor's signed commitment to its masked contribution;
     - the survivor set as signed by the parties;
     - attestation record IDs;
     - a commitment to the aggregate.
   - `verify_aggregation_receipt` checks all of it against the reader's own
     spec.

8. **Signed contribution metadata.** Before any protocol message, each
   party signs a `ContributionMetadata` with its identity key. It names the
   RoundID, its AssetID, PolicyID, training ExecutionSpecID, codec ID,
   vector length, a digest of its protocol keys, and its attestation record.
   The coordinator refuses a mismatch with ENC2102, naming the field. The
   receipt carries every contributor's metadata, and the verifier re-checks
   it. The aggregate asset gets an AssetID derived from the receipt, so it
   takes its place in the asset graph with the contributing assets as
   parents.

9. **Attested contributors (optional).** A spec may require an attestation
   policy (ADR-011). Each party's contribution key must then be the evaluator
   key bound by an attestation record that satisfies the policy. The
   coordinator checks the record, and the receipt lists record IDs. This is
   how "only the approved training workload may contribute" will be enforced.

10. **Key broker storage** (hardening from ADR-011). A `SecretStore` trait
   holds broker keys. `DevelopmentFileStore` stores plaintext and is refused
   by production brokers. `LocalKekStore` wraps each key with
   ChaCha20-Poly1305 under a KEK kept outside the state file, bound to
   broker, asset and version. `revoke` destroys the material of a revoked
   version rather than only flagging it. `rotate` re-wraps keys under
   another store (`encompute keys rewrap --new-kek`), for KEK rotation or a
   move to a KMS. A KMS, HSM, KMIP or vault store implements the same
   trait.

## Security

| Adversary | Protected? |
|---|---|
| Honest-but-curious coordinator | Yes: it sees masked vectors only. |
| Malicious coordinator (drops, forges, equivocates on survivors) | Yes: it cannot collect both kinds of share of an honest party. It can abort the round, or report a wrong aggregate (no output integrity). |
| Coordinator colluding with c parties | Yes, for c up to the declared `colluding` (the threshold enforces `t > (n + c)/2`). Beyond the declared bound, no. |
| Malicious participant | Cannot learn others' inputs. It can bias the aggregate (no input validation or poisoning defence) or abort by revealing bad shares; attestation (8) limits who may contribute. |
| Colluding participants (without the coordinator) | Learn nothing beyond the aggregate. |
| Participant dropout | Tolerated down to t survivors at every stage; below that the round aborts and nothing is released. |
| Replay attacker | Messages and contributions are bound to the round ID and signed; parties refuse rounds not newer than the last they joined (the CLI's required `--state`; library callers must persist it). |
| Cloud operator | Same as the coordinator, or as the network: messages are signed, and shares are encrypted end to end between parties. |

Secure aggregation hides individual contributions. It does **not** limit
what the aggregate reveals: with three hospitals, the sum and two gradients
give the third. That needs differential privacy (the next milestone). The
coordinator's aggregate is not verified to be correct, and a malicious
coordinator can release a wrong one. The receipt proves who contributed and
under what spec, not that the sum is right.

## Consequences

- `aggregate_only` now has a mechanism. `privacy explain` shows the policy,
  the mechanism and its status.
- Adding an `aggregate` declaration changes the `PolicyId`. Programs without
  one keep their IDs.
- The GF(2^8) Shamir sharing limits a round to 255 parties.

## Evidence

- `crates/encompute-analysis/tests/aggregation.rs`: lowering, the derived
  policy, invalid declarations and overflow.
- `crates/encompute-secagg/tests/protocol.rs`:
  - exact sums;
  - dropouts at every stage;
  - aborts below the threshold;
  - an equivocating coordinator (a false survivor set, too few or forged
    confirmations);
  - authentication, duplicates, round binding and tampering.
- `crates/encompute-runtime/tests/aggregation.rs`:
  - three hospitals with 4096-value gradients over HTTP, matching the clear
    sum within the quantization bound;
  - dropouts, the mean, and every case on the milestone's attack list;
  - attested contributors;
  - the explain output.
- `crates/encompute-cli/tests/cli.rs` (`secure_aggregation_round`),
  `python/tests/test_aggregation.py`, and `examples/confidential_federated_update/`.
