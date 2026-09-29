# ADR-013 — Differential privacy: budgets, mechanism, ledger

Status: **Accepted** (2026-09-25)

## Context

Secure aggregation (ADR-012) stops anyone from seeing one hospital's gradient.
The aggregates it releases can still reveal information about the patients
behind them, round after round. Encompute therefore has to account for how much
information a collaboration releases over time, and refuse a release that
would exceed what the data owners approved.

Each layer answers a different question, and one never substitutes for
another:

| Layer | Question it answers |
|---|---|
| FHE / MPC | Can the computation run without seeing the data? |
| Secure aggregation | Can anyone see an individual contribution? |
| Differential privacy | How much may be learned from what is released? |
| Attestation | Which workload ran? |
| Execution proofs | Was the computation correct? |

## Decision

1. **Budgets belong to assets.**
   - An asset declares whose privacy it protects and its lifetime budget:
     ```text
     asset "gradient-a" gradient owners ["hospital-a"] ... release aggregate_only
       privacy unit "patient" epsilon 3.0 delta 1e-6
     ```
   - Units are `record`, `user`, `patient`, `device`, `organization`, or a
     custom ID. The budget requires ε > 0 and 0 < δ < 1. There are no
     implicit defaults.
   - Every release derived from the asset debits this budget.
   - Named levels map to a budget and noise. Their clip norm is 1:

     | Level | ε | δ | Listed noise multiplier | Effective, organization | Effective, record / patient / user / device |
     |---|---|---|---|---|---|
     | `standard` | 8 | 1e-5 | 2.2 | 2.2 | 4.4 |
     | `strong` | 3 | 1e-6 | 6 | 6 | 12 |
     | `maximum` | 1 | 1e-7 | 18 | 18 | 36 |

     Without Poisson sampling nothing clips one unit inside a party's
     contribution, so a record, patient, user or device is charged twice
     the clip norm, like an organization. A level therefore uses twice its
     listed noise for those units. The noise-to-sensitivity ratio is then
     the same for every unit, and each level affords about 10
     full-participation releases of a record-, patient- or user-level
     budget (about 2.5 of an organization-level one). The program records
     the level next to the effective noise (`... noise_multiplier 12.0
     preset "strong"`), the compiler refuses a level whose noise is not
     exactly that, and `privacy explain` and the trust report show
     `preset=strong, sensitivity_factor=2, effective_noise_multiplier=12
     (2x preset 6.0)`. The effective noise is what is sampled, charged and
     written in receipts and ledgers.

     In Python: `asset(..., privacy="strong", unit="patient")`. `DP(epsilon,
     delta)` sets an explicit budget.

2. **Release boundaries are found by the compiler.**
   - An output that leaves confidential computation (to a party, or public)
     and derives from a budgeted asset is a privacy release.
   - It must go through a DP mechanism; without one it is ENC2203.
   - Sealed outputs stay confidential, cost nothing, and need no mechanism.
     Internal confidential transformations are never charged.

3. **Mechanism: discrete Gaussian on the integer aggregate.**
   - Declared on the aggregation:
     ```text
     aggregate "g" sum ... dp discrete_gaussian clip_norm 1.0 noise_multiplier 6.0
     ```
     In Python: `secure_aggregate(..., privacy="strong")` (the level's
     noise for the units of the program's budgets) or
     `DiscreteGaussian(...)`.
   - Clipping:
     - Each party's vector is clipped to L2 norm `clip_norm` before encoding.
     - The codec's clip range must contain 0, so per-coordinate clipping never
       increases a norm.
   - Noise:
     - The coordinator adds noise to the secure-aggregation sum, in code
       units, with `σ² = ⌈(noise_multiplier · clip_norm · scale)²⌉`.
     - The noise is exact discrete Gaussian: a port of Canonne, Kamath and
       Steinke's reference sampler (NeurIPS 2020, Apache-2.0), with bignum
       rationals and no floating point.
     - Randomness is ChaCha20 under an OS-random key.
   - The order is:
     ```text
     clip (L2, per party) → encode → secure aggregation → noise → decode → release
     ```
   - Continuous Gaussian noise on floats would be open to floating-point
     attacks (Mironov 2012), so it is not used.
   - Test randomness is available only behind the `insecure-deterministic-noise`
     feature. It is labelled in the ledger and receipts, and verification
     refuses it.

4. **Sensitivity** is expressed in code units as `⌈k · clip_norm · scale⌉ +
   ⌈√d⌉`. Neighbouring datasets never change which parties contribute: the
   contributor list is public, and the protocol decides it, not any one
   unit's data. So the encoding offset `−clip_min · scale` appears in both
   sums and cancels. (A review asked whether it breaks the bound; it would
   only under add/remove of a whole party, which is not a neighbouring
   dataset here. A property test checks the bound.)
   - the `√d` term covers rounding each coordinate to a code;
   - `k = 1` for records, users, patients and devices: adding or removing a
     unit changes one party's vector by at most the clip norm, and the
     contributor count is unchanged;
   - `k = 2` for organizations: the contributor count is public, so the
     neighbouring dataset replaces one party's contribution.

   For units finer than the organization, Encompute clips whole
   contributions. Bounding each patient's influence inside a contribution is
   the contributing workload's job, typically DP-SGD-style per-example
   clipping in an attested training workload. The compiler warns about this.

5. **Accounting: zCDP** (Bun & Steinke 2016).
   - A release costs `ρ = Δ²/(2σ²)` (CKS Theorem 14).
   - Costs compose by addition.
   - ρ converts to (ε, δ) at the budget's δ with the CKS optimal conversion
     (`cdp_eps`, ported from their `cdp2adp.py`).
   - Two parties must reach the same decision, so the maths uses the pure-Rust
     `libm` (the same bits everywhere) and rounds results up.
   - The `PrivacyAccountant` trait allows other accountants.
   - There is no sampling amplification: every round is full participation.

6. **The ledger**: one hash-chained, append-only file per budgeted asset.
   - The genesis fixes the asset, budget and `PrivacyPolicyId`.
   - A release is one transaction:
     1. Lock every charged ledger, in a fixed order.
     2. Verify each chain and check each budget.
     3. Append a `Reserve` event (charged, fsync) to each.
     4. Draw the noise.
     5. Append a `Commit` event with the output commitment.
     6. Sign a `PrivacyReceipt` per asset.
   - A crash after reserving leaves the budget spent. That is conservative, so
     no release is ever unaccounted.
   - The OS file lock prevents two processes from double-spending.
   - Each (round, output) pair is released at most once.
   - Deleting, reordering or editing an entry breaks the chain.
   - Events record the integer sensitivity and σ², so anyone can recompute
     the cost.

7. **Owners enforce the budget too.**
   - The coordinator shows each budgeted asset's ledger in the round offer.
   - Each owner verifies its own ledger: the chain, the genesis (its asset,
     budget and policy), and production randomness.
   - It checks that the ledger extends the last checkpoint it saw, which
     detects rollback and reset.
   - It then previews this round's cost and refuses to contribute if the
     budget would be exceeded.
   - After the round, it verifies its privacy receipt and records the new
     checkpoint (`--state`).
   - So a coordinator that deletes or rolls back its ledger loses its
     participants rather than gaining budget.
   - **One owner's state protects all.** Every aggregation receipt carries
     each charged asset's signed checkpoint. Each owner records all of them
     and, before contributing, checks every offered ledger against every
     checkpoint it knows. So a rollback of hospital A's ledger is refused by
     B and C even if A lost its state.
   - What remains trust-on-first-use is a consortium where no owner holds
     any state yet. Owners can bootstrap state out of band, for example by
     copying another owner's state file. A transparency-log witness would
     close this gap; it is future work.

8. **Identity.**
   - A `PrivacyPolicyId` (`encprivacy1:`) hashes every budget (unit, ε, δ)
     and every mechanism (kind, clip norm, noise multiplier, codec).
   - It is bound into the `ExecutionSpec`, the aggregation plan (and so the
     spec), each ledger's genesis, and each receipt.
   - An attested coordinator binds it too. `WorkloadBinding` and
     `AttestationPolicy` carry `privacy_policy_id`. A spec's
     `coordinator_attestation` requires the coordinator's attestation to bind
     the plan, the round's key and nonce, and the privacy policy. Parties
     check this before contributing.
   - A host cannot claim the approved noise while running less. A version
     with less noise, a larger clip or a larger budget is a different spec,
     and parties refuse it.

9. **In the CLI.**
   - `aggregate coordinator-policy` writes the attestation policy a
     coordinator must satisfy.
   - `--coordinator-policy` requires that policy on both sides.
   - `aggregate serve --attester …` attests the coordinator.
   - `aggregate join --mock-root/--jwks` verifies it.

10. **Tools.**
   - `privacy explain` shows each budget, the mechanism, the cost of one
     release and how many releases the budget affords, with runtime
     enforcement ACTIVE.
   - `explain --ledger DIR` previews the next release: current, after and
     budget, PERMITTED or DENIED.
   - `privacy budget --ledger DIR` lists spent, remaining and every release.
   - `aggregate serve --ledger DIR` refuses a round no budget can afford
     before it starts.

## Trust

This is **central** DP. The coordinator sees the aggregate before noise, and
the guarantee holds against everyone who sees only released outputs.

The coordinator is trusted to add the noise. That trust is as strong as its
attestation (8). A coordinator that is not attested could release the
aggregate without noise, and nothing here would stop it.

Distributed noise removes this assumption: each party adds a discrete
Gaussian share before masking (Kairouz et al., ICML 2021). The design leaves
room for it, since the noise is already integer and added in code units, but
it is future work.

Timing side channels of rejection sampling are not addressed; do not expose
per-release latency.

## Evidence

- **`crates/encompute-privacy/tests/privacy.rs`:**
  - sampler statistics;
  - accountant values that match the reference implementation;
  - composition and exhaustion;
  - concurrent double-spend (8 threads, exactly one release fits);
  - duplicate release;
  - deletion, reordering, editing, rollback, reset and substituted ledgers;
  - receipt binding (output, parameters, ledger, signer, replay);
  - invalid budgets and a mechanism without noise.
- **`crates/encompute-runtime/tests/privacy.rs`:**
  - rounds until the budget is spent, then denial, persisting across
    restarts;
  - weaker noise, clip or budget refused by owners even when the coordinator
    skips its own check;
  - rollback, deletion, reset and another asset's ledger;
  - an attested coordinator bound to the privacy configuration (unattested,
    unapproved image, other privacy policy);
  - explain, preview and budget report.
- **`crates/encompute-analysis/tests/aggregation.rs`:** release-boundary
  detection, sealed outputs, invalid declarations, `PrivacyPolicyId`
  sensitivity, presets.
- **`python/tests/test_privacy.py`**, and
  **`examples/09_differential_privacy/`**: 12 rounds permitted, the 13th
  denied.

## Update (2026-09)

Section 5 says there is no sampling amplification. That is still true for
organization-level releases on secure aggregates. Patient-level DP-SGD,
added later, samples patients with Poisson sampling and uses a Rényi DP
accountant for Poisson-sampled releases (`rdp-poisson-zw2019`), which does
account for sampling. The sampling rate is part of `DpMechanism` and of the
`PrivacyPolicyId`. See `0017-patient-level-dp.md`.

## Update (2026-09-28)

An external security review of 0.3.0-rc.3 found two statements above too
permissive. The code and the threat model now follow the rules below; the
sections above are kept as they were decided.

**Section 2, sealed outputs.** Sealed outputs of encrypted computation stay
confidential, cost nothing, and need no mechanism. A secure-aggregation
aggregate is always a release, even when sealed: the protocol unmasks it to
the coordinator, which writes it out. So an aggregation of a budgeted asset
always needs `dp` and a ledger (`aggregate serve --ledger`). The compiler
refuses such an aggregation without `dp` (ENC2203); the aggregation spec,
each owner and the receipt verifier refuse it too.

**Section 4, the value of `k`.**
- `k = 1` only for a unit inside a party (record, user, patient, device)
  with Poisson sampling (DP-SGD): the attested workload clips each sampled
  unit's gradient to the clip norm.
- `k = 2` otherwise, including every unsampled unit. Encompute clips only
  each party's whole contribution, so one unit may move it anywhere in the
  clipping ball.

`privacy explain` shows this as the `unit bound` line. The last paragraph
of section 4 (per-unit clipping is the contributing workload's job) no
longer lowers the charge: without sampling, a finer unit is charged as an
organization is. A release for such a unit costs about four times the ρ it
cost before, so the named levels in section 1 afford fewer releases for
it. Example 09 now uses noise multiplier 12 to keep its costs: 5 releases
permitted, the 6th denied.

**Section 5, rounding.** Each curve value carries an allowance for its
rounding error, and each epsilon is raised by a relative margin of 1e-12
before the final rounding up, so accounting stays at or above a
high-precision reference. Epsilons change around the 12th significant
digit.
