# ADR-017 — Patient-level differential privacy (DP-SGD)

Status: **Accepted** (2026-09-26)

## Context

Confidential fine-tuning clipped each hospital's whole update, so its
budget protected one hospital's contribution (organization level). A
hospital's patients need a stronger statement: the adapter reveals little
about whether any one patient's records were used. That needs per-example
clipping, sampling and an accountant for sampled releases. It must also
never be claimed for a run that does not do them.

## Decision

1. **Mechanism: DP-FedSGD with central attested noise.**
   - In each round, every participant's attested worker Poisson-samples its
     privacy units with rate `q`, using operating-system randomness.
   - The worker computes per-example gradients of the LoRA parameters
     (`torch.func` `vmap` over `grad`, in microbatches). It sums each unit's
     records (grouping by `unit_ids`), clips each unit's gradient to `C`,
     and sums the sampled units.
   - It contributes the sum, rescaled so each unit's norm is at most the
     codec clip, to secure aggregation. The coordinator adds discrete
     Gaussian noise with standard deviation `z · clip` to the sum.
   - The model owner takes one SGD step: `adapter −= lr · sum / (q · N)`,
     where `N` is the total number of units. One step per round: every step
     is one accounted release.
   - The noise is central, added by the attested coordinator. It is not
     distributed noise.
2. **Neighbouring relation and sensitivity.**
   - Neighbours differ by adding or removing one unit, with all its
     records, from one participant's dataset. Which participants
     contribute is public, so organizations are never sampled; the
     compiler refuses sampling with an organization unit.
   - One unit moves its participant's contribution by at most the clip.
     The codec's per-coordinate clamp is 1-Lipschitz, and rounding adds at
     most `√d` codes, so the existing sensitivity bound
     `ceil(clip · scale) + ceil(√d)` holds.
   - With sampling, the secure-aggregation client no longer clips the whole
     contribution. The attested worker clips each unit instead, and the
     codec bounds each coordinate.
   - So a sampled round accepts only attested contributors. A coordinator
     cannot open one without a contributor attestation policy, and a party
     cannot join one without an attestation record.
     - The policy binds the approved plan, the training code's digest and
       the image. It binds the plan rather than the training spec, because
       the training spec already binds the aggregation spec.
     - Each record binds the party's contribution key.
     - The trust report's Training row fails a DP-SGD run whose aggregation
       accepts unattested contributions.
3. **Accountant: `rdp-poisson-zw2019`.**
   - The discrete Gaussian with sensitivity `Δ` and variance `σ²` is
     `ρ`-zCDP with `ρ = Δ²/(2σ²)` (Canonne, Kamath and Steinke 2020), so its
     Rényi DP is `αρ`.
   - Poisson subsampling uses Zhu and Wang's general upper bound (2019,
     Theorem 6), which holds for any mechanism. The tighter
     Gaussian-specific formula is derived for the continuous Gaussian, and
     our noise is discrete, so we do not use it. We take the minimum with
     `αρ`.
   - Curves are evaluated at integer orders 2–256 plus a tail to 1024, and
     compose by addition. They convert to `(ε, δ)` with CKS 2020
     Proposition 12.
   - The arithmetic is `libm`, identical on every party, and rounded up.
   - Reference vectors (240 cases) come from an independent implementation:
     autodp's general upper bound, plus a 60-digit mpmath evaluation of the
     theorem. The Rust accountant must agree to 1e-7 relative and never be
     below the reference.
   - Ledgers use the Rényi accountant only when a sampled release exists.
     Otherwise they use the unchanged zCDP path.
4. **Bindings.**
   - `DpMechanism.sampling_rate` is part of the program and of the
     PrivacyPolicyId, whose accountant name changes with it.
   - The training spec's `dp_sgd` binds:
     - the unit, the per-example clip, the sampling (`poisson`) and its
       rate;
     - the noise, delta, grouping (`unit_ids` or `none`), the accountant
       and the expected batch.
   - Each dataset commitment binds its number of units and the digest of
     its unit IDs. The dataset digest also covers them.
   - `local_steps` must be 1.
   - Organization-level specs have none of these fields, so their IDs are
     unchanged.
5. **Preview before training.** `finetune` projects the planned rounds'
   cost for every budget with the same accountant, and denies an
   over-budget run (ENC2201) before any worker starts.
   `encompute privacy explain --rounds N` prints the same preview and exits
   1 when the run is over budget.
6. **Claims.**
   - The training declaration carries the privacy unit and whether examples
     are clipped. The planner refuses a patient-level unit without
     per-example clipping and sampling, and an organization unit with them.
   - The plan's DP mechanism says "example level" and gives the sampling
     rate.
   - The trust report's Training row refuses a spec that does not match
     the program's privacy:
     - a non-organization budget without DP-SGD;
     - DP-SGD whose unit, sampling rate, noise or delta differs from the
       program's.
   - The lineage prints the unit and the DP-SGD settings.
7. **Interfaces.**
   - `encompute.Privacy(unit=, level=, epsilon=, delta=, noise_multiplier=,
     sampling_rate=, per_example_clip=)`.
   - The levels `standard-patient` (ε 8, δ 1e-5, z 1.0) and
     `strong-patient` (ε 3, δ 1e-6, z 1.2).
   - `encompute.torch.private_dataset(x, y, unit_ids=)`.
   - The sampling rate defaults to the batch size over the smallest
     dataset's unit count.
   - Workers report nothing about their data: no loss, sample size or
     clipping statistics.
8. **Sampler and accountant state.**
   - The sampler is stateless: fresh operating-system randomness every
     round, so a resumed run cannot replay a sample.
   - The accountant's state is the privacy ledgers, which checkpoints
     already bind. Lost rounds stay charged.

## Consequences and limits

- On the example workload (1,000 patients per hospital, q = 0.032,
  z = 1.2), 20 rounds cost ε = 1.75 at δ = 1e-6. Accuracy on held-out data
  goes from 0.38 to about 0.73, against about 0.76 without noise.
- Per-example gradients cost about 2.6× a plain batch gradient for this
  model, with microbatch 64. A round's time is dominated by the
  secure-aggregation round trips, as before.
- Trust assumptions: attested worker code clips and samples, and the
  attested coordinator adds the noise. The contribution key must live only
  in the attested worker. In development, the worker receives it from the
  party's key file, so a party that bypasses its own worker is limited only
  by the mock attestation. That party can harm only its own patients'
  guarantee, whose data it holds anyway. Patient IDs must be correct: the
  digest makes them fixed and auditable, not right. Each dataset's unit
  count is shared.
- Not covered: Hugging Face models, LLMs, distributed noise.
- Assurance: INV-130 to INV-135, `examples/16_patient_private_lora`.
