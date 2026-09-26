# 12 — Full confidential collaboration

## What this demonstrates

Everything together, the way a real collaboration runs. Three hospitals and
ModelCo:

1. declare their parties, assets and policies;
2. let Encompute plan the mechanisms;
3. approve the program;
4. have ModelCo's model key released only to an attested workload;
5. securely aggregate the hospitals' model updates, with differential
   privacy, through an attested coordinator;
6. check every piece of evidence with one trust report.

The requirements:

| Requirement | Enforced by |
|---|---|
| Hospitals cannot see each other's data | policy (release never), secure aggregation |
| ModelCo cannot see hospital data | policy; only the noised aggregate reaches ModelCo |
| Hospitals cannot inspect ModelCo's model | policy; the model key is released only to an attested workload |
| The cloud cannot read the model or the datasets | the planner puts training in a TEE; keys are gated by attestation |
| Individual updates are never released | secure aggregation (threshold 3, up to 1 colluding party) |
| The aggregate is DP-protected | discrete Gaussian noise, charged to each hospital's patient-level budget |
| Only approved workloads get keys | the key broker checks attestation against the approved policy |
| Execution evidence is required | receipts, attestation records and privacy receipts in one trust bundle |

## Threat model

- The coordinator (ModelCo's server) and the cloud are untrusted.
- At most one hospital colludes with the coordinator.
- Each party knows every other party's public key out of band
  (`parties.json`, and ModelCo's coordinator key).
- TEE hardware is trusted. Here it is **development mock attestation**,
  which protects nothing. The checks are the ones real Confidential Space
  evidence goes through.

## Architecture

```text
 hospitals          ModelCo                      verifier
 ─────────          ───────                      ────────
 declare policies ─► encompute plan  (TEE, SecAgg, DP, attestation)
 authorize program   key broker ──sealed key──► attested workload
 local updates ────► attested coordinator: SecAgg + DP ─► noised update
        │                        │
        └── receipts, attestation records, privacy receipts ──► trust bundle
                                                                  │
                                            encompute trust report
```

## Run it

```sh
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/12_confidential_collaboration/run.sh
examples/12_confidential_collaboration/attack.sh all     # or one attack by name
```

## Expected output

```text
== 2. Plan: Encompute chooses the mechanisms ==
train:patients-a
  mock TEE, confidential compute (mock, mock) + attestation (mock) + attestation-gated key release
aggregate:model_update
  across the parties, secure aggregation (threshold 3, colluding ≤ 1) + differential privacy (discrete Gaussian, noise 6.0, clip 1.0) + attestation (mock)
ALL TRUST REQUIREMENTS SATISFIED
...
Key           base-model v1 from modelco: RECEIVED (32 bytes, sealed to this session)
3 CONTRIBUTION ACCEPTED (only the aggregate is released)
AGGREGATION COMPLETE
AGGREGATION RECEIPT VERIFIED
...
Evidence                VERIFIED
Program                 VERIFIED
Policy                  VERIFIED
Plan                    SATISFIED
Owner authorization     AUTHORIZED
Workload                ATTESTED
Private aggregation     VERIFIED
Privacy budget          SATISFIED
Execution               NOT PRESENT
Lineage                 COMPLETE

RESULT
TRUST REQUIREMENTS SATISFIED
PLAN SATISFIED BY OBSERVED EXECUTION
```

`Execution NOT PRESENT`: this collaboration has no encrypted evaluation
step, so there are no execution receipts to check.

## Try breaking it

`./attack.sh NAME` runs the real flow up to the attack. It then shows the
boundary that refuses it and why:

| Attack | Boundary | Refusal |
|---|---|---|
| `stale-attestation`: replay a workload's evidence to get the key again | the key broker answers each challenge once | ENC2003 |
| `wrong-party`: Hospital D contributes | only parties in `parties.json` count | ENC2101 |
| `replay-gradient`: the coordinator reruns round 1 to collect the updates twice | each party joins a round once | ENC2102 |
| `weaken-dp`: noise 6.0 → 1.0 under the approved plan | the plan is for another program | ENC2402 |
| `weaken-dp`: the same, without the plan | weak noise is charged at its true cost, over budget | ENC2201 |
| `weaken-dp`: noise 3.0, within budget | each party checks the spec is the approved one | ENC2102 |
| `rollback-ledger`: the coordinator resets the privacy ledgers | each party's ledger checkpoint | ENC2202 |
| `tamper-output`: edit the released update | the receipt commits to the released aggregate | ENC2104 |
| `wrong-plan`: run under a plan the owners did not approve | the spec binds the approved PlanId | ENC2102 |

## What Encompute guarantees

- Only the noised sum of the three updates is released. The coordinator
  never sees an individual update, provided at most one hospital colludes
  with it.
- Every release is charged to each hospital's patient-level budget in a
  tamper-evident ledger. A reset or rollback is detected by the hospitals.
- The model key reaches only a workload whose attestation binds the
  approved execution spec, policy and image.
- The round runs only under the approved plan, program, policy and
  coordinator attestation, or the hospitals refuse to contribute.
- The trust report rebuilds the graph from the signed evidence and checks
  it against keys the verifier supplies. It never trusts what the bundle
  says about itself.

## What Encompute does NOT guarantee

- **Mock attestation protects nothing.** With real TEEs the same checks
  apply to hardware-signed evidence.
- **Local training is not part of this example.** The hospitals' updates
  are fixed vectors. The confidential fine-tuning example will run real
  PyTorch training inside attested workloads.
- **The coordinator sees the aggregate before noise** (central DP). Its
  attestation is what limits what it can do with it.
- **DP bounds what the released aggregate reveals about one patient at the
  declared budget,** not about a whole hospital or a population.
- **The trust report checks what was recorded.** A coordinator that never
  records a round leaves no trace. The hospitals' own round state and
  ledger checkpoints are what stop that round from being reused.

## Relevant source modules

- `crates/encompute-planner`: requirements, mechanism selection, plan validation.
- `crates/encompute-attestation`, `crates/encompute-keybroker`: attestation and key release.
- `crates/encompute-secagg`: secure aggregation, specs and receipts.
- `crates/encompute-privacy`: noise, budgets, ledgers.
- `crates/encompute-trust`: the trust graph and report.
- Design notes: `docs/adr/0011-attested-key-release.md` through `docs/adr/0015-planner.md`.
