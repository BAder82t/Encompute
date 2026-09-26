# 11 — Automatic planner

## What this demonstrates

User declares requirements. Encompute chooses mechanisms.

Hospitals A, B and C train ModelCo's model on their patients. The Python
`Project` names the parties, the data, the model and two requirements
(`privacy="strong"`, `verification="required"`). No mechanism is named.
`planner.py` asks the planner and prints what it chose:

```text
Training          -> confidential compute (mock TEE)
Gradient sharing  -> secure aggregation
Output release    -> differential privacy
Key access        -> attestation (attestation-gated key release)
```

The only TEE on this machine is development mock attestation, so the
example declares it and passes `allow_development=True`. Mock attestation
protects nothing: it lets the plan be computed here. Declare a real TEE
(`{"tee": "intel-tdx", "provider": "gcp-confidential-space", ...}`) and the
planner picks it in the same place, without the flag.

Then the same program through the CLI (`encompute plan`, `encompute check`
with `--infrastructure` and `--training`), which yields the same plan ID;
the fail-closed case (no TEE, while the model must stay hidden from the
cloud): `PLANNING FAILED` with a reason for every rejected candidate; and
the deep explanation (`explain --deep`, `plan --deep`): every candidate the
planner weighed, and the security assumptions behind them.

## Threat model

The planner is a compile-time decision, not a runtime defence. Its inputs
are the program's policies (who owns and may read each asset, purposes,
budgets) and the declared infrastructure. The adversaries it plans against
are the ones those policies name: other hospitals, ModelCo (for patient
data), and the compute host (for everything). A plan it returns satisfies
every requirement with the mechanisms it lists, or it returns none.

## Architecture

```text
Project(parties, data, model) ─ train(privacy, verification, infrastructure)
        │  generates the program: assets, policies, aggregate
        ▼
planner: for each step, every candidate placement and mechanism
        (local at each party, FHE on an ordinary host, each declared TEE;
         secure aggregation, with or without attestation)
        ├─ reject candidates that break a requirement (with the reason)
        ├─ pick the cheapest valid one (--prefer latency|cost)
        └─ none valid for a step → PLANNING FAILED (ENC2401)
        ▼
plan.json (encplan1:..., deterministic) → aggregate --plan, trust bundle
```

## Run it

```sh
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/11_automatic_planner/run.sh
```

It only plans: nothing is trained and no TEE is started.

## Expected output

```text
== What Encompute chose ==
Training          -> confidential compute (mock TEE)
Gradient sharing  -> secure aggregation
Output release    -> differential privacy
Key access        -> attestation (attestation-gated key release)

Selected mechanisms
────────────────────────────
train:patients-a
  mock TEE, confidential compute (mock, mock) + attestation (mock) + attestation-gated key release
  estimated 91000 ms
...
aggregate:update
  across the parties, secure aggregation (threshold 3, colluding ≤ 1) + differential privacy (discrete Gaussian, noise 6.0, clip 1.0)
  estimated 955 ms

RESULT
ALL TRUST REQUIREMENTS SATISFIED
(estimated 273955 ms in total; estimates, not guarantees)

== Take the TEE away (the cloud still must not see the model) ==
error[ENC2401]
No valid mechanism
────────────────────────────
train:patients-a
  - at hospital-a, local execution at hospital-a: hospital-a would run a step reading base-model
  - at hospital-b, local execution at hospital-b: hospital-b would run a step reading base-model
  - at hospital-c, local execution at hospital-c: hospital-c would run a step reading base-model
  - at modelco, local execution at modelco: modelco may not read everything train:patients-a reads
  - ordinary host, FHE (CKKS, openfhe): general training is not supported under FHE
  ... (train:patients-b and train:patients-c: the same)

RESULT
PLANNING FAILED
No execution plan satisfies the policy; no requirement was weakened.
```

Each rejection is a policy reason. Training at a hospital would show it
ModelCo's model. Training at ModelCo would show it the patients' data. FHE
is rejected because general training is not supported under FHE, not
because this build lacks an FHE backend. The CLI says the same, and
exits 1:

```text
$ encompute check train.eir --training training.json --infrastructure no-tee.json
program valid   OK
policy valid    OK
privacy valid   OK
plan exists     NO   PLANNING FAILED (see `encompute plan`)
```

## Try breaking it

`run.sh` runs each of these. Every one ends in `PLANNING FAILED` (exit 1)
with the TEE candidate's rejection:

| Attempt | Rejected because |
|---|---|
| Mock TEE without `--allow-development` | `mock is development-only attestation` |
| Mock TEE under `--profile maximum`, even with `--allow-development` | `mock is development-only attestation` |
| A TEE declared `"debug_only": true` | `intel-tdx only runs debug workloads, whose memory the host can read` |
| A cloud TEE with `--local-only` | `intel-tdx runs in the cloud; local-only was required` |

## What Encompute guarantees

- The planner never weakens a requirement to find a plan. If no candidate
  satisfies a step, planning fails and every rejected candidate is listed
  with its reason.
- Plans are deterministic: the same program, declarations and preferences
  give the same plan ID from Python and the CLI.
- The plan ID binds the plan. Aggregation rounds and trust bundles check
  that they ran under it (example 10).
- Development mock attestation is refused unless explicitly allowed, and
  always under the maximum profile.

## What Encompute does NOT guarantee

- The planner believes the infrastructure you declare. Declaring a TEE
  you do not have yields a plan you cannot run. Attestation at run time
  (example 07) is what checks the hardware.
- The plan here uses mock attestation. It protects nothing: a mock TEE
  is an ordinary process, and anyone can produce mock evidence.
- "Estimated" means estimated: costs are coarse per-mechanism figures,
  not measurements.
- The requirements are only the declared ones. Anything the policies do
  not say (for example what the aggregate itself reveals, beyond the DP
  budget) is not planned for.
- `explain --deep` takes no `--training` or `--infrastructure`, so it
  shows only the aggregation step's candidates; `plan --deep` shows the
  training steps.

## Relevant source modules

- `python/encompute/_project.py`: `Project`, `train`, the generated
  program.
- `crates/encompute-planner/src/planner.rs`: candidates and selection.
- `crates/encompute-planner/src/requirements.rs`: requirements from
  policies.
- `crates/encompute-planner/src/render.rs`: the plan and failure reports.
- `crates/encompute-cli/src/plan.rs`: `plan`, `check`, `explain --deep`.
- `docs/adr/0015-planner.md`: the design.
