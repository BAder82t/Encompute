# 14 — Python Project API

## What this demonstrates

The simplest way in for Python developers: say who the parties are, what
data each owns and which policy applies. Encompute chooses the protection
mechanisms and explains every choice, or refuses. The user code names no
scheme, key or protocol:

```python
project = encompute.Project("demo", parties=["alice", "bob"])
a = project.data("alice-data", owner="alice", policy="private-training")
b = project.data("bob-data", owner="bob", policy="private-training")
plan = project.plan(data=[a, b], privacy="strong")
print(plan.explain())
```

`project_api.py` then trains a model owned by a third party on both
datasets:

- with a (development) TEE available, the planner picks confidential
  compute with attestation and attestation-gated key release for each
  training step, and secure aggregation with differential privacy for the
  update;
- with no TEE, planning fails closed with `encompute.PlanningFailed`
  (ENC2401), and the report says why each candidate was rejected;
- the mock TEE is refused unless `allow_development=True` is passed.

## Threat model

Alice, Bob and ModelCo do not trust each other with their assets, nor the
host that runs the computation. `private-training` means only the owner
reads the data, it is used only for the project's purpose, and only a
noised aggregate of its gradients leaves. `private-model` means only its
owner reads the model. Asset IDs are lowercase letters, digits, `-`, `_`
and `.` (no `/`).

## Architecture

```text
Project(parties, assets, policies)
   │  expands presets into declarations, compiles a program
   ▼
planner ── infrastructure (TEEs, key broker) ──► plan: steps, mechanisms, reasons, evidence
   │                                          or PlanningFailed + why
   ▼
plan.explain(), plan.plan_id, plan.save_plan(path) for the CLI
```

## Run it

```sh
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/14_python_project_api/run.sh
```

## Expected output

The first plan (abridged):

```text
ENCOMPUTE PLAN
encplan1:...
Requirements
alice-data
  alice-data hidden from bob
  alice-data used only for "demo"
gradient-alice-data
  gradient-alice-data revealed only inside the aggregate update
  gradient-alice-data: record-level privacy, ε ≤ 3.0, δ ≤ 1e-6
Selected mechanisms
aggregate:update
  across the parties, secure aggregation (threshold 2, colluding ≤ 0) + differential privacy (discrete Gaussian, noise 6.0, clip 1.0)
RESULT
ALL TRUST REQUIREMENTS SATISFIED
```

Training:

```text
== Training with a (development) TEE available ==
train:alice-data
  mock TEE, confidential compute (mock, mock) + attestation (mock) + attestation-gated key release
aggregate:update
  across the parties, secure aggregation (threshold 2, colluding ≤ 0) + differential privacy (discrete Gaussian, noise 6.0, clip 1.0)
ALL TRUST REQUIREMENTS SATISFIED

== The same training with no TEE ==
PlanningFailed ENC2401
train:alice-data
  - at alice, local execution at alice: alice may not read everything train:alice-data reads
  - at bob, local execution at bob: bob would run a step reading alice-data
  - at modelco, local execution at modelco: modelco would run a step reading alice-data
  - ordinary host, FHE (CKKS, openfhe): general training is not supported under FHE
PLANNING FAILED
No execution plan satisfies the policy; no requirement was weakened.

== The mock TEE without allow_development ==
PlanningFailed ENC2401
- mock TEE, ...: mock is development-only attestation
```

## Try breaking it

- Train with no infrastructure: `PlanningFailed` (ENC2401). There is no
  fallback to a weaker mechanism.
- Pass the mock TEE without `allow_development=True`: refused, because
  mock attestation protects nothing.
- Use an ID with `/` or capitals (`"alice/data"`): ENC1906 before anything
  is planned.
- Aggregate a single party's data (`data=[a]`): ENC2106, an aggregate of
  one is that party's data.

## What Encompute guarantees

- A plan is produced only if every requirement the policies imply is
  satisfied by some mechanism, and `explain()` names the mechanism, the
  reason and the evidence each one leaves.
- Planning is deterministic: the same declarations and infrastructure give
  the same `plan_id`.
- When nothing fits, it fails closed and says why, per step and candidate;
  no requirement is weakened.

## What Encompute does NOT guarantee

- A plan is a decision, not an execution. Nothing ran here: running it
  needs the parties' brokers, workloads and aggregation rounds (examples
  07, 08, 12).
- The planner trusts the infrastructure description you give it. Saying a
  TEE exists does not make one exist; attestation at run time is what
  checks it.
- The mock TEE in the successful plan protects nothing. A real deployment
  needs real TEEs.
- Timings in the report are estimates, not guarantees.
- Differential privacy bounds what the aggregate reveals about one record;
  it does not hide the aggregate itself.

## Relevant source modules

- `python/encompute/_project.py`: `Project`, the policy presets,
  `PlanningFailed`.
- `crates/encompute-planner`: requirements, candidate mechanisms, the
  report.
- `python/tests/test_project.py`: the behaviours shown here, as tests.
- `docs/adr/0015-planner.md` (design).
