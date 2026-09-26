# 06 — Confidentiality policy

## What this demonstrates

A program declares who owns each input, who may learn it, what it may be
used for and how it may be released. Encompute derives the policy of every
intermediate value and output, and an illegal flow is a compile error with
a code, before anything runs.

Three parties take part in one training step (`training.eir`):

| Asset | Owner | May learn it | Release |
|---|---|---|---|
| `patients` (dataset) | Hospital A | nobody | never |
| `weights` (model) | ModelCo | nobody | never |
| gradient derived from both | Hospital A, ModelCo | Coordinator | aggregate only |

`encompute privacy explain` prints the resulting graph and `privacy graph`
the same graph in Graphviz DOT. Three variants of the program then break
one rule each and must fail to compile. `confidential_training.py` states
the same policy from Python.

## Threat model

The parties do not trust each other with their assets, and the coordinator
must learn gradients only as part of an aggregate. The program author may
make mistakes (or be careless); the compiler is trusted to check the
declared policy. Compile-time checks only cover what the program does;
run-time enforcement is examples 07 (key release) and 08 (secure
aggregation).

## Architecture

```text
patients (Hospital A) ─┐
                       ├─ mul ─► gradient (aggregate_only, to Coordinator) ─► sealed output
weights  (ModelCo)    ─┘
```

Policies join: a value derived from `patients` and `weights` is at least as
restricted as both. Only a `derive` the owners declared (`derive [gradient
aggregate_only to ["coordinator"]]`) relaxes it, and only that far.

## Run it

```sh
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/06_confidentiality_policy/run.sh
```

## Expected output

```text
CONFIDENTIALITY GRAPH  training_step
purpose disease-training
...
  gradient %2
    kind          gradient
    derived from  patients + weights
    owners        hospital-a, modelco
    may learn it  coordinator
    purposes      disease-training
    release       aggregate_only

Warnings
  output "gradient" (gradient) may only be released as part of an aggregate: it needs an aggregation boundary (e.g. secure aggregation) before any party learns it

ATTACK   return patient data publicly
REFUSED  error[ENC1901]: confidential value flows to a public output: output "records" (derived from patients) has release never; ...
ATTACK   send the gradient straight to the coordinator (no aggregation)
REFUSED  error[ENC1905]: output "gradient" (derived from patients, weights) may only be released as part of an aggregate; ...
ATTACK   use the datasets for another purpose (marketing)
REFUSED  error[ENC1903]: asset patients cannot be used for purpose "marketing": it allows only disease-training
leak rejected: ENC1905: ...
```

## Try breaking it

Each file differs from `training.eir` in one line:

| File | Change | Error |
|---|---|---|
| `leak_patient_data.eir` | `output "records" = %0 public` | ENC1901: confidential value flows to a public output |
| `gradient_to_coordinator.eir` | `output "gradient" = %2 to "coordinator"` | ENC1905: aggregate-only value revealed without an aggregation boundary |
| `wrong_purpose.eir` | `purpose "marketing"` | ENC1903: an input asset does not allow the program's purpose |

Other things to try: add `output "peek" = %0 to "modelco"` (ENC1902:
ModelCo may not learn patient data), reveal the gradient to `hospital-a`
(ENC1905 again: even an owner gets it only through an aggregate), or list
an undeclared party as a reader (ENC1906).

## What Encompute guarantees

- A compiled artifact carries a policy in which every value is at least as
  restricted as its sources; the policy ID (`encpolicy1:...`) is bound into
  the artifact, attestation policies and receipts.
- Outputs are sealed unless every source asset allows the stated release,
  and aggregate-only values leave only through a declared aggregation.
- Programs whose declared purpose an input does not allow do not compile.

## What Encompute does NOT guarantee

- The policy is only as good as its declarations. If Hospital A declares
  `readers ["hospital-a", "modelco"] ... release allowed_parties`, the
  program may reveal patient data to ModelCo, and it compiles.
- Compile-time checks do not stop anyone at run time: a party holding keys
  can decrypt whatever they are given. Keys, attestation and secure
  aggregation (examples 07, 08) enforce the policy at run time.
- Purposes are labels. Encompute checks that the program declares an
  allowed one; it cannot tell whether the computation really serves it.
- An aggregate can still leak information about individual inputs. Bound
  that with differential privacy (example 09).

## Relevant source modules

- `crates/encompute-ir/src/confidentiality.rs`: parties, assets, releases,
  the policy lattice.
- `crates/encompute-analysis`: flow checking and the ENC19xx errors.
- `crates/encompute-cli`: `privacy explain` and `privacy graph`.
- `docs/errors.md` (codes), `docs/adr/0010-confidentiality-ir.md` (design).
