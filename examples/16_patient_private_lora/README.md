# 16 — Patient-level differential privacy (DP-SGD)

## What this demonstrates

Two hospitals fine-tune ModelCo's private model twice, on the same data,
with two kinds of privacy:

| | Organization-level (`privacy="standard"`) | Patient-level (`privacy="strong-patient"`) |
|---|---|---|
| What is clipped | each hospital's whole update | each patient's gradient, inside the attested worker |
| Who is sampled | nobody: every hospital contributes | each patient, independently (Poisson), every round |
| The budget bounds what the adapter reveals about | one hospital's contribution | any one patient |
| Accountant | zCDP | Rényi DP with Poisson subsampling |
| Steps per round | several local steps | one accounted step |

The developer asks for patient-level privacy in one argument:

```python
result = project.finetune(
    model=model, data=[a, b],
    privacy=encompute.Privacy(unit="patient", level="strong-patient", per_example_clip=1.0),
    verification="required", allow_development=True,
)
```

Each dataset says which records belong to which patient:

```python
et.private_dataset(tokens, labels, unit_ids=patient_ids)
```

A patient with many visits is one unit: their records' gradients are summed
and then clipped once.

Encompute then:

1. **previews** the privacy cost of every planned round before anything
   runs, and denies a run that would exceed the budget;
2. **binds** every DP-SGD setting into the training spec: unit, clip,
   sampling rate, noise, delta, grouping, accountant, expected batch and
   each hospital's patient count;
3. **computes** per-example gradients of the LoRA parameters with
   `torch.func` (`vmap` over `grad`), in microbatches, inside each attested
   worker;
4. **samples** patients with the operating system's randomness, so nobody
   (ModelCo included) chooses who is in a round;
5. **aggregates** each hospital's sum of clipped patient gradients through
   secure aggregation. The coordinator adds discrete Gaussian noise and
   charges each hospital's ledger with the Rényi DP accountant;
6. **records** the privacy unit in the trust report and the lineage. The
   report fails if a run claims patient-level privacy without per-example
   clipping.

## Threat model

As in example 15: untrusted cloud host; ModelCo must not see patient data;
neither hospital may obtain the model or the other's data; mock attestation
(no hardware confidentiality). In addition:

- Anyone who later obtains the adapter must not learn whether a given
  patient's records were used, beyond the stated ε and δ.
- ModelCo runs the coordinator and chooses round seeds. It must not be able
  to choose which patients are sampled.
- A hospital must not be able to weaken its patients' protection, for
  example by giving each record its own patient ID.

## Run it

```sh
pip install torch --index-url https://download.pytorch.org/whl/cpu
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/16_patient_private_lora/run.sh
```

It takes about a minute.

## Expected output

```text
PRIVACY PREVIEW
Asset                   gradient-patients-a (update)
Privacy unit            patient
Level                   example (DP-SGD, Poisson sampling 0.032)
Accountant              rdp-poisson-zw2019
Rounds                  20
Projected               epsilon 1.749 of 3 (delta 1e-6)
Budget affords          131 rounds
RESULT                  WITHIN BUDGET
...
Privacy unit: patient. Each patient's gradient is clipped to 1.0 (DP-SGD,
Poisson sampling 0.032), accounted with Rényi DP.
TRUST REQUIREMENTS SATISFIED
...
PRIVACY BUDGET EXCEEDED: DENIED BEFORE TRAINING. 400 rounds would cost
gradient-patients-a epsilon 4.667 of 3.0; its budget affords 131 rounds

Privacy             Protects each  ε used        Accuracy before  after   s/round  Trust
organization        hospital       6.34 / 8.00   0.380            0.43    2.8      SATISFIED
patient (DP-SGD)    patient        1.75 / 3.00   0.380            0.73    2.6      SATISFIED
```

Accuracy is measured on ModelCo's own held-out set. The organization run
takes only two rounds, so it is not a quality comparison. The patient run
shows that DP-SGD at ε = 1.75 still learns the task. Accuracy varies
slightly between runs, because patients are sampled with fresh randomness.

## Try breaking it

`attack.py` attacks the finished patient-level run:

| Attack | Boundary | Refusal |
|---|---|---|
| less noise, a higher sampling rate, a larger clip, or records as the unit | every DP-SGD setting is in the training spec, so the key broker refuses | ENC2002 |
| leave a patient's records ungrouped | the spec's grouping must match each dataset's | ENC2501 |
| ten unaccounted local steps per round | DP-SGD takes one accounted step per round | ENC2501 |
| give each record its own patient ID | the dataset digest covers the patient IDs | refused |
| contribute an unclipped vector without the attested worker | DP-SGD rounds accept only attested contributors, at the coordinator and at each party | ENC2106 / ENC2101 |
| label organization-level training as patient-level | the planner requires per-example clipping and sampling | ENC2401 |
| Poisson-sample whole hospitals | which parties contribute is public; the compiler refuses | ENC2203 |
| record organization-style training under a patient-level program | the trust report's Training row checks the unit | NOT SATISFIED |
| more rounds than the budget affords | the preview denies it before training | ENC2201 |

`python/tests/test_dpsgd.py` also checks:

- the vectorized gradients match a one-patient-at-a-time reference, for
  any microbatch size;
- a canary patient with 30 records moves the sum by at most the clip;
- sampling ignores every seed;
- the ledgers charge exactly what the preview projected;
- accuracy stays within a bound of non-private training.

## What Encompute guarantees

- The released adapter is (ε, δ)-differentially private per patient, for
  each hospital's patients, with the stated ε and δ. Adding or removing
  one patient (all of their records) changes a hospital's contribution by
  at most the clip. The accountant charges that bound, amplified by
  Poisson sampling, composed over rounds, and rounded up.
- The accountant agrees with an independent implementation (autodp, and a
  60-digit mpmath evaluation of the same theorem) and is never below it.
- A run over budget never starts. Every released round is charged, even if
  the run later crashes.
- A patient-level claim needs per-example clipping. The compiler, the
  planner and the trust report each refuse the claim without it.

## What Encompute does NOT guarantee

- **Central noise, trusted coordinator.** The noise is added by ModelCo's
  coordinator, which is attested under the strong profile. It is not
  distributed noise: a coordinator that could skip the noise would see the
  un-noised sum of clipped gradients, though never an individual
  hospital's.
- **Clipping and sampling run in the attested worker.** Secure aggregation
  bounds only each coordinate, so a DP-SGD round accepts only contributions
  from attested workers running the bound training code. Per-patient
  clipping and fair sampling rest on that attestation. Here attestation is
  a mock, and the contribution key comes from the party's key file; in a
  deployment it must be created inside the TEE.
- **The patient IDs must be right.** If a hospital's records of one person
  carry two IDs, that person counts as two units. The digest makes the
  grouping fixed and auditable, but not correct.
- **Patient counts are shared.** Each hospital's number of patients is in
  the training spec, because it sets the sampling rate and the update's
  scale.
- **Accuracy costs something.** A tiny model and synthetic data show the
  mechanism, not production accuracy.

## Relevant source modules

- `python/encompute/torch/dpsgd.py`: per-example gradients, grouping,
  clipping and Poisson sampling.
- `python/encompute/_privacy.py`: `encompute.Privacy` and the patient
  levels.
- `crates/encompute-privacy/src/rdp.rs`: the Rényi DP accountant.
  `tests/reference/` holds the independent reference vectors.
- `crates/encompute-training/src/spec.rs`: `DpSgdConfig` in the training
  spec.
- Design notes: `docs/adr/0017-patient-level-dp.md`.
