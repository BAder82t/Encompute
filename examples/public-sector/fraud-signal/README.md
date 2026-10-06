# Example C: a bounded signal released to one agency

> Read [`DISCLAIMER.md`](DISCLAIMER.md) first. `run.sh` prints it before
> anything else.

The Tax Agency holds, for each applicant, an income gap (declared minus
recorded income). The Benefit Integrity Unit may learn only a category for
one declared purpose, `benefit-integrity-2027`: 0 none, 1 low, 2 review
suggested. It never learns the gap, and nobody else learns anything.

```
examples/public-sector/fraud-signal/run.sh
```

It uses the command line and the mock backend only, so it runs in
`examples/run-all.sh quick`. The data (`data/applicants.txt`) is invented.

## What the Tax Agency declares

In the program's `asset` line, the owner allows one audience
(`integrity-unit`), one purpose, and one release form: a category bounded
by 2 (`forms [bounded_category 2]`). The compiler proves, from the ranges of
the inputs, that the released value fits; it refuses anything it cannot
prove.

## Attacks that must fail

| Attack | Refused with |
|---|---|
| Release the income gap itself | `ENC1907` (the output is only a category bounded by 100000) |
| Widen the categories to four | `ENC1907` (bounded by 3, the owner allowed 2) |
| Use the data for `debt-collection-2027` | `ENC1903` (the asset allows only `benefit-integrity-2027`) |
| Release the signal to the Housing Agency | `ENC1902` (it is not the audience) |

## What this example is not

- **It is the single-source form.** The cross-agency form of this idea (the
  records of one person at several agencies, linked) needs record linkage,
  which is not built; it will go through external cryptographic review
  before it ships. Nothing here links records.
- **The compiler's checks stand in for a governed project's.** In a
  governed project the control plane enforces the same release classes at
  submission and the key brokers check again. Two attacks of the plan's
  version of this example need that control plane, not the command line: an
  auditor running the job (`ENC2716`) and onward export of a result. They
  are in `scripts/governance-attacks.sh`.
- **It is not a fraud method.** See the disclaimer.
