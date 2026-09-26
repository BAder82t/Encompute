# 09 — Differential privacy budgets

## What this demonstrates

Example 08 hides each hospital's vector, but not what the sum reveals. Here
the same three-hospital secure aggregation adds discrete Gaussian noise to
every released aggregate, and each hospital's asset carries a privacy
budget (`privacy unit "patient" epsilon 1.8 delta 1e-6` in `fedavg.eir`).
The budget is deliberately small: it affords 5 releases.

`run.sh`:

1. Prints the privacy plan: mechanism, cost per release, and how many
   releases the budget affords.
2. Runs rounds, each with a new coordinator process and three hospital
   processes, printing the epsilon each round costs and the total spent
   (read from the signed privacy receipts), until round 6 is refused with
   `RELEASE DENIED` (ENC2201).
3. Restarts: every process has exited; a new coordinator process on the
   same ledger directory is still denied, and `encompute privacy budget`
   shows the same spend as before.
4. Tries to reset the budget with an empty ledger. The hospitals refuse to
   contribute (ENC2202).

## Threat model

The coordinator adds the noise and keeps the ledgers; it is trusted to add
noise (central DP) but not to keep its own books honestly. It may restart,
retry, or present a reset ledger to get more releases. Anyone who sees
released aggregates, including the coordinator, is a potential attacker on
individual patients. Hospitals trust their own processes and `--state`
files.

## Architecture

```text
Hospital A/B/C processes ──masked vectors──► coordinator process
   (each checks the ledger it is shown       │ 1. lock ledger, check budget
    against the checkpoint in its --state)   │ 2. reserve cost (fsync)
                                             │ 3. unmask sum, add discrete Gaussian noise
                                             │ 4. commit, sign privacy receipts
                                             ▼
                      round-N.json (noisy sum) + receipt-N.json   ledger/gradient-{a,b,c}.ledger
```

Costs are accounted in zero-concentrated DP (zCDP) and composed across
releases, so later rounds cost less epsilon than the first. The ledger is
one hash-chained, append-only file per asset.

## Run it

```sh
cargo build --bins
examples/09_differential_privacy/run.sh
```

In a debug build `privacy explain` takes about 13 s of the run (it computes
how many releases fit); the whole example takes about 30 s.

## Expected output

```text
  budget               gradient-a: privacy unit patient, epsilon 1.8 delta 1e-6, one release costs epsilon 0.741; the budget affords 5 releases
Round 1  PERMITTED  epsilon this round 0.741, spent 0.741 of 1.8
Round 2  PERMITTED  epsilon this round 0.333, spent 1.074 of 1.8
Round 3  PERMITTED  epsilon this round 0.261, spent 1.335 of 1.8
Round 4  PERMITTED  epsilon this round 0.224, spent 1.559 of 1.8
Round 5  PERMITTED  epsilon this round 0.200, spent 1.759 of 1.8
Round 6  DENIED     error[ENC2201]: RELEASE DENIED: asset gradient-a has spent epsilon 1.7592 of 1.8; this release would bring it to 1.9419 (delta 1e-6)
...
Round 7  DENIED     error[ENC2201]: RELEASE DENIED: asset gradient-a has spent epsilon 1.7592 of 1.8; this release would bring it to 1.9419 (delta 1e-6)
Budget after restart: unchanged (epsilon 1.759  (rho 0.06958))
```

## Try breaking it

- **Restart the coordinator** to forget the spend. `run.sh` does this: the
  new process reads the same ledger and denies the release (ENC2201).
- **Reset the ledger**: start a coordinator on an empty ledger directory.
  `run.sh` does this; Hospital A's client refuses with `error[ENC2202]:
  asset gradient-a's ledger: the ledger has 0 entries but 10 were already
  seen: it was rolled back or reset`. Each hospital's `--state` file records
  the last ledger checkpoint it saw.
- **Two coordinators racing for the last release** on the same ledger. This
  is not scripted here because a two-coordinator race is timing-dependent.
  The ledger takes an OS file lock for each release; the assurance check
  `dp_multi_process_double_spend` races separate processes for a budget
  that fits exactly one release:
  `target/release/assurance-report --only dp_multi_process_double_spend`
  (build with `cargo build --release -p encompute-assurance --bins --examples`).

## What Encompute guarantees

- Every release is charged to each contributing asset's ledger before the
  noise is drawn; a crash after reserving leaves the budget spent, never
  unaccounted.
- A release that would exceed any asset's budget is denied (ENC2201) and
  reserves nothing, by the coordinator, across restarts.
- The hospitals enforce it too: each checks the ledger the coordinator
  shows it against the checkpoint it saw last, and refuses a ledger that
  was rolled back, reset or edited (ENC2202), or a release over budget.
- Each release comes with signed privacy receipts that record the
  mechanism, noise variance, sensitivity, cost and cumulative spend, so
  anyone can recompute the accounting.

## What Encompute does NOT guarantee

- This is central DP: the coordinator unmasks the exact sum before adding
  noise. The guarantee holds against everyone who sees only released
  outputs, not against the coordinator. A coordinator that is not attested
  could release the sum without noise, and nothing here would stop it.
- DP bounds leakage only at the declared unit (here, one patient) and only
  if one patient's influence on a hospital's vector is bounded. Encompute
  clips each hospital's whole contribution to L2 norm 1; per-patient
  clipping inside the contribution is the training workload's job, and the
  compiler warns about it.
- The budget covers releases through this program's ledgers only. Anything
  the hospitals publish elsewhere about the same patients is not counted,
  and owners who approve a new policy start a new budget.
- Epsilon 1.8 is a bound, not zero leakage: each release still reveals a
  noisy sum, and the bound degrades as epsilon grows.
- A hospital that loses its `--state` file loses its view of the ledger's
  history and cannot detect a reset.
- There is no sampling amplification (every round uses every hospital), and
  timing side channels of the noise sampler are not addressed.

## Relevant source modules

- `crates/encompute-privacy/src/sampler.rs`: the discrete Gaussian sampler.
- `crates/encompute-privacy/src/accountant.rs`: zCDP accounting and the
  conversion to (epsilon, delta).
- `crates/encompute-privacy/src/ledger.rs`: the hash-chained ledger, file
  locking, rollback and reset detection.
- `crates/encompute-privacy/src/release.rs`: release checks and privacy
  receipts.
- `crates/encompute-secagg/src/round.rs`: the owner-side ledger checks when
  joining a DP round.
- `docs/adr/0013-differential-privacy.md`, `docs/assurance.md`,
  `docs/errors.md` (ENC2201–ENC2204).
