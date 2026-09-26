# 13 — Assurance suite

## What this demonstrates

How to run the assurance report and read what it says. Every security
claim Encompute makes is an invariant with a stable ID (`INV-nnn`) and four
kinds of evidence: positive, negative, adversarial and end to end. The
report runs the assurance checks, confirms that every test the catalog
cites still exists, and ends with one verdict:

```text
All tested security invariants satisfied.
```

`run.sh` runs six fast checks (about a second), writes the JSON and
Markdown reports, summarizes them, and then shows the report failing when a
cited test disappears.

## Threat model

The adversary here is drift, not an attacker: a refactor that deletes or
renames the test behind a claim, or a change that breaks a property no one
re-checked. The report is the release gate that catches both. The threat
models behind the invariants themselves are in `docs/threat-model.md`.

## Architecture

```text
catalog.rs (INV-001 ... INV-115)
   │  each invariant cites checks and tests
   ├─► checks (src/checks/*): run now, at quick or nightly scale
   └─► test references: confirmed to exist (they run in cargo test / CI)
            │
            ▼
assurance-report ─► per-check lines, JSON, Markdown, exit 0 or 1
```

## Run it

```sh
cargo build --release -p encompute-assurance --bins --examples   # a few minutes
examples/13_assurance_suite/run.sh
```

`run.sh` uses `target/release/assurance-report`, or the debug build if
that is all there is, and skips if neither exists. The full report:

```sh
./target/release/assurance-report --json assurance-report.json --md assurance-report.md
./target/release/assurance-report --nightly     # larger populations
./target/release/assurance-report --only dp_crash_injection
```

The full quick report takes about 11 seconds in a release build here.

## Expected output

```text
ok   execution_receipt_mutation
ok   secagg_coordinator_sees_no_input
ok   dp_invalid_noise
ok   dp_ledger_tampering
ok   planner_adversarial
ok   planner_plan_id_binding
All tested security invariants satisfied.

Scale            quick
Check            dp_invalid_noise                     pass  5 cases
Check            dp_ledger_tampering                  pass  12 cases
Check            execution_receipt_mutation           pass  80 cases
Check            planner_adversarial                  pass  13 cases
Check            planner_plan_id_binding              pass  576 cases
Check            secagg_coordinator_sees_no_input     pass  5 cases
Invariants       52, 52 satisfied
Tracked gaps     INV-010, INV-053, INV-061, INV-065, INV-070, INV-071, INV-081, INV-101, INV-103, INV-111, INV-114
Scope            Testing shows the documented invariants held for the tested cases, modes and boundaries; it does not prove the system secure.

INVARIANTS VIOLATED: INV-041
  INV-041: crates/encompute-keybroker/tests/release.rs has no test untrusted_workloads_receive_no_key
```

The invariant count and gap list change as the catalog grows.

## Try breaking it

`run.sh` builds a copy of the repository (symlinks) in which one test in
`crates/encompute-keybroker/tests/release.rs` is renamed, and runs the
report against it with `--root`. The report names the invariant whose
evidence vanished and exits 1.

Also try running the report from another directory without `--root`:
every cited file is then missing and every invariant is reported violated.

## What Encompute guarantees

- The report exits 1 if any check fails, panics or does not run, or if any
  cited test or script no longer exists. CI uses that exit code as the
  release gate.
- Each run records its scale and how many cases every check tried.
- Invariants with a missing kind of evidence are listed as tracked gaps,
  never silently counted as covered.

## What Encompute does NOT guarantee

- Tests provide evidence for documented invariants; they do not
  mathematically prove the system secure. A passing report means the
  invariants held for the tested cases, modes and boundaries.
- The report confirms cited tests exist; it does not run them. They run in
  `cargo test` and the CI jobs that build their features (OpenFHE,
  verified execution; TFHE-rs in research CI).
- Nothing here establishes the security of the cryptography itself or of
  TEE hardware, or covers properties no invariant states.
- This example runs six of the fourteen checks, at quick scale.
- `--only` with a misspelled check name runs nothing and still prints the
  passing verdict (exit 0). Read the per-check `ok` lines, not only the
  last line.

## Relevant source modules

- `crates/encompute-assurance/src/catalog.rs`: the invariants and their
  evidence.
- `crates/encompute-assurance/src/checks/`: the assurance checks.
- `crates/encompute-assurance/src/report.rs`: the report, reference
  checking, JSON and Markdown.
- `docs/assurance.md`: the matrix, CI jobs and known gaps.
