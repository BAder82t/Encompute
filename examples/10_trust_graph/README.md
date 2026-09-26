# 10 — Trust graph

## What this demonstrates

Everything a collaboration produces, collected in one trust bundle and
checked as one trust report. Hospitals A, B and C sum their gradients
through a coordinator; each hospital's gradient is aggregate-only and has a
patient-level privacy budget (ε 3, δ 1e-6). The example:

1. compiles the program (`fedavg.eir`) and plans it (`encompute plan -o`):
   secure aggregation plus differential privacy;
2. starts a bundle with the program, the plan and the consortium's keys
   (`trust init`), and each hospital approves the program for its gradient
   (`trust authorize`);
3. runs one real secure-aggregation round with discrete Gaussian noise
   (`aggregate serve --trust-bundle --plan --ledger` and three
   `aggregate join` processes); the coordinator records the round's signed
   receipts in the bundle;
4. prints the trust report, the lineage of `gradient-a` and the graph
   (Graphviz DOT);
5. doctors copies of the bundle six ways. Each is refused with
   `TRUST REQUIREMENTS NOT SATISFIED` and the failing row.

Keys come from the verifier, never from the bundle. `trust report` checks
signatures only against the party keys (`--parties parties.json`) and the
coordinator key (`--coordinator-key`) that the auditor obtained out of band.
The bundle also carries public keys, but a bundle that could vouch for
itself would prove nothing: evidence without a trusted key is reported as
`PRESENT (not checked)`, and the report is then not satisfied.

## Threat model

Whoever hands over the bundle (the coordinator, a hospital, a cloud
operator) may edit it: delete evidence, change receipts, add or swap plans,
or re-sign things with keys of their own. The auditor trusts only the keys
it holds and the program text. The hospitals trust the coordinator's key
only because they received it out of band.

## Architecture

```text
fedavg.eir ─ compile ─ plan -o ─► plan.json
                               │
trust init (program, plan, parties.json) ─► trust.json ◄─ trust authorize (A, B, C)
                               ▲
aggregate serve --trust-bundle ┘  ◄── masked gradients ── aggregate join (A, B, C)
  (round receipt + privacy receipts, noise charged to each ledger)

auditor: trust report --parties parties.json --coordinator-key <hex>
  rebuilds the graph from the evidence alone, checks every signature
  against its own keys, and compares the round with the approved plan
```

## Run it

```sh
cargo build --bins
examples/10_trust_graph/run.sh
```

Needs only the `encompute` CLI and Python 3 (to edit bundle copies). The
round runs on localhost with three join processes.

## Expected output

IDs and keys differ per run; they are shortened here.

```text
== One secure-aggregation round with differential privacy ==
AGGREGATION COMPLETE
Contributors    hospital-a, hospital-b, hospital-c
Minimum         3 (threshold 3, private against 2 colluding)
Privacy         epsilon 0.7410674902696281 spent of 3.0 (this round 0.7410674902696281)

== Trust report (keys from the verifier, never from the bundle) ==
TRUST REPORT
bundle 8e431ed035a8022d

Evidence                VERIFIED
Program                 VERIFIED
Policy                  VERIFIED
Plan                    SATISFIED
Owner authorization     AUTHORIZED
Workload                NOT PRESENT
Private aggregation     VERIFIED
Privacy budget          SATISFIED
Execution               NOT PRESENT
Lineage                 COMPLETE

RESULT
TRUST REQUIREMENTS SATISFIED
PLAN SATISFIED BY OBSERVED EXECUTION

== Lineage of gradient-a ==
asset:gradient-a
  derived from: {}
  derived into: {"aggregate:ccf0fad88b4f6701.."}
```

`Workload` and `Execution` are `NOT PRESENT`: this collaboration has no
attested workloads or evaluator receipts. They are not required here; pass
`--require Workload` to make an absence fail (`Workload is required but
not present`).

## Try breaking it

`run.sh` runs each of these on a copy of the bundle. Each report exits 1.

| Attack | Failing row | Reason printed |
|---|---|---|
| Delete `gradient-a`'s privacy receipt | Evidence FAILED | `edge aggregate:.. -ReleasedBy-> privacy:.. implied by the evidence is missing` |
| Edit a privacy receipt (noise multiplier 6.0 → 60.0) | Evidence FAILED | `privacy:..: privacy:.. already has different evidence` |
| Hospital A revokes `gradient-a` (`trust revoke`) | Owner authorization FAILED | `gradient-a: no valid authorization from hospital-a for program:..`, plus `Revoked ... (retrain or unlearn)` |
| Report with no trusted keys | Owner authorization, Private aggregation, Privacy budget PRESENT (not checked) | `no trusted key for hospital-a`, `coordinator .. is not trusted` |
| Trust a different coordinator key | Private aggregation FAILED, Privacy budget FAILED | `coordinator .. is not trusted`, `signer .. is not a trusted coordinator` |
| Approve a different plan (`plan --prefer cost`, `trust add`) | Plan FAILED | `round:.. did not run under the approved plan` |

Why the edited receipt fails: the report rebuilds the graph from the signed
evidence alone. The round's signed aggregation receipt carries the original
privacy receipts, so an edited copy contradicts it. A deleted receipt is
still implied by the round receipt, so its absence is detected too.

## What Encompute guarantees

- The report is derived from evidence, not from the bundle's own nodes and
  edges. Any difference between the two fails the report.
- Signatures are checked only against keys the verifier supplies. Nothing
  in the bundle can make itself trusted, and unchecked evidence never
  counts as satisfied.
- Each round is bound to the approved plan's ID. A bundle that approves a
  different plan than the one the round ran under fails.
- A revocation lists everything derived from the revoked asset.

## What Encompute does NOT guarantee

- The report checks what was recorded. A coordinator that runs a round
  and never adds it to the bundle leaves no trace. Owners still enforce
  budgets at contribution time, and `--require` makes an absence explicit.
- A verified aggregation receipt is a signed claim by the coordinator, not
  a proof that the sum was computed correctly.
- Secure aggregation and differential privacy protect individual
  gradients, not everything the aggregate reveals. With noise multiplier
  6.0 and ε 3, the budget bounds that leakage; it does not remove it.
- The answer is never better than the keys supplied. If the auditor gets
  the coordinator's key from the coordinator's own bundle, it proves
  nothing.
- Revocation stops future use and names the derived aggregates. It does
  not remove what a model has already learned: retraining or unlearning is
  up to the parties.
- The gradients here are small fixed vectors (4 values, one round). No
  model is trained.

## Relevant source modules

- `crates/encompute-trust/src/report.rs`: the trust report and its rows.
- `crates/encompute-trust/src/ingest.rs`, `graph.rs`: rebuilding the graph
  from evidence.
- `crates/encompute-trust/src/authz.rs`: authorizations and revocations.
- `crates/encompute-cli/src/trust.rs`, `aggregate.rs`: the CLI.
- `docs/adr/0014-trust-graph.md`: the design.
