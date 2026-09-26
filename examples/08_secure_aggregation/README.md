# 08 — Secure aggregation

## What this demonstrates

Hospitals A, B and C each hold a private gradient of 16 values, declared
`release aggregate_only` in `fedavg.eir`. Each hospital runs its own
participant process (`encompute aggregate join`), and a separate coordinator
process (`encompute aggregate serve`) runs one secure-aggregation round. The
coordinator receives only the sum of the three vectors; no single hospital's
vector ever leaves that hospital's process unmasked.

The script then checks that:

- the secure aggregate equals the clear sum A+B+C, within the fixed-point
  codec's resolution (each value is rounded to 1/65536, so the sum of three
  is within 3 × 0.5/65536);
- none of the individual values, or their fixed-point codes, appear in the
  aggregate, the signed receipt or the coordinator's log;
- `encompute aggregate verify` accepts the receipt and the aggregate.

The test vectors (`hospital-*.json`) are plaintext files only because this
is a demo; in a deployment each stays on its hospital's machine.

## Threat model

The coordinator is untrusted with the inputs: it may be curious, drop
messages, replay old rounds or offer a weaker spec. It must not learn any
single hospital's vector. Up to 2 hospitals may collude with it (the
program declares `colluding 2`). Parties outside `parties.json` must not be
able to contribute. Each hospital trusts its own process and key.

## Architecture

```text
Hospital A process ─┐  masked vector + secret-shared mask seeds
Hospital B process ─┼──────────────────────────────►  coordinator process
Hospital C process ─┘  (signed with keys from parties.json)   │
                                                              ▼
                                  aggregate.json (A+B+C) + aggregation-receipt.json
```

The masks cancel only in the sum. Recovering a dropped party's mask needs a
threshold (here 3) of shares, so a coordinator with fewer cannot unmask.

## Run it

```sh
cargo build --bins
examples/08_secure_aggregation/run.sh
```

Each attack also runs alone, e.g. `examples/08_secure_aggregation/attack-replay.sh`.

## Expected output

```text
Hospital A  CONTRIBUTION ACCEPTED (only the aggregate is released)
...
AGGREGATION COMPLETE
Contributors    hospital-a, hospital-b, hospital-c
Clear A+B+C       +0.18 -0.03 +0.65 +0.12 -0.22 -0.30 +0.57 +0.30 +0.24 +0.61 +0.26 -0.21 -0.15 +0.67 -0.22 +0.27
Secure aggregate  +0.18 -0.03 +0.65 +0.12 -0.22 -0.30 +0.57 +0.30 +0.24 +0.61 +0.26 -0.21 -0.15 +0.67 -0.22 +0.27
Max difference    1.65e-05 (codec resolution: 3 x 0.5/65536 = 2.29e-05)
PASS
Hospital A values found in the output, receipt or log: 0
...
NO INDIVIDUAL VECTOR RELEASED
AGGREGATION RECEIPT VERIFIED
```

## Try breaking it

`run.sh` runs all four scripts; each also runs on its own and prints the
attack, the refusal and the boundary that refused it.

| Script | Attack | Result |
|---|---|---|
| `attack-unauthorized-party.sh` | Hospital D, not in `parties.json`, joins; then joins as `hospital-a` with its own key | ENC2101 `party hospital-d is not authorized for aggregation spec ...`; ENC2101 `this identity key is not party hospital-a's key for the round` |
| `attack-below-threshold.sh` | Only A and B show up (minimum 3) | ENC2103 `only 2 parties advertised keys; the round needs 3 (aborted: no aggregate is released)`; no aggregate or receipt is written |
| `attack-replay.sh` | A second copy of Hospital A submits in the same round; then the coordinator replays round 1 to A | ENC2102 `coordinator: hospital-a already submitted this round's message`; ENC2102 `round 1 is not newer than round 1 already joined (replay)` |
| `attack-wrong-round.sh` | After round 2, the coordinator offers round 1; then a round 3 whose spec lowers the minimum to 2 | ENC2102 `round 1 is not newer than round 2 already joined (replay)`; ENC2102 `the coordinator's aggregation spec is not the approved one: they differ in: program, PolicyID, minimum or collusion bound` |

The two Hospital D attacks are refused by D's own (unmodified) client
before anything is sent; the coordinator applies the same checks to every
message it receives, but this demo does not send a forged message.

## What Encompute guarantees

- The coordinator sees only masked vectors and the final sum, including
  when it colludes with up to the declared 2 hospitals.
- Only parties in `parties.json` can contribute, and every message is
  signed by the party's listed key.
- Below the minimum number of parties the round aborts and nothing is
  released.
- Each contribution is bound to one round of one approved spec. A party
  refuses a spec that differs from the one it approved, and refuses any
  round not newer than the last it joined (`--state`).
- The receipt binds the round, spec, policy, contributors and a commitment
  to the aggregate, and is signed by the coordinator.

## What Encompute does NOT guarantee

- Secure aggregation does not stop leakage from the aggregate itself. With
  three hospitals, the sum plus any two vectors gives the third; repeated
  rounds with different participants allow differencing. Bounding what the
  aggregate reveals needs differential privacy (example 09).
- The aggregate is not proven correct. A malicious coordinator can abort a
  round or publish a wrong sum; the receipt is a signed claim about who
  contributed under which spec, not a proof that the sum is right.
- A hospital can contribute any vector within the clip range: there is no
  input validation or poisoning defence. Values outside the clip range are
  clipped silently.
- The `--state` file is the party's replay protection. A party that loses
  or resets it can be made to rejoin an old round.
- Collusion beyond the declared bound (here, the coordinator plus all
  other hospitals) reveals the remaining input, by definition of a sum.
- Nothing here attests the coordinator or the hospitals' workloads; that is
  example 07 and `aggregate serve --coordinator-policy`.

## Relevant source modules

- `crates/encompute-secagg/src/protocol.rs`: the masking protocol, threshold
  shares, per-party message checks.
- `crates/encompute-secagg/src/round.rs`: aggregation specs, round binding,
  the replay check, receipts.
- `crates/encompute-secagg/src/service.rs`: the coordinator's HTTP service
  and the participant client.
- `crates/encompute-cli`: `aggregate identity | serve | join | verify`.
- `docs/adr/0012-secure-aggregation.md`, `docs/errors.md` (ENC2101–ENC2106).
