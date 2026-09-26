# 05 — Verified execution

## What this demonstrates

**A receipt is not a correctness proof.** Example 04 shows that a receipt
binds what the evaluator claims to have run: the program, the keys, the
exact request and the exact response. An evaluator can sign a wrong answer
just as easily as a right one. This example is about the other half: a
proof that the response is the correct evaluation of the program over the
request.

```python
@encompute.compile(verification="required")
def precheck(income: secret[u16, 0:5000], member: secret[bool_], flagged: secret[bool_]):
    return {"score": income * 3 + 7, "ok": member & ~flagged}
```

`verification="required"` restricts the program to the proven subset
(u8, u16, bool; add, sub, mul, constants; and, or, xor, not). It compiles
to OpenFHE BGV, and every result must carry an execution proof. The client
re-runs the computation over the exact ciphertexts it sent, with its own
evaluation keys, and decrypts only if the response matches byte for byte:
no proof, no decryption.

What runs depends on the build:

| Step | This build (no OpenFHE) | Research build |
|---|---|---|
| compile, proof coverage 100% | runs | runs |
| semantic transcript | runs | runs |
| uncovered program refused (ENC1801) | runs | runs |
| planner refuses (`PLANNING FAILED`), keys refused (ENC1501) | runs | — |
| mock remote run: receipt only, `EXECUTION PROOF NOT PRESENT` | runs | — |
| BGV remote run, `VERIFIED PRIVATE EXECUTION` | SKIPPED | runs |
| offline `encompute verify --proof`, `EXECUTION VERIFIED` | SKIPPED | runs |
| tampered proof, replayed output rejected | SKIPPED | runs |

The research-build rows were not run for this README; their commands are
in `run.sh`.

## Threat model

The evaluator is malicious: it may return a random, replayed, substituted
or mutated result, or skip operations, and still sign a valid receipt for
it. It never holds the secret key. The client is trusted and keeps its
evaluation keys, which it needs to check the proof.

## Architecture

```text
client                                          evaluator (BGV)
request (ciphertexts) ───────────────────────►  evaluate transcript T
response, receipt, proof ◄──────────────────────┘
re-execute T on request with eval.keys
response == re-execution ? decrypt : refuse (ENC1801)
```

The proof protocol is `reexecution-v1`: sound, not succinct. Checking
costs about one evaluation.

## Run it

```sh
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/05_verified_execution/run.sh      # this build: checks, then SKIPPED
```

The verified path needs OpenFHE and the research verifier; the repository
README gives `--features vfhe-research` (implies `openfhe`) for the CLI,
and the evaluator needs its `openfhe` feature. `examples/run-all.sh full`
includes this example.

## Expected output

In this build:

```text
  scheme                  BGV
  verification            required
  proof backend           reexecution-v1 (sound, not succinct: verifying costs one evaluation)
  proof coverage          100%
  execution proof         REQUIRED: results are decrypted only after the proof verifies
Instructions
0003 MUL_CONST  r0 3               -> r3 : u16
0004 ADD_CONST  r3 7               -> r4 : u16
0005 NOT        r2                 -> r5 : bool
0006 AND        r1 r5              -> r6 : bool
ATTACK   require verification for a comparison (outside the proven subset)
REFUSED  exit 2: error[ENC1801]: this program cannot be fully verified: unsupported proof operation GE_CONST ...
ATTACK   plan a verified run without OpenFHE BGV
REFUSED  exit 1: PLANNING FAILED
ATTACK   generate BGV keys without OpenFHE
REFUSED  exit 2: error[ENC1501]: this program requires verified execution on OpenFHE BGV; ...
Evaluator receipt       verified
Execution proof         not present
Encrypted result        accepted (receipt only)
RECEIPT VERIFIED
EXECUTION PROOF NOT PRESENT
SKIPPED
Reason: verified-execution unavailable in this build (see README: Build)
```

In the research build, `run.sh` requires `VERIFIED PRIVATE EXECUTION` from
the remote run and `EXECUTION VERIFIED` from `encompute verify --proof`.

## Try breaking it

- Require verification for a comparison (`uncovered.py`: `age >= 18`):
  compilation fails with ENC1801 and reports the coverage (50%). Encompute
  never silently falls back to receipts.
- Plan the program in a build without OpenFHE: `PLANNING FAILED`, "no
  requirement was weakened".
- Research build only (not run here): flip one bit of `proof.bin`, or pair
  the receipt with the response of another run; `encompute verify` must
  reject both.
- A malicious evaluator (random output, replayed output, skipped operation,
  substituted program, mutated ciphertext) signing valid receipts: the
  evaluator binary has no switch for these. They are exercised in
  `crates/encompute-runtime/tests/vfhe.rs` (`malicious_evaluator_is_caught`,
  research build):
  `cargo test -p encompute-runtime --features vfhe-research --test vfhe`.

## What Encompute guarantees

- With `verification="required"`, a program outside the proven subset does
  not compile (ENC1801), and a build that cannot verify refuses to plan or
  generate keys rather than run unverified.
- In the research build, the client decrypts only after the execution
  proof verifies: a result the evaluator computed wrongly is rejected even
  with a valid receipt.
- The transcript lists operations only, never runtime values.

## What Encompute does NOT guarantee

- A receipt alone (example 04, and the mock run here) proves only that the
  evaluator signed the bindings. `accepted (receipt only)` means the result
  was not checked.
- Mock runs are never verified: a mock evaluator is accepted on its receipt
  even for a `verification="required"` program, and labelled so.
- The proof is re-execution: sound, not succinct. Checking costs about one evaluation on the client.
- Only the small exact subset is covered: no comparisons, no CKKS, no
  lookups.
- Proofs do not cover confidentiality leaks through sizes or timing, or a
  client that chose wrong inputs.
- This is research code: the verified path did not run in this build.

## Relevant source modules

- `crates/encompute-vfhe`: the re-execution proof backend.
- `crates/encompute-verification`: receipts, transcripts, proofs.
- `crates/encompute-runtime/src/client.rs`: `decrypt_proven` (no proof, no
  decryption).
- `crates/encompute-runtime/tests/vfhe.rs`: honest and malicious evaluators.
- `crates/encompute-cli`: `transcript`, `verify --proof`.
- `docs/adr/0007-verifiable-execution.md`,
  `docs/adr/0008-semantic-transcripts.md`,
  `docs/adr/0009-vfhe-proof-backend.md`.
