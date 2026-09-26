# 19 — Exact programs on OpenFHE exact

## What this demonstrates

Exact programs (integers and Booleans) run encrypted on **OpenFHE exact**:
OpenFHE's BinFHE scheme, one ciphertext per bit, every gate bootstrapped.
This is the production exact backend. It uses only OpenFHE (BSD-2-Clause),
so no TFHE-rs or other Zama code ships in commercial builds.

The language and the compiled plan do not change. The same `ExactPlan` that
runs on the mock runs on OpenFHE exact, and every mode must agree bit for
bit:

- **Boolean logic:** `member & consent & ~flagged`.
- **A lookup:** `TIERS[score >> 5]`, a public table read at an encrypted
  index, evaluated as a multiplexer tree.
- **The eligibility rule** from example 02 (comparisons, constant
  multiplication, Boolean AND), run by a separate evaluator process. The
  evaluator returns a signed receipt, and anyone holding the files can
  verify it.

Then it attacks every binding the evaluator and the client check.

## Threat model

The evaluator is honest-but-curious about the data: it runs the program
but would like to learn ages, incomes and decisions. It holds only the
evaluation keys (bootstrapping and key-switching keys), never a secret key.

The network and other clients are active attackers. They can edit, splice
and replay envelopes, and recompute any checksum. The client holds its
secret key and trusts its own artifact.

## Architecture

```text
client (alice)                                  evaluator (openfhe-exact)
compile → keys generate ─ eval.keys (524 MiB) ─► holds evaluation keys only
age, income, debt, risk ─ encrypt bit by bit ─► gates on ciphertexts
eligible ◄───────── decrypt ◄──── encrypted Boolean + signed receipt
```

Every ciphertext carries:

- the backend (`openfhe-exact`);
- the parameter-set ID (a hash of the vetted profile
  `BINFHE_STD128_GINX_BITS_V1`);
- the client's key ID;
- its element type;
- a checksum.

The request envelope around the ciphertexts binds the program ID, the key
ID and the parameter set.

## Run it

```sh
cargo build --release --bins -p encompute-cli -p encompute-evaluator \
  --features encompute-cli/openfhe,encompute-evaluator/openfhe
maturin develop --release -m crates/encompute-py/Cargo.toml --features openfhe
BIN=target/release examples/19_openfhe_exact/run.sh
```

The run takes about two minutes on one machine. Key generation takes about
7 seconds per client. Each gate costs about 60 ms, and the eligibility rule
needs a few hundred gates, so one remote run takes about 30 seconds. The
evaluation keys are 524 MiB per client. Without the `openfhe` build, the
script prints `SKIPPED`.

## Expected output

```text
  scheme                  BinFHE
  backend                 openfhe-exact 1.5.1
  parameter profile       BINFHE_STD128_GINX_BITS_V1
  bootstrapped gates      19 (the same for every input; ~60 ms each on one core)
  failure probability     2^-135 per gate
screen(member, consent, not flagged)     clear=True  mock=True  encrypted=True  MATCH
tier(score=200)                          clear=2     mock=2     encrypted=2     MATCH
...
alice (age 31): encrypted=True clear=True MATCH
bob   (age 17): encrypted=False clear=False MATCH
RECEIPT VERIFIED
secret.key files in the evaluator's directory: 0
```

## Try breaking it

`forge.py` edits envelopes the way a network attacker could. It recomputes
the outer checksum, so a refusal comes from a binding check, not from the
checksum. `run.sh` requires every one of these to be refused:

| Attack | Refused by |
|---|---|
| bob's encrypted `age` spliced into alice's request | ENC1605: a ciphertext under another key |
| alice's ciphertexts sent against bob's evaluation keys | ENC1605 |
| a ciphertext whose parameter-set ID was edited | ENC1603: another parameter set |
| the request relabelled for `tfhe-rs` | ENC1602: made for TFHE on tfhe-rs |
| one ciphertext bit flipped | ENC1601: the ciphertext's own checksum |
| the evaluator runs a modified plan (`age >= 16`) on alice's request | ENC1604: made for a different program |
| the client runs an edited artifact | ENC1401: manifest hash mismatch |
| alice's receipt replayed as evidence for bob's result | `INVALID: receipt output commitment does not match` |
| decrypting with only what the evaluator holds (`eval.keys`) | no secret key |
| `income * 1_000_000` in a `u32` program | ENC1303: possible integer overflow, at compile time |
| a 1001-entry lookup (`wide.py`) | ENC1501: tables are limited to 256 entries, at compile time |
| selecting TFHE-rs in a production build (`ENCOMPUTE_RESEARCH_EXACT_BACKEND=tfhe-rs`) | ENC1501: BACKEND UNAVAILABLE |
| `encompute-evaluator serve --backend tfhe-rs` in a production build | BACKEND UNAVAILABLE |

Replaying alice's *request* is not refused. The evaluator computes the same
encrypted answer again, and only alice can decrypt it.

## What Encompute guarantees

- Exact results: the encrypted result equals the clear reference and the
  mock, with no tolerance. OpenFHE exact is tested against both on every
  operation, exhaustively for 8-bit types, and against TFHE-rs in research
  CI.
- The gate count depends only on the program, never on the inputs, and
  `explain` prints it.
- The parameter profile is fixed and bound into every artifact, key and
  ciphertext: 128-bit security, failure probability 2^-135 per gate.
  Objects made for another profile, key, backend or program are refused.
- Operations outside the capability matrix are refused at compile time,
  not partway through an encrypted run.
- Production builds cannot select TFHE-rs, and
  `scripts/audit-commercial-build.sh` checks that no TFHE-rs code is linked.

## What Encompute does NOT guarantee

- A receipt is a signed claim, not a proof: the evaluator could sign a
  wrong answer. BinFHE execution has no proof backend yet. Example 05 shows
  verified execution on BGV for a smaller subset.
- The checksums detect accidents, not forgeries. Integrity against a
  network attacker comes from the key, program and parameter bindings, and
  from the receipt, which binds the exact request and response bytes.
- Evaluation is slow: about 60 ms per gate on one core. The evaluation keys
  are large (524 MiB).
- Ciphertext sizes, gate counts and timings are visible to the evaluator.
  They depend on the program and input types, not on the values.
- Input ranges are checked by the client before encryption; the evaluator
  cannot check them on ciphertexts.

## Relevant source modules

- `crates/encompute-exact/src/bits.rs`: the bit-level circuits (adders,
  comparators, multiplexers, division by constants, lookups) and the
  capability matrix.
- `crates/encompute-openfhe-exact`: the backend's envelope, parameter
  profile and gate binding.
- `crates/encompute-openfhe/cpp/binfhe.cc`: the evaluator side of OpenFHE
  BinFHE.
- `crates/encompute-openfhe-client/src/exact.rs`: client key generation,
  encryption and decryption.
- `scripts/audit-commercial-build.sh`: the commercial dependency audit.
- `docs/adr/0020-openfhe-exact.md`.
