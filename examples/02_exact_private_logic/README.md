# 02 — Exact private logic

## What this demonstrates

A business rule over private integers becomes an encrypted computation with
no approximation error:

```python
@encompute.compile()
def eligible(age: secret[u8, 0:120],
             income: secret[u32, 0:1_000_000],
             risk: secret[u16, 0:1000]):
    return (age >= 18) & (income >= 40_000) & (risk <= 650)
```

Comparisons (`>=`, `<=`) and Boolean `&` compile to TFHE. The rule runs on
five inputs placed on or next to each threshold, in each available mode,
and every mode must give exactly the same answer:

| Mode | What runs | Needs |
|---|---|---|
| clear | the reference semantics, in plaintext | nothing |
| mock | the compiled TFHE plan, without encryption | nothing |
| encrypted | the plan on TFHE-rs ciphertexts | the research `tfhe-rs` build |

Then 500 sampled inputs are compared (exact match, no tolerance).

It also shows the two contracts an exact program carries: declared input
ranges, enforced before anything is encrypted, and overflow freedom, proven
at compile time for every input in range.

`eligibility.py` is a second, larger rule (with a debt-to-income ratio). It
is the program `scripts/exact-demo.sh` runs against a remote TFHE-rs
evaluator.

## Threat model

The evaluator is honest-but-curious: it runs the program but wants to learn
the applicant's age, income, risk score and the decision. The client holds
the secret key and is trusted to supply inputs within the declared ranges;
the client library checks them before encrypting.

## Architecture

```text
client                                        evaluator
age, income, risk ─ range check ─ encrypt ─►  (age>=18) & (income>=40000)
                                              & (risk<=650) on ciphertexts
eligible (bool) ◄──────────── decrypt ─────── encrypted Boolean
```

## Run it

```sh
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/02_exact_private_logic/run.sh
```

The encrypted mode needs the research build (TFHE-rs; commercial use needs
a patent license from Zama). Without it, the script says
`Encrypted mode    not run: TFHE-rs is not in this build`.

## Expected output

```text
Scheme            exact (TFHE: integers and Booleans)
Encrypted mode    not run: TFHE-rs is not in this build
age=31 income=52000 risk=410       clear=True  mock=True   MATCH
age=18 income=40000 risk=650       clear=True  mock=True   MATCH
age=17 income=52000 risk=410       clear=False mock=False  MATCH
age=31 income=39999 risk=410       clear=False mock=False  MATCH
age=31 income=52000 risk=651       clear=False mock=False  MATCH
Sampled inputs    500 cases, 0 mismatches
MATCH
...
  integer overflow        proven: no operation overflows for inputs in range
  result semantics        exact (no approximation error)
```

## Try breaking it

`run.sh` runs each of these and requires the refusal:

- An input outside its declared range (`age=130`, `income=-1`): refused
  with ENC1102 before encryption. The evaluator cannot check ranges on
  ciphertexts, so the client does.
- A fractional value for an integer input (`age=31.5`): ENC1102.
- `unsafe.py` multiplies a `u32` income in `[0, 1_000_000]` by 1,000,000.
  The product can reach 10^12, which does not fit in `u32`: compilation
  fails with ENC1303 (possible integer overflow). Nobody can see an overflow
  on ciphertexts, so Encompute refuses the program rather than risk a
  wrong answer.

## What Encompute guarantees

- Exact semantics: the compiled plan computes the same integers and
  Booleans as the Python function, with no approximation error, for every
  input in the declared ranges.
- No operation overflows its type for any input in range; programs where
  one could are rejected at compile time.
- Out-of-range, missing and non-integer inputs are rejected before
  encryption.
- The evaluator never receives the secret key: it sees ciphertexts in and
  returns a ciphertext out.

## What Encompute does NOT guarantee

- In this build the encrypted mode did not run: mock mode checks the plan
  but encrypts nothing.
- The decision itself is revealed to whoever decrypts it. If the client
  shares `eligible`, anyone can probe the rule with chosen inputs and learn
  the thresholds (here they are public constants anyway).
- The evaluator can return a wrong or stale ciphertext. Receipts
  (example 04) bind what it claims to have run; verified execution
  (example 05) checks the computation.
- Ranges are a contract on the client's inputs, not a check the evaluator
  can enforce: a client that bypasses the library can encrypt anything.
- Ciphertext sizes and timings are visible to the evaluator.

## Relevant source modules

- `python/encompute/_frontend.py`: tracing Python into the IR.
- `crates/encompute-analysis/src/exact.rs`: range and overflow analysis.
- `crates/encompute-exact`: lowering exact programs to TFHE.
- `crates/encompute-ir/src/eval.rs`: reference semantics and input checks.
- `crates/encompute-tfhe`, `crates/encompute-tfhe-client`: TFHE-rs backend.
- `docs/adr/0006-exact-programs.md`.
