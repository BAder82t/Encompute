# 00 — Hello, encrypted

A five-minute first run. One command, no services, no Rust build.

## What this demonstrates

A clinic has four private test results. A risk service has a small model.
The service scores the results without ever seeing them. The script plays
both roles in one process and explains each step as it runs:

1. the clinic's private data;
2. what the risk service is told (the program, not the data);
3. encrypt, compute while encrypted, decrypt;
4. a check of the answer against plain Python;
5. three unsafe things Encompute refuses to do.

The score is `sigmoid(weights . panel + bias)`, an approximate computation
(CKKS: an encryption scheme for real numbers, where results are correct to
a declared precision, here 0.001).

## Threat model

The evaluator is honest-but-curious: it runs the program but wants to learn
the inputs. The client holds the secret key and is trusted.

## Run it

You need Python 3.11 or later and the Python package from the release. In a
fresh virtual environment (macOS on Apple silicon shown; on Linux x86_64
use the `manylinux` wheel of the same release):

```sh
git clone https://github.com/BAder82t/Encompute && cd Encompute
python3 -m venv hello-env && . hello-env/bin/activate
gh release download v0.3.0 -R BAder82t/Encompute -p 'encompute-0.3.0-cp311-abi3-macosx_11_0_arm64.whl'
pip install ./encompute-0.3.0-cp311-abi3-macosx_11_0_arm64.whl
examples/00_hello_encrypted/run.sh
```

Check the download first if you like: [docs/verify-release.md](../../docs/verify-release.md).
The package needs nothing else. From a source checkout, `maturin develop
--features openfhe` gives the same thing. Without OpenFHE the script runs
in mock mode and says that nothing was encrypted.

## Expected output

This is the real output of the released 0.3.0 wheel (macOS arm64, Python
3.12, a clean virtual environment). The byte sizes and timings differ from
machine to machine and run to run; the rest is stable.

```text
== Score four private test results without revealing them ==
Step 1. The clinic's private data (the evaluator never sees this)
  panel = [0.62, 0.18, 0.91, 0.4]

Step 2. What the risk service is told: the program, not the data
  scheme    CKKS (approximate), 128-bit classical
  the evaluator can see:
    - program structure (operations and their order)
    - public constants (weights, coefficients)
    - input and output shapes
    - declared input ranges
  evaluator receives the secret key: no

Step 3. Encrypt, compute while encrypted, decrypt
  (the sizes below come from a second encrypted run with fresh keys)
  the clinic made a secret key and public keys, and encrypted the panel
  the evaluator received 1,574,609 bytes of ciphertext
    and 18,882,955 bytes of evaluation keys (no secret key)
  the evaluator computed sigmoid(weights . panel + bias) on ciphertext
  it returned 526,087 bytes: one ciphertext only the clinic can open
  the clinic decrypted it (timings in ms: keygen 460, encrypt 21, evaluate 94, decrypt 11)

Step 4. Check the answer against plain Python
  plain result      0.77171
  encrypted result  0.77161
  difference        0.00010  (allowed: 0.00100)

Step 5. What Encompute refuses to do
  tried: a value outside the declared range [0, 1]
  refused: ENC1102: input "panel"[0] = 2 is outside its declared range [0, 1]
  tried: an if-statement on a secret
  refused: ENC1003: comparison of secret values (<, <=, >, >=, ==, !=) needs exact values: declare inputs as e.g. secret[u32, 0:1000] or secret[bool_] (approximate float values cannot be compared or branched on)
  tried: printing a secret
  refused: ENC1004: a secret value cannot flow into a public sink (print, str, format, float, int, logging)

PASS
```

## What just happened

- **Step 2** is the manifest Encompute writes into every compiled program.
  The evaluator sees the operations, the public weights, the shapes and the
  declared ranges. It never receives the secret key.
- **Step 3**: the client generated keys, encrypted the panel and sent the
  ciphertext and the evaluation keys. The evaluator computed on ciphertext
  and returned one ciphertext. Only the holder of the secret key can read
  it. The sizes are measured by a second encrypted run with fresh keys.
- **Step 4**: the encrypted result differs from the plain one by about
  0.0001. That is the approximation the program declared (0.001), not a
  mistake.
- **Step 5**: unsafe programs and inputs are stopped by the compiler or the
  client, with a stable error code (see [docs/errors.md](../../docs/errors.md)),
  rather than leaking quietly.

## What this does not show

- Both roles run in one process. The evaluator here is not a separate
  machine, so you did not watch it fail to read anything. Example
  [03](../03_remote_evaluator/) puts a network between them.
- It does not show a signed receipt, or any check that the evaluator
  computed honestly. A receipt is a signed claim, not a proof. See example
  [04](../04_execution_receipts/).
- It involves one party's data. Several parties with their own rules is
  example [06](../06_confidentiality_policy/) and later.
- The evaluator still learns the program's structure, the public weights,
  the shapes, the ranges, the timing and the ciphertext sizes. Encrypted
  model weights are not supported.
- Never send a decrypted CKKS result back to the evaluator. See
  [KNOWN_LIMITATIONS.md](../../KNOWN_LIMITATIONS.md).
- The speed here says nothing about bigger programs. See
  [docs/performance.md](../../docs/performance.md).

## Where to go next

- [01 private inference](../01_ckks_private_inference/): the same idea with
  32 features, `explain`, `test` and `bench`.
- [02 exact private logic](../02_exact_private_logic/): integers and
  yes/no decisions, such as an eligibility rule, where `if`-style
  comparisons are allowed.
- The [developer guide](../../docs/guide/developer.md), and the
  [guide index](../../docs/guide/README.md) for the other topics.

## Try breaking it

- Change `precision=1e-3` in `hello.py` to `1e-12`. Compilation fails with
  ENC1202: the parameters cannot reach that precision, and Encompute does
  not quietly weaken them.
- Change the panel to `[0.62, 0.18, 0.91, 1.5]`. The client refuses it
  before encrypting (ENC1102).

## What Encompute guarantees

- The evaluator role never receives the secret key.
- Inputs outside their declared range, branches on secrets and prints of
  secrets are refused, with a code.
- The encrypted result matches the plain one within the declared precision
  (checked here for one input, and over many in example 01).

## What Encompute does NOT guarantee

- That the evaluator computed honestly (see examples 04 and 05).
- Anything about data once you decrypt it and share it.
- A mock-mode run (no OpenFHE in the build) encrypts nothing.

## Relevant source modules

`python/encompute` (the tracing frontend and `Model`), `crates/encompute-ckks`
(the CKKS plan and parameters), `crates/encompute-openfhe` and
`crates/encompute-openfhe-client` (the evaluator and client sides).
