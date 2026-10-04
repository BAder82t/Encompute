# Writing and running programs

How Encompute programs look, what the compiler and runtime do, and the backends.

Encompute compiles ordinary Python into encrypted computation. You declare
which values are secret and their ranges; Encompute picks the encryption
scheme from the types, builds a plan, chooses 128-bit parameters, runs it
on an evaluator that never sees your data, and checks the encrypted result
against plaintext.

Two kinds of programs share one API:

The first snippet uses NumPy (`pip install numpy`); the SDK itself does not need it.

```python
import numpy as np
import encompute
from encompute import secret, Tensor, u8, u16, u32

# Approximate: real numbers, CKKS (OpenFHE), within a declared precision.
w, b = np.random.default_rng(0).normal(0, 0.3, 32), 0.1

@encompute.compile(precision=1e-3)
def score(x: secret[Tensor[32], -1.0:1.0]):
    return encompute.sigmoid(encompute.dot(w, x) + b)

# Exact: integers and Booleans, comparisons, encrypted selection.
@encompute.compile()
def approve(age: secret[u8, 0:120], income: secret[u32, 0:1_000_000],
            debt: secret[u32, 0:500_000], risk: secret[u16, 0:1000]):
    return (age >= 18) & (debt * 100 < income * 40) & (risk <= 650)

x = np.random.default_rng(1).uniform(-1, 1, 32)
score(x)                                   # plaintext reference
score(x, mode="encrypted")                 # CKKS on OpenFHE
approve(35, 100_000, 20_000, 400, mode="mock")   # True, exactly
print(approve.test(cases=1000))            # 1000 matches, 0 mismatches
print(score.explain())                     # plan, parameters, precision, verification
score.save("score.encompute")              # reproducible artifact, no keys
```

## What Encompute does

**Privacy types.** `secret[float, lo:hi]` and `secret[Tensor[n], lo:hi]`
(approximate); `secret[u8, lo:hi]` … `secret[u64, lo:hi]`,
`secret[i8, lo:hi]` … `secret[i64, lo:hi]` and `secret[bool_]` (exact).
Using a secret in `if`, `print`, `int()` or as a divisor is a compile-time
error with a stable code, not a silent leak. Exact values at the API are
integers within ±2^53, because values cross the API as
64-bit floats.

**Operations.**
- Approximate: `+ - *`, `sum`, `dot`, public-matrix `@`, `poly`, `sigmoid`,
  `x ** k`, division by public values.
- Exact: `+ - *`, comparisons, `& | ^ ~`, shifts, `//` and `%` by constants,
  `encompute.select`, `minimum`/`maximum`, `lookup`, `cast`.

**Compiler.** The program's types choose the scheme: approximate programs
lower to CKKS (SIMD packing, hybrid diagonal matrix–vector products,
Chebyshev approximation of `sigmoid` to the requested precision, parameters
checked against the HE Standard 128-bit table); exact programs lower to a
backend-independent plan, with integer range analysis proving that no
operation overflows (a possible overflow is ENC1303). Programs mixing both
kinds are refused: one encrypted scheme per program.

**Runtime.** `clear`, `mock` and `encrypted` modes. Client and evaluator
are separate roles talking only through versioned, checksummed envelopes
bound to scheme, backend, parameters, program and key; the evaluator never
receives the secret key and its binary links no client crypto. Locally both
roles run in one process; `run --remote` puts a network between them.

**Testing.** `test()` / `encompute test` compares encrypted and plaintext
results: within the precision for approximate programs, exactly (matches
and mismatches, boundary values first) for exact ones.

**Backends.**
- **OpenFHE CKKS: production.** OpenFHE v1.5.1, statically linked, for
  approximate programs.
- **OpenFHE exact: production.** OpenFHE BinFHE (STD128, one ciphertext
  per bit, bootstrapped gates) for exact programs, run as an optimized
  circuit with parallel gates. OpenFHE BGV runs verified exact programs,
  and unverified programs whose operations are all in the BGV subset when
  it is estimated no slower.
- **TFHE-rs: research only.** TFHE-rs 1.8.1, behind the off-by-default
  `research-tfhe-rs` feature, for research and differential testing only:
  Zama requires a patent license for commercial use of its technology.
  Production builds cannot select it (BACKEND UNAVAILABLE), and
  `scripts/audit-commercial-build.sh` checks that none of it is linked.
- A plaintext mock for both kinds, for development and tests.
