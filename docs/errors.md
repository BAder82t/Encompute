# Veil error codes

Every diagnostic carries a stable code. The CLI prints `error[CODE]: message`;
Python raises `veil.VeilError` with `.code` and `.message`.

| Code | Raised by | Meaning | What to do |
|---|---|---|---|
| VEIL1001 | Python frontend | Python control flow on a secret (`if`, `while`, `and`/`or`/`not`, `bool()`) | Express the logic arithmetically; `veil.select` arrives with TFHE in 0.3 |
| VEIL1002 | Python frontend | Division by a secret value | Divide by public values only |
| VEIL1003 | Python frontend | Comparison of secrets (`<`, `>`, `==`, …) | Needs TFHE (0.3) |
| VEIL1004 | Python frontend | A secret flows into a public sink (`print`, `str`, f-string, `float`, `int`, logging) | Return the value as an output; the client decrypts it |
| VEIL1005 | frontend, IR | Operation not supported on secrets in v0.1 (indexing, iteration, non-integer powers, secret matrices, `select`) | See the message for the version that adds it |
| VEIL1101 | frontend, IR | Secret input has no declared range, or `lo >= hi` | `secret[float, lo:hi]` / `secret[Tensor[n], lo:hi]` |
| VEIL1102 | runtime | Input missing, wrong length, unknown, or outside its declared range | Fix the input; ranges are part of the security and precision contract |
| VEIL1201 | compiler | Multiplicative depth exceeds the largest 128-bit parameter set (N = 2^16) without bootstrapping | Reduce chained multiplications or approximation degree; bootstrapping arrives in 0.2 |
| VEIL1202 | compiler | Precision unreachable: scale above 59 bits, first modulus above 60 bits, unbounded range, or a sigmoid needing degree > 127 | Relax `precision` or narrow input ranges |
| VEIL1301 | frontend, IR | Type error: shape mismatch, public-only computation, output not depending on a secret, bad constant | See message |
| VEIL1302 | IR parser | Malformed `.vlir` text (message includes the line) | — |
| VEIL1401 | runtime | Artifact missing, modified (hash mismatch), or compiled by a different Veil version | Recompile the artifact |
| VEIL1501 | backend | Backend error (OpenFHE exception, missing rotation key, depth budget exhausted, build without OpenFHE) | See message |
