# Encompute error codes

Every diagnostic carries a stable code. The CLI prints `error[CODE]: message`;
Python raises `encompute.EncomputeError` with `.code` and `.message`.

| Code | Raised by | Meaning | What to do |
|---|---|---|---|
| ENC1001 | Python frontend | Python control flow on a secret (`if`, `while`, `and`/`or`/`not`, `bool()`, builtin `min`/`max`) | Use `encompute.select(cond, a, b)`, `& \| ~`, or `encompute.minimum`/`maximum` on exact values; express approximate logic arithmetically |
| ENC1002 | Python frontend | Division by a secret value | Divide by public values only |
| ENC1003 | Python frontend | Comparison (or logic, shift) on approximate (float) secrets | Declare the inputs with exact types (`secret[u32, lo:hi]`, `secret[bool_]`); comparisons of exact values give encrypted Booleans |
| ENC1004 | Python frontend | A secret flows into a public sink (`print`, `str`, f-string, `float`, `int`, logging) | Return the value as an output; the client decrypts it |
| ENC1005 | frontend, IR | Operation not supported on secrets (indexing, iteration, non-integer powers, secret matrices, `select` without an encrypted bool condition, programs mixing approximate and exact values) | See the message for the version that adds it |
| ENC1101 | frontend, IR | Secret input has no declared range, or `lo >= hi` | `secret[float, lo:hi]` / `secret[Tensor[n], lo:hi]` |
| ENC1102 | runtime | Input missing, wrong length, unknown, or outside its declared range | Fix the input; ranges are part of the security and precision contract |
| ENC1201 | compiler | Multiplicative depth exceeds the largest 128-bit parameter set (N = 2^16) without bootstrapping | Reduce chained multiplications or approximation degree; bootstrapping arrives in 0.2 |
| ENC1202 | compiler | Precision unreachable: scale above 59 bits, first modulus above 60 bits, unbounded range, or a sigmoid needing degree > 127 | Relax `precision` or narrow input ranges |
| ENC1301 | frontend, IR | Type error: shape mismatch, public-only computation, output not depending on a secret, bad constant | See message |
| ENC1302 | IR parser | Malformed `.eir` text (message includes the line) | — |
| ENC1303 | analysis | An exact integer operation may overflow its type for inputs in the declared ranges, a lookup index may leave its table, or an exact output may exceed ±2^53 | Use a wider type (`cast`) or narrower input ranges |
| ENC1401 | runtime | Artifact missing, modified (hash mismatch), or compiled by a different Encompute version | Recompile the artifact |
| ENC1501 | backend | Backend error (OpenFHE exception, missing rotation key, depth budget exhausted, build without OpenFHE) | See message |
| ENC1601 | envelope | Malformed, truncated or corrupted envelope (checksum mismatch) | — |
| ENC1602 | envelope | Wrong kind, format, scheme or backend version | Match client and evaluator versions |
| ENC1603 | envelope | Made for a different parameter set | Recompile or regenerate keys |
| ENC1604 | envelope | Made for a different program | — |
| ENC1605 | envelope | Different or unregistered key | Upload `eval.keys` |
| ENC1606 | client | An execution receipt is malformed, has a bad signature, comes from an untrusted evaluator key, or does not match the program, plan, parameters, key, request or response | Do not use the result; check which evaluator you trust (`--trust-evaluator`) and that request and response were not altered |
| ENC1701 | remote | Network or protocol failure between client and evaluator | — |
| ENC1702 | client, audit | A semantic transcript is malformed, of an unknown version, or its hash does not match the exact plan or the verification metadata ("transcript commitment mismatch") | Recompile the artifact; do not trust a receipt whose transcript hash differs |
| ENC1801 | compiler, client | Verified execution was required but is not possible or failed: the program uses an operation or type no proof backend covers, the evaluator sent no proof, or the proof does not verify | Use `verification="receipt"`, restrict the program to the proven subset, or refuse the result; never decrypt without a valid proof when verification is required |
