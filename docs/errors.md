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
| ENC1901 | compiler | A confidential value flows to a public output | Keep it sealed, or derive a public value only where every source asset allows it |
| ENC1902 | compiler | A value is revealed to a party that may not learn it (outside its audience, or release `never`) | Reveal only to parties every source asset allows |
| ENC1903 | compiler | An input asset does not allow the program's purpose (or the program declares none) | Declare a purpose every input asset allows |
| ENC1904 | compiler | A derivation weakens a policy more than its source assets permit | Ask the owners to permit that derivation (`derive [...]`), or keep it restricted |
| ENC1905 | compiler | An aggregate-only value (e.g. a gradient) is revealed without an aggregation boundary | Keep it sealed until it is aggregated |
| ENC1906 | compiler | Confidentiality declarations are malformed: unknown party or asset, duplicate IDs, unbound secret input, bad ID or release | Fix the declaration |
| ENC2001 | broker, verifier | Attestation evidence is malformed, forged or tampered, from an unknown provider or signing key, or does not commit to the workload binding it was sent with (a substituted session key, evaluator key, spec or policy) | Do not release keys or trust receipts from this workload; check which providers you trust (`--jwks`, `--mock-root`) |
| ENC2002 | broker, verifier | A verified workload does not satisfy the attestation policy: image, TEE, TCB, debug state, GPU, execution spec, policy or artifact differ; or development evidence meets a production policy or broker | Approve the new image or spec in a new policy, or refuse the workload |
| ENC2003 | broker | Attestation freshness: the challenge is unknown, expired or already used (a replay), or the evidence is stale, predates the challenge, or has expired | Request a new challenge and attest again |
| ENC2004 | broker, workload | Key release refused: no attested session, unknown asset, revoked key version, or a grant for another session | Attest first; rotate a revoked key; open grants only in their own session |
| ENC2101 | secure aggregation | A party is not in the aggregation spec, or a message is not signed by its party's identity key, or an attested round's contributor is unattested | Add the party to the consortium's parties.json (a new spec), or check the key it signs with |
| ENC2102 | secure aggregation | A contribution or round does not match the approved spec (PolicyID, ExecutionSpecID, shape, codec, parties or keys differ), belongs to another round, repeats a message, or replays an older round | Rebuild the spec from the same artifact and parties.json; start a new round |
| ENC2103 | secure aggregation | Too few parties remain (below the minimum or the protocol threshold): the round aborts and nothing is released | Rerun with more participants, or lower the minimum in a new policy |
| ENC2104 | secure aggregation | A protocol message is malformed, tampered, out of order, or the coordinator equivocated; or a reconstruction failed (a bad share) | Do not trust this round; rerun it and investigate the coordinator or party named |
| ENC2105 | compiler | The fixed-point encoding could overflow the modulus: parties × maximum code ≥ 2^modulus | Increase the modulus, or reduce the clip range or scale |
| ENC2106 | compiler | An aggregate declaration is invalid: not a sum of one input per party, a minimum outside 2..parties, a collusion bound the parties cannot meet, a bad codec, or an unknown output | Fix the declaration; tolerating more colluders needs more parties |
| ENC2201 | coordinator, owner | RELEASE DENIED: the release would exceed an asset's privacy budget | Stop releasing from this asset, or have its owners approve a new budget (a new policy) |
| ENC2202 | coordinator, owner | A privacy ledger is malformed, tampered (deleted, reordered or edited entries), rolled back or reset, for another asset or policy, or not shown | Restore the ledger; do not contribute until it extends the last checkpoint you saw |
| ENC2203 | compiler | Privacy declarations are invalid (epsilon, delta, unit, clip, noise), or a budgeted asset is released without a privacy mechanism | Fix the declaration, or add `dp` (Python `privacy=`) to the aggregation |
| ENC2204 | runtime | A privacy mechanism, its parameters, randomness or receipt do not match the approved configuration (including non-production randomness) | Refuse the release; check the coordinator's privacy configuration and attestation |
