# 03 — Remote evaluator

## What this demonstrates

The client and the evaluator are two processes. The client compiles the
model, generates keys, encrypts a query, sends it, and decrypts the answer.
The evaluator computes on what it receives and holds no key that can
decrypt anything. The script makes that visible:

- `encompute keys generate` writes two files: `secret.key` (mode 600, stays
  on the client) and `eval.keys` (uploaded).
- The evaluator runs in its own empty directory and reports
  `holds_secret_keys false` on `/v1/info`.
- Its request log shows exactly three uploads: the program, a key upload
  byte-for-byte the size of `eval.keys`, and the encrypted query. No
  request carries `secret.key`.
- `encompute audit --evaluator` checks the evaluator binary contains no
  Encompute key-generation, encryption or decryption code.

The model is a 384-dimensional similarity search against 64 public
documents (`search_model.py`, also used by `scripts/two-machine-demo.sh`,
which puts the evaluator in a container).

## Threat model

The evaluator is honest-but-curious: it runs the program as sent but wants
to learn the query and the scores. The client is trusted and holds the
secret key. The network is untrusted for confidentiality only with real
encryption; this demo speaks plain HTTP on localhost.

## Architecture

```text
client machine                                  evaluator machine
──────────────                                  ─────────────────
search.encompute ──── POST /v1/programs ──────► program
keys/eval.keys   ──── POST .../keys ──────────► evaluation keys
keys/secret.key  (never leaves; mode 600)
query ─ encrypt ───── POST .../jobs ──────────► docs @ q on ciphertexts
scores ◄─ decrypt ─── result + signed receipt ◄─┘
```

## Run it

```sh
cargo build --bins && maturin develop -m crates/encompute-py/Cargo.toml
examples/03_remote_evaluator/run.sh
```

This build has no OpenFHE, so both sides use the mock backend. With an
OpenFHE build the same script uses real CKKS keys and the `openfhe`
backend (`examples/run-all.sh crypto`); that path was not run here.

## Expected output

```text
  secret.key secret_key             333 bytes  mode 600
  eval.keys  evaluation_keys        412 bytes  mode 644
role evaluator | holds_secret_keys false
Evaluator receipt       verified
Execution proof         not present
Encrypted result        accepted (receipt only)
top-5 documents   [17, 33, 38, 22, 62] (plaintext: [17, 33, 38, 22, 62])
Result            MATCH (within 1e-3)
POST /v1/programs  status 200  received 539389 bytes
POST /v1/programs/<id>/keys  status 200  received 412 bytes
POST /v1/programs/<id>/jobs  status 200  received 4510 bytes
key upload = eval.keys (412 bytes); secret.key was never sent
secret.key files in the evaluator's directory: 0
PASS  evaluator.no_client_crypto   no Encompute key-generation, encryption or decryption code; ...
```

## Try breaking it

- Decrypt with only what the evaluator holds: `run.sh` copies `eval.keys`
  into a fresh key directory and runs the client with it. It is refused
  with ENC1605 (no `secret.key`). Evaluation keys let the evaluator compute,
  not decrypt.
- Point the client at a different evaluator after the first run: the
  evaluator's signing key is pinned on first use (`keys/evaluator.pub`),
  and a new identity is refused with ENC1606 (example 04).

## What Encompute guarantees

- The secret key is generated on the client, written with mode 600, and
  never sent: the protocol has no request that carries it.
- The evaluator binary contains no Encompute client crypto, checked by
  `encompute audit --evaluator` (and `scripts/audit-evaluator-binary.sh`).
- The client checks the evaluator's signed receipt before decrypting.

## What Encompute does NOT guarantee

- The mock backend encrypts nothing: its "ciphertexts" are plaintext slot
  vectors with simulated noise, so the mock evaluator here can read the
  query. Only the key separation and the protocol are real in this run.
- Holding no secret key does not make the evaluator honest. It can return
  a wrong result; the receipt only says what it claims to have run
  (example 04), and checking the computation needs verified execution
  (example 05).
- Metadata leaks: the evaluator sees the program, request sizes, timing,
  and when the client calls.
- No TLS: the evaluator speaks plain HTTP. Put it behind a TLS proxy for
  remote clients.
- The model weights are public constants in the program; the evaluator
  learns them. Private models need a confidentiality policy and attested
  execution (examples 06, 07).

## Relevant source modules

- `crates/encompute-evaluator/src/server.rs`: the evaluator's HTTP API.
- `crates/encompute-runtime/src/client.rs`: remote runs (encrypt, upload,
  verify receipt, decrypt).
- `crates/encompute-cli`: `keys generate`, `run --remote`, `audit`.
- `scripts/audit-evaluator-binary.sh`, `scripts/two-machine-demo.sh`.
- `docs/adr/0005-evaluator-process-isolation.md`, `docs/threat-model.md`.
