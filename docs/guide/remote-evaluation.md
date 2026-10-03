# Remote evaluation

Run the evaluator as a separate service and verify what it returns.

```sh
cargo build --release --features openfhe -p encompute-cli -p encompute-evaluator
encompute keys generate score.encompute -o score.keys          # secret.key stays here
encompute-evaluator serve score.encompute --listen 127.0.0.1:8750 --identity evaluator.key
# a TLS proxy on the evaluator host forwards https://EVALUATOR to 127.0.0.1:8750
encompute run score.encompute --remote https://EVALUATOR --keys score.keys --input x=... \
  --save-receipt result.receipt.json --save-envelopes exchange/
encompute verify result.receipt.json --model score.encompute \
  --request exchange/request.bin --response exchange/response.bin --trust-evaluator KEY
```

`verify` exits 0 only when every binding was checked (the trusted
evaluator key, the artifact, the backend, the transcript, the evidence
kind, the key ID, the request and the response) and any proof the receipt
names was verified; 3 when some bindings were not supplied or a named
proof was not checked (a `NOT CHECKED:` line lists them); 1 when any
check fails; and 2 on an error such as a missing file or a bad argument. An attestation the receipt binds is checked only with
`--attestation` and `--attestation-policy`, and exit 0 does not require
it. The evaluator speaks plain HTTP: keep it on `127.0.0.1` or a private
network behind a TLS proxy, as above. `--listen 0.0.0.0:…` exposes it
unencrypted on every interface. On one machine, `--remote
http://127.0.0.1:8750` works without a proxy.
`scripts/audit-evaluator-binary.sh` checks that the evaluator binary
contains no Encompute key-generation, encryption or decryption code.
