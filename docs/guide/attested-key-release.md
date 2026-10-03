# Attested key release

Asset keys go only to a workload that proves what it is, with hardware attestation.

Owners release asset keys only to a workload that proves, with hardware
attestation, that it runs the approved artifact under the approved
execution spec and policy, in an approved TEE, for a fresh session. The
key is sealed to a session key generated inside the TEE: the cloud
operator relays it but cannot open it.

```sh
# Owner: an attestation policy for the artifact, and a protected key.
encompute attest policy model.encompute --image sha256:… --tee intel_tdx > policy.json
encompute keys protect --asset weights --policy policy.json --broker-id https://broker.modelco.example
encompute keys serve --jwks google --listen 0.0.0.0:8760   # behind a TLS proxy

# Workload, inside Confidential Space: attest, receive, serve.
encompute workload keys model.encompute --key weights@https://broker.modelco.example --identity eval.id
encompute-evaluator serve model.encompute --identity eval.id --attestation attestation.json
```

A wrong image, spec or policy, a debug build, an outdated TCB, stale,
replayed, tampered or expired evidence, a substituted session or evaluator
key, or a revoked key: no key. Receipts from an attested evaluator bind the
attestation, and `encompute verify --attestation …` checks the chain
hardware → workload → evaluator key → receipt. Providers: Google
Confidential Space ([deploy/confidential-space](../../deploy/confidential-space/))
and a development-only mock.
