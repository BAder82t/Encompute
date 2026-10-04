# Roadmap

What is done and what is next.

- **Succinct proofs**: a zkVM proof of the same relation, starting with
  a cost benchmark of one BGV ciphertext multiplication.
- ✓ Patient-level DP-SGD (per-patient clipping, Poisson sampling, Rényi DP
  accounting).
- ✓ Hugging Face Transformers + PEFT LoRA (sequence classification).
- ✓ Confidential Space training worker: a Hugging Face workload, hardware
  attestation gating the model and dataset keys. It is rehearsed locally and
  in CI; the live GCP run needs a project.
- ✓ OpenFHE CKKS (approximate programs).
- ✓ OpenFHE exact (BinFHE): the production exact backend, with a commercial
  build audit.
- ✓ TFHE-rs isolated to research builds.
- ✓ Enterprise deployment foundation: control plane, OIDC and service
  identities, tenant isolation, customer-managed keys, durable privacy
  state, audit, API v1, Compose deployment.
- ✓ OpenFHE performance and hybrid optimization: optimized circuits,
  parallel gate evaluation, BGV or BinFHE per program by calibrated cost.
  Functional bootstrapping was measured and not adopted.
- ✓ Release 0.3.0.
- → `encompute migrate` for artifact formats
  ([docs/compatibility.md](../compatibility.md)).
- → Multi-machine orchestration.
- → A message-broker adapter, if needed; then Kubernetes.
- → Commercial UI.
