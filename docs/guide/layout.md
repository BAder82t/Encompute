# Repository layout

What each crate and directory is for.

| Path | Role |
|---|---|
| `crates/encompute-ir` | Scheme-independent SSA IR, `.eir` text form, reference semantics |
| `crates/encompute-analysis` | Range, overflow and privacy analyses |
| `crates/encompute-ckks` | Lowering to CKKS plans; Chebyshev approximation; parameter selection |
| `crates/encompute-exact` | Exact plans: lowering, validation, execution, semantic transcripts |
| `crates/encompute-backend` | Client and evaluator traits; mock backends |
| `crates/encompute-protocol` | Versioned, checksummed envelopes |
| `crates/encompute-verification` | Execution specs, signed receipts, transcripts, proofs and proof interfaces (no FHE dependency) |
| `crates/encompute-attestation` | Provider-neutral workload attestation, bindings, attestation policies, sealed key grants |
| `crates/encompute-keybroker` | Policy-gated key release to attested workloads (library, HTTP server, client) |
| `crates/encompute-secagg` | Secure aggregation (Bonawitz et al.) bound to policies, rounds and receipts |
| `crates/encompute-privacy` | Differential privacy: budgets, discrete Gaussian noise, zCDP accounting, ledger, receipts |
| `crates/encompute-training` | Confidential fine-tuning: training specs, sealed assets and checkpoints, adapter records, export control |
| `python/encompute/torch` | PyTorch integration: LoRA, attested training and inference workers, `Project.finetune` |
| `crates/encompute-planner` | Planner: trust requirements, mechanism selection, plan validator, PlanIds |
| `crates/encompute-trust` | Trust graph: authorizations, revocations, lineage, evidence, trust report |
| `crates/encompute-assurance` | Assurance suite: invariant catalog, adversarial checks, release-gate report (not published) |
| `crates/encompute-vfhe` | Re-execution proof verifier on OpenFHE BGV (research) |
| `crates/encompute-openfhe`, `-openfhe-client` | OpenFHE evaluator side; client side (keys, encryption, decryption), CKKS and BinFHE |
| `crates/encompute-openfhe-exact` | OpenFHE exact backend: envelopes, parameter profile, gate binding |
| `crates/encompute-tfhe`, `-tfhe-client` | TFHE-rs evaluator side; client side (research feature, never in commercial builds) |
| `crates/encompute-control` | Control plane: API v1, identities, tenancy, jobs, scheduler, privacy ledgers, state anchor, audit |
| `crates/encompute-evaluator` | Evaluator sessions and HTTP service; never links client crypto |
| `crates/encompute-runtime` | Execution, differential testing, explain, bench, audit, artifacts |
| `crates/encompute-cli` | `encompute` command |
| `crates/encompute-py`, `python/encompute` | Python SDK: extension module and tracing frontend |
| `examples/` | Runnable examples for every capability, `run-all.sh` ([examples/README.md](../../examples/README.md)) |
