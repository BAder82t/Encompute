# Status at a glance

The status summary that used to be the README's status block. The authoritative list is the [support matrix](../support-matrix.md); if the two disagree, the support matrix wins.

**Status: the supported release is v0.3.3**, the first completed release
with the fixes for the security advisory
[GHSA-rm8x-939m-3fgp](https://github.com/BAder82t/Encompute/security/advisories/GHSA-rm8x-939m-3fgp)
(v0.3.0 is affected; v0.3.1 and v0.3.2 were incomplete, unsupported release
attempts; `main` is unreleased 0.4 development). Earlier review findings and
their fixes, some partial, are kept as history in
[docs/security-findings.md](../security-findings.md). What you can rely on is in the
[support matrix](../support-matrix.md); what Encompute does not do is in
[known limitations](../../KNOWN_LIMITATIONS.md). See also the
[release notes for v0.3.3](https://github.com/BAder82t/Encompute/blob/v0.3.3/docs/release-notes-0.3.3.md), [changelog](../../CHANGELOG.md),
[performance](../performance.md), [compatibility](../compatibility.md),
[API stability](../api-stability.md), [threat model](../threat-model.md),
[cryptography](../cryptography.md) and [error codes](../errors.md).

| Area | Status |
|---|---|
| Approximate programs on OpenFHE CKKS | **Supported** (production) |
| Exact programs on OpenFHE exact (BinFHE) | **Supported** (production): optimized circuits, parallel gates |
| Exact programs on OpenFHE BGV | **Supported subset**: arithmetic-only `u8`/`u16`/`bool` programs, chosen by calibrated cost |
| TFHE-rs | **Research only** (`research-tfhe-rs`); production builds refuse it |
| Remote evaluator, worker processes | **Supported**, single node |
| Signed execution receipts | **Supported** (signed claims, not proofs) |
| Verified execution (execution proofs) | **Research only** (`vfhe-research`): re-execution on BGV, small exact subset |
| Confidentiality policies, planner, trust graph | **Supported** |
| Secure aggregation | **Supported** |
| Differential privacy: organization level, patient-level DP-SGD | **Supported** |
| PyTorch LoRA; Hugging Face Transformers + PEFT | **Supported subset**: sequence classification with BERT or DistilBERT |
| Attested key release on Google Confidential Space | **Experimental**: rehearsed locally and in CI, live GCP run pending. The mock is for development only |
| Control plane: PostgreSQL, OIDC, OpenBao/Vault BYOK, API v1 (frozen) | **Supported** |
| Docker Compose deployment | **Supported**; its bundled OpenBao runs in development mode |
| Python SDK | **Supported** |
| Platforms | Linux x86_64 and macOS arm64 **supported**; Linux arm64 **experimental** |
| Assurance | 175 invariants (150 in 0.3) with positive, negative, adversarial and end-to-end evidence; a release gate in CI ([docs/assurance.md](../assurance.md)) |
| Commercial dependency boundary | Audited: no TFHE-rs in the dependency graph, SBOM, binaries, wheel or container of a production build (`scripts/audit-commercial-build.sh`) |
