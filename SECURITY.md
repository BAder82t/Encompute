# Security policy

## Supported releases

| Release | Status | Security fixes |
|---|---|---|
| [0.3.3](https://github.com/BAder82t/Encompute/releases/tag/v0.3.3) | **current supported release** (the first completed release with the fixes for [GHSA-rm8x-939m-3fgp](https://github.com/BAder82t/Encompute/security/advisories/GHSA-rm8x-939m-3fgp)) | yes |
| 0.3.0, 0.3.1, 0.3.2 and the 0.3.0 release candidates (`0.3.0-rc.N`) | **unsupported**. 0.3.0 and its release candidates are affected by the advisory (`encompute-control` `>= 0.3.0-rc.1, < 0.3.1`). `v0.3.1` and `v0.3.2` were incomplete release attempts: no completed GitHub release, no signed release artifacts, and their container image tags must not be used | no: upgrade to 0.3.3 |
| `main` (version `0.4.0-rc.1` in the source) | **unreleased development**; no `v0.4.*` tag or release exists. Its control-plane security remediation is still in progress. Do not deploy it as a release | development only; reports welcome |
| 0.2.x | superseded | no: upgrade to 0.3.3 |
| 0.1.x | superseded | no |

Reviews and test suites run by the maintainers, including AI-assisted
reviews, assurance suites and adversarial test matrices, are not independent
external audits. Earlier documents in this repository describe a review of 0.3.0-rc.3 as
independent or external; those descriptions are kept as history and have not
been re-verified. Some findings of that review were only partly fixed; see
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

Only the production build is in scope for security fixes: OpenFHE CKKS,
OpenFHE exact (BinFHE and the BGV subset), the control plane, key brokers,
secure aggregation and the Python SDK. Research features
(`research-tfhe-rs`, `vfhe-research`) are not supported releases. We
still welcome reports about them.

What each capability's status is: [docs/support-matrix.md](docs/support-matrix.md).

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability
reporting: **Security → Report a vulnerability** on this repository. Do not
open a public issue, pull request or discussion.

Please include:

- the affected version or commit, and the build features;
- the component (compiler, evaluator, control plane, key broker, SecAgg
  coordinator, Python SDK, deployment files);
- steps to reproduce, or a proof of concept;
- the impact you expect.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| First assessment (valid or not, severity) | within 10 business days |
| Mitigation for a confirmed critical issue | within 7 days; the final fix as soon as practical |
| Fix or mitigation for a confirmed high issue | within 30 days |
| Fix for a confirmed medium or low issue | in a following release |

These are targets for a solo-maintained project, not contractual service
levels.

We keep you informed until the issue is closed. Tell us if you want credit
in the release notes.

## Responsible disclosure

- Give us a reasonable time to fix the issue before you disclose it. We
  aim to publish an advisory within 90 days of the report, or with the
  fix if it is earlier.
- We coordinate the disclosure date with you.
- Test only against your own deployments and data. Do not access, modify
  or delete other people's data, and do not degrade services you do not
  own.
- We will not pursue legal action for research that follows this policy
  in good faith.

## Scope

In scope:

- An evaluator, a control plane, a SecAgg coordinator or a network
  observer learning secret values.
- Key material in artifacts, logs, metrics, audit events or the database.
- Parameter selection below the stated 128-bit security.
- A result accepted without the checks the documentation promises:
  receipts, execution proofs (research build), attestation, trust reports.
- Key release without valid attestation, or to the wrong session.
- Privacy budget bypass: a release over budget, a double spend, or a
  ledger rollback that goes unnoticed.
- Tenant isolation failures in the control plane, and authentication or
  authorization bypass.
- A production build that links TFHE-rs, or selects it.
- Memory-safety issues in the OpenFHE shim.

Out of scope, because they are documented limitations
([KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md),
[docs/threat-model.md](docs/threat-model.md)):

- CKKS is not IND-CPA-D secure: decrypted results must never be returned
  to the evaluator.
- Without verified execution, an evaluator can sign a wrong result. A
  receipt is a signed claim, not a proof.
- Program structure, public weights, shapes, declared ranges, timing and
  ciphertext sizes are visible to the evaluator by design.
- The development attestation mock and the development-mode OpenBao in
  Docker Compose protect nothing.
- A malicious SecAgg coordinator can abort a round or report a wrong
  aggregate.
- Side channels on the client.
- Vulnerabilities in OpenFHE, PyTorch, Transformers, PEFT or other
  dependencies. Report those upstream. Tell us too if Encompute's use of
  them makes the issue worse.
