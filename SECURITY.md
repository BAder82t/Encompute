# Security policy

Encompute is pre-release research software (v0.1). Do not use it to protect
production data yet.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository. Do not open a
public issue.

Relevant reports include anything that lets the evaluator learn secret
values, key material ending up in artifacts or logs, parameter selection
below the stated 128-bit security, or memory-safety issues in the OpenFHE
shim.

## Scope

The v0.1 threat model is in [docs/threat-model.md](docs/threat-model.md).
Known limitations, not vulnerabilities:

- CKKS is not IND-CPA-D secure: decrypted results must never be returned
  to the evaluator.
- The evaluator is assumed honest-but-curious; results are not verifiable.
- Program structure, public weights, shapes and declared ranges are visible
  to the evaluator by design.
