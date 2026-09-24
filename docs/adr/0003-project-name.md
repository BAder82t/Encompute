# ADR-003 — Project name

Status: **Internal codename only**

## Decision

"Veil" is the internal codename, pending trademark, domain, GitHub, PyPI,
crates.io and npm clearance.

Nothing may depend on owning the bare `veil` namespace:

- Python distribution: `veilcompute` (import name decided at release; `import veil`
  is not a technical requirement).
- Rust crates: `veil-*` (`veil-ir`, `veil-analysis`, `veil-ckks`, `veil-backend`,
  `veil-openfhe`, `veil-runtime`, `veil-cli`). Not published before clearance.
- CLI binary: `veil` (local only until clearance).
- GitHub org: candidate `veilcompute`.

## Known conflicts (unverified by counsel)

- `veil` on PyPI, taken since 2014.
- Enveil ("Encrypted Veil"): PETs, homomorphic encryption, secure AI.
- A Canadian VEIL trademark application (Feb 2026) covering data-security software,
  AI infrastructure and privacy-preserving machine learning.
- Several open-source privacy projects named Veil.

Whether any of these blocks use is a legal question for a jurisdiction- and
class-specific trademark search. Do not build brand equity before that.
