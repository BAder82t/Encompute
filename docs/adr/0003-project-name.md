# ADR-003 — Project name

Status: **Accepted** (2026-09-24): **Encompute**. Supersedes the earlier
codename "Veil".

## Decision

The project is named **Encompute** ("encrypted compute"). Names:

- GitHub: `BAder82t/Encompute`
- Python distribution and import: `encompute`
- Rust crates: `encompute-*`
- CLI: `encompute`
- IR text files: `.eir`; compiled artifacts: `<name>.encompute/`
- Diagnostic codes: `ENC####`

## Why not "Veil"

"Veil" conflicted in the same market:

- Enveil ("Encrypted Veil") sells PETs, homomorphic encryption and secure AI.
- A Canadian VEIL trademark application (Feb 2026) covers data-security
  software, AI infrastructure and privacy-preserving machine learning.
- `veil` on PyPI has been taken since 2014, and several open-source privacy
  projects use the name.

Variants such as "FHEVeil" kept the same conflict: a descriptive prefix does
not usually distinguish a mark in the same class.

## Checks behind "Encompute" (2026-09-24)

- PyPI, crates.io and npm: `encompute` unregistered.
- `encompute.dev` and `encompute.io`: no DNS records; `encompute.com` is registered.
- Web search: no company or product named Encompute.
- A coined word, which makes a stronger trademark than a descriptive one
  ("ciphercompute").

Alternatives considered: Blindsum (fully available, less descriptive of
confidential computing), Sealedcore (fully available, close to Microsoft
SEAL), Hushfold and Obliva (existing privacy products), and others taken
on registries.

These are availability checks, not legal clearance. A jurisdiction- and
class-specific trademark search is still needed before launch or before
publishing packages.
