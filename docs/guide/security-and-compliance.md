# Security and compliance path

You need to know what Encompute protects, against whom, and what evidence
it leaves. Read the limits first.

## 1. What it does not do

- [Known limitations](../../KNOWN_LIMITATIONS.md): read this before real
  data goes through it.
- [Support matrix](../support-matrix.md): what is supported, what is a
  subset, what is experimental, research only, or unsupported.
- No formal proof covers the whole system. The building blocks have
  published analyses; their composition in Encompute does not.
- A receipt is a signed claim, not a proof that the evaluator computed
  honestly. Execution proofs exist only in a research build, for a small
  exact subset ([verification](verification.md)).
- The evaluator always learns the program's structure, its public
  constants, shapes, declared ranges, timing and ciphertext sizes.
- Attested key release on Google Confidential Space is experimental: it is
  rehearsed locally and in CI, and the live run on Google Cloud has not
  been done.
- Several security findings from the 0.3.0-rc.3 review are only partly
  fixed, and the v0.3.3 security update has documented residual limits
  (see [SECURITY.md](../../SECURITY.md) and the advisory
  [GHSA-rm8x-939m-3fgp](https://github.com/BAder82t/Encompute/security/advisories/GHSA-rm8x-939m-3fgp)).

## 2. The threat model

- [Threat model](../threat-model.md): the adversaries considered (evaluator,
  cloud operator, participants, coordinator, compromised accounts, database,
  transport, artifact storage), the conditions a deployment must uphold, and
  what is not covered.
- [Cryptography](../cryptography.md): mechanisms and parameters.

## 3. The evidence

- [Assurance](../assurance.md): the invariant catalog (150 invariants), with
  positive, negative, adversarial and end-to-end evidence, run as a release
  gate. A passing report means the tested invariants held for the tested
  cases. It does not mean the system is proven secure.
- Each example says what it protects and what it does not, and runs the
  attacks: [examples](../../examples/).
- The [trust graph](trust-graph.md) joins signed evidence into one report
  that is checked only against keys you supply.
- [Verification](verification.md): receipts, and the three verification
  states.

## 4. Security history

The supported release is v0.3.3. The security advisory
[GHSA-rm8x-939m-3fgp](https://github.com/BAder82t/Encompute/security/advisories/GHSA-rm8x-939m-3fgp)
describes what it fixes and what it does not. The advisory credits the
maintainers' internal review, which was AI-assisted and is not an
independent audit. Internal reviews, assurance suites and test matrices are
not independent external audits. Earlier documents in this repository
describe a review of 0.3.0-rc.3 as independent or external; those descriptions
are kept as history and have not been re-verified.

- [Findings and their status](../security-findings.md) (history of earlier
  reviews)
- [Release notes for v0.3.3](https://github.com/BAder82t/Encompute/blob/v0.3.3/docs/release-notes-0.3.3.md)
- Report a vulnerability: [SECURITY.md](../../SECURITY.md).

## 5. Check what you download

[Verifying a release](../verify-release.md): checksums, signatures and build
provenance, in a few commands.

## 6. Privacy controls for data owners

[Confidentiality policies](confidentiality-policies.md),
[secure aggregation](secure-aggregation.md),
[differential privacy](differential-privacy.md) and
[attested key release](attested-key-release.md) are the mechanisms.
The [planner](planner.md) chooses them from stated requirements, or
refuses.
