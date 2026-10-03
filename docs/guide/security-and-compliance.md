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
  fixed.

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

## 4. The independent review

The independent review of 0.3.0-rc.3 and a later review of its fixes
reported 62 findings. All are fixed in 0.3.0, several only partly. The fixes
were checked internally (two adversarial review passes, the release gate and
a soak). The reviewers have not reviewed the fixes in 0.3.0.

- [Findings and their status](../security-findings.md)
- [Review package](../../security-review/)
- [Release notes](../release-notes-0.3.0.md)
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
