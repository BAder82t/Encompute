# Security findings process

This page says how Encompute handles a security finding: from the report,
through the fix, to the regression test that keeps it fixed. It applies to
findings from the independent security review, from internal review, and
from outside reporters.

The threat model is [threat-model.md](threat-model.md). The cryptographic
design is [cryptography.md](cryptography.md). The review package is
[security-review/](../security-review/README.md).

## Intake

- **Outside reporters** follow [SECURITY.md](../SECURITY.md): a private
  report through GitHub (**Security → Report a vulnerability**). Never a
  public issue.
- **Review teams** file each finding as a private GitHub security advisory
  draft on the repository, or send the findings list to the maintainers
  through the channel agreed for the engagement. One advisory per finding.
- **Maintainers** who find a problem themselves open a private advisory
  too, so every finding has the same record.

Every finding gets an ID when it is accepted: `ENC-SF-YYYY-NNN` (year, then
a running number). The ID appears in the advisory, the fix commit message,
the regression test's comment and, where there is one, the new invariant's
claim.

**Proposed policy (to be confirmed by the owner):** the first response to
a report (acknowledgement and an initial severity) is due within
**3 working days**.

## Severity

Severity follows impact on the assets in the [threat model](threat-model.md),
under that model's assumptions. A finding that needs an assumption the
threat model rules out (for example, a malicious evaluator in a
configuration documented as honest-but-curious) is rated against the
documented model, and the report says which assumption it breaks.

| Severity | Definition | Examples | Fix target |
|---|---|---|---|
| **Critical** | An adversary inside the threat model breaks a core guarantee without unusual preconditions: learns protected plaintext or a secret key, obtains a released asset key without valid attestation, reads another tenant's data, or makes an unverified result look verified. | The evaluator can decrypt; a key broker releases a key to mock evidence in production; a cross-tenant read through API v1; a forged receipt that verifies. | Fix or mitigation within **7 days** of confirmation. Advisory published with the fixed release. |
| **High** | A core guarantee breaks under realistic but specific conditions, or an integrity or accounting guarantee breaks without preconditions. | Privacy spending can be rolled back or double-spent; a SecAgg coordinator learns one party's input with fewer colluders than declared; parameters below the stated 128-bit level for some programs; a replayed job grant runs. | **30 days**. |
| **Medium** | A guarantee is weakened but not broken, needs several unlikely conditions, or the failure is detected later (fails closed, but late). Also: denial of service of a trust-relevant component by an unauthenticated party. | Audit records miss a security-sensitive transition; a parser panics on crafted input (process crash, no leak); a missing size limit on an authenticated endpoint. | **90 days**. |
| **Low** | Defense in depth: hardening gaps with no demonstrated path to a guarantee. | A key file created with group-readable permissions in a directory already owner-only; verbose error text; a missing security header. | Next planned release. |
| **Informational** | No security impact today: documentation errors, unclear claims, test gaps, suggestions. | A doc states a property the code does not enforce, but no deployment relies on it; an invariant without adversarial evidence. | Tracked; fixed when convenient. A wrong security claim in the docs is fixed before the next release. |

Rules:

- When in doubt between two levels, choose the higher one until the
  analysis is done.
- **Proposed policy (to be confirmed by the owner):** a finding in a research-only feature (`research-tfhe-rs`,
  `vfhe-research`, mock attestation) is rated one level lower, unless a
  production build can reach it. A finding that shows a production build
  *can* reach a research feature is at least High.
- Fix targets run from confirmation, not from the report. If a target
  cannot be met, the owner records why and the new date in the advisory.

## What every finding gets

Each accepted finding must have all of these before it is closed:

1. **An owner.** One named person, responsible until it is closed.
2. **A fix.** A commit or pull request that removes the cause, or a
   documented mitigation with a follow-up for the real fix. Accepting the
   risk is allowed only for Low and Informational findings, and only with
   a written reason.
3. **A test.** A test that fails before the fix and passes after it. It
   exercises the attack, not only the patched function.
4. **A regression invariant, where possible.** A new or extended entry in
   the assurance catalog
   ([`crates/encompute-assurance/src/catalog.rs`](../crates/encompute-assurance/src/catalog.rs)),
   so `assurance-report` keeps checking it:
   - add an `inv!` entry with the next free ID in its area (`INV-nnn`),
     worded as a testable claim, never as "guaranteed" or "proven";
   - reference the new test as evidence (`test:<file>::<fn>`), or add a
     check under `src/checks/`;
   - add the row to the matrix in [assurance.md](assurance.md) (a test
     checks every ID appears there).
   If the finding extends an existing invariant, add the new test to that
   invariant's evidence instead. If no invariant fits (for example, a
   documentation error), the finding says so.
5. **A documentation update** when the finding changes a claim: the threat
   model, the cryptography design, an example's "what this does not
   protect", or the known limitations.
6. **A changelog entry** in the release that ships the fix, naming the
   finding ID once the advisory is public.

A finding is **closed** when the fix is merged, the test and invariant are
in the release gate, and `assurance-report` passes on the release branch.

## Disclosure

- Findings stay private until a fixed release is available.
- The advisory is then published with the finding ID, severity, affected
  versions, fixed version, and credit to the reporter if they want it.
- Encompute is pre-release software. There is no embargo agreement with
  downstream users yet; if one is needed for a Critical finding, the
  maintainers arrange it case by case.

## Findings table

Keep one table per review engagement (for example in the engagement's
advisory list or tracking issue). Copy this template:

```markdown
| ID | Title | Severity | Component | Status | Owner | Reported | Confirmed | Target | Fix | Test | Invariant | Docs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ENC-SF-2026-001 | <short title> | High | encompute-secagg | open | @owner | 2026-10-01 | 2026-10-02 | 2026-11-01 | <PR link> | `crates/…/tests/….rs::<fn>` | INV-nnn (new) | threat-model.md §… |
```

Status values: `new`, `triaged`, `confirmed`, `fixing`, `fixed`
(merged, not released), `released`, `closed`, `wont-fix` (Low or
Informational, with a reason), `not-a-bug` (with a reason).

For each finding, the advisory text holds:

```markdown
### ENC-SF-YYYY-NNN: <title>

- Severity: <level>, and why (which asset, which adversary, which assumption)
- Component and files: <crate>, <file:line>
- Reproduction: <commands or test>
- Impact: <what the adversary gains>
- Fix: <what changed>
- Test: <file::function>, fails before the fix
- Invariant: <INV-nnn, new or extended>, or why none fits
- Docs changed: <files>
```
