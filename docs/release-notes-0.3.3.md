# Encompute 0.3.3: release notes

A patch release for the stable 0.3 line. It is the first supported release
that contains the fixes made in the source tagged 0.3.1: the two privacy
accounting findings in the control plane (ENC-SF-2026-326 and
ENC-SF-2026-329), the revocation and anchor findings found while closing them
(ENC-SF-2026-411, 412 and 413), the container base image refresh and the
notice changes. The product code is the same as in 0.3.2 and 0.3.1: nothing
under `crates/*/src` changed. 0.3.3 corrects a shared test helper, adds a
nonpublishing rehearsal of the release path, and updates version and
documentation. No API, format, migration or build feature changes. 0.3.0 is
not modified: its tag, artifacts and digests stay as published.

## Use 0.3.3, not 0.3.1 or 0.3.2

0.3.1 and 0.3.2 are failed release attempts. Neither produced a GitHub
release or signed artifacts. Their tags (`v0.3.1`, `v0.3.2`) are immutable
and kept as evidence, nothing built from them is supported, and the public
container image tags `0.3.1` and `0.3.2` belong to those attempts.

- **0.3.1** failed because the shipping build ran `scripts/release/env.sh`
  before exporting `OPENFHE_ROOT`, so the OpenFHE path remap was missing and
  the shipped Linux binaries did not match the ones the release gate built.
  The shipped-binary identity check refused to sign.
- **0.3.2** corrected that: the root is resolved and validated before
  `env.sh`, OpenFHE's source paths are remapped (build id `static-4`), a
  Linux path guard fails closed, and the shipping build is one shared script.
  A nonpublishing diagnostic showed the binaries agreeing across jobs on
  Ubuntu 24.04. The tag workflow's release-check job then failed on two
  timing-based regression tests,
  `w05_genesis_rewritten_in_the_window_of_the_first_spend` and
  `role_removal_undone_in_the_window_is_not_acknowledged`.

## Why those tests failed, and what changed

The test helper took its two table locks with one `LOCK TABLE a, b`.
PostgreSQL acquires the tables one after the other, so under load the
service's read after its commit could run before the simulated attacker held
the second table. Reading the server log in order, 28 of 28 natural
failures of the first test on GitHub runners were observations that tore the
window (the genesis read before the attacker's lock, the entries read after
the attack). None was an attack inside the window that the service
acknowledged. The product code was not changed.

- **One shared helper** (`crates/encompute-control/tests/common/window.rs`)
  now serves the rollback regression tests. It proves the adversarial window
  happened, or fails loudly as INCONCLUSIVE; it never passes or fails on a
  race it did not control.
- **A negative control** shows the helper reports INCONCLUSIVE when the
  window is not proven.
- **W05b** stays a separate test of the accepted race after verification,
  which the proven-window tests do not cover.
- **A nonpublishing rehearsal** of the whole Ubuntu 24.04 release path:
  `gh workflow run release.yml --ref <branch> -f rehearsal=true`. It builds
  the Linux binaries and tarball, builds the five images locally, runs the
  full release check and the shipped-binary comparison, and runs the window
  tests 20 times each under CPU load. It signs nothing, pushes nothing and
  creates no release. See [release-process.md](release-process.md).

## Security fixes (from the 0.3.1 source)

The fixes, their upgrade steps and their limits are those of the 0.3.1 notes
([release-notes-0.3.1.md](release-notes-0.3.1.md)), which describe this
source. In short: a privacy spend or a ledger registration is acknowledged
only when the anchor holds exactly what the call committed; revocations,
disables, cancellations, withdrawals and removals likewise; a ledger the
anchor holds no genesis for refuses spends until an operator reviews and
anchors it; and the database is checked against the anchored transitions
before every request. Upgrade with
[Upgrading from 0.3.0 to 0.3.3](deployment.md#upgrading-from-030-to-033-security-upgrade):
back up the database and the anchor first, review every ledger's genesis
before `anchor-ledgers`, and do not downgrade by swapping the 0.3.0 binary
back in. The container base images are refreshed; 0.3.0 images carry known
base-package findings. See the [changelog](../CHANGELOG.md) and
[security findings](security-findings.md).

## Verifying

[verify-release.md](verify-release.md): use the tag `v0.3.3`. The image
digests are in the release's `images.txt` files.

## What is not changed

Everything in the [0.3.0 notes](release-notes-0.3.0.md), including the open
items and limitations (the check-to-use gap, the anchor restored with the
database, no supported downgrade, and the review of ledger genesis before
`anchor-ledgers`), still applies.
