# Encompute 0.3.2: release notes

A patch release for the stable 0.3 line. It is the first supported release
that contains the fixes made in the source tagged 0.3.1: the two privacy
accounting findings in the control plane (ENC-SF-2026-326 and
ENC-SF-2026-329), the revocation and anchor findings found while closing them
(ENC-SF-2026-411, 412 and 413), the container base image refresh and the
notice changes. The product code is the 0.3.1 source; 0.3.2 changes the
release pipeline only. No API, format, migration or build feature changes.
0.3.0 is not modified: its tag, artifacts and digests stay as published.

## Use 0.3.2, not 0.3.1

0.3.1 was never released as a complete release. Its release workflow built
and gated the artifacts, then stopped at the shipped-binary identity check,
before signing or creating a draft release: the three Linux binaries the
shipping job built did not have the digests of the binaries the gate had
approved. The tag `v0.3.1` is kept as evidence of that attempt and must not
be used; nothing built from it is supported.

## Why the digests differed, and what changed

- **Build order.** The shipping job sourced `scripts/release/env.sh` and only
  then set `OPENFHE_ROOT`. `env.sh` computes the OpenFHE path remap once, from
  the root it sees; the shipping build saw none, so OpenFHE header paths
  (`<checkout>/.deps/openfhe/include/...`) stayed in the binaries, while the
  gate's builds, which had the root set first, remapped them to `/openfhe`.
  A diagnostic run reproduced both digest sets exactly on a clean 24.04
  runner, in either order, on two independent runners. Now `env.sh` resolves
  and validates `OPENFHE_ROOT` first: unset, it is `.deps/openfhe` when that
  exists; set, it is used as given and must be a valid static install, or
  sourcing fails. Every caller exports the root before sourcing, and the
  shipping build is one script (`scripts/release/build-release-binaries.sh`)
  that the `binaries` job and the diagnostic both run.
- **OpenFHE's own paths.** The same binaries carried the source paths of the
  OpenFHE checkout (`.deps/src/openfhe-development/...`), from OpenFHE's own
  objects. They agreed across jobs only because both used the same checkout
  directory. `scripts/install-openfhe.sh` now remaps the OpenFHE source and
  install directories (`/openfhe-src`, `/openfhe`). This changes the OpenFHE
  objects and so every binary digest relative to 0.3.1.
- **Path guard.** `scripts/release/check-binary-paths.sh` fails the `binaries`
  job (Linux) and the reproducibility check if a binary names a build path.
  The macOS binaries are not covered.
- **Diagnostic mode.** `gh workflow run release.yml --ref <branch> -f
  diagnostic=true` builds the binaries in several configurations on two
  runners and compares digests, without publishing anything.

## Security fixes (from the 0.3.1 source)

The fixes, their upgrade steps and their limits are those of the 0.3.1 notes
([release-notes-0.3.1.md](release-notes-0.3.1.md)), which describe this
source. In short: a privacy spend or a ledger registration is acknowledged
only when the anchor holds exactly what the call committed; revocations,
disables, cancellations, withdrawals and removals likewise; a ledger the
anchor holds no genesis for refuses spends until an operator reviews and
anchors it; and the database is checked against the anchored transitions
before every request. Upgrade with
[Upgrading from 0.3.0 to 0.3.2](deployment.md#upgrading-from-030-to-032-security-upgrade):
back up the database and the anchor first, review every ledger's genesis
before `anchor-ledgers`, and do not downgrade by swapping the 0.3.0 binary
back in. See the [changelog](../CHANGELOG.md) and
[security findings](security-findings.md).

## Verifying

[verify-release.md](verify-release.md): use the tag `v0.3.2`. The image
digests are in the release's `images.txt` files.

## What is not changed

Everything in the [0.3.0 notes](release-notes-0.3.0.md), including the open
items and limitations, still applies.
