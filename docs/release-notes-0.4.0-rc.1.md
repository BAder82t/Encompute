# Encompute 0.4.0-rc.1: release notes

This is a release candidate for the 0.4 line, **governed cross-organization
computation**. It is pre-release. It is not claimed production-ready, and the
new authorization, key, revocation and log surface has not had an independent
security review; one is planned before 0.4.0. The stable release remains
[0.3.0](release-notes-0.3.0.md).

## What is in it

Governed projects ([public-sector.md](public-sector.md)): organizations keep
ownership and key control, authorize specific purposes, and receive evidence of
what was authorized, computed and released.

- Governance keys, purposes, owner-signed authorizations with four-eyes
  approval, immutable dataset versions, strict validity windows,
  non-retroactive revocation.
- Sovereign key custody and two-part key release: a key broker releases a key
  only for a signed authorization plus a short-lived, single-use release
  ticket, so a compromised control plane can only deny.
- Release classes and forms, derived results with lineage, retention, auditor
  access.
- A hash-chained governance log with per-project partitions, a constant-size
  state anchor, mirror compaction, audit-head anchoring, and verifiable audit.
- Revocation that crypto-shreds by key-encryption-key rotation.
- One-time, client-bound upload grants (ENC2608).
- Privacy scopes and populations, and an aggregate (statistics) mode.
- Residency constraints and operators.
- Production TLS: with `ENCOMPUTE_ENV=production` the control plane requires
  `sslmode=verify-full` to PostgreSQL (see "BREAKING" in the
  [changelog](../CHANGELOG.md)). Native TLS (rustls with ring only) and a
  reference production topology.

Scale of the change over 0.3.0: 14 new database migrations (0005 to 0018),
assurance invariants 150 to 179, 30 new `ENC27xx` error codes, no new crates
and no new third-party packages.

## Other changes since 0.3.0

- **Concurrent job starts no longer fail on a state-anchor race.** A typed
  conflict, one bound of three attempts, and no repeated side effects; see the
  changelog.
- **Container base images:** the pinned Debian bases move to versions with the
  fixed `perl-base` and `libpcre2-8-0`, and the training image moves to
  `python:3.11.17-slim-bookworm`.
- **Third-party notices** now cover the two source files derived from IBM's
  discrete-gaussian differential privacy code (Apache-2.0), with a checker.
- **The test runner records provenance** (commit, tree, clean start and end) and
  its default manifest is now the governance manifest.

## What is still open

- **No independent review of the 0.4 surface.** Authorization and revocation,
  the governance log and anchor, crypto-shred and the generation mark, release
  tickets and upload grants, privacy population accounting and evidence
  verification are the review priorities.
- Record linkage is not built; decryption control of a governed result by a
  recipient is not built; the cross-agency report cannot read SATISFIED yet.
  See the [support matrix](support-matrix.md) and
  [known limitations](../KNOWN_LIMITATIONS.md).
- Compaction of the governance mirror has been proven only against a
  development-mode OpenBao.
- Under very heavy concurrent contention the bounded anchor retry can still
  exhaust; the call then fails closed with ENC2202, never with a wrong
  decision.
- The published 0.3.0 container images contain the older Debian packages; the
  0.3.0 artifacts are not modified.

## Verifying it

[verify-release.md](verify-release.md) describes how to verify a release's
signatures, provenance, SBOMs and image digests. Use the tag `v0.4.0-rc.1`.
