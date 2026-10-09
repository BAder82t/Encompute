# Encompute 0.3.1: release notes

A security patch release for the stable 0.3 line. It fixes two privacy
accounting findings in the control plane (ENC-SF-2026-326 and
ENC-SF-2026-329), and changes container base images, security-policy
exceptions and third-party notices. It changes no API, format, migration or
build feature. 0.3.0 is not modified: its tag, artifacts and digests stay as
published.

## Security fix

0.3.0 documented that committed privacy spending is anchored before it is
acknowledged. A database writer who erased a spend, or rewrote a new
ledger's genesis, between the call's commit and its anchoring left the call
acknowledged and the change unnoticed. 0.3.1 acknowledges a spend or a
registration only when the anchor holds exactly what the call committed.
Upgrade; there is no migration. A client may see `500 ENC2202` for a spend
whose entry was erased in that interval, and retrying the same event is
correct. See the [changelog](../CHANGELOG.md) and
[security findings](security-findings.md).

## Why (supply chain and notices)

- **Published 0.3.0 images carry fixable base-package findings.** Scanning the
  five images in the 0.3.0 release (evaluator, control, services,
  confidential-space, training) found `perl-base` 5.36.0-7+deb12u3 (3 critical,
  4 high) and `libpcre2-8-0` 10.42-1+deb12u1 (1 high) in every one, with
  Debian fixes available. The training image also carries `torch` and
  `transformers` findings that were already reviewed and recorded as
  exceptions. Whether the affected components are reachable in these
  containers was not assessed; the images run no Perl workload of ours.
- **A notice was missing.** Two source files are ports of Apache-2.0 code from
  IBM's discrete-gaussian differential privacy repository. 0.3.0 did not carry
  the notice.

## What changed

- New pinned Debian base and an upgrade of `perl-base` and `libpcre2-8-0` in
  the runtime stage of the control, services, evaluator and confidential-space
  images; the training image moves to `python:3.11.17-slim-bookworm`.
- Five exceptions in `security/exceptions.toml` deleted (they named their own
  removal once the bases were refreshed).
- Notice and header text for the two ported files, and a checker that fails
  if they go missing.
- Anchoring of privacy spends and ledger registrations bound to the entry or
  genesis the call committed (`encompute-control`).
- Version 0.3.1 and lockfiles.

## Verifying

[verify-release.md](verify-release.md): use the tag `v0.3.1`. The new image
digests are in the release's `images.txt` files.

## What is not changed

Everything in the [0.3.0 notes](release-notes-0.3.0.md), including the open
items and limitations, still applies.
