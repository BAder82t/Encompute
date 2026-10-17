# Encompute 0.3.1: release notes

> **0.3.1 was not released.** Its release workflow stopped at the shipped-binary
> identity check, before signing or any GitHub release. Do not use it, and do
> not use [0.3.2](release-notes-0.3.2.md), also a failed attempt. Use
> [0.3.3](release-notes-0.3.3.md), which has the same fixes. These notes
> describe the 0.3.1 source and stay as the detailed record of the fixes.

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
The same gap existed for revocations, disables, cancellations, approval
withdrawals, project leaves and role removals (ENC-SF-2026-411); they are now
acknowledged only when the anchor holds what the call wrote. Two more were found while
closing these out and are fixed: a ledger the anchor never recorded accepted
any genesis at its first spend (ENC-SF-2026-412; a crash or outage during
registration, or a database writer, could produce one), and a transition the
anchor held, reverted while the service ran, permitted the operation it
denied until the next restart (ENC-SF-2026-413). Upgrade; there is no
migration, with one operator step if `encompute_unanchored_ledgers` is not 0
after the upgrade (see
[Upgrading from 0.3.0 to 0.3.3](deployment.md#upgrading-from-030-to-033-security-upgrade):
back up the database and the anchor first, review every ledger's genesis
before `anchor-ledgers`, and do not downgrade by swapping the 0.3.0 binary
back in). A client may see `500 ENC2202` for a spend
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
- Spends are refused on a ledger the anchor holds no genesis for; the new
  command `encompute-control anchor-ledgers` and gauge
  `encompute_unanchored_ledgers`.
- The database is checked against the anchored revocations, disables,
  cancellations, withdrawals and removals before every request and on every
  tick; a mismatch latches the control plane (ENC2202, `/ready` 503).
- Defensive revalidation inside the transaction for the API operations that
  call `ops::revalidate`: creating an organization, user, service account,
  project, plan or policy proposal; disabling a user or service account;
  removing a role; recording a key rotation; adding or removing a project
  member; registering, approving, withdrawing the approval of and revoking
  an asset; authorizing a privacy spender and a privacy spend; approving a
  policy; submitting, cancelling, approving, starting and completing a job;
  the evaluator's receipt (REST and message); registering an evaluator and
  reporting its status; and the sending account and roles of every message kind
  `receive_message` accepts, including `key.release`: locked and re-read, and
  a lock wait past 5 s fails the request. The message path does not lock
  assets or approvals, and a `job.completed` message waits for its job row
  without the 5 s bound. Not covered: bootstrap, the background tick (scheduling,
  evaluator expiry, outbox delivery, anchor sync and the audit checkpoint,
  `checkpoint_audit`), the command-line recovery commands, and read-only
  operations. The key broker's release decision is the broker's own; the
  control plane only records its report. It narrows the gap between the live
  check and the effect; it does not close or bound it. Status: the original
  check-to-use attack (B2) was NOT EXECUTED; the defensive revalidation is
  implemented; full database-writer TOCTOU resistance is NOT INDEPENDENTLY
  ESTABLISHED; the B3 limitation is unchanged (authority recreated under a
  new ID is not detected).
- Not eliminated: the anchor restored together with the database, and
  compromised anchor or signing-key custody, remain out of scope; a request
  already past its check can finish; see `KNOWN_LIMITATIONS.md`.
- Version 0.3.1 and lockfiles.

Release boundary: 0.3.1 strengthens externally anchored privacy accounting, revocation and denial operations against identified database rollback attacks. It does not provide comprehensive protection against every form of database-administrator compromise or independently authenticate every newly introduced authority record.

## Verifying

[verify-release.md](verify-release.md): there is nothing to verify for 0.3.1: it
produced no signed artifacts. Use the tag `v0.3.3`.

## What is not changed

Everything in the [0.3.0 notes](release-notes-0.3.0.md), including the open
items and limitations, still applies.
