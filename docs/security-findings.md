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

## Release candidate findings (2026)

The findings fixed in the release-candidate round: the security review
(SF-1 to SF-13), the network attack and restart suites, fuzzing and
verification. Every fix commit is on `main`, merged from its
release-candidate branch without rewriting. Owner of all: @BAder82t.
All were reported and confirmed on 2026-09-27 and fixed within their
targets, so the Target column is empty. Status `fixed` means merged, not
yet released.

| ID | Title | Severity | Component | Status | Owner | Reported | Confirmed | Target | Fix | Test | Invariant | Docs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ENC-SF-2026-001 | Cross-tenant key destruction: a key reference or revocation naming another organization's key could destroy it (SF-1) | High | encompute-keybroker, encompute-control | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `3d4f113` | `crates/encompute-control/tests/keys.rs::cross_tenant_key_ref_cannot_be_registered_or_revoked`, `crates/encompute-keybroker/tests/revocation.rs::revocations_for_another_organization_destroy_nothing` | INV-181 (new) | — |
| ENC-SF-2026-002 | The OpenBao plain-HTTP check matched a loopback prefix (`http://127.0.0.1.evil…`) (SF-2) | Medium | encompute-keybroker (`root.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `8465b5e` | `crates/encompute-keybroker/tests/lifecycle.rs::production_provider_misconfiguration_is_refused` | INV-180 (new) | — |
| ENC-SF-2026-003 | Key grants were not signed by the broker, so a substituted grant was accepted (SF-3) | Medium | encompute-attestation, encompute-keybroker | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `5681f12` | `crates/encompute-attestation/tests/attestation.rs::grants_are_signed_by_the_broker`, `crates/encompute-keybroker/tests/release.rs::a_substituted_grant_is_refused` | INV-182 (new) | — |
| ENC-SF-2026-004 | Service request signatures did not cover the query string (SF-4) | Medium | encompute-verification, encompute-control | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `6489997` | `crates/encompute-control/tests/isolation.rs::signed_service_requests_bind_the_query` | INV-174 (new) | Updated: api.md, deployment.md, threat-model.md, KNOWN_LIMITATIONS.md, the review brief and protocols.md |
| ENC-SF-2026-005 | Message deduplication did not commit in the same transaction as the message's effects (SF-5) | Medium | encompute-control (`transport.rs`, `ops/jobs.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `9aeb258` | `crates/encompute-control/tests/keys.rs::concurrent_duplicate_messages_apply_once` | INV-175 (new) | — |
| ENC-SF-2026-006 | The evaluator accepted program and key uploads without a job grant under a control plane; job IDs were guessable (SF-6) | Medium | encompute-evaluator | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `52f91a2` | `crates/encompute-evaluator/tests/uploads.rs::uploads_need_a_grant_with_a_control_plane`, `crates/encompute-evaluator/tests/uploads.rs::local_uploads_need_no_grant_and_job_ids_are_random` | INV-176 (new) | — |
| ENC-SF-2026-007 | Key file modes were set only when a file was created; an existing or leftover file kept a wider mode (SF-7) | Low | encompute-cli, encompute-keybroker | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `0780e10` | `crates/encompute-cli/tests/cli.rs::keys_and_audit`, `crates/encompute-keybroker/tests/release.rs::state_round_trips_without_printing_keys` | INV-183 (new) | — |
| ENC-SF-2026-008 | The Python SDK trusted the evaluator receipt key chosen by the control plane (SF-8) | Medium | python (`encompute/client.py`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `9be1492` | `python/tests/test_client.py::test_a_key_outside_the_pinned_set_is_refused` | INV-184 (new) | — |
| ENC-SF-2026-009 | DP aggregation receipts verified without their bound privacy receipts (SF-9) | High | encompute-secagg, encompute-privacy | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `a98cf89` | `crates/encompute-runtime/tests/privacy.rs::dp_receipts_require_bound_privacy_receipts` | INV-185 (new) | — |
| ENC-SF-2026-010 | Privacy spend was charged at the control plane only after the aggregate was released (SF-10) | High | encompute-cli (`aggregate.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `ea8f700` | `crates/encompute-cli/src/aggregate.rs::release_never_precedes_the_control_plane_reservation` | INV-186 (new) | — |
| ENC-SF-2026-011 | The training workload's `privacy_policy_id` was never bound into attestation (SF-11) | Medium | encompute-attestation, encompute-training | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `5c1cc63` | `crates/encompute-attestation/tests/attestation.rs::privacy_policy_binding` | INV-187 (new) | — |
| ENC-SF-2026-012 | Offline `verify` did not check the evidence kind and could exit 0 with unchecked bindings (SF-12) | Medium | encompute-cli | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `5a962f9` | `crates/encompute-cli/tests/cli.rs::remote_receipts_and_verify` | INV-188 (new) | README.md (`verify` exit codes) |
| ENC-SF-2026-013 | DP-SGD Poisson sampling used a seeded PRNG instead of the OS CSPRNG (SF-13) | Medium | python (`encompute/torch/dpsgd.py`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `cef6ca5` | `python/tests/test_dpsgd.py::test_poisson_sampling_draws_from_the_csprng` | INV-132 (extended) | — |
| ENC-SF-2026-014 | Slow clients (slowloris) could hold every connection thread, or all of the single-threaded key broker and coordinator | High | encompute-verification (`http.rs`), every service | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `4ecae39`, `25b5ff2` | `crates/encompute-control/tests/network_attacks.rs::slow_clients_cannot_starve_the_server`, `crates/encompute-verification/src/http.rs::a_trickled_body_is_cut_despite_a_large_declared_length` | INV-173 (new) | — |
| ENC-SF-2026-015 | Asset revocations were not anchored: restoring an older database un-revoked an asset | High | encompute-control | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `7d5b61c` | `crates/encompute-control/tests/state.rs::restoring_an_older_backup_cannot_unrevoke_an_asset` | INV-178 (new) | — |
| ENC-SF-2026-016 | `restore.sh` overwrote a newer key broker state | High | deploy/docker-compose | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `bdcea84` | `scripts/release/backup-drill.sh` | INV-178 (new) | deployment.md |
| ENC-SF-2026-017 | Jobs an evaluator was running stayed `running` after it restarted | Medium | encompute-control (`ops/jobs.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `40bf6d0` | `crates/encompute-control/tests/restart.rs::evaluator_restart_fails_its_running_jobs` | INV-177 (new) | — |
| ENC-SF-2026-018 | `backup.sh` captured the anchor after the database | Medium | deploy/docker-compose | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `bdcea84` | `scripts/release/backup-drill.sh` | INV-178 (new) | deployment.md |
| ENC-SF-2026-019 | A duplicated key release report produced duplicate `key.release` audit events | Medium | encompute-control | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `dceaba5` | `crates/encompute-control/tests/network_attacks.rs::duplicate_messages_apply_once_even_concurrently` | INV-175 (new) | — |
| ENC-SF-2026-020 | Asset `storage_uri` accepted `..` path traversal | Low | encompute-control (`model.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `dceaba5` | `crates/encompute-control/tests/network_attacks.rs::bad_artifact_references_are_refused` | INV-172 (new) | — |
| ENC-SF-2026-021 | The evaluator answered refused job grants with 500 instead of 401, 409 or 503 | Low | encompute-evaluator (`server.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `1256331` | `crates/encompute-control/tests/network_attacks.rs::evaluator_runs_only_granted_jobs_once` | INV-176 (new) | — |
| ENC-SF-2026-022 | The worker `read_frame` allocated the declared frame length (allocation abort) | Medium | encompute-evaluator (`pool.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `d181e04` | `crates/encompute-evaluator/src/pool.rs::huge_declared_lengths_are_refused_without_allocating` | INV-172 (new) | — |
| ENC-SF-2026-023 | An out-of-range sampling rate hit an assert (panic) in privacy accounting | Medium | encompute-privacy (`ledger.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `50c6931` | `crates/encompute-privacy/tests/fuzz_smoke.rs::out_of_range_sampling_rates_are_refused` | INV-172 (new) | — |
| ENC-SF-2026-024 | Tensor file and adapter layout offsets could overflow | Low | encompute-training (`layout.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `4a4bdfb` | `crates/encompute-training/tests/fuzz_smoke.rs::overflowing_offsets_are_refused` | INV-172 (new) | — |
| ENC-SF-2026-025 | Chunk sizes in the launcher HTTP parser could overflow | Low | encompute-attestation (`gcp.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `b39cb13` | `crates/encompute-attestation/src/gcp.rs::huge_chunk_sizes_are_refused` | INV-172 (new) | — |
| ENC-SF-2026-026 | Privacy ledger reads had no size limit | Low | encompute-privacy (`ledger.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `50c6931` | `crates/encompute-privacy/tests/fuzz_smoke.rs::oversized_and_malformed_ledgers_are_typed_errors` | INV-172 (new) | — |
| ENC-SF-2026-027 | A short EXECUTE reply from a worker panicked the evaluator | Low | encompute-evaluator (`pool.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `d181e04` | `crates/encompute-evaluator/src/pool.rs::malformed_execute_replies_are_errors` | INV-172 (new) | — |
| ENC-SF-2026-028 | The clock-skew check overflowed on far-future service messages | Informational | encompute-verification (`service.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `f191528` | `crates/encompute-verification/tests/fuzz_smoke.rs::resource_limits_are_typed_errors` | INV-172 (new) | — |
| ENC-SF-2026-029 | The aggregation coordinator exited before parties could collect the receipt when reporting to the control plane failed | Low | encompute-cli (`aggregate.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `f2ac47f`, superseded by `ea8f700` (it now refuses before the round) | `crates/encompute-cli/tests/aggregate_report.rs::a_coordinator_that_cannot_report_refuses_before_the_round` | INV-186 (new) | — |
| ENC-SF-2026-030 | Stale OpenFHE locking comments, and no test pinning the STD128 LWE parameters | Informational | encompute-openfhe, encompute-openfhe-client | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `661fec0` (directly on main) | `crates/encompute-openfhe-client/tests/binfhe.rs::std128_context_has_the_vetted_lwe_parameters` | INV-153 (extended) | — |
| ENC-SF-2026-031 | A stale CKKS bootstrapping error message | Informational | encompute-ckks (`params.rs`) | fixed | @BAder82t | 2026-09-27 | 2026-09-27 | — | `661fec0` (directly on main) | None: message text only | None fits: a wording error with no security property | errors.md |
| ENC-SF-2026-032 | Resuming fine-tuning after the aggregation coordinator was killed once parties had joined the round reused its SecAgg sequence; the parties refused it as a replay and the resume could not proceed. Fails closed: nothing released, nothing charged | Low | encompute.torch (`finetune.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | — | release/0.3 (rc.4) | `python/tests/test_finetune_crash.py::test_crash_then_recover_and_resume[kill-coordinator-after-join-False]` | Covered by the fine-tuning crash-recovery invariant | CHANGELOG |

## Independent review of 0.3.0-rc.3 (2026-09-28)

An external adversarial review of tag `v0.3.0-rc.3` reported 55 findings:
5 High, 15 Medium, 30 Low and 5 Informational, counting grouped items as
one. The review's own ID is given in brackets after each title. Owner of all: @BAder82t. All were
reported and confirmed on 2026-09-28. The fixes are on
`fix/rc3-review-findings`, merged for 0.3.0-rc.4; the Fix column gives
each finding's commits. Several are only partly fixed; what remains is
under "Open" below. ENC-SF-2026-088 to 094 come from a later review of
the control plane (the review's IDs are `rc.4 F1` to `F10`), reported and
confirmed on 2026-09-29.

| ID | Title | Severity | Component | Status | Owner | Reported | Confirmed | Target | Fix | Test | Invariant | Docs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ENC-SF-2026-033 | A privacy-ledger rollback made while the control plane ran was written into the state anchor, and startup then accepted it (CP-S-1) | High | encompute-control (`anchor.rs`, `ops/assets.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-10-28 | `caaf754` | `crates/encompute-control/tests/anchor_rollback.rs::online_ledger_rollback_is_refused_and_never_anchored` | INV-160 (extended) | threat-model.md §4.6, deployment.md, api.md, errors.md |
| ENC-SF-2026-034 | A frozen ledger could be unfrozen, by a database update or by restoring the same backup twice and running recover (CP-S-2) | High | encompute-control (`control.rs`, `ops/assets.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-10-28 | `caaf754` | `crates/encompute-control/tests/anchor_rollback.rs::a_frozen_ledger_stays_frozen_whatever_the_database_says` | INV-192 (new) | threat-model.md §4.6, deployment.md, api.md |
| ENC-SF-2026-035 | A co-tenant could replace another client's OpenFHE evaluation keys (key-tag poisoning); the result was wrong but its receipt verified (EV-2) | High | encompute-openfhe (`shim.cc`), encompute-evaluator | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-10-28 | `adb2dc5` | `crates/encompute-openfhe-client/tests/key_tags.rs::another_clients_keys_under_the_victims_tag_are_never_used` | INV-171 (extended) | threat-model.md §4.3, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-036 | The grant-signer pin came from the operator, so the host could substitute the training output key (incomplete fix of ENC-SF-2026-003) (KB-1) | High | encompute-keybroker (`workload.rs`, `client.rs`), encompute-training, python (`cs_worker.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-10-28 | `b7c0cd6` | `crates/encompute-keybroker/tests/grant_pinning.rs::only_broker_keys_from_the_attested_identity_are_trusted`, `python/tests/test_confidential_job.py::test_only_the_specs_broker_key_is_trusted` | INV-182 (extended) | threat-model.md §4.2, protocols.md, appsec-review-brief.md, cryptography.md, compatibility.md |
| ENC-SF-2026-037 | A training spec could name any importable callable as the model factory; workers ran it after opening the dataset (TR-1) | High | encompute-training (`spec.rs`), python (`torch/models.py`, `cs_worker.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-10-28 | `b7c0cd6` | `crates/encompute-training/tests/training.rs::a_spec_names_only_an_allowlisted_factory`, `python/tests/test_confidential_job.py::test_the_worker_refuses_other_code_before_any_key` | INV-208 (new) | threat-model.md §4.2, support-matrix.md, compatibility.md, examples/15 |
| ENC-SF-2026-038 | An audit rollback made while the control plane ran was re-anchored at the next checkpoint (CP-S-3) | Medium | encompute-control (`control.rs`, `audit.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `caaf754` | `crates/encompute-control/tests/anchor_rollback.rs::online_audit_rollback_is_never_reanchored` | INV-162 (extended) | threat-model.md §4.6, deployment.md, api.md |
| ENC-SF-2026-039 | Only revocations were anchored: a restore undid service-account and user disables and job cancellations (CP-S-4) | Medium | encompute-control (`anchor.rs`, `control.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `caaf754` | `crates/encompute-control/tests/anchor_rollback.rs::restore_and_recovery_keep_disables_and_cancellations` | INV-178 (extended) | threat-model.md §4.6, deployment.md |
| ENC-SF-2026-040 | An organization added to a project later inherited earlier asset approvals (CP-A-1) | Medium | encompute-control (`authz.rs`, `ops/jobs.rs`, migration 0003) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `caaf754` | `crates/encompute-control/tests/collaboration.rs::a_late_joiner_inherits_no_asset_approval` | INV-194 (new) | threat-model.md §4.3, api.md |
| ENC-SF-2026-041 | Service IDs were one global namespace: a tenant could squat another organization's key-broker name (CP-A-3) | Medium | encompute-control (`ops/tenancy.rs`, `ops/assets.rs`, `ops/jobs.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `caaf754` | `crates/encompute-control/tests/collaboration.rs::a_tenant_cannot_squat_another_organizations_key_broker` | INV-196 (new) | api.md |
| ENC-SF-2026-042 | No API to disable a user or remove roles, memberships, project members or approvals (CP-A-4) | Medium | encompute-control (`api.rs`, `ops/tenancy.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `caaf754` | `crates/encompute-control/tests/collaboration.rs::every_grant_can_be_withdrawn_through_the_api` | INV-197 (new) | threat-model.md §4.5, api.md |
| ENC-SF-2026-043 | Release policies in the key broker state file were not integrity-protected (KB-2) | Medium | encompute-keybroker (`store.rs`, `lib.rs`), encompute-cli (`keys upgrade-state`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `ee17952` | `crates/encompute-keybroker/tests/state_integrity.rs::an_edited_state_file_does_not_open` | INV-199 (new) | threat-model.md §4.8, protocols.md, cryptography.md, deployment.md, compatibility.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-044 | A refused program upload was still compiled and loaded (incomplete fix of ENC-SF-2026-006) (EV-1) | Medium | encompute-evaluator (`server.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `adb2dc5` | `crates/encompute-evaluator/tests/uploads.rs::a_refused_program_upload_loads_nothing` | INV-176 (extended) | — |
| ENC-SF-2026-045 | BinFHE bootstrapping keys were loaded without checking their parameters; a crafted key crashed the evaluator (EV-3) | Medium | encompute-openfhe (`binfhe.cc`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `adb2dc5` | `crates/encompute-openfhe-client/tests/binfhe.rs::foreign_bootstrapping_keys_are_refused_before_any_gate` | INV-201 (new) | threat-model.md §4.3 |
| ENC-SF-2026-046 | `encompute jobs run` and the native SDK trusted the control plane's evaluator receipt key (incomplete fix of ENC-SF-2026-008) (EV-4) | Medium | encompute-cli (`control.rs`), encompute-runtime (`remote.rs`), encompute-py | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `adb2dc5` | `crates/encompute-cli/tests/jobs_run.rs::a_key_outside_the_pin_set_is_refused_before_anything_is_sent`, `python/tests/test_client.py::test_the_native_run_enforces_the_pin_before_sending_anything` | INV-184 (extended) | threat-model.md §5.6, deployment.md, api-stability.md, errors.md |
| ENC-SF-2026-047 | A budgeted asset was aggregated with no DP, no ledger and no charge when the output was sealed (DP-1) | Medium | encompute-analysis (`confidentiality.rs`), encompute-secagg (`round.rs`), encompute-cli (`aggregate.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `1e67c3c` | `crates/encompute-secagg/src/round_tests.rs::a_budgeted_party_does_not_join_a_round_without_dp`, `crates/encompute-cli/tests/aggregate_privacy.rs::a_sealed_budgeted_aggregate_without_dp_does_not_compile` | INV-205 (new) | threat-model.md §4.4, adr/0013, compatibility.md |
| ENC-SF-2026-048 | Assets with a missing or malformed control-plane mapping were released with no reservation (incomplete fix of ENC-SF-2026-010) (SA-1) | Medium | encompute-cli (`aggregate.rs`), encompute-control (`ops/assets.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `caaf754`, `1e67c3c` | `crates/encompute-cli/src/aggregate.rs::unmapped_budgeted_assets_release_nothing`, `crates/encompute-control/tests/state.rs::a_reservation_cannot_under_declare_its_sensitivity` | INV-186 (extended), INV-198 (new) | api.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-049 | Training specs published exact privacy-unit counts and unsalted data digests (DP-2) | Medium | encompute-training (`spec.rs`), python (`torch/finetune.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `b7c0cd6` | `python/tests/test_dpsgd.py::test_the_sampling_rate_is_never_derived_from_the_data`, `python/tests/test_dpsgd.py::test_published_dataset_digests_hide_the_data` | INV-210 (new) | adr/0017, compatibility.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-050 | The operator's job descriptor set hyperparameters, seed and input adapter, which the evidence did not bind (TR-2, with KB-6) | Medium | encompute-training (`worker.rs`, `adapter.rs`), python (`cs_worker.py`, `worker.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `b7c0cd6` | `python/tests/test_confidential_job.py::test_the_descriptor_cannot_change_the_training`, `crates/encompute-training/tests/training.rs::a_worker_trains_only_from_the_previous_recorded_adapter` | INV-209 (new) | threat-model.md §4.2, compatibility.md |
| ENC-SF-2026-051 | A lookup indexed by a Boolean with 3 or more entries panicked in every compile path (EX-1) | Medium | encompute-ir (`program.rs`), encompute-exact (`bits.rs`, `plan.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `adb2dc5` | `crates/encompute-exact/tests/lowering_differential.rs::lookups_never_read_index_bits_the_index_lacks` | INV-007 (extended) | — |
| ENC-SF-2026-052 | Review documents still described grants as unsigned with TLS as the mitigation, and the SDK as trusting the control plane's key (DOC-1, with KB-3 and PY-2) | Medium | docs, security-review | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | 2026-12-27 | `bdb0b00` | None: documentation | None fits: a documentation error | threat-model.md §4.2 and §5.6, protocols.md, appsec-review-brief.md, cryptography.md |
| ENC-SF-2026-053 | A job failed at start for a revoked asset was not audited (CP-S-5) | Low | encompute-control (`ops/jobs.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `caaf754` | `crates/encompute-control/tests/jobs.rs::a_job_failed_at_start_for_a_revoked_asset_is_audited` | INV-162 (extended) | — |
| ENC-SF-2026-054 | An evaluator re-registering lifted an operator's drain; receipt-key changes were not audited (CP-S-6) | Low | encompute-control (`ops/jobs.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `caaf754` | `crates/encompute-control/tests/jobs.rs::re_registration_keeps_an_operators_drain_and_audits_the_receipt_key` | INV-162 (extended) | — |
| ENC-SF-2026-055 | `restore.sh` did not stop on SQL errors (CP-S-7) | Low | deploy/docker-compose (`restore.sh`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `caaf754` | `scripts/release/backup-drill.sh` | INV-178 (existing) | deployment.md |
| ENC-SF-2026-056 | One organization admin could satisfy four-eyes policy approval with two service accounts (CP-A-2) | Low | encompute-control (`ops/policies.rs`, `ops/tenancy.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `caaf754` | `crates/encompute-control/tests/collaboration.rs::policy_four_eyes_are_two_people_of_the_projects_owner` | INV-195 (new) | threat-model.md §4.5, api.md |
| ENC-SF-2026-057 | Cross-tenant existence oracles; project membership without the member's consent (CP-A-5) | Low | encompute-control (`ops/tenancy.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `caaf754` | `crates/encompute-control/tests/collaboration.rs::membership_needs_the_invited_organizations_consent` | INV-156 (extended) | threat-model.md §4.3, api.md, deployment.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-058 | Platform automation accounts could not be disabled (CP-A-6) | Low | encompute-control (`ops/tenancy.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `caaf754` | `crates/encompute-control/tests/collaboration.rs::a_platform_automation_account_can_be_disabled` | INV-156 (extended) | api.md |
| ENC-SF-2026-059 | Nonce retention equalled the acceptance window, so clock drift allowed replay (CP-A-7) | Low | encompute-control (`authn.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `caaf754` | `crates/encompute-control/tests/request_hardening.rs::nonces_outlive_their_acceptance_window` | INV-174 (extended) | — |
| ENC-SF-2026-060 | Control-plane hardening: planning compiled before authorization, identity-provider errors echoed, unbounded token lifetimes, a default database password in the URL query string passed the check, an unset `ENCOMPUTE_ENV` meant development, the evaluator shown to non-submitters, repeated query parameters, open `/metrics` (CP-A-8 a–h) | Low | encompute-control (`authn.rs`, `config.rs`, `api.rs`, `metrics.rs`), encompute-verification (`service.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `caaf754` | `crates/encompute-control/tests/request_hardening.rs::production_metrics_need_the_metrics_token`, `crates/encompute-control/src/config.rs::unset_or_misspelt_environment_refuses_to_start` | INV-156, INV-164, INV-174 (extended) | threat-model.md §4.5 and §4.7, api.md, deployment.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-061 | The OpenBao client forwarded its token across redirects (incomplete fix of ENC-SF-2026-002) (KB-4) | Low | encompute-keybroker (`root.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `ee17952` | `crates/encompute-keybroker/tests/root_keys.rs::openbao_redirects_are_refused_and_the_token_stays_home` | INV-180 (extended) | protocols.md, deployment.md |
| ENC-SF-2026-062 | Worker evidence self-reported its image; verify skipped the privacy policy and artifact (KB-5) | Low | encompute-training (`worker.rs`), python (`cs_worker.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `b7c0cd6` | `crates/encompute-training/tests/training.rs::worker_evidence_binds_its_spec_assets_and_attestation` | INV-147 (extended) | compatibility.md |
| ENC-SF-2026-063 | Key-broker notes: existing key-file modes, Google JWKS refresh, policy detail in 403 bodies (KB-n) | Low | encompute-keybroker, encompute-attestation (`policy.rs`, `gcp.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `ee17952` | `crates/encompute-keybroker/tests/secret_files.rs::an_existing_kek_file_must_be_private`, `crates/encompute-keybroker/tests/network_attacks.rs::refusals_do_not_reveal_the_release_policy`, `crates/encompute-attestation/tests/attestation.rs::confidential_space_keys_are_refreshed` | INV-143, INV-183 (extended), INV-200 (new) | protocols.md, deployment.md |
| ENC-SF-2026-064 | Unauthenticated program listing and key-presence oracle on a shared evaluator (EV-5) | Low | encompute-evaluator (`server.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `adb2dc5` | `crates/encompute-evaluator/tests/uploads.rs::with_a_control_plane_programs_and_keys_are_not_advertised` | INV-202 (new) | threat-model.md §4.3, appsec-review-brief.md, api-stability.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-065 | Decrypted exact outputs were not range-checked; the BGV noise model ignored additions (EV-6, EX-3) | Low | encompute-runtime (`client.rs`), encompute-exact (`bgv.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `adb2dc5` | `crates/encompute-runtime/src/client.rs::exact_outputs_outside_their_proven_range_are_refused`, `crates/encompute-evaluator/tests/exact_selection.rs::programs_beyond_the_bgv_noise_budget_do_not_run_on_bgv` | INV-203, INV-204 (new) | cryptography.md, compatibility.md |
| ENC-SF-2026-066 | BGV selection admitted integer bitwise logic that BGV cannot run (EX-2) | Low | encompute-exact (`bgv.rs`), encompute-verification (`backend.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `adb2dc5` | `crates/encompute-evaluator/tests/exact_selection.rs::integer_bitwise_logic_is_not_selected_for_bgv` | INV-170 (extended) | cryptography.md |
| ENC-SF-2026-067 | The worker's sampling rate and clip were not tied to the plan's (DP-3) | Low | python (`torch/worker.py`), encompute-py (`training.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `b7c0cd6` | `python/tests/test_dpsgd.py::test_workers_apply_the_plans_clip_and_rate` | INV-211 (new) | — |
| ENC-SF-2026-068 | Unsampled sub-organization units were charged k = 1 and labelled patient-level (DP-4) | Low | encompute-privacy (`release.rs`), encompute-runtime (`privacy.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `1e67c3c` | `crates/encompute-privacy/tests/privacy.rs::an_unsampled_patient_is_charged_the_whole_contribution_swing` | INV-207 (new) | adr/0013, compatibility.md, examples/09 |
| ENC-SF-2026-069 | A non-finite unit gradient dropped the party (a data-dependent signal) (DP-5) | Low | python (`torch/dpsgd.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `b7c0cd6` | `python/tests/test_dpsgd.py::test_non_finite_unit_gradients_contribute_nothing` | INV-130 (extended) | — |
| ENC-SF-2026-070 | Group privacy across parties was not documented (DP-6) | Low | docs | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `1e67c3c` | None: documentation | None fits: a documentation gap | adr/0017, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-071 | The party `--state` file was not crash- or race-safe (SA-2) | Low | encompute-cli (`aggregate.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `1e67c3c` | `crates/encompute-cli/src/aggregate.rs::concurrent_state_updates_are_never_lost` | INV-206 (new) | threat-model.md §4.4, adr/0012, compatibility.md |
| ENC-SF-2026-072 | Hugging Face model import followed symbolic links (TR-3) | Low | python (`torch/hf.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `b7c0cd6` | `python/tests/test_huggingface.py::test_symbolic_links_never_enter_a_package` | INV-138 (extended) | — |
| ENC-SF-2026-073 | `tokenizer_config.json` and `quantization_config` were not checked; `_attn_implementation*` keys were accepted (TR-4) | Low | python (`torch/hf.py`), encompute-training (`hf.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `b7c0cd6` | `python/tests/test_huggingface.py::test_package_settings_outside_the_allowlist_are_refused` | INV-137 (extended) | — |
| ENC-SF-2026-074 | Export and resume revocation checks relied on the beneficiary's bundle; infer skipped revocation; export matched a substring (TR-5) | Low | python (`torch/finetune.py`, `torch/infer.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `b7c0cd6` | `python/tests/test_finetune_matrix.py::test_export_denied_after_revocation_or_tampering` | INV-142 (extended) | api-stability.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-075 | The trust report honoured revocations by non-owners (TG-1) | Low | encompute-trust (`ingest.rs`, `report.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `43c87fd` | `crates/encompute-runtime/tests/trust_bundle_checks.rs::a_revocation_by_a_non_owner_is_ignored_with_a_note` | INV-213 (new) | — |
| ENC-SF-2026-076 | Ingest validation was not re-run when a bundle was rebuilt (TG-2) | Low | encompute-trust (`ingest.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `43c87fd` | `crates/encompute-runtime/tests/trust_bundle_checks.rs::an_invalid_training_spec_in_a_bundle_fails_the_report` | INV-101 (extended) | — |
| ENC-SF-2026-077 | The plan validator trusted the plan's own context; claimed proofs satisfied correctness (TG-3) | Low | encompute-planner (`validate.rs`), encompute-trust (`report.rs`), encompute-control | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `43c87fd` | `crates/encompute-planner/tests/planner.rs::the_validator_checks_the_plans_own_context_against_the_verifiers_floor`, `crates/encompute-trust/tests/report_plan_floor.rs::a_claimed_execution_proof_is_unchecked_until_the_proof_is_checked` | INV-214 (new) | api-stability.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-078 | An empty evaluator pin set failed open, and pinning was opt-in (PY-1) | Low | python (`encompute/client.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `adb2dc5` | `python/tests/test_client.py::test_an_empty_pin_set_refuses_every_evaluator` | INV-184 (extended) | threat-model.md §5.6, api-stability.md |
| ENC-SF-2026-079 | The commercial build audit passed when it could read no symbols (SC-1) | Low | scripts (`audit-commercial-build.sh`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `43c87fd` | `scripts/audit-commercial-build.sh` | INV-215 (new) | — |
| ENC-SF-2026-080 | Confidential Space images had unpinned bases and no pip hashes, and were not built by the release (SC-2) | Low | deploy/confidential-space*, `.github/workflows/release.yml` | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `43c87fd` | `scripts/release/check-pins.sh` | INV-216 (new) | release-process.md |
| ENC-SF-2026-081 | Workflow actions were pinned by tag (SC-3) | Low | `.github/workflows/` | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `43c87fd` | `scripts/release/check-pins.sh` | INV-216 (new) | release-process.md |
| ENC-SF-2026-082 | Test hooks (canary, failpoints) were honoured in production workers (SC-5) | Low | python (`torch/worker.py`, `cs_worker.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | next release | `b7c0cd6` | `python/tests/test_confidential_job.py::test_test_hooks_are_off_with_hardware_attestation` | INV-212 (new) | — |
| ENC-SF-2026-083 | Anchor compare-and-set conflicts were never reloaded (CP-S-8) | Informational | encompute-control (`anchor.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | — | `caaf754` | `crates/encompute-control/src/anchor.rs::a_lost_compare_and_set_reloads_and_reapplies` | INV-178 (extended) | deployment.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-084 | A revocation could reach the key broker before the anchor recorded it (CP-S-9) | Informational | encompute-control (`ops/assets.rs`, outbox) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | — | `caaf754` | `crates/encompute-control/tests/anchor_rollback.rs::broker_revocation_is_delivered_only_once_anchored` | INV-193 (new) | threat-model.md §4.6, deployment.md |
| ENC-SF-2026-085 | The accountant's "rounded up, never optimistic" claim held only to about 1e-13 (DP-7) | Informational | encompute-privacy (`rdp.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | — | `1e67c3c` | `crates/encompute-privacy/tests/rdp.rs::long_compositions_are_never_optimistic` | INV-131 (extended) | adr/0017 |
| ENC-SF-2026-086 | THIRD_PARTY_NOTICES omitted the permissively licensed crates' notices (SC-4) | Informational | THIRD_PARTY_NOTICES.md, scripts (`third_party_notices.py`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | — | `43c87fd` | `scripts/third_party_notices.py --check` | INV-217 (new) | release-process.md |
| ENC-SF-2026-087 | The key cache module documentation claimed isolation that did not hold (EV-7) | Informational | encompute-evaluator (`keycache.rs`) | fixed | @BAder82t | 2026-09-28 | 2026-09-28 | — | `adb2dc5` | `crates/encompute-openfhe-client/tests/key_tags.rs::another_clients_keys_under_the_victims_tag_are_never_used` | INV-171 (extended) | — |
| ENC-SF-2026-088 | A job's purpose was the request's free text, never compared with the purpose its program declares: an approval for one purpose ran a program written for another (rc.4 F1) | Medium | encompute-control (`ops/jobs.rs`) | fixed | @BAder82t | 2026-09-29 | 2026-09-29 | 2026-12-28 | `caaf754` | `crates/encompute-control/tests/collaboration.rs::an_approval_covers_only_programs_declared_for_its_purpose` | INV-194 (extended) | api.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-089 | A job's `source_assets` were the submitter's choice, never matched with the assets its program reads: leaving one out skipped its owner's approval (rc.4 F2) | Medium | encompute-control (`ops/jobs.rs`) | fixed | @BAder82t | 2026-09-29 | 2026-09-29 | 2026-12-28 | `caaf754`, `1a3d68d` | `crates/encompute-control/tests/collaboration.rs::a_job_lists_exactly_the_registered_assets_its_program_reads` | INV-194 (extended) | api.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-090 | Job approvals accepted service accounts holding an owner role (rc.4 F3) | Low | encompute-control (`ops/jobs.rs`) | fixed | @BAder82t | 2026-09-29 | 2026-09-29 | next release | `caaf754` | `crates/encompute-control/tests/collaboration.rs::a_job_is_approved_by_a_person_of_the_owner` | INV-195 (extended) | api.md |
| ENC-SF-2026-091 | Withdrawn asset approvals and left project memberships were not anchored: a database restore shared the asset, or the project, again (rc.4 F4) | Medium | encompute-control (`anchor.rs`, `control.rs`, `ops/assets.rs`, `ops/tenancy.rs`, migration 0004) | fixed | @BAder82t | 2026-09-29 | 2026-09-29 | 2026-12-28 | `caaf754` | `crates/encompute-control/tests/anchor_rollback.rs::restore_and_recovery_keep_withdrawn_approvals`, `crates/encompute-control/tests/anchor_rollback.rs::restore_and_recovery_keep_a_left_project_left` | INV-178 (extended) | api.md, deployment.md, threat-model.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-092 | Organizations an asset was shared with saw its key reference, storage location, size and full policy, and job histories showed other organizations' user IDs (rc.4 F10) | Medium | encompute-control (`ops/assets.rs`, `ops/jobs.rs`) | fixed | @BAder82t | 2026-09-29 | 2026-09-29 | 2026-12-28 | `caaf754` | `crates/encompute-control/tests/isolation.rs::collaborators_see_no_private_metadata` | INV-156 (extended) | api.md |
| ENC-SF-2026-093 | Removing a role (`memberships/remove`) was not anchored: a database restore gave the principal the role back (rc.4) | Medium | encompute-control (`anchor.rs`, `control.rs`, `ops/tenancy.rs`, migration 0004) | fixed | @BAder82t | 2026-09-29 | 2026-09-29 | 2026-12-28 | `caaf754` | `crates/encompute-control/tests/anchor_rollback.rs::restore_and_recovery_keep_a_removed_role_removed`, `crates/encompute-control/tests/anchor_rollback.rs::approvals_from_before_version_4_get_stable_ids` | INV-178 (extended) | api.md, deployment.md, threat-model.md, KNOWN_LIMITATIONS.md |
| ENC-SF-2026-094 | Source-asset lists were trusted for jobs whose program binds no registered asset (the ENC-SF-2026-089 residual): an omitted or extra asset became the job's lineage, revocation scope and trust report | Medium | encompute-control (`ops/jobs.rs`) | fixed | @BAder82t | 2026-09-29 | 2026-09-29 | 2026-12-28 | `1a3d68d` | `crates/encompute-control/tests/collaboration.rs::a_job_lists_exactly_the_assets_its_program_binds_even_its_own`, `crates/encompute-control/tests/collaboration.rs::the_derived_sources_drive_revocation_and_the_trust_report` | INV-194 (extended) | api.md, KNOWN_LIMITATIONS.md, CHANGELOG.md |

### Open (accepted / needs design)

Known issues from the release-candidate rounds that are not fixed yet.
Each needs a design decision, or is accepted for now with the mitigation
stated.

- **Several key brokers in one training job need a per-asset binding.**
  A workload trusts each broker its spec names for every asset, so a second
  broker could grant a key for the first one's assets. Specs are limited to
  exactly one broker (`TrainingSpec::validate`, tested by
  `crates/encompute-training/tests/training.rs::a_spec_binds_its_key_brokers`,
  closing the gap in ENC-SF-2026-036); an asset-to-broker map is the
  design for multi-owner custody.
- **An older key broker state file resurrects revoked keys.**
  `lifecycle_restoring_an_older_state_file_resurrects_a_revoked_key`
  documents it. Since ENC-SF-2026-043 the state file is authenticated
  under a key derived from the KEK, so an edited file does not open; but
  an older copy that was genuinely authenticated still opens, and
  restoring it by hand brings the revoked keys back. `restore.sh` keeps a
  newer broker state. Detecting the rollback needs the state's
  generation anchored outside the file (in the KMS or the control plane).
- **Revocation does not crypto-shred.** A revocation rewrites the current
  state file only; an old state file plus the unchanged KEK still yields
  the revoked keys. A per-asset KEK, or KEK rotation on revoke, would fix
  it.
- **An anchor restored from the same backup forgets later spend.** When
  the database and the anchor are restored together, privacy spend rolls
  back to the backup. Keep the anchor outside the backup set, in the
  customer's vault.
- **The evaluator program table has no eviction.** Uploaded programs stay
  in memory until the evaluator restarts.
- **Trust Graph queries are quadratic** in the number of records.
- **macOS loads two OpenMP runtimes** when OpenFHE and torch run in one
  process.
- **torch and transformers CVEs** are `not_affected` exceptions in the
  vulnerability policy until 2026-12-31.
- **The audit chain has an unanchored tail:** events after the last
  anchor can be truncated without detection.
- **A DP plan with no budgeted asset produces no privacy receipt**, so an
  aggregation receipt has nothing to bind.
- **Identity providers are not bound per organization**
  (ENC-SF-2026-057, partly fixed). Membership now needs the invited
  organization's consent and invitations answer the same whether the
  organization exists, but an identity another organization will onboard
  can still be pre-registered, and `create_user` still answers 409 for an
  existing identity.
- **The control plane bounds a reservation, but does not recompute it**
  (ENC-SF-2026-048, partly fixed). A reservation whose declared
  sensitivity is below what its own noise implies is refused, but its
  `noise_multiplier` and `sampling_rate` are still what the coordinator
  declares.
- **One control-plane process per anchor** (ENC-SF-2026-083, partly
  fixed). A lost compare-and-set now reloads and re-applies, but running
  several replicas against one anchor is not supported; the anchor's sets
  of ended jobs, withdrawn approvals, removed project memberships and
  removed roles grow without bound, and the whole anchor is rewritten on each update.
  OpenBao's KV store refuses an entry above its raft `max_entry_size`
  (1 MiB by default, roughly 25,000 to 30,000 ended jobs); past it anchor
  writes fail and the control plane fails closed (spends, cancellations
  and revocation acknowledgements stop). Mitigation for now: the
  `encompute_anchor_bytes` gauge and a warning above 512 KiB, and raising
  `max_entry_size`. The cost of keeping the anchor grows with the
  deployment's age as well: each privacy spend re-loads and re-verifies
  the whole ledger when it anchors it (on top of the verification inside
  the spend's transaction), and every security-negative operation rescans
  all the anchored-state tables. Both fail closed. A hash-chained
  governance event log replaces these sets, and both costs, before general
  availability.
- **Evaluator upload grants are reusable until they expire**
  (ENC-SF-2026-064, partly fixed), and are not bound to a client.
- **A co-tenant can block a victim's key upload** (ENC-SF-2026-035,
  residual). A client that knows the victim's key tag can upload its own
  keys under it first; the victim's upload is then refused (409) until
  the entry is evicted. The victim's result is never wrong.
- **The plan validator's exact-equality check still uses the planner's
  `derive`** (ENC-SF-2026-077, partly fixed). The validator's independent
  floor covers the core requirements only.
- **An owner-approved public unit count is released outside DP**
  (ENC-SF-2026-049, residual). A DP-SGD spec may carry the number of
  privacy units an owner approves for publication (`public_units`); that
  figure is disclosed by consent, not under the privacy guarantee.
- **Local fine-tuning revocation checks are run by the beneficiary**
  (ENC-SF-2026-074, residual). Resume, inference and export read the
  model owner's bundle and any owner-supplied bundles; the model owner
  benefits from forgetting a revocation, so enforcement relies on owners
  revoking at their key brokers or the control plane.
- **Group privacy across parties** (ENC-SF-2026-070, documented). A
  person whose records several parties hold is protected at group level
  k, not as one unit.
- **The Linux wheel may bundle libgomp**, which THIRD_PARTY_NOTICES does
  not list.
