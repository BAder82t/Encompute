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

### Open (accepted / needs design)

Known issues from the same round that are not fixed yet. Each needs a
design decision, or is accepted for now with the mitigation stated.

- **An older key broker state file resurrects revoked keys.**
  `lifecycle_restoring_an_older_state_file_resurrects_a_revoked_key`
  documents it. `restore.sh` keeps a newer broker state, but restoring
  the file by hand still brings the keys back.
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
- **`hf::check_config` should reject `_attn_implementation*` keys.**
- **The audit chain has an unanchored tail:** events after the last
  anchor can be truncated without detection.
- **A DP plan with no budgeted asset produces no privacy receipt**, so an
  aggregation receipt has nothing to bind.
