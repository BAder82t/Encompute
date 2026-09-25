# Assurance

For every security claim Encompute makes, the assurance suite keeps four
kinds of evidence:

- **Positive:** the mechanism works when used correctly.
- **Negative:** a violation is refused.
- **Adversarial:** an attacker actively tries to bypass it.
- **End to end:** the property survives composition with the rest of the
  system.

Each claim is an invariant with a stable ID (`INV-nnn`), defined in
[`crates/encompute-assurance/src/catalog.rs`](../crates/encompute-assurance/src/catalog.rs).
Its evidence is either an assurance check in that crate or an existing
test or script. The report confirms that every referenced test still
exists, so the catalog cannot silently go stale.

## What a passing report means

A passing report says: **"All tested security invariants satisfied."**

That means the documented invariants held for the tested cases, execution
modes and integration boundaries, under the threat models in
[threat-model.md](threat-model.md). It does not mean Encompute is proven
secure. Testing cannot establish the security of the cryptography, of the
TEE hardware, or of properties no test exercises.

## Running it

```sh
cargo build --release -p encompute-assurance --bins --examples
./target/release/assurance-report --json assurance-report.json --md assurance-report.md
./target/release/assurance-report --nightly     # larger populations
./target/release/assurance-report --only dp_crash_injection
```

The report exits 1 if any invariant is violated. A check that fails,
panics or does not run counts as a violation, and so does a reference to a
test that no longer exists. CI treats this exit code as the release gate.

Each run records its scale and how many cases every check tried:

| Check | Quick (pull requests) | Nightly |
|---|---|---|
| `secagg_sum_sweep` | n in {2, 3, 4, 5, 8, 13, 20} | n = 2..100 |
| `secagg_collusion_bound` | n ≤ 64, every colluding count and threshold | n ≤ 255 |
| `dp_sampler_statistics` | 20 000 samples × 4 variances | 400 000 × 4 |
| `dp_multi_parent_atomicity` | 4 parents | 12 parents |
| `dp_crash_injection` | 5 failpoints × 1 | 5 failpoints × 5 |
| `dp_multi_process_double_spend` | 8 processes | 100 processes |

The other checks are exhaustive at either scale: every-field receipt
mutation, the ledger tamper list, and invalid noise.

**Crash injection.** Crash injection uses failpoints compiled into
`encompute-privacy` only under its `failpoints` feature. The
`assurance-helper` child process enables that feature through a
dev-dependency. It is an example rather than a binary, so resolver 2 never
enables failpoints in a production build.

**Property-based and differential suites.** These run in the existing test
suites at larger sizes nightly (`conformance.yml`). The exact-compiler
differential runs 25 000 programs. The OpenFHE conformance runs the full
10 080-point parameter grid and 200 encrypted programs.

## CI

| Job | When | What |
|---|---|---|
| `ci.yml` / `mock` | every pull request | `cargo test`, including the assurance crate's quick checks and catalog tests |
| `ci.yml` / `assurance` | every pull request | the quick report: gate, and `assurance-report.{json,md}` as artifacts |
| `ci.yml` / `openfhe`, `exact-research` | every pull request | encrypted backends, verified execution, evaluator binary audit |
| `assurance.yml` | nightly | the nightly report, plus `cargo deny` (advisories, bans, sources) |
| `conformance.yml` | nightly | parameter grid, encrypted programs, 25 000-program exact differential |

## Adding an invariant

1. Add an `inv!` entry to the catalog with the next free ID in its area.
   Word the claim as something testable, never as "guaranteed" or "proven".
2. Reference existing tests (`test:<file>::<fn>`), or add a check under
   `src/checks/`, register it in `CHECKS`, and add its test to
   `tests/assurance.rs`.
3. Add the invariant to the matrix below. A test checks that every ID
   appears here.

## Known gaps

These kinds of evidence are missing. The report lists them as tracked gaps,
not failures:

- **INV-010:** there is no adversarial attempt to smuggle client crypto
  past the binary audit.
- **INV-053:** there is no multi-process collusion scenario. The bound is
  checked exhaustively in the model and against the protocol in memory.
- **INV-061:** there is no negative test that a biased sampler is detected.
- **INV-065, INV-070:** there are no concurrent or crashing coordinators in
  the CLI round.
- **INV-071:** there is no adversarial or end-to-end test of the sensitivity
  bound beyond the property test.
- **INV-081:** there is no adversarial scan of logs and error output for
  key material.
- **INV-101, INV-103:** there is no multi-process trust-bundle scenario for
  these (the CLI round covers INV-100 and INV-102).

## Matrix

| ID | Claim | Positive | Negative | Adversarial | End to end |
|---|---|---|---|---|---|
| INV-001 | Accepted CKKS programs compute the reference semantics within their precision target. | `logistic_demo_on_mock` | `diff_test_reports_failures` | `lowering_preserves_semantics` | `accepted_programs_meet_their_precision_encrypted` |
| INV-002 | Accepted exact programs equal the reference interpreter bit for bit. | `flagship_lowers_and_runs` | `wrong_scheme_and_overflow_are_refused` | `random_programs_match_interpreter_exactly` | `random_programs_on_tfhe_rs` |
| INV-003 | Possible overflow, underflow or out-of-range values are compile errors, never wrap-around. | `flagship_semantics_text_and_ranges` | `overflow_is_a_compile_error` | `exact_analysis_is_sound` | `wide_ranges_fail_closed` |
| INV-004 | Parameters meet the security table; unreachable depth or precision is refused, never weakened. | `shallow_circuit_fits_small_ring` | `errors_have_codes` | `refusals_are_justified` | `parameter_selection_conforms_to_table_and_openfhe` |
| INV-005 | Artifacts are reproducible, carry no key material, and any corruption is refused without a panic. | `artifact_round_trips_and_is_reproducible` | `tampered_artifacts_are_rejected` | `corrupted_artifacts_never_panic` | `policy_artifact_round_trips_and_detects_tampering` |
| INV-006 | Ciphertext envelopes are bound to kind, scheme, parameters, program and key; any byte change is refused. | `round_trip_and_items` | `every_binding_is_enforced` | `mutations_never_pass_or_panic` | `round_trip_and_rejections` |
| INV-007 | Parsers never panic on arbitrary input (IR text, envelopes, HTTP requests). | `print_parse_round_trip` | `parse_errors_carry_line_numbers` | `arbitrary_bytes_never_panic`<br>`parse_never_panics_on_arbitrary_text` | `malformed_requests_are_rejected_with_codes` |
| INV-008 | CKKS and exact schemes never cross: envelopes, keys and backends of one are refused by the other. | `exact_model_runs_clear_and_mock` | `schemes_do_not_cross` | `exact_program_in_workers` | `exact_remote_round_trip` |
| INV-010 | The evaluator binary links no key generation, encryption or decryption. | `scripts/audit-evaluator-binary.sh` | `scripts/audit-evaluator-binary.sh` | gap | `scripts/two-machine-demo.sh` |
| INV-011 | The evaluator never holds a secret key; clients' keys upload once and unknown clients are refused. | `remote_round_trip_uploads_program_and_keys_once` | `mock_enforces_rotation_keys_and_depth` | `concurrent_jobs_crash_isolation_and_replay` | `remote_receipts_and_verify` |
| INV-020 | Every field of an execution receipt is bound by the evaluator's signature. | `valid_receipt_verifies_and_is_not_a_proof` | `every_tampering_fails_closed` | `execution_receipt_mutation` | `tampering_fails_closed` |
| INV-021 | A receipt does not verify for another request, output, program, policy or evaluator (no replay). | `remote_receipts_verify_for_both_schemes` | `receipts_do_not_transfer_between_executions` | `execution_receipt_mutation` | `receipts_bind_the_policy` |
| INV-022 | A malicious evaluator's signed lie is caught when proofs are required (research: V3a re-execution). | `honest_evaluation_is_verified` | `proof_tampering_fails_closed` | `malicious_evaluator_is_caught` | `remote_verified_execution` |
| INV-023 | Transcripts are deterministic, contain no runtime values, and any semantic change changes their hash. | `deterministic_across_compilations` | `strict_parsing` | `every_semantic_change_changes_the_hash` | `receipts_bind_the_transcript_and_form_a_statement` |
| INV-030 | Policy join is a lattice meet: derived data is never less restricted than its inputs. | `the_training_scenario` | `illegal_flows_are_compile_errors` | `kinds_cannot_be_laundered` | `illegal_flows_fail_compilation` |
| INV-031 | Data is used only for its declared purpose and released only to permitted recipients. | `join_is_a_lattice_meet` | `neither_party_sees_the_other` | `contradictory_or_unsafe_declarations` | `privacy_explain_and_graph` |
| INV-032 | aggregate_only data leaves only through a declared aggregation boundary, to authorized parties. | `only_sums_of_one_input_per_party` | `aggregate_only_needs_the_boundary` | `the_aggregate_is_not_public_or_for_anyone` | `attacks_fail_closed` |
| INV-033 | Owners must permit declassification; the policy artifact cannot be weakened after compilation. | `policy_ids_are_deterministic_and_bound_to_the_spec` | `owners_must_permit_aggregate_release` | `policy_artifact_round_trips_and_detects_tampering` | `receipts_bind_the_policy` |
| INV-040 | Evidence verifies only for the approved image, spec, policy, TEE, TCB and a fresh challenge. | `mock_happy_path` | `policy_mismatches` | `tampering_and_substitution`<br>`freshness` | `receipts_bind_the_attested_session` |
| INV-041 | Keys are released only to an attested, approved workload, as HPKE grants that open only in their session. | `honest_workload_receives_its_key` | `no_key_without_attestation` | `untrusted_workloads_receive_no_key`<br>`grants_open_only_in_their_session` | `two_party_demo_over_http` |
| INV-042 | Revoked keys are destroyed; rotation rewraps; production never falls back to plaintext storage. | `wrapped_key_store` | `revoke_destroys_and_rewrap_rotates` | `production_brokers_refuse_development_evidence` | `attestation_and_key_release` |
| INV-043 | Production policies refuse mock evidence and debug or out-of-date workloads. | `confidential_space_happy_path` | `production_policies_refuse_mock_evidence` | `confidential_space_rejections`<br>`debug_and_tcb` | `attested_coordinator_round` |
| INV-050 | The aggregate is exactly the sum of the surviving parties' inputs. | `secagg_sum_sweep` | `tampered_masked_contribution_is_refused` | `messages_are_authenticated_and_bound` | `three_hospitals_over_http` |
| INV-051 | Dropouts down to the threshold still give the survivors' exact sum; below it nothing is released. | `secagg_sum_sweep` | `aborts_below_the_threshold` | `tolerates_dropouts_down_to_the_threshold` | `dropouts_within_the_threshold` |
| INV-052 | A malicious or equivocating coordinator learns no individual input. | `secagg_coordinator_sees_no_input` | `thresholds_below_a_majority_are_refused` | `equivocating_coordinator_learns_nothing` | `secure_aggregation_round` |
| INV-053 | With up to the declared number of colluding parties, no split-quorum attack recovers an honest input. | `collusion_bound_sets_the_threshold` | `secagg_collusion_bound` | `collusion_bound_defeats_split_survivor_sets` | gap |
| INV-054 | Contributions, their metadata and the aggregation receipt are signed and bound to the round and spec. | `three_hospitals_over_http` | `contribution_metadata_is_bound` | `attacks_fail_closed` | `attested_participants` |
| INV-055 | Quantization cannot overflow the modulus; clipping is always reported. | `codec_round_trip` | `quantization_overflow_is_a_compile_error` | `clipping_is_never_hidden` | `mean_divides_by_the_contributors` |
| INV-060 | The zCDP accountant matches the reference conversion and is monotone and conservative. | `matches_the_reference` | `invalid_budgets_and_mechanisms` | `monotone_and_conservative` | `accounting_is_deterministic_and_composes` |
| INV-061 | The discrete Gaussian sampler has the stated distribution (mean 0, variance sigma^2). | `discrete_gaussian_statistics` | gap | `dp_sampler_statistics` | `rounds_until_the_budget_is_spent` |
| INV-062 | No release without noise; weak noise is charged at its true cost. | `rounds_until_the_budget_is_spent` | `dp_invalid_noise` | `weaker_mechanisms_are_not_the_approved_spec` | `privacy_budgets_need_a_mechanism_at_the_release_boundary` |
| INV-063 | Releases continue until the budget is spent, then every further release is denied and reserves nothing. | `rounds_until_the_budget_is_spent` | `duplicate_release_is_refused` | `dp_multi_process_double_spend` | `rounds_until_the_budget_is_spent` |
| INV-064 | Spent budget survives restart; a crashed release's charge stands and its round cannot be rerun. | `rounds_until_the_budget_is_spent` | `dp_crash_injection` | `dp_crash_injection` | `rounds_until_the_budget_is_spent` |
| INV-065 | Concurrent releases, in threads or separate processes, cannot double-spend a budget. | `dp_multi_process_double_spend` | `concurrent_releases_cannot_double_spend` | `dp_multi_process_double_spend` | gap |
| INV-066 | Any edit, deletion, insertion, reordering or truncation of a ledger is refused. | `accounting_is_deterministic_and_composes` | `tampering_rollback_and_reset_are_detected` | `dp_ledger_tampering` | `ledger_rollback_deletion_reset_and_substitution_fail_closed` |
| INV-067 | Ledger rollback or reset is detected by any owner holding a later checkpoint. | `tampering_rollback_and_reset_are_detected` | `tampering_rollback_and_reset_are_detected` | `dp_ledger_tampering` | `any_owner_detects_another_assets_rollback` |
| INV-068 | Privacy receipts bind output, parameters, ledger position and signer; every field is covered. | `receipts_bind_output_ledger_and_parameters` | `receipts_bind_output_ledger_and_parameters` | `dp_receipt_mutation` | `attested_coordinator_binds_the_privacy_configuration` |
| INV-069 | A release charged to several assets is all-or-nothing. | `dp_multi_parent_atomicity` | `dp_multi_parent_atomicity` | `dp_crash_injection` | `rounds_until_the_budget_is_spent` |
| INV-070 | A crash at any step of a release never yields an unaccounted output or a corrupt ledger. | `dp_crash_injection` | `dp_crash_injection` | `dp_crash_injection` | gap |
| INV-071 | The charged sensitivity bounds the encoded sum's movement for one privacy unit. | `sensitivity_bounds_the_encoded_difference` | `accounting_is_deterministic_and_composes` | gap | gap |
| INV-080 | No secret input appears in what an untrusted party sees (coordinator messages, artifacts). | `artifact_round_trips_and_is_reproducible` | `no_runtime_values_in_transcripts` | `secagg_coordinator_sees_no_input` | `three_hospitals_over_http` |
| INV-081 | Key files are owner-only and keys never appear in debug output. | `state_round_trips_without_printing_keys` | `keys_and_audit` | gap | gap |

| INV-100 | The trust report checks every signature against keys the verifier supplies; evidence without an anchor is never reported as trusted. | `a_whole_collaboration_verifies` | `nothing_vouches_for_itself` | `nothing_vouches_for_itself` | `secure_aggregation_round` |
| INV-101 | The graph the report reads is exactly what its evidence implies; any added, dropped or edited edge, node or attribute fails. | `a_whole_collaboration_verifies` | `tampered_evidence_fails_the_report` | `edges_come_from_the_evidence` | gap |
| INV-102 | Every asset a program uses is approved by each owner for that program, unexpired and unrevoked; a revocation lists everything derived from the asset. | `owners_must_approve_the_program` | `owners_must_approve_the_program` | `revocation_shows_its_reach_and_forbids_later_use` | `secure_aggregation_round` |
| INV-103 | Recorded privacy releases stay within the budget the program declares, with finite values, signed by a trusted coordinator; absent required evidence is never satisfied. | `privacy_releases_answer_to_the_declared_budget` | `absent_evidence_is_not_satisfied` | `privacy_releases_answer_to_the_declared_budget` | gap |
