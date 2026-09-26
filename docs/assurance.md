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
| `planner_property` | 2 000 generated planning scenarios | 50 000 |

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
- **INV-111, INV-114:** plan tampering is checked in memory (every
  mechanism removal, every field mutation), not across processes.
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
| INV-110 | Every hard trust requirement of an accepted plan is satisfied by a valid, available mechanism, as the independent validator confirms. | `gradients_need_secure_aggregation_and_budgets_need_dp` | `the_validator_refuses_weakened_plans` | `planner_property` | `observed_execution_matches_the_approved_plan` |
| INV-111 | Removing any required mechanism from a plan makes validation fail. | `private_model_training_needs_attested_confidential_compute` | `the_validator_refuses_weakened_plans` | `planner_property` | gap |
| INV-112 | The planner never weakens confidentiality, release, privacy or verification requirements; profiles only add requirements. | `strong_profile_attests_the_coordinator_or_fails` | `the_validator_refuses_weakened_plans` | `planner_property` | `test_presets_expand_visibly` |
| INV-113 | When no available mechanism combination satisfies the policy, there is no plan (PLANNING FAILED), never a weaker one. | `private_exact_eligibility_is_verified_fhe` | `verified_training_requires_attested_workloads` | `planner_adversarial` | `test_no_valid_mechanism_fails_closed` |
| INV-114 | Plans are deterministic, and the PlanId changes with every change to the plan; the validator refuses every security-relevant change. | `plans_are_deterministic_and_identified` | `planner_plan_id_binding` | `planner_plan_id_binding` | gap |
| INV-115 | The trust report refuses execution evidence that does not match the approved plan: another PlanId, no plan, or a missing mechanism. | `observed_execution_matches_the_approved_plan` | `observed_execution_matches_the_approved_plan` | `observed_execution_matches_the_approved_plan` | `observed_execution_matches_the_approved_plan` |
| INV-120 | Private base-model keys are released only to workloads attesting to the approved training spec (image, code, configuration, plan). | `test_training_run_is_trusted_end_to_end` | `test_keys_only_for_the_approved_workload` | `examples/15_confidential_lora/attack.py` | `test_adapter_is_usable_and_changed` |
| INV-121 | Raw LoRA updates never cross the aggregate-only boundary: they leave a worker only as masked secure-aggregation contributions. | `test_training_run_is_trusted_end_to_end` | `test_no_raw_update_is_ever_written` | `secagg_coordinator_sees_no_input` | `examples/15_confidential_lora/attack.py` |
| INV-122 | Every released training aggregate is charged to each contributing dataset's budget; training stops when the next release would exceed it. | `test_every_release_is_charged` | `test_budget_exhaustion_stops_training` | `examples/15_confidential_lora/attack.py` | `test_training_run_is_trusted_end_to_end` |
| INV-123 | Checkpoint resume cannot roll privacy state back, and refuses another project, spec or policy. | `checkpoint_resume_never_rolls_back_privacy` | `test_checkpoint_rollback_and_swap_are_refused`<br>`test_resume_matrix` | `examples/15_confidential_lora/attack.py` | `test_checkpoint_rollback_and_swap_are_refused` |
| INV-124 | Every adapter is linked, by signed records, to its base model, datasets, training spec and aggregation round; tampering fails the report. | `test_lineage_links_model_data_and_evidence` | `test_tampered_adapter_evidence_fails_the_report` | `adapter_records_are_signed` | `test_training_run_is_trusted_end_to_end` |
| INV-125 | A derived adapter cannot be exported when any parent's policy forbids it. | `export_follows_every_parent` | `test_export_is_denied_by_inherited_policy` | `examples/15_confidential_lora/attack.py`<br>`test_export_denied_after_revocation_or_tampering` | `test_export_is_denied_by_inherited_policy`<br>`test_export_follows_every_parent` |
| INV-126 | Changing any security-relevant training setting (model, code, layout, LoRA, optimizer, privacy, aggregation, participants, plan) changes the TrainingSpecId. | `attestation_policy_binds_the_spec_and_code`<br>`test_training_spec_id` | `every_field_changes_the_spec_id`<br>`test_model_digest_covers_weights_architecture_and_config`<br>`test_dataset_commitment_covers_every_sample_label_and_order`<br>`test_every_layout_change_changes_the_digest` | `test_keys_only_for_the_approved_workload` | `examples/15_confidential_lora/attack.py` |
| INV-127 | Training fails closed when the approved plan cannot be satisfied: no trusted environment means no training, never ordinary training. | `test_training_run_is_trusted_end_to_end` | `test_no_trusted_environment_fails_closed` | `planner_adversarial` | `test_wrong_model_layout_or_dataset_is_refused` |
| INV-128 | A crash or kill at any point of a training round never leaves a privacy release uncharged or an unaccepted adapter usable; recovery finalizes or discards, and training resumes or stops safely. | `test_crash_then_recover_and_resume` | `checkpoint_resume_never_rolls_back_privacy` | `dp_crash_injection` | `test_crash_then_recover_and_resume` |
| INV-129 | Patient data, base-model weights, raw updates and asset keys never appear outside their allowed locations, in any file or output of a run. | `test_the_run_completed` | `test_no_raw_update_files` | `test_raw_updates_never_leave_a_worker` | `test_patient_data_stays_with_its_owner`<br>`test_model_weights_never_appear_in_the_clear`<br>`test_keys_stay_in_the_owners_key_store` |
| INV-130 | Each privacy unit's gradient is computed per example, grouped by unit and clipped before summation, so one unit moves a worker's contribution by at most the clip, for any microbatch size. | `test_vectorized_gradients_match_the_reference_for_any_microbatch` | `test_unit_index_groups_records_by_patient` | `test_one_patient_moves_the_sum_by_at_most_the_clip`<br>`test_contributions_bypassing_the_attested_worker_are_refused` | `test_patient_run_is_satisfied_and_binds_every_setting` |
| INV-131 | The Poisson-subsampled Rényi DP accountant agrees with an independent reference and is never optimistic; composition and the affordable-release boundary are consistent. | `curves_match_the_reference_and_are_never_optimistic`<br>`epsilon_matches_the_reference_and_is_never_optimistic` | `ledger_costs_use_rdp_only_with_sampled_releases` | `dp_rdp_accountant_properties` | `test_the_ledgers_charge_what_the_preview_projected` |
| INV-132 | Poisson sampling uses operating-system randomness inside the attested worker: no party's seed chooses the sample, and each unit is included independently. | `test_poisson_sampling_uses_os_randomness` | `test_workers_report_nothing_about_their_data` | `test_poisson_sampling_uses_os_randomness` | `test_raw_updates_never_leave_a_worker` |
| INV-133 | Every DP-SGD setting (unit, clip, sampling, noise, delta, grouping, accountant, batch, unit counts) is bound in the TrainingSpecId; changing one gets no model key. | `test_patient_run_is_satisfied_and_binds_every_setting` | `every_dp_sgd_setting_changes_the_spec_id` | `test_changed_dp_settings_get_no_model_key` | `examples/16_patient_private_lora/attack.py` |
| INV-134 | A run whose planned rounds would exceed any budget is denied before training starts; the ledgers charge exactly what the preview projected. | `test_the_preview_uses_the_sampled_accountant` | `test_over_budget_runs_are_denied_before_training` | `examples/16_patient_private_lora/attack.py` | `test_the_ledgers_charge_what_the_preview_projected` |
| INV-135 | Patient-level privacy is never claimed for organization-level training: the compiler, the planner and the trust report each refuse it. | `test_patient_run_is_satisfied_and_binds_every_setting` | `test_the_planner_refuses_patient_claims_without_per_example_clipping`<br>`test_organizations_cannot_be_sampled` | `test_the_trust_report_refuses_patient_claims_from_organization_training` | `examples/16_patient_private_lora/attack.py` |
| INV-136 | A Hugging Face training run is bound to an immutable model package: its resolved revision, every file's digest, the tokenizer and the library versions; changing any of them gets no model key. | `test_packages_are_content_addressed`<br>`test_hub_revisions_resolve_and_credentials_are_never_stored` | `hugging_face_packages_and_peft_are_bound_and_checked` | `test_changed_settings_get_no_model_key` | `test_the_run_is_trusted_and_binds_the_package` |
| INV-137 | Confidential workers never execute repository code: remote code, custom-code configurations and trust_remote_code are refused, and models are rebuilt from Transformers-native classes only. | `test_the_run_is_trusted_and_binds_the_package` | `test_unsafe_repositories_are_refused`<br>`hugging_face_packages_and_peft_are_bound_and_checked` | `examples/17_huggingface_peft/attack.py` | `examples/17_huggingface_peft/attack.py` |
| INV-138 | Only safetensors, configuration and tokenizer files enter a model package; pickled or unknown files are refused before any loading. | `test_packages_are_content_addressed` | `test_unsafe_repositories_are_refused` | `hugging_face_packages_and_peft_are_bound_and_checked` | `examples/17_huggingface_peft/attack.py` |
| INV-139 | The PEFT adapter layout is canonical and identical for every participant; every PEFT setting is bound in the TrainingSpecId. | `test_the_peft_layout_is_canonical` | `test_changed_settings_get_no_model_key`<br>`hugging_face_packages_and_peft_are_bound_and_checked` | `examples/17_huggingface_peft/attack.py` | `test_exported_adapters_load_with_standard_peft` |
| INV-140 | Tokenization and chunking cannot change the declared privacy grouping: every chunk keeps its record's unit, and a regrouped or ungrouped dataset is refused. | `test_tokenization_keeps_each_patients_records_together` | `test_workers_refuse_regrouped_or_ungrouped_text` | `examples/17_huggingface_peft/attack.py` | `test_the_run_is_trusted_and_binds_the_package` |
| INV-141 | A model without valid per-unit gradients cannot satisfy patient-level privacy: the fast and reference gradient paths agree with a per-record reference, and training fails closed when neither works. | `test_both_gradient_paths_match_the_reference` | `test_no_per_unit_gradients_fails_closed` | `test_both_gradient_paths_match_the_reference` | `test_the_run_is_trusted_and_binds_the_package` |
| INV-142 | An adapter is exported as PEFT files only when every parent permits it, no parent is revoked and the trust report is satisfied; otherwise nothing is written. | `test_exported_adapters_load_with_standard_peft` | `test_private_adapters_are_never_exported` | `test_export_after_revocation_writes_nothing` | `examples/17_huggingface_peft/attack.py` |
| INV-143 | Production model and dataset keys are released only to a hardware-attested workload running the approved training image, acting for the participant whose keys they are; development (mock) evidence never receives them. | `test_the_approved_workload_trains_and_its_evidence_verifies` | `test_mock_evidence_gets_no_production_keys`<br>`production_brokers_refuse_development_evidence` | `test_a_genuine_tee_with_another_image_gets_no_keys`<br>`test_a_session_acts_for_one_participant_only` | `examples/18_confidential_space_hf/job.py` |
| INV-144 | Debug-enabled Confidential Space workloads cannot receive production asset keys. | `test_the_approved_workload_trains_and_its_evidence_verifies` | `test_a_debug_workload_gets_no_keys` | `untrusted_workloads_receive_no_key` | `examples/18_confidential_space_hf/job.py` |
| INV-145 | A genuine TEE running an unapproved image, or the approved image under another training spec, cannot receive production asset keys. | `test_the_approved_workload_trains_and_its_evidence_verifies` | `test_a_genuine_tee_with_another_image_gets_no_keys` | `test_another_training_spec_gets_no_keys` | `examples/18_confidential_space_hf/job.py` |
| INV-146 | Training asset key grants are bound to one fresh attested session: a replayed token, challenge or grant receives nothing. | `grants_open_only_in_their_session` | `freshness` | `test_replayed_evidence_and_outputs_are_refused` | `examples/18_confidential_space_hf/job.py` |
| INV-147 | A confidential training output is sealed, and bound by signed evidence to its training spec, participant, round, source assets and attestation; substituted assets or a second output for a round are refused. | `worker_evidence_binds_its_spec_assets_and_attestation` | `test_substituted_assets_are_refused` | `test_replayed_evidence_and_outputs_are_refused` | `test_the_approved_workload_trains_and_its_evidence_verifies`<br>`test_the_output_is_sealed_to_attested_workloads` |
| INV-148 | Plaintext model weights, patient records, per-patient gradients and asset keys never cross the confidential workload boundary in the tested deployment. | `test_the_output_is_sealed_to_attested_workloads` | `test_no_plaintext_leaves_the_workload` | `test_no_plaintext_leaves_the_workload` | `examples/18_confidential_space_hf/job.py` |
| INV-149 | Exact programs run encrypted on OpenFHE exact give exactly the clear reference's and the mock's results, for every supported operation and width: no tolerance. | `openfhe_exact_equals_clear_reference_and_mock` | `eight_bit_operations_are_exhaustively_exact` | `random_programs_on_openfhe_exact` | `openfhe_exact_end_to_end`<br>`examples/19_openfhe_exact/run.sh` |
| INV-150 | Production builds run exact programs on OpenFHE exact and never on TFHE-rs: the compiler, the evaluator and the planner select OpenFHE exact, and a request for TFHE-rs is BACKEND UNAVAILABLE, not a fallback. | `production_builds_select_openfhe_exact_and_refuse_tfhe_rs` | `exact_programs_plan_openfhe_exact_never_tfhe_rs_by_default` | `examples/19_openfhe_exact/run.sh` | `scripts/exact-demo.sh` |
| INV-151 | Production artifacts contain no TFHE-rs: the dependency graph, SBOM, CLI, evaluator, Python extension, wheel and container are audited, and the audit rejects a research build. | `scripts/audit-commercial-build.sh` | `scripts/sbom.py` | `.github/workflows/ci.yml` | `scripts/release-check.sh` |
| INV-152 | OpenFHE exact ciphertexts and keys are bound to their backend, parameter set, client key and type: objects under another key, parameter set or backend, and corrupted objects, are refused before any gate runs. | `openfhe_exact_end_to_end` | `wrong_keys_parameters_backends_and_corruption_fail_closed` | `examples/19_openfhe_exact/forge.py` | `examples/19_openfhe_exact/run.sh` |
| INV-153 | OpenFHE exact runs only the vetted parameter profile (STD128 with GINX bootstrapping, 128-bit, 2^-135 per gate), and every field of it is bound into the parameter-set ID that artifacts, keys and ciphertexts carry. | `the_profile_is_vetted_and_bound_into_the_parameter_id` | `wrong_keys_parameters_backends_and_corruption_fail_closed` | `examples/19_openfhe_exact/forge.py` | `examples/19_openfhe_exact/run.sh` |
| INV-154 | Programs outside OpenFHE exact's capability matrix are refused at compile time, never partway through an encrypted run. | `unary_operations_shifts_casts_select_and_lookup` | `production_builds_select_openfhe_exact_and_refuse_tfhe_rs` | `examples/19_openfhe_exact/wide.py` | `examples/19_openfhe_exact/run.sh` |
| INV-155 | Semantic transcripts do not depend on the exact backend, and OpenFHE exact agrees with TFHE-rs on the same programs in research CI; receipts bind the backend that actually ran. | `transcripts_are_backend_independent` | `openfhe_exact_end_to_end` | `openfhe_exact_equals_tfhe_rs` | `examples/19_openfhe_exact/run.sh` |
| INV-156 | An authenticated identity cannot read or use resources owned solely by another organization (projects, assets, policies, jobs, privacy ledgers, trust reports, key references, audit records) without an explicit collaboration grant. | `every_route_authenticates_authorizes_and_isolates` | `cross_tenant_attacks_fail` | `credentials_are_checked` | `scripts/enterprise-e2e.sh` |
| INV-157 | Production asset keys are protected by the configured customer root key provider, and never silently fall back to local or plaintext development storage: an unavailable, disabled or wrong provider, organization or key version releases nothing. | `openbao_wraps_unwraps_rotates_rewraps_and_revokes` | `development_root_key_wraps_rotates_and_is_refused_in_production` | `openbao_failures_never_fall_back` | `scripts/enterprise-e2e.sh` |
| INV-158 | Duplicate, reordered or replayed job submissions and transport deliveries cannot produce duplicate security-sensitive effects: one job per idempotency key, one charge per privacy event, one receipt per job. | `submission_is_idempotent_even_concurrently` | `privacy_spending_is_race_safe_and_idempotent` | `lifecycle_receipt_trust_and_duplicate_messages`<br>`secagg_privacy_events_arrive_once_through_messages` | `deploy/docker-compose/smoke.sh` |
| INV-159 | A control-plane restart cannot forget committed privacy spending, jobs or trust evidence. | `restart_keeps_spending_and_restoring_an_older_backup_is_refused` | `restart_preserves_jobs_and_never_replays` | `privacy_spending_is_race_safe_and_idempotent` | `scripts/enterprise-e2e.sh` |
| INV-160 | Restoring an older database cannot silently roll back authoritative privacy or audit state: startup is refused until an operator's explicit recovery freezes the rolled-back ledgers (treated as exhausted). | `restart_keeps_spending_and_restoring_an_older_backup_is_refused` | `truncated_audit_and_tampered_or_missing_anchor_are_refused` | `audit_chain_is_tamper_evident_and_anchored` | `scripts/enterprise-e2e.sh` |
| INV-161 | A revoked asset cannot start a new authorized job or receive a new key release: jobs not yet running fail, new submissions are refused (also when racing the revocation), and the key broker destroys the key. | `revocation_stops_future_use` | `revocation_racing_submissions_leaves_no_usable_job` | `openbao_wraps_unwraps_rotates_rewraps_and_revokes` | `scripts/enterprise-e2e.sh` |
| INV-162 | Audit records identify every security-sensitive state transition in a tamper-evident, anchored chain, without containing protected payloads (keys, data, weights, gradients, input values). | `lifecycle_receipt_trust_and_duplicate_messages`<br>`key_releases_and_rotations_are_audited` | `audit_chain_is_tamper_evident_and_anchored` | `truncated_audit_and_tampered_or_missing_anchor_are_refused` | `scripts/enterprise-e2e.sh` |
| INV-163 | An evaluator executes only jobs compatible with its registered backend and parameter profile, only with an unexpired grant from the pinned control plane naming it and the job's program, and only after the control plane consents to the start. | `jobs_run_only_on_compatible_ready_evaluators` | `job_grants_bind_issuer_evaluator_program_and_expiry` | `every_route_authenticates_authorizes_and_isolates` | `scripts/enterprise-e2e.sh` |
| INV-164 | Production mode rejects development identities and tokens, development key stores and root keys, missing signing keys, default database credentials and plain-HTTP identity providers. | `production_refuses_insecure_fallbacks` | `oidc_tokens_and_production_refusals` | `development_root_key_wraps_rotates_and_is_refused_in_production` | `scripts/enterprise-e2e.sh` |
| INV-165 | The control plane is not a trust anchor: a job's trust report is rebuilt from signed evidence (grant, receipt, commitments, plan) and trusted keys on every request, so edited database records cannot make a job trusted. | `lifecycle_receipt_trust_and_duplicate_messages` | `lifecycle_receipt_trust_and_duplicate_messages` | `cross_tenant_attacks_fail` | `scripts/enterprise-e2e.sh` |
