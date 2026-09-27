//! The invariant catalog: every security claim Encompute makes, with its
//! evidence. Evidence is either an assurance check in this crate
//! (`check:<name>`, run by `assurance-report`) or an existing test, script
//! or CI step (`test:<file>::<fn>`, `script:<file>`), which the report
//! confirms still exists so the catalog cannot silently go stale.

use serde::Serialize;

/// What a piece of evidence shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The mechanism works when used correctly.
    Positive,
    /// A violation is refused.
    Negative,
    /// An attacker actively tries to bypass it.
    Adversarial,
    /// The property survives composition with the rest of the system.
    EndToEnd,
}

pub const KINDS: [Kind; 4] = [
    Kind::Positive,
    Kind::Negative,
    Kind::Adversarial,
    Kind::EndToEnd,
];

#[derive(Clone, Debug, Serialize)]
pub struct Invariant {
    pub id: &'static str,
    pub area: &'static str,
    pub claim: &'static str,
    pub evidence: &'static [(Kind, &'static str)],
}

use Kind::*;

macro_rules! inv {
    ($id:literal, $area:literal, $claim:literal, [$(($k:ident, $e:literal)),* $(,)?]) => {
        Invariant { id: $id, area: $area, claim: $claim, evidence: &[$(($k, $e)),*] }
    };
}

pub const INVARIANTS: &[Invariant] = &[
    // Compiler, artifacts, envelopes.
    inv!("INV-001", "compiler", "Accepted CKKS programs compute the reference semantics within their precision target.", [
        (Positive, "test:crates/encompute-runtime/tests/mock.rs::logistic_demo_on_mock"),
        (Negative, "test:crates/encompute-runtime/tests/mock.rs::diff_test_reports_failures"),
        (Adversarial, "test:crates/encompute-runtime/tests/mock.rs::lowering_preserves_semantics"),
        (EndToEnd, "test:crates/encompute-runtime/tests/conformance.rs::accepted_programs_meet_their_precision_encrypted"),
    ]),
    inv!("INV-002", "compiler", "Accepted exact programs equal the reference interpreter bit for bit.", [
        (Positive, "test:crates/encompute-exact/tests/lower.rs::flagship_lowers_and_runs"),
        (Negative, "test:crates/encompute-exact/tests/lower.rs::wrong_scheme_and_overflow_are_refused"),
        (Adversarial, "test:crates/encompute-exact/tests/lower.rs::random_programs_match_interpreter_exactly"),
        (EndToEnd, "test:crates/encompute-tfhe-client/tests/exact.rs::random_programs_on_tfhe_rs"),
    ]),
    inv!("INV-003", "compiler", "Possible overflow, underflow or out-of-range values are compile errors, never wrap-around.", [
        (Positive, "test:crates/encompute-analysis/tests/exact.rs::flagship_semantics_text_and_ranges"),
        (Negative, "test:crates/encompute-analysis/tests/exact.rs::overflow_is_a_compile_error"),
        (Adversarial, "test:crates/encompute-analysis/tests/exact.rs::exact_analysis_is_sound"),
        (EndToEnd, "test:crates/encompute-analysis/tests/exact.rs::wide_ranges_fail_closed"),
    ]),
    inv!("INV-004", "compiler", "Parameters meet the security table; unreachable depth or precision is refused, never weakened.", [
        (Positive, "test:crates/encompute-ckks/src/params.rs::shallow_circuit_fits_small_ring"),
        (Negative, "test:crates/encompute-ckks/src/params.rs::errors_have_codes"),
        (Adversarial, "test:crates/encompute-openfhe/tests/conformance.rs::refusals_are_justified"),
        (EndToEnd, "test:crates/encompute-openfhe/tests/conformance.rs::parameter_selection_conforms_to_table_and_openfhe"),
    ]),
    inv!("INV-005", "artifacts", "Artifacts are reproducible, carry no key material, and any corruption is refused without a panic.", [
        (Positive, "test:crates/encompute-runtime/tests/model.rs::artifact_round_trips_and_is_reproducible"),
        (Negative, "test:crates/encompute-runtime/tests/model.rs::tampered_artifacts_are_rejected"),
        (Adversarial, "test:crates/encompute-runtime/tests/model.rs::corrupted_artifacts_never_panic"),
        (EndToEnd, "test:crates/encompute-runtime/tests/policy.rs::policy_artifact_round_trips_and_detects_tampering"),
    ]),
    inv!("INV-006", "envelopes", "Ciphertext envelopes are bound to kind, scheme, parameters, program and key; any byte change is refused.", [
        (Positive, "test:crates/encompute-protocol/tests/envelope.rs::round_trip_and_items"),
        (Negative, "test:crates/encompute-protocol/tests/envelope.rs::every_binding_is_enforced"),
        (Adversarial, "test:crates/encompute-protocol/tests/envelope.rs::mutations_never_pass_or_panic"),
        (EndToEnd, "test:crates/encompute-runtime/tests/sessions.rs::round_trip_and_rejections"),
    ]),
    inv!("INV-007", "envelopes", "Parsers never panic on arbitrary input (IR text, envelopes, HTTP requests).", [
        (Positive, "test:crates/encompute-ir/tests/ir.rs::print_parse_round_trip"),
        (Negative, "test:crates/encompute-ir/tests/ir.rs::parse_errors_carry_line_numbers"),
        (Adversarial, "test:crates/encompute-protocol/tests/envelope.rs::arbitrary_bytes_never_panic"),
        (Adversarial, "test:crates/encompute-ir/tests/ir.rs::parse_never_panics_on_arbitrary_text"),
        (EndToEnd, "test:crates/encompute-runtime/tests/network.rs::malformed_requests_are_rejected_with_codes"),
    ]),
    inv!("INV-008", "compiler", "CKKS and exact schemes never cross: envelopes, keys and backends of one are refused by the other.", [
        (Positive, "test:crates/encompute-runtime/tests/exact.rs::exact_model_runs_clear_and_mock"),
        (Negative, "test:crates/encompute-runtime/tests/exact.rs::schemes_do_not_cross"),
        (Adversarial, "test:crates/encompute-evaluator/tests/workers.rs::exact_program_in_workers"),
        (EndToEnd, "test:crates/encompute-runtime/tests/exact.rs::exact_remote_round_trip"),
    ]),
    // Evaluator key boundary.
    inv!("INV-010", "evaluator", "The evaluator binary links no key generation, encryption or decryption.", [
        (Positive, "script:scripts/audit-evaluator-binary.sh"),
        (Negative, "script:scripts/audit-evaluator-binary.sh"),
        (EndToEnd, "script:scripts/two-machine-demo.sh"),
    ]),
    inv!("INV-011", "evaluator", "The evaluator never holds a secret key; clients' keys upload once and unknown clients are refused.", [
        (Positive, "test:crates/encompute-runtime/tests/network.rs::remote_round_trip_uploads_program_and_keys_once"),
        (Negative, "test:crates/encompute-runtime/tests/mock.rs::mock_enforces_rotation_keys_and_depth"),
        (Adversarial, "test:crates/encompute-evaluator/tests/workers.rs::concurrent_jobs_crash_isolation_and_replay"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::remote_receipts_and_verify"),
    ]),
    // Receipts, transcripts, malicious evaluator.
    inv!("INV-020", "receipts", "Every field of an execution receipt is bound by the evaluator's signature.", [
        (Positive, "test:crates/encompute-verification/tests/receipts.rs::valid_receipt_verifies_and_is_not_a_proof"),
        (Negative, "test:crates/encompute-verification/tests/receipts.rs::every_tampering_fails_closed"),
        (Adversarial, "check:execution_receipt_mutation"),
        (EndToEnd, "test:crates/encompute-runtime/tests/receipts.rs::tampering_fails_closed"),
    ]),
    inv!("INV-021", "receipts", "A receipt does not verify for another request, output, program, policy or evaluator (no replay).", [
        (Positive, "test:crates/encompute-runtime/tests/receipts.rs::remote_receipts_verify_for_both_schemes"),
        (Negative, "test:crates/encompute-verification/tests/receipts.rs::receipts_do_not_transfer_between_executions"),
        (Adversarial, "check:execution_receipt_mutation"),
        (EndToEnd, "test:crates/encompute-runtime/tests/policy.rs::receipts_bind_the_policy"),
    ]),
    inv!("INV-022", "receipts", "A malicious evaluator's signed lie is caught when proofs are required (research: V3a re-execution).", [
        (Positive, "test:crates/encompute-runtime/tests/vfhe.rs::honest_evaluation_is_verified"),
        (Negative, "test:crates/encompute-runtime/tests/vfhe.rs::proof_tampering_fails_closed"),
        (Adversarial, "test:crates/encompute-runtime/tests/vfhe.rs::malicious_evaluator_is_caught"),
        (EndToEnd, "test:crates/encompute-runtime/tests/vfhe.rs::remote_verified_execution"),
    ]),
    inv!("INV-023", "receipts", "Transcripts are deterministic, contain no runtime values, and any semantic change changes their hash.", [
        (Positive, "test:crates/encompute-exact/tests/transcript.rs::deterministic_across_compilations"),
        (Negative, "test:crates/encompute-exact/tests/transcript.rs::strict_parsing"),
        (Adversarial, "test:crates/encompute-exact/tests/transcript.rs::every_semantic_change_changes_the_hash"),
        (EndToEnd, "test:crates/encompute-runtime/tests/receipts.rs::receipts_bind_the_transcript_and_form_a_statement"),
    ]),
    // Confidentiality policy.
    inv!("INV-030", "policy", "Policy join is a lattice meet: derived data is never less restricted than its inputs.", [
        (Positive, "test:crates/encompute-analysis/tests/confidentiality.rs::the_training_scenario"),
        (Negative, "test:crates/encompute-analysis/tests/confidentiality.rs::illegal_flows_are_compile_errors"),
        (Adversarial, "test:crates/encompute-analysis/tests/confidentiality.rs::kinds_cannot_be_laundered"),
        (EndToEnd, "test:crates/encompute-runtime/tests/policy.rs::illegal_flows_fail_compilation"),
    ]),
    inv!("INV-031", "policy", "Data is used only for its declared purpose and released only to permitted recipients.", [
        (Positive, "test:crates/encompute-analysis/tests/confidentiality.rs::join_is_a_lattice_meet"),
        (Negative, "test:crates/encompute-analysis/tests/confidentiality.rs::neither_party_sees_the_other"),
        (Adversarial, "test:crates/encompute-analysis/tests/confidentiality.rs::contradictory_or_unsafe_declarations"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::privacy_explain_and_graph"),
    ]),
    inv!("INV-032", "policy", "aggregate_only data leaves only through a declared aggregation boundary, to authorized parties.", [
        (Positive, "test:crates/encompute-analysis/tests/aggregation.rs::only_sums_of_one_input_per_party"),
        (Negative, "test:crates/encompute-analysis/tests/aggregation.rs::aggregate_only_needs_the_boundary"),
        (Adversarial, "test:crates/encompute-analysis/tests/aggregation.rs::the_aggregate_is_not_public_or_for_anyone"),
        (EndToEnd, "test:crates/encompute-runtime/tests/aggregation.rs::attacks_fail_closed"),
    ]),
    inv!("INV-033", "policy", "Owners must permit declassification; the policy artifact cannot be weakened after compilation.", [
        (Positive, "test:crates/encompute-runtime/tests/policy.rs::policy_ids_are_deterministic_and_bound_to_the_spec"),
        (Negative, "test:crates/encompute-analysis/tests/aggregation.rs::owners_must_permit_aggregate_release"),
        (Adversarial, "test:crates/encompute-runtime/tests/policy.rs::policy_artifact_round_trips_and_detects_tampering"),
        (EndToEnd, "test:crates/encompute-runtime/tests/policy.rs::receipts_bind_the_policy"),
    ]),
    // Attestation and key release.
    inv!("INV-040", "attestation", "Evidence verifies only for the approved image, spec, policy, TEE, TCB and a fresh challenge.", [
        (Positive, "test:crates/encompute-attestation/tests/attestation.rs::mock_happy_path"),
        (Negative, "test:crates/encompute-attestation/tests/attestation.rs::policy_mismatches"),
        (Adversarial, "test:crates/encompute-attestation/tests/attestation.rs::tampering_and_substitution"),
        (Adversarial, "test:crates/encompute-attestation/tests/attestation.rs::freshness"),
        (EndToEnd, "test:crates/encompute-runtime/tests/attested.rs::receipts_bind_the_attested_session"),
    ]),
    inv!("INV-041", "keybroker", "Keys are released only to an attested, approved workload, as HPKE grants that open only in their session.", [
        (Positive, "test:crates/encompute-keybroker/tests/release.rs::honest_workload_receives_its_key"),
        (Negative, "test:crates/encompute-keybroker/tests/release.rs::no_key_without_attestation"),
        (Adversarial, "test:crates/encompute-keybroker/tests/release.rs::untrusted_workloads_receive_no_key"),
        (Adversarial, "test:crates/encompute-attestation/tests/attestation.rs::grants_open_only_in_their_session"),
        (EndToEnd, "test:crates/encompute-keybroker/tests/release.rs::two_party_demo_over_http"),
    ]),
    inv!("INV-042", "keybroker", "Revoked keys are destroyed; rotation rewraps; production never falls back to plaintext storage.", [
        (Positive, "test:crates/encompute-keybroker/tests/release.rs::wrapped_key_store"),
        (Negative, "test:crates/encompute-keybroker/tests/release.rs::revoke_destroys_and_rewrap_rotates"),
        (Adversarial, "test:crates/encompute-keybroker/tests/release.rs::production_brokers_refuse_development_evidence"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::attestation_and_key_release"),
    ]),
    inv!("INV-043", "attestation", "Production policies refuse mock evidence and debug or out-of-date workloads.", [
        (Positive, "test:crates/encompute-attestation/tests/attestation.rs::confidential_space_happy_path"),
        (Negative, "test:crates/encompute-attestation/tests/attestation.rs::production_policies_refuse_mock_evidence"),
        (Adversarial, "test:crates/encompute-attestation/tests/attestation.rs::confidential_space_rejections"),
        (Adversarial, "test:crates/encompute-attestation/tests/attestation.rs::debug_and_tcb"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::attested_coordinator_round"),
    ]),
    // Secure aggregation.
    inv!("INV-050", "secagg", "The aggregate is exactly the sum of the surviving parties' inputs.", [
        (Positive, "check:secagg_sum_sweep"),
        (Negative, "test:crates/encompute-secagg/tests/protocol.rs::tampered_masked_contribution_is_refused"),
        (Adversarial, "test:crates/encompute-secagg/tests/protocol.rs::messages_are_authenticated_and_bound"),
        (EndToEnd, "test:crates/encompute-runtime/tests/aggregation.rs::three_hospitals_over_http"),
    ]),
    inv!("INV-051", "secagg", "Dropouts down to the threshold still give the survivors' exact sum; below it nothing is released.", [
        (Positive, "check:secagg_sum_sweep"),
        (Negative, "test:crates/encompute-secagg/tests/protocol.rs::aborts_below_the_threshold"),
        (Adversarial, "test:crates/encompute-secagg/tests/protocol.rs::tolerates_dropouts_down_to_the_threshold"),
        (EndToEnd, "test:crates/encompute-runtime/tests/aggregation.rs::dropouts_within_the_threshold"),
    ]),
    inv!("INV-052", "secagg", "A malicious or equivocating coordinator learns no individual input.", [
        (Positive, "check:secagg_coordinator_sees_no_input"),
        (Negative, "test:crates/encompute-secagg/tests/protocol.rs::thresholds_below_a_majority_are_refused"),
        (Adversarial, "test:crates/encompute-secagg/tests/protocol.rs::equivocating_coordinator_learns_nothing"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::secure_aggregation_round"),
    ]),
    inv!("INV-053", "secagg", "With up to the declared number of colluding parties, no split-quorum attack recovers an honest input.", [
        (Positive, "test:crates/encompute-analysis/tests/aggregation.rs::collusion_bound_sets_the_threshold"),
        (Negative, "check:secagg_collusion_bound"),
        (Adversarial, "test:crates/encompute-secagg/tests/protocol.rs::collusion_bound_defeats_split_survivor_sets"),
    ]),
    inv!("INV-054", "secagg", "Contributions, their metadata and the aggregation receipt are signed and bound to the round and spec.", [
        (Positive, "test:crates/encompute-runtime/tests/aggregation.rs::three_hospitals_over_http"),
        (Negative, "test:crates/encompute-runtime/tests/aggregation.rs::contribution_metadata_is_bound"),
        (Adversarial, "test:crates/encompute-runtime/tests/aggregation.rs::attacks_fail_closed"),
        (EndToEnd, "test:crates/encompute-runtime/tests/aggregation.rs::attested_participants"),
    ]),
    inv!("INV-055", "secagg", "Quantization cannot overflow the modulus; clipping is always reported.", [
        (Positive, "test:crates/encompute-analysis/tests/aggregation.rs::codec_round_trip"),
        (Negative, "test:crates/encompute-analysis/tests/aggregation.rs::quantization_overflow_is_a_compile_error"),
        (Adversarial, "test:crates/encompute-analysis/tests/aggregation.rs::clipping_is_never_hidden"),
        (EndToEnd, "test:crates/encompute-runtime/tests/aggregation.rs::mean_divides_by_the_contributors"),
    ]),
    // Differential privacy.
    inv!("INV-060", "dp", "The zCDP accountant matches the reference conversion and is monotone and conservative.", [
        (Positive, "test:crates/encompute-privacy/src/accountant.rs::matches_the_reference"),
        (Negative, "test:crates/encompute-privacy/tests/privacy.rs::invalid_budgets_and_mechanisms"),
        (Adversarial, "test:crates/encompute-privacy/src/accountant.rs::monotone_and_conservative"),
        (EndToEnd, "test:crates/encompute-privacy/tests/privacy.rs::accounting_is_deterministic_and_composes"),
    ]),
    inv!("INV-061", "dp", "The discrete Gaussian sampler has the stated distribution (mean 0, variance sigma^2).", [
        (Positive, "test:crates/encompute-privacy/tests/privacy.rs::discrete_gaussian_statistics"),
        (Adversarial, "check:dp_sampler_statistics"),
        (EndToEnd, "test:crates/encompute-runtime/tests/privacy.rs::rounds_until_the_budget_is_spent"),
    ]),
    inv!("INV-062", "dp", "No release without noise; weak noise is charged at its true cost.", [
        (Positive, "test:crates/encompute-privacy/tests/privacy.rs::rounds_until_the_budget_is_spent"),
        (Negative, "check:dp_invalid_noise"),
        (Adversarial, "test:crates/encompute-runtime/tests/privacy.rs::weaker_mechanisms_are_not_the_approved_spec"),
        (EndToEnd, "test:crates/encompute-analysis/tests/aggregation.rs::privacy_budgets_need_a_mechanism_at_the_release_boundary"),
    ]),
    inv!("INV-063", "dp", "Releases continue until the budget is spent, then every further release is denied and reserves nothing.", [
        (Positive, "test:crates/encompute-privacy/tests/privacy.rs::rounds_until_the_budget_is_spent"),
        (Negative, "test:crates/encompute-privacy/tests/privacy.rs::duplicate_release_is_refused"),
        (Adversarial, "check:dp_multi_process_double_spend"),
        (EndToEnd, "test:crates/encompute-runtime/tests/privacy.rs::rounds_until_the_budget_is_spent"),
    ]),
    inv!("INV-064", "dp", "Spent budget survives restart; a crashed release's charge stands and its round cannot be rerun.", [
        (Positive, "test:crates/encompute-privacy/tests/privacy.rs::rounds_until_the_budget_is_spent"),
        (Negative, "check:dp_crash_injection"),
        (Adversarial, "check:dp_crash_injection"),
        (EndToEnd, "test:crates/encompute-runtime/tests/privacy.rs::rounds_until_the_budget_is_spent"),
    ]),
    inv!("INV-065", "dp", "Concurrent releases, in threads or separate processes, cannot double-spend a budget.", [
        (Positive, "check:dp_multi_process_double_spend"),
        (Negative, "test:crates/encompute-privacy/tests/privacy.rs::concurrent_releases_cannot_double_spend"),
        (Adversarial, "check:dp_multi_process_double_spend"),
    ]),
    inv!("INV-066", "dp", "Any edit, deletion, insertion, reordering or truncation of a ledger is refused.", [
        (Positive, "test:crates/encompute-privacy/tests/privacy.rs::accounting_is_deterministic_and_composes"),
        (Negative, "test:crates/encompute-privacy/tests/privacy.rs::tampering_rollback_and_reset_are_detected"),
        (Adversarial, "check:dp_ledger_tampering"),
        (EndToEnd, "test:crates/encompute-runtime/tests/privacy.rs::ledger_rollback_deletion_reset_and_substitution_fail_closed"),
    ]),
    inv!("INV-067", "dp", "Ledger rollback or reset is detected by any owner holding a later checkpoint.", [
        (Positive, "test:crates/encompute-privacy/tests/privacy.rs::tampering_rollback_and_reset_are_detected"),
        (Negative, "test:crates/encompute-privacy/tests/privacy.rs::tampering_rollback_and_reset_are_detected"),
        (Adversarial, "check:dp_ledger_tampering"),
        (EndToEnd, "test:crates/encompute-runtime/tests/privacy.rs::any_owner_detects_another_assets_rollback"),
    ]),
    inv!("INV-068", "dp", "Privacy receipts bind output, parameters, ledger position and signer; every field is covered.", [
        (Positive, "test:crates/encompute-privacy/tests/privacy.rs::receipts_bind_output_ledger_and_parameters"),
        (Negative, "test:crates/encompute-privacy/tests/privacy.rs::receipts_bind_output_ledger_and_parameters"),
        (Adversarial, "check:dp_receipt_mutation"),
        (EndToEnd, "test:crates/encompute-runtime/tests/privacy.rs::attested_coordinator_binds_the_privacy_configuration"),
    ]),
    inv!("INV-069", "dp", "A release charged to several assets is all-or-nothing.", [
        (Positive, "check:dp_multi_parent_atomicity"),
        (Negative, "check:dp_multi_parent_atomicity"),
        (Adversarial, "check:dp_crash_injection"),
        (EndToEnd, "test:crates/encompute-runtime/tests/privacy.rs::rounds_until_the_budget_is_spent"),
    ]),
    inv!("INV-070", "dp", "A crash at any step of a release never yields an unaccounted output or a corrupt ledger.", [
        (Positive, "check:dp_crash_injection"),
        (Negative, "check:dp_crash_injection"),
        (Adversarial, "check:dp_crash_injection"),
    ]),
    inv!("INV-071", "dp", "The charged sensitivity bounds the encoded sum's movement for one privacy unit.", [
        (Positive, "test:crates/encompute-privacy/tests/privacy.rs::sensitivity_bounds_the_encoded_difference"),
        (Negative, "test:crates/encompute-privacy/tests/privacy.rs::accounting_is_deterministic_and_composes"),
    ]),
    // Leakage.
    inv!("INV-080", "leakage", "No secret input appears in what an untrusted party sees (coordinator messages, artifacts).", [
        (Adversarial, "check:secagg_coordinator_sees_no_input"),
        (Negative, "test:crates/encompute-exact/tests/transcript.rs::no_runtime_values_in_transcripts"),
        (Positive, "test:crates/encompute-runtime/tests/model.rs::artifact_round_trips_and_is_reproducible"),
        (EndToEnd, "test:crates/encompute-runtime/tests/aggregation.rs::three_hospitals_over_http"),
    ]),
    inv!("INV-081", "leakage", "Key files are owner-only and keys never appear in debug output.", [
        (Positive, "test:crates/encompute-keybroker/tests/release.rs::state_round_trips_without_printing_keys"),
        (Negative, "test:crates/encompute-cli/tests/cli.rs::keys_and_audit"),
    ]),
    // Trust graph.
    inv!("INV-100", "trust", "The trust report checks every signature against keys the verifier supplies; evidence without an anchor is never reported as trusted.", [
        (Positive, "test:crates/encompute-runtime/tests/trust.rs::a_whole_collaboration_verifies"),
        (Negative, "test:crates/encompute-runtime/tests/trust.rs::nothing_vouches_for_itself"),
        (Adversarial, "test:crates/encompute-runtime/tests/trust.rs::nothing_vouches_for_itself"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::secure_aggregation_round"),
    ]),
    inv!("INV-101", "trust", "The graph the report reads is exactly what its evidence implies; any added, dropped or edited edge, node or attribute fails.", [
        (Positive, "test:crates/encompute-runtime/tests/trust.rs::a_whole_collaboration_verifies"),
        (Negative, "test:crates/encompute-runtime/tests/trust.rs::tampered_evidence_fails_the_report"),
        (Adversarial, "test:crates/encompute-runtime/tests/trust.rs::edges_come_from_the_evidence"),
    ]),
    inv!("INV-102", "trust", "Every asset a program uses is approved by each owner for that program, unexpired and unrevoked; a revocation lists everything derived from the asset.", [
        (Positive, "test:crates/encompute-runtime/tests/trust.rs::owners_must_approve_the_program"),
        (Negative, "test:crates/encompute-runtime/tests/trust.rs::owners_must_approve_the_program"),
        (Adversarial, "test:crates/encompute-runtime/tests/trust.rs::revocation_shows_its_reach_and_forbids_later_use"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::secure_aggregation_round"),
    ]),
    inv!("INV-103", "trust", "Recorded privacy releases stay within the budget the program declares, with finite values, signed by a trusted coordinator; absent required evidence is never satisfied.", [
        (Positive, "test:crates/encompute-runtime/tests/trust.rs::privacy_releases_answer_to_the_declared_budget"),
        (Negative, "test:crates/encompute-runtime/tests/trust.rs::absent_evidence_is_not_satisfied"),
        (Adversarial, "test:crates/encompute-runtime/tests/trust.rs::privacy_releases_answer_to_the_declared_budget"),
    ]),
    // Planner.
    inv!("INV-110", "planner", "Every hard trust requirement of an accepted plan is satisfied by a valid, available mechanism, as the independent validator confirms.", [
        (Positive, "test:crates/encompute-planner/tests/planner.rs::gradients_need_secure_aggregation_and_budgets_need_dp"),
        (Negative, "test:crates/encompute-planner/tests/planner.rs::the_validator_refuses_weakened_plans"),
        (Adversarial, "check:planner_property"),
        (EndToEnd, "test:crates/encompute-runtime/tests/trust.rs::observed_execution_matches_the_approved_plan"),
    ]),
    inv!("INV-111", "planner", "Removing any required mechanism from a plan makes validation fail.", [
        (Positive, "test:crates/encompute-planner/tests/planner.rs::private_model_training_needs_attested_confidential_compute"),
        (Negative, "test:crates/encompute-planner/tests/planner.rs::the_validator_refuses_weakened_plans"),
        (Adversarial, "check:planner_property"),
    ]),
    inv!("INV-112", "planner", "The planner never weakens confidentiality, release, privacy or verification requirements; profiles only add requirements.", [
        (Positive, "test:crates/encompute-planner/tests/planner.rs::strong_profile_attests_the_coordinator_or_fails"),
        (Negative, "test:crates/encompute-planner/tests/planner.rs::the_validator_refuses_weakened_plans"),
        (Adversarial, "check:planner_property"),
        (EndToEnd, "test:python/tests/test_project.py::test_presets_expand_visibly"),
    ]),
    inv!("INV-113", "planner", "When no available mechanism combination satisfies the policy, there is no plan (PLANNING FAILED), never a weaker one.", [
        (Positive, "test:crates/encompute-planner/tests/planner.rs::private_exact_eligibility_is_verified_fhe"),
        (Negative, "test:crates/encompute-planner/tests/planner.rs::verified_training_requires_attested_workloads"),
        (Adversarial, "check:planner_adversarial"),
        (EndToEnd, "test:python/tests/test_project.py::test_no_valid_mechanism_fails_closed"),
    ]),
    inv!("INV-114", "planner", "Plans are deterministic, and the PlanId changes with every change to the plan; the validator refuses every security-relevant change.", [
        (Positive, "test:crates/encompute-planner/tests/planner.rs::plans_are_deterministic_and_identified"),
        (Negative, "check:planner_plan_id_binding"),
        (Adversarial, "check:planner_plan_id_binding"),
    ]),
    inv!("INV-115", "planner", "The trust report refuses execution evidence that does not match the approved plan: another PlanId, no plan, or a missing mechanism.", [
        (Positive, "test:crates/encompute-runtime/tests/trust.rs::observed_execution_matches_the_approved_plan"),
        (Negative, "test:crates/encompute-runtime/tests/trust.rs::observed_execution_matches_the_approved_plan"),
        (Adversarial, "test:crates/encompute-runtime/tests/trust.rs::observed_execution_matches_the_approved_plan"),
        (EndToEnd, "test:crates/encompute-runtime/tests/trust.rs::observed_execution_matches_the_approved_plan"),
    ]),
    // Confidential fine-tuning.
    inv!("INV-120", "training", "Private base-model keys are released only to workloads attesting to the approved training spec (image, code, configuration, plan).", [
        (Positive, "test:python/tests/test_finetune.py::test_training_run_is_trusted_end_to_end"),
        (Negative, "test:python/tests/test_finetune.py::test_keys_only_for_the_approved_workload"),
        (Adversarial, "script:examples/15_confidential_lora/attack.py"),
        (EndToEnd, "test:python/tests/test_finetune.py::test_adapter_is_usable_and_changed"),
    ]),
    inv!("INV-121", "training", "Raw LoRA updates never cross the aggregate-only boundary: they leave a worker only as masked secure-aggregation contributions.", [
        (Positive, "test:python/tests/test_finetune.py::test_training_run_is_trusted_end_to_end"),
        (Negative, "test:python/tests/test_finetune.py::test_no_raw_update_is_ever_written"),
        (Adversarial, "check:secagg_coordinator_sees_no_input"),
        (EndToEnd, "script:examples/15_confidential_lora/attack.py"),
    ]),
    inv!("INV-122", "training", "Every released training aggregate is charged to each contributing dataset's budget; training stops when the next release would exceed it.", [
        (Positive, "test:python/tests/test_finetune.py::test_every_release_is_charged"),
        (Negative, "test:python/tests/test_finetune.py::test_budget_exhaustion_stops_training"),
        (Adversarial, "script:examples/15_confidential_lora/attack.py"),
        (EndToEnd, "test:python/tests/test_finetune.py::test_training_run_is_trusted_end_to_end"),
    ]),
    inv!("INV-123", "training", "Checkpoint resume cannot roll privacy state back, and refuses another project, spec or policy.", [
        (Positive, "test:crates/encompute-training/tests/training.rs::checkpoint_resume_never_rolls_back_privacy"),
        (Negative, "test:python/tests/test_finetune.py::test_checkpoint_rollback_and_swap_are_refused"),
        (Negative, "test:python/tests/test_finetune_matrix.py::test_resume_matrix"),
        (Adversarial, "script:examples/15_confidential_lora/attack.py"),
        (EndToEnd, "test:python/tests/test_finetune.py::test_checkpoint_rollback_and_swap_are_refused"),
    ]),
    inv!("INV-124", "training", "Every adapter is linked, by signed records, to its base model, datasets, training spec and aggregation round; tampering fails the report.", [
        (Positive, "test:python/tests/test_finetune.py::test_lineage_links_model_data_and_evidence"),
        (Negative, "test:python/tests/test_finetune.py::test_tampered_adapter_evidence_fails_the_report"),
        (Adversarial, "test:crates/encompute-training/tests/training.rs::adapter_records_are_signed"),
        (EndToEnd, "test:python/tests/test_finetune.py::test_training_run_is_trusted_end_to_end"),
    ]),
    inv!("INV-125", "training", "A derived adapter cannot be exported when any parent's policy forbids it.", [
        (Positive, "test:crates/encompute-training/tests/training.rs::export_follows_every_parent"),
        (Negative, "test:python/tests/test_finetune.py::test_export_is_denied_by_inherited_policy"),
        (Adversarial, "script:examples/15_confidential_lora/attack.py"),
        (Adversarial, "test:python/tests/test_finetune_matrix.py::test_export_denied_after_revocation_or_tampering"),
        (EndToEnd, "test:python/tests/test_finetune.py::test_export_is_denied_by_inherited_policy"),
        (EndToEnd, "test:python/tests/test_finetune_matrix.py::test_export_follows_every_parent"),
    ]),
    inv!("INV-126", "training", "Changing any security-relevant training setting (model, code, layout, LoRA, optimizer, privacy, aggregation, participants, plan) changes the TrainingSpecId.", [
        (Positive, "test:crates/encompute-training/tests/training.rs::attestation_policy_binds_the_spec_and_code"),
        (Negative, "test:crates/encompute-training/tests/training.rs::every_field_changes_the_spec_id"),
        (Negative, "test:python/tests/test_finetune_matrix.py::test_model_digest_covers_weights_architecture_and_config"),
        (Negative, "test:python/tests/test_finetune_matrix.py::test_dataset_commitment_covers_every_sample_label_and_order"),
        (Negative, "test:python/tests/test_finetune_matrix.py::test_every_layout_change_changes_the_digest"),
        (Positive, "test:python/tests/test_training_contract.py::test_training_spec_id"),
        (Adversarial, "test:python/tests/test_finetune.py::test_keys_only_for_the_approved_workload"),
        (EndToEnd, "script:examples/15_confidential_lora/attack.py"),
    ]),
    inv!("INV-127", "training", "Training fails closed when the approved plan cannot be satisfied: no trusted environment means no training, never ordinary training.", [
        (Positive, "test:python/tests/test_finetune.py::test_training_run_is_trusted_end_to_end"),
        (Negative, "test:python/tests/test_finetune.py::test_no_trusted_environment_fails_closed"),
        (Adversarial, "check:planner_adversarial"),
        (EndToEnd, "test:python/tests/test_finetune.py::test_wrong_model_layout_or_dataset_is_refused"),
    ]),
    inv!("INV-128", "training", "A crash or kill at any point of a training round never leaves a privacy release uncharged or an unaccepted adapter usable; recovery finalizes or discards, and training resumes or stops safely.", [
        (Positive, "test:python/tests/test_finetune_crash.py::test_crash_then_recover_and_resume"),
        (Negative, "test:crates/encompute-training/tests/training.rs::checkpoint_resume_never_rolls_back_privacy"),
        (Adversarial, "check:dp_crash_injection"),
        (EndToEnd, "test:python/tests/test_finetune_crash.py::test_crash_then_recover_and_resume"),
    ]),
    inv!("INV-129", "training", "Patient data, base-model weights, raw updates and asset keys never appear outside their allowed locations, in any file or output of a run.", [
        (Positive, "test:python/tests/test_finetune_leakage.py::test_the_run_completed"),
        (Negative, "test:python/tests/test_finetune_leakage.py::test_no_raw_update_files"),
        (Adversarial, "test:python/tests/test_finetune_leakage.py::test_raw_updates_never_leave_a_worker"),
        (EndToEnd, "test:python/tests/test_finetune_leakage.py::test_patient_data_stays_with_its_owner"),
        (EndToEnd, "test:python/tests/test_finetune_leakage.py::test_model_weights_never_appear_in_the_clear"),
        (EndToEnd, "test:python/tests/test_finetune_leakage.py::test_keys_stay_in_the_owners_key_store"),
    ]),
    // Patient-level differential privacy (DP-SGD).
    inv!("INV-130", "dp-sgd", "Each privacy unit's gradient is computed per example, grouped by unit and clipped before summation, so one unit moves a worker's contribution by at most the clip, for any microbatch size.", [
        (Positive, "test:python/tests/test_dpsgd.py::test_vectorized_gradients_match_the_reference_for_any_microbatch"),
        (Negative, "test:python/tests/test_dpsgd.py::test_unit_index_groups_records_by_patient"),
        (Adversarial, "test:python/tests/test_dpsgd.py::test_one_patient_moves_the_sum_by_at_most_the_clip"),
        (Adversarial, "test:python/tests/test_dpsgd.py::test_contributions_bypassing_the_attested_worker_are_refused"),
        (EndToEnd, "test:python/tests/test_dpsgd.py::test_patient_run_is_satisfied_and_binds_every_setting"),
    ]),
    inv!("INV-131", "dp-sgd", "The Poisson-subsampled Rényi DP accountant agrees with an independent reference and is never optimistic; composition and the affordable-release boundary are consistent.", [
        (Positive, "test:crates/encompute-privacy/tests/rdp.rs::curves_match_the_reference_and_are_never_optimistic"),
        (Positive, "test:crates/encompute-privacy/tests/rdp.rs::epsilon_matches_the_reference_and_is_never_optimistic"),
        (Negative, "test:crates/encompute-privacy/tests/rdp.rs::ledger_costs_use_rdp_only_with_sampled_releases"),
        (Adversarial, "check:dp_rdp_accountant_properties"),
        (EndToEnd, "test:python/tests/test_dpsgd.py::test_the_ledgers_charge_what_the_preview_projected"),
    ]),
    inv!("INV-132", "dp-sgd", "Poisson sampling draws every unit's inclusion from the operating system's CSPRNG inside the attested worker, never from a seeded PRNG: no party's seed chooses the sample, and each unit is included independently (ENC-SF-2026-013).", [
        (Positive, "test:python/tests/test_dpsgd.py::test_poisson_sampling_uses_os_randomness"),
        (Negative, "test:python/tests/test_dpsgd.py::test_workers_report_nothing_about_their_data"),
        (Adversarial, "test:python/tests/test_dpsgd.py::test_poisson_sampling_uses_os_randomness"),
        (Adversarial, "test:python/tests/test_dpsgd.py::test_poisson_sampling_draws_from_the_csprng"),
        (EndToEnd, "test:python/tests/test_finetune_leakage.py::test_raw_updates_never_leave_a_worker"),
    ]),
    inv!("INV-133", "dp-sgd", "Every DP-SGD setting (unit, clip, sampling, noise, delta, grouping, accountant, batch, unit counts) is bound in the TrainingSpecId; changing one gets no model key.", [
        (Positive, "test:python/tests/test_dpsgd.py::test_patient_run_is_satisfied_and_binds_every_setting"),
        (Negative, "test:crates/encompute-training/tests/training.rs::every_dp_sgd_setting_changes_the_spec_id"),
        (Adversarial, "test:python/tests/test_dpsgd.py::test_changed_dp_settings_get_no_model_key"),
        (EndToEnd, "script:examples/16_patient_private_lora/attack.py"),
    ]),
    inv!("INV-134", "dp-sgd", "A run whose planned rounds would exceed any budget is denied before training starts; the ledgers charge exactly what the preview projected.", [
        (Positive, "test:python/tests/test_dpsgd.py::test_the_preview_uses_the_sampled_accountant"),
        (Negative, "test:python/tests/test_dpsgd.py::test_over_budget_runs_are_denied_before_training"),
        (Adversarial, "script:examples/16_patient_private_lora/attack.py"),
        (EndToEnd, "test:python/tests/test_dpsgd.py::test_the_ledgers_charge_what_the_preview_projected"),
    ]),
    inv!("INV-135", "dp-sgd", "Patient-level privacy is never claimed for organization-level training: the compiler, the planner and the trust report each refuse it.", [
        (Positive, "test:python/tests/test_dpsgd.py::test_patient_run_is_satisfied_and_binds_every_setting"),
        (Negative, "test:python/tests/test_dpsgd.py::test_the_planner_refuses_patient_claims_without_per_example_clipping"),
        (Negative, "test:python/tests/test_dpsgd.py::test_organizations_cannot_be_sampled"),
        (Adversarial, "test:python/tests/test_dpsgd.py::test_the_trust_report_refuses_patient_claims_from_organization_training"),
        (EndToEnd, "script:examples/16_patient_private_lora/attack.py"),
    ]),
    // Hugging Face Transformers + PEFT.
    inv!("INV-136", "huggingface", "A Hugging Face training run is bound to an immutable model package: its resolved revision, every file's digest, the tokenizer and the library versions; changing any of them gets no model key.", [
        (Positive, "test:python/tests/test_huggingface.py::test_packages_are_content_addressed"),
        (Positive, "test:python/tests/test_huggingface.py::test_hub_revisions_resolve_and_credentials_are_never_stored"),
        (Negative, "test:crates/encompute-training/tests/training.rs::hugging_face_packages_and_peft_are_bound_and_checked"),
        (Adversarial, "test:python/tests/test_huggingface.py::test_changed_settings_get_no_model_key"),
        (EndToEnd, "test:python/tests/test_huggingface.py::test_the_run_is_trusted_and_binds_the_package"),
    ]),
    inv!("INV-137", "huggingface", "Confidential workers never execute repository code: remote code, custom-code configurations and trust_remote_code are refused, and models are rebuilt from Transformers-native classes only.", [
        (Positive, "test:python/tests/test_huggingface.py::test_the_run_is_trusted_and_binds_the_package"),
        (Negative, "test:python/tests/test_huggingface.py::test_unsafe_repositories_are_refused"),
        (Negative, "test:crates/encompute-training/tests/training.rs::hugging_face_packages_and_peft_are_bound_and_checked"),
        (Adversarial, "script:examples/17_huggingface_peft/attack.py"),
        (EndToEnd, "script:examples/17_huggingface_peft/attack.py"),
    ]),
    inv!("INV-138", "huggingface", "Only safetensors, configuration and tokenizer files enter a model package; pickled or unknown files are refused before any loading.", [
        (Positive, "test:python/tests/test_huggingface.py::test_packages_are_content_addressed"),
        (Negative, "test:python/tests/test_huggingface.py::test_unsafe_repositories_are_refused"),
        (Adversarial, "test:crates/encompute-training/tests/training.rs::hugging_face_packages_and_peft_are_bound_and_checked"),
        (EndToEnd, "script:examples/17_huggingface_peft/attack.py"),
    ]),
    inv!("INV-139", "huggingface", "The PEFT adapter layout is canonical and identical for every participant; every PEFT setting is bound in the TrainingSpecId.", [
        (Positive, "test:python/tests/test_huggingface.py::test_the_peft_layout_is_canonical"),
        (Negative, "test:python/tests/test_huggingface.py::test_changed_settings_get_no_model_key"),
        (Negative, "test:crates/encompute-training/tests/training.rs::hugging_face_packages_and_peft_are_bound_and_checked"),
        (Adversarial, "script:examples/17_huggingface_peft/attack.py"),
        (EndToEnd, "test:python/tests/test_huggingface.py::test_exported_adapters_load_with_standard_peft"),
    ]),
    inv!("INV-140", "huggingface", "Tokenization and chunking cannot change the declared privacy grouping: every chunk keeps its record's unit, and a regrouped or ungrouped dataset is refused.", [
        (Positive, "test:python/tests/test_huggingface.py::test_tokenization_keeps_each_patients_records_together"),
        (Negative, "test:python/tests/test_huggingface.py::test_workers_refuse_regrouped_or_ungrouped_text"),
        (Adversarial, "script:examples/17_huggingface_peft/attack.py"),
        (EndToEnd, "test:python/tests/test_huggingface.py::test_the_run_is_trusted_and_binds_the_package"),
    ]),
    inv!("INV-141", "huggingface", "A model without valid per-unit gradients cannot satisfy patient-level privacy: the fast and reference gradient paths agree with a per-record reference, and training fails closed when neither works.", [
        (Positive, "test:python/tests/test_huggingface.py::test_both_gradient_paths_match_the_reference"),
        (Negative, "test:python/tests/test_huggingface.py::test_no_per_unit_gradients_fails_closed"),
        (Adversarial, "test:python/tests/test_huggingface.py::test_both_gradient_paths_match_the_reference"),
        (EndToEnd, "test:python/tests/test_huggingface.py::test_the_run_is_trusted_and_binds_the_package"),
    ]),
    inv!("INV-142", "huggingface", "An adapter is exported as PEFT files only when every parent permits it, no parent is revoked and the trust report is satisfied; otherwise nothing is written.", [
        (Positive, "test:python/tests/test_huggingface.py::test_exported_adapters_load_with_standard_peft"),
        (Negative, "test:python/tests/test_huggingface.py::test_private_adapters_are_never_exported"),
        (Adversarial, "test:python/tests/test_huggingface.py::test_export_after_revocation_writes_nothing"),
        (EndToEnd, "script:examples/17_huggingface_peft/attack.py"),
    ]),
    // Confidential Space training workers.
    inv!("INV-143", "confidential-space", "Production model and dataset keys are released only to a hardware-attested workload running the approved training image, acting for the participant whose keys they are; development (mock) evidence never receives them.", [
        (Positive, "test:python/tests/test_confidential_job.py::test_the_approved_workload_trains_and_its_evidence_verifies"),
        (Negative, "test:python/tests/test_confidential_job.py::test_mock_evidence_gets_no_production_keys"),
        (Negative, "test:crates/encompute-keybroker/tests/release.rs::production_brokers_refuse_development_evidence"),
        (Adversarial, "test:python/tests/test_confidential_job.py::test_a_genuine_tee_with_another_image_gets_no_keys"),
        (Adversarial, "test:python/tests/test_confidential_job.py::test_a_session_acts_for_one_participant_only"),
        (EndToEnd, "script:examples/18_confidential_space_hf/job.py"),
    ]),
    inv!("INV-144", "confidential-space", "Debug-enabled Confidential Space workloads cannot receive production asset keys.", [
        (Positive, "test:python/tests/test_confidential_job.py::test_the_approved_workload_trains_and_its_evidence_verifies"),
        (Negative, "test:python/tests/test_confidential_job.py::test_a_debug_workload_gets_no_keys"),
        (Adversarial, "test:crates/encompute-keybroker/tests/release.rs::untrusted_workloads_receive_no_key"),
        (EndToEnd, "script:examples/18_confidential_space_hf/job.py"),
    ]),
    inv!("INV-145", "confidential-space", "A genuine TEE running an unapproved image, or the approved image under another training spec, cannot receive production asset keys.", [
        (Positive, "test:python/tests/test_confidential_job.py::test_the_approved_workload_trains_and_its_evidence_verifies"),
        (Negative, "test:python/tests/test_confidential_job.py::test_a_genuine_tee_with_another_image_gets_no_keys"),
        (Adversarial, "test:python/tests/test_confidential_job.py::test_another_training_spec_gets_no_keys"),
        (EndToEnd, "script:examples/18_confidential_space_hf/job.py"),
    ]),
    inv!("INV-146", "confidential-space", "Training asset key grants are bound to one fresh attested session: a replayed token, challenge or grant receives nothing.", [
        (Positive, "test:crates/encompute-attestation/tests/attestation.rs::grants_open_only_in_their_session"),
        (Negative, "test:crates/encompute-attestation/tests/attestation.rs::freshness"),
        (Adversarial, "test:python/tests/test_confidential_job.py::test_replayed_evidence_and_outputs_are_refused"),
        (EndToEnd, "script:examples/18_confidential_space_hf/job.py"),
    ]),
    inv!("INV-147", "confidential-space", "A confidential training output is sealed, and bound by signed evidence to its training spec, participant, round, source assets and attestation; substituted assets or a second output for a round are refused.", [
        (Positive, "test:crates/encompute-training/tests/training.rs::worker_evidence_binds_its_spec_assets_and_attestation"),
        (Negative, "test:python/tests/test_confidential_job.py::test_substituted_assets_are_refused"),
        (Adversarial, "test:python/tests/test_confidential_job.py::test_replayed_evidence_and_outputs_are_refused"),
        (EndToEnd, "test:python/tests/test_confidential_job.py::test_the_approved_workload_trains_and_its_evidence_verifies"),
        (EndToEnd, "test:python/tests/test_confidential_job.py::test_the_output_is_sealed_to_attested_workloads"),
    ]),
    inv!("INV-148", "confidential-space", "Plaintext model weights, patient records, per-patient gradients and asset keys never cross the confidential workload boundary in the tested deployment.", [
        (Positive, "test:python/tests/test_confidential_job.py::test_the_output_is_sealed_to_attested_workloads"),
        (Negative, "test:python/tests/test_confidential_job.py::test_no_plaintext_leaves_the_workload"),
        (Adversarial, "test:python/tests/test_confidential_job.py::test_no_plaintext_leaves_the_workload"),
        (EndToEnd, "script:examples/18_confidential_space_hf/job.py"),
    ]),
    // Commercial exact execution on OpenFHE.
    inv!("INV-149", "openfhe-exact", "Exact programs run encrypted on OpenFHE exact give exactly the clear reference's and the mock's results, for every supported operation and width: no tolerance.", [
        (Positive, "test:crates/encompute-openfhe-client/tests/exact.rs::openfhe_exact_equals_clear_reference_and_mock"),
        (Negative, "test:crates/encompute-exact/tests/bits.rs::eight_bit_operations_are_exhaustively_exact"),
        (Adversarial, "test:crates/encompute-openfhe-client/tests/exact.rs::random_programs_on_openfhe_exact"),
        (EndToEnd, "test:crates/encompute-runtime/tests/openfhe_exact.rs::openfhe_exact_end_to_end"),
        (EndToEnd, "script:examples/19_openfhe_exact/run.sh"),
    ]),
    inv!("INV-150", "openfhe-exact", "Production builds run exact programs on OpenFHE exact and never on TFHE-rs: the compiler, the evaluator and the planner select OpenFHE (BinFHE, or BGV for programs inside the BGV subset), and a request for TFHE-rs is BACKEND UNAVAILABLE, not a fallback.", [
        (Positive, "test:crates/encompute-evaluator/tests/exact_backend.rs::production_builds_select_openfhe_exact_and_refuse_tfhe_rs"),
        (Negative, "test:crates/encompute-planner/tests/planner.rs::exact_programs_plan_openfhe_exact_never_tfhe_rs_by_default"),
        (Adversarial, "script:examples/19_openfhe_exact/run.sh"),
        (EndToEnd, "script:scripts/exact-demo.sh"),
    ]),
    inv!("INV-151", "openfhe-exact", "Production artifacts contain no TFHE-rs: the dependency graph, SBOM, CLI, evaluator, Python extension, wheel and container are audited, and the audit rejects a research build.", [
        (Positive, "script:scripts/audit-commercial-build.sh"),
        (Negative, "script:scripts/sbom.py"),
        (Adversarial, "script:.github/workflows/ci.yml"),
        (EndToEnd, "script:scripts/release-check.sh"),
    ]),
    inv!("INV-152", "openfhe-exact", "OpenFHE exact ciphertexts and keys are bound to their backend, parameter set, client key and type: objects under another key, parameter set or backend, and corrupted objects, are refused before any gate runs.", [
        (Positive, "test:crates/encompute-runtime/tests/openfhe_exact.rs::openfhe_exact_end_to_end"),
        (Negative, "test:crates/encompute-openfhe-client/tests/exact.rs::wrong_keys_parameters_backends_and_corruption_fail_closed"),
        (Adversarial, "script:examples/19_openfhe_exact/forge.py"),
        (EndToEnd, "script:examples/19_openfhe_exact/run.sh"),
    ]),
    inv!("INV-153", "openfhe-exact", "OpenFHE exact runs only the vetted parameter profile (STD128 with GINX bootstrapping, 128-bit, 2^-135 per gate), and every field of it is bound into the parameter-set ID that artifacts, keys and ciphertexts carry; the STD128 context OpenFHE builds has the vetted LWE parameters.", [
        (Positive, "test:crates/encompute-openfhe-exact/src/lib.rs::the_profile_is_vetted_and_bound_into_the_parameter_id"),
        (Positive, "test:crates/encompute-openfhe-client/tests/binfhe.rs::std128_context_has_the_vetted_lwe_parameters"),
        (Negative, "test:crates/encompute-openfhe-client/tests/exact.rs::wrong_keys_parameters_backends_and_corruption_fail_closed"),
        (Adversarial, "script:examples/19_openfhe_exact/forge.py"),
        (EndToEnd, "script:examples/19_openfhe_exact/run.sh"),
    ]),
    inv!("INV-154", "openfhe-exact", "Programs outside OpenFHE exact's capability matrix are refused at compile time, never partway through an encrypted run.", [
        (Positive, "test:crates/encompute-exact/tests/bits.rs::unary_operations_shifts_casts_select_and_lookup"),
        (Negative, "test:crates/encompute-evaluator/tests/exact_backend.rs::production_builds_select_openfhe_exact_and_refuse_tfhe_rs"),
        (Adversarial, "script:examples/19_openfhe_exact/wide.py"),
        (EndToEnd, "script:examples/19_openfhe_exact/run.sh"),
    ]),
    inv!("INV-155", "openfhe-exact", "Semantic transcripts do not depend on the exact backend, and OpenFHE exact agrees with TFHE-rs on the same programs in research CI; receipts bind the backend that actually ran.", [
        (Positive, "test:crates/encompute-openfhe-client/tests/exact.rs::transcripts_are_backend_independent"),
        (Negative, "test:crates/encompute-runtime/tests/openfhe_exact.rs::openfhe_exact_end_to_end"),
        (Adversarial, "test:crates/encompute-runtime/tests/cross_backend.rs::openfhe_exact_equals_tfhe_rs"),
        (EndToEnd, "script:examples/19_openfhe_exact/run.sh"),
    ]),
    // Enterprise deployment: control plane, tenancy, keys, durable state.
    inv!("INV-156", "deployment", "An authenticated identity cannot read or use resources owned solely by another organization (projects, assets, policies, jobs, privacy ledgers, trust reports, key references, audit records) without an explicit collaboration grant.", [
        (Positive, "test:crates/encompute-control/tests/isolation.rs::every_route_authenticates_authorizes_and_isolates"),
        (Negative, "test:crates/encompute-control/tests/isolation.rs::cross_tenant_attacks_fail"),
        (Adversarial, "test:crates/encompute-control/tests/isolation.rs::credentials_are_checked"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-157", "deployment", "Production asset keys are protected by the configured customer root key provider, and never silently fall back to local or plaintext development storage: an unavailable, disabled or wrong provider, organization or key version releases nothing.", [
        (Positive, "test:crates/encompute-keybroker/tests/root_keys.rs::openbao_wraps_unwraps_rotates_rewraps_and_revokes"),
        (Negative, "test:crates/encompute-keybroker/tests/root_keys.rs::development_root_key_wraps_rotates_and_is_refused_in_production"),
        (Adversarial, "test:crates/encompute-keybroker/tests/root_keys.rs::openbao_failures_never_fall_back"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-158", "deployment", "Duplicate, reordered or replayed job submissions and transport deliveries cannot produce duplicate security-sensitive effects: one job per idempotency key, one charge per privacy event, one receipt per job.", [
        (Positive, "test:crates/encompute-control/tests/jobs.rs::submission_is_idempotent_even_concurrently"),
        (Negative, "test:crates/encompute-control/tests/state.rs::privacy_spending_is_race_safe_and_idempotent"),
        (Adversarial, "test:crates/encompute-control/tests/jobs.rs::lifecycle_receipt_trust_and_duplicate_messages"),
        (Adversarial, "test:crates/encompute-control/tests/state.rs::secagg_privacy_events_arrive_once_through_messages"),
        (EndToEnd, "script:deploy/docker-compose/smoke.sh"),
    ]),
    inv!("INV-159", "deployment", "A control-plane restart cannot forget committed privacy spending, jobs or trust evidence.", [
        (Positive, "test:crates/encompute-control/tests/state.rs::restart_keeps_spending_and_restoring_an_older_backup_is_refused"),
        (Negative, "test:crates/encompute-control/tests/jobs.rs::restart_preserves_jobs_and_never_replays"),
        (Adversarial, "test:crates/encompute-control/tests/state.rs::privacy_spending_is_race_safe_and_idempotent"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-160", "deployment", "Restoring an older database cannot silently roll back authoritative privacy or audit state: startup is refused until an operator's explicit recovery freezes the rolled-back ledgers (treated as exhausted).", [
        (Positive, "test:crates/encompute-control/tests/state.rs::restart_keeps_spending_and_restoring_an_older_backup_is_refused"),
        (Negative, "test:crates/encompute-control/tests/state.rs::truncated_audit_and_tampered_or_missing_anchor_are_refused"),
        (Adversarial, "test:crates/encompute-control/tests/state.rs::audit_chain_is_tamper_evident_and_anchored"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-161", "deployment", "A revoked asset cannot start a new authorized job or receive a new key release: jobs not yet running fail, new submissions are refused (also when racing the revocation), and the key broker destroys the key.", [
        (Positive, "test:crates/encompute-control/tests/jobs.rs::revocation_stops_future_use"),
        (Negative, "test:crates/encompute-control/tests/state.rs::revocation_racing_submissions_leaves_no_usable_job"),
        (Adversarial, "test:crates/encompute-keybroker/tests/root_keys.rs::openbao_wraps_unwraps_rotates_rewraps_and_revokes"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-162", "deployment", "Audit records identify every security-sensitive state transition in a tamper-evident, anchored chain, without containing protected payloads (keys, data, weights, gradients, input values).", [
        (Positive, "test:crates/encompute-control/tests/jobs.rs::lifecycle_receipt_trust_and_duplicate_messages"),
        (Positive, "test:crates/encompute-control/tests/keys.rs::key_releases_and_rotations_are_audited"),
        (Negative, "test:crates/encompute-control/tests/state.rs::audit_chain_is_tamper_evident_and_anchored"),
        (Adversarial, "test:crates/encompute-control/tests/state.rs::truncated_audit_and_tampered_or_missing_anchor_are_refused"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-163", "deployment", "An evaluator executes only jobs compatible with its registered backend and parameter profile, only with an unexpired grant from the pinned control plane naming it and the job's program, and only after the control plane consents to the start.", [
        (Positive, "test:crates/encompute-control/tests/jobs.rs::jobs_run_only_on_compatible_ready_evaluators"),
        (Negative, "test:crates/encompute-verification/src/service.rs::job_grants_bind_issuer_evaluator_program_and_expiry"),
        (Adversarial, "test:crates/encompute-control/tests/isolation.rs::every_route_authenticates_authorizes_and_isolates"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-164", "deployment", "Production mode rejects development identities and tokens, development key stores and root keys, missing signing keys, default database credentials and plain-HTTP identity providers.", [
        (Positive, "test:crates/encompute-control/src/config.rs::production_refuses_insecure_fallbacks"),
        (Negative, "test:crates/encompute-control/tests/isolation.rs::oidc_tokens_and_production_refusals"),
        (Adversarial, "test:crates/encompute-keybroker/tests/root_keys.rs::development_root_key_wraps_rotates_and_is_refused_in_production"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-165", "deployment", "The control plane is not a trust anchor: a job's trust report is rebuilt from signed evidence (grant, receipt, commitments, plan) and trusted keys on every request, so edited database records cannot make a job trusted.", [
        (Positive, "test:crates/encompute-control/tests/jobs.rs::lifecycle_receipt_trust_and_duplicate_messages"),
        (Negative, "test:crates/encompute-control/tests/jobs.rs::lifecycle_receipt_trust_and_duplicate_messages"),
        (Adversarial, "test:crates/encompute-control/tests/isolation.rs::cross_tenant_attacks_fail"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-166", "exact-optimization", "Optimized exact execution equals the reference lowering bit for bit: random programs under every circuit strategy and worker count, adversarial boundary inputs and the benchmark corpus match the clear interpreter, on the mock and on OpenFHE.", [
        (Positive, "test:crates/encompute-exact/tests/circuit.rs::random_programs_are_identical_under_every_strategy_and_worker_count"),
        (Negative, "test:crates/encompute-exact/tests/bench_baseline.rs::optimized_circuits_equal_the_interpreter"),
        (Adversarial, "test:crates/encompute-exact/tests/circuit.rs::adversarial_boundaries"),
        (EndToEnd, "test:crates/encompute-openfhe-client/tests/exact.rs::optimized_circuits_equal_reference_on_openfhe"),
    ]),
    inv!("INV-167", "exact-optimization", "Optimization cannot bypass range or overflow validation: circuits are built only for plans that passed overflow analysis, widths are narrowed only by the declared input ranges, and values outside those ranges are refused before encryption.", [
        (Positive, "test:crates/encompute-exact/tests/circuit.rs::optimization_cannot_bypass_range_or_overflow_validation"),
        (Negative, "test:crates/encompute-exact/tests/lower.rs::wrong_scheme_and_overflow_are_refused"),
        (Adversarial, "test:crates/encompute-analysis/tests/exact.rs::exact_analysis_is_sound"),
        (EndToEnd, "script:examples/20_openfhe_optimization/run.sh"),
    ]),
    inv!("INV-168", "exact-optimization", "Parallel gate scheduling is deterministic: the same plan, ranges and worker count build the same circuit, and every worker count gives the same result bits.", [
        (Positive, "test:crates/encompute-exact/tests/circuit.rs::parallel_scheduling_is_deterministic"),
        (Negative, "test:crates/encompute-exact/tests/bench_baseline.rs::stable_quantities_do_not_regress"),
        (Adversarial, "test:crates/encompute-exact/tests/circuit.rs::random_programs_are_identical_under_every_strategy_and_worker_count"),
        (EndToEnd, "test:crates/encompute-openfhe-client/tests/exact.rs::optimized_circuits_equal_reference_on_openfhe"),
    ]),
    inv!("INV-169", "exact-optimization", "Planner cost never overrides security: verification and correctness requirements are checked before cost, so a cheaper backend without the required proofs is never selected.", [
        (Positive, "test:crates/encompute-planner/tests/planner.rs::unverified_exact_programs_take_the_cheaper_calibrated_backend"),
        (Negative, "test:crates/encompute-planner/tests/planner.rs::correctness_overrides_cost"),
        (Adversarial, "test:crates/encompute-planner/tests/planner.rs::the_validator_accepts_unverified_bgv_only_in_the_subset"),
        (EndToEnd, "test:crates/encompute-runtime/tests/exact.rs::planner_and_compiler_select_the_same_exact_backend"),
    ]),
    inv!("INV-170", "exact-optimization", "A program runs on BGV only when every one of its operations is in the BGV subset; one unsupported operation keeps the whole program on BinFHE, and schemes are never mixed within a program.", [
        (Positive, "test:crates/encompute-evaluator/src/cost.rs::arithmetic_scoring_runs_on_bgv"),
        (Negative, "test:crates/encompute-evaluator/src/cost.rs::one_op_outside_the_subset_keeps_the_whole_program_on_binfhe"),
        (Adversarial, "test:crates/encompute-evaluator/src/cost.rs::comparisons_stay_on_binfhe"),
        (EndToEnd, "test:crates/encompute-runtime/tests/openfhe_bgv.rs::arithmetic_programs_run_on_bgv_without_proofs"),
    ]),
    inv!("INV-171", "exact-optimization", "The evaluation-key cache is bounded in serialized key bytes (a single entry larger than the bound is admitted alone) and never runs a ciphertext under another client's keys: sessions use only keys registered with them, a ciphertext runs only under the key its envelope is bound to, and evicted keys are reported missing.", [
        (Positive, "test:crates/encompute-runtime/tests/keycache.rs::bounded_shared_and_isolated"),
        (Negative, "test:crates/encompute-runtime/tests/sessions.rs::round_trip_and_rejections"),
        (Adversarial, "test:crates/encompute-evaluator/src/keycache.rs::bounded_lru_and_shared_loads"),
        (EndToEnd, "test:crates/encompute-runtime/tests/network.rs::remote_round_trip_uploads_program_and_keys_once"),
    ]),
    // Release-candidate hardening: fuzzing, network attacks, restarts and
    // the security findings fixed for the release candidate
    // (docs/security-findings.md).
    inv!("INV-172", "hardening", "Malformed network or artifact input never panics, never allocates the size it declares, and is never accepted: every parser (programs, envelopes, receipts, proofs, service messages, attestation evidence, trust bundles, tokens, ledgers, tensors, artifacts and worker frames) returns a typed error for mutated, truncated, huge or overflowing input, and artifact references that traverse paths are refused.", [
        (Positive, "test:crates/encompute-ir/tests/fuzz_smoke.rs::mutated_programs_never_panic_and_round_trip"),
        (Positive, "test:crates/encompute-evaluator/src/pool.rs::frames_round_trip"),
        (Negative, "test:crates/encompute-protocol/tests/fuzz_smoke.rs::huge_declared_lengths_are_refused"),
        (Negative, "test:crates/encompute-ir/tests/fuzz_smoke.rs::huge_dimensions_are_refused_without_allocating"),
        (Negative, "test:crates/encompute-evaluator/src/pool.rs::huge_declared_lengths_are_refused_without_allocating"),
        (Negative, "test:crates/encompute-evaluator/src/pool.rs::malformed_execute_replies_are_errors"),
        (Negative, "test:crates/encompute-training/tests/fuzz_smoke.rs::overflowing_offsets_are_refused"),
        (Negative, "test:crates/encompute-attestation/src/gcp.rs::huge_chunk_sizes_are_refused"),
        (Negative, "test:crates/encompute-privacy/tests/fuzz_smoke.rs::out_of_range_sampling_rates_are_refused"),
        (Negative, "test:crates/encompute-privacy/tests/fuzz_smoke.rs::oversized_and_malformed_ledgers_are_typed_errors"),
        (Negative, "test:crates/encompute-verification/tests/fuzz_smoke.rs::resource_limits_are_typed_errors"),
        (Negative, "test:crates/encompute-control/tests/network_attacks.rs::bad_artifact_references_are_refused"),
        (Adversarial, "test:crates/encompute-protocol/tests/fuzz_smoke.rs::mutated_envelopes_never_panic"),
        (Adversarial, "test:crates/encompute-verification/tests/fuzz_smoke.rs::mutated_receipts_never_panic_or_verify"),
        (Adversarial, "test:crates/encompute-verification/tests/fuzz_smoke.rs::mutated_service_headers_never_panic_or_verify"),
        (Adversarial, "test:crates/encompute-attestation/tests/fuzz_smoke.rs::mutated_evidence_never_panics_or_verifies"),
        (Adversarial, "test:crates/encompute-trust/tests/fuzz_smoke.rs::mutated_records_never_panic_or_verify"),
        (Adversarial, "test:crates/encompute-control/tests/fuzz_smoke.rs::mutated_tokens_never_panic_or_authenticate_as_another"),
        (Adversarial, "test:crates/encompute-runtime/tests/fuzz_smoke.rs::mutated_artifacts_never_panic_or_load"),
        (Adversarial, "test:crates/encompute-training/tests/fuzz_smoke.rs::mutated_sealed_artifacts_never_panic"),
        (Adversarial, "test:crates/encompute-privacy/tests/fuzz_smoke.rs::mutated_ledger_files_never_panic"),
        (EndToEnd, "test:crates/encompute-evaluator/tests/fuzz_smoke.rs::the_http_server_answers_every_mutated_request"),
        (EndToEnd, "script:fuzz/run_all.sh"),
    ]),
    inv!("INV-173", "hardening", "A slow, oversized or malformed client cannot starve a service: the control plane, evaluator, key broker and coordinator serve through a bounded HTTP server with fixed connection threads, a bounded queue, head and body deadlines with a minimum body rate, and size limits checked before reading.", [
        (Positive, "test:crates/encompute-verification/src/http.rs::parses_and_refuses"),
        (Negative, "test:crates/encompute-verification/src/http.rs::a_full_queue_answers_busy"),
        (Negative, "test:crates/encompute-verification/src/http.rs::a_trickled_body_is_cut_despite_a_large_declared_length"),
        (Adversarial, "test:crates/encompute-verification/src/http.rs::slow_clients_time_out_without_blocking_others"),
        (Adversarial, "test:crates/encompute-control/tests/network_attacks.rs::slow_clients_cannot_starve_the_server"),
        (Adversarial, "test:crates/encompute-evaluator/tests/network_attacks.rs::slow_clients_cannot_hold_the_evaluator"),
        (Adversarial, "test:crates/encompute-keybroker/tests/network_attacks.rs::slow_clients_cannot_hold_the_broker"),
        (Adversarial, "test:crates/encompute-keybroker/tests/network_attacks.rs::request_floods_are_limited_per_address"),
        (EndToEnd, "test:crates/encompute-control/tests/network_attacks.rs::oversized_and_malformed_requests_are_refused_before_the_api"),
        (EndToEnd, "test:crates/encompute-evaluator/tests/network_attacks.rs::oversized_and_malformed_uploads_are_refused"),
        (EndToEnd, "test:crates/encompute-keybroker/tests/network_attacks.rs::oversized_malformed_and_unauthenticated_requests_are_refused"),
        (EndToEnd, "script:scripts/release/soak.sh"),
    ]),
    inv!("INV-174", "deployment", "Signed service requests are fresh, single-use and bound: the signature covers the method, the path with its query string, the body hash, the sender, the recipient, the timestamp and a nonce, and a replayed nonce, a stale timestamp or any changed field (the query included) is refused (ENC-SF-2026-004).", [
        (Positive, "test:crates/encompute-control/tests/isolation.rs::signed_service_requests_bind_the_query"),
        (Negative, "test:crates/encompute-control/tests/network_attacks.rs::expired_forged_and_misaddressed_messages_are_refused"),
        (Adversarial, "test:crates/encompute-control/tests/network_attacks.rs::signed_requests_are_fresh_single_use_and_bound"),
        (EndToEnd, "test:crates/encompute-keybroker/tests/network_attacks.rs::control_messages_are_authenticated_fresh_and_applied_once"),
    ]),
    inv!("INV-175", "deployment", "Every service message applies at most once, even when duplicates arrive concurrently: the deduplication record and the message's effects commit in one transaction, so a redelivered privacy event, key release report or job status is recorded once (ENC-SF-2026-005).", [
        (Positive, "test:crates/encompute-control/tests/keys.rs::concurrent_duplicate_messages_apply_once"),
        (Negative, "test:crates/encompute-control/tests/jobs.rs::lifecycle_receipt_trust_and_duplicate_messages"),
        (Adversarial, "test:crates/encompute-control/tests/network_attacks.rs::duplicate_messages_apply_once_even_concurrently"),
        (EndToEnd, "test:crates/encompute-keybroker/tests/network_attacks.rs::control_messages_are_authenticated_fresh_and_applied_once"),
    ]),
    inv!("INV-176", "deployment", "An evaluator that has a control plane accepts programs, keys and jobs only with a job grant from that control plane, runs each granted job once, and gives jobs random, unguessable IDs; a local evaluator without a control plane needs no grant (ENC-SF-2026-006).", [
        (Positive, "test:crates/encompute-evaluator/tests/uploads.rs::local_uploads_need_no_grant_and_job_ids_are_random"),
        (Negative, "test:crates/encompute-evaluator/tests/uploads.rs::uploads_need_a_grant_with_a_control_plane"),
        (Adversarial, "test:crates/encompute-control/tests/network_attacks.rs::evaluator_runs_only_granted_jobs_once"),
        (Adversarial, "test:crates/encompute-evaluator/tests/network_attacks.rs::unknown_and_traversing_references_are_not_found"),
        (EndToEnd, "script:scripts/enterprise-e2e.sh"),
    ]),
    inv!("INV-177", "deployment", "A crash or lost database connection at any step of a job neither loses nor duplicates an acknowledged effect, and no job stays running after its evaluator restarts: the restarted evaluator's running jobs fail and can be resubmitted.", [
        (Positive, "test:crates/encompute-control/tests/restart.rs::crashes_at_every_job_step_recover_without_duplicates"),
        (Negative, "test:crates/encompute-control/tests/restart.rs::evaluator_restart_fails_its_running_jobs"),
        (Adversarial, "test:crates/encompute-control/tests/restart.rs::connection_loss_mid_transaction_neither_loses_nor_duplicates"),
        (Adversarial, "test:crates/encompute-control/tests/restart.rs::evaluator_restarts_at_random_points_leave_no_job_behind"),
        (EndToEnd, "test:crates/encompute-control/tests/restart.rs::killed_control_plane_process_recovers_every_time"),
        (EndToEnd, "test:crates/encompute-control/tests/restart.rs::http_server_survives_database_connection_loss"),
    ]),
    inv!("INV-178", "deployment", "Asset revocations survive a database rollback: they are recorded in the signed state anchor, so restoring an older database is refused at startup and recovery re-applies them; backups capture the anchor before the database, and a restore keeps a newer key broker state.", [
        (Positive, "test:crates/encompute-control/tests/jobs.rs::revocation_stops_future_use"),
        (Negative, "test:crates/encompute-keybroker/tests/lifecycle.rs::lifecycle_revocation_survives_rollback_after_kek_rotation_and_root_retirement"),
        (Adversarial, "test:crates/encompute-control/tests/state.rs::restoring_an_older_backup_cannot_unrevoke_an_asset"),
        (EndToEnd, "script:scripts/release/backup-drill.sh"),
    ]),
    inv!("INV-179", "secagg", "A restarted SecAgg coordinator never re-runs a round or releases a round's aggregate twice, and each release is charged once.", [
        (Positive, "test:crates/encompute-runtime/tests/secagg_restart.rs::coordinator_restart_never_reruns_a_round_or_releases_twice"),
        (Negative, "test:crates/encompute-privacy/tests/privacy.rs::rounds_until_the_budget_is_spent"),
        (Adversarial, "test:crates/encompute-runtime/tests/secagg_restart.rs::coordinator_restart_never_reruns_a_round_or_releases_twice"),
        (EndToEnd, "test:crates/encompute-control/tests/state.rs::secagg_privacy_events_arrive_once_through_messages"),
    ]),
    inv!("INV-180", "keybroker", "Key broker restarts fail closed: a restart forgets challenges and sessions but never keys, a revocation that was not persisted is not acknowledged and is applied on redelivery, and production never falls back to development key storage; plain HTTP to OpenBao is allowed only for an exact loopback host (ENC-SF-2026-002).", [
        (Positive, "test:crates/encompute-keybroker/tests/restart.rs::a_restart_forgets_challenges_and_sessions_never_keys"),
        (Negative, "test:crates/encompute-keybroker/tests/lifecycle.rs::production_provider_misconfiguration_is_refused"),
        (Negative, "test:crates/encompute-keybroker/tests/lifecycle.rs::lifecycle_disabled_root_key_refuses_every_reopen"),
        (Adversarial, "test:crates/encompute-keybroker/tests/restart.rs::an_unpersisted_revocation_is_not_acknowledged_and_is_applied_on_redelivery"),
        (Adversarial, "test:crates/encompute-keybroker/tests/lifecycle.rs::production_never_falls_back_to_development_storage_local_kek"),
        (EndToEnd, "test:crates/encompute-keybroker/tests/lifecycle.rs::production_never_falls_back_to_development_storage_openbao"),
        (EndToEnd, "test:crates/encompute-cli/tests/keys_lifecycle.rs::production_keys_commands_never_fall_back_to_development_storage"),
    ]),
    inv!("INV-181", "keybroker", "One organization cannot destroy another's keys: a key reference is registered only for the organization that owns it, and a revocation destroys only keys recorded for the revoking organization (ENC-SF-2026-001).", [
        (Positive, "test:crates/encompute-keybroker/tests/revocation.rs::only_keys_recorded_for_the_organization_are_revoked"),
        (Negative, "test:crates/encompute-keybroker/tests/revocation.rs::revocations_for_another_organization_destroy_nothing"),
        (Adversarial, "test:crates/encompute-control/tests/keys.rs::cross_tenant_key_ref_cannot_be_registered_or_revoked"),
        (EndToEnd, "test:crates/encompute-keybroker/tests/network_attacks.rs::control_messages_are_authenticated_fresh_and_applied_once"),
    ]),
    inv!("INV-182", "keybroker", "Key grants are signed by the key broker, and a workload that pins the broker key refuses a grant substituted or re-signed by anyone else (ENC-SF-2026-003).", [
        (Positive, "test:crates/encompute-attestation/tests/attestation.rs::grants_are_signed_by_the_broker"),
        (Negative, "test:crates/encompute-attestation/tests/attestation.rs::grants_open_only_in_their_session"),
        (Adversarial, "test:crates/encompute-keybroker/tests/release.rs::a_substituted_grant_is_refused"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::attestation_and_key_release"),
    ]),
    inv!("INV-183", "keybroker", "Secret key files are owner-only (0600) after every write, including over an existing wider-mode file or a leftover temporary file; the public evaluator pin is written 0644, and pinning it over plain HTTP to a remote host is warned (ENC-SF-2026-007).", [
        (Positive, "test:crates/encompute-cli/tests/cli.rs::keys_and_audit"),
        (Negative, "test:crates/encompute-keybroker/tests/release.rs::state_round_trips_without_printing_keys"),
        (Adversarial, "test:crates/encompute-keybroker/tests/release.rs::state_round_trips_without_printing_keys"),
        (Adversarial, "test:crates/encompute-cli/src/main.rs::pinning_over_plain_http_to_another_host_is_warned"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::remote_receipts_and_verify"),
    ]),
    inv!("INV-184", "receipts", "A client sends no inputs to an evaluator whose receipt key is outside its pinned set: a compromised control plane cannot choose which evaluator key the Python client accepts (ENC-SF-2026-008).", [
        (Positive, "test:python/tests/test_client.py::test_a_pinned_key_passes_and_unpinned_warns"),
        (Negative, "test:python/tests/test_client.py::test_a_key_outside_the_pinned_set_is_refused"),
        (Adversarial, "test:python/tests/test_client.py::test_the_pin_comes_from_the_environment"),
        (EndToEnd, "test:crates/encompute-cli/tests/cli.rs::remote_receipts_and_verify"),
    ]),
    inv!("INV-185", "dp", "A differentially private aggregation receipt verifies only with the privacy receipts it binds: missing, substituted or unbound privacy receipts fail verification (ENC-SF-2026-009).", [
        (Positive, "test:crates/encompute-runtime/tests/privacy.rs::dp_receipts_require_bound_privacy_receipts"),
        (Negative, "test:crates/encompute-runtime/tests/privacy.rs::ledger_rollback_deletion_reset_and_substitution_fail_closed"),
        (Adversarial, "test:crates/encompute-runtime/tests/privacy.rs::dp_receipts_require_bound_privacy_receipts"),
        (EndToEnd, "script:examples/09_differential_privacy/run.sh"),
    ]),
    inv!("INV-186", "dp", "A coordinator under a control plane never releases an aggregate before the control plane has reserved its privacy spend, and a coordinator that cannot report refuses before the round starts, so no party contributes (ENC-SF-2026-010).", [
        (Positive, "test:crates/encompute-cli/src/aggregate.rs::release_never_precedes_the_control_plane_reservation"),
        (Negative, "test:crates/encompute-cli/tests/aggregate_report.rs::a_coordinator_that_cannot_report_refuses_before_the_round"),
        (Adversarial, "test:crates/encompute-cli/src/aggregate.rs::release_never_precedes_the_control_plane_reservation"),
        (EndToEnd, "test:crates/encompute-cli/tests/aggregate_report.rs::a_coordinator_that_cannot_report_refuses_before_the_round"),
    ]),
    inv!("INV-187", "training", "A training workload's attestation policy binds its privacy policy ID: evidence or grants for another privacy policy receive no keys (ENC-SF-2026-011).", [
        (Positive, "test:crates/encompute-training/tests/training.rs::attestation_policy_binds_the_spec_and_code"),
        (Negative, "test:crates/encompute-attestation/tests/attestation.rs::privacy_policy_binding"),
        (Adversarial, "test:crates/encompute-attestation/tests/attestation.rs::privacy_policy_binding"),
        (EndToEnd, "test:python/tests/test_finetune.py::test_keys_only_for_the_approved_workload"),
    ]),
    inv!("INV-188", "receipts", "Offline `encompute verify` checks the receipt's evidence kind against the artifact and exits 0 only when every binding was checked and any named proof verified; unchecked bindings exit 3 and are listed (ENC-SF-2026-012).", [
        (Positive, "test:crates/encompute-cli/tests/cli.rs::remote_receipts_and_verify"),
        (Negative, "test:crates/encompute-cli/tests/cli.rs::remote_receipts_and_verify"),
        (Adversarial, "test:crates/encompute-cli/tests/cli.rs::remote_receipts_and_verify"),
        (EndToEnd, "script:examples/04_execution_receipts/run.sh"),
    ]),
    inv!("INV-189", "artifacts", "Unknown, unreadable and future artifact versions fail closed, and `encompute migrate` never rewrites signed, hash-chained or content-addressed evidence: it checks read-only by default and upgrades only unsigned formats into a new output.", [
        (Positive, "test:crates/encompute-cli/tests/migrate.rs::model_artifact_current_upgraded_and_refused"),
        (Positive, "test:crates/encompute-cli/tests/migrate.rs::party_state_upgrade"),
        (Negative, "test:crates/encompute-cli/tests/migrate.rs::unknown_and_unreadable_inputs"),
        (Adversarial, "test:crates/encompute-cli/tests/migrate.rs::execution_receipts"),
        (Adversarial, "test:crates/encompute-cli/tests/migrate.rs::checkpoints_sealed_assets_and_adapter_records"),
        (EndToEnd, "test:crates/encompute-cli/tests/migrate.rs::privacy_ledgers"),
        (EndToEnd, "test:crates/encompute-cli/tests/migrate.rs::attestation_policy_and_signed_round_objects"),
    ]),
    inv!("INV-190", "exact-optimization", "The OpenFHE differential gate holds: on random, corpus and boundary programs, the clear interpreter, the mock, the optimized circuit and the reference lowering agree on every plaintext bit, and OpenFHE agrees with them.", [
        (Positive, "test:crates/encompute-openfhe-client/tests/differential.rs::gate_programs_agree_on_plaintext_bits"),
        (Negative, "test:crates/encompute-exact/tests/optimizer.rs::diff_execute_rejects_what_the_reference_rejects"),
        (Adversarial, "test:crates/encompute-openfhe-client/tests/differential.rs::openfhe_differential_gate"),
        (EndToEnd, "script:scripts/release/differential-gate.sh"),
    ]),
    inv!("INV-191", "exact-optimization", "Every optimizer transformation (Boolean rules, constant folding, range narrowing, common-subexpression reuse, dead-gate removal, prefix adders, tree comparators, selection and parallel execution) has a unit, a property and a differential test, and the table naming them names only existing tests.", [
        (Positive, "test:crates/encompute-exact/tests/optimizer.rs::optimizer_tests_table_names_existing_tests"),
        (Negative, "test:crates/encompute-exact/tests/optimizer.rs::execute_propagates_gate_errors"),
        (Adversarial, "test:crates/encompute-exact/tests/optimizer.rs::prop_ranges_are_sound"),
        (Adversarial, "test:crates/encompute-exact/src/circuit.rs::prop_known_bits_are_sound"),
        (EndToEnd, "test:crates/encompute-exact/tests/optimizer.rs::diff_optimize_matches_reference_lowering"),
    ]),
];
