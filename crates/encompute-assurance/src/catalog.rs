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
];
