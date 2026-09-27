# Optimizer tests

Every transformation of the exact execution plan (`src/circuit.rs`,
`src/bits.rs`) and the tests that verify it. Each row names a **unit** test
(hand-picked cases), a **property** test (proptest with a deterministic
ChaCha RNG and no failure persistence; case counts follow
`ENCOMPUTE_EXACT_PROGRAMS`) and a **differential** test (the optimized
circuits against the reference lowering, `BitEvaluator` with
`Strategy::REFERENCE` run instruction by instruction through
`evaluate_exact`, and the clear interpreter `encompute_ir::evaluate`).

References are `path::function`, relative to `crates/encompute-exact`.
`tests/optimizer.rs::optimizer_tests_table_names_existing_tests` checks that
every function named here exists in that file and is a `#[test]`.

Two property tests cover every rule at once as well as the rule-specific
ones: `src/circuit.rs::prop_recorded_dags_compute_their_expressions`
(random Boolean DAGs through the recorder compute their expressions and
leave none of the rewritten patterns behind) and
`tests/optimizer.rs::prop_circuit_structure_and_stats` (the same invariants,
liveness and a recount of the statistics on circuits of random programs).

| Transformation | Code | Unit test | Property test | Differential test |
| --- | --- | --- | --- | --- |
| Constant folding: AND with a public bit (`0 & x = 0`, `1 & x = x`) | `BitEvaluator::and` | `src/bits.rs::bit_and_folds_constants` | `src/bits.rs::prop_bit_constant_folding` | `tests/optimizer.rs::diff_bit_constant_folding`, `tests/optimizer.rs::prop_constant_lifting_differential` |
| Constant folding: OR with a public bit | `BitEvaluator::or` | `src/bits.rs::bit_or_folds_constants` | `src/bits.rs::prop_bit_constant_folding` | `tests/optimizer.rs::diff_bit_constant_folding`, `tests/optimizer.rs::prop_constant_lifting_differential` |
| Constant folding: XOR with a public bit (`x ^ 1 = !x`) | `BitEvaluator::xor` | `src/bits.rs::bit_xor_folds_constants` | `src/bits.rs::prop_bit_constant_folding` | `tests/optimizer.rs::diff_bit_constant_folding`, `tests/optimizer.rs::prop_constant_lifting_differential` |
| Constant folding: NOT of a public bit | `BitEvaluator::not` | `src/bits.rs::bit_not_folds_constants` | `src/bits.rs::prop_bit_constant_folding` | `tests/optimizer.rs::diff_bit_constant_folding` |
| Constant folding: multiplexer (public condition; `c ? 1 : 0 = c`; `c ? 0 : 1 = !c`; equal public branches) | `BitEvaluator::mux` | `src/bits.rs::bit_mux_folds_constants` | `src/bits.rs::prop_bit_constant_folding` | `tests/optimizer.rs::diff_bit_constant_folding` |
| Recorder: AND with a constant node (`x & 0`, `0 & x`, `x & 1`, `1 & x`) | `Recorder::gate` | `src/circuit.rs::rule_and_with_constants`, `src/circuit.rs::rule_constant_operands_fold_completely` | `src/circuit.rs::prop_rule_and_with_constants` | `tests/optimizer.rs::diff_rule_and_with_constants` |
| Recorder: OR with a constant node (`x \| 1`, `1 \| x`, `x \| 0`, `0 \| x`) | `Recorder::gate` | `src/circuit.rs::rule_or_with_constants`, `src/circuit.rs::rule_constant_operands_fold_completely` | `src/circuit.rs::prop_rule_or_with_constants` | `tests/optimizer.rs::diff_rule_or_with_constants` |
| Recorder: XOR with a constant node (`x ^ 0 = x`, `x ^ 1 = !x`, either side) | `Recorder::gate` | `src/circuit.rs::rule_xor_with_constants`, `src/circuit.rs::rule_constant_operands_fold_completely` | `src/circuit.rs::prop_rule_xor_with_constants` | `tests/optimizer.rs::diff_rule_xor_with_constants` |
| Recorder: NOT of a constant node | `Recorder::not` | `src/circuit.rs::rule_not_of_constant` | `src/circuit.rs::prop_rule_not_of_constant` | `tests/optimizer.rs::diff_rule_not_of_constant` |
| Recorder: `x & x = x` | `Recorder::gate` | `src/circuit.rs::rule_and_self` | `src/circuit.rs::prop_rule_and_self`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_rule_and_self` |
| Recorder: `x \| x = x` | `Recorder::gate` | `src/circuit.rs::rule_or_self` | `src/circuit.rs::prop_rule_or_self`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_rule_or_self` |
| Recorder: `x ^ x = 0` | `Recorder::gate` | `src/circuit.rs::rule_xor_self` | `src/circuit.rs::prop_rule_xor_self`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_rule_xor_self` |
| Recorder: `x & !x = 0` (either order) | `Recorder::gate`, `Recorder::is_not_of` | `src/circuit.rs::rule_and_not_self` | `src/circuit.rs::prop_rule_and_not_self`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_rule_and_not_self` |
| Recorder: `x \| !x = 1` (either order) | `Recorder::gate`, `Recorder::is_not_of` | `src/circuit.rs::rule_or_not_self` | `src/circuit.rs::prop_rule_or_not_self`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_rule_or_not_self` |
| Recorder: `x ^ !x = 1` (either order) | `Recorder::gate`, `Recorder::is_not_of` | `src/circuit.rs::rule_xor_not_self` | `src/circuit.rs::prop_rule_xor_not_self`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_rule_xor_not_self` |
| Recorder: NOT pulled out of XOR, left (`!x ^ y = !(x ^ y)`) | `Recorder::gate` | `src/circuit.rs::rule_xor_not_pull_out_left` | `src/circuit.rs::prop_rule_xor_not_pull_out_left`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_rule_xor_not_pull_out_left` |
| Recorder: NOT pulled out of XOR, right (`x ^ !y = !(x ^ y)`; both sides cancel) | `Recorder::gate` | `src/circuit.rs::rule_xor_not_pull_out_right` | `src/circuit.rs::prop_rule_xor_not_pull_out_right`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_rule_xor_not_pull_out_right` |
| Recorder: double negation (`!!x = x`) | `Recorder::not` | `src/circuit.rs::rule_double_negation` | `src/circuit.rs::prop_rule_double_negation`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_rule_double_negation` |
| Hash-consing CSE and the `cse_hits` statistic | `Recorder::node` | `src/circuit.rs::cse_hash_conses_gates_and_counts_hits`, `tests/optimizer.rs::cse_reuses_repeated_and_commuted_instructions` | `src/circuit.rs::prop_cse_replay_adds_nothing_and_counts_every_gate`, `tests/optimizer.rs::prop_cse_duplicated_plan_is_free` | `tests/optimizer.rs::diff_cse_matches_reference` |
| CSE operand canonicalization (`a < b`) | `Recorder::gate` | `src/circuit.rs::cse_canonicalizes_operand_order` | `src/circuit.rs::prop_cse_operands_are_canonical`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_cse_matches_reference`, `tests/optimizer.rs::diff_rule_xor_not_pull_out_right` |
| Interval analysis, per instruction | `ranges` | `tests/optimizer.rs::ranges_per_instruction` | `tests/optimizer.rs::prop_ranges_are_sound` | `tests/optimizer.rs::diff_range_folding_matches_unfolded` |
| Known bits: constant values, non-negative and negative ranges | `known_bits` | `src/circuit.rs::known_bits_constant_nonnegative_negative_and_sign_copy` | `src/circuit.rs::prop_known_bits_are_sound` | `tests/optimizer.rs::diff_range_folding_matches_unfolded` |
| Known bits: mixed-sign ranges (high bits copy the sign) | `known_bits` | `src/circuit.rs::known_bits_constant_nonnegative_negative_and_sign_copy`, `tests/optimizer.rs::range_folding_in_build` | `src/circuit.rs::prop_known_bits_are_sound` | `tests/optimizer.rs::diff_range_folding_matches_unfolded` |
| Range folding loop and its statistics (`range_bits_folded`, `input_bits_used`) | `build` | `tests/optimizer.rs::range_folding_in_build` | `tests/optimizer.rs::prop_constant_lifting_differential`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_range_folding_matches_unfolded` |
| Dead-code elimination (liveness, renumbering) and `dead_gates` | `build` | `tests/optimizer.rs::dce_removes_unreachable_and_folded_gates` | `tests/optimizer.rs::prop_dce_counts_every_recorded_gate`, `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_dce_matches_reference` |
| Sklansky prefix adder (width 4 and up) vs ripple | `BitEvaluator::prefix_add`, `BitEvaluator::add_bits` | `src/bits.rs::prefix_add_and_tree_carry_out_match_ripple_exhaustively_to_8_bits`, `src/bits.rs::prefix_add_and_tree_carry_out_match_ripple_on_wide_samples`, `src/bits.rs::prefix_adder_and_tree_comparator_are_used_from_width_4`, `src/bits.rs::prefix_adder_and_tree_comparator_have_logarithmic_depth` | `src/bits.rs::prop_prefix_add_and_tree_carry_out_match_ripple` | `tests/optimizer.rs::diff_prefix_adder_every_width` |
| Tree comparator (width 4 and up) vs ripple carry out | `BitEvaluator::tree_carry_out`, `BitEvaluator::carry_out` | `src/bits.rs::prefix_add_and_tree_carry_out_match_ripple_exhaustively_to_8_bits`, `src/bits.rs::prefix_add_and_tree_carry_out_match_ripple_on_wide_samples`, `src/bits.rs::prefix_adder_and_tree_comparator_are_used_from_width_4`, `src/bits.rs::prefix_adder_and_tree_comparator_have_logarithmic_depth` | `src/bits.rs::prop_prefix_add_and_tree_carry_out_match_ripple` | `tests/optimizer.rs::diff_tree_comparator_every_width` |
| Strategy selection (fewest rounds, then gates; the reference on ties) | `optimize` | `tests/optimizer.rs::optimize_prefers_fewest_rounds_then_gates_and_the_reference_on_ties` | `tests/optimizer.rs::prop_optimize_selects_fewest_rounds_then_gates` | `tests/optimizer.rs::diff_optimize_matches_reference_lowering` |
| Cost model: rounds and gates per level | `Circuit::rounds`, `Circuit::level_sizes` | `tests/optimizer.rs::rounds_and_level_sizes_follow_levels` | `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_optimize_matches_reference_lowering` |
| Level analysis and circuit statistics (depth, width, gates, NOTs, input bits) | `Circuit::analyze` | `tests/optimizer.rs::execute_evaluates_each_gate_once_level_by_level`, `tests/optimizer.rs::rounds_and_level_sizes_follow_levels` | `tests/optimizer.rs::prop_circuit_structure_and_stats` | `tests/optimizer.rs::diff_execute_workers_match_reference` |
| Levelized parallel execution (1..N workers; each gate once) | `execute` | `tests/optimizer.rs::execute_evaluates_each_gate_once_level_by_level`, `tests/optimizer.rs::execute_propagates_gate_errors` | `tests/optimizer.rs::prop_execute_is_worker_count_independent` | `tests/optimizer.rs::diff_execute_workers_match_reference` |
| Execution input validation | `execute` | `tests/optimizer.rs::execute_rejects_bad_inputs` | `tests/optimizer.rs::prop_execute_rejects_malformed_inputs` | `tests/optimizer.rs::diff_execute_rejects_what_the_reference_rejects` |
