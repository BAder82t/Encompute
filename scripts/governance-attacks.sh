#!/usr/bin/env bash
# The governance attack suite: every attack below must be refused with its
# documented ENC code, and must leave its trail (an audit event, an anchored
# log event, or a refused start) and no job, ticket, key release or budget.
# Each row names the test that runs the attack against the real service or
# library; the test asserts the code and the trail, and the ones written for
# this suite print one `ATTACK ... -> CODE (trail)` line per attack.
#
#   scripts/governance-attacks.sh            run every attack
#   scripts/governance-attacks.sh NAME...    run the attacks whose row contains NAME
#
# Needs the services the governance tests run against, because without them
# those tests skip and pass (the suite refuses to run without them):
#
#   ENCOMPUTE_TEST_DATABASE_URL   a PostgreSQL URL (the tests make databases)
#   ENCOMPUTE_TEST_BAO_ADDR / ENCOMPUTE_TEST_BAO_TOKEN   an OpenBao dev server
#   OPENFHE_ROOT                  the OpenFHE install the workspace builds against
#
# Run it alone: the tests share the database server.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
for v in ENCOMPUTE_TEST_DATABASE_URL ENCOMPUTE_TEST_BAO_ADDR ENCOMPUTE_TEST_BAO_TOKEN; do
  [ -n "${!v:-}" ] || { echo "governance attacks: $v is not set (the service-backed tests would skip)" >&2; exit 2; }
done
export ENCOMPUTE_REQUIRE_SERVICES=1

# attack | code | package | test file | test
ATTACKS='
forged or tampered owner signature|ENC2701|encompute-control|governed_jobs|attack_a_forged_or_tampered_owner_signature_activates_nothing
job outside what the owners signed (unsigned, purpose, program, recipient, class, version)|ENC2701 ENC2702 ENC2703 ENC2704 ENC2709|encompute-control|governed_jobs|attack_a_job_outside_what_the_owners_signed_is_refused_and_audited
expired, revoked or key-revoked authorization|ENC2705 ENC2706 ENC2708|encompute-control|governed_jobs|attack_an_expired_or_revoked_authorization_is_refused_and_audited
release ticket for a job that is not running|ENC2604 ENC2704|encompute-control|governed_jobs|attack_a_release_ticket_for_a_job_that_is_not_running_is_refused
wrong purpose|ENC2702|encompute-control|governed_jobs|purpose_mismatch_refused_2702
wrong program|ENC2703|encompute-control|governed_jobs|program_outside_program_set_refused_2703
wrong source version|ENC2704|encompute-control|governed_jobs|wrong_version_2704
over-release past the owners class|ENC2709|encompute-control|governed_jobs|release_form_stronger_than_class_refused_2709
over-release of a value (compile time)|ENC1907|encompute-analysis|release_forms|value_output_from_boolean_only_does_not_compile_1907
scope-pin conflict|ENC2719|encompute-control|privacy_scopes|two_authorizations_that_pin_different_scopes_are_refused
spend without a scope|ENC2719|encompute-control|privacy_scopes|a_job_with_no_scope_cannot_spend
residency violation at submission|ENC2710|encompute-control|residency|an_owners_own_constraints_apply_and_never_leak
residency violation: no ticket outside the constraints|ENC2710|encompute-control|residency|no_release_ticket_goes_to_an_evaluator_outside_the_constraints
operator separation|ENC2725|encompute-control|residency|a_data_owner_operated_evaluator_gets_no_job_start_or_ticket
auditor runs a job or holds a role|ENC2716|encompute-control|auditor|auditor_org_cannot_submit_or_receive
service account approves|ENC2707|encompute-control|governed_jobs|service_account_cannot_approve_2707
derived result without every lineage owners consent|ENC2701|encompute-control|governed_jobs|derived_source_needs_every_lineage_owners_authorization
export after a source was revoked|ENC2706|encompute-control|governed_jobs|export_of_derived_asset_whose_source_was_revoked_2706
grant replayed across projects|refused|encompute-control|governed_jobs|cross_project_grant_replay_refused
skipped or replayed log sequence number|ENC2717|encompute-control|revocation_heads|skipped_or_replayed_seq_refused
rolled-back database against the anchor|ENC2202|encompute-control|governance_rollback|restores_resurrecting_governed_state_are_refused_and_recovered
forged release ticket at the broker|ENC2712|encompute-keybroker|sovereign|forged_ticket_refused
replayed release ticket at the broker|ENC2712|encompute-keybroker|sovereign|replayed_ticket_refused
ticket for another organization at the broker|ENC2712|encompute-keybroker|sovereign|ticket_for_other_org_refused
rolled-back broker state|ENC2713|encompute-keybroker|generation|broker_state_rollback_refused_by_kms_generation
edited evidence bundle|refused or visibly changed|encompute-trust|governance_bundle|every_single_field_edit_fails
tampered report|changes nothing|encompute-trust|governance_report|a_tampered_report_or_cached_attribute_changes_nothing
'

want=("$@")
pass=0; fail=0
while IFS='|' read -r name code pkg file test; do
  [ -n "$name" ] || continue
  if [ ${#want[@]} -gt 0 ]; then
    hit=0
    for w in "${want[@]}"; do case "$name|$code|$test" in *"$w"*) hit=1 ;; esac; done
    [ $hit -eq 1 ] || continue
  fi
  out="$(cargo test -q -p "$pkg" --test "$file" -- --exact "$test" --nocapture 2>&1)"
  rc=$?
  # A run that matched no test, or ran none, is a failure, not a pass.
  if [ $rc -eq 0 ] && echo "$out" | grep -q '^test result: ok. 1 passed'; then
    printf 'REFUSED  %-78s %s\n' "$name" "$code"
    echo "$out" | grep '^ATTACK ' | sed 's/^/           /'
    pass=$((pass + 1))
  else
    printf 'FAILED   %-78s %s\n' "$name" "$code"
    echo "$out" | tail -n 20 | sed 's/^/           | /'
    fail=$((fail + 1))
  fi
done <<< "$ATTACKS"
printf '\n%s attacks refused, %s failed\n' "$pass" "$fail"
[ $fail -eq 0 ] && [ $pass -gt 0 ]
