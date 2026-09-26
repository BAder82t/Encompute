#!/usr/bin/env bash
# 12: a full confidential collaboration. Three hospitals and ModelCo declare
# their policies; Encompute plans the mechanisms; workloads attest and
# receive keys; the hospitals' updates are securely aggregated with
# differential privacy; every piece of evidence goes into a trust bundle
# that one report verifies.
source "$(dirname "$0")/../lib.sh"
need_cli
need_python
source "$HERE/setup.sh"

step "1. Declare parties, assets and policies"
declare_collaboration
"$E" privacy explain collab.encompute 2>/dev/null | sed -n '/^Assets/,/^Flows/p' | grep -v '^Flows'

step "2. Plan: Encompute chooses the mechanisms"
plan_collaboration
sed -n '/^Selected mechanisms/,/^Why/p' plan.txt | grep -v '^Why'
grep '^ALL TRUST REQUIREMENTS SATISFIED' plan.txt
echo "(the only TEE here is development mock attestation: it protects nothing,"
echo " but every check below is the one a real TEE's evidence goes through)"

step "3. Owners approve the program"
approve

step "4. ModelCo's key broker releases the model key only to the attested workload"
protect_model_key
release_model_key

step "5. Secure aggregation with differential privacy (attested coordinator)"
round 1 || { cat coordinator-1.log join-*-1.log; exit 1; }
grep -h "CONTRIBUTION ACCEPTED" join-*-1.log | sort | uniq -c | sed 's/^ *//'
grep -E "^AGGREGATION COMPLETE|^Privacy" coordinator-1.log
"$E" aggregate verify receipt-1.json collab.encompute --parties parties.json --plan plan.json \
  --coordinator-policy coord-policy.json --aggregate update-1.json | grep VERIFIED

step "6. One trust report over all of it"
trust_report | tee report.txt
grep -q "TRUST REQUIREMENTS SATISFIED" report.txt

if [ "$MODE" = full ]; then
  step "7. Every attack fails closed"
  bash "$HERE/attack.sh" all 2>&1 | grep -E '^== |^BOUNDARY|^REFUSED|^RESULT'
fi
