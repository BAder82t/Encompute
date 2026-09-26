#!/usr/bin/env bash
# 13: the assurance report. Runs a few fast checks and confirms every test
# the invariant catalog cites still exists.
source "$(dirname "$0")/../lib.sh"

REPORT=""
for b in "$ROOT/target/release/assurance-report" "$ROOT/target/debug/assurance-report"; do
  [ -x "$b" ] && { REPORT="$b"; break; }
done
[ -n "$REPORT" ] ||
  skip "assurance-report is not built (cargo build --release -p encompute-assurance --bins --examples)"

CHECKS=(execution_receipt_mutation secagg_coordinator_sees_no_input dp_invalid_noise
  dp_ledger_tampering planner_adversarial planner_plan_id_binding)
ONLY=()
for c in "${CHECKS[@]}"; do ONLY+=(--only "$c"); done

step "Run six fast checks and write the report"
"$REPORT" --root "$ROOT" "${ONLY[@]}" --json "$W/assurance-report.json" --md "$W/assurance-report.md" 2>&1 |
  sed 's/ ([0-9.]*s)$//' | tee "$W/out.txt"
# A misspelled --only name runs nothing and still passes: count the checks.
[ "$(grep -c '^ok ' "$W/out.txt")" -eq "${#CHECKS[@]}" ] || { echo "not every check ran" >&2; exit 1; }

step "What the report contains"
"$PYTHON" - "$W/assurance-report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print(f"Scale            {r['scale']}")
for c in r["checks"]:
    print(f"Check            {c['name']:36} {'pass' if c['passed'] else 'FAIL'}  {c['cases']} cases")
inv = r["invariants"]
gaps = [i["id"] for i in inv if i["gaps"]]
print(f"Invariants       {len(inv)}, {sum(i['passed'] for i in inv)} satisfied")
print(f"Tracked gaps     {', '.join(gaps)}")
print(f"Scope            {r['scope'].split('. ')[-1]}")
PY
grep -m1 'All tested' "$W/assurance-report.md"

step "Try breaking it: a cited test disappears"
# A copy of the repository in which one keybroker test was renamed.
mkdir -p "$W/root/crates/encompute-keybroker/tests"
for e in "$ROOT"/*; do [ "${e##*/}" = crates ] || ln -s "$e" "$W/root/"; done
for e in "$ROOT"/crates/*; do [ "${e##*/}" = encompute-keybroker ] || ln -s "$e" "$W/root/crates/"; done
for e in "$ROOT"/crates/encompute-keybroker/*; do [ "${e##*/}" = tests ] || ln -s "$e" "$W/root/crates/encompute-keybroker/"; done
sed 's/fn untrusted_workloads_receive_no_key(/fn renamed(/' \
  "$ROOT/crates/encompute-keybroker/tests/release.rs" > "$W/root/crates/encompute-keybroker/tests/release.rs"
if out="$("$REPORT" --root "$W/root" --only dp_invalid_noise 2>&1)"; then
  echo "$out"; echo "ATTACK SUCCEEDED (this is a bug): stale catalog passed" >&2; exit 1
fi
echo "$out" | grep -E '^INVARIANTS VIOLATED|^  INV-'
echo "(exit 1: a missing test fails the report, so the catalog cannot silently go stale)"
