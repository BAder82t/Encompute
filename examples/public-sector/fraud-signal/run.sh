#!/usr/bin/env bash
# Public-sector example C: a bounded signal released to one agency. The
# Tax Agency's records hold an income gap; the Benefit Integrity Unit may
# learn only a category (0 none, 1 low, 2 review suggested), never the
# gap, for one declared purpose, and nobody else learns anything. This is
# the single-source form: one agency's data, with no record linkage.
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"

step "Read this first"
cat "$HERE/DISCLAIMER.md"

step "The policy: what the integrity unit may learn, and for what"
"$E" compile "$HERE/income-gap.eir" -o "$W/signal.encompute" > /dev/null
"$E" privacy explain "$W/signal.encompute" | sed -n '/^Assets/,/^Flows/p' |
  grep -E "income-gap|output signal|may learn it|purposes|release|goes to"
echo "RELEASE FORM  declared: a category from 0 to 2 (the compiler refuses an output it cannot prove fits)"

step "Run it on synthetic rows (each runs on the Tax Agency's side; the unit sees the category)"
while read -r id gap; do
  case "$id" in ''|'#'*) continue ;; esac
  out="$("$E" run "$W/signal.encompute" --mode mock --input "gap=$gap")"
  cat=$(echo "$out" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["signal"])')
  printf '%s  category %s  (%s)\n' "$id" "$cat" "$(category_name "$cat")"
done < "$HERE/data/applicants.txt"

step "Try breaking it: each program below must fail to compile"
for a in release-the-gap widened-categories debt-collection housing-agency; do
  bash "$HERE/attack-$a.sh"
done

step "What this example does not show"
echo "The cross-agency form (the Housing, Tax and Benefits records of one person, linked)"
echo "needs record linkage, which is not built. An auditor running the job and onward"
echo "export of a result are refused by the control plane: scripts/governance-attacks.sh."
