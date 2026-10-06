#!/usr/bin/env bash
# Public-sector example B: weekly disease counts from four regional
# authorities, by secure aggregation with differential privacy. Each
# authority's privacy budget is the cap of its population (all versions of
# its series, every project); this project spends it through a scope. When
# the population cannot pay for another week, the release is denied.
source "$(dirname "$0")/../../lib.sh"
need_cli
source "$HERE/common.sh"
consortium

step "The policy: the ministry learns only the aggregate, with noise"
"$E" privacy explain surveillance.encompute | sed -n '/^Aggregation boundary/,/STATUS/p' |
  grep -E "participants|minimum|collusion|layout|linkage|sources/unit|STATUS"
"$E" privacy explain surveillance.encompute | sed -n '/^Differential privacy/,$p' |
  grep -E "mechanism|budget" | head -n 3

step "The owners allocate: a population per region (the cap), and this project's scope of it"
for x in $REGIONS; do
  "$E" privacy population --ledger ledger --id "residents-$x" --organization "region-$x" \
    --series regional-residents-2027 --unit patient --epsilon 1.0 --delta 1e-6 | head -n 1
done
allocate "$PS_PROJECT" ledger scoping.json
export PS_WORLD="$W"
echo "SCOPES allocated to $PS_PROJECT: one per region, each for the population's whole epsilon"
"$E" privacy budget --ledger ledger --asset scope-n | sed -n '2,6p'

step "Weeks 1 to 4: each authority contributes from its own process"
for week in 1 2 3 4; do
  week "$week" || { cat "$CLOG" join-*-"$week"0.log; exit 1; }
  spent "$week"
  if [ "$week" -eq 2 ]; then
    cp -R ledger ledger-after-week-2
    step "(A replay of week 2, and a week with too few authorities, are refused)"
    coordinator surveillance.encompute 20 scoping.json ledger
    pids=""
    for x in $REGIONS; do join "$x" surveillance.encompute scoping.json > "replay-$x.log" 2>&1 & pids="$pids $!"; done
    for p in $pids; do wait "$p" || true; done
    stop_coordinator
    grep -h "ENC2102" replay-n.log | head -n 1
    bash "$HERE/attack-below-threshold.sh"
    step "Weeks 3 and 4"
  fi
done

step "Week 5: the population cannot pay for another release"
if week 5; then echo "UNEXPECTED: week 5 ran" >&2; exit 1; fi
denied 50
echo "Population residents-n: spent $("$E" privacy budget --ledger ledger --asset residents-n | grep Consumed | sed 's/^ *Consumed *//')"

step "Anyone with the spec checks a week's receipt"
"$E" aggregate verify receipt-40.json surveillance.encompute --parties parties.json \
  --scoping scoping.json --aggregate round-40.json | tail -n 1

step "Try breaking it"
for a in restore-budget new-version unrelated-project raw-release; do
  bash "$HERE/attack-$a.sh"
done
