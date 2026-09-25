#!/usr/bin/env bash
# Private federated training rounds (ADR-012, ADR-013): Hospitals A, B and C
# each hold a private gradient (4096 values) with a patient-level privacy
# budget ("strong": epsilon 3, delta 1e-6). Every round is secure
# aggregation plus discrete Gaussian noise, charged to each hospital's
# ledger; when the next round would exceed the budget, it is denied.
#
#   cargo build --bin encompute
#   examples/private_federated_training/run.sh
set -eu
E="${BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug}/encompute"
W="$(mktemp -d)"
cd "$W"
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"' EXIT
ready() { for _ in $(seq 100); do curl -s -o /dev/null "$1" && return 0; sleep 0.2; done; echo "$1 did not start" >&2; exit 1; }

python3 - <<'PY'
import json, random
n = 4096
lines = ['encompute 0.1', 'program fedavg precision 0.001 purpose "disease-training"',
         'party "coordinator" "Coordinator"']
for x in "abc":
    lines.append(f'party "hospital-{x}" "Hospital {x.upper()}"')
for x in "abc":
    lines.append(f'asset "gradient-{x}" gradient owners ["hospital-{x}"] readers ["coordinator"] '
                 'purposes ["disease-training"] release aggregate_only '
                 'privacy unit "patient" epsilon 3.0 delta 1e-6')
for i, x in enumerate("abc"):
    lines.append(f'%{i} = input "g{x}" [-1.0, 1.0] asset "gradient-{x}" : secret vector<{n}>')
lines += [f'%3 = add %0, %1 : secret vector<{n}>', f'%4 = add %3, %2 : secret vector<{n}>',
          'output "global_gradient" = %4 to "coordinator"',
          'aggregate "global_gradient" sum minimum 3 colluding 2 clip [-1.0, 1.0] scale 4096 '
          'modulus 40 dp discrete_gaussian clip_norm 1.0 noise_multiplier 6.0']
open("fedavg.eir", "w").write("\n".join(lines) + "\n")
rng = random.Random(7)
for x in "abc":
    # Gradients with L2 norm below the clip norm of 1.
    json.dump([rng.uniform(-1, 1) / 100 for _ in range(n)], open(f"gradient-{x}.json", "w"))
PY
"$E" compile fedavg.eir -o fedavg.encompute > /dev/null
echo "== The policy: secure aggregation, then differential privacy"
"$E" privacy explain fedavg.encompute | sed -n '/Differential privacy/,/STATUS/p'
for x in a b c; do "$E" aggregate identity --party "hospital-$x" --key "$x.key"; done > parties.jsonl
python3 -c "import json;print(json.dumps([json.loads(l) for l in open('parties.jsonl')]))" > parties.json

round=0
while :; do
  round=$((round + 1))
  if ! "$E" aggregate serve fedavg.encompute --parties parties.json --key coordinator.key \
       --listen 127.0.0.1:18780 --stage-timeout 20 --sequence "$round" --ledger ledger \
       --out "round-$round.json" > "coordinator-$round.log" 2>&1 & then :; fi
  coordinator=$!
  # A denied round never opens: the coordinator exits at once.
  for _ in $(seq 50); do
    curl -s -o /dev/null http://127.0.0.1:18780/v1/round && break
    kill -0 "$coordinator" 2>/dev/null || break
    sleep 0.2
  done
  if ! kill -0 "$coordinator" 2>/dev/null && ! [ -f "round-$round.json" ]; then
    echo; echo "== Round $round"
    grep -o 'ENC2201.*' "coordinator-$round.log" || cat "coordinator-$round.log"
    break
  fi
  pids=""
  for x in a b c; do
    "$E" aggregate join fedavg.encompute --parties parties.json --coordinator http://127.0.0.1:18780 \
      --party "hospital-$x" --key "$x.key" --values "gradient-$x.json" --state "$x.state" \
      > "join-$x-$round.log" 2>&1 &
    pids="$pids $!"
  done
  for p in $pids; do wait "$p"; done
  wait "$coordinator"
  printf "Round %-3s permitted   %s\n" "$round" "$(grep '^Privacy' join-a-$round.log | sed 's/Privacy *//')"
done

echo; echo "== Hospital A's ledger"
"$E" privacy budget --ledger ledger --asset gradient-a | sed -n '/Budget/,/Ledger/p'
