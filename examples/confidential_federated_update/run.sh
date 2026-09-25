#!/usr/bin/env bash
# Secure aggregation, locally (ADR-012): Hospitals A, B and C each hold a
# private gradient (4096 values, aggregate-only); the coordinator learns
# only their sum. Hospital D, not in the consortium, is refused.
#
#   cargo build --bin encompute
#   examples/confidential_federated_update/run.sh
set -eu
E="${BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug}/encompute"
W="$(mktemp -d)"
cd "$W"
# Wait until an HTTP server answers (up to 20 s).
ready() { for _ in $(seq 100); do curl -s -o /dev/null "$1" && return 0; sleep 0.2; done; echo "$1 did not start" >&2; exit 1; }
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"' EXIT

python3 - <<'PY'
import json, random
n = 4096
lines = ['encompute 0.1', 'program fedavg precision 0.001 purpose "disease-training"',
         'party "coordinator" "Coordinator"']
for x in "abc":
    lines.append(f'party "hospital-{x}" "Hospital {x.upper()}"')
for x in "abc":
    lines.append(f'asset "gradient-{x}" gradient owners ["hospital-{x}"] readers ["coordinator"] '
                 'purposes ["disease-training"] release aggregate_only')
for i, x in enumerate("abc"):
    lines.append(f'%{i} = input "g{x}" [-1.0, 1.0] asset "gradient-{x}" : secret vector<{n}>')
lines += [f'%3 = add %0, %1 : secret vector<{n}>', f'%4 = add %3, %2 : secret vector<{n}>',
          'output "global_gradient" = %4 to "coordinator"',
          'aggregate "global_gradient" sum minimum 3 colluding 2 clip [-1.0, 1.0] scale 65536 modulus 32']
open("fedavg.eir", "w").write("\n".join(lines) + "\n")
rng = random.Random(7)
for x in "abcd":
    json.dump([rng.uniform(-1, 1) for _ in range(n)], open(f"gradient-{x}.json", "w"))
PY
"$E" compile fedavg.eir -o fedavg.encompute > /dev/null

echo "== The policy, and the mechanism that satisfies it"
"$E" privacy explain fedavg.encompute | sed -n '/Aggregation boundary/,/STATUS/p'

echo; echo "== Each hospital creates its identity; the consortium shares parties.json"
for x in a b c; do "$E" aggregate identity --party "hospital-$x" --key "$x.key"; done > parties.jsonl
python3 -c "import json;print(json.dumps([json.loads(l) for l in open('parties.jsonl')]))" > parties.json

"$E" aggregate serve fedavg.encompute --parties parties.json --key coordinator.key \
  --listen 127.0.0.1:18770 --stage-timeout 20 > coordinator.log 2>&1 &
coordinator=$!
ready http://127.0.0.1:18770/v1/round
echo; echo "== Hospital D (not in the consortium) tries to join"
"$E" aggregate identity --party hospital-d --key d.key > /dev/null
if "$E" aggregate join fedavg.encompute --parties parties.json --coordinator http://127.0.0.1:18770 \
     --party hospital-d --key d.key --values gradient-d.json --state d.round 2>&1 | tee d.log | grep -q ENC2101; then cat d.log; else
  cat d.log; echo "UNEXPECTED: D was not refused as unauthorized"; exit 1
fi

echo; echo "== Hospitals A, B and C contribute"
for x in a b c; do
  "$E" aggregate join fedavg.encompute --parties parties.json --coordinator http://127.0.0.1:18770 \
    --party "hospital-$x" --key "$x.key" --values "gradient-$x.json" --state "$x.round" > "$x.log" 2>&1 &
  hospitals="${hospitals:-} $!"
done
for pid in $hospitals; do wait "$pid"; done
sed -n 1p a.log
wait "$coordinator"
echo; cat coordinator.log | grep -v "^aggregation round"

echo; echo "== The aggregate equals the clear sum within the declared quantization"
python3 - <<'PY'
import json
agg = json.load(open("aggregate.json"))
g = [json.load(open(f"gradient-{x}.json")) for x in "abc"]
err = max(abs(agg["values"][j] - sum(v[j] for v in g)) for j in range(len(agg["values"])))
print(f"max |secure - clear| = {err:.2e} (bound 3 x 0.5/65536 = {3*0.5/65536:.2e})")
assert err <= 3 * 0.5 / 65536 + 1e-12
print("owners", sorted(agg["policy"]["owners"]), "may learn it:", agg["policy"]["audience"])
PY

echo; echo "== Anyone with the spec checks the receipt"
"$E" aggregate verify aggregation-receipt.json fedavg.encompute --parties parties.json \
  --aggregate aggregate.json | tail -2
