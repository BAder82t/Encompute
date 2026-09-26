#!/usr/bin/env bash
# 08: secure aggregation. Three hospitals, three processes; the coordinator
# learns only the sum of their vectors.
source "$(dirname "$0")/../lib.sh"
need_cli
source "$HERE/common.sh"
consortium

step "The policy, and the mechanism that satisfies it"
"$E" privacy explain fedavg.encompute | sed -n '/Aggregation boundary/,/STATUS/p'

step "The test vectors (plaintext here only because this is a demo)"
for x in a b c; do printf 'Hospital %s  %s\n' "$(echo $x | tr a-z A-Z)" "$(cat "$HERE/hospital-$x.json")"; done

step "Each hospital creates its identity; the consortium shares parties.json"
"$PYTHON" -c 'import json; print("Parties", ", ".join(p["party"] for p in json.load(open("parties.json"))))'

step "The coordinator opens round 1; Hospitals A, B and C contribute from separate processes"
full_round 1
for x in a b c; do printf 'Hospital %s  %s\n' "$(echo $x | tr a-z A-Z)" "$(head -n 1 "join-$x-1.log")"; done
echo
grep -v '^aggregation round' "$CLOG"

step "Secure aggregate == clear A+B+C"
"$PYTHON" - "$HERE" <<'PY'
import json, sys
here = sys.argv[1]
vec = {x: json.load(open(f"{here}/hospital-{x}.json")) for x in "abc"}
agg = json.load(open("aggregate.json"))["values"]
clear = [sum(v[i] for v in vec.values()) for i in range(16)]
err = max(abs(a - c) for a, c in zip(agg, clear))
bound = 3 * 0.5 / 65536  # each party's value is rounded to 1/65536
print("Clear A+B+C      ", " ".join(f"{c:+.2f}" for c in clear))
print("Secure aggregate ", " ".join(f"{a:+.2f}" for a in agg))
print(f"Max difference    {err:.2e} (codec resolution: 3 x 0.5/65536 = {bound:.2e})")
assert err <= bound + 1e-12
print("PASS")
PY

step "The coordinator's output holds no individual vector"
"$PYTHON" - "$HERE" "$CLOG" <<'PY'
import json, re, sys
here, log = sys.argv[1], sys.argv[2]
vec = {x: json.load(open(f"{here}/hospital-{x}.json")) for x in "abc"}
def numbers(v):
    if isinstance(v, dict):
        for x in v.values(): yield from numbers(x)
    elif isinstance(v, list):
        for x in v: yield from numbers(x)
    elif isinstance(v, (int, float)) and not isinstance(v, bool):
        yield v
seen = set()
for f in ["aggregate.json", "aggregation-receipt.json"]:
    seen |= set(numbers(json.load(open(f))))
seen |= {float(n) for n in open(log).read().split() if re.fullmatch(r"-?\d+(\.\d+)?", n)}
receipt = json.load(open("aggregation-receipt.json"))
print("Receipt holds    ", ", ".join(sorted(receipt["manifest"])))
for x, v in vec.items():
    # Each value as given, and as the fixed-point code the protocol masks.
    leaked = [y for y in v if y in seen or round((y + 1) * 65536) in seen]
    print(f"Hospital {x.upper()} values found in the output, receipt or log: {len(leaked)}")
    assert not leaked
print("NO INDIVIDUAL VECTOR RELEASED")
PY

step "Anyone with the spec checks the receipt"
"$E" aggregate verify aggregation-receipt.json fedavg.encompute --parties parties.json \
  --aggregate aggregate.json | tail -n 2

step "Try breaking it"
for a in unauthorized-party below-threshold replay wrong-round; do
  bash "$HERE/attack-$a.sh"
done
