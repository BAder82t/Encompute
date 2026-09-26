#!/usr/bin/env bash
# 10: the trust graph. One secure-aggregation round with differential
# privacy, recorded in a trust bundle and checked as one trust report; then
# doctored copies of the bundle, each refused.
source "$(dirname "$0")/../lib.sh"
need_cli
cd "$W"

# 64-hex IDs, shortened for reading.
short() { sed -E 's/([0-9a-f]{16})[0-9a-f]{48}/\1../g'; }

step "Program, consortium and plan"
"$E" compile "$HERE/fedavg.eir" -o fedavg.encompute
for x in a b c; do
  "$E" aggregate identity --party "hospital-$x" --key "$x.key"
  echo "[0.01, -0.02, 0.03, 0.0]" > "$x.json"
done > parties.jsonl
"$PYTHON" -c "import json; print(json.dumps([json.loads(l) for l in open('parties.jsonl')]))" > parties.json
# The coordinator's key: the hospitals and the auditor get it out of band.
COORD_KEY="$("$E" aggregate identity --party coordinator --key coord.key |
  "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')"
"$E" plan fedavg.encompute -o plan.json 2>/dev/null | sed -n '/Selected mechanisms/,/^$/p;/^RESULT/,$p' | short

step "Trust bundle: program, plan, parties, owners' authorizations"
"$E" trust init fedavg.encompute --parties parties.json --plan plan.json --bundle trust.json | short
for x in a b c; do
  "$E" trust authorize --party "hospital-$x" --key "$x.key" --bundle trust.json
done

step "One secure-aggregation round with differential privacy"
port="$(free_port)"
"$E" aggregate serve fedavg.encompute --parties parties.json --plan plan.json --key coord.key \
  --listen "127.0.0.1:$port" --stage-timeout 20 --sequence 1 --ledger ledger \
  --out aggregate.json --receipt receipt.json --trust-bundle trust.json > coordinator.log 2>&1 &
coordinator=$!
ready_port "$port"
pids=""
for x in a b c; do
  "$E" aggregate join fedavg.encompute --parties parties.json --plan plan.json \
    --coordinator "http://127.0.0.1:$port" --party "hospital-$x" --key "$x.key" \
    --values "$x.json" --state "$x.round" > "join-$x.log" 2>&1 &
  pids="$pids $!"
done
for p in $pids; do wait "$p"; done
wait "$coordinator" || { cat coordinator.log; exit 1; }
grep -E '^(AGGREGATION COMPLETE|Contributors|Minimum)' coordinator.log
grep -E '^Privacy' join-a.log

report() { "$E" trust report --parties parties.json --coordinator-key "$COORD_KEY" "$@"; }

step "Trust report (keys from the verifier, never from the bundle)"
report --bundle trust.json | short

step "Lineage of gradient-a"
"$E" trust lineage gradient-a --bundle trust.json | short

step "Graph (Graphviz DOT, first lines)"
"$E" trust graph --bundle trust.json > trust.dot
head -n 6 trust.dot | short
echo "... $(grep -c -- '->' trust.dot) edges (render with: dot -Tsvg)"

# Each attack edits a copy of the bundle; the report must refuse it.
#   refused "what" command...   prints the failing rows and the verdict
refused() {
  local what="$1" out
  shift
  if out="$("$@" 2>&1)"; then
    echo "$out"
    echo "ATTACK SUCCEEDED (this is a bug): $what" >&2
    exit 1
  fi
  echo "$out" | grep -q 'TRUST REQUIREMENTS NOT SATISFIED' ||
    { echo "$out"; echo "unexpected failure: $what" >&2; exit 1; }
  printf '\nATTACK   %s\n' "$what"
  echo "$out" | awk '/^[A-Z][a-z].*(FAILED|not checked)/ {row=1; print; n=0; next}
    /^Revoked/ {row=0; print; getline; print; next}
    /^[A-Z]/ {row=0} row && /^  - / && n++ < 1 {print}
    /^RESULT/ {res=1} res' | short
}

step "Try breaking it"
"$PYTHON" "$HERE/tamper.py" trust.json dropped.json drop-privacy-receipt
refused "remove gradient-a's privacy receipt" report --bundle dropped.json

"$PYTHON" "$HERE/tamper.py" trust.json noise.json less-noise
refused "edit a privacy receipt (claim 10x the noise)" report --bundle noise.json

cp trust.json revoked.json
"$E" trust revoke --party hospital-a --key a.key --asset gradient-a \
  --reason "consent withdrawn" --bundle revoked.json > revoke.log
refused "use gradient-a after hospital-a revoked it" report --bundle revoked.json

refused "report with no trusted keys (the bundle vouches for itself)" \
  "$E" trust report --bundle trust.json
OTHER_KEY="$("$E" aggregate identity --party coordinator --key other.key |
  "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')"
refused "receipts signed by a coordinator the verifier does not trust" \
  "$E" trust report --bundle trust.json --parties parties.json --coordinator-key "$OTHER_KEY"

"$E" plan fedavg.encompute --prefer cost -o other-plan.json > /dev/null 2>&1
cp trust.json replanned.json
"$E" trust add other-plan.json --bundle replanned.json > /dev/null
refused "approve a different plan than the round ran under" report --bundle replanned.json
