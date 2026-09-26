# The collaboration, as steps shared by run.sh and attack.sh. Expects
# lib.sh to be sourced (W, E, PYTHON, step, free_port, ready_port).

# The program: three hospitals' model updates, aggregate-only with a
# patient-level budget, securely summed with differential privacy for
# ModelCo. $1 is the noise multiplier (the approved one is 6.0).
write_program() {
  "$PYTHON" - "$W/$2" "$1" <<'PY'
import sys
out, noise = sys.argv[1], sys.argv[2]
L = ['encompute 0.1', 'program collaboration precision 0.001 purpose "disease-model"',
     'party "modelco" "ModelCo"']
L += [f'party "hospital-{x}" "Hospital {x.upper()}"' for x in "abc"]
L.append('asset "base-model" model owners ["modelco"] readers [] purposes ["disease-model"] release never')
for x in "abc":
    L.append(f'asset "patients-{x}" dataset owners ["hospital-{x}"] readers [] '
             'purposes ["disease-model"] release never')
for x in "abc":
    L.append(f'asset "update-{x}" gradient owners ["hospital-{x}"] readers ["modelco"] '
             'purposes ["disease-model"] release aggregate_only '
             'privacy unit "patient" epsilon 3.0 delta 1e-6')
for i, x in enumerate("abc"):
    L.append(f'%{i} = input "u{x}" [-1.0, 1.0] asset "update-{x}" : secret vector<8>')
L += ['%3 = add %0, %1 : secret vector<8>', '%4 = add %3, %2 : secret vector<8>',
      'output "model_update" = %4 to "modelco"',
      'aggregate "model_update" sum minimum 3 colluding 1 clip [-1.0, 1.0] scale 1024 '
      f'modulus 32 dp discrete_gaussian clip_norm 1.0 noise_multiplier {noise}']
open(out, "w").write("\n".join(L) + "\n")
PY
}

declare_collaboration() {
  cd "$W"
  write_program 6.0 collab.eir
  "$E" compile collab.eir -o collab.encompute >/dev/null
  # Identities: public keys go into parties.json, which every party
  # obtains out of band; ModelCo's coordinator key likewise.
  local ids=()
  for x in a b c; do
    ids+=("$("$E" aggregate identity --party "hospital-$x" --key "$x.key")")
  done
  (IFS=,; echo "[${ids[*]}]") > parties.json
  COORD_KEY="$("$E" aggregate identity --party modelco --key coord.key |
    "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')"
  # The infrastructure: a TEE (development mock attestation here), a key
  # broker, ordinary hosts in the cloud.
  MOCK_ROOT="$("$E" attest mock-root hw.seed)"
  IMAGE="sha256:$(printf '9%.0s' $(seq 64))"
  echo '{"tees": [{"tee": "mock", "provider": "mock", "cloud": true}], "key_broker": true, "host_cloud": true}' > infra.json
  echo '{"model": "base-model", "data": ["patients-a", "patients-b", "patients-c"], "verified": true}' > training.json
  "$PYTHON" - <<'PY'
import json, random
random.seed(12)
for x in "abcd":   # each hospital's clipped model update, computed locally
    json.dump([round(random.uniform(-0.3, 0.3), 3) for _ in range(8)], open(f"{x}.json", "w"))
PY
}

plan_collaboration() {
  "$E" plan collab.encompute --profile strong --infrastructure infra.json \
    --training training.json --allow-development -o plan.json > plan.txt 2>/dev/null
}

approve() {
  "$E" aggregate coordinator-policy collab.encompute --image "$IMAGE" --tee mock \
    --development --plan plan.json > coord-policy.json
  "$E" trust init collab.encompute --parties parties.json --plan plan.json \
    --coordinator-policy coord-policy.json --bundle trust.json >/dev/null
  for x in a b c; do
    "$E" trust authorize --party "hospital-$x" --key "$x.key" --bundle trust.json
  done
}

protect_model_key() {
  "$E" attest policy collab.encompute --backend mock --image "$IMAGE" --tee mock \
    --development > model-policy.json
  head -c 32 /dev/urandom > model.key
  "$E" keys protect --asset base-model --policy model-policy.json --key-file model.key \
    --broker-id modelco --development --broker broker.json >/dev/null
}

release_model_key() {
  local port
  port="$(free_port)"
  "$E" keys serve --listen "127.0.0.1:$port" --mock-root "$MOCK_ROOT" \
    --broker broker.json > broker.log 2>&1 &
  BROKER=$!
  ready_port "$port"
  "$E" workload keys collab.encompute --backend mock --key "base-model@http://127.0.0.1:$port" \
    --identity workload.id --attester mock --mock-seed hw.seed --mock-image "$IMAGE" \
    --record attestation.json 2>/dev/null | grep -E '^(Key|Record)'
  kill "$BROKER"
  wait "$BROKER" 2>/dev/null || true
  "$E" trust add attestation.json --bundle trust.json >/dev/null
}

# One round: round SEQ [coordinator artifact] [coordinator plan]
# [parties...]. Parties always use the approved artifact and plan.
round() {
  local seq="$1" art="${2:-collab.encompute}" cplan="${3:-plan.json}"
  shift 3 2>/dev/null || shift $#
  local parties=("${@:-a b c}")
  [ $# -eq 0 ] && parties=(a b c)
  local port planarg=()
  port="$(free_port)"
  [ "$cplan" != none ] && planarg=(--plan "$cplan")
  "$E" aggregate serve "$art" --parties parties.json ${planarg[@]+"${planarg[@]}"} \
    --coordinator-policy "${COORD_POLICY:-coord-policy.json}" --key coord.key \
    --listen "127.0.0.1:$port" --stage-timeout 8 --sequence "$seq" --attester mock --mock-seed hw.seed \
    --mock-image "$IMAGE" --ledger ledgers --out "update-$seq.json" \
    --receipt "receipt-$seq.json" --trust-bundle trust.json > "coordinator-$seq.log" 2>&1 &
  local coord=$! joins=() x i
  # The coordinator may refuse to start at all (that is a refusal too).
  for i in $(seq 150); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
    kill -0 "$coord" 2>/dev/null || { wait "$coord"; return 1; }
    sleep 0.2
  done
  for x in "${parties[@]}"; do
    "$E" aggregate join collab.encompute --parties parties.json --plan plan.json \
      --coordinator-policy coord-policy.json --mock-root "$MOCK_ROOT" \
      --coordinator "http://127.0.0.1:$port" --party "hospital-$x" --key "$x.key" \
      --values "$x.json" --state "$x.state" --timeout 10 > "join-$x-$seq.log" 2>&1 &
    joins+=($!)
  done
  local ok=0
  wait "$coord" || ok=1
  for x in "${joins[@]}"; do wait "$x" || ok=1; done
  return $ok
}

trust_report() {
  "$E" trust report --bundle trust.json --parties parties.json --coordinator-key "$COORD_KEY" \
    --mock-root "$MOCK_ROOT" --execution-policy model-policy.json \
    --require "Private aggregation" --require "Privacy budget" --require Plan --require Workload
}
