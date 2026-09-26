#!/usr/bin/env bash
# 07: attested key release with the development-only mock TEE. No cloud.
source "$(dirname "$0")/../lib.sh"
need_cli
need_evaluator
need_python
cd "$W"

cp "$HERE/step.eir" .
"$E" compile step.eir -o step.encompute > /dev/null
ROOT=$("$E" attest mock-root hw.seed 2>/dev/null)
IMAGE="sha256:$(printf approved | { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-64)"

step "ModelCo approves this artifact, on this image, in the (mock) TEE"
"$E" attest policy step.encompute --backend mock --image "$IMAGE" --tee mock --development > policy.json
"$E" keys protect --asset weights --policy policy.json --broker-id modelco --development --broker modelco.json

# Challenge the broker, then answer it from a (mock) workload.
#   evidence OUT [ARTIFACT] [BACKEND] [IMAGE]
evidence() {
  "$E" keys challenge --broker modelco.json > challenge.json
  "$E" workload attest "${2:-step.encompute}" --backend "${3:-mock}" --challenge challenge.json \
    --identity eval.id --attester mock --mock-seed hw.seed --mock-image "${4:-$IMAGE}" \
    --out "$1" 2>/dev/null > /dev/null
}
release() {
  "$E" keys release --asset weights --attestation "$1" --mock-root "$ROOT" \
    --broker modelco.json --out grant.json
}

step "Challenge, attestation, verification, sealed key grant"
evidence ev.json
"$E" attest verify ev.json --policy policy.json --mock-root "$ROOT" 2>/dev/null |
  grep -E 'Execution|Policy  |Debug|DEVELOPMENT EVIDENCE|ATTESTATION'
release ev.json
"$PYTHON" - <<'PY'
import json
g = json.load(open("grant.json"))
print("SEALED KEY GRANT  asset %(asset_id)s, key version %(key_version)s, one attested session" % g["header"])
print("Grant fields      %s (no plaintext key)" % ", ".join(k for k in g if k != "header"))
PY

step "Try breaking it: every request below must be refused"
attack "replay the same evidence (its challenge nonce is used up)" release ev.json
evidence ev-spec.json step.encompute openfhe
attack "same artifact, another ExecutionSpecID (openfhe backend)" release ev-spec.json
sed 's/to \["coordinator"\]/to ["coordinator", "modelco"]/' step.eir > relaxed.eir
"$E" compile relaxed.eir -o relaxed.encompute > /dev/null
evidence ev-policy.json relaxed.encompute
attack "another artifact with a weaker policy (other PolicyID)" release ev-policy.json
evidence ev-image.json step.encompute mock sha256:modified
attack "a modified workload image" release ev-image.json
evidence ev-session.json
"$PYTHON" - <<'PY'
import json
e = json.load(open("ev-session.json"))
e["binding"]["session_public_key"] = json.load(open("ev.json"))["binding"]["session_public_key"]
json.dump(e, open("ev-session.json", "w"))
PY
attack "the host swaps in another session's key" release ev-session.json
echo "(Debug workloads, stale evidence and opening a grant in another session"
echo " cannot be staged from the CLI: see README, Try breaking it.)"

step "Over HTTP: two owners' brokers, one attested workload"
"$E" keys protect --asset patients --policy policy.json --broker-id hospital --development --broker hospital.json > /dev/null
P1=$(free_port); P2=$(free_port); P3=$(free_port)
"$E" keys serve --broker hospital.json --listen "127.0.0.1:$P1" --mock-root "$ROOT" 2> /dev/null &
"$E" keys serve --broker modelco.json --listen "127.0.0.1:$P2" --mock-root "$ROOT" 2> /dev/null &
ready "http://127.0.0.1:$P1/"
ready "http://127.0.0.1:$P2/"
KEYS=(--key "patients@http://127.0.0.1:$P1" --key "weights@http://127.0.0.1:$P2")
attack "a modified workload asks both brokers" \
  "$E" workload keys step.encompute --backend mock "${KEYS[@]}" --identity evil.id \
  --attester mock --mock-seed hw.seed --mock-image sha256:modified --record evil.json
"$E" workload keys step.encompute --backend mock "${KEYS[@]}" --identity eval.id \
  --attester mock --mock-seed hw.seed --mock-image "$IMAGE" --record attestation.json 2>/dev/null
"$EVAL" serve step.encompute --backend mock --listen "127.0.0.1:$P3" \
  --identity eval.id --attestation attestation.json 2> /dev/null &
ready "http://127.0.0.1:$P3/v1/info"

step "A client runs it and checks the attested receipt"
"$E" keys generate step.encompute -o client.keys --mode mock > /dev/null
"$E" run step.encompute --remote "http://127.0.0.1:$P3" --keys client.keys \
  --input x=0.1,0.2,0.3,0.4 --input w=1,1,1,1 --save-receipt receipt.json \
  --save-envelopes env > /dev/null 2>&1
curl -s "http://127.0.0.1:$P3/v1/attestation" > record.json
PK=$(curl -s "http://127.0.0.1:$P3/v1/info" | sed 's/.*"public_key":"\([0-9a-f]*\)".*/\1/')
"$E" verify receipt.json --model step.encompute --request env/request.bin \
  --response env/response.bin --trust-evaluator "$PK" --attestation record.json \
  --attestation-policy policy.json --mock-root "$ROOT" | sed -n '/Workload attestation/,$p'

PIDS=$(jobs -p); disown -a; kill $PIDS 2>/dev/null || true
