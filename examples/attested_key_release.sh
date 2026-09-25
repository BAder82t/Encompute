#!/usr/bin/env bash
# Attested key release, locally, with the development-only mock TEE
# (ADR-011). Hospital and ModelCo each run a key broker; the approved
# workload receives both keys and serves with attested receipts; a modified
# workload receives none. For real hardware see deploy/confidential-space.
#
#   cargo build --bin encompute --bin encompute-evaluator
#   examples/attested_key_release.sh
set -eu
BIN="${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}"
E="$BIN/encompute"
W="$(mktemp -d)"
cd "$W"
# Wait until an HTTP server answers (up to 20 s).
ready() { for _ in $(seq 100); do curl -s -o /dev/null "$1" && return 0; sleep 0.2; done; echo "$1 did not start" >&2; exit 1; }
trap 'kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$W"' EXIT

cat > step.eir <<'EIR'
encompute 0.1
program step precision 0.01 purpose "disease-training"
party "hospital-a" "Hospital A"
party "modelco" "ModelCo"
party "coordinator" "Coordinator"
asset "patients" dataset owners ["hospital-a"] readers ["hospital-a"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator"]]
asset "weights" model owners ["modelco"] readers ["modelco"] purposes ["disease-training"] release never derive [gradient aggregate_only to ["coordinator"]]
%0 = input "x" [-1.0, 1.0] asset "patients" : secret vector<4>
%1 = input "w" [-1.0, 1.0] asset "weights" : secret vector<4>
%2 = mul %0, %1 : secret vector<4>
derive %2 gradient aggregate_only
output "gradient" = %2
EIR
"$E" compile step.eir -o step.encompute > /dev/null
ROOT=$("$E" attest mock-root hw.seed 2>/dev/null)
IMAGE="sha256:$(printf approved | { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-64)"

echo "== Owners approve this artifact, on this image, in the (mock) TEE"
"$E" attest policy step.encompute --backend mock --image "$IMAGE" --tee mock --development > policy.json
"$E" keys protect --asset patients --policy policy.json --broker-id hospital --development --broker hospital.json
"$E" keys protect --asset weights --policy policy.json --broker-id modelco --development --broker modelco.json
"$E" keys serve --broker hospital.json --listen 127.0.0.1:18761 --mock-root "$ROOT" 2> /dev/null &
"$E" keys serve --broker modelco.json --listen 127.0.0.1:18762 --mock-root "$ROOT" 2> /dev/null &
# Brokers answer only POST; any HTTP reply means they are up.
ready http://127.0.0.1:18761/
ready http://127.0.0.1:18762/
KEYS="--key patients@http://127.0.0.1:18761 --key weights@http://127.0.0.1:18762"

echo; echo "== A modified workload asks for the keys"
# shellcheck disable=SC2086
if "$E" workload keys step.encompute --backend mock $KEYS --identity evil.id \
     --attester mock --mock-seed hw.seed --mock-image sha256:modified --record evil.json; then
  echo "UNEXPECTED: keys released"; exit 1
fi
echo "NO KEYS RELEASED"

echo; echo "== The approved workload attests and receives both keys"
# shellcheck disable=SC2086
"$E" workload keys step.encompute --backend mock $KEYS --identity eval.id \
  --attester mock --mock-seed hw.seed --mock-image "$IMAGE" --record attestation.json
"$BIN/encompute-evaluator" serve step.encompute --backend mock --listen 127.0.0.1:18763 \
  --identity eval.id --attestation attestation.json 2> /dev/null &
ready http://127.0.0.1:18763/v1/info

echo; echo "== A client runs it and checks the attested receipt"
"$E" keys generate step.encompute -o client.keys --mode mock > /dev/null
"$E" run step.encompute --remote http://127.0.0.1:18763 --keys client.keys \
  --input x=0.1,0.2,0.3,0.4 --input w=1,1,1,1 --save-receipt receipt.json \
  --save-envelopes env > /dev/null 2>&1
curl -s http://127.0.0.1:18763/v1/attestation > record.json
PK=$(curl -s http://127.0.0.1:18763/v1/info | sed 's/.*"public_key":"\([0-9a-f]*\)".*/\1/')
"$E" verify receipt.json --model step.encompute --request env/request.bin \
  --response env/response.bin --trust-evaluator "$PK" --attestation record.json \
  --attestation-policy policy.json --mock-root "$ROOT" | sed -n '/Workload attestation/,$p'
