#!/usr/bin/env bash
# Soak test: a mixed workload against a locally started stack, sampled every
# minute, failing on resource leaks, stuck jobs, deadlock or errors.
#
#   scripts/release/soak.sh              # 10-minute smoke
#   scripts/release/soak.sh 8h           # release soak (also 24h, 90m, 600s)
#
# The stack (as scripts/enterprise-e2e.sh starts it, production mode): the
# control plane on a FRESH PostgreSQL database (created here, dropped at the
# end unless SOAK_KEEP_DB=1) with OpenBao Transit for the organization's
# root key, and an evaluator with worker processes (OpenFHE when the
# binaries are built with it; else the mock backend, and FHE jobs are skipped).
#
# Workload, in a loop: exact jobs, CKKS jobs, secure aggregation rounds,
# differential-privacy releases (secure aggregation with DP on a privacy
# ledger, and privacy spending through the API), API requests, and key
# rotations (asset key rotation in the key broker, and root key rotation in
# OpenBao recorded in the audit trail). Training jobs are skipped: they need
# PyTorch (the confidential fine-tuning suite covers them).
#
# Every SAMPLE_SECS (60): RSS and open file descriptors (lsof) of every
# process, jobs by state and jobs stuck longer than STUCK_MINUTES, the
# database size (pg_database_size), evaluator worker restarts, operations
# and errors -> samples.csv. Every operation -> ops.csv. A summary ->
# summary.txt. Exits 1 on:
#   - monotonic memory growth of a process beyond MEM_GROWTH_MB (256) and
#     MEM_GROWTH_PCT (50) percent of its post-warm-up baseline;
#   - monotonic file-descriptor growth beyond FD_GROWTH (32);
#   - a job not finished STUCK_MINUTES (5) after its last change;
#   - no completed operation for DEADLOCK_MINUTES (5);
#   - any failed operation, service exit or worker restart.
#
# Needs: release binaries (BIN, default target/release: encompute,
# encompute-evaluator, encompute-control), python3 with `cryptography`,
# curl, lsof, and the services:
#   SOAK_DATABASE_URL  (default $ENCOMPUTE_TEST_DATABASE_URL) an admin URL
#                      allowed to create roles and databases; psql, or
#                      `docker exec $SOAK_PG_CONTAINER psql` (default enc-pg)
#   BAO_ADDR, BAO_TOKEN (default $ENCOMPUTE_TEST_BAO_ADDR, dev-root)
# Output: SOAK_OUT (default target/soak/<UTC time>).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DURATION_ARG="${1:-10m}"
duration_secs() {
  case "$1" in
    *h) echo $(( ${1%h} * 3600 )) ;;
    *m) echo $(( ${1%m} * 60 )) ;;
    *s) echo "${1%s}" ;;
    *[!0-9]*|'') echo "soak: bad duration $1 (use 10m, 8h, 24h or seconds)" >&2; exit 2 ;;
    *) echo "$1" ;;
  esac
}
DURATION="$(duration_secs "$DURATION_ARG")" || exit 2
SAMPLE_SECS="${SAMPLE_SECS:-60}"
STUCK_MINUTES="${STUCK_MINUTES:-5}"
DEADLOCK_MINUTES="${DEADLOCK_MINUTES:-5}"
OP_TIMEOUT="${OP_TIMEOUT:-600}"
MEM_GROWTH_MB="${MEM_GROWTH_MB:-256}"
MEM_GROWTH_PCT="${MEM_GROWTH_PCT:-50}"
FD_GROWTH="${FD_GROWTH:-32}"

BIN="${BIN:-$ROOT/target/release}"
E="$BIN/encompute"; EVAL="$BIN/encompute-evaluator"; CTL="$BIN/encompute-control"
PYTHON="${TOOL_PYTHON:-python3}"
ADMIN_URL="${SOAK_DATABASE_URL:-${ENCOMPUTE_TEST_DATABASE_URL:-}}"
: "${ADMIN_URL:?set SOAK_DATABASE_URL or ENCOMPUTE_TEST_DATABASE_URL (PostgreSQL admin URL)}"
BAO_ADDR="${BAO_ADDR:-${ENCOMPUTE_TEST_BAO_ADDR:-}}"
: "${BAO_ADDR:?set BAO_ADDR or ENCOMPUTE_TEST_BAO_ADDR (OpenBao)}"
BAO_TOKEN="${BAO_TOKEN:-${ENCOMPUTE_TEST_BAO_TOKEN:-dev-root}}"
PG_CONTAINER="${SOAK_PG_CONTAINER:-enc-pg}"
for b in "$E" "$EVAL" "$CTL"; do
  [ -x "$b" ] || { echo "soak: $b is not built (cargo build --release --bins)" >&2; exit 2; }
done
for t in curl lsof; do
  command -v "$t" >/dev/null || { echo "soak: needs $t" >&2; exit 2; }
done

OUT="${SOAK_OUT:-$ROOT/target/soak/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT/logs"
W="$(mktemp -d)"
mkdir -p "$W/pids" "$W/secrets" "$W/anchor" "$W/idp"
chmod 700 "$W/secrets"
LOGS="$OUT/logs"
STOP="$W/stop"
PIDS=()
TAG="soak_$("$PYTHON" -c 'import secrets; print(secrets.token_hex(4))')"

say() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/soak.log"; }
die() {
  say "SOAK SETUP FAILED: $*"
  for l in "$LOGS"/*.log; do [ -f "$l" ] && { echo "--- $(basename "$l")"; tail -n 15 "$l"; }; done
  exit 2
}

# --- PostgreSQL ---------------------------------------------------------------------
ADMIN_BASE="${ADMIN_URL%/*}"
HOSTPART="${ADMIN_BASE#*@}"
ADMIN_USER="${ADMIN_BASE#*://}"; ADMIN_USER="${ADMIN_USER%%:*}"
ADMIN_DB="${ADMIN_URL##*/}"; ADMIN_DB="${ADMIN_DB%%\?*}"
psql_admin() {  # psql_admin DB SQL: one value per line
  if command -v psql >/dev/null 2>&1; then
    psql "${ADMIN_BASE}/$1" -qtAX -c "$2"
  else
    docker exec -i "$PG_CONTAINER" psql -U "$ADMIN_USER" -d "$1" -qtAX -c "$2"
  fi
}

cleanup() {
  touch "$STOP"
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  for f in "$W"/pids/*; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ "${SOAK_KEEP_DB:-0}" != 1 ] && [ -n "${DB_CREATED:-}" ]; then
    psql_admin "$ADMIN_DB" "DROP DATABASE IF EXISTS $TAG WITH (FORCE)" >/dev/null 2>&1 || true
    psql_admin "$ADMIN_DB" "DROP ROLE IF EXISTS $TAG" >/dev/null 2>&1 || true
  fi
  rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

free_port() { "$PYTHON" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_http() { for _ in $(seq 300); do curl -fs "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; die "$1 did not start"; }
rand() { "$PYTHON" -c 'import secrets; print(secrets.token_hex(16))'; }

say "soak $TAG: $DURATION s, sampling every $SAMPLE_SECS s, output $OUT"
DBPASS="$(rand)"
psql_admin "$ADMIN_DB" "CREATE ROLE $TAG LOGIN PASSWORD '$DBPASS'" >/dev/null || die "cannot create the role"
psql_admin "$ADMIN_DB" "CREATE DATABASE $TAG OWNER $TAG" >/dev/null || die "cannot create the database"
DB_CREATED=1
DB_URL="postgres://$TAG:$DBPASS@$HOSTPART/$TAG"
say "database $TAG created (fresh)"

# --- OpenBao, identities, secrets --------------------------------------------------------
bao() { curl -fs -H "X-Vault-Token: $BAO_TOKEN" "$@"; }
bao -X POST -d '{"type":"transit"}' "$BAO_ADDR/v1/sys/mounts/transit" >/dev/null 2>&1 || true
bao -X POST "$BAO_ADDR/v1/transit/keys/$TAG-modelco" >/dev/null || die "OpenBao transit key"
"$PYTHON" "$ROOT/scripts/test-idp.py" keygen "$W/idp" >/dev/null || die "test IdP (python3 needs cryptography)"
ISS="https://idp.$TAG.test.invalid"
printf '%s' "$DB_URL" > "$W/secrets/db-url"
for k in control evaluator; do "$PYTHON" -c 'import secrets; print(secrets.token_hex(32))' > "$W/secrets/$k.key"; done
printf '%s' "$BAO_TOKEN" > "$W/secrets/bao-token"
rand > "$W/secrets/metrics-token"
chmod 600 "$W/secrets/"*

# Tokens are cached per subject and refreshed every 30 minutes (1 h TTL).
tok() {
  local f="$W/tok-$1"
  if [ ! -f "$f" ] || [ -n "$(find "$f" -mmin +30 2>/dev/null)" ]; then
    "$PYTHON" "$ROOT/scripts/test-idp.py" token "$W/idp" "$1" --iss "$ISS" > "$f.tmp" && mv "$f.tmp" "$f"
  fi
  cat "$f"
}

CTL_PORT="$(free_port)"; EVAL_PORT="$(free_port)"
CTL_URL="http://127.0.0.1:$CTL_PORT"
control_env() {
  exec env ENCOMPUTE_ENV=production \
    ENCOMPUTE_LISTEN="127.0.0.1:$CTL_PORT" \
    ENCOMPUTE_DATABASE_URL_FILE="$W/secrets/db-url" \
    ENCOMPUTE_SIGNING_KEY_FILE="$W/secrets/control.key" \
    ENCOMPUTE_METRICS_TOKEN_FILE="$W/secrets/metrics-token" \
    ENCOMPUTE_OIDC_ISSUER="$ISS" ENCOMPUTE_OIDC_AUDIENCE=encompute \
    ENCOMPUTE_OIDC_JWKS_FILE="$W/idp/jwks.json" \
    ENCOMPUTE_ANCHOR_DIR="$W/anchor" \
    "$@"
}
start_control() {
  ( control_env "$CTL" serve ) >>"$LOGS/control.log" 2>&1 &
  echo $! > "$W/pids/control"
  wait_http "$CTL_URL/ready"
}
api() {  # api SUBJECT METHOD PATH [JSON]
  local t; t="$(tok "$1")"
  if [ -n "${4:-}" ]; then
    curl -fsS --max-time 60 -X "$2" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' -d "$4" "$CTL_URL$3"
  else
    curl -fsS --max-time 60 -X "$2" -H "Authorization: Bearer $t" "$CTL_URL$3"
  fi
}
jget() { "$PYTHON" -c "import json,sys; v=json.load(sys.stdin); print($1)"; }
# Workload state survives the subshells operations run in.
mkdir -p "$W/state"
st_get() { cat "$W/state/$1"; }
st_set() { printf '%s' "$2" > "$W/state/$1"; }

say "control plane: migrate, bootstrap, start"
( control_env "$CTL" migrate ) >>"$LOGS/control.log" 2>&1 || die "migrate"
( control_env "$CTL" bootstrap --issuer "$ISS" --subject platform-admin ) >>"$LOGS/control.log" 2>&1 || die "bootstrap"
start_control
CONTROL_KEY="$(curl -fs "$CTL_URL/v1/info" | jget 'v["public_key"]')"

say "tenants, users, project, assets"
api platform-admin POST /v1/organizations "{\"id\":\"hospital-a\",\"display_name\":\"Hospital A\",\"admin\":{\"issuer\":\"$ISS\",\"subject\":\"a-admin\"}}" >/dev/null || die "organization"
api platform-admin POST /v1/organizations "{\"id\":\"modelco\",\"display_name\":\"ModelCo\",\"admin\":{\"issuer\":\"$ISS\",\"subject\":\"b-admin\"}}" >/dev/null || die "organization"
api a-admin POST /v1/organizations/hospital-a/users "{\"issuer\":\"$ISS\",\"subject\":\"a-owner\",\"roles\":[\"data_owner\",\"auditor\"]}" >/dev/null || die "user"
api b-admin POST /v1/organizations/modelco/users "{\"issuer\":\"$ISS\",\"subject\":\"b-dev\",\"roles\":[\"ml_developer\",\"auditor\"]}" >/dev/null || die "user"
api b-admin POST /v1/organizations/modelco/users "{\"issuer\":\"$ISS\",\"subject\":\"b-sec\",\"roles\":[\"security_admin\"]}" >/dev/null || die "user"
PROJECT="$(api b-dev POST /v1/projects '{"organization":"modelco","name":"soak"}' | jget 'v["id"]')" || die "project"
api b-admin POST "/v1/projects/$PROJECT/members" '{"organization":"hospital-a"}' >/dev/null || die "member"
# Membership takes the invited organization's consent: its admin accepts.
api a-admin POST "/v1/projects/$PROJECT/members" '{"organization":"hospital-a"}' >/dev/null || die "accept"
new_dataset() {  # a dataset with a privacy budget; prints its ID
  api a-owner POST /v1/assets "{\"organization\":\"hospital-a\",\"kind\":\"dataset\",\"name\":\"soak-$1\",\"digest\":\"$(printf '%064x' "$1")\",\"privacy_budget\":{\"unit\":\"patient\",\"epsilon\":\"50.0\",\"delta\":\"1e-6\"}}" | jget 'v["id"]'
}
DATASET="$(new_dataset 1)" || die "dataset"
st_set dataset "$DATASET"; st_set datasets 1; st_set last_job ""

say "programs and keys"
cd "$W"
cp "$ROOT/examples/04_execution_receipts/adult.eir" adult.eir
cat > score.eir <<'EIR'
encompute 0.1
program score precision 0.001
%0 = input "x" [-1.0, 1.0] : secret vector<4>
%1 = mul %0, %0 : secret vector<4>
output "y" = %1
EIR
"$E" compile adult.eir -o adult.encompute >/dev/null || die "compile adult.eir"
"$E" compile score.eir -o score.encompute >/dev/null || die "compile score.eir"
"$E" keys generate adult.encompute -o exact.keys >/dev/null || die "exact keys"
"$E" keys generate score.encompute -o ckks.keys >/dev/null || die "CKKS keys"
# Secure aggregation (examples 08 and 09): three hospitals.
cp "$ROOT"/examples/08_secure_aggregation/hospital-{a,b,c}.json .
"$E" compile "$ROOT/examples/08_secure_aggregation/fedavg.eir" -o sa.encompute >/dev/null || die "compile fedavg (08)"
"$E" compile "$ROOT/examples/09_differential_privacy/fedavg.eir" -o dp.encompute >/dev/null || die "compile fedavg (09)"
for x in a b c; do "$E" aggregate identity --party "hospital-$x" --key "$x.key"; done > parties.jsonl
"$PYTHON" -c 'import json,sys; print(json.dumps([json.loads(l) for l in open(sys.argv[1])]))' parties.jsonl > parties.json
# The model key under modelco's root key in OpenBao (key rotations).
"$E" attest policy adult.encompute --image "sha256:$(printf 'a%.0s' $(seq 64))" --tee intel_tdx > policy.json || die "policy"
BROKER_ARGS=(--broker "$W/broker.json" --root-key "openbao:transit/$TAG-modelco" --organization modelco --wrapped-kek "$W/kek.wrapped.json")
BAO_ADDR="$BAO_ADDR" BAO_TOKEN_FILE="$W/secrets/bao-token" "$E" keys protect --asset model-7 --policy policy.json \
  --broker-id keybroker-modelco "${BROKER_ARGS[@]}" >/dev/null || die "keys protect"

BACKEND="mock"
EVAL_BACKEND=(--backend mock)
INFO="$("$E" info 2>/dev/null)"
if grep -q '^openfhe-exact *yes' <<< "$INFO" && grep -q '^openfhe *yes' <<< "$INFO"; then
  BACKEND="openfhe"; EVAL_BACKEND=()
else
  say "WARNING: binaries without OpenFHE: the planner finds no FHE plan, so exact and CKKS jobs are skipped"
fi
say "evaluator ($BACKEND, 2 worker processes)"
pubkey() { "$PYTHON" - "$1" <<'PY'
import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
seed = bytes.fromhex(open(sys.argv[1]).read().strip())
k = Ed25519PrivateKey.from_private_bytes(seed).public_key()
print(k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
PY
}
api platform-admin POST /v1/organizations/platform/service-accounts \
  "{\"id\":\"evaluator-1\",\"kind\":\"evaluator\",\"public_key\":\"$(pubkey "$W/secrets/evaluator.key")\",\"url\":\"http://127.0.0.1:$EVAL_PORT\"}" >/dev/null || die "service account"
# Clients pin the evaluator's receipt key out of band (here: read from the
# evaluator this script started) and refuse any other.
pin_evaluator() {
  ENCOMPUTE_TRUSTED_EVALUATORS="$(curl -fs "http://127.0.0.1:$EVAL_PORT/v1/info" | jget 'v["evaluator"]["public_key"]')" \
    || return 1
  export ENCOMPUTE_TRUSTED_EVALUATORS
}
start_evaluator() {
  mkdir -p "$W/evaluator"
  ( cd "$W/evaluator" && exec env ENCOMPUTE_CONTROL_URL="$CTL_URL" ENCOMPUTE_CONTROL_PUBLIC_KEY="$CONTROL_KEY" \
      ENCOMPUTE_SERVICE_ID=evaluator-1 ENCOMPUTE_SERVICE_KEY_FILE="$W/secrets/evaluator.key" \
      ENCOMPUTE_ADVERTISE_URL="http://127.0.0.1:$EVAL_PORT" ENCOMPUTE_CAPACITY=2 \
      "$EVAL" serve --listen "127.0.0.1:$EVAL_PORT" --identity "$W/evaluator/receipt.key" \
        --workers 2 ${EVAL_BACKEND[@]+"${EVAL_BACKEND[@]}"} ) >>"$LOGS/evaluator.log" 2>&1 &
  echo $! > "$W/pids/evaluator"
  for _ in $(seq 300); do grep -q "registered with the control plane" "$LOGS/evaluator.log" && { pin_evaluator; return; }; sleep 0.2; done
  die "the evaluator did not register"
}
start_evaluator
# Only the commands meant to talk to the control plane get its URL (an
# aggregation coordinator reports rounds when ENCOMPUTE_CONTROL_URL is set).

# --- operations ------------------------------------------------------------------
OPS_CSV="$OUT/ops.csv"
echo "time,iteration,op,status,seconds,detail" > "$OPS_CSV"
COUNTERS="$W/counters"   # ok errors expected_denials
OK=0; ERRORS=0; DENIED=0
echo "0 0 0" > "$COUNTERS"
ITER=0

# run_op NAME command...: runs with a timeout, records it; a non-zero exit
# is an error (the command prints why on its last line of output).
run_op() {
  local name="$1"; shift
  local t0 status detail log="$W/op.out"
  t0="$("$PYTHON" -c 'import time; print(time.time())')"
  ( "$@" ) > "$log" 2>&1 &
  local p=$! waited=0
  while kill -0 "$p" 2>/dev/null; do
    sleep 0.2; waited=$((waited + 1))
    if [ "$waited" -ge $((OP_TIMEOUT * 5)) ]; then
      pkill -P "$p" 2>/dev/null; kill "$p" 2>/dev/null
      echo "timed out after ${OP_TIMEOUT}s" >> "$log"
      break
    fi
  done
  wait "$p"; status=$?
  local secs; secs="$("$PYTHON" -c "import time; print(round(time.time() - $t0, 2))")"
  detail="$(tail -n 1 "$log" | tr ',\n' ';  ' | cut -c1-200)"
  if [ "$status" = 0 ]; then
    OK=$((OK + 1)); echo "$(date -u +%FT%TZ),$ITER,$name,ok,$secs,$detail" >> "$OPS_CSV"
  elif [ "$status" = 3 ]; then
    # An expected denial (an exhausted privacy budget): not an error.
    OK=$((OK + 1)); DENIED=$((DENIED + 1))
    echo "$(date -u +%FT%TZ),$ITER,$name,denied,$secs,$detail" >> "$OPS_CSV"
  else
    ERRORS=$((ERRORS + 1)); echo "$(date -u +%FT%TZ),$ITER,$name,ERROR,$secs,$detail" >> "$OPS_CSV"
    { echo "--- $(date -u +%FT%TZ) $name (iteration $ITER)"; cat "$log"; } >> "$LOGS/errors.log"
  fi
  echo "$OK $ERRORS $DENIED" > "$COUNTERS"
}

op_exact() {
  local age=$(( (ITER * 37) % 121 ))
  local out
  out="$(ENCOMPUTE_CONTROL_URL="$CTL_URL" ENCOMPUTE_TOKEN="$(tok b-dev)" "$E" jobs run "$W/adult.encompute" --project "$PROJECT" --purpose soak \
    --keys "$W/exact.keys" --idempotency-key "soak-exact-$ITER" --input "age=$age" 2>"$W/exact.err")" \
    || { cat "$W/exact.err"; return 1; }
  grep -q "Trust report            SATISFIED" "$W/exact.err" || { cat "$W/exact.err"; echo "exact: trust not satisfied"; return 1; }
  api b-dev GET "/v1/jobs?project=$PROJECT" | jget 'v[0]["id"]' > "$W/state/last_job" 2>/dev/null || true
  local want=false; [ "$age" -ge 18 ] && want=true
  echo "$out" | "$PYTHON" -c "import json,sys; v=json.load(sys.stdin); assert v['adult'] is $( [ $want = true ] && echo True || echo False ), v; print('adult', v['adult'], 'age $age')"
}
op_ckks() {
  local out
  out="$(ENCOMPUTE_CONTROL_URL="$CTL_URL" ENCOMPUTE_TOKEN="$(tok b-dev)" "$E" jobs run "$W/score.encompute" --project "$PROJECT" --purpose soak \
    --keys "$W/ckks.keys" --idempotency-key "soak-ckks-$ITER" --input x=0.5,-0.25,0.1,1.0 2>"$W/ckks.err")" \
    || { cat "$W/ckks.err"; return 1; }
  grep -q "Trust report            SATISFIED" "$W/ckks.err" || { cat "$W/ckks.err"; echo "CKKS: trust not satisfied"; return 1; }
  echo "$out" | "$PYTHON" -c 'import json,sys; y=json.load(sys.stdin)["y"]; e=max(abs(a-b) for a,b in zip(y,[0.25,0.0625,0.01,1.0])); assert e<1e-3, y; print(f"max error {e:.2e}")'
}
# A secure aggregation round (sa: plain; dp: with differential privacy on
# the ledger in LEDGER). Exit 3: the coordinator denied the release (budget).
st_set seq 0
aggregation_round() {
  local kind="$1" model="$W/$1.encompute" port url clog coord extra=() SEQ
  SEQ=$(( $(st_get seq) + 1 )); st_set seq "$SEQ"
  port="$(free_port)"; url="http://127.0.0.1:$port"; clog="$W/coordinator.log"
  [ "$kind" = dp ] && extra=(--ledger "$W/$(st_get ledger)")
  "$E" aggregate serve "$model" --parties "$W/parties.json" --key "$W/coordinator.key" \
    --listen "127.0.0.1:$port" --sequence "$SEQ" --stage-timeout 60 \
    --out "$W/aggregate.json" --receipt "$W/receipt.json" ${extra[@]+"${extra[@]}"} > "$clog" 2>&1 &
  coord=$!
  local up=0
  for _ in $(seq 300); do
    curl -s -o /dev/null "$url/v1/round" && { up=1; break; }
    kill -0 "$coord" 2>/dev/null || break
    sleep 0.1
  done
  if [ "$up" = 0 ]; then
    wait "$coord"
    if grep -q ENC2201 "$clog"; then grep ENC2201 "$clog" | tail -1; return 3; fi
    cat "$clog"; echo "the coordinator did not start"; return 1
  fi
  local pids="" x
  for x in a b c; do
    "$E" aggregate join "$model" --parties "$W/parties.json" --coordinator "$url" \
      --party "hospital-$x" --key "$W/$x.key" --values "$W/hospital-$x.json" --state "$W/$kind-$x.state" \
      > "$W/join-$x.log" 2>&1 &
    pids="$pids $!"
  done
  local failed=0
  for x in $pids; do wait "$x" || failed=1; done
  wait "$coord" || failed=1
  if [ "$failed" = 1 ] || ! grep -q "AGGREGATION COMPLETE" "$clog"; then
    cat "$clog" "$W"/join-*.log; echo "$kind round $SEQ failed"; return 1
  fi
  "$PYTHON" - "$W" "$kind" <<'PY'
import json, sys
w, kind = sys.argv[1], sys.argv[2]
vec = [json.load(open(f"{w}/hospital-{x}.json")) for x in "abc"]
agg = json.load(open(f"{w}/aggregate.json"))["values"]
clear = [sum(v[i] for v in vec) for i in range(16)]
err = max(abs(a - c) for a, c in zip(agg, clear))
if kind == "sa":
    assert err <= 3 * 0.5 / 65536 + 1e-12, err
print(f"{kind}: {len(agg)} values, |aggregate - clear| max {err:.2e}")
PY
}
st_set ledger ledger-1; st_set ledgers 1
op_secagg() { aggregation_round sa; }
op_dp_round() {
  aggregation_round dp
  local s=$? n
  if [ "$s" = 3 ]; then
    # The budget is spent (the correct outcome): a new budget epoch, a
    # new study. The parties' state remembers the old ledger (a coordinator
    # presenting a shorter one is refused as a rollback), so it starts over.
    n=$(( $(st_get ledgers) + 1 )); st_set ledgers "$n"; st_set ledger "ledger-$n"
    rm -f "$W"/dp-?.state
  fi
  return "$s"
}
op_dp_spend() {
  local body code ds n
  ds="$(st_get dataset)"
  body="$(printf '{"kind":"reserve","event_id":"soak-%s-%s","policy_id":null,"execution_spec_id":null,"round_id":null,"output":"update","mechanism":{"kind":"discrete_gaussian","clip_norm":"1.0","noise_multiplier":"1000.0"},"sensitivity":2,"sigma2":800,"vector_len":1,"rng":"csprng"}' "$ds" "$ITER")"
  code="$(curl -sS --max-time 60 -o "$W/spend.json" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $(tok a-owner)" -H 'Content-Type: application/json' -d "$body" \
    "$CTL_URL/v1/privacy/$ds/events")" || { echo "spend: no response"; return 1; }
  case "$code" in
    2??) api a-owner GET "/v1/privacy/$ds" | jget '"spent epsilon " + str(v["spent"]["epsilon"])' ;;
    409)
      # ENC2201: the budget is spent (the correct outcome); a new dataset.
      grep -q ENC2201 "$W/spend.json" || { cat "$W/spend.json"; echo; echo "spend: HTTP 409"; return 1; }
      n=$(( $(st_get datasets) + 1 )); st_set datasets "$n"
      st_set dataset "$(new_dataset "$n")" || return 1
      echo "ENC2201: budget spent; new dataset $(st_get dataset)"
      return 3 ;;
    *) cat "$W/spend.json"; echo; echo "spend: HTTP $code"; return 1 ;;
  esac
}
op_api() {
  local who path n=0
  for req in "b-dev /v1/whoami" "b-dev /v1/projects" "b-dev /v1/projects/$PROJECT" \
             "b-dev /v1/jobs?project=$PROJECT" "b-dev /v1/assets" \
             "a-owner /v1/privacy/$(st_get dataset)" "b-dev /v1/audit?limit=100" \
             "b-dev /v1/trust/$(st_get last_job)"; do
    who="${req%% *}"; path="${req#* }"
    [ "$path" = "/v1/trust/" ] && continue
    api "$who" GET "$path" >/dev/null || { echo "GET $path failed"; return 1; }
    n=$((n + 1))
  done
  curl -fs --max-time 30 -H "Authorization: Bearer $(cat "$W/secrets/metrics-token")" "$CTL_URL/metrics" >/dev/null \
    || { echo "GET /metrics failed"; return 1; }
  n=$((n + 1))
  for path in /ready /live /v1/info; do
    curl -fs --max-time 30 "$CTL_URL$path" >/dev/null || { echo "GET $path failed"; return 1; }
    n=$((n + 1))
  done
  echo "$n requests"
}
op_rotate_asset_key() {
  BAO_ADDR="$BAO_ADDR" BAO_TOKEN_FILE="$W/secrets/bao-token" "$E" keys rotate --asset model-7 "${BROKER_ARGS[@]}"
}
op_rotate_root_key() {
  BAO_ADDR="$BAO_ADDR" BAO_TOKEN_FILE="$W/secrets/bao-token" ENCOMPUTE_CONTROL_URL="$CTL_URL" ENCOMPUTE_TOKEN="$(tok b-sec)" \
    "$E" keys rotate-root --report "${BROKER_ARGS[@]}"
}

# --- sampling ----------------------------------------------------------------------
SAMPLES="$OUT/samples.csv"
echo "time,elapsed_s,process,pid,rss_kb,fds,jobs_active,jobs_stuck,jobs_succeeded,jobs_failed,db_bytes,worker_restarts,ops_ok,errors,denied" > "$SAMPLES"
sampler() {
  local start=$SECONDS known_workers="" restarts=0
  while [ ! -f "$STOP" ]; do
    local now el
    now="$(date -u +%FT%TZ)"; el=$((SECONDS - start))
    local jobs stuck succ fail dbb
    jobs="$(psql_admin "$TAG" "SELECT count(*) FROM jobs WHERE state NOT IN ('succeeded','failed','cancelled')" 2>/dev/null || echo -1)"
    stuck="$(psql_admin "$TAG" "SELECT count(*) FROM jobs WHERE state NOT IN ('succeeded','failed','cancelled') AND updated_at < now() - interval '$STUCK_MINUTES minutes'" 2>/dev/null || echo -1)"
    succ="$(psql_admin "$TAG" "SELECT count(*) FROM jobs WHERE state = 'succeeded'" 2>/dev/null || echo -1)"
    fail="$(psql_admin "$TAG" "SELECT count(*) FROM jobs WHERE state = 'failed'" 2>/dev/null || echo -1)"
    dbb="$(psql_admin "$ADMIN_DB" "SELECT pg_database_size('$TAG')" 2>/dev/null || echo -1)"
    # Evaluator worker processes: a new PID is a restart.
    local epid workers w
    epid="$(cat "$W/pids/evaluator" 2>/dev/null)"
    workers="$(pgrep -P "$epid" 2>/dev/null | sort | tr '\n' ' ')"
    for w in $workers; do
      case " $known_workers " in *" $w "*) ;; *)
        [ -n "$known_workers" ] && restarts=$((restarts + 1))
        ;;
      esac
    done
    [ -n "$workers" ] && known_workers="$known_workers $workers"
    local counters; counters="$(tr ' ' ',' < "$COUNTERS")"
    local name pid
    for entry in "control:$(cat "$W/pids/control" 2>/dev/null)" "evaluator:$epid" \
                 $(i=0; for w in $workers; do i=$((i + 1)); echo "worker-$i:$w"; done); do
      name="${entry%%:*}"; pid="${entry#*:}"
      [ -n "$pid" ] || continue
      local rss fds
      rss="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')"; rss="${rss:--1}"
      fds="$(lsof -p "$pid" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
      [ "$rss" = -1 ] && fds=-1
      echo "$now,$el,$name,$pid,$rss,$fds,$jobs,$stuck,$succ,$fail,$dbb,$restarts,$counters" >> "$SAMPLES"
    done
    local s=0
    while [ "$s" -lt "$SAMPLE_SECS" ] && [ ! -f "$STOP" ]; do sleep 1; s=$((s + 1)); done
  done
}
sampler &
SAMPLER=$!
PIDS+=("$SAMPLER")

# --- the loop ------------------------------------------------------------------------
say "workload: exact, CKKS, secure aggregation, DP releases, API requests, key rotations (training: skipped, needs PyTorch)"
START=$SECONDS
LAST_OK=0; LAST_PROGRESS=$SECONDS
DEADLOCK=0
alive() {  # alive NAME: restart a service that exited (counted as an error)
  local p; p="$(cat "$W/pids/$1")"
  if ! kill -0 "$p" 2>/dev/null; then
    ERRORS=$((ERRORS + 1))
    echo "$(date -u +%FT%TZ),$ITER,$1-alive,ERROR,0,the $1 exited" >> "$OPS_CSV"
    say "the $1 exited; restarting"
    "start_$1"
  fi
}
while [ $((SECONDS - START)) -lt "$DURATION" ]; do
  ITER=$((ITER + 1))
  alive control; alive evaluator
  run_op api op_api
  if [ "$BACKEND" = openfhe ]; then
    run_op exact_job op_exact
    run_op ckks_job op_ckks
  fi
  run_op secagg_round op_secagg
  run_op dp_release op_dp_round
  run_op dp_spend op_dp_spend
  if [ $((ITER % 3)) = 0 ]; then
    run_op rotate_asset_key op_rotate_asset_key
    run_op rotate_root_key op_rotate_root_key
  fi
  if [ "$OK" != "$LAST_OK" ]; then LAST_OK=$OK; LAST_PROGRESS=$SECONDS; fi
  if [ $((SECONDS - LAST_PROGRESS)) -ge $((DEADLOCK_MINUTES * 60)) ]; then DEADLOCK=1; break; fi
  if [ $((ITER % 5)) = 0 ]; then
    say "iteration $ITER: $OK operations ok, $ERRORS errors, $DENIED expected denials ($(( (SECONDS - START) / 60 )) min)"
  fi
done
ELAPSED=$((SECONDS - START))
# A last sample, then stop.
sleep 2
touch "$STOP"; wait "$SAMPLER" 2>/dev/null

# --- analysis ------------------------------------------------------------------------
"$PYTHON" - "$OUT" "$ELAPSED" "$ITER" "$DEADLOCK" "$BACKEND" "$MEM_GROWTH_MB" "$MEM_GROWTH_PCT" "$FD_GROWTH" "$DEADLOCK_MINUTES" "$STUCK_MINUTES" <<'PY'
import csv, sys
from collections import defaultdict
out, elapsed, iters, deadlock, backend = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4] == "1", sys.argv[5]
mem_mb, mem_pct, fd_growth, deadlock_min, stuck_min = (float(x) for x in sys.argv[6:11])
rows = list(csv.DictReader(open(f"{out}/samples.csv")))
ops = list(csv.DictReader(open(f"{out}/ops.csv")))
lines, failures = [], []
def p(s=""):
    lines.append(s)

by_op = defaultdict(lambda: {"ok": 0, "denied": 0, "ERROR": 0, "secs": []})
for o in ops:
    d = by_op[o["op"]]
    d[o["status"]] += 1
    d["secs"].append(float(o["seconds"]))
p(f"SOAK SUMMARY: {elapsed} s ({elapsed / 3600:.2f} h), {iters} iterations, backend {backend}")
p(f"{'operation':<18}{'ok':>6}{'denied':>8}{'errors':>8}{'mean s':>9}{'max s':>9}")
for name, d in by_op.items():
    s = d["secs"]
    p(f"{name:<18}{d['ok']:>6}{d['denied']:>8}{d['ERROR']:>8}{sum(s) / len(s):>9.2f}{max(s):>9.2f}")
p(f"{'training_job':<18}  skipped: needs PyTorch (covered by the confidential fine-tuning suite)")
errors = sum(d["ERROR"] for d in by_op.values())
if errors:
    failures.append(f"{errors} failed operations (logs/errors.log)")

procs = defaultdict(list)
for r in rows:
    if int(r["rss_kb"]) >= 0:
        procs[r["process"]].append((int(r["elapsed_s"]), int(r["rss_kb"]), int(r["fds"])))

def trend(series):
    """(growth over the post-warm-up window by least squares, share of
    non-decreasing steps, baseline)."""
    n = len(series)
    w = series[max(1, n // 5):] if n >= 4 else series
    if len(w) < 3:
        return 0.0, 0.0, (w[0][1] if w else 0)
    xs = [t for t, _ in w]; ys = [v for _, v in w]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    den = sum((x - mx) ** 2 for x in xs) or 1
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
    ups = sum(1 for a, b in zip(ys, ys[1:]) if b >= a) / (len(ys) - 1)
    return slope * (xs[-1] - xs[0]), ups, ys[0]

p()
p(f"{'process':<12}{'samples':>8}{'RSS first MiB':>15}{'RSS last MiB':>14}{'RSS max MiB':>13}{'trend MiB':>11}{'fds first':>11}{'fds last':>10}{'fd trend':>10}")
for name, s in sorted(procs.items()):
    rss = [(t, v) for t, v, _ in s]
    fds = [(t, f) for t, _, f in s]
    g, ups, base = trend(rss)
    fg, fups, _ = trend(fds)
    p(f"{name:<12}{len(s):>8}{rss[0][1] / 1024:>15.1f}{rss[-1][1] / 1024:>14.1f}{max(v for _, v in rss) / 1024:>13.1f}{g / 1024:>11.1f}{fds[0][1]:>11}{fds[-1][1]:>10}{fg:>10.1f}")
    if g / 1024 > mem_mb and g > base * mem_pct / 100 and ups >= 0.75:
        failures.append(f"{name}: monotonic memory growth {g / 1024:.0f} MiB ({ups:.0%} of steps up)")
    if fg > fd_growth and fups >= 0.75:
        failures.append(f"{name}: file descriptors grew by {fg:.0f} ({fups:.0%} of steps up)")

ctl = [r for r in rows if r["process"] == "control"]
if ctl:
    first, last = ctl[0], ctl[-1]
    stuck = max(int(r["jobs_stuck"]) for r in ctl)
    db0, db1 = int(first["db_bytes"]), int(last["db_bytes"])
    dt = max(1, int(last["elapsed_s"]) - int(first["elapsed_s"]))
    restarts = int(last["worker_restarts"])
    p()
    p(f"jobs: {last['jobs_succeeded']} succeeded, {last['jobs_failed']} failed, {last['jobs_active']} active at the end; max stuck (> {stuck_min:.0f} min) {stuck}")
    p(f"database: {db0 / 2**20:.1f} MiB -> {db1 / 2**20:.1f} MiB ({(db1 - db0) / 2**20 / dt * 3600:.1f} MiB/hour)")
    p(f"evaluator worker restarts: {restarts}")
    if stuck > 0:
        failures.append(f"{stuck} jobs stuck longer than {stuck_min:.0f} minutes")
    if int(last["jobs_failed"]) > 0:
        failures.append(f"{last['jobs_failed']} jobs failed")
    if restarts > 0:
        failures.append(f"{restarts} evaluator worker restarts")
else:
    failures.append("no samples")
if deadlock:
    failures.append(f"deadlock: no operation completed for {deadlock_min:.0f} minutes")
p()
if failures:
    p("SOAK FAILED")
    for f in failures:
        p(f"  - {f}")
else:
    p("SOAK PASSED")
open(f"{out}/summary.txt", "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
sys.exit(1 if failures else 0)
PY
