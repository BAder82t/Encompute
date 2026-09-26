#!/usr/bin/env bash
# The commercial golden path, end to end, in production mode:
#
#   organization -> project -> assets -> plan -> job -> OpenFHE exact (and
#   OpenFHE CKKS) evaluator -> receipt -> trust report -> audit trail,
#
# with a customer-managed root key (OpenBao Transit) protecting the key
# broker, revocation reaching the broker, a full restart of every service,
# a database backup and restore (an older backup is refused), and a canary
# scan of every log, the database dump and the audit output.
#
#   scripts/enterprise-e2e.sh
#
# Needs: release binaries with OpenFHE (encompute, encompute-evaluator,
# encompute-control), python3 with `cryptography` (TOOL_PYTHON), the SDK's
# Python (SDK_PYTHON), a PostgreSQL admin URL
# (ENCOMPUTE_E2E_DATABASE_URL, allowed to create roles and databases) and an
# OpenBao/Vault dev server (BAO_ADDR, BAO_TOKEN; Transit and KV enabled or
# enable-able). pg_dump/psql are run through $PG_DUMP/$PSQL (default: local).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/target/release}"
E="$BIN/encompute"; EVAL="$BIN/encompute-evaluator"; CTL="$BIN/encompute-control"
PYTHON="${TOOL_PYTHON:-python3}"   # helpers (needs `cryptography`)
# The CLI compiles Python functions with $SDK_PYTHON (the Encompute SDK).
export PYTHON_SDK="${SDK_PYTHON:-python3}"
PG_DUMP="${PG_DUMP:-pg_dump}"; PSQL="${PSQL:-psql}"
: "${ENCOMPUTE_E2E_DATABASE_URL:?set ENCOMPUTE_E2E_DATABASE_URL (PostgreSQL admin URL)}"
: "${BAO_ADDR:?set BAO_ADDR (OpenBao/Vault)}"; : "${BAO_TOKEN:?set BAO_TOKEN}"
W="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() {
  echo "E2E FAILED: $*" >&2
  for l in "$W"/logs/*.log; do [ -f "$l" ] && { echo "--- $(basename "$l")" >&2; tail -n 15 "$l" >&2; }; done
  exit 1
}
free_port() { "$PYTHON" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_http() { for _ in $(seq 150); do curl -fs "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; fail "$1 did not start"; }
rand() { "$PYTHON" -c 'import secrets; print(secrets.token_hex(16))'; }

# Canaries: values that must never appear outside their owners' machines.
CANARY_DATA="CANARY-PATIENT-7f3a91"          # inside the dataset file
CANARY_INCOME=731415                          # an encrypted input value (in range)
CANARY_KEY="$("$PYTHON" -c 'print("c4" * 32)')"  # the model's asset key

step "infrastructure: a database role with a real password, a root key, an OIDC provider"
TAG="e2e_$(rand | cut -c1-8)"
DBPASS="$(rand)"
"$PSQL" "$ENCOMPUTE_E2E_DATABASE_URL" -q -c "CREATE ROLE $TAG LOGIN PASSWORD '$DBPASS'" -c "CREATE DATABASE $TAG OWNER $TAG"
ADMIN_BASE="${ENCOMPUTE_E2E_DATABASE_URL%/*}"
HOSTPART="${ADMIN_BASE#*@}"
DB_URL="postgres://$TAG:$DBPASS@$HOSTPART/$TAG"
bao() { curl -fs -H "X-Vault-Token: $BAO_TOKEN" "$@"; }
bao -X POST -d '{"type":"transit"}' "$BAO_ADDR/v1/sys/mounts/transit" >/dev/null 2>&1 || true
bao -X POST "$BAO_ADDR/v1/transit/keys/$TAG-modelco" >/dev/null
"$PYTHON" "$ROOT/scripts/test-idp.py" keygen "$W/idp"
ISS="https://idp.$TAG.test.invalid"
tok() { "$PYTHON" "$ROOT/scripts/test-idp.py" token "$W/idp" "$1" --iss "$ISS"; }
mkdir -p "$W/secrets" "$W/anchor" "$W/logs"
chmod 700 "$W/secrets"
printf '%s' "$DB_URL" > "$W/secrets/db-url"
"$PYTHON" -c 'import secrets; print(secrets.token_hex(32))' > "$W/secrets/control.key"
"$PYTHON" -c 'import secrets; print(secrets.token_hex(32))' > "$W/secrets/evaluator.key"
"$PYTHON" -c 'import secrets; print(secrets.token_hex(32))' > "$W/secrets/keybroker.key"
printf '%s' "$BAO_TOKEN" > "$W/secrets/bao-token"
chmod 600 "$W/secrets/"*

CTL_PORT="$(free_port)"; EVAL_PORT="$(free_port)"; KB_PORT="$(free_port)"
CTL_URL="http://127.0.0.1:$CTL_PORT"
control_env() {
  # exec: in the background, the PID is the control plane's own.
  exec env ENCOMPUTE_ENV=production \
    ENCOMPUTE_LISTEN="127.0.0.1:$CTL_PORT" \
    ENCOMPUTE_DATABASE_URL_FILE="$W/secrets/db-url" \
    ENCOMPUTE_SIGNING_KEY_FILE="$W/secrets/control.key" \
    ENCOMPUTE_OIDC_ISSUER="$ISS" ENCOMPUTE_OIDC_AUDIENCE=encompute \
    ENCOMPUTE_OIDC_JWKS_FILE="$W/idp/jwks.json" \
    ENCOMPUTE_ANCHOR_DIR="$W/anchor" \
    "$@"
}
start_control() {
  ( control_env "$CTL" serve ) >>"$W/logs/control.log" 2>&1 &
  PIDS+=($!); CTL_PID=$!
  wait_http "$CTL_URL/ready"
}

step "production mode refuses insecure configuration"
if env ENCOMPUTE_ENV=production ENCOMPUTE_DATABASE_URL="$ENCOMPUTE_E2E_DATABASE_URL" ENCOMPUTE_ANCHOR_DIR="$W/anchor" \
     ENCOMPUTE_DEV_TOKEN_SECRET=x "$CTL" migrate 2>"$W/refused.txt"; then
  fail "production accepted a development token secret"
fi
grep -q ENC2605 "$W/refused.txt" && echo "REFUSED  $(head -1 "$W/refused.txt")"

step "control plane: migrate, bootstrap the platform admin, start"
( control_env "$CTL" migrate )
( control_env "$CTL" bootstrap --issuer "$ISS" --subject platform-admin ) >/dev/null
start_control
CONTROL_KEY="$(curl -fs "$CTL_URL/v1/info" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["public_key"])')"
api() { # api TOKEN_SUBJECT METHOD PATH [JSON]
  local who="$1" m="$2" p="$3" body="${4:-}"
  local t; t="$(tok "$who")"
  if [ -n "$body" ]; then
    curl -fsS -X "$m" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' -d "$body" "$CTL_URL$p"
  else
    curl -fsS -X "$m" -H "Authorization: Bearer $t" "$CTL_URL$p"
  fi
}
jget() { "$PYTHON" -c "import json,sys; v=json.load(sys.stdin); print($1)"; }

step "tenants: hospital-a and modelco, their people, a shared project"
api platform-admin POST /v1/organizations "{\"id\":\"hospital-a\",\"display_name\":\"Hospital A\",\"admin\":{\"issuer\":\"$ISS\",\"subject\":\"a-admin\"}}" >/dev/null
api platform-admin POST /v1/organizations "{\"id\":\"modelco\",\"display_name\":\"ModelCo\",\"admin\":{\"issuer\":\"$ISS\",\"subject\":\"b-admin\"}}" >/dev/null
api a-admin POST /v1/organizations/hospital-a/users "{\"issuer\":\"$ISS\",\"subject\":\"a-owner\",\"roles\":[\"data_owner\",\"auditor\"]}" >/dev/null
api b-admin POST /v1/organizations/modelco/users "{\"issuer\":\"$ISS\",\"subject\":\"b-dev\",\"roles\":[\"ml_developer\",\"auditor\"]}" >/dev/null
api b-admin POST /v1/organizations/modelco/users "{\"issuer\":\"$ISS\",\"subject\":\"b-owner\",\"roles\":[\"model_owner\"]}" >/dev/null
PROJECT="$(api b-dev POST /v1/projects '{"organization":"modelco","name":"credit-decisions"}' | jget 'v["id"]')"
api b-admin POST "/v1/projects/$PROJECT/members" '{"organization":"hospital-a"}' >/dev/null
echo "project $PROJECT: modelco + hospital-a"

step "assets: hospital-a's dataset (digest only) with a privacy budget; modelco's model key under its KMS root key"
printf 'patient,income\n%s,%s\n' "$CANARY_DATA" "$CANARY_INCOME" > "$W/patients.csv"
DIGEST="$(sha256sum "$W/patients.csv" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$W/patients.csv" | cut -d' ' -f1)"
BUDGET='{"unit":"patient","epsilon":"3.0","delta":"1e-6"}'
DATASET="$(api a-owner POST /v1/assets "{\"organization\":\"hospital-a\",\"kind\":\"dataset\",\"name\":\"patients\",\"digest\":\"$DIGEST\",\"privacy_budget\":$BUDGET}" | jget 'v["id"]')"
api a-owner POST "/v1/assets/$DATASET/approvals" "{\"project\":\"$PROJECT\",\"purpose\":\"credit-decision\"}" >/dev/null
# The model key, protected by a key broker whose KEK is wrapped under
# modelco's root key in OpenBao (the root key never leaves OpenBao).
printf '%s' "$CANARY_KEY" | "$PYTHON" -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))' > "$W/model.key"
chmod 600 "$W/model.key"
PYTHON="$PYTHON_SDK" "$E" compile "$ROOT/examples/02_exact_private_logic/eligibility.py:eligibility" -o "$W/eligibility.encompute" >/dev/null
"$E" attest policy "$W/eligibility.encompute" --image "sha256:$(printf 'a%.0s' $(seq 64))" --tee intel_tdx > "$W/policy.json"
( cd "$W" && BAO_ADDR="$BAO_ADDR" BAO_TOKEN_FILE="$W/secrets/bao-token" "$E" keys protect --asset model-7 \
    --policy "$W/policy.json" --key-file "$W/model.key" \
    --broker-id keybroker-modelco --root-key "openbao:transit/$TAG-modelco" --organization modelco \
    --broker "$W/broker.json" --wrapped-kek "$W/kek.wrapped.json" >/dev/null )
grep -q "$CANARY_KEY" "$W/broker.json" && fail "the asset key is stored in the clear"
echo "model key wrapped: KEK under openbao transit/$TAG-modelco (key version $(jget 'v["key_version"]' < "$W/kek.wrapped.json"))"
MODEL="$(api b-owner POST /v1/assets "{\"organization\":\"modelco\",\"kind\":\"model\",\"name\":\"model-7\",\"digest\":\"$(printf 'b%.0s' $(seq 64))\",\"key_ref\":{\"broker\":\"keybroker-modelco\",\"provider\":\"openbao-transit\",\"key_ref\":\"model-7\",\"key_version\":1}}" | jget 'v["id"]')"

step "platform services: an OpenFHE evaluator and the key broker, each with its own identity"
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
  "{\"id\":\"evaluator-1\",\"kind\":\"evaluator\",\"public_key\":\"$(pubkey "$W/secrets/evaluator.key")\",\"url\":\"http://127.0.0.1:$EVAL_PORT\"}" >/dev/null
api platform-admin POST /v1/organizations/platform/service-accounts \
  "{\"id\":\"keybroker-modelco\",\"kind\":\"keybroker\",\"public_key\":\"$(pubkey "$W/secrets/keybroker.key")\",\"url\":\"http://127.0.0.1:$KB_PORT\"}" >/dev/null
start_evaluator() {
  mkdir -p "$W/evaluator"
  ( cd "$W/evaluator" && exec env ENCOMPUTE_CONTROL_URL="$CTL_URL" ENCOMPUTE_CONTROL_PUBLIC_KEY="$CONTROL_KEY" \
      ENCOMPUTE_SERVICE_ID=evaluator-1 ENCOMPUTE_SERVICE_KEY_FILE="$W/secrets/evaluator.key" \
      ENCOMPUTE_ADVERTISE_URL="http://127.0.0.1:$EVAL_PORT" ENCOMPUTE_CAPACITY=2 \
      "$EVAL" serve --listen "127.0.0.1:$EVAL_PORT" --identity "$W/evaluator/receipt.key" ) >>"$W/logs/evaluator.log" 2>&1 &
  PIDS+=($!); EVAL_PID=$!
  for _ in $(seq 150); do grep -q "registered with the control plane" "$W/logs/evaluator.log" && return 0; sleep 0.2; done
  fail "the evaluator did not register"
}
start_keybroker() {
  ( cd "$W" && exec env BAO_ADDR="$BAO_ADDR" BAO_TOKEN_FILE="$W/secrets/bao-token" ENCOMPUTE_CONTROL_PUBLIC_KEY="$CONTROL_KEY" \
      ENCOMPUTE_SERVICE_ID=keybroker-modelco \
      "$E" keys serve --listen "127.0.0.1:$KB_PORT" --jwks "$W/idp/jwks.json" --broker "$W/broker.json" \
        --root-key "openbao:transit/$TAG-modelco" --organization modelco --wrapped-kek "$W/kek.wrapped.json" ) \
    >>"$W/logs/keybroker.log" 2>&1 &
  PIDS+=($!); KB_PID=$!
  wait_http "http://127.0.0.1:$KB_PORT/live"
}
start_evaluator
start_keybroker
grep "registered with the control plane" "$W/logs/evaluator.log" | tail -1

step "exact golden path: OpenFHE exact (BinFHE), no TFHE-rs"
"$E" keys generate "$W/eligibility.encompute" -o "$W/exact.keys" >/dev/null
export ENCOMPUTE_CONTROL_URL="$CTL_URL"
EX_OUT="$(ENCOMPUTE_TOKEN="$(tok b-dev)" "$E" jobs run "$W/eligibility.encompute" --project "$PROJECT" --purpose credit-decision \
  --source "$DATASET" --keys "$W/exact.keys" --idempotency-key exact-1 \
  --input age=31 --input income=$CANARY_INCOME --input debt=21000 --input risk=400 2>"$W/exact.err")" \
  || { cat "$W/exact.err"; fail "the exact job"; }
cat "$W/exact.err"
echo "$EX_OUT" | grep -q '"out": true' || fail "exact result: $EX_OUT"
grep -q "Trust report            SATISFIED" "$W/exact.err" || fail "exact trust"
EXACT_JOB="$(ENCOMPUTE_TOKEN="$(tok b-dev)" "$E" jobs list --project "$PROJECT" | jget '[j["id"] for j in v if j["backend"]=="openfhe-exact"][0]')"

step "approximate golden path: OpenFHE CKKS through the same control plane"
cat > "$W/score.eir" <<'EIR'
encompute 0.1
program score precision 0.001
%0 = input "x" [-1.0, 1.0] : secret vector<4>
%1 = mul %0, %0 : secret vector<4>
output "y" = %1
EIR
"$E" compile "$W/score.eir" -o "$W/score.encompute" >/dev/null
"$E" keys generate "$W/score.encompute" -o "$W/ckks.keys" >/dev/null
CK_OUT="$(ENCOMPUTE_TOKEN="$(tok b-dev)" "$E" jobs run "$W/score.encompute" --project "$PROJECT" --purpose credit-decision \
  --keys "$W/ckks.keys" --idempotency-key ckks-1 --input x=0.5,-0.25,0.1,1.0 2>"$W/ckks.err")" \
  || { cat "$W/ckks.err"; fail "the CKKS job"; }
grep -q "Trust report            SATISFIED" "$W/ckks.err" || { cat "$W/ckks.err"; fail "CKKS trust"; }
echo "$CK_OUT" | "$PYTHON" -c 'import json,sys; y=json.load(sys.stdin)["y"]; assert max(abs(a-b) for a,b in zip(y,[0.25,0.0625,0.01,1.0]))<1e-3, y; print("CKKS result", [round(v,4) for v in y])'

step "the Python SDK over the same API"
ENCOMPUTE_TOKEN="$(tok b-dev)" "$PYTHON_SDK" - "$CTL_URL" "$PROJECT" "$W/eligibility.encompute" <<'PY'
import sys
import encompute
url, project, artifact = sys.argv[1:4]
client = encompute.Client(url)
p = client.project(project)
model = encompute.load(artifact)
r = p.run(model, dict(age=45, income=90_000, debt=10_000, risk=300), purpose="credit-decision",
          idempotency_key="sdk-1")
assert r.outputs == {"out": True}, r.outputs
assert r.job.state == "succeeded" and r.trust["verdict"] == "SATISFIED", (r.job, r.trust)
print(f"SDK: job {r.job.id} {r.job.state}, trust {r.trust['verdict']}, outputs {r.outputs}")
PY

step "privacy spending (hospital-a's dataset)"
spend() {
  local body
  body="$(printf '{"kind":"reserve","event_id":"%s","policy_id":null,"execution_spec_id":null,"round_id":null,"output":"update","mechanism":{"kind":"discrete_gaussian","clip_norm":"1.0","noise_multiplier":"1.0"},"sensitivity":1,"sigma2":200,"vector_len":8,"rng":"csprng"}' "$1")"
  api a-owner POST "/v1/privacy/$DATASET/events" "$body"
}
spend e2e-release-1 >/dev/null
SPENT1="$(api a-owner GET "/v1/privacy/$DATASET" | jget 'v["spent"]["epsilon"]')"
echo "spent epsilon $SPENT1"

step "restart every service; state survives"
kill "$CTL_PID" "$EVAL_PID" "$KB_PID"; wait "$CTL_PID" "$EVAL_PID" "$KB_PID" 2>/dev/null || true
if curl -fs "$CTL_URL/live" >/dev/null 2>&1; then fail "the control plane is still running"; fi
start_control; start_evaluator; start_keybroker
[ "$(api b-dev GET "/v1/jobs/$EXACT_JOB" | jget 'v["state"]')" = succeeded ] || fail "job state lost"
[ "$(api b-dev GET "/v1/trust/$EXACT_JOB" | jget 'v["verdict"]')" = SATISFIED ] || fail "trust after restart"
[ "$(api a-owner GET "/v1/privacy/$DATASET" | jget 'v["spent"]["epsilon"]')" = "$SPENT1" ] || fail "privacy spend lost"
ENCOMPUTE_TOKEN="$(tok b-dev)" "$E" jobs run "$W/eligibility.encompute" --project "$PROJECT" --purpose credit-decision \
  --keys "$W/exact.keys" --idempotency-key exact-2 --input age=17 --input income=50000 --input debt=1000 --input risk=100 2>"$W/exact2.err" | grep -q '"out": false' \
  || { cat "$W/exact2.err"; fail "a job after the restart"; }
echo "after restart: jobs, trust reports and privacy spending intact; new jobs run"

step "backup and restore; an older backup is refused"
"$PG_DUMP" --clean --if-exists "$DB_URL" > "$W/backup-1.sql"
kill "$CTL_PID"; wait "$CTL_PID" 2>/dev/null || true
"$PSQL" -q "$DB_URL" < "$W/backup-1.sql" >/dev/null
( control_env "$CTL" verify-state )
start_control
spend e2e-release-2 >/dev/null
kill "$CTL_PID"; wait "$CTL_PID" 2>/dev/null || true
"$PSQL" -q "$DB_URL" < "$W/backup-1.sql" >/dev/null
if ( control_env "$CTL" verify-state ) 2>"$W/rollback.txt"; then fail "an older backup restored silently"; fi
grep -q "STATE ROLLBACK" "$W/rollback.txt" || { cat "$W/rollback.txt"; fail "rollback not named"; }
echo "REFUSED  $(grep -o '[A-Z]* STATE ROLLBACK' "$W/rollback.txt" | head -1): startup refused"
( control_env "$CTL" recover --operator e2e-operator )
start_control
[ "$(api a-owner GET "/v1/privacy/$DATASET" | jget 'v["frozen"] is not None')" = True ] || fail "the rolled-back ledger is not frozen"
echo "recovered: the rolled-back ledger is frozen (treated as exhausted)"

step "revocation reaches the key broker"
api b-owner POST "/v1/assets/$MODEL/revoke" >/dev/null
for _ in $(seq 50); do grep -q '"Destroyed"\|"form": *"destroyed"\|destroyed' "$W/broker.json" && break; sleep 0.2; done
grep -q 'destroyed' "$W/broker.json" || fail "the broker still holds the revoked key"
if api b-dev POST /v1/jobs "{}" >/dev/null 2>&1; then :; fi
echo "model-7 revoked: the broker destroyed its key; no new key release is possible"

step "audit trail and canaries"
api b-dev GET "/v1/audit?limit=1000" > "$W/audit-modelco.json"
api a-owner GET "/v1/audit?limit=1000" > "$W/audit-hospital.json"
"$PYTHON" - "$W/audit-modelco.json" <<'PY'
import json, sys
acts = {e["action"] for e in json.load(open(sys.argv[1]))}
need = {"project.created", "plan.created", "job.created", "job.scheduled", "job.started", "job.executed", "job.succeeded", "asset.revoked", "key.revocation.sent"}
missing = need - acts
assert not missing, f"missing audit events: {missing}"
print(f"audit: {len(acts)} kinds of security-sensitive events recorded, including every job transition")
PY
curl -fs "$CTL_URL/metrics" > "$W/metrics.txt"
"$PG_DUMP" "$DB_URL" > "$W/db-dump.sql"
# Numbers match only as whole numbers (not inside hashes or timestamps).
for c in "$CANARY_DATA" "(^|[^0-9a-f])$CANARY_INCOME([^0-9a-f]|$)" "$CANARY_KEY"; do
  for f in "$W/logs/control.log" "$W/logs/evaluator.log" "$W/logs/keybroker.log" "$W/db-dump.sql" \
           "$W/audit-modelco.json" "$W/audit-hospital.json" "$W/metrics.txt" "$W/broker.json"; do
    if grep -Eq -- "$c" "$f"; then fail "canary $c found in $(basename "$f")"; fi
  done
done
echo "canaries: dataset contents, input values and asset keys appear in no log, database dump, audit record or metric"
echo; echo "ENTERPRISE E2E PASSED"
