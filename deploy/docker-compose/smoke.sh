#!/usr/bin/env bash
# Compose smoke test: the deployment in production mode with a throwaway
# OIDC provider. Brings everything up, runs the exact golden path through
# the control plane, restarts every container, checks state survived, and
# revokes an asset (the key broker destroys its key). Removes the stack
# unless KEEP=1.
#
#   deploy/docker-compose/smoke.sh
#
# Needs the images (encompute-control, encompute-evaluator, encompute-services
# tagged :dev), an `encompute` client built with OpenFHE, and python3 with
# `cryptography` (TOOL_PYTHON) plus the SDK's Python (SDK_PYTHON).
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"
E="${E:-$ROOT/target/release/encompute}"
TOOL_PYTHON="${TOOL_PYTHON:-python3}"
SDK_PYTHON="${SDK_PYTHON:-python3}"
W="$(mktemp -d)"
dc() { docker compose "$@"; }
cleanup() {
  [ "${KEEP:-}" = 1 ] || dc down -v >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT
step() { printf '\n== %s\n' "$*"; }
fail() { echo "COMPOSE SMOKE FAILED: $*" >&2; dc logs --tail 20 >&2 || true; exit 1; }
wait_http() { for _ in $(seq 150); do curl -fs "$1" >/dev/null 2>&1 && return 0; sleep 0.4; done; fail "$1 did not answer"; }
jget() { "$TOOL_PYTHON" -c "import json,sys; v=json.load(sys.stdin); print($1)"; }

step "secrets, a throwaway identity provider, and a clean stack"
dc down -v >/dev/null 2>&1 || true
rm -rf secrets .env
"$TOOL_PYTHON" "$ROOT/scripts/test-idp.py" keygen oidc
ISS="https://idp.compose.test.invalid"
ENCOMPUTE_OIDC_ISSUER="$ISS" ./init.sh
tok() { "$TOOL_PYTHON" "$ROOT/scripts/test-idp.py" token oidc "$1" --iss "$ISS"; }
api() {
  local t; t="$(tok "$1")"
  if [ -n "${4:-}" ]; then
    curl -fsS -X "$2" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' -d "$4" "http://127.0.0.1:8770$3"
  else
    curl -fsS -X "$2" -H "Authorization: Bearer $t" "http://127.0.0.1:8770$3"
  fi
}
# shellcheck disable=SC1091
set -a; . ./.env; set +a

step "database, root key provider and control plane"
dc up -d postgres openbao control
wait_http http://127.0.0.1:8770/ready
dc exec -T control encompute-control bootstrap --issuer "$ISS" --subject platform-admin
dc exec -T -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$ENCOMPUTE_DEV_BAO_TOKEN" openbao \
  sh -c 'bao secrets enable transit >/dev/null 2>&1 || true; bao write -f transit/keys/modelco >/dev/null'

step "tenants, project, assets, platform services"
api platform-admin POST /v1/organizations "{\"id\":\"hospital-a\",\"display_name\":\"Hospital A\",\"admin\":{\"issuer\":\"$ISS\",\"subject\":\"a-admin\"}}" >/dev/null
api platform-admin POST /v1/organizations "{\"id\":\"modelco\",\"display_name\":\"ModelCo\",\"admin\":{\"issuer\":\"$ISS\",\"subject\":\"b-admin\"}}" >/dev/null
api b-admin POST /v1/organizations/modelco/users "{\"issuer\":\"$ISS\",\"subject\":\"b-dev\",\"roles\":[\"ml_developer\"]}" >/dev/null
api a-admin POST /v1/organizations/hospital-a/users "{\"issuer\":\"$ISS\",\"subject\":\"a-owner\",\"roles\":[\"data_owner\",\"auditor\"]}" >/dev/null
api b-admin POST /v1/organizations/modelco/users "{\"issuer\":\"$ISS\",\"subject\":\"b-owner\",\"roles\":[\"model_owner\"]}" >/dev/null
PROJECT="$(api b-dev POST /v1/projects '{"organization":"modelco","name":"credit"}' | jget 'v["id"]')"
MODEL="$(api b-owner POST /v1/assets "{\"organization\":\"modelco\",\"kind\":\"model\",\"name\":\"model-7\",\"digest\":\"$(printf 'b%.0s' $(seq 64))\",\"key_ref\":{\"broker\":\"keybroker-modelco\",\"provider\":\"openbao-transit\",\"key_ref\":\"model-7\",\"key_version\":1}}" | jget 'v["id"]')"
DATASET="$(api a-owner POST /v1/assets "{\"organization\":\"hospital-a\",\"kind\":\"dataset\",\"name\":\"patients\",\"digest\":\"$(printf 'c%.0s' $(seq 64))\",\"privacy_budget\":{\"unit\":\"patient\",\"epsilon\":\"3.0\",\"delta\":\"1e-6\"}}" | jget 'v["id"]')"
reg() {
  api platform-admin POST /v1/organizations/platform/service-accounts \
    "{\"id\":\"$1\",\"kind\":\"$2\",\"public_key\":\"$3\",\"url\":\"$4\"}" >/dev/null
}
reg evaluator-1 evaluator "$ENCOMPUTE_EVALUATOR_PUBLIC_KEY" http://127.0.0.1:8750
reg keybroker-modelco keybroker "$ENCOMPUTE_KEYBROKER_PUBLIC_KEY" http://openbao:8760
reg secagg-1 secagg "$ENCOMPUTE_SECAGG_PUBLIC_KEY" http://secagg:8770

step "the model key, wrapped by modelco's root key in OpenBao"
PYTHON="$SDK_PYTHON" "$E" compile "$ROOT/examples/02_exact_private_logic/eligibility.py:eligibility" -o "$W/eligibility.encompute" >/dev/null
"$E" attest policy "$W/eligibility.encompute" --image "sha256:$(printf 'a%.0s' $(seq 64))" --tee intel_tdx > "$W/policy.json"
chmod 644 "$W/policy.json"
dc run --rm -T -v "$W/policy.json:/tmp/policy.json:ro" keybroker keys protect --asset model-7 --policy /tmp/policy.json \
  --broker-id keybroker-modelco --root-key openbao:transit/modelco --organization modelco \
  --broker /var/lib/encompute/broker.json --wrapped-kek /var/lib/encompute/kek.wrapped.json >/dev/null
dc up -d evaluator keybroker
for _ in $(seq 150); do
  s="$(api platform-admin GET /v1/evaluators | jget '[e["status"] for e in v if e["id"]=="evaluator-1"]')"
  [ "$s" = "['ready']" ] && break; sleep 0.5
done
[ "$s" = "['ready']" ] || fail "the evaluator did not register"
echo "evaluator-1 registered and ready; key broker up"

step "exact golden path through the deployment"
"$E" keys generate "$W/eligibility.encompute" -o "$W/keys" >/dev/null
run_job() {
  ENCOMPUTE_CONTROL_URL=http://127.0.0.1:8770 ENCOMPUTE_TOKEN="$(tok b-dev)" "$E" jobs run "$W/eligibility.encompute" \
    --project "$PROJECT" --purpose credit --keys "$W/keys" --idempotency-key "$1" \
    --input age="$2" --input income=120000 --input debt=21000 --input risk=400
}
OUT="$(run_job smoke-1 31 2>"$W/job.err")" || { cat "$W/job.err"; fail "the job"; }
grep -q "Trust report            SATISFIED" "$W/job.err" || { cat "$W/job.err"; fail "trust"; }
echo "$OUT" | grep -q '"out": true' || fail "result $OUT"
JOB="$(api b-dev GET "/v1/jobs?project=$PROJECT" | jget 'v[0]["id"]')"
echo "job $JOB succeeded; trust SATISFIED"

step "restart every Encompute container: state survives"
# The KMS is the customer's, outside this restart (the bundled OpenBao runs
# in development mode, in memory: restarting it would lose its keys).
dc restart postgres control evaluator keybroker
wait_http http://127.0.0.1:8770/ready
[ "$(api b-dev GET "/v1/jobs/$JOB" | jget 'v["state"]')" = succeeded ] || fail "job lost"
[ "$(api b-dev GET "/v1/trust/$JOB" | jget 'v["verdict"]')" = SATISFIED ] || fail "trust after restart"
for _ in $(seq 150); do
  s="$(api platform-admin GET /v1/evaluators | jget '[e["status"] for e in v if e["id"]=="evaluator-1"]')"
  [ "$s" = "['ready']" ] && break; sleep 0.5
done
run_job smoke-2 17 2>"$W/job2.err" | grep -q '"out": false' || { cat "$W/job2.err"; fail "a job after the restart"; }
echo "after the restart: the job, its trust report, and new jobs all work"

step "privacy spending, backup, destroy the environment, restore"
api a-owner POST "/v1/privacy/$DATASET/events" '{"kind":"reserve","event_id":"smoke-release-1","policy_id":null,"execution_spec_id":null,"round_id":null,"output":"update","mechanism":{"kind":"discrete_gaussian","clip_norm":"1.0","noise_multiplier":"1.0"},"sensitivity":1,"sigma2":200,"vector_len":8,"rng":"csprng"}' >/dev/null
SPENT="$(api a-owner GET "/v1/privacy/$DATASET" | jget 'v["spent"]["epsilon"]')"
./backup.sh "$W/backup"
# Everything Encompute runs is destroyed; the customer's KMS (OpenBao) is not.
dc rm -sfv control evaluator keybroker postgres >/dev/null
docker volume rm encompute_pgdata encompute_anchor encompute_broker encompute_evaluator >/dev/null
./restore.sh "$W/backup"
wait_http http://127.0.0.1:8770/ready
dc up -d evaluator keybroker
[ "$(api b-dev GET "/v1/projects/$PROJECT" | jget 'v["name"]')" = credit ] || fail "project lost"
[ "$(api b-dev GET "/v1/jobs/$JOB" | jget 'v["state"]')" = succeeded ] || fail "job lost"
[ "$(api b-dev GET "/v1/trust/$JOB" | jget 'v["verdict"]')" = SATISFIED ] || fail "trust evidence after restore"
[ "$(api a-owner GET "/v1/privacy/$DATASET" | jget 'v["spent"]["epsilon"]')" = "$SPENT" ] || fail "privacy spend lost"
for _ in $(seq 60); do curl -fs http://127.0.0.1:8760/live >/dev/null 2>&1 && break; sleep 0.5; done
curl -fs http://127.0.0.1:8760/live >/dev/null || fail "the key broker could not open its wrapped KEK after the restore"
echo "restored: projects, jobs, trust evidence and privacy spending intact; the wrapped keys open through the KMS"

step "revocation reaches the key broker"
api b-owner POST "/v1/assets/$MODEL/revoke" >/dev/null
for _ in $(seq 50); do dc exec -T keybroker cat /var/lib/encompute/broker.json | grep -q destroyed && break; sleep 0.3; done
dc exec -T keybroker cat /var/lib/encompute/broker.json | grep -q destroyed || fail "the broker still holds the revoked key"
echo "model-7 revoked; the broker destroyed the key"
echo; echo "COMPOSE SMOKE PASSED"
