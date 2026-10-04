#!/usr/bin/env bash
# Negative tests for validate.sh: starts a deliberately misconfigured
# topology (compose.misconfigured.yaml) and runs the validator against it.
# The validator must exit non-zero AND fail the specific checks that match
# each planted misconfiguration; this script asserts both and prints the
# validator's own lines as evidence.
#
#   ./negative/run.sh
#
# Planted misconfigurations and the check that must FAIL for each:
#   plaintext PostgreSQL accepted          PG-02, PG-03, PG-04
#   dev-mode OpenBao, over http            BAO-01, BAO-02, BAO-04, BAO-05
#   no client certificate required         EDGE-04, EDGE-06
#   secrets as environment literals        SEC-01, SEC-02
#   no health check                        HLTH-01
#   a network with a route out             TOP-03
#   TLS client not verifying PostgreSQL    PG-07
# Names and ports (all overridable): project encompute-negative, host ports
# 8480-8483 and 58221, loopback only. Everything is removed at the end.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
export COMPOSE_PROJECT_NAME="${NEG_PROJECT:-encompute-negative}"
export NEG_API_PORT="${NEG_API_PORT:-8480}" NEG_EVALUATOR_PORT="${NEG_EVALUATOR_PORT:-8481}" \
       NEG_OPS_PORT="${NEG_OPS_PORT:-8482}" NEG_KEYBROKER_PORT="${NEG_KEYBROKER_PORT:-8483}" NEG_BAO_PORT="${NEG_BAO_PORT:-58221}"
# shellcheck source=../lib.sh
. ../lib.sh
W="$(mktemp -d "${TMPDIR:-/tmp}/encompute-negative.XXXXXX")"
export NEG_SECRETS="$W/secrets"
dc() { d compose -p "$COMPOSE_PROJECT_NAME" -f compose.misconfigured.yaml "$@"; }
cleanup() { DOCKER_TIMEOUT=120 dc down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$W"; }
trap cleanup EXIT

../gen-test-certs.sh "$NEG_SECRETS" >/dev/null
printf '%s' "dbpassword-$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')" > "$NEG_SECRETS/db-password"
printf '%s' "$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')" > "$NEG_SECRETS/control.key"
chmod 644 "$NEG_SECRETS"/db-password "$NEG_SECRETS"/control.key
NEG_SIGNING_KEY="$(cat "$NEG_SECRETS/control.key")"; NEG_DB_PASSWORD="$(cat "$NEG_SECRETS/db-password")"
export NEG_SIGNING_KEY NEG_DB_PASSWORD
DOCKER_TIMEOUT=240 dc up -d >"$W/up.log" 2>&1 || { echo "could not start the misconfigured topology" >&2; tail -n 20 "$W/up.log" >&2; exit 2; }
for _ in $(seq 60); do
  n="$(dc ps --format '{{.Health}}' 2>/dev/null | grep -c '^healthy$')"
  [ "$n" -ge 3 ] && break; sleep 1
done
sleep 3

OUT="$W/validate.out"
BAO_PROJECT="$COMPOSE_PROJECT_NAME" SECRETS_DIR="$NEG_SECRETS" \
  EDGE_API_PORT="$NEG_API_PORT" EDGE_EVALUATOR_PORT="$NEG_EVALUATOR_PORT" EDGE_OPS_PORT="$NEG_OPS_PORT" EDGE_KEYBROKER_PORT="$NEG_KEYBROKER_PORT" \
  EDGE_CA="$NEG_SECRETS/edge-ca.crt" OPS_CERT="$NEG_SECRETS/ops-client.crt" OPS_KEY="$NEG_SECRETS/ops-client.key" \
  BAO_ADDR="http://127.0.0.1:$NEG_BAO_PORT" BAO_CACERT="$NEG_SECRETS/bao-ca.crt" \
  ../validate.sh > "$OUT" 2>&1
code=$?

want="PG-02 PG-03 PG-04 PG-07 BAO-01 BAO-02 BAO-04 BAO-05 EDGE-04 EDGE-06 SEC-01 SEC-02 HLTH-01 TOP-03"
missed=""
for id in $want; do
  grep -qE "^FAIL  $id " "$OUT" || missed="$missed $id"
done
grep -E '^(FAIL|PASS|SKIP|DEPLOYMENT)' "$OUT"
echo
if [ "$code" -ne 0 ] && [ -z "$missed" ]; then
  echo "NEGATIVE TESTS PASSED: the validator exited $code and failed every planted misconfiguration ($want)"
  exit 0
fi
echo "NEGATIVE TESTS FAILED: validator exit $code; checks that did not fail:${missed:- none}" >&2
exit 1
