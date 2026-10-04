#!/usr/bin/env bash
# LABORATORY ONLY: brings the whole reference topology up on a laptop with
# throwaway certificates, a throwaway identity provider and the reference
# OpenBao, and registers the platform services. Real deployments follow
# docs/production-deployment.md; this script is that runbook, executed.
#
#   ./lab-up.sh            up
#   ./lab-up.sh down       remove everything it created (containers, volumes, networks, secrets)
#
# Names and ports are overridable (defaults are the topology's own):
#   COMPOSE_PROJECT_NAME (encompute-prod)   BAO_PROJECT (encompute-bao)   BAO_NETWORK (encompute-bao)
#   BAO_PORT (8200, loopback)   EDGE_API_PORT/EDGE_EVALUATOR_PORT/EDGE_OPS_PORT/EDGE_KEYBROKER_PORT (8443-8446)
# Needs docker compose, openssl, curl, python3 with `cryptography`.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-encompute-prod}"
export BAO_PROJECT="${BAO_PROJECT:-encompute-bao}" BAO_NETWORK="${BAO_NETWORK:-encompute-bao}" BAO_PORT="${BAO_PORT:-8200}"
export EDGE_API_PORT="${EDGE_API_PORT:-8443}" EDGE_EVALUATOR_PORT="${EDGE_EVALUATOR_PORT:-8444}" \
       EDGE_OPS_PORT="${EDGE_OPS_PORT:-8445}" EDGE_KEYBROKER_PORT="${EDGE_KEYBROKER_PORT:-8446}"
# shellcheck source=lib.sh
. ./lib.sh
dc() { d compose -p "$COMPOSE_PROJECT_NAME" "$@"; }
dcb() { d compose -p "$BAO_PROJECT" -f compose.openbao.yaml "$@"; }
step() { printf '\n== %s\n' "$*"; }

if [ "${1:-}" = down ]; then
  export DOCKER_TIMEOUT=180
  dc down -v --remove-orphans || true
  dcb down -v --remove-orphans || true
  d network rm "$BAO_NETWORK" >/dev/null 2>&1 || true
  # Volumes a restore created outside Compose, if any.
  for v in pgdata anchor broker evaluator; do d volume rm "${COMPOSE_PROJECT_NAME}_$v" >/dev/null 2>&1 || true; done
  rm -rf secrets oidc oidc-lab .env
  echo "removed the laboratory topology"
  exit 0
fi

ISS="${ENCOMPUTE_OIDC_ISSUER:-https://idp.lab.test.invalid}"
export BAO_ADDR="https://localhost:$BAO_PORT" BAO_CACERT="$PWD/secrets/bao-ca.crt"
EDGE="https://localhost:$EDGE_API_PORT"
CA="$PWD/secrets/edge-ca.crt"
tok() { python3 "$ROOT/scripts/test-idp.py" token oidc-lab "$1" --iss "$ISS"; }
api() { # WHO METHOD PATH [BODY]
  local t; t="$(tok "$1")"
  if [ -n "${4:-}" ]; then
    curl -fsS --cacert "$CA" -X "$2" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' -d "$4" "$EDGE$3"
  else
    curl -fsS --cacert "$CA" -X "$2" -H "Authorization: Bearer $t" "$EDGE$3"
  fi
}
wait_for() { for _ in $(seq "${3:-120}"); do eval "$2" >/dev/null 2>&1 && return 0; sleep 1; done; echo "timed out: $1" >&2; exit 1; }

step "throwaway PKI and identity provider"
./gen-test-certs.sh >/dev/null
[ -s oidc-lab/idp.pem ] || python3 "$ROOT/scripts/test-idp.py" keygen oidc-lab
mkdir -p oidc; cp oidc-lab/jwks.json oidc/jwks.json

step "the reference OpenBao: start, initialise, unseal, bootstrap"
dcb up -d
wait_for "openbao answers" 'curl -s --cacert "$BAO_CACERT" "$BAO_ADDR/v1/sys/health?uninitcode=200&sealedcode=200"' 60
BAO_KEY_SHARES=1 BAO_KEY_THRESHOLD=1 ./bootstrap-openbao.sh
./bao-token.sh login

step "secrets"
ENCOMPUTE_OIDC_ISSUER="$ISS" BAO_UPSTREAM=openbao:8200 BAO_SERVER_NAME=openbao ./init-secrets.sh
set -a; . ./.env; set +a

step "database, control plane, edge"
DOCKER_TIMEOUT=300 dc up -d --build postgres pg-tunnel control bao-tunnel edge
wait_for "the edge serves the API over TLS" "curl -fs --cacert '$CA' $EDGE/ready" 120
dc exec -T control encompute-control bootstrap --issuer "$ISS" --subject platform-admin

step "platform services: register the evaluator and the key broker"
reg() { api platform-admin POST /v1/organizations/platform/service-accounts \
  "{\"id\":\"$1\",\"kind\":\"$2\",\"public_key\":\"$3\",\"url\":\"$4\"}" >/dev/null; }
reg evaluator-1 evaluator "$ENCOMPUTE_EVALUATOR_PUBLIC_KEY" "$ENCOMPUTE_EVALUATOR_URL"
reg "keybroker-$KEYBROKER_ORG" keybroker "$ENCOMPUTE_KEYBROKER_PUBLIC_KEY" "http://bao-tunnel:8760"

step "key broker state: protect one asset (wraps the broker's KEK in OpenBao)"
POL="$(mktemp)"
trap 'rm -f "$POL"' EXIT
d run --rm -v "$ROOT/deploy/confidential-space/demo.eir:/m.eir:ro" --entrypoint encompute \
  "${ENCOMPUTE_SERVICES_IMAGE:-ghcr.io/bader82t/encompute-services@sha256:b76d8993cc375291e6627e093eed4abc32a5f9dc9ddbbf8c1a7a710b06a36f33}" \
  attest policy /m.eir --image "sha256:$(printf 'a%.0s' $(seq 64))" --tee intel_tdx > "$POL"
chmod 644 "$POL"
./protect-asset.sh lab-asset "$POL" >/dev/null

step "the rest of the stack"
DOCKER_TIMEOUT=300 dc up -d
wait_for "every service healthy" '[ -z "$(d ps --filter label=com.docker.compose.project='"$COMPOSE_PROJECT_NAME"' --format "{{.Status}}" | grep -v "(healthy)")" ]' 180
echo; echo "LAB TOPOLOGY UP: API $EDGE (CA secrets/edge-ca.crt), ops https://localhost:$EDGE_OPS_PORT (mTLS: secrets/ops-client.{crt,key})"
