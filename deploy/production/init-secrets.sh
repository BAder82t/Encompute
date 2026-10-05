#!/usr/bin/env bash
# Creates this deployment's random secrets (./secrets, never committed) and
# .env (public keys, ports, the root-key provider's address: nothing secret).
#
#   ENCOMPUTE_OIDC_ISSUER=https://login.example.com \
#   BAO_UPSTREAM=bao.internal:8200 \
#   ENCOMPUTE_CONTROL_IMAGE=ghcr.io/...@sha256:... ENCOMPUTE_SERVICES_IMAGE=ghcr.io/...@sha256:... \
#   ./init-secrets.sh
#
# Needs, already in ./secrets (yours, or ./gen-test-certs.sh for a laptop):
#   edge.crt edge.key          the edge's server certificate and key
#   client-ca.crt              the CA whose client certificates the edge accepts
#   internal-ca.crt            the CA that signed PostgreSQL's certificates
#   pg-server.crt pg-server.key   PostgreSQL's server certificate (name: postgres)
#   pg-client.crt pg-client.key   the control plane's database client certificate
#                              (CN: encompute)
#   bao-ca.crt                 the CA that signed the root-key provider's certificate
# bao-token is written by ./bootstrap-openbao.sh and ./bao-token.sh.
# Existing secrets are kept: run it again to add what is missing.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
: "${ENCOMPUTE_OIDC_ISSUER:?set ENCOMPUTE_OIDC_ISSUER (https; your identity provider)}"
: "${BAO_UPSTREAM:?set BAO_UPSTREAM (host:port of your OpenBao/Vault; the host must be a name in its certificate)}"
: "${ENCOMPUTE_SERVICES_IMAGE:?set ENCOMPUTE_SERVICES_IMAGE (the services image, by digest, from a release with native TLS)}"
: "${ENCOMPUTE_CONTROL_IMAGE:?set ENCOMPUTE_CONTROL_IMAGE (the control plane image, by digest, from a release with native TLS)}"
mkdir -p secrets oidc
chmod 700 secrets
for f in edge.crt edge.key client-ca.crt internal-ca.crt pg-server.crt pg-server.key pg-client.crt pg-client.key bao-ca.crt; do
  [ -s "secrets/$f" ] || { echo "missing secrets/$f (see the header of this script; ./gen-test-certs.sh makes a throwaway set)" >&2; exit 1; }
done
rand() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }
new() { [ -s "secrets/$1" ] || printf '%s' "$2" > "secrets/$1"; chmod 644 "secrets/$1"; }
new db-password "$(rand 24)"
# The control plane speaks TLS to PostgreSQL itself: sslmode=verify-full
# checks the server's certificate chain (against the internal CA) and its name
# (postgres), and the client certificate (CN encompute) is presented. The
# paths are inside the control plane's container, where the secrets mount.
# See docs/production-deployment.md.
new db-url "postgres://encompute:$(cat secrets/db-password)@postgres:5432/encompute?sslmode=verify-full&sslrootcert=/run/secrets/internal-ca.crt&sslcert=/run/secrets/pg-client.crt&sslkey=/run/secrets/pg-client.key"
for k in control evaluator keybroker; do new "$k.key" "$(rand 32)"; done
new metrics-token "$(rand 32)"
IMG="$ENCOMPUTE_CONTROL_IMAGE"
# shellcheck source=lib.sh
. ./lib.sh
export DOCKER_TIMEOUT=120
pub() { d run --rm -v "$PWD/secrets/$1.key:/run/secrets/key:ro" "$IMG" public-key /run/secrets/key; }
control_pub="$(pub control)"
evaluator_pub="$(pub evaluator)"
keybroker_pub="$(pub keybroker)"
{
  echo "ENCOMPUTE_CONTROL_PUBLIC_KEY=$control_pub"
  echo "ENCOMPUTE_EVALUATOR_PUBLIC_KEY=$evaluator_pub"
  echo "ENCOMPUTE_KEYBROKER_PUBLIC_KEY=$keybroker_pub"
  echo "ENCOMPUTE_OIDC_ISSUER=$ENCOMPUTE_OIDC_ISSUER"
  echo "ENCOMPUTE_OIDC_AUDIENCE=${ENCOMPUTE_OIDC_AUDIENCE:-encompute}"
  echo "ENCOMPUTE_OIDC_JWKS_URL=${ENCOMPUTE_OIDC_JWKS_URL:-}"
  if [ -f oidc/jwks.json ]; then echo "ENCOMPUTE_OIDC_JWKS_FILE=/etc/encompute/oidc/jwks.json"; fi
  echo "ENCOMPUTE_EVALUATOR_URL=${ENCOMPUTE_EVALUATOR_URL:-https://localhost:${EDGE_EVALUATOR_PORT:-8444}}"
  echo "ENCOMPUTE_CONTROL_IMAGE=$ENCOMPUTE_CONTROL_IMAGE"
  echo "ENCOMPUTE_SERVICES_IMAGE=$ENCOMPUTE_SERVICES_IMAGE"
  echo "BAO_UPSTREAM=$BAO_UPSTREAM"
  echo "BAO_NETWORK=${BAO_NETWORK:-encompute-bao}"
  echo "KEYBROKER_ORG=${KEYBROKER_ORG:-modelco}"
  echo "EDGE_BIND=${EDGE_BIND:-127.0.0.1}"
  echo "EDGE_API_PORT=${EDGE_API_PORT:-8443}"
  echo "EDGE_EVALUATOR_PORT=${EDGE_EVALUATOR_PORT:-8444}"
  echo "EDGE_OPS_PORT=${EDGE_OPS_PORT:-8445}"
  echo "EDGE_KEYBROKER_PORT=${EDGE_KEYBROKER_PORT:-8446}"
} > .env
chmod 600 .env
echo "wrote secrets/ and .env (control plane key ${control_pub:0:16}...)"
