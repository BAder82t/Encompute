#!/usr/bin/env bash
# Creates this deployment's secrets (./secrets, never committed) and .env.
#
#   ./init.sh
#
# Secrets are random: the database password, the control plane's signing
# key, each service's identity key, and the development OpenBao token. The
# directory is 0700; its files are readable by the containers' users (the
# directory protects them on the host). OIDC settings come from the
# environment: ENCOMPUTE_OIDC_ISSUER, ENCOMPUTE_OIDC_AUDIENCE, and
# ENCOMPUTE_OIDC_JWKS_URL (or a JWKS file placed in ./oidc/jwks.json).
set -euo pipefail
cd "$(dirname "$0")"
umask 077
mkdir -p secrets oidc
chmod 700 secrets
rand() { od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'; }
new() { [ -s "secrets/$1" ] || { printf '%s' "$2" > "secrets/$1"; }; chmod 644 "secrets/$1"; }
new db-password "$(rand 24)"
new db-url "postgres://encompute:$(cat secrets/db-password)@postgres:5432/encompute"
for k in control evaluator secagg keybroker; do new "$k.key" "$(rand 32)"; done
new bao-token "$(rand 16)"
pub() { docker run --rm -v "$PWD/secrets:/s:ro" "encompute-control:${ENCOMPUTE_VERSION:-dev}" public-key "/s/$1.key"; }
{
  echo "ENCOMPUTE_CONTROL_PUBLIC_KEY=$(pub control)"
  echo "ENCOMPUTE_EVALUATOR_PUBLIC_KEY=$(pub evaluator)"
  echo "ENCOMPUTE_KEYBROKER_PUBLIC_KEY=$(pub keybroker)"
  echo "ENCOMPUTE_SECAGG_PUBLIC_KEY=$(pub secagg)"
  echo "ENCOMPUTE_DEV_BAO_TOKEN=$(cat secrets/bao-token)"
  echo "ENCOMPUTE_OIDC_ISSUER=${ENCOMPUTE_OIDC_ISSUER:-}"
  echo "ENCOMPUTE_OIDC_AUDIENCE=${ENCOMPUTE_OIDC_AUDIENCE:-encompute}"
  echo "ENCOMPUTE_OIDC_JWKS_URL=${ENCOMPUTE_OIDC_JWKS_URL:-}"
  if [ -f oidc/jwks.json ]; then echo "ENCOMPUTE_OIDC_JWKS_FILE=/etc/encompute/oidc/jwks.json"; fi
} > .env
chmod 600 .env
echo "wrote secrets/ and .env (control plane key $(grep CONTROL_PUBLIC .env | cut -d= -f2 | cut -c1-16)...)"
