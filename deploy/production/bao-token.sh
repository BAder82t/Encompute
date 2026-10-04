#!/usr/bin/env bash
# The key broker's OpenBao/Vault token. The broker reads one token file
# (BAO_TOKEN_FILE) and cannot log in itself, so this script logs in with the
# AppRole (secrets/bao-role-id, secrets/bao-secret-id) and writes
# secrets/bao-token; the token is periodic and renewable.
#
#   BAO_ADDR=... BAO_CACERT=... ./bao-token.sh login   write a fresh token file
#   BAO_ADDR=... BAO_CACERT=... ./bao-token.sh renew   renew it; log in again if that fails
#
# Run `renew` on a timer well inside the period (default 24h: every 6h), and
# alert when it fails. After `login` wrote a NEW token, restart the broker
# (`docker compose restart keybroker`): it reads the file at start. `renew`
# keeps the same token, so no restart is needed.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
# shellcheck source=lib.sh
. ./lib.sh
: "${BAO_ADDR:?set BAO_ADDR (https)}"
: "${BAO_CACERT:?set BAO_CACERT}"
jq_() { python3 -c "import json,sys; v=json.load(sys.stdin); print($1)"; }
login() {
  BAO_TOKEN_VALUE="" bao_api PUT auth/approle/login \
    "{\"role_id\":\"$(cat secrets/bao-role-id)\",\"secret_id\":\"$(cat secrets/bao-secret-id)\"}" \
    | jq_ 'v["auth"]["client_token"]' | tr -d '\n' > secrets/bao-token.new
  mv secrets/bao-token.new secrets/bao-token
  chmod 644 secrets/bao-token   # a mounted secret: readable by the broker's user, in a 0700 directory
  echo "logged in: new token written to secrets/bao-token (restart the key broker)"
}
case "${1:-}" in
  login) login ;;
  renew)
    BAO_TOKEN_VALUE="$(cat secrets/bao-token 2>/dev/null || true)"
    if [ -n "$BAO_TOKEN_VALUE" ] && bao_api POST auth/token/renew-self '{}' >/dev/null 2>&1; then
      echo "renewed the token in secrets/bao-token"
    else
      login
    fi ;;
  *) echo "usage: $0 login|renew" >&2; exit 2 ;;
esac
