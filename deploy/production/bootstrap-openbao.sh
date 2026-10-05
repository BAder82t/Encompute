#!/usr/bin/env bash
# Prepares an EXTERNAL OpenBao/Vault for the key broker: initialises and
# unseals it if it is not, then enables Transit and AppRole, creates the
# organization's root key, a least-privilege policy and an AppRole for the
# key broker, and revokes the root token. It speaks the HTTP API over
# verified TLS, so it works against any reachable server, not only the
# reference one.
#
#   BAO_ADDR=https://bao.internal:8200 BAO_CACERT=secrets/bao-ca.crt \
#   ./bootstrap-openbao.sh [--keep-root-token]
#
# Environment:
#   BAO_ADDR, BAO_CACERT   the server and the CA that signed its certificate
#   KEYBROKER_ORG          the organization (default modelco): root key transit/ORG
#   BAO_INIT_DIR           where init output (unseal key shares, root token) is
#                          written, mode 0600 (default ./secrets/openbao-init).
#                          MOVE IT to your own custody and delete it here:
#                          anyone holding enough shares can unseal the vault.
#   BAO_KEY_SHARES / BAO_KEY_THRESHOLD   default 5 / 3 (a laboratory may use 1 / 1)
#   BAO_PGP / auto-unseal   production vaults normally auto-unseal through a
#                          cloud KMS or HSM; then there are no shares to handle.
#
# After it: the AppRole's role-id and secret-id are in ./secrets (mode 0600),
# and bao-token.sh login writes the key broker's token file from them. The
# root token is revoked unless --keep-root-token is given; to administer
# the vault again, generate a new one with the unseal shares
# (`bao operator generate-root`).
set -euo pipefail
cd "$(dirname "$0")"
umask 077
# shellcheck source=lib.sh
. ./lib.sh
KEEP_ROOT=0
[ "${1:-}" != "--keep-root-token" ] || KEEP_ROOT=1
ORG="${KEYBROKER_ORG:-modelco}"
INIT_DIR="${BAO_INIT_DIR:-secrets/openbao-init}"
SHARES="${BAO_KEY_SHARES:-5}"; THRESHOLD="${BAO_KEY_THRESHOLD:-3}"
: "${BAO_ADDR:?set BAO_ADDR (https)}"
: "${BAO_CACERT:?set BAO_CACERT}"
case "$BAO_ADDR" in https://*) ;; *) echo "BAO_ADDR must be https" >&2; exit 1;; esac
export BAO_TOKEN_VALUE=""
log() { printf '== %s\n' "$*"; }
jq_() { python3 -c "import json,sys; v=json.load(sys.stdin); print($1)"; }

log "initialise (once)"
status="$(bao_api GET sys/init)"
if [ "$(jq_ 'v["initialized"]' <<<"$status")" = False ]; then
  mkdir -p "$INIT_DIR"; chmod 700 "$INIT_DIR"
  bao_api PUT sys/init "{\"secret_shares\":$SHARES,\"secret_threshold\":$THRESHOLD}" > "$INIT_DIR/init.json"
  chmod 600 "$INIT_DIR/init.json"
  echo "initialised: $SHARES shares, threshold $THRESHOLD, written to $INIT_DIR/init.json (mode 0600)."
  echo "MOVE IT to your own custody and remove it from this host."
else
  echo "already initialised"
fi

log "unseal"
if [ "$(bao_api GET sys/seal-status | jq_ 'v["sealed"]')" = True ]; then
  [ -s "$INIT_DIR/init.json" ] || { echo "sealed, and no $INIT_DIR/init.json: unseal it with your key shares, then rerun" >&2; exit 1; }
  for k in $(jq_ '" ".join(v["keys"][:'"$THRESHOLD"'])' < "$INIT_DIR/init.json"); do
    bao_api PUT sys/unseal "{\"key\":\"$k\"}" >/dev/null
  done
fi
[ "$(bao_api GET sys/seal-status | jq_ 'v["sealed"]')" = False ] || { echo "still sealed" >&2; exit 1; }
echo "unsealed"

[ -s "$INIT_DIR/init.json" ] || { echo "no root token available ($INIT_DIR/init.json); nothing more to do" >&2; exit 1; }
BAO_TOKEN_VALUE="$(jq_ 'v["root_token"]' < "$INIT_DIR/init.json")"
if [ -z "$BAO_TOKEN_VALUE" ] || [ "$BAO_TOKEN_VALUE" = None ]; then
  echo "init.json holds no root token (already revoked): generate one, export nothing, and rerun with it in $INIT_DIR/init.json" >&2; exit 1
fi
# The server may need a moment to elect itself leader after an unseal.
for _ in $(seq 30); do bao_api GET auth/token/lookup-self >/dev/null 2>&1 && break; sleep 1; done

log "audit device (stdout) and engines"
# Idempotent and strict: enable only what is missing, and let a real error stop the script.
has() { bao_api GET "$1" | python3 -c "import json,sys; v=json.load(sys.stdin); sys.exit(0 if '$2' in v.get('data', v) else 1)"; }
has sys/audit stdout/ || bao_api PUT sys/audit/stdout '{"type":"file","options":{"file_path":"stdout"}}' >/dev/null
has sys/mounts transit/ || bao_api PUT sys/mounts/transit '{"type":"transit"}' >/dev/null
has sys/auth approle/ || bao_api PUT sys/auth/approle '{"type":"approle"}' >/dev/null

log "root key transit/$ORG (not exportable, not deletable)"
if ! bao_api GET "transit/keys/$ORG" >/dev/null 2>&1; then
  bao_api PUT "transit/keys/$ORG" '{"type":"aes256-gcm96","exportable":false,"allow_plaintext_backup":false}' >/dev/null
fi

log "policy encompute-keybroker-$ORG"
policy="$(sed "s|@ORG@|$ORG|g" config/keybroker-policy.hcl.template)"
bao_api PUT "sys/policies/acl/encompute-keybroker-$ORG" "$(python3 -c 'import json,sys; print(json.dumps({"policy": sys.stdin.read()}))' <<<"$policy")" >/dev/null

log "AppRole encompute-keybroker-$ORG (periodic, renewable tokens)"
bao_api PUT "auth/approle/role/encompute-keybroker-$ORG" \
  "{\"token_policies\":[\"encompute-keybroker-$ORG\"],\"token_period\":\"${BAO_TOKEN_PERIOD:-24h}\",\"token_no_default_policy\":true,\"secret_id_num_uses\":0,\"secret_id_ttl\":\"0\"}" >/dev/null
umask 077
bao_api GET "auth/approle/role/encompute-keybroker-$ORG/role-id" | jq_ 'v["data"]["role_id"]' | tr -d '\n' > secrets/bao-role-id
bao_api PUT "auth/approle/role/encompute-keybroker-$ORG/secret-id" '{}' | jq_ 'v["data"]["secret_id"]' | tr -d '\n' > secrets/bao-secret-id
chmod 600 secrets/bao-role-id secrets/bao-secret-id
echo "role-id and secret-id written to secrets/ (mode 0600)"

if [ "$KEEP_ROOT" = 0 ]; then
  log "revoke the root token"
  bao_api POST auth/token/revoke-self >/dev/null
  python3 - "$INIT_DIR/init.json" <<'PY'
import json, sys
p = sys.argv[1]
v = json.load(open(p))
v.pop("root_token", None)
json.dump(v, open(p, "w"))
PY
  echo "root token revoked and removed from $INIT_DIR/init.json"
fi
echo "bootstrap done: now ./bao-token.sh login"
