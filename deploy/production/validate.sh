#!/usr/bin/env bash
# Checks a RUNNING topology against the reference production topology's
# requirements and prints a checklist: one PASS / FAIL / SKIP line per
# requirement, then a verdict. Exits 1 if any requirement FAILs.
#
#   ./validate.sh [--backup-dir DIR] [--drill]
#
#   --backup-dir DIR   also verify a backup taken with ./backup.sh (BAK-01)
#   --drill            also run the backup-and-restore drill against this
#                      topology (BAK-02). DESTRUCTIVE: it takes a backup,
#                      destroys the volumes and restores them. Run it on a
#                      staging copy or a laboratory, not on live data.
#
# THIS CHECKS CONFIGURATION. It shows that the running topology is set up the
# way the reference topology requires (TLS where designed, plaintext refused,
# secrets as files, health checks green). It does not show the topology is
# secure: it tests no application logic, finds no vulnerability, and says
# nothing about your certificates' issuance, your vault's custody or your
# network beyond this host. See docs/production-deployment.md.
#
# Environment (defaults suit the laboratory run, ./lab-up.sh):
#   COMPOSE_PROJECT_NAME  the Compose project (encompute-prod)
#   BAO_PROJECT           the project running a reference OpenBao, if any (encompute-bao)
#   SECRETS_DIR           ./secrets
#   EDGE_HOST             localhost (must be in the edge certificate)
#   EDGE_API_PORT 8443, EDGE_EVALUATOR_PORT 8444, EDGE_OPS_PORT 8445, EDGE_KEYBROKER_PORT 8446
#   EDGE_CA               the CA to verify the edge with ($SECRETS_DIR/edge-ca.crt)
#   OPS_CERT, OPS_KEY     a client certificate the edge accepts ($SECRETS_DIR/ops-client.{crt,key})
#   BAO_ADDR, BAO_CACERT  the root-key provider's API (https://localhost:8200) and its CA ($SECRETS_DIR/bao-ca.crt)
#   KEYBROKER_ORG         modelco
set -uo pipefail
cd "$(dirname "$0")" || exit 1
# shellcheck source=lib.sh
. ./lib.sh
PROJECT="${COMPOSE_PROJECT_NAME:-encompute-prod}"
BAO_PROJECT="${BAO_PROJECT:-encompute-bao}"
SECRETS_DIR="${SECRETS_DIR:-./secrets}"
EDGE_HOST="${EDGE_HOST:-localhost}"
API_PORT="${EDGE_API_PORT:-8443}"; EVAL_PORT="${EDGE_EVALUATOR_PORT:-8444}"
OPS_PORT="${EDGE_OPS_PORT:-8445}"; KB_PORT="${EDGE_KEYBROKER_PORT:-8446}"
EDGE_CA="${EDGE_CA:-$SECRETS_DIR/edge-ca.crt}"
OPS_CERT="${OPS_CERT:-$SECRETS_DIR/ops-client.crt}"; OPS_KEY="${OPS_KEY:-$SECRETS_DIR/ops-client.key}"
export BAO_ADDR="${BAO_ADDR:-https://localhost:8200}"
export BAO_CACERT="${BAO_CACERT:-$SECRETS_DIR/bao-ca.crt}"
ORG="${KEYBROKER_ORG:-modelco}"
BACKUP_DIR=""; DRILL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --backup-dir) BACKUP_DIR="${2:?--backup-dir DIR}"; shift 2 ;;
    --drill) DRILL=1; shift ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "usage: $0 [--backup-dir DIR] [--drill]" >&2; exit 2 ;;
  esac
done

PASSES=0; FAILS=0; SKIPS=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/encompute-validate.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %-8s %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL  %-8s %s\n' "$1" "$2"; [ -z "${3:-}" ] || printf '%s\n' "$3" | head -n 6 | sed 's/^/                 /'; }
skip() { SKIPS=$((SKIPS + 1)); printf 'SKIP  %-8s %s\n' "$1" "$2"; }
section() { printf '\n[%s]\n' "$*"; }

# curl to the edge; prints the HTTP status ("000" when the connection failed).
edge_status() { # PORT PATH [curl args...]
  local port="$1" path="$2"; shift 2
  curl -s -o "$WORK/body" -w '%{http_code}' --max-time 15 "$@" "https://$EDGE_HOST:$port$path" 2>"$WORK/curl.err" || true
}
mtls=(--cacert "$EDGE_CA" --cert "$OPS_CERT" --key "$OPS_KEY")
cids_all() { d ps -aq --filter "label=com.docker.compose.project=$PROJECT"; }
psql_sock() { # run SQL in the postgres container over the local socket
  d exec -i "$PG" psql -U encompute -d encompute -tAq -c "$1" 2>&1
}

PG="$(cid postgres)"; CONTROL="$(cid control)"; TUN="$(cid pg-tunnel)"
ALL="$(cids_all)"

# -----------------------------------------------------------------------------
section "Topology"
if [ -z "$ALL" ]; then
  fail TOP-00 "no containers for project '$PROJECT': is the topology up?"
else
  bad=""
  for c in $ALL; do
    img="$(d inspect -f '{{.Config.Image}}' "$c")"
    case "$img" in *@sha256:*|encompute-tunnel:*) ;; *) bad="$bad $(d inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c")=$img" ;; esac
  done
  [ -z "$bad" ] && pass TOP-01 "every image is pinned by digest (the tunnel is built from a digest-pinned Dockerfile)" \
    || fail TOP-01 "images not pinned by digest:$bad"
  pub=""
  for c in $ALL; do
    p="$(d port "$c" 2>/dev/null)"
    [ -z "$p" ] || [ "$(d inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c")" = edge ] || pub="$pub $(d inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c")"
  done
  [ -z "$pub" ] && pass TOP-02 "only the edge publishes ports on the host" || fail TOP-02 "services publishing host ports besides the edge:$pub"
  nets="$(d network ls -q --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.network=backend")"
  if [ -z "$nets" ]; then fail TOP-03 "no 'backend' network found"
  elif [ "$(d network inspect -f '{{.Internal}}' $nets)" = true ]; then pass TOP-03 "the backend network is internal (no route out)"
  else fail TOP-03 "the backend network is not internal"; fi
fi

# -----------------------------------------------------------------------------
section "Edge: TLS and mutual TLS"
s="$(edge_status "$API_PORT" /live --cacert "$EDGE_CA")"
[ "$s" = 200 ] && pass EDGE-01 "API listener :$API_PORT serves TLS verified against the edge CA (GET /live 200)" \
  || fail EDGE-01 "API listener :$API_PORT over verified TLS: HTTP $s" "$(cat "$WORK/curl.err")"
s="$(curl -s -o "$WORK/body" -w '%{http_code}' --max-time 10 "http://$EDGE_HOST:$API_PORT/live" 2>/dev/null || true)"
if [ "$s" = 200 ] || grep -q '"live"' "$WORK/body" 2>/dev/null; then fail EDGE-02 "plaintext HTTP reaches the service on :$API_PORT (HTTP $s)"
else pass EDGE-02 "plaintext HTTP on :$API_PORT does not reach the service (HTTP $s)"; fi
protos=""; badp=""
for p in "$API_PORT" "$EVAL_PORT" "$OPS_PORT" "$KB_PORT"; do
  v="$(echo | openssl s_client -connect "$EDGE_HOST:$p" -servername "$EDGE_HOST" -CAfile "$EDGE_CA" 2>/dev/null | sed -n 's/^New, \(TLSv[0-9.]*\),.*/\1/p' | head -n 1)"
  case "$v" in TLSv1.2|TLSv1.3) protos="$protos $p=$v" ;; *) badp="$badp $p=${v:-none}" ;; esac
done
[ -z "$badp" ] && pass EDGE-03 "all four listeners negotiate TLS 1.2 or 1.3 ($protos )" || fail EDGE-03 "listeners without TLS 1.2+:$badp"
s="$(edge_status "$OPS_PORT" /control/live --cacert "$EDGE_CA")"
[ "$s" = 000 ] && pass EDGE-04 "ops listener :$OPS_PORT refuses a connection without a client certificate" \
  || fail EDGE-04 "ops listener :$OPS_PORT answered HTTP $s without a client certificate (mutual TLS not enforced)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/rogue.key" -out "$WORK/rogue.crt" \
  -subj "/CN=rogue" -days 1 >/dev/null 2>&1
s="$(edge_status "$OPS_PORT" /control/live --cacert "$EDGE_CA" --cert "$WORK/rogue.crt" --key "$WORK/rogue.key")"
[ "$s" = 000 ] && pass EDGE-05 "ops listener refuses a client certificate from an untrusted CA" \
  || fail EDGE-05 "ops listener answered HTTP $s to an untrusted client certificate"
s="$(edge_status "$KB_PORT" /live --cacert "$EDGE_CA")"
[ "$s" = 000 ] && pass EDGE-06 "key broker listener :$KB_PORT refuses a connection without a client certificate" \
  || fail EDGE-06 "key broker listener :$KB_PORT answered HTTP $s without a client certificate"
s="$(edge_status "$API_PORT" /metrics --cacert "$EDGE_CA")"
s2="$(edge_status "$OPS_PORT" /control/metrics "${mtls[@]}")"
if [ -r "$SECRETS_DIR/metrics-token" ]; then
  s3="$(edge_status "$OPS_PORT" /control/metrics "${mtls[@]}" -H "Authorization: Bearer $(cat "$SECRETS_DIR/metrics-token")")"
else s3="no-token-file"; fi
if [ "$s" = 404 ] && [ "$s2" = 401 ] && [ "$s3" = 200 ]; then
  pass EDGE-07 "/metrics: 404 on the API listener; on the ops listener 401 without the token, 200 with it"
else fail EDGE-07 "/metrics exposure: API listener $s (want 404), ops without token $s2 (want 401), with token $s3 (want 200)"; fi

# -----------------------------------------------------------------------------
section "PostgreSQL: TLS required"
if [ -z "$PG" ]; then
  fail PG-00 "no postgres container in project '$PROJECT'"
else
  out="$(psql_sock "select current_setting('ssl')||' '||current_setting('ssl_min_protocol_version')||' '||current_setting('password_encryption')")"
  case "$out" in
    "on TLSv1.2 scram-sha-256"|"on TLSv1.3 scram-sha-256") pass PG-01 "ssl=on, TLS >= 1.2, scram-sha-256 password hashing ($out)" ;;
    *) fail PG-01 "server settings (ssl, minimum TLS, password hashing): $out" ;;
  esac
  rules="$(psql_sock "select type||' '||auth_method from pg_hba_file_rules where error is null order by line_number")"
  weak="$(printf '%s\n' "$rules" | grep -E '^(host|hostnossl) ' | grep -vE ' (reject)$' || true)"
  weak="$weak$(printf '%s\n' "$rules" | grep -E ' (trust|md5|password)$' | grep -v '^local ' || true)"
  if [ -z "$rules" ]; then fail PG-02 "could not read pg_hba_file_rules" "$rules"
  elif [ -z "$weak" ]; then pass PG-02 "pg_hba admits network clients only over TLS: no plaintext 'host' rule that accepts, no trust/md5/password over the network"
  else fail PG-02 "pg_hba admits plaintext or weak network authentication:" "$weak"; fi
  pw_cmd='PGPASSWORD="$(cat /run/secrets/db-password 2>/dev/null)" PGCONNECT_TIMEOUT=5 psql -tAq -h 127.0.0.1 -U encompute -d encompute'
  out="$(d exec -i "$PG" sh -c "PGSSLMODE=disable $pw_cmd -c 'select 1' 2>&1" | tr '\n' ' ')"
  if printf '%s' "$out" | grep -qE '(^| )1( |$)'; then fail PG-03 "a plaintext TCP connection with the correct password succeeded"
  elif printf '%s' "$out" | grep -qiE 'no pg_hba.conf entry.*(no encryption|SSL off)|encryption'; then pass PG-03 "a plaintext TCP connection is refused (no pg_hba.conf entry ... no encryption)"
  else fail PG-03 "plaintext connection was not shown to be refused for the right reason:" "$out"; fi
  out="$(d exec -i "$PG" sh -c "PGSSLMODE=require $pw_cmd -c 'select 1' 2>&1" | tr '\n' ' ')"
  if printf '%s' "$out" | grep -qE '(^| )1( |$)'; then fail PG-04 "a TLS connection WITHOUT a client certificate succeeded"
  elif printf '%s' "$out" | grep -qiE 'certificate|connection requires a valid client'; then pass PG-04 "a TLS connection without a client certificate is refused"
  else fail PG-04 "TLS without a client certificate was not shown to be refused for the right reason:" "$out"; fi
  out="$(psql_sock "select count(*) filter (where s.ssl is not true), count(*) from pg_stat_activity a left join pg_stat_ssl s using (pid) where a.client_addr is not null")"
  if [ "$out" = "0|0" ]; then fail PG-05 "no network connection to inspect (is the control plane connected?)"
  elif [ "${out%%|*}" = 0 ]; then pass PG-05 "every network connection to the database uses TLS (${out#*|} connection(s) inspected)"
  else fail PG-05 "$out (non-TLS | total) network connections to the database"; fi
  if [ -r "$SECRETS_DIR/db-password" ]; then
    pw="$(cat "$SECRETS_DIR/db-password")"
    case "$pw" in postgres|password|encompute|changeme|admin|secret|test|encompute-test|"") w=1 ;; *) w=0 ;; esac
    if [ "$w" = 0 ] && [ "${#pw}" -ge 24 ]; then pass PG-06 "the database password is not a default and is ${#pw} characters"
    else fail PG-06 "the database password is a default or shorter than 24 characters"; fi
  else fail PG-06 "cannot read $SECRETS_DIR/db-password"; fi
  url=""; [ -r "$SECRETS_DIR/db-url" ] && url="$(cat "$SECRETS_DIR/db-url")"
  host="$(printf '%s' "$url" | sed -n 's|^[a-z]*://[^@]*@\([^:/?]*\).*|\1|p')"
  case "$host" in
    127.0.0.1|localhost)
      cfg=""; [ -n "$TUN" ] && cfg="$(d exec "$TUN" cat /etc/stunnel/pg.conf 2>/dev/null)"
      if printf '%s' "$cfg" | grep -qiE '^verifyChain *= *yes' && printf '%s' "$cfg" | grep -qiE '^checkHost *= *[a-z]' \
         && printf '%s' "$cfg" | grep -qiE '^CAfile *=' && ! printf '%s' "$cfg" | grep -qiE '^(verify *= *0|verifyPeer *= *no)'; then
        pass PG-07 "the control plane reaches PostgreSQL through a TLS client that verifies the server's chain and name (the verify-full equivalent)"
      else fail PG-07 "the connection string points at loopback but no TLS client that verifies chain AND name is in front of it" "$cfg"; fi ;;
    "") fail PG-07 "cannot read the database URL ($SECRETS_DIR/db-url)" ;;
    *) if printf '%s' "$url" | grep -q 'sslmode=verify-full'; then pass PG-07 "the connection string requires sslmode=verify-full"
       else fail PG-07 "the connection string reaches $host without sslmode=verify-full"; fi ;;
  esac
fi

# -----------------------------------------------------------------------------
section "OpenBao / Vault: external, TLS, not dev mode"
status=""
case "$BAO_ADDR" in
  https://*)
    status="$(curl -sS --max-time 10 --cacert "$BAO_CACERT" "$BAO_ADDR/v1/sys/seal-status" 2>"$WORK/bao.err")"
    if [ -n "$status" ]; then pass BAO-01 "$BAO_ADDR is https and answers with a certificate verified against $BAO_CACERT"
    else fail BAO-01 "no verified TLS answer from $BAO_ADDR" "$(cat "$WORK/bao.err")"; fi ;;
  *)
    status="$(curl -sS --max-time 10 "$BAO_ADDR/v1/sys/seal-status" 2>"$WORK/bao.err")"
    fail BAO-01 "the root-key provider address is not https ($BAO_ADDR)" ;;
esac
if [ -n "$status" ]; then
  plain="$(printf '%s' "$BAO_ADDR" | sed 's|^https://|http://|')"
  if curl -s --max-time 5 "$plain/v1/sys/seal-status" 2>/dev/null | grep -q '"initialized"'; then fail BAO-02 "plaintext HTTP is answered at $plain"
  else pass BAO-02 "plaintext HTTP to the provider's port is refused"; fi
  read -r init sealed stype <<<"$(printf '%s' "$status" | python3 -c 'import json,sys; v=json.load(sys.stdin); print(v.get("initialized"), v.get("sealed"), v.get("storage_type"))' 2>/dev/null)"
  [ "$init" = True ] && [ "$sealed" = False ] && pass BAO-03 "initialised and unsealed" || fail BAO-03 "initialised=$init sealed=$sealed"
  case "$stype" in
    inmem|"") fail BAO-04 "storage type '${stype:-unknown}': in-memory storage is development mode" ;;
    *) pass BAO-04 "persistent storage backend ($stype), not in-memory" ;;
  esac
else
  fail BAO-02 "no answer from the provider: cannot test plaintext refusal"
  fail BAO-03 "no answer from the provider: cannot read its seal status"
  fail BAO-04 "no answer from the provider: cannot read its storage type"
fi
devs=""
for c in $( { d ps -aq --filter "label=com.docker.compose.project=$PROJECT"; d ps -aq --filter "label=com.docker.compose.project=$BAO_PROJECT"; } | sort -u); do
  j="$(d inspect -f '{{.Config.Image}} {{.Path}} {{join .Args " "}} {{join .Config.Env " "}}' "$c")"
  if printf '%s' "$j" | grep -qE '(openbao|vault)' && printf '%s' "$j" | grep -qE -- '(^| )-dev( |$)|-dev-|(BAO|VAULT)_DEV_'; then
    devs="$devs $(d inspect -f '{{.Name}}' "$c")"
  fi
done
if [ -z "$devs" ]; then pass BAO-05 "no OpenBao/Vault container in dev mode (-dev, BAO_DEV_*) in the project or the reference vault project"
else fail BAO-05 "dev-mode OpenBao/Vault:$devs"; fi
if [ -r "$SECRETS_DIR/bao-token" ] && [ -n "$status" ]; then
  tok="$(cat "$SECRETS_DIR/bao-token")"
  info="$(BAO_TOKEN_VALUE="$tok" bao_api GET auth/token/lookup-self 2>/dev/null)"
  verdict="$(printf '%s' "$info" | python3 -c '
import json,sys
try: d=json.load(sys.stdin)["data"]
except Exception: print("unreadable"); sys.exit()
pol=sorted(d.get("policies",[]))
bad=[]
if "root" in pol: bad.append("root policy")
if pol!=["encompute-keybroker-'"$ORG"'"]: bad.append("policies "+",".join(pol))
if not d.get("renewable"): bad.append("not renewable")
if not d.get("period"): bad.append("not periodic")
print("ok" if not bad else "; ".join(bad))' 2>/dev/null)"
  if [ "$verdict" = ok ]; then pass BAO-06 "the key broker's token is periodic, renewable, and holds only encompute-keybroker-$ORG (no root)"
  else fail BAO-06 "the key broker's token: $verdict"; fi
else fail BAO-06 "cannot check the key broker's token (no $SECRETS_DIR/bao-token or no provider answer)"; fi

# -----------------------------------------------------------------------------
section "Secrets: files, never environment"
envbad=""; valbad=""
: > "$WORK/inspect.json"
for c in $ALL; do d inspect -f '{{json .Config.Env}} {{json .Config.Cmd}} {{json .Config.Entrypoint}}' "$c" >> "$WORK/inspect.json"; done
for c in $ALL; do
  svc="$(d inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c")"
  names="$(d inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" | sed 's/=.*//' | grep -iE 'PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE|_KEY' | grep -viE 'PUBLIC|_FILE$' || true)"
  [ -z "$names" ] || envbad="$envbad $svc:$(echo $names | tr ' ' ',')"
done
[ -z "$envbad" ] && pass SEC-01 "no secret-named environment variable (every secret is a *_FILE path)" || fail SEC-01 "secret-named environment variables:$envbad"
if [ -d "$SECRETS_DIR" ]; then
  for f in "$SECRETS_DIR"/*; do
    [ -f "$f" ] || continue
    case "$f" in *.crt|*.key.pub) continue ;; esac
    v="$(cat "$f" 2>/dev/null)"
    case "$(basename "$f")" in *.key) case "$v" in "-----BEGIN"*) continue ;; esac ;; esac   # PEM keys are files by nature; hex seeds are checked
    [ "${#v}" -ge 8 ] || continue
    if grep -qF -- "$v" "$WORK/inspect.json"; then valbad="$valbad $(basename "$f")"; fi
  done
  [ -z "$valbad" ] && pass SEC-02 "no secret value from $SECRETS_DIR appears in any container's environment or command line" \
    || fail SEC-02 "secret values found in container configuration:$valbad"
else fail SEC-02 "no secrets directory at $SECRETS_DIR to compare against"; fi
if [ -n "$CONTROL" ]; then
  m="$(d inspect -f '{{range .Mounts}}{{.Destination}} {{end}}' "$CONTROL")"
  case "$m" in *"/run/secrets/db-url"*"/run/secrets/control-key"*|*"/run/secrets/control-key"*"/run/secrets/db-url"*) pass SEC-03 "the control plane's secrets are mounted as files under /run/secrets" ;;
    *) fail SEC-03 "the control plane has no /run/secrets mounts for db-url and control-key (mounts: $m)" ;; esac
  # And it must be told so: *_FILE variables, production mode.
  e="$(d inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CONTROL")"
  if printf '%s\n' "$e" | grep -q '^ENCOMPUTE_ENV=production$' && printf '%s\n' "$e" | grep -q '^ENCOMPUTE_DATABASE_URL_FILE=' \
     && printf '%s\n' "$e" | grep -q '^ENCOMPUTE_SIGNING_KEY_FILE=' && ! printf '%s\n' "$e" | grep -q '^ENCOMPUTE_DEV_TOKEN_SECRET'; then
    pass SEC-04 "the control plane runs in production mode with *_FILE secrets and no development token secret"
  else fail SEC-04 "the control plane is not configured for production mode with *_FILE secrets"; fi
else fail SEC-03 "no control container"; fi
if [ -d "$SECRETS_DIR" ]; then
  mode="$(stat -c '%a' "$SECRETS_DIR" 2>/dev/null || stat -f '%Lp' "$SECRETS_DIR")"
  [ "$mode" = 700 ] && pass SEC-05 "$SECRETS_DIR is mode 0700" || fail SEC-05 "$SECRETS_DIR is mode $mode (want 700)"
fi
if git rev-parse --git-dir >/dev/null 2>&1; then
  tracked="$(git ls-files . | grep -E '(^|/)(secrets|oidc|oidc-lab)/|\.env$|\.pem$|\.key$' || true)"
  if [ -z "$tracked" ] && { [ ! -d "$SECRETS_DIR" ] || git check-ignore -q "$SECRETS_DIR/x" 2>/dev/null; }; then pass SEC-06 "no secret or private key is tracked in git, and $SECRETS_DIR is ignored"
  else fail SEC-06 "tracked secret-like files, or $SECRETS_DIR is not git-ignored:" "$tracked"; fi
else skip SEC-06 "not inside a git checkout"; fi

# -----------------------------------------------------------------------------
section "Health: every service has a check, and it is green"
nohc=""; unhealthy=""; n=0
for c in $ALL; do
  svc="$(d inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c")"
  h="$(d inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c")"
  n=$((n + 1))
  case "$h" in none) nohc="$nohc $svc" ;; healthy) ;; *) unhealthy="$unhealthy $svc=$h" ;; esac
done
[ -z "$nohc" ] && [ "$n" -gt 0 ] && pass HLTH-01 "all $n services define a health check" || fail HLTH-01 "services without a health check:${nohc:- (no containers)}"
[ -z "$unhealthy" ] && [ "$n" -gt 0 ] && pass HLTH-02 "all $n services report healthy" || fail HLTH-02 "services not healthy:${unhealthy:- (no containers)}"
miss=""
for ep in /control/live /control/ready /evaluator/v1/info /keybroker/live; do
  s="$(edge_status "$OPS_PORT" "$ep" "${mtls[@]}")"; [ "$s" = 200 ] || miss="$miss $ep=$s"
done
s="$(edge_status "$EVAL_PORT" /v1/info --cacert "$EDGE_CA")"; [ "$s" = 200 ] || miss="$miss :$EVAL_PORT/v1/info=$s"
s="$(edge_status "$KB_PORT" /live "${mtls[@]}")"; [ "$s" = 200 ] || miss="$miss :$KB_PORT/live=$s"
[ -z "$miss" ] && pass HLTH-03 "readiness and liveness answer 200 for the control plane, evaluator and key broker, through the edge" \
  || fail HLTH-03 "endpoints not answering 200 through the edge:$miss"

# -----------------------------------------------------------------------------
section "Backup"
if [ -n "$BACKUP_DIR" ]; then
  if out="$(COMPOSE_PROJECT_NAME="$PROJECT" ./backup.sh --verify "$BACKUP_DIR" 2>&1)"; then pass BAK-01 "backup $BACKUP_DIR verifies: checksums match and the dump restores into a scratch database"
  else fail BAK-01 "backup $BACKUP_DIR does not verify" "$out"; fi
else skip BAK-01 "no --backup-dir given (take one with ./backup.sh DIR)"; fi
if [ "$DRILL" = 1 ]; then
  if out="$(COMPOSE_PROJECT_NAME="$PROJECT" ../../scripts/release/backup-drill.sh --production 2>&1)"; then
    pass BAK-02 "backup and restore drill passed ($(printf '%s\n' "$out" | tail -n 1))"
  else fail BAK-02 "backup and restore drill failed" "$(printf '%s\n' "$out" | tail -n 8)"; fi
else skip BAK-02 "backup drill not run (destructive: rerun with --drill on a staging copy)"; fi

# -----------------------------------------------------------------------------
echo
if [ "$FAILS" -eq 0 ] && [ "$PASSES" -gt 0 ]; then
  echo "DEPLOYMENT VALIDATION: PASS ($PASSES checks passed, $SKIPS skipped)"
  echo "This is a configuration check, not a security assessment."
  exit 0
fi
echo "DEPLOYMENT VALIDATION: FAIL ($FAILS failed, $PASSES passed, $SKIPS skipped)"
exit 1
