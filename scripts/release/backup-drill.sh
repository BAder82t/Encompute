#!/usr/bin/env bash
# Backup and restore drill: proves that a backup of a running deployment
# restores to the same privacy, revocation, trust and audit state, and that
# an OLDER backup restored over a NEWER state anchor is refused.
#
#   scripts/release/backup-drill.sh             local services (default)
#   scripts/release/backup-drill.sh --compose   deploy/docker-compose (smoke,
#                                               backup.sh, restore.sh)
#   scripts/release/backup-drill.sh --production  a RUNNING deploy/production
#                                               topology (see production_drill)
#
# Prints one PASS/FAIL line per check, then a final PASS/FAIL line, and exits
# non-zero if any check failed.
#
# LOCAL MODE (no Docker Compose). Runs, as separate processes, the control
# plane (encompute-control serve), an OpenFHE evaluator (encompute-evaluator)
# and a key broker (encompute keys serve) whose KEK is wrapped by an OpenBao
# Transit root key, against:
#   ENCOMPUTE_TEST_DATABASE_URL  a PostgreSQL account that may CREATE DATABASE
#                                (default postgres://encompute:encompute-test@127.0.0.1:55432/encompute).
#                                The drill creates its own database and drops it.
#   ENCOMPUTE_TEST_BAO_ADDR      OpenBao/Vault with Transit (default http://127.0.0.1:58200)
#   ENCOMPUTE_TEST_BAO_TOKEN     its token (default dev-root)
# pg_dump/psql: local ones if on PATH (or $PG_DUMP/$PSQL), else run inside the
# PostgreSQL container ENCOMPUTE_PG_CONTAINER (default enc-pg).
# Binaries: target/debug, built here with OpenFHE (OPENFHE_ROOT, default
# .deps/openfhe); override with ENCOMPUTE_CONTROL_BIN, ENCOMPUTE_CLI_BIN,
# ENCOMPUTE_EVALUATOR_BIN, or skip the build with ENCOMPUTE_DRILL_NO_BUILD=1.
# KEEP=1 keeps the work directory and the database for inspection.
#
# What is state, and where it lives (as in deploy/docker-compose):
#   database   PostgreSQL: tenants, projects, assets, plans, jobs, privacy
#              ledgers, trust evidence, the audit chain
#   anchor     the state anchor directory (signed privacy-ledger and audit
#              roots), deliberately OUTSIDE the database
#   broker     the key broker's broker.json (wrapped asset keys, destroyed
#              keys) and kek.wrapped.json (the KEK wrapped by the KMS root key)
#   evaluator  the evaluator's receipt-signing identity
# Secrets (the control plane's signing key, service identity keys, the KMS
# token) are NOT in a backup: they live in the secret manager and survive a
# disaster, like ./secrets in the Compose deployment. The KMS root key never
# leaves OpenBao.
#
# The two restore cases, and why the anchor is handled differently:
#   * FULL DISASTER: database, anchor, broker and evaluator volumes are all
#     lost. The anchor directory is empty, so it is restored from the backup,
#     together with the database. Database and anchor come from the same
#     backup, so the database extends the anchor and the control plane starts.
#     Without the anchor, startup is refused (ANCHOR STATE ROLLBACK).
#   * DATABASE LOSS ONLY (or an operator restoring an old dump): the anchor
#     survives and is AUTHORITATIVE; restore.sh never overwrites a non-empty
#     anchor. If the restored database is older than the anchor (spending
#     happened after the backup), the control plane refuses to start with
#     PRIVACY STATE ROLLBACK until `encompute-control recover` freezes the
#     rolled-back ledgers (treated as exhausted, so forgotten spending can
#     never be spent again).
#   Consequence (a residual risk, by design): in a full disaster, spending
#   after the newest backup is forgotten together with its anchor, and cannot
#   be detected. Keep the anchor in the customer's vault
#   (ENCOMPUTE_ANCHOR_BAO_ADDR) so it survives the loss of the deployment.
#
# Backup ORDER matters: the anchor is captured BEFORE the database dump. A
# database that is ahead of the anchor is valid (every spend commits to the
# database before it is anchored); an anchor ahead of the database is a
# rollback. The drill spends privacy budget between the two captures of its
# first backup to prove that a live backup restores.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODE=local
case "${1:-}" in
  "") ;;
  --compose) MODE=compose ;;
  --production) MODE=production ;;
  -h|--help) sed -n '2,72p' "$0"; exit 0 ;;
  *) echo "usage: $0 [--compose | --production]" >&2; exit 2 ;;
esac
PY="${TOOL_PYTHON:-python3}"

# --- reporting -----------------------------------------------------------------
PASSES=0
FAILS=0
FAILED=()
step() { printf '\n== %s\n' "$*"; }
pass() { PASSES=$((PASSES + 1)); printf 'PASS  %s\n' "$*"; }
fail_check() { FAILS=$((FAILS + 1)); FAILED+=("$*"); printf 'FAIL  %s\n' "$*"; }
# check NAME COMMAND...: PASS if the command succeeds.
check() {
  local name="$1"; shift
  if "$@"; then pass "$name"; else fail_check "$name"; fi
}
# eq GOT WANT: equal, or explain.
eq() {
  [ "$1" = "$2" ] && return 0
  printf '      want: %s\n      got:  %s\n' "$2" "$1" | cut -c1-400
  return 1
}
contains() { # contains FILE PATTERN
  grep -q -- "$2" "$1" && return 0
  printf '      %s does not contain %s\n' "$(basename "$1")" "$2"
  return 1
}
summary() {
  echo
  if [ "$FAILS" -eq 0 ] && [ "$PASSES" -gt 0 ]; then
    echo "BACKUP DRILL ($MODE): PASS ($PASSES checks)"
    return 0
  fi
  echo "BACKUP DRILL ($MODE): FAIL ($FAILS of $((PASSES + FAILS)) checks failed)"
  local f; for f in "${FAILED[@]:-}"; do [ -n "$f" ] && echo "  failed: $f"; done
  return 1
}
jget() { "$PY" -c "import json,sys; v=json.load(sys.stdin); print($1)"; }
canon() { "$PY" -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))'; }
rand() { "$PY" -c 'import secrets; print(secrets.token_hex(16))'; }
free_port() { "$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
sha() { shasum -a 256 "$@"; }
is_empty_dir() { [ -z "$(ls -A "$1" 2>/dev/null)" ]; }
reserve_body() { # reserve_body EVENT_ID
  printf '{"kind":"reserve","event_id":"%s","policy_id":null,"execution_spec_id":null,"round_id":null,"output":"update","mechanism":{"kind":"discrete_gaussian","clip_norm":"1.0","noise_multiplier":"1000.0"},"sensitivity":2,"sigma2":800,"vector_len":1,"rng":"csprng"}' "$1"
}
commit_body() { # commit_body EVENT_ID
  printf '{"kind":"commit","event_id":"%s","output_commitment":"%s"}' "$1" "$(printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1)"
}

# =============================================================================
# COMPOSE MODE: deploy/docker-compose/{smoke,backup,restore}.sh
# =============================================================================
compose_drill() {
  local D="$ROOT/deploy/docker-compose" W
  if ! docker compose version >/dev/null 2>&1; then
    echo "SKIP  Docker Compose is not available"; echo "BACKUP DRILL (compose): SKIPPED"; exit 0
  fi
  local img
  for img in encompute-control encompute-evaluator encompute-services; do
    if ! docker image inspect "$img:${ENCOMPUTE_VERSION:-dev}" >/dev/null 2>&1; then
      echo "SKIP  image $img:${ENCOMPUTE_VERSION:-dev} is not built (see deploy/docker-compose/README.md)"
      echo "BACKUP DRILL (compose): SKIPPED"; exit 0
    fi
  done
  # smoke.sh's client: an `encompute` built with OpenFHE (E), and the SDK's
  # Python (SDK_PYTHON) to compile the example.
  export E="${E:-$ROOT/target/release/encompute}"
  if [ ! -x "$E" ]; then
    echo "SKIP  no OpenFHE client at $E (set E, see deploy/docker-compose/smoke.sh)"
    echo "BACKUP DRILL (compose): SKIPPED"; exit 0
  fi
  W="$(mktemp -d "${TMPDIR:-/tmp}/encompute-drill.XXXXXX")"
  # shellcheck disable=SC2064
  trap "[ \"\${KEEP:-}\" = 1 ] || (cd '$D' && docker compose down -v >/dev/null 2>&1) || true; rm -rf '$W'" EXIT
  local ISS="https://idp.compose.test.invalid"
  tok() { (cd "$D" && "$PY" "$ROOT/scripts/test-idp.py" token oidc "$1" --iss "$ISS"); }
  capi() { # WHO METHOD PATH [BODY]: prints the status; the body goes to $W/body
    local args=(-sS -o "$W/body" -w '%{http_code}' -X "$2" -H "Authorization: Bearer $(tok "$1")")
    if [ -n "${4:-}" ]; then args+=(-H 'Content-Type: application/json' -d "$4"); fi
    curl "${args[@]}" "http://127.0.0.1:8770$3"
  }

  step "compose smoke: golden path, restart, backup.sh, full teardown, restore.sh, revocation"
  if (cd "$D" && KEEP=1 ./smoke.sh) >"$W/smoke.log" 2>&1; then
    pass "compose smoke (backup.sh / destroy / restore.sh: projects, jobs, trust, privacy spend intact)"
  else
    tail -n 30 "$W/smoke.log"; fail_check "compose smoke"; summary; exit 1
  fi

  step "compose: an older backup over a newer anchor is refused; recover freezes"
  local DATASET SPENT_B1
  capi a-owner GET /v1/assets >/dev/null
  DATASET="$(jget '[a["id"] for a in v if a["kind"]=="dataset"][0]' < "$W/body")"
  capi a-owner GET "/v1/privacy/$DATASET" >/dev/null
  SPENT_B1="$(jget 'v["spent"]["epsilon"]' < "$W/body")"
  (cd "$D" && ./backup.sh "$W/b1") >/dev/null
  check "compose backup has database, anchor, broker, evaluator and checksums" \
    test -s "$W/b1/db.sql" -a -s "$W/b1/anchor.tar" -a -s "$W/b1/broker.tar" -a -s "$W/b1/SHA256SUMS"
  eq "$(capi a-owner POST "/v1/privacy/$DATASET/events" "$(reserve_body drill-after-backup)")" 200 \
    || fail_check "compose spend after the backup"
  (cd "$D" && ./restore.sh "$W/b1") >"$W/restore.log" 2>&1 || true
  check "compose restore.sh keeps the newer anchor" contains "$W/restore.log" "anchor kept"
  check "compose restore.sh keeps the existing key broker state" contains "$W/restore.log" "broker kept"
  local running=1
  for _ in $(seq 60); do
    running="$(cd "$D" && docker compose ps --status running -q control | wc -l | tr -d ' ')"
    [ "$running" = 0 ] && break; sleep 1
  done
  (cd "$D" && docker compose logs control) >"$W/control.log" 2>&1 || true
  check "compose control plane refuses to start (not running)" eq "$running" 0
  check "compose refusal names PRIVACY STATE ROLLBACK" contains "$W/control.log" "PRIVACY STATE ROLLBACK"
  (cd "$D" && docker compose run --rm -T control recover --operator drill-operator) >"$W/recover.log" 2>&1 || true
  check "compose recover freezes the rolled-back ledger" contains "$W/recover.log" "RECOVERED"
  (cd "$D" && docker compose up -d control) >/dev/null 2>&1
  for _ in $(seq 150); do curl -fs http://127.0.0.1:8770/ready >/dev/null 2>&1 && break; sleep 0.4; done
  capi a-owner GET "/v1/privacy/$DATASET" >/dev/null || true
  check "compose privacy view shows the ledger frozen" eq "$(jget 'v["frozen"] is not None' < "$W/body")" True
  check "compose spent epsilon is the backup's (rolled back, frozen)" eq "$(jget 'v["spent"]["epsilon"]' < "$W/body")" "$SPENT_B1"
  local s
  s="$(capi a-owner POST "/v1/privacy/$DATASET/events" "$(reserve_body drill-after-recovery)")"
  check "compose spend on the frozen ledger refused (409 ENC2201)" \
    eq "$s $(jget 'v.get("code")' < "$W/body")" "409 ENC2201"
  summary
}

if [ "$MODE" = compose ]; then
  compose_drill
  exit $?
fi

# =============================================================================
# PRODUCTION MODE: a running deploy/production topology
# =============================================================================
# The same two cases as compose mode, against the reference production
# topology (TLS edge, TLS-only PostgreSQL, external OpenBao). DESTRUCTIVE: it
# destroys the topology's containers and volumes and restores them from its
# own backup, so run it on a laboratory or staging copy. Needs the topology up
# (deploy/production/lab-up.sh, or your own with a throwaway identity provider:
# DRILL_OIDC_DIR holds idp.pem and the control plane trusts its jwks.json, and
# DRILL_OIDC_ISSUER names it), and the external OpenBao unsealed.
#   COMPOSE_PROJECT_NAME  the project (default encompute-prod)
#   EDGE_API_PORT         the edge's API port (default 8443)
#   DRILL_OIDC_DIR        default deploy/production/oidc-lab
#   DRILL_OIDC_ISSUER     default https://idp.lab.test.invalid
# Steps: state is created through the TLS edge; backup.sh; a spend after the
# backup; FULL DISASTER (every container and volume of the stack is removed)
# and restore.sh; the state is the backup's and the key broker opens its wrapped
# KEK through OpenBao again; then an OLDER backup over a NEWER anchor is refused
# and `recover` freezes the ledger.
production_drill() {
  local D="$ROOT/deploy/production" W
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-encompute-prod}"
  local P="$COMPOSE_PROJECT_NAME" PORT="${EDGE_API_PORT:-8443}"
  local OIDC="${DRILL_OIDC_DIR:-$D/oidc-lab}" ISS="${DRILL_OIDC_ISSUER:-https://idp.lab.test.invalid}"
  local CA="$D/secrets/edge-ca.crt"
  dc() { (cd "$D" && perl -e 'alarm 240; exec @ARGV' docker compose -p "$P" "$@"); }
  if ! docker compose version >/dev/null 2>&1; then
    echo "SKIP  Docker Compose is not available"; echo "BACKUP DRILL (production): SKIPPED"; exit 0
  fi
  if [ ! -s "$OIDC/idp.pem" ] || [ ! -s "$CA" ]; then
    echo "SKIP  no running deploy/production lab topology (no $OIDC/idp.pem or $CA): run deploy/production/lab-up.sh"
    echo "BACKUP DRILL (production): SKIPPED"; exit 0
  fi
  W="$(mktemp -d "${TMPDIR:-/tmp}/encompute-drill.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$W'" EXIT
  tok() { "$PY" "$ROOT/scripts/test-idp.py" token "$OIDC" "$1" --iss "$ISS"; }
  capi() { # WHO METHOD PATH [BODY]: prints the status; the body goes to $W/body
    local args=(-sS --cacert "$CA" -o "$W/body" -w '%{http_code}' -X "$2" -H "Authorization: Bearer $(tok "$1")")
    if [ -n "${4:-}" ]; then args+=(-H 'Content-Type: application/json' -d "$4"); fi
    curl "${args[@]}" "https://localhost:$PORT$3"
  }
  wait_ready() { for _ in $(seq 150); do curl -fs --cacert "$CA" "https://localhost:$PORT/ready" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
  local RUN ORG DATASET SPENT_B1 s
  RUN="$(rand)"; ORG="drill-$RUN"

  step "production: state through the TLS edge"
  wait_ready || { fail_check "the topology's edge does not answer /ready on :$PORT"; summary; exit 1; }
  s="$(capi platform-admin POST /v1/organizations "{\"id\":\"$ORG\",\"display_name\":\"Drill $RUN\",\"admin\":{\"issuer\":\"$ISS\",\"subject\":\"admin-$RUN\"}}")"
  check "organization created through the edge (201)" eq "$s" 201
  capi "admin-$RUN" POST "/v1/organizations/$ORG/users" "{\"issuer\":\"$ISS\",\"subject\":\"owner-$RUN\",\"roles\":[\"data_owner\",\"auditor\"]}" >/dev/null
  s="$(capi "owner-$RUN" POST /v1/assets "{\"organization\":\"$ORG\",\"kind\":\"dataset\",\"name\":\"patients\",\"digest\":\"$(printf 'c%.0s' $(seq 64))\",\"privacy_budget\":{\"unit\":\"patient\",\"epsilon\":\"3.0\",\"delta\":\"1e-6\"}}")"
  check "dataset with a privacy budget created (201)" eq "$s" 201
  DATASET="$(jget 'v["id"]' < "$W/body")"
  eq "$(capi "owner-$RUN" POST "/v1/privacy/$DATASET/events" "$(reserve_body "drill-before-$RUN")")" 200 || fail_check "spend before the backup"
  capi "owner-$RUN" GET "/v1/privacy/$DATASET" >/dev/null
  SPENT_B1="$(jget 'v["spent"]["epsilon"]' < "$W/body")"

  step "production: backup, verify, spend after the backup"
  (cd "$D" && ./backup.sh "$W/b1") >/dev/null
  check "backup has database, anchor, broker, evaluator and checksums" \
    test -s "$W/b1/db.sql" -a -s "$W/b1/anchor.tar" -a -s "$W/b1/broker.tar" -a -s "$W/b1/evaluator.tar" -a -s "$W/b1/SHA256SUMS"
  check "backup.sh --verify: checksums, archives, dump restores into a scratch database" \
    bash -c "cd '$D' && ./backup.sh --verify '$W/b1' >/dev/null"
  local f
  for f in control.key evaluator.key db-password metrics-token bao-token; do cat "$D/secrets/$f"; echo; done | sed '/^$/d' > "$W/secret-values"
  check "the backup holds no secret value (signing keys, password, tokens)" \
    bash -c "! grep -qF -f '$W/secret-values' '$W/b1/db.sql' '$W/b1/anchor.tar' '$W/b1/broker.tar' '$W/b1/evaluator.tar'"
  eq "$(capi "owner-$RUN" POST "/v1/privacy/$DATASET/events" "$(reserve_body "drill-after-$RUN")")" 200 || fail_check "spend after the backup"

  step "production: full disaster (every container and volume removed), restore.sh"
  dc rm -sfv edge control evaluator keybroker postgres >/dev/null 2>&1 || true
  docker volume rm "${P}_pgdata" "${P}_anchor" "${P}_broker" "${P}_evaluator" >/dev/null 2>&1 || true
  check "volumes are gone before the restore" bash -c "! docker volume ls -q | grep -q '^${P}_\(pgdata\|anchor\|broker\|evaluator\)\$'"
  (cd "$D" && ./restore.sh "$W/b1") >"$W/restore1.log" 2>&1 || { tail -n 15 "$W/restore1.log"; fail_check "restore.sh"; }
  check "restore.sh restored the anchor into the empty volume" contains "$W/restore1.log" "anchor restored"
  check "restore.sh restored the key broker state into the empty volume" contains "$W/restore1.log" "broker restored"
  check "the control plane is ready again through the edge" wait_ready
  s="$(capi "admin-$RUN" GET "/v1/organizations/$ORG")"
  check "the organization survived the disaster (200)" eq "$s" 200
  capi "owner-$RUN" GET "/v1/privacy/$DATASET" >/dev/null || true
  check "privacy spending is the backup's (spending after it is forgotten, as documented)" \
    eq "$(jget 'v["spent"]["epsilon"]' < "$W/body")" "$SPENT_B1"
  dc up -d >/dev/null 2>&1 || true
  local healthy=0
  for _ in $(seq 120); do
    healthy="$(dc ps --format '{{.Health}}' 2>/dev/null | grep -c '^healthy$')"
    [ "$healthy" = 5 ] && break; sleep 1
  done
  check "all 5 services are healthy again, the key broker having opened its wrapped KEK through OpenBao" eq "$healthy" 5

  step "production: an older backup over a newer anchor is refused; recover freezes"
  eq "$(capi "owner-$RUN" POST "/v1/privacy/$DATASET/events" "$(reserve_body "drill-newer-$RUN")")" 200 || fail_check "spend before the old restore"
  (cd "$D" && ./restore.sh "$W/b1") >"$W/restore2.log" 2>&1 || true
  check "restore.sh keeps the newer anchor" contains "$W/restore2.log" "anchor kept"
  check "restore.sh keeps the existing key broker state" contains "$W/restore2.log" "broker kept"
  local refused=0
  for _ in $(seq 60); do
    dc logs control 2>&1 | grep -q "PRIVACY STATE ROLLBACK" && { refused=1; break; }; sleep 1
  done
  check "the control plane refuses to start and names PRIVACY STATE ROLLBACK" eq "$refused" 1
  check "the edge does not report the control plane ready" bash -c "! curl -fs --cacert '$CA' https://localhost:$PORT/ready >/dev/null 2>&1"
  dc stop control >/dev/null 2>&1 || true
  dc run --rm -T --no-deps control recover --operator drill-operator >"$W/recover.log" 2>&1 || true
  check "recover freezes the rolled-back ledger" contains "$W/recover.log" "RECOVERED"
  dc up -d control edge >/dev/null 2>&1 || true
  wait_ready || true
  capi "owner-$RUN" GET "/v1/privacy/$DATASET" >/dev/null || true
  check "privacy view shows the ledger frozen" eq "$(jget 'v["frozen"] is not None' < "$W/body")" True
  s="$(capi "owner-$RUN" POST "/v1/privacy/$DATASET/events" "$(reserve_body "drill-after-recovery-$RUN")")"
  check "spend on the frozen ledger refused (409 ENC2201)" eq "$s $(jget 'v.get("code")' < "$W/body")" "409 ENC2201"
  # Leave the topology as it was found: every service up and healthy.
  dc up -d >/dev/null 2>&1 || true
  for _ in $(seq 120); do
    healthy="$(dc ps --format '{{.Health}}' 2>/dev/null | grep -c '^healthy$')"
    [ "$healthy" = 5 ] && break; sleep 1
  done
  check "all 5 services are healthy after recovery" eq "$healthy" 5
  summary
}

if [ "$MODE" = production ]; then
  production_drill
  exit $?
fi

# =============================================================================
# LOCAL MODE
# =============================================================================
# The drill always starts from an empty database, migrated by the real
# binaries, and restores through the real pg_dump/psql path: it never uses the
# test template databases (ENCOMPUTE_TEST_DB_MODE), which are for `cargo test`.
ADMIN_URL="${ENCOMPUTE_TEST_DATABASE_URL:-postgres://encompute:encompute-test@127.0.0.1:55432/encompute}"
BAO_ADDR="${ENCOMPUTE_TEST_BAO_ADDR:-http://127.0.0.1:58200}"
BAO_TOKEN="${ENCOMPUTE_TEST_BAO_TOKEN:-dev-root}"
PG_CONTAINER="${ENCOMPUTE_PG_CONTAINER:-enc-pg}"
PG_CONTAINER_PORT="${ENCOMPUTE_PG_CONTAINER_PORT:-5432}"
BIN="$ROOT/target/debug"
CTL="${ENCOMPUTE_CONTROL_BIN:-$BIN/encompute-control}"
E="${ENCOMPUTE_CLI_BIN:-$BIN/encompute}"
EVAL="${ENCOMPUTE_EVALUATOR_BIN:-$BIN/encompute-evaluator}"

# The URL's parts (postgres://USER:PASS@HOST:PORT/DB).
case "$ADMIN_URL" in postgres://*|postgresql://*) ;; *) echo "ENCOMPUTE_TEST_DATABASE_URL must be a postgres:// URL" >&2; exit 2 ;; esac
_rest="${ADMIN_URL#*://}"
_creds="${_rest%%@*}"
PGUSER_="${_creds%%:*}"
PGPASS_="${_creds#*:}"
_hostdb="${_rest#*@}"
ADMIN_DB="${_hostdb#*/}"; ADMIN_DB="${ADMIN_DB%%\?*}"
URL_BASE="${ADMIN_URL%/*}"
db_url() { printf '%s/%s' "$URL_BASE" "$1"; }

if [ -n "${PSQL:-}" ] || { command -v psql >/dev/null 2>&1 && command -v pg_dump >/dev/null 2>&1; }; then
  PSQL_BIN="${PSQL:-psql}"; PG_DUMP_BIN="${PG_DUMP:-pg_dump}"
  psql_db() { local db="$1"; shift; "$PSQL_BIN" -X -q -v ON_ERROR_STOP=1 "$@" "$(db_url "$db")"; }
  pg_dump_db() { "$PG_DUMP_BIN" --clean --if-exists "$(db_url "$1")"; }
  PG_TOOLS="local psql/pg_dump"
else
  docker inspect "$PG_CONTAINER" >/dev/null 2>&1 \
    || { echo "no local psql/pg_dump and no container $PG_CONTAINER (set ENCOMPUTE_PG_CONTAINER)" >&2; exit 2; }
  psql_db() {
    local db="$1"; shift
    docker exec -i -e PGPASSWORD="$PGPASS_" "$PG_CONTAINER" \
      psql -X -q -v ON_ERROR_STOP=1 -h 127.0.0.1 -p "$PG_CONTAINER_PORT" -U "$PGUSER_" "$@" -d "$db"
  }
  pg_dump_db() {
    docker exec -i -e PGPASSWORD="$PGPASS_" "$PG_CONTAINER" \
      pg_dump --clean --if-exists -h 127.0.0.1 -p "$PG_CONTAINER_PORT" -U "$PGUSER_" -d "$1"
  }
  PG_TOOLS="psql/pg_dump in container $PG_CONTAINER"
fi
sql() { psql_db "$ADMIN_DB" -tA -c "$1"; }        # on the admin database
sql_in() { psql_db "$DB" -tA -c "$1"; }           # on the drill's database

TAG="drill_$(rand | cut -c1-10)"
DB="enc_$TAG"
DB_URL="$(db_url "$DB")"
W="$(mktemp -d "${TMPDIR:-/tmp}/encompute-drill.XXXXXX")"
LIVE="$W/live"           # the deployment's volumes (destroyed in the drill)
SECRETS="$W/secrets"     # the secret manager (survives)
BACKUPS="$W/backups"
LOGS="$W/logs"
mkdir -p "$LIVE/anchor" "$LIVE/broker" "$LIVE/evaluator" "$SECRETS" "$BACKUPS" "$LOGS" "$W/tok"
chmod 700 "$SECRETS"
PIDS=()
CTL_PID=""; EVAL_PID=""; KB_PID=""
DB_CREATED=0
cleanup() {
  local rc=$?
  local p
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ "${KEEP:-}" = 1 ]; then
    echo "KEEP=1: work directory $W, database $DB"
  else
    if [ "$DB_CREATED" = 1 ]; then
      sql "DROP DATABASE IF EXISTS $DB WITH (FORCE)" >/dev/null 2>&1 || true
    fi
    rm -rf "$W"
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
# Fatal: also from inside $(...), so everything goes to stderr.
die() {
  {
    fail_check "$*"
    local l
    for l in "$LOGS"/*.log; do [ -f "$l" ] && { echo "--- $(basename "$l")"; tail -n 12 "$l"; }; done
    summary || true
  } >&2
  exit 1
}

# --- binaries -------------------------------------------------------------------
step "binaries (OpenFHE build), database and KMS"
if [ "${ENCOMPUTE_DRILL_NO_BUILD:-}" != 1 ]; then
  export OPENFHE_ROOT="${OPENFHE_ROOT:-$ROOT/.deps/openfhe}"
  [ -d "$OPENFHE_ROOT" ] || die "OpenFHE not found at $OPENFHE_ROOT (scripts/install-openfhe.sh, or set OPENFHE_ROOT): the evaluator and the client need it"
  (cd "$ROOT" && cargo build -q -p encompute-control -p encompute-cli -p encompute-evaluator \
     --features encompute-cli/openfhe,encompute-evaluator/openfhe) || die "cargo build"
fi
for b in "$CTL" "$E" "$EVAL"; do [ -x "$b" ] || die "missing binary $b"; done
echo "binaries: $CTL, $E, $EVAL"
echo "database: $(db_url "$DB" | sed 's#//[^@]*@#//***@#') via $PG_TOOLS"

sql "CREATE DATABASE $DB" >/dev/null || die "cannot create database $DB (ENCOMPUTE_TEST_DATABASE_URL must allow CREATE DATABASE)"
DB_CREATED=1
# The KMS: a Transit root key for modelco's key broker.
bao() { curl -fsS -H "X-Vault-Token: $BAO_TOKEN" "$@"; }
BAO_OK=0
if curl -fs "$BAO_ADDR/v1/sys/health" >/dev/null 2>&1; then
  bao -X POST -d '{"type":"transit"}' "$BAO_ADDR/v1/sys/mounts/transit" >/dev/null 2>&1 || true
  bao -X POST "$BAO_ADDR/v1/transit/keys/$TAG-modelco" >/dev/null && BAO_OK=1
fi
[ "$BAO_OK" = 1 ] || info "OpenBao at $BAO_ADDR unavailable: the key broker part of the drill is skipped"
printf '%s' "$BAO_TOKEN" > "$SECRETS/bao-token"
printf '%s' "$DB_URL" > "$SECRETS/db-url"
for k in control evaluator keybroker; do "$PY" -c 'import secrets; print(secrets.token_hex(32))' > "$SECRETS/$k.key"; done
chmod 600 "$SECRETS/"*
DEV_SECRET="$(rand)"
# The attestation provider's keys the broker trusts (a throwaway one: no key
# is released in this drill).
"$PY" "$ROOT/scripts/test-idp.py" keygen "$W/idp" >/dev/null || die "test-idp.py keygen (needs python3 with cryptography)"
chmod 600 "$SECRETS"/*

CTL_PORT="$(free_port)"; EVAL_PORT="$(free_port)"; KB_PORT="$(free_port)"
CTL_URL="http://127.0.0.1:$CTL_PORT"
N_START=0
# Development mode (development tokens) with production-shaped state: a
# signing key from the secret store, the anchor in its own directory.
control_env() {
  exec env ENCOMPUTE_ENV=development \
    ENCOMPUTE_LISTEN="127.0.0.1:$CTL_PORT" \
    ENCOMPUTE_DATABASE_URL_FILE="$SECRETS/db-url" \
    ENCOMPUTE_SIGNING_KEY_FILE="$SECRETS/control.key" \
    ENCOMPUTE_DEV_TOKEN_SECRET="$DEV_SECRET" \
    ENCOMPUTE_ANCHOR_DIR="$LIVE/anchor" \
    "$@"
}
ctl() { ( control_env "$CTL" "$@" ); }
tok() {
  local f="$W/tok/$1"
  [ -s "$f" ] || ctl dev-token --subject "$1" > "$f"
  cat "$f"
}
alive() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }
# start_control: starts `serve`; returns non-zero if it exits instead.
start_control() {
  N_START=$((N_START + 1))
  CTL_LOG="$LOGS/control-$N_START.log"
  ( control_env "$CTL" serve ) >"$CTL_LOG" 2>&1 &
  CTL_PID=$!; PIDS+=("$CTL_PID")
  local _
  for _ in $(seq 150); do
    curl -fs "$CTL_URL/ready" >/dev/null 2>&1 && return 0
    alive "$CTL_PID" || return 1
    sleep 0.2
  done
  return 1
}
stop() { # stop PID...
  local p
  for p in "$@"; do if alive "$p"; then kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; fi; done
}
# Clients pin the evaluator's receipt key out of band (here: read from the
# evaluator this script started) and refuse any other.
pin_evaluator() {
  ENCOMPUTE_TRUSTED_EVALUATORS="$(curl -fs "http://127.0.0.1:$EVAL_PORT/v1/info" | jget 'v["evaluator"]["public_key"]')" \
    || return 1
  export ENCOMPUTE_TRUSTED_EVALUATORS
}
start_evaluator() {
  N_START=$((N_START + 1))
  EVAL_LOG="$LOGS/evaluator-$N_START.log"
  ( cd "$LIVE/evaluator" && exec env ENCOMPUTE_CONTROL_URL="$CTL_URL" ENCOMPUTE_CONTROL_PUBLIC_KEY="$CONTROL_KEY" \
      ENCOMPUTE_SERVICE_ID=evaluator-1 ENCOMPUTE_SERVICE_KEY_FILE="$SECRETS/evaluator.key" \
      ENCOMPUTE_ADVERTISE_URL="http://127.0.0.1:$EVAL_PORT" ENCOMPUTE_CAPACITY=2 \
      "$EVAL" serve --listen "127.0.0.1:$EVAL_PORT" --identity "$LIVE/evaluator/receipt.key" ) >"$EVAL_LOG" 2>&1 &
  EVAL_PID=$!; PIDS+=("$EVAL_PID")
  local _
  for _ in $(seq 150); do
    grep -q "registered with the control plane" "$EVAL_LOG" && { pin_evaluator; return; }
    alive "$EVAL_PID" || return 1
    sleep 0.2
  done
  return 1
}
start_keybroker() {
  [ "$BAO_OK" = 1 ] || return 0
  N_START=$((N_START + 1))
  KB_LOG="$LOGS/keybroker-$N_START.log"
  ( cd "$LIVE/broker" && exec env BAO_ADDR="$BAO_ADDR" BAO_TOKEN_FILE="$SECRETS/bao-token" \
      ENCOMPUTE_CONTROL_PUBLIC_KEY="$CONTROL_KEY" ENCOMPUTE_SERVICE_ID=keybroker-modelco \
      "$E" keys serve --listen "127.0.0.1:$KB_PORT" --jwks "$W/idp/jwks.json" --broker "$LIVE/broker/broker.json" \
        --root-key "openbao:transit/$TAG-modelco" --organization modelco \
        --wrapped-kek "$LIVE/broker/kek.wrapped.json" ) >"$KB_LOG" 2>&1 &
  KB_PID=$!; PIDS+=("$KB_PID")
  local _
  for _ in $(seq 150); do
    curl -fs "http://127.0.0.1:$KB_PORT/live" >/dev/null 2>&1 && return 0
    alive "$KB_PID" || return 1
    sleep 0.2
  done
  return 1
}
# api WHO METHOD PATH [BODY] [IDEMPOTENCY-KEY]: prints the HTTP status; the
# body is in $W/body.
api() {
  local args=(-sS -o "$W/body" -w '%{http_code}' -X "$2" -H "Authorization: Bearer $(tok "$1")")
  if [ -n "${4:-}" ]; then args+=(-H 'Content-Type: application/json' -d "$4"); fi
  if [ -n "${5:-}" ]; then args+=(-H "Idempotency-Key: $5"); fi
  curl "${args[@]}" "$CTL_URL$3" || true
}
# ok WHO METHOD PATH [BODY] [KEY]: the body of a 2xx response, or die.
ok() {
  local s; s="$(api "$@")"
  case "$s" in 2??) cat "$W/body" ;; *) die "$2 $3 -> $s $(cut -c1-300 "$W/body")" ;; esac
}
body() { jget "$1" < "$W/body"; }
# broker_key_state ASSET: the broker's key state for ASSET (from broker.json).
broker_key_state() {
  "$PY" - "$LIVE/broker/broker.json" "$1" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
asset = sys.argv[2]
def find(o):
    if isinstance(o, dict):
        if asset in o:
            return o[asset]
        for v in o.values():
            r = find(v)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = find(v)
            if r is not None:
                return r
    return None
e = find(s)
t = json.dumps(e).lower() if e is not None else ""
print("missing" if e is None else ("destroyed" if "destroyed" in t else "active"))
PY
}

# --- the deployment -----------------------------------------------------------------
ctl migrate >"$LOGS/setup.log" 2>&1 || die "migrate"
ctl bootstrap --issuer encompute-development --subject platform-admin >>"$LOGS/setup.log" 2>&1 || die "bootstrap"
start_control || die "the control plane did not start"
CONTROL_KEY="$(curl -fs "$CTL_URL/v1/info" | jget 'v["public_key"]')"
echo "control plane $CTL_URL (key ${CONTROL_KEY:0:16}...), anchor $LIVE/anchor"

step "1. workload: organizations, users, project, assets, services, plan, jobs"
ISS=encompute-development
ok platform-admin POST /v1/organizations "{\"id\":\"hospital-a\",\"display_name\":\"Hospital A\",\"admin\":{\"issuer\":\"$ISS\",\"subject\":\"a-admin\"}}" >/dev/null
ok platform-admin POST /v1/organizations "{\"id\":\"modelco\",\"display_name\":\"ModelCo\",\"admin\":{\"issuer\":\"$ISS\",\"subject\":\"b-admin\"}}" >/dev/null
ok a-admin POST /v1/organizations/hospital-a/users "{\"issuer\":\"$ISS\",\"subject\":\"a-owner\",\"roles\":[\"data_owner\",\"auditor\"]}" >/dev/null
ok b-admin POST /v1/organizations/modelco/users "{\"issuer\":\"$ISS\",\"subject\":\"b-dev\",\"roles\":[\"ml_developer\",\"auditor\"]}" >/dev/null
ok b-admin POST /v1/organizations/modelco/users "{\"issuer\":\"$ISS\",\"subject\":\"b-owner\",\"roles\":[\"model_owner\"]}" >/dev/null
PROJECT="$(ok b-dev POST /v1/projects '{"organization":"modelco","name":"drill"}' | jget 'v["id"]')"
ok b-admin POST "/v1/projects/$PROJECT/members" '{"organization":"hospital-a"}' >/dev/null
ok a-admin POST "/v1/projects/$PROJECT/members" '{"organization":"hospital-a"}' >/dev/null
BUDGET='{"unit":"patient","epsilon":"3.0","delta":"1e-6"}'
DS1="$(ok a-owner POST /v1/assets "{\"organization\":\"hospital-a\",\"kind\":\"dataset\",\"name\":\"patients\",\"digest\":\"$(printf 'c%.0s' $(seq 64))\",\"privacy_budget\":$BUDGET}" | jget 'v["id"]')"
DS2="$(ok a-owner POST /v1/assets "{\"organization\":\"hospital-a\",\"kind\":\"dataset\",\"name\":\"claims\",\"digest\":\"$(printf 'd%.0s' $(seq 64))\",\"privacy_budget\":$BUDGET}" | jget 'v["id"]')"
ok a-owner POST "/v1/assets/$DS1/approvals" "{\"project\":\"$PROJECT\",\"purpose\":\"drill\"}" >/dev/null
keyref() { printf '{"broker":"keybroker-modelco","provider":"openbao-transit","key_ref":"%s","key_version":1}' "$1"; }
MODEL="$(ok b-owner POST /v1/assets "{\"organization\":\"modelco\",\"kind\":\"model\",\"name\":\"model-7\",\"digest\":\"$(printf 'b%.0s' $(seq 64))\",\"key_ref\":$(keyref model-7)}" | jget 'v["id"]')"
MODEL2="$(ok b-owner POST /v1/assets "{\"organization\":\"modelco\",\"kind\":\"model\",\"name\":\"model-8\",\"digest\":\"$(printf 'e%.0s' $(seq 64))\",\"key_ref\":$(keyref model-8)}" | jget 'v["id"]')"
echo "project $PROJECT; datasets $DS1 $DS2; models $MODEL $MODEL2"

# The program: OpenFHE CKKS (its keys generate in seconds even in a debug
# build; the exact BinFHE path is covered by scripts/enterprise-e2e.sh).
cat > "$W/score.eir" <<'EIR'
encompute 0.1
program score precision 0.001
%0 = input "x" [-1.0, 1.0] : secret vector<4>
%1 = mul %0, %0 : secret vector<4>
output "y" = %1
EIR
"$E" compile "$W/score.eir" -o "$W/score.encompute" >/dev/null || die "compile"
"$E" keys generate "$W/score.encompute" -o "$W/score.keys" >/dev/null || die "keys generate"
# The same over hospital-a's dataset: a job using another organization's
# asset runs a program that declares its purpose (the one the owner
# approved) and reads the asset by its registered ID.
cat > "$W/score-ds1.eir" <<EIR
encompute 0.1
program score precision 0.001 purpose "drill"
party "hospital-a" "Hospital A"
party "modelco" "ModelCo"
asset "$DS1" dataset owners ["hospital-a"] readers ["modelco"] purposes ["drill"] release allowed_parties
%0 = input "x" [-1.0, 1.0] asset "$DS1" : secret vector<4>
%1 = mul %0, %0 : secret vector<4>
output "y" = %1 to "modelco"
EIR
"$E" compile "$W/score-ds1.eir" -o "$W/score-ds1.encompute" >/dev/null || die "compile (over DS1)"
"$E" keys generate "$W/score-ds1.encompute" -o "$W/score-ds1.keys" >/dev/null || die "keys generate (over DS1)"
# close OUTPUT_JSON WANT...: output y is within 1e-3 of WANT.
close() {
  echo "$1" | "$PY" -c 'import json,sys; y=json.load(sys.stdin).get("y") or []; w=[float(a) for a in sys.argv[1:]]; print(len(y)==len(w) and max(abs(a-b) for a,b in zip(y,w))<1e-3)' "${@:2}"
}

svc() { # svc ID KIND KEYFILE URL
  ok platform-admin POST /v1/organizations/platform/service-accounts \
    "{\"id\":\"$1\",\"kind\":\"$2\",\"public_key\":\"$(ctl public-key "$3")\",\"url\":\"$4\"}" >/dev/null
}
svc evaluator-1 evaluator "$SECRETS/evaluator.key" "http://127.0.0.1:$EVAL_PORT"
start_evaluator || die "the evaluator did not register"
if [ "$BAO_OK" = 1 ]; then
  svc keybroker-modelco keybroker "$SECRETS/keybroker.key" "http://127.0.0.1:$KB_PORT"
  "$E" attest policy "$W/score.encompute" --image "sha256:$(printf 'a%.0s' $(seq 64))" --tee intel_tdx > "$W/policy.json"
  for m in model-7 model-8; do
    ( cd "$LIVE/broker" && BAO_ADDR="$BAO_ADDR" BAO_TOKEN_FILE="$SECRETS/bao-token" "$E" keys protect --asset "$m" \
        --policy "$W/policy.json" --broker-id keybroker-modelco --root-key "openbao:transit/$TAG-modelco" \
        --organization modelco --broker "$LIVE/broker/broker.json" --wrapped-kek "$LIVE/broker/kek.wrapped.json" ) >/dev/null \
      || die "keys protect $m"
  done
  start_keybroker || die "the key broker did not start"
  echo "evaluator-1 registered; key broker up (KEK wrapped by transit/$TAG-modelco)"
fi

# plan_of FILE: a plan of the program in FILE, in the drill's project.
plan_of() {
  ok b-dev POST /v1/plans "$("$PY" -c 'import json,sys; print(json.dumps({"project": sys.argv[1], "program": open(sys.argv[2]).read()}))' "$PROJECT" "$1")" | jget 'v["id"]'
}
# A job's sources are exactly the registered assets its program binds, even
# over modelco's own models: these programs bind their input to each model.
for m in "$MODEL" "$MODEL2"; do
  cat > "$W/score-$m.eir" <<EIR
encompute 0.1
program score precision 0.001 purpose "drill"
party "modelco" "ModelCo"
asset "$m" model owners ["modelco"] readers ["modelco"] purposes ["drill"] release allowed_parties
%0 = input "x" [-1.0, 1.0] asset "$m" : secret vector<4>
%1 = mul %0, %0 : secret vector<4>
output "y" = %1 to "modelco"
EIR
done
PLAN_M7="$(plan_of "$W/score-$MODEL.eir")"
PLAN_M8="$(plan_of "$W/score-$MODEL2.eir")"
# A job that runs end to end (client-side encryption, OpenFHE evaluator,
# signed receipt, trust report).
export ENCOMPUTE_CONTROL_URL="$CTL_URL"
OUT="$(ENCOMPUTE_TOKEN="$(tok b-dev)" "$E" jobs run "$W/score-ds1.encompute" --project "$PROJECT" --purpose drill \
  --source "$DS1" --keys "$W/score-ds1.keys" --idempotency-key drill-job-1 --input x=0.5,-0.25,0.1,1.0 2>"$W/job1.err")" \
  || { cat "$W/job1.err" >&2; die "the end-to-end job"; }
check "job runs end to end (CKKS result correct, trust SATISFIED)" \
  eq "$(close "$OUT" 0.25 0.0625 0.01 1.0) $(grep -c 'Trust report *SATISFIED' "$W/job1.err")" "True 1"
ok b-dev GET "/v1/jobs?project=$PROJECT" >/dev/null
JOB_OK="$(body '[j["id"] for j in v if j["state"]=="succeeded"][0]')"
# Jobs that never start (no client drives them): revocation must fail them.
QJOB="$(ok b-dev POST /v1/jobs "{\"project\":\"$PROJECT\",\"plan\":\"$PLAN_M7\",\"purpose\":\"drill\",\"source_assets\":[\"$MODEL\"],\"requested_output\":\"y\"}" drill-queued-1 | jget 'v["id"]')"
QJOB2="$(ok b-dev POST /v1/jobs "{\"project\":\"$PROJECT\",\"plan\":\"$PLAN_M8\",\"purpose\":\"drill\",\"source_assets\":[\"$MODEL2\"],\"requested_output\":\"y\"}" drill-queued-2 | jget 'v["id"]')"
echo "plans $PLAN_M7 $PLAN_M8; job $JOB_OK succeeded; jobs $QJOB, $QJOB2 $(ok b-dev GET "/v1/jobs/$QJOB" | jget 'v["state"]')"

step "2. privacy spending (reservations and commits)"
for ev in r1 r2 r3; do ok a-owner POST "/v1/privacy/$DS1/events" "$(reserve_body "$ev")" >/dev/null; done
ok a-owner POST "/v1/privacy/$DS1/events" "$(commit_body r1)" >/dev/null
ok a-owner POST "/v1/privacy/$DS1/events" "$(commit_body r2)" >/dev/null
ok a-owner POST "/v1/privacy/$DS2/events" "$(reserve_body d1)" >/dev/null
# A duplicate delivery is not charged twice.
ok a-owner POST "/v1/privacy/$DS1/events" "$(reserve_body r1)" | jget 'v["duplicate"]' | grep -q True \
  || die "a duplicate privacy event was charged"
echo "$DS1: $(ok a-owner GET "/v1/privacy/$DS1" | jget '"%s entries, epsilon %s" % (v["entries"], v["spent"]["epsilon"])')"

step "3. revocation"
ok b-owner POST "/v1/assets/$MODEL/revoke" >/dev/null
check "revocation fails the job that had not started" eq "$(ok b-dev GET "/v1/jobs/$QJOB" | jget 'v["state"]')" failed
if [ "$BAO_OK" = 1 ]; then
  for _ in $(seq 50); do [ "$(broker_key_state model-7)" = destroyed ] && break; sleep 0.2; done
  check "revocation reached the key broker (model-7 destroyed, model-8 active)" \
    eq "$(broker_key_state model-7) $(broker_key_state model-8)" "destroyed active"
fi
# Anchor the audit chain (a signed checkpoint), as the background task does
# every ENCOMPUTE_AUDIT_CHECKPOINT_EVERY events.
ok platform-admin POST /v1/audit/checkpoints >/dev/null

# The state everything must come back to (DS2 changes once more, during the
# backup; recorded after it).
snapshot() { # snapshot DIR: the observable state
  local d="$1" a
  mkdir -p "$d"
  for a in "$DS1" "$DS2"; do
    ok a-owner GET "/v1/privacy/$a" | canon > "$d/privacy-$a.json"
    ok a-owner GET "/v1/privacy/$a/ledger" | canon > "$d/ledger-$a.json"
  done
  ok b-owner GET "/v1/assets/$MODEL" | jget 'v["status"]' > "$d/asset-$MODEL.txt"
  ok b-owner GET "/v1/assets/$MODEL2" | jget 'v["status"]' > "$d/asset-$MODEL2.txt"
  ok a-owner GET "/v1/assets/$DS1" | jget 'v["status"]' > "$d/asset-$DS1.txt"
  for j in "$JOB_OK" "$QJOB" "$QJOB2"; do ok b-dev GET "/v1/jobs/$j" | jget 'v["state"]' > "$d/job-$j.txt"; done
  ok b-dev GET "/v1/trust/$JOB_OK" | canon > "$d/trust.json"
  ok b-dev GET "/v1/audit?limit=1000" | canon > "$d/audit-modelco.json"
  ok a-owner GET "/v1/audit?limit=1000" | canon > "$d/audit-hospital.json"
}

# --- backup -----------------------------------------------------------------------
# backup DIR [HOOK]: the local equivalent of deploy/docker-compose/backup.sh,
# taken while the deployment runs. The anchor is captured FIRST; HOOK (a
# command) runs between the anchor and the database captures.
backup() {
  local B="$1"; shift
  mkdir -p "$B"; chmod 700 "$B"
  tar -C "$LIVE/anchor" -cf "$B/anchor.tar" .
  if [ $# -gt 0 ]; then "$@"; fi
  pg_dump_db "$DB" > "$B/db.sql"
  tar -C "$LIVE/broker" -cf "$B/broker.tar" .
  tar -C "$LIVE/evaluator" -cf "$B/evaluator.tar" .
  chmod 600 "$B"/*
  ( cd "$B" && sha db.sql anchor.tar broker.tar evaluator.tar > SHA256SUMS )
}
# restore DIR: the local equivalent of deploy/docker-compose/restore.sh, into
# a stopped deployment: the database always; the anchor and the broker state
# only into EMPTY directories (existing ones are authoritative: a newer anchor
# detects a rollback; a newer broker keeps keys destroyed since the backup);
# the evaluator identity always.
restore_db() {
  sql "DROP DATABASE IF EXISTS $DB WITH (FORCE)" >/dev/null 2>&1   # (a NOTICE when absent)
  sql "CREATE DATABASE $DB" >/dev/null
  psql_db "$DB" < "$1/db.sql" >/dev/null
}
restore() {
  local B="$1"
  ( cd "$B" && sha -c SHA256SUMS >/dev/null ) || { echo "backup checksums do not match"; return 1; }
  restore_db "$B"
  mkdir -p "$LIVE/anchor" "$LIVE/broker" "$LIVE/evaluator"
  if is_empty_dir "$LIVE/anchor"; then tar -C "$LIVE/anchor" -xf "$B/anchor.tar"; echo "anchor restored"
  else echo "anchor kept (existing anchor is authoritative)"; fi
  if is_empty_dir "$LIVE/broker"; then tar -C "$LIVE/broker" -xf "$B/broker.tar"; echo "broker restored"
  else echo "broker kept (existing broker state is authoritative)"; fi
  tar -C "$LIVE/evaluator" -xf "$B/evaluator.tar"
}

step "4. backup (live: privacy spending lands between the anchor and the database captures)"
spend_during_backup() { ok a-owner POST "/v1/privacy/$DS2/events" "$(reserve_body d2-during-backup)" >/dev/null; }
backup "$BACKUPS/b1" spend_during_backup
snapshot "$W/pre"
echo "backup b1: $(wc -c < "$BACKUPS/b1/db.sql" | tr -d ' ') bytes of database, anchor, broker, evaluator identity"
check "backup has database, anchor, broker, evaluator identity and checksums" \
  test -s "$BACKUPS/b1/db.sql" -a -s "$BACKUPS/b1/anchor.tar" -a -s "$BACKUPS/b1/broker.tar" -a -s "$BACKUPS/b1/evaluator.tar" -a -s "$BACKUPS/b1/SHA256SUMS"
check "backup's database dump holds the privacy ledgers and the audit chain" \
  contains "$BACKUPS/b1/db.sql" "privacy_entries"

step "5. destroy the deployment (full disaster: processes, database, anchor, broker, evaluator state)"
stop "$KB_PID" "$EVAL_PID" "$CTL_PID"
sql "DROP DATABASE $DB WITH (FORCE)" >/dev/null
rm -rf "$LIVE/anchor" "$LIVE/broker" "$LIVE/evaluator"
check "deployment destroyed (no process answers, database gone, volumes gone)" eq \
  "$(curl -fs "$CTL_URL/live" >/dev/null 2>&1 && echo up || echo down) $(sql "SELECT count(*) FROM pg_database WHERE datname = '$DB'") $(find "$LIVE" -mindepth 1 | wc -l | tr -d ' ')" \
  "down 0 0"

step "6. restore"
verify_sums() { ( cd "$1" && sha -c SHA256SUMS >/dev/null ); }
check "backup checksums verify" verify_sums "$BACKUPS/b1"
# The database without its anchor: refused (the anchor is part of the backup
# for exactly this case).
restore_db "$BACKUPS/b1"
mkdir -p "$LIVE/anchor"
if ctl verify-state >"$W/noanchor.txt" 2>&1; then
  fail_check "a restored database without its anchor is refused"
else
  check "a restored database without its anchor is refused (ANCHOR STATE ROLLBACK)" contains "$W/noanchor.txt" "ANCHOR STATE ROLLBACK"
fi
restore "$BACKUPS/b1" > "$W/restore1.txt"
check "full disaster: the anchor is restored into the empty anchor directory" contains "$W/restore1.txt" "anchor restored"
check "restored anchor is the backup's anchor" eq \
  "$(sha "$LIVE/anchor/state-anchor.json" | cut -d' ' -f1)" "$(tar -xOf "$BACKUPS/b1/anchor.tar" ./state-anchor.json | sha | cut -d' ' -f1)"
ctl verify-state >"$W/verify1.txt" 2>&1 || true
check "verify-state: STATE VERIFIED (database extends the anchor; audit chain intact)" contains "$W/verify1.txt" "STATE VERIFIED"
start_control || die "the control plane did not start after the restore: $(tail -n 3 "$CTL_LOG")"
pass "control plane starts on the restored state"
start_evaluator || die "the evaluator did not re-register after the restore"
start_keybroker || die "the key broker could not open its wrapped KEK after the restore"
[ "$BAO_OK" = 1 ] && pass "key broker opens its restored wrapped KEK through the KMS"

step "7. verify the restored state"
snapshot "$W/post"
for a in "$DS1" "$DS2"; do
  check "privacy $a: spent epsilon, entries, root and frozen equal the backup" \
    eq "$(canon < "$W/post/privacy-$a.json")" "$(canon < "$W/pre/privacy-$a.json")"
  check "privacy $a: the ledger (every entry) equals the backup" \
    cmp -s "$W/post/ledger-$a.json" "$W/pre/ledger-$a.json"
done
check "privacy $DS2: the spend made during the backup survived" \
  eq "$(jget 'v["entries"]' < "$W/post/privacy-$DS2.json")" 2
check "revocation survived: $MODEL revoked, $MODEL2 and $DS1 active" \
  eq "$(cat "$W/post/asset-$MODEL.txt") $(cat "$W/post/asset-$MODEL2.txt") $(cat "$W/post/asset-$DS1.txt")" "revoked active active"
check "jobs survived: end-to-end job succeeded, revoked job failed, other queued job untouched" \
  eq "$(cat "$W/post/job-$JOB_OK.txt") $(cat "$W/post/job-$QJOB.txt") $(cat "$W/post/job-$QJOB2.txt")" \
     "succeeded failed $(cat "$W/pre/job-$QJOB2.txt")"
check "trust report still verifies: SATISFIED, identical to before the backup" \
  eq "$(jget 'v["verdict"]' < "$W/post/trust.json") $(cmp -s "$W/post/trust.json" "$W/pre/trust.json" && echo same)" "SATISFIED same"
for o in modelco hospital; do
  check "audit export ($o): every event up to the backup, unchanged" "$PY" - "$W/pre/audit-$o.json" "$W/post/audit-$o.json" <<'PY'
import json, sys
pre, post = (json.load(open(p)) for p in sys.argv[1:3])
ok = len(pre) > 0 and post[:len(pre)] == pre
if not ok:
    print(f"      pre {len(pre)} events, post {len(post)} events; first difference at",
          next((i for i, (a, b) in enumerate(zip(pre, post)) if a != b), min(len(pre), len(post))))
sys.exit(0 if ok else 1)
PY
done
check "audit export includes the revocation and the privacy spending" "$PY" - "$W/post/audit-modelco.json" "$W/post/audit-hospital.json" <<'PY'
import json, sys
acts = {e["action"] for p in sys.argv[1:] for e in json.load(open(p))}
need = {"asset.revoked", "job.failed", "job.succeeded", "privacy.spent", "privacy.committed"}
missing = need - acts
if missing:
    print("      missing:", missing)
sys.exit(1 if missing else 0)
PY
s="$(api b-dev POST /v1/jobs "{\"project\":\"$PROJECT\",\"plan\":\"$PLAN_M7\",\"purpose\":\"drill\",\"source_assets\":[\"$MODEL\"],\"requested_output\":\"y\"}" drill-after-restore)"
check "a new job using the revoked model is refused (409)" eq "$s" 409
if [ "$BAO_OK" = 1 ]; then
  check "key broker: model-7 still destroyed after the restore" eq "$(broker_key_state model-7)" destroyed
fi
OUT="$(ENCOMPUTE_TOKEN="$(tok b-dev)" "$E" jobs run "$W/score.encompute" --project "$PROJECT" --purpose drill \
  --keys "$W/score.keys" --idempotency-key drill-job-2 --input x=0.1,0.2,-0.3,0.9 2>"$W/job2.err")" || { cat "$W/job2.err"; OUT='{}'; }
check "a new job runs after the restore (CKKS result correct, trust SATISFIED)" \
  eq "$(close "$OUT" 0.01 0.04 0.09 0.81) $(grep -c 'Trust report *SATISFIED' "$W/job2.err")" "True 1"

step "7b. database loss only: the surviving anchor is kept and the same backup restores"
stop "$KB_PID" "$EVAL_PID" "$CTL_PID"
restore "$BACKUPS/b1" > "$W/restore2.txt"
check "database-only restore keeps the existing anchor and broker state" eq \
  "$(grep -c 'anchor kept' "$W/restore2.txt") $(grep -c 'broker kept' "$W/restore2.txt")" "1 1"
ctl verify-state >"$W/verify2.txt" 2>&1 || true
check "verify-state: STATE VERIFIED (the backup is as new as the anchor)" contains "$W/verify2.txt" "STATE VERIFIED"
start_control || die "the control plane did not start after the database-only restore: $(tail -n 3 "$CTL_LOG")"
start_evaluator || die "the evaluator did not re-register"
start_keybroker || die "the key broker did not restart"
check "privacy state equals the backup after the database-only restore" eq \
  "$(ok a-owner GET "/v1/privacy/$DS1" | canon)|$(ok a-owner GET "/v1/privacy/$DS2" | canon)" \
  "$(canon < "$W/pre/privacy-$DS1.json")|$(canon < "$W/pre/privacy-$DS2.json")"

step "8. an OLDER backup over a NEWER anchor is refused; recovery freezes"
PRE_DS1_SPENT="$(jget 'v["spent"]["epsilon"]' < "$W/pre/privacy-$DS1.json")"
ok a-owner POST "/v1/privacy/$DS1/events" "$(reserve_body r4-after-backup)" >/dev/null
NEW_DS1="$(ok a-owner GET "/v1/privacy/$DS1" | canon)"
check "spending after the backup advanced $DS1 (the anchor is now newer than b1)" \
  test "$(echo "$NEW_DS1" | jget 'v["entries"]')" -gt "$(jget 'v["entries"]' < "$W/pre/privacy-$DS1.json")"
# A revocation after the backup, too: the key broker's state is newer than b1.
ok b-owner POST "/v1/assets/$MODEL2/revoke" >/dev/null
if [ "$BAO_OK" = 1 ]; then
  for _ in $(seq 50); do [ "$(broker_key_state model-8)" = destroyed ] && break; sleep 0.2; done
fi
stop "$KB_PID" "$EVAL_PID" "$CTL_PID"
restore "$BACKUPS/b1" > "$W/restore3.txt"
check "restoring the older backup keeps the newer anchor" contains "$W/restore3.txt" "anchor kept"
if start_control; then
  fail_check "the control plane refuses to start on the older backup"
  stop "$CTL_PID"
else
  wait "$CTL_PID" 2>/dev/null && rc=0 || rc=$?
  check "the control plane refuses to start on the older backup (exit $rc, not ready)" \
    test "$rc" -ne 0 -a "$(curl -fs "$CTL_URL/ready" >/dev/null 2>&1 && echo up || echo down)" = down
  check "the refusal names PRIVACY STATE ROLLBACK and STARTUP REFUSED" \
    eq "$(grep -c 'PRIVACY STATE ROLLBACK.*STARTUP REFUSED' "$CTL_LOG")" 1
fi
if ctl verify-state >"$W/verify3.txt" 2>&1; then
  fail_check "verify-state refuses the older backup"
else
  check "verify-state refuses the older backup (PRIVACY STATE ROLLBACK, ledger $DS1)" \
    eq "$(grep -c "PRIVACY STATE ROLLBACK.*$DS1" "$W/verify3.txt")" 1
fi
ctl recover --operator drill-operator >"$W/recover.txt" 2>&1 || true
check "recover --operator freezes exactly the rolled-back ledger ($DS1, not $DS2)" eq \
  "$(grep -c "privacy ledger $DS1: frozen" "$W/recover.txt") $(grep -c "privacy ledger $DS2" "$W/recover.txt") $(grep -c RECOVERED "$W/recover.txt")" \
  "1 0 1"
ctl verify-state >"$W/verify4.txt" 2>&1 || true
check "verify-state after recovery: STATE VERIFIED" contains "$W/verify4.txt" "STATE VERIFIED"
start_control || die "the control plane did not start after recovery: $(tail -n 3 "$CTL_LOG")"
pass "control plane starts after recovery"
ok a-owner GET "/v1/privacy/$DS1" > "$W/frozen.json"
check "privacy view of $DS1 shows frozen (rolled back behind the anchor)" \
  eq "$(jget '"rolled back" in (v["frozen"] or "")' < "$W/frozen.json")" True
check "$DS1 shows the backup's spending (the forgotten spend is covered by the freeze)" \
  eq "$(jget 'v["spent"]["epsilon"]' < "$W/frozen.json")" "$PRE_DS1_SPENT"
s="$(api a-owner POST "/v1/privacy/$DS1/events" "$(reserve_body r5-after-recovery)")"
check "a further spend on $DS1 is refused (409 ENC2201, PrivacyBudgetExceeded)" eq "$s $(body 'v.get("code")')" "409 ENC2201"
check "$DS2 (not rolled back) is not frozen" eq "$(ok a-owner GET "/v1/privacy/$DS2" | jget 'v["frozen"]')" None
s="$(api a-owner POST "/v1/privacy/$DS2/events" "$(reserve_body d3-after-recovery)")"
check "$DS2 still spends (200)" eq "$s" 200
check "the freeze is on the audit chain (privacy.ledger.frozen)" \
  eq "$(sql_in "SELECT count(*) FROM audit_events WHERE action = 'privacy.ledger.frozen' AND resource_id = '$DS1'")" 1
if [ "$BAO_OK" = 1 ]; then
  check "key broker state was kept: model-8 (revoked after the backup) stays destroyed" \
    eq "$(broker_key_state model-8)" destroyed
fi
# Revocations are anchored too: the older database forgot the revocation
# made after the backup, and recovery re-applies it.
check "recover re-applies the revocation the older database forgot ($MODEL2)" \
  contains "$W/recover.txt" "asset $MODEL2: revocation re-applied"
api b-owner GET "/v1/assets/$MODEL2" >/dev/null
check "$MODEL2 (revoked after the backup) is revoked again after recovery" \
  eq "$(body 'v["status"]')" revoked

summary
