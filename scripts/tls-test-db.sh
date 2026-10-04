#!/usr/bin/env bash
# A TLS-enabled PostgreSQL for the database-TLS tests (crates/encompute-control
# tests/database_tls.rs). It requires TLS and a client certificate, like the
# reference production topology's database.
#
#   scripts/tls-test-db.sh up   [DIR]   write a throwaway PKI to DIR and start the server
#   scripts/tls-test-db.sh env  [DIR]   print the variables the tests read
#   scripts/tls-test-db.sh down [DIR]   remove the container and DIR
#
# DIR defaults to ${TMPDIR:-/tmp}/encompute-tls-test-db. The PKI is
# throwaway (deploy/production/gen-test-certs.sh); nothing in it is committed.
# The server's certificate is for the name `postgres` only, so the tests
# reach it as host=postgres hostaddr=127.0.0.1 (the right name) and as
# 127.0.0.1 (the wrong one).
#
# PORT (default 55445) and NAME (default enc-pg-tls) choose the container.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cmd="${1:-}"
DIR="${2:-${TMPDIR:-/tmp}/encompute-tls-test-db}"
PORT="${PORT:-55445}"
NAME="${NAME:-enc-pg-tls}"
IMAGE="${PG_IMAGE:-postgres:16-alpine}"
dk() { perl -e 'alarm 120; exec @ARGV' docker "$@"; }

case "$cmd" in
up)
  mkdir -p "$DIR"
  "$ROOT/deploy/production/gen-test-certs.sh" "$DIR" >/dev/null
  cp "$ROOT/deploy/production/config/pg_hba.conf" "$DIR/pg_hba.conf"
  dk rm -f "$NAME" >/dev/null 2>&1 || true
  dk run -d --name "$NAME" -p "127.0.0.1:$PORT:5432" \
    -e POSTGRES_USER=encompute -e POSTGRES_DB=encompute -e POSTGRES_PASSWORD=encompute-tls-test \
    --tmpfs /run/pgtls:mode=0700,uid=70,gid=70 \
    -v "$DIR:/pki:ro" --entrypoint sh "$IMAGE" -c '
      install -m 0600 -o postgres -g postgres /pki/pg-server.key /run/pgtls/server.key &&
      install -m 0644 -o postgres -g postgres /pki/pg-server.crt /run/pgtls/server.crt &&
      install -m 0644 -o postgres -g postgres /pki/internal-ca.crt /run/pgtls/ca.crt &&
      install -m 0644 -o postgres -g postgres /pki/pg_hba.conf /run/pgtls/pg_hba.conf &&
      exec docker-entrypoint.sh postgres -c listen_addresses=* -c ssl=on \
        -c ssl_cert_file=/run/pgtls/server.crt -c ssl_key_file=/run/pgtls/server.key \
        -c ssl_ca_file=/run/pgtls/ca.crt -c ssl_min_protocol_version=TLSv1.2 \
        -c password_encryption=scram-sha-256 -c hba_file=/run/pgtls/pg_hba.conf' >/dev/null
  for _ in $(seq 1 60); do
    if dk exec "$NAME" psql -U encompute -d encompute -tAc 'select 1' 2>/dev/null | grep -q 1 \
       && dk exec "$NAME" pg_isready -q -h 127.0.0.1 -U encompute -d encompute; then
      echo "TLS PostgreSQL up on 127.0.0.1:$PORT (PKI in $DIR)"; exit 0
    fi
    sleep 1
  done
  echo "TLS PostgreSQL did not become ready" >&2; dk logs "$NAME" | tail -20 >&2; exit 1 ;;
env)
  echo "export ENCOMPUTE_TEST_TLS_DATABASE=127.0.0.1:$PORT"
  echo "export ENCOMPUTE_TEST_TLS_DATABASE_PASSWORD=encompute-tls-test"
  echo "export ENCOMPUTE_TEST_TLS_PKI=$DIR" ;;
down)
  dk rm -f -v "$NAME" >/dev/null 2>&1 || true
  rm -rf "$DIR" ;;
*) echo "usage: $0 up|env|down [DIR]" >&2; exit 2 ;;
esac
