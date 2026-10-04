#!/usr/bin/env bash
# Backs up the topology's durable state into DIR (same contents and the
# same order as deploy/docker-compose/backup.sh):
#   anchor.tar      the state anchor (signed privacy and audit roots), FIRST
#   db.sql          PostgreSQL (the dump is taken inside the container, over its
#                   local socket: the TLS-only network listener is not involved)
#   broker.tar      the key broker's state: wrapped keys and the wrapped KEK
#                   (no plaintext key: the root key stays in OpenBao). Restoring
#                   an older copy brings back keys revoked since: keep backups
#                   access-controlled
#   evaluator.tar   the evaluator's receipt-signing identity
#   SHA256SUMS
#
#   ./backup.sh DIR            take a backup
#   ./backup.sh --verify DIR   check one WITHOUT touching the running topology:
#                              checksums, tar listings, and the dump restored
#                              into a scratch PostgreSQL that has no network
#
# NOT in a backup, and needed to restore: ./secrets (the signing keys, the
# database password, the TLS material, the key broker's token) and the
# OpenBao itself (back it up with its own procedure: a raft snapshot, and
# keep the unseal key shares). See docs/production-deployment.md.
set -euo pipefail
cd "$(dirname "$0")"
PROJECT="${COMPOSE_PROJECT_NAME:-encompute-prod}"
dc() { docker compose -p "$PROJECT" "$@"; }
ALPINE="alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

if [ "${1:-}" = "--verify" ]; then
  DIR="$(cd "${2:?usage: backup.sh --verify DIR}" && pwd)"
  ( cd "$DIR" && shasum -a 256 -c SHA256SUMS >/dev/null ) || { echo "checksums do not match" >&2; exit 1; }
  for f in db.sql anchor.tar broker.tar evaluator.tar; do
    [ -s "$DIR/$f" ] || { echo "$f is missing or empty" >&2; exit 1; }
  done
  for f in anchor broker evaluator; do tar -tf "$DIR/$f.tar" >/dev/null || { echo "$f.tar is not a readable archive" >&2; exit 1; }; done
  # The image of the running database (same major version as the dump), no network, no published port.
  IMG="$(docker inspect -f '{{.Image}}' "$(dc ps -q postgres)")"
  S="$(docker run -d --rm --network none -e POSTGRES_USER=encompute -e POSTGRES_DB=encompute -e POSTGRES_HOST_AUTH_METHOD=trust "$IMG")"
  trap 'docker rm -f "$S" >/dev/null 2>&1 || true' EXIT
  for _ in $(seq 60); do docker exec "$S" psql -h 127.0.0.1 -q -U encompute -d encompute -c 'select 1' >/dev/null 2>&1 && break; sleep 1; done
  docker exec -i "$S" psql -q -v ON_ERROR_STOP=1 --single-transaction -U encompute encompute < "$DIR/db.sql" >/dev/null \
    || { echo "the dump does not restore" >&2; exit 1; }
  n="$(docker exec "$S" psql -U encompute -d encompute -tAc "select count(*) from information_schema.tables where table_schema='public'")"
  [ "${n:-0}" -gt 0 ] || { echo "the restored dump has no tables" >&2; exit 1; }
  echo "backup $DIR verified: checksums match, archives readable, dump restores ($n tables)"
  exit 0
fi

DIR="${1:?usage: backup.sh DIR | backup.sh --verify DIR}"
mkdir -p "$DIR"; chmod 700 "$DIR"
vol() { docker run --rm -v "${PROJECT}_$1:/v:ro" "$ALPINE" tar -C /v -cf - . > "$DIR/$1.tar"; }
# The anchor BEFORE the database: spending commits to the database before it
# is anchored, so a dump taken after the anchor always extends it.
vol anchor
dc exec -T postgres pg_dump -U encompute --clean --if-exists encompute > "$DIR/db.sql"
vol broker; vol evaluator
chmod 600 "$DIR"/*
( cd "$DIR" && shasum -a 256 db.sql anchor.tar broker.tar evaluator.tar > SHA256SUMS )
echo "backup in $DIR: $(wc -c < "$DIR/db.sql" | tr -d ' ') bytes of database, anchor, broker, evaluator identity"
