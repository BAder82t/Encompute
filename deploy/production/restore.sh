#!/usr/bin/env bash
# Restores a backup from DIR into a stopped topology (volumes empty, or
# being replaced), then starts the control plane, which refuses to start if
# the database is older than the state anchor (PRIVACY/AUDIT STATE ROLLBACK).
# The same rules as deploy/docker-compose/restore.sh: an existing anchor and an
# existing key broker state are authoritative and are never overwritten.
#
#   ./restore.sh DIR
#
# Needs ./secrets in place (they are not in the backup), the external
# OpenBao up and unsealed, and its token file current (bao-token.sh).
set -euo pipefail
cd "$(dirname "$0")"
PROJECT="${COMPOSE_PROJECT_NAME:-encompute-prod}"
dc() { docker compose -p "$PROJECT" "$@"; }
ALPINE="alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
DIR="$(cd "${1:?usage: restore.sh DIR}" && pwd)"
( cd "$DIR" && shasum -a 256 -c SHA256SUMS >/dev/null ) || { echo "backup checksums do not match" >&2; exit 1; }
dc stop edge control evaluator keybroker >/dev/null 2>&1 || true
dc up -d postgres
# Wait for the real server, not the image's temporary start-up server: a
# query over TCP succeeds only once the final server is up and the database
# exists. (The superuser role reaches it on the local socket; the TLS-only
# network listener is for the control plane.)
for _ in $(seq 120); do dc exec -T postgres psql -q -U encompute -d encompute -c 'select 1' >/dev/null 2>&1 && break; sleep 1; done
# One transaction, stopping at the first error: a partial restore fails
# (and leaves the database as it was) instead of reporting success.
dc exec -T postgres psql -q -v ON_ERROR_STOP=1 --single-transaction -U encompute encompute < "$DIR/db.sql" >/dev/null
# Volumes are created here with the labels Compose puts on its own, so that
# Compose adopts them (no "not created by Docker Compose" warning) and
# `docker compose down -v` removes them.
ensure_vol() {
  docker volume inspect "${PROJECT}_$1" >/dev/null 2>&1 || docker volume create \
    --label "com.docker.compose.project=$PROJECT" --label "com.docker.compose.volume=$1" "${PROJECT}_$1" >/dev/null
}
for v in anchor broker evaluator; do ensure_vol "$v"; done
untar() { docker run --rm -v "${PROJECT}_$1:/v" -v "$DIR:/b:ro" "$ALPINE" sh -c "$2"; }
untar anchor '[ -z "$(ls -A /v)" ] && tar -C /v -xf /b/anchor.tar && echo "anchor restored" || echo "anchor kept (existing anchor is authoritative)"'
untar broker '[ -z "$(ls -A /v)" ] && tar -C /v -xf /b/broker.tar && echo "broker restored" || echo "broker kept (existing broker state is authoritative)"'
untar evaluator 'tar -C /v -xf /b/evaluator.tar'
dc up -d pg-tunnel control edge
echo "restored from $DIR; the control plane verifies the database against the anchor at start"
