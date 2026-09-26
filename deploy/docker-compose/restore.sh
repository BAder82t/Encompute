#!/usr/bin/env bash
# Restores a backup from DIR into a stopped deployment (volumes empty, or
# being replaced), then starts the control plane, which refuses to start if
# the database is older than the state anchor (PRIVACY/AUDIT STATE ROLLBACK).
#
#   ./restore.sh DIR
#
# The anchor is restored only into an empty anchor volume: an existing
# (newer) anchor is kept, so an old database backup can never roll back
# privacy spending silently. See docs/deployment.md for recovery.
set -euo pipefail
cd "$(dirname "$0")"
DIR="$(cd "${1:?usage: restore.sh DIR}" && pwd)"
( cd "$DIR" && shasum -a 256 -c SHA256SUMS >/dev/null ) || { echo "backup checksums do not match" >&2; exit 1; }
docker compose stop control evaluator keybroker >/dev/null 2>&1 || true
docker compose up -d postgres
for _ in $(seq 60); do docker compose exec -T postgres pg_isready -U encompute >/dev/null 2>&1 && break; sleep 1; done
docker compose exec -T postgres psql -q -U encompute encompute < "$DIR/db.sql" >/dev/null
untar() { docker run --rm -v "encompute_$1:/v" -v "$DIR:/b:ro" alpine sh -c "$2"; }
untar anchor '[ -z "$(ls -A /v)" ] && tar -C /v -xf /b/anchor.tar && echo "anchor restored" || echo "anchor kept (existing anchor is authoritative)"'
untar broker 'tar -C /v -xf /b/broker.tar'
untar evaluator 'tar -C /v -xf /b/evaluator.tar'
docker compose up -d control
echo "restored from $DIR; the control plane verifies the database against the anchor at start"
