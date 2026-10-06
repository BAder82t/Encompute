#!/usr/bin/env bash
# Restores a backup from DIR into a stopped deployment (volumes empty, or
# being replaced), then starts the control plane, which refuses to start if
# the database is older than the state anchor (PRIVACY/AUDIT STATE ROLLBACK):
# any backup older than the last anchored checkpoint (in practice older than a
# couple of seconds or the last deny event) is refused until
# `docker compose run --rm control recover --operator NAME` records the
# rewind (the audit events after the backup are lost: the chain has no mirror).
#
#   ./restore.sh DIR
#
# The anchor is restored only into an empty anchor volume: an existing
# (newer) anchor is kept, so an old database backup can never roll back
# privacy spending silently. See docs/deployment.md for recovery. The key
# broker's state is likewise restored only into an empty broker volume: an
# existing one keeps keys destroyed (revoked) or protected since the backup.
set -euo pipefail
cd "$(dirname "$0")"
DIR="$(cd "${1:?usage: restore.sh DIR}" && pwd)"
( cd "$DIR" && shasum -a 256 -c SHA256SUMS >/dev/null ) || { echo "backup checksums do not match" >&2; exit 1; }
docker compose stop control evaluator keybroker >/dev/null 2>&1 || true
docker compose up -d postgres
# Wait for the real server, not the image's temporary start-up server: that one
# listens only on the Unix socket, answers pg_isready and then restarts, and
# creates the database late. A query over TCP succeeds only once the final
# server is up and the database exists.
for _ in $(seq 120); do docker compose exec -T postgres psql -h 127.0.0.1 -q -U encompute -d encompute -c 'select 1' >/dev/null 2>&1 && break; sleep 1; done
# One transaction, stopping at the first error: a partial restore fails
# (and leaves the database as it was) instead of reporting success.
docker compose exec -T postgres psql -q -v ON_ERROR_STOP=1 --single-transaction -U encompute encompute < "$DIR/db.sql" >/dev/null
untar() { docker run --rm -v "encompute_$1:/v" -v "$DIR:/b:ro" alpine sh -c "$2"; }
untar anchor '[ -z "$(ls -A /v)" ] && tar -C /v -xf /b/anchor.tar && echo "anchor restored" || echo "anchor kept (existing anchor is authoritative)"'
untar broker '[ -z "$(ls -A /v)" ] && tar -C /v -xf /b/broker.tar && echo "broker restored" || echo "broker kept (existing broker state is authoritative)"'
untar evaluator 'tar -C /v -xf /b/evaluator.tar'
docker compose up -d control
echo "restored from $DIR; the control plane verifies the database against the anchor at start"
