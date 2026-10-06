#!/usr/bin/env bash
# Backs up the deployment's durable state into DIR:
#   db.sql          PostgreSQL (organizations, projects, assets, plans, jobs,
#                   privacy ledgers, trust metadata, audit records)
#   anchor.tar      the state anchor (signed privacy and audit roots and the
#                   governance log's head) with the governance log's mirror
#                   (governance-log/: every anchored event, in immutable
#                   segments), from which recovery restores the events an
#                   older database backup lacks
#   broker.tar      the key broker's state: wrapped keys and the wrapped KEK
#                   (no plaintext key: the root key stays in the KMS). The
#                   state is authenticated under the KEK. A revocation
#                   replaces the KEK, but a backup taken before it holds
#                   the old state and the old wrapped KEK, which opens
#                   while the root key version that wraps it does: after
#                   a revocation, run `keys rotate-root
#                   --retire-old-versions` (docs/deployment.md), and keep
#                   backups access-controlled
#   evaluator.tar   the evaluator's receipt-signing identity
#
#   ./backup.sh DIR
#
# Large encrypted artifacts live in object storage with its own replication.
set -euo pipefail
cd "$(dirname "$0")"
DIR="${1:?usage: backup.sh DIR}"
mkdir -p "$DIR"; chmod 700 "$DIR"
# Streamed to the host, so the files belong to the operator, not to the
# container's root (which the chmod below could not change on Linux).
vol() { docker run --rm -v "encompute_$1:/v:ro" alpine tar -C /v -cf - . > "$DIR/$1.tar"; }
# The anchor BEFORE the database: spending commits to the database before it
# is anchored, so a dump taken after the anchor always extends it. The other
# order lets a spend (or an audit checkpoint) land between the two, and the
# backup restores as a rollback that only `recover` (freezing) gets past.
vol anchor
test -n "$(tar -tf "$DIR/anchor.tar" | grep -m1 'governance-log/' || true)" \
  || echo "note: the anchor volume holds no governance log mirror yet (written at the first checkpoint)" >&2
docker compose exec -T postgres pg_dump -U encompute --clean --if-exists encompute > "$DIR/db.sql"
vol broker; vol evaluator
chmod 600 "$DIR"/*
( cd "$DIR" && shasum -a 256 db.sql anchor.tar broker.tar evaluator.tar > SHA256SUMS )
echo "backup in $DIR: $(wc -c < "$DIR/db.sql" | tr -d ' ') bytes of database, anchor, broker, evaluator identity"
