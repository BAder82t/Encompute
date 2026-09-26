#!/usr/bin/env bash
# Backs up the deployment's durable state into DIR:
#   db.sql          PostgreSQL (organizations, projects, assets, plans, jobs,
#                   privacy ledgers, trust metadata, audit records)
#   anchor.tar      the state anchor (signed privacy and audit roots)
#   broker.tar      the key broker's state: wrapped keys and the wrapped KEK
#                   (no plaintext key: the root key stays in the KMS)
#   evaluator.tar   the evaluator's receipt-signing identity
#
#   ./backup.sh DIR
#
# Large encrypted artifacts live in object storage with its own replication.
set -euo pipefail
cd "$(dirname "$0")"
DIR="${1:?usage: backup.sh DIR}"
mkdir -p "$DIR"; chmod 700 "$DIR"
docker compose exec -T postgres pg_dump -U encompute --clean --if-exists encompute > "$DIR/db.sql"
vol() { docker run --rm -v "encompute_$1:/v:ro" -v "$(cd "$DIR" && pwd):/b" alpine tar -C /v -cf "/b/$1.tar" .; }
vol anchor; vol broker; vol evaluator
chmod 600 "$DIR"/*
( cd "$DIR" && shasum -a 256 db.sql anchor.tar broker.tar evaluator.tar > SHA256SUMS )
echo "backup in $DIR: $(wc -c < "$DIR/db.sql" | tr -d ' ') bytes of database, anchor, broker, evaluator identity"
