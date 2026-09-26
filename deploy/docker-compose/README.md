# Encompute on Docker Compose

The first supported deployment:
- the control plane and its PostgreSQL;
- an OpenFHE evaluator (CKKS and OpenFHE exact);
- a key broker whose KEK is wrapped by a root key in OpenBao;
- a secure-aggregation coordinator (profile `secagg`).

It runs in production mode: OIDC identities only, secrets from files, no
development fallbacks. See [docs/deployment.md](../../docs/deployment.md) for
the architecture and [docs/api.md](../../docs/api.md) for the API.

## Start

```sh
# Images (from the repository root)
docker build -f Dockerfile.control  -t encompute-control:dev .
docker build -f Dockerfile.services -t encompute-services:dev .
docker build -f Dockerfile.evaluator -t encompute-evaluator:dev .

cd deploy/docker-compose
export ENCOMPUTE_OIDC_ISSUER=https://login.example.com   # your identity provider
export ENCOMPUTE_OIDC_JWKS_URL=https://login.example.com/.well-known/jwks.json
./init.sh                     # secrets/ (random) and .env (public keys, OIDC)
docker compose up -d postgres openbao control
docker compose exec control encompute-control bootstrap --issuer "$ENCOMPUTE_OIDC_ISSUER" --subject YOUR-SUBJECT
```

Then, as the platform admin (with a token from your identity provider):

1. Create organizations: `POST /v1/organizations`, naming each one's first
   admin.
2. Register the platform services with the public keys from `.env`: the
   evaluator, the key broker (URL `http://openbao:8760`) and the SecAgg
   coordinator.
3. Create the root key in your KMS: `transit/keys/ORG`.
4. Protect each asset key:

   ```sh
   docker compose run --rm keybroker keys protect ... --root-key openbao:transit/ORG --organization ORG
   ```

5. `docker compose up -d evaluator keybroker`.

`smoke.sh` does all of this with a throwaway identity provider, then runs:
- a job through the stack;
- a restart;
- a backup, a full teardown and a restore;
- a revocation.

## The KMS

The bundled OpenBao runs in **development mode, in memory**: it stands in for
the customer's KMS in trials. Point the key broker at your own OpenBao or
Vault instead: set `BAO_ADDR` (https) and a token file. The broker shares
OpenBao's network namespace here, so it reaches it on loopback. The root-key
client refuses plain HTTP to anything else.

## Backup and restore

```sh
./backup.sh /backups/2026-09-27      # database, anchor, key broker state, evaluator identity
./restore.sh /backups/2026-09-27
```

The state anchor (signed privacy and audit roots) is restored only into an
empty anchor volume. If a restored database is older than the anchor, the
control plane refuses to start (PRIVACY STATE ROLLBACK). Then either restore
a newer backup, or run `encompute-control recover`, which freezes the
affected privacy ledgers so the forgotten spending is never reused.

## Operations

- `curl http://127.0.0.1:8770/ready`, `/live` and `/metrics` (Prometheus).
- Drain an evaluator before upgrading it: `POST /v1/evaluators/evaluator-1/status {"status":"draining"}`.
- `docker compose logs control` gives JSON lines with request, job, project
  and organization IDs, and never payloads.
