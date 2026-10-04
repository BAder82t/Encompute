# Reference production topology

This page describes one blessed topology for running Encompute with TLS in
front of every client, PostgreSQL that accepts only TLS, an external
OpenBao or Vault, and secrets as files. It is built from the existing
services with configuration and scripts only
([deploy/production](../deploy/production/)). There is one topology on
purpose: it is the one that is validated, and the one a review should start
from.

It is a reference production topology, not a certification. The validation
script checks that a running deployment is configured the way this page says.
It does not check that the deployment is secure (see [What the validation does
not show](#what-the-validation-does-not-show)). No external review or audit
of this topology has been done.

## Topology

```text
   clients (CLI, SDK, browsers)      operators / monitoring     platform services,
                │  TLS                      │  mutual TLS       attested workloads
                │                           │                         │ mutual TLS
        :8443 API   :8444 evaluator    :8445 ops (health, metrics)   :8446 key broker
   ┌────────────┴───────────┴───────────────┴────────────────────────┴──────────┐
   │ edge (Caddy): terminates TLS 1.2+, verifies client certificates on 8445/8446│
   └───────┬─────────────────────┬───────────────────────────┬──────────────────┘
           │ backend network (internal: no route out)        │
   ┌───────▼────────┐   ┌────────▼───────┐   ┌────────────────▼───────────────┐
   │ control plane  │   │   evaluator    │   │ key broker                      │
   │ (shares the    │   │   (OpenFHE)    │   │ (shares the namespace of        │
   │ namespace of   │   └────────────────┘   │  bao-tunnel)                    │
   │ pg-tunnel)     │                        └───────────────┬─────────────────┘
   └───────┬────────┘                                        │ loopback http
           │ loopback, no TLS                       ┌────────▼────────┐
   ┌───────▼────────┐                               │ bao-tunnel      │
   │ pg-tunnel      │                               │ (stunnel)       │
   │ (stunnel): TLS │                               └────────┬────────┘
   │ + client cert, │                                        │ TLS, chain and name
   │ verifies name  │                                        │ verified
   └───────┬────────┘                                        │
           │ TLS 1.2+, client certificate required   ┌───────▼─────────────────┐
   ┌───────▼────────┐                                │ OpenBao / Vault         │
   │ PostgreSQL 16  │                                │ EXTERNAL: TLS listener, │
   │ hostssl only   │                                │ raft storage, sealed    │
   └────────────────┘                                │ until unsealed          │
                                                     └─────────────────────────┘
   volumes: pgdata, anchor (state anchor), broker (wrapped keys), evaluator (identity)
   secrets: files under ./secrets, mounted at /run/secrets (never environment values)
```

Only the edge publishes ports. The `backend` network is a Docker internal
network: the database, evaluator and key broker have no route out. The
control plane and the tunnels sit on one more network each (`egress`, `bao`)
because the control plane fetches its identity provider's keys and the key
broker must reach the vault.

### Why two tunnels

The control plane connects to PostgreSQL without TLS, and the key broker's
HTTPS client trusts only the built-in public web roots, so it cannot verify a
private CA. Neither binary has TLS settings you can configure (see
[known limitations](../KNOWN_LIMITATIONS.md)). The topology therefore puts a TLS
client sidecar in the same network namespace as each of them, the pattern the
Compose deployment already uses for its key broker:

- `pg-tunnel` (stunnel, protocol `pgsql`): the control plane connects to
  `127.0.0.1:5432` inside the shared namespace, with `sslmode=disable` in its
  connection string, which never leaves that namespace. The sidecar speaks
  TLS to PostgreSQL, verifies the certificate chain and the name (`verifyChain`
  and `checkHost`, the equivalent of `sslmode=verify-full`) and presents a
  client certificate. PostgreSQL's `pg_hba.conf` accepts only `hostssl` with
  `clientcert=verify-full`, so a connection without TLS or without the
  certificate is refused by the server, not just discouraged by the client.
- `bao-tunnel` (stunnel): the key broker uses `BAO_ADDR=http://127.0.0.1:8200`.
  The broker accepts plain HTTP only on loopback. The sidecar verifies the
  vault's certificate against your CA and name.

The honest consequence: the control plane's connection string says
`sslmode=disable`, and the guarantee comes from the sidecar and the server's
`pg_hba.conf`. Native TLS in the binaries would remove both sidecars; it is not
done (see [What is not covered](#what-is-not-covered)).

## What each component protects, and what it trusts

| Component | Protects | Trusts |
|---|---|---|
| Edge (Caddy) | Confidentiality and integrity of client and operator traffic in transit; keeps the operations and key-broker listeners to holders of a client certificate; keeps `/metrics` off the public listeners. | The server certificate you give it, and the client CA. It forwards to the backend over the internal network without TLS: the backend network is the trust boundary. |
| Control plane | Tenancy, policy, plans, jobs, trust evidence, the audit trail. Authenticates every request itself (OIDC tokens, signed service requests). | The identity provider's keys; PostgreSQL, through the tunnel; its anchor volume. |
| PostgreSQL | The database's contents in transit (TLS 1.2+, client certificate, SCRAM). | Its own volume and host. It is not encrypted at rest by this topology: use volume encryption. |
| pg-tunnel | The control plane's database connection. | The internal CA you give it. |
| Evaluator | Computes on ciphertexts only; holds no client secret key. | The control plane's pinned public key. |
| Key broker | Releases asset keys to attested workloads under their owners' policies. | The vault (through bao-tunnel), and the attestation provider's keys. |
| bao-tunnel | The key broker's connection to the vault. | The vault CA you give it. |
| OpenBao / Vault (external) | The organization's root key (not exportable): the broker's KEK is wrapped under it. | Its operators and its seal. |
| `./secrets` | Signing keys, database password, TLS keys, tokens, as files. | The host's file permissions: the directory is 0700, as in the Compose deployment. |

## Bring-up

The commands below are what [`lab-up.sh`](../deploy/production/lab-up.sh)
executes on a laptop with throwaway certificates; a real deployment replaces
the certificate and vault steps with its own.

1. **Certificates.** Provide, in `deploy/production/secrets/`:
   the edge's server certificate and key (`edge.crt`, `edge.key`; from a CA your
   clients trust: the Encompute CLI and SDK verify servers against the built-in
   public web roots, so use a publicly trusted certificate for the API and
   evaluator listeners if they will be reached by those clients), `client-ca.crt`
   (the CA whose client certificates the edge accepts), `internal-ca.crt` with
   `pg-server.{crt,key}` (name `postgres`) and `pg-client.{crt,key}` (CN
   `encompute`, the database role), and `bao-ca.crt` (the CA that signed the
   vault's certificate). Use separate CAs for separate purposes.
   `gen-test-certs.sh` makes a throwaway set for a laptop and nothing else.
2. **The vault.** An OpenBao or Vault you operate, reachable over TLS (see
   [The external OpenBao or Vault](#the-external-openbao-or-vault)). Run
   `bootstrap-openbao.sh` against it, then `bao-token.sh login`.
3. **Secrets.** `ENCOMPUTE_OIDC_ISSUER=... BAO_UPSTREAM=host:port
   BAO_SERVER_NAME=name ./init-secrets.sh` writes the random secrets (database
   password, signing keys, metrics token) and `.env` (public keys, ports).
4. **Database, control plane and edge.** `docker compose up -d postgres
   pg-tunnel control bao-tunnel edge`, then
   `docker compose exec control encompute-control bootstrap --issuer ISSUER
   --subject YOU`.
5. **Register the platform services** through the edge (`POST
   /v1/organizations/platform/service-accounts` for the evaluator and for the
   key broker, with the public keys in `.env`; the broker's URL is
   `http://bao-tunnel:8760`). The evaluator cannot register with the control
   plane until its service account exists.
6. **Protect the first asset** with `protect-asset.sh ASSET POLICY.json`. The key
   broker refuses to start without its state; this creates it and wraps its KEK
   in the vault.
7. **The rest.** `docker compose up -d`.
8. **Validate.** `./validate.sh` (below).

Images are pinned by digest in `compose.yaml`. The Encompute images default to
the digests published with the v0.3.0 release (verify them as
[verify-release.md](verify-release.md) describes) and are overridable with
`ENCOMPUTE_CONTROL_IMAGE`, `ENCOMPUTE_EVALUATOR_IMAGE` and
`ENCOMPUTE_SERVICES_IMAGE`. The release images are `linux/amd64`. The tunnel
image is built from `deploy/production/tunnel/Dockerfile` (a digest-pinned
Alpine base; the stunnel package is the one Alpine 3.20 ships and is not pinned
by version).

## The external OpenBao or Vault

The vault is not part of the Compose project: it is the customer's, and its
operators are a different trust domain from the platform's. Expectations:

- **Not dev mode.** A TLS listener, persistent storage (integrated raft or
  another persistent backend), sealed until initialised and unsealed.
  [`config/openbao.hcl`](../deploy/production/config/openbao.hcl) and
  [`compose.openbao.yaml`](../deploy/production/compose.openbao.yaml) show the
  shape, and are what the laboratory run uses.
- **Initialisation and unseal.** `bootstrap-openbao.sh` initialises (5 shares,
  threshold 3 by default) and unseals through the HTTP API, and writes the
  shares to a 0600 file you must move into your own custody and delete from
  the host. Production vaults normally auto-unseal through a cloud KMS or an
  HSM, in which case there are no shares to handle. The script revokes the root
  token when it finishes; administer the vault again with `operator
  generate-root`.
- **Policy.** [`keybroker-policy.hcl.template`](../deploy/production/config/keybroker-policy.hcl.template)
  lets the key broker encrypt and decrypt with one Transit key, read its
  metadata and rotate it, and inspect and renew its own token. It cannot read
  key material (the key is not exportable), create or delete keys, or touch any
  other path.
- **AppRole.** The script creates an AppRole with that policy and periodic,
  renewable tokens (24 hours by default). The key broker reads a token file and
  cannot log in, so `bao-token.sh login` writes `secrets/bao-token` from the
  role-id and secret-id, and `bao-token.sh renew` renews it (run it from a timer,
  every six hours, and alert on failure). A new token needs a key broker
  restart; a renewal does not. Production deployments should deliver the
  secret-id wrapped and bind the role to the broker's address; the script uses
  an unwrapped, unbound secret-id for simplicity.
- **Audit.** The script enables an audit device that writes to stdout.
- **Backup of the vault.** Not part of `backup.sh`. Take a raft snapshot (`bao
  operator raft snapshot save`) on your own schedule with a token that has
  that capability, and keep the unseal shares or the auto-unseal key. Without
  the root key, the wrapped KEK in a restored key broker cannot be opened.

## Secrets

Every secret is a file under `deploy/production/secrets/` (directory mode
0700, git-ignored), declared in the `secrets:` block of `compose.yaml` and
mounted at `/run/secrets`. No secret is an environment value: the services take
`*_FILE` variables. The validation compares every secret file's contents with
every container's environment and command line.

| Secret | Used by |
|---|---|
| `db-password`, `db-url` | PostgreSQL; the control plane (`db-url` points at the tunnel) |
| `control.key`, `evaluator.key` | service signing keys |
| `metrics-token` | the control plane's `/metrics` |
| `bao-token` | the key broker (periodic AppRole token) |
| `edge.{crt,key}`, `client-ca.crt` | the edge |
| `pg-server.{crt,key}`, `internal-ca.crt` | PostgreSQL |
| `pg-client.{crt,key}`, `internal-ca.crt` | pg-tunnel |
| `bao-ca.crt` | bao-tunnel |

PostgreSQL insists its key is owned by it and not readable by others; a
mounted secret is neither, so the PostgreSQL container copies the key into a
tmpfs it owns at start (never into the data volume).

## Health checks

| Service | Check | Meaning |
|---|---|---|
| postgres | `pg_isready` over TCP and a query over the socket | the final server is up and the database exists |
| pg-tunnel, bao-tunnel | the loopback port is open | the TLS client is listening |
| control | `GET /ready` | the database answers |
| evaluator | `GET /v1/info` | the evaluator serves |
| keybroker | `GET /live` | the broker started, and could open its state |
| edge | `GET /live` through the API listener | TLS works and the control plane is reachable |

`depends_on` waits for `service_healthy`. Through the edge, an operator's
monitoring (client certificate) reaches `/control/live`, `/control/ready`,
`/evaluator/v1/info` and `/keybroker/live` on the operations listener, and
`/control/metrics` with the metrics token.

## Backup and the drill

`backup.sh DIR` and `restore.sh DIR` are the Compose deployment's, adapted to
this topology (anchor first, then the database taken over the container's local
socket; the anchor and the key broker's state are restored only into empty
volumes). `backup.sh --verify DIR` checks a backup without touching the running
topology: checksums, archives, and the dump restored into a scratch PostgreSQL
with no network.

`scripts/release/backup-drill.sh --production` is the drill for this topology.
It is destructive (it removes the stack's containers and volumes), so it is for
a laboratory or a staging copy. It:

1. creates an organization, a dataset and privacy spending through the TLS edge;
2. takes a backup, verifies it, and checks it holds no secret value;
3. spends after the backup, then destroys every container and volume and runs
   `restore.sh`: the state is the backup's (spending after it is forgotten, as
   the Compose drill documents), and all services are healthy again, the key
   broker having opened its wrapped KEK through the vault;
4. restores the older backup over the newer anchor: the control plane refuses to
   start (PRIVACY STATE ROLLBACK), `recover` freezes the ledger, and a spend on
   it is refused (409 ENC2201).

Not covered by the drill: the vault's own backup and restore, and `./secrets`,
which must survive in your secret manager.

## Validation

```sh
cd deploy/production
./validate.sh                       # configuration checklist
./validate.sh --backup-dir DIR      # also verify a backup
./validate.sh --drill               # also run the destructive drill (laboratory)
./negative/run.sh                   # prove the validator fails a misconfigured topology
```

`validate.sh` prints one PASS, FAIL or SKIP line per requirement and exits 1 if
any fails.

| ID | Requirement |
|---|---|
| TOP-01..03 | images pinned by digest; only the edge publishes ports; the backend network is internal |
| EDGE-01..07 | TLS on the API listener; plaintext does not reach the service; TLS 1.2+ on all four listeners; the operations and key-broker listeners refuse no certificate, and the operations listener an untrusted one; `/metrics` is off the public listener and token-protected |
| PG-01..07 | `ssl=on`, TLS 1.2+, SCRAM; `pg_hba` has no plaintext accepting rule and no trust over the network; a plaintext connection and a TLS connection without a client certificate are refused; every network connection is TLS; the password is not a default; the control plane's connection is verified (chain and name) |
| BAO-01..06 | https verified against your CA; plaintext refused; initialised and unsealed; not in-memory storage; no dev-mode container; the broker's token is periodic, renewable, and holds only its policy |
| SEC-01..06 | no secret-named environment variable; no secret value in any environment or command line; secrets mounted as files; the control plane in production mode with `*_FILE` secrets; `secrets/` is 0700; no secret tracked in git |
| HLTH-01..03 | every service has a health check; all report healthy; the endpoints answer 200 through the edge |
| BAK-01..02 | a backup verifies; the drill passes (both optional) |

`negative/run.sh` starts a deliberately misconfigured topology (plaintext
PostgreSQL, dev-mode OpenBao over http, no client certificate required,
secrets in the environment, no health check) and asserts that the validator
exits non-zero and fails each of the matching checks.

### What the validation does not show

The validation script checks configuration. It shows that a running topology
is set up the way the reference topology requires. It is not a penetration
test, a proof of security, or an audit. It does not test the application, does
not check how your certificates were issued or are rotated, whether your vault
shares are in safe custody, whether your host or Docker daemon is hardened,
what else shares the network, or whether the images match what you reviewed
(verify those yourself, as [verify-release.md](verify-release.md) describes). A
PASS means no listed misconfiguration was found.

## Hardening checklist

- Replace the throwaway certificates with certificates from your own CAs, one
  CA per purpose, with a rotation plan (`CERT_DAYS` in the laboratory script is
  30 days).
- Publish the edge only on the interfaces that need it (`EDGE_BIND`), and put
  a network firewall in front of ports 8445 and 8446.
- Keep the vault's operators separate from the platform's. Move the init
  output out of the host; revoke the root token (the script does).
- Wrap the AppRole secret-id and bind it to the key broker's address; renew
  the token on a timer and alert on failure.
- Put the anchor in your vault (`ENCOMPUTE_ANCHOR_BAO_*`, https) rather than on a
  volume that could be restored with the database, once the vault's CA is one
  the control plane trusts (see not covered).
- Encrypt the volumes and the backups at rest; restrict access to backups (a
  restored older key broker state brings back revoked keys).
- Alert on `encompute_state_rollback_total`, `encompute_anchor_bytes` and the
  `encompute_legacy_service_admins` gauge ([deployment.md](deployment.md#operations)).
- Pin and review upgrades: new image digests, the new `compose.yaml`, and
  rerun `validate.sh`.
- Disable or encrypt swap on the vault host (OpenBao no longer calls `mlock`).
- Give the Docker daemon and the host the same care as the secrets they hold:
  anyone who can run `docker exec` can read every secret.

## What is not covered

- **High availability.** One of each service, one database. No replicated
  control plane, no database failover, no vault cluster beyond what you run
  yourself. A restart is a restore from backup when state is lost.
- **Native TLS in the Encompute binaries.** TLS is provided by the edge and the
  two stunnel sidecars. The control plane has no TLS client for PostgreSQL and
  the key broker's HTTPS client trusts only built-in public roots, so a
  vault, an identity provider or an anchor vault behind a private CA works only
  through a sidecar like `bao-tunnel`. Evaluators and the control plane speak
  plain HTTP on the backend network.
- **Mutual TLS for everything.** Mutual TLS is required on the operations and
  key-broker listeners only. The API and evaluator listeners authenticate
  with OIDC tokens and signed requests, because the CLI and SDK present no client
  certificates.
- **KMS adapters beyond OpenBao and Vault Transit.** No AWS, GCP or Azure KMS.
- **A multi-machine evaluator.** One job runs on one machine.
- **Kubernetes and Helm.**
- **Anchor in the vault with a private CA.** The anchor lives on its own
  volume in this topology.
- **At-rest encryption of the volumes, secret management beyond files,
  secret-id wrapping, and certificate issuance and rotation.** Yours to provide.
- **The secure-aggregation coordinator** is not part of this topology.
