# Application security review brief

For the external application-security reviewer. Each area states the
claim, where it is implemented, how it is tested, and specific questions.
Background: [threat-model.md](../docs/threat-model.md) (sections 4.5 to
4.8), [protocols.md](protocols.md), [docs/deployment.md](../docs/deployment.md),
[docs/api.md](../docs/api.md).

Stack: Rust services on `tiny_http` 0.12 (plain HTTP), synchronous
`postgres` 0.19 with `r2d2` pooling, `jsonwebtoken` 11.1, `ureq` 2.12 for
outbound calls, `ed25519-dalek` 2.2. Python SDK over the same API.

The end-to-end check of this surface is
[`scripts/enterprise-e2e.sh`](../scripts/enterprise-e2e.sh) (production
mode) and [`deploy/docker-compose/smoke.sh`](../deploy/docker-compose/smoke.sh).
The control-plane tests need PostgreSQL and OpenBao
(`ENCOMPUTE_TEST_DATABASE_URL`, `ENCOMPUTE_TEST_BAO_ADDR`,
`ENCOMPUTE_TEST_BAO_TOKEN`); see [README.md](README.md#build-and-test).

## A1. OIDC and user authentication

**Claim.** People authenticate with OpenID Connect. Each token is checked
against the issuer's JWKS: signature, issuer, audience, expiry. Only
asymmetric algorithms are accepted from an identity provider. Development
tokens are refused in production (INV-156, INV-164).

**Where.** `crates/encompute-control/src/authn.rs`:

- the issuer is read unverified only to pick the configured issuer;
- accepted algorithms: RS256/384/512, ES256/384, PS256/384/512; a `kid` is
  required; tokens ≤ 16 KiB;
- `exp`, `iss`, `aud`, `sub` required; 60 s leeway; `nbf` and `iat` are
  not checked;
- the `(issuer, subject)` pair must be an active user; roles come from
  memberships;
- JWKS from a file, inline, or a URL (default `{issuer}/.well-known/jwks.json`,
  no discovery document); a known `kid` is served from cache without
  refresh; an unknown `kid` refetches at most once a minute.

Configuration and production refusals: `crates/encompute-control/src/config.rs`
(`validate`: no development secret, an https issuer and JWKS URL, a signing
key file, a non-default database password, an https anchor address).

**Tests.** `oidc_tokens_and_production_refusals`, `credentials_are_checked`
(`crates/encompute-control/tests/isolation.rs`, including an HS256 token
naming the real issuer); `production_refuses_insecure_fallbacks`
(`config.rs`).

**Questions.**

1. Is issuer selection from the unverified payload safe with several
   configured issuers?
2. A signing key removed from the provider's JWKS stays trusted until
   restart. What is the practical exposure after a provider key
   compromise?
3. Only one issuer can be configured from the environment. Any issue with
   how users of different organizations are tied to issuers
   (`create_user` accepts an issuer string)?
4. Is there any way to obtain a development token or reach the development
   issuer in production mode?

## A2. Tenant isolation

**Claim.** An authenticated identity cannot read or use resources owned
solely by another organization without an explicit collaboration grant
(project membership plus the owner's asset approval for a project and
purpose). Other tenants' IDs do not confirm existence (INV-156).

**Where.** `crates/encompute-control/src/authz.rs` (`require`,
`project_visible`, `asset_visible`), `ops/tenancy.rs`, `ops/assets.rs`,
`ops/jobs.rs` (`job_visible`), `ops/policies.rs`. Isolation is
application-level: role checks plus organization filters in SQL. There is
no PostgreSQL row-level security, and one database role is used.

**Tests.** `every_route_authenticates_authorizes_and_isolates`,
`cross_tenant_attacks_fail` (`tests/isolation.rs`); `scripts/enterprise-e2e.sh`.

**Questions.**

1. Does every reference a tenant supplies (asset key references naming a
   key broker and key, storage URIs, service-account URLs, collaboration
   targets) get checked for ownership before the control plane acts on it,
   including in messages it sends to other services on the tenant's behalf?
2. Do uniqueness conflicts (identities, service IDs and keys, evaluator
   receipt keys) reveal the existence of another tenant's objects?
3. Can the platform organization's roles be obtained or impersonated by a
   tenant?
4. Would row-level security be worth adding as defense in depth?

## A3. API authorization

**Claim.** Every route authenticates and then authorizes by role in the
relevant organization. Policies need a second admin's approval (four
eyes). Only the scheduled evaluator can start a job (INV-156, INV-163).

**Where.** `crates/encompute-control/src/api.rs` (routing, body limit
8 MiB, idempotency keys), `authz.rs`, `ops/*.rs`. Roles:
`organization_admin`, `security_admin`, `data_owner`, `model_owner`,
`ml_developer`, `auditor`, `operator` (`model.rs`, and a database CHECK).
`/metrics`, `/live`, `/ready` and `/v1/info` need no authentication.

**Tests.** `every_route_authenticates_authorizes_and_isolates`,
`submission_is_idempotent_even_concurrently`,
`jobs_run_only_on_compatible_ready_evaluators`
(`crates/encompute-control/tests/`).

**Questions.**

1. Does the role table in `docs/deployment.md` match the code for every
   route (for example who may spend privacy budget, create plans, and
   create audit checkpoints)?
2. `create_plan` parses and compiles a program of up to 4 MiB. Does any
   expensive work happen before authorization?
3. There is no rate limiting and no socket read timeout on the control
   plane. What is the cost of a slow-body attack against the default 8
   worker threads?
4. Is anything sensitive exposed by `/metrics` or `/v1/info`?

## A4. SQL boundaries and state integrity

**Claim.** All SQL is parameterized. Privacy spending is race-safe and
idempotent. Restoring an older database is detected against the signed
state anchor, and startup is refused (INV-158, INV-159, INV-160, INV-162).

**Where.** `crates/encompute-control/src/db.rs` (pool, migrations with
checksums under an advisory lock, retries on deadlock and serialization
failures), `migrations/0001_initial.sql`, `0002_evaluator_profiles.sql`,
`ops/assets.rs` (`privacy_spend`: row lock, idempotency by event ID,
frozen ledgers), `audit.rs` (hash chain under a lock on `audit_head`),
`anchor.rs`, `control.rs` (startup rollback check and recovery). The
isolation level is READ COMMITTED with explicit row locks. The only SQL
built with `format!` appends a constant `FOR UPDATE`.

The driver is configured with `NoTls`: database traffic is plaintext.

**Tests.** `privacy_spending_is_race_safe_and_idempotent`,
`restart_keeps_spending_and_restoring_an_older_backup_is_refused`,
`truncated_audit_and_tampered_or_missing_anchor_are_refused`,
`audit_chain_is_tamper_evident_and_anchored`
(`crates/encompute-control/tests/state.rs`).

**Questions.**

1. Is any query injectable, or any identifier interpolated?
2. Are the row locks sufficient under READ COMMITTED for every
   security-relevant state transition (job start, revocation racing
   submission, privacy spend, policy approval)?
3. Message deduplication (`inbox`) and the message's effect run in
   separate database operations. Which message kinds are not idempotent
   under a crash or concurrent duplicate?
4. The audit chain between anchored checkpoints (every 100 events by
   default) is protected only by an unkeyed hash chain. Is that acceptable?
5. The Compose deployment stores the anchor in a directory volume and
   backs it up with the database. Does that defeat rollback detection
   in practice?

## A5. KMS and Vault (OpenBao Transit)

**Claim.** Production asset keys are protected by the customer's root key
in OpenBao or Vault Transit, and never fall back to local or plaintext
storage (INV-157, INV-042, INV-161).

**Where.** `crates/encompute-keybroker/src/root.rs` (`OpenBaoTransit`:
token in `X-Vault-Token`, `encrypt`/`decrypt` with associated data naming
the organization, rewrap as decrypt then encrypt, `rotate`; https required
except for loopback addresses; 10 s timeout; token from `BAO_TOKEN_FILE`
or `BAO_TOKEN`), `store.rs` (`LocalKekStore`, `RootWrappedKekStore`),
`lib.rs` (production mode refuses development stores and evidence). The
control plane uses OpenBao only for the optional KV v2 anchor.

**Tests.** `openbao_wraps_unwraps_rotates_rewraps_and_revokes`,
`openbao_failures_never_fall_back`,
`development_root_key_wraps_rotates_and_is_refused_in_production`
(`crates/encompute-keybroker/tests/root_keys.rs`, skipped unless
`ENCOMPUTE_TEST_BAO_ADDR` is set).

**Questions.**

1. Is the "plain HTTP only on loopback" rule for the OpenBao address
   implemented robustly for every URL form?
2. The Transit key type is not set or checked by Encompute. Should it be?
3. Revocation replaces the stored key with `Destroyed` in the broker's
   state file; the KEK is unchanged. What do older copies of the state
   file (backups, temporary files) still allow?
4. What Transit policy should the broker's token have? The Compose
   deployment uses the development root token.
5. The key broker's challenge, attest and release endpoints have no caller
   authentication, and grants are not signed by the broker. Is the
   resulting exposure acceptable given attestation and HPKE sealing?

## A6. Containers

**Claim.** Services run as non-root users in minimal images; secrets come
from files (INV-164 covers the production refusals, not container
hardening).

**Where.** `Dockerfile.control` (uid 10002), `Dockerfile.evaluator` (uid
10001), `Dockerfile.services` (uid 10003); `deploy/docker-compose/compose.yaml`,
`init.sh`, `backup.sh`, `smoke.sh`; `deploy/confidential-space*/`.

Facts:

- Base images are referenced by tag, not by digest (`rust:1.98-bookworm`,
  `debian:bookworm-slim`, `postgres:16-alpine`, `openbao/openbao:2.1.0`).
  OpenFHE is cloned by tag.
- Compose sets no `read_only`, `cap_drop`, `no-new-privileges` or resource
  limits.
- `init.sh` creates secrets in a 0700 directory but sets each file to
  mode 0644; the comment in `compose.yaml` says 0600.
- The OpenBao development root token is written to `.env` and passed in
  the container environment.
- Healthchecks exist only for the control plane and PostgreSQL.

**Tests.** `deploy/docker-compose/smoke.sh`; the release gate's
Confidential Space image check (`scripts/release-check.sh`, "CS training
image"); `scripts/audit-commercial-build.sh` (no TFHE-rs in images).

**Questions.**

1. What hardening should the Compose deployment carry before it is
   presented as production-ready?
2. Is the Confidential Space training image minimal, and does the
   production image exclude the `encompute` CLI as the release gate checks?
3. Are image and dependency pins adequate for supply-chain integrity
   (`deny.toml`, `scripts/sbom.py`)?

## A7. Service identities

**Claim.** Every service has an Ed25519 key; identity is the key, never a
network location. Requests and messages are signed with a timestamp and a
single-use nonce; job grants come from the pinned control-plane key
(INV-156, INV-158, INV-163).

**Where.** `crates/encompute-verification/src/service.rs` (statement:
method, path with its canonical query string, sender, recipient, timestamp, nonce,
`bind`, body hash; ±300 s; message envelopes; job grants),
`crates/encompute-control/src/authn.rs` (nonce store in PostgreSQL),
`ops/tenancy.rs` (service-account registration and disabling),
`crates/encompute-evaluator/src/control.rs` (grant check, in-memory used
set, consent to start), `crates/encompute-keybroker/src/server.rs`
(control-plane messages, in-memory replay cache).

**Tests.** `credentials_are_checked` (replayed nonces),
`job_grants_bind_issuer_evaluator_program_and_expiry`
(`crates/encompute-verification/src/service.rs`),
`lifecycle_receipt_trust_and_duplicate_messages`,
`restart_preserves_jobs_and_never_replays`.

**Questions.**

1. The signature covers the path with its query parameters sorted into a
   canonical form. Can two different requests share a canonical target?
2. `bind` is informational. Is any authorization decision made from it
   anywhere?
3. There is no service-key rotation endpoint. What is the recovery path
   after a service key compromise?
4. A disabled evaluator service account: does it stop receiving jobs
   immediately?
5. Evaluator re-registration replaces its receipt key, and past receipts
   are re-verified against the current key. Is that the intended behavior?

## A8. Network exposure

**Claim.** Services never treat network location as identity. TLS is
provided by a proxy in front of each service.

**Facts.**

| Service | Default listen | Compose | TLS |
|---|---|---|---|
| Control plane | `127.0.0.1:8770` | `0.0.0.0:8770` in the container, published on host `127.0.0.1:8770` | none |
| Evaluator | `127.0.0.1:8750` | `0.0.0.0:8750`, published on host `127.0.0.1:8750` | none |
| Key broker | `127.0.0.1:8760` | `0.0.0.0:8760`, sharing OpenBao's network namespace | none |
| OpenBao | n/a | `127.0.0.1:8200` inside that namespace | none (development server) |
| PostgreSQL | n/a | on the default Compose network, not published | none (`NoTls`) |

The Compose deployment defines one default network with no segmentation
and runs no TLS proxy. The evaluator's API is unauthenticated except that
running a job needs a grant when a control plane is configured; program
and key uploads and result fetches are open. The default key-upload limit
is 4 GiB per request.

**Questions.**

1. What must a production deployment put in front of each service, and
   should the services refuse to start without it?
2. Is the unauthenticated evaluator API (program and key upload, result
   fetch by job ID) acceptable for a multi-tenant evaluator?
3. What memory exhaustion is possible through the evaluator's upload
   limits and 8 HTTP threads?

## A9. Logging and secrets

**Claim.** Audit records identify security-sensitive transitions without
protected payloads. Keys, data, weights, gradients and input values never
appear in logs, the database, audit output or metrics (INV-162, INV-081,
INV-129).

**Where.** `crates/encompute-control/src/log.rs` (JSON lines on stderr;
request logs with the path but not the query string), `audit.rs`
(`check_ref_value`), `metrics.rs` (label values restricted),
`config.rs` (`Debug` omits secrets; secrets in `Zeroizing`; `NAME_FILE`
preferred, plain environment variables accepted), `db.rs` (PostgreSQL
error text reaches API error bodies); key material types with redacted
`Debug` in `crates/encompute-keybroker/src/lib.rs`.

**Tests.** The canary scan in `scripts/enterprise-e2e.sh` (dataset
contents, input values and asset keys in no log, database dump, audit
record or metric); `state_round_trips_without_printing_keys`,
`keys_and_audit` (INV-081); `test_keys_stay_in_the_owners_key_store`
(INV-129).

**Questions.**

1. Do error messages returned to clients (including database error text)
   leak anything across tenants?
2. Are secret files read with any permission check? Service key files are
   not checked; the evaluator identity file is.
3. Is there an adversarial scan of logs for key material (INV-081 lists
   this as a gap)?
