# ADR-021 — Enterprise deployment foundation

Status: **Accepted** (2026-09-27)

## Context

Encompute could compile, encrypt, evaluate, aggregate and verify, but an
organization could not operate it. There were no persistent tenants, users
or jobs, no customer-managed keys, and no durable privacy state beyond
files. It had no audit trail across services and no supported deployment.
The cryptography was in place; the operating layer around it was not.

## Decision

1. **Control is separate from computation.**
   - A control plane (`encompute-control`) handles organizations,
     identities, roles, projects, assets (metadata only), policies, plans,
     jobs, scheduling, privacy ledgers, trust reports and the audit trail.
   - Evaluators compute. Key brokers authorize secret release. SecAgg
     coordinators aggregate.
   - Only these four are separate services. The planner, policy, trust,
     receipt and privacy modules stay inside the control plane.
2. **The control plane is not a trust anchor.**
   - Trust reports are rebuilt from signed evidence (the job grant, the
     evaluator's receipt, the client's commitments, the plan) and trusted
     keys on every request.
   - No database row says "trusted", so an edited database cannot make a
     job trusted.
3. **Identities.**
   - People authenticate with OpenID Connect (JWKS; issuer, audience and
     expiry checked).
   - Services authenticate with their own Ed25519 keys. Every request and
     message is signed, binds the sender, the recipient, a timestamp, a
     single-use nonce, the body hash and the IDs it concerns.
   - We chose signed requests over mTLS: signatures survive proxies and
     message brokers, reuse the key discipline receipts already use, and do
     not require a private CA. TLS stays in front of every service.
   - Development tokens exist; production mode refuses them.
4. **Tenancy.**
   - Roles are per organization, and deliberately simple (seven roles).
   - Isolation is the default. Collaboration is explicit: project
     membership plus the owner's approval of each asset for a project and
     purpose. Ownership never moves.
   - Other tenants' resources are "not found", never "forbidden".
5. **Jobs.**
   - An explicit, validated state machine.
   - Idempotent submission (`Idempotency-Key`).
   - Capability-aware scheduling: backend, parameter profile, health,
     capacity. Research backends are never scheduled.
   - Grants are signed by the control plane and pinned by evaluators.
   - Evaluators ask the control plane before starting, so revoked or
     cancelled jobs never start.
   - Nothing security-sensitive is replayed after a restart.
6. **Keys.**
   - A `RootKeyProvider` wraps each key broker's KEK under the
     organization's root key in its KMS. OpenBao/Vault Transit is the first
     adapter.
   - Root rotation re-wraps only the KEK.
   - Revocation reaches the broker as a signed message and destroys the key.
   - There is no fallback to local or plaintext keys.
7. **Durable privacy.**
   - PostgreSQL holds the hash-chained ledgers, with a row lock per ledger
     and idempotent events.
   - A signed state anchor outside the database records the latest ledger
     and audit roots. A database that does not extend it is refused at
     start.
   - Recovery freezes rolled-back ledgers (treats them as exhausted) and
     never forgets spending.
8. **Audit.**
   - An append-only, hash-chained event per security-sensitive transition,
     written in the same transaction.
   - Identifiers only.
   - Signed checkpoints anchored like the ledgers.
9. **Transport.**
   - A `MessageTransport` interface: HTTP with an outbox, and in-memory for
     tests.
   - Messages are signed envelopes with IDs, scopes, expiry and payload
     digests. Consumers are idempotent.
   - The transport is untrusted: duplication, reordering, loss and replay
     are tolerated by design.
   - Message brokers and key brokers are never merged.
10. **Deployment.**
    - Docker Compose first: control plane, PostgreSQL, evaluator, key
      broker (sidecar to its KMS), SecAgg coordinator.
    - Secrets come from mounted files.
    - `/live` and `/ready`, Prometheus metrics, and JSON logs.
    - No Kubernetes, message-broker cluster or UI in this milestone.

## Consequences

- Organizations can deploy, operate, secure, audit and integrate Encompute.
- API v1 is the stable external contract.
- Enforcement is layered:
  - privacy budgets are enforced by the coordinator's ledger and again by
    the control plane's;
  - revocation is enforced by the control plane, the evaluator's start
    check, and the key broker.
- A frozen ledger costs availability, never privacy: after a database
  rollback, the affected datasets can release nothing more until their
  owners set up a new budget.
- The anchor must be backed up separately from the database, and should
  live in the customer's vault. If both are restored from the same old
  backup, the rollback cannot be detected.
- Not yet built:
  - SAML and SCIM on the same user model;
  - more KMS adapters (AWS KMS, Google Cloud KMS, Azure Key Vault, PKCS#11);
  - a queue adapter;
  - Kubernetes;
  - a UI.

## Alternatives considered

- **Microservices per module.** Rejected: more trust boundaries to defend,
  and none of the modules is a separate trust domain.
- **mTLS only.** Rejected: identity would end at the TLS terminator, and
  messages relayed through a broker would lose it.
- **Storing trust verdicts.** Rejected: that would make the database a trust
  anchor.
- **Rolling back to the backup's privacy state.** Rejected: spent privacy
  must never be forgotten.

## Relevant source modules

- `crates/encompute-control`
- `crates/encompute-keybroker/src/root.rs`, `crates/encompute-keybroker/src/server.rs`
- `crates/encompute-verification/src/service.rs`
- `crates/encompute-evaluator/src/control.rs`
- `deploy/docker-compose`, `scripts/enterprise-e2e.sh`
