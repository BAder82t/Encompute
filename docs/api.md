# Control Plane API v1

The stable external contract of `encompute-control`. JSON over HTTPS
(terminate TLS in front of the service). The CLI (`encompute login`,
`projects`, `assets`, `jobs`, `trust report`, `audit list`) and the Python
SDK (`encompute.Client`) are clients of this API.

Only this contract is stable. Internal Rust types are not. A breaking change
goes to `/v2`; `/v1` keeps its meaning.

## Authentication

Every `/v1` route except `/v1/info` needs one of:

- `Authorization: Bearer <token>`: an OpenID Connect token from the
  organization's identity provider (RS256, ES256 or PS256). Its issuer and
  subject must be a registered user.
- A service signature: the headers `Encompute-Sender`,
  `Encompute-Recipient`, `Encompute-Timestamp`, `Encompute-Nonce`,
  `Encompute-Bind` and `Encompute-Signature`. They carry an Ed25519
  signature over the method, the path, the SHA-256 of the body, the sender
  and recipient, the timestamp (±300 s), a single-use nonce, and the bound
  IDs (`encompute_verification::service`).

Development tokens (issuer `encompute-development`) work only when the
control plane is not in production mode.

## Errors

Errors are JSON `{"code": "ENCnnnn", "message": "..."}`:

| HTTP | Codes |
|---|---|
| 400 | ENC1102 malformed request; ENC1604 receipt problems |
| 401 | ENC2601 unauthenticated; ENC2607 bad service signature, replay |
| 403 | ENC2602 missing role |
| 404 | ENC2603 not found, including other tenants' resources |
| 409 | ENC2604 conflict (state, idempotency key, revoked asset); ENC2201 privacy budget exceeded |
| 422 | ENC2401 PLANNING FAILED |
| 500 | ENC2605 insecure configuration; ENC2202 privacy state rollback |

## Idempotency

`POST /v1/jobs` requires an `Idempotency-Key` header. The same key with the
same body returns the same job (200; 201 the first time). The same key with
another body is ENC2604. Privacy events are idempotent by their event ID, and
service messages by their message ID.

## Resources

### Service

| | |
|---|---|
| `GET /live`, `GET /ready` | health (no authentication) |
| `GET /metrics` | Prometheus text format (no authentication; expose internally) |
| `GET /v1/info` | `{service, api: "v1", public_key, production}`: pin `public_key` in evaluators and brokers |
| `GET /v1/whoami` | the caller, its organization and roles |

### Organizations and identities

| | |
|---|---|
| `POST /v1/organizations` | platform admins. `{id, display_name, admin?: {issuer, subject, email?}}` |
| `GET /v1/organizations/{id}` | members |
| `POST /v1/organizations/{id}/users` | organization admins. `{issuer, subject, email?, roles: [...]}` |
| `POST /v1/organizations/{id}/service-accounts` | organization admins; platform services in `platform`. `{id, kind, public_key, roles?, url?}` |
| `POST /v1/organizations/{id}/service-accounts/{sa}/disable` | organization or security admins |

Roles: `organization_admin`, `security_admin`, `data_owner`, `model_owner`,
`ml_developer`, `auditor`, `operator`. Service kinds: `evaluator`, `secagg`,
`keybroker` (platform services), and `automation`.

### Projects and policies

| | |
|---|---|
| `POST /v1/projects` | `{organization, name}` |
| `GET /v1/projects`, `GET /v1/projects/{id}` | the projects the caller's organizations take part in, with their members and approved assets |
| `POST /v1/projects/{id}/members` | the owner's admins. `{organization}` |
| `POST /v1/projects/{id}/policies` | security admins. A JSON policy document; stored with its digest, `proposed` |
| `POST /v1/policies/{id}/approve` | a different security admin |

### Assets

| | |
|---|---|
| `POST /v1/assets` | `{organization, kind, name, digest, size_bytes?, media_type?, storage_uri?, policy?, parents?, key_ref?, privacy_budget?}`. Metadata only |
| `GET /v1/assets`, `GET /v1/assets/{id}` | owned, or approved for a project the caller takes part in |
| `POST /v1/assets/{id}/approvals` | owners. `{project, purpose}` |
| `POST /v1/assets/{id}/revoke` | owners and security admins. Fails jobs not yet running; tells the key broker |
| `GET /v1/assets/{id}/lineage` | ancestors and descendants visible to the caller; others counted as `not_visible` |

`kind` is one of `dataset`, `model`, `adapter`, `checkpoint`, `program` or
`artifact`. `key_ref` is `{broker, provider, key_ref, key_version}` and
never contains key material. `privacy_budget` is
`{unit, epsilon, delta}`, with exact decimal strings.

### Plans and jobs

| | |
|---|---|
| `POST /v1/plans` | `{project, program}` (`.eir` text). The planner chooses mechanisms from the deployment's registered backends; returns `{id, plan_id, program_id, spec_id, scheme, backend, profile, mechanisms}` |
| `POST /v1/jobs` | `{project, plan, purpose, source_assets, requested_output, policy?}` + `Idempotency-Key` |
| `GET /v1/jobs?project=`, `GET /v1/jobs/{id}` | state, transitions, and, for the submitting organization, the evaluator's URL and receipt key and the grant |
| `POST /v1/jobs/{id}/approve` | owners of assets whose policy sets `require_job_approval` |
| `POST /v1/jobs/{id}/cancel` | |
| `POST /v1/jobs/{id}/start` | the scheduled evaluator, before running |
| `POST /v1/jobs/{id}/receipt` | the scheduled evaluator. `{receipt, evaluation_ms?}` |
| `POST /v1/jobs/{id}/complete` | the submitting organization. `{receipt, request_commitment, output_commitment, key_id}` |
| `GET /v1/trust/{job}` | the trust report, rebuilt from the evidence: plan, spec, grant, receipt, source assets; `verdict` is `SATISFIED` or `NOT SATISFIED` |

### Evaluators

| | |
|---|---|
| `POST /v1/evaluators` | the evaluator itself. `{id, url, receipt_key, backends, profiles, openfhe_version, capacity}`. Research backends are refused |
| `GET /v1/evaluators` | platform operators |
| `POST /v1/evaluators/{id}/status` | `{status}`: the evaluator (`ready`, `busy`, `unhealthy`), or operators (`draining`, `ready`) |

### Privacy

| | |
|---|---|
| `GET /v1/privacy/{asset}` | owners and auditors. Budget, spent epsilon and delta, entries, root, frozen |
| `GET /v1/privacy/{asset}/ledger` | auditors and data owners. The full hash-chained ledger |
| `POST /v1/privacy/{asset}/events` | Data owners, and SecAgg services the owner authorized for this asset. A privacy event (reserve or commit): race-safe, idempotent, anchored before the reply |
| `POST /v1/privacy/{asset}/spenders` | Owners. `{service}`: authorizes a SecAgg service to record privacy events for this asset |

### Audit and messages

| | |
|---|---|
| `GET /v1/audit?organization=&after=&limit=` | auditors and admins of that organization |
| `POST /v1/audit/checkpoints` | platform operators. A signed checkpoint of the chain, anchored |
| `POST /v1/messages` | services. A signed message envelope: `job.completed`, `evaluator.heartbeat`, `privacy.event`, `secagg.round.completed` |
