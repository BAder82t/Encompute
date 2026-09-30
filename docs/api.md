# Control Plane API v1

The stable external contract of `encompute-control`. JSON over HTTPS
(terminate TLS in front of the service). The CLI (`encompute login`,
`projects`, `assets`, `jobs`, `trust report`, `audit list`) and the Python
SDK (`encompute.Client`) are clients of this API.

Only this contract is stable. Internal Rust types are not. A breaking change
goes to `/v2`; `/v1` keeps its meaning. API v1 is frozen for the 0.3
release: what that means, and the deprecation policy, are in
[api-stability.md](api-stability.md).

## Authentication

Every `/v1` route except `/v1/info` needs one of:

- `Authorization: Bearer <token>`: an OpenID Connect token from the
  organization's identity provider (RS256, ES256 or PS256). Its issuer and
  subject must be a registered, active user. The token must carry `iat`
  (not in the future) and live no longer than
  `ENCOMPUTE_MAX_TOKEN_LIFETIME_SECS` (`exp - iat`, default 86400 s);
  `nbf` is enforced when present.
- A service signature: the headers `Encompute-Sender`,
  `Encompute-Recipient`, `Encompute-Timestamp`, `Encompute-Nonce`,
  `Encompute-Bind` and `Encompute-Signature`. They carry an Ed25519
  signature over the method, the path with its canonical (sorted) query string, the SHA-256
  of the body, the sender and recipient, the timestamp (±300 s), a
  single-use nonce, and the bound IDs (`encompute_verification::service`).

Development tokens (issuer `encompute-development`) work only when the
control plane is not in production mode.

A request whose query string names a parameter twice is refused (400,
ENC1102) before authentication: a signature covers the query as sent, and
two readers could otherwise pick different values.

## Errors

Errors are JSON `{"code": "ENCnnnn", "message": "..."}`:

| HTTP | Codes |
|---|---|
| 400 | ENC1102 malformed request (including a repeated query parameter); ENC1604 receipt problems; ENC2204 a privacy reservation inconsistent with its own mechanism |
| 401 | ENC2601 unauthenticated (including a disabled user, and `/metrics` without the metrics token); ENC2607 bad service signature, replay |
| 403 | ENC2602 missing role; ENC2701-ENC2712 refused by governance in a governed project (see [errors.md](errors.md)) |
| 404 | ENC2603 not found, including other tenants' resources |
| 409 | ENC2604 conflict (state, idempotency key, revoked asset); ENC2201 privacy budget exceeded, or ledger frozen |
| 422 | ENC2401 PLANNING FAILED; ENC2402 a plan that does not satisfy its program or the control plane's floor |
| 500 | ENC2605 insecure configuration; ENC2202 PRIVACY or AUDIT STATE ROLLBACK (the database no longer extends the state anchor) |

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
| `GET /metrics` | Prometheus text format. With a metrics token configured (`ENCOMPUTE_METRICS_TOKEN_FILE`), only with `Authorization: Bearer <metrics token>`. Without one: open in development; in production refused (401, ENC2601) unless `ENCOMPUTE_METRICS_PUBLIC=true`. Expose it internally either way |
| `GET /v1/info` | `{service, api: "v1", public_key, production}`: pin `public_key` in evaluators and brokers |
| `GET /v1/whoami` | the caller, its organization and roles |

### Organizations and identities

| | |
|---|---|
| `POST /v1/organizations` | platform admins. `{id, display_name, admin?: {issuer, subject, email?}}` |
| `GET /v1/organizations/{id}` | members |
| `POST /v1/organizations/{id}/users` | organization admins. `{issuer, subject, email?, roles: [...]}` |
| `POST /v1/organizations/{id}/users/{user}/disable` | organization or security admins. Every request by the user is refused (ENC2601) from its next one. Anchored before the reply |
| `POST /v1/organizations/{id}/memberships/remove` | organization admins. `{principal, role?}`: removes that role of a user or service account in the organization, or all its roles there without `role`; effective from its next request. Each removed role is anchored as removed before the reply: a restored database that holds it again is refused at startup (ROLE STATE ROLLBACK) until `encompute-control recover` removes it again; a role granted again later is a new membership. Returns `{principal, organization, removed}` |
| `POST /v1/organizations/{id}/service-accounts` | organization admins; platform services in `platform`. `{id, kind, public_key, roles?, url?}`. Service accounts cannot hold `security_admin` (400); no other route grants it to them either. An organization's `keybroker` cannot take an ID that another organization's assets name as their broker (409, the same answer as a taken ID) |
| `POST /v1/organizations/{id}/service-accounts/{sa}/disable` | organization or security admins; in `platform`, also the platform's services. Anchored before the reply |
| `POST /v1/organizations/{id}/key-rotations` | organization or security admins. `{provider, key_ref, old_version, new_version}`: records a root-key rotation (`encompute keys rotate-root`) in the audit trail. The new version must be newer |

Roles: `organization_admin`, `security_admin`, `data_owner`, `model_owner`,
`ml_developer`, `auditor`, `operator`. Service kinds: `evaluator` and
`secagg` (platform services), `keybroker`, and `automation`. A `keybroker`
is either the platform's, serving any organization, or an organization's
own, serving only that organization's assets.

### Projects and policies

| | |
|---|---|
| `POST /v1/projects` | `{organization, name, governance?, organizations?, custody?}`. `governance` is `standard` (the default) or `governed`, fixed at creation. `custody` follows the mode and never changes: a governed project is always `sovereign` (every source's key is held by a key broker its own organization registered; asking for `standard` is refused, ENC2715), a standard project always `standard` (asking for `sovereign` is refused, 400, and its replies carry no `custody`). `organizations` are invited (each one's admins accept with `POST /v1/projects/{id}/members`); the reply lists them as `invited`, whether or not they exist. A governed project, or one that invites, is created by a person who is an organization admin of the owner |
| `GET /v1/projects`, `GET /v1/projects/{id}` | the projects the caller's organizations are active members of, with their `governance`, `members`, the organizations `invited` and not yet accepted, and `approved_assets`: only the approvals that cover the caller's organizations, or of the caller's own assets |
| `POST /v1/projects/{id}/members` | `{organization}`. The owner's admins invite: `status: invited`, the same answer whether or not the organization exists. The invited organization's admins accept with the same call, naming their own organization: `status: active`. An admin of both organizations adds it directly (`active`). An invited organization sees and does nothing in the project until it accepts |
| `POST /v1/projects/{id}/members/remove` | `{organization}`. The owner's admins, or the member's own admins (this also declines an invitation). The owner cannot leave (403). Removes the member's approvals in the project both ways (others' assets approved to it, its own assets approved to the project), recorded as withdrawn and anchored (a restored database that still holds them is refused at startup), and fails the project's jobs that have not started and that it submitted or that use its assets. The membership (or invitation) is anchored as removed too: a restored database that lists it again is refused at startup (MEMBERSHIP STATE ROLLBACK) until `encompute-control recover` removes it again; joining again is a new membership. Returns `failed_jobs`; anchored before the reply |
| `POST /v1/projects/{id}/policies` | security admins (people, not service accounts). A JSON policy document; stored with its digest, `proposed` |
| `POST /v1/policies/{id}/approve` | a security admin of the project owner's organization other than the author. Both are people: a service account neither proposes nor approves |

### Assets

| | |
|---|---|
| `POST /v1/assets` | `{organization, kind, name, digest, size_bytes?, media_type?, storage_uri?, policy?, parents?, key_ref?, privacy_budget?, series?, version?}`. Metadata only. With `series` and `version` (both or neither; `name` is then `series@version`) the asset is a dataset version: the reply adds its content-addressed `version_id`, and the version is immutable (its digest, owner, lineage and policy never change, it is never deleted, a revoked version stays revoked). A version may carry `delete_after` (Unix seconds, in the future): no governed job uses it from then on and no grant outlives it; it may later be brought forward, never extended or cleared. The same series and version with another digest is refused (ENC2704). With `project` (a project the owner is an active member of), an asset registered for a project in sovereign custody must name in `key_ref` a key broker its own organization registered (`POST /v1/organizations/{id}/key-brokers`) and that is active: no `key_ref`, a platform broker, or an unregistered or disabled one is refused (ENC2715) |
| `GET /v1/assets`, `GET /v1/assets/{id}` | owned, or approved for a project the caller takes part in. In a governed project a source is visible beyond its owner only to an organization an active authorization of it names as a recipient (while a member), and to the submitting organization of a job that runs under an authorization of it; any other member gets 404. The owner's members see every field (and, on `GET /v1/assets/{id}`, its `approvals`). Other organizations see only `id`, `organization`, `kind`, `name`, `digest`, `status`, `lineage_root`, `parents` and `policy` reduced to `require_job_approval` (when the owner set it): never `key_ref`, `storage_uri`, `size_bytes`, `media_type` or the rest of the policy |
| `POST /v1/assets/{id}/approvals` | owners. `{project, purpose}`. Covers the organizations that are active project members now (returned as `members`); an organization that joins later needs a new approval. Approving again after a withdrawal makes a new approval (a new ID), never the withdrawn one |
| `POST /v1/assets/{id}/approvals/withdraw` | owners. `{project, purpose}`. Other members no longer see or use the asset for that purpose; their jobs using it there that have not started fail (returned as `failed_jobs`). The withdrawal is anchored before the reply: a restored database that still holds the approval is refused at startup (APPROVAL STATE ROLLBACK) until `encompute-control recover` withdraws it again |
| `POST /v1/assets/{id}/revoke` | owners and security admins. Fails jobs not yet running; anchored before the reply; the key broker is told once the revocation is anchored |
| `GET /v1/assets/{id}/lineage` | ancestors and descendants visible to the caller; others counted as `not_visible` |

`kind` is one of `dataset`, `model`, `adapter`, `checkpoint`, `program` or
`artifact`. `key_ref` is `{broker, provider, key_ref, key_version}` and
never contains key material. A `broker` that is registered must be a key
broker of the platform or of the asset's organization (409 otherwise). `privacy_budget` is
`{unit, epsilon, delta}`, with exact decimal strings.

### Plans and jobs

| | |
|---|---|
| `POST /v1/plans` | `{project, program}` (`.eir` text). The caller is authorized before the program is parsed or compiled. In production the plan is checked against the control plane's own floor (the compiler's facts for the program, production backends and attestation only, at least the standard profile), not only the context it declares. The planner chooses mechanisms from the deployment's registered backends; returns `{id, plan_id, program_id, spec_id, scheme, backend, profile, mechanisms, estimated_gates, estimated_single_core_ms}`. `estimated_gates` counts bootstrapped gates (exact programs; 0 for CKKS). In a sovereign-custody (governed) project, each registered asset the program reads must be held by an active key broker its own organization registered, or planning is refused (ENC2715, audited as `plan.failed`); the plan then binds each source's owner and broker as a `key_custody` requirement. Standard projects plan as before |
| `POST /v1/jobs` | `{project, plan, purpose, source_assets, requested_output, policy?}` + `Idempotency-Key`. When the plan's program declares a purpose (`purpose "..."` on its `program` line), `purpose` must equal it (403 otherwise). A job that lists another organization's asset needs a program that declares its purpose, matching the owner's approval, and reads the asset by its registered ID. The job's sources are derived from its program: the registered assets its secret inputs are bound to (an `asset` declaration whose ID is the registered asset ID). `source_assets` must list exactly those assets, each once, for every job, the submitter's own data included, and must be empty when the program binds none: an asset it binds and the list leaves out, one listed that it does not bind (another registered version of a dataset included), or one listed twice is refused (403, audited as `job.denied`); a listed asset the caller cannot see is 404. The job records the derived set, which its lineage, revocation, audit and trust report follow. In a governed project the request also names `purpose_id` (an active purpose of the project; its name is `purpose` and the program's declared purpose, ENC2702) and `outputs` (`{name: {release_class, recipients}}` for every program output, within the purpose, ENC2709); both are refused in a standard project (400). Every source must be a registered dataset version (ENC2704) that is live and before its `delete_after` (ENC2705, ENC2706), with an active authorization signed by its owner, the submitter's own sources included (ENC2701), usable now (ENC2705, ENC2706, ENC2708), covering the program, its confidentiality and privacy policies and any spec pin (ENC2703), the purpose's linkage (ENC2711) and each output's release class and recipients (ENC2709). If an authorization that covers a source asks for per-job four-eyes approval, the job runs under it (even when a broader one would also cover the source) and is `waiting_for_approval` until its owner's people approve it (see `POST /v1/jobs/{id}/approve`). The job's `spec_id` is then the plan's spec under the governance binding built from these, shown with `purpose_id` and `governance_id`; the job is scheduled with a version 2 grant whose `expires_at` never passes `not_after`, the earliest end of its authorizations, purpose and sources' deletion dates. Scheduling and start revalidate a governed job with one check (also callable read-only as `Control::revalidate_governed_job`): past `not_after` (ENC2705); an authorization it runs under revoked, no longer active or superseded, or its governance key revoked (ENC2706, ENC2701, ENC2703, ENC2708); its purpose retired or expired (ENC2706, ENC2705); a source revoked, expired, past its deletion date or with its version substituted (ENC2706, ENC2705, ENC2704); a source key's broker disabled or re-bound (ENC2715); or its stored binding, spec, authorization set or grant no longer recomputing (ENC2703): it fails and is anchored as ended |
| `GET /v1/jobs?project=`, `GET /v1/jobs/{id}` | state, transitions, and, only for the submitting organization, the actors' IDs (`initiated_by`, `transitions[].actor`: other viewers, the owners of its source assets, see another organization's user or service account as `organization/user` or `organization/service`; platform services by ID), the evaluator's URL (`evaluator_url`), its receipt key (`evaluator_receipt_key`) and the grant. Also `estimated_gates` (from the plan; 0 for plans made before estimates), `estimated_ms` (the scheduler's completion estimate on the chosen evaluator, its queue included) and `evaluator_parallel_gates` (the threads per job that evaluator advertised) |
| `POST /v1/jobs/{id}/approve` | Standard projects: owners of assets whose policy sets `require_job_approval`: a person (not a service account) of the asset's own organization with `data_owner`, `model_owner` or `organization_admin` there. Governed projects ignore `require_job_approval`: a job waits only when an authorization it runs under asks for per-job four eyes, and then each such owner organization approves it under its approval rule for the project (at least two distinct people; by default one data owner and one security admin). An approver is a person homed in that organization holding a role the rule names; never the job's submitter or a service account (ENC2707), never an auditor or someone homed in another organization (403); one approval per person (again: ENC2707), counted for one of the rule's roles they hold that is still needed. Each approval is a statement over the job, its governed spec and its authorization set (`SHA256("encompute.job-approval.v1" || 0x00 || canonical {job, spec_id, authorization_set_id})`), stored append-only; only approvals of the job's current statement count. Approving revalidates the job as scheduling does: if it may no longer run (past `not_after`, ENC2705; an authorization revoked, ENC2706; any other revalidation refusal) the approval is refused and the job fails, anchored as ended. Once every such owner's quorum is met the job is `authorized` and scheduled; scheduling and start check every quorum again (ENC2707), counting an approval only while its approver is still an active user, homed in the organization, holding the recorded role and not an auditor there. A job not yet scheduled whose approvals stop counting goes back to `waiting_for_approval` (audited as `job.approval_lapsed`) for new approvals; a scheduled one is refused at start and fails. The approval rows stay as evidence |
| `POST /v1/jobs/{id}/cancel` | anchored before the reply |
| `POST /v1/jobs/{id}/start` | the scheduled evaluator, before running. A governed job is checked again on the control plane's clock (ENC2705, ENC2706, ENC2708): refused, it fails and is anchored as ended |
| `POST /v1/jobs/{id}/receipt` | the scheduled evaluator. `{receipt, evaluation_ms?}` |
| `POST /v1/jobs/{id}/complete` | the submitting organization. `{receipt, request_commitment, output_commitment, key_id}`. A governed job needs a version 4 receipt naming the digest of its own grant (also for `/receipt`), and completes when it started before `not_after`, even after it |
| `GET /v1/trust/{job}` | the trust report, rebuilt from the evidence: plan, spec, grant, receipt, source assets (the `source assets` check lists the assets the program binds in `sources`, and fails when the job's recorded sources differ from them); `verdict` is `SATISFIED` or `NOT SATISFIED`. A governed job adds a `governance` check that judges its authorizations at the job's start (VALID AT EXECUTION), and lists their current state in `now` without failing the report |

### Evaluators

| | |
|---|---|
| `POST /v1/evaluators` | the evaluator itself. `{id, url, receipt_key, backends, profiles, openfhe_version, capacity}`, and optionally a machine profile: `cpu_model`, `logical_cores`, `memory_bytes`, `benchmark_profile`, `max_parallel_gates` (threads per job). The machine profile is self-reported and used only for scheduling, never for a security decision. Registering again without it clears it. Registering again keeps an operator's `draining` status. Research backends are refused |
| `GET /v1/evaluators` | platform operators. Includes each machine profile (`null` where not sent) |
| `POST /v1/evaluators/{id}/status` | `{status}`: the evaluator (`ready`, `busy`, `unhealthy`), or operators (`draining`, `ready`) |

### Privacy

| | |
|---|---|
| `GET /v1/privacy/{asset}` | the owner's data owners, auditors, organization admins and security admins. Budget, spent epsilon and delta, entries, root, frozen |
| `GET /v1/privacy/{asset}/ledger` | auditors and data owners. The full hash-chained ledger |
| `POST /v1/privacy/{asset}/events` | the owner's data owners and operators, and SecAgg services the owner authorized for this asset. A privacy event (reserve or commit): race-safe, idempotent, anchored before the reply. Refused: a reservation whose declared sensitivity is below what its own noise implies for the ledger's unit, or, in production, not drawn with `csprng` (ENC2204); a ledger that no longer extends the state anchor (ENC2202 PRIVACY STATE ROLLBACK); a ledger frozen in the anchor, whatever the database says (ENC2201) |
| `POST /v1/privacy/{asset}/spenders` | the owner's data owners and organization admins. `{service}`: authorizes an active SecAgg service to record privacy events for this asset |

### Governed projects

A governed project computes across organizations for declared purposes,
under authorizations each owner signs with its own governance key. The
control plane holds only the public keys; signing happens outside it
(`encompute governance sign`). Every step is taken by people of the
organization concerned: never a service account, an auditor, or someone
homed in another organization (ENC2707 when a service account tries).
Approvals take a different person than the one who proposed (ENC2707).
V1 asset approvals are refused there (ENC2701): an owner's consent is its
signed authorization. A job in a governed project names its purpose and
each output's release, and runs only under an active authorization of
every source's owner (see `POST /v1/jobs`); validity is checked again at
scheduling and start, and a job's evaluator asks for release tickets
below.

| | |
|---|---|
| `POST /v1/organizations/{id}/governance-keys` | organization or security admins. `{public_key, kms_key_ref?}` (hex Ed25519; `kms_key_ref` names where the private key lives, never key material). `proposed`, with its `key_id` |
| `GET /v1/organizations/{id}/governance-keys` | the organization's members. Each key's `status`, and `revoked_at` (Unix seconds) once revoked |
| `POST /v1/organizations/{id}/governance-keys/{key}/approve` | a security admin other than the proposer. One active key per organization (409 while another is active) |
| `POST /v1/organizations/{id}/governance-keys/{key}/revoke` | security or organization admins. Final; replies with `revoked_at`, recorded once and never changed (revoking again returns the same time). From then on the key activates nothing and signs no revocation (ENC2708), and no authorization it signed is used (ENC2708), whether signed before or after a new key is approved; uses before `revoked_at` stay valid history |
| `POST /v1/projects/{id}/purposes` | a security admin of a member. `{organization, name, revision?, description?, legal_basis_ref?, modes, allowed_release_classes, recipients, linkage_policy_id?, min_aggregate_parties?, valid_from, valid_until}`. The ID is the PurposeId of the document (project included); `proposed`. 409 in a standard project |
| `GET /v1/projects/{id}/purposes`, `GET /v1/purposes/{id}` | project members; a purpose shows its document and the organizations that `accepted_by` it |
| `POST /v1/purposes/{id}/approve` | a security admin of the proposing organization other than the proposer: `active` |
| `POST /v1/purposes/{id}/accept` | a security or organization admin of a member. `{acceptance}`: a `PurposeAcceptance {version, organization, project, purpose_id, accepted_at}` signed with the organization's active governance key (ENC2708 without one, ENC2701 under another key) |
| `POST /v1/purposes/{id}/retire` | a security admin of the proposing organization. Final: the purpose takes no new authorization, and its authorizations are not used from its retirement on (ENC2706) |
| `POST /v1/authorizations` | a data owner or security admin of the owner. `{body}`: an `AuthorizationV2` without approvals. It must name an active purpose of the project that its organization accepted (ENC2702), a dataset version the organization registered (ENC2704), a release class and recipients the purpose allows (ENC2709), the purpose's linkage policy (ENC2711), and a window inside the purpose's that is not over (ENC2705); one program or one program set, never a wildcard |
| `GET /v1/authorizations/{id}` | the owner's members only. `body` is the document to sign, approvals included; once active, `authorization_id`, the `signed` document, `activated_at` and `governance_key_revoked_at` (null unless its key was revoked); `revoked_at` once revoked. `usable` says whether anything new may use it now; when it is `false`, `unusable` gives the refusal's `code` and `message` (the same check the enforcement phases make) |
| `POST /v1/authorizations/{id}/approve` | a person of the owner, in a role it holds there: `{role}`. One approval per person. By default two people, a data owner and a security admin, make it `approved`. Then its approvals are closed: approving an authorization that is `approved`, `active` or `revoked` is refused (409, ENC2604), and the database refuses to add, remove or change its approvals and recipients. An approved authorization is immutable evidence: to change anything (program, purpose, asset version, window, release class, recipients, approvers), propose a new authorization |
| `POST /v1/authorizations/{id}/signature` | a data owner or security admin of the owner. `{public_key, signature}` over `body`, by the organization's active governance key: `active`. Refused before four eyes (ENC2707), under another key or over another body (ENC2701), under a revoked key (ENC2708), after revocation (ENC2706) or once over (ENC2705) |
| `POST /v1/authorizations/{id}/revoke` | a data owner or security admin of the owner. `{reason, revocation?}` (the owner's signed `RevocationV2`, checked under its active governance key; ENC2708 under a revoked one). Final: a state transition, never an edit. Its time is recorded once; from then on nothing new uses the authorization (ENC2706). The revocation is anchored before the reply: a restored database that shows it unrevoked is refused at startup (AUTHORIZATION STATE ROLLBACK) until `encompute-control recover` revokes it again. Only once it is anchored are the owner's key brokers told (`authorization.revoked`, deny-only: they stop releasing under it) |
| `POST /v1/organizations/{id}/key-brokers` | a person who is a security admin of the organization (never a service account, ENC2707; never an auditor). `{id, grant_public_key, provider_kind, key_ref_namespace, location?}`: one of the organization's own active `keybroker` service accounts, the hex Ed25519 key it signs key grants with, the kind of KMS behind it, the key namespace it serves, and where it says it runs (`location`, up to 16 string fields, self-declared and never evidence). A platform broker is refused (ENC2715), another organization's account is not found (404), a registered one is not registered again (409). Audited (`key_broker.registered`). A broker's identity, organization and grant key never change, and it is never deleted |
| `GET /v1/organizations/{id}/key-brokers` | people (not service accounts) who are the organization's security admins, admins, auditors or data owners. Its registered brokers and their `status` |
| `POST /v1/jobs/{id}/release-ticket` | the job's scheduled evaluator only (another service gets 404, a person 403). `{asset_version_id}` of one of the job's sources. Returns `{ticket}`: a `ReleaseTicket` for the source's key broker, signed with the control plane's key (`GET /v1/info` `public_key`, the key brokers pin), naming the job's own authorization for that source (the one recorded at submission, never another of the owner's, however broad), checked again as at start (usable now, still covering the job's program, policies, linkage, releases and spec pin, and part of the set its grant names), the job's execution spec and governance binding, and the evaluator's receipt key. `not_after = min(now + 300 s, the grant's governed not_after, the grant's expiry, the authorizations' valid_until)`. Refused unless the job is queued or running in a governed project under a governed grant the control plane signed (409), the version is a source the job reads (ENC2704) and neither revoked (ENC2706) nor expired (ENC2705), the job's authorization for it passes that check (ENC2701, ENC2703, ENC2705, ENC2706, ENC2708, ENC2709, ENC2711), the governed window is open (ENC2705), and the key is held by a broker the owner registered (ENC2715). A window closing within the 60 seconds of skew a broker counts against a ticket gets none (ENC2712). Every ticket is new, stored (append-only) and audited (`release_ticket.issued`, in the owner's and the submitter's trail) |

Expiry is strict: `valid_from <= now < valid_until`, with no margin.

Revocations take effect at the time the control plane records (its own
clock), never earlier: a revoked governance key, a revoked authorization,
a retired purpose or a revoked dataset version blocks every use from that
time on, and leaves uses before it valid as history. The later phases
check an authorization at each plan, submission, schedule, start, key
release and export against the time of that step.

### Security

| | |
|---|---|
| `GET /v1/security/legacy-service-admins` | organization admins, security admins and auditors, for their own organizations; platform operators, admins, security admins and auditors, for every organization. The service accounts that still hold `security_admin`, granted before 0.3.0 refused it: `{count, refused_from, service_accounts: [{organization, id, kind, status, created_at, last_activity, remove: {method, path, body}}]}`, by organization then ID. `created_at` and `last_activity` (the account's last audited action, or `null`) are UTC RFC 3339 times. `remove` is the `memberships/remove` call that takes the role away. They keep the role in 0.3.x but are never a policy's proposer or approver; 0.4.0 refuses them |

### Audit and messages

| | |
|---|---|
| `GET /v1/audit?organization=&after=&limit=` | auditors and admins of that organization |
| `POST /v1/audit/checkpoints` | platform operators. A signed checkpoint of the chain, anchored. Refused (ENC2202 AUDIT STATE ROLLBACK) when the chain does not extend the anchored checkpoint |
| `POST /v1/messages` | services. A signed message envelope: `job.completed`, `evaluator.heartbeat`, `privacy.event`, `secagg.round.completed` |

The control plane sends key brokers `asset.revoked`, `authorization.revoked`
(an owner authorization of a governed project was revoked: to the brokers
its organization registered and the broker its dataset version's key
names) and `asset.expired` (the asset's retention ended: to the broker its
key names), each only once the state anchor holds the revocation or expiry.

## Key broker routes for governed projects

These are routes of the organization's own key broker
(`encompute keys serve`), not of the control plane. Like the rest of the
key broker's HTTP API they are experimental (see
[api-stability.md](api-stability.md)). A broker becomes governed when its
owner pins a governance key (`encompute keys governance-key pin`); from
then on it releases keys only through `/v1/release/governed`, and the plain
`/v1/release` refuses every key. Every route below changes the broker's
state: the state file is written and, when a generation mark is
configured, the mark in the organization's KMS is advanced before the
reply. A broker that cannot record the change answers with an error and
changes nothing (ENC2713, or 503 when the mark is unreachable); a broker
that does not persist its state serves none of these routes.

| | |
|---|---|
| `POST /v1/release/governed` | the attested workload. `{session, asset_id, authorization_id, ticket}`: the session from `/v1/attest`, the key's asset ID, the owner authorization the release is under, and the `ReleaseTicket` the control plane issued for this job and source. The broker checks, in order and stopping at the first failure: the session, the key and its bound version, the release policy, that the authorization is installed and not revoked, that it covers the spec, confidentiality and privacy policies and program, its strict validity window on the broker's clock, declared placement (refused until attested placement exists, ENC2710), the ticket (ENC2712), then the authorization's limits (ENC2714). Counters and the seen ticket are persisted before the grant is sealed. Returns `{grant, receipt}`: a version 3 grant header naming the authorization, project, purpose, validity and ticket, and a signed `KeyRelease` receipt that never contains a key. Without a ticket (`execution_spec` and `binding` instead) only on a development broker with `ENCOMPUTE_ENV=development` |
| `POST /v1/authorizations` | the owner (the body is its proof). A signed `AuthorizationV2` of the broker's own organization, verified under the pinned governance key (ENC2701 for another organization, ENC2708 for another key). Idempotent; a revoked authorization is never installed again (ENC2706). Returns `{authorization_id}` |
| `POST /v1/authorizations/revoke` | the owner. A signed `RevocationV2` of the broker's own organization, verified under the pinned governance key. It takes effect at once, from its issue time, whether or not the control plane is reachable. Returns `{authorization_id}`. When the broker cannot record it, revoke offline in the state file (`encompute keys authorization revoke ID`) |

The control plane reaches a broker only through `/v1/messages`, and its
governed messages (`authorization.revoked`, `asset.expired`) can only stop
releases: they are accepted only for the broker's own organization and
recorded only for authorizations installed there.
