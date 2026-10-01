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
| `POST /v1/organizations/{id}/users` | organization admins. `{issuer, subject, email?, roles: [...]}`. In an organization that takes part in a governed project (as owner, member or auditor organization, invited or not) `auditor` is granted alone: with any other role it is refused (ENC2716). Elsewhere roles combine as before |
| `POST /v1/organizations/{id}/users/{user}/disable` | organization or security admins. Every request by the user is refused (ENC2601) from its next one. Anchored before the reply |
| `POST /v1/organizations/{id}/memberships/remove` | organization admins. `{principal, role?}`: removes that role of a user or service account in the organization, or all its roles there without `role`; effective from its next request. Each removed role is anchored as removed before the reply: a restored database that holds it again is refused at startup (ROLE STATE ROLLBACK) until `encompute-control recover` removes it again; a role granted again later is a new membership. Returns `{principal, organization, removed}` |
| `POST /v1/organizations/{id}/service-accounts` | organization admins; platform services in `platform`. `{id, kind, public_key, roles?, url?}`. Service accounts cannot hold `security_admin` (400); no other route grants it to them either. `auditor` with another role is refused in an organization taking part in a governed project (ENC2716). An organization's `keybroker` cannot take an ID that another organization's assets name as their broker (409, the same answer as a taken ID) |
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
| `GET /v1/projects`, `GET /v1/projects/{id}` | the projects the caller's organizations are active members (or accepted auditor organizations) of, with their `governance`, `members`, the organizations `invited` and not yet accepted, and `approved_assets`: only the approvals that cover the caller's organizations, or of the caller's own assets. A governed project is one shared view, the same bytes for everyone taking part: `approved_assets` is empty (consent there is by authorizations), and `auditors` and `invited_auditors` list its auditor organizations |
| `POST /v1/projects/{id}/members` | `{organization, participation?}`. The owner's admins invite: `status: invited`, the same answer whether or not the organization exists. The invited organization's admins accept with the same call, naming their own organization: `status: active`. An admin of both organizations adds it directly (`active`). An invited organization sees and does nothing in the project until it accepts. `participation` is `member` (the default) or, in a governed project only, `auditor` (400 elsewhere, and for the owner): an auditor organization reads the project's shared records and changes nothing (see "Auditors and views" below); replies for one carry `participation: auditor`. How an organization takes part is fixed by its invitation (another participation is 409; leaving and being invited again is a new membership). Joining a governed project (accepting, or being added directly) is refused (ENC2716) while one of the organization's principals holds `auditor` with another role there, while an auditor organization would join as a member, and while a member of a governed project would join as an auditor organization; creating a governed project is refused likewise for its owner. Auditors are refused (403) |
| `POST /v1/projects/{id}/members/remove` | `{organization}`. The owner's admins, or the member's (or auditor organization's) own admins (this also declines an invitation). Auditors are refused (403). The owner cannot leave (403). Removes the member's approvals in the project both ways (others' assets approved to it, its own assets approved to the project), recorded as withdrawn and anchored (a restored database that still holds them is refused at startup), and fails the project's jobs that have not started and that it submitted or that use its assets. The membership (or invitation) is anchored as removed too: a restored database that lists it again is refused at startup (MEMBERSHIP STATE ROLLBACK) until `encompute-control recover` removes it again; joining again is a new membership. Returns `failed_jobs`; anchored before the reply |
| `POST /v1/projects/{id}/policies` | security admins (people, not service accounts). A JSON policy document; stored with its digest, `proposed` |
| `POST /v1/policies/{id}/approve` | a security admin of the project owner's organization other than the author. Both are people: a service account neither proposes nor approves |

### Assets

| | |
|---|---|
| `POST /v1/assets` | `{organization, kind, name, digest, size_bytes?, media_type?, storage_uri?, policy?, parents?, key_ref?, privacy_budget?, series?, version?}`. Metadata only. With `series` and `version` (both or neither; `name` is then `series@version`) the asset is a dataset version: the reply adds its content-addressed `version_id`, and the version is immutable (its digest, owner, lineage and policy never change, it is never deleted, a revoked version stays revoked). A version may carry `delete_after` (Unix seconds, in the future): no governed job uses it from then on and no grant outlives it; it may later be brought forward, never extended or cleared. It may also carry `retention_until` (until when its owner keeps it; fixed, never after `delete_after`, 400 otherwise) and `evidence_retention_until` (until when the evidence about it is kept; it may later be extended, never shortened). Once `delete_after` passes, the control plane expires the version in the background (see `POST /v1/assets/{id}/retention`); the owner's view shows `delete_after`, `retention_until`, `evidence_retention_until` and, once expired, `expired_at` A version may also carry its owner's registered policy (in a governed project every source version must, see below): `ir_policy` (the confidentiality policy in the program language's JSON form: `{owners, readers, purposes, release, derive, privacy?, forms?}`, canonical, with no unknown field, owned by the registering organization alone) and `release_class` (a release-class ceiling). Both are fixed with the version: a governed job's program must declare a policy at least as strict for it, every output's release class must be within the registered class, and no authorization of it may exceed that class (ENC2709). The same series and version with another digest is refused (ENC2704). With `project` (a project the owner is an active member of), an asset registered for a project in sovereign custody must name in `key_ref` a key broker its own organization registered (`POST /v1/organizations/{id}/key-brokers`) and that is active: no `key_ref`, a platform broker, or an unregistered or disabled one is refused (ENC2715) |
| `GET /v1/assets`, `GET /v1/assets/{id}` | owned, or approved for a project the caller takes part in. In a governed project a source is visible beyond its owner only to an organization an active authorization of it names as a recipient (while a member), and to the submitting organization of a job that runs under an authorization of it; any other member gets 404. The owner's members see every field (and, on `GET /v1/assets/{id}`, its `approvals`). Other organizations see only `id`, `organization`, `kind`, `name`, `digest`, `status`, `lineage_root`, `parents` and `policy` reduced to `require_job_approval` (when the owner set it): never `key_ref`, `storage_uri`, `size_bytes`, `media_type` or the rest of the policy |
| `POST /v1/assets/{id}/approvals` | owners. `{project, purpose}`. Covers the organizations that are active project members now (returned as `members`); an organization that joins later needs a new approval. Approving again after a withdrawal makes a new approval (a new ID), never the withdrawn one |
| `POST /v1/assets/{id}/approvals/withdraw` | owners. `{project, purpose}`. Other members no longer see or use the asset for that purpose; their jobs using it there that have not started fail (returned as `failed_jobs`). The withdrawal is anchored before the reply: a restored database that still holds the approval is refused at startup (APPROVAL STATE ROLLBACK) until `encompute-control recover` withdraws it again |
| `POST /v1/assets/{id}/retention` | a person (never a service account or an auditor) who is a security admin or data owner of the version's organization (others get 404 or 403). `{delete_after?, evidence_retention_until?}`, at least one. Brings the deletion date forward (a version without one gets one), never back and never before `retention_until` (409), or extends the evidence retention, never shortening it (409); the database refuses the same. Audited (`asset.retention_changed`, with the previous and new values). Returns `{id, delete_after, retention_until, evidence_retention_until, expires_now?}`. A deletion date at or before now expires the version at once. Expiry (also run in the background once a deletion date passes): the version is marked expired (`expired_at`, final) and no job uses it again (ENC2705); every derived result downstream is marked `source_expired_at` (set once) and is not used, derived from or exported again (ENC2705); jobs not yet started that read any of them fail; a job already running may finish, but nothing it released is recorded or exported; the expiry is anchored, then the key broker is told (`asset.expired`). Audited as `asset.expired` (reason `delete_after`), `asset.source_expired` for each custodian, and `job.failed`. Deleting the data itself is the owner's storage's job; the evidence (receipts, audit events, anchors, release records, the trust report, which notes the expiry) stays verifiable |
| `POST /v1/assets/{id}/revoke` | owners and security admins. Fails jobs not yet running; anchored before the reply; the key broker is told once the revocation is anchored. In a governed project it also marks every derived result downstream `source_revoked_at` (set once) and fails their jobs not yet running; the reply then lists them (`downstream`) with `"erased": false`: nothing already released is recalled or deleted |
| `GET /v1/assets/{id}/lineage` | ancestors and descendants visible to the caller; others counted as `not_visible`. A derived result shows `derived_from_job`, and `source_revoked_at` (Unix seconds) once a source of it was revoked |

`kind` is one of `dataset`, `model`, `adapter`, `checkpoint`, `program` or
`artifact`. `key_ref` is `{broker, provider, key_ref, key_version}` and
never contains key material. A `broker` that is registered must be a key
broker of the platform or of the asset's organization (409 otherwise). `privacy_budget` is
`{unit, epsilon, delta}`, with exact decimal strings.

### Plans and jobs

| | |
|---|---|
| `POST /v1/plans` | `{project, program}` (`.eir` text). The caller is authorized before the program is parsed or compiled. In production the plan is checked against the control plane's own floor (the compiler's facts for the program, production backends and attestation only, at least the standard profile), not only the context it declares. The planner chooses mechanisms from the deployment's registered backends; returns `{id, plan_id, program_id, spec_id, scheme, backend, profile, mechanisms, estimated_gates, estimated_single_core_ms}`. `estimated_gates` counts bootstrapped gates (exact programs; 0 for CKKS). In a sovereign-custody (governed) project, each registered asset the program reads must be held by an active key broker its own organization registered, or planning is refused (ENC2715, audited as `plan.failed`); the plan then binds each source's owner and broker as a `key_custody` requirement. Standard projects plan as before |
| `POST /v1/jobs` | `{project, plan, purpose, source_assets, requested_output, policy?, purpose_id?, outputs?}` + `Idempotency-Key`. When the plan's program declares a purpose (`purpose "..."` on its `program` line), `purpose` must equal it (403 otherwise). A job that lists another organization's asset needs a program that declares its purpose, matching the owner's approval, and reads the asset by its registered ID. The job's sources are derived from its program: the registered assets its secret inputs are bound to (an `asset` declaration whose ID is the registered asset ID). `source_assets` must list exactly those assets, each once, for every job, the submitter's own data included, and must be empty when the program binds none: an asset it binds and the list leaves out, one listed that it does not bind (another registered version of a dataset included), or one listed twice is refused (403, audited as `job.denied`); a listed asset the caller cannot see is 404. The job records the derived set, which its lineage, revocation, audit and trust report follow. In a governed project the request also names `purpose_id` (an active purpose of the project; its name is `purpose` and the program's declared purpose, ENC2702) and `outputs` (`{name: {release_class, recipients}}` for every program output, within the purpose, ENC2709); both are refused in a standard project (400). Every source must be a registered dataset version (ENC2704) that is live and before its `delete_after` (ENC2705, ENC2706), with an active authorization signed by its owner, the submitter's own sources included (ENC2701), usable now (ENC2705, ENC2706, ENC2708), covering the program, its confidentiality and privacy policies and any spec pin (ENC2703), the purpose's linkage (ENC2711) and each output's release class and recipients (ENC2709). Release classes follow the owners' order: every class is within itself; `boolean-only`, `aggregate-only` and `dp-aggregate-only` are within `authorized-agency-only`; `dp-aggregate-only` is within `aggregate-only`; `derived-artifact-only` and `never` are within only themselves. Each output's class must be within a class the purpose allows and within every authorization's `release_class` (an output released as `never`, to nobody, always is), and a class other than `authorized-agency-only` or `never` must admit a form the compiler proves the output takes: a boolean or a category within a bound its sources declared (`boolean-only`), an aggregate (`aggregate-only`), a differentially private aggregate (`dp-aggregate-only`, `aggregate-only`), a derived model, update, checkpoint or adapter (`derived-artifact-only`); otherwise ENC2709. Every source must be registered with `ir_policy` and `release_class` (ENC2709). An authorization's `release_class` ceiling bounds only the classes within it, and one job releases at most the authorization's `limits.max_outputs_per_job` boolean-only outputs per source (one when absent, ENC2709). A source's `ir_policy` must be declared by the program at least as strictly for the job's purpose (ENC2709; ENC2702 for its purposes), and every output's class must be within a source's registered `release_class` (ENC2709). If an authorization that covers a source asks for per-job four-eyes approval, the job runs under it (even when a broader one would also cover the source) and is `waiting_for_approval` until its owner's people approve it (see `POST /v1/jobs/{id}/approve`). The job's `spec_id` is then the plan's spec under the governance binding built from these, shown with `purpose_id` and `governance_id`; the job is scheduled with a version 2 grant whose `expires_at` never passes `not_after`, the earliest end of its authorizations, purpose and sources' deletion dates. Scheduling and start revalidate a governed job with one check (also callable read-only as `Control::revalidate_governed_job`): past `not_after` (ENC2705); an authorization it runs under revoked, no longer active or superseded, or its governance key revoked (ENC2706, ENC2701, ENC2703, ENC2708); its purpose retired or expired (ENC2706, ENC2705); a source revoked, expired, past its deletion date or with its version substituted (ENC2706, ENC2705, ENC2704); a source key's broker disabled or re-bound (ENC2715); or its stored binding, spec, authorization set or grant no longer recomputing (ENC2703): it fails and is anchored as ended |
| `GET /v1/jobs?project=`, `GET /v1/jobs/{id}` | the caller's organizations' jobs, and (by ID) jobs using their assets; in a governed project, every job of the project to everyone taking part in it (members and auditor organizations), who get the shared view below. State, transitions, and, only for the submitting organization, the actors' IDs (`initiated_by`, `transitions[].actor`: other viewers, the owners of its source assets, see another organization's user or service account as `organization/user` or `organization/service`; platform services by ID), the evaluator's URL (`evaluator_url`), its receipt key (`evaluator_receipt_key`) and the grant. Also `estimated_gates` (from the plan; 0 for plans made before estimates), `estimated_ms` (the scheduler's completion estimate on the chosen evaluator, its queue included) and `evaluator_parallel_gates` (the threads per job that evaluator advertised) |
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
| `GET /v1/organizations/{id}/governance-key-attestation?key_id=` | members of the organization and of organizations that take part in a project with it (anyone else gets 404). The control plane's signed attestation of the organization's governance key, from its record of approved keys: `{body: {version: 1, organization, key_id, public_key, status, revoked_at?, issued_at}, issuer, issuer_public_key, signature}`, signed with the control plane's key (`GET /v1/info` `public_key`) under its own domain (`encompute.governance-key-attestation.v1`). Without `key_id`, the active key (ENC2708 when there is none); with it, that key, `active` or `revoked` (with `revoked_at`); a proposed key is never attested (404). A custodian's key broker pins a lineage owner's key only from it (`encompute keys governance-key pin-lineage --attestation FILE`, or `--url`): a later attestation of another key replaces the pin, a revoked one unpins it |
| `POST /v1/organizations/{id}/governance-keys/{key}/approve` | a security admin other than the proposer. One active key per organization (409 while another is active) |
| `POST /v1/organizations/{id}/governance-keys/{key}/revoke` | security or organization admins. Final; replies with `revoked_at`, recorded once and never changed (revoking again returns the same time). From then on the key activates nothing and signs no revocation (ENC2708), and no authorization it signed is used (ENC2708), whether signed before or after a new key is approved; uses before `revoked_at` stay valid history |
| `POST /v1/projects/{id}/purposes` | a security admin of a member. `{organization, name, revision?, description?, legal_basis_ref?, modes, allowed_release_classes, recipients, linkage_policy_id?, min_aggregate_parties?, valid_from, valid_until}`. The ID is the PurposeId of the document (project included); `proposed`. 409 in a standard project |
| `GET /v1/projects/{id}/purposes`, `GET /v1/purposes/{id}` | project members; a purpose shows its document and the organizations that `accepted_by` it |
| `POST /v1/purposes/{id}/approve` | a security admin of the proposing organization other than the proposer: `active` |
| `POST /v1/purposes/{id}/accept` | a security or organization admin of a member. `{acceptance}`: a `PurposeAcceptance {version, organization, project, purpose_id, accepted_at}` signed with the organization's active governance key (ENC2708 without one, ENC2701 under another key) |
| `POST /v1/purposes/{id}/retire` | a security admin of the proposing organization. Final: the purpose takes no new authorization, and its authorizations are not used from its retirement on (ENC2706) |
| `POST /v1/authorizations` | a data owner or security admin of the owner. `{body}`: an `AuthorizationV2` without approvals. It must name an active purpose of the project that its organization accepted (ENC2702), a dataset version the organization registered (ENC2704), a release class within one the purpose allows and within the release class the version was registered with (a version without a registered policy and release class is refused); when its class admits boolean-only releases (`boolean-only`, `authorized-agency-only`), `limits.max_executions` and `limits.max_releases` (`limits.max_outputs_per_job`, optional, caps boolean-only outputs per job; one when absent), and recipients the purpose allows (all ENC2709), the purpose's linkage policy (ENC2711), and a window inside the purpose's that is not over (ENC2705); one program or one program set, never a wildcard |
| `GET /v1/authorizations/{id}` | the owner's members, and everyone else taking part in the project (members and auditor organizations), who get the shared view: each approval in `body.approvals` is only `{organization, role, at, approver}`, `approver` being the pseudonym `psn_` + hex HMAC-SHA256(key, project ‖ 0x00 ‖ principal ID) under a key only the control plane holds (HKDF-SHA256 of its signing key, info `encompute.approver-pseudonym.v1`): one person is one pseudonym within a project and another elsewhere, knowing a principal ID does not confirm it, and a new signing key gives new pseudonyms, and there is no `signed` document. For the owner's members `body` is the document to sign, approvals included; once active, `authorization_id`, the `signed` document, `activated_at` and `governance_key_revoked_at` (null unless its key was revoked); `revoked_at` once revoked. `usable` says whether anything new may use it now; when it is `false`, `unusable` gives the refusal's `code` and `message` (the same check the enforcement phases make) |
| `POST /v1/authorizations/{id}/approve` | a person of the owner, in a role it holds there: `{role}`. One approval per person. By default two people, a data owner and a security admin, make it `approved`. Then its approvals are closed: approving an authorization that is `approved`, `active` or `revoked` is refused (409, ENC2604), and the database refuses to add, remove or change its approvals and recipients. An approved authorization is immutable evidence: to change anything (program, purpose, asset version, window, release class, recipients, approvers), propose a new authorization |
| `POST /v1/authorizations/{id}/signature` | a data owner or security admin of the owner. `{public_key, signature}` over `body`, by the organization's active governance key: `active`. Refused before four eyes (ENC2707), under another key or over another body (ENC2701), under a revoked key (ENC2708), after revocation (ENC2706) or once over (ENC2705) |
| `POST /v1/authorizations/{id}/revoke` | a data owner or security admin of the owner. `{reason, revocation?}` (the owner's signed `RevocationV2`, checked under its active governance key; ENC2708 under a revoked one). Final: a state transition, never an edit. Its time is recorded once; from then on nothing new uses the authorization (ENC2706). The revocation is anchored before the reply: a restored database that shows it unrevoked is refused at startup (AUTHORIZATION STATE ROLLBACK) until `encompute-control recover` revokes it again. Only once it is anchored are the owner's key brokers told (`authorization.revoked`, deny-only: they stop releasing under it), and so is the key broker of every custodian holding a result derived (every hop) from a job that ran under it, where the authorization is installed as a lineage owner's (the message names the custodian's organization; audited as `authorization.revocation.sent` in the owner's and the custodian's trail) |
| `POST /v1/organizations/{id}/key-brokers` | a person who is a security admin of the organization (never a service account, ENC2707; never an auditor). `{id, grant_public_key, provider_kind, key_ref_namespace, location?}`: one of the organization's own active `keybroker` service accounts, the hex Ed25519 key it signs key grants with, the kind of KMS behind it, the key namespace it serves, and where it says it runs (`location`, up to 16 string fields, self-declared and never evidence). A platform broker is refused (ENC2715), another organization's account is not found (404), a registered one is not registered again (409). Audited (`key_broker.registered`). A broker's identity, organization and grant key never change, and it is never deleted |
| `GET /v1/organizations/{id}/key-brokers` | people (not service accounts) who are the organization's security admins, admins, auditors or data owners. Its registered brokers and their `status` |
| `POST /v1/jobs/{id}/release-ticket` | the job's scheduled evaluator only (another service gets 404, a person 403). `{asset_version_id}` of one of the job's sources. Returns `{ticket}`: a `ReleaseTicket` for the source's key broker, signed with the control plane's key (`GET /v1/info` `public_key`, the key brokers pin), naming the job's own authorization for that source (the one recorded at submission, never another of the owner's, however broad), checked again as at start (usable now, still covering the job's program, policies, linkage, releases and spec pin, and part of the set its grant names), the job's execution spec and governance binding, and the evaluator's receipt key. `not_after = min(now + 300 s, the grant's governed not_after, the grant's expiry, the authorizations' valid_until)`. Refused unless the job is queued or running in a governed project under a governed grant the control plane signed (409), the version is a source the job reads (ENC2704) and neither revoked (ENC2706) nor expired (ENC2705), the job's authorization for it passes that check (ENC2701, ENC2703, ENC2705, ENC2706, ENC2708, ENC2709, ENC2711), the governed window is open (ENC2705), and the key is held by a broker the owner registered (ENC2715). A window closing within the 60 seconds of skew a broker counts against a ticket gets none (ENC2712). Every ticket is new, stored (append-only) and audited (`release_ticket.issued`, in the owner's and the submitter's trail) |
| `POST /v1/jobs/{id}/derived-assets` | a person (never a service account, ENC2707; never an auditor) of an organization that output `output` names as a recipient, once the governed job succeeded (409 before). `{output, kind, series, version, digest, key_ref, ir_policy, release_class, release_record}`. Records the result as a dataset version its organization holds as custodian (`series@version`, the organization's own): its parents are the job's source versions; `release_class` must be within the output's class, every parent's registered class and every authorization's ceiling in the lineage, and `ir_policy` (the IR asset policy, canonical) no wider than the parents' registered policies joined (their owners, the weakest release none exceeds, the readers, purposes, forms and derivations all allow, the same privacy budget) (ENC2709); `key_ref.broker` is a broker the custodian registered (ENC2715). `release_record` is a `SignedReleaseRecord {version: 1, party (the custodian), project, purpose_id, job_id, governance_id, output, output_commitment, derived_version_id, release_class, parents (the source version IDs), authorization_ids (the job's), onward_policy_id (SHA-256 of the canonical JSON of `ir_policy`), recipients (organization → X25519 export key), lineage_owners (every other organization owning data in the lineage → the ID of its active governance key; the custodian's broker requires an authorization of each), issued_at}` signed with the custodian's active governance key (ENC2701, ENC2708); every field must be the job's (ENC2704), and each recipient must be named by every authorization in the lineage (ENC2709) and never be an auditor organization (ENC2716). Refused when a source or an ancestor of it is revoked (ENC2706) or expired (ENC2705). One per output and custodian; frozen. The result is visible only to its custodian, the recipients its record names, the owners of the data it derives from (every hop up) and the project's auditor organizations; anyone else gets 404. A governed job reading it as a source needs an authorization of every organization owning data up its lineage besides the custodian's (such an organization proposes an `AuthorizationV2` for the derived version, under the same digest commitment), else ENC2701; and every job reading it counts against the `max_executions`, and every export of what it releases against the `max_releases`, of each authorization up the lineage (ENC2714). Audited (`asset.derived`) for the custodian and every owner in the lineage. Returns `{id, custodian, version_id, parents, release_class, release_record, release_cosignature, ...}`: `release_cosignature` is the control plane's signature, under its own domain (`encompute.derived-release-cosignature.v1`), over `{version: 1, organization (the custodian), asset_id, broker, key_ref, derived_version_id, release_record_id, lineage_owners, issued_at}` for the record it validated; stored with the result and frozen. The custodian's broker binds the result's key only with it (`encompute keys bind-version KEY VERSION --derived RECORD --cosignature FILE`), so a record that leaves a lineage owner out is never bound (ENC2704) |
| `GET /v1/assets/{id}/release-cosignature` | a person who is a security admin or data owner of the derived result's custodian (its other people get 403; anyone else, a lineage owner included, gets 404; so does a source version). `{asset, custodian, release_cosignature, registered_cosignature, reissued}`: the control plane's co-signature in force (the latest re-issue, else the one made at registration), the one made at registration, and how many times it was re-issued |
| `POST /v1/assets/{id}/release-cosignature` | a person who is a security admin of the derived result's custodian (never a service account or an auditor; anyone else gets 404). After a lineage owner rotated its governance key: re-issues the co-signature in force with each lineage owner's active governance key ID, the custodian, asset, broker, key, derived version and record unchanged, issued later than the one it replaces; recorded append-only and audited (`asset.release_cosignature_reissued`) for the custodian and every lineage owner. 409 when the co-signature in force already names every owner's active key; ENC2708 when an owner has no active key; ENC2705 when the result expired or a source of it did. Returns `{asset, custodian, release_cosignature}`. Until the custodian's broker re-binds the key with it (`encompute keys rebind-lineage KEY --cosignature FILE`), the result is not released or exported there (ENC2708): the broker accepts it only signed by its pinned control-plane key, for the binding in force, naming the same lineage owners, each under the key it pinned from the control plane's attestation (pin it first with `pin-lineage`), and newer than the co-signature it holds (ENC2704 otherwise) |
| `POST /v1/assets/{id}/exports` | a person of the derived result's custodian (others get 404; never a service account or an auditor). `{recipient, release_class?}` (default: the result's class). Returns `{id, asset, recipient, release_class, ticket}`: an `Export` ticket for the custodian's broker, naming the recipient and the export key the custodian's record gives it, the job's execution spec, binding and authorizations. `not_after = min(now + 300 s, every lineage authorization's valid_until, the purpose's valid_until)`. Refused when the result or an ancestor is revoked or source-revoked (ENC2706) or expired (ENC2705), an authorization in the lineage is not usable now (after its window, ENC2705: a job that started inside it finished, but nothing it released is exported; revoked, ENC2706; its key revoked, ENC2708), the recipient is not named by every such authorization and by the custodian's record, or the class is not within the result's and every ceiling (ENC2709), the recipient audits the project (ENC2716), an owner's `max_releases` is used up by exports of results released under its authorization (ENC2714), the custodian's governance key is no longer active (ENC2708), or the window closes within the brokers' 60 seconds of skew (ENC2712). One export row per ticket (UNIQUE, append-only), and the ticket is audited (`release_ticket.issued`, kind `export`) for the custodian, the recipient and every owner in the lineage. The recipient redeems it at the custodian's broker (`POST /v1/export/governed` with `{asset_id, ticket, release_record}`), once, for a key sealed to its export key |

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
| `GET /v1/security/legacy-service-admins` | organization admins, security admins and auditors, for their own organizations; platform operators, admins, security admins and auditors, for every organization. The service accounts that still hold `security_admin`, granted before 0.3.0 refused it: `{count, refused_from, service_accounts: [{organization, id, kind, status, created_at, last_activity, remove: {method, path, body}}], auditor_combinations: [{organization, id, kind, roles, governed, remove}]}`, by organization then ID. `auditor_combinations` lists the users and service accounts holding `auditor` with another role in an organization (bootstrap admins hold `organization_admin`, `operator` and `auditor` in `platform`, which never takes part in a project); `governed` says whether the organization takes part in a governed project, which it cannot join while the combination lasts, and `remove` takes the `auditor` role away. A later migration removes the combinations. `created_at` and `last_activity` (the account's last audited action, or `null`) are UTC RFC 3339 times. `remove` is the `memberships/remove` call that takes the role away. They keep the role in 0.3.x but are never a policy's proposer or approver; 0.4.0 refuses them |

### Audit and messages

| | |
|---|---|
| `GET /v1/audit?organization=&after=&limit=` | auditors and admins of that organization. Events recorded for the organization; a principal of another tenant organization who acted on it (an invitation, a removal, a revocation that failed one of its jobs) appears as `organization/user` or `organization/service` (each event's `hash` covers the actor as recorded) |
| `GET /v1/audit?project=&after=&limit=` | governed projects: auditors, organization admins and security admins of an organization taking part (member or auditor organization). The project's events as everyone taking part sees them, the same bytes for each: `{seq, at_us, organization, actor, action, resource_type, resource_id, project, result, refs}`, actors as `organization/kind` (platform services by ID), `refs` limited to the project's own identifiers, and no request IDs or chain hashes. With `organization=` too: 400. A standard project: 400 |
| `GET /v1/projects/{id}/audit?after=&limit=` | governed projects: auditors, organization admins and security admins of an organization taking part (anyone else: 404). The project's own governance log, `p:<id>`, and nothing else: `{project, checkpoint, witnesses, witness_status, members, witnessed_by, missing_witnesses, events: [{event, leaf_hash, inclusion_proof}], next}`. `checkpoint` is the control plane's latest signed checkpoint of the project; each `inclusion_proof` leads from the event's leaf to its root (RFC 6962), so a reader verifies every event offline with `encompute-trust`. `after` is an event position (from 0), `limit` at most 200 (default 100); `after`, `limit` and `since` must be whole numbers (`limit` from 1) or the call is 400; a caller is limited to 120 requests a minute on the three project log routes (503, retry shortly); `next` is the last position returned while more remain, else `null`. Events hold identifiers, the kind of transition and when, never a person, a storage location or a key reference, and the answer is the same bytes for every reader. A project with no checkpoint yet answers `checkpoint: null` (both routes alike). A standard project: 400 |
| `GET /v1/projects/{id}/checkpoints/latest?since=` | the same readers. The latest signed checkpoint with its witnesses and label (`witnessed` when every member organization at that size signed, otherwise `unwitnessed`; `members`, `witnessed_by`, `missing_witnesses`), and, with `since=<size>`, `consistency`: the control plane's signed consistency proof from that size to the checkpoint's (a `since` beyond the checkpoint's size: `consistency` is `null`, the caller compares the checkpoints it holds, see `encompute governance check-equivocation`) |
| `POST /v1/projects/{id}/checkpoints/{size}/witnesses` | governed projects: a person who is a security admin of a member organization (never a service account, never an auditor: ENC2602; an auditor organization or a non-member: 403 or 404). Body: the signed `CheckpointWitness` `{body: {version, organization, partition, size, root, at}, public_key, signature}`, signed with the organization's active governance key (ENC2708 when that key is revoked or none is active, ENC2701 when not its key). The organization must have been a member when the log had `size` events (403 to someone who takes part in the project; 404 to anyone else, a former member included, for sizes it was not a member at). A former member can countersign the sizes at which it was a member and reads nothing else, and the witness must be for exactly the stored checkpoint's partition, size and root (ENC2718, 409); a checkpoint that does not exist: 404. 201 with the checkpoint's witness state, or 200 when the organization had witnessed it already. A label never blocks anything |
| `POST /v1/audit/checkpoints` | platform operators. A signed checkpoint of the chain, anchored. Refused (ENC2202 AUDIT STATE ROLLBACK) when the chain does not extend the anchored checkpoint |
| `POST /v1/messages` | services. A signed message envelope: `job.completed`, `evaluator.heartbeat`, `privacy.event`, `secagg.round.completed` |

The control plane sends key brokers `asset.revoked`, `authorization.revoked`
(an owner authorization of a governed project was revoked: to the brokers
its organization registered, the broker its dataset version's key names,
and the broker of every custodian holding a result derived from a job that
ran under it, every hop down) and `asset.expired` (the asset's deletion date passed: to the broker its
key names), each only once the state anchor holds the revocation or expiry.

### Auditors and views in governed projects

Auditors are read-only. In a governed project every mutating route refuses (403, "auditors are
read-only") anyone holding `auditor` in an organization taking part in it,
whatever else they hold, and anyone acting for one of its auditor
organizations: nothing about its members, policies, purposes,
authorizations, plans, jobs, approvals or sources changes at an auditor's
request, and organization-level routes refuse an organization's auditor
there once it takes part in a governed project (assets, privacy ledgers,
key brokers). An auditor holds no other role in such an organization
(ENC2716). An auditor organization owns no source in the project,
submits, plans, approves and proposes nothing, is named as no recipient (a
purpose naming it is 400, a job releasing to it ENC2716), is issued no
release ticket (ENC2716) and registers no key broker (ENC2716).

What each organization sees follows one table (`crates/encompute-control/src/views.rs`):

| Data | Owner | Other participants | Auditor organization |
|---|---|---|---|
| project, members, purposes | full | full | full |
| asset version used (ID, organization, name, digest, status) | full | the named recipients and submitters | yes |
| `key_ref`, `storage_uri`, size, other versions, other projects | yes | no | no |
| owner authorizations | real approvers | (organization, role, time) and a pseudonym | same |
| job spec, program, purpose, `governance_id`, state, evaluator | full | yes | yes |
| grant, evaluator URL and receipt key, initiator, actors | submitter | labels | labels |
| privacy ledger | full | no | no |
| audit | own organization | the project's events | the project's events |

The shared view of a record is the same bytes for every organization that
does not own it. A governed job's scheduled evaluator sees `{id, grant}`
and nothing else (and no trust report). The signed grant's governance
binding maps each source's asset version ID (never its key reference) to
its owner's broker (`asset_brokers`), which the owner's broker checks
against the version the key is bound to. Another organization's IDs answer
as unknown ones do (404, the same message).

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

A broker pins the control plane's public key in its state the first time
it is configured with one (`--control-key` or
`ENCOMPUTE_CONTROL_PUBLIC_KEY`); every later command, `keys serve` and its
message channel included, must name the same key (ENC2605). Replacing it
needs `--replace-control-key` with another key, recorded in the broker's
state (`control_key_history`: previous key, new key, time) and printed as
an audit line (`AUDIT key_broker.control_key.replaced`). A custodian's broker relies on a
lineage owner's key pinned from the control plane's attestation only while
the attestation is younger than `--lineage-attestation-max-age` (24 hours
by default, at most 7 days): older, re-attest it (`pin-lineage`) before
anything derived from that owner's data is released or exported
(ENC2708).
