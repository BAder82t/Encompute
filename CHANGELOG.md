# Changelog

## Unreleased (public-sector governance, not in 0.3)

Work toward confidential cross-agency computation
([docs/public-sector.md](docs/public-sector.md)). None of it is part of
0.3.

- **Assurance, attacks and examples (phase 9).** The attack suite
  `scripts/governance-attacks.sh` runs 27 attacks on the governance
  surface (forged or edited authorizations, expired or revoked ones, wrong
  purpose, program or source, over-release, early, forged or replayed
  tickets, scope-pin conflicts, residency and operator violations, auditor
  separation, a service account approving, lineage consent, a rolled-back
  database or broker state, skipped or replayed log numbers, edited
  bundles) and checks each is refused with its ENC code and leaves its
  trail. A refused release-ticket request by a job's scheduled evaluator is
  now audited (`release_ticket.denied`). Three assurance checks
  (`governance_authorization_property`, `governance_release_class_order`,
  `governance_placement_property`) judge shared functions against
  independent models; INV-240 (authorization limits bound repeated
  queries; per-subject limits are not enforced) and INV-242 (the minimize
  objective) are new, end-to-end evidence is added for INV-222, INV-228 and
  INV-231, and INV-224, 225, 237, 238 and 239 stay reserved for record
  linkage. Example C, a bounded signal released to one agency (single
  source, no linkage), joins example B in `examples/run-all.sh`;
  `scripts/release-check.sh` requires both and runs the attack suite.
  The threat model, known limitations and support matrix cover the
  collusion, central-DP, linkage and decryption-key limits.
- **Cross-agency report, explain and evidence bundle (phase 8).**
  `TrustGraph::governance_report`: governance rows computed from signed
  evidence against the caller's pins (a missing anchor, missing evidence
  or an unverifiable proof is UNCHECKED or NOT EVIDENCED, never a pass;
  authorizations judged at the grant's signed time; a revocation head
  covers only up to its own date). `GET /v1/jobs/{id}/governance-bundle`
  (`view=shared|org`: the same bytes for every member, no other
  organization's private metadata, capped at 5,000 log events, rate
  limited). `encompute governance export | verify | report | countersign`
  with a pins file and one table of exit codes (0 satisfied or accepted, 1
  not satisfied, 2 malformed or refused, 3 unchecked or unpinned);
  `encompute explain --governance JOB | --bundle FILE`. ENC2727 to
  ENC2730; INV-243, INV-244. Standard jobs, `trust report` and `explain`
  are unchanged. No migration.
- **Governed projects (phase 1):** governance keys, purposes, owner-signed
  authorizations with four-eyes approval, immutable dataset versions,
  strict validity windows and non-retroactive revocation; migration 0005;
  ENC2701 to ENC2712; INV-218, INV-219, INV-220, INV-222, INV-228,
  INV-231.
- **Residency and operators (phase 6).** Placement constraints decide
  where governed work runs, and who may run the machines. The project's
  constraints (`GET` and `POST /v1/projects/{id}/placement`: any member's
  security admin tightens at once, loosening needs every member) and each
  owner's own (`limits.placement` of its signed authorization) combine so
  that adding a source only narrows what is admitted; prohibited locations
  win. Locations come from a versioned table
  (`encompute_verification::placement::locations`), never from whoever
  declares them. Evaluators have an operator (the organization of their
  service account; organizations may now hold evaluator accounts of their
  own, which run only governed jobs that admit them) and a location with an
  evidence level: self-declared (never accepted in production),
  operator-declared (`POST /v1/evaluators/{id}/location-declarations` by a
  security admin of the operator) or attested (the key broker takes the
  Confidential Space zone from the token and judges it at every key
  release, replacing the old refusal of any declared placement). The
  planner records the admissible evaluators in the plan, refuses a plan
  nothing admits, and keeps the evaluator's operator apart from source
  owners and decryptors; submission, scheduling, start and release tickets
  check again, and an evaluator that moved fails the job. `jobs run
  --placement --evaluator-pins` lets a client refuse an evaluator outside
  its own rules; `Objective::Minimize` (`plan --prefer minimize`) prefers
  the plan that releases least. Another tenant's evaluator is admitted only
  where its organization takes part in the project or a constraint names it;
  an owner may pin the project's constraint digest in its authorization. Migrations 0017 and 0018; ENC2723 to
  ENC2726; INV-233 and INV-234. Standard projects are unchanged.
- **Two-part key release (phase 2).** A governed key broker releases a key
  only with an owner-signed authorization installed at the broker and a
  single-use, job-bound release ticket signed by the pinned control-plane
  key (300 seconds at most, 60 seconds of clock skew counted toward
  denial). The ticket's signature is checked before any of its fields is
  used, and the release is counted and persisted before the key is
  granted. New broker routes `/v1/release/governed`, `/v1/authorizations`
  and `/v1/authorizations/revoke`; grant header version 3 (version 2
  grants are unchanged); a `KeyRelease` receipt that never contains a
  key. Once a governance key is pinned, the plain release path refuses
  every key; releasing without a ticket needs a development broker with
  `ENCOMPUTE_ENV=development`. Declared placement was refused until
  attested placement existed (see residency, below).
- **Broker state rollback guard.** A governed broker records its state
  generation and MAC in the organization's KMS (OpenBao or Vault KV-v2,
  compare-and-set) and refuses an older, forked or unchained state
  (ENC2713). Crash recovery accepts only the write that was in flight.
  A governed production broker needs a mark; an unreachable mark grants
  nothing. Standard brokers without a mark are unchanged.
- **Sovereign custody.** Governed projects are always sovereign: each
  source's key must be held by a broker its own organization registered
  (`POST` and `GET /v1/organizations/{id}/key-brokers`), and platform
  brokers are refused (ENC2715). Release tickets from
  `POST /v1/jobs/{id}/release-ticket`, for the job's scheduled evaluator
  only, audited.
- **Per-asset broker binding.** Training specs can bind each key to its
  owner's broker (`asset_brokers`, `broker_organizations`), and a workload
  accepts a key's grant only from that broker; the governance binding
  carries the map, and planning binds each source's owner broker into the
  PlanId. Specs without the map keep their IDs and the one-broker rule.
- **The control plane can only deny.** Revoked authorizations and expired
  assets are anchored before brokers are told (`authorization.revoked`,
  `asset.expired`, deny-only). A missing row now counts as undone for
  every anchored revocation, disable, ended job and expiry: start is
  refused until recovery acknowledges the loss, and the ID stays blocked.
  Governance tables refuse DELETE. Migration 0006; ENC2713 to ENC2715.
- **Governed jobs (phase 3).** A job in a governed project names its
  purpose (`purpose_id`) and each output's release (`outputs`), and is
  submitted only under an active authorization signed by every source's
  owner, its own sources included, covering its program, policies,
  linkage and recipients. The governance binding is built at submission
  and carried in the job's spec; the job is scheduled with a version 2
  grant capped at the end of every authorization, purpose and source
  window; validity is checked again at scheduling and start (a failing
  job is anchored as ended); revoking an authorization fails the jobs
  under it that have not started; completion needs a version 4 receipt
  naming the job's own grant. A job that started inside its window may
  complete after it, and its trust report judges validity at its start.
  Dataset versions may carry `delete_after`, which may be brought forward
  but never extended. An expired source now gets ENC2705 at ticket issue.
  A release ticket names only the job's own authorization for its source,
  checked as at start; in a governed project a source is visible only to
  its owner, the recipients an active authorization names, and the
  submitters of jobs under one. Migration 0007.
- **Per-job four eyes (phase 3).** A governed job under an authorization
  that asks for per-job four-eyes approval is no longer refused (ENC2707):
  it runs under that authorization, even when a broader one would also
  cover the source, and waits for approval. Each such owner organization
  approves through `POST /v1/jobs/{id}/approve` under its approval rule
  for the project (at least two distinct people; by default a data owner
  and a security admin), with people homed there; the job's submitter,
  service accounts, auditors and people homed elsewhere never count. An
  approval is a statement over the job, its governed spec and its
  authorization set, stored append-only; approving revalidates the job (a
  job past its window or under a revoked authorization fails), and
  scheduling and start require every owner's quorum. Governed projects
  ignore the free-form `require_job_approval` policy field; standard
  projects are unchanged. One quorum check serves authorizations and jobs.
  Approvals count at scheduling and start only while the approver is
  still an active user of the organization with the recorded role: a job
  not yet scheduled waits for approval again, a scheduled one fails at
  start. Approval rules may not require `auditor` or unknown roles.
  Migration 0008; INV-228 extended.
- **Auditors and views (phase 3).** Auditors are read-only: every
  mutating route that touches a governed project refuses anyone holding
  `auditor` in an organization taking part in it, whatever else they
  hold, and anyone acting for one of its auditor organizations (a test
  enumerates the router's routes). An organization joins a governed
  project as a member or, invited with `participation: auditor`, as an
  auditor organization: it reads the project's shared records and never
  owns a source, submits, receives a release, approves or registers a key
  broker there, and takes part in no governed project as a member. In an
  organization taking part in a governed project an auditor holds no
  other role: granting one is refused, and an organization with such a
  combination neither creates nor joins a governed project until it is
  removed (new ENC2716 "auditor separation"). Bootstrap admins keep
  admin, operator and auditor: the platform organization never takes part
  in a project. `GET /v1/security/legacy-service-admins` now lists
  `auditor_combinations` for later removal. Standard organizations keep
  their role combinations. Migration 0009.
- **Cross-organization views of governed projects.** One static table
  (`views.rs`) decides what each organization sees; everyone who does not
  own a record gets the same bytes. Authorizations are readable by every
  organization taking part, with approvers as per-project pseudonyms
  (HMAC under a key derived from the control plane's signing key, so a
  known principal ID cannot be confirmed) and without the signed copy; jobs are visible to every organization taking
  part, with actors as `organization/kind` and without the grant, the
  evaluator URL or its receipt key; the scheduled evaluator sees a
  governed job's grant only. New `GET /v1/audit?project=`: the project's
  events as everyone taking part sees them. An organization's own trail
  now labels another organization's people who acted on it. The
  governance binding's broker map (`asset_brokers`) is keyed by asset
  version ID instead of the owner's key reference, so grants and tickets
  name no KMS key; a governed broker checks the version its key is bound
  to. Bindings without the map keep their GovernanceIds.
- **Release classes and forms (phase 3).** Release classes are ordered
  as the owners decided: boolean-only, aggregate-only and
  dp-aggregate-only are within authorized-agency-only, dp-aggregate-only
  within aggregate-only, and never and derived-artifact-only only within
  themselves. A governed job's output class must be within a class the
  purpose allows and within every source authorization's ceiling (no
  longer an exact match), and must admit a form the compiler proves the
  output takes (a boolean, a bounded category its sources declared, an
  aggregate, a DP aggregate, a derived artifact); otherwise ENC2709. The
  key broker uses the same function. Asset policies gain optional release
  forms (`release R forms [boolean]`), joined by intersection; a released
  output that cannot be proven to take an allowed form does not compile
  (new ENC1907). Policies without forms keep their PolicyIds. A dataset
  version may carry its owner's registered policy (`ir_policy`) and
  `release_class`, frozen with the version (migration 0010): a governed
  job's program must declare a policy at least as strict for it, and
  nothing is released or authorized beyond its class. Every governed
  source version must carry both. Probing controls: an authorization
  whose ceiling admits boolean-only releases needs `max_executions` and
  `max_releases`, and a job releases at most `max_outputs_per_job`
  boolean-only outputs per source (one when absent; control plane and
  broker share the check). An output released as `never` names no
  recipient.
- **Derived results and exports (phase 3).** Once a governed job
  succeeded, a person of a recipient organization of an output records
  the result as a derived asset (`POST /v1/jobs/{id}/derived-assets`): a
  dataset version its organization holds as custodian, whose parents are
  the job's exact source versions, whose release class is within the
  output's, every parent's and every authorization's, and whose onward
  policy is never wider than the parents' registered policies joined
  (ENC2709). Its key is at the custodian's own broker, and the custodian
  signs a release record of it with its governance key
  (`SignedReleaseRecord`: output commitment, class, parents,
  authorizations, onward policy, recipients with their export keys).
  Revoking a source marks every derived result downstream
  `source_revoked_at` (set once), fails their jobs that have not started,
  and lists them in its answer with `"erased": false`: revocation blocks
  new use and is not retroactive. Every governed use, derivation, ticket
  and export walks the ancestors themselves (ENC2706, ENC2705), so a
  restored database that lost the mark changes nothing. The custodian
  asks for an export (`POST /v1/assets/{id}/exports`): a single-use
  `Export` ticket for one recipient, refused after any authorization in
  the lineage ends (ENC2705), when the recipient is not named by every
  such authorization and by the record, or the class is wider than any
  ceiling (ENC2709), or an owner's `max_releases` is used up (ENC2714);
  one export row per ticket (UNIQUE, append-only). The custodian's broker
  redeems it at `POST /v1/export/governed` with the same ticket checks as
  a key release (signature first, window, single use), only for a key
  bound to that result (`encompute keys bind-version --derived`), under
  the custodian's record verified under its pinned governance key, sealed
  to the export key the record names; decryption tickets are refused.
  A job reading a derived result needs an authorization from its
  custodian and from every owner of the data it derives from (ENC2701),
  and executions and exports count against every authorization up the
  lineage (ENC2714). A derived result is visible only to its custodian,
  the recipients its record names, the owners of its data and the
  project's auditors. The custodian's broker enforces lineage consent
  itself: the release record names every lineage owner and its governance
  key, and a key release or export needs an installed authorization of
  each, counted locally. Because the custodian runs that broker, it takes
  two facts from the control plane, verified under the pinned
  control-plane key: a lineage owner's key is pinned only from the
  control plane's signed attestation of it (`GET
  /v1/organizations/{id}/governance-key-attestation`; `encompute keys
  governance-key pin-lineage --for ORG --attestation FILE` or `--url`),
  replaced only by a later attestation and unpinned by a revoked one
  (ENC2708); and a derived key is bound only to a release record the
  control plane co-signed at registration (`release_cosignature`;
  `bind-version --derived RECORD --cosignature FILE`), so a record leaving
  a lineage owner out is never bound (ENC2704). An original owner's
  revoked authorization is forwarded, once anchored, as deny-only
  `authorization.revoked` to every custodian broker holding a result
  derived from a job under it. The custodian remains trusted for derived
  data it holds: these checks stop a compromised control plane or a
  careless custodian, and only both compromised together could fake a
  lineage owner's consent. Decided: an export defaults to the result's own
  class, a derived result keeps its parents' owners, and a result may be
  recorded after its window while its export is blocked. Standard
  projects are unchanged. Migration 0011.
- **Derived results after a key rotation.** The custodian's members
  re-fetch the control plane's co-signature of a derived result's record
  (`GET /v1/assets/{id}/release-cosignature`; anyone else gets not found).
  When a lineage owner rotates its governance key, a result bound under
  the old key ID is no longer released or exported (ENC2708) until a
  security admin of the custodian has the co-signature re-issued with
  every lineage owner's active key ID (`POST
  /v1/assets/{id}/release-cosignature`: the record, version, key and
  broker unchanged, a later issue time; audited for the custodian and
  every lineage owner; ENC2708 when an owner has no active key) and the
  custodian's broker re-binds the key (`encompute keys rebind-lineage
  ASSET --cosignature FILE`). The broker accepts the re-issue only signed
  by its pinned control plane, for the binding in force, changing nothing
  but the lineage owners' key IDs, each the key it pinned from the
  control plane's attestation, and newer than the co-signature it holds
  (ENC2704 otherwise). Only the custodian's security admins and data
  owners read the co-signature, and none is re-issued for an expired or
  source-expired result (ENC2705). Migration 0012.
- **Fresh lineage attestations.** A custodian's broker relies on a lineage
  owner's pinned key only while the control plane's attestation of it is
  younger than a maximum age (24 hours by default, `keys serve
  --lineage-attestation-max-age SECS`, at most 30 days; every governed
  broker has one): older, nothing derived from that owner's data is
  released or exported until the key is attested again (ENC2708,
  "re-attest").
- **The control-plane key is pinned in broker state.** The first
  configuration with a control-plane key (`--control-key` or
  `ENCOMPUTE_CONTROL_PUBLIC_KEY`) pins it in the broker's MAC-protected
  state; every later command or `keys serve` must name the same key
  (ENC2605 otherwise), revocation messages included. Replacing it needs
  `--replace-control-key` with another key, recorded in the broker's
  state (`control_key_history`) and printed as an audit line
  (`AUDIT key_broker.control_key.replaced`).
- **Retention (phase 3).** A dataset version may carry `retention_until`
  (until when its owner keeps it; fixed, never after `delete_after`) and
  `evidence_retention_until` (until when its evidence is kept; only ever
  extended), besides `delete_after` (fixed at registration, only ever
  brought forward). The owner's security admins and data owners change
  them through `POST /v1/assets/{id}/retention`, audited; pushing a
  deletion date back, bringing it before `retention_until`, or shortening
  evidence retention is refused (409), and the database refuses it too.
  Once `delete_after` passes, the background task expires the version:
  it is marked expired, every derived result downstream is marked
  `source_expired_at` (set once), their jobs that have not started fail,
  the expiry is anchored, and only then is the key broker told
  (`asset.expired`). A job that started before the deletion date may
  finish, but nothing derived from an expired version is used, derived
  from or exported again (ENC2705); every check walks the ancestors, whose
  expiry the anchor holds, and a restored database that undid an expiry
  does not start. Receipts, audit events, anchors and release records stay
  verifiable after the data is deleted, and the trust report notes the
  expiry without failing. Deleting the data itself is the owner's
  storage's job. Migration 0012.
- **Project audit with proofs and checkpoint witnessing.** A governed
  project's log is readable by its members and auditors:
  `GET /v1/projects/{id}/audit` returns the project's own events, each with
  an inclusion proof against the control plane's latest signed checkpoint,
  in bounded pages, and `GET /v1/projects/{id}/checkpoints/latest?since=`
  the checkpoint with a signed consistency proof from the size the caller
  last saw. Each member organization countersigns checkpoints
  (`POST /v1/projects/{id}/checkpoints/{size}/witnesses`, a human security
  admin, under the organization's active governance key, for a member at
  that size; ENC2718 for another size or root). A checkpoint every member
  signed is labelled `witnessed`, any other `unwitnessed`; the label never
  blocks a job. A member joining a governed project is now an event of its
  log (`membership.added`), so the members at any size come from the log.
  `encompute governance witness` signs only a checkpoint that extends the
  last one that member witnessed and otherwise writes an equivocation
  proof and exits 1; `encompute governance check-equivocation` verifies
  two signed checkpoints or a rollback proof, and `encompute governance
  verify-audit` recomputes the whole check (every proof, the members, the
  witnesses under pinned keys) without trusting the control plane's label.
  ENC2718; INV-247.
- **Owner revocation heads.** Each organization signs, with its governance
  key, the root over every revocation it made in a governed project (its
  authorizations and their signed revocations, its assets revoked or
  expired where the project used them, the purposes it retired, the keys it
  revoked), so an evidence bundle cannot omit one. `GET
  /v1/projects/{id}/revocation-heads/{org}/draft` states the sorted leaves,
  the root and the next number; `encompute governance sign --kind
  revocation-head` recomputes the root from the leaves before signing
  (`--verify-draft` prints what would be signed); `POST
  /v1/projects/{id}/revocation-heads` accepts a head only from a security
  admin, under the organization's active key, one past the previous head
  (never in the future or before it) and with exactly the control plane's
  own fold of the log (ENC2717). A governed authorization revocation or
  purpose retirement may carry its head and is then recorded with it or
  not at all; without one the revocation takes effect at once and the
  owner owes the next head (derived from the log: the revocations after
  its latest head). The trust crate gains
  `RevocationHead::covers`, `latest_at_or_after` and a verdict (covered,
  omitted revocation, head too old or missing: unchecked, never a pass,
  head under a revoked key, bad signature). `verify-audit` checks each
  organization's head when pins are given, and now exits 3 without
  `--pins` unless `--allow-unpinned` is passed. Standard projects are
  unchanged. ENC2717; INV-247. Heads are judged through the proven log
  (the latest recorded head must be supplied, dated at or after the
  decision time, not recorded after its key's revocation), a stale or
  older-key head is UNCHECKED, two roots for one number are provable owner
  equivocation, `verify-audit` exits 3 on any UNCHECKED organization
  unless `--allow-unchecked`, and `sign --expect-leaves` checks the draft
  against the owner's own records.
- **Governance event log and a constant-size state anchor (phase 4).**
  Every security-negative transition (an asset revoked or expired, a
  service account or user disabled, a job cancelled or failed, an approval
  withdrawn, a membership or role removed, an owner authorization revoked,
  a purpose retired, a governance key revoked, a ledger frozen) and every
  privacy ledger checkpoint is an event of one hash-chained, Merkle-tree
  governance log in the database (migration 0013), written in the same
  transaction. The state anchor (version 2) holds only the audit root and
  the log's size and head: its size no longer grows with assets,
  revocations or spends, and the `anchor_size_warning` is now a tripwire.
  A ledger's floor is the latest `privacy.ledger_checkpoint` event of its
  asset (its asset, entry count and root, in the platform partition),
  read through an index: a spend appends it and checkpoints the log before
  it is acknowledged (concurrent spends share a checkpoint), and a ledger
  restored behind its floor is refused and frozen as before. Every start
  recomputes the log and refuses a database that does not hold the
  anchored head (GOVERNANCE LOG STATE ROLLBACK, ENC2202); the anchor store
  mirrors the log so recovery can rebuild an older database's missing
  events. A version-1 anchor (0.3.0) migrates once, at the first start,
  into genesis events (its sets and its ledger checkpoints); there is no
  downgrade. Sequential spend latency rises by about 25 ms on a local
  PostgreSQL and a directory anchor (two durable writes instead of one),
  and is unchanged with eight concurrent spenders. INV-160, INV-192,
  INV-193 and INV-226 evidence extended. A spend is also refused before it commits when the log no longer holds the anchored head, spends are limited to 1,200 a minute per actor and asset, and a reservation must charge at least a zCDP cost of 1e-9.
- **DP scopes, populations and aggregate mode (phase 5).** Differential
  privacy in a governed project is charged to a **scope**, a share of the
  **population** of the source's dataset series, never to a per-version
  ledger that a new version would reset. A population (one organization's
  series, every version, one privacy unit) carries a hard cap that no
  scope, project or version raises; a scope serves one project, purpose
  and optionally program. One security admin of the owner proposes a scope
  and a different one approves it (four eyes; never an auditor or a
  service account), and its allocation is an event of the project's log.
  A release is reserved in the scope and the population and must fit in
  both: the population is authoritative, and scopes may add up to more
  than it. A project with no scope cannot spend and inherits nothing
  (ENC2719); an owner's authorization may pin the scope
  (`privacy_scope_id`). A governed job whose program releases a
  differential-privacy aggregate is checked at scheduling and start, and
  reserves its own release, computed by the control plane from its program,
  in each source's scope when it starts, before any noise exists: an
  exhausted scope or population fails it (ENC2201), a coordinator's report
  of the same release is the same entry and an under-declared one is
  refused (ENC2721). Scopes and populations are ledgers like an asset's:
  checkpointed in the governance log before a call returns, refused and
  frozen when restored behind it. Ledger genesis version 2 (version 1 is
  unchanged), `scope` in `PrivacyEvent`, `rho_cap`. Aggregations may
  declare `max_sources_per_unit` (multiplied into the sensitivity; every
  participant when scoped and undeclared) and a `layout` of strata whose
  digest every contribution must name (ENC2722); an aggregate always
  states that it links no records. `encompute privacy population`,
  `privacy scope` and `aggregate --scoping --job` do the same with file
  ledgers. New routes under `/v1/privacy/populations` and
  `/v1/privacy/scopes`; migrations 0014 to 0016; ENC2719 to ENC2722;
  INV-230, INV-241. Standard projects and assets whose series has no
  population are unchanged, but creating a population refuses
  reservations against the per-asset ledgers of that series. Reviewed:
  a party derives its layout digest from its own labels (`join
  --labels`); a governed program declaring fewer sources per unit than
  participants needs every owner's signed `limits.max_sources_per_unit`;
  populations are proposed and approved by two people for a registered
  series and may be superseded for new scopes; a governed job whose
  reserved release has no reported commit does not succeed; a start whose
  anchoring failed is retried and swept; estimates and `privacy explain
  --scoped` show every participant for scoped aggregates, with a warning
  where the default is 1.
- **Assurance:** INV-232 (release tickets), INV-235 (sovereign custody),
  INV-236 (the control plane can only deny; broker state cannot be
  rolled back), INV-223 (auditors), INV-229 (cross-organization
  views), INV-221 (over-release), INV-227 (release lineage, control-plane
  part), INV-245 (derived results), INV-246 (retention), INV-230
  (privacy scopes and populations) and INV-241 (aggregate mode); 167
  invariants.

## 0.3.0 — 2026-10-02

The first stable 0.3 release. Its content is that of 0.3.0-rc.4 (see that
section below for every change, the security fixes for findings
ENC-SF-2026-033 to 094 and the breaking and behaviour changes). Several of
those fixes are only partial; the remainders are in the "Open" list of
`docs/security-findings.md` and in `KNOWN_LIMITATIONS.md`. The fixes have
been checked by two internal adversarial review passes, the release gate
and an 8-hour soak; they have not been reviewed by the independent
reviewers.

### Changes since 0.3.0-rc.4

- **Dependency lock:** `yoke-derive` 0.8.3 to 0.8.4 in `Cargo.lock` and
  `fuzz/Cargo.lock` (0.8.3 was yanked upstream and failed the supply-chain
  gate). No other third-party package moved.
- **Third-party notices** regenerated.
- **`restore.sh`** waits for a query over TCP, which only the final
  PostgreSQL server accepts, instead of `pg_isready`, which the image's
  temporary start-up server also answers. A restore into a fresh volume
  could fail ("the database system is shutting down", "database does not
  exist"); it failed loudly and worked on a second try.
- **Tests and examples:** the signed-request freshness test uses 310
  seconds, not 301, so a clock tick cannot put it on the accepted edge of
  the server's 300-second window (the server's rule is unchanged); example
  17 requires an accuracy gain above 0.02 instead of 0.1, which noise that
  is random by design made fail about one run in five.
- Version and release documents updated. No product runtime code,
  migration, configuration default or build feature changed.

## 0.3.0-rc.4 — 2026-09-29

- **Fine-tuning resume after a coordinator crash.** Every aggregation
  attempt now gets a new, strictly increasing SecAgg sequence, recorded
  with its training round before the coordinator starts. Resuming after a
  coordinator was killed once the parties had joined its round reused the
  sequence, which the parties refused as a replay. Nothing was released or
  charged; the run just could not continue.
- **Security response targets:** critical issues get a 7-day mitigation
  target, high issues 30 days.
- **Python 3.11 or later** is required (3.9 is end of life; 3.10 reaches it
  in October 2026). CI runs the whole SDK suite on 3.11.

### Security

Fixes for the independent review of 0.3.0-rc.3 and the follow-up review of
its fixes (findings ENC-SF-2026-033 to 094 in `docs/security-findings.md`; partial fixes and residuals are in
its "Open" list and in `KNOWN_LIMITATIONS.md`):

- **033:** a privacy ledger rolled back while the control plane runs is
  refused at the next spend (PRIVACY STATE ROLLBACK) and never anchored;
  the anchor records only checkpoints that extend the anchored one.
- **034:** a ledger frozen in the anchor stays frozen whatever the
  database says; startup refuses an unfrozen copy and recovery re-freezes,
  re-creating the ledger row, frozen, if the database lost it.
- **Anchor size:** the `encompute_anchor_bytes` gauge and an
  `anchor_size_warning` log line above 512 KiB (the anchor's sets grow
  without bound; see `KNOWN_LIMITATIONS.md`).
- **035:** evaluation keys are checked in full before OpenFHE loads them,
  must carry the tag they are sent under, and a tag already loaded is
  shared only by byte-identical key material.
- **036:** a workload accepts key grants only from broker keys bound into
  its attested identity (the training spec's `key_brokers`, or the keys
  baked into the FHE workload image), one signer per session; an unpinned
  broker is refused with a hardware attester.
- **037:** a training spec names only a factory the worker image ships,
  with schema-checked arguments; Hugging Face models are built only from
  the package's own `config.json`; a worker whose code differs from the
  spec's refuses before it attests.
- **038:** an audit checkpoint over a chain that does not extend the
  anchored root is refused (AUDIT STATE ROLLBACK) and raises an alarm.
- **039, 083:** disabled service accounts and users, and cancelled and
  failed jobs, are anchored and re-applied by recovery; a lost anchor
  compare-and-set reloads and retries.
- **040:** an asset approval covers only the organizations that were
  project members when it was given.
- **041:** a key broker named by an asset must belong to the platform or
  to the asset's organization; key messages go to and come from that
  broker only. Registering a service and registering an asset that names
  it serialize on the broker ID, so they cannot race past each other.
- **042:** API routes to disable a user, remove roles and memberships,
  remove project members and withdraw asset approvals.
- **043:** key broker state is authenticated (an HMAC keyed from the
  KEK); an edited state file does not open. An older copy that was
  genuinely authenticated still opens (rollback is not detected; see
  `KNOWN_LIMITATIONS.md`).
- **044:** a refused program upload is refused before anything is
  compiled or loaded.
- **045:** BinFHE bootstrapping keys with another method, dimensions or
  moduli than the vetted context are refused before any gate runs.
- **046, 078:** `encompute jobs run`, the Python SDK and the native SDK
  pin evaluator receipt keys themselves; an empty pin set refuses every
  evaluator.
- **047:** a secure-aggregation aggregate is always a release: a budgeted
  contributor needs `dp` and a ledger even when the output is sealed.
- **048:** every budgeted contributor needs a well-formed control-plane
  mapping before the round; the control plane refuses a reservation that
  under-declares its sensitivity.
- **049:** DP-SGD specs publish no data-derived count; dataset and
  grouping digests are salted commitments.
- **050:** the training configuration comes from the spec, and the input
  adapter must be the spec's initial one or the previous round's signed
  adapter record; the worker evidence commits to the input adapter, the
  configuration digest and the seed (which still comes from the job
  descriptor).
- **051:** a lookup table longer than its index type can reach is a type
  error instead of a panic.
- **052:** the threat model and review documents describe signed grants,
  where the grant pin comes from, and client-side evaluator pinning.
- **053, 054:** a job failed at start for a revoked asset is audited; an
  evaluator re-registering keeps an operator's drain, and its receipt key
  is audited.
- **055:** `restore.sh` restores in one transaction and stops at the
  first error.
- **056:** policy approval needs two different people with
  `security_admin` in the project owner's organization; no path grants
  `security_admin` to a service account. Accounts that hold it from an
  earlier release keep it but are never a policy's proposer or approver;
  the control plane reports them on every start (log line, one
  `security.legacy_service_admins` audit event per affected organization,
  `encompute_legacy_service_admins` gauge). New
  `GET /v1/security/legacy-service-admins` and
  `encompute security legacy-service-admins` (exit 1 while any remain)
  list them with the `memberships/remove` call that removes the role.
  0.3.x accepts them with these warnings; 0.4.0 will refuse them, at
  startup or through a migration announced in advance.
- **057:** project membership needs the invited organization's consent;
  invitations answer the same whether the organization exists.
- **058:** platform automation accounts can be disabled.
- **059:** used nonces are kept past the end of their acceptance window.
- **060:** planning is authorized before compiling; identity-provider
  errors are not echoed; tokens need `iat` and a bounded lifetime, and
  `nbf` is enforced; a default password in the database URL's query string
  is refused; `ENCOMPUTE_ENV` must be set; only the submitter learns a
  job's evaluator; repeated query parameters are refused; production
  `/metrics` needs a token.
- **061:** the OpenBao client follows no redirects.
- **062:** worker evidence names the attested image, and verification
  compares its privacy policy and artifact with the spec.
- **063:** an existing KEK file must be private and the OpenBao token file
  writable by its owner only; Google's attestation keys are refreshed;
  refusals do not reveal the release policy. `keys upgrade-state` prints
  every release gate (GPU attestation, maximum evidence age, mock
  evidence, policy format) before `--confirm`, and the state MAC is
  compared in constant time.
- **064:** under a control plane, `/v1/info` and the key lookup disclose a
  program only to a holder of its grant.
- **065:** the client refuses decrypted exact outputs outside their proven
  range, and an exact program without one proven range per output is
  refused at key generation, restore and decryption (a missing range was
  skipped, and the ranges were left out of the serialized program); BGV
  tracks noise from additions and refuses plans above its budget.
- **066:** BGV selection admits bitwise logic on Booleans only.
- **067:** a DP-SGD worker samples at the plan's rate and clips to the
  plan's norm, or refuses.
- **068:** units other than organizations are charged `2 × clip_norm`
  unless Poisson-sampled; `privacy explain` shows the unit bound.
  The named levels `standard`, `strong` and `maximum` now use twice their
  listed noise (4.4, 12, 36) for a record, patient, user or device budget,
  so each still affords about ten releases; organization-level noise is
  unchanged. The program records the level (`preset "strong"`) beside the
  effective noise, which is what is sampled, charged and receipted, and
  `privacy explain` and the trust report show `preset=strong,
  sensitivity_factor=2, effective_noise_multiplier=12 (2x preset 6.0)`.
- **069:** a non-finite unit gradient contributes zero.
- **070:** group privacy across parties is documented.
- **071:** the party `--state` file is locked, written atomically and kept
  per aggregation spec.
- **072, 073:** Hugging Face import refuses symbolic links, and
  tokenizer, quantization and attention-implementation settings outside
  the allowlist. `tokenizer_config.json` may not name files
  (`tokenizer_file`, `full_tokenizer_file`, `special_tokens_map_file`):
  Transformers prefers them to the package's own files and opens the path
  they name. Current Transformers never saves them; re-save an older
  tokenizer that carries them.
- **074:** `resume`, `infer`, `export_adapter` and `export_peft` take
  owner-supplied revocations and read the check's exit code. Supplied
  revocations are judged against the run's own program and ownership, so
  an owner's bundle holding only its signed revocation counts (it was
  ignored); a bundle that cannot be read, or a revocation of a parent
  asset that the trust report does not honour, refuses instead of being
  dropped. `finetune(resume=...)` takes `revocations=` too and checks them
  before any key is released.
- **075, 076:** the trust report honours revocations only from the asset's
  owner or the authorization's signer, and re-validates bundle records.
- **077:** the plan validator recomputes semantics and applies its own
  and the caller's floor, and refuses a plan whose program's semantics
  cannot be determined; a claimed execution proof counts only when
  checked.
- **079:** the commercial audit fails when it cannot read a binary's
  symbols, when it audits nothing, when listing an image's files fails,
  and when the training image carries no SDK native extension.
- **080, 081:** Actions pinned by commit SHA, base images by digest, and
  the TEE images install hash-locked Python packages and are built,
  signed and attested by the release. The TEE images
  (`encompute-confidential-space`, `encompute-training`) are also in the
  release's vulnerability gate, which fails unless every required image
  was scanned. Vulnerability exceptions are narrow and machine-checked:
  one advisory, one package and the exact installed version per entry,
  with a rationale, compensating controls, an upstream tracking link, an
  added date and an expiry; a missing field, a wildcard or list, an
  expired entry or one added after the approval fails the gate, and an
  exception for another version covers nothing. The exceptions'
  compensating control is a scan of the SDK's syntax tree
  (`scripts/release/scan_torch_usage.py`), which also catches aliased
  imports, from-imports and lookups by literal name, and fails the gate
  when it cannot complete.
- **082:** test hooks work only with development attestation.
- **084:** a key broker hears of a revocation only once it is anchored.
- **085:** the RDP accountant adds a relative rounding margin.
- **086:** `THIRD_PARTY_NOTICES.md` reproduces every production crate's
  license and notice files (`scripts/third_party_notices.py`).
- **087:** the key cache documentation matches what it isolates.

Later review of the control plane (ENC-SF-2026-088 to 094):

- **088:** a job's purpose is the one its program declares; a request
  stating another is refused, and a program that declares none cannot use
  another organization's asset. An approval for one purpose no longer runs
  a program written for another.
- **089:** a job's `source_assets` are exactly the registered assets its
  program reads (bound by asset ID in the program's `asset` declarations);
  another organization's asset is usable only that way, so a source can be
  neither left out nor stood in for.
- **090:** jobs over assets that require the owner's approval are approved
  only by a person of the asset's organization, never a service account.
- **091:** withdrawn asset approvals, the grants an organization loses by
  leaving a project, and the project membership itself are anchored: a
  restored database that still holds one is refused at startup (APPROVAL
  or MEMBERSHIP STATE ROLLBACK) and recovery withdraws or removes it again.
  Approving, or joining, again makes a new approval or membership.
- **092:** organizations an asset is shared with no longer see its key
  reference, storage location, size, media type or full policy, nor the
  submitting organization's user IDs in a job's history.
- **093:** removing a role (`memberships/remove`) is anchored: a restored
  database that still holds it is refused at startup (ROLE STATE
  ROLLBACK) and recovery removes it again. A role granted again is a new
  membership.
- **094:** every job's sources are derived from its program: the request's
  `source_assets` must list exactly the registered assets the program
  binds, each once, and none when it binds none. An omitted, extra,
  repeated or substituted asset (another registered version of a dataset)
  is refused, also over the submitter's own data, where rc.3 took the
  submitter's list. Lineage, revocation, audit and the trust report follow
  the derived set; the trust report fails a job whose recorded sources
  differ from its program's.
- **Pre-merge hardening:** the production training image also removes the
  standard library's `ensurepip` (which bundles pip and setuptools); the
  fine-tuning revocation check of a production-targeted run uses the trust
  report's `--production` strictness; the reference model's arguments are
  bounded together (at most 2^28 parameters and 2^28 activations per
  sample), not only one by one; and the unpinned-evaluator opt-out is
  honoured only under an explicit `ENCOMPUTE_ENV=development`.
- **Assurance:** invariants INV-192 to INV-217; INV-007, INV-101, INV-130,
  INV-131, INV-137, INV-138, INV-142, INV-143, INV-147, INV-156, INV-160,
  INV-162, INV-164, INV-170, INV-171, INV-174, INV-176, INV-178, INV-180,
  INV-182, INV-183, INV-184, INV-186, INV-194 and INV-195 extended.

### Breaking and behaviour changes

- **`ENCOMPUTE_ENV` is required** by the control plane: `production` or
  `development`. Unset or anything else refuses to start.
- **Production `/metrics` needs a token** (`ENCOMPUTE_METRICS_TOKEN_FILE`),
  or `ENCOMPUTE_METRICS_PUBLIC=true`. `init.sh` creates
  `secrets/metrics-token`.
- **Database migrations 0003** (`0003_consent_bound_sharing.sql`) **and
  0004** (`0004_approval_identity.sql`, approval and grant IDs) run at
  startup. Migrations are forward only.
- **A job over another organization's asset needs a program that declares
  its purpose and reads the asset by its registered ID** (`purpose "..."`
  on the `program` line; `asset "<asset ID>" ...` bound to the secret
  inputs), and `purpose` must equal the declared one.
- **A job lists exactly the registered assets its program binds**, its own
  included: `source_assets` (`--source`, `sources=`) names each asset the
  program binds an input to (`asset "<asset ID>" ...`), once, and is empty
  for a program that binds none. To record an own asset as a job's source,
  bind it in the program. A job recorded before this release with sources
  its program does not bind gets a failed `source assets` check in its
  trust report.
- **Shared assets are redacted for other organizations** (no `key_ref`,
  `storage_uri`, `size_bytes`, `media_type`; `policy` reduced to
  `require_job_approval`), and a job's actors appear to source owners as
  `organization/user` or `organization/service`.
- **Job approval (`POST /v1/jobs/{id}/approve`) takes a person** of the
  asset's own organization; service accounts are refused.
- **Project membership is by invitation:** the owner's admins invite, and
  the invited organization's admins accept with the same call. `POST
  /v1/projects/{id}/members` answers `200 {"status": "invited"}`, also for
  an organization that does not exist (was 404), and its response gains
  `status`; `GET /v1/projects/{id}` gains `invited`, and its
  `approved_assets` lists only the approvals that cover the caller's
  organizations, or of its own assets. Existing approvals cover only the
  members at the time they were given.
- **Identity tokens need `iat`** and a lifetime no longer than
  `ENCOMPUTE_MAX_TOKEN_LIFETIME_SECS` (default 24 hours); otherwise 401.
- **Service accounts cannot hold `security_admin`:** `POST
  .../service-accounts` with it answers 400. Policies are proposed and
  approved only by people, and the approver is a security admin of the
  project owner's organization.
- **A query string that names a parameter twice** is refused (400).
- **`evaluator_url` and `evaluator_receipt_key`** in `GET /v1/jobs/{id}`
  are `null` for every organization but the submitter's.
- **Privacy reservations** that under-declare their sensitivity, or in
  production are not drawn with `csprng`, are refused.
- **Production trust reports apply the verifier's plan floor**
  (`--production`, the default under `ENCOMPUTE_ENV=production`, and
  `--minimum-profile`, default `standard`): a job or model whose plan
  uses development attestation, a research backend or a weaker profile,
  as older plans may, now reports FAILED (ENC2402).
- **`jobs run` and `Project.run` need an evaluator pin**
  (`--trust-evaluator`, `ENCOMPUTE_TRUSTED_EVALUATORS`,
  `trusted_evaluators=`). Without one a job is refused unless
  `--allow-unpinned-evaluator` / `allow_unpinned_evaluator=True` is given,
  and that development opt-out is honoured only with
  `ENCOMPUTE_ENV=development` set explicitly: unset, `production` or any
  other value refuses it (rc.3 refused it only under `production`). Local
  scripts that use the opt-out must now also set `ENCOMPUTE_ENV=development`.
- **BGV parameter-set IDs change** (the profile's failure-probability text
  is part of the ID): recompile BGV artifacts and re-key.
- **KEK-protected key broker state needs an upgrade:** run `encompute keys
  upgrade-state` with the broker's usual `--kek` or `--root-key` options,
  check the printed policies, then rerun with `--confirm`. Until then an
  rc.3 state file protected by a KEK does not open. Development plaintext
  stores load as before.
- **The key broker's KEK file must be owner-only.** An existing KEK file
  readable or writable by group or others (mode bits `077`), for example a
  Kubernetes secret mounted with the default `0644` or with `0440`, is
  refused at startup. Fix it with `chmod 600` (or `400`), or mount the
  secret with `defaultMode: 0400` (or `0600`) and run the broker as the
  user that owns the file.
- **Downgrading after the upgrade is not supported.** Schema version 4
  refuses an rc.3 binary, and once the control plane writes the new anchor
  sets (ended jobs, withdrawn approvals, removed memberships and roles) an
  rc.3 binary cannot read the anchor. To roll back, restore the backup
  taken before the upgrade together with its matching anchor.
- **TrainingSpec v2, WorkerEvidence v2 and job descriptor v2.** Specs bind
  `key_brokers`, `coordinator_key` and `initial_adapter_digest`;
  `architecture` must name an allowlisted factory. rc.3 specs, evidence and
  descriptors are refused.
- **Doubled sensitivity for unsampled sub-organization units:** new
  privacy receipts and ledger entries record `2 × clip_norm`, and rc.3
  privacy receipts for such units no longer verify (ENC2204). Ledger
  entries keep the sensitivity they recorded, so spend recorded under rc.3
  stays charged at the old rate. Presets afford fewer releases. Example 09
  now uses `noise_multiplier` 12.
- **New epsilons change around the 12th significant digit** (the
  accountant's rounding margin). Recorded epsilons are not recomputed.
- **`aggregate serve` needs `--ledger`** whenever a participant has a
  budget, and artifacts with a sealed budgeted aggregation without `dp`
  are refused.
- **`--control-asset` is strict:** malformed, duplicated or missing
  mappings for a budgeted asset refuse the round.
- **Party `--state` files** keep sequences per aggregation spec.
- **New CLI flags:** `keys upgrade-state`, `jobs run --trust-evaluator`
  and `--allow-unpinned-evaluator`, `trust --production` and
  `--minimum-profile`.

## 0.3.0-rc.3 — 2026-09-28

The first published release candidate. 0.3.0-rc.1 and 0.3.0-rc.2 were
tagged but never released: their release workflows failed before signing
(fixes below and under rc.2).

- **Tests:** restoring a control-plane test database closes its sessions
  and drops it in one step (`DROP ... WITH (FORCE)`); a reconnecting pool
  could make the restore fail.
- **Example 17** names the check that failed as its last output lines.

## 0.3.0-rc.2 — 2026-09-28 (tagged, not released)

- **Release check:** the backup drill runs with the release-check Python
  environment; on the release runner the system `python3` lacked
  `cryptography`, which the drill's OIDC test issuer needs.
- **Image builds:** agent worktrees, nested build output and git data stay
  out of Docker build contexts.

## 0.3.0-rc.1 — 2026-09-27 (tagged, not released)

### Release candidate hardening

- **Security fixes** (findings ENC-SF-2026-001 to 031 in
  `docs/security-findings.md`): key revocations bound to the owning
  organization; broker-signed key grants; the query string signed in
  service requests; service messages applied once, transactionally;
  evaluator uploads need a job grant under a control plane, and job IDs
  are random; key files 0600 after every write; the Python client pins
  evaluator keys; DP aggregation receipts require bound privacy receipts;
  privacy spend reserved at the control plane before any release; the
  training privacy policy bound into attestation; offline `verify` checks
  the evidence kind and exits 0 only when every binding was checked;
  DP-SGD sampling from the OS CSPRNG.
- **Fuzzing.** Fuzz smoke tests for every parser, cargo-fuzz targets with a
  seed corpus and a nightly workflow (`fuzz/run_all.sh`). Fixed: unbounded
  worker frames, panics on out-of-range sampling rates and short worker
  replies, overflowing tensor offsets and launcher chunk sizes, unbounded
  ledger reads, clock-skew overflow.
- **Network attacks.** A bounded HTTP server for every service, with
  attack suites for slow, oversized, malformed, replayed and duplicated
  requests over real HTTP.
- **Restarts and backups.** Crash, connection-loss and restart suites for
  the control plane, evaluator, key broker and SecAgg coordinator;
  anchored revocations; a backup and restore drill
  (`scripts/release/backup-drill.sh`).
- **Correctness gates.** An OpenFHE differential gate (clear, mock,
  optimized and reference agree bit for bit;
  `scripts/release/differential-gate.sh`), unit, property and differential
  tests for every optimizer transformation, and a soak harness
  (`scripts/release/soak.sh`).
- **`encompute migrate`** checks and upgrades persistent artifacts; unknown
  and future versions fail closed, and signed evidence is never rewritten.
- **Release tooling.** Pinned inputs and reproducible-build checks,
  per-artifact CycloneDX SBOMs, vulnerability and license scans with a
  severity policy, and a signed release workflow that creates a draft
  GitHub release.
- **Assurance.** Invariants INV-172 to INV-191; INV-132, INV-153 and
  INV-171 extended or reworded.

### Release candidate documentation

- **Support matrix** (`docs/support-matrix.md`): the one authoritative
  list of what is supported, a supported subset, experimental, research
  only or unsupported, including unsupported combinations and platforms.
  The README's status table summarizes it.
- **Known limitations** (`KNOWN_LIMITATIONS.md`), **performance**
  (`docs/performance.md`, measured numbers only), **artifact
  compatibility** (`docs/compatibility.md`), **API stability**
  (`docs/api-stability.md`: Control Plane API v1 is frozen, with a
  deprecation policy) and the draft **release notes** for 0.3.0-rc.1
  (`docs/release-notes-rc.md`).
- `SECURITY.md`: supported releases, response targets, disclosure policy
  and scope.
- Drift fixed: CLI help no longer names TFHE-rs as a default backend;
  `docs/api.md` lists `POST /v1/organizations/{id}/key-rotations`; example
  13 shows the current catalog (104 invariants, 15 checks); example 19
  uses the measured gate times; CONTRIBUTING no longer asks for
  `--all-features`; decision-record numbers removed from user-facing
  text.
- `docs/deployment.md` states what the code does today: signatures do not
  cover the query string; TLS and database network security are the
  operator's job; privacy-spending roles; the audit chain's unanchored
  tail; ID conflicts; environment-variable fallbacks for secrets; the
  CLI coordinator's direct (non-outbox) reports; missing configuration
  variables. Decision records 0007, 0008, 0009, 0011, 0013 and 0020 gained
  dated update notes.

### Release-candidate resilience (tests, hardening, fixes)

- **Bounded HTTP server.** The control plane, evaluator, key broker and
  SecAgg coordinator serve through `encompute_verification::http`
  instead of tiny_http: fixed connection threads and a bounded queue
  (`503` beyond it), head and body deadlines with a minimum body rate
  (`408`), limits checked before reading (`413`, `431`), Content-Length
  only (`411` for chunked), one request per connection. A stalled or
  trickling client no longer holds a worker (or, on the single-threaded
  key broker and coordinator, the whole service).
- **Revocations are anchored.** Restoring an older database no longer
  makes a revoked asset usable again: startup is refused (REVOCATION STATE
  ROLLBACK) and `recover` re-applies the revocation.
- **Fixes.** A key release report is recorded once per message; asset
  storage URIs refuse `..` traversal; a restarted evaluator's running jobs
  fail instead of staying running; the evaluator answers refused grants
  with 401/409/503 instead of 500; plain-HTTP OpenBao addresses must be
  true loopback; `backup.sh` captures the anchor before the database;
  `restore.sh` keeps a newer key broker state.
- **Suites.** Network attack suites (control plane, evaluator, key
  broker), restart and crash suites (control plane process kills,
  `pg_terminate_backend` mid-transaction, evaluator, key broker and SecAgg
  coordinator restarts), key lifecycle review tests with OpenBao, and
  `scripts/release/backup-drill.sh`.

### OpenFHE performance and hybrid exact optimization

- **Optimized exact circuits.** Exact plans run as a gate circuit:
  - range-aware widths from the declared input ranges;
  - constant folding, Boolean simplification, common-subexpression reuse
    and dead-gate removal;
  - parallel-prefix adders and tree comparators when they finish in fewer
    rounds.

  The reference lowering stays as the correctness oracle
  (`ENCOMPUTE_EXACT_EXECUTION=reference`).
- **Parallel gates.** Independent gates run concurrently, in a
  deterministic order, within a process thread budget
  (`ENCOMPUTE_EXACT_THREADS`, `ENCOMPUTE_EXACT_WORKERS`). With 8 workers,
  the benchmark corpus runs 1.7 to 9.4 times faster than the reference
  lowering, with identical results.
- **BGV or BinFHE per program.** Unverified programs whose operations are
  all in the BGV subset run on OpenFHE BGV when the calibrated estimate is
  no slower. The planner and the compiler use the same estimates, and cost
  never overrides a security or verification requirement. `explain` lists
  both candidates.
- **Evaluation-key cache.** Keys are loaded once, bounded
  (`ENCOMPUTE_KEY_CACHE_BYTES`, LRU), shared read-only by concurrent jobs
  and isolated per session. Evaluators serve `GET /metrics`.
- **Provenance.** The optimizer version and circuit statistics are in the
  evaluator's program info and job response, not in any semantic ID.
  `explain` shows the optimized circuit; `explain --deep` shows the full
  optimization report.
- **Benchmarks.** `benches/exact/` is a 16-program corpus with a regression
  gate (`bench_baseline`), a timed OpenFHE benchmark (`exact_bench`) and a
  history (`history.jsonl`). Functional bootstrapping was measured and not
  adopted (`scripts/lut-measure.sh`).
- **Scheduling.** Evaluators register a machine profile. The control plane
  estimates completion time from gate counts and the queue.
- **Example 20** (`examples/20_openfhe_optimization`); a [decision record](docs/adr/0022-exact-optimization.md);
  invariants INV-166 to INV-171.

### Enterprise deployment foundation

- **Control plane** (`encompute-control`, API v1). It manages:
  - organizations, users (OpenID Connect) and service accounts (Ed25519),
    with seven roles;
  - projects with explicit cross-organization collaboration;
  - an asset registry (metadata, digests and wrapped-key references only);
  - four-eyes policies, planned jobs, evaluator registration, privacy
    ledgers, trust reports and an audit trail.

  It coordinates and holds no keys. Trust reports are rebuilt from signed
  evidence on every request.
- **Tenant isolation.** Other tenants' resources are "not found". Every
  route is tested unauthenticated, with the wrong role, from the wrong
  tenant and authorized, and a cross-tenant attack suite runs on top.
- **Service identity.** Signed requests and messages bind the sender,
  recipient, timestamp, a single-use nonce, the body hash and the IDs they
  concern. Evaluators run only jobs granted by their pinned control plane,
  and ask before starting each one.
- **Jobs.**
  - An explicit state machine and idempotent submission (`Idempotency-Key`).
  - Capability-aware scheduling: backend, parameter profile, health,
    capacity, draining.
  - Recovery after a restart never replays a job.
  - OpenFHE exact and OpenFHE CKKS both run through the same control plane.
- **Customer-managed keys.** `RootKeyProvider`, with OpenBao/Vault Transit
  as the first adapter. The key broker's KEK is wrapped by the
  organization's root key. `encompute keys rotate-root` re-wraps only the
  KEK. Revocation reaches the broker as a signed message. There is no
  fallback to local or plaintext keys.
- **Durable privacy state.**
  - Hash-chained ledgers in PostgreSQL: race-safe and idempotent.
  - A signed state anchor outside the database. Restoring an older database
    is refused (PRIVACY STATE ROLLBACK).
  - `encompute-control recover` freezes rolled-back ledgers.
- **Audit.** A hash-chained, anchored event for every security-sensitive
  transition. Events carry identifiers only.
- **Operations.**
  - `/live`, `/ready`, Prometheus metrics, JSON logs.
  - Production mode refuses development identities, key stores and default
    credentials.
  - Secrets come only from files or the environment.
- **Message transport.** HTTP (with an outbox) and in-memory
  implementations. Signed envelopes, idempotent consumers. SecAgg
  coordinators report privacy events and round durations.
- **Clients.**
  - `encompute login`, `projects`, `assets`, `jobs submit|run|status|list|cancel`,
    `trust report JOB`, `audit list`.
  - Python `encompute.Client` (`project.run(...)`).
- **Deployment.** Docker Compose: control plane, PostgreSQL, OpenFHE
  evaluator, key broker (as a sidecar to its KMS), SecAgg coordinator. It
  comes with images, `init.sh`, `backup.sh`, `restore.sh` and `smoke.sh`.
- **Evidence.**
  - `scripts/enterprise-e2e.sh`, in production mode:
    - both golden paths and the SDK;
    - a full restart;
    - backup and restore, where an older backup is refused;
    - revocation;
    - a canary scan of logs, the database, audit output and metrics.
  - Invariants INV-156 to INV-165.
- **Documentation.** A [decision record](docs/adr/0021-enterprise-deployment.md), docs/deployment.md, docs/api.md. Error codes
  ENC2601–ENC2607.

### Commercial exact execution on OpenFHE

- **OpenFHE exact** (`openfhe-exact`, scheme BinFHE): exact programs run
  encrypted on OpenFHE 1.5.1 BinFHE. Each value is a vector of encrypted
  bits (two's complement), and every plan operation is a Boolean circuit:
  - add, sub, mul, and multiplication by constants;
  - signed and unsigned comparisons, select, min and max;
  - division and remainder by constants;
  - shifts, casts, Boolean logic;
  - lookups up to 256 entries.

  The language and `ExactPlan` are unchanged.
- **The default exact backend.** The compiler, the evaluator and the
  planner select OpenFHE exact for unverified exact programs. Verified
  programs stay on BGV with re-execution proofs.
- **One vetted profile**: `BINFHE_STD128_GINX_BITS_V1` (STD128, GINX,
  128-bit, 2^-135 per gate). It is bound into artifacts, evaluation keys
  and ciphertexts.
- **Versioned envelopes** (`ENCBINF1`) bind every key and ciphertext to
  its backend, parameter set, client key and type. Mismatches are refused
  before any gate runs.
- **TFHE-rs is research-only.** The feature is renamed `research-tfhe-rs`.
  Selecting TFHE-rs in a production build (the
  `ENCOMPUTE_RESEARCH_EXACT_BACKEND` variable, `--backend tfhe-rs`, or a
  TFHE-rs artifact) fails with ENC1501 BACKEND UNAVAILABLE; it never falls
  back.
- **Commercial build audit** (`scripts/audit-commercial-build.sh`) checks
  the dependency graph, a CycloneDX SBOM (`scripts/sbom.py`), and the CLI,
  evaluator and Python extension binaries; optionally also a wheel and a
  container image. CI runs it on production builds, and runs it on a
  research build as a negative control.
- **Capability matrix.** Operations outside it are refused at compile
  time. `explain` prints each program's bootstrapped gate count.
- **CLI and SDK.** `encompute info` has an `openfhe-exact` row, and
  `encompute.has_exact()` is new.
- **Evidence.**
  - Exhaustive 8-bit circuit tests.
  - OpenFHE exact equals the clear reference and the mock on every
    operation and on random programs.
  - Remote execution with receipts.
  - Backend-independent transcripts.
  - A research differential test: OpenFHE exact equals TFHE-rs.
  - Invariants INV-149 to INV-155.
- **Example 19** (`examples/19_openfhe_exact`) covers Boolean logic, a
  lookup, and remote eligibility with a verified receipt. It also runs 13
  attacks: forged keys, parameters and backends, corruption, a modified
  plan, receipt replay, overflow, unsupported operations, and TFHE-rs
  selection.
- Benchmarks: gate counts per operation and width; about 62 ms per gate;
  524 MiB of evaluation keys (docs/benchmarks.md).
- A [decision record](docs/adr/0020-openfhe-exact.md).

### Confidential training on Google Confidential Space

- **Confidential training jobs**: `encompute.torch.job.prepare` plans a
  run for Intel TDX on Confidential Space and writes:
  - production attestation policies (the image digest, no debugging, no
    mock evidence);
  - a production broker with wrapped keys for the model, datasets, adapter
    and outputs;
  - sealed assets;
  - per-participant job descriptors with public commitments only.
- **The job worker** (`python -m encompute.torch.cs_worker`):
  - attests once per broker from an in-memory session, receives its keys
    sealed to that session, and decrypts and checks every asset in memory;
  - runs the same Hugging Face + PEFT DP-SGD step as example 17;
  - seals its contribution and signs **worker evidence** (run, spec,
    participant, round, model package, dataset, layout, image,
    attestation, output commitments).
  - Refusals: KEY RELEASE DENIED, TRAINING SPEC MISMATCH, ASSET MISMATCH,
    DATASET ASSET MISMATCH, MODEL PACKAGE MISMATCH.
- **Participant-scoped attestation**: a job attests to the spec scoped to
  its participant, so one session never receives another participant's
  dataset or output key, and the evidence's participant is attested.
- **Trust graph**: worker evidence nodes. The Training row verifies them
  against their spec and attestation, and flags a second output for one
  round.
- **The worker image** (`deploy/confidential-space-training`): pinned
  dependencies, `--locked` builds, offline Hugging Face. The launch policy
  lets the operator set only `JOB_URL`.
  - `deploy.sh`: `prepare-only`, `approved`, `tampered` and `debug`
    variants.
  - `cleanup.sh`, least-privilege worker identity, separate input and
    output buckets.
- **Local rehearsal**: `encompute attest simulate-launcher` (development
  only) and a production broker with a test JWKS; `job.py container` runs
  the built image.
- **CI**: builds the image and runs approved and tampered images on every
  pull request; `test_confidential_job.py`; example 18 required; a manual
  `confidential-space-live` workflow (SKIPPED without GCP); release-check
  rows for the image and the live run.
- **Broker**: one attestation per broker per session;
  `keys serve --requests-per-minute`; `trust init --attestation-policy`.
- **DP-SGD**: the gradient-path probe's tolerance is relative to the
  gradient's scale (see the benchmarks).
- A [decision record](docs/adr/0019-confidential-space-training.md); INV-143–INV-148 (81 invariants). The live GCP run is pending a
  project.

### Hugging Face Transformers + PEFT

- **Hugging Face models**:
  - `encompute.torch.huggingface(source, revision=)` imports a local or
    Hub model into a content-addressed package (`enchf1:`). The revision is
    resolved to an immutable commit; only safetensors, configuration and
    tokenizer files are kept, each hashed.
  - Refused (ENC2504): remote code (`*.py`, `auto_map`,
    `trust_remote_code`), pickled weights, unknown files, a shard index
    naming anything but the package's safetensors, unsupported
    architectures, and other library versions than the package binds.
  - Credentials are used for the download only.
- **Workers never download.** They rebuild the Transformers-native class
  from its configuration and load the sealed weights. The training spec
  binds the whole package, which the lineage prints.
- **PEFT LoRA** (`method="peft-lora"`):
  - The official `peft` library adds the adapters. `PeftConfig` in the
    training spec binds every setting.
  - The adapter layout (the LoRA matrices and the head) is canonical.
  - The reference LoRA stays for `method="lora"`.
- **Text datasets**: `private_text_dataset(texts, labels, tokenizer=,
  max_length=, stride=, unit_ids=)`.
  - Every chunk keeps its patient.
  - The tokenization is bound per dataset, and must use the package's
    tokenizer.
- **Per-patient gradients for Transformers**:
  - a vectorized fast path and a one-patient-at-a-time reference path,
    with identical semantics, chosen per model by a probe;
  - training fails closed if neither works;
  - task adapters read structured outputs.
- **PEFT export**: `FineTuneResult.export_peft(dir)` writes standard PEFT
  files and `encompute-adapter.json`. It does so only when every owner
  permits (`adapters="public"`), no parent is revoked and the trust report
  is satisfied. The files load with `PeftModel.from_pretrained`.
- **Planner**: the training declaration names the framework (workload
  metadata).
- **Packaging**: the `encompute[huggingface]` extra.
- **CI**:
  - The fine-tuning gate now also runs `test_dpsgd.py`, which it
    previously missed, and `test_huggingface.py`.
  - Examples 15–17 are required.
  - `examples/17_huggingface_peft` runs with 22 attacks failing closed.
- A [decision record](docs/adr/0018-huggingface-peft.md); INV-136–INV-142 (75 invariants).

### Patient-level differential privacy (DP-SGD)

- **DP-SGD for confidential fine-tuning**:
  `privacy="strong-patient"` or `"standard-patient"`, or
  `encompute.Privacy(unit="patient", ...)`, with
  `private_dataset(x, y, unit_ids=)`.
  - Each attested worker computes per-example LoRA gradients with
    `torch.func` (`vmap` over `grad`, microbatched). It groups each
    patient's records, clips each patient's gradient, and Poisson-samples
    patients with operating-system randomness.
  - Secure aggregation sums the clipped gradients. The attested
    coordinator adds discrete Gaussian noise.
  - One accounted step per round. Organization-level mode is unchanged.
- **Rényi DP accountant for Poisson-sampled releases**
  (`rdp-poisson-zw2019`: Zhu and Wang's general bound over the discrete
  Gaussian's zCDP curve; CKS conversion; rounded up).
  - Checked against 240 independent reference vectors (autodp and a
    60-digit mpmath evaluation).
  - `DpMechanism.sampling_rate` is in the IR text and the
    PrivacyPolicyId.
- **Every DP-SGD setting in the TrainingSpecId**: unit, clip, sampling,
  noise, delta, grouping, accountant and expected batch, plus each
  dataset's unit count and grouping digest.
- **Privacy preview**: a DP-SGD run over budget is denied before training
  (ENC2201). `encompute privacy explain --rounds N` prints the projection.
- **No false patient-level claims**:
  - the compiler refuses sampling with an organization unit;
  - the planner requires per-example clipping for a patient unit, and the
    plan shows the example level;
  - the trust report's Training row checks the unit;
  - the lineage prints it.
- `examples/16_patient_private_lora`: organization-level and patient-level
  privacy side by side, the preview denial, and eight attacks failing
  closed.
- `test_dpsgd.py`:
  - the vectorized gradients match the per-unit reference for any
    microbatch;
  - canary patient sensitivity;
  - sampling ignores seeds;
  - the ledgers match the preview;
  - the accuracy regression bound.
  The leakage canaries now run in both modes. INV-130–INV-135
  (68 invariants).

### Confidential PyTorch fine-tuning

- **Real PyTorch LoRA fine-tuning, protected end to end** (new crate
  `encompute-training`, `encompute.torch`):
  `Project.finetune(model=, data=, method="lora", privacy=,
  verification=)` plans the run, attests each participant's training
  worker, releases the model key only to it, trains LoRA locally with
  PyTorch, securely aggregates the clipped updates with differential
  privacy (organization-level), writes immutable sealed adapters and
  checkpoints, records signed adapter lineage, and verifies the whole run
  with one trust report.
- **Training spec** (`enctrain1:`) binding the plan, model and dataset
  digests, training code, LoRA configuration and tensor layout; workers
  rebuild models from bound factories (never pickles).
- **Checkpoint resume** refuses stale, foreign, tampered or rolled-back
  state against the authoritative privacy ledgers.
- `encompute lineage`, `encompute export` (EXPORT DENIED unless every
  parent permits), `encompute train`, `aggregate join --values -`; trust
  graph Training and Adapter nodes and a Training report row; attested
  inference with the adapter. Errors ENC2501–ENC2503.
- `examples/15_confidential_lora` with every attack failing closed.
- **The PyTorch boundary**: PyTorch computes in plaintext inside the
  attested workload; the TEE, secure aggregation and differential privacy
  protect it. Privacy unit: organization (each hospital's whole update is
  clipped). Patient-level DP requires per-example clipping (DP-SGD) and is
  not claimed.
- **Crash-safe rounds**: a round's adapter and checkpoint are provisional
  until its signed adapter record enters the trust bundle (the commit
  point); `recover` finalizes or discards after a crash, a released but
  uncommitted round stays charged, and `finetune(resume=workdir)`
  continues from the last accepted adapter (resume accepts only declared
  lost rounds after the checkpoint, checks the run ID and refuses once a
  parent is revoked).
- **Rust owns the formats**: TrainingSpec, checkpoints, adapter records,
  sealed-asset headers, the adapter layout (versioned, validated) and the
  canonical tensor file (pickles refused before loading), with contract
  fixtures checked by both the Rust tests and the Python bindings.
- **Release gate**: end-to-end, commitment, canary-leakage (datasets,
  weights, raw updates, keys), crash and kill (ten injection points) and
  contract tests run on every pull request, with example 15 required;
  `scripts/release-check.sh` from a clean checkout; export also refused
  after a revocation or a failed trust report. Package description:
  "Compiler and trust runtime for confidential AI".
- INV-120–INV-129 (62 invariants).

### Examples

- **A runnable example for every capability** (`examples/01`–`14`): CKKS
  and exact private computation, remote evaluation, receipts, verified
  execution, confidentiality policies, attested key release, secure
  aggregation, differential privacy, the trust graph, the planner, a full
  confidential collaboration with seven fail-closed attacks, the assurance
  suite, and the Python Project API. Each has `run.sh`, `expected.txt` and
  a README with its threat model and what it does not protect.
- `examples/run-all.sh quick|standard|crypto|full` with dependency
  detection (`encompute info`), in CI on every pull request (standard), in
  the OpenFHE job (crypto) and nightly (full).
- CONTRIBUTING: a user-visible feature is done with tests, docs and an
  example.
- Fixed: `aggregate verify --aggregate` now checks the released decoded
  values (and the asset's other fields) against the committed sum; an
  edited aggregate previously verified.
- `aggregate coordinator-policy --plan` and `trust init
  --coordinator-policy`, so planned rounds with attested coordinators work;
  `trust report --execution-policy`; `Project.plan(data=...)`; `explain`
  shows a declared DP mechanism; `transcript` defaults to the program's
  target backend; `assurance-report --only` refuses unknown checks.

### Planner

- **Declare trust requirements; Encompute chooses the mechanisms**
  (new crate `encompute-planner`): requirements derived from the
  confidentiality policy (hide from parties and the compute host,
  aggregate-only, purpose, privacy budgets, participants, correctness,
  attestation, region), profiles `standard`/`strong`/`maximum` that only
  add requirements, and selection among the existing mechanisms (FHE,
  verified execution, attested confidential compute with key release,
  secure aggregation, DP, local execution) by estimated cost. PLANNING
  FAILED (ENC2401) when nothing satisfies the policy; nothing is weakened.
- **Auditable, deterministic plans** with a reason and expected evidence
  for every requirement; `encplan1:` PlanIds; an independent validator
  (`verify_plan`, ENC2402).
- **Plans bound to execution**: `AggregationPlan.execution_plan_id` (spec,
  receipts, coordinator attestation), a Plan node in the trust graph, and a
  report row that fails on evidence outside the approved plan (ENC2403)
  and prints PLAN SATISFIED BY OBSERVED EXECUTION.
- CLI: `encompute plan`, `encompute check`, `explain --deep`,
  `aggregate … --plan`, `trust init --plan`. Python: `Project`, `.data`,
  `.model`, `.train(...)`, `PlanningFailed`.
- Assurance INV-110–INV-115: 50 000 generated planning scenarios nightly,
  every mechanism removal and plan-field mutation, the adversarial list.
- Fixed a flaky trust test (shared ledger directory between parallel
  tests).

### Trust graph

- **One verifiable record of a collaboration** (new crate
  `encompute-trust`): parties, assets, programs, policies, owner
  authorizations and revocations, aggregation rounds, aggregates, privacy
  releases, attestations and executions in one content-addressed bundle,
  with the signed evidence inside.
- **Owners approve programs**: signed `Authorization`s (program, policy,
  privacy policy, purpose, expiry) and `Revocation`s; a revocation lists
  every aggregate derived from the asset.
- **A trust report that trusts nothing the bundle says about itself**: it
  rebuilds the graph from the evidence (edges, nodes and attributes must
  match), checks signatures only against keys the verifier supplies
  (`--parties`, `--coordinator-key`, `--evaluator-key`), compares privacy
  spend with the budget the program declares, and never reports an empty
  or unchecked bundle as satisfied (`--require` for rows that must be
  present).
- CLI: `encompute trust init | authorize | revoke | add | report | lineage
  | graph`, `aggregate serve --trust-bundle`. Errors ENC2301–ENC2303.
- `PrivacyReceipt::sign`.

### Assurance

- **System assurance suite** (`encompute-assurance`, `docs/assurance.md`):
  62 security invariants, each with positive, negative, adversarial and
  end-to-end evidence; adversarial checks for DP crash injection,
  multi-parent atomicity, multi-process double spend, ledger tampering,
  receipt mutation and SecAgg at scale; `assurance-report` as the release
  gate in CI, nightly at larger scale with `cargo deny`.

### Differential privacy

- **Privacy budgets per asset**: `privacy unit "patient"
  epsilon 3.0 delta 1e-6` (Python `asset(..., privacy="strong",
  unit="patient")` or `DP(epsilon, delta)`), with named levels
  `standard`, `strong` and `maximum`.
- **Release boundaries**: outputs that reveal a budgeted asset must go
  through a DP mechanism (ENC2203); sealed values cost nothing.
- **Discrete Gaussian mechanism** on the secure-aggregation sum (`dp
  discrete_gaussian clip_norm C noise_multiplier z`; Python
  `secure_aggregate(..., privacy="strong")`): parties clip to L2 norm C,
  the coordinator adds exact integer noise (CKS 2020 sampler, CSPRNG).
- **zCDP accounting** with the CKS conversion; a hash-chained, locked,
  persistent **ledger** per asset with reserve-then-commit releases (no
  unaccounted release, no concurrent double spend); signed
  **PrivacyReceipts**; owners check their ledger (and its last checkpoint)
  before contributing and refuse over-budget rounds (ENC2201) or
  rolled-back ledgers (ENC2202).
- **PrivacyPolicyId** (`encprivacy1:`) in the execution spec, aggregation
  plan, ledgers, receipts and coordinator attestation.
- **Attested coordinators from the CLI**: `aggregate coordinator-policy`,
  `--coordinator-policy`, `aggregate serve --attester …`, and `join
  --mock-root`/`--jwks`.
- **Every owner checks every ledger**: each owner records every charged
  asset's checkpoint from the signed receipts and refuses a round that
  rolls back any of them.
- CI uses Node 24 actions (`checkout@v7`, `cache@v6`, `setup-python@v7`).
- New crate `encompute-privacy`. CLI: `encompute privacy budget`,
  `explain --ledger`, `aggregate serve --ledger`. Errors ENC2201–ENC2204.
  `examples/private_federated_training/`.

### Multi-party secure aggregation

- **Aggregation boundaries**. `aggregate "out" sum|mean minimum
  N colluding C clip [lo, hi] scale S modulus M` (Python
  `secure_aggregate(...)`)
  declares that an output is a sum of one input per party, released only by
  secure aggregation to its recipient if at least N parties contributed. It
  satisfies `aggregate_only` (ENC1905 otherwise); the aggregate gets a
  derived policy (contributors as owners, never public by default).
- **Compile-time quantization analysis**: clipping, scale and modulus are
  explicit, and encodings that could wrap the modulus are refused
  (ENC2105). Shown in `privacy explain`, `explain` and receipts.
- **`encompute-secagg`**: Bonawitz et al. (CCS 2017) secure aggregation,
  active-adversary variant (signed keys, consistency check). The declared
  collusion bound sets the threshold `max(N, ⌊(n + C)/2⌋ + 1)`; dropouts
  are tolerated down to it. Aggregation specs (`encagg1:`) and rounds
  (`encround1:`) bind every message; signed `AggregationReceipt`s record
  contributors, dropouts, commitments, attestations and the aggregate
  commitment. Optional attested contributors.
- Aggregation programs never run on a single evaluator (ENC1905).
- Each contribution carries signed metadata: RoundID, AssetID, PolicyID,
  ExecutionSpecID, codec ID, shape, protocol keys and attestation. The
  coordinator checks it and the receipt records it. The aggregate asset has
  its own AssetID, with the contributing assets as parents.
  `privacy explain` shows individual release PROHIBITED, aggregate release
  PERMITTED, and runtime enforcement ACTIVE.
- CLI: `encompute aggregate identity|serve|join|verify`;
  `examples/confidential_federated_update/`. Errors ENC2101–ENC2106.
- **Key broker storage**: `SecretStore` (`DevelopmentFileStore`,
  `LocalKekStore`); production brokers refuse plaintext key storage
  (`encompute keys … --kek FILE`). Revocation destroys key material, and
  `encompute keys rewrap --new-kek` rotates the KEK.

### Attested confidential compute

- **Policy-gated key release**. Asset keys are released only to a
  workload whose fresh hardware attestation binds the approved execution
  spec, `PolicyId`, artifact digest, evaluator receipt key and an ephemeral
  session key, and satisfies the asset's `AttestationPolicy` (TEE, image
  digest, debug, TCB, GPU). Keys travel as HPKE grants sealed to the
  attested session; the host relaying them cannot open them.
- **`encompute-attestation`**: provider-neutral `VerifiedWorkload` claims,
  `WorkloadBinding`, single-use challenges, `AttestationPolicy`. Providers:
  Google Confidential Space (OIDC tokens verified against Google's JWKS)
  and a development-only mock that production policies and brokers refuse.
- **`encompute-keybroker`**: challenges, attested sessions, release,
  rotation and revocation; HTTP server and client; workload-side
  `acquire_keys`.
- **Receipts bind the attested session** (receipt version 3: optional
  `attestation` with the record ID and session ID). `encompute-evaluator
  serve --attestation FILE`, `GET /v1/attestation`, and `encompute verify
  --attestation … --attestation-policy …` check the chain attestation →
  evaluator key → receipt.
- CLI: `encompute attest verify|policy|mock-root`, `encompute keys
  protect|challenge|release|rotate|revoke|serve`, `encompute workload
  keys|attest`. Errors ENC2001–ENC2004.
- `deploy/confidential-space/`: image, entrypoint and deploy script for the
  real Confidential Space run.

### Confidentiality IR

- **Parties, assets and policies** in the IR: owners, readers,
  purposes, release (`never`, `owner_only`, `allowed_parties`,
  `aggregate_only`, `public`), and owner-permitted derivations; secret
  inputs bind to assets; outputs are sealed, revealed to a party, or public.
  Requirements only: execution is unchanged.
- **Confidentiality analysis.** Every value's policy is the join of its
  inputs' (owners union, audience and purposes intersection, most
  restrictive release); policies weaken only through derivations every
  source permits. Illegal flows are compile errors ENC1901–ENC1906.
- **Policy identity.** `PolicyId` (`encpolicy1:`) is part of the execution
  spec when a program declares a policy, so receipts and proofs bind it.
  Artifacts (format 5) carry `policy.json`.
- `encompute privacy explain` and `privacy graph --format dot`; Python
  `Party`, `asset(...)`, `secret[shape, lo:hi, asset]`, `confidential(...)`,
  `reveal(...)`, `publish(...)`, `compile(purpose=...)`, `Model.privacy()`;
  `examples/confidential_training.py`.

### Verified execution (research)

- **Verified private execution.** `verification="required"` (Python) /
  `verification required` (`.eir`) compiles exact programs to a new OpenFHE
  BGV backend (u8, u16, bool; `+ - *`, constants, `& | ^ ~`) and fails with
  ENC1801 unless every instruction is provable. Each result carries an
  `ExecutionProof` (relation `FheEvaluationV1`, protocol `reexecution-v1`)
  bound in the signed receipt; the client re-executes over the committed
  request with its evaluation keys and decrypts only on a byte-for-byte
  match. Sound, not succinct. Research feature `vfhe-research`
  (crate `encompute-vfhe`).
- **Malicious evaluator caught.** Random, replayed, skipped, substituted
  and mutated results, each with a valid signed receipt, are rejected by
  the proof; with receipts alone the same lie is accepted.
- **Proof plumbing.** `VerificationRelation`, `CiphertextBinding` (checked
  against the commitments before a backend sees them),
  `VerificationKeyId` (`encvk1:`), `ExecutionProof` (`ENCP` encoding),
  receipt evidence `Vfhe` (proof digest), `VerificationState`
  (unverified / receipt verified / execution verified), capability
  negotiation, `GET /v1/jobs/{j}/proof`.
- **CLI.** `run --remote` prints `VERIFIED PRIVATE EXECUTION` only after the
  proof verifies and saves `proof.bin`; `verify --proof --evaluation-keys`.
- Research findings recorded in a [decision record](docs/adr/0009-vfhe-proof-backend.md): Fherret binds no output ciphertext
  and has no license; ZHE's published analysis had a bug; TFHE-rs
  evaluation is not byte-reproducible; OpenFHE BGV is.
- Cost (loan pre-check, M3 Max): evaluation 24 ms, verification 65 ms,
  proof 543 bytes.

### Semantic transcripts

- **Semantic transcripts.** Every exact plan maps deterministically to a
  `SemanticTranscript` (stable numeric opcodes, typed canonical constants,
  plan-local registers, inputs without values) with a stable hash
  (`enctrace1:…`), bound to the execution spec.
- **Receipts v2** bind the transcript hash; clients compute it from their
  own plan and refuse a mismatch (ENC1702). `verification.json` stores the
  transcript version and hash; `encompute audit` checks it.
- **Proof boundary.** `ExecutionStatement` (spec, commitments, transcript
  hash), `StatementShape`, `VerificationCapabilities`, and a
  `VerificationBackend` with proving/verification keys, witness and
  evidence types; `NoProofBackend` still proves nothing.
- **Observers** receive `InstructionEvent`s and can fail an execution;
  `TranscriptObserver` records the plan-derived transcript.
- `ReferenceTranscriptEvaluator` (plaintext replay, for tests only): 12 132
  generated plans replay exactly; nightly runs 25 000 programs.
- CLI: `encompute transcript`; `explain` reports verification readiness;
  `verify` checks the transcript hash against the artifact.
- Fix: evaluator worker processes kept the gateway's backends (a mock for
  one semantics replaced OpenFHE for the other).

### Execution identity and receipts

- **Execution specs.** `ExecutionSpec` binds program, plan, parameters,
  plan kind and version, semantics, scheme and backend; its domain-separated
  ID is stable across machines and compilations. Artifacts (format 4) carry
  `verification.json`.
- **Signed receipts.** Every evaluation (local or remote, CKKS or exact)
  produces an `ExecutionReceiptV1` signed with the evaluator's Ed25519
  identity, binding the spec, key, and exact request and response
  envelopes. Clients verify it before decrypting (ENC1606 on any mismatch).
  A receipt is a signed claim, not a proof: `evidence` is `None`.
- **Evaluator identity.** `encompute-evaluator serve --identity FILE`;
  clients pin the key on first use or take `--trust-evaluator`.
- **CLI.** `run --remote` prints receipt status and can
  `--save-receipt`/`--save-envelopes`; `encompute verify` checks saved
  receipts and prints `RECEIPT VERIFIED` / `EXECUTION PROOF NOT PRESENT`.
- **Proof hooks.** `ExecutionObserver` on exact plans (structure only, never
  values) and the `VerificationBackend` interface (`NoProofBackend`).
- Canonical JSON and domain separation: see the [decision record](docs/adr/0007-verifiable-execution.md).
- Exact tests: 10 000+ random programs on the mock; TFHE-rs on every
  operation at the boundaries of all eight integer widths and on random
  programs; benchmark example `exact_ops`.

### Exact programs

Exact private computation: integers and Booleans, computed exactly.

- **Exact types.** Integer (`u8`–`u64`, `i8`–`i64`) and `bool` values with
  `+ - *`, comparisons, logic, shifts, min/max, select, lookup tables, casts and
  division by public constants. Integer range analysis proves no operation
  overflows; a possible overflow is a compile error (ENC1303). Exact values
  at the API are integers within ±2^53.
- **Python.** `secret[u8, 0:120]` … `secret[i64, lo:hi]`, `secret[bool_]`;
  `+ - *`, `< <= > >= == !=`, `& | ^ ~`, `<< >>`, `//` and `%` by constants,
  `encompute.select`, `minimum`, `maximum`, `lookup`, `cast`. Results come
  back as `int` and `bool`.
- **One compiler, two schemes.** The program's types choose the
  lowering: approximate programs → CKKS, exact programs → a
  backend-independent `ExactPlan` (validated before it runs). Mixed programs
  are refused until 0.4.
- **Scheme-neutral runtime.** `Model`, client and evaluator sessions,
  artifacts (format 3: `semantics`, `scheme`, per-plan-kind versions),
  envelopes (explicit scheme check), the evaluator service (one backend per
  semantics), worker processes, and `run`/`test`/`explain`/`bench`/`audit`/
  `keys` handle exact programs. Exact tests report matches and mismatches,
  never error metrics.
- **TFHE-rs backend** (`encompute-tfhe`, `encompute-tfhe-client`) behind the
  off-by-default `tfhe-rs` feature: research use only; Zama requires a patent
  license for commercial use. Encrypted results equal the clear reference on
  1000 random inputs of the eligibility example. `scripts/exact-demo.sh`
  runs it through a separate evaluator process.
- Rust toolchain 1.98.1.

## 0.2.0 — 2026-09-25

Real private execution: a client encrypts, a separate evaluator computes,
only the client decrypts.

- **Client/evaluator split.** `CkksClient` and `CkksEvaluator` traits; the
  OpenFHE code is split into `encompute-openfhe` (evaluation only) and
  `encompute-openfhe-client` (keys, encryption, decryption). The evaluator
  binary links no client crypto; `scripts/audit-evaluator-binary.sh` checks
  it in CI.
- **Envelopes.** Every ciphertext, key set and result is wrapped in a
  versioned, SHA-256-checksummed envelope bound to parameter set, program and
  key. Wrong key, program, parameters or kind, and corruption, are rejected
  with ENC16xx codes.
- **Evaluator service.** `encompute-evaluator serve` (HTTP): program upload,
  one-time evaluation-key registration, jobs. `--workers N` runs worker
  processes with crash restart and replay. Container image:
  `Dockerfile.evaluator`.
- **CLI.** `keys generate`, `serve`, `run --remote --keys`, `audit`,
  `explain --measure` (measured bytes, time, memory, error, ranking).
- **Hardening.** Parameter conformance against OpenFHE (10 080-point grid,
  nightly) and encrypted execution of random programs; fuzzing of the
  parser, envelopes and artifacts; artifact format 2 with versioned
  compiler, plan and parameter-selector provenance.
- **Demo.** `scripts/two-machine-demo.sh`: 384-d encrypted query vs 64
  documents on a containerized evaluator, max error 1.9e-7, top-5 equal to
  plaintext, no secret key in the container. Runs in CI.
- **Benchmarks.** `docs/benchmarks.md`: five workloads and evaluator
  concurrency.

Breaking: artifact format 2 (recompile 0.1 artifacts); error codes renamed
VEIL#### → ENC####; project renamed Veil → Encompute.

## 0.1.0 — 2026-09-24

First end-to-end version: typed Python → Encompute IR → CKKS plan →
OpenFHE, with automatic 128-bit parameters, Chebyshev sigmoid,
differential testing, `explain`, `bench` and reproducible artifacts.
