# ADR-026 — Placement, operators and data minimization in the planner

Status: **Accepted** (2026-09-29) for the placement model, constraint
composition, enforcement points, operator separation and the minimization
objective, as design. The items under "Open decisions" are **Proposed** and
not decided. Placement and operator separation are built on the development
branch (see "As built" below); nothing here is part of 0.3.

## Context

An institution that authorizes a computation over its records usually
also has rules about where that computation may run and who may operate
the machines: a region or jurisdiction, a list of operators it accepts,
locations it will not accept at all. In a cross-agency project each
member brings its own such rules, and they must all hold at once.

Encompute 0.3 places work with the planner (ADR-015), but its model has
no notion of location or operator:

- `TeeOffer` and the host path are judged by `tee_unusable` and
  `host_unusable` on capability (backend, profile, attestation), not on
  where the machine is or which organization runs it.
- Evaluators are platform services, registered by a service account. There
  is no operator identity separate from the platform, so "the evaluator is
  not run by a data owner" cannot be stated, let alone checked.
- The scheduler picks any healthy evaluator. The client's pin set
  (INV-184) pins receipt keys, not locations.
- The key broker checks attestation, spec and policy (ADR-011), but not
  placement.
- `Objective` is `Latency` or `Cost`. Nothing prefers the plan that
  releases the least.

ADR-025 defines location evidence levels and the broker's placement check.
This record defines how placement constraints are declared, combined,
planned and enforced, how operators are kept separate, and how the planner
prefers the narrowest release.

## Decision

### 1. Types

In `crates/encompute-planner/src/model.rs`:

```
Location { jurisdiction, provider, region, zone? }
LocationEvidence = SelfDeclared < OperatorDeclared < Attested      (ordered)
PlacementConstraints {
  allowed_regions?:      [LocationPattern],   // absent = no restriction
  prohibited_locations:  [LocationPattern],   // deny wins
  allowed_operators?:    [OrganizationId],
  allowed_evaluators?:   [EvaluatorId],
  min_evidence:          LocationEvidence,
  applies_to:            {plaintext, ciphertext, keys, evidence}
}
EvaluatorOffer { id, operator, backends, profiles, location,
                 evidence, evidence_digest }
```

- `Infrastructure` gains the evaluator offers, the per-organization
  brokers and the SecAgg coordinator offers.
- `PlanningContext` gains `placement` and `roles { decryptors,
  coordinator }`.
- `TrustRequirement` gains `Placement`, `OperatorSeparation` and
  `KeyCustody` (the last is ADR-025's per-asset custody requirement).
- The evidence levels and how each is obtained are in ADR-025, section 7.
  In short: `SelfDeclared` is the service's own claim; `OperatorDeclared`
  is signed by a human `security_admin` of the operator organization
  through `POST /v1/evaluators/{id}/location-declarations`, audited and
  recorded in the governance event log; `Attested` comes from a verified
  TEE attestation (the GCE zone in a Confidential Space token), refreshed
  after `max_evidence_age`.

**Locations table.** Patterns match against a versioned table,
`crates/encompute-planner/src/locations.rs`, mapping each provider region
and zone to its jurisdiction. The table's digest goes into the plan, so a
plan records which version of the table it was made with. A region or zone
missing from the table never matches an allowed pattern, and an evaluator
whose location is unknown is inadmissible under any constraint. Region is
not jurisdiction: a region names where a machine is, not whose law reaches
it. That is why `allowed_operators` exists alongside `allowed_regions`.

**Scope (`applies_to`).** A constraint can apply to steps that handle
plaintext (an owner's client, a TEE decryptor), ciphertexts (an
evaluator, a SecAgg coordinator), keys (brokers, KMS, the decryptor's key
store) or stored evidence. Whether all four are covered by default is open
(K-9); the recommendation is all four.

### 2. Where constraints live

Three sources, each signed by whoever is entitled to set it:

- **Asset policy.** The owner declares `placement` in the IR
  `AssetPolicy`. It is part of the policy, so it is part of the PolicyId,
  and a program cannot quietly drop it. Plan-time `refines` (the
  registered-policy check) is extended so that a program's declared
  placement must be at least as tight as the owner's registered one.
- **Project.** The project's placement is part of the governed project's
  policy digest (`project_policy_digest` in the GovernanceBinding,
  ADR-023). **Any member may tighten it; loosening it needs every member.**
  Either change is a signed, logged governance event. A tightening applies
  to every plan made afterwards, and `schedule_job` re-checks existing
  plans against the current project constraints (section 4).
- **Purpose.** `Purpose.placement` (ADR-023, section 4) is accepted by
  every source owner along with the rest of the purpose.

An owner's `AuthorizationV2` may also carry `placement`. It can only
tighten the constraints for steps that consume that owner's asset, never
loosen them.

### 3. Effective constraints

The planner computes an effective constraint for each step from every
source that applies to it: the project, the purpose, and the asset policy
and authorization of every asset whose plaintext, ciphertexts or keys the
step handles (as selected by `applies_to`). An evaluator step that consumes
three agencies' ciphertexts must satisfy all three agencies' constraints.

| Field | Composition |
|---|---|
| `allowed_regions`, `allowed_operators`, `allowed_evaluators` | intersection (an absent set does not restrict) |
| `prohibited_locations` | union |
| `min_evidence` | maximum |
| `applies_to` | each source applies to the steps its own `applies_to` selects |

- **Deny wins.** A location matching any prohibited pattern is refused even
  if an allowed pattern also matches.
- The composition is monotone: adding a source can only shrink the
  admissible set. No combination of sources widens what any one of them
  allows.
- The effective constraints, the locations-table digest and the resulting
  admissible evaluator set are recorded in the plan and bound into the
  PlanId, and their digest is the GovernanceBinding's `placement_digest`.

### 4. Enforcement points

Placement is checked where the decision is made and again wherever a key
or data could leave:

1. **Planner.** `placement_unusable` replaces `tee_unusable` and
   `host_unusable` and judges capability, location, operator and evidence
   together. `derive` emits the `Placement`, `OperatorSeparation` and
   `KeyCustody` requirements; `validate` re-checks them against the plan.
2. **`create_plan`** (control plane) builds `Infrastructure` from the
   evaluator registry: each evaluator's operator organization, location,
   evidence level and evidence digest.
3. **`schedule_job`** picks only from the plan's admissible set, and only an
   evaluator whose current evidence is at least `min_evidence` and fresh.
   If none qualifies, the job waits with "no admissible evaluator". It
   never falls back to another evaluator.
4. **`start_job`** re-checks the chosen evaluator's evidence before the grant
   is used. The JobGrant v2 names the evaluator operator and location
   (ADR-023), so the evidence records where the job was placed.
5. **Client-side pin check.** The client's pin set (INV-184) gains the
   operator, location and evidence level per pinned evaluator. An agency's
   client refuses to send its asset's ciphertexts to an evaluator outside
   its own asset's constraints, judged by what it pinned rather than what the
   control plane answers (as built: key, URL, operator, location, evidence). The
   client needs only its own constraints to do this.
6. **Broker.** The key broker admits a session only if its attested
   placement satisfies the constraints for that asset (ADR-025, check 7).
   Missing placement evidence is a refusal.

No grant, release ticket or key goes to an evaluator, coordinator or
decryptor outside the effective constraints. Self-declared locations never
satisfy a production deployment.

### 5. Failing closed without leaking

If the admissible set is empty, planning ends in **PLANNING FAILED** (ENC2710
at the control plane). The failure gives one reason per constraint that
excluded the offers, and is written so it does not reveal one agency's
private constraints to another:

- the caller sees the values of constraints it set itself, and of project
  and purpose constraints, which every member already holds;
- for a constraint that comes from another organization's asset policy or
  authorization, the caller sees only which organization's constraint and
  which field excluded the offers (for example "an input owned by
  tax-agency: allowed_regions admits none of the offered evaluators"), not
  that organization's allowed or prohibited values;
- the owning organization sees its own values in its own view.

The planner never relaxes a constraint to find a plan, and a failure is
never downgraded to a warning.

### 6. Operator separation

Each evaluator has an operator: the organization of the service account
that registered it. Today that is the platform operator. In governed
projects, a designated operator organization may register and run
evaluators (open decision O-1), so that the operator is a separate,
named organization.

In governed projects, `OperatorSeparation` requires:

- the evaluator's operator is not a source owner of the job and not a
  decryptor of its output;
- the evaluator holds no decryption key;
- a SecAgg coordinator is not a contributor to the round;
- the control-plane operator holds no key that protects data (ADR-025).

Plan validation refuses a plan that violates any of these, and the
governance report shows "Decryption control" as FAILED if the key holder
is the evaluator operator (ADR-027).

| Role | Receives | Never receives |
|---|---|---|
| Agency | its own plaintext, K1–K4, K11, tickets, receipts | others' K3 or K5, others' plaintext |
| Evaluator operator | ciphertexts, K6, the bound artifact, the JobGrant | K1–K5, K11, the linkage key, plaintext, others' private metadata |
| Decryptor | K5 and the one output ciphertext | input ciphertexts |
| SecAgg coordinator | masked vectors | individual contributions, K3 |
| Control-plane operator | metadata, tickets, grants | any key |

Key classes are ADR-025's. Separation limits what a malicious evaluator can
do, but does not remove it: an evaluator could return one bit of an input
attribute in place of the expected Boolean. That is bounded by the output
width check and `max_releases`, not prevented, and the documentation says
so. Verified execution in production would close it and is out of scope
here.

### 7. Data minimization objective

A new `Objective::Minimize` orders admissible candidates lexicographically:

1. release-class rank, narrowest first: never < boolean < bounded category
   < DP aggregate < aggregate < value;
2. bits released;
3. the number of principals who learn the result;
4. latency.

- Minimization only orders candidates that already satisfy every hard
  constraint. It never trades a constraint for a narrower release.
- The planner never rewrites a program. It prefers mechanisms that release
  less for the same program: source-side predicate pushdown (ADR-024),
  secure aggregation over decrypting per-party values, noise added before
  decryption.
- A program output wider than an input asset's release class (ADR-023's
  `release_class`) is PLANNING FAILED, with a hint naming the narrower form
  (for example a Boolean or a bounded category) that the class allows.

### 8. Invariants and error codes

- INV-233 (placement decides where work runs), INV-234 (operator
  separation) and INV-242 (minimization) in the `public-sector` area, with
  positive, negative and adversarial evidence
  (`crates/encompute-planner/tests/{placement,residency}.rs` and the
  cross-agency property check).
- ENC2710 "Residency or placement unsatisfied" (ADR-023, section 13).

## Open decisions

These are recorded in the milestone plan's open decisions and are not
decided here:

- **K-3 Location evidence required in production.** `OperatorDeclared`
  (human-signed) as the floor; whether `Attested` is required when an
  organization declares prohibited locations. Recommendation: the floor
  now, `Attested` in the strong profile.
- **K-9 Residency scope.** Whether constraints cover ciphertexts, keys and
  stored evidence, not only plaintext. Recommendation: all four by default
  through `applies_to`. Ciphertexts copied to a prohibited location remain
  FHE-protected, but a stricter scope may still be required by an owner.
- **K-8 Location taxonomy.** Who maintains `locations.rs` and how new
  regions are added and reviewed, and which clouds the first table covers
  (together with the KMS adapter order in ADR-025).
- **O-1 Operator-owned evaluators.** Whether a designated operator
  organization may register evaluators in governed projects.
  Recommendation: yes; operator separation needs an operator identity
  other than the platform.

## Consequences

- Residency becomes a planning input rather than a deployment convention.
  An unsatisfiable combination is found before any key or ciphertext
  moves, and the reason names the constraint.
- Every placement decision is recorded in the PlanId and the grant, so the
  governance report can say where a job ran and on what evidence.
- Agencies must keep their constraints and the location table accurate. A
  stale table fails closed (unknown regions never match), which can block
  jobs until it is updated.
- A declared location is attributable, not proven. Without a TEE, an
  operator can declare falsely, or move a machine after declaring. The
  report labels each location "attested" or "declared" so readers can tell.
- Network routing, copies made outside Encompute and lawful access by the
  state hosting a machine are outside what placement can control. The legal
  assessment of a location stays with the owner.
- Operator separation needs at least one organization willing to run
  evaluators that is neither a source nor a decryptor.

## Alternatives considered

- **Placement as deployment configuration only.** Pin evaluators per
  project by hand. Rejected: nothing would record or check it, and a
  scheduler change could silently move a job.
- **Union of allowed sets.** Rejected: one member's permissive rule would
  override another's restriction.
- **Allow wins over deny.** Rejected: an explicit prohibition must hold
  even when a broad allowed pattern also matches.
- **Relax constraints to find a plan, with a warning.** Rejected: a
  warning is not consent.
- **Report the full conflicting constraint set on failure.** Rejected: it
  would disclose one agency's placement rules to the others.
- **Minimization by rewriting programs.** Rejected: the planner would be
  changing what the owners authorized. It chooses among mechanisms for the
  authorized program only.

## As built (residency and operators, phase 6)

Recorded 2026-10-01. Where this differs from the design above, this
section is what was built.

- **Types live in the verification crate.** `Location`, `LocationEvidence`,
  `LocationPattern`, `PlacementConstraints`, `Scope` (the `applies_to`
  values), `GrantPlacement`, `EvaluatorPin` and the versioned locations
  table are in `crates/encompute-verification/src/placement.rs`, not in the
  planner: the key broker, the control plane, the CLI and the planner all
  need them, and the broker cannot depend on the planner. The planner
  re-exports them (`encompute_planner::locations` is the table). The
  planner has `EvaluatorOffer`, `PlacementContext`, `Roles`, the
  `Placement` and `OperatorSeparation` requirements, the admissible set
  (`crates/encompute-planner/src/placement.rs`) and
  `Objective::Minimize`. `TeeOffer` gained no location, so a TEE offer can
  never satisfy a placement constraint in a plan (it is refused, not
  assumed); `PlanningContext.placement` is absent outside governed
  projects, so standard plans and PlanIds are unchanged.
- **The table.** Version 1 lists Google Cloud, AWS and Azure regions and
  organizations' own premises by country (`onprem`), with ISO 3166
  country codes as jurisdictions. It is compiled in, reviewed in the
  repository (K-8: whoever changes it changes a reviewed file), and its
  digest is recorded in every governed plan; a plan made with another
  version no longer validates. An unknown provider, region or zone is
  refused when a constraint or location is declared, never ignored.
- **Which constraints are carried where.** The plan carries only the
  project's constraints (every member holds them). An owner's own
  constraints ride in the owner-signed authorization
  (`limits.placement`, part of the AuthorizationId, so a looser copy is
  another authorization) and are applied where the job is bound, at
  scheduling, at start and by the owner's broker; they never appear in a
  plan or another organization's view. `AssetPolicy.placement` in the IR
  and `Purpose.placement` were not built: a purpose is accepted by every
  owner already, and the owner's authorization is the per-asset,
  per-purpose place for the rule.
- **Project constraints** (`POST` and `GET /v1/projects/{id}/placement`,
  migration 0018). A member's security admin tightens at once; any other
  change loosens and takes effect when every member organization has sent
  exactly the same constraints from the same version. A job's binding
  names the digest of the version it was bound under
  (`placement_digest`), and everything that judges it afterwards reads
  that version together with the current one, so a later loosening never
  widens a bound job and a later tightening applies at once.
- **Evidence** (migration 0017). The operator of an evaluator is the
  organization of its service account; an organization may hold evaluator
  accounts of its own (O-1). An evaluator reports its location when it
  registers (self-declared, with the jurisdiction taken from the table);
  `POST /v1/evaluators/{id}/location-declarations` by a person who is a
  security admin of the operator makes it operator-declared, valid for up
  to 366 days. A changed location loses the evidence; lapsed evidence
  counts as none. K-3: in production the floor for any location rule is
  operator-declared. Attested evidence for evaluators is the broker's:
  the Confidential Space token's `submods.gce.zone` becomes
  `VerifiedWorkload.location` and the key broker checks it per release.
  The control plane does not yet take attestation from an evaluator, so an
  evaluator's own evidence level reaches at most operator-declared there.
- **Enforcement.** `create_plan` records the admissible set (a governed
  job is never planned at a party: it runs on an evaluator).
  `submit_governed` refuses a job nothing admits (ENC2710, or ENC2725 when
  operator separation is all that refused). `schedule_job` places only on
  an admitted evaluator and records its operator, location and evidence in
  the grant; a job nothing admits waits and says why
  (`placement_waiting`). `revalidate_governed` and release tickets check
  at start and at the ticket that the evaluator is still admitted and is
  still the machine the grant recorded. The broker's check 7 judges the
  zone the attestation names against the project's constraints (the
  document the signed ticket carries, whose digest the binding names) and
  the owner's; no document, no zone or an unknown zone refuses (ENC2710).
  A broker cannot see an operator or an evaluator ID: those fields are
  enforced by the control plane that issues the ticket.
- **Client check.** `jobs run --placement FILE --evaluator-pins FILE`
  refuses to send anything unless the evaluator the client pinned (by
  receipt key, with operator, location and evidence) is inside the
  client's own constraints, and unless the control plane's record agrees
  with the pin (ENC2726). The Python and native SDKs do not carry this
  check yet.
- **Minimization.** `Objective::Minimize` orders candidates by the release
  rank of the program's outputs, then by how many principals learn
  plaintext, then by latency. The "bits released" step of the design is
  not distinguished yet (it is equal for every candidate of one
  program), and the output-wider-than-class refusal remains the
  governed submission's ENC2709 check.
- **Not built:** operator-owned SecAgg coordinators (the coordinator check
  exists in the planner, but the control plane names no coordinator), the
  `Purpose.placement` source, and the governance report's "Decryption
  control" row (the report is a later phase).

## Relevant source modules

Planned changes touch:

- `crates/encompute-planner/src/{model,planner,requirements,validate}.rs`,
  a new `crates/encompute-planner/src/locations.rs`
- `crates/encompute-ir` (`AssetPolicy.placement`)
- `crates/encompute-analysis` (`refines` extended to placement)
- `crates/encompute-control/src/ops/jobs.rs` (`create_plan`,
  `schedule_job`, `start_job`), evaluator registration and location
  declarations, a migration for evaluator location and operator
- `crates/encompute-attestation/src/gcp.rs` (GCE zone in
  `VerifiedWorkload.location`)
- `crates/encompute-keybroker` (placement check)
- the CLI and SDK pin sets (operator, location, evidence per pin)

### Review fixes (residency and operators)

- **Deny by default.** An operator-owned evaluator is admissible only if
  its operator is a member of the project or a constraint names the
  operator or the evaluator; the platform's own evaluators are the
  exception. Other tenants' evaluators are not put in a plan or named in a
  refusal.
- **Endpoint evidence.** Location evidence covers the evaluator's URL and
  receipt key; registering again with either changed drops the evidence,
  and the grant records the endpoint, which start compares.
- **Owner-pinned project constraints.** `limits.project_placement_digest`
  in the signed authorization; the broker requires the binding to name it.
- **Not built:** an operator-signed evaluator binding verified by brokers
  and clients (operator separation therefore assumes an honest control
  plane), and placement on export tickets.
