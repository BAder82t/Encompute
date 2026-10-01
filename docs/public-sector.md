# Confidential cross-agency computation

> **Status: in development after 0.3.0; not released.** Nothing on this
> page is part of Encompute 0.3. It describes what is being designed and
> built, so that institutions, reviewers and design partners can comment on
> it. Features, names and formats may change before they ship. Where this
> page says Encompute "refuses" or "checks" something, it describes the
> design or unreleased code, not released behaviour. What is built so far
> is listed under "Development status" below.

Encompute lets public institutions compute across organizational
boundaries without centralizing sensitive data. Each institution retains
ownership and key control, authorizes specific purposes, and receives
verifiable evidence of what was computed and released.

In short: compute across institutions without pooling sensitive records.

## Who this is for

Public bodies that need an answer depending on records several of them
hold, and that cannot, or should not, copy those records to one place. For
example:

- a benefits agency that needs to know whether an applicant meets a rule
  that depends on tax and residency records held elsewhere;
- regional health authorities that want joint weekly statistics without
  sending each other case-level data;
- several institutions that want to improve a shared model without any of
  them seeing the others' training data.

## Four collaboration patterns

| Pattern | What is computed | Mechanism | What is released |
|---|---|---|---|
| **1. Exact eligibility** | A rule over one person's records held by several institutions | Exact encrypted computation (OpenFHE Boolean circuits), with a declared record-linkage policy | A single yes/no, or a small bounded category, to the one authorized institution |
| **2. Encrypted statistics** | Totals, rates or distributions over several institutions' data | Encrypted arithmetic, with differential privacy applied before release | Noisy aggregates, within a privacy budget |
| **3. Multi-institution secure aggregation** | Sums of per-institution local results | Secure aggregation with a minimum number of contributors, plus differential privacy | Only the combined, noised result; no single contribution |
| **4. Confidential model collaboration** | Fine-tuning a shared model | Confidential fine-tuning, with each owner's keys at the owner's own key broker | A model adapter or update, as a derived artifact with its own release rules |

Patterns 2 and 3 need no new cryptography and are expected to be available
first. Pattern 1 needs record linkage and a multi-party key model that will
go through external cryptographic review before they ship. Pattern 4 builds
on the existing confidential fine-tuning.

## What each institution retains

- **Its data.** Records stay with the institution that holds them. Other
  parties receive ciphertexts, masked contributions or nothing, depending
  on the pattern. The released result is the only thing decrypted, and only
  for its authorized recipient.
- **Its keys.** Each institution's keys stay in its own key management
  system, released only by its own key broker. There is no shared project
  key and no central master key. The platform operator holds no key that
  protects data.
- **Its authorization.** Each institution signs, with a governance key it
  holds, exactly what it allows: which program may run over which version
  of its dataset, for which declared purpose, until when, with which
  approvals, and which result may be released to whom. Using its own data
  in a project needs such an authorization too.
- **Its approvals.** Authorizations need two distinct people in the
  institution. Automated service accounts never count as approvers.
- **Its revocation.** An institution can revoke an authorization or a
  dataset at any time, including locally at its own key broker if the
  control plane is unavailable. Revocation stops future use; it cannot
  recall results already released, and the evidence says so.
- **Its evidence.** Each institution can export a governance evidence
  bundle for a computation and verify it offline, using only public keys it
  has obtained itself. The bundle contains no source records.

## How a governed project works

1. Institutions create a *governed* project together. Each member's
   administrator accepts, and the members co-sign a project charter naming
   the members and any appointed auditor organization. A project's
   governance mode cannot be changed later.
2. The members agree on a **purpose**: its name, what may be computed, what
   may be released and to whom, where computation may run, and its validity
   period. Every institution whose data is used signs its acceptance.
3. Each data-owning institution signs an **authorization** for one dataset
   version, one program (or a fixed set of programs) and that purpose, with
   an end date. Two of its people approve it.
4. A job is planned. Planning fails if any authorization is missing,
   expired, for another purpose or program, or if no evaluator meets the
   declared placement rules.
5. Each institution's own software checks the job against its own
   authorization before encrypting anything. Its key broker releases a key
   only when it holds that institution's signed authorization **and** a
   short-lived, single-use ticket for the job.
6. The result is released only in the form and to the recipients every
   source authorized. It becomes a new asset with its own lineage and
   release rules.
7. Anyone holding the institutions' public keys can check the evidence:
   what was computed, over which versions, under which authorizations and
   approvals, where, and what was released.

Authorization windows are strict. Evidence from a computation that ran
inside its window stays valid after the window ends; it is judged at the
time the computation ran, not the time someone checks it.

## Roles

| Role | Holds | Never receives |
|---|---|---|
| Data-owning institution | Its own records and keys, its governance key | Other institutions' records or keys |
| Result recipient | The released result | The inputs |
| Evaluator operator (a separate organization) | Ciphertexts and the program | Any decryption key, any records |
| Platform (control-plane) operator | Metadata, schedules, tickets | Any key that protects data |
| Auditor organization | Read access to authorizations, evidence, lineage and privacy spending | The ability to run, approve, receive or change anything |

The auditor role is read-only and cannot be combined with any other role.

## Technical enforcement and legal authority

Encompute enforces a declared technical policy. Each institution in a
project signs what may happen to its data: which program may run over which
dataset version, for which declared purpose, until when, with which
approvals, and which result may be released to whom. Encompute refuses any
computation, key release or export those signed declarations do not allow,
and it produces evidence anyone holding the institutions' public keys can
check.

Encompute does not decide whether any of this is lawful. It does not
determine:

- the lawful basis or statutory authority for a computation;
- whether a purpose is legitimate, necessary or proportionate;
- retention periods required by law or records schedules (it enforces the
  periods an institution declares);
- the rights of the people concerned, including access, correction,
  objection, notification and appeal;
- whether a decision requires human oversight, or whether a result may be
  used in a decision about a person;
- jurisdiction and cross-border rules (it enforces the regions and
  operators an institution declares).

A purpose name or legal reference recorded in Encompute is a label an
institution declared and signed. Encompute binds it to the computation and
shows it in reports; it does not check it against any law.

"CROSS-AGENCY REQUIREMENTS SATISFIED" means the computation matched what
the institutions technically authorized. It is not legal advice, a
compliance certification, or evidence that an authorization was lawful.
Evidence cannot show what an institution did outside Encompute, and a
released result cannot be recalled: revocation stops future use and lists
what was derived. "Ownership" in reports means control within Encompute
(keys, authorization, revocation), not legal title.

Each institution remains responsible for its own legal assessment and for
its use of data and results.

Every governance report ends with a one-line form of this boundary.

## Known limits of the design

- **Record linkage is pseudonymous, not anonymous.** Whoever holds a
  linkage key, or a linkage authority, can recompute the pseudonym of a
  person it can identify. An institution colluding with the evaluator
  operator can learn which of its subjects appear in another institution's
  records.
- **Recipient-held decryption relies on non-collusion.** If the recipient
  institution holds the decryption key, confidentiality of the inputs
  against it rests on the evaluator operator not colluding with it. Reports
  state this assumption wherever it applies.
- **Repeated queries can reveal values.** Limits on queries per person and
  per job, and the audit trail, bound this; they do not prevent it.
- **Declared locations are declarations.** A location declared by an
  operator is attributable, not proven. Only attested locations are
  checked cryptographically, and reports label which is which.
- **Released results cannot be recalled.**

## Non-goals

Encompute will not be:

- a national citizen-data platform;
- a data lake;
- an identity registry or national identity system;
- a case-management system;
- a system that automates policy decisions;
- a legal authorization engine;
- a records-management system;
- a data-quality platform;
- a full data catalog;
- a user interface for every workflow.

## Development status

Built on the development branch, not released:

- **Phase 1, governed projects and owner-signed authorizations.**
  Governance keys, purposes, owner authorizations with four-eyes
  approval, immutable dataset versions, strict validity windows and
  non-retroactive revocation.
- **Phase 2, sovereign keys and two-part key release.** Each
  institution's key broker releases a key only when it holds that
  institution's signed authorization and a short-lived, single-use
  release ticket for the job; a ticket alone releases nothing, so a
  compromised control plane can only deny. Governed projects always keep
  each source's key at a broker its own institution registered, never at
  a platform broker, and keys are bound to brokers one by one. The
  broker's own state cannot be rolled back to undo a revocation or reset
  a limit: it is guarded by a generation mark in the institution's key
  management system. The owner can revoke at its broker even when the
  control plane is down.

- **Phase 3, purpose, program and source enforcement (complete).**
  Everything below.

Jobs in governed projects run under their owners' authorizations: each
source's owner must have authorized the job's purpose, program and
releases, and validity is checked again at scheduling and start, strictly,
on the control plane's clock. A job that started inside its window may
finish after it.

An authorization may ask for per-job four eyes: a job under it waits
until enough distinct people of the owner (its approval rule, at least
two, never the job's submitter) approve that job, its spec and its
authorization set.

An institution can be appointed the project's auditor: it reads the
project, its purposes, the owners' signed authorizations, the jobs, their
trust reports and the project's audit events, and changes nothing. No
auditor, in any institution taking part, can act in the project, and an
auditor holds no other role there. Every institution that does not own a
record sees the same shared view of it: never where another institution's
data is stored or which key protects it, and approvers only as
pseudonyms.

Each output is released in a class the owners allowed (boolean,
aggregate, differentially private aggregate, derived artifact) and in a
form the compiler can show it takes. A released result can be recorded as
a derived dataset held by its recipient, which signs what it may be used
for; using or exporting it needs the consent of every institution whose
data it comes from, enforced again by the recipient's own key broker, and
a revocation upstream blocks it without claiming to recall anything. An
institution that rotates its governance key does not strand what was
derived from its data: the recipient has the binding re-issued under the
new key.

Each dataset version carries its owner's retention: a deletion date,
fixed at registration and only ever brought forward, until when the data
is kept, and until when the evidence about it is kept (only ever
extended). Once the deletion date passes nothing uses the version or
anything derived from it again, its key broker is told, and the evidence
stays verifiable. Deleting the data itself is the institution's own
storage's job.

**Phase 4, a governance log and verifiable audit (complete).**
Every security-negative transition and every privacy ledger checkpoint
is an event of one tamper-evident log, and the state anchor holds only
where it stands, so it stays a constant size however many assets,
revocations and spends there are. A governed project's own events are
readable by its members and auditors with proofs, members countersign
its checkpoints, and each owner signs the revocations it made, so an
evidence bundle cannot silently omit one.

**Phase 8, the cross-agency report, `explain --governance` and the
evidence bundle (complete).** `encompute governance export` fetches a governed
job's bundle (one `<project>-<job>.encgov.json`: the trust graph, the
grant, the owners' authorizations, the signed release records and the
project's whole log with proofs, witnesses and revocation heads),
checks it before writing, and `encompute governance verify`, `report`
and `explain --governance` verify it offline against keys you pinned
yourself and say what it means in plain words. The bundle holds no
source records, is the same bytes for every member (another
organization's authorization appears as a card until its owner
discloses it), and any edit, omission or reordering fails. The report
shows "raw data centralized", "ownership retained" and "unauthorized
releases" only with signed backing, judges authorizations at the time
the job ran, and cannot yet read SATISFIED: who can decrypt a result is
not recorded in signed evidence yet, and residency and record linkage
are not evidenced until they are built.

Not yet built: placement and operator rules (a broker refuses any
execution that declares placement until placement can be attested),
record linkage. The limits of
what exists are in [known limitations](../KNOWN_LIMITATIONS.md).

## Design records

- [Governed projects and owner-signed authorizations](adr/0023-governed-projects.md)
- [Record linkage](adr/0024-record-linkage.md) (proposed; open decisions and
  the external review scope)
- [Sovereign keys and two-part key release](adr/0025-sovereign-keys.md)
- [Placement, operators and data minimization](adr/0026-placement-and-operators.md)
- [Cross-agency trust report and governance evidence bundle](adr/0027-governance-report-and-bundle.md)

Related: [threat model](threat-model.md), [known
limitations](../KNOWN_LIMITATIONS.md), [support matrix](support-matrix.md).
