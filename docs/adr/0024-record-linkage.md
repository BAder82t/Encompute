# ADR-024 — Record linkage

Status: **Proposed** (2026-09-29). This record presents options and their
leakage; it decides none of the open questions below. The construction
needs an external cryptographic review before any of it ships. Nothing here
is part of 0.3.

## Context

Record-level collaboration means evaluating a rule over one person's
records held by several agencies: is this applicant an adult, resident for
five years, under an income threshold and not already enrolled? Each agency
holds its own register, keyed by its own identifiers, in its own order.
Encompute 0.3 has no way to say "these rows belong to the same person":

- A program with several owners' per-subject inputs would have to assume
  positional alignment, and nothing checks it. Two registers sorted
  differently would silently produce wrong answers.
- A wrong or mismatched identifier space makes every subject "not found".
  In an eligibility rule that is a silent denial of a benefit.
- Aggregate collaboration (statistics, secure aggregation) needs no
  linkage at all, and should say so explicitly.

Encompute is not an identity system and will not become one. What is
needed is a linkage *abstraction*: a declared, signed statement of how
records are matched, bound into the computation's identity, with checks
that catch a mismatch before anything is evaluated.

## Proposed structure

These parts are common to every option and are proposed as the frame for
the decision:

```
LinkagePolicy { version,
  scheme: hmac-sha256-v1 | authority-assigned-v1 | none
          | oprf-ristretto255-v1 (reserved, refused),
  namespace, purpose, epoch, normalization,
  key_commitment?, authority?, canary,
  missing: reject | false, per_job_pseudonyms: bool }
LinkageId = SHA256("encompute.linkage-policy.v1" || 0x00 || canonical JSON)
```

- Declared in the IR (`Confidentiality.linkage`), so the PolicyId binds
  it, and referenced by the Purpose and the GovernanceBinding (ADR-023),
  so every field reaches the PlanId, ExecutionSpecId and GovernanceId.
- `purpose` equals the IR purpose: a pseudonym namespace is tied to one
  purpose.
- Registered in the control plane and **co-signed by every source owner**.
  It is trust-graph evidence.
- `normalization` names a versioned, published function (for example
  `nid-digits-checksum-v1`) with test vectors, so two agencies compute the
  same input from the same identifier.
- Aggregate programs declare `scheme: none`. "No record linkage performed"
  then becomes a stated, checkable fact in the report, not an absence.
- The planner refuses a program with several owners' per-subject inputs
  and no linkage policy.

## Options

### L-A: HMAC pseudonyms, key in each agency's KMS

```
pid = HMAC-SHA256(K_ns, "encompute.pid.v1" || namespace || epoch || normalize(nid))
```

- `K_ns` is fresh per namespace and non-exportable, held in each agency's
  KMS (OpenBao/Vault Transit `hmac`, which is audited and rate-limited).
- Distribution: wrapped with HPKE to the other agencies' KMS import keys.
  It is not yet verified that OpenBao supports importing the same key into
  several independent instances.
- Rotation creates a new epoch. Every pseudonym changes, and every
  authorization naming the linkage policy must be reissued.
- No new cryptography; the construction is standard.

### L-B: authority-assigned pseudonyms

- A linkage authority (for example an existing national linkage unit)
  assigns pseudonyms and signs batch statements
  `{namespace, epoch, agency, batch_root, count}`.
- Agencies hold no linkage key. The authority is fully trusted for
  consistent, non-colliding pseudonyms and for not disclosing the mapping.
- No new cryptography. It matches how many public-sector linkage
  arrangements already work.

### L-C: oblivious PRF (deferred)

- An OPRF (RFC 9497, ristretto255) would let agencies derive pseudonyms
  without any of them holding the full key.
- The scheme name is reserved and **refused** by the implementation. The
  design goes to external review; it does not ship in the first version.

### L-D: private set intersection

Out of scope for this milestone.

## Leakage analysis

What each party can learn, beyond the released result, under each option:

| Party | L-A (HMAC) | L-B (authority) |
|---|---|---|
| Any `K_ns` holder | Can recompute the pseudonym of any person whose identifier it knows or can enumerate. National IDs are low-entropy, so pseudonyms are invertible offline | Holds no key |
| Linkage authority | — | The full mapping, for every agency |
| Evaluator | Pseudonym-set sizes and values, the intersection pattern, join and query sizes. Not identities, unless it colludes with a key holder | Same |
| An agency colluding with the evaluator | Membership: which of its subjects appear in another agency's set (for example, the tax agency learns who applied for a benefit) | Same, with the authority's help or its batch statements |
| Across jobs, with stable pseudonyms | The same person is linkable across jobs within an epoch, unless `per_job_pseudonyms` is set | Same |

Consequences that hold for every option:

- **A keyed pseudonym is not anonymisation.** It protects against parties
  without the key, not against key holders.
- **L-A is not sovereign.** N agencies hold copies of one secret. Any one
  of them, or its KMS, can recompute everyone's pseudonyms. This is a real
  departure from the per-agency key custody of ADR-025.
- **Match rate and counts are releases.** How many subjects matched, and
  who is missing, leak information. They are withheld unless the release
  class allows them.
- **Recipient probing.** A recipient that controls some inputs could
  binary-search another agency's value by repeated queries, or, under L-A,
  query any person it can name. The proposed mitigations bound this rather
  than prevent it: fixed or range-limited recipient inputs,
  `limits.max_evaluations_per_subject` per purpose and epoch (anchored like
  a privacy budget), `max_subjects_per_job`, and the query count in shared
  evidence. Beyond that, the controls are legal and procedural, and the
  documentation says so.

## Mismatch checks

A wrong namespace or epoch must fail loudly, before evaluation:

1. **Metadata check.** Every contribution and ciphertext envelope carries
   the `LinkageId`; the evaluator refuses a mismatch before loading
   anything.
2. **Canary.** Each contribution includes the pseudonym of a fixed, public
   canary identifier. The evaluator compares it against the policy's
   `canary` and across contributions. A contribution computed under another
   key, namespace, epoch or normalization is refused.
3. **Optional match-rate floor.** A job may require a minimum match rate.
   The observed rate is itself a release, so this is off unless the release
   class allows it.

## Open owner decisions

None of these are decided by this record:

- **L-1 Scheme for the first version, and key distribution.** L-A, L-B, or
  both? Who generates `K_ns`, and how is it distributed, given that a
  shared `K_ns` is not sovereign? The plan's recommendation is to ship
  both, lead with L-B where a linkage authority exists, and send L-C to
  review.
- **L-3 Query mode.** Snapshot (sources upload encrypted per-subject
  records once per version; they never learn who applied; cost grows with
  the population) or on-demand (sources learn the queried set; cost grows
  with the query). Recommendation: snapshot.
- **L-4 Pseudonym stability and scope lists.** Stable per epoch, or per job
  at the cost of re-uploading? Should sources upload scope lists to hide
  membership from the evaluator, at the cost of exposing them to other
  sources?
- **L-5 Missing subjects and counts.** Release an unmatched subject as
  `false` (which hides missingness) or three-valued? May match, join or
  subject counts appear in the shared view? Recommendation: `false`;
  counts withheld unless the release class allows them.
- **L-6 Recipient probing defaults.** Default `max_evaluations_per_subject`
  and `max_subjects_per_job`, and whether fixed recipient inputs are
  mandatory.
- **L-7 Source-side predicate pushdown.** Each owner evaluates its own
  predicates in plaintext and contributes one encrypted bit per subject,
  which cuts ciphertext size and gate count by one to two orders of
  magnitude and releases less by construction. Recommendation: yes. BGV
  packing for the combining step must not assume positional alignment.
- **L-8 External review.** Who reviews, and whether sign-off gates a
  design-partner pilot or only general availability.
- **L-9 Aggregate defaults.** `max_sources_per_unit` defaulting to the
  number of participants; secure aggregation rather than CKKS for the first
  aggregate version.
- **L-10 Wording** of the limitations and report entries for linkage
  re-identification.

## External review scope

The review covers, at least:

1. The pseudonym construction: domain separation, namespace and epoch
   encoding, and the claim that pseudonyms from different namespaces or
   epochs are unlinkable to parties without the keys.
2. Normalization: that the published functions are deterministic across
   implementations, and their test vectors.
3. The canary: that it detects a wrong key, namespace, epoch or
   normalization without leaking more than the canary's own pseudonym.
4. Key distribution for L-A: HPKE wrapping to KMS import keys, and
   non-exportability after import.
5. The L-C OPRF design, before its scheme name is ever accepted.
6. The recipient-probing bounds and the leakage table above.

The review also covers the record-level key model and BinFHE public-key
encryption, which are in ADR-025's scope. Invariants that depend on this
record (linkage substitution, positional alignment, contribution origin,
announced keys and probing bounds) carry a note in the catalog until the
review closes.

## Consequences

- Record-level collaboration (exact eligibility and bounded signals) stays
  blocked until these decisions and the review close. Aggregate
  collaboration does not depend on this record.
- Whatever scheme is chosen, the report states it, and states the
  re-identification capability of key holders or the authority in plain
  words.
- The documentation lists "not a national identity system" as a non-goal.

## Alternatives considered

- **Positional alignment.** Rejected: unverifiable, and wrong alignment is
  silent.
- **Raw identifiers under FHE.** Encrypting identifiers and matching under
  FHE is not proposed: equality over encrypted identifiers across several
  keys is new protocol surface, costly per comparison, and still leaks the
  join pattern to the evaluator.
- **Pseudonyms chosen per job by the control plane.** Not proposed: the
  control plane would become a linkage authority without being accountable
  as one.

## Relevant source modules

Planned:

- a new crate `encompute-linkage` (normalization with test vectors, a
  test-only HMAC reference, canary, `LinkageId`, input contributions, an
  OPRF trait)
- `crates/encompute-ir` (`Confidentiality.linkage`)
- `crates/encompute-planner/src/requirements.rs` (a record-linkage
  requirement)
- `crates/encompute-evaluator` (contribution checks before loading)
