# ADR-015 — The planner: declare trust requirements, not mechanisms

Status: **Accepted** (2026-09-26)

## Context

Encompute has a set of mechanisms:
- CKKS and exact FHE, and re-execution proofs;
- attestation and attestation-gated key release;
- secure aggregation;
- differential privacy;
- signed receipts;
- the trust graph.

Until now a developer had to pick among them and compose them correctly. That
is the hard part of confidential computing, and a wrong choice is a silent
security failure.

## Decision

1. **Requirements, derived from declarations** (`encompute-planner`).
   - The program's confidentiality policy yields `TrustRequirement`s, which
     state what must be true, never how:
     - `HideFrom { asset, principal }`, where the principal is every party
       outside an asset's audience, and the compute host for everything a
       step reads;
     - `AggregateOnly`, `Purpose`, `PrivacyBudget` and
       `MinimumParticipants`;
     - `RequireCorrectness`, from `verification required`;
     - `RequireAttestation`, `ExecutionRegion` and `SignedEvidence`.
   - A project's training declaration adds one training step per dataset.
   - Profiles (`standard`, `strong`, `maximum`) only add requirements, and
     the plan lists them:
     - **strong** attests every aggregation coordinator;
     - **maximum** requires every computation to be verifiably correct and
       accepts production attestation only.
2. **Mechanisms that already exist, with capabilities and prerequisites.**

   | Mechanism | Hides from the host | Other properties | Prerequisites |
   |---|---|---|---|
   | FHE (CKKS, BinFHE, BGV; TFHE in research builds) | Yes | — | The program compiles to an encrypted plan, and the backend is built |
   | Verified execution | — | Correctness | BGV, and full proof coverage |
   | Confidential compute | Yes (memory) | — | Attestation, attested key release, a usable TEE |
   | Secure aggregation | Individual contributions | — | An aggregation boundary; the threshold from the collusion bound |
   | Differential privacy | — | Bounds the release; charged to budgets | A declared mechanism |
   | Local execution | Yes | — | The party may read everything the step reads |

   A TEE is usable only if all of the following hold:
   - its attestation provider is one Encompute verifies;
   - it is not debug-only;
   - its evidence is production evidence, unless development was allowed and
     the profile is not maximum;
   - it fits the local-only and region constraints.
3. **Selection.**
   - For each step (evaluation, each training step, each aggregation) the
     planner enumerates every combination of placement and mechanisms.
   - It keeps those that discharge every requirement touching the step.
   - Among those, it picks the cheapest by estimated cost (latency or cost
     objective), with a deterministic tie-break.
   - Security requirements are hard constraints; preferences only rank valid
     plans.
   - If any step has no valid candidate, the result is **PLANNING FAILED**
     (ENC2401), with every candidate's reason. No requirement is ever
     weakened to find a plan.
4. **Auditable plans.**
   - Each requirement records:
     - the step and the mechanisms that satisfy it;
     - the reason, e.g. "the only release boundary for gradient-a is the
       aggregation of update, with threshold 3";
     - the evidence to expect.
   - Costs are labelled estimates.
   - `explain --deep` shows every candidate, why it was rejected, and the
     security assumptions.
5. **An independent validator.**
   - `verify_plan` shares none of the planner's selection or capability
     logic. It re-derives the requirements from the program and the plan's
     own context, so none may be dropped or added.
   - It checks every mechanism against the context: available, supported,
     prerequisites present, and with the placement that provides it.
   - It checks, with its own rules, that every requirement is discharged.
   - A plan the validator refuses is never returned or accepted (ENC2402).
6. **Plan identity and binding.**
   - The PlanId is `SHA256("encompute.confidential-execution-plan.v1" ||
     0x00 || canonical plan)`, written `encplan1:`.
   - The plan carries its whole planning context, so anyone can recheck it.
   - The same program, context and preferences always give the same plan
     and ID.
   - The ID is bound into:
     - the aggregation plan (`execution_plan_id`), and through it the spec
       ID, every aggregation receipt, and the coordinator's attestation;
     - the trust graph, as a Plan node.
   - The trust report's **Plan** row compares observed execution with the
     approved plan:
     - rounds must run under its ID, with its threshold, noise and
       attestation;
     - executions of its program must use its scheme and backend, and carry
       its proof.
   - A mismatch fails (ENC2403). A step with no evidence yet is unchecked.
     Only a fully observed plan prints **PLAN SATISFIED BY OBSERVED
     EXECUTION**.
7. **Interfaces.**
   - `encompute plan` (with `-o`, `--profile`, `--infrastructure`,
     `--training`, `--prefer`, `--local-only`, `--region` and `--deep`).
   - `encompute check`: program, policy, privacy, and whether a plan exists.
   - `explain --deep`.
   - `aggregate … --plan` and `trust init --plan`.
   - Python: `Project(...)`, `.data`, `.model`, and
     `.train(model=, data=, privacy=, verification=)`. Named policies
     (`private-training`, `private-model`, `shared-model`) expand into
     visible declarations.

## Consequences and limits

- The developer declares policies, and Encompute chooses the mechanisms or
  explains why none will do.
- Training correctness has no execution proof. For training,
  `verification="required"` means an attested workload, which gives
  integrity under the TEE's hardware trust. The plan states this; it does
  not call it a proof.
- Execution receipts are matched to the plan by program, scheme, backend
  and proof. Adding the PlanId to the `ExecutionSpec` itself would change
  the client–evaluator protocol, and is left for later.
- Cost estimates are coarse per-mechanism constants, not measurements.
  Feeding `encompute bench` results back into the estimates is future work.
- Assurance: INV-110 to INV-115 ([assurance.md](../assurance.md)). They
  include 50 000 generated planning scenarios nightly (with regression
  seeds), every mechanism removal, every field mutation of a plan, and the
  milestone's adversarial list.
