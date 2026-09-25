# ADR-008 — Semantic transcripts: the statement a proof must satisfy

Status: **Accepted** (2026-09-25)

## Context

Receipts (ADR-007) bind *which* program, plan, parameters, key, request and
response were involved. A proof of correct execution must also know *which
sequence of operations* connects the request to the result, in a form every
evaluator, platform and future proof system agrees on.

## Decision

1. **A semantic transcript per exact plan.** `SemanticTranscript` (format
   `EncomputeProofTranscriptV1`, `transcript_version` 1) is derived from the
   compiled `ExactPlan` alone: a header binding the `ExecutionSpecId`, plan
   kind and version; input declarations (position, name, type, visibility;
   never values); output declarations (name, register, type); and one entry
   per instruction (index, opcode, operand registers, result register, result
   type, public parameters). Registers are plan-local SSA IDs: `r{n}` is
   the result of instruction `n`.
2. **Semantics, not backend execution.** One `SELECT` stays one `SELECT`
   however many bootstraps TFHE-rs spends on it. Threading, batching, PBS
   fusion and GPU scheduling never enter the transcript. A future
   `BackendWitness` describes how a backend proves the semantics.
3. **Stable opcodes.** Numeric codes below are the canonical encoding; names
   are for display. Changing an opcode's meaning requires a new transcript
   version. All values are checked: every result must fit its type.

| Opcode | Code | Semantics (a, b: operands; c: public constant) |
|---|---|---|
| `INPUT` | 0x0001 | r = input #i (secret; its value never appears) |
| `CONST` | 0x0002 | r = c |
| `ADD` | 0x0010 | r = a + b |
| `SUB` | 0x0011 | r = a − b |
| `MUL` | 0x0012 | r = a × b |
| `NEG` | 0x0013 | r = −a |
| `ADD_CONST` | 0x0014 | r = a + c |
| `SUB_CONST` | 0x0015 | r = a − c |
| `MUL_CONST` | 0x0016 | r = a × c |
| `CONST_SUB` | 0x0017 | r = c − a |
| `DIV_CONST` | 0x0018 | r = a / c, truncated toward zero; c ≠ 0 |
| `REM_CONST` | 0x0019 | r = a − c·(a / c): sign of a; c ≠ 0 |
| `EQ … GE` | 0x0020–0x0025 | r = (a ⋈ b) as bool; ⋈ ∈ {=, ≠, <, ≤, >, ≥} |
| `EQ_CONST … GE_CONST` | 0x0028–0x002d | r = (a ⋈ c) as bool |
| `AND, OR, XOR` | 0x0030–0x0032 | bool: logic; integers: bitwise on the two's-complement value |
| `NOT` | 0x0033 | bool: 1 − a; signed: ¬a (two's complement); unsigned: 2^w − 1 − a |
| `SELECT` | 0x0040 | r = c ≠ 0 ? a : b (operands c, a, b) |
| `SHL, SHR` | 0x0050, 0x0051 | r = a × 2^k; r = ⌊a / 2^k⌋ (arithmetic); k < width |
| `MIN, MAX` | 0x0060, 0x0061 | r = min(a, b), max(a, b) |
| `LOOKUP` | 0x0070 | r = table[a]; 0 ≤ a < len |
| `CAST` | 0x0080 | r = a, in the result type |

4. **Canonical encoding.** Canonical JSON (ADR-007); constants are
   `{"type": "u32", "value": "35"}` with the value as a canonical decimal
   string, never floating point. `TranscriptHash = SHA256(
   "encompute.execution-transcript.v1" || 0x00 || canonical transcript)`,
   shown as `enctrace1:…`. No timestamps, workers, hosts or process IDs.
5. **Binding.** Receipts (version 2) carry `transcript_hash`; clients
   compute it from their own plan and refuse a mismatch (ENC1702). The
   artifact's `verification.json` stores only the transcript version and
   hash; the transcript is regenerated from `plan.json`, so there is one
   source of semantics. `encompute audit` checks the stored hash.
6. **The statement.** `ExecutionStatement` = spec ID `S`, request commitment
   `R`, output commitment `O`, transcript hash `T`, instruction count and
   runtime-public inputs (none today). A proof must show there exist secret
   inputs `X` and encrypted execution state `W` such that `X` corresponds to
   the request committed by `R`, execution follows `T` from `X` under the
   semantics above, and produces outputs whose encryption is committed by
   `O`.
7. **Proof backends.** `VerificationBackend` has associated proving key,
   verification key, witness and evidence types, `setup(StatementShape)`,
   `prove`, `verify`, and `capabilities()` (supported opcodes and types), so
   `explain` can report proof coverage. No FHE library type appears.
   Backends own witness construction; `NoProofBackend` proves nothing.
8. **Observation.** `ExecutionObserver` receives `InstructionEvent`s
   (structure only) and may fail the execution; `TranscriptObserver`
   records the same transcript as the plan-derived one.
9. **Reference replay.** `ReferenceTranscriptEvaluator` replays a
   transcript on plaintext inputs to test transcript semantics against the
   plan. It is not a verifier and not secure.

## What a transcript is not

- Not a proof: a transcript hash proves nothing about an execution; it
  fixes what a proof must show. The CLI says `TRANSCRIPT AVAILABLE` and
  `EXECUTION PROOF NOT PRESENT`.
- Not private: it reveals the plan's structure, operation counts, types,
  public constants (business thresholds) and lookup tables, exactly as
  `plan.json` already does. Programs are public in Encompute; private-program
  verification is future work.
- Not canonical across equivalent programs: `x + 0` and `x` may have
  different transcripts; a transcript describes the compiled plan, not
  mathematical equivalence.
- CKKS plans have no transcript yet; their receipts carry none.

## Evidence

`crates/encompute-exact/tests/transcript.rs`: pinned cross-platform
fixture, determinism, a mutation per semantic change (constant, comparison,
type, logic, select order, output register, operand order), strict parsing,
observer agreement, no runtime values; 25 000 generated programs (12 132
compiled plans, 72 792 cases) replay exactly against the mock and the
interpreter; building and hashing a transcript takes ~70 µs for the
eligibility plan versus ~2 s of TFHE-rs evaluation.
