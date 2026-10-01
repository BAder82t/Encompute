//! The BGV exact subset (ADR-009): what the OpenFHE BGV backend
//! executes and the re-execution proof covers. Plaintext modulus 65537;
//! unsigned 8/16-bit integers and Booleans, whose values (proven in range)
//! never wrap modulo 65537.

use std::collections::BTreeSet;

use encompute_ir::Elem;
use encompute_verification::transcript::ProofOp;
use encompute_verification::{
    ExecutionProof, ExecutionSpec, ProofHeader, VerificationCapabilities, VerificationEvidence,
    VerificationKeyId, VerificationRelation,
};

use crate::plan::{ExactInstr, ExactPlan, ExactProfile};

/// Plaintext modulus of the BGV context.
pub const PLAINTEXT_MODULUS: i64 = 65537;
/// Re-execution protocol name (ADR-009).
pub const PROTOCOL: &str = "reexecution-v1";

/// Operations the BGV backend executes (and re-execution proves).
pub fn capabilities() -> VerificationCapabilities {
    use ProofOp::*;
    VerificationCapabilities {
        protocol: PROTOCOL.into(),
        transcript_version: encompute_verification::TRANSCRIPT_VERSION,
        fhe_backend: "openfhe".into(),
        parameter_profiles: vec!["openfhe-bgv-v1".into()],
        supported_ops: [
            Input, Add, Sub, Mul, AddConst, SubConst, MulConst, ConstSub, And, Or, Xor, Not,
        ]
        .into_iter()
        .collect(),
        supported_types: [Elem::U8, Elem::U16, Elem::Bool]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        // Bitwise logic is arithmetic on 0/1 (and = ab, not = 1 - a): the
        // BGV evaluator runs it on Booleans only, so programs using it on
        // integers are not selected for BGV.
        op_types: [And, Or, Xor, Not]
            .into_iter()
            .map(|op| (op, BTreeSet::from([Elem::Bool])))
            .collect(),
    }
}

/// Multiplicative depth: ciphertext–ciphertext products (including `and`,
/// `or`, `xor` on Booleans) and products by constants each take a level.
pub fn mult_depth(plan: &ExactPlan) -> u32 {
    let mut depth = vec![0u32; plan.instrs.len()];
    for (i, instr) in plan.instrs.iter().enumerate() {
        let d = instr
            .operands()
            .iter()
            .map(|r| depth[*r as usize])
            .max()
            .unwrap_or(0);
        use ExactInstr::*;
        let own = match instr {
            Mul(..) | MulScalar(..) | Logic(..) => 1,
            _ => 0,
        };
        depth[i] = d + own;
    }
    depth.into_iter().max().unwrap_or(0).max(1)
}

/// The largest noise multiplier (see [`noise_multiplier`]) a plan may
/// reach on the BGV profile. OpenFHE sizes the moduli for the plan's
/// multiplicative depth only; additions are free there but grow the noise.
/// Calibrated on OpenFHE 1.5.1 (plaintext modulus 65537, 128-bit, FIXEDAUTO,
/// HYBRID, depths 1 to 3), worst case (one ciphertext added to itself):
/// multipliers up to 2^17 after a product still decrypt correctly, 2^18 do
/// not (without products, and at depth 2 or more, the budget is larger).
/// 2^13 keeps a 16x margin; a plan above it does not run on BGV.
pub const MAX_NOISE_MULTIPLIER: u128 = 1 << 13;

/// Worst-case growth of the noise of each register, relative to a fresh
/// (or freshly multiplied) ciphertext, maximized over the plan: sums and
/// differences add their operands' multipliers, products multiply them
/// (bitwise logic on Booleans is arithmetic: `or` = a + b − ab), and
/// operations with public constants keep them. Saturates.
pub fn noise_multiplier(plan: &ExactPlan) -> u128 {
    let mut m = vec![1u128; plan.instrs.len()];
    for (i, instr) in plan.instrs.iter().enumerate() {
        let g = |r: &crate::plan::Reg| m[*r as usize];
        use encompute_ir::LogicOp;
        use ExactInstr::*;
        m[i] = match instr {
            Input { .. } | Trivial { .. } => 1,
            Add(a, b) | Sub(a, b) | Min(a, b) | Max(a, b) => g(a).saturating_add(g(b)),
            Mul(a, b) | Logic(LogicOp::And, a, b) => g(a).saturating_mul(g(b)),
            Logic(LogicOp::Or, a, b) => g(a)
                .saturating_add(g(b))
                .saturating_add(g(a).saturating_mul(g(b))),
            Logic(LogicOp::Xor, a, b) => g(a)
                .saturating_add(g(b))
                .saturating_add(g(a).saturating_mul(g(b)).saturating_mul(2)),
            Select(c, a, b) => g(c).saturating_mul(g(a).saturating_add(g(b))),
            other => other.operands().iter().map(g).max().unwrap_or(1),
        };
    }
    m.into_iter().max().unwrap_or(1)
}

/// Why `plan` may not run on the BGV profile because of noise, if so.
pub fn noise_unsupported(plan: &ExactPlan) -> Option<String> {
    let m = noise_multiplier(plan);
    (m > MAX_NOISE_MULTIPLIER).then(|| {
        format!(
            "noise from additions: a value's noise may grow {}x (the BGV budget is {}x); \
             fewer or smaller sums, or the BinFHE backend, keep results exact",
            if m == u128::MAX {
                "over 10^38".to_owned()
            } else {
                m.to_string()
            },
            MAX_NOISE_MULTIPLIER
        )
    })
}

/// The parameter profile of a BGV exact plan.
pub fn profile(plan: &ExactPlan) -> ExactProfile {
    ExactProfile {
        backend: "openfhe".into(),
        backend_version: "1.5.1".into(),
        profile: format!(
            "BGVRNS_T65537_DEPTH{}_HEStd128_FIXEDAUTO_HYBRID",
            mult_depth(plan)
        ),
        security: "128-bit classical".into(),
        // Exact modular arithmetic once decrypted correctly; decryption
        // is correct while the noise stays in its budget, which
        // `noise_unsupported` enforces with a margin (not a proven bound).
        failure_probability: "negligible (noise budget enforced; not zero)".into(),
        parameter_selector_version: "openfhe-bgv-v1".into(),
    }
}

/// Protocol version of [`PROTOCOL`].
pub const PROTOCOL_VERSION: u32 = 1;

/// Verification key of re-execution: the plan and the evaluation key. Its
/// ID binds both, so an evaluator cannot pick another setup.
pub fn verification_key_id(plan_id: &str, key_id: &str) -> VerificationKeyId {
    let mut bytes = b"reexecution-v1".to_vec();
    for part in [plan_id, key_id] {
        bytes.push(0);
        bytes.extend_from_slice(part.as_bytes());
    }
    VerificationKeyId::of(&bytes)
}

/// The execution proof a BGV evaluator attaches: the public statement
/// fields and no proof bytes. Re-execution needs none: the verifier re-runs
/// the transcript over the committed request with the evaluation key and
/// compares the response byte for byte (ADR-009).
pub fn reexecution_proof(
    spec: &ExecutionSpec,
    transcript_hash: &str,
    key_id: &str,
    request: &[u8],
    response: &[u8],
) -> ExecutionProof {
    ExecutionProof {
        header: ProofHeader {
            version: encompute_verification::PROOF_VERSION,
            relation: VerificationRelation::FheEvaluationV1,
            spec_id: spec.id().hex(),
            transcript_hash: transcript_hash.to_owned(),
            request_commitment: encompute_verification::request_commitment(request),
            output_commitment: encompute_verification::output_commitment(response),
            verification_key_id: verification_key_id(&spec.plan_id, key_id).hex(),
            protocol: PROTOCOL.into(),
            protocol_version: PROTOCOL_VERSION,
            proof_bytes: 0,
        },
        proof: vec![],
    }
}

/// The receipt evidence naming `proof`.
pub fn evidence(proof: &ExecutionProof) -> encompute_ir::Result<VerificationEvidence> {
    Ok(VerificationEvidence::Vfhe {
        relation: proof.header.relation,
        protocol: proof.header.protocol.clone(),
        protocol_version: proof.header.protocol_version,
        verification_key_id: proof.header.verification_key_id.clone(),
        proof_digest: proof.digest()?,
    })
}
