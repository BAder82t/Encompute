//! The BGV exact subset (0.4 V3, ADR-009): what the OpenFHE BGV backend
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
        failure_probability: "0 (exact modular arithmetic)".into(),
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
