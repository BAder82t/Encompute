//! Executes compiled programs (CKKS or exact) on a backend, runs
//! clear-vs-encrypted differential tests, explains plans, and reads and
//! writes compiled artifacts.

mod aggregation;
mod artifact;
pub mod attested;
pub mod audit;
mod client;
mod diff;
mod explain;
mod model;
pub mod privacy;
mod remote;

pub use artifact::FORMAT as ARTIFACT_FORMAT;
pub use client::ClientSession;
pub use diff::{
    diff_test, sample_inputs, DiffReport, ExactOutput, ExactReport, FailingCase, OutputError,
    TestReport,
};
pub use encompute_attestation as attestation;
pub use encompute_evaluator::{
    BackendKind, Backends, CompiledProgram, EvaluatorSession, ExactProgram, Ids, Semantics,
};
pub use encompute_keybroker as keybroker;
pub use encompute_secagg as secagg;
pub use encompute_verification as verification;
pub use explain::Measurement;
pub use model::{has_openfhe, has_tfhe, BenchDetail, BenchReport, Mode, Model};
pub use remote::{Remote, RemoteRun, RemoteStats};

/// The execution spec for `model` on backend `kind` (what its receipts
/// must state).
pub fn verification_spec(model: &Model, kind: BackendKind) -> verification::ExecutionSpec {
    encompute_evaluator::execution_spec(&model.ids(), model.compiled(), kind)
}

/// The semantic transcript of `model` on backend `kind` (exact programs).
pub fn verification_transcript(
    model: &Model,
    kind: BackendKind,
) -> Option<verification::SemanticTranscript> {
    encompute_evaluator::transcript_for(model.compiled(), &verification_spec(model, kind))
}

/// Offline check of a saved execution (`encompute verify`): the receipt
/// against `model` on its target backend, then the execution proof by
/// re-execution with the client's evaluation keys (`eval.keys` envelope).
/// Needs the research `vfhe-research` build.
pub fn verify_execution_offline(
    model: &Model,
    receipt: &verification::SignedExecutionReceipt,
    trusted: &verification::EvaluatorIdentity,
    request: &[u8],
    response: &[u8],
    proof: &verification::ExecutionProof,
    evaluation_keys: &[u8],
) -> encompute_ir::Result<verification::VerificationState> {
    #[cfg(feature = "vfhe-research")]
    {
        use encompute_ir::{Code, Error};
        use verification::{
            output_commitment, request_commitment, verify_execution, verify_receipt,
            CiphertextBinding, ExecutionStatement, ExpectedExecution,
        };
        let spec = verification_spec(model, model.compiled().target_backend());
        let transcript = verification_transcript(model, model.compiled().target_backend())
            .ok_or_else(|| {
                Error::new(
                    Code::Unverified,
                    "only exact programs have execution proofs",
                )
            })?;
        let key_id = encompute_protocol::Envelope::decode(request)?
            .header
            .key_id
            .ok_or_else(|| Error::new(Code::WrongKey, "request carries no key ID"))?;
        let keys = encompute_protocol::Envelope::decode(evaluation_keys)?.payload;
        if encompute_protocol::sha256_hex(&keys) != key_id {
            return Err(Error::new(
                Code::WrongKey,
                "evaluation keys of another key pair",
            ));
        }
        let (rc, oc) = (request_commitment(request), output_commitment(response));
        let th = transcript.id().hex();
        let verified = verify_receipt(
            receipt,
            &ExpectedExecution {
                spec: &spec,
                key_id: &key_id,
                request_commitment: &rc,
                output_commitment: &oc,
                transcript_hash: Some(&th),
                proof_expected: true,
                trusted_evaluator: trusted,
            },
        )?;
        let statement = ExecutionStatement::new(&verified, &transcript)?;
        let binding = CiphertextBinding::new(request, response, &statement)?;
        let plan = &model.compiled().exact().expect("exact").plan;
        let key = encompute_vfhe::ReexecutionKey::new(plan, &spec.plan_id, &key_id, &keys);
        verify_execution(
            &verified,
            &statement,
            &binding,
            proof,
            &encompute_vfhe::ReexecutionBackend,
            &key,
        )
    }
    #[cfg(not(feature = "vfhe-research"))]
    {
        let _ = (
            model,
            receipt,
            trusted,
            request,
            response,
            proof,
            evaluation_keys,
        );
        Err(encompute_ir::Error::new(
            encompute_ir::Code::Unverified,
            "verifying execution proofs needs the research `vfhe-research` build",
        ))
    }
}
