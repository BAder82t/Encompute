//! Verifiable-FHE proof backends (0.4 V3, ADR-009; research).
//!
//! [`ReexecutionBackend`] (`reexecution-v1`) proves the relation
//! `FheEvaluationV1`, `C_out = Eval_T(C_in, evk)`, for exact programs on
//! OpenFHE BGV by deterministic re-execution: the verifier re-runs the
//! semantic transcript's plan over the committed request ciphertexts with
//! the evaluation key and compares the committed response byte for byte.
//! BGV evaluation is exact modular arithmetic with no randomness, so an
//! honest evaluator's response is reproduced exactly and any other response
//! is rejected. Sound, not succinct: verifying costs one evaluation. It needs
//! no secret key and no plaintext.

use encompute_backend::ExactEvaluator;
use encompute_exact::{bgv, evaluate_exact, semantic_transcript, ExactPlan};
use encompute_ir::{Code, Error, Result};
use encompute_openfhe::BgvEvaluator;
use encompute_protocol::Envelope;
use encompute_verification::{
    CiphertextBinding, ExecutionStatement, StatementShape, VerificationBackend,
    VerificationCapabilities, VerificationKeyId,
};

/// What re-execution verifies with: the plan (bound by the spec's plan ID)
/// and the evaluation key (bound by the receipt's key ID).
pub struct ReexecutionKey {
    plan: ExactPlan,
    /// Evaluation-key payload (inside the envelope the client exported).
    evaluation_keys: Vec<u8>,
    id: VerificationKeyId,
}

impl ReexecutionKey {
    pub fn new(plan: &ExactPlan, plan_id: &str, key_id: &str, evaluation_keys: &[u8]) -> Self {
        Self {
            plan: plan.clone(),
            evaluation_keys: evaluation_keys.to_vec(),
            id: bgv::verification_key_id(plan_id, key_id),
        }
    }

    pub fn id(&self) -> VerificationKeyId {
        self.id
    }
}

fn unverified(msg: impl Into<String>) -> Error {
    Error::new(Code::Unverified, msg)
}

pub struct ReexecutionBackend;

impl VerificationBackend for ReexecutionBackend {
    type ProvingKey = ();
    type VerificationKey = ReexecutionKey;
    /// None: the ciphertexts are public.
    type Witness = ();
    /// None: the relation is checked by recomputation.
    type Evidence = ();

    fn capabilities(&self) -> VerificationCapabilities {
        bgv::capabilities()
    }

    fn verification_key_id(&self, key: &ReexecutionKey) -> VerificationKeyId {
        key.id
    }

    /// Re-execution proofs carry no bytes.
    fn decode_evidence(&self, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            Ok(())
        } else {
            Err(unverified("re-execution proofs carry no proof bytes"))
        }
    }

    /// Re-execution needs no setup beyond coverage: every operation and type
    /// of the statement must be in the BGV subset.
    fn setup(&self, shape: &StatementShape) -> Result<((), ReexecutionKey)> {
        let caps = self.capabilities();
        if !shape.ops.is_subset(&caps.supported_ops)
            || !shape.types.is_subset(&caps.supported_types)
        {
            return Err(unverified(
                "the statement uses operations or types re-execution does not cover",
            ));
        }
        Err(unverified(
            "re-execution keys come from the plan and the evaluation key: use ReexecutionKey::new",
        ))
    }

    fn prove(&self, _: &(), _: &ExecutionStatement, _: &()) -> Result<()> {
        Ok(())
    }

    fn verify(
        &self,
        key: &ReexecutionKey,
        statement: &ExecutionStatement,
        binding: &CiphertextBinding<'_>,
        _: &(),
    ) -> Result<()> {
        // The plan re-executed is the one the statement's transcript names.
        let t = semantic_transcript(&key.plan, &statement.spec_id);
        if t.id().hex() != statement.transcript_hash {
            return Err(unverified(
                "the plan does not match the statement's transcript",
            ));
        }
        let caps = self.capabilities();
        if let Some(e) = caps.first_unsupported(&t) {
            return Err(unverified(format!(
                "re-execution does not cover {} on {}",
                e.op, e.ty
            )));
        }
        let request = Envelope::decode(binding.request_envelope)?;
        let response = Envelope::decode(binding.response_envelope)?;
        let inputs = request.items();
        let want: Vec<&str> = key.plan.inputs.iter().map(|i| i.name.as_str()).collect();
        if inputs.iter().map(|(n, _)| *n).collect::<Vec<_>>() != want {
            return Err(unverified("request does not carry the plan's inputs"));
        }
        let mut ev = BgvEvaluator::new(bgv::mult_depth(&key.plan))?;
        ev.load_keys(&key.evaluation_keys)?;
        let cts = key
            .plan
            .inputs
            .iter()
            .zip(&inputs)
            .map(|(i, (_, b))| ev.load(i.elem, b))
            .collect::<Result<Vec<_>>>()?;
        let outs = evaluate_exact(&ev, &key.plan, cts)?;
        let got = response.items();
        if got.len() != outs.len() {
            return Err(unverified("response has the wrong number of outputs"));
        }
        for ((o, ct), (name, bytes)) in key.plan.outputs.iter().zip(&outs).zip(&got) {
            if o.name != *name || ev.store(ct)? != *bytes {
                return Err(unverified(format!(
                    "output {:?} is not the evaluation of the transcript over the request",
                    o.name
                )));
            }
        }
        Ok(())
    }
}
