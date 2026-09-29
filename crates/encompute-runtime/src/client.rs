//! The client role: owns the secret key; encrypts inputs into envelopes and
//! decrypts output envelopes. Talks to an evaluator only through envelopes.
//! One session type serves both semantics (CKKS and exact).

use encompute_backend::{CkksClient, ExactClient, MockClient, MockConfig, PlainExactClient};
use encompute_evaluator::{execution_spec, transcript_for, BackendKind, CompiledProgram, Ids};
use encompute_ir::{check_inputs, Code, Error, Inputs, Outputs, Program, Result};
use encompute_protocol::{open, sha256_hex, Envelope, Expect, Header, Kind};
use encompute_verification::{
    output_commitment, request_commitment, verify_receipt, EvaluatorIdentity, ExecutionProof,
    ExecutionSpec, ExpectedExecution, SemanticTranscript, SignedExecutionReceipt,
    VerificationState, VerifiedReceipt,
};

/// The concrete client, so the secret key can be exported.
enum Client {
    Mock(MockClient),
    #[cfg(feature = "openfhe")]
    OpenFhe(encompute_openfhe_client::OpenFheClient),
    ExactMock(PlainExactClient),
    #[cfg(feature = "research-tfhe-rs")]
    TfheRs(Box<encompute_tfhe_client::TfheRsClient>),
    #[cfg(feature = "openfhe")]
    Bgv(encompute_openfhe_client::BgvClient),
    #[cfg(feature = "openfhe")]
    OpenFheExact(Box<encompute_openfhe_client::OpenFheExactClient>),
}

impl Client {
    fn ckks(&self) -> &dyn CkksClient {
        match self {
            Client::Mock(c) => c,
            #[cfg(feature = "openfhe")]
            Client::OpenFhe(c) => c,
            _ => unreachable!("exact client used for a CKKS program"),
        }
    }

    fn exact(&self) -> &dyn ExactClient {
        match self {
            Client::ExactMock(c) => c,
            #[cfg(feature = "research-tfhe-rs")]
            Client::TfheRs(c) => c.as_ref(),
            #[cfg(feature = "openfhe")]
            Client::Bgv(c) => c,
            #[cfg(feature = "openfhe")]
            Client::OpenFheExact(c) => c.as_ref(),
            _ => unreachable!("CKKS client used for an exact program"),
        }
    }

    fn evaluation_keys(&self) -> Result<Vec<u8>> {
        match self {
            Client::ExactMock(_) => self.exact().evaluation_keys(),
            #[cfg(feature = "research-tfhe-rs")]
            Client::TfheRs(_) => self.exact().evaluation_keys(),
            #[cfg(feature = "openfhe")]
            Client::Bgv(_) => self.exact().evaluation_keys(),
            #[cfg(feature = "openfhe")]
            Client::OpenFheExact(_) => self.exact().evaluation_keys(),
            _ => self.ckks().evaluation_keys(),
        }
    }

    fn secret_key(&self) -> Result<Vec<u8>> {
        match self {
            Client::Mock(c) => Ok(c.secret_key()),
            #[cfg(feature = "openfhe")]
            Client::OpenFhe(c) => c.secret_key(),
            Client::ExactMock(c) => Ok(c.secret_key()),
            #[cfg(feature = "research-tfhe-rs")]
            Client::TfheRs(c) => c.secret_key(),
            #[cfg(feature = "openfhe")]
            Client::Bgv(c) => c.secret_key(),
            #[cfg(feature = "openfhe")]
            Client::OpenFheExact(c) => c.secret_key(),
        }
    }
}

fn not_built(kind: BackendKind) -> Error {
    Error::new(
        Code::Backend,
        format!("this build has no {} backend", kind.name()),
    )
}

pub struct ClientSession {
    client: Client,
    kind: BackendKind,
    ids: Ids,
    key_id: String,
    compiled: CompiledProgram,
    /// Evaluation-keys envelope, to send to the evaluator once (and, for
    /// programs requiring proofs, to verify by re-execution).
    evaluation_keys: Option<Vec<u8>>,
}

impl ClientSession {
    fn header(&self, kind: Kind) -> Header {
        let (backend, backend_version) = self.kind.label();
        Header {
            governance_id: None,
            kind,
            scheme: self.compiled.scheme().into(),
            backend: backend.into(),
            backend_version: backend_version.into(),
            parameter_set_id: self.ids.parameter_set_id.clone(),
            program_id: matches!(kind, Kind::Inputs | Kind::Outputs)
                .then(|| self.ids.program_id.clone()),
            key_id: Some(self.key_id.clone()),
            items: vec![],
        }
    }

    fn expect(&self, kind: Kind) -> Expect<'_> {
        let (backend, backend_version) = self.kind.label();
        Expect {
            governance_id: None,
            kind,
            scheme: self.compiled.scheme(),
            backend,
            backend_version,
            parameter_set_id: &self.ids.parameter_set_id,
            program_id: Some(&self.ids.program_id),
            key_id: Some(&self.key_id),
        }
    }

    /// Fresh keys for `compiled` on backend `kind`. `seed` seeds mock keys.
    pub fn generate(
        ids: Ids,
        compiled: &CompiledProgram,
        kind: BackendKind,
        seed: u64,
    ) -> Result<Self> {
        // Refused before any key: its outputs could not be checked.
        if let CompiledProgram::Exact(e) = compiled {
            e.check_output_ranges()?;
        }
        let client = match (compiled, kind) {
            (CompiledProgram::Approx(c), BackendKind::Mock) => Client::Mock(MockClient::new(
                &c.params,
                &c.plan.rotations,
                MockConfig { seed, noise: true },
            )),
            #[cfg(feature = "openfhe")]
            (CompiledProgram::Approx(c), BackendKind::OpenFhe) => Client::OpenFhe(
                encompute_openfhe_client::OpenFheClient::generate(&c.params, &c.plan.rotations)?,
            ),
            (CompiledProgram::Exact(_), BackendKind::Mock) => {
                Client::ExactMock(PlainExactClient::new(seed))
            }
            #[cfg(feature = "research-tfhe-rs")]
            (CompiledProgram::Exact(_), BackendKind::TfheRs) => {
                Client::TfheRs(Box::new(encompute_tfhe_client::TfheRsClient::generate()?))
            }
            #[cfg(feature = "openfhe")]
            (CompiledProgram::Exact(e), BackendKind::OpenFhe) => {
                Client::Bgv(encompute_openfhe_client::BgvClient::generate(
                    encompute_exact::bgv::mult_depth(&e.plan),
                )?)
            }
            #[cfg(feature = "openfhe")]
            (CompiledProgram::Exact(e), BackendKind::OpenFheExact) => {
                // Before any key: the backend must support every operation.
                encompute_exact::bits::check_capabilities(&e.plan)?;
                Client::OpenFheExact(Box::new(
                    encompute_openfhe_client::OpenFheExactClient::generate()?,
                ))
            }
            (c, k) if !k.runs(c) => {
                return Err(Error::new(
                    Code::Backend,
                    format!("{} cannot run {} programs", k.name(), c.scheme()),
                ))
            }
            (_, k) => return Err(not_built(k)),
        };
        let payload = client.evaluation_keys()?;
        let mut s = Self {
            client,
            kind,
            ids,
            key_id: sha256_hex(&payload),
            compiled: compiled.clone(),
            evaluation_keys: None,
        };
        let env = Envelope::new(
            s.header(Kind::EvaluationKeys),
            vec![("keys".into(), payload)],
        );
        s.evaluation_keys = Some(env.encode());
        Ok(s)
    }

    /// Restore a client from a secret-key envelope written by
    /// [`ClientSession::secret_key_envelope`]; the backend is taken from it.
    pub fn restore(ids: Ids, compiled: &CompiledProgram, secret: &[u8]) -> Result<Self> {
        if let CompiledProgram::Exact(e) = compiled {
            e.check_output_ranges()?;
        }
        let env = Envelope::decode(secret)?;
        let kind = BackendKind::parse(&env.header.backend).ok_or_else(|| {
            Error::new(
                Code::Incompatible,
                format!("unknown backend {:?}", env.header.backend),
            )
        })?;
        let (backend, backend_version) = kind.label();
        env.check(&Expect {
            governance_id: None,
            kind: Kind::SecretKey,
            scheme: compiled.scheme(),
            backend,
            backend_version,
            parameter_set_id: &ids.parameter_set_id,
            program_id: None,
            key_id: None,
        })?;
        let key_id = env
            .header
            .key_id
            .clone()
            .ok_or_else(|| Error::new(Code::WrongKey, "secret key carries no key ID"))?;
        let client =
            match (compiled, kind) {
                (CompiledProgram::Approx(c), BackendKind::Mock) => Client::Mock(
                    MockClient::restore(&c.params, &env.payload, MockConfig::default())?,
                ),
                #[cfg(feature = "openfhe")]
                (CompiledProgram::Approx(c), BackendKind::OpenFhe) => Client::OpenFhe(
                    encompute_openfhe_client::OpenFheClient::restore(&c.params, &env.payload)?,
                ),
                (CompiledProgram::Exact(_), BackendKind::Mock) => {
                    Client::ExactMock(PlainExactClient::restore(&env.payload)?)
                }
                #[cfg(feature = "openfhe")]
                (CompiledProgram::Exact(e), BackendKind::OpenFhe) => {
                    Client::Bgv(encompute_openfhe_client::BgvClient::restore(
                        encompute_exact::bgv::mult_depth(&e.plan),
                        &env.payload,
                    )?)
                }
                #[cfg(feature = "research-tfhe-rs")]
                (CompiledProgram::Exact(_), BackendKind::TfheRs) => Client::TfheRs(Box::new(
                    encompute_tfhe_client::TfheRsClient::restore(&env.payload)?,
                )),
                #[cfg(feature = "openfhe")]
                (CompiledProgram::Exact(_), BackendKind::OpenFheExact) => {
                    Client::OpenFheExact(Box::new(
                        encompute_openfhe_client::OpenFheExactClient::restore(&env.payload)?,
                    ))
                }
                (_, k) => return Err(not_built(k)),
            };
        Ok(Self {
            client,
            kind,
            ids,
            key_id,
            compiled: compiled.clone(),
            evaluation_keys: None,
        })
    }

    /// Secret-key envelope for the client's disk. Never send it anywhere.
    pub fn secret_key_envelope(&self) -> Result<Vec<u8>> {
        let payload = self.client.secret_key()?;
        Ok(Envelope::new(
            self.header(Kind::SecretKey),
            vec![("secret".into(), payload)],
        )
        .encode())
    }

    pub fn kind(&self) -> BackendKind {
        self.kind
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn ids(&self) -> &Ids {
        &self.ids
    }

    /// The evaluation-keys envelope; `None` for a client restored from disk
    /// (its evaluation keys were exported when it was generated).
    pub fn evaluation_keys(&self) -> Option<&[u8]> {
        self.evaluation_keys.as_deref()
    }

    /// Encode and encrypt inputs into an inputs envelope.
    pub fn encrypt(&self, program: &Program, inputs: &Inputs) -> Result<Vec<u8>> {
        check_inputs(program, inputs)?;
        let items = match &self.compiled {
            CompiledProgram::Approx(c) => c
                .plan
                .inputs
                .iter()
                .enumerate()
                .map(|(i, inp)| {
                    let ct = self
                        .client
                        .ckks()
                        .encrypt(&c.plan.encode_input(i, &inputs[&inp.name]))?;
                    Ok((inp.name.clone(), ct))
                })
                .collect::<Result<Vec<_>>>()?,
            // check_inputs proved each value an integer within its range.
            CompiledProgram::Exact(e) => e
                .plan
                .inputs
                .iter()
                .map(|inp| {
                    let v = inputs[&inp.name][0] as i128;
                    Ok((inp.name.clone(), self.client.exact().encrypt(inp.elem, v)?))
                })
                .collect::<Result<Vec<_>>>()?,
        };
        Ok(Envelope::new(self.header(Kind::Inputs), items).encode())
    }

    /// What this client expects the evaluator to execute: the statement
    /// its receipts must carry.
    pub fn spec(&self) -> ExecutionSpec {
        execution_spec(&self.ids, &self.compiled, self.kind)
    }

    /// The semantic transcript of this client's own plan (exact programs):
    /// what receipts must bind and a future proof must follow.
    pub fn transcript(&self) -> Option<SemanticTranscript> {
        transcript_for(&self.compiled, &self.spec())
    }

    /// Verify `receipt` against this client's own spec and key, the exact
    /// `request` it sent and `response` it received, and the evaluator it
    /// trusts; only then decrypt. The receipt is a signed claim by that
    /// evaluator, not a proof that it computed correctly.
    pub fn decrypt_verified(
        &self,
        request: &[u8],
        response: &[u8],
        receipt: &SignedExecutionReceipt,
        trusted: &EvaluatorIdentity,
    ) -> Result<(Outputs, VerifiedReceipt)> {
        if self.compiled.proof_required() && self.kind != BackendKind::Mock {
            return Err(Error::new(
                Code::Unverified,
                "this program requires verified execution: use decrypt_proven",
            ));
        }
        let spec = self.spec();
        let (rc, oc) = (request_commitment(request), output_commitment(response));
        let transcript_hash = self.transcript().map(|t| t.id().hex());
        let verified = verify_receipt(
            receipt,
            &ExpectedExecution {
                spec: &spec,
                key_id: &self.key_id,
                request_commitment: &rc,
                output_commitment: &oc,
                transcript_hash: transcript_hash.as_deref(),
                proof_expected: self.compiled.proof_required() && self.kind != BackendKind::Mock,
                trusted_evaluator: trusted,
            },
        )?;
        Ok((self.decrypt(response)?, verified))
    }

    /// Give a restored client its evaluation-keys envelope (`eval.keys`),
    /// needed to verify execution proofs by re-execution. Checked against
    /// this client's key ID.
    pub fn attach_evaluation_keys(&mut self, envelope: &[u8]) -> Result<()> {
        let env = Envelope::decode(envelope)?;
        if sha256_hex(&env.payload) != self.key_id {
            return Err(Error::new(
                Code::WrongKey,
                "these evaluation keys belong to another key pair",
            ));
        }
        self.evaluation_keys = Some(envelope.to_vec());
        Ok(())
    }

    /// Verify the receipt and, for programs requiring verified execution,
    /// the execution proof, before decrypting. No proof, no decryption:
    /// when the program requires one, a missing or invalid proof is an
    /// error (ENC1801) and nothing is decrypted. Mock runs are never
    /// reported as verified.
    pub fn decrypt_proven(
        &self,
        request: &[u8],
        response: &[u8],
        receipt: &SignedExecutionReceipt,
        proof: Option<&ExecutionProof>,
        trusted: &EvaluatorIdentity,
    ) -> Result<(Outputs, VerificationState)> {
        let (_, verified) = self.verify_receipt_only(request, response, receipt, trusted)?;
        if !self.compiled.proof_required() || self.kind == BackendKind::Mock {
            return Ok((self.decrypt(response)?, VerificationState::ReceiptVerified));
        }
        let proof = proof.ok_or_else(|| {
            Error::new(
                Code::Unverified,
                "this program requires verified execution and the evaluator sent no execution \
                 proof: no proof, no decryption",
            )
        })?;
        let state = self.verify_proof(&verified, request, response, proof)?;
        Ok((self.decrypt(response)?, state))
    }

    #[cfg(feature = "vfhe-research")]
    fn verify_proof(
        &self,
        verified: &VerifiedReceipt,
        request: &[u8],
        response: &[u8],
        proof: &ExecutionProof,
    ) -> Result<VerificationState> {
        use encompute_verification::{verify_execution, CiphertextBinding, ExecutionStatement};
        use encompute_vfhe::{ReexecutionBackend, ReexecutionKey};
        let transcript = self
            .transcript()
            .ok_or_else(|| Error::new(Code::Transcript, "exact program without a transcript"))?;
        let statement = ExecutionStatement::new(verified, &transcript)?;
        let binding = CiphertextBinding::new(request, response, &statement)?;
        let keys = self.evaluation_keys.as_deref().ok_or_else(|| {
            Error::new(
                Code::Unverified,
                "verifying needs this client's evaluation keys (eval.keys)",
            )
        })?;
        let payload = Envelope::decode(keys)?.payload;
        let plan = &self
            .compiled
            .exact()
            .expect("proof-required programs are exact")
            .plan;
        let key = ReexecutionKey::new(plan, &self.spec().plan_id, &self.key_id, &payload);
        verify_execution(
            verified,
            &statement,
            &binding,
            proof,
            &ReexecutionBackend,
            &key,
        )
    }

    #[cfg(not(feature = "vfhe-research"))]
    fn verify_proof(
        &self,
        _: &VerifiedReceipt,
        _: &[u8],
        _: &[u8],
        _: &ExecutionProof,
    ) -> Result<VerificationState> {
        Err(Error::new(
            Code::Unverified,
            "verifying execution proofs needs the research `vfhe-research` build",
        ))
    }

    /// Verify only the receipt against this client's spec, key, transcript
    /// and the exact envelopes.
    pub fn verify_receipt(
        &self,
        request: &[u8],
        response: &[u8],
        receipt: &SignedExecutionReceipt,
        trusted: &EvaluatorIdentity,
    ) -> Result<VerifiedReceipt> {
        self.verify_receipt_only(request, response, receipt, trusted)
            .map(|(_, v)| v)
    }

    fn verify_receipt_only(
        &self,
        request: &[u8],
        response: &[u8],
        receipt: &SignedExecutionReceipt,
        trusted: &EvaluatorIdentity,
    ) -> Result<((), VerifiedReceipt)> {
        let spec = self.spec();
        let (rc, oc) = (request_commitment(request), output_commitment(response));
        let transcript_hash = self.transcript().map(|t| t.id().hex());
        let verified = verify_receipt(
            receipt,
            &ExpectedExecution {
                spec: &spec,
                key_id: &self.key_id,
                request_commitment: &rc,
                output_commitment: &oc,
                transcript_hash: transcript_hash.as_deref(),
                proof_expected: self.compiled.proof_required() && self.kind != BackendKind::Mock,
                trusted_evaluator: trusted,
            },
        )?;
        Ok(((), verified))
    }

    /// Check and decrypt an outputs envelope, without a receipt.
    pub fn decrypt(&self, bytes: &[u8]) -> Result<Outputs> {
        let env = open(bytes, &self.expect(Kind::Outputs))?;
        let items = env.items();
        let want: Vec<&str> = match &self.compiled {
            CompiledProgram::Approx(c) => c.plan.outputs.iter().map(|o| o.name.as_str()).collect(),
            CompiledProgram::Exact(e) => e.plan.outputs.iter().map(|o| o.name.as_str()).collect(),
        };
        let got: Vec<&str> = items.iter().map(|(n, _)| *n).collect();
        if got != want {
            return Err(Error::new(
                Code::Envelope,
                format!("expected outputs {want:?}, got {got:?}"),
            ));
        }
        match &self.compiled {
            CompiledProgram::Approx(c) => c
                .plan
                .outputs
                .iter()
                .zip(items)
                .map(|(o, (_, ct))| {
                    let mut v = self.client.ckks().decrypt(ct)?;
                    v.truncate(o.len);
                    Ok((o.name.clone(), v))
                })
                .collect(),
            CompiledProgram::Exact(e) => {
                e.check_output_ranges()?;
                e.plan
                    .outputs
                    .iter()
                    .zip(items)
                    .enumerate()
                    .map(|(i, (o, (_, ct)))| {
                        let v = self.client.exact().decrypt(o.elem, ct)?;
                        // Range analysis proved every output's interval: a value
                        // outside it is a wrong result (tampering, other keys, or
                        // noise), never a valid one.
                        // A missing range is an error, never a skipped check.
                        let (lo, hi) = e.output_range(i)?;
                        if v < lo || v > hi {
                            return Err(Error::new(
                                Code::Backend,
                                format!(
                                    "output {:?} decrypted to {v}, outside its proven range \
                                 [{lo}, {hi}]: the result is wrong",
                                    o.name
                                ),
                            ));
                        }
                        Ok((o.name.clone(), vec![v as f64]))
                    })
                    .collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use encompute_ir::{Builder, Elem, Range};

    /// Review finding EV-6 (ENC-SF-2026-065): the client decrypted exact outputs without
    /// comparing them with the interval range analysis proves, so a wrong
    /// result inside the output's type (another client's keys, tampering,
    /// BGV noise) was returned as if correct.
    #[test]
    fn exact_outputs_outside_their_proven_range_are_refused() {
        let mut b = Builder::new("r", 1e-3).unwrap();
        let x = b
            .input_exact("x", Elem::U8, Some(Range::new(0.0, 10.0)))
            .unwrap();
        let one = b.constant_exact(Elem::U8, 1.0).unwrap();
        let y = b.add(x, one).unwrap();
        b.output("y", y).unwrap();
        let p = b.finish().unwrap();
        let compiled = encompute_evaluator::compile_program(&p).unwrap();
        let s = ClientSession::generate(Ids::of(&p, &compiled), &compiled, BackendKind::Mock, 1)
            .unwrap();
        let outputs = |v: i128| {
            let ct = s.client.exact().encrypt(Elem::U8, v).unwrap();
            Envelope::new(s.header(Kind::Outputs), vec![("y".into(), ct)]).encode()
        };
        for v in [1, 11] {
            assert_eq!(s.decrypt(&outputs(v)).unwrap()["y"], vec![v as f64]);
        }
        for v in [0, 12, 200, 255] {
            let e = s.decrypt(&outputs(v)).unwrap_err();
            assert_eq!(e.code, Code::Backend);
            assert!(
                e.message.contains("outside its proven range [1, 11]"),
                "{e}"
            );
        }
    }

    /// ENC-SF-2026-065 follow-up: the check above was skipped when the
    /// program carried no proven range for an output (`.get(i)` on ranges
    /// that `#[serde(skip)]` drops from a serialized program). A missing
    /// range is now refused: no session is created for such a program, and
    /// a session whose program lost its ranges decrypts nothing.
    #[test]
    fn exact_outputs_without_a_proven_range_are_refused() {
        let mut b = Builder::new("r", 1e-3).unwrap();
        let x = b
            .input_exact("x", Elem::U8, Some(Range::new(0.0, 10.0)))
            .unwrap();
        let one = b.constant_exact(Elem::U8, 1.0).unwrap();
        let y = b.add(x, one).unwrap();
        b.output("y", y).unwrap();
        let p = b.finish().unwrap();
        let compiled = encompute_evaluator::compile_program(&p).unwrap();
        let ids = Ids::of(&p, &compiled);
        let mut s = ClientSession::generate(ids.clone(), &compiled, BackendKind::Mock, 1).unwrap();
        let secret = s.secret_key_envelope().unwrap();
        let outputs = |s: &ClientSession, v: i128| {
            let ct = s.client.exact().encrypt(Elem::U8, v).unwrap();
            Envelope::new(s.header(Kind::Outputs), vec![("y".into(), ct)]).encode()
        };

        // The program as a client would get it without its ranges.
        let mut stripped = compiled.clone();
        match &mut stripped {
            CompiledProgram::Exact(e) => e.output_ranges.clear(),
            CompiledProgram::Approx(_) => unreachable!("exact program"),
        }
        for e in [
            ClientSession::generate(ids.clone(), &stripped, BackendKind::Mock, 1).err(),
            ClientSession::restore(ids, &stripped, &secret).err(),
        ] {
            let e = e.expect("refused");
            assert_eq!(e.code, Code::Backend);
            assert!(
                e.message.contains("0 proven output ranges for 1 outputs"),
                "{e}"
            );
        }

        // A session whose program lost its ranges refuses in-range and
        // out-of-range values alike, instead of returning them unchecked.
        let envs: Vec<Vec<u8>> = [5, 200].iter().map(|&v| outputs(&s, v)).collect();
        s.compiled = stripped;
        for env in envs {
            let e = s.decrypt(&env).unwrap_err();
            assert_eq!(e.code, Code::Backend);
            assert!(
                e.message.contains("0 proven output ranges for 1 outputs"),
                "{e}"
            );
        }
    }
}
