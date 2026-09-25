//! The client role: owns the secret key; encrypts inputs into envelopes and
//! decrypts output envelopes. Talks to an evaluator only through envelopes.
//! One session type serves both semantics (CKKS and exact).

use encompute_backend::{CkksClient, ExactClient, MockClient, MockConfig, PlainExactClient};
use encompute_evaluator::{execution_spec, BackendKind, CompiledProgram, Ids};
use encompute_ir::{check_inputs, Code, Error, Inputs, Outputs, Program, Result};
use encompute_protocol::{open, sha256_hex, Envelope, Expect, Header, Kind};
use encompute_verification::{
    output_commitment, request_commitment, verify_receipt, EvaluatorIdentity, ExecutionSpec,
    ExpectedExecution, SignedExecutionReceipt, VerifiedReceipt,
};

/// The concrete client, so the secret key can be exported.
enum Client {
    Mock(MockClient),
    #[cfg(feature = "openfhe")]
    OpenFhe(encompute_openfhe_client::OpenFheClient),
    ExactMock(PlainExactClient),
    #[cfg(feature = "tfhe-rs")]
    TfheRs(Box<encompute_tfhe_client::TfheRsClient>),
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
            #[cfg(feature = "tfhe-rs")]
            Client::TfheRs(c) => c.as_ref(),
            _ => unreachable!("CKKS client used for an exact program"),
        }
    }

    fn evaluation_keys(&self) -> Result<Vec<u8>> {
        match self {
            Client::ExactMock(_) => self.exact().evaluation_keys(),
            #[cfg(feature = "tfhe-rs")]
            Client::TfheRs(_) => self.exact().evaluation_keys(),
            _ => self.ckks().evaluation_keys(),
        }
    }

    fn secret_key(&self) -> Result<Vec<u8>> {
        match self {
            Client::Mock(c) => Ok(c.secret_key()),
            #[cfg(feature = "openfhe")]
            Client::OpenFhe(c) => c.secret_key(),
            Client::ExactMock(c) => Ok(c.secret_key()),
            #[cfg(feature = "tfhe-rs")]
            Client::TfheRs(c) => c.secret_key(),
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
    /// Evaluation-keys envelope, to send to the evaluator once.
    evaluation_keys: Option<Vec<u8>>,
}

impl ClientSession {
    fn header(&self, kind: Kind) -> Header {
        let (backend, backend_version) = self.kind.label();
        Header {
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
            #[cfg(feature = "tfhe-rs")]
            (CompiledProgram::Exact(_), BackendKind::TfheRs) => {
                Client::TfheRs(Box::new(encompute_tfhe_client::TfheRsClient::generate()?))
            }
            (c, k) if !k.supports(c.semantics()) => {
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
        let env = Envelope::decode(secret)?;
        let kind = BackendKind::parse(&env.header.backend).ok_or_else(|| {
            Error::new(
                Code::Incompatible,
                format!("unknown backend {:?}", env.header.backend),
            )
        })?;
        let (backend, backend_version) = kind.label();
        env.check(&Expect {
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
                #[cfg(feature = "tfhe-rs")]
                (CompiledProgram::Exact(_), BackendKind::TfheRs) => Client::TfheRs(Box::new(
                    encompute_tfhe_client::TfheRsClient::restore(&env.payload)?,
                )),
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
        let spec = self.spec();
        let (rc, oc) = (request_commitment(request), output_commitment(response));
        let verified = verify_receipt(
            receipt,
            &ExpectedExecution {
                spec: &spec,
                key_id: &self.key_id,
                request_commitment: &rc,
                output_commitment: &oc,
                trusted_evaluator: trusted,
            },
        )?;
        Ok((self.decrypt(response)?, verified))
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
            CompiledProgram::Exact(e) => e
                .plan
                .outputs
                .iter()
                .zip(items)
                .map(|(o, (_, ct))| {
                    let v = self.client.exact().decrypt(o.elem, ct)?;
                    Ok((o.name.clone(), vec![v as f64]))
                })
                .collect(),
        }
    }
}
