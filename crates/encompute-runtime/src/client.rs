//! The client role: owns the secret key; encrypts inputs into envelopes and
//! decrypts output envelopes. Talks to an evaluator only through envelopes.

use encompute_backend::{CkksClient, MockClient, MockConfig};
use encompute_ckks::CkksPlan;
use encompute_evaluator::{BackendKind, Ids};
use encompute_ir::{check_inputs, Code, Error, Inputs, Outputs, Program, Result};
use encompute_protocol::{open, sha256_hex, Envelope, Expect, Header, Kind};

/// The concrete client, so the secret key can be exported.
enum Client {
    Mock(MockClient),
    #[cfg(feature = "openfhe")]
    OpenFhe(encompute_openfhe_client::OpenFheClient),
}

impl Client {
    fn get(&self) -> &dyn CkksClient {
        match self {
            Client::Mock(c) => c,
            #[cfg(feature = "openfhe")]
            Client::OpenFhe(c) => c,
        }
    }

    fn secret_key(&self) -> Result<Vec<u8>> {
        match self {
            Client::Mock(c) => Ok(c.secret_key()),
            #[cfg(feature = "openfhe")]
            Client::OpenFhe(c) => c.secret_key(),
        }
    }
}

pub struct ClientSession {
    client: Client,
    kind: BackendKind,
    ids: Ids,
    key_id: String,
    plan: CkksPlan,
    /// Evaluation-keys envelope, to send to the evaluator once.
    evaluation_keys: Option<Vec<u8>>,
}

impl ClientSession {
    fn header(&self, kind: Kind) -> Header {
        let (backend, backend_version) = self.kind.label();
        Header {
            kind,
            scheme: "CKKS".into(),
            backend: backend.into(),
            backend_version: backend_version.into(),
            parameter_set_id: self.ids.parameter_set_id.clone(),
            program_id: matches!(kind, Kind::Inputs | Kind::Outputs)
                .then(|| self.ids.program_id.clone()),
            key_id: Some(self.key_id.clone()),
            items: vec![],
        }
    }

    fn with_keys(client: Client, kind: BackendKind, ids: Ids, plan: CkksPlan) -> Result<Self> {
        let payload = client.get().evaluation_keys()?;
        let key_id = sha256_hex(&payload);
        let mut s = Self {
            client,
            kind,
            ids,
            key_id,
            plan,
            evaluation_keys: None,
        };
        let env = Envelope::new(
            s.header(Kind::EvaluationKeys),
            vec![("keys".into(), payload)],
        );
        s.evaluation_keys = Some(env.encode());
        Ok(s)
    }

    /// Fresh mock keys.
    pub fn mock(
        ids: Ids,
        plan: &CkksPlan,
        params: &encompute_ckks::CkksParams,
        seed: u64,
    ) -> Result<Self> {
        let client = MockClient::new(params, &plan.rotations, MockConfig { seed, noise: true });
        Self::with_keys(Client::Mock(client), BackendKind::Mock, ids, plan.clone())
    }

    /// Fresh OpenFHE keys.
    #[cfg(feature = "openfhe")]
    pub fn openfhe(ids: Ids, plan: &CkksPlan, params: &encompute_ckks::CkksParams) -> Result<Self> {
        let client = encompute_openfhe_client::OpenFheClient::generate(params, &plan.rotations)?;
        Self::with_keys(
            Client::OpenFhe(client),
            BackendKind::OpenFhe,
            ids,
            plan.clone(),
        )
    }

    /// Restore a client from a secret-key envelope written by
    /// [`ClientSession::secret_key_envelope`]; the backend is taken from it.
    pub fn restore(
        ids: Ids,
        plan: &CkksPlan,
        params: &encompute_ckks::CkksParams,
        secret: &[u8],
    ) -> Result<Self> {
        let env = Envelope::decode(secret)?;
        let kind = match env.header.backend.as_str() {
            "mock" => BackendKind::Mock,
            _ => BackendKind::OpenFhe,
        };
        let (backend, backend_version) = kind.label();
        env.check(&Expect {
            kind: Kind::SecretKey,
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
        let client = match kind {
            BackendKind::Mock => Client::Mock(MockClient::restore(
                params,
                &env.payload,
                MockConfig::default(),
            )?),
            #[cfg(feature = "openfhe")]
            BackendKind::OpenFhe => Client::OpenFhe(
                encompute_openfhe_client::OpenFheClient::restore(params, &env.payload)?,
            ),
            #[cfg(not(feature = "openfhe"))]
            BackendKind::OpenFhe => {
                return Err(Error::new(
                    Code::Backend,
                    "this build has no OpenFHE backend",
                ))
            }
        };
        Ok(Self {
            client,
            kind,
            ids,
            key_id,
            plan: plan.clone(),
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
        let items = self
            .plan
            .inputs
            .iter()
            .enumerate()
            .map(|(i, inp)| {
                let ct = self
                    .client
                    .get()
                    .encrypt(&self.plan.encode_input(i, &inputs[&inp.name]))?;
                Ok((inp.name.clone(), ct))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Envelope::new(self.header(Kind::Inputs), items).encode())
    }

    /// Check and decrypt an outputs envelope.
    pub fn decrypt(&self, bytes: &[u8]) -> Result<Outputs> {
        let (backend, backend_version) = self.kind.label();
        let env = open(
            bytes,
            &Expect {
                kind: Kind::Outputs,
                backend,
                backend_version,
                parameter_set_id: &self.ids.parameter_set_id,
                program_id: Some(&self.ids.program_id),
                key_id: Some(&self.key_id),
            },
        )?;
        let items = env.items();
        if items.len() != self.plan.outputs.len() {
            return Err(Error::new(Code::Envelope, "wrong number of outputs"));
        }
        self.plan
            .outputs
            .iter()
            .zip(items)
            .map(|(o, (name, ct))| {
                if name != o.name {
                    return Err(Error::new(
                        Code::Envelope,
                        format!("unexpected output {name:?}"),
                    ));
                }
                let mut v = self.client.get().decrypt(ct)?;
                v.truncate(o.len);
                Ok((o.name.clone(), v))
            })
            .collect()
    }
}
