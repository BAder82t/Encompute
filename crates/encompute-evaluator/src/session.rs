use std::collections::HashMap;
use std::time::{Duration, Instant};

use encompute_backend::{CkksEvaluator, MockConfig, MockEvaluator};
use encompute_ckks::{compile, Compiled};
use encompute_ir::{Code, Error, Program, Result};
use encompute_protocol::{open, sha256_hex, Envelope, Expect, Header, Kind};

use crate::exec::evaluate_encrypted;

/// SHA-256 of the canonical `.eir` text.
pub fn program_id(program: &Program) -> String {
    sha256_hex(program.to_string().as_bytes())
}

/// Identifiers binding envelopes to one compiled program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ids {
    pub parameter_set_id: String,
    pub program_id: String,
}

impl Ids {
    pub fn of(program: &Program, compiled: &Compiled) -> Self {
        Self {
            parameter_set_id: sha256_hex(compiled.params.canonical_json().as_bytes()),
            program_id: program_id(program),
        }
    }
}

/// Which evaluator implementation a session uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendKind {
    Mock,
    OpenFhe,
}

impl BackendKind {
    /// `(backend, backend_version)` written into and required of envelopes.
    pub fn label(self) -> (&'static str, &'static str) {
        match self {
            BackendKind::Mock => ("mock", "0"),
            BackendKind::OpenFhe => (encompute_ckks::BACKEND, encompute_ckks::BACKEND_VERSION),
        }
    }
}

/// Named serialized ciphertexts.
type Named = Vec<(String, Vec<u8>)>;

enum Keyed {
    Mock(MockEvaluator),
    #[cfg(feature = "openfhe")]
    OpenFhe(encompute_openfhe::OpenFheEvaluator),
}

/// One compiled program, the evaluation keys registered for it, and nothing
/// else: no secret key, no plaintext inputs or outputs.
pub struct EvaluatorSession {
    program: Program,
    compiled: Compiled,
    ids: Ids,
    kind: BackendKind,
    keys: HashMap<String, Keyed>,
}

/// Timing of one [`EvaluatorSession::execute`] call.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecTimes {
    pub load: Duration,
    pub evaluate: Duration,
    pub store: Duration,
}

impl EvaluatorSession {
    /// Compile `program` independently of the client (the evaluator trusts
    /// its own compilation, not the client's plan).
    pub fn new(program: Program, kind: BackendKind) -> Result<Self> {
        if kind == BackendKind::OpenFhe && !cfg!(feature = "openfhe") {
            return Err(Error::new(
                Code::Backend,
                "this evaluator was built without OpenFHE",
            ));
        }
        let compiled = compile(&program)?;
        let ids = Ids::of(&program, &compiled);
        Ok(Self {
            program,
            compiled,
            ids,
            kind,
            keys: HashMap::new(),
        })
    }

    pub fn ids(&self) -> &Ids {
        &self.ids
    }

    pub fn program(&self) -> &Program {
        &self.program
    }

    pub fn compiled(&self) -> &Compiled {
        &self.compiled
    }

    pub fn kind(&self) -> BackendKind {
        self.kind
    }

    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    fn expect(&self, kind: Kind, key_id: Option<&'static str>) -> Expect<'_> {
        let (backend, backend_version) = self.kind.label();
        Expect {
            kind,
            backend,
            backend_version,
            parameter_set_id: &self.ids.parameter_set_id,
            program_id: None,
            key_id,
        }
    }

    /// Register an evaluation-keys envelope. Returns its key ID. Registering
    /// the same keys twice is a no-op.
    pub fn register_keys(&mut self, bytes: &[u8]) -> Result<String> {
        let env = open(bytes, &self.expect(Kind::EvaluationKeys, None))?;
        let key_id = sha256_hex(&env.payload);
        if env.header.key_id.as_deref() != Some(key_id.as_str()) {
            return Err(Error::new(
                Code::WrongKey,
                "key ID does not match the key material",
            ));
        }
        if self.keys.contains_key(&key_id) {
            return Ok(key_id);
        }
        let params = &self.compiled.params;
        let keyed = match self.kind {
            BackendKind::Mock => Keyed::Mock(MockEvaluator::new(
                params,
                &env.payload,
                MockConfig::default(),
            )?),
            #[cfg(feature = "openfhe")]
            BackendKind::OpenFhe => {
                let mut ev = encompute_openfhe::OpenFheEvaluator::new(params)?;
                ev.load_keys(&env.payload)?;
                Keyed::OpenFhe(ev)
            }
            #[cfg(not(feature = "openfhe"))]
            BackendKind::OpenFhe => unreachable!("rejected in new()"),
        };
        self.keys.insert(key_id.clone(), keyed);
        Ok(key_id)
    }

    /// Execute an inputs envelope; returns the outputs envelope.
    pub fn execute(&self, bytes: &[u8]) -> Result<(Vec<u8>, ExecTimes)> {
        let env = Envelope::decode(bytes)?;
        let mut expect = self.expect(Kind::Inputs, None);
        expect.program_id = Some(&self.ids.program_id);
        env.check(&expect)?;
        let key_id = env
            .header
            .key_id
            .clone()
            .ok_or_else(|| Error::new(Code::WrongKey, "inputs carry no key ID"))?;
        let keyed = self.keys.get(&key_id).ok_or_else(|| {
            Error::new(
                Code::WrongKey,
                "no evaluation keys are registered for this key ID",
            )
        })?;
        let items = env.items();
        let names: Vec<&str> = items.iter().map(|(n, _)| *n).collect();
        let want: Vec<&str> = self
            .compiled
            .plan
            .inputs
            .iter()
            .map(|i| i.name.as_str())
            .collect();
        if names != want {
            return Err(Error::new(
                Code::BadInput,
                format!("expected encrypted inputs {want:?}, got {names:?}"),
            ));
        }
        let (outputs, times) = match keyed {
            Keyed::Mock(ev) => self.run(ev, &items)?,
            #[cfg(feature = "openfhe")]
            Keyed::OpenFhe(ev) => self.run(ev, &items)?,
        };
        let (backend, backend_version) = self.kind.label();
        let header = Header {
            kind: Kind::Outputs,
            scheme: "CKKS".into(),
            backend: backend.into(),
            backend_version: backend_version.into(),
            parameter_set_id: self.ids.parameter_set_id.clone(),
            program_id: Some(self.ids.program_id.clone()),
            key_id: Some(key_id),
            items: vec![],
        };
        Ok((Envelope::new(header, outputs).encode(), times))
    }

    fn run<E: CkksEvaluator>(&self, ev: &E, items: &[(&str, &[u8])]) -> Result<(Named, ExecTimes)> {
        let mut times = ExecTimes::default();
        let t = Instant::now();
        let cts = items
            .iter()
            .map(|(_, b)| ev.load_ciphertext(b))
            .collect::<Result<Vec<_>>>()?;
        times.load = t.elapsed();
        let t = Instant::now();
        let outs = evaluate_encrypted(ev, &self.compiled.plan, &self.program, cts)?;
        times.evaluate = t.elapsed();
        let t = Instant::now();
        let stored = self
            .compiled
            .plan
            .outputs
            .iter()
            .zip(&outs)
            .map(|(o, ct)| Ok((o.name.clone(), ev.store_ciphertext(ct)?)))
            .collect::<Result<Vec<_>>>()?;
        times.store = t.elapsed();
        Ok((stored, times))
    }
}
