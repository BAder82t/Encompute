use std::collections::HashMap;
use std::time::{Duration, Instant};

use encompute_backend::{
    CkksEvaluator, ExactEvaluator, MockConfig, MockEvaluator, PlainExactEvaluator,
};
use encompute_exact::{evaluate_exact, ExactPlan};
use encompute_ir::{Code, Error, Program, Result};
use encompute_protocol::{open, sha256_hex, Envelope, Expect, Header, Kind};

use crate::compiled::{compile_program, CompiledProgram, Semantics};
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
    pub fn of(program: &Program, compiled: &CompiledProgram) -> Self {
        Self {
            parameter_set_id: sha256_hex(compiled.parameters_json().as_bytes()),
            program_id: program_id(program),
        }
    }
}

/// Which implementation runs a program. The mock serves both semantics;
/// OpenFHE runs approximate (CKKS) programs, TFHE-rs exact ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BackendKind {
    Mock,
    OpenFhe,
    TfheRs,
}

impl BackendKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mock" => Some(BackendKind::Mock),
            "openfhe" => Some(BackendKind::OpenFhe),
            "tfhe-rs" => Some(BackendKind::TfheRs),
            _ => None,
        }
    }

    /// Command-line name.
    pub fn name(self) -> &'static str {
        match self {
            BackendKind::Mock => "mock",
            BackendKind::OpenFhe => "openfhe",
            BackendKind::TfheRs => "tfhe-rs",
        }
    }

    /// `(backend, backend_version)` written into and required of envelopes.
    pub fn label(self) -> (&'static str, &'static str) {
        match self {
            BackendKind::Mock => ("mock", "0"),
            BackendKind::OpenFhe => (encompute_ckks::BACKEND, encompute_ckks::BACKEND_VERSION),
            BackendKind::TfheRs => (encompute_tfhe::BACKEND, encompute_tfhe::BACKEND_VERSION),
        }
    }

    pub fn supports(self, s: Semantics) -> bool {
        match self {
            BackendKind::Mock => true,
            BackendKind::OpenFhe => s == Semantics::Approximate,
            BackendKind::TfheRs => s == Semantics::Exact,
        }
    }

    /// Whether this build includes the backend.
    pub fn built(self) -> bool {
        match self {
            BackendKind::Mock => true,
            BackendKind::OpenFhe => cfg!(feature = "openfhe"),
            BackendKind::TfheRs => cfg!(feature = "tfhe-rs"),
        }
    }

    fn check(self, s: Semantics) -> Result<()> {
        if !self.supports(s) {
            return Err(Error::new(
                Code::Backend,
                format!(
                    "{} cannot run {} programs",
                    self.name(),
                    match s {
                        Semantics::Approximate => "approximate (CKKS)",
                        Semantics::Exact => "exact (integer/Boolean)",
                    }
                ),
            ));
        }
        if !self.built() {
            return Err(Error::new(
                Code::Backend,
                match self {
                    BackendKind::TfheRs => {
                        "this build has no TFHE-rs backend (research use only): rebuild with \
                         the `tfhe-rs` feature, or use the mock"
                    }
                    _ => "this build has no OpenFHE backend: rebuild with the `openfhe` feature",
                },
            ));
        }
        Ok(())
    }
}

/// The backend an evaluator uses for each semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backends {
    pub approx: BackendKind,
    pub exact: BackendKind,
}

impl Backends {
    pub const MOCK: Self = Self {
        approx: BackendKind::Mock,
        exact: BackendKind::Mock,
    };

    /// Real cryptography where this build has it, the mock otherwise.
    pub fn for_build() -> Self {
        Self {
            approx: if BackendKind::OpenFhe.built() {
                BackendKind::OpenFhe
            } else {
                BackendKind::Mock
            },
            exact: if BackendKind::TfheRs.built() {
                BackendKind::TfheRs
            } else {
                BackendKind::Mock
            },
        }
    }

    /// Use `k` for every semantics it supports.
    pub fn with(self, k: BackendKind) -> Self {
        match k {
            BackendKind::Mock => Self::MOCK,
            BackendKind::OpenFhe => Self { approx: k, ..self },
            BackendKind::TfheRs => Self { exact: k, ..self },
        }
    }

    pub fn for_semantics(self, s: Semantics) -> BackendKind {
        match s {
            Semantics::Approximate => self.approx,
            Semantics::Exact => self.exact,
        }
    }

    /// Command-line arguments reproducing this choice.
    pub fn args(self) -> Vec<&'static str> {
        vec![
            "--backend",
            self.approx.name(),
            "--backend",
            self.exact.name(),
        ]
    }
}

/// Named serialized ciphertexts.
type Named = Vec<(String, Vec<u8>)>;

enum Keyed {
    Mock(MockEvaluator),
    #[cfg(feature = "openfhe")]
    OpenFhe(encompute_openfhe::OpenFheEvaluator),
    ExactMock(PlainExactEvaluator),
    #[cfg(feature = "tfhe-rs")]
    TfheRs(encompute_tfhe::tfhe_rs::TfheRsEvaluator),
}

/// One compiled program, the evaluation keys registered for it, and nothing
/// else: no secret key, no plaintext inputs or outputs.
pub struct EvaluatorSession {
    program: Program,
    compiled: CompiledProgram,
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
        let compiled = compile_program(&program)?;
        kind.check(compiled.semantics())?;
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

    pub fn compiled(&self) -> &CompiledProgram {
        &self.compiled
    }

    pub fn kind(&self) -> BackendKind {
        self.kind
    }

    pub fn has_key(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    fn expect(&self, kind: Kind, program_id: Option<&'static str>) -> Expect<'_> {
        let (backend, backend_version) = self.kind.label();
        Expect {
            kind,
            scheme: self.compiled.scheme(),
            backend,
            backend_version,
            parameter_set_id: &self.ids.parameter_set_id,
            program_id,
            key_id: None,
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
        let keyed = match (&self.compiled, self.kind) {
            (CompiledProgram::Approx(c), BackendKind::Mock) => Keyed::Mock(MockEvaluator::new(
                &c.params,
                &env.payload,
                MockConfig::default(),
            )?),
            #[cfg(feature = "openfhe")]
            (CompiledProgram::Approx(c), BackendKind::OpenFhe) => {
                let mut ev = encompute_openfhe::OpenFheEvaluator::new(&c.params)?;
                ev.load_keys(&env.payload)?;
                Keyed::OpenFhe(ev)
            }
            (CompiledProgram::Exact(_), BackendKind::Mock) => {
                Keyed::ExactMock(PlainExactEvaluator::new(&env.payload)?)
            }
            #[cfg(feature = "tfhe-rs")]
            (CompiledProgram::Exact(_), BackendKind::TfheRs) => {
                Keyed::TfheRs(encompute_tfhe::tfhe_rs::TfheRsEvaluator::new(&env.payload)?)
            }
            _ => unreachable!("backend checked in new()"),
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
        let want = self.compiled.input_names();
        if names != want {
            return Err(Error::new(
                Code::BadInput,
                format!("expected encrypted inputs {want:?}, got {names:?}"),
            ));
        }
        let (outputs, times) = match (keyed, &self.compiled) {
            (Keyed::Mock(ev), CompiledProgram::Approx(c)) => self.run(ev, c, &items)?,
            #[cfg(feature = "openfhe")]
            (Keyed::OpenFhe(ev), CompiledProgram::Approx(c)) => self.run(ev, c, &items)?,
            (Keyed::ExactMock(ev), CompiledProgram::Exact(e)) => run_exact(ev, &e.plan, &items)?,
            #[cfg(feature = "tfhe-rs")]
            (Keyed::TfheRs(ev), CompiledProgram::Exact(e)) => run_exact(ev, &e.plan, &items)?,
            _ => unreachable!("keys are registered for this session's program"),
        };
        let (backend, backend_version) = self.kind.label();
        let header = Header {
            kind: Kind::Outputs,
            scheme: self.compiled.scheme().into(),
            backend: backend.into(),
            backend_version: backend_version.into(),
            parameter_set_id: self.ids.parameter_set_id.clone(),
            program_id: Some(self.ids.program_id.clone()),
            key_id: Some(key_id),
            items: vec![],
        };
        Ok((Envelope::new(header, outputs).encode(), times))
    }

    fn run<E: CkksEvaluator>(
        &self,
        ev: &E,
        c: &encompute_ckks::Compiled,
        items: &[(&str, &[u8])],
    ) -> Result<(Named, ExecTimes)> {
        let mut times = ExecTimes::default();
        let t = Instant::now();
        let cts = items
            .iter()
            .map(|(_, b)| ev.load_ciphertext(b))
            .collect::<Result<Vec<_>>>()?;
        times.load = t.elapsed();
        let t = Instant::now();
        let outs = evaluate_encrypted(ev, &c.plan, &self.program, cts)?;
        times.evaluate = t.elapsed();
        let t = Instant::now();
        let stored = c
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

fn run_exact<E: ExactEvaluator>(
    ev: &E,
    plan: &ExactPlan,
    items: &[(&str, &[u8])],
) -> Result<(Named, ExecTimes)>
where
    E::Ciphertext: Clone,
{
    let mut times = ExecTimes::default();
    let t = Instant::now();
    let cts = plan
        .inputs
        .iter()
        .zip(items)
        .map(|(i, (_, b))| ev.load(i.elem, b))
        .collect::<Result<Vec<_>>>()?;
    times.load = t.elapsed();
    let t = Instant::now();
    let outs = evaluate_exact(ev, plan, cts)?;
    times.evaluate = t.elapsed();
    let t = Instant::now();
    let stored = plan
        .outputs
        .iter()
        .zip(&outs)
        .map(|(o, ct)| Ok((o.name.clone(), ev.store(ct)?)))
        .collect::<Result<Vec<_>>>()?;
    times.store = t.elapsed();
    Ok((stored, times))
}
