use std::collections::HashMap;
use std::time::{Duration, Instant};

use encompute_backend::{
    CkksEvaluator, ExactEvaluator, MockConfig, MockEvaluator, PlainExactEvaluator,
};
use encompute_exact::{
    evaluate_exact_observed, semantic_transcript, ExactPlan, ExecutionContext, ExecutionObserver,
    NoopObserver,
};
use encompute_ir::{Code, Error, Program, Result};
use encompute_protocol::{open, sha256_hex, Envelope, Expect, Header, Kind};
use encompute_verification::{
    EvaluatorSigner, ExecutionProof, ExecutionReceipt, ExecutionSpec, SemanticTranscript,
    SignedExecutionReceipt, VerificationEvidence, SPEC_VERSION,
};

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

/// The execution specification of `compiled` (with `ids`) on backend
/// `kind`: the statement every receipt refers to. The IDs are SHA-256 of
/// the artifact's `program.eir`, `plan.json` and `parameters.json`.
pub fn execution_spec(ids: &Ids, compiled: &CompiledProgram, kind: BackendKind) -> ExecutionSpec {
    let (plan_kind, plan_version) = compiled.plan_format();
    let (backend, backend_version) = kind.label();
    ExecutionSpec {
        version: SPEC_VERSION,
        program_id: ids.program_id.clone(),
        plan_id: sha256_hex(compiled.plan_json().as_bytes()),
        parameter_set_id: ids.parameter_set_id.clone(),
        plan_kind: plan_kind.into(),
        plan_version,
        semantics: match compiled.semantics() {
            Semantics::Approximate => "approximate",
            Semantics::Exact => "exact",
        }
        .into(),
        scheme: compiled.scheme().into(),
        backend: backend.into(),
        backend_version: backend_version.into(),
    }
}

/// The semantic transcript of an exact program under `spec`;
/// `None` for CKKS programs, which are not transcribed yet.
pub fn transcript_for(
    compiled: &CompiledProgram,
    spec: &ExecutionSpec,
) -> Option<SemanticTranscript> {
    compiled
        .exact()
        .map(|e| semantic_transcript(&e.plan, &spec.id().hex()))
}

fn request_key_id(request: &[u8]) -> Result<String> {
    Envelope::decode(request)?
        .header
        .key_id
        .ok_or_else(|| Error::new(Code::WrongKey, "inputs carry no key ID"))
}

/// The execution proof an evaluator attaches, when the program requires
/// one and runs on the proof-capable OpenFHE BGV backend (ADR-009).
pub fn execution_proof(
    spec: &ExecutionSpec,
    transcript_hash: Option<&str>,
    proof_required: bool,
    request: &[u8],
    response: &[u8],
) -> Result<Option<ExecutionProof>> {
    if !proof_required || spec.backend != BackendKind::OpenFhe.label().0 {
        return Ok(None);
    }
    let t = transcript_hash
        .ok_or_else(|| Error::new(Code::Transcript, "exact program without a transcript"))?;
    Ok(Some(encompute_exact::bgv::reexecution_proof(
        spec,
        t,
        &request_key_id(request)?,
        request,
        response,
    )))
}

/// Sign a receipt binding `spec`, the transcript hash (exact programs), the
/// request's key ID, the exact request and response envelope bytes, and
/// `proof` (by digest) if there is one.
pub fn issue_receipt(
    spec: &ExecutionSpec,
    transcript_hash: Option<&str>,
    request: &[u8],
    response: &[u8],
    proof: Option<&ExecutionProof>,
    signer: &EvaluatorSigner,
) -> Result<SignedExecutionReceipt> {
    let evidence = match proof {
        Some(p) => encompute_exact::bgv::evidence(p)?,
        None => VerificationEvidence::None,
    };
    ExecutionReceipt::with_evidence(
        spec,
        transcript_hash,
        &request_key_id(request)?,
        request,
        response,
        &signer.identity(),
        evidence,
    )?
    .sign(signer)
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

    /// Whether this backend can run `compiled` (the mock runs everything;
    /// real backends only the programs targeting them).
    pub fn runs(self, compiled: &CompiledProgram) -> bool {
        self == BackendKind::Mock || self == compiled.target_backend()
    }

    fn check(self, compiled: &CompiledProgram) -> Result<()> {
        let s = compiled.semantics();
        if !self.runs(compiled) {
            return Err(Error::new(
                Code::Backend,
                format!(
                    "{} cannot run {} programs of scheme {}",
                    self.name(),
                    match s {
                        Semantics::Approximate => "approximate",
                        Semantics::Exact => "exact",
                    },
                    compiled.scheme()
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

    /// The backend for `compiled`: exact programs targeting OpenFHE BGV run
    /// on OpenFHE when this evaluator runs OpenFHE, else on the mock.
    pub fn for_program(self, compiled: &CompiledProgram) -> BackendKind {
        match (compiled, compiled.target_backend()) {
            (CompiledProgram::Exact(_), BackendKind::OpenFhe) => {
                if self.approx == BackendKind::OpenFhe {
                    BackendKind::OpenFhe
                } else {
                    BackendKind::Mock
                }
            }
            _ => self.for_semantics(compiled.semantics()),
        }
    }

    /// Command-line arguments reproducing exactly this choice (for worker
    /// processes): one flag per semantics, so no flag overrides the other.
    pub fn args(self) -> Vec<&'static str> {
        vec![
            "--approx-backend",
            self.approx.name(),
            "--exact-backend",
            self.exact.name(),
        ]
    }

    /// Apply one command-line flag: `--backend` (every semantics the
    /// backend supports; `mock` means both), `--approx-backend` or
    /// `--exact-backend` (that semantics only). `None` if the flag or value
    /// is not valid.
    pub fn apply(self, flag: &str, value: &str) -> Option<Self> {
        let k = BackendKind::parse(value)?;
        match flag {
            "--backend" => Some(self.with(k)),
            "--approx-backend" if k.supports(Semantics::Approximate) => {
                Some(Self { approx: k, ..self })
            }
            "--exact-backend" if k.supports(Semantics::Exact) => Some(Self { exact: k, ..self }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Workers get exactly the gateway's backends (a mock for one semantics
    /// must not replace the real backend of the other).
    #[test]
    fn backend_args_round_trip() {
        use BackendKind::*;
        for (approx, exact) in [
            (Mock, Mock),
            (OpenFhe, Mock),
            (Mock, TfheRs),
            (OpenFhe, TfheRs),
        ] {
            let b = Backends { approx, exact };
            let mut got = Backends::MOCK;
            for pair in b.args().chunks(2) {
                got = got.apply(pair[0], pair[1]).unwrap();
            }
            assert_eq!(got, b);
        }
        assert_eq!(
            Backends::MOCK.apply("--approx-backend", "tfhe-rs"),
            None,
            "TFHE-rs cannot run approximate programs"
        );
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
    #[cfg(feature = "openfhe")]
    Bgv(encompute_openfhe::BgvEvaluator),
}

/// One compiled program, the evaluation keys registered for it, and nothing
/// else: no secret key, no plaintext inputs or outputs.
pub struct EvaluatorSession {
    program: Program,
    compiled: CompiledProgram,
    ids: Ids,
    spec: ExecutionSpec,
    /// Exact programs: hash of the semantic transcript receipts bind.
    transcript_hash: Option<String>,
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
        kind.check(&compiled)?;
        let ids = Ids::of(&program, &compiled);
        let spec = execution_spec(&ids, &compiled, kind);
        let transcript_hash = transcript_for(&compiled, &spec).map(|t| t.id().hex());
        Ok(Self {
            program,
            compiled,
            ids,
            spec,
            transcript_hash,
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

    /// What this session executes, as receipts state it.
    pub fn spec(&self) -> &ExecutionSpec {
        &self.spec
    }

    /// The transcript hash receipts bind (exact programs).
    pub fn transcript_hash(&self) -> Option<&str> {
        self.transcript_hash.as_deref()
    }

    /// The execution proof for one execution, if this program requires one
    /// and this session can produce it.
    pub fn proof_for(&self, request: &[u8], response: &[u8]) -> Result<Option<ExecutionProof>> {
        execution_proof(
            &self.spec,
            self.transcript_hash(),
            self.compiled.proof_required(),
            request,
            response,
        )
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
            #[cfg(feature = "openfhe")]
            (CompiledProgram::Exact(e), BackendKind::OpenFhe) => {
                let mut ev = encompute_openfhe::BgvEvaluator::new(
                    encompute_exact::bgv::mult_depth(&e.plan),
                )?;
                ev.load_keys(&env.payload)?;
                Keyed::Bgv(ev)
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
        self.execute_observed(bytes, &mut NoopObserver)
    }

    /// [`EvaluatorSession::execute`], reporting each step of an exact plan
    /// to `observer` (CKKS plans are not observed yet).
    pub fn execute_observed(
        &self,
        bytes: &[u8],
        observer: &mut dyn ExecutionObserver,
    ) -> Result<(Vec<u8>, ExecTimes)> {
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
            (Keyed::ExactMock(ev), CompiledProgram::Exact(e)) => {
                run_exact(ev, &e.plan, &items, &self.context(), observer)?
            }
            #[cfg(feature = "openfhe")]
            (Keyed::Bgv(ev), CompiledProgram::Exact(e)) => {
                run_exact(ev, &e.plan, &items, &self.context(), observer)?
            }
            #[cfg(feature = "tfhe-rs")]
            (Keyed::TfheRs(ev), CompiledProgram::Exact(e)) => {
                run_exact(ev, &e.plan, &items, &self.context(), observer)?
            }
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

    fn context(&self) -> ExecutionContext {
        ExecutionContext {
            spec_id: self.spec.id().hex(),
        }
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
    ctx: &ExecutionContext,
    observer: &mut dyn ExecutionObserver,
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
    let outs = evaluate_exact_observed(ev, plan, cts, ctx, observer)?;
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
