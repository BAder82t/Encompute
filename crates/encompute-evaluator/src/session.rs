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
    SignedExecutionReceipt, VerificationEvidence, WorkloadAttestationRef, SPEC_VERSION,
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
    /// Hex `PolicyId` of the program's confidentiality declarations.
    pub policy_id: Option<String>,
    /// Hex `PrivacyPolicyId` of its privacy budgets and mechanisms.
    pub privacy_policy_id: Option<String>,
}

impl Ids {
    pub fn of(program: &Program, compiled: &CompiledProgram) -> Self {
        Self {
            parameter_set_id: sha256_hex(compiled.parameters_json().as_bytes()),
            program_id: program_id(program),
            policy_id: program
                .confidentiality()
                .map(|c| encompute_verification::PolicyId::of(c).hex()),
            privacy_policy_id: program
                .confidentiality()
                .and_then(encompute_verification::PrivacyPolicyId::of)
                .map(|p| p.hex()),
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
        governance_id: None,
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
        policy_id: ids.policy_id.clone(),
        privacy_policy_id: ids.privacy_policy_id.clone(),
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
/// `proof` (by digest) if there is one, and the attested workload session
/// the evaluator runs in, if any.
pub fn issue_receipt(
    spec: &ExecutionSpec,
    transcript_hash: Option<&str>,
    request: &[u8],
    response: &[u8],
    proof: Option<&ExecutionProof>,
    attestation: Option<&WorkloadAttestationRef>,
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
    .attested(attestation.cloned())
    .sign(signer)
}

/// Which implementation runs a program. The mock serves both semantics;
/// OpenFHE runs approximate (CKKS) programs and verified exact programs
/// (BGV), OpenFHE exact runs exact programs (BinFHE), TFHE-rs runs exact
/// programs in research builds only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BackendKind {
    Mock,
    OpenFhe,
    OpenFheExact,
    TfheRs,
}

impl BackendKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mock" => Some(BackendKind::Mock),
            "openfhe" => Some(BackendKind::OpenFhe),
            "openfhe-exact" => Some(BackendKind::OpenFheExact),
            "tfhe-rs" => Some(BackendKind::TfheRs),
            _ => None,
        }
    }

    /// Command-line name.
    pub fn name(self) -> &'static str {
        match self {
            BackendKind::Mock => "mock",
            BackendKind::OpenFhe => "openfhe",
            BackendKind::OpenFheExact => "openfhe-exact",
            BackendKind::TfheRs => "tfhe-rs",
        }
    }

    /// `(backend, backend_version)` written into and required of envelopes.
    pub fn label(self) -> (&'static str, &'static str) {
        match self {
            BackendKind::Mock => ("mock", "0"),
            BackendKind::OpenFhe => (encompute_ckks::BACKEND, encompute_ckks::BACKEND_VERSION),
            BackendKind::OpenFheExact => (
                encompute_exact::bits::OPENFHE_EXACT_BACKEND,
                encompute_exact::bits::OPENFHE_EXACT_VERSION,
            ),
            BackendKind::TfheRs => (
                encompute_exact::research::TFHE_RS_BACKEND,
                encompute_exact::research::TFHE_RS_VERSION,
            ),
        }
    }

    pub fn supports(self, s: Semantics) -> bool {
        match self {
            BackendKind::Mock => true,
            BackendKind::OpenFhe => s == Semantics::Approximate,
            BackendKind::OpenFheExact | BackendKind::TfheRs => s == Semantics::Exact,
        }
    }

    /// Whether this build includes the backend.
    pub fn built(self) -> bool {
        match self {
            BackendKind::Mock => true,
            BackendKind::OpenFhe | BackendKind::OpenFheExact => cfg!(feature = "openfhe"),
            BackendKind::TfheRs => cfg!(feature = "research-tfhe-rs"),
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
                        "BACKEND UNAVAILABLE: TFHE-rs is available only in research builds (the \
                         `research-tfhe-rs` feature); production exact programs run on OpenFHE \
                         exact"
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
            // Never TFHE-rs: a research build must ask for it.
            exact: if BackendKind::OpenFheExact.built() {
                BackendKind::OpenFheExact
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
            BackendKind::OpenFheExact | BackendKind::TfheRs => Self { exact: k, ..self },
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
            // BGV exact programs: any OpenFHE evaluator runs them.
            (CompiledProgram::Exact(_), BackendKind::OpenFhe) => {
                if self.approx == BackendKind::OpenFhe || self.exact == BackendKind::OpenFheExact {
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
            (Mock, OpenFheExact),
            (OpenFhe, OpenFheExact),
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
    #[cfg(feature = "research-tfhe-rs")]
    TfheRs(encompute_tfhe::tfhe_rs::TfheRsEvaluator),
    #[cfg(feature = "openfhe")]
    Bgv(encompute_openfhe::BgvEvaluator),
    /// Shared: concurrent jobs run their circuits on the same keys.
    #[cfg(feature = "openfhe")]
    OpenFheExact(std::sync::Arc<encompute_openfhe_exact::OpenFheGates>),
}

/// A job's hold on its keys. OpenFHE exact keys are shared read-only, so
/// concurrent jobs do not wait for each other; other backends run one job
/// at a time per key.
enum Held<'a> {
    #[cfg(feature = "openfhe")]
    Shared(Keyed),
    Locked(std::sync::MutexGuard<'a, Keyed>),
}

impl<'a> Held<'a> {
    fn of(entry: &'a std::sync::Mutex<Keyed>) -> Self {
        let guard = entry.lock().unwrap_or_else(|p| p.into_inner());
        #[cfg(feature = "openfhe")]
        if let Keyed::OpenFheExact(g) = &*guard {
            return Held::Shared(Keyed::OpenFheExact(g.clone()));
        }
        Held::Locked(guard)
    }
}

impl std::ops::Deref for Held<'_> {
    type Target = Keyed;
    fn deref(&self) -> &Keyed {
        match self {
            #[cfg(feature = "openfhe")]
            Held::Shared(k) => k,
            Held::Locked(g) => g,
        }
    }
}

/// This process's evaluation-key cache counters.
pub fn key_cache_stats() -> crate::keycache::CacheStats {
    key_cache().stats()
}

/// This process's evaluation keys (see [`crate::keycache`]).
fn key_cache() -> &'static crate::keycache::KeyCache<std::sync::Mutex<Keyed>> {
    static C: std::sync::OnceLock<crate::keycache::KeyCache<std::sync::Mutex<Keyed>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| crate::keycache::KeyCache::new(crate::keycache::max_bytes_from_env()))
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
    /// The key IDs registered with this session. The loaded keys live in the
    /// process cache (shared, bounded); a session only uses keys registered
    /// with it.
    registered: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Exact programs on a bit-level backend: the optimized execution plan
    /// (a gate DAG), unless the reference execution is configured.
    circuit: Option<std::sync::Arc<encompute_exact::circuit::Circuit>>,
}

/// Whether exact programs run instruction by instruction on the reference
/// circuits (`ENCOMPUTE_EXACT_EXECUTION=reference`), not optimized.
pub fn reference_execution() -> bool {
    std::env::var("ENCOMPUTE_EXACT_EXECUTION").as_deref() == Ok("reference")
}

/// The declared ranges of `program`'s inputs, in plan order.
pub fn input_ranges(
    program: &Program,
    plan: &ExactPlan,
) -> Vec<Option<encompute_exact::circuit::Interval>> {
    plan.inputs
        .iter()
        .map(|i| {
            program
                .inputs()
                .find(|(_, n, _, _)| *n == i.name)
                .map(|(_, _, _, r)| (r.lo.ceil() as i128, r.hi.floor() as i128))
        })
        .collect()
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
        if kind == BackendKind::OpenFheExact {
            if let Some(e) = compiled.exact() {
                encompute_exact::bits::check_capabilities(&e.plan)?;
            }
        }
        let ids = Ids::of(&program, &compiled);
        let spec = execution_spec(&ids, &compiled, kind);
        let transcript_hash = transcript_for(&compiled, &spec).map(|t| t.id().hex());
        let circuit = match (kind, compiled.exact()) {
            (BackendKind::OpenFheExact, Some(e)) if !reference_execution() => {
                Some(std::sync::Arc::new(encompute_exact::circuit::optimize(
                    &e.plan,
                    &input_ranges(&program, &e.plan),
                    crate::budget::job_workers() as u32,
                )?))
            }
            _ => None,
        };
        Ok(Self {
            program,
            compiled,
            ids,
            spec,
            transcript_hash,
            kind,
            registered: Default::default(),
            circuit,
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

    /// Where this session's keys live in the cache: OpenFHE exact keys do
    /// not depend on the program (shared by all programs); other backends'
    /// keys are specific to the program's parameters.
    fn cache_key(&self, key_id: &str) -> crate::keycache::CacheKey {
        crate::keycache::CacheKey {
            backend: self.kind.name(),
            scope: if self.kind == BackendKind::OpenFheExact {
                String::new()
            } else {
                self.ids.program_id.clone()
            },
            key_id: key_id.to_owned(),
        }
    }

    pub fn has_key(&self, key_id: &str) -> bool {
        self.registered().contains(key_id) && key_cache().contains(&self.cache_key(key_id))
    }

    fn registered(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<String>> {
        self.registered.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn expect(&self, kind: Kind, program_id: Option<&'static str>) -> Expect<'_> {
        let (backend, backend_version) = self.kind.label();
        Expect {
            governance_id: None,
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
    pub fn register_keys(&self, bytes: &[u8]) -> Result<String> {
        let env = open(bytes, &self.expect(Kind::EvaluationKeys, None))?;
        let key_id = sha256_hex(&env.payload);
        if env.header.key_id.as_deref() != Some(key_id.as_str()) {
            return Err(Error::new(
                Code::WrongKey,
                "key ID does not match the key material",
            ));
        }
        key_cache().get_or_load(self.cache_key(&key_id), bytes.len() as u64, || {
            self.load_keys(&env.payload).map(std::sync::Mutex::new)
        })?;
        self.registered().insert(key_id.clone());
        Ok(key_id)
    }

    fn load_keys(&self, payload: &[u8]) -> Result<Keyed> {
        Ok(match (&self.compiled, self.kind) {
            (CompiledProgram::Approx(c), BackendKind::Mock) => Keyed::Mock(MockEvaluator::new(
                &c.params,
                payload,
                MockConfig::default(),
            )?),
            #[cfg(feature = "openfhe")]
            (CompiledProgram::Approx(c), BackendKind::OpenFhe) => {
                let mut ev = encompute_openfhe::OpenFheEvaluator::new(&c.params)?;
                ev.load_keys(payload)?;
                Keyed::OpenFhe(ev)
            }
            (CompiledProgram::Exact(_), BackendKind::Mock) => {
                Keyed::ExactMock(PlainExactEvaluator::new(payload)?)
            }
            #[cfg(feature = "openfhe")]
            (CompiledProgram::Exact(e), BackendKind::OpenFhe) => {
                let mut ev = encompute_openfhe::BgvEvaluator::new(
                    encompute_exact::bgv::mult_depth(&e.plan),
                )?;
                ev.load_keys(payload)?;
                Keyed::Bgv(ev)
            }
            #[cfg(feature = "research-tfhe-rs")]
            (CompiledProgram::Exact(_), BackendKind::TfheRs) => {
                Keyed::TfheRs(encompute_tfhe::tfhe_rs::TfheRsEvaluator::new(payload)?)
            }
            #[cfg(feature = "openfhe")]
            (CompiledProgram::Exact(e), BackendKind::OpenFheExact) => {
                Keyed::OpenFheExact(std::sync::Arc::new(
                    encompute_openfhe_exact::OpenFheGates::new(&e.profile, payload)?,
                ))
            }
            _ => unreachable!("backend checked in new()"),
        })
    }

    /// The optimized execution plan, if this session runs one.
    pub fn circuit(&self) -> Option<&encompute_exact::circuit::Circuit> {
        self.circuit.as_deref()
    }

    /// Execute an inputs envelope; returns the outputs envelope. Exact
    /// programs on OpenFHE exact run their optimized circuit.
    pub fn execute(&self, bytes: &[u8]) -> Result<(Vec<u8>, ExecTimes)> {
        self.execute_with(bytes, &mut NoopObserver, true)
    }

    /// [`EvaluatorSession::execute`], reporting each step of an exact plan
    /// to `observer` (CKKS plans are not observed yet).
    pub fn execute_observed(
        &self,
        bytes: &[u8],
        observer: &mut dyn ExecutionObserver,
    ) -> Result<(Vec<u8>, ExecTimes)> {
        // Observers follow the plan instruction by instruction: the
        // reference execution.
        self.execute_with(bytes, observer, false)
    }

    fn execute_with(
        &self,
        bytes: &[u8],
        observer: &mut dyn ExecutionObserver,
        optimized: bool,
    ) -> Result<(Vec<u8>, ExecTimes)> {
        let _ = optimized; // only bit-level backends have an optimized path
        let env = Envelope::decode(bytes)?;
        let mut expect = self.expect(Kind::Inputs, None);
        expect.program_id = Some(&self.ids.program_id);
        env.check(&expect)?;
        let key_id = env
            .header
            .key_id
            .clone()
            .ok_or_else(|| Error::new(Code::WrongKey, "inputs carry no key ID"))?;
        let entry = self
            .registered()
            .contains(&key_id)
            .then(|| key_cache().get(&self.cache_key(&key_id)))
            .flatten()
            .ok_or_else(|| {
                Error::new(
                    Code::WrongKey,
                    "no evaluation keys are registered for this key ID",
                )
            })?;
        let held = Held::of(&entry);
        let keyed: &Keyed = &held;
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
            #[cfg(feature = "research-tfhe-rs")]
            (Keyed::TfheRs(ev), CompiledProgram::Exact(e)) => {
                run_exact(ev, &e.plan, &items, &self.context(), observer)?
            }
            #[cfg(feature = "openfhe")]
            (Keyed::OpenFheExact(gates), CompiledProgram::Exact(e)) => match &self.circuit {
                Some(c) if optimized => {
                    let permit = crate::budget::acquire(crate::budget::job_workers());
                    let t = Instant::now();
                    let inputs: Vec<(encompute_ir::Elem, &[u8])> = e
                        .plan
                        .inputs
                        .iter()
                        .zip(&items)
                        .map(|(i, (_, b))| (i.elem, *b))
                        .collect();
                    let outs = gates.run_circuit(c, &inputs, permit.threads)?;
                    let times = ExecTimes {
                        evaluate: t.elapsed(),
                        ..ExecTimes::default()
                    };
                    let named = e
                        .plan
                        .outputs
                        .iter()
                        .zip(outs)
                        .map(|(o, b)| (o.name.clone(), b))
                        .collect();
                    (named, times)
                }
                _ => {
                    let ev = encompute_exact::bits::BitEvaluator::new(gates.clone());
                    run_exact(&ev, &e.plan, &items, &self.context(), observer)?
                }
            },
            _ => unreachable!("keys are registered for this session's program"),
        };
        let (backend, backend_version) = self.kind.label();
        let header = Header {
            governance_id: None,
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
