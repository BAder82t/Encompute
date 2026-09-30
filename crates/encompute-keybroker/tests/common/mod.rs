//! A governed world for key-broker tests: one owner organization
//! (`tax-agency`) with its broker, governance key and one source version,
//! the control plane that issues tickets, and a scheduled evaluator.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;

use encompute_attestation::mock::{MockHardware, MockProvider};
use encompute_attestation::{
    AttestationEvidence, AttestationPolicy, Attester, EncryptedKeyGrant, KeyReleaseReceipt,
    TeeKind, Verifier, WorkloadSession,
};
use encompute_ir::Result;
use encompute_keybroker::{
    BrokerMode, DevelopmentFileStore, GovernanceConfig, GovernedReleaseRequest, KeyBroker,
    KeyMaterial,
};
use encompute_trust::authz::{AuthorizationV2, SignedAuthorizationV2};
use encompute_verification::governance::{
    GovernanceBinding, GovernanceInput, GovernanceOutput, ProgramRef, ReleaseClass,
};
use encompute_verification::ticket::{ReleaseTicket, TicketKind, TICKET_VERSION};
use encompute_verification::{hex, EvaluatorSigner, ExecutionSpec, ServiceSigner};

pub const T0: u64 = 1_900_000_000;
pub const ORG: &str = "tax-agency";
pub const BROKER: &str = "tax-broker";
pub const ASSET: &str = "income";
pub const PROJECT: &str = "prj_1";
pub const IMAGE: &str = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
pub const ARTIFACT: &str = "33333333333333333333333333333333333333333333333333333333333333cc";
pub const KEY: &[u8] = b"income register key, 32 bytes.."; // any length

pub fn h(c: char) -> String {
    c.to_string().repeat(64)
}

/// The source version the owner registered.
pub fn asset_version() -> String {
    h('3')
}

pub fn policy_id() -> String {
    h('d')
}

pub fn hw() -> MockHardware {
    MockHardware::from_seed(&[7; 32])
}

pub fn verifier() -> Verifier {
    Verifier::new().with(MockProvider::new(&hw().public_key()).unwrap())
}

pub fn control() -> ServiceSigner {
    ServiceSigner::from_seed("control-plane", &[42; 32]).unwrap()
}

pub fn governance_key() -> SigningKey {
    SigningKey::from_bytes(&[21; 32])
}

pub fn rogue_governance_key() -> SigningKey {
    SigningKey::from_bytes(&[22; 32])
}

pub fn governance_public_key() -> String {
    hex(&governance_key().verifying_key().to_bytes())
}

pub fn binding() -> GovernanceBinding {
    GovernanceBinding {
        version: 1,
        project: PROJECT.into(),
        purpose_id: h('1'),
        linkage_policy_id: None,
        inputs: BTreeMap::from([(
            "income".into(),
            GovernanceInput {
                asset_version_id: asset_version(),
                digest_commitment: h('4'),
                organization: ORG.into(),
            },
        )]),
        outputs: BTreeMap::from([(
            "eligible".into(),
            GovernanceOutput {
                release_class: ReleaseClass::BooleanOnly,
                recipients: BTreeSet::from(["benefits-agency".into()]),
            },
        )]),
        placement_digest: None,
        project_policy_digest: None,
    }
}

pub fn spec_for(binding: &GovernanceBinding) -> ExecutionSpec {
    ExecutionSpec {
        version: 1,
        program_id: h('a'),
        plan_id: h('b'),
        parameter_set_id: h('c'),
        plan_kind: "exact".into(),
        plan_version: 1,
        semantics: "exact".into(),
        scheme: "BinFHE".into(),
        backend: "openfhe-exact".into(),
        backend_version: "1.5.1".into(),
        policy_id: Some(policy_id()),
        privacy_policy_id: None,
        governance_id: None,
    }
    .governed(binding)
}

/// The owner's authorization of this program, for this version, purpose
/// and project, valid for an hour from `T0 - 100`.
pub fn authorization() -> AuthorizationV2 {
    AuthorizationV2 {
        version: 2,
        party: ORG.into(),
        project: PROJECT.into(),
        purpose_id: h('1'),
        asset_version_id: asset_version(),
        asset_digest_commitment: h('4'),
        program: ProgramRef::Program { program_id: h('a') },
        policy_id: policy_id(),
        privacy_policy_id: None,
        linkage_policy_id: None,
        release_class: ReleaseClass::BooleanOnly,
        recipients: BTreeSet::from(["benefits-agency".into()]),
        privacy_scope_id: None,
        execution_spec_ids: None,
        limits: Default::default(),
        per_job_four_eyes: false,
        valid_from: T0 - 100,
        valid_until: T0 + 3600,
        issued_at: T0 - 200,
        nonce: "ab".repeat(16),
        approvals: vec![],
    }
}

pub fn signed(a: AuthorizationV2) -> SignedAuthorizationV2 {
    a.sign(&governance_key()).unwrap()
}

pub fn release_policy(spec: &ExecutionSpec) -> AttestationPolicy {
    let mut p = AttestationPolicy::new(&spec.id().hex(), spec.policy_id.as_deref());
    p.allowed_tee = vec![TeeKind::Mock];
    p.allowed_images = vec![IMAGE.into()];
    p.allow_development = true;
    p
}

pub struct World {
    pub broker: KeyBroker,
    pub clock: Arc<AtomicU64>,
    pub evaluator: EvaluatorSigner,
    pub binding: GovernanceBinding,
    pub spec: ExecutionSpec,
    pub authorization: SignedAuthorizationV2,
}

/// A bare development broker for `ORG` holding `ASSET` under the governed
/// spec's release policy (not yet bound, pinned or authorized).
pub fn bare_broker(clock: &Arc<AtomicU64>, spec: &ExecutionSpec) -> KeyBroker {
    let c = clock.clone();
    let mut b = KeyBroker::new(
        BROKER,
        BrokerMode::Development,
        verifier(),
        Box::new(DevelopmentFileStore),
    )
    .unwrap()
    .with_clock(move || c.load(Ordering::SeqCst));
    b.set_organization(ORG).unwrap();
    b.add_secret(
        ASSET,
        Some(KeyMaterial::from_bytes(KEY).unwrap()),
        release_policy(spec),
    )
    .unwrap();
    b
}

pub fn governance() -> GovernanceConfig {
    GovernanceConfig {
        control_key: control().public_key_hex(),
        require_ticket: true,
    }
}

/// A governed broker: the version bound, the owner's governance key
/// pinned, the control plane's key configured and `authorization`
/// installed.
pub fn world_with(binding: GovernanceBinding, authorization: AuthorizationV2) -> World {
    let clock = Arc::new(AtomicU64::new(T0));
    let spec = spec_for(&binding);
    let mut broker = bare_broker(&clock, &spec)
        .with_governance(governance())
        .unwrap();
    broker.bind_version(ASSET, &asset_version()).unwrap();
    broker.pin_governance_key(&governance_public_key()).unwrap();
    let authorization = signed(authorization);
    broker.install_authorization(&authorization).unwrap();
    World {
        broker,
        clock,
        evaluator: EvaluatorSigner::from_seed(&[9; 32]),
        binding,
        spec,
        authorization,
    }
}

pub fn world() -> World {
    world_with(binding(), authorization())
}

impl World {
    pub fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    pub fn set_now(&self, t: u64) {
        self.clock.store(t, Ordering::SeqCst)
    }

    pub fn session(&self) -> WorkloadSession {
        WorkloadSession::new(&self.evaluator.identity())
    }

    pub fn evaluator_key(&self) -> String {
        self.evaluator.identity().public_key_hex()
    }

    pub fn authorization_id(&self) -> String {
        self.authorization.id()
    }

    /// Evidence for `session`, issued at `issued_at`, for the governed
    /// spec.
    pub fn evidence_at(
        &mut self,
        session: &WorkloadSession,
        issued_at: u64,
    ) -> AttestationEvidence {
        let c = self.broker.challenge().unwrap();
        let b = session.binding(
            &c,
            &self.spec.id().hex(),
            self.spec.policy_id.as_deref(),
            ARTIFACT,
        );
        hw().attester(IMAGE)
            .issued_at(issued_at)
            .attest(&c, &b)
            .unwrap()
    }

    /// An attested session (the broker's handle for it).
    pub fn attest(&mut self, session: &WorkloadSession) -> String {
        let e = self.evidence_at(session, self.now());
        self.broker.verify_attestation(&e).unwrap().session
    }

    /// A ticket for this job's release of the source to the evaluator,
    /// valid from now for 300 seconds, unsigned.
    pub fn ticket_body(&self) -> ReleaseTicket {
        let now = self.now();
        ReleaseTicket {
            version: TICKET_VERSION,
            ticket_id: ReleaseTicket::new_ticket_id().unwrap(),
            kind: TicketKind::KeyRelease,
            organization: ORG.into(),
            broker: BROKER.into(),
            asset_version_id: asset_version(),
            authorization_ids: BTreeSet::from([self.authorization_id()]),
            job_id: "job_1".into(),
            project: self.binding.project.clone(),
            purpose_id: self.binding.purpose_id.clone(),
            governance_id: self.binding.id().hex(),
            plan_id: h('6'),
            execution_spec_id: self.spec.id().hex(),
            policy_id: self.spec.policy_id.clone(),
            workload_or_recipient: self.evaluator_key(),
            placement_digest: self.binding.placement_digest.clone(),
            execution_spec: self.spec.clone(),
            binding: self.binding.clone(),
            not_before: now,
            not_after: now + 300,
            anchor_counter: 1,
            issuer: String::new(),
            issuer_public_key: String::new(),
            signature: String::new(),
        }
    }

    pub fn ticket(&self) -> ReleaseTicket {
        self.ticket_body().sign(&control()).unwrap()
    }

    pub fn request(&self, session: &str, ticket: Option<ReleaseTicket>) -> GovernedReleaseRequest {
        GovernedReleaseRequest {
            session: session.into(),
            asset_id: ASSET.into(),
            authorization_id: self.authorization_id(),
            ticket,
            execution_spec: None,
            binding: None,
        }
    }

    /// Prepare and finish (the persistence step is the caller's).
    pub fn release(
        &mut self,
        req: &GovernedReleaseRequest,
    ) -> Result<(EncryptedKeyGrant, KeyReleaseReceipt)> {
        let p = self.broker.prepare_governed_release(req)?;
        self.broker.finish_release(p)
    }

    /// A fresh session, attested now, released with a fresh ticket.
    pub fn release_fresh(&mut self) -> Result<(EncryptedKeyGrant, KeyReleaseReceipt)> {
        let s = self.session();
        let handle = self.attest(&s);
        let req = self.request(&handle, Some(self.ticket()));
        self.release(&req)
    }
}
