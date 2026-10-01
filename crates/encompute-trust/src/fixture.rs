//! A whole governed cross-agency job, signed by throwaway keys, for tests
//! (the `fixtures` feature): two agencies, a control plane, an evaluator,
//! the job's evidence and the project's log. Nothing here is used outside
//! tests.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;

use encompute_ir::parse;
use encompute_planner::{
    plan_or_fail, BackendCatalog, Infrastructure, PlanningContext, Preferences, Profile,
    ProgramFacts, SourceCustody,
};
use encompute_verification::governance::{
    GovernanceBinding, GovernanceInput, GovernanceOutput, GrantGovernance, ProgramRef, Purpose,
    PurposeMode, ReleaseClass,
};
use encompute_verification::service::{ServiceSigner, JOB_GRANT, JOB_GRANT_V2};
use encompute_verification::{
    hex, EvaluatorSigner, ExecutionReceipt, ExecutionSpec, JobGrant, PolicyId, SPEC_VERSION,
};

use crate::authz::{
    governance_key_id, ApprovalEvidence, AuthorizationLimits, AuthorizationSetId, AuthorizationV2,
    PurposeAcceptance, ReleaseRecord,
};
use crate::governance::{
    AuditEntry, AuditEvidence, AuthorizationCard, AuthorizationEntry, GovernanceAnchors,
    GovernanceEvidence, GovernanceOptions, SharedApproval, GOVERNANCE_EVIDENCE_VERSION,
};
use crate::govlog::{
    hash_hex, kind, revocation_root, root, CheckpointWitness, GovEvent, InclusionProof,
    ProjectCheckpoint, RevocationHead, GOVLOG_VERSION,
};
use crate::report::{Anchors, ReportOptions};
use crate::TrustGraph;

pub const PROJECT: &str = "prj_cross";
pub const JOB: &str = "job_1";
pub const TAX: &str = "tax-agency";
pub const BEN: &str = "benefits-agency";
/// The submitter: an organization whose data the job does not read.
pub const OTHER: &str = "other-co";
/// The signed time of the run: the grant's issue time.
pub const T0: u64 = 1_800_000_000;

pub const PROGRAM: &str = "encompute 0.1
program adult precision 0.001 purpose \"eligibility\"
party \"tax-agency\" \"Tax\"
party \"benefits-agency\" \"Benefits\"
asset \"income\" dataset owners [\"tax-agency\"] readers [\"tax-agency\"] purposes [\"eligibility\"] release allowed_parties
asset \"claims\" dataset owners [\"benefits-agency\"] readers [\"benefits-agency\"] purposes [\"eligibility\"] release allowed_parties
%0 = input \"age\" [0.0, 120.0] asset \"income\" : secret u8
%1 = input \"min\" [0.0, 120.0] asset \"claims\" : secret u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2
";

pub fn h(c: char) -> String {
    c.to_string().repeat(64)
}

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn pk(k: &SigningKey) -> String {
    hex(&k.verifying_key().to_bytes())
}

/// What a test may change before the evidence is signed.
#[derive(Clone, Debug)]
pub struct Knobs {
    /// The authorizations' window.
    pub valid_from: u64,
    pub valid_until: u64,
    /// The people approving each authorization.
    pub approvers: usize,
    pub release_class: ReleaseClass,
    /// Authorization recipients.
    pub recipients: BTreeSet<String>,
    /// Sign a release record of the output.
    pub release_record: bool,
    /// The revocation events of the log, before the heads: (org, kind, refs, at).
    pub revocations: Vec<(String, String, BTreeMap<String, String>, u64)>,
    /// The date of the owners' heads.
    pub head_at: u64,
    pub linkage: bool,
    pub placement: bool,
    pub privacy_policy: bool,
    /// The submitting organization.
    pub submitter: &'static str,
    /// Events of other jobs before the authorizations were issued.
    pub filler: usize,
    /// Events after the owners' heads: (organization, kind, subject).
    pub late: Vec<(String, String, String)>,
    /// Whether the owners sign a head.
    pub heads: bool,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            valid_from: T0 - 1000,
            valid_until: T0 + 86_400,
            approvers: 2,
            release_class: ReleaseClass::BooleanOnly,
            recipients: BTreeSet::from([TAX.to_owned()]),
            release_record: true,
            revocations: vec![],
            head_at: T0 + 50,
            linkage: false,
            placement: false,
            privacy_policy: false,
            submitter: OTHER,
            filler: 0,
            late: vec![],
            heads: true,
        }
    }
}

pub struct Fixture {
    pub graph: TrustGraph,
    pub evidence: GovernanceEvidence,
    pub audit: AuditEvidence,
    pub anchors: GovernanceAnchors,
    pub evaluator: EvaluatorSigner,
    pub control: ServiceSigner,
    pub tax: SigningKey,
    pub ben: SigningKey,
    pub other: SigningKey,
    pub knobs: Knobs,
}

fn context() -> PlanningContext {
    PlanningContext {
        profile: Profile::Standard,
        catalog: BackendCatalog {
            ckks: true,
            tfhe: true,
            openfhe_exact: true,
            bgv: true,
            verified_execution: false,
        },
        infrastructure: Infrastructure {
            tees: vec![],
            key_broker: true,
            host_cloud: true,
            host_region: Some("eu".into()),
        },
        preferences: Preferences::default(),
        facts: ProgramFacts {
            semantics: "exact".into(),
            fhe_supported: true,
            proof_covered: false,
            operations: 1,
            binfhe_ms: None,
            bgv_ms: None,
        },
        training: None,
        custody: vec![
            SourceCustody {
                asset: "income".into(),
                organization: TAX.into(),
                broker: "tax-broker".into(),
            },
            SourceCustody {
                asset: "claims".into(),
                organization: BEN.into(),
                broker: "ben-broker".into(),
            },
        ],
    }
}

fn approval(b: &AuthorizationV2, n: usize) -> ApprovalEvidence {
    let (subject, role) = (
        format!("person-{n}"),
        if n.is_multiple_of(2) {
            "data_owner"
        } else {
            "security_admin"
        },
    );
    ApprovalEvidence {
        statement_digest: b.approval_statement("https://idp.example", &subject, role),
        approver_subject: subject,
        idp_issuer: "https://idp.example".into(),
        auth_time: Some(T0 - 500),
        acr: None,
        amr: None,
        role: role.into(),
        organization: b.party.clone(),
        at: T0 - 400,
    }
}

impl Fixture {
    pub fn build() -> Self {
        Self::with(Knobs::default())
    }

    pub fn with(k: Knobs) -> Self {
        let tax = key(1);
        let ben = key(2);
        let other = key(3);
        let control = ServiceSigner::from_seed("encompute-control", &[9u8; 32]).unwrap();
        let evaluator = EvaluatorSigner::from_seed(&[7; 32]);
        let program = parse(PROGRAM).unwrap();
        let program_text = program.to_string();
        let program_id = crate::program_id(&program_text);
        let c = program.confidentiality().unwrap();
        let policy_id = PolicyId::of(c).hex();

        let purpose = Purpose {
            version: 1,
            project_id: PROJECT.into(),
            name: "eligibility".into(),
            revision: 1,
            description: "decide eligibility".into(),
            legal_basis_ref: Some("act-12".into()),
            modes: BTreeSet::from([PurposeMode::Aggregate]),
            allowed_release_classes: BTreeSet::from([ReleaseClass::BooleanOnly]),
            recipients: BTreeSet::from([TAX.to_owned()]),
            linkage_policy_id: k.linkage.then(|| h('9')),
            min_aggregate_parties: None,
            valid_from: T0 - 5000,
            valid_until: T0 + 100_000,
            created_by_org: TAX.into(),
        };
        let purpose_id = purpose.id().hex();

        let (v_tax, v_ben) = (h('a'), h('b'));
        let binding = GovernanceBinding {
            version: 1,
            project: PROJECT.into(),
            purpose_id: purpose_id.clone(),
            linkage_policy_id: k.linkage.then(|| h('9')),
            inputs: BTreeMap::from([
                (
                    "age".to_owned(),
                    GovernanceInput {
                        asset_version_id: v_tax.clone(),
                        digest_commitment: h('c'),
                        organization: TAX.into(),
                    },
                ),
                (
                    "min".to_owned(),
                    GovernanceInput {
                        asset_version_id: v_ben.clone(),
                        digest_commitment: h('d'),
                        organization: BEN.into(),
                    },
                ),
            ]),
            outputs: BTreeMap::from([(
                "out".to_owned(),
                GovernanceOutput {
                    release_class: ReleaseClass::BooleanOnly,
                    recipients: BTreeSet::from([TAX.to_owned()]),
                },
            )]),
            placement_digest: k.placement.then(|| h('8')),
            project_policy_digest: None,
            asset_brokers: BTreeMap::from([
                (v_tax.clone(), "tax-broker".to_owned()),
                (v_ben.clone(), "ben-broker".to_owned()),
            ]),
        };
        let gov_id = binding.id().hex();
        let plan = plan_or_fail(&program, &context())
            .unwrap()
            .governed(&gov_id);
        let plan_hex = plan.id().unwrap().hex();

        let mut docs = vec![];
        for (org, key_, version, commitment) in
            [(TAX, &tax, &v_tax, h('c')), (BEN, &ben, &v_ben, h('d'))]
        {
            let mut b = AuthorizationV2 {
                version: 2,
                party: org.into(),
                project: PROJECT.into(),
                purpose_id: purpose_id.clone(),
                asset_version_id: version.clone(),
                asset_digest_commitment: commitment,
                program: ProgramRef::Program {
                    program_id: program_id.clone(),
                },
                policy_id: policy_id.clone(),
                privacy_policy_id: k.privacy_policy.then(|| h('7')),
                linkage_policy_id: None,
                release_class: k.release_class,
                recipients: k.recipients.clone(),
                privacy_scope_id: None,
                execution_spec_ids: None,
                limits: AuthorizationLimits {
                    max_executions: Some(10),
                    max_releases: Some(10),
                    ..AuthorizationLimits::default()
                },
                per_job_four_eyes: false,
                valid_from: k.valid_from,
                valid_until: k.valid_until,
                issued_at: T0 - 900,
                nonce: h('e')[..32].to_owned(),
                approvals: vec![],
            };
            b.approvals = (0..k.approvers).map(|n| approval(&b, n)).collect();
            docs.push(b.sign(key_).unwrap());
        }
        let ids: Vec<String> = docs.iter().map(|d| d.id()).collect();
        let set_id = AuthorizationSetId::of(ids.clone())
            .unwrap()
            .hex()
            .to_owned();
        let not_after = k.valid_until.min(purpose.valid_until);
        let gg = GrantGovernance {
            plan_hash: plan_hex.clone(),
            purpose_id: purpose_id.clone(),
            governance_id: gov_id.clone(),
            binding: binding.clone(),
            authorization_set_id: set_id,
            not_after,
        };
        let spec = ExecutionSpec {
            version: SPEC_VERSION,
            program_id: program_id.clone(),
            plan_id: plan_hex.clone(),
            parameter_set_id: h('3'),
            plan_kind: "exact".into(),
            plan_version: 1,
            semantics: "exact".into(),
            scheme: "BinFHE".into(),
            backend: "openfhe-exact".into(),
            backend_version: "1.5.1".into(),
            policy_id: Some(policy_id),
            privacy_policy_id: k.privacy_policy.then(|| h('7')),
            governance_id: None,
        }
        .governed(&binding);
        let mut grant = JobGrant {
            version: JOB_GRANT_V2,
            job_id: JOB.into(),
            organization: k.submitter.into(),
            project: PROJECT.into(),
            plan_id: plan_hex,
            spec_id: spec.id().hex(),
            program_id: program_id.clone(),
            evaluator: "evaluator-1".into(),
            backend: "openfhe-exact".into(),
            profile: "standard".into(),
            issued_at: T0,
            expires_at: T0 + 3600,
            issuer: control.id().to_owned(),
            issuer_public_key: control.public_key_hex(),
            governance: Some(gg),
            signature: String::new(),
        };
        grant.signature = control.sign(JOB_GRANT, &grant.unsigned()).unwrap();
        let receipt = ExecutionReceipt::new(
            &spec,
            None,
            &h('4'),
            b"request",
            b"response",
            &evaluator.identity(),
        )
        .unwrap()
        .with_grant(Some(grant.digest()))
        .sign(&evaluator)
        .unwrap();

        let mut graph = TrustGraph::new();
        graph.add_program(&program_text).unwrap();
        graph.add_plan(plan).unwrap();
        graph.add_execution_receipt(receipt).unwrap();

        let acceptances = [(TAX, &tax), (BEN, &ben)]
            .into_iter()
            .map(|(o, key_)| {
                PurposeAcceptance {
                    version: 1,
                    organization: o.into(),
                    project: PROJECT.into(),
                    purpose_id: purpose_id.clone(),
                    accepted_at: T0 - 100,
                }
                .sign(key_)
                .unwrap()
            })
            .collect();

        let mut release_records = vec![];
        if k.release_record {
            release_records.push(
                ReleaseRecord {
                    version: 1,
                    party: TAX.into(),
                    project: PROJECT.into(),
                    purpose_id: purpose_id.clone(),
                    job_id: JOB.into(),
                    governance_id: gov_id,
                    output: "out".into(),
                    output_commitment: h('5'),
                    derived_version_id: h('6'),
                    release_class: ReleaseClass::BooleanOnly,
                    parents: BTreeSet::from([v_tax, v_ben]),
                    authorization_ids: ids.iter().cloned().collect(),
                    onward_policy_id: h('1'),
                    recipients: BTreeMap::from([(TAX.to_owned(), h('f'))]),
                    lineage_owners: BTreeMap::from([(
                        BEN.to_owned(),
                        governance_key_id(&pk(&ben)),
                    )]),
                    issued_at: T0 + 100,
                }
                .sign(&tax)
                .unwrap(),
            );
        }
        let evidence = GovernanceEvidence {
            version: GOVERNANCE_EVIDENCE_VERSION,
            project: PROJECT.into(),
            job_id: JOB.into(),
            purpose,
            purpose_acceptances: acceptances,
            spec,
            grant,
            authorizations: docs
                .into_iter()
                .map(|d| AuthorizationEntry::Signed {
                    document: Box::new(d),
                })
                .collect(),
            authorization_revocations: vec![],
            release_records,
            submitter: Some("psn_submitter".into()),
        };

        let audit = Self::log(&k, &control, &tax, &ben, &other, &ids, &[TAX, BEN]);
        Self {
            graph,
            evidence,
            audit,
            anchors: GovernanceAnchors {
                organizations: BTreeMap::from([
                    (TAX.to_owned(), pk(&tax)),
                    (BEN.to_owned(), pk(&ben)),
                    (OTHER.to_owned(), pk(&other)),
                ]),
                control_plane: Some(control.public_key_hex()),
            },
            evaluator,
            control,
            tax,
            ben,
            other,
            knobs: k,
        }
    }

    fn event(
        pseq: u64,
        kind_: &str,
        subject: &str,
        org: &str,
        at: u64,
        refs: &[(&str, &str)],
    ) -> GovEvent {
        GovEvent {
            v: GOVLOG_VERSION,
            partition: format!("p:{PROJECT}"),
            pseq,
            kind: kind_.into(),
            subject: subject.into(),
            org: Some(org.into()),
            at,
            refs: refs
                .iter()
                .map(|(a, b)| ((*a).into(), (*b).into()))
                .collect(),
        }
    }

    /// The project's log: the knobs' revocations, then each owner's head,
    /// a checkpoint of all of it and both members' witnesses.
    fn log(
        k: &Knobs,
        control: &ServiceSigner,
        tax: &SigningKey,
        ben: &SigningKey,
        other: &SigningKey,
        ids: &[String],
        parties: &[&str],
    ) -> AuditEvidence {
        let mut events: Vec<GovEvent> = vec![];
        for _ in 0..k.filler {
            events.push(Self::event(
                events.len() as u64 + 1,
                kind::JOB_FAILED,
                "job_other",
                TAX,
                T0 - 100,
                &[],
            ));
        }
        // Each authorization's issuance, in the project's log.
        for (id, party) in ids.iter().zip(parties) {
            events.push(Self::event(
                events.len() as u64 + 1,
                kind::AUTHORIZATION_ISSUED,
                "row",
                party,
                T0 - 900,
                &[("authorization_id", id)],
            ));
        }
        for (org, kind_, refs, at) in &k.revocations {
            let refs: Vec<(&str, &str)> =
                refs.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
            events.push(Self::event(
                events.len() as u64 + 1,
                kind_,
                "subject_1",
                org,
                *at,
                &refs,
            ));
        }
        let mut heads = vec![];
        for (org, key_) in [(TAX, tax), (BEN, ben)].into_iter().filter(|_| k.heads) {
            let leaves = crate::govlog::revocation_leaves(&events, org);
            let head = RevocationHead {
                version: GOVLOG_VERSION,
                organization: org.into(),
                project: PROJECT.into(),
                seq: 1,
                root: hash_hex(&revocation_root(&leaves).unwrap()),
                at: k.head_at,
            }
            .sign(key_)
            .unwrap();
            events.push(Self::event(
                events.len() as u64 + 1,
                kind::REVOCATION_HEAD_SIGNED,
                org,
                org,
                k.head_at,
                &[("seq", "1"), ("root", &head.body.root)],
            ));
            heads.push(head);
        }
        for (org, kind_, subject) in &k.late {
            events.push(Self::event(
                events.len() as u64 + 1,
                kind_,
                subject,
                org,
                T0 + 20,
                &[],
            ));
        }
        let leaves: Vec<_> = events.iter().map(|e| e.leaf_hash().unwrap()).collect();
        let partition = format!("p:{PROJECT}");
        let cp = ProjectCheckpoint {
            version: GOVLOG_VERSION,
            partition: partition.clone(),
            size: leaves.len() as u64,
            root: hash_hex(&root(&leaves)),
            gseq: leaves.len() as u64,
            at: T0 + 60,
        }
        .sign(control)
        .unwrap();
        let witnesses = [(TAX, tax), (BEN, ben), (OTHER, other)]
            .into_iter()
            .map(|(o, key_)| {
                CheckpointWitness {
                    version: GOVLOG_VERSION,
                    organization: o.into(),
                    partition: partition.clone(),
                    size: cp.body.size,
                    root: cp.body.root.clone(),
                    at: T0 + 70,
                }
                .sign(key_)
                .unwrap()
            })
            .collect();
        AuditEvidence {
            version: GOVERNANCE_EVIDENCE_VERSION,
            project: PROJECT.into(),
            checkpoint: Some(cp),
            members: vec![BEN.into(), OTHER.into(), TAX.into()],
            witnesses,
            events: events
                .iter()
                .enumerate()
                .map(|(i, e)| AuditEntry {
                    event: e.clone(),
                    proof: InclusionProof::from_leaves(&partition, &leaves, i as u64).unwrap(),
                })
                .collect(),
            revocation_heads: heads,
        }
    }

    pub fn options(&self) -> GovernanceOptions<'static> {
        GovernanceOptions {
            base: ReportOptions {
                anchors: Anchors {
                    evaluators: [self.evaluator.identity().public_key_hex()].into(),
                    ..Anchors::default()
                },
                now: Some(T0 + 10),
                ..ReportOptions::default()
            },
            anchors: self.anchors.clone(),
            as_of: None,
            now: Some(T0 + 10),
            disclosures: vec![],
        }
    }

    /// The evidence as a participant sees it: a card for every signed
    /// authorization.
    pub fn shared(&self) -> GovernanceEvidence {
        let mut ev = self.evidence.clone();
        ev.authorizations = ev
            .authorizations
            .iter()
            .map(|e| match e {
                AuthorizationEntry::Signed { document } => {
                    let mut body = document.body.clone();
                    let approvals = body
                        .approvals
                        .drain(..)
                        .map(|a| SharedApproval {
                            organization: a.organization,
                            role: a.role,
                            at: a.at,
                            approver: format!("psn_{}", hex(a.approver_subject.as_bytes())),
                        })
                        .collect();
                    AuthorizationEntry::Card {
                        card: Box::new(AuthorizationCard {
                            id: document.id(),
                            governance_key_id: governance_key_id(&document.public_key),
                            body,
                            approvals,
                        }),
                    }
                }
                other => other.clone(),
            })
            .collect();
        ev
    }

    /// The signed documents of the evidence (what an owner discloses).
    pub fn documents(&self) -> Vec<crate::authz::SignedAuthorizationV2> {
        self.evidence
            .authorizations
            .iter()
            .filter_map(|e| match e {
                AuthorizationEntry::Signed { document } => Some((**document).clone()),
                _ => None,
            })
            .collect()
    }
}
