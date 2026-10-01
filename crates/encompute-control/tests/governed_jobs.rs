//! Jobs in governed projects (public-sector governance, phase 3): a job
//! names its purpose and its outputs' releases, and runs only under an
//! active, owner-signed authorization for every source (the submitter's own
//! included) that covers its program, policy, linkage and recipients. The
//! control plane binds the governance into the job's execution spec at
//! submission, signs a version 2 grant capped at the end of every window,
//! re-checks validity at scheduling and start (strictly, on its own
//! clock), fails a job whose authorization is revoked before it starts, and
//! accepts completion only with a version 4 receipt naming the job's own
//! grant. A job that started inside its window may complete after it.
//! A job under an authorization that asks for per-job four eyes waits
//! until every such owner's quorum of its own people (never the job's
//! submitter) approves the job, its spec and its authorization set.
//! Standard projects behave as before.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use common::*;
use encompute_control::authn::DEV_ISSUER;
use encompute_trust::authz::{
    job_approval_statement, AuthorizationSetId, AuthorizationV2, PurposeAcceptance,
};
use encompute_verification::governance::{ProgramRef, ReleaseClass};
use encompute_verification::service::JobGrant;
use encompute_verification::{
    hex, output_commitment, request_commitment, ExecutionReceipt, ExecutionSpec, ServiceSigner,
};

const TAX: &str = "tax-agency";
const BEN: &str = "benefits-agency";
/// A third member of the project, named by no authorization.
const OTHER: &str = "other-co";
const PURPOSE: &str = "benefits-eligibility";
const KEY_ID: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

fn now() -> u64 {
    encompute_verification::service::now()
}

/// Waits until the clock has passed second `t`.
fn after(t: u64) {
    while now() <= t {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

/// Asserts `(status, body)` is a refusal with `c`.
fn refused(r: (u16, Value), c: &str) {
    assert!(r.0 >= 400, "expected {c}, got {} {}", r.0, r.1);
    assert_eq!(code(&r.1), c, "{} {}", r.0, r.1);
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(k: &SigningKey) -> String {
    hex(&k.verifying_key().to_bytes())
}

struct G {
    t: T,
    tax_admin: As,
    tax_sec1: As,
    tax_sec2: As,
    tax_owner: As,
    tax_dev: As,
    ben_dev: As,
    other_dev: As,
    evaluator: Evaluator,
    project: String,
    tax_key: SigningKey,
    /// The active purpose (recipients: benefits and tax).
    purpose: String,
}

fn broker_account(t: &T, admin: &As, org: &str, id: &str, seed: u8) {
    let s = ServiceSigner::from_seed(id, &[seed; 32]).unwrap();
    t.ok(
        admin,
        "POST",
        &format!("/v1/organizations/{org}/service-accounts"),
        Some(
            json!({"id": id, "kind": "keybroker", "public_key": s.public_key_hex(),
                    "url": format!("http://{id}.internal:8760")}),
        ),
    );
}

/// Tax (the source owner) and benefits (the submitter and recipient) in a
/// governed project; tax has its own key broker, an active governance key
/// and an active purpose it accepted.
fn world() -> Option<G> {
    let t = setup()?;
    t.control
        .bootstrap(DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let platform = As::User("platform-admin".into());
    for (org, admin) in [(TAX, "t-admin"), (BEN, "b-admin"), (OTHER, "o-admin")] {
        t.ok(
            &platform,
            "POST",
            "/v1/organizations",
            Some(json!({"id": org, "display_name": org, "admin": {"issuer": DEV_ISSUER, "subject": admin}})),
        );
    }
    let tax_admin = As::User("t-admin".into());
    let ben_admin = As::User("b-admin".into());
    let tax_sec1 = user(&t, &tax_admin, TAX, "t-sec1", &["security_admin"]);
    let tax_sec2 = user(&t, &tax_admin, TAX, "t-sec2", &["security_admin"]);
    let tax_owner = user(&t, &tax_admin, TAX, "t-owner", &["data_owner"]);
    let tax_dev = user(&t, &tax_admin, TAX, "t-dev", &["ml_developer"]);
    let ben_dev = user(&t, &ben_admin, BEN, "b-dev", &["ml_developer"]);
    let other_admin = As::User("o-admin".into());
    let other_dev = user(&t, &other_admin, OTHER, "o-dev", &["ml_developer"]);
    let evaluator = common::evaluator(
        &t,
        &platform,
        "evaluator-1",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    broker_account(&t, &tax_admin, TAX, "tax-broker", 31);
    let (s, v) = t.call(
        &tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/key-brokers"),
        Some(json!({"id": "tax-broker", "grant_public_key": pk(&key(41)),
                    "provider_kind": "openbao-transit", "key_ref_namespace": "transit/tax"})),
    );
    assert_eq!(s, 201, "{v}");
    let p = t.ok(
        &tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "benefits-eligibility",
                    "governance": "governed", "organizations": [BEN, OTHER]})),
    );
    let project = p["id"].as_str().unwrap().to_owned();
    t.ok(
        &ben_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": BEN})),
    );
    t.ok(
        &other_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": OTHER})),
    );
    let mut g = G {
        t,
        tax_admin,
        tax_sec1,
        tax_sec2,
        tax_owner,
        tax_dev,
        ben_dev,
        other_dev,
        evaluator,
        project,
        tax_key: key(7),
        purpose: String::new(),
    };
    g.governance_key();
    g.purpose = g.purpose(PURPOSE, now() + 10_000);
    Some(g)
}

/// A program over tax's registered assets `assets`, declaring `purpose`,
/// released to `to`.
fn program(assets: &[&str], purpose: &str, to: &str) -> String {
    let mut p = format!(
        "encompute 0.1\nprogram adult precision 0.001 purpose \"{purpose}\"\n\
         party \"{TAX}\" \"Tax\"\nparty \"{BEN}\" \"Benefits\"\n"
    );
    for a in assets {
        p.push_str(&format!(
            "asset \"{a}\" dataset owners [\"{TAX}\"] readers [\"{BEN}\", \"{TAX}\"] purposes \
             [\"{purpose}\"] release allowed_parties\n"
        ));
    }
    for (i, a) in assets.iter().enumerate() {
        p.push_str(&format!(
            "%{i} = input \"x{i}\" [0.0, 120.0] asset \"{a}\" : secret u8\n"
        ));
    }
    let n = assets.len();
    p.push_str(&format!(
        "%{n} = const [18.0] : public u8\n%{} = ge %0, %{n} : secret bool\noutput \"out\" = %{} to \"{to}\"\n",
        n + 1,
        n + 1
    ));
    p
}

/// The execution spec of `program` before any governance binding.
fn base_spec(program: &str) -> ExecutionSpec {
    let p = encompute_ir::parse(program).unwrap();
    let c = encompute_evaluator::compile_program(&p).unwrap();
    encompute_evaluator::execution_spec(
        &encompute_evaluator::Ids::of(&p, &c),
        &c,
        c.target_backend(),
    )
}

fn transcript(program: &str, spec: &ExecutionSpec) -> Option<String> {
    let p = encompute_ir::parse(program).unwrap();
    let c = encompute_evaluator::compile_program(&p).unwrap();
    encompute_evaluator::transcript_for(&c, spec).map(|t| t.id().hex())
}

/// A dataset version of tax's income series, its key at tax's broker.
#[derive(Clone)]
struct Version {
    asset: String,
    version: String,
}

/// An authorization as proposed (edited by the test before proposing).
struct Auth {
    row: String,
    id: String,
}

impl G {
    fn governance_key(&self) -> String {
        let v = self.t.ok(
            &self.tax_admin,
            "POST",
            &format!("/v1/organizations/{TAX}/governance-keys"),
            Some(
                json!({"public_key": pk(&self.tax_key), "kms_key_ref": "vault:transit/governance"}),
            ),
        );
        let id = v["id"].as_str().unwrap().to_owned();
        self.t.ok(
            &self.tax_sec1,
            "POST",
            &format!("/v1/organizations/{TAX}/governance-keys/{id}/approve"),
            None,
        );
        id
    }

    /// An active purpose `name` (recipients benefits and tax), accepted by
    /// tax.
    fn purpose(&self, name: &str, valid_until: u64) -> String {
        self.purpose_for(name, valid_until, &[BEN, TAX])
    }

    fn purpose_for(&self, name: &str, valid_until: u64, recipients: &[&str]) -> String {
        let v = self.t.ok(
            &self.tax_sec1,
            "POST",
            &format!("/v1/projects/{}/purposes", self.project),
            Some(json!({"organization": TAX, "name": name,
                        "description": "Eligibility for housing benefit",
                        "modes": ["aggregate"], "allowed_release_classes": ["boolean-only"],
                        "recipients": recipients, "valid_from": now() - 60,
                        "valid_until": valid_until})),
        );
        let purpose = v["id"].as_str().unwrap().to_owned();
        self.t.ok(
            &self.tax_sec2,
            "POST",
            &format!("/v1/purposes/{purpose}/approve"),
            None,
        );
        let acceptance = PurposeAcceptance {
            version: 1,
            organization: TAX.into(),
            project: self.project.clone(),
            purpose_id: purpose.clone(),
            accepted_at: now(),
        }
        .sign(&self.tax_key)
        .unwrap();
        self.t.ok(
            &self.tax_sec2,
            "POST",
            &format!("/v1/purposes/{purpose}/accept"),
            Some(json!({"acceptance": acceptance})),
        );
        purpose
    }

    fn version(&self, label: &str, extra: Value) -> Version {
        let mut b = json!({"organization": TAX, "kind": "dataset", "name": format!("income@{label}"),
                           "series": "income", "version": label,
                           "digest": "c".repeat(64), "project": self.project,
                           "key_ref": {"broker": "tax-broker", "provider": "openbao-transit",
                                       "key_ref": format!("income-{label}"), "key_version": 1}});
        if let (Value::Object(b), Value::Object(r)) = (&mut b, registered(TAX)) {
            b.extend(r);
        }
        if let (Value::Object(b), Value::Object(e)) = (&mut b, extra) {
            b.extend(e);
            b.retain(|_, v| !v.is_null());
        }
        let v = self.t.ok(&self.tax_owner, "POST", "/v1/assets", Some(b));
        Version {
            asset: v["id"].as_str().unwrap().to_owned(),
            version: v["version_id"].as_str().unwrap().to_owned(),
        }
    }

    /// The authorization body tax would sign for `program` over `v`.
    fn body(&self, v: &Version, program: &str) -> AuthorizationV2 {
        let spec = base_spec(program);
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        AuthorizationV2 {
            version: 2,
            party: TAX.into(),
            project: self.project.clone(),
            purpose_id: self.purpose.clone(),
            asset_version_id: v.version.clone(),
            asset_digest_commitment: "d".repeat(64),
            program: ProgramRef::Program {
                program_id: spec.program_id.clone(),
            },
            policy_id: spec.policy_id.clone().unwrap(),
            privacy_policy_id: spec.privacy_policy_id.clone(),
            linkage_policy_id: None,
            release_class: ReleaseClass::BooleanOnly,
            recipients: [BEN.to_string()].into(),
            privacy_scope_id: None,
            execution_spec_ids: None,
            limits: probing_limits(),
            per_job_four_eyes: false,
            valid_from: now() - 30,
            valid_until: now() + 1800,
            issued_at: now(),
            nonce: hex(&nonce),
            approvals: vec![],
        }
    }

    /// Proposed, approved by two people and signed with tax's key.
    fn authorize(&self, body: AuthorizationV2) -> Auth {
        let v = self.t.ok(
            &self.tax_owner,
            "POST",
            "/v1/authorizations",
            Some(json!({"body": body})),
        );
        let row = v["id"].as_str().unwrap().to_owned();
        for (who, role) in [
            (&self.tax_owner, "data_owner"),
            (&self.tax_sec1, "security_admin"),
        ] {
            self.t.ok(
                who,
                "POST",
                &format!("/v1/authorizations/{row}/approve"),
                Some(json!({"role": role})),
            );
        }
        let v = self.t.ok(
            &self.tax_sec1,
            "GET",
            &format!("/v1/authorizations/{row}"),
            None,
        );
        let doc: AuthorizationV2 = serde_json::from_value(v["body"].clone()).unwrap();
        let s = doc.sign(&self.tax_key).unwrap();
        let v = self.t.ok(
            &self.tax_sec1,
            "POST",
            &format!("/v1/authorizations/{row}/signature"),
            Some(json!({"public_key": s.public_key, "signature": s.signature})),
        );
        Auth {
            row,
            id: v["authorization_id"].as_str().unwrap().to_owned(),
        }
    }

    fn plan(&self, who: &As, program: &str) -> String {
        let v = self.t.ok(
            who,
            "POST",
            "/v1/plans",
            Some(json!({"project": self.project, "program": program})),
        );
        v["id"].as_str().unwrap().to_owned()
    }

    /// The governed request: benefits' output to `recipients`.
    fn request(&self, plan: &str, sources: &[&str], recipients: &[&str]) -> Value {
        json!({"project": self.project, "plan": plan, "purpose": PURPOSE,
               "purpose_id": self.purpose, "source_assets": sources, "requested_output": "out",
               "outputs": {"out": {"release_class": "boolean-only", "recipients": recipients}}})
    }

    fn submit(&self, who: &As, body: Value, key: &str) -> (u16, Value) {
        self.t.call_with(
            who,
            "POST",
            "/v1/jobs",
            Some(body),
            &[("Idempotency-Key", key)],
        )
    }

    /// Everything a governed job needs, submitted by benefits: (version,
    /// authorization, program, job view).
    fn job(
        &self,
        label: &str,
        edit: impl FnOnce(&mut AuthorizationV2),
    ) -> (Version, Auth, String, Value) {
        let v = self.version(label, json!({}));
        let program = program(&[&v.asset], PURPOSE, BEN);
        let mut body = self.body(&v, &program);
        edit(&mut body);
        let a = self.authorize(body);
        let plan = self.plan(&self.ben_dev, &program);
        let (s, j) = self.submit(
            &self.ben_dev,
            self.request(&plan, &[&v.asset], &[BEN]),
            &format!("k-{label}"),
        );
        assert_eq!(s, 201, "{j}");
        (v, a, program, j)
    }

    fn view(&self, job: &str) -> Value {
        self.t
            .ok(&self.ben_dev, "GET", &format!("/v1/jobs/{job}"), None)
    }

    fn grant(&self, job: &str) -> JobGrant {
        serde_json::from_value(self.view(job)["grant"].clone()).unwrap()
    }

    fn start(&self, job: &str) -> (u16, Value) {
        self.t.call(
            &self.evaluator.service,
            "POST",
            &format!("/v1/jobs/{job}/start"),
            None,
        )
    }

    /// The evaluator's signed receipt for `program` under `grant_digest`.
    fn receipt(&self, program: &str, spec: &ExecutionSpec, grant_digest: Option<String>) -> Value {
        let r = ExecutionReceipt::new(
            spec,
            transcript(program, spec).as_deref(),
            KEY_ID,
            b"request",
            b"response",
            &self.evaluator.receipt.identity(),
        )
        .unwrap()
        .with_grant(grant_digest)
        .sign(&self.evaluator.receipt)
        .unwrap();
        serde_json::to_value(r).unwrap()
    }

    fn complete(&self, job: &str, receipt: &Value) -> (u16, Value) {
        self.t.call(
            &self.ben_dev,
            "POST",
            &format!("/v1/jobs/{job}/complete"),
            Some(
                json!({"receipt": receipt, "request_commitment": request_commitment(b"request"),
                        "output_commitment": output_commitment(b"response"), "key_id": KEY_ID}),
            ),
        )
    }

    fn state(&self, job: &str) -> String {
        self.view(job)["state"].as_str().unwrap().to_owned()
    }
}

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
}

// --- step 1: submission ------------------------------------------------------------

#[test]
fn submit_under_active_authorizations_binds_governance_id() {
    let Some(g) = world() else { return };
    let (v, a, program, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    assert_eq!(j["state"], "queued", "{j}");
    let grant = g.grant(&job);
    let gov = grant.governance.clone().expect("a governed grant");
    assert_eq!(grant.version, 2);
    // The binding: the purpose, the exact version with the owner's
    // commitment, the output's release, and the source's broker.
    assert_eq!(gov.purpose_id, g.purpose);
    assert_eq!(gov.binding.project, g.project);
    let input = &gov.binding.inputs["x0"];
    assert_eq!(input.asset_version_id, v.version);
    assert_eq!(input.digest_commitment, "d".repeat(64));
    assert_eq!(input.organization, TAX);
    assert_eq!(
        gov.binding.outputs["out"].release_class,
        ReleaseClass::BooleanOnly
    );
    assert_eq!(
        gov.binding.outputs["out"].recipients,
        BTreeSet::from([BEN.to_string()])
    );
    // Keyed by the source version, never by the owner's key reference.
    assert_eq!(gov.binding.asset_brokers[&v.version], "tax-broker");
    assert_eq!(gov.binding.asset_brokers.len(), 1);
    assert_eq!(gov.governance_id, gov.binding.id().hex());
    assert_eq!(
        gov.authorization_set_id,
        AuthorizationSetId::of([a.id.clone()]).unwrap().hex()
    );
    // The job's spec is the plan's under the binding: its ID changes.
    let spec = base_spec(&program).governed(&gov.binding);
    let view = g.view(&job);
    assert_eq!(view["spec_id"], spec.id().hex());
    assert_ne!(view["spec_id"], base_spec(&program).id().hex());
    assert_eq!(view["purpose_id"], g.purpose);
    assert_eq!(view["governance_id"], gov.governance_id);
    // The job's authorizations are recorded, and cannot be edited.
    let mut c = g.t.control.db.conn().unwrap();
    let rows: Vec<String> = c
        .query(
            "SELECT authorization_row FROM job_authorizations WHERE job_id = $1",
            &[&job],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(rows, vec![a.row.clone()]);
    assert!(c
        .execute("DELETE FROM job_authorizations WHERE job_id = $1", &[&job])
        .is_err());
    assert!(c
        .execute(
            "UPDATE jobs SET governance = NULL, purpose_id = NULL WHERE id = $1",
            &[&job]
        )
        .is_err());
    // Benefits sees the source it was authorized to use.
    g.t.ok(&g.ben_dev, "GET", &format!("/v1/assets/{}", v.asset), None);
    // The request's own purpose, outputs and listing are required.
    let plan = g.plan(&g.ben_dev, &program);
    let mut body = g.request(&plan, &[&v.asset], &[BEN]);
    body.as_object_mut().unwrap().remove("outputs");
    let (s, _) = g.submit(&g.ben_dev, body, "no-outputs");
    assert_eq!(s, 400);
    let mut body = g.request(&plan, &[&v.asset], &[BEN]);
    body.as_object_mut().unwrap().remove("purpose_id");
    let (s, _) = g.submit(&g.ben_dev, body, "no-purpose");
    assert_eq!(s, 400);
}

#[test]
fn program_outside_program_set_refused_2703() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let program = program(&[&v.asset], PURPOSE, BEN);
    let mut body = g.body(&v, &program);
    body.program = ProgramRef::ProgramSet {
        program_set_id: encompute_verification::governance::ProgramSetId::of([
            "a".repeat(64),
            "b".repeat(64),
        ])
        .unwrap()
        .hex(),
        programs: BTreeSet::from(["a".repeat(64), "b".repeat(64)]),
    };
    g.authorize(body);
    let plan = g.plan(&g.ben_dev, &program);
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1"),
        "ENC2703",
    );
    // Another confidentiality policy than authorized is the same refusal.
    let mut body = g.body(&v, &program);
    body.policy_id = "b".repeat(64);
    g.authorize(body);
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k2"),
        "ENC2703",
    );
    // An authorization pinned to other execution specs.
    let mut body = g.body(&v, &program);
    body.execution_spec_ids = Some(BTreeSet::from(["e".repeat(64)]));
    g.authorize(body);
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k3"),
        "ENC2703",
    );
    // Refusals are audited.
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action = 'job.denied'",
                &[],
            )
            .unwrap()
            .get(0);
    assert_eq!(n, 3);
}

#[test]
fn purpose_mismatch_refused_2702() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let good = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &good));
    let plan = g.plan(&g.ben_dev, &good);
    // The request's purpose name is not the purpose's.
    let mut body = g.request(&plan, &[&v.asset], &[BEN]);
    body["purpose"] = json!("fraud-detection");
    refused(g.submit(&g.ben_dev, body, "k1"), "ENC2702");
    // The program declares another purpose than the purpose object's name.
    let other = program(&[&v.asset], "fraud-detection", BEN);
    let plan2 = g.plan(&g.ben_dev, &other);
    let mut body = g.request(&plan2, &[&v.asset], &[BEN]);
    body["purpose"] = json!("fraud-detection");
    refused(g.submit(&g.ben_dev, body, "k2"), "ENC2702");
    // A purpose that is not an active purpose of this project.
    let mut body = g.request(&plan, &[&v.asset], &[BEN]);
    body["purpose_id"] = json!("f".repeat(64));
    refused(g.submit(&g.ben_dev, body, "k3"), "ENC2702");
    // A retired purpose is withdrawn.
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{}/retire", g.purpose),
        None,
    );
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k5"),
        "ENC2706",
    );
}

#[test]
fn missing_owner_authorization_refused_2701() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    let plan = g.plan(&g.ben_dev, &p);
    // Proposed and approved, but never signed: not an authorization.
    let body = g.body(&v, &p);
    let r = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": body})),
    );
    let row = id(&r);
    for (who, role) in [
        (&g.tax_owner, "data_owner"),
        (&g.tax_sec1, "security_admin"),
    ] {
        g.t.ok(
            who,
            "POST",
            &format!("/v1/authorizations/{row}/approve"),
            Some(json!({"role": role})),
        );
    }
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1"),
        "ENC2701",
    );
    // An owner's use of its own dataset needs its authorization too.
    let own = program(&[&v.asset], PURPOSE, TAX);
    let plan_own = g.plan(&g.tax_dev, &own);
    refused(
        g.submit(&g.tax_dev, g.request(&plan_own, &[&v.asset], &[TAX]), "k2"),
        "ENC2701",
    );
    // A program reading no registered source runs under no authorization.
    let bare = program(&["not-a-registered-asset"], PURPOSE, BEN);
    let plan_bare = g.plan(&g.ben_dev, &bare);
    refused(
        g.submit(&g.ben_dev, g.request(&plan_bare, &[], &[BEN]), "k3"),
        "ENC2701",
    );
    // No job was created.
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM jobs", &[])
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
}

#[test]
fn recipient_not_in_authorization_refused_2709() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let plan = g.plan(&g.ben_dev, &p);
    // Tax is a recipient the purpose allows, but the owner authorized
    // release to benefits only.
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN, TAX]), "k1"),
        "ENC2709",
    );
    // An organization the purpose does not name.
    refused(
        g.submit(
            &g.ben_dev,
            g.request(&plan, &[&v.asset], &["other-co"]),
            "k2",
        ),
        "ENC2709",
    );
    // A release class the purpose does not allow.
    let mut body = g.request(&plan, &[&v.asset], &[BEN]);
    body["outputs"]["out"]["release_class"] = json!("aggregate-only");
    refused(g.submit(&g.ben_dev, body, "k3"), "ENC2709");
    // Every output of the program is declared.
    let mut body = g.request(&plan, &[&v.asset], &[BEN]);
    body["outputs"] = json!({});
    refused(g.submit(&g.ben_dev, body, "k4"), "ENC2709");
    // Within the authorization it runs.
    let (s, j) = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k5");
    assert_eq!(s, 201, "{j}");
}

#[test]
fn expired_authorization_at_submit_2705() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    let mut body = g.body(&v, &p);
    let until = now() + 3;
    body.valid_until = until;
    g.authorize(body);
    let plan = g.plan(&g.ben_dev, &p);
    after(until);
    // Strict: at valid_until it is over.
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1"),
        "ENC2705",
    );
}

#[test]
fn revoked_governance_key_cascades_2708() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let plan = g.plan(&g.ben_dev, &p);
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let k = keys[0]["id"].as_str().unwrap().to_owned();
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{k}/revoke"),
        None,
    );
    after(now());
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1"),
        "ENC2708",
    );
}

#[test]
fn wrong_version_2704() {
    let Some(g) = world() else { return };
    // A source that is not a dataset version cannot be authorized.
    let a = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "income-unversioned",
                    "digest": "e".repeat(64), "project": g.project,
                    "key_ref": {"broker": "tax-broker", "provider": "openbao-transit",
                                "key_ref": "income-unversioned", "key_version": 1}}),
        ),
    );
    let unversioned = id(&a);
    let p = program(&[&unversioned], PURPOSE, BEN);
    let plan = g.plan(&g.ben_dev, &p);
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&unversioned], &[BEN]), "k1"),
        "ENC2704",
    );
    // An authorization of another version does not cover this one.
    let q1 = g.version("2026-q1", json!({}));
    let q2 = g.version("2026-q2", json!({}));
    let p2 = program(&[&q2.asset], PURPOSE, BEN);
    let mut body = g.body(&q1, &p2);
    body.asset_version_id = q1.version.clone();
    g.authorize(body);
    let plan2 = g.plan(&g.ben_dev, &p2);
    refused(
        g.submit(&g.ben_dev, g.request(&plan2, &[&q2.asset], &[BEN]), "k2"),
        "ENC2701",
    );
}

#[test]
fn standard_project_submit_unchanged() {
    let Some(g) = world() else { return };
    let p = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "statistics"})),
    );
    let standard = id(&p);
    let plan = g.t.ok(
        &g.tax_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": standard, "program": EXACT})),
    );
    let body = json!({"project": standard, "plan": plan["id"], "purpose": "statistics",
                      "source_assets": [], "requested_output": "out"});
    let (s, j) = g.submit(&g.tax_dev, body.clone(), "std-1");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "queued");
    // A version 1 grant, the plan's own spec, nothing governed.
    let grant: JobGrant = serde_json::from_value(j["grant"].clone()).unwrap();
    assert_eq!(grant.version, 1);
    assert!(grant.governance.is_none());
    assert_eq!(j["spec_id"], plan["spec_id"]);
    assert!(j.get("purpose_id").is_none(), "{j}");
    assert!(j.get("governance_id").is_none(), "{j}");
    // A standard job runs and completes with a version 3 receipt.
    g.t.ok(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{}/start", id(&j)),
        None,
    );
    let r = g.receipt(EXACT, &base_spec(EXACT), None);
    let (s, v) = g.t.call(
        &g.tax_dev,
        "POST",
        &format!("/v1/jobs/{}/complete", id(&j)),
        Some(
            json!({"receipt": r, "request_commitment": request_commitment(b"request"),
                    "output_commitment": output_commitment(b"response"), "key_id": KEY_ID}),
        ),
    );
    assert_eq!((s, v["state"].as_str()), (200, Some("succeeded")), "{v}");
    // Governed fields belong to governed projects.
    let mut b = body;
    b["purpose_id"] = json!(g.purpose);
    let (s, _) = g.submit(&g.tax_dev, b, "std-2");
    assert_eq!(s, 400);
}

// --- step 2: scheduling, start and completion ---------------------------------------

#[test]
fn governed_job_runs_end_to_end_with_v2_grant_and_v4_receipt() {
    let Some(g) = world() else { return };
    let (v, a, program, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    let grant = g.grant(&job);
    let gov = grant.governance.clone().unwrap();
    // The evaluator verifies the grant under the pinned control-plane key.
    grant
        .verify(
            &g.t.control.signer.public_key_hex(),
            &g.evaluator.id,
            &grant.program_id,
            now(),
        )
        .unwrap();
    // A release ticket for the real job's source.
    let t = g.t.ok(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/release-ticket"),
        Some(json!({"asset_version_id": v.version})),
    );
    let ticket: encompute_verification::ticket::ReleaseTicket =
        serde_json::from_value(t["ticket"].clone()).unwrap();
    assert_eq!(ticket.governance_id, gov.governance_id);
    assert!(ticket.authorization_ids.contains(&a.id));
    assert!(ticket.not_after <= gov.not_after);
    let spec = base_spec(&program).governed(&gov.binding);
    assert_eq!(ticket.execution_spec_id, spec.id().hex());
    // Start, the evaluator's v4 receipt, the client's completion.
    let s = g.t.ok(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    assert_eq!(s["state"], "running");
    let started: Option<i64> =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT floor(extract(epoch FROM started_at))::bigint FROM jobs WHERE id = $1",
                &[&job],
            )
            .unwrap()
            .get(0);
    assert!(started.is_some());
    let r = g.receipt(&program, &spec, Some(grant.digest()));
    let msg = serde_json::to_value(
        encompute_control::transport::seal(
            &g.evaluator.signer,
            "job.completed",
            "control-plane",
            encompute_control::transport::Scope {
                job: Some(job.clone()),
                ..Default::default()
            },
            &json!({"receipt": r}),
            300,
        )
        .unwrap(),
    )
    .unwrap();
    g.t.ok(&g.evaluator.service, "POST", "/v1/messages", Some(msg));
    assert_eq!(g.state(&job), "verifying");
    let (s, done) = g.complete(&job, &r);
    assert_eq!(s, 200, "{done}");
    assert_eq!(done["state"], "succeeded");
    let tr = g.t.ok(&g.ben_dev, "GET", &format!("/v1/trust/{job}"), None);
    assert_eq!(tr["verdict"], "SATISFIED", "{tr}");
}

#[test]
fn grant_capped_at_not_after() {
    let Some(g) = world() else { return };
    // The authorization's window ends first.
    let until = now() + 900;
    let (_, _, _, j) = g.job("2026-q1", |b| b.valid_until = until);
    let grant = g.grant(&id(&j));
    let gov = grant.governance.unwrap();
    assert_eq!(gov.not_after, until);
    assert_eq!(grant.expires_at, until);
    // The source's deletion date comes first.
    let delete_after = now() + 600;
    let v = g.version("2026-q2", json!({"delete_after": delete_after}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let plan = g.plan(&g.ben_dev, &p);
    let (s, j) = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k2");
    assert_eq!(s, 201, "{j}");
    let grant = g.grant(&id(&j));
    assert_eq!(grant.governance.unwrap().not_after, delete_after);
    assert_eq!(grant.expires_at, delete_after);
    // Otherwise the grant's own lifetime.
    let (_, _, _, j) = g.job("2026-q3", |b| b.valid_until = now() + 9000);
    let grant = g.grant(&id(&j));
    assert_eq!(grant.expires_at, grant.issued_at + 3600);
    assert!(grant.governance.unwrap().not_after > grant.expires_at);
    // A version's deletion date is only brought forward: extending or
    // clearing it is refused, shortening it is not.
    let mut c = g.t.control.db.conn().unwrap();
    for sql in [
        "UPDATE assets SET delete_after = delete_after + 1 WHERE id = $1",
        "UPDATE assets SET delete_after = NULL WHERE id = $1",
    ] {
        let e = c.execute(sql, &[&v.asset]).unwrap_err();
        let m = e
            .as_db_error()
            .map(|d| d.message().to_owned())
            .unwrap_or_default();
        assert!(m.contains("only brought forward"), "{e:?}");
    }
    c.execute(
        "UPDATE assets SET delete_after = delete_after - 60 WHERE id = $1",
        &[&v.asset],
    )
    .unwrap();
    let d: i64 = c
        .query_one("SELECT delete_after FROM assets WHERE id = $1", &[&v.asset])
        .unwrap()
        .get(0);
    assert_eq!(d as u64, delete_after - 60);
    // Only a dataset version has one.
    let (s, _) = g.t.call(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "plain",
                    "digest": "e".repeat(64), "delete_after": now() + 60}),
        ),
    );
    assert_eq!(s, 400);
}

#[test]
fn start_after_valid_until_fails_and_is_anchored_2705() {
    let Some(g) = world() else { return };
    let until = now() + 6;
    let (_, _, _, j) = g.job("2026-q1", |b| b.valid_until = until);
    let job = id(&j);
    assert_eq!(j["state"], "queued");
    after(until);
    refused(g.start(&job), "ENC2705");
    assert_eq!(g.state(&job), "failed");
    assert!(g.t.control.anchor.snapshot().ended_jobs.contains(&job));
    // Scheduling refuses it too: a queued job is re-checked.
    let n: i64 = g
        .t
        .control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'job.failed' AND resource_id = $1",
            &[&job],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1);
}

#[test]
fn revocation_before_start_fails_job_2706() {
    let Some(g) = world() else { return };
    let (_, a, _, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    let r = g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", a.row),
        Some(json!({"reason": "withdrawn"})),
    );
    assert_eq!(r["status"], "revoked");
    // The unstarted job failed with the revocation, anchored.
    let v = g.view(&job);
    assert_eq!(v["state"], "failed", "{v}");
    assert!(g.t.control.anchor.snapshot().ended_jobs.contains(&job));
    let (s, _) = g.start(&job);
    assert_eq!(s, 409);
    // A source revoked behind the job's back is found at start (ENC2706).
    let (v3, _, _, j3) = g.job("2026-q3", |_| {});
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE assets SET status = 'revoked', revoked_at = now() WHERE id = $1",
            &[&v3.asset],
        )
        .unwrap();
    refused(g.start(&id(&j3)), "ENC2706");
    assert_eq!(g.state(&id(&j3)), "failed");
    // A source expired behind the job's back likewise (ENC2705); an
    // expiry through the control plane fails the job at once.
    let (v4, _, _, j4) = g.job("2026-q4", |_| {});
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE assets SET expired_at = now() WHERE id = $1",
            &[&v4.asset],
        )
        .unwrap();
    refused(g.start(&id(&j4)), "ENC2705");
    // A revoked governance key is found at start (ENC2708): the job fails
    // and is anchored as ended.
    let (_, _, _, j2) = g.job("2026-q2", |_| {});
    let job2 = id(&j2);
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let k = keys[0]["id"].as_str().unwrap().to_owned();
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{k}/revoke"),
        None,
    );
    after(now());
    refused(g.start(&job2), "ENC2708");
    assert_eq!(g.state(&job2), "failed");
    assert!(g.t.control.anchor.snapshot().ended_jobs.contains(&job2));
}

#[test]
fn job_started_inside_window_completes_after_it() {
    let Some(g) = world() else { return };
    let until = now() + 6;
    let (_, _, program, j) = g.job("2026-q1", |b| b.valid_until = until);
    let job = id(&j);
    let s = g.t.ok(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    assert_eq!(s["state"], "running");
    after(until);
    let grant = g.grant(&job);
    let spec = base_spec(&program).governed(&grant.governance.clone().unwrap().binding);
    let r = g.receipt(&program, &spec, Some(grant.digest()));
    let (s, v) = g.complete(&job, &r);
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["state"], "succeeded");
    // But no new release ticket after the window (export is blocked).
    let (s, v) = g.t.call(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/release-ticket"),
        Some(json!({"asset_version_id": grant.governance.unwrap().binding.inputs["x0"].asset_version_id})),
    );
    assert!(s >= 400, "{v}");
}

#[test]
fn receipt_without_grant_digest_refused() {
    let Some(g) = world() else { return };
    let (_, _, program, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    g.t.ok(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    let grant = g.grant(&job);
    let spec = base_spec(&program).governed(&grant.governance.clone().unwrap().binding);
    // The evaluator's report of a version 3 receipt is refused.
    let v3 = g.receipt(&program, &spec, None);
    let (s, v) = g.t.call(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/receipt"),
        Some(json!({"receipt": v3})),
    );
    assert!(s >= 400, "{v}");
    assert_eq!(g.state(&job), "running");
    // A receipt for the plan's spec without the binding is refused.
    let bare = g.receipt(&program, &base_spec(&program), Some(grant.digest()));
    let (s, _) = g.t.call(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/receipt"),
        Some(json!({"receipt": bare})),
    );
    assert!(s >= 400);
    // The client's completion with it fails the job.
    let (s, v) = g.complete(&job, &v3);
    assert!(s >= 400, "{v}");
    assert_eq!(code(&v), "ENC1606", "{v}");
    assert_eq!(g.state(&job), "failed");
}

#[test]
fn cross_project_grant_replay_refused() {
    let Some(mut g) = world() else { return };
    let (_, _, prog, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    let (first_project, first_purpose) = (g.project.clone(), g.purpose.clone());
    // A second governed project with its own job over another version.
    let p2 = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "second", "governance": "governed"})),
    );
    g.project = id(&p2);
    g.purpose = g.purpose_for(PURPOSE, now() + 3600, &[TAX]);
    let v2 = g.version("2026-q2", json!({}));
    let p_other = program(&[&v2.asset], PURPOSE, TAX);
    let mut body = g.body(&v2, &p_other);
    body.recipients = [TAX.to_string()].into();
    g.authorize(body);
    let plan2 = g.plan(&g.tax_dev, &p_other);
    let (s, j2) = g.submit(&g.tax_dev, g.request(&plan2, &[&v2.asset], &[TAX]), "x");
    assert_eq!(s, 201, "{j2}");
    let other_grant: JobGrant = serde_json::from_value(
        g.t.ok(&g.tax_dev, "GET", &format!("/v1/jobs/{}", id(&j2)), None)["grant"].clone(),
    )
    .unwrap();
    g.project = first_project;
    g.purpose = first_purpose;
    assert_ne!(other_grant.project, g.project);
    // The first job runs; a receipt naming the other project's grant is
    // refused, as is the other job's spec.
    g.t.ok(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    let grant = g.grant(&job);
    let spec = base_spec(&prog).governed(&grant.governance.clone().unwrap().binding);
    let replayed = g.receipt(&prog, &spec, Some(other_grant.digest()));
    let (s, _) = g.t.call(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/receipt"),
        Some(json!({"receipt": replayed})),
    );
    assert!(s >= 400);
    let other_spec = base_spec(&p_other).governed(&other_grant.governance.clone().unwrap().binding);
    let wrong = g.receipt(&p_other, &other_spec, Some(other_grant.digest()));
    let (s, _) = g.complete(&job, &wrong);
    assert!(s >= 400);
    assert_eq!(g.state(&job), "failed");
    // A grant moved to another project's job gets no ticket.
    let mut c = g.t.control.db.conn().unwrap();
    c.execute(
        "UPDATE jobs SET job_grant = (SELECT job_grant FROM jobs WHERE id = $2) WHERE id = $1",
        &[&id(&j2), &job],
    )
    .unwrap();
    let (s, _) = g.t.call(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{}/release-ticket", id(&j2)),
        Some(json!({"asset_version_id": v2.version})),
    );
    assert!(s >= 400);
}

// --- start-time revalidation: whatever changed since submission -------------------

/// Start refuses `job` with `code`: it fails, and is anchored as ended.
fn start_refused(g: &G, job: &str, code: &str) -> Value {
    let (s, v) = g.start(job);
    refused((s, v.clone()), code);
    let view = g.view(job);
    assert_eq!(view["state"], "failed", "{view}");
    assert!(
        g.t.control.anchor.snapshot().ended_jobs.contains(job),
        "{job} is not anchored as ended"
    );
    // Audited as a failed revalidation at start.
    let refs: Value =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT refs FROM audit_events WHERE action = 'job.failed' AND resource_id = $1",
                &[&job],
            )
            .unwrap()
            .get(0);
    assert_eq!(refs["reason"], code, "{refs}");
    assert_eq!(refs["stage"], "start", "{refs}");
    assert_eq!(refs["check"], "revalidate_governed", "{refs}");
    v
}

/// A queued governed job over a fresh version `label`.
fn queued(g: &G, label: &str) -> (Version, Auth, String) {
    let (v, a, _, j) = g.job(label, |_| {});
    assert_eq!(j["state"], "queued", "{j}");
    (v, a, id(&j))
}

#[test]
fn start_refuses_a_revoked_or_unapproved_authorization() {
    let Some(g) = world() else { return };
    let url = g.t.env0.url.clone();
    // Revoked in the database without the revocation's own cascade (a lost
    // or delayed cascade): start still refuses (ENC2706).
    let (_, a, job) = queued(&g, "2026-q1");
    attacker(
        &url,
        &["authorizations"],
        &format!(
            "UPDATE authorizations SET status = 'revoked', revoked_at = now() WHERE id = '{}'",
            a.row
        ),
    );
    start_refused(&g, &job, "ENC2706");
    // Its approval state changed: no longer active (ENC2701).
    let (_, a, job) = queued(&g, "2026-q2");
    attacker(
        &url,
        &["authorizations"],
        &format!(
            "UPDATE authorizations SET status = 'approved' WHERE id = '{}'",
            a.row
        ),
    );
    start_refused(&g, &job, "ENC2701");
}

#[test]
fn start_refuses_an_expired_authorization() {
    let Some(g) = world() else { return };
    let until = now() + 6;
    let (_, _, _, j) = g.job("2026-q1", |b| b.valid_until = until);
    after(until);
    let v = start_refused(&g, &id(&j), "ENC2705");
    assert!(v["message"].as_str().unwrap().contains("valid"), "{v}");
}

#[test]
fn start_refuses_a_superseded_authorization() {
    let Some(g) = world() else { return };
    let (v, a, job) = queued(&g, "2026-q1");
    // The owner issued a new authorization for the same version; the row
    // the job runs under is made to carry the new document instead.
    let p = program(&[&v.asset], PURPOSE, BEN);
    let newer = g.authorize(g.body(&v, &p));
    attacker(
        &g.t.env0.url,
        &["authorizations"],
        &format!(
            "CREATE TEMP TABLE newer AS
                 SELECT authorization_id, signed FROM authorizations WHERE id = '{n}';
             UPDATE authorizations SET authorization_id = NULL, signed = NULL, activated_at = NULL,
                 status = 'approved' WHERE id = '{n}';
             UPDATE authorizations SET (authorization_id, signed) =
                 (SELECT authorization_id, signed FROM newer) WHERE id = '{o}'",
            n = newer.row,
            o = a.row
        ),
    );
    start_refused(&g, &job, "ENC2703");
    // Revoking and reissuing: the new one does not rescue a job submitted
    // under the old one (the revocation failed it already).
    let (v2, a2, job2) = queued(&g, "2026-q2");
    let p2 = program(&[&v2.asset], PURPOSE, BEN);
    g.authorize(g.body(&v2, &p2));
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", a2.row),
        Some(json!({"reason": "superseded"})),
    );
    assert_eq!(g.state(&job2), "failed");
    let (s, _) = g.start(&job2);
    assert_eq!(s, 409);
}

#[test]
fn start_refuses_after_the_governance_key_is_revoked() {
    let Some(g) = world() else { return };
    let (_, _, job) = queued(&g, "2026-q1");
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let k = keys[0]["id"].as_str().unwrap().to_owned();
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{k}/revoke"),
        None,
    );
    after(now());
    start_refused(&g, &job, "ENC2708");
}

#[test]
fn start_refuses_a_retired_or_expired_purpose() {
    let Some(mut g) = world() else { return };
    let (_, _, job) = queued(&g, "2026-q1");
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{}/retire", g.purpose),
        None,
    );
    after(now());
    start_refused(&g, &job, "ENC2706");
    // A purpose whose window ends before the job starts.
    let until = now() + 8;
    let short = "benefits-short";
    g.purpose = g.purpose_for(short, until, &[BEN]);
    let mut policy = registered(TAX)["ir_policy"].clone();
    policy["purposes"] = json!([short]);
    let v = g.version("2026-q2", json!({"ir_policy": policy}));
    let p = program(&[&v.asset], short, BEN);
    let mut body = g.body(&v, &p);
    body.valid_until = until;
    g.authorize(body);
    let plan = g.plan(&g.ben_dev, &p);
    let mut req = g.request(&plan, &[&v.asset], &[BEN]);
    req["purpose"] = json!(short);
    let (s, j) = g.submit(&g.ben_dev, req, "short");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "queued");
    after(until);
    let r = start_refused(&g, &id(&j), "ENC2705");
    assert!(r["message"].as_str().unwrap().contains("purpose"), "{r}");
}

#[test]
fn start_refuses_a_revoked_or_expired_source() {
    let Some(g) = world() else { return };
    let (v, _, job) = queued(&g, "2026-q1");
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE assets SET status = 'revoked', revoked_at = now() WHERE id = $1",
            &[&v.asset],
        )
        .unwrap();
    start_refused(&g, &job, "ENC2706");
    // An expiry fails the jobs that have not started at once (anchored as
    // ended), and a start is refused.
    let (v, _, job) = queued(&g, "2026-q2");
    g.t.control.expire_asset("retention", &v.asset).unwrap();
    assert_eq!(g.state(&job), "failed");
    assert!(g.t.control.anchor.snapshot().ended_jobs.contains(&job));
    let refs: Value =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT refs FROM audit_events WHERE action = 'job.failed' AND resource_id = $1",
                &[&job],
            )
            .unwrap()
            .get(0);
    assert_eq!(refs["expired_asset"], v.asset.as_str(), "{refs}");
    let (s, _) = g.start(&job);
    assert!(s >= 400);
}

#[test]
fn start_refuses_a_source_past_its_brought_forward_deletion_date() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({"delete_after": now() + 3000}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let plan = g.plan(&g.ben_dev, &p);
    let (s, j) = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1");
    assert_eq!(s, 201, "{j}");
    let job = id(&j);
    // The owner brings the deletion date forward; it passes before start.
    let soon = now() + 2;
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE assets SET delete_after = $2 WHERE id = $1",
            &[&v.asset, &(soon as i64)],
        )
        .unwrap();
    after(soon);
    start_refused(&g, &job, "ENC2705");
}

#[test]
fn start_refuses_a_substituted_version() {
    let Some(g) = world() else { return };
    let (v, _, job) = queued(&g, "2026-q1");
    attacker(
        &g.t.env0.url,
        &["assets"],
        &format!(
            "UPDATE assets SET version_id = '{}' WHERE id = '{}'",
            "9".repeat(64),
            v.asset
        ),
    );
    start_refused(&g, &job, "ENC2704");
}

#[test]
fn start_refuses_a_disabled_or_rebound_broker() {
    let Some(g) = world() else { return };
    let (v, _, job) = queued(&g, "2026-q1");
    // The source's key moved to another key name at the broker (re-bound):
    // not the key the job's binding gives to that broker.
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE assets SET key_ref = jsonb_set(key_ref, '{key_ref}', '\"income-moved\"') WHERE id = $1",
            &[&v.asset],
        )
        .unwrap();
    start_refused(&g, &job, "ENC2715");
    // The owner's broker is disabled.
    let (_, _, job) = queued(&g, "2026-q2");
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts/tax-broker/disable"),
        None,
    );
    start_refused(&g, &job, "ENC2715");
}

#[test]
fn start_refuses_a_binding_or_spec_that_no_longer_recomputes() {
    let Some(g) = world() else { return };
    let url = g.t.env0.url.clone();
    // The stored spec ID.
    let (_, _, job) = queued(&g, "2026-q1");
    attacker(
        &url,
        &["jobs"],
        &format!(
            "UPDATE jobs SET spec_id = '{}' WHERE id = '{job}'",
            "e".repeat(64)
        ),
    );
    start_refused(&g, &job, "ENC2703");
    // The stored binding (a wider release than submitted).
    let (_, _, job) = queued(&g, "2026-q2");
    attacker(
        &url,
        &["jobs"],
        &format!(
            "UPDATE jobs SET governance = jsonb_set(governance, '{{binding,outputs,out,recipients}}',
                 '[\"benefits-agency\", \"tax-agency\"]') WHERE id = '{job}'"
        ),
    );
    start_refused(&g, &job, "ENC2703");
    // The job's recorded authorizations.
    let (_, _, job) = queued(&g, "2026-q3");
    attacker(
        &url,
        &["job_authorizations"],
        &format!("DELETE FROM job_authorizations WHERE job_id = '{job}'"),
    );
    start_refused(&g, &job, "ENC2703");
    // The grant, re-signed by nobody.
    let (_, _, job) = queued(&g, "2026-q4");
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE jobs SET job_grant = jsonb_set(job_grant, '{governance,not_after}',
                 to_jsonb((job_grant->'governance'->>'not_after')::bigint + 60)) WHERE id = $1",
            &[&job],
        )
        .unwrap();
    start_refused(&g, &job, "ENC2703");
}

/// Scheduling and start revalidate with the same function: the same change
/// is refused alike at either transition, and the read-only entry point a
/// later layer binds to answers exactly as they do.
#[test]
fn schedule_and_start_share_one_revalidation() {
    use encompute_control::GovernedStage;
    let Some(g) = world() else { return };
    // Job A stays authorized (no ready evaluator); job B is queued.
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute("UPDATE evaluators SET status = 'draining'", &[])
        .unwrap();
    let (_, _, _, ja) = g.job("2026-q1", |_| {});
    let job_a = id(&ja);
    assert_eq!(ja["state"], "authorized", "{ja}");
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute("UPDATE evaluators SET status = 'ready'", &[])
        .unwrap();
    let (_, _, job_b) = queued(&g, "2026-q2");
    // Both are valid now, for both stages.
    let na =
        g.t.control
            .revalidate_governed_job(&job_b, GovernedStage::Schedule)
            .unwrap();
    assert_eq!(
        g.t.control
            .revalidate_governed_job(&job_b, GovernedStage::Start)
            .unwrap(),
        na
    );
    assert_eq!(g.grant(&job_b).governance.unwrap().not_after, na);
    // The owner's broker is disabled.
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts/tax-broker/disable"),
        None,
    );
    let at_schedule =
        g.t.control
            .revalidate_governed_job(&job_b, GovernedStage::Schedule)
            .unwrap_err();
    let at_start =
        g.t.control
            .revalidate_governed_job(&job_b, GovernedStage::Start)
            .unwrap_err();
    assert_eq!(at_schedule.code.as_str(), "ENC2715");
    assert_eq!(
        (at_schedule.code, &at_schedule.message),
        (at_start.code, &at_start.message)
    );
    // Scheduling fails A, start fails B: the same check, the same code.
    g.t.control.schedule_pending().unwrap();
    assert_eq!(g.state(&job_a), "failed");
    assert!(g.t.control.anchor.snapshot().ended_jobs.contains(&job_a));
    let v = start_refused(&g, &job_b, "ENC2715");
    assert_eq!(v["message"].as_str().unwrap(), at_start.message);
    let refs: Value =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT refs FROM audit_events WHERE action = 'job.failed' AND resource_id = $1",
                &[&job_a],
            )
            .unwrap()
            .get(0);
    assert_eq!(refs["reason"], "ENC2715", "{refs}");
    assert_eq!(refs["stage"], "schedule", "{refs}");
    assert_eq!(refs["check"], "revalidate_governed", "{refs}");
}

// --- review fixes: tickets, visibility, lock order, four eyes ----------------------

fn ticket(g: &G, job: &str, version: &str) -> (u16, Value) {
    g.t.call(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/release-ticket"),
        Some(json!({"asset_version_id": version})),
    )
}

#[test]
fn ticket_uses_only_the_jobs_own_authorizations() {
    let Some(g) = world() else { return };
    let (v, a, program, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    // A second authorization for the same version, broader (tax as a
    // recipient too) and valid for longer.
    let mut broader = g.body(&v, &program);
    broader.recipients = [BEN.to_string(), TAX.to_string()].into();
    broader.valid_until = now() + 5000;
    let b = g.authorize(broader);
    let (s, t) = ticket(&g, &job, &v.version);
    assert_eq!(s, 201, "{t}");
    let ticket: encompute_verification::ticket::ReleaseTicket =
        serde_json::from_value(t["ticket"].clone()).unwrap();
    assert_eq!(ticket.authorization_ids, BTreeSet::from([a.id.clone()]));
    assert!(!ticket.authorization_ids.contains(&b.id));
}

#[test]
fn ticket_refused_when_jobs_authorization_superseded() {
    let Some(g) = world() else { return };
    let (v, a, program, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    g.t.ok(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    // The owner supersedes: a new authorization, then the old one revoked.
    // The running job keeps running, but gets no ticket under the new one.
    g.authorize(g.body(&v, &program));
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", a.row),
        Some(json!({"reason": "superseded"})),
    );
    assert_eq!(g.state(&job), "running");
    refused(ticket(&g, &job, &v.version), "ENC2706");
    // A job's authorization rewritten in the database is refused too.
    let (v2, a2, _, j2) = g.job("2026-q2", |_| {});
    attacker(
        &g.t.env0.url,
        &["authorizations"],
        &format!(
            "UPDATE authorizations SET signed = jsonb_set(signed, '{{body,recipients}}',
                 '[\"benefits-agency\", \"tax-agency\"]') WHERE id = '{}'",
            a2.row
        ),
    );
    let (s, v) = ticket(&g, &id(&j2), &v2.version);
    assert!(s >= 400, "{v}");
}

#[test]
fn ticket_refuses_four_eyes_authorization_not_bound_to_job() {
    let Some(g) = world() else { return };
    let (v, a, program, j) = g.job("2026-q1", |_| {});
    let mut four = g.body(&v, &program);
    four.per_job_four_eyes = true;
    let f = g.authorize(four);
    let (s, t) = ticket(&g, &id(&j), &v.version);
    assert_eq!(s, 201, "{t}");
    let ids: BTreeSet<String> =
        serde_json::from_value(t["ticket"]["authorization_ids"].clone()).unwrap();
    assert_eq!(ids, BTreeSet::from([a.id.clone()]));
    assert!(!ids.contains(&f.id));
}

#[test]
fn member_org_not_named_cannot_see_source() {
    let Some(g) = world() else { return };
    let (v, _, _, _) = g.job("2026-q1", |_| {});
    // A member of the project that no authorization names, and that
    // submitted nothing over it: not found, like an unknown ID.
    let (s, body) = g.t.call(
        &g.other_dev,
        "GET",
        &format!("/v1/assets/{}", v.asset),
        None,
    );
    assert_eq!(s, 404, "{body}");
    let (s2, unknown) = g.t.call(
        &g.other_dev,
        "GET",
        "/v1/assets/ast_00000000000000000000000000000000",
        None,
    );
    assert_eq!(s2, 404);
    assert_eq!(code(&body), code(&unknown));
}

#[test]
fn recipient_sees_redacted_source() {
    let Some(g) = world() else { return };
    let v = g.version(
        "2026-q1",
        json!({"storage_uri": "s3://tax/income-2026-q1", "size_bytes": 1024}),
    );
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let a =
        g.t.ok(&g.ben_dev, "GET", &format!("/v1/assets/{}", v.asset), None);
    assert_eq!(a["id"], v.asset.as_str());
    for f in ["storage_uri", "key_ref", "size_bytes"] {
        assert!(a.get(f).is_none_or(Value::is_null), "{f} shown: {a}");
    }
    // The owner sees it in full.
    let own = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/assets/{}", v.asset),
        None,
    );
    assert_eq!(own["storage_uri"], "s3://tax/income-2026-q1");
}

#[test]
fn submitter_of_bound_job_sees_source() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let path = format!("/v1/assets/{}", v.asset);
    assert_eq!(g.t.call(&g.other_dev, "GET", &path, None).0, 404);
    // Other-co submits a job over it (releasing to benefits, as authorized).
    let plan = g.plan(&g.other_dev, &p);
    let (s, j) = g.submit(&g.other_dev, g.request(&plan, &[&v.asset], &[BEN]), "o1");
    assert_eq!(s, 201, "{j}");
    let a = g.t.ok(&g.other_dev, "GET", &path, None);
    assert!(a.get("key_ref").is_none_or(Value::is_null), "{a}");
}

#[test]
fn concurrent_revoke_and_start_do_not_deadlock() {
    let Some(g) = world() else { return };
    for i in 0..5 {
        let (_, a, _, j) = g.job(&format!("2026-r{i}"), |_| {});
        let job = id(&j);
        let (start, revoke) = std::thread::scope(|s| {
            let st = s.spawn(|| g.start(&job));
            let rv = s.spawn(|| {
                g.t.call(
                    &g.tax_sec1,
                    "POST",
                    &format!("/v1/authorizations/{}/revoke", a.row),
                    Some(json!({"reason": "race"})),
                )
            });
            (st.join().unwrap(), rv.join().unwrap())
        });
        assert_eq!(revoke.0, 200, "{}", revoke.1);
        assert!(start.0 < 500, "a deadlock or error surfaced: {}", start.1);
        let failed = revoke.1["failed_jobs"].as_array().unwrap();
        if start.0 == 200 {
            // Started first: the revocation found nothing to fail.
            assert!(failed.is_empty(), "{}", revoke.1);
            assert_eq!(g.state(&job), "running");
        } else {
            // Revoked first: the job failed, and start was refused.
            assert_eq!(failed.len(), 1, "{}", revoke.1);
            assert_eq!(g.state(&job), "failed");
        }
    }
}

#[test]
fn broader_authorization_does_not_shadow_four_eyes_one() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let mut four = g.body(&v, &p);
    four.per_job_four_eyes = true;
    let f = g.authorize(four);
    let plan = g.plan(&g.ben_dev, &p);
    // The job runs under the authorization that asks for four eyes, and
    // waits for that approval.
    let (s, j) = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "waiting_for_approval", "{j}");
    let bound: Vec<String> =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query(
                "SELECT authorization_row FROM job_authorizations WHERE job_id = $1",
                &[&id(&j)],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
    assert_eq!(bound, vec![f.row]);
}

// --- step 3: per-job four eyes -----------------------------------------------------

/// A governed job whose authorization asks for per-job four eyes, submitted
/// by benefits: it waits for tax's people.
fn four_eyes_job(g: &G, label: &str) -> (Version, Auth, String) {
    let (v, a, _, j) = g.job(label, |b| b.per_job_four_eyes = true);
    assert_eq!(j["state"], "waiting_for_approval", "{j}");
    (v, a, id(&j))
}

fn approve(g: &G, who: &As, job: &str) -> (u16, Value) {
    g.t.call(who, "POST", &format!("/v1/jobs/{job}/approve"), None)
}

/// The job's per-job approvals: (approver, organization, role, statement).
fn approvals(g: &G, job: &str) -> Vec<(String, String, String, String)> {
    g.t.control
        .db
        .conn()
        .unwrap()
        .query(
            "SELECT approver_id, organization_id, role, statement_digest FROM job_human_approvals
              WHERE job_id = $1 ORDER BY at, approver_id",
            &[&job],
        )
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect()
}

fn principal_id(g: &G, who: &As) -> String {
    g.t.ok(who, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn self_approval_by_submitter_refused_2707() {
    let Some(g) = world() else { return };
    // A tax developer who is also a data owner submits a job over tax's
    // own version.
    let both = user(
        &g.t,
        &g.tax_admin,
        TAX,
        "t-both",
        &["ml_developer", "data_owner"],
    );
    let v = g.version("2026-q1", json!({}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    let mut body = g.body(&v, &p);
    body.per_job_four_eyes = true;
    g.authorize(body);
    let plan = g.plan(&both, &p);
    let (s, j) = g.submit(&both, g.request(&plan, &[&v.asset], &[BEN]), "self");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "waiting_for_approval", "{j}");
    let job = id(&j);
    refused(approve(&g, &both, &job), "ENC2707");
    assert!(approvals(&g, &job).is_empty());
    // Two other people of tax.
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    assert_eq!(v["state"], "queued", "{v}");
}

#[test]
fn same_person_twice_is_one_approver() {
    let Some(g) = world() else { return };
    let (_, _, job) = four_eyes_job(&g, "2026-q1");
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    assert_eq!(v["state"], "waiting_for_approval", "{v}");
    refused(approve(&g, &g.tax_owner, &job), "ENC2707");
    assert_eq!(approvals(&g, &job).len(), 1);
    assert_eq!(g.state(&job), "waiting_for_approval");
    // One person holding both of the rule's roles is still one person.
    let (_, _, job2) = four_eyes_job(&g, "2026-q2");
    let dual = user(
        &g.t,
        &g.tax_admin,
        TAX,
        "t-dual",
        &["data_owner", "security_admin"],
    );
    let v =
        g.t.ok(&dual, "POST", &format!("/v1/jobs/{job2}/approve"), None);
    assert_eq!(v["state"], "waiting_for_approval", "{v}");
    refused(approve(&g, &dual, &job2), "ENC2707");
    let v = g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/jobs/{job2}/approve"),
        None,
    );
    assert_eq!(v["state"], "queued", "{v}");
}

#[test]
fn quorum_not_met_stays_waiting() {
    let Some(g) = world() else { return };
    let (_, _, job) = four_eyes_job(&g, "2026-q1");
    // Two people, but both security admins: the rule also needs a data
    // owner.
    for who in [&g.tax_sec1, &g.tax_sec2] {
        let v =
            g.t.ok(who, "POST", &format!("/v1/jobs/{job}/approve"), None);
        assert_eq!(v["state"], "waiting_for_approval", "{v}");
    }
    g.t.control.schedule_pending().unwrap();
    assert_eq!(g.state(&job), "waiting_for_approval");
    let (s, v) = g.start(&job);
    assert!(s >= 400, "{v}");
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    assert_eq!(v["state"], "queued", "{v}");
    let roles: BTreeSet<String> = approvals(&g, &job).into_iter().map(|a| a.2).collect();
    assert_eq!(
        roles,
        BTreeSet::from(["data_owner".to_string(), "security_admin".to_string()])
    );
}

#[test]
fn approver_homed_in_other_org_does_not_count() {
    let Some(g) = world() else { return };
    let (_, _, job) = four_eyes_job(&g, "2026-q1");
    // A benefits person granted data_owner in tax.
    let ben_admin = As::User("b-admin".into());
    let ben_sec = user(&g.t, &ben_admin, BEN, "b-sec", &["security_admin"]);
    let who = principal_id(&g, &ben_sec);
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    c.execute(
        "INSERT INTO memberships (principal_id, organization_id, role) VALUES ($1, $2, 'data_owner')",
        &[&who, &TAX],
    )
    .unwrap();
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    let (s, v) = approve(&g, &ben_sec, &job);
    assert_eq!(s, 403, "{v}");
    // Another organization's person with no role in tax: no approval to
    // give.
    let (s, v) = approve(&g, &g.other_dev, &job);
    assert!(s == 403 || s == 404, "{s} {v}");
    assert_eq!(approvals(&g, &job).len(), 1);
    assert_eq!(g.state(&job), "waiting_for_approval");
}

#[test]
fn service_account_cannot_approve_2707() {
    let Some(g) = world() else { return };
    let (_, _, job) = four_eyes_job(&g, "2026-q1");
    let signer = std::sync::Arc::new(ServiceSigner::from_seed("tax-robot", &[9; 32]).unwrap());
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts"),
        Some(
            json!({"id": "tax-robot", "kind": "automation", "public_key": signer.public_key_hex(),
                    "roles": ["organization_admin", "data_owner"]}),
        ),
    );
    let robot = As::Service(signer);
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    refused(approve(&g, &robot, &job), "ENC2707");
    assert_eq!(approvals(&g, &job).len(), 1);
    assert_eq!(g.state(&job), "waiting_for_approval");
}

#[test]
fn approval_after_window_2705() {
    let Some(g) = world() else { return };
    let until = now() + 6;
    let (_, _, _, j) = g.job("2026-q1", |b| {
        b.per_job_four_eyes = true;
        b.valid_until = until;
    });
    let job = id(&j);
    assert_eq!(j["state"], "waiting_for_approval", "{j}");
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    after(until);
    refused(approve(&g, &g.tax_owner, &job), "ENC2705");
    // The job can never run now: it failed, anchored as ended.
    assert_eq!(g.state(&job), "failed");
    assert!(g.t.control.anchor.snapshot().ended_jobs.contains(&job));
    assert_eq!(approvals(&g, &job).len(), 1);
    let refs: Value =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT refs FROM audit_events WHERE action = 'job.failed' AND resource_id = $1",
                &[&job],
            )
            .unwrap()
            .get(0);
    assert_eq!(refs["reason"], "ENC2705", "{refs}");
    assert_eq!(refs["stage"], "approve", "{refs}");
}

#[test]
fn approval_of_revoked_authorization_job_fails() {
    let Some(g) = world() else { return };
    // Revoked behind the job's back (a lost cascade): the approval
    // revalidates, refuses, and fails the job.
    let (_, a, job) = four_eyes_job(&g, "2026-q1");
    attacker(
        &g.t.env0.url,
        &["authorizations"],
        &format!(
            "UPDATE authorizations SET status = 'revoked', revoked_at = now() WHERE id = '{}'",
            a.row
        ),
    );
    refused(approve(&g, &g.tax_owner, &job), "ENC2706");
    assert_eq!(g.state(&job), "failed");
    assert!(g.t.control.anchor.snapshot().ended_jobs.contains(&job));
    assert!(approvals(&g, &job).is_empty());
    // Revoked properly: the waiting job fails with the revocation, and
    // there is nothing left to approve.
    let (_, a2, job2) = four_eyes_job(&g, "2026-q2");
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", a2.row),
        Some(json!({"reason": "withdrawn"})),
    );
    assert_eq!(g.state(&job2), "failed");
    let (s, _) = approve(&g, &g.tax_owner, &job2);
    assert_eq!(s, 409);
}

/// A program over tax's version `a` and benefits' version `b`.
fn two_owner_program(a: &str, b: &str) -> String {
    format!(
        "encompute 0.1\nprogram adult precision 0.001 purpose \"{PURPOSE}\"\n\
         party \"{TAX}\" \"Tax\"\nparty \"{BEN}\" \"Benefits\"\n\
         asset \"{a}\" dataset owners [\"{TAX}\"] readers [\"{BEN}\", \"{TAX}\"] purposes \
         [\"{PURPOSE}\"] release allowed_parties\n\
         asset \"{b}\" dataset owners [\"{BEN}\"] readers [\"{BEN}\", \"{TAX}\"] purposes \
         [\"{PURPOSE}\"] release allowed_parties\n\
         %0 = input \"x0\" [0.0, 120.0] asset \"{a}\" : secret u8\n\
         %1 = input \"x1\" [0.0, 120.0] asset \"{b}\" : secret u8\n\
         %2 = ge %0, %1 : secret bool\noutput \"out\" = %2 to \"{BEN}\"\n"
    )
}

#[test]
fn schedule_requires_every_owner_quorum() {
    let Some(g) = world() else { return };
    // Benefits owns a source too: its own governance key, broker, purpose
    // acceptance and people.
    let ben_admin = As::User("b-admin".into());
    let ben_sec1 = user(&g.t, &ben_admin, BEN, "b-sec1", &["security_admin"]);
    let ben_sec2 = user(&g.t, &ben_admin, BEN, "b-sec2", &["security_admin"]);
    let ben_owner = user(&g.t, &ben_admin, BEN, "b-owner", &["data_owner"]);
    let ben_key = key(8);
    let k = g.t.ok(
        &ben_admin,
        "POST",
        &format!("/v1/organizations/{BEN}/governance-keys"),
        Some(json!({"public_key": pk(&ben_key), "kms_key_ref": "vault:transit/governance"})),
    );
    g.t.ok(
        &ben_sec1,
        "POST",
        &format!(
            "/v1/organizations/{BEN}/governance-keys/{}/approve",
            k["id"].as_str().unwrap()
        ),
        None,
    );
    let acceptance = PurposeAcceptance {
        version: 1,
        organization: BEN.into(),
        project: g.project.clone(),
        purpose_id: g.purpose.clone(),
        accepted_at: now(),
    }
    .sign(&ben_key)
    .unwrap();
    g.t.ok(
        &ben_sec2,
        "POST",
        &format!("/v1/purposes/{}/accept", g.purpose),
        Some(json!({"acceptance": acceptance})),
    );
    broker_account(&g.t, &ben_admin, BEN, "ben-broker", 32);
    let (s, v) = g.t.call(
        &ben_sec1,
        "POST",
        &format!("/v1/organizations/{BEN}/key-brokers"),
        Some(json!({"id": "ben-broker", "grant_public_key": pk(&key(42)),
                    "provider_kind": "openbao-transit", "key_ref_namespace": "transit/ben"})),
    );
    assert_eq!(s, 201, "{v}");
    let tv = g.version("2026-q1", json!({}));
    let bv = g.t.ok(
        &ben_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": BEN, "kind": "dataset", "name": "claims@2026-q1",
                    "series": "claims", "version": "2026-q1",
                    "digest": "e".repeat(64), "project": g.project,
                    "ir_policy": registered(BEN)["ir_policy"], "release_class": "boolean-only",
                    "key_ref": {"broker": "ben-broker", "provider": "openbao-transit",
                                "key_ref": "claims-2026-q1", "key_version": 1}}),
        ),
    );
    let bv = Version {
        asset: bv["id"].as_str().unwrap().to_owned(),
        version: bv["version_id"].as_str().unwrap().to_owned(),
    };
    let p = two_owner_program(&tv.asset, &bv.asset);
    // Both owners ask for per-job four eyes.
    let mut tax_body = g.body(&tv, &p);
    tax_body.per_job_four_eyes = true;
    g.authorize(tax_body);
    let mut ben_body = g.body(&bv, &p);
    ben_body.party = BEN.into();
    ben_body.per_job_four_eyes = true;
    let row = g.t.ok(
        &ben_owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": ben_body})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for (who, role) in [(&ben_owner, "data_owner"), (&ben_sec1, "security_admin")] {
        g.t.ok(
            who,
            "POST",
            &format!("/v1/authorizations/{row}/approve"),
            Some(json!({"role": role})),
        );
    }
    let doc: AuthorizationV2 = serde_json::from_value(
        g.t.ok(&ben_sec1, "GET", &format!("/v1/authorizations/{row}"), None)["body"].clone(),
    )
    .unwrap();
    let signed = doc.sign(&ben_key).unwrap();
    g.t.ok(
        &ben_sec1,
        "POST",
        &format!("/v1/authorizations/{row}/signature"),
        Some(json!({"public_key": signed.public_key, "signature": signed.signature})),
    );
    let plan = g.plan(&g.other_dev, &p);
    let (s, j) = g.submit(
        &g.other_dev,
        g.request(&plan, &[&tv.asset, &bv.asset], &[BEN]),
        "two",
    );
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "waiting_for_approval", "{j}");
    let job = id(&j);
    // Tax's quorum alone is not enough.
    for who in [&g.tax_owner, &g.tax_sec1] {
        let v =
            g.t.ok(who, "POST", &format!("/v1/jobs/{job}/approve"), None);
        assert_eq!(v["state"], "waiting_for_approval", "{v}");
    }
    g.t.control.schedule_pending().unwrap();
    assert_eq!(g.state(&job), "waiting_for_approval");
    let e =
        g.t.control
            .revalidate_governed_job(&job, encompute_control::GovernedStage::Schedule)
            .unwrap_err();
    assert_eq!(e.code.as_str(), "ENC2707", "{}", e.message);
    assert!(e.message.contains(BEN), "{}", e.message);
    // Another tax person's approval counts for tax, never for benefits.
    let v = g.t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    assert_eq!(v["state"], "waiting_for_approval", "{v}");
    g.t.ok(&ben_owner, "POST", &format!("/v1/jobs/{job}/approve"), None);
    let v =
        g.t.ok(&ben_sec2, "POST", &format!("/v1/jobs/{job}/approve"), None);
    assert_eq!(v["state"], "queued", "{v}");
    let orgs: BTreeSet<String> = approvals(&g, &job).into_iter().map(|a| a.1).collect();
    assert_eq!(orgs, BTreeSet::from([TAX.to_string(), BEN.to_string()]));

    // A job pushed to authorized without its quorum (a tampered state) is
    // not scheduled: it waits for approval again.
    let (_, _, job2) = four_eyes_job(&g, "2026-q2");
    attacker(
        &g.t.env0.url,
        &["jobs"],
        &format!("UPDATE jobs SET state = 'authorized' WHERE id = '{job2}'"),
    );
    assert!(!g.t.control.schedule_job(&job2).unwrap());
    assert_eq!(g.state(&job2), "waiting_for_approval");
    let refs: Value = g
        .t
        .control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT refs FROM audit_events WHERE action = 'job.approval_lapsed' AND resource_id = $1",
            &[&job2],
        )
        .unwrap()
        .get(0);
    assert_eq!(refs["reason"], "ENC2707", "{refs}");
    assert_eq!(refs["stage"], "schedule", "{refs}");
}

#[test]
fn standard_job_approval_unchanged() {
    let Some(w) = common::world() else { return };
    let t = &w.t;
    let d = t.ok(
        &w.a_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "hospital-a", "kind": "dataset", "name": "gated",
                    "digest": "f".repeat(64), "policy": {"require_job_approval": true}}),
        ),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals"),
        Some(json!({"project": w.project, "purpose": "medical-training"})),
    );
    let plan = w.plan(&exact_over(&d, "hospital-a", "dataset", "medical-training"));
    let (s, j) = w.job(&plan, &[&d], "std-1");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "waiting_for_approval", "{j}");
    let job = id(&j);
    // The submitter's organization does not approve its own job.
    let (s, _) = t.call(&w.b_admin, "POST", &format!("/v1/jobs/{job}/approve"), None);
    assert_eq!(s, 403);
    // One person of the owner approves, as in rc.4: no quorum of two, and
    // nothing recorded as a per-job four-eyes approval.
    let v = t.ok(&w.a_owner, "POST", &format!("/v1/jobs/{job}/approve"), None);
    assert_ne!(v["state"], "waiting_for_approval", "{v}");
    let mut c = t.control.db.conn().unwrap();
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM job_approvals WHERE job_id = $1",
            &[&job],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1);
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM job_human_approvals WHERE job_id = $1",
            &[&job],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 0);
}

#[test]
fn governed_job_ignores_require_job_approval() {
    let Some(g) = world() else { return };
    // The free-form policy field asks for approval; a governed job waits
    // only for an authorization's per-job four eyes.
    let v = g.version("2026-q1", json!({"policy": {"require_job_approval": true}}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let plan = g.plan(&g.ben_dev, &p);
    let (s, j) = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "queued", "{j}");
    let (s, _) = approve(&g, &g.tax_owner, &id(&j));
    assert_eq!(s, 409);
}

#[test]
fn approval_statement_binds_spec_and_authorization_set() {
    let Some(g) = world() else { return };
    let (_, a, job) = four_eyes_job(&g, "2026-q1");
    let spec_id = g.view(&job)["spec_id"].as_str().unwrap().to_owned();
    let set = AuthorizationSetId::of([a.id.clone()]).unwrap();
    let statement = job_approval_statement(&job, &spec_id, set.hex());
    g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    let rows = approvals(&g, &job);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].3, statement);
    assert_ne!(
        rows[0].3,
        job_approval_statement(&job, &"0".repeat(64), set.hex())
    );
    assert_ne!(
        rows[0].3,
        job_approval_statement(&job, &spec_id, &"0".repeat(64))
    );
    // An approval over another spec or authorization set (a row written
    // behind the control plane's back) does not count.
    let sec1 = principal_id(&g, &g.tax_sec1);
    let stale = job_approval_statement(&job, &spec_id, &"0".repeat(64));
    attacker(
        &g.t.env0.url,
        &["job_human_approvals"],
        &format!(
            "INSERT INTO job_human_approvals (job_id, organization_id, approver_id, role, statement_digest)
             VALUES ('{job}', '{TAX}', '{sec1}', 'security_admin', '{stale}')"
        ),
    );
    let e =
        g.t.control
            .revalidate_governed_job(&job, encompute_control::GovernedStage::Schedule)
            .unwrap_err();
    assert_eq!(e.code.as_str(), "ENC2707", "{}", e.message);
    // Approvals are append-only.
    let mut c = g.t.control.db.conn().unwrap();
    assert!(c
        .execute(
            "UPDATE job_human_approvals SET statement_digest = $2 WHERE job_id = $1",
            &[&job, &statement],
        )
        .is_err());
    assert!(c
        .execute("DELETE FROM job_human_approvals WHERE job_id = $1", &[&job])
        .is_err());
    // A person approving the job's own statement completes the quorum.
    let v = g.t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    assert_eq!(v["state"], "queued", "{v}");
}

// --- per-job four eyes at execution time ---------------------------------------------

/// A four-eyes job approved by tax's data owner and first security admin.
fn approved_job(g: &G, label: &str) -> String {
    let (_, _, job) = four_eyes_job(g, label);
    g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    job
}

fn evaluators(g: &G, status: &str) {
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute("UPDATE evaluators SET status = $1", &[&status])
        .unwrap();
}

/// A scheduled job is started only while its approvers still count: once
/// one no longer does, start refuses (ENC2707) and fails the job, anchored
/// as ended. The approval stays on record.
#[test]
fn approver_disabled_after_approving_no_longer_counts() {
    let Some(g) = world() else { return };
    let job = approved_job(&g, "2026-q1");
    assert_eq!(g.state(&job), "queued");
    let sec1 = principal_id(&g, &g.tax_sec1);
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/users/{sec1}/disable"),
        None,
    );
    start_refused(&g, &job, "ENC2707");
    assert_eq!(approvals(&g, &job).len(), 2, "evidence stays");
}

/// A job not yet scheduled goes back to waiting for approval (not failed)
/// when an approver no longer holds the role their approval counted for;
/// a new approval by someone who does lets it run.
#[test]
fn approver_role_removed_after_approving_no_longer_counts() {
    let Some(g) = world() else { return };
    evaluators(&g, "draining");
    let job = approved_job(&g, "2026-q1");
    assert_eq!(g.state(&job), "authorized");
    let owner = principal_id(&g, &g.tax_owner);
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/memberships/remove"),
        Some(json!({"principal": owner, "role": "data_owner"})),
    );
    let e =
        g.t.control
            .revalidate_governed_job(&job, encompute_control::GovernedStage::Schedule)
            .unwrap_err();
    assert_eq!(e.code.as_str(), "ENC2707", "{}", e.message);
    evaluators(&g, "ready");
    g.t.control.schedule_pending().unwrap();
    assert_eq!(g.state(&job), "waiting_for_approval");
    let refs: Value = g
        .t
        .control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT refs FROM audit_events WHERE action = 'job.approval_lapsed' AND resource_id = $1",
            &[&job],
        )
        .unwrap()
        .get(0);
    assert_eq!(refs["reason"], "ENC2707", "{refs}");
    assert_eq!(approvals(&g, &job).len(), 2, "evidence stays");
    // Another data owner of tax restores the quorum.
    let owner2 = user(&g.t, &g.tax_admin, TAX, "t-owner2", &["data_owner"]);
    let v =
        g.t.ok(&owner2, "POST", &format!("/v1/jobs/{job}/approve"), None);
    assert_eq!(v["state"], "queued", "{v}");
}

/// Removed from the organization (every role taken away): the approval
/// no longer counts, and start refuses and fails the job.
#[test]
fn approver_removed_from_org_no_longer_counts() {
    let Some(g) = world() else { return };
    let job = approved_job(&g, "2026-q1");
    assert_eq!(g.state(&job), "queued");
    // A second job, approved by the data owner and the other security admin.
    let (_, _, job2) = four_eyes_job(&g, "2026-q2");
    g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/jobs/{job2}/approve"),
        None,
    );
    let v = g.t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/jobs/{job2}/approve"),
        None,
    );
    assert_eq!(v["state"], "queued", "{v}");
    let sec1 = principal_id(&g, &g.tax_sec1);
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/memberships/remove"),
        Some(json!({"principal": sec1})),
    );
    start_refused(&g, &job, "ENC2707");
    // The second job does not depend on that person.
    g.t.control
        .revalidate_governed_job(&job2, encompute_control::GovernedStage::Start)
        .unwrap();
    // Its data owner homed in another organization now (behind the control
    // plane's back): no longer counts either.
    let owner = principal_id(&g, &g.tax_owner);
    attacker(
        &g.t.env0.url,
        &["users"],
        &format!("UPDATE users SET organization_id = '{BEN}' WHERE id = '{owner}'"),
    );
    let e =
        g.t.control
            .revalidate_governed_job(&job2, encompute_control::GovernedStage::Start)
            .unwrap_err();
    assert_eq!(e.code.as_str(), "ENC2707", "{}", e.message);
}

/// An approval rule naming `auditor` could never be met (auditors never
/// approve): the database refuses it, on insert and on update.
#[test]
fn approval_rule_naming_auditor_refused() {
    let Some(g) = world() else { return };
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    let e = c
        .execute(
            "INSERT INTO approval_rules (project_id, organization_id, min_distinct_humans, required_roles, created_by)
             VALUES ($1, $2, 2, '{\"auditor\": 1, \"data_owner\": 1}', 'test')",
            &[&g.project, &TAX],
        )
        .unwrap_err();
    assert!(format!("{e:?}").contains("auditor"), "{e:?}");
    c.execute(
        "INSERT INTO approval_rules (project_id, organization_id, min_distinct_humans, required_roles, created_by)
         VALUES ($1, $2, 2, '{\"data_owner\": 1, \"security_admin\": 1}', 'test')",
        &[&g.project, &TAX],
    )
    .unwrap();
    let e = c
        .execute(
            "UPDATE approval_rules SET required_roles = '{\"auditor\": 1}'
              WHERE project_id = $1 AND organization_id = $2",
            &[&g.project, &TAX],
        )
        .unwrap_err();
    assert!(format!("{e:?}").contains("auditor"), "{e:?}");
    // Only roles a person may approve with are named.
    let e = c
        .execute(
            "UPDATE approval_rules SET required_roles = '{\"no_such_role\": 1}'
              WHERE project_id = $1 AND organization_id = $2",
            &[&g.project, &TAX],
        )
        .unwrap_err();
    assert!(format!("{e:?}").contains("unknown role"), "{e:?}");
}

// --- step 5: release classes -------------------------------------------------------

/// [`program`] releasing a value (the age plus 18), not a boolean.
fn value_program(assets: &[&str]) -> String {
    program(assets, PURPOSE, BEN).replace("ge %0, %1 : secret bool", "add %0, %1 : secret u8")
}

/// Tax's registered policy for its income versions: readers benefits and
/// tax, for the purpose, released only as a boolean.
fn registered_policy() -> Value {
    json!({"owners": [TAX], "readers": [BEN, TAX], "purposes": [PURPOSE],
           "release": "allowed_parties", "derive": {}, "forms": ["boolean"]})
}

#[test]
fn release_form_stronger_than_class_refused_2709() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    // Owner-authorized, but boolean-only for a value the compiler cannot
    // prove is a boolean or a small category.
    let p = value_program(&[&v.asset]);
    g.authorize(g.body(&v, &p));
    let plan = g.plan(&g.ben_dev, &p);
    let r = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1");
    assert!(
        r.1["message"].as_str().unwrap_or("").contains("form"),
        "{}",
        r.1
    );
    refused(r, "ENC2709");
    // Released to nobody, it may run.
    let mut sealed = g.request(&plan, &[&v.asset], &[]);
    sealed["outputs"]["out"]["release_class"] = json!("never");
    let (s, j) = g.submit(&g.ben_dev, sealed, "k2");
    assert_eq!(s, 201, "{j}");
    // A program whose sources allow only booleans and that releases a
    // value does not compile (ENC1907), so it is never planned.
    let forms = value_program(&[&v.asset]).replace(
        "release allowed_parties",
        "release allowed_parties forms [boolean]",
    );
    refused(
        g.t.call(
            &g.ben_dev,
            "POST",
            "/v1/plans",
            Some(json!({"project": g.project, "program": forms})),
        ),
        "ENC1907",
    );
    // The boolean itself is within the class.
    let (_, _, _, j) = g.job("2026-q2", |_| {});
    assert_eq!(j["state"], "queued", "{j}");
}

#[test]
fn program_weaker_than_registered_refused() {
    let Some(g) = world() else { return };
    let v = g.version(
        "2026-q1",
        json!({"ir_policy": registered_policy(), "release_class": "boolean-only"}),
    );
    // Declaring no forms is weaker than the registered `forms [boolean]`.
    let weak = program(&[&v.asset], PURPOSE, BEN);
    let plan = g.plan(&g.ben_dev, &weak);
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1"),
        "ENC2709",
    );
    // Another purpose beside the job's.
    let two = weak
        .replace(
            "release allowed_parties",
            "release allowed_parties forms [boolean]",
        )
        .replace(
            &format!("purposes [\"{PURPOSE}\"]"),
            &format!("purposes [\"{PURPOSE}\", \"statistics\"]"),
        );
    let plan = g.plan(&g.ben_dev, &two);
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k2"),
        "ENC2702",
    );
    // At least as strict: it runs under the owner's authorization.
    let strict = weak.replace(
        "release allowed_parties",
        "release allowed_parties forms [boolean]",
    );
    g.authorize(g.body(&v, &strict));
    let plan = g.plan(&g.ben_dev, &strict);
    let (s, j) = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k3");
    assert_eq!(s, 201, "{j}");
    // A version registered as aggregate-only: a boolean-only authorization
    // of it, or a boolean-only output, is beyond it.
    let agg = g.version(
        "2026-q2",
        json!({"ir_policy": registered_policy(), "release_class": "aggregate-only"}),
    );
    let p = strict.replace(&v.asset, &agg.asset);
    refused(
        g.t.call(
            &g.tax_owner,
            "POST",
            "/v1/authorizations",
            Some(json!({"body": g.body(&agg, &p)})),
        ),
        "ENC2709",
    );
    let plan = g.plan(&g.ben_dev, &p);
    let r = g.submit(&g.ben_dev, g.request(&plan, &[&agg.asset], &[BEN]), "k4");
    assert!(
        r.1["message"]
            .as_str()
            .unwrap_or("")
            .contains("aggregate-only"),
        "{}",
        r.1
    );
    refused(r, "ENC2709");
    // The registered policy and class are fixed with the version.
    let mut c = g.t.control.db.conn().unwrap();
    for sql in [
        "UPDATE assets SET release_class = 'authorized-agency-only' WHERE id = $1",
        "UPDATE assets SET ir_policy = NULL WHERE id = $1",
    ] {
        let e = c.execute(sql, &[&v.asset]).unwrap_err();
        let m = e
            .as_db_error()
            .map(|d| d.message().to_owned())
            .unwrap_or_default();
        assert!(m.contains("immutable"), "{e:?}");
    }
    // Registration: versions only, owned by the registering organization
    // alone, canonical, a known class.
    let register = |label: &str, extra: Value| {
        let mut b = json!({"organization": TAX, "kind": "dataset",
                           "name": format!("income@{label}"), "series": "income",
                           "version": label, "digest": "c".repeat(64), "project": g.project,
                           "key_ref": {"broker": "tax-broker", "provider": "openbao-transit",
                                       "key_ref": format!("income-{label}"), "key_version": 1}});
        if let (Value::Object(b), Value::Object(e)) = (&mut b, extra) {
            b.extend(e);
        }
        g.t.call(&g.tax_owner, "POST", "/v1/assets", Some(b))
    };
    let mut other = registered_policy();
    other["owners"] = json!([BEN]);
    let mut unknown = registered_policy();
    unknown["forms_extra"] = json!(true);
    let mut two = registered_policy();
    two["forms"] = json!([{"bounded_category": {"max": 2}}, {"bounded_category": {"max": 3}}]);
    for (label, extra) in [
        ("x1", json!({"ir_policy": other})),
        ("x2", json!({"ir_policy": unknown})),
        ("x3", json!({"ir_policy": two})),
        ("x4", json!({"release_class": "sometimes"})),
    ] {
        let (s, e) = register(label, extra);
        assert_eq!(s, 400, "{label}: {e}");
    }
    let (s, e) = g.t.call(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "plain",
                    "digest": "c".repeat(64), "release_class": "boolean-only"}),
        ),
    );
    assert_eq!(s, 400, "{e}");
}

#[test]
fn standard_project_outputs_unchanged() {
    let Some(g) = world() else { return };
    let p = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "statistics"})),
    );
    let standard = id(&p);
    // A standard project's job releases a value with no release class.
    let value = EXACT.replace("ge %0, %1 : secret bool", "add %0, %1 : secret u8");
    for (i, program) in [EXACT.to_owned(), value].into_iter().enumerate() {
        let plan = g.t.ok(
            &g.tax_dev,
            "POST",
            "/v1/plans",
            Some(json!({"project": standard, "program": program})),
        );
        let (s, j) = g.submit(
            &g.tax_dev,
            json!({"project": standard, "plan": plan["id"], "purpose": "statistics",
                   "source_assets": [], "requested_output": "out"}),
            &format!("std-{i}"),
        );
        assert_eq!(s, 201, "{j}");
        assert!(j.get("governance_id").is_none(), "{j}");
        // Governed outputs belong to governed projects.
        let (s, _) = g.submit(
            &g.tax_dev,
            json!({"project": standard, "plan": plan["id"], "purpose": "statistics",
                   "source_assets": [], "requested_output": "out",
                   "outputs": {"out": {"release_class": "boolean-only", "recipients": [TAX]}}}),
            &format!("std-o-{i}"),
        );
        assert_eq!(s, 400);
    }
}

// --- step 5 review: probing, registered policies, never ------------------------------

#[test]
fn boolean_authorization_without_probing_limits_refused_2709() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    for (e, r) in [(None, Some(10)), (Some(10), None), (None, None)] {
        let mut body = g.body(&v, &p);
        body.limits.max_executions = e;
        body.limits.max_releases = r;
        refused(
            g.t.call(
                &g.tax_owner,
                "POST",
                "/v1/authorizations",
                Some(json!({"body": body})),
            ),
            "ENC2709",
        );
    }
}

/// Two boolean outputs of one job could jointly encode more than one bit:
/// one per job per source unless the owner allows more.
#[test]
fn boolean_outputs_per_job_capped_2709() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let two = program(&[&v.asset], PURPOSE, BEN)
        .replace(
            "%2 = ge %0, %1 : secret bool\n",
            "%2 = ge %0, %1 : secret bool\n%3 = const [65.0] : public u8\n%4 = ge %0, %3 : secret bool\n",
        )
        .replace(
            &format!("output \"out\" = %2 to \"{BEN}\"\n"),
            &format!("output \"out\" = %2 to \"{BEN}\"\noutput \"old\" = %4 to \"{BEN}\"\n"),
        );
    g.authorize(g.body(&v, &two));
    let plan = g.plan(&g.ben_dev, &two);
    let mut body = g.request(&plan, &[&v.asset], &[BEN]);
    body["outputs"]["old"] = json!({"release_class": "boolean-only", "recipients": [BEN]});
    let r = g.submit(&g.ben_dev, body.clone(), "k1");
    assert!(
        r.1["message"]
            .as_str()
            .unwrap_or("")
            .contains("boolean-only outputs"),
        "{}",
        r.1
    );
    refused(r, "ENC2709");
    // One of them sealed: one boolean released.
    let mut one = body.clone();
    one["outputs"]["old"] = json!({"release_class": "never", "recipients": []});
    let (s, j) = g.submit(&g.ben_dev, one, "k2");
    assert_eq!(s, 201, "{j}");
    // The owner allows two per job.
    let v2 = g.version("2026-q2", json!({}));
    let two2 = two.replace(&v.asset, &v2.asset);
    let mut b = g.body(&v2, &two2);
    b.limits.max_outputs_per_job = Some(2);
    g.authorize(b);
    let plan = g.plan(&g.ben_dev, &two2);
    let mut body = g.request(&plan, &[&v2.asset], &[BEN]);
    body["outputs"]["old"] = json!({"release_class": "boolean-only", "recipients": [BEN]});
    let (s, j) = g.submit(&g.ben_dev, body, "k3");
    assert_eq!(s, 201, "{j}");
}

/// A governed source is always a version with its owner's registered
/// policy and release class.
#[test]
fn governed_source_without_registered_policy_refused() {
    let Some(g) = world() else { return };
    let bare = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "income@bare",
                    "series": "income", "version": "bare", "digest": "c".repeat(64),
                    "project": g.project,
                    "key_ref": {"broker": "tax-broker", "provider": "openbao-transit",
                                "key_ref": "income-bare", "key_version": 1}}),
        ),
    );
    let asset = id(&bare);
    let p = program(&[&asset], PURPOSE, BEN);
    let plan = g.plan(&g.ben_dev, &p);
    let r = g.submit(&g.ben_dev, g.request(&plan, &[&asset], &[BEN]), "k1");
    assert!(
        r.1["message"]
            .as_str()
            .unwrap_or("")
            .contains("registered policy"),
        "{}",
        r.1
    );
    refused(r, "ENC2709");
}

#[test]
fn authorization_for_unregistered_version_refused() {
    let Some(g) = world() else { return };
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "income@bare",
                    "series": "income", "version": "bare", "digest": "c".repeat(64),
                    "project": g.project,
                    "key_ref": {"broker": "tax-broker", "provider": "openbao-transit",
                                "key_ref": "income-bare", "key_version": 1}}),
        ),
    );
    let version = Version {
        asset: id(&v),
        version: v["version_id"].as_str().unwrap().to_owned(),
    };
    let p = program(&[&version.asset], PURPOSE, BEN);
    refused(
        g.t.call(
            &g.tax_owner,
            "POST",
            "/v1/authorizations",
            Some(json!({"body": g.body(&version, &p)})),
        ),
        "ENC2709",
    );
    // Only a registered class and policy together will do.
    let half = g.version("half", json!({"ir_policy": null}));
    let p = program(&[&half.asset], PURPOSE, BEN);
    refused(
        g.t.call(
            &g.tax_owner,
            "POST",
            "/v1/authorizations",
            Some(json!({"body": g.body(&half, &p)})),
        ),
        "ENC2709",
    );
}

/// An output released as `never` names no recipient, and nothing about the
/// job lets anyone decrypt it: the grant binds it to nobody, the only
/// ticket the job gets releases its source key to the attested evaluator,
/// and there is no export (exports arrive with derived assets).
#[test]
fn never_output_is_released_to_nobody() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let plan = g.plan(&g.ben_dev, &p);
    // Never, yet naming a recipient: refused.
    let mut named = g.request(&plan, &[&v.asset], &[BEN]);
    named["outputs"]["out"]["release_class"] = json!("never");
    let (s, e) = g.submit(&g.ben_dev, named, "k1");
    assert_eq!(s, 400, "{e}");
    let mut sealed = g.request(&plan, &[&v.asset], &[]);
    sealed["outputs"]["out"]["release_class"] = json!("never");
    let (s, j) = g.submit(&g.ben_dev, sealed, "k2");
    assert_eq!(s, 201, "{j}");
    let job = id(&j);
    let grant = g.grant(&job);
    let out = &grant.governance.unwrap().binding.outputs["out"];
    assert_eq!(out.release_class, ReleaseClass::Never);
    assert!(out.recipients.is_empty());
    let (s, t) = ticket(&g, &job, &v.version);
    assert_eq!(s, 201, "{t}");
    let t: encompute_verification::ticket::ReleaseTicket =
        serde_json::from_value(t["ticket"].clone()).unwrap();
    assert_eq!(
        t.kind,
        encompute_verification::ticket::TicketKind::KeyRelease
    );
    let text = serde_json::to_string(&t).unwrap();
    assert!(!text.contains(BEN), "{text}");
    // No export route (derived assets and exports are the next step).
    let (s, _) = g.t.call(
        &g.ben_dev,
        "POST",
        &format!("/v1/assets/{}/exports", v.asset),
        Some(json!({"recipient": BEN})),
    );
    assert_eq!(s, 404);
}

// --- step 6: derived results, source revocation downstream, exports ------------------

/// A governed job that ran to success: its source version, authorization,
/// job and GovernanceId.
struct Released {
    v: Version,
    a: Auth,
    job: String,
    governance_id: String,
}

fn succeeded(g: &G, label: &str, edit: impl FnOnce(&mut AuthorizationV2)) -> Released {
    let (v, a, program, j) = g.job(label, edit);
    let job = id(&j);
    let governance_id = run(g, &program, &job);
    Released {
        v,
        a,
        job,
        governance_id,
    }
}

/// Runs queued governed job `job` of `program` to success: start, the
/// evaluator's v4 receipt, completion. Returns its GovernanceId.
fn run(g: &G, program: &str, job: &str) -> String {
    let grant = g.grant(job);
    let gov = grant.governance.clone().unwrap();
    g.t.ok(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    let spec = base_spec(program).governed(&gov.binding);
    let r = g.receipt(program, &spec, Some(grant.digest()));
    let msg = serde_json::to_value(
        encompute_control::transport::seal(
            &g.evaluator.signer,
            "job.completed",
            "control-plane",
            encompute_control::transport::Scope {
                job: Some(job.to_owned()),
                ..Default::default()
            },
            &json!({"receipt": r}),
            300,
        )
        .unwrap(),
    )
    .unwrap();
    g.t.ok(&g.evaluator.service, "POST", "/v1/messages", Some(msg));
    let (s, done) = g.complete(job, &r);
    assert_eq!(
        (s, done["state"].as_str()),
        (200, Some("succeeded")),
        "{done}"
    );
    gov.governance_id
}

/// Benefits as a custodian: its active governance key and its own key
/// broker.
struct Custodian {
    sec: As,
    owner: As,
    key: SigningKey,
}

fn custodian(g: &G) -> Custodian {
    let admin = As::User("b-admin".into());
    let sec = user(&g.t, &admin, BEN, "b-sec1", &["security_admin"]);
    let governance = key(9);
    let v = g.t.ok(
        &admin,
        "POST",
        &format!("/v1/organizations/{BEN}/governance-keys"),
        Some(json!({"public_key": pk(&governance), "kms_key_ref": "vault:transit/governance"})),
    );
    g.t.ok(
        &sec,
        "POST",
        &format!("/v1/organizations/{BEN}/governance-keys/{}/approve", id(&v)),
        None,
    );
    broker_account(&g.t, &admin, BEN, "ben-broker", 32);
    let (s, v) = g.t.call(
        &sec,
        "POST",
        &format!("/v1/organizations/{BEN}/key-brokers"),
        Some(json!({"id": "ben-broker", "grant_public_key": pk(&key(43)),
                    "provider_kind": "openbao-transit", "key_ref_namespace": "transit/ben"})),
    );
    assert_eq!(s, 201, "{v}");
    let owner = user(&g.t, &admin, BEN, "b-owner", &["data_owner"]);
    // Benefits accepts the purpose, so it can authorize its results.
    let acceptance = PurposeAcceptance {
        version: 1,
        organization: BEN.into(),
        project: g.project.clone(),
        purpose_id: g.purpose.clone(),
        accepted_at: now(),
    }
    .sign(&governance)
    .unwrap();
    g.t.ok(
        &sec,
        "POST",
        &format!("/v1/purposes/{}/accept", g.purpose),
        Some(json!({"acceptance": acceptance})),
    );
    Custodian {
        sec,
        owner,
        key: governance,
    }
}

/// The derived result's onward policy: tax's registered policy, unchanged.
fn onward() -> Value {
    registered(TAX)["ir_policy"].clone()
}

fn derived_version(label: &str) -> String {
    encompute_verification::governance::AssetVersion {
        version: encompute_verification::governance::ASSET_VERSION_VERSION,
        organization: BEN.into(),
        series: "eligibility".into(),
        label: label.into(),
        digest: "e".repeat(64),
    }
    .id()
    .hex()
}

/// The custodian's record of `rel`'s output as version `label`, exported
/// to benefits under `export_key`.
fn record(
    g: &G,
    rel: &Released,
    label: &str,
    policy: &Value,
    export_key: &str,
) -> encompute_trust::authz::ReleaseRecord {
    encompute_trust::authz::ReleaseRecord {
        version: 1,
        party: BEN.into(),
        project: g.project.clone(),
        purpose_id: g.purpose.clone(),
        job_id: rel.job.clone(),
        governance_id: rel.governance_id.clone(),
        output: "out".into(),
        output_commitment: "f".repeat(64),
        derived_version_id: derived_version(label),
        release_class: ReleaseClass::BooleanOnly,
        parents: [rel.v.version.clone()].into(),
        authorization_ids: [rel.a.id.clone()].into(),
        onward_policy_id: encompute_control::onward_policy_id(policy).unwrap(),
        recipients: [(BEN.to_string(), export_key.to_owned())].into(),
        lineage_owners: [(
            TAX.to_string(),
            encompute_trust::authz::governance_key_id(&pk(&g.tax_key)),
        )]
        .into(),
        issued_at: now(),
    }
}

fn derived_body(
    label: &str,
    policy: &Value,
    class: &str,
    record: encompute_trust::authz::ReleaseRecord,
    key: &SigningKey,
) -> Value {
    json!({"output": "out", "kind": "dataset", "series": "eligibility", "version": label,
           "digest": "e".repeat(64),
           "key_ref": {"broker": "ben-broker", "provider": "openbao-transit",
                       "key_ref": format!("result-{label}"), "key_version": 1},
           "ir_policy": policy, "release_class": class,
           "release_record": record.sign(key).unwrap()})
}

fn register_derived(g: &G, who: &As, job: &str, body: Value) -> (u16, Value) {
    g.t.call(
        who,
        "POST",
        &format!("/v1/jobs/{job}/derived-assets"),
        Some(body),
    )
}

/// A succeeded job's result, recorded by benefits as a derived asset: (the
/// release, the custodian, the derived asset's ID, the recipient's export
/// key pair).
fn derived(
    g: &G,
    label: &str,
    edit: impl FnOnce(&mut AuthorizationV2),
) -> (
    Released,
    Custodian,
    String,
    encompute_attestation::ExportRecipient,
) {
    let rel = succeeded(g, label, edit);
    let c = custodian(g);
    let recipient = encompute_attestation::ExportRecipient::generate();
    let policy = onward();
    let rec = record(g, &rel, label, &policy, &recipient.public_key_hex());
    let (s, v) = register_derived(
        g,
        &g.ben_dev,
        &rel.job,
        derived_body(label, &policy, "boolean-only", rec, &c.key),
    );
    assert_eq!(s, 201, "{v}");
    let d = id(&v);
    (rel, c, d, recipient)
}

fn export(g: &G, who: &As, asset: &str, body: Value) -> (u16, Value) {
    g.t.call(
        who,
        "POST",
        &format!("/v1/assets/{asset}/exports"),
        Some(body),
    )
}

/// A derived result's policy and class are never wider than its parents':
/// a wider onward policy, a wider class, or a record naming a recipient no
/// authorization names is refused (ENC2709); within them it is recorded,
/// its parents the job's exact source versions.
#[test]
fn derived_policy_wider_than_parents_fails() {
    let Some(g) = world() else { return };
    let rel = succeeded(&g, "2026-q1", |_| {});
    let c = custodian(&g);
    let xk = encompute_attestation::ExportRecipient::generate().public_key_hex();
    let label = "2026-q1-result";
    // Readers wider than the parent's.
    let mut wide = onward();
    wide["readers"] = json!([BEN, OTHER, TAX]);
    let rec = record(&g, &rel, label, &wide, &xk);
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &rel.job,
            derived_body(label, &wide, "boolean-only", rec, &c.key),
        ),
        "ENC2709",
    );
    // A release weaker than the parent's.
    let mut public = onward();
    public["release"] = json!("public");
    let rec = record(&g, &rel, label, &public, &xk);
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &rel.job,
            derived_body(label, &public, "boolean-only", rec, &c.key),
        ),
        "ENC2709",
    );
    // A class wider than the output's, the parent's and the ceiling.
    let policy = onward();
    let mut rec = record(&g, &rel, label, &policy, &xk);
    rec.release_class = ReleaseClass::AuthorizedAgencyOnly;
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &rel.job,
            derived_body(label, &policy, "authorized-agency-only", rec, &c.key),
        ),
        "ENC2709",
    );
    // A record naming a recipient the authorization does not.
    let mut rec = record(&g, &rel, label, &policy, &xk);
    rec.recipients.insert(OTHER.into(), xk.clone());
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &rel.job,
            derived_body(label, &policy, "boolean-only", rec, &c.key),
        ),
        "ENC2709",
    );
    // A record of other parents, or signed with another key.
    let mut rec = record(&g, &rel, label, &policy, &xk);
    rec.parents = ["3".repeat(64)].into();
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &rel.job,
            derived_body(label, &policy, "boolean-only", rec, &c.key),
        ),
        "ENC2704",
    );
    let rec = record(&g, &rel, label, &policy, &xk);
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &rel.job,
            derived_body(label, &policy, "boolean-only", rec, &key(10)),
        ),
        "ENC2701",
    );
    // Narrower is fine: fewer readers, a stricter release.
    let mut narrow = onward();
    narrow["readers"] = json!([BEN]);
    narrow["release"] = json!("owner_only");
    let rec = record(&g, &rel, label, &narrow, &xk);
    let (s, v) = register_derived(
        &g,
        &g.ben_dev,
        &rel.job,
        derived_body(label, &narrow, "boolean-only", rec, &c.key),
    );
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["custodian"], BEN);
    assert_eq!(v["parents"], json!([rel.v.asset]));
    assert_eq!(v["version_id"], derived_version(label));
    // Its lineage names its parent and the job.
    let d =
        g.t.ok(&g.ben_dev, "GET", &format!("/v1/assets/{}", id(&v)), None);
    assert_eq!(d["derived_from_job"], json!(rel.job));
    assert_eq!(d["organization"], BEN);
    assert!(d.get("source_revoked_at").is_none(), "{d}");
    // Frozen: the database refuses to move it to another job or custodian.
    let e =
        g.t.control
            .db
            .conn()
            .unwrap()
            .execute(
                "UPDATE assets SET derived_output = 'other' WHERE id = $1",
                &[&id(&v)],
            )
            .unwrap_err();
    assert!(
        e.to_string().contains("immutable") || format!("{e:?}").contains("immutable"),
        "{e:?}"
    );
}

/// Only a person of a recipient organization of the output records it,
/// and only once its job succeeded: not the source owner, not another
/// member, not a service account, not before success; once per output.
#[test]
fn derived_asset_only_by_recipient_human() {
    let Some(g) = world() else { return };
    let c = custodian(&g);
    let xk = encompute_attestation::ExportRecipient::generate().public_key_hex();
    let policy = onward();
    // Before success.
    let (v, a, _, j) = g.job("2026-q0", |_| {});
    let early = Released {
        v,
        a,
        job: id(&j),
        governance_id: g.grant(&id(&j)).governance.unwrap().governance_id,
    };
    let rec = record(&g, &early, "early", &policy, &xk);
    let (s, e) = register_derived(
        &g,
        &g.ben_dev,
        &early.job,
        derived_body("early", &policy, "boolean-only", rec, &c.key),
    );
    assert_eq!(s, 409, "{e}");
    let rel = succeeded(&g, "2026-q1", |_| {});
    let body = || {
        derived_body(
            "q1",
            &policy,
            "boolean-only",
            record(&g, &rel, "q1", &policy, &xk),
            &c.key,
        )
    };
    // The source owner is no recipient of the output.
    refused_status(register_derived(&g, &g.tax_dev, &rel.job, body()), 403);
    // Another member of the project is none either.
    refused_status(register_derived(&g, &g.other_dev, &rel.job, body()), 403);
    // An automation account of benefits is not a person.
    let bot = std::sync::Arc::new(ServiceSigner::from_seed("ben-bot", &[54; 32]).unwrap());
    g.t.ok(
        &As::User("b-admin".into()),
        "POST",
        &format!("/v1/organizations/{BEN}/service-accounts"),
        Some(
            json!({"id": "ben-bot", "kind": "automation", "public_key": bot.public_key_hex(),
                    "roles": ["ml_developer"]}),
        ),
    );
    refused(
        register_derived(&g, &As::Service(bot), &rel.job, body()),
        "ENC2707",
    );
    // Benefits' person records it; its custodian is benefits.
    let (s, v) = register_derived(&g, &c.sec, &rel.job, body());
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["custodian"], BEN);
    // Once per output and custodian.
    let (s, again) = register_derived(&g, &g.ben_dev, &rel.job, body());
    assert!(s >= 400, "{again}");
}

fn refused_status(r: (u16, Value), s: u16) {
    assert_eq!(r.0, s, "{}", r.1);
}

/// K-7: a job inside its window finished, but nothing it released is
/// exported after the window ends (ENC2705).
#[test]
fn export_after_valid_until_refused_2705() {
    let Some(g) = world() else { return };
    let until = now() + 15;
    let (_, _, d, _) = derived(&g, "2026-q1", |b| b.valid_until = until);
    after(until);
    refused(
        export(&g, &g.ben_dev, &d, json!({"recipient": BEN})),
        "ENC2705",
    );
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM exports WHERE asset_id = $1", &[&d])
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
}

/// Once a source is revoked, no derived result of it is exported (ENC2706),
/// even when a restored database lost the mark: the ancestors decide.
#[test]
fn export_of_derived_asset_whose_source_was_revoked_2706() {
    let Some(g) = world() else { return };
    let (rel, _, d, _) = derived(&g, "2026-q1", |_| {});
    g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", rel.v.asset),
        None,
    );
    refused(
        export(&g, &g.ben_dev, &d, json!({"recipient": BEN})),
        "ENC2706",
    );
    // An attacker clears the mark: the revoked ancestor still refuses.
    attacker(
        &g.t.env0.url,
        &["assets"],
        &format!("UPDATE assets SET source_revoked_at = NULL WHERE id = '{d}'"),
    );
    refused(
        export(&g, &g.ben_dev, &d, json!({"recipient": BEN})),
        "ENC2706",
    );
}

/// An export goes only to a recipient every authorization in the lineage
/// names (and never to an auditor or an unknown organization).
#[test]
fn export_to_unnamed_recipient_2709() {
    let Some(g) = world() else { return };
    let (_, _, d, _) = derived(&g, "2026-q1", |_| {});
    refused(
        export(&g, &g.ben_dev, &d, json!({"recipient": OTHER})),
        "ENC2709",
    );
    refused(
        export(&g, &g.ben_dev, &d, json!({"recipient": TAX})),
        "ENC2709",
    );
    // The custodian's export to benefits itself is named.
    let (s, v) = export(&g, &g.ben_dev, &d, json!({"recipient": BEN}));
    assert_eq!(s, 201, "{v}");
    // Only the custodian's people export it.
    refused_status(export(&g, &g.tax_owner, &d, json!({"recipient": BEN})), 404);
}

/// The export's class is within the result's own class and every ancestor
/// authorization's ceiling.
#[test]
fn export_class_within_every_ancestor() {
    let Some(g) = world() else { return };
    let (_, _, d, _) = derived(&g, "2026-q1", |_| {});
    // Wider than the result's class and the authorization's ceiling (both
    // boolean-only).
    refused(
        export(
            &g,
            &g.ben_dev,
            &d,
            json!({"recipient": BEN, "release_class": "aggregate-only"}),
        ),
        "ENC2709",
    );
    refused(
        export(
            &g,
            &g.ben_dev,
            &d,
            json!({"recipient": BEN, "release_class": "authorized-agency-only"}),
        ),
        "ENC2709",
    );
    let (s, v) = export(
        &g,
        &g.ben_dev,
        &d,
        json!({"recipient": BEN, "release_class": "boolean-only"}),
    );
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["release_class"], "boolean-only");
}

/// Benefits' key broker as custodian of derived result `d` (key
/// `result-2026-q1`): its governance key pinned, the result's key bound to
/// the custodian's record with the control plane's co-signature (as stored
/// at registration), and tax's governance key pinned from the control
/// plane's attestation of it (fetched by a benefits member). Returns the
/// broker and the record.
fn custodian_broker(
    g: &G,
    c: &Custodian,
    d: &str,
    execution_spec_id: &str,
) -> (
    encompute_keybroker::KeyBroker,
    encompute_trust::authz::SignedReleaseRecord,
) {
    use encompute_keybroker::{
        BrokerMode, DevelopmentFileStore, GovernanceConfig, KeyBroker, KeyMaterial,
    };
    let mut db = g.t.control.db.conn().unwrap();
    let row = db
        .query_one(
            "SELECT release_record, release_cosignature FROM assets WHERE id = $1",
            &[&d],
        )
        .unwrap();
    let record: encompute_trust::authz::SignedReleaseRecord =
        serde_json::from_value(row.get(0)).unwrap();
    let cosignature: encompute_trust::authz::SignedDerivedReleaseCosignature =
        serde_json::from_value(row.get(1)).unwrap();
    let mut b = KeyBroker::new(
        "ben-broker",
        BrokerMode::Development,
        encompute_attestation::Verifier::new(),
        Box::new(DevelopmentFileStore),
    )
    .unwrap()
    .with_governance(GovernanceConfig::new(&g.t.control.signer.public_key_hex()))
    .unwrap();
    b.set_organization(BEN).unwrap();
    // (An exported key needs no attestation; the policy only guards a
    // key release of it as a source.)
    let mut policy = encompute_attestation::AttestationPolicy::new(execution_spec_id, None);
    policy.allowed_tee = vec![encompute_attestation::TeeKind::Mock];
    policy.allowed_images = vec![format!("sha256:{}", "4".repeat(64))];
    policy.allow_development = true;
    b.add_secret(
        "result-2026-q1",
        Some(KeyMaterial::from_bytes(b"the derived result's key").unwrap()),
        policy,
    )
    .unwrap();
    b.pin_governance_key(&pk(&c.key)).unwrap();
    b.bind_derived_version("result-2026-q1", &record, &cosignature)
        .unwrap();
    // Tax, whose data the result derives from: its key pinned here from
    // the control plane's attestation of it.
    let a: encompute_trust::authz::SignedGovernanceKeyAttestation = serde_json::from_value(g.t.ok(
        &g.ben_dev,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-key-attestation"),
        None,
    ))
    .unwrap();
    assert!(b.pin_lineage_governance_key(TAX, &a).unwrap());
    (b, record)
}

/// An export ticket is single-use: the control plane records each once
/// (UNIQUE, append-only), and the custodian's broker, which verifies it
/// under the pinned control-plane key and the custodian's signed record,
/// accepts it once (ENC2712).
#[test]
fn replayed_export_ticket_refused_2712() {
    use encompute_keybroker::GovernedExportRequest;
    let Some(g) = world() else { return };
    let (rel, c, d, recipient) = derived(&g, "2026-q1", |_| {});
    let (s, v) = export(&g, &g.ben_dev, &d, json!({"recipient": BEN}));
    assert_eq!(s, 201, "{v}");
    let ticket: encompute_verification::ticket::ReleaseTicket =
        serde_json::from_value(v["ticket"].clone()).unwrap();
    assert_eq!(
        ticket.kind,
        encompute_verification::ticket::TicketKind::Export
    );
    assert_eq!(ticket.recipient.as_deref(), Some(BEN));
    assert_eq!(ticket.workload_or_recipient, recipient.public_key_hex());
    assert_eq!(ticket.broker, "ben-broker");
    assert_eq!(ticket.asset_version_id, derived_version("2026-q1"));
    // The control plane: one export row per ticket, never changed.
    let mut db = g.t.control.db.conn().unwrap();
    let e = db
        .execute(
            "INSERT INTO exports (id, asset_id, ticket_id, recipient, release_class, requested_by)
             VALUES ('exp_replay', $1, $2, $3, 'boolean-only', 'x')",
            &[&d, &ticket.ticket_id, &BEN],
        )
        .unwrap_err();
    assert_eq!(
        e.code(),
        Some(&postgres::error::SqlState::UNIQUE_VIOLATION),
        "{e:?}"
    );
    for sql in [
        "UPDATE exports SET recipient = 'other-co'",
        "DELETE FROM exports",
    ] {
        let e = db.execute(sql, &[]).unwrap_err();
        assert!(format!("{e:?}").contains("append-only"), "{sql}: {e:?}");
    }
    // The custodian's broker.
    let (mut b, record) = custodian_broker(&g, &c, &d, &ticket.execution_spec_id);
    let doc: AuthorizationV2 = serde_json::from_value(
        g.t.ok(
            &g.tax_sec1,
            "GET",
            &format!("/v1/authorizations/{}", rel.a.row),
            None,
        )["body"]
            .clone(),
    )
    .unwrap();
    let req0 = GovernedExportRequest {
        asset_id: "result-2026-q1".into(),
        ticket: ticket.clone(),
        release_record: record.clone(),
    };
    // Without it nothing is exported (and the ticket is not spent).
    assert_eq!(
        b.prepare_governed_export(&req0).unwrap_err().code.as_str(),
        "ENC2701"
    );
    b.install_authorization(&doc.sign(&g.tax_key).unwrap())
        .unwrap();
    let req = GovernedExportRequest {
        asset_id: "result-2026-q1".into(),
        ticket,
        release_record: record,
    };
    let p = b.prepare_governed_export(&req).unwrap();
    let (grant, _) = b.finish_release(p).unwrap();
    assert_eq!(
        recipient.open(&grant).unwrap().as_slice(),
        b"the derived result's key"
    );
    let e = b.prepare_governed_export(&req).unwrap_err();
    assert_eq!(e.code.as_str(), "ENC2712", "{e}");
}

/// Revoking a source lists the derived results downstream and marks them,
/// never claiming to erase them: they stay on record (active, their source
/// revocation shown), their job stays succeeded, and nothing more is
/// derived from them.
#[test]
fn revocation_lists_downstream_without_claiming_erasure() {
    let Some(g) = world() else { return };
    let (rel, c, d, _) = derived(&g, "2026-q1", |_| {});
    let r = g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", rel.v.asset),
        None,
    );
    assert_eq!(r["downstream"], json!([d]), "{r}");
    assert_eq!(r["erased"], json!(false), "{r}");
    // Still on record, its source revocation shown.
    let v = g.t.ok(&g.ben_dev, "GET", &format!("/v1/assets/{d}"), None);
    assert_eq!(v["status"], "active", "{v}");
    assert!(v["source_revoked_at"].as_i64().is_some(), "{v}");
    let l = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/assets/{}/lineage", rel.v.asset),
        None,
    );
    let desc = l["descendants"].as_array().unwrap();
    assert!(
        desc.iter()
            .any(|x| x["id"] == json!(d) && x["source_revoked_at"].as_i64().is_some()),
        "{l}"
    );
    assert!(!l.to_string().contains("erased\":true"), "{l}");
    // The job that released it is not undone.
    assert_eq!(g.state(&rel.job), "succeeded");
    // Nothing more is derived from the revoked source.
    let xk = encompute_attestation::ExportRecipient::generate().public_key_hex();
    let policy = onward();
    let rec = record(&g, &rel, "again", &policy, &xk);
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &rel.job,
            derived_body("again", &policy, "boolean-only", rec, &c.key),
        ),
        "ENC2706",
    );
    // The custodian's trail records it.
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action = 'asset.source_revoked'
                AND resource_id = $1 AND organization_id = $2",
                &[&d, &BEN],
            )
            .unwrap()
            .get(0);
    assert_eq!(n, 1);
}

/// Standard projects are unchanged: a revoked asset's children are not
/// marked and the answer lists nothing downstream; derived results and
/// exports belong to governed projects.
#[test]
fn standard_project_unchanged() {
    let Some(g) = world() else { return };
    let parent = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(json!({"organization": TAX, "kind": "dataset", "name": "raw", "digest": "a".repeat(64)})),
    );
    let child = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(json!({"organization": TAX, "kind": "dataset", "name": "clean", "digest": "b".repeat(64),
                    "parents": [id(&parent)]})),
    );
    let r = g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", id(&parent)),
        None,
    );
    let keys: BTreeSet<&str> = r.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    assert_eq!(keys, BTreeSet::from(["id", "status", "failed_jobs"]), "{r}");
    let c = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/assets/{}", id(&child)),
        None,
    );
    for k in ["source_revoked_at", "derived_from_job", "custodian"] {
        assert!(c.get(k).is_none(), "{k}: {c}");
    }
    assert_eq!(c["status"], "active");
    // A standard job's result is not a derived asset; a standard asset is
    // not exported.
    let p = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "statistics"})),
    );
    let plan = g.t.ok(
        &g.tax_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": id(&p), "program": EXACT})),
    );
    let (s, j) = g.submit(
        &g.tax_dev,
        json!({"project": id(&p), "plan": plan["id"], "purpose": "statistics",
               "source_assets": [], "requested_output": "out"}),
        "std-derived",
    );
    assert_eq!(s, 201, "{j}");
    let policy = onward();
    let xk = "7".repeat(64);
    let body = json!({"output": "out", "kind": "dataset", "series": "s", "version": "1",
                      "digest": "e".repeat(64),
                      "key_ref": {"broker": "tax-broker", "provider": "p", "key_ref": "k", "key_version": 1},
                      "ir_policy": policy, "release_class": "boolean-only",
                      "release_record": encompute_trust::authz::ReleaseRecord {
                          version: 1, party: TAX.into(), project: id(&p), purpose_id: "1".repeat(64),
                          job_id: id(&j), governance_id: "2".repeat(64), output: "out".into(),
                          output_commitment: "3".repeat(64), derived_version_id: "4".repeat(64),
                          release_class: ReleaseClass::BooleanOnly, parents: ["5".repeat(64)].into(),
                          authorization_ids: ["6".repeat(64)].into(), onward_policy_id: "8".repeat(64),
                          recipients: [(TAX.to_string(), xk)].into(),
                          lineage_owners: Default::default(), issued_at: now(),
                      }.sign(&g.tax_key).unwrap()});
    refused_status(register_derived(&g, &g.tax_dev, &id(&j), body), 409);
    refused_status(
        export(&g, &g.tax_owner, &id(&child), json!({"recipient": TAX})),
        409,
    );
}

/// Probing: an owner's `max_releases` bounds the exports of results
/// released under its authorization (ENC2714).
#[test]
fn export_respects_release_limits_2714() {
    let Some(g) = world() else { return };
    let (_, _, d, _) = derived(&g, "2026-q1", |b| b.limits.max_releases = Some(1));
    let (s, v) = export(&g, &g.ben_dev, &d, json!({"recipient": BEN}));
    assert_eq!(s, 201, "{v}");
    refused(
        export(&g, &g.ben_dev, &d, json!({"recipient": BEN})),
        "ENC2714",
    );
}

// --- derived results as sources: consent and limits carry through ---------------------

/// `body` proposed by `owner`, approved by `owner` (data owner) and `sec`
/// (security admin), signed with `key`.
fn authorize_with(g: &G, owner: &As, sec: &As, key: &SigningKey, body: AuthorizationV2) -> Auth {
    let v = g.t.ok(
        owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": body})),
    );
    let row = id(&v);
    for (who, role) in [(owner, "data_owner"), (sec, "security_admin")] {
        g.t.ok(
            who,
            "POST",
            &format!("/v1/authorizations/{row}/approve"),
            Some(json!({"role": role})),
        );
    }
    let v =
        g.t.ok(sec, "GET", &format!("/v1/authorizations/{row}"), None);
    let doc: AuthorizationV2 = serde_json::from_value(v["body"].clone()).unwrap();
    let s = doc.sign(key).unwrap();
    let v = g.t.ok(
        sec,
        "POST",
        &format!("/v1/authorizations/{row}/signature"),
        Some(json!({"public_key": s.public_key, "signature": s.signature})),
    );
    Auth {
        row,
        id: v["authorization_id"].as_str().unwrap().to_owned(),
    }
}

/// Benefits' own authorization of its derived result `d` for `program`.
fn custodian_authorizes(g: &G, c: &Custodian, d: &Version, program: &str) -> Auth {
    let mut b = g.body(d, program);
    b.party = BEN.into();
    authorize_with(g, &c.owner, &c.sec, &c.key, b)
}

/// A second job, by benefits, reading derived result `d`.
fn submit_over(g: &G, d: &Version, program: &str, key: &str) -> (u16, Value) {
    let plan = g.plan(&g.ben_dev, program);
    g.submit(&g.ben_dev, g.request(&plan, &[&d.asset], &[BEN]), key)
}

fn derived_version_of(d: &str, label: &str) -> Version {
    Version {
        asset: d.to_owned(),
        version: derived_version(label),
    }
}

/// A derived result used as a source needs an authorization from every
/// owner in its lineage, not only from its custodian (ENC2701); with both,
/// the job runs under both.
#[test]
fn derived_source_needs_every_lineage_owners_authorization() {
    let Some(g) = world() else { return };
    let (_, c, d, _) = derived(&g, "2026-q1", |_| {});
    let d1 = derived_version_of(&d, "2026-q1");
    let p2 = program(&[&d1.asset], PURPOSE, BEN);
    // The custodian alone authorizes its own derived result.
    let ben = custodian_authorizes(&g, &c, &d1, &p2);
    refused(submit_over(&g, &d1, &p2, "k-d2"), "ENC2701");
    // Another organization cannot authorize it, not owning its data.
    let mut other = g.body(&d1, &p2);
    other.party = OTHER.into();
    let (s, _) = g.t.call(
        &As::User("o-admin".into()),
        "POST",
        "/v1/authorizations",
        Some(json!({"body": other})),
    );
    assert!(s >= 400);
    // Tax, whose data it derives from, authorizes too: the job runs under
    // both.
    let tax = g.authorize(g.body(&d1, &p2));
    let (s, j) = submit_over(&g, &d1, &p2, "k-d2b");
    assert_eq!(s, 201, "{j}");
    let bound: BTreeSet<String> =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query(
                "SELECT authorization_id FROM job_authorizations WHERE job_id = $1",
                &[&id(&j)],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
    assert_eq!(bound, BTreeSet::from([ben.id, tax.id.clone()]));
    // Tax revokes its authorization: the queued job fails.
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", tax.row),
        Some(json!({"reason": "withdrawn"})),
    );
    assert_eq!(g.state(&id(&j)), "failed");
}

/// Executions of jobs reading a derived result count against the original
/// source's authorization (ENC2714), however many hops away.
#[test]
fn multi_hop_executions_count_against_original_authorization_2714() {
    let Some(g) = world() else { return };
    let (_, c, d, _) = derived(&g, "2026-q1", |b| b.limits.max_executions = Some(1));
    let d1 = derived_version_of(&d, "2026-q1");
    let p2 = program(&[&d1.asset], PURPOSE, BEN);
    custodian_authorizes(&g, &c, &d1, &p2);
    g.authorize(g.body(&d1, &p2));
    // Both authorizations of the derived result allow 1000 executions; the
    // original allowed one, used by the first job.
    refused(submit_over(&g, &d1, &p2, "k-d2"), "ENC2714");
}

/// Exports of results derived from a derived result count against the
/// original source's authorization (ENC2714).
#[test]
fn multi_hop_exports_count_against_original_authorization_2714() {
    let Some(g) = world() else { return };
    let (_, c, d, recipient) = derived(&g, "2026-q1", |b| b.limits.max_releases = Some(1));
    let d1 = derived_version_of(&d, "2026-q1");
    let p2 = program(&[&d1.asset], PURPOSE, BEN);
    let ben = custodian_authorizes(&g, &c, &d1, &p2);
    let tax = g.authorize(g.body(&d1, &p2));
    let (s, j) = submit_over(&g, &d1, &p2, "k-d2");
    assert_eq!(s, 201, "{j}");
    let j2 = id(&j);
    let gid = run(&g, &p2, &j2);
    // The second hop's result.
    let policy = onward();
    let rel2 = Released {
        v: d1.clone(),
        a: Auth {
            row: ben.row.clone(),
            id: ben.id.clone(),
        },
        job: j2.clone(),
        governance_id: gid,
    };
    let mut rec = record(&g, &rel2, "2026-q1-b", &policy, &recipient.public_key_hex());
    rec.authorization_ids = [ben.id.clone(), tax.id.clone()].into();
    let (s, v) = register_derived(
        &g,
        &g.ben_dev,
        &j2,
        derived_body("2026-q1-b", &policy, "boolean-only", rec, &c.key),
    );
    assert_eq!(s, 201, "{v}");
    let d2 = id(&v);
    // One export of the first result uses the original's one release.
    let (s, v) = export(&g, &g.ben_dev, &d, json!({"recipient": BEN}));
    assert_eq!(s, 201, "{v}");
    // The second hop's export counts against it too.
    refused(
        export(&g, &g.ben_dev, &d2, json!({"recipient": BEN})),
        "ENC2714",
    );
}

/// A queued job over a derived result fails when the original source is
/// revoked, cannot start, and no new one is submitted (ENC2706).
#[test]
fn job_over_derived_source_fails_after_original_source_revoked() {
    let Some(g) = world() else { return };
    let (rel, c, d, _) = derived(&g, "2026-q1", |_| {});
    let d1 = derived_version_of(&d, "2026-q1");
    let p2 = program(&[&d1.asset], PURPOSE, BEN);
    custodian_authorizes(&g, &c, &d1, &p2);
    g.authorize(g.body(&d1, &p2));
    let (s, j) = submit_over(&g, &d1, &p2, "k-d2");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "queued", "{j}");
    let r = g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", rel.v.asset),
        None,
    );
    assert!(
        r["failed_jobs"]
            .as_array()
            .unwrap()
            .contains(&json!(id(&j))),
        "{r}"
    );
    assert_eq!(g.state(&id(&j)), "failed");
    let (s, _) = g.start(&id(&j));
    assert!(s >= 400);
    refused(submit_over(&g, &d1, &p2, "k-d2c"), "ENC2706");
}

/// A derived result is hidden from a project member that is neither its
/// custodian, a recipient its record names, nor an owner of its data.
#[test]
fn derived_asset_hidden_from_unrelated_member() {
    let Some(g) = world() else { return };
    let (rel, _, d, _) = derived(&g, "2026-q1", |_| {});
    refused_status(
        g.t.call(&g.other_dev, "GET", &format!("/v1/assets/{d}"), None),
        404,
    );
    let l = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/assets/{}/lineage", rel.v.asset),
        None,
    );
    assert!(l.to_string().contains(&d), "{l}");
    let l = g.t.call(
        &g.other_dev,
        "GET",
        &format!("/v1/assets/{d}/lineage"),
        None,
    );
    assert_eq!(l.0, 404, "{}", l.1);
}

/// The owners of the data a result derives from, and the recipients its
/// record names, see it (redacted); its custodian sees it in full.
#[test]
fn derived_asset_visible_to_lineage_owner_and_recipient() {
    let Some(g) = world() else { return };
    let (_, _, d, _) = derived(&g, "2026-q1", |_| {});
    let owner =
        g.t.ok(&g.tax_owner, "GET", &format!("/v1/assets/{d}"), None);
    assert!(owner["derived_from_job"].is_string(), "{owner}");
    assert!(owner.get("key_ref").is_none(), "{owner}");
    let custodian = g.t.ok(&g.ben_dev, "GET", &format!("/v1/assets/{d}"), None);
    assert!(custodian["key_ref"].is_object(), "{custodian}");
    // A recipient the record names that is neither custodian nor owner
    // sees it too. (No authorization here names another organization, so
    // the record is edited in place, bypassing its guards, to show the
    // rule alone decides.)
    refused_status(
        g.t.call(&g.other_dev, "GET", &format!("/v1/assets/{d}"), None),
        404,
    );
    attacker(
        &g.t.env0.url,
        &["assets"],
        &format!(
            "UPDATE assets SET release_record = jsonb_set(release_record, '{{body,recipients,{OTHER}}}', '\"{}\"')
              WHERE id = '{d}'",
            "8".repeat(64)
        ),
    );
    let seen =
        g.t.ok(&g.other_dev, "GET", &format!("/v1/assets/{d}"), None);
    assert!(seen.get("key_ref").is_none(), "{seen}");
}

// --- what the custodian's broker takes from the control plane -------------------------

/// The control plane attests an organization's governance key, signed
/// under its own domain with its service key, from its record of approved
/// keys: the active key, or the one named (revoked ones as revoked), to
/// members of organizations that share a project with it only.
#[test]
fn control_plane_attests_governance_keys() {
    let Some(g) = world() else { return };
    let control = g.t.control.signer.public_key_hex();
    let url = format!("/v1/organizations/{TAX}/governance-key-attestation");
    let a: encompute_trust::authz::SignedGovernanceKeyAttestation =
        serde_json::from_value(g.t.ok(&g.ben_dev, "GET", &url, None)).unwrap();
    a.verify(&control).unwrap();
    assert_eq!(a.body.organization, TAX);
    assert_eq!(a.body.public_key, pk(&g.tax_key));
    assert_eq!(
        a.body.key_id,
        encompute_trust::authz::governance_key_id(&pk(&g.tax_key))
    );
    assert_eq!(
        a.body.status,
        encompute_trust::authz::GovernanceKeyStatus::Active
    );
    // Not a release ticket or any other statement: its own domain.
    assert!(encompute_verification::service::verify_signed(
        &control,
        encompute_verification::ticket::KEY_TICKET,
        &a.body,
        &a.signature
    )
    .is_err());
    // Its own members, and other project members, see it; an organization
    // sharing no project with it does not.
    g.t.ok(&g.tax_dev, "GET", &url, None);
    g.t.ok(&g.other_dev, "GET", &url, None);
    let platform = As::User("platform-admin".into());
    g.t.ok(
        &platform,
        "POST",
        "/v1/organizations",
        Some(json!({"id": "outsider-co", "display_name": "outsider-co",
                    "admin": {"issuer": DEV_ISSUER, "subject": "x-admin"}})),
    );
    let outsider = user(
        &g.t,
        &As::User("x-admin".into()),
        "outsider-co",
        "x-dev",
        &["ml_developer"],
    );
    refused_status(g.t.call(&outsider, "GET", &url, None), 404);
    // Revoked: attested as revoked, by key ID; no active key is attested.
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let row = keys
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["status"] == "active")
        .unwrap()
        .clone();
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!(
            "/v1/organizations/{TAX}/governance-keys/{}/revoke",
            row["id"].as_str().unwrap()
        ),
        None,
    );
    refused(g.t.call(&g.ben_dev, "GET", &url, None), "ENC2708");
    let r: encompute_trust::authz::SignedGovernanceKeyAttestation = serde_json::from_value(g.t.ok(
        &g.ben_dev,
        "GET",
        &format!("{url}?key_id={}", a.body.key_id),
        None,
    ))
    .unwrap();
    r.verify(&control).unwrap();
    assert_eq!(
        r.body.status,
        encompute_trust::authz::GovernanceKeyStatus::Revoked
    );
    assert!(r.body.revoked_at.is_some());
    refused_status(
        g.t.call(
            &g.ben_dev,
            "GET",
            &format!("{url}?key_id={}", "0".repeat(64)),
            None,
        ),
        404,
    );
}

/// Recording a derived result, the control plane co-signs the custodian's
/// record it validated against the result's real ancestry (every lineage
/// owner named), for the custodian's broker and key; a record leaving a
/// lineage owner out is refused and never co-signed (ENC2704).
#[test]
fn derived_registration_cosigns_validated_record() {
    let Some(g) = world() else { return };
    let rel = succeeded(&g, "2026-q1", |_| {});
    let c = custodian(&g);
    let xk = encompute_attestation::ExportRecipient::generate().public_key_hex();
    let policy = onward();
    // Leaving tax out.
    let mut omitting = record(&g, &rel, "2026-q1", &policy, &xk);
    omitting.lineage_owners.clear();
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &rel.job,
            derived_body("2026-q1", &policy, "boolean-only", omitting, &c.key),
        ),
        "ENC2704",
    );
    let honest = record(&g, &rel, "2026-q1", &policy, &xk);
    let honest_id = honest.id();
    let (s, v) = register_derived(
        &g,
        &g.ben_dev,
        &rel.job,
        derived_body("2026-q1", &policy, "boolean-only", honest.clone(), &c.key),
    );
    assert_eq!(s, 201, "{v}");
    let cs: encompute_trust::authz::SignedDerivedReleaseCosignature =
        serde_json::from_value(v["release_cosignature"].clone()).unwrap();
    cs.verify(&g.t.control.signer.public_key_hex()).unwrap();
    assert_eq!(cs.body.organization, BEN);
    assert_eq!(cs.body.asset_id, id(&v));
    assert_eq!(cs.body.broker, "ben-broker");
    assert_eq!(cs.body.key_ref, "result-2026-q1");
    assert_eq!(cs.body.release_record_id, honest_id);
    assert_eq!(cs.body.lineage_owners, honest.lineage_owners);
    assert!(cs.body.lineage_owners.contains_key(TAX));
    // Stored with the result, and as immutable as its record.
    let mut db = g.t.control.db.conn().unwrap();
    let e = db
        .execute(
            "UPDATE assets SET release_cosignature = '{}' WHERE id = $1",
            &[&id(&v)],
        )
        .unwrap_err();
    assert!(format!("{e:?}").contains("immutable"), "{e:?}");
}

/// Revoking an original owner's authorization tells, once the revocation
/// is anchored and never before, the key broker of every custodian holding
/// a result derived from a job under it (deny-only, naming the custodian's
/// organization), and that broker then exports nothing more (ENC2706).
#[test]
fn lineage_revocation_forwarded_to_custodian_brokers() {
    use encompute_keybroker::GovernedExportRequest;
    let Some(g) = world() else { return };
    let (rel, c, d, _) = derived(&g, "2026-q1", |_| {});
    let (s, v) = export(&g, &g.ben_dev, &d, json!({"recipient": BEN}));
    assert_eq!(s, 201, "{v}");
    let ticket: encompute_verification::ticket::ReleaseTicket =
        serde_json::from_value(v["ticket"].clone()).unwrap();
    let (mut b, record) = custodian_broker(&g, &c, &d, &ticket.execution_spec_id);
    let doc: AuthorizationV2 = serde_json::from_value(
        g.t.ok(
            &g.tax_sec1,
            "GET",
            &format!("/v1/authorizations/{}", rel.a.row),
            None,
        )["body"]
            .clone(),
    )
    .unwrap();
    b.install_authorization(&doc.sign(&g.tax_key).unwrap())
        .unwrap();
    g.t.transport.drain();
    // Committed but not yet anchored (a crash between the two): queued for
    // the owner's and the custodian's brokers, and sent to neither.
    let queued =
        g.t.control
            .db
            .tx(|t| {
                t.execute(
                "UPDATE authorizations SET status = 'revoked', revoked_by = 'x', revoked_at = now()
                  WHERE id = $1",
                &[&rel.a.row],
            )
            .unwrap();
                g.t.control
                    .queue_authorization_revoked(t, "x", "test", &rel.a.row)
            })
            .unwrap();
    assert_eq!(queued, 2, "the owner's broker and the custodian's");
    g.t.control.deliver_outbox().unwrap();
    assert!(
        g.t.transport.drain().is_empty(),
        "sent before it was anchored"
    );
    assert!(!g
        .t
        .control
        .anchor
        .snapshot()
        .revoked_authorizations
        .contains(&rel.a.row));
    // Anchored: delivered to the custodian's broker, for its organization.
    g.t.control.tick();
    assert!(g
        .t
        .control
        .anchor
        .snapshot()
        .revoked_authorizations
        .contains(&rel.a.row));
    let sent = g.t.transport.drain();
    let (_, m) = sent
        .iter()
        .find(|(u, m)| u == "http://ben-broker.internal:8760" && m.kind == "authorization.revoked")
        .unwrap_or_else(|| panic!("{sent:?}"));
    assert_eq!(m.recipient, "ben-broker");
    assert_eq!(m.organization.as_deref(), Some(BEN));
    assert_eq!(m.payload["authorization_id"], rel.a.id.as_str());
    assert!(sent
        .iter()
        .any(|(u, m)| u == "http://tax-broker.internal:8760" && m.kind == "authorization.revoked"));
    // The custodian's trail records it.
    let trail = g.t.ok(
        &As::User("b-admin".into()),
        "GET",
        &format!("/v1/audit?organization={BEN}"),
        None,
    );
    assert!(
        trail.to_string().contains("authorization.revocation.sent"),
        "{trail}"
    );
    // At the custodian's broker the message only denies: nothing more is
    // exported under the revoked authorization.
    let at = m.payload["revoked_at"].as_u64().unwrap();
    assert!(b
        .revoke_authorization_from_control(rel.a.id.as_str(), at)
        .unwrap());
    let e = b
        .prepare_governed_export(&GovernedExportRequest {
            asset_id: "result-2026-q1".into(),
            ticket,
            release_record: record,
        })
        .unwrap_err();
    assert_eq!(e.code.as_str(), "ENC2706", "{e}");
}

// --- a derived result's co-signature: re-fetched, and re-issued after a rotation ----

/// The custodian's members re-fetch the control plane's co-signature of a
/// derived result (the one stored at registration while nothing was
/// re-issued); nobody else learns it exists (not found), not even an owner
/// of its data, and a source version has none.
#[test]
fn release_cosignature_refetched_by_custodian_only() {
    let Some(g) = world() else { return };
    let rel = succeeded(&g, "2026-q1", |_| {});
    let c = custodian(&g);
    let xk = encompute_attestation::ExportRecipient::generate().public_key_hex();
    let policy = onward();
    let rec = record(&g, &rel, "2026-q1", &policy, &xk);
    let (s, v) = register_derived(
        &g,
        &g.ben_dev,
        &rel.job,
        derived_body("2026-q1", &policy, "boolean-only", rec, &c.key),
    );
    assert_eq!(s, 201, "{v}");
    let d = id(&v);
    let url = format!("/v1/assets/{d}/release-cosignature");
    for who in [&c.sec, &c.owner] {
        let r = g.t.ok(who, "GET", &url, None);
        assert_eq!(r["release_cosignature"], v["release_cosignature"], "{r}");
        assert_eq!(r["registered_cosignature"], v["release_cosignature"], "{r}");
        assert_eq!(r["reissued"], 0, "{r}");
    }
    let cs: encompute_trust::authz::SignedDerivedReleaseCosignature =
        serde_json::from_value(g.t.ok(&c.sec, "GET", &url, None)["release_cosignature"].clone())
            .unwrap();
    cs.verify(&g.t.control.signer.public_key_hex()).unwrap();
    // Other people of the custodian: refused like the re-issue (403).
    let auditor = user(
        &g.t,
        &As::User("b-admin".into()),
        BEN,
        "b-auditor",
        &["auditor"],
    );
    for who in [&g.ben_dev, &auditor] {
        refused_status(g.t.call(who, "GET", &url, None), 403);
    }
    // A lineage owner, another member, the evaluator: not found.
    for who in [
        &g.tax_owner,
        &g.tax_sec1,
        &g.other_dev,
        &g.evaluator.service,
    ] {
        refused_status(g.t.call(who, "GET", &url, None), 404);
    }
    // A source version has no co-signature.
    refused_status(
        g.t.call(
            &g.tax_owner,
            "GET",
            &format!("/v1/assets/{}/release-cosignature", rel.v.asset),
            None,
        ),
        404,
    );
}

/// Tax rotates its governance key: its active key is revoked and `new`
/// approved. Returns the new key's ID.
fn rotate_tax_key(g: &G, new: &SigningKey) -> String {
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let active = keys
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["status"] == "active")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{active}/revoke"),
        None,
    );
    let v = g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        Some(json!({"public_key": pk(new), "kms_key_ref": "vault:transit/governance-2"})),
    );
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{}/approve", id(&v)),
        None,
    );
    encompute_trust::authz::governance_key_id(&pk(new))
}

/// After a lineage owner rotates its governance key, a security admin of
/// the custodian has the control plane re-issue its co-signature with the
/// owner's current key ID (the record, version, key and broker unchanged,
/// a later issue time), audited for the custodian and the owner; the
/// custodian's broker, which pinned the new key from the control plane's
/// attestation, re-binds the result's key with it. Nobody else re-issues
/// it, and nothing is re-issued while every key is current (409) or an
/// owner has no active key (ENC2708).
#[test]
fn rotation_rebind_reissues_cosignature() {
    let Some(g) = world() else { return };
    let (rel, c, d, _) = derived(&g, "2026-q1", |_| {});
    let url = format!("/v1/assets/{d}/release-cosignature");
    let registered: encompute_trust::authz::SignedDerivedReleaseCosignature =
        serde_json::from_value(g.t.ok(&c.sec, "GET", &url, None)["release_cosignature"].clone())
            .unwrap();
    // Nothing rotated: nothing to re-issue.
    refused_status(g.t.call(&c.sec, "POST", &url, None), 409);
    // Revoked, not yet replaced: no active key to re-bind to.
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let rotated = key(17);
    let new_id = {
        let _ = keys;
        rotate_tax_key(&g, &rotated)
    };
    // Only the custodian's security admin, a person.
    refused_status(g.t.call(&g.ben_dev, "POST", &url, None), 403);
    refused_status(g.t.call(&c.owner, "POST", &url, None), 403);
    refused_status(g.t.call(&g.tax_sec1, "POST", &url, None), 404);
    let r = g.t.ok(&c.sec, "POST", &url, None);
    let reissued: encompute_trust::authz::SignedDerivedReleaseCosignature =
        serde_json::from_value(r["release_cosignature"].clone()).unwrap();
    reissued
        .verify(&g.t.control.signer.public_key_hex())
        .unwrap();
    assert_eq!(reissued.body.lineage_owners[TAX], new_id);
    assert!(reissued.body.issued_at > registered.body.issued_at);
    for (what, same) in [
        (
            "custodian",
            reissued.body.organization == registered.body.organization,
        ),
        ("asset", reissued.body.asset_id == registered.body.asset_id),
        ("broker", reissued.body.broker == registered.body.broker),
        ("key", reissued.body.key_ref == registered.body.key_ref),
        (
            "version",
            reissued.body.derived_version_id == registered.body.derived_version_id,
        ),
        (
            "record",
            reissued.body.release_record_id == registered.body.release_record_id,
        ),
    ] {
        assert!(same, "{what} changed");
    }
    // The re-fetch returns it now; the registration's stays as it was.
    let f = g.t.ok(&c.sec, "GET", &url, None);
    assert_eq!(f["release_cosignature"], r["release_cosignature"]);
    assert_eq!(
        f["registered_cosignature"],
        serde_json::to_value(&registered).unwrap()
    );
    assert_eq!(f["reissued"], 1);
    refused_status(g.t.call(&c.sec, "POST", &url, None), 409);
    // Append-only.
    let mut db = g.t.control.db.conn().unwrap();
    for sql in [
        "UPDATE derived_cosignatures SET issued_at = 0",
        "DELETE FROM derived_cosignatures",
    ] {
        let e = db.execute(sql, &[]).unwrap_err();
        assert!(format!("{e:?}").contains("append-only"), "{sql}: {e:?}");
    }
    // Audited for the custodian and the lineage owner.
    for org in [BEN, TAX] {
        let n: i64 = db
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action = 'asset.release_cosignature_reissued'
                  AND resource_id = $1 AND organization_id = $2",
                &[&d, &org],
            )
            .unwrap()
            .get(0);
        assert_eq!(n, 1, "{org}");
    }
    // The custodian's broker: bound under the old key ID, it pins tax's
    // new key from the control plane's attestation and re-binds.
    let spec = g.grant(&rel.job).spec_id;
    let (mut b, _) = custodian_broker(&g, &c, &d, &spec);
    assert_eq!(
        b.state().secrets["result-2026-q1"].lineage_owners[TAX],
        registered.body.lineage_owners[TAX]
    );
    assert!(b
        .rebind_derived_lineage("result-2026-q1", &reissued)
        .unwrap());
    assert_eq!(
        b.state().secrets["result-2026-q1"].lineage_owners[TAX],
        new_id
    );
    // The registration's co-signature, older, re-binds nothing back.
    assert_eq!(
        b.rebind_derived_lineage("result-2026-q1", &registered)
            .unwrap_err()
            .code
            .as_str(),
        "ENC2704"
    );
    // An owner left without an active key: nothing is re-issued.
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let active = keys
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["status"] == "active")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{active}/revoke"),
        None,
    );
    refused(g.t.call(&c.sec, "POST", &url, None), "ENC2708");
}

// --- retention ----------------------------------------------------------------------

fn retention(g: &G, who: &As, asset: &str, body: Value) -> (u16, Value) {
    g.t.call(
        who,
        "POST",
        &format!("/v1/assets/{asset}/retention"),
        Some(body),
    )
}

fn db_message(e: &postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string())
}

/// A version past its deletion date is used by no job (ENC2705), before
/// the background expiry and after it; once expired, its owner sees when.
#[test]
fn version_past_delete_after_is_not_used_2705() {
    let Some(g) = world() else { return };
    let delete_after = now() + 3;
    let v = g.version("2026-q1", json!({"delete_after": delete_after}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let plan = g.plan(&g.ben_dev, &p);
    after(delete_after);
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1"),
        "ENC2705",
    );
    // The background expiry marks it, anchored.
    assert_eq!(g.t.control.expire_assets().unwrap(), vec![v.asset.clone()]);
    assert!(g
        .t
        .control
        .anchor
        .snapshot()
        .expired_assets
        .contains(&v.asset));
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k2"),
        "ENC2705",
    );
    let a = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/assets/{}", v.asset),
        None,
    );
    assert!(a["expired_at"].as_i64().is_some(), "{a}");
    assert_eq!(a["delete_after"], json!(delete_after), "{a}");
    // Nothing more to expire.
    assert!(g.t.control.expire_assets().unwrap().is_empty());
}

/// Once its owner brings a source's deletion date to now, the source
/// expires: a queued job over it fails (anchored as ended) and never
/// starts, and nothing derived from it is derived from again or exported
/// (ENC2705).
#[test]
fn expired_source_blocks_start_and_export() {
    let Some(g) = world() else { return };
    let (v, _, job) = queued(&g, "2026-q1");
    let (s, r) = retention(&g, &g.tax_owner, &v.asset, json!({"delete_after": now()}));
    assert_eq!(s, 200, "{r}");
    assert_eq!(r["expires_now"], true, "{r}");
    assert_eq!(g.state(&job), "failed");
    assert!(g.t.control.anchor.snapshot().ended_jobs.contains(&job));
    let (s, _) = g.start(&job);
    assert!(s >= 400);
    // A derived result of another version.
    let (rel, c, d, _) = derived(&g, "2026-q2", |_| {});
    let (s, _) = export(&g, &g.ben_dev, &d, json!({"recipient": BEN}));
    assert_eq!(s, 201);
    let (s, r) = retention(
        &g,
        &g.tax_owner,
        &rel.v.asset,
        json!({"delete_after": now()}),
    );
    assert_eq!(s, 200, "{r}");
    refused(
        export(&g, &g.ben_dev, &d, json!({"recipient": BEN})),
        "ENC2705",
    );
    let xk = encompute_attestation::ExportRecipient::generate().public_key_hex();
    let policy = onward();
    let rec = record(&g, &rel, "again", &policy, &xk);
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &rel.job,
            derived_body("again", &policy, "boolean-only", rec, &c.key),
        ),
        "ENC2705",
    );
}

/// A job that started before its source's deletion date may finish (as a
/// job running when its window ends does), but nothing it released is
/// recorded as a derived result after the source expired (ENC2705).
#[test]
fn job_started_before_expiry_finishes_but_nothing_is_derived() {
    let Some(g) = world() else { return };
    let (v, a, program, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    let grant = g.grant(&job);
    let gov = grant.governance.clone().unwrap();
    g.t.ok(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/start"),
        None,
    );
    let (s, r) = retention(&g, &g.tax_owner, &v.asset, json!({"delete_after": now()}));
    assert_eq!(s, 200, "{r}");
    assert_eq!(g.state(&job), "running", "a running job is not failed");
    let spec = base_spec(&program).governed(&gov.binding);
    let receipt = g.receipt(&program, &spec, Some(grant.digest()));
    let msg = serde_json::to_value(
        encompute_control::transport::seal(
            &g.evaluator.signer,
            "job.completed",
            "control-plane",
            encompute_control::transport::Scope {
                job: Some(job.clone()),
                ..Default::default()
            },
            &json!({"receipt": receipt}),
            300,
        )
        .unwrap(),
    )
    .unwrap();
    g.t.ok(&g.evaluator.service, "POST", "/v1/messages", Some(msg));
    let (s, done) = g.complete(&job, &receipt);
    assert_eq!(
        (s, done["state"].as_str()),
        (200, Some("succeeded")),
        "{done}"
    );
    let c = custodian(&g);
    let rel = Released {
        v,
        a,
        job: job.clone(),
        governance_id: gov.governance_id,
    };
    let xk = encompute_attestation::ExportRecipient::generate().public_key_hex();
    let policy = onward();
    let rec = record(&g, &rel, "2026-q1", &policy, &xk);
    refused(
        register_derived(
            &g,
            &g.ben_dev,
            &job,
            derived_body("2026-q1", &policy, "boolean-only", rec, &c.key),
        ),
        "ENC2705",
    );
}

/// A source's expiry reaches every derived result downstream like a
/// revocation: each is marked source-expired (set once; the custodian's
/// trail records it), their queued jobs fail, and none is used again
/// (ENC2705), even when a restored database lost the mark: the walk up the
/// lineage decides.
#[test]
fn expiry_cascades_to_derived_assets() {
    let Some(g) = world() else { return };
    let (rel, c, d, _) = derived(&g, "2026-q1", |_| {});
    let d1 = derived_version_of(&d, "2026-q1");
    let p2 = program(&[&d1.asset], PURPOSE, BEN);
    custodian_authorizes(&g, &c, &d1, &p2);
    g.authorize(g.body(&d1, &p2));
    let (s, j) = submit_over(&g, &d1, &p2, "k-d2");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "queued", "{j}");
    let (s, r) = retention(
        &g,
        &g.tax_owner,
        &rel.v.asset,
        json!({"delete_after": now()}),
    );
    assert_eq!(s, 200, "{r}");
    assert_eq!(g.state(&id(&j)), "failed");
    let v = g.t.ok(&g.ben_dev, "GET", &format!("/v1/assets/{d}"), None);
    assert!(v["source_expired_at"].as_i64().is_some(), "{v}");
    assert_eq!(v["status"], "active", "{v}");
    let mut db = g.t.control.db.conn().unwrap();
    let n: i64 = db
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'asset.source_expired'
              AND resource_id = $1 AND organization_id = $2",
            &[&d, &BEN],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1);
    refused(submit_over(&g, &d1, &p2, "k-d2b"), "ENC2705");
    // Set once.
    let e = db
        .execute(
            "UPDATE assets SET source_expired_at = NULL WHERE id = $1",
            &[&d],
        )
        .unwrap_err();
    assert!(db_message(&e).contains("source expiry is final"), "{e}");
    // An attacker clears the marks: the expired ancestor still refuses.
    attacker(
        &g.t.env0.url,
        &["assets"],
        &format!("UPDATE assets SET source_expired_at = NULL WHERE id = '{d}'"),
    );
    refused(submit_over(&g, &d1, &p2, "k-d2c"), "ENC2705");
    refused(
        export(&g, &g.ben_dev, &d, json!({"recipient": BEN})),
        "ENC2705",
    );
}

/// The evidence outlives the source: after the source version expired
/// (its data deleted by its owner's storage), the job's trust report is
/// still satisfied (noting the expiry), the custodian's release record and
/// the control plane's co-signature still verify, the audit chain still
/// checkpoints, the export stays on record and the state still matches
/// its anchor.
#[test]
fn evidence_verifies_after_source_deletion() {
    let Some(g) = world() else { return };
    let (rel, c, d, _) = derived(&g, "2026-q1", |_| {});
    let (s, v) = export(&g, &g.ben_dev, &d, json!({"recipient": BEN}));
    assert_eq!(s, 201, "{v}");
    let (s, r) = retention(
        &g,
        &g.tax_owner,
        &rel.v.asset,
        json!({"delete_after": now()}),
    );
    assert_eq!(s, 200, "{r}");
    assert!(g
        .t
        .control
        .anchor
        .snapshot()
        .expired_assets
        .contains(&rel.v.asset));
    let tr =
        g.t.ok(&g.ben_dev, "GET", &format!("/v1/trust/{}", rel.job), None);
    assert_eq!(tr["verdict"], "SATISFIED", "{tr}");
    assert!(tr.to_string().contains("expired since"), "{tr}");
    let mut db = g.t.control.db.conn().unwrap();
    let row = db
        .query_one(
            "SELECT release_record, release_cosignature FROM assets WHERE id = $1",
            &[&d],
        )
        .unwrap();
    let record: encompute_trust::authz::SignedReleaseRecord =
        serde_json::from_value(row.get(0)).unwrap();
    record.verify(&pk(&c.key)).unwrap();
    let cs: encompute_trust::authz::SignedDerivedReleaseCosignature =
        serde_json::from_value(row.get(1)).unwrap();
    cs.verify(&g.t.control.signer.public_key_hex()).unwrap();
    let n: i64 = db
        .query_one("SELECT count(*) FROM exports WHERE asset_id = $1", &[&d])
        .unwrap()
        .get(0);
    assert_eq!(n, 1);
    g.t.control.checkpoint_audit().unwrap();
    g.t.control.verify_state(true).unwrap();
}

/// Evidence retention is only extended: the owner's route refuses to
/// shorten it (409) and extends it, audited; the database refuses to
/// shorten or clear it whoever asks; only a person who is a security admin
/// or data owner of the version's organization changes it.
#[test]
fn evidence_retention_cannot_be_shortened() {
    let Some(g) = world() else { return };
    let until = now() + 100_000;
    let v = g.version(
        "2026-q1",
        json!({"evidence_retention_until": until, "delete_after": now() + 5000}),
    );
    let a = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/assets/{}", v.asset),
        None,
    );
    assert_eq!(a["evidence_retention_until"], json!(until), "{a}");
    refused_status(
        retention(
            &g,
            &g.tax_owner,
            &v.asset,
            json!({"evidence_retention_until": until - 1}),
        ),
        409,
    );
    let (s, r) = retention(
        &g,
        &g.tax_sec1,
        &v.asset,
        json!({"evidence_retention_until": until + 50_000}),
    );
    assert_eq!(s, 200, "{r}");
    assert_eq!(r["evidence_retention_until"], json!(until + 50_000));
    // Only the owner's security admins and data owners, people.
    refused_status(
        retention(
            &g,
            &g.tax_dev,
            &v.asset,
            json!({"evidence_retention_until": until + 60_000}),
        ),
        403,
    );
    refused_status(
        retention(
            &g,
            &g.ben_dev,
            &v.asset,
            json!({"evidence_retention_until": until + 60_000}),
        ),
        404,
    );
    let mut db = g.t.control.db.conn().unwrap();
    for sql in [
        "UPDATE assets SET evidence_retention_until = evidence_retention_until - 1 WHERE id = $1",
        "UPDATE assets SET evidence_retention_until = NULL WHERE id = $1",
    ] {
        let e = db.execute(sql, &[&v.asset]).unwrap_err();
        assert!(db_message(&e).contains("only extended"), "{sql}: {e}");
    }
    let n: i64 = db
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'asset.retention_changed'
              AND resource_id = $1 AND organization_id = $2",
            &[&v.asset, &TAX],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1);
}

/// A deletion date is fixed at registration and only ever brought forward
/// by the owner: never pushed back or cleared (route 409; the database
/// refuses too), never before the version's `retention_until` (route 409,
/// database constraint), whose own value never changes; a version is not
/// registered to be kept past its deletion date.
#[test]
fn delete_after_can_only_be_shortened() {
    let Some(g) = world() else { return };
    let (keep, delete) = (now() + 3000, now() + 5000);
    let v = g.version(
        "2026-q1",
        json!({"delete_after": delete, "retention_until": keep}),
    );
    refused_status(
        retention(
            &g,
            &g.tax_owner,
            &v.asset,
            json!({"delete_after": delete + 1}),
        ),
        409,
    );
    refused_status(
        retention(
            &g,
            &g.tax_owner,
            &v.asset,
            json!({"delete_after": keep - 1}),
        ),
        409,
    );
    let (s, r) = retention(
        &g,
        &g.tax_owner,
        &v.asset,
        json!({"delete_after": delete - 1000}),
    );
    assert_eq!(s, 200, "{r}");
    let a = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/assets/{}", v.asset),
        None,
    );
    assert_eq!(a["delete_after"], json!(delete - 1000), "{a}");
    assert_eq!(a["retention_until"], json!(keep), "{a}");
    let mut db = g.t.control.db.conn().unwrap();
    let refs: Value = db
        .query_one(
            "SELECT refs FROM audit_events WHERE action = 'asset.retention_changed' AND resource_id = $1",
            &[&v.asset],
        )
        .unwrap()
        .get(0);
    assert_eq!(refs["delete_after"], (delete - 1000).to_string(), "{refs}");
    assert_eq!(refs["previous_delete_after"], delete.to_string(), "{refs}");
    for (sql, msg) in [
        (
            "UPDATE assets SET delete_after = delete_after + 1 WHERE id = $1",
            "only brought forward",
        ),
        (
            "UPDATE assets SET delete_after = NULL WHERE id = $1",
            "only brought forward",
        ),
        (
            "UPDATE assets SET retention_until = retention_until + 1 WHERE id = $1",
            "fixed at registration",
        ),
        (
            "UPDATE assets SET delete_after = retention_until - 1 WHERE id = $1",
            "assets_retention_before_deletion",
        ),
    ] {
        let e = db.execute(sql, &[&v.asset]).unwrap_err();
        assert!(
            db_message(&e).contains(msg) || format!("{e:?}").contains(msg),
            "{sql}: {e:?}"
        );
    }
    // A version without a deletion date gets one only brought forward from
    // never; a non-version has no retention.
    let w = g.version("2026-q2", json!({}));
    let (s, r) = retention(
        &g,
        &g.tax_owner,
        &w.asset,
        json!({"delete_after": now() + 9000}),
    );
    assert_eq!(s, 200, "{r}");
    refused_status(
        retention(
            &g,
            &g.tax_owner,
            &w.asset,
            json!({"delete_after": now() + 9001}),
        ),
        409,
    );
    // Kept past its deletion date: not registered.
    let mut b = json!({"organization": TAX, "kind": "dataset", "name": "income@2026-q3",
                       "series": "income", "version": "2026-q3",
                       "digest": "c".repeat(64), "project": g.project,
                       "delete_after": now() + 100, "retention_until": now() + 200,
                       "key_ref": {"broker": "tax-broker", "provider": "openbao-transit",
                                   "key_ref": "income-2026-q3", "key_version": 1}});
    if let (Value::Object(b), Value::Object(r)) = (&mut b, registered(TAX)) {
        b.extend(r);
    }
    refused_status(g.t.call(&g.tax_owner, "POST", "/v1/assets", Some(b)), 400);
}

/// A database restored to before an expiry (the expiry and the deletion
/// date undone) does not make the version usable again: the state anchor
/// holds the expiry, so the control plane refuses to start on it, and
/// every use walks it (ENC2705).
#[test]
fn restore_undoing_expiry_refuses_start() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({"delete_after": now() + 5000}));
    let p = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &p));
    let plan = g.plan(&g.ben_dev, &p);
    let (s, r) = retention(&g, &g.tax_owner, &v.asset, json!({"delete_after": now()}));
    assert_eq!(s, 200, "{r}");
    assert!(g
        .t
        .control
        .anchor
        .snapshot()
        .expired_assets
        .contains(&v.asset));
    // The restore: the expiry and the brought-forward date undone.
    attacker(
        &g.t.env0.url,
        &["assets"],
        &format!(
            "UPDATE assets SET expired_at = NULL, delete_after = {} WHERE id = '{}'",
            now() + 5000,
            v.asset
        ),
    );
    let e = g.t.control.verify_state(true).unwrap_err();
    assert!(
        e.message.contains("EXPIRY") || e.message.contains("expir"),
        "{e}"
    );
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1"),
        "ENC2705",
    );
}

/// The background task expires a version once its deletion date passes:
/// the expiry is recorded in the database first, sent to no broker until
/// it is anchored, and then sent to the version's key broker
/// (`asset.expired`, for its organization), audited with its reason.
#[test]
fn background_expiry_sends_asset_expired_after_anchor() {
    let Some(g) = world() else { return };
    let delete_after = now() + 2;
    let v = g.version("2026-q1", json!({"delete_after": delete_after}));
    after(delete_after);
    g.t.transport.drain();
    // Expired in the database, not anchored: nothing is sent.
    assert_eq!(
        g.t.control.expire_due(now()).unwrap(),
        vec![v.asset.clone()]
    );
    g.t.control.deliver_outbox().unwrap();
    assert!(
        !g.t.transport
            .drain()
            .iter()
            .any(|(_, m)| m.kind == "asset.expired"),
        "sent before it was anchored"
    );
    assert!(!g
        .t
        .control
        .anchor
        .snapshot()
        .expired_assets
        .contains(&v.asset));
    // The background tick anchors it, then sends it.
    g.t.control.tick();
    assert!(g
        .t
        .control
        .anchor
        .snapshot()
        .expired_assets
        .contains(&v.asset));
    let sent = g.t.transport.drain();
    let (_, m) = sent
        .iter()
        .find(|(u, m)| u == "http://tax-broker.internal:8760" && m.kind == "asset.expired")
        .unwrap_or_else(|| panic!("{sent:?}"));
    assert_eq!(m.organization.as_deref(), Some(TAX));
    assert_eq!(m.payload["key_ref"], "income-2026-q1");
    // A second version, only the background task.
    let delete_after = now() + 2;
    let w = g.version("2026-q2", json!({"delete_after": delete_after}));
    after(delete_after);
    g.t.control.tick();
    assert!(g
        .t
        .control
        .anchor
        .snapshot()
        .expired_assets
        .contains(&w.asset));
    let refs: Value =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT refs FROM audit_events WHERE action = 'asset.expired' AND resource_id = $1",
                &[&w.asset],
            )
            .unwrap()
            .get(0);
    assert_eq!(refs["reason"], "delete_after", "{refs}");
}

/// No co-signature of an expired or source-expired derived result is
/// re-issued (ENC2705): nothing is re-bound to it.
#[test]
fn reissue_refused_for_expired_derived_result_2705() {
    let count = |g: &G| -> i64 {
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM derived_cosignatures", &[])
            .unwrap()
            .get(0)
    };
    // Its source expires: the result is source-expired.
    {
        let Some(g) = world() else { return };
        let (rel, c, d, _) = derived(&g, "2026-q1", |_| {});
        rotate_tax_key(&g, &key(17));
        let (s, r) = retention(
            &g,
            &g.tax_owner,
            &rel.v.asset,
            json!({"delete_after": now()}),
        );
        assert_eq!(s, 200, "{r}");
        let url = format!("/v1/assets/{d}/release-cosignature");
        refused(g.t.call(&c.sec, "POST", &url, None), "ENC2705");
        assert_eq!(count(&g), 0);
    }
    // The result itself expires (its own deletion date passed).
    let Some(g) = world() else { return };
    let (_, c, d, _) = derived(&g, "2026-q1", |_| {});
    rotate_tax_key(&g, &key(17));
    let (s, r) = retention(&g, &c.sec, &d, json!({"delete_after": now()}));
    assert_eq!(s, 200, "{r}");
    let url = format!("/v1/assets/{d}/release-cosignature");
    refused(g.t.call(&c.sec, "POST", &url, None), "ENC2705");
    assert_eq!(count(&g), 0);
}

// --- source revocation and expiry in the governance log ----------------------

/// A source whose result was derived in the main project, a second
/// governed project that ran a job over the derived result (reached only
/// through lineage), and an unrelated governed project: (source asset,
/// lineage project, unrelated project).
fn lineage_projects(g: &G) -> (String, String, String) {
    let (rel, _, d, _) = derived(g, "2026-q1", |_| {});
    let mk = |name: &str| -> String {
        id(&g.t.ok(
            &g.tax_admin,
            "POST",
            "/v1/projects",
            Some(
                json!({"organization": TAX, "name": name, "governance": "governed",
                        "organizations": [BEN]}),
            ),
        ))
    };
    let (p2, p3) = (mk("lineage-reuse"), mk("unrelated"));
    // A finished job of the second project over the derived result.
    g.t.control
        .db
        .conn()
        .unwrap()
        .batch_execute(&format!(
            "INSERT INTO plans (id, organization_id, project_id, program_id, spec_id, program, document, created_by)
                  VALUES ('pl_reuse', '{TAX}', '{p2}', 'x', 'y', '', '{{}}', 'u');
             INSERT INTO jobs (id, organization_id, project_id, plan_id, spec_id, program_id, purpose, source_assets,
                               requested_output, scheme, backend, profile, state, initiated_by, idempotency_key, request_digest)
                  VALUES ('job_reuse', '{TAX}', '{p2}', 'pl_reuse', 'y', 'x', 'p', '[\"{d}\"]', 'out', 'exact',
                          'openfhe-exact', 'P', 'succeeded', 'u', 'k-reuse', 'd');"
        ))
        .unwrap();
    (rel.v.asset.clone(), p2, p3)
}

/// The partitions holding a `kind` event about `subject`.
fn partitions_of(g: &G, kind: &str, subject: &str) -> BTreeSet<String> {
    g.t.control
        .db
        .conn()
        .unwrap()
        .query(
            "SELECT partition FROM governance_events WHERE kind = $1 AND subject_id = $2",
            &[&kind, &subject],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

/// Revoking a source is recorded for its owner and in the log of every
/// governed project that uses it: where an authorization names it, and
/// where a result derived from it was used. An unrelated project's log
/// gets nothing.
#[test]
fn source_revocation_appears_in_every_using_projects_log() {
    let Some(g) = world() else { return };
    let (source, p2, p3) = lineage_projects(&g);
    g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{source}/revoke"),
        None,
    );
    let got = partitions_of(&g, "asset.revoked", &source);
    let want: BTreeSet<String> = [
        format!("o:{TAX}"),
        format!("p:{}", g.project),
        format!("p:{p2}"),
    ]
    .into();
    assert_eq!(got, want);
    assert!(!got.contains(&format!("p:{p3}")));
    encompute_control::govlog::verify_chain(&mut *g.t.control.db.conn().unwrap()).unwrap();
}

/// Likewise for a source's expiry.
#[test]
fn source_expiry_appears_likewise() {
    let Some(g) = world() else { return };
    let (source, p2, p3) = lineage_projects(&g);
    assert!(g.t.control.expire_asset("operator-1", &source).unwrap());
    let got = partitions_of(&g, "asset.expired", &source);
    let want: BTreeSet<String> = [
        format!("o:{TAX}"),
        format!("p:{}", g.project),
        format!("p:{p2}"),
    ]
    .into();
    assert_eq!(got, want);
    assert!(!got.contains(&format!("p:{p3}")));
    encompute_control::govlog::verify_chain(&mut *g.t.control.db.conn().unwrap()).unwrap();
}
