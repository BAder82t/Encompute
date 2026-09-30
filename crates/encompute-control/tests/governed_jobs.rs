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
use encompute_trust::authz::{AuthorizationSetId, AuthorizationV2, PurposeAcceptance};
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
        if let (Value::Object(b), Value::Object(e)) = (&mut b, extra) {
            b.extend(e);
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
            limits: Default::default(),
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
    assert_eq!(gov.binding.asset_brokers["income-2026-q1"], "tax-broker");
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
    // An expired source likewise (ENC2705).
    let (v4, _, _, j4) = g.job("2026-q4", |_| {});
    g.t.control.expire_asset("retention", &v4.asset).unwrap();
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
    let v = g.version("2026-q2", json!({}));
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
    let (v, _, job) = queued(&g, "2026-q2");
    g.t.control.expire_asset("retention", &v.asset).unwrap();
    start_refused(&g, &job, "ENC2705");
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
    g.authorize(four);
    let plan = g.plan(&g.ben_dev, &p);
    refused(
        g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1"),
        "ENC2707",
    );
}
