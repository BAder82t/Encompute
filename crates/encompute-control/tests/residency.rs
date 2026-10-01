//! Residency and operators in governed projects (INV-233, INV-234): the
//! project's constraints (any member tightens, loosening needs every
//! member), the owners' own constraints in their authorizations, operator
//! separation, and the scheduler, the start check and release tickets that
//! place a job only where all of them admit it, again at every step.
//! Standard projects behave as before.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

#![allow(dead_code)]

mod common;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use common::*;
use encompute_control::authn::DEV_ISSUER;
use encompute_trust::authz::{AuthorizationV2, PurposeAcceptance};
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
    robot: As,
    tax_auditor: As,
    platform: As,
    ben_admin: As,
    other_admin: As,
    ben_sec: As,
    other_sec: As,
    plat_sec: As,
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
    let tax_auditor = user(&t, &tax_admin, TAX, "t-auditor", &["auditor"]);
    // An automation key with the organization's admin and owner roles.
    let robot_signer =
        std::sync::Arc::new(ServiceSigner::from_seed("tax-robot", &[9; 32]).unwrap());
    t.ok(
        &tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts"),
        Some(json!({"id": "tax-robot", "kind": "automation", "public_key": robot_signer.public_key_hex(),
                    "roles": ["organization_admin", "data_owner"]})),
    );
    let robot = As::Service(robot_signer);
    let ben_sec = user(&t, &ben_admin, BEN, "b-sec1", &["security_admin"]);
    let other_sec = user(&t, &other_admin, OTHER, "o-sec1", &["security_admin"]);
    let plat_sec = user(&t, &platform, "platform", "p-sec", &["security_admin"]);
    let mut g = G {
        t,
        robot,
        tax_auditor,
        platform,
        ben_admin,
        other_admin,
        ben_sec,
        other_sec,
        plat_sec,
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

/// Start refuses `job` with `code`: it fails, and is anchored as ended.
fn start_refused(g: &G, job: &str, code: &str) -> Value {
    start_refused_by(g, &g.evaluator.service, job, code)
}

/// [`start_refused`] by evaluator `who`.
fn start_refused_by(g: &G, who: &As, job: &str, code: &str) -> Value {
    let (s, v) =
        g.t.call(who, "POST", &format!("/v1/jobs/{job}/start"), None);
    refused((s, v.clone()), code);
    let view = g.view(job);
    assert_eq!(view["state"], "failed", "{view}");
    assert!(
        g.t.control
            .anchored(encompute_control::govlog::NegSet::EndedJobs, job)
            .unwrap(),
        "{job} is not anchored as ended"
    );
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

const PROFILES: &[&str] = &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"];

fn gcp(region: &str) -> Value {
    json!({"provider": "gcp", "region": region})
}

fn allow_regions(j: &[&str]) -> Value {
    json!({"allowed_regions": j.iter().map(|x| json!({"jurisdiction": x})).collect::<Vec<_>>()})
}

fn prohibit_region(provider: &str, region: &str) -> Value {
    json!({"prohibited_locations": [{"provider": provider, "region": region}]})
}

impl G {
    /// A platform evaluator `ev` that reports `region` (self-declared) and,
    /// when `declared`, whose location the platform's security admin then
    /// declares.
    fn platform_evaluator(&self, ev: &str, region: Option<&str>, declared: bool) -> Evaluator {
        let machine = region.map_or(json!({}), |r| json!({"location": gcp(r)}));
        let e = common::evaluator_with(
            &self.t,
            &self.platform,
            ev,
            &["openfhe", "openfhe-exact"],
            PROFILES,
            4,
            machine,
        );
        if let (true, Some(r)) = (declared, region) {
            let (s, v) = self.declare(&self.plat_sec, ev, r);
            assert_eq!(s, 201, "{v}");
        }
        e
    }

    /// An evaluator held by `org` (registered by `admin`), reporting
    /// `region`, declared by `declared_by` when given.
    fn org_evaluator(
        &self,
        admin: &As,
        org: &str,
        ev: &str,
        region: Option<&str>,
        declared_by: Option<&As>,
    ) -> Evaluator {
        let seed = {
            let mut s = [0u8; 32];
            for (i, b) in ev.bytes().enumerate() {
                s[i % 32] ^= b;
            }
            s[31] ^= 0x71;
            s
        };
        let signer = std::sync::Arc::new(ServiceSigner::from_seed(ev, &seed).unwrap());
        self.t.ok(
            admin,
            "POST",
            &format!("/v1/organizations/{org}/service-accounts"),
            Some(
                json!({"id": ev, "kind": "evaluator", "public_key": signer.public_key_hex(),
                        "url": format!("http://{ev}.internal:8750")}),
            ),
        );
        let receipt = encompute_verification::EvaluatorSigner::from_seed(&seed.map(|b| b ^ 0x33));
        let e = Evaluator {
            id: ev.into(),
            service: As::Service(signer.clone()),
            signer,
            receipt,
        };
        let (s, v) = self.register(&e, region.map(gcp));
        assert_eq!(s, 201, "{v}");
        if let (Some(who), Some(r)) = (declared_by, region) {
            let (s, v) = self.declare(who, ev, r);
            assert_eq!(s, 201, "{v}");
        }
        e
    }

    fn register(&self, e: &Evaluator, location: Option<Value>) -> (u16, Value) {
        let mut body = json!({"id": e.id, "url": format!("http://{}.internal:8750", e.id),
                    "receipt_key": e.receipt.identity().public_key_hex(),
                    "backends": ["openfhe", "openfhe-exact"], "profiles": PROFILES,
                    "openfhe_version": "1.5.1", "capacity": 4});
        if let Some(l) = location {
            body["location"] = l;
        }
        self.t
            .call(&e.service, "POST", "/v1/evaluators", Some(body))
    }

    fn declare(&self, who: &As, ev: &str, region: &str) -> (u16, Value) {
        self.t.call(
            who,
            "POST",
            &format!("/v1/evaluators/{ev}/location-declarations"),
            Some(gcp(region)),
        )
    }

    /// The project's placement: (version, view).
    fn placement(&self) -> (i64, Value) {
        let v = self.t.ok(
            &self.tax_sec1,
            "GET",
            &format!("/v1/projects/{}/placement", self.project),
            None,
        );
        (v["version"].as_i64().unwrap(), v)
    }

    /// Changes the project's constraints as `who`, from the current version.
    fn constrain(&self, who: &As, constraints: Value) -> (u16, Value) {
        let (base, _) = self.placement();
        self.t.call(
            who,
            "POST",
            &format!("/v1/projects/{}/placement", self.project),
            Some(json!({"constraints": constraints, "base_version": base})),
        )
    }

    fn drain(&self, ev: &str) {
        self.t.ok(
            &self.platform,
            "POST",
            &format!("/v1/evaluators/{ev}/status"),
            Some(json!({"status": "draining"})),
        );
    }

    fn undrain(&self, ev: &str) {
        self.t.ok(
            &self.platform,
            "POST",
            &format!("/v1/evaluators/{ev}/status"),
            Some(json!({"status": "ready"})),
        );
    }

    /// The governed events of the project's shared log, as (kind, refs).
    fn log_kinds(&self) -> Vec<(String, Value)> {
        let v = self.t.ok(
            &self.tax_sec1,
            "GET",
            &format!("/v1/projects/{}/audit?limit=200", self.project),
            None,
        );
        v["events"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|e| {
                        (
                            e["event"]["kind"].as_str().unwrap_or("").to_owned(),
                            e["event"]["refs"].clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The platform's own evaluator has no location; with it drained the
/// located ones are the candidates.
fn quiet_platform_default(g: &G) {
    g.drain("evaluator-1");
}

// --- INV-233: where a job may run -------------------------------------------------

#[test]
fn allowed_regions_choose_the_evaluator() {
    let Some(g) = world() else { return };
    g.platform_evaluator("ev-de", Some("europe-west3"), true);
    g.platform_evaluator("ev-us", Some("us-central1"), true);
    let (s, v) = g.constrain(&g.tax_sec1, allow_regions(&["DE"]));
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "applied");
    assert_eq!(v["change"], "tighten");
    let (_, _, _, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    let view = g.view(&job);
    assert_eq!(view["state"], "queued", "{view}");
    // Not evaluator-1 (no location: inadmissible under a location rule),
    // not ev-us (outside the constraint), although both are idle and ev-us
    // sorts before evaluator-1.
    assert_eq!(view["evaluator"], "ev-de", "{view}");
    // The grant and every member's view record where it was placed, with
    // the evidence.
    let p = &view["placement"];
    assert_eq!(p["operator"], "platform");
    assert_eq!(p["location"]["region"], "europe-west3");
    assert_eq!(p["location"]["jurisdiction"], "DE");
    assert_eq!(p["evidence"], "operator_declared");
    assert_eq!(p["evidence_digest"].as_str().unwrap().len(), 64);
    assert_eq!(
        g.grant(&job)
            .governance
            .unwrap()
            .placement
            .unwrap()
            .operator,
        "platform"
    );
    // The binding names the constraints' digest, so the spec and the job
    // are bound to them.
    let (_, pv) = g.placement();
    let gov = g.grant(&job).governance.unwrap();
    assert_eq!(
        gov.binding.placement_digest.as_deref(),
        pv["digest"].as_str()
    );
    // The other members see the same placement.
    for who in [&g.tax_dev, &g.other_dev] {
        let v = g.t.ok(who, "GET", &format!("/v1/jobs/{job}"), None);
        assert_eq!(v["placement"], *p, "{v}");
    }
}

#[test]
fn prohibited_beats_allowed_and_unlocated_evaluators_never_run_a_constrained_job() {
    let Some(g) = world() else { return };
    g.platform_evaluator("ev-w3", Some("europe-west3"), true);
    g.platform_evaluator("ev-w10", Some("europe-west10"), true);
    let mut c = allow_regions(&["DE"]);
    c["prohibited_locations"] = json!([{"provider": "gcp", "region": "europe-west3"}]);
    assert_eq!(g.constrain(&g.tax_sec1, c).0, 200);
    let (_, _, _, j) = g.job("2026-q1", |_| {});
    // Both are German; the one in the prohibited region is refused.
    assert_eq!(g.view(&id(&j))["evaluator"], "ev-w10");
}

#[test]
fn unsatisfiable_constraints_give_no_plan() {
    let Some(g) = world() else { return };
    g.platform_evaluator("ev-de", Some("europe-west3"), true);
    assert_eq!(g.constrain(&g.tax_sec1, allow_regions(&["FR"])).0, 200);
    let v = g.version("2026-q1", json!({}));
    let program = program(&[&v.asset], PURPOSE, BEN);
    let (s, body) = g.t.call(
        &g.ben_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": g.project, "program": program})),
    );
    assert_eq!(s, 422, "{body}");
    let m = body["message"].as_str().unwrap();
    assert!(
        m.contains("PLANNING FAILED") && m.contains("no admissible evaluator"),
        "{m}"
    );
    // The project's own constraints are the members' to read.
    assert!(m.contains("evaluator ev-de"), "{m}");
    // No plan row, and the failure is audited.
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM plans", &[])
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
}

#[test]
fn unknown_regions_and_invalid_constraints_are_refused_when_declared() {
    let Some(g) = world() else { return };
    for bad in [
        json!({"allowed_regions": [{"provider": "gcp", "region": "europe-west99"}]}),
        json!({"allowed_regions": []}),
        json!({"prohibited_locations": [{"jurisdiction": "ZZ"}]}),
        json!({"allowed_regions": [{"jurisdiction": "DE"}], "applies_to": []}),
    ] {
        refused(g.constrain(&g.tax_sec1, bad), "ENC2724");
    }
    let (s, v) = g.t.call(
        &g.tax_sec1,
        "POST",
        &format!("/v1/projects/{}/placement", g.project),
        Some(json!({"constraints": {"allowed_region": []}, "base_version": 0})),
    );
    assert_eq!(s, 400, "{v}");
    assert_eq!(g.placement().0, 0, "nothing was recorded");
}

#[test]
fn an_owners_own_constraints_apply_and_never_leak() {
    let Some(g) = world() else { return };
    g.platform_evaluator("ev-de", Some("europe-west3"), true);
    g.platform_evaluator("ev-us", Some("us-central1"), true);
    // No project constraints: tax's own authorization keeps its data in
    // Germany.
    let (_, _, _, j) = g.job("2026-q1", |a| {
        a.limits.placement = serde_json::from_value(allow_regions(&["DE"])).unwrap();
    });
    assert_eq!(g.view(&id(&j))["evaluator"], "ev-de");
    // An owner that asks for more than any evaluator has: no job is bound,
    // and the refusal names the organization and the field, not its values.
    let v = g.version("2026-q2", json!({}));
    let prog = program(&[&v.asset], PURPOSE, BEN);
    let mut body = g.body(&v, &prog);
    body.limits.placement = serde_json::from_value(
        json!({"allowed_regions": [{"jurisdiction": "FR"}], "min_evidence": "attested"}),
    )
    .unwrap();
    g.authorize(body);
    let plan = g.plan(&g.ben_dev, &prog);
    let (s, r) = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k-fr");
    assert_eq!(s, 403, "{r}");
    assert_eq!(code(&r), "ENC2710", "{r}");
    let m = r["message"].as_str().unwrap();
    assert!(m.contains("an input owned by tax-agency"), "{m}");
    assert!(m.contains("allowed_regions"), "{m}");
    assert!(
        !m.contains("FR") && !m.contains("attested"),
        "private values leaked: {m}"
    );
    // The refusal is audited and no job exists for it.
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM jobs WHERE idempotency_key = 'k-fr'",
                &[],
            )
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
    let denied: i64 = g.t.control.db.conn().unwrap().query_one(
        "SELECT count(*) FROM audit_events WHERE action = 'job.denied' AND refs->>'reason' = 'placement'", &[]).unwrap().get(0);
    assert_eq!(denied, 1);
}

#[test]
fn an_owners_invalid_constraints_are_not_an_authorization() {
    let Some(g) = world() else { return };
    let v = g.version("2026-q1", json!({}));
    let prog = program(&[&v.asset], PURPOSE, BEN);
    let mut body = g.body(&v, &prog);
    body.limits.placement = serde_json::from_value(
        json!({"allowed_regions": [{"provider": "gcp", "region": "europe-west99"}]}),
    )
    .unwrap();
    let (s, r) = g.t.call(
        &g.tax_owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": body})),
    );
    assert!(s >= 400, "{s} {r}");
}

#[test]
fn a_tightening_after_scheduling_fails_the_job_at_start() {
    let Some(g) = world() else { return };
    quiet_platform_default(&g);
    let ev = g.platform_evaluator("ev-us", Some("us-central1"), true);
    let (_, _, job) = queued(&g, "2026-q1");
    assert_eq!(g.view(&job)["evaluator"], "ev-us");
    // Every member's security admin may tighten; the scheduled evaluator
    // is now in a prohibited place.
    let (s, v) = g.constrain(&g.other_sec, prohibit_region("gcp", "us-central1"));
    assert_eq!(s, 200, "{v}");
    start_refused_by(&g, &ev.service, &job, "ENC2710");
}

#[test]
fn no_release_ticket_goes_to_an_evaluator_outside_the_constraints() {
    let Some(g) = world() else { return };
    quiet_platform_default(&g);
    let ev = g.platform_evaluator("ev-us", Some("us-central1"), true);
    let (v, _, job) = queued(&g, "2026-q1");
    let ticket = |g: &G| {
        g.t.call(
            &ev.service,
            "POST",
            &format!("/v1/jobs/{job}/release-ticket"),
            Some(json!({"asset_version_id": v.version})),
        )
    };
    assert_eq!(
        g.constrain(&g.tax_sec1, prohibit_region("gcp", "us-central1"))
            .0,
        200
    );
    refused(ticket(&g), "ENC2710");
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM release_tickets WHERE job_id = $1",
                &[&job],
            )
            .unwrap()
            .get(0);
    assert_eq!(n, 0, "no ticket was issued");
}

#[test]
fn an_evaluator_that_moves_after_scheduling_fails_the_job() {
    let Some(g) = world() else { return };
    quiet_platform_default(&g);
    let e = g.platform_evaluator("ev-de", Some("europe-west3"), true);
    // No project constraint at all: the evidence the grant recorded is
    // what start compares.
    let (_, _, job) = queued(&g, "2026-q1");
    assert_eq!(g.view(&job)["placement"]["evidence"], "operator_declared");
    // The evaluator re-registers reporting another location.
    let (s, r) = g.register(&e, Some(gcp("europe-west1")));
    assert_eq!(s, 201, "{r}");
    start_refused_by(&g, &e.service, &job, "ENC2710");
}

#[test]
fn an_evaluator_that_loses_its_evidence_after_scheduling_fails_the_job() {
    let Some(g) = world() else { return };
    quiet_platform_default(&g);
    let e = g.platform_evaluator("ev-de", Some("europe-west3"), true);
    assert_eq!(g.constrain(&g.tax_sec1, allow_regions(&["DE"])).0, 200);
    let (_, _, job) = queued(&g, "2026-q1");
    // The declaration lapses (its validity ends).
    g.t.control.db.conn().unwrap().execute(
        "UPDATE evaluators SET location_valid_until = now() - interval '1 second' WHERE id = 'ev-de'", &[]).unwrap();
    // Self-declared evidence still passes a constraint that asks for none,
    // but it is not the evidence the grant recorded.
    start_refused_by(&g, &e.service, &job, "ENC2710");
}

#[test]
fn a_job_is_held_not_moved_when_nothing_is_admissible() {
    let Some(g) = world() else { return };
    quiet_platform_default(&g);
    let ev = g.platform_evaluator("ev-de", Some("europe-west3"), true);
    g.platform_evaluator("ev-us", Some("us-central1"), true);
    assert_eq!(g.constrain(&g.tax_sec1, allow_regions(&["DE"])).0, 200);
    // The only German evaluator is busy: the job waits for it and never
    // falls back to the American one.
    g.drain("ev-de");
    let (_, _, _, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    let v = g.view(&job);
    assert_eq!(v["state"], "authorized", "{v}");
    assert_eq!(v["evaluator"], Value::Null);
    g.t.control.schedule_pending().unwrap();
    assert_eq!(g.view(&job)["state"], "authorized");
    // It moves to ev-de once that is ready again.
    g.undrain("ev-de");
    g.t.control.schedule_pending().unwrap();
    let v = g.view(&job);
    assert_eq!(v["state"], "queued", "{v}");
    assert_eq!(v["evaluator"], "ev-de");
    let _ = ev;
}

#[test]
fn a_waiting_job_says_why_when_its_evaluator_leaves_the_constraints() {
    let Some(g) = world() else { return };
    quiet_platform_default(&g);
    let e = g.platform_evaluator("ev-de", Some("europe-west3"), true);
    assert_eq!(g.constrain(&g.tax_sec1, allow_regions(&["DE"])).0, 200);
    g.drain("ev-de");
    let (_, _, _, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    // While it waits, the evaluator is re-registered somewhere else.
    assert_eq!(g.register(&e, Some(gcp("us-central1"))).0, 201);
    g.undrain("ev-de");
    g.t.control.schedule_pending().unwrap();
    let v = g.view(&job);
    assert_eq!(v["state"], "authorized", "{v}");
    assert!(
        v["placement_waiting"]
            .as_str()
            .unwrap()
            .contains("no admissible evaluator"),
        "{v}"
    );
    // Every member reads the same.
    let other =
        g.t.ok(&g.other_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(other["placement_waiting"], v["placement_waiting"]);
}

#[test]
fn a_later_loosening_never_widens_a_bound_job() {
    let Some(g) = world() else { return };
    quiet_platform_default(&g);
    g.platform_evaluator("ev-de", Some("europe-west3"), true);
    g.platform_evaluator("ev-us", Some("us-central1"), true);
    assert_eq!(g.constrain(&g.tax_sec1, allow_regions(&["DE"])).0, 200);
    g.drain("ev-de");
    let (_, _, _, j) = g.job("2026-q1", |_| {});
    let job = id(&j);
    assert_eq!(g.view(&job)["state"], "authorized");
    // Every member agrees to drop the constraint.
    for who in [&g.tax_sec1, &g.ben_sec, &g.other_sec] {
        let (s, v) = g.constrain(who, json!({}));
        assert_eq!(s, 200, "{v}");
    }
    assert_eq!(g.placement().1["constraints"], json!({}));
    // The job was bound under Germany only: it still waits for ev-de.
    g.t.control.schedule_pending().unwrap();
    let v = g.view(&job);
    assert_eq!(v["state"], "authorized", "{v}");
    g.undrain("ev-de");
    g.t.control.schedule_pending().unwrap();
    assert_eq!(g.view(&job)["evaluator"], "ev-de");
}

#[test]
fn only_a_members_security_admin_changes_the_constraints() {
    let Some(g) = world() else { return };
    let url = format!("/v1/projects/{}/placement", g.project);
    let body = json!({"constraints": allow_regions(&["DE"]), "base_version": 0});
    // Not security admins, not people, auditors, strangers.
    for who in [&g.tax_dev, &g.tax_owner, &g.tax_admin, &g.ben_dev, &g.robot] {
        let (s, v) = g.t.call(who, "POST", &url, Some(body.clone()));
        assert!(s == 403 || s == 404, "{s} {v}");
    }
    let (s, v) = g.t.call(&g.tax_auditor, "POST", &url, Some(body.clone()));
    assert_eq!(s, 403, "{v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap()
            .contains("auditors are read-only"),
        "{v}"
    );
    assert_eq!(g.placement().0, 0);
    // Auditors read it.
    let (s, v) = g.t.call(&g.tax_auditor, "GET", &url, None);
    assert_eq!(s, 200, "{v}");
    // A standard project has none.
    let p = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "standard"})),
    );
    let (s, v) = g.t.call(
        &g.tax_sec1,
        "POST",
        &format!("/v1/projects/{}/placement", id(&p)),
        Some(body),
    );
    assert_eq!(code(&v), "ENC2724", "{s} {v}");
}

#[test]
fn tightening_is_immediate_and_loosening_needs_every_member() {
    let Some(g) = world() else { return };
    // A first set is a tightening of nothing.
    let (s, v) = g.constrain(&g.tax_sec1, allow_regions(&["DE", "FR"]));
    assert_eq!((s, v["version"].as_i64()), (200, Some(1)), "{v}");
    // Another member narrows it at once.
    let (s, v) = g.constrain(&g.ben_sec, allow_regions(&["DE"]));
    assert_eq!(
        (s, v["version"].as_i64(), v["change"].as_str()),
        (200, Some(2), Some("tighten")),
        "{v}"
    );
    // A stale base is refused.
    let (s, v) = g.t.call(
        &g.tax_sec1,
        "POST",
        &format!("/v1/projects/{}/placement", g.project),
        Some(json!({"constraints": allow_regions(&["DE"]), "base_version": 1})),
    );
    assert_eq!(code(&v), "ENC2724", "{s} {v}");
    // Widening to France is a loosening: one member's word does not do it,
    // and it is visible while it waits.
    let widen = allow_regions(&["DE", "FR"]);
    let (s, v) = g.constrain(&g.tax_sec1, widen.clone());
    assert_eq!((s, v["status"].as_str()), (200, Some("pending")), "{v}");
    assert_eq!(g.placement().0, 2);
    let pending = g.placement().1["pending_loosening"].clone();
    assert_eq!(pending[0]["proposed_by"], json!([TAX]), "{pending}");
    assert_eq!(pending[0]["waiting_for"], json!([BEN, OTHER]), "{pending}");
    // The same member again changes nothing; a different proposal is its
    // own.
    assert_eq!(
        g.constrain(&g.tax_sec1, widen.clone()).1["status"],
        "pending"
    );
    assert_eq!(
        g.constrain(&g.ben_sec, allow_regions(&["DE", "NL"])).1["status"],
        "pending"
    );
    assert_eq!(g.placement().0, 2);
    // Everyone proposes the same: it takes effect.
    assert_eq!(
        g.constrain(&g.ben_sec, widen.clone()).1["status"],
        "pending"
    );
    let (s, v) = g.constrain(&g.other_sec, widen);
    assert_eq!(
        (s, v["status"].as_str(), v["change"].as_str()),
        (200, Some("applied"), Some("loosen")),
        "{v}"
    );
    assert_eq!(g.placement().0, 3);
    assert!(g.placement().1["pending_loosening"]
        .as_array()
        .unwrap()
        .is_empty());
    // A tightening in between voids proposals from the old version.
    assert_eq!(g.constrain(&g.tax_sec1, json!({})).1["status"], "pending");
    assert_eq!(
        g.constrain(&g.ben_sec, allow_regions(&["DE"])).1["version"],
        4
    );
    assert!(g.placement().1["pending_loosening"]
        .as_array()
        .unwrap()
        .is_empty());
    // The change was checkpointed before the call returned: the project's
    // latest signed checkpoint already covers every event of its log.
    let latest = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/projects/{}/checkpoints/latest", g.project),
        None,
    );
    assert_eq!(
        latest["checkpoint"]["body"]["size"].as_u64().unwrap() as usize,
        g.log_kinds().len(),
        "{latest}"
    );
    // Every change is in every member's trail and in the project's log.
    for who in [&g.tax_sec1, &g.ben_sec, &g.other_sec] {
        let org = if std::ptr::eq(who, &g.tax_sec1) {
            TAX
        } else if std::ptr::eq(who, &g.ben_sec) {
            BEN
        } else {
            OTHER
        };
        let audit = g.t.ok(
            who,
            "GET",
            &format!("/v1/audit?organization={org}&limit=1000"),
            None,
        );
        let n = audit
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["action"] == "project.placement_changed")
            .count();
        assert_eq!(n, 4, "{org}: {audit}");
    }
    let changes: Vec<_> = g
        .log_kinds()
        .into_iter()
        .filter(|(k, _)| k == "placement.changed")
        .collect();
    assert_eq!(changes.len(), 4, "{changes:?}");
    assert_eq!(changes.last().unwrap().1["change"], "tighten");
}

// --- INV-234: operator separation -----------------------------------------------------

#[test]
fn a_separate_operator_is_selected() {
    let Some(g) = world() else { return };
    // Retire the platform's own evaluator: only organizations' evaluators
    // remain.
    g.t.ok(
        &g.platform,
        "POST",
        "/v1/organizations/platform/service-accounts/evaluator-1/disable",
        None,
    );
    g.org_evaluator(&g.tax_admin, TAX, "ev-tax", None, None);
    g.org_evaluator(&g.ben_admin, BEN, "ev-ben", None, None);
    // Tax owns the source; benefits receives the result: both hold keys.
    // At planning only the source owner is known (from the custody), so
    // benefits' evaluator still plans; binding the job names the output's
    // recipient too, and nothing is left.
    let v = g.version("2026-q1", json!({}));
    let prog = program(&[&v.asset], PURPOSE, BEN);
    g.authorize(g.body(&v, &prog));
    let plan = g.plan(&g.ben_dev, &prog);
    let (s, r) = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k0");
    assert_eq!(code(&r), "ENC2725", "{s} {r}");
    assert!(
        r["message"]
            .as_str()
            .unwrap()
            .contains("operator separation"),
        "{r}"
    );
    // A third organization operates one.
    g.org_evaluator(&g.other_admin, OTHER, "ev-other", None, None);
    let (s, j) = g.submit(&g.ben_dev, g.request(&plan, &[&v.asset], &[BEN]), "k1");
    assert_eq!(s, 201, "{j}");
    let view = g.view(&id(&j));
    // Idle and sorted before ev-other, ev-ben and ev-tax are still refused.
    assert_eq!(view["evaluator"], "ev-other", "{view}");
    assert_eq!(view["placement"]["operator"], OTHER);
}

#[test]
fn a_data_owner_operated_evaluator_gets_no_job_start_or_ticket() {
    let Some(g) = world() else { return };
    // Tax's own evaluator sorts before the platform's.
    let owner_ev = g.org_evaluator(&g.tax_admin, TAX, "aaa-tax", None, None);
    let (v, _, job) = queued(&g, "2026-q1");
    assert_eq!(
        g.view(&job)["evaluator"],
        "evaluator-1",
        "never aaa-tax: it is tax's own"
    );
    // It asks for the job's ticket: it is not the job's evaluator.
    let (s, r) = g.t.call(
        &owner_ev.service,
        "POST",
        &format!("/v1/jobs/{job}/release-ticket"),
        Some(json!({"asset_version_id": v.version})),
    );
    assert!(s == 403 || s == 404, "{s} {r}");
    // Were the job handed to it anyway (a corrupted database), the start
    // refuses on operator separation (ENC2725) and fails the job.
    attacker(
        &g.t.env0.url,
        &["jobs"],
        &format!("UPDATE jobs SET evaluator_id = 'aaa-tax' WHERE id = '{job}'"),
    );
    start_refused_by(&g, &owner_ev.service, &job, "ENC2725");
}

// --- fan-out and shared views -----------------------------------------------------------

#[test]
fn location_changes_reach_every_project_that_uses_the_evaluator() {
    let Some(g) = world() else { return };
    quiet_platform_default(&g);
    let e = g.platform_evaluator("ev-de", Some("europe-west3"), true);
    // A plan in the project names ev-de among its admissible evaluators.
    let v = g.version("2026-q1", json!({}));
    let prog = program(&[&v.asset], PURPOSE, BEN);
    let plan = g.plan(&g.ben_dev, &prog);
    let _ = plan;
    // A second governed project with no plan: it does not use ev-de.
    let q = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "other-project", "governance": "governed", "organizations": []})),
    );
    let before = g.log_kinds().len();
    let (s, r) = g.declare(&g.plat_sec, "ev-de", "europe-west1");
    assert_eq!(s, 201, "{r}");
    let kinds = g.log_kinds();
    assert_eq!(kinds.len(), before + 1, "{kinds:?}");
    let (k, refs) = kinds.last().unwrap();
    assert_eq!(k, "evaluator.location_declared");
    // Shared-safe: the evidence level and digest, nothing about the
    // declarer or the storage.
    assert_eq!(refs["evidence"], "operator_declared");
    assert!(
        refs.as_object()
            .unwrap()
            .keys()
            .all(|k| k == "evidence" || k == "evidence_digest"),
        "{refs}"
    );
    // A change of location by the evaluator itself too.
    assert_eq!(g.register(&e, Some(gcp("us-central1"))).0, 201);
    assert_eq!(
        g.log_kinds().last().unwrap().0,
        "evaluator.location_changed"
    );
    // The project that never used it hears nothing.
    let other = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/projects/{}/audit?limit=200", id(&q)),
        None,
    );
    let n = other["events"].as_array().map_or(0, |a| {
        a.iter()
            .filter(|e| {
                e["event"]["kind"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("evaluator.")
            })
            .count()
    });
    assert_eq!(n, 0, "{other}");
}

#[test]
fn the_production_floor_refuses_a_plan_that_accepts_self_declared_locations() {
    let Some(g) = world() else { return };
    g.platform_evaluator("ev-de", Some("europe-west3"), true);
    let v = g.version("2026-q1", json!({}));
    let prog = program(&[&v.asset], PURPOSE, BEN);
    let plan_row = g.plan(&g.ben_dev, &prog);
    let stored: Value =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT document FROM plans WHERE id = $1", &[&plan_row])
            .unwrap()
            .get(0);
    let plan: encompute_planner::ConfidentialExecutionPlan =
        serde_json::from_value(stored["plan"].clone()).unwrap();
    assert!(!plan.context.placement.as_ref().unwrap().production);
    let program = encompute_ir::parse(&prog).unwrap();
    // The development control plane accepts it; a production one does not.
    g.t.control.verify_stored_plan(&program, &plan).unwrap();
    let Some(url) = fresh_database() else { return };
    let db = encompute_control::db::Db::connect(&url).unwrap();
    db.migrate().unwrap();
    let prod = encompute_control::Control::with_parts(
        encompute_control::config::Env::Production,
        "control-plane",
        db,
        encompute_control::authn::Authenticator::new(
            encompute_control::config::Env::Production,
            "control-plane",
            vec![],
            None,
        ),
        ServiceSigner::from_seed("control-plane", &[8; 32]).unwrap(),
        Box::new(encompute_control::anchor::DirAnchor::new(tmp_dir("floor")).unwrap()),
        None,
        5,
    )
    .unwrap();
    let e = prod.verify_stored_plan(&program, &plan).unwrap_err();
    assert!(e.message.contains("self-declared"), "{e}");
}

#[test]
fn a_release_ticket_carries_the_constraints_its_binding_names() {
    let Some(g) = world() else { return };
    quiet_platform_default(&g);
    let ev = g.platform_evaluator("ev-de", Some("europe-west3"), true);
    let constraints = allow_regions(&["DE"]);
    assert_eq!(g.constrain(&g.tax_sec1, constraints.clone()).0, 200);
    let (v, _, job) = queued(&g, "2026-q1");
    let (s, r) = g.t.call(
        &ev.service,
        "POST",
        &format!("/v1/jobs/{job}/release-ticket"),
        Some(json!({"asset_version_id": v.version})),
    );
    assert_eq!(s, 201, "{r}");
    let t = &r["ticket"];
    // The document, and the digest the binding the workload attests to
    // names: the broker judges the attested zone by it.
    assert_eq!(t["placement"], constraints, "{t}");
    assert_eq!(t["placement_digest"], g.placement().1["digest"]);
    assert_eq!(t["binding"]["placement_digest"], t["placement_digest"]);
    let ticket: encompute_verification::ticket::ReleaseTicket =
        serde_json::from_value(t.clone()).unwrap();
    ticket.check_consistent().unwrap();
    assert_eq!(
        ticket.placement.as_ref().unwrap().digest(),
        ticket.placement_digest.clone().unwrap()
    );
}

#[test]
fn a_release_ticket_without_project_constraints_carries_none() {
    let Some(g) = world() else { return };
    let (v, _, job) = queued(&g, "2026-q1");
    let (s, r) = g.t.call(
        &g.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/release-ticket"),
        Some(json!({"asset_version_id": v.version})),
    );
    assert_eq!(s, 201, "{r}");
    let t = r["ticket"].as_object().unwrap();
    assert!(
        !t.contains_key("placement") && !t.contains_key("placement_digest"),
        "{t:?}"
    );
}
