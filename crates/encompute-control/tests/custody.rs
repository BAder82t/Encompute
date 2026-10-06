//! Key custody in governed projects (public-sector governance, phase 2):
//! sovereign custody (always, in a governed project; immutable) takes
//! each source's key to a key broker its own organization registered,
//! never a platform broker (ENC2715); only a person who is a security admin
//! of the organization registers its brokers; release tickets go to the
//! scheduled evaluator only, capped by the job's governed window and grant,
//! and verify under the control plane's key as a broker checks them; an
//! owner authorization's revocation is anchored before its brokers hear of
//! it, and a restored database that forgot it is refused at start.
//! Standard projects behave as before.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use common::*;
use encompute_control::authn::DEV_ISSUER;
use encompute_trust::authz::{AuthorizationSetId, AuthorizationV2};
use encompute_verification::governance::{
    GovernanceBinding, GovernanceInput, GovernanceOutput, GrantGovernance, ProgramRef,
    ReleaseClass, GOVERNANCE_BINDING_VERSION,
};
use encompute_verification::service::{JobGrant, JOB_GRANT, JOB_GRANT_V2};
use encompute_verification::ticket::ReleaseTicket;
use encompute_verification::{hex, ServiceSigner};

const TAX: &str = "tax-agency";
const BEN: &str = "benefits-agency";
const TAX_BROKER_URL: &str = "http://tax-broker.internal:8760";

fn now() -> u64 {
    encompute_verification::service::now()
}

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

/// Asserts `(status, body)` is a refusal with `c`.
fn refused(r: (u16, Value), c: &str) {
    assert!(r.0 >= 400, "expected {c}, got {} {}", r.0, r.1);
    assert_eq!(code(&r.1), c, "{} {}", r.0, r.1);
}

fn db_msg(e: &postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string())
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(k: &SigningKey) -> String {
    hex(&k.verifying_key().to_bytes())
}

struct C {
    t: T,
    platform: As,
    tax_admin: As,
    tax_sec1: As,
    tax_sec2: As,
    tax_owner: As,
    tax_auditor: As,
    tax_dev: As,
    ben_admin: As,
    ben_sec1: As,
    evaluator: Evaluator,
    other_evaluator: Evaluator,
    /// The governed project (sovereign custody by default).
    project: String,
}

/// A keybroker service account `id` of `org` (registered by `admin`), or of
/// the platform.
fn broker_account(t: &T, admin: &As, org: &str, id: &str, seed: u8, url: &str) {
    let s = ServiceSigner::from_seed(id, &[seed; 32]).unwrap();
    t.ok(
        admin,
        "POST",
        &format!("/v1/organizations/{org}/service-accounts"),
        Some(json!({"id": id, "kind": "keybroker", "public_key": s.public_key_hex(), "url": url})),
    );
}

fn register_broker(t: &T, who: &As, org: &str, id: &str, seed: u8) -> (u16, Value) {
    t.call(
        who,
        "POST",
        &format!("/v1/organizations/{org}/key-brokers"),
        Some(json!({"id": id, "grant_public_key": pk(&key(seed)),
                    "provider_kind": "openbao-transit", "key_ref_namespace": "transit/tax",
                    "location": {"country": "NL", "region": "eu-west"}})),
    )
}

fn world() -> Option<C> {
    let t = setup()?;
    t.control
        .bootstrap(DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let platform = As::User("platform-admin".into());
    for (org, admin) in [(TAX, "t-admin"), (BEN, "b-admin")] {
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
    let tax_auditor = user(&t, &tax_admin, TAX, "t-auditor", &["auditor"]);
    let tax_dev = user(&t, &tax_admin, TAX, "t-dev", &["ml_developer"]);
    let ben_sec1 = user(&t, &ben_admin, BEN, "b-sec1", &["security_admin"]);
    let evaluator = common::evaluator(
        &t,
        &platform,
        "evaluator-1",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    let other_evaluator = common::evaluator(
        &t,
        &platform,
        "evaluator-2",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    // The organizations' own brokers, and a platform broker.
    broker_account(&t, &tax_admin, TAX, "tax-broker", 31, TAX_BROKER_URL);
    broker_account(
        &t,
        &tax_admin,
        TAX,
        "tax-broker-unregistered",
        32,
        "http://tax-broker-2.internal:8760",
    );
    broker_account(
        &t,
        &ben_admin,
        BEN,
        "ben-broker",
        33,
        "http://ben-broker.internal:8760",
    );
    broker_account(
        &t,
        &platform,
        "platform",
        "platform-broker",
        34,
        "http://platform-broker.internal:8760",
    );
    let p = t.ok(
        &tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "benefits-eligibility",
                    "governance": "governed", "organizations": [BEN]})),
    );
    let project = p["id"].as_str().unwrap().to_owned();
    t.ok(
        &ben_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": BEN})),
    );
    Some(C {
        t,
        platform,
        tax_admin,
        tax_sec1,
        tax_sec2,
        tax_owner,
        tax_auditor,
        tax_dev,
        ben_admin,
        ben_sec1,
        evaluator,
        other_evaluator,
        project,
    })
}

fn key_ref(broker: &str, name: &str) -> Value {
    json!({"broker": broker, "provider": "openbao-transit", "key_ref": name, "key_version": 1})
}

/// Everything a release ticket needs: an active governance key, an
/// accepted purpose, a version of tax's income series held by its own
/// broker, and an owner authorization for it.
struct Ready {
    purpose: String,
    version: String,
    asset: String,
    authorization_row: String,
    authorization_id: String,
    governance_key: SigningKey,
}

impl C {
    fn own_broker(&self) {
        let (s, v) = register_broker(&self.t, &self.tax_sec1, TAX, "tax-broker", 41);
        assert_eq!(s, 201, "{v}");
    }

    fn register_asset(&self, body: Value) -> (u16, Value) {
        self.t
            .call(&self.tax_owner, "POST", "/v1/assets", Some(body))
    }

    fn version_body(
        &self,
        label: &str,
        digest: char,
        broker: Option<&str>,
        project: bool,
    ) -> Value {
        let mut b = json!({"organization": TAX, "kind": "dataset", "name": format!("income@{label}"),
                           "series": "income", "version": label,
                           "digest": digest.to_string().repeat(64),
                           "ir_policy": registered(TAX)["ir_policy"], "release_class": "boolean-only"});
        if let Some(k) = broker {
            b["key_ref"] = key_ref(k, &format!("income-{label}"));
        }
        if project {
            b["project"] = json!(self.project);
        }
        b
    }

    fn authorization(&self, purpose: &str, version: &str, k: &SigningKey) -> (String, String) {
        self.authorization_for(purpose, version, k, &"a".repeat(64), &"b".repeat(64))
    }

    /// An active authorization of `version` for `program_id` under
    /// `policy_id`.
    fn authorization_for(
        &self,
        purpose: &str,
        version: &str,
        k: &SigningKey,
        program_id: &str,
        policy_id: &str,
    ) -> (String, String) {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let body = AuthorizationV2 {
            version: 2,
            party: TAX.into(),
            project: self.project.clone(),
            purpose_id: purpose.into(),
            asset_version_id: version.into(),
            asset_digest_commitment: "d".repeat(64),
            program: ProgramRef::Program {
                program_id: program_id.into(),
            },
            policy_id: policy_id.into(),
            privacy_policy_id: None,
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
        };
        let v = self.t.ok(
            &self.tax_owner,
            "POST",
            "/v1/authorizations",
            Some(json!({"body": body})),
        );
        let id = v["id"].as_str().unwrap().to_owned();
        for (who, role) in [
            (&self.tax_owner, "data_owner"),
            (&self.tax_sec1, "security_admin"),
        ] {
            self.t.ok(
                who,
                "POST",
                &format!("/v1/authorizations/{id}/approve"),
                Some(json!({"role": role})),
            );
        }
        let v = self.t.ok(
            &self.tax_sec1,
            "GET",
            &format!("/v1/authorizations/{id}"),
            None,
        );
        let to_sign: AuthorizationV2 = serde_json::from_value(v["body"].clone()).unwrap();
        let s = to_sign.sign(k).unwrap();
        let v = self.t.ok(
            &self.tax_sec1,
            "POST",
            &format!("/v1/authorizations/{id}/signature"),
            Some(json!({"public_key": s.public_key, "signature": s.signature})),
        );
        (id, v["authorization_id"].as_str().unwrap().to_owned())
    }

    fn ready(&self) -> Ready {
        self.own_broker();
        let k = key(7);
        let v = self.t.ok(
            &self.tax_admin,
            "POST",
            &format!("/v1/organizations/{TAX}/governance-keys"),
            Some(json!({"public_key": pk(&k), "kms_key_ref": "vault:transit/governance"})),
        );
        let gk = v["id"].as_str().unwrap().to_owned();
        self.t.ok(
            &self.tax_sec1,
            "POST",
            &format!("/v1/organizations/{TAX}/governance-keys/{gk}/approve"),
            None,
        );
        let v = self.t.ok(
            &self.tax_sec1,
            "POST",
            &format!("/v1/projects/{}/purposes", self.project),
            Some(json!({"organization": TAX, "name": "benefits-eligibility",
                        "description": "Eligibility for housing benefit",
                        "modes": ["aggregate"], "allowed_release_classes": ["boolean-only"],
                        "recipients": [BEN], "valid_from": now() - 60, "valid_until": now() + 3600})),
        );
        let purpose = v["id"].as_str().unwrap().to_owned();
        self.t.ok(
            &self.tax_sec2,
            "POST",
            &format!("/v1/purposes/{purpose}/approve"),
            None,
        );
        let acceptance = encompute_trust::authz::PurposeAcceptance {
            version: 1,
            organization: TAX.into(),
            project: self.project.clone(),
            purpose_id: purpose.clone(),
            accepted_at: now(),
        }
        .sign(&k)
        .unwrap();
        self.t.ok(
            &self.tax_sec2,
            "POST",
            &format!("/v1/purposes/{purpose}/accept"),
            Some(json!({"acceptance": acceptance})),
        );
        let v = self.t.ok(
            &self.tax_owner,
            "POST",
            "/v1/assets",
            Some(self.version_body("2026-q3", 'c', Some("tax-broker"), true)),
        );
        let version = v["version_id"].as_str().unwrap().to_owned();
        let asset = v["id"].as_str().unwrap().to_owned();
        // Authorized for the program the fixture jobs run: tax's version,
        // read by `reading`.
        let spec = reading_spec(&asset);
        let (authorization_row, authorization_id) = self.authorization_for(
            &purpose,
            &version,
            &k,
            &spec.program_id,
            spec.policy_id.as_deref().unwrap(),
        );
        Ready {
            purpose,
            version,
            asset,
            authorization_row,
            authorization_id,
            governance_key: k,
        }
    }

    /// A governed job row as submission writes it, with its grant's window
    /// chosen by the test: planned by tax's developer (a program reading
    /// the ready version), under the ready authorization, over `asset`
    /// (version `version`), queued on evaluator-1 under a grant the control
    /// plane signed, with `not_after` and `expires_at` as given.
    fn governed_job(
        &self,
        r: &Ready,
        asset: &str,
        version: &str,
        state: &str,
        not_after: u64,
        expires_at: u64,
    ) -> String {
        let plan = self.t.ok(
            &self.tax_dev,
            "POST",
            "/v1/plans",
            Some(json!({"project": self.project, "program": reading(&[&r.asset])})),
        );
        let plan_row = plan["id"].as_str().unwrap().to_owned();
        let binding = GovernanceBinding {
            version: GOVERNANCE_BINDING_VERSION,
            project: self.project.clone(),
            purpose_id: r.purpose.clone(),
            linkage_policy_id: None,
            inputs: BTreeMap::from([(
                "x0".to_string(),
                GovernanceInput {
                    asset_version_id: version.into(),
                    digest_commitment: "d".repeat(64),
                    organization: TAX.into(),
                },
            )]),
            outputs: BTreeMap::from([(
                "out".to_string(),
                GovernanceOutput {
                    release_class: ReleaseClass::BooleanOnly,
                    recipients: BTreeSet::from([BEN.to_string()]),
                },
            )]),
            placement_digest: None,
            project_policy_digest: None,
            asset_brokers: BTreeMap::new(),
        };
        let spec = reading_spec(&r.asset).governed(&binding);
        let plan_hash = plan["plan_id"]
            .as_str()
            .unwrap()
            .strip_prefix("encplan1:")
            .unwrap()
            .to_owned();
        // What the real submission stores, so the job revalidates like one.
        let governance = json!({
            "binding": binding,
            "governance_id": binding.id().hex(),
            "plan_hash": plan_hash,
            "authorization_set_id": AuthorizationSetId::of([r.authorization_id.clone()]).unwrap().hex(),
            "authorizations": {r.authorization_row.clone(): r.authorization_id.clone()},
        });
        let job = format!("job_{}", hex(&rand16()));
        let signer = &self.t.control.signer;
        let mut g = JobGrant {
            version: JOB_GRANT_V2,
            job_id: job.clone(),
            organization: TAX.into(),
            project: self.project.clone(),
            plan_id: plan_row.clone(),
            spec_id: spec.id().hex(),
            program_id: plan["program_id"].as_str().unwrap().into(),
            evaluator: self.evaluator.id.clone(),
            backend: plan["backend"].as_str().unwrap().into(),
            profile: plan["profile"].as_str().unwrap().into(),
            issued_at: now(),
            expires_at,
            issuer: signer.id().into(),
            issuer_public_key: signer.public_key_hex(),
            governance: Some(GrantGovernance {
                plan_hash: plan_hash.clone(),
                purpose_id: r.purpose.clone(),
                governance_id: binding.id().hex(),
                binding,
                authorization_set_id: AuthorizationSetId::of([r.authorization_id.clone()])
                    .unwrap()
                    .hex()
                    .to_owned(),
                not_after,
                placement: None,
            }),
            signature: String::new(),
        };
        g.signature = signer.sign(JOB_GRANT, &g.unsigned()).unwrap();
        let mut c = self.t.control.db.conn().unwrap();
        c.execute(
            "INSERT INTO jobs (id, organization_id, project_id, plan_id, spec_id, program_id, purpose,
                 source_assets, requested_output, scheme, backend, profile, state, evaluator_id,
                 job_grant, initiated_by, idempotency_key, request_digest, governance, purpose_id)
             VALUES ($1, $2, $3, $4, $5, $6, 'benefits-eligibility', $7, 'out', $8, $9, $10, $11,
                     $12, $13, 't-dev', $1, 'fixture', $14, $15)",
            &[
                &job,
                &TAX,
                &self.project,
                &plan_row,
                &g.spec_id,
                &g.program_id,
                &json!([asset]),
                &plan["scheme"].as_str().unwrap(),
                &g.backend,
                &g.profile,
                &state,
                &self.evaluator.id,
                &serde_json::to_value(&g).unwrap(),
                &governance,
                &r.purpose,
            ],
        )
        .unwrap();
        c.execute(
            "INSERT INTO job_authorizations (job_id, authorization_row, authorization_id, asset_id)
             VALUES ($1, $2, $3, $4)",
            &[&job, &r.authorization_row, &r.authorization_id, &r.asset],
        )
        .unwrap();
        job
    }

    fn ticket(&self, who: &As, job: &str, version: &str) -> (u16, Value) {
        self.t.call(
            who,
            "POST",
            &format!("/v1/jobs/{job}/release-ticket"),
            Some(json!({"asset_version_id": version})),
        )
    }
}

fn rand16() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).unwrap();
    b
}

fn ticket_of(v: &Value) -> ReleaseTicket {
    serde_json::from_value(v["ticket"].clone()).unwrap()
}

#[test]
fn sovereign_project_refuses_platform_broker() {
    let Some(c) = world() else { return };
    let v = c.t.ok(
        &c.tax_admin,
        "GET",
        &format!("/v1/projects/{}", c.project),
        None,
    );
    assert_eq!(v["custody"], "sovereign", "the governed default: {v}");
    // An asset registered for the project whose key a platform broker holds.
    refused(
        c.register_asset(c.version_body("2026-q1", '1', Some("platform-broker"), true)),
        "ENC2715",
    );
    // The platform's broker is not an organization's own, either.
    refused(
        register_broker(&c.t, &c.tax_sec1, TAX, "platform-broker", 50),
        "ENC2715",
    );
    refused(
        register_broker(&c.t, &c.platform, "platform", "platform-broker", 50),
        "ENC2715",
    );
    // Nothing was registered.
    let n: i64 =
        c.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM assets WHERE series = 'income'", &[])
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
}

#[test]
fn sovereign_asset_needs_own_org_broker() {
    let Some(c) = world() else { return };
    c.own_broker();
    // No key reference at all.
    refused(
        c.register_asset(c.version_body("2026-q1", '1', None, true)),
        "ENC2715",
    );
    // Its own key-broker service account, but never registered as a broker.
    refused(
        c.register_asset(c.version_body("2026-q1", '1', Some("tax-broker-unregistered"), true)),
        "ENC2715",
    );
    // Another organization's broker (refused before custody is asked).
    let (s, v) = register_broker(&c.t, &c.ben_sec1, BEN, "ben-broker", 42);
    assert_eq!(s, 201, "{v}");
    refused(
        c.register_asset(c.version_body("2026-q1", '1', Some("ben-broker"), true)),
        "ENC2604",
    );
    // Its own registered broker.
    let (s, v) = c.register_asset(c.version_body("2026-q1", '1', Some("tax-broker"), true));
    assert_eq!(s, 201, "{v}");
    // A registered broker that is later disabled holds nothing new.
    c.t.ok(
        &c.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts/tax-broker/disable"),
        None,
    );
    refused(
        c.register_asset(c.version_body("2026-q2", '2', Some("tax-broker"), true)),
        "ENC2715",
    );
    // An organization that is not a member cannot register for the project.
    let (s, _) = c.t.call(
        &c.ben_admin,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": BEN, "kind": "dataset", "name": "claims",
                    "digest": "9".repeat(64), "project": "prj_unknown"}),
        ),
    );
    assert_eq!(s, 404);
}

#[test]
fn standard_project_asset_registration_unchanged() {
    let Some(c) = world() else { return };
    let p = c.t.ok(
        &c.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "statistics"})),
    );
    assert!(p.get("custody").is_none(), "{p}");
    let standard = p["id"].as_str().unwrap().to_owned();
    let v = c.t.ok(
        &c.tax_admin,
        "GET",
        &format!("/v1/projects/{standard}"),
        None,
    );
    assert!(v.get("custody").is_none(), "{v}");
    // A platform broker, an unregistered broker, no broker: all as before.
    for (name, broker) in [
        ("a", Some("platform-broker")),
        ("b", Some("tax-broker-unregistered")),
        ("c", Some("keybroker-nobody-registered")),
        ("d", None),
    ] {
        let mut body = json!({"organization": TAX, "kind": "dataset", "name": name,
                              "digest": "a".repeat(64)});
        if let Some(b) = broker {
            body["key_ref"] = key_ref(b, name);
        }
        let (s, v) = c.register_asset(body.clone());
        assert_eq!(s, 201, "{v}");
        body["name"] = json!(format!("{name}-in-project"));
        body["project"] = json!(standard);
        let (s, v) = c.register_asset(body);
        assert_eq!(s, 201, "{v}");
    }
    // Sovereign custody belongs to governed projects.
    let (s, v) = c.t.call(
        &c.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "other", "custody": "sovereign"})),
    );
    assert_eq!(s, 400, "{v}");
    // Asking for standard custody explicitly is as before.
    let p = c.t.ok(
        &c.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "explicit", "custody": "standard"})),
    );
    assert!(p.get("custody").is_none(), "{p}");
}

/// A governed project is always in sovereign custody: asking for standard
/// custody is refused, and the database refuses it too.
#[test]
fn governed_project_cannot_opt_into_standard_custody() {
    let Some(c) = world() else { return };
    refused(
        c.t.call(
            &c.tax_admin,
            "POST",
            "/v1/projects",
            Some(json!({"organization": TAX, "name": "governed-standard",
                        "governance": "governed", "custody": "standard"})),
        ),
        "ENC2715",
    );
    let p = c.t.ok(
        &c.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "governed-sovereign",
                    "governance": "governed", "custody": "sovereign"})),
    );
    assert_eq!(p["custody"], "sovereign", "{p}");
    let mut db = c.t.control.db.conn().unwrap();
    let e = db
        .execute(
            "INSERT INTO projects (id, organization_id, name, status, governance, custody)
             VALUES ('prj_x', $1, 'x', 'active', 'governed', 'standard')",
            &[&TAX],
        )
        .expect_err("a governed project in standard custody");
    assert!(db_msg(&e).contains("projects_custody_governed"), "{e}");
    // Omitted, a governed project's custody is sovereign; in the database
    // too.
    db.execute(
        "INSERT INTO projects (id, organization_id, name, status, governance)
         VALUES ('prj_y', $1, 'y', 'active', 'governed')",
        &[&TAX],
    )
    .unwrap();
    let r: String = db
        .query_one("SELECT custody FROM projects WHERE id = 'prj_y'", &[])
        .unwrap()
        .get(0);
    assert_eq!(r, "sovereign");
}

#[test]
fn custody_is_immutable() {
    let Some(c) = world() else { return };
    let standard = c.t.ok(
        &c.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "statistics"})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut db = c.t.control.db.conn().unwrap();
    for (project, to) in [(&c.project, "standard"), (&standard, "sovereign")] {
        let e = db
            .execute(
                "UPDATE projects SET custody = $2 WHERE id = $1",
                &[project, &to],
            )
            .expect_err("custody changed");
        assert!(
            db_msg(&e).contains("custody is immutable") || db_msg(&e).contains("check constraint"),
            "{e}"
        );
    }
    let r: String = db
        .query_one("SELECT custody FROM projects WHERE id = $1", &[&c.project])
        .unwrap()
        .get(0);
    assert_eq!(r, "sovereign");
    // A registered broker's identity and grant key never change, and it is
    // never deleted.
    drop(db);
    c.own_broker();
    let mut db = c.t.control.db.conn().unwrap();
    for sql in [
        "UPDATE key_brokers SET organization_id = 'benefits-agency' WHERE id = 'tax-broker'",
        "UPDATE key_brokers SET grant_public_key = repeat('0', 64) WHERE id = 'tax-broker'",
        "DELETE FROM key_brokers WHERE id = 'tax-broker'",
    ] {
        assert!(db.execute(sql, &[]).is_err(), "{sql}");
    }
    // A platform broker never becomes an organization's through the
    // database either.
    let e = db
        .execute(
            "INSERT INTO key_brokers (id, organization_id, grant_public_key, provider_kind,
                 key_ref_namespace, status, created_by)
             VALUES ('platform-broker', 'tax-agency', repeat('1', 64), 'x', 'y', 'active', 'z')",
            &[],
        )
        .expect_err("platform broker registered as an organization's");
    assert!(db_msg(&e).contains("its own key-broker"), "{e}");
}

#[test]
fn only_org_security_admin_registers_brokers() {
    let Some(c) = world() else { return };
    // An organization admin who is not a security admin.
    refused(
        register_broker(&c.t, &c.tax_admin, TAX, "tax-broker", 41),
        "ENC2602",
    );
    // A security admin of another organization.
    let (s, _) = register_broker(&c.t, &c.ben_sec1, TAX, "tax-broker", 41);
    assert_eq!(s, 404);
    // An auditor, whatever else it holds (a combination from before
    // auditor separation: granting it now is refused, ENC2716).
    legacy_role(&c.t, "t-auditor", TAX, "security_admin");
    refused(
        register_broker(&c.t, &c.tax_auditor, TAX, "tax-broker", 41),
        "ENC2602",
    );
    // A service account (an automation key with the admin's roles).
    let robot = ServiceSigner::from_seed("tax-robot", &[9; 32]).unwrap();
    c.t.ok(
        &c.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts"),
        Some(
            json!({"id": "tax-robot", "kind": "automation", "public_key": robot.public_key_hex(),
                    "roles": ["organization_admin"]}),
        ),
    );
    let robot = As::Service(std::sync::Arc::new(robot));
    refused(
        register_broker(&c.t, &robot, TAX, "tax-broker", 41),
        "ENC2707",
    );
    // Listing is for people too.
    refused(
        c.t.call(
            &robot,
            "GET",
            &format!("/v1/organizations/{TAX}/key-brokers"),
            None,
        ),
        "ENC2602",
    );
    // Another organization's broker account is not found; one that is not
    // a key broker is refused.
    let (s, _) = register_broker(&c.t, &c.tax_sec1, TAX, "ben-broker", 41);
    assert_eq!(s, 404);
    refused(
        register_broker(&c.t, &c.tax_sec1, TAX, "tax-robot", 41),
        "ENC2604",
    );
    // The organization's security admin registers it, once.
    let (s, v) = register_broker(&c.t, &c.tax_sec1, TAX, "tax-broker", 41);
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["organization"], TAX);
    refused(
        register_broker(&c.t, &c.tax_sec2, TAX, "tax-broker", 43),
        "ENC2604",
    );
    // Listed to the organization's data owners; audited.
    let list = c.t.ok(
        &c.tax_owner,
        "GET",
        &format!("/v1/organizations/{TAX}/key-brokers"),
        None,
    );
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list[0]["location"]["country"], "NL");
    let (s, _) = c.t.call(
        &c.ben_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/key-brokers"),
        None,
    );
    assert_eq!(s, 404);
    let audit = c.t.ok(
        &c.tax_sec1,
        "GET",
        &format!("/v1/audit?organization={TAX}&limit=1000"),
        None,
    );
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "key_broker.registered" && e["resource_id"] == "tax-broker"),
        "{audit}"
    );
}

#[test]
fn ticket_only_for_scheduled_evaluator() {
    let Some(c) = world() else { return };
    let r = c.ready();
    let far = now() + 3600;
    let job = c.governed_job(&r, &r.asset, &r.version, "running", far, far);
    // Nobody but the scheduled evaluator: not a person, not another
    // evaluator.
    refused(c.ticket(&c.tax_dev, &job, &r.version), "ENC2602");
    let (s, _) = c.ticket(&c.other_evaluator.service, &job, &r.version);
    assert_eq!(s, 404);
    // The scheduled evaluator, for a source of its job.
    let (s, v) = c.ticket(&c.evaluator.service, &job, &r.version);
    assert_eq!(s, 201, "{v}");
    // Not for a version the job does not read.
    let other = c.t.ok(
        &c.tax_owner,
        "POST",
        "/v1/assets",
        Some(c.version_body("2026-q4", '4', Some("tax-broker"), true)),
    )["version_id"]
        .as_str()
        .unwrap()
        .to_owned();
    refused(c.ticket(&c.evaluator.service, &job, &other), "ENC2704");
    // Not for a job that ended.
    let ended = c.governed_job(&r, &r.asset, &r.version, "failed", far, far);
    refused(
        c.ticket(&c.evaluator.service, &ended, &r.version),
        "ENC2604",
    );
    // Not for a grant the control plane did not sign.
    let forged = c.governed_job(&r, &r.asset, &r.version, "running", far, far);
    c.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE jobs SET job_grant = jsonb_set(job_grant, '{expires_at}', to_jsonb($2::bigint)) WHERE id = $1",
            &[&forged, &((far + 60) as i64)],
        )
        .unwrap();
    refused(
        c.ticket(&c.evaluator.service, &forged, &r.version),
        "ENC2604",
    );
    // Not for a queued job: start is the gate, and it has not run (ENC2604).
    let queued = c.governed_job(&r, &r.asset, &r.version, "queued", far, far);
    refused(
        c.ticket(&c.evaluator.service, &queued, &r.version),
        "ENC2604",
    );
    // Not once the owner revoked its authorization: a running job gets no
    // ticket (ENC2706), and the revocation fails a queued one.
    let running = c.governed_job(&r, &r.asset, &r.version, "running", far, far);
    c.t.ok(
        &c.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", r.authorization_row),
        Some(json!({"reason": "withdrawn"})),
    );
    refused(c.ticket(&c.evaluator.service, &job, &r.version), "ENC2706");
    refused(
        c.ticket(&c.evaluator.service, &running, &r.version),
        "ENC2706",
    );
    refused(
        c.ticket(&c.evaluator.service, &queued, &r.version),
        "ENC2604",
    );
}

#[test]
fn ticket_ttl_capped_by_grant_not_after() {
    let Some(c) = world() else { return };
    let r = c.ready();
    let far = now() + 3600;
    // By default five minutes.
    let job = c.governed_job(&r, &r.asset, &r.version, "running", far, far);
    let t = ticket_of(&c.t.ok(
        &c.evaluator.service,
        "POST",
        &format!("/v1/jobs/{job}/release-ticket"),
        Some(json!({"asset_version_id": r.version})),
    ));
    assert_eq!(t.not_after - t.not_before, 300);
    // Capped by the governed window of the grant...
    let soon = now() + 120;
    let job = c.governed_job(&r, &r.asset, &r.version, "running", soon, far);
    let t = ticket_of(&c.ticket(&c.evaluator.service, &job, &r.version).1);
    assert_eq!(t.not_after, soon);
    // ... and by the grant's expiry.
    let soon = now() + 100;
    let job = c.governed_job(&r, &r.asset, &r.version, "running", far, soon);
    let t = ticket_of(&c.ticket(&c.evaluator.service, &job, &r.version).1);
    assert_eq!(t.not_after, soon);
    // A window closing within the skew gets no ticket; one that ended, none
    // either.
    let job = c.governed_job(&r, &r.asset, &r.version, "running", now() + 30, far);
    refused(c.ticket(&c.evaluator.service, &job, &r.version), "ENC2712");
    let job = c.governed_job(&r, &r.asset, &r.version, "running", now() - 1, far);
    refused(c.ticket(&c.evaluator.service, &job, &r.version), "ENC2705");
}

#[test]
fn ticket_is_verifiable_by_the_broker() {
    let Some(c) = world() else { return };
    let r = c.ready();
    let far = now() + 3600;
    let job = c.governed_job(&r, &r.asset, &r.version, "running", far, far);
    let (s, v) = c.ticket(&c.evaluator.service, &job, &r.version);
    assert_eq!(s, 201, "{v}");
    let t = ticket_of(&v);
    // The pinned control-plane key, as a broker holds it.
    let control_key = c.t.control.signer.public_key_hex();
    t.verify(&control_key, now()).unwrap();
    t.check_consistent().unwrap();
    assert_eq!(t.organization, TAX);
    assert_eq!(t.broker, "tax-broker");
    assert_eq!(t.asset_version_id, r.version);
    assert_eq!(t.job_id, job);
    assert_eq!(t.project, c.project);
    assert_eq!(t.purpose_id, r.purpose);
    assert_eq!(
        t.workload_or_recipient,
        c.evaluator.receipt.identity().public_key_hex()
    );
    assert_eq!(
        t.authorization_ids,
        BTreeSet::from([r.authorization_id.clone()])
    );
    // Any change breaks it; another key never verifies it.
    let mut forged = t.clone();
    forged.not_after += 60;
    assert!(forged.verify(&control_key, now()).is_err());
    let other = ServiceSigner::from_seed("control-plane", &[1; 32]).unwrap();
    assert!(t.verify(&other.public_key_hex(), now()).is_err());
    assert!(t
        .clone()
        .sign(&other)
        .unwrap()
        .verify(&control_key, now())
        .is_err());
    // Stored, append-only, and audited.
    let mut db = c.t.control.db.conn().unwrap();
    let stored: Value = db
        .query_one(
            "SELECT body FROM release_tickets WHERE ticket_id = $1 AND job_id = $2 AND broker_id = 'tax-broker'",
            &[&t.ticket_id, &job],
        )
        .unwrap()
        .get(0);
    assert_eq!(serde_json::from_value::<ReleaseTicket>(stored).unwrap(), t);
    for sql in [
        "UPDATE release_tickets SET not_after = not_after + 600",
        "DELETE FROM release_tickets",
    ] {
        let e = db.execute(sql, &[]).expect_err(sql);
        assert!(db_msg(&e).contains("append-only"), "{e}");
    }
    let audit = c.t.ok(
        &c.tax_sec1,
        "GET",
        &format!("/v1/audit?organization={TAX}&limit=1000"),
        None,
    );
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "release_ticket.issued" && e["resource_id"] == job.as_str()),
        "{audit}"
    );
    // Each request is a new, single-use ticket.
    let again = ticket_of(&c.ticket(&c.evaluator.service, &job, &r.version).1);
    assert_ne!(again.ticket_id, t.ticket_id);
    let _ = &r.governance_key;
}

/// A source registered outside the project, its key at a platform broker,
/// gets no ticket in sovereign custody: registration without a project is
/// no way around custody.
#[test]
fn sovereign_ticket_refuses_a_platform_held_source() {
    let Some(c) = world() else { return };
    let r = c.ready();
    let v = c.t.ok(
        &c.tax_owner,
        "POST",
        "/v1/assets",
        Some(c.version_body("2026-q2", '2', Some("platform-broker"), false)),
    );
    let (asset, version) = (
        v["id"].as_str().unwrap().to_owned(),
        v["version_id"].as_str().unwrap().to_owned(),
    );
    c.authorization(&r.purpose, &version, &r.governance_key);
    let far = now() + 3600;
    let job = c.governed_job(&r, &asset, &version, "running", far, far);
    refused(c.ticket(&c.evaluator.service, &job, &version), "ENC2715");
}

#[test]
fn authorization_revoked_sent_only_after_anchor() {
    let Some(c) = world() else { return };
    let r = c.ready();
    c.t.transport.drain();
    // Revoked through the API: anchored before the answer, then sent to the
    // owner's broker.
    c.t.ok(
        &c.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", r.authorization_row),
        Some(json!({"reason": "withdrawn"})),
    );
    assert!(c
        .t
        .control
        .anchored(
            encompute_control::govlog::NegSet::RevokedAuthorizations,
            &r.authorization_row
        )
        .unwrap());
    let sent = c.t.transport.drain();
    let m = sent
        .iter()
        .find(|(u, m)| u == TAX_BROKER_URL && m.kind == "authorization.revoked")
        .unwrap_or_else(|| panic!("{sent:?}"));
    assert_eq!(m.1.payload["authorization_id"], r.authorization_id.as_str());
    assert_eq!(m.1.organization.as_deref(), Some(TAX));
    assert_eq!(m.1.recipient, "tax-broker");
    // A revocation committed but not yet anchored (a crash between the
    // two) stays in the outbox until the background anchoring catches up.
    let (row, aid) = c.authorization(&r.purpose, &r.version, &r.governance_key);
    let m = encompute_control::transport::seal(
        &c.t.control.signer,
        "authorization.revoked",
        "tax-broker",
        encompute_control::transport::Scope {
            organization: Some(TAX.into()),
            ..Default::default()
        },
        &json!({"authorization": row, "authorization_id": aid, "revoked_at": now()}),
        300,
    )
    .unwrap();
    // The revocation as it stands after its commit (its governance log
    // event included), before the log is checkpointed and anchored.
    c.t.control
        .db
        .tx(|db| {
            let project: String = db
                .query_one(
                    "UPDATE authorizations SET status = 'revoked', revoked_by = 'x', revoked_at = now()
                      WHERE id = $1 RETURNING project_id",
                    &[&row],
                )
                .unwrap()
                .get(0);
            let partition = encompute_control::govlog::for_project(db, &project, None)?;
            encompute_control::govlog::append(
                db,
                encompute_control::govlog::Draft::new(
                    partition,
                    encompute_control::govlog::kind::AUTHORIZATION_REVOKED,
                    &row,
                )
                .r#ref("authorization_id", aid.as_str()),
            )?;
            db.execute(
                "INSERT INTO outbox (message_id, recipient, url, envelope) VALUES ($1, 'tax-broker', $2, $3)",
                &[&m.message_id, &TAX_BROKER_URL, &serde_json::to_value(&m).unwrap()],
            )
            .unwrap();
            Ok(())
        })
        .unwrap();
    c.t.control.deliver_outbox().unwrap();
    assert!(
        c.t.transport.drain().is_empty(),
        "sent before it was anchored"
    );
    c.t.control.tick();
    assert!(c
        .t
        .control
        .anchored(
            encompute_control::govlog::NegSet::RevokedAuthorizations,
            &row
        )
        .unwrap());
    let sent = c.t.transport.drain();
    assert!(
        sent.iter()
            .any(|(u, x)| u == TAX_BROKER_URL && x.message_id == m.message_id),
        "{sent:?}"
    );
}

/// An asset's expiry (its owner's retention ended) is anchored, and only
/// then its broker is told; the expired source gets no ticket (an expiry,
/// ENC2705, not a revocation).
#[test]
fn asset_expiry_is_anchored_before_the_broker_hears_of_it() {
    let Some(c) = world() else { return };
    let r = c.ready();
    let far = now() + 3600;
    // Running (a job not yet started fails at the expiry): it may finish,
    // but gets no ticket for its expired source.
    let job = c.governed_job(&r, &r.asset, &r.version, "running", far, far);
    c.t.transport.drain();
    assert!(c.t.control.expire_asset("retention", &r.asset).unwrap());
    assert!(!c.t.control.expire_asset("retention", &r.asset).unwrap());
    assert!(c
        .t
        .control
        .anchored(encompute_control::govlog::NegSet::ExpiredAssets, &r.asset)
        .unwrap());
    let sent = c.t.transport.drain();
    assert!(
        sent.iter().any(|(u, m)| u == TAX_BROKER_URL
            && m.kind == "asset.expired"
            && m.payload["key_ref"] == "income-2026-q3"),
        "{sent:?}"
    );
    refused(c.ticket(&c.evaluator.service, &job, &r.version), "ENC2705");
    let e =
        c.t.control
            .db
            .conn()
            .unwrap()
            .execute(
                "UPDATE assets SET expired_at = NULL WHERE id = $1",
                &[&r.asset],
            )
            .expect_err("expiry cleared");
    assert!(db_msg(&e).contains("expiry is final"), "{e}");
}

#[test]
fn restore_dropping_revoked_authorization_refuses_start() {
    let Some(c) = world() else { return };
    let r = c.ready();
    let C { t, tax_sec1, .. } = c;
    let url = t.env0.url.clone();
    let env0 = t.env0;
    drop(t.control);
    let backup = format!("{}_authz", url.rsplit('/').next().unwrap());
    backup_database(&url, &backup);
    let t = env0.started();
    t.ok(
        &tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", r.authorization_row),
        Some(json!({"reason": "withdrawn"})),
    );
    assert!(t
        .control
        .anchored(
            encompute_control::govlog::NegSet::RevokedAuthorizations,
            &r.authorization_row
        )
        .unwrap());
    let env0 = t.env0;
    drop(t.control);
    restore_keeping_log(&env0, &backup);
    let e = env0
        .start()
        .err()
        .expect("a restore brought a revoked authorization back silently");
    assert!(e.message.contains("AUTHORIZATION STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&r.authorization_row), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&r.authorization_row) && n.contains("revocation re-applied")),
        "{notes:?}"
    );
    let t = env0.started();
    let v = t.ok(
        &tax_sec1,
        "GET",
        &format!("/v1/authorizations/{}", r.authorization_row),
        None,
    );
    assert_eq!(v["status"], "revoked", "{v}");
    // Its broker is told again (from the outbox, once anchored).
    t.control.tick();
    let sent = t.transport.drain();
    assert!(
        sent.iter().any(|(u, m)| u == TAX_BROKER_URL
            && m.kind == "authorization.revoked"
            && m.payload["authorization_id"] == r.authorization_id.as_str()),
        "{sent:?}"
    );
    // A second restart is clean.
    t.restarted();
}

/// A database-level attacker deletes a revoked authorization's row
/// (triggers disabled): the anchored revocation is undone as surely as by
/// setting it active again, and start is refused. Recovery records the
/// loss in the anchor; the owner's signed document stays revoked, so a row
/// carrying it again (under another row ID) is refused too.
#[test]
fn deleting_a_revoked_authorization_row_refuses_start() {
    let Some(c) = world() else { return };
    let r = c.ready();
    c.t.ok(
        &c.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", r.authorization_row),
        Some(json!({"reason": "withdrawn"})),
    );
    assert!(anchored(
        &c.t,
        NegSet::RevokedAuthorizations,
        &r.authorization_row
    ));
    assert!(anchored(
        &c.t,
        NegSet::RevokedAuthorizations,
        &r.authorization_id
    ));
    // The row as it was, to replay later.
    let row: (
        String,
        String,
        String,
        String,
        String,
        Value,
        i64,
        i64,
        Value,
        String,
    ) = {
        let mut db = c.t.control.db.conn().unwrap();
        let x = db
            .query_one(
                "SELECT organization_id, project_id, purpose_id, asset_id, asset_version_id, body,
                        valid_from, valid_until, signed, governance_key_id
                   FROM authorizations WHERE id = $1",
                &[&r.authorization_row],
            )
            .unwrap();
        (
            x.get(0),
            x.get(1),
            x.get(2),
            x.get(3),
            x.get(4),
            x.get(5),
            x.get(6),
            x.get(7),
            x.get(8),
            x.get(9),
        )
    };
    let C { t, .. } = c;
    let env0 = t.env0;
    drop(t.control);
    let tables = [
        "authorizations",
        "authorization_approvals",
        "authorization_recipients",
    ];
    attacker(
        &env0.url,
        &tables,
        &format!(
            "DELETE FROM authorization_approvals WHERE authorization_row = '{0}';
             DELETE FROM authorization_recipients WHERE authorization_row = '{0}';
             DELETE FROM authorizations WHERE id = '{0}'",
            r.authorization_row
        ),
    );
    let e = env0
        .start()
        .err()
        .expect("a deleted revoked authorization passed the rollback check");
    assert!(e.message.contains("AUTHORIZATION STATE ROLLBACK"), "{e}");
    let notes = run_recovery(&env0);
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&r.authorization_row) && n.contains("lost")),
        "{notes:?}"
    );
    let t = env0.started();
    drop(t.control);
    // The same signed document, active again under a new row.
    {
        let mut db = postgres::Client::connect(&env0.url, postgres::NoTls).unwrap();
        db.execute(
            "INSERT INTO authorizations (id, organization_id, project_id, purpose_id, asset_id,
                 asset_version_id, body, valid_from, valid_until, status, authorization_id, signed,
                 governance_key_id, proposed_by, activated_at)
             VALUES ('auz_replayed', $1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10, $11, 'x', now())",
            &[
                &row.0, &row.1, &row.2, &row.3, &row.4, &row.5, &row.6, &row.7,
                &r.authorization_id, &row.8, &row.9,
            ],
        )
        .unwrap();
    }
    let e = env0
        .start()
        .err()
        .expect("a replayed revoked authorization passed the rollback check");
    assert!(e.message.contains("AUTHORIZATION STATE ROLLBACK"), "{e}");
    assert!(e.message.contains("auz_replayed"), "{e}");
}

/// The governance tables have no delete path: a row is revoked, retired or
/// disabled, never deleted.
#[test]
fn governance_rows_are_never_deleted() {
    let Some(c) = world() else { return };
    let r = c.ready();
    let far = now() + 3600;
    let job = c.governed_job(&r, &r.asset, &r.version, "running", far, far);
    assert_eq!(c.ticket(&c.evaluator.service, &job, &r.version).0, 201);
    let mut db = c.t.control.db.conn().unwrap();
    for table in [
        "authorization_approvals",
        "authorization_recipients",
        "authorizations",
        "purpose_acceptances",
        "purposes",
        "governance_keys",
        "approval_rules",
        "release_tickets",
        "key_brokers",
    ] {
        let mut t = db.transaction().unwrap();
        // Every row of the table (an empty table has nothing to refuse).
        let n: i64 = t
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .unwrap()
            .get(0);
        if n == 0 {
            t.execute(
                "INSERT INTO approval_rules (project_id, organization_id, created_by)
                 VALUES ($1, $2, 'x')",
                &[&c.project, &TAX],
            )
            .unwrap();
        }
        let e = t
            .execute(&format!("DELETE FROM {table}"), &[])
            .expect_err(table);
        assert!(
            db_msg(&e).contains("never deleted")
                || db_msg(&e).contains("append-only")
                // (An approved authorization's evidence was guarded before.)
                || (table.starts_with("authorization_") && db_msg(&e).contains("immutable")),
            "{table}: {e}"
        );
        drop(t);
    }
}

/// A ticket and a revocation of the authorization it would name race: the
/// revocation committed first (the ticket's request waited on the
/// authorization's row), so no ticket is issued.
#[test]
fn a_ticket_waits_for_a_concurrent_revocation() {
    let Some(c) = world() else { return };
    let r = c.ready();
    let far = now() + 3600;
    let job = c.governed_job(&r, &r.asset, &r.version, "running", far, far);
    let mut db = postgres::Client::connect(&c.t.env0.url, postgres::NoTls).unwrap();
    let mut tx = db.transaction().unwrap();
    tx.execute(
        "SELECT 1 FROM authorizations WHERE id = $1 FOR UPDATE",
        &[&r.authorization_row],
    )
    .unwrap();
    tx.execute(
        "UPDATE authorizations SET status = 'revoked', revoked_by = 'x',
                revoked_at = now() - interval '1 second' WHERE id = $1",
        &[&r.authorization_row],
    )
    .unwrap();
    let control = c.t.control.clone();
    let who = c.evaluator.service.clone();
    let url = format!("/v1/jobs/{job}/release-ticket");
    let body = serde_json::to_vec(&json!({"asset_version_id": r.version})).unwrap();
    let h = std::thread::spawn(move || {
        let headers = auth_headers(&who, "POST", &url, &body);
        let resp = encompute_control::api::handle(
            &control,
            &encompute_control::api::Request {
                method: "POST".into(),
                url,
                headers,
                body,
            },
        );
        (
            resp.status,
            serde_json::from_slice::<Value>(&resp.body).unwrap_or(Value::Null),
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(700));
    assert!(
        !h.is_finished(),
        "the ticket did not wait for the revocation"
    );
    tx.commit().unwrap();
    refused(h.join().unwrap(), "ENC2706");
}

/// A program reading `assets` (registered IDs) of tax's, released to tax.
fn reading(assets: &[&str]) -> String {
    let mut p = String::from(
        "encompute 0.1\nprogram adult precision 0.001 purpose \"benefits-eligibility\"\n\
         party \"tax-agency\" \"Tax\"\n",
    );
    for a in assets {
        p.push_str(&format!(
            "asset \"{a}\" dataset owners [\"tax-agency\"] readers [\"tax-agency\"] purposes \
             [\"benefits-eligibility\"] release allowed_parties\n"
        ));
    }
    for (i, a) in assets.iter().enumerate() {
        p.push_str(&format!(
            "%{i} = input \"x{i}\" [0.0, 120.0] asset \"{a}\" : secret u8\n"
        ));
    }
    let n = assets.len();
    p.push_str(&format!(
        "%{n} = const [18.0] : public u8\n%{} = ge %0, %{n} : secret bool\noutput \"out\" = %{} to \"tax-agency\"\n",
        n + 1,
        n + 1
    ));
    p
}

/// The execution spec (before any binding) of `reading(&[asset])`.
fn reading_spec(asset: &str) -> encompute_verification::ExecutionSpec {
    let program = encompute_ir::parse(&reading(&[asset])).unwrap();
    let compiled = encompute_evaluator::compile_program(&program).unwrap();
    encompute_evaluator::execution_spec(
        &encompute_evaluator::Ids::of(&program, &compiled),
        &compiled,
        compiled.target_backend(),
    )
}

impl C {
    fn plan(&self, project: &str, program: &str) -> (u16, Value) {
        self.t.call(
            &self.tax_dev,
            "POST",
            "/v1/plans",
            Some(json!({"project": project, "program": program})),
        )
    }

    /// The stored plan document's plan.
    fn stored_plan(&self, id: &str) -> Value {
        let doc: Value = self
            .t
            .control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT document FROM plans WHERE id = $1", &[&id])
            .unwrap()
            .get(0);
        doc["plan"].clone()
    }

    fn tax_asset(&self, name: &str, broker: Option<&str>, project: Option<&str>) -> String {
        let mut b = json!({"organization": TAX, "kind": "dataset", "name": name,
                           "digest": "e".repeat(64)});
        if let Some(k) = broker {
            b["key_ref"] = key_ref(k, name);
        }
        if let Some(p) = project {
            b["project"] = json!(p);
        }
        let (s, v) = self.register_asset(b);
        assert_eq!(s, 201, "{v}");
        v["id"].as_str().unwrap().to_owned()
    }
}

/// Sovereign planning checks each source's own broker (a broker the
/// source's organization registered), not merely that some broker exists,
/// and binds it into the plan as a key-custody requirement.
#[test]
fn sovereign_planning_requires_owner_broker() {
    let Some(c) = world() else { return };
    c.own_broker();
    let held = c.tax_asset("income-own", Some("tax-broker"), Some(&c.project));
    let v = c.t.ok(
        &c.tax_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": c.project, "program": reading(&[&held])})),
    );
    let plan = c.stored_plan(v["id"].as_str().unwrap());
    let want = json!({"requirement": "key_custody", "asset": held, "organization": TAX,
                      "broker": "tax-broker"});
    assert!(
        plan["requirements"].as_array().unwrap().contains(&want),
        "{}",
        plan["requirements"]
    );
    assert_eq!(
        plan["context"]["custody"],
        json!([{"asset": held, "organization": TAX, "broker": "tax-broker"}])
    );
    // A source of tax's whose key a platform broker holds, or no broker at
    // all (registered outside the project, where that is allowed): no plan
    // in sovereign custody, although a platform broker exists.
    let platform_held = c.tax_asset("income-platform", Some("platform-broker"), None);
    let unheld = c.tax_asset("income-unheld", None, None);
    let unregistered = c.tax_asset("income-unreg", Some("tax-broker-unregistered"), None);
    for a in [&platform_held, &unheld, &unregistered] {
        let (s, v) = c.plan(&c.project, &reading(&[&held, a]));
        refused((s, v.clone()), "ENC2715");
        assert!(v["message"].as_str().unwrap().contains(a.as_str()), "{v}");
    }
    // Once tax's broker is disabled, its own sources have no broker either.
    c.t.ok(
        &c.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts/tax-broker/disable"),
        None,
    );
    refused(c.plan(&c.project, &reading(&[&held])), "ENC2715");
    // Every refusal is audited.
    let n: i64 =
        c.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action = 'plan.failed'",
                &[],
            )
            .unwrap()
            .get(0);
    assert_eq!(n, 4);
}

/// Standard projects plan as before: any active broker will do, and the
/// plan carries no custody, so its bytes and PlanId are unchanged.
#[test]
fn standard_planning_unchanged() {
    let Some(c) = world() else { return };
    let p = c.t.ok(
        &c.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "statistics"})),
    );
    let standard = p["id"].as_str().unwrap().to_owned();
    let platform_held = c.tax_asset("s-platform", Some("platform-broker"), Some(&standard));
    let unheld = c.tax_asset("s-unheld", None, Some(&standard));
    let program = reading(&[&platform_held, &unheld]);
    let (s, v) = c.plan(&standard, &program);
    assert_eq!(s, 201, "{v}");
    let plan = c.stored_plan(v["id"].as_str().unwrap());
    let text = plan.to_string();
    assert!(!text.contains("custody"), "{text}");
    // The same plan as the planner makes without custody, byte for byte.
    let parsed: encompute_planner::ConfidentialExecutionPlan =
        serde_json::from_value(plan).unwrap();
    assert!(parsed.context.custody.is_empty());
    assert!(parsed.context.infrastructure.key_broker);
    let again =
        encompute_planner::plan_or_fail(&encompute_ir::parse(&program).unwrap(), &parsed.context)
            .unwrap();
    assert_eq!(
        again.id().unwrap().to_string(),
        v["plan_id"].as_str().unwrap()
    );
}
