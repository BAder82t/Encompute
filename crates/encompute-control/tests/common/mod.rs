//! Shared test harness: a fresh PostgreSQL database per test (from
//! `ENCOMPUTE_TEST_DATABASE_URL`, an account allowed to create databases),
//! a temporary anchor directory, development tokens, and an in-memory
//! transport. Without the variable the tests are skipped, unless
//! `ENCOMPUTE_REQUIRE_SERVICES=1` (CI), where that is a failure.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

use encompute_control::anchor::DirAnchor;
use encompute_control::api::{handle, Request};
use encompute_control::authn::{dev_token, Authenticator, DEV_ISSUER};
use encompute_control::config::{Env, OidcIssuer};
use encompute_control::db::Db;
use encompute_control::transport::InMemoryTransport;
use encompute_control::Control;
use encompute_verification::ServiceSigner;

pub const SECRET: &str = "test-development-secret";

static N: AtomicU64 = AtomicU64::new(0);

/// A database for one test, or `None` (skipped).
pub fn fresh_database() -> Option<String> {
    let admin = match std::env::var("ENCOMPUTE_TEST_DATABASE_URL") {
        Ok(u) => u,
        Err(_) if std::env::var("ENCOMPUTE_REQUIRE_SERVICES").is_ok() => {
            panic!("ENCOMPUTE_REQUIRE_SERVICES is set but ENCOMPUTE_TEST_DATABASE_URL is not")
        }
        Err(_) => {
            eprintln!("SKIPPED: set ENCOMPUTE_TEST_DATABASE_URL (a PostgreSQL account that may create databases)");
            return None;
        }
    };
    let name = format!(
        "enc_test_{}_{}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
            % 1_000_000
    );
    let mut c = postgres::Client::connect(&admin, postgres::NoTls).expect("test database");
    c.batch_execute(&format!("CREATE DATABASE {name}")).unwrap();
    // Replace the database name in the URL.
    let url = match admin.rsplit_once('/') {
        Some((base, _)) if admin.starts_with("postgres") => format!("{base}/{name}"),
        _ => format!("{admin} dbname={name}"),
    };
    Some(url)
}

fn admin_url() -> String {
    std::env::var("ENCOMPUTE_TEST_DATABASE_URL").unwrap()
}

fn db_name(url: &str) -> String {
    url.rsplit('/').next().unwrap().to_owned()
}

/// "Backs up" `url` into database `backup` (a template copy; no connection
/// to the source may be open).
pub fn backup_database(url: &str, backup: &str) {
    let mut c = postgres::Client::connect(&admin_url(), postgres::NoTls).unwrap();
    c.batch_execute(&format!(
        "CREATE DATABASE {backup} TEMPLATE {}",
        db_name(url)
    ))
    .unwrap();
}

/// Restores `backup` over `url`'s database (drops it first).
pub fn restore_database(backup: &str, url: &str) {
    let mut c = postgres::Client::connect(&admin_url(), postgres::NoTls).unwrap();
    let live = db_name(url);
    c.batch_execute(&format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{live}'"
    ))
    .unwrap();
    c.batch_execute(&format!("DROP DATABASE {live}")).unwrap();
    c.batch_execute(&format!("CREATE DATABASE {live} TEMPLATE {backup}"))
        .unwrap();
}

pub fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "encompute-control-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub struct Env0 {
    pub url: String,
    pub anchor_dir: PathBuf,
    pub seed: [u8; 32],
    pub oidc: Vec<OidcIssuer>,
    pub env: Env,
}

pub struct T {
    pub control: Arc<Control>,
    pub transport: Arc<InMemoryTransport>,
    pub env0: Env0,
}

struct SharedTransport(Arc<InMemoryTransport>);

impl encompute_control::transport::MessageTransport for SharedTransport {
    fn send(
        &self,
        url: &str,
        m: &encompute_control::model::MessageEnvelope,
    ) -> encompute_ir::Result<()> {
        self.0.send(url, m)
    }
}

impl Env0 {
    pub fn start(&self) -> encompute_ir::Result<T> {
        let db = Db::connect(&self.url)?;
        db.migrate()?;
        let signer = ServiceSigner::from_seed("control-plane", &self.seed)?;
        let transport = Arc::new(InMemoryTransport::default());
        let control = Control::with_parts(
            self.env,
            "control-plane",
            db,
            Authenticator::new(
                self.env,
                "control-plane",
                self.oidc.clone(),
                Some(zeroize::Zeroizing::new(SECRET.into())),
            ),
            signer,
            Box::new(DirAnchor::new(self.anchor_dir.clone())?),
            Some(Box::new(SharedTransport(transport.clone()))),
            5,
        )?;
        Ok(T {
            control: Arc::new(control),
            transport,
            env0: Env0 {
                url: self.url.clone(),
                anchor_dir: self.anchor_dir.clone(),
                seed: self.seed,
                oidc: self.oidc.clone(),
                env: self.env,
            },
        })
    }
}

/// A fresh control plane (development mode), or `None` when skipped.
pub fn setup() -> Option<T> {
    let url = fresh_database()?;
    let env0 = Env0 {
        url,
        anchor_dir: tmp_dir("anchor"),
        seed: [42; 32],
        oidc: vec![],
        env: Env::Development,
    };
    Some(env0.start().unwrap())
}

/// Who calls.
#[derive(Clone)]
pub enum As {
    Nobody,
    User(String),
    Service(Arc<ServiceSigner>),
    Raw(String),
}

pub fn token(subject: &str) -> String {
    dev_token(SECRET, subject, 3600).unwrap()
}

impl T {
    pub fn restart(self) -> encompute_ir::Result<T> {
        let env0 = self.env0;
        drop(self.control);
        env0.start()
    }

    pub fn call(&self, who: &As, method: &str, url: &str, body: Option<Value>) -> (u16, Value) {
        self.call_with(who, method, url, body, &[])
    }

    pub fn call_with(
        &self,
        who: &As,
        method: &str,
        url: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> (u16, Value) {
        let body = body
            .map(|b| serde_json::to_vec(&b).unwrap())
            .unwrap_or_default();
        let mut headers: Vec<(String, String)> = extra
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        match who {
            As::Nobody => {}
            As::User(sub) => {
                headers.push(("Authorization".into(), format!("Bearer {}", token(sub))))
            }
            As::Raw(t) => headers.push(("Authorization".into(), format!("Bearer {t}"))),
            As::Service(s) => {
                let path = url.split('?').next().unwrap();
                let h = s
                    .sign_request(method, path, "control-plane", &Default::default(), &body)
                    .unwrap();
                for (k, v) in h.to_pairs() {
                    headers.push((k.into(), v));
                }
            }
        }
        let r = handle(
            &self.control,
            &Request {
                method: method.into(),
                url: url.into(),
                headers,
                body,
            },
        );
        let v = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        (r.status, v)
    }

    /// Calls and asserts a 2xx status.
    pub fn ok(&self, who: &As, method: &str, url: &str, body: Option<Value>) -> Value {
        let (s, v) = self.call(who, method, url, body);
        assert!((200..300).contains(&s), "{method} {url}: {s} {v}");
        v
    }
}

/// A world with the platform, two organizations (A: hospital-a, B: modelco),
/// their people, and a shared project.
pub struct World {
    pub t: T,
    pub platform: As,
    pub a_admin: As,
    pub a_owner: As,
    pub a_dev: As,
    pub a_auditor: As,
    pub b_admin: As,
    pub b_owner: As,
    pub b_dev: As,
    pub b_auditor: As,
    pub c_admin: As,
    pub c_dev: As,
    pub b_sec: As,
    pub b_sec2: As,
    pub project: String,
    pub dataset_a: String,
    pub model_b: String,
    pub evaluator: Evaluator,
}

pub fn user(t: &T, admin: &As, org: &str, subject: &str, roles: &[&str]) -> As {
    t.ok(
        admin,
        "POST",
        &format!("/v1/organizations/{org}/users"),
        Some(json!({"issuer": DEV_ISSUER, "subject": subject, "roles": roles})),
    );
    As::User(subject.into())
}

pub fn world() -> Option<World> {
    let t = setup()?;
    t.control
        .bootstrap(DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let platform = As::User("platform-admin".into());
    for (org, admin) in [
        ("hospital-a", "a-admin"),
        ("modelco", "b-admin"),
        ("other-co", "c-admin"),
    ] {
        t.ok(
            &platform,
            "POST",
            "/v1/organizations",
            Some(json!({"id": org, "display_name": org, "admin": {"issuer": DEV_ISSUER, "subject": admin}})),
        );
    }
    let a_admin = As::User("a-admin".into());
    let b_admin = As::User("b-admin".into());
    let a_owner = user(&t, &a_admin, "hospital-a", "a-owner", &["data_owner"]);
    let a_dev = user(&t, &a_admin, "hospital-a", "a-dev", &["ml_developer"]);
    let a_auditor = user(&t, &a_admin, "hospital-a", "a-auditor", &["auditor"]);
    let b_owner = user(&t, &b_admin, "modelco", "b-owner", &["model_owner"]);
    let b_dev = user(&t, &b_admin, "modelco", "b-dev", &["ml_developer"]);
    let b_auditor = user(&t, &b_admin, "modelco", "b-auditor", &["auditor"]);
    let b_sec = user(&t, &b_admin, "modelco", "b-sec", &["security_admin"]);
    let b_sec2 = user(&t, &b_admin, "modelco", "b-sec2", &["security_admin"]);
    let c_admin = As::User("c-admin".into());
    let c_dev = user(&t, &c_admin, "other-co", "c-dev", &["ml_developer"]);
    let evaluator = evaluator(
        &t,
        &platform,
        "evaluator-1",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    let p = t.ok(
        &b_dev,
        "POST",
        "/v1/projects",
        Some(json!({"organization": "modelco", "name": "medical-training"})),
    );
    let project = p["id"].as_str().unwrap().to_owned();
    t.ok(
        &b_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": "hospital-a"})),
    );
    let d = t.ok(
        &a_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "hospital-a", "kind": "dataset", "name": "patients-2026",
                    "digest": "a".repeat(64),
                    "privacy_budget": budget(3.0)}),
        ),
    );
    let m = t.ok(
        &b_owner,
        "POST",
        "/v1/assets",
        Some(json!({"organization": "modelco", "kind": "model", "name": "model-7", "digest": "b".repeat(64),
                    "key_ref": {"broker": "keybroker-modelco", "provider": "openbao-transit",
                                "key_ref": "model-7", "key_version": 1}})),
    );
    Some(World {
        t,
        platform,
        a_admin,
        a_owner,
        a_dev,
        a_auditor,
        b_admin,
        b_owner,
        b_dev,
        b_auditor,
        c_admin,
        c_dev,
        b_sec,
        b_sec2,
        project,
        dataset_a: d["id"].as_str().unwrap().into(),
        model_b: m["id"].as_str().unwrap().into(),
        evaluator,
    })
}

pub fn budget(epsilon: f64) -> Value {
    serde_json::to_value(encompute_ir::confidentiality::PrivacyBudget {
        unit: encompute_ir::confidentiality::PrivacyUnit::Patient,
        epsilon,
        delta: 1e-6,
    })
    .unwrap()
}

/// A reservation costing `sigma2`-dependent privacy (sensitivity 1).
pub fn reserve(event: &str, sigma2: u64) -> Value {
    serde_json::to_value(encompute_privacy::PrivacyEvent::Reserve {
        event_id: event.into(),
        policy_id: None,
        execution_spec_id: None,
        round_id: None,
        output: "update".into(),
        mechanism: encompute_ir::confidentiality::DpMechanism {
            kind: encompute_ir::confidentiality::DpKind::DiscreteGaussian,
            clip_norm: 1.0,
            noise_multiplier: 1.0,
            sampling_rate: None,
        },
        sensitivity: 1,
        sigma2,
        vector_len: 8,
        rng: encompute_privacy::CSPRNG.into(),
    })
    .unwrap()
}

/// An exact program (u8 comparison), and an approximate one.
pub const EXACT: &str = "encompute 0.1
program adult precision 0.001
%0 = input \"age\" [0.0, 120.0] : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2
";

pub const APPROX: &str = "encompute 0.1
program score precision 0.001
%0 = input \"x\" [-1.0, 1.0] : secret vector<4>
%1 = mul %0, %0 : secret vector<4>
output \"y\" = %1
";

impl World {
    /// A plan of `program` in the shared project, by modelco's developer.
    pub fn plan(&self, program: &str) -> String {
        let p = self.t.ok(
            &self.b_dev,
            "POST",
            "/v1/plans",
            Some(json!({"project": self.project, "program": program})),
        );
        p["id"].as_str().unwrap().into()
    }

    /// A job by modelco's developer (idempotency key `key`).
    pub fn job(&self, plan: &str, sources: &[&str], key: &str) -> (u16, Value) {
        self.t.call_with(
            &self.b_dev,
            "POST",
            "/v1/jobs",
            Some(
                json!({"project": self.project, "plan": plan, "purpose": "medical-training",
                        "source_assets": sources, "requested_output": "out"}),
            ),
            &[("Idempotency-Key", key)],
        )
    }
}

/// A registered evaluator service (identity + receipt key).
pub struct Evaluator {
    pub id: String,
    pub service: As,
    pub signer: Arc<ServiceSigner>,
    pub receipt: encompute_verification::EvaluatorSigner,
}

pub fn evaluator(
    t: &T,
    platform: &As,
    id: &str,
    backends: &[&str],
    profiles: &[&str],
    capacity: i32,
) -> Evaluator {
    let seed = {
        let mut s = [0u8; 32];
        for (i, b) in id.bytes().enumerate() {
            s[i % 32] ^= b;
        }
        s[31] ^= 0x5a;
        s
    };
    let signer = Arc::new(ServiceSigner::from_seed(id, &seed).unwrap());
    t.ok(
        platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(
            json!({"id": id, "kind": "evaluator", "public_key": signer.public_key_hex(),
                    "url": format!("http://{id}.internal:8750")}),
        ),
    );
    let receipt = encompute_verification::EvaluatorSigner::from_seed(&seed.map(|b| b ^ 0x33));
    let service = As::Service(signer.clone());
    t.ok(
        &service,
        "POST",
        "/v1/evaluators",
        Some(json!({"id": id, "url": format!("http://{id}.internal:8750"),
                    "receipt_key": receipt.identity().public_key_hex(),
                    "backends": backends, "profiles": profiles, "openfhe_version": "1.5.1", "capacity": capacity})),
    );
    Evaluator {
        id: id.into(),
        service,
        signer,
        receipt,
    }
}
