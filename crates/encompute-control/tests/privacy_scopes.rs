//! Privacy populations and scopes in governed projects (public-sector
//! governance, phase 5): a population is the authoritative cap over one
//! organization's series of datasets; a scope is a share of it for one
//! project, purpose and program, allocated with four eyes; a governed job
//! that releases a differential-privacy aggregate reserves its release in
//! each source's scope and population when it starts, is refused at
//! scheduling and start when a scope is missing or either ledger is
//! exhausted, and leaves ledgers that ride the governance log (a restored
//! older scope or population is refused).
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::sync::atomic::Ordering;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use common::*;
use encompute_control::authn::DEV_ISSUER;
use encompute_trust::authz::{AuthorizationV2, PurposeAcceptance};
use encompute_verification::governance::{ProgramRef, ProgramSetId, ReleaseClass};
use encompute_verification::{hex, ExecutionSpec, ServiceSigner};

const A: &str = "region-a";
const B: &str = "region-b";
const MIN: &str = "ministry";
const PURPOSE: &str = "notifiable-disease-surveillance-2027";
const SERIES: &str = "weekly-counts";

fn now() -> u64 {
    encompute_verification::service::now()
}

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

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

fn id(v: &Value) -> String {
    v["id"].as_str().unwrap().to_owned()
}

/// A region: its people, key and population.
struct Region {
    org: &'static str,
    admin: As,
    sec1: As,
    sec2: As,
    owner: As,
    auditor: As,
    key: SigningKey,
    population: String,
}

/// A governed project of the three organizations with one active purpose
/// every owner accepted.
#[derive(Clone)]
struct Proj {
    id: String,
    purpose: String,
}

struct G {
    t: T,
    platform: As,
    a: Region,
    b: Region,
    dev: As,
    min_admin: As,
    evaluator: Evaluator,
    /// The first project.
    main: Proj,
}

fn budget_json(eps: &str) -> Value {
    json!({"unit": "patient", "epsilon": eps, "delta": "1e-6"})
}

/// The registered policy of a region's weekly counts: aggregate-only to the
/// ministry for the purpose, with the series' own budget.
fn registered_dp(org: &str, eps: &str) -> Value {
    json!({
        "ir_policy": {"owners": [org], "readers": [MIN], "purposes": [PURPOSE],
                      "release": "aggregate_only", "derive": {},
                      "privacy": budget_json(eps)},
        "release_class": "dp-aggregate-only"
    })
}

fn region(t: &T, platform: &As, org: &'static str, seed: u8) -> Region {
    let admin_subject = format!("{org}-admin");
    t.ok(
        platform,
        "POST",
        "/v1/organizations",
        Some(json!({"id": org, "display_name": org, "admin": {"issuer": DEV_ISSUER, "subject": admin_subject}})),
    );
    let admin = As::User(admin_subject);
    let sec1 = user(t, &admin, org, &format!("{org}-sec1"), &["security_admin"]);
    let sec2 = user(t, &admin, org, &format!("{org}-sec2"), &["security_admin"]);
    let owner = user(t, &admin, org, &format!("{org}-owner"), &["data_owner"]);
    let auditor = user(t, &admin, org, &format!("{org}-auditor"), &["auditor"]);
    // Its own key broker (sovereign custody) and governance key.
    let broker = format!("{org}-broker");
    let s = ServiceSigner::from_seed(&broker, &[seed; 32]).unwrap();
    t.ok(
        &admin,
        "POST",
        &format!("/v1/organizations/{org}/service-accounts"),
        Some(
            json!({"id": broker, "kind": "keybroker", "public_key": s.public_key_hex(),
                    "url": format!("http://{broker}.internal:8760")}),
        ),
    );
    let (st, v) = t.call(
        &sec1,
        "POST",
        &format!("/v1/organizations/{org}/key-brokers"),
        Some(json!({"id": broker, "grant_public_key": pk(&key(seed + 50)),
                    "provider_kind": "openbao-transit", "key_ref_namespace": format!("transit/{org}")})),
    );
    assert_eq!(st, 201, "{v}");
    let k = key(seed + 100);
    let v = t.ok(
        &admin,
        "POST",
        &format!("/v1/organizations/{org}/governance-keys"),
        Some(json!({"public_key": pk(&k), "kms_key_ref": "vault:transit/governance"})),
    );
    t.ok(
        &sec1,
        "POST",
        &format!("/v1/organizations/{org}/governance-keys/{}/approve", id(&v)),
        None,
    );
    Region {
        org,
        admin,
        sec1,
        sec2,
        owner,
        auditor,
        key: k,
        population: String::new(),
    }
}

fn world() -> Option<G> {
    let t = setup()?;
    t.control
        .bootstrap(DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let platform = As::User("platform-admin".into());
    let a = region(&t, &platform, A, 31);
    let b = region(&t, &platform, B, 32);
    t.ok(
        &platform,
        "POST",
        "/v1/organizations",
        Some(json!({"id": MIN, "display_name": MIN, "admin": {"issuer": DEV_ISSUER, "subject": "min-admin"}})),
    );
    let min_admin = As::User("min-admin".into());
    let dev = user(&t, &min_admin, MIN, "min-dev", &["ml_developer"]);
    let evaluator = evaluator(
        &t,
        &platform,
        "evaluator-1",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    let mut g = G {
        t,
        platform,
        a,
        b,
        dev,
        min_admin,
        evaluator,
        main: Proj {
            id: String::new(),
            purpose: String::new(),
        },
    };
    g.main = g.new_project("surveillance", PURPOSE);
    // Each region's population: the hard cap on its series (which must be
    // one of its registered series), proposed and approved by two people.
    for org in [A, B] {
        g.version(g.region(org), "2027-w00");
        let r = g.region(org);
        let v = g.t.ok(
            &r.sec1,
            "POST",
            "/v1/privacy/populations",
            Some(json!({"organization": r.org, "series": SERIES, "budget": budget_json("1.0")})),
        );
        let pop = id(&v);
        assert_eq!(v["status"], "proposed");
        g.t.ok(
            &r.sec2,
            "POST",
            &format!("/v1/privacy/populations/{pop}/approve"),
            None,
        );
        if org == A {
            g.a.population = pop;
        } else {
            g.b.population = pop;
        }
    }
    Some(g)
}

impl G {
    /// A governed project of the regions and the ministry, with an active
    /// purpose `purpose` proposed and approved by two of region-a's
    /// security admins and accepted by each owner with its key.
    fn new_project(&self, name: &str, purpose_name: &str) -> Proj {
        let t = &self.t;
        let p = t.ok(
            &self.a.admin,
            "POST",
            "/v1/projects",
            Some(
                json!({"organization": A, "name": name, "governance": "governed",
                        "organizations": [B, MIN]}),
            ),
        );
        let project = id(&p);
        for (admin, org) in [(&self.b.admin, B), (&self.min_admin, MIN)] {
            t.ok(
                admin,
                "POST",
                &format!("/v1/projects/{project}/members"),
                Some(json!({"organization": org})),
            );
        }
        let v = t.ok(
            &self.a.sec1,
            "POST",
            &format!("/v1/projects/{project}/purposes"),
            Some(json!({"organization": A, "name": purpose_name,
                        "description": "Weekly notifiable-disease counts",
                        "modes": ["aggregate"], "allowed_release_classes": ["dp-aggregate-only"],
                        "recipients": [MIN], "valid_from": now() - 60, "valid_until": now() + 20_000})),
        );
        let purpose = id(&v);
        t.ok(
            &self.a.sec2,
            "POST",
            &format!("/v1/purposes/{purpose}/approve"),
            None,
        );
        for r in [&self.a, &self.b] {
            let acceptance = PurposeAcceptance {
                version: 1,
                organization: r.org.into(),
                project: project.clone(),
                purpose_id: purpose.clone(),
                accepted_at: now(),
            }
            .sign(&r.key)
            .unwrap();
            t.ok(
                &r.sec2,
                "POST",
                &format!("/v1/purposes/{purpose}/accept"),
                Some(json!({"acceptance": acceptance})),
            );
        }
        Proj {
            id: project,
            purpose,
        }
    }
}

/// A weekly aggregate over the two regions' versions: SecAgg `minimum 2`,
/// discrete-Gaussian noise, released to the ministry.
fn program(assets: [&str; 2], dp: &str) -> String {
    let mut p = format!(
        "encompute 0.1\nprogram weekly precision 0.001 purpose \"{PURPOSE}\"\n\
         party \"{MIN}\" \"Ministry\"\nparty \"{A}\" \"A\"\nparty \"{B}\" \"B\"\n"
    );
    for (a, org) in assets.iter().zip([A, B]) {
        p.push_str(&format!(
            "asset \"{a}\" dataset owners [\"{org}\"] readers [\"{MIN}\"] purposes [\"{PURPOSE}\"] \
             release aggregate_only privacy unit \"patient\" epsilon 1.0 delta 1e-6\n"
        ));
    }
    p.push_str(&format!(
        "%0 = input \"a\" [-1.0, 1.0] asset \"{}\" : secret vector<4>\n\
         %1 = input \"b\" [-1.0, 1.0] asset \"{}\" : secret vector<4>\n\
         %2 = add %0, %1 : secret vector<4>\n\
         output \"counts\" = %2 to \"{MIN}\"\n\
         aggregate \"counts\" sum minimum 2 colluding 0 clip [-1.0, 1.0] scale 4096 modulus 40 {dp}\n",
        assets[0], assets[1]
    ));
    p
}

const DP: &str = "dp discrete_gaussian clip_norm 1.0 noise_multiplier 40.0";

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

/// A dataset version of a region's series: (asset ID, version ID).
type Version = (String, String);

/// The program's own ID (what a scope may be pinned to).
fn program_id(program: &str) -> String {
    base_spec(program).program_id
}

impl G {
    fn region(&self, org: &str) -> &Region {
        if org == A {
            &self.a
        } else {
            &self.b
        }
    }

    fn version(&self, r: &Region, label: &str) -> Version {
        let mut b = json!({"organization": r.org, "kind": "dataset", "name": format!("{SERIES}@{label}"),
                           "series": SERIES, "version": label, "digest": "c".repeat(64),
                           "key_ref": {"broker": format!("{}-broker", r.org), "provider": "openbao-transit",
                                       "key_ref": format!("counts-{label}"), "key_version": 1}});
        b.as_object_mut()
            .unwrap()
            .extend(registered_dp(r.org, "1.0").as_object().unwrap().clone());
        let v = self.t.ok(&r.owner, "POST", "/v1/assets", Some(b));
        (id(&v), v["version_id"].as_str().unwrap().to_owned())
    }

    /// A scope of `r`'s population for `proj`'s purpose: proposed by one
    /// security admin, approved by the other.
    fn scope_in(&self, proj: &Proj, r: &Region, eps: &str, program: Option<&str>) -> String {
        let (s, v) = self.try_scope(proj, r, eps, program);
        assert_eq!(s, 201, "{v}");
        let scope = id(&v);
        let v = self.t.ok(
            &r.sec2,
            "POST",
            &format!("/v1/privacy/scopes/{scope}/approve"),
            None,
        );
        assert_eq!(v["status"], "active", "{v}");
        scope
    }

    fn try_scope(&self, proj: &Proj, r: &Region, eps: &str, program: Option<&str>) -> (u16, Value) {
        self.t.call(
            &r.sec1,
            "POST",
            "/v1/privacy/scopes",
            Some(
                json!({"population": r.population, "project": proj.id, "purpose": PURPOSE,
                        "program_id": program, "epsilon": eps.parse::<f64>().unwrap()}),
            ),
        )
    }

    /// An active purpose `name` of `proj`, accepted by both owners.
    fn add_purpose(&self, proj: &Proj, name: &str) {
        let v = self.t.ok(
            &self.a.sec1,
            "POST",
            &format!("/v1/projects/{}/purposes", proj.id),
            Some(json!({"organization": A, "name": name, "description": "Another purpose",
                        "modes": ["aggregate"], "allowed_release_classes": ["dp-aggregate-only"],
                        "recipients": [MIN], "valid_from": now() - 60, "valid_until": now() + 20_000})),
        );
        let purpose = id(&v);
        self.t.ok(
            &self.a.sec2,
            "POST",
            &format!("/v1/purposes/{purpose}/approve"),
            None,
        );
        for r in [&self.a, &self.b] {
            let acceptance = PurposeAcceptance {
                version: 1,
                organization: r.org.into(),
                project: proj.id.clone(),
                purpose_id: purpose.clone(),
                accepted_at: now(),
            }
            .sign(&r.key)
            .unwrap();
            self.t.ok(
                &r.sec2,
                "POST",
                &format!("/v1/purposes/{purpose}/accept"),
                Some(json!({"acceptance": acceptance})),
            );
        }
    }

    fn scope(&self, r: &Region, eps: &str, program: Option<&str>) -> String {
        self.scope_in(&self.main, r, eps, program)
    }

    /// `r`'s authorization of `v` in `proj` for `programs` (one, or a set),
    /// proposed by its data owner, approved by two people and signed with
    /// its key; `pin` names the scope the authorization is for.
    fn authorize_in(
        &self,
        proj: &Proj,
        r: &Region,
        v: &Version,
        programs: &[&str],
        pin: Option<&str>,
    ) -> String {
        self.authorize_full(proj, r, v, programs, pin, None)
    }

    /// [`Self::authorize_in`], also pinning `limits.max_sources_per_unit`.
    fn authorize_full(
        &self,
        proj: &Proj,
        r: &Region,
        v: &Version,
        programs: &[&str],
        pin: Option<&str>,
        sources: Option<u32>,
    ) -> String {
        let specs: Vec<ExecutionSpec> = programs.iter().map(|p| base_spec(p)).collect();
        let program = if specs.len() == 1 {
            ProgramRef::Program {
                program_id: specs[0].program_id.clone(),
            }
        } else {
            let ids: std::collections::BTreeSet<String> =
                specs.iter().map(|s| s.program_id.clone()).collect();
            ProgramRef::ProgramSet {
                program_set_id: ProgramSetId::of(ids.iter().cloned()).unwrap().hex(),
                programs: ids,
            }
        };
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let body = AuthorizationV2 {
            version: 2,
            party: r.org.into(),
            project: proj.id.clone(),
            purpose_id: proj.purpose.clone(),
            asset_version_id: v.1.clone(),
            asset_digest_commitment: "d".repeat(64),
            program,
            policy_id: specs[0].policy_id.clone().unwrap(),
            privacy_policy_id: specs[0].privacy_policy_id.clone(),
            linkage_policy_id: None,
            release_class: ReleaseClass::DpAggregateOnly,
            recipients: [MIN.to_string()].into(),
            privacy_scope_id: pin.map(str::to_owned),
            execution_spec_ids: None,
            limits: encompute_trust::authz::AuthorizationLimits {
                max_sources_per_unit: sources,
                ..Default::default()
            },
            per_job_four_eyes: false,
            valid_from: now() - 30,
            valid_until: now() + 1800,
            issued_at: now(),
            nonce: hex(&nonce),
            approvals: vec![],
        };
        let p = self.t.ok(
            &r.owner,
            "POST",
            "/v1/authorizations",
            Some(json!({"body": body})),
        );
        let row = id(&p);
        for (who, role) in [(&r.owner, "data_owner"), (&r.sec1, "security_admin")] {
            self.t.ok(
                who,
                "POST",
                &format!("/v1/authorizations/{row}/approve"),
                Some(json!({"role": role})),
            );
        }
        let shown = self
            .t
            .ok(&r.sec1, "GET", &format!("/v1/authorizations/{row}"), None);
        let doc: AuthorizationV2 = serde_json::from_value(shown["body"].clone()).unwrap();
        let sig = doc.sign(&r.key).unwrap();
        self.t.ok(
            &r.sec1,
            "POST",
            &format!("/v1/authorizations/{row}/signature"),
            Some(json!({"public_key": sig.public_key, "signature": sig.signature})),
        );
        row
    }

    fn plan_in(&self, proj: &Proj, program: &str) -> String {
        id(&self.t.ok(
            &self.dev,
            "POST",
            "/v1/plans",
            Some(json!({"project": proj.id, "program": program})),
        ))
    }

    fn submit_in(&self, proj: &Proj, plan: &str, sources: &[&str], key: &str) -> (u16, Value) {
        self.t.call_with(
            &self.dev,
            "POST",
            "/v1/jobs",
            Some(json!({"project": proj.id, "plan": plan, "purpose": PURPOSE,
                        "purpose_id": proj.purpose, "source_assets": sources,
                        "requested_output": "counts",
                        "outputs": {"counts": {"release_class": "dp-aggregate-only",
                                               "recipients": [MIN]}}})),
            &[("Idempotency-Key", key)],
        )
    }

    fn view(&self, job: &str) -> Value {
        self.t
            .ok(&self.dev, "GET", &format!("/v1/jobs/{job}"), None)
    }

    fn start(&self, job: &str) -> (u16, Value) {
        self.t.call(
            &self.evaluator.service,
            "POST",
            &format!("/v1/jobs/{job}/start"),
            None,
        )
    }

    /// The ledger of a population or scope, from the database.
    fn ledger(&self, key: &str) -> encompute_privacy::LedgerView {
        let mut c = self.t.control.db.conn().unwrap();
        encompute_control::control::load_ledger(&mut *c, key)
            .unwrap()
            .expect("the ledger")
    }

    fn pop_ledger(&self, r: &Region) -> encompute_privacy::LedgerView {
        self.ledger(&format!("population:{}", r.population))
    }

    fn scope_ledger(&self, scope: &str) -> encompute_privacy::LedgerView {
        self.ledger(&format!("scope:{scope}"))
    }

    /// Two versions of the week's counts, the program over them (with
    /// mechanism `dp`), and each owner's authorization of it in `proj`
    /// (pinning scopes when given): (versions, program).
    fn week_in(
        &self,
        proj: &Proj,
        label: &str,
        dp: &str,
        pins: [Option<&str>; 2],
    ) -> ([Version; 2], String) {
        let va = self.version(&self.a, label);
        let vb = self.version(&self.b, label);
        let prog = program([&va.0, &vb.0], dp);
        self.authorize_in(proj, &self.a, &va, &[&prog], pins[0]);
        self.authorize_in(proj, &self.b, &vb, &[&prog], pins[1]);
        ([va, vb], prog)
    }

    fn week(&self, label: &str, dp: &str) -> ([Version; 2], String) {
        self.week_in(&self.main, label, dp, [None, None])
    }

    /// Submits the job of `prog` over `v` in `proj`.
    fn job_in(&self, proj: &Proj, v: &[Version; 2], prog: &str, key: &str) -> (u16, Value) {
        let plan = self.plan_in(proj, prog);
        self.submit_in(proj, &plan, &[&v[0].0, &v[1].0], key)
    }

    fn job(&self, v: &[Version; 2], prog: &str, key: &str) -> (u16, Value) {
        self.job_in(&self.main, v, prog, key)
    }

    /// A job's state and, for a failed one, the audit reason's code.
    fn state(&self, job: &str) -> String {
        self.view(job)["state"].as_str().unwrap().to_owned()
    }

    fn failure(&self, job: &str) -> String {
        let mut c = self.t.control.db.conn().unwrap();
        c.query_opt(
            "SELECT e.refs->>'reason' FROM audit_events e
              WHERE e.action = 'job.failed' AND e.resource_id = $1 ORDER BY e.seq DESC LIMIT 1",
            &[&job],
        )
        .unwrap()
        .and_then(|r| r.get::<_, Option<String>>(0))
        .unwrap_or_default()
    }

    /// A SecAgg coordinator service account the scope's owner authorized to
    /// report the scope's events.
    fn secagg_spender(&self, scope: &str) -> As {
        let signer = std::sync::Arc::new(ServiceSigner::from_seed("secagg-1", &[39; 32]).unwrap());
        let (s, v) = self.t.call(
            &self.platform,
            "POST",
            "/v1/organizations/platform/service-accounts",
            Some(
                json!({"id": "secagg-1", "kind": "secagg", "public_key": signer.public_key_hex()}),
            ),
        );
        // Created once: another scope authorizes the same service.
        assert!(s == 201 || s == 409, "{s} {v}");
        let owner = self.owner_of_scope(scope);
        self.t.ok(
            &owner.owner,
            "POST",
            &format!("/v1/privacy/scopes/{scope}/spenders"),
            Some(json!({"service": "secagg-1"})),
        );
        As::Service(signer)
    }

    fn owner_of_scope(&self, scope: &str) -> &Region {
        let mut c = self.t.control.db.conn().unwrap();
        let org: String = c
            .query_one(
                "SELECT organization_id FROM privacy_scopes WHERE id = $1",
                &[&scope],
            )
            .unwrap()
            .get(0);
        self.region(&org)
    }

    /// Reservations in a ledger.
    fn reserves(v: &encompute_privacy::LedgerView) -> usize {
        v.entries
            .iter()
            .filter(|e| matches!(e.event, encompute_privacy::PrivacyEvent::Reserve { .. }))
            .count()
    }
}

/// A second noise multiplier: another program, the same shape.
const DP2: &str = "dp discrete_gaussian clip_norm 1.0 noise_multiplier 41.0";

fn events_of(g: &G, project: &str, who: &As) -> Vec<Value> {
    let (s, v) = g.t.call(
        who,
        "GET",
        &format!("/v1/projects/{project}/audit?limit=200"),
        None,
    );
    assert_eq!(s, 200, "{v}");
    v["events"]
        .as_array()
        .map(|a| a.iter().map(|e| e["event"].clone()).collect())
        .unwrap_or_default()
}

// --- allocation: populations and scopes, with four eyes ----------------------------

#[test]
fn scope_allocation_needs_four_eyes_of_the_owner() {
    let Some(g) = world() else { return };
    let r = &g.a;
    // A population is allocated once per series, whatever the cap asked.
    refused(
        g.t.call(
            &r.sec1,
            "POST",
            "/v1/privacy/populations",
            Some(json!({"organization": A, "series": SERIES, "budget": budget_json("9.0")})),
        ),
        "ENC2720",
    );
    // Only people of the owning organization create one: not an auditor,
    // not a service account, not another organization.
    let (s, v) = g.t.call(
        &r.auditor,
        "POST",
        "/v1/privacy/populations",
        Some(json!({"organization": A, "series": "another", "budget": budget_json("1.0")})),
    );
    assert_eq!(s, 403, "{v}");
    let (s, v) = g.t.call(
        &g.b.sec1,
        "POST",
        "/v1/privacy/populations",
        Some(json!({"organization": A, "series": "another", "budget": budget_json("1.0")})),
    );
    assert!((400..500).contains(&s), "{s} {v}");
    // The scope: one security admin proposes...
    let (s, v) = g.try_scope(&g.main, r, "0.5", None);
    assert_eq!(s, 201, "{v}");
    let scope = id(&v);
    assert_eq!(v["status"], "proposed");
    let approve = |who: &As| {
        g.t.call(
            who,
            "POST",
            &format!("/v1/privacy/scopes/{scope}/approve"),
            None,
        )
    };
    // ...and nobody but a different security admin of the owner approves.
    refused(approve(&r.sec1), "ENC2707"); // the proposer again
    refused(approve(&r.auditor), "ENC2602"); // an auditor, never
    refused(approve(&r.owner), "ENC2602"); // a data owner is not a security admin
    refused(approve(&g.b.sec1), "ENC2602"); // another member organization
    refused(approve(&g.min_admin), "ENC2602");
    // The proposal is the owner's business: no other member sees it.
    refused(
        g.t.call(&g.dev, "GET", &format!("/v1/privacy/scopes/{scope}"), None),
        "ENC2603",
    );
    // An automation key holding the roles is not a second pair of eyes.
    let robot = std::sync::Arc::new(ServiceSigner::from_seed("a-robot", &[77; 32]).unwrap());
    g.t.ok(
        &r.admin,
        "POST",
        &format!("/v1/organizations/{A}/service-accounts"),
        Some(
            json!({"id": "a-robot", "kind": "automation", "public_key": robot.public_key_hex(),
                    "roles": ["organization_admin", "data_owner"]}),
        ),
    );
    refused(approve(&As::Service(robot)), "ENC2707");
    let v = approve(&r.sec2);
    assert_eq!(v.0, 200, "{}", v.1);
    assert_eq!(v.1["status"], "active");
    // Already approved; and one share of a population per project, purpose
    // and program.
    assert_eq!(approve(&r.sec2).0, 409);
    let (s, v2) = g.try_scope(&g.main, r, "0.4", None);
    assert_eq!(s, 201, "{v2}");
    refused(
        g.t.call(
            &r.sec2,
            "POST",
            &format!("/v1/privacy/scopes/{}/approve", id(&v2)),
            None,
        ),
        "ENC2720",
    );
    // A cap above the population's, another purpose than the project's, an
    // unknown population: refused.
    refused(g.try_scope(&g.main, r, "1.5", None), "ENC2720");
    refused(
        g.t.call(
            &r.sec1,
            "POST",
            "/v1/privacy/scopes",
            Some(json!({"population": r.population, "project": g.main.id,
                        "purpose": "debt-collection-2027", "epsilon": 0.1})),
        ),
        "ENC2720",
    );
    refused(
        g.t.call(
            &r.sec1,
            "POST",
            "/v1/privacy/scopes",
            Some(json!({"population": g.b.population, "project": g.main.id,
                        "purpose": PURPOSE, "epsilon": 0.1})),
        ),
        "ENC2603",
    );
    // An auditor of the owner proposes nothing there either.
    let (s, v) = g.t.call(
        &r.auditor,
        "POST",
        "/v1/privacy/scopes",
        Some(json!({"population": r.population, "project": g.main.id,
                    "purpose": PURPOSE, "program_id": "x", "epsilon": 0.1})),
    );
    assert_eq!((s, code(&v)), (403, "ENC2602"), "{v}");
    // The active scope: its owner sees it in full, the project's other
    // members its totals, an outsider nothing.
    let full = g.t.ok(
        &r.owner,
        "GET",
        &format!("/v1/privacy/scopes/{scope}"),
        None,
    );
    assert_eq!(full["population"], r.population);
    assert_eq!(full["spent"]["epsilon"], 0.0);
    let shared =
        g.t.ok(&g.dev, "GET", &format!("/v1/privacy/scopes/{scope}"), None);
    assert_eq!(shared["budget"]["epsilon"], "0.5");
    assert!(
        shared.get("population").is_none() && shared.get("organization").is_none(),
        "{shared}"
    );
    // Its allocation is an event of the project's log (members see it, with
    // the cap and never a population's spending), and its ledger is
    // checkpointed in the platform partition before the call returned.
    let ev = events_of(&g, &g.main.id, &g.min_admin);
    let e = ev
        .iter()
        .find(|e| e["kind"] == "privacy.scope_allocated")
        .unwrap_or_else(|| panic!("no allocation event in {ev:?}"));
    assert_eq!(e["subject"], scope);
    // By the purpose's ID: a name is free text, which no log event carries.
    assert_eq!(e["refs"]["purpose"], g.main.purpose.as_str());
    assert!(!e.to_string().contains(&r.population), "{e}");
    let mut c = g.t.control.db.conn().unwrap();
    let cps: i64 = c
        .query_one(
            "SELECT count(*) FROM governance_events WHERE kind = 'privacy.ledger_checkpoint' AND subject_id = $1",
            &[&format!("scope:{scope}")],
        )
        .unwrap()
        .get(0);
    assert_eq!(cps, 1);
    // The database refuses an approver who is the proposer, and an edit of
    // an active scope.
    assert!(c
        .execute(
            "UPDATE privacy_scopes SET approved_by = proposed_by WHERE id = $1",
            &[&scope]
        )
        .is_err());
    assert!(c
        .execute(
            "UPDATE privacy_scopes SET epsilon = 0.9 WHERE id = $1",
            &[&scope]
        )
        .is_err());
    assert!(c
        .execute("DELETE FROM privacy_scopes WHERE id = $1", &[&scope])
        .is_err());
    assert!(c
        .execute(
            "UPDATE privacy_populations SET series = 'x' WHERE id = $1",
            &[&r.population]
        )
        .is_err());
}

// --- governed jobs: scheduling, start, reservation -------------------------------------

/// The latest checkpoint the governance log holds of ledger `key`.
fn floor(g: &G, key: &str) -> Option<(u64, String)> {
    g.t.control
        .ledger_floor(key)
        .unwrap()
        .map(|c| (c.seq, c.root))
}

#[test]
fn budgets_are_scoped_by_program_and_purpose() {
    let Some(g) = world() else { return };
    let (v1, p1) = g.week("2027-w01", DP);
    let (v2, p2) = g.week("2027-w02", DP2);
    // Each region allocates the project a general scope (any program of the
    // purpose) and one for the second program only.
    let (any_a, any_b) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let pid2 = program_id(&p2);
    let (only_a, only_b) = (
        g.scope(&g.a, "0.6", Some(&pid2)),
        g.scope(&g.b, "0.6", Some(&pid2)),
    );
    let (s, j1) = g.job(&v1, &p1, "k1");
    assert_eq!(s, 201, "{j1}");
    let job1 = id(&j1);
    assert_eq!(g.start(&job1).0, 200);
    // The first program is served by the general scope; the pinned ones,
    // for the other program, were not touched.
    assert_eq!(G::reserves(&g.scope_ledger(&any_a)), 1);
    assert_eq!(G::reserves(&g.scope_ledger(&any_b)), 1);
    assert_eq!(G::reserves(&g.scope_ledger(&only_a)), 0);
    assert_eq!(G::reserves(&g.scope_ledger(&only_b)), 0);
    let (s, j2) = g.job(&v2, &p2, "k2");
    assert_eq!(s, 201, "{j2}");
    let job2 = id(&j2);
    assert_eq!(g.start(&job2).0, 200);
    // The second program is served by its own scope (the program's, first),
    // and both releases are in the population, which composes them.
    assert_eq!(G::reserves(&g.scope_ledger(&any_a)), 1);
    assert_eq!(G::reserves(&g.scope_ledger(&only_a)), 1);
    assert_eq!(G::reserves(&g.scope_ledger(&only_b)), 1);
    let pop = g.pop_ledger(&g.a);
    assert_eq!(G::reserves(&pop), 2);
    let rho = |v: &encompute_privacy::LedgerView| v.cost().unwrap().rho;
    assert!(
        (rho(&pop) - (rho(&g.scope_ledger(&any_a)) + rho(&g.scope_ledger(&only_a)))).abs() < 1e-12,
        "the population is the sum of its scopes"
    );
    // Ledgers are checkpointed in the governance log, before the start
    // returned: the floor of each is its entry count and root.
    for (key, view) in [
        (format!("scope:{any_a}"), g.scope_ledger(&any_a)),
        (format!("scope:{only_b}"), g.scope_ledger(&only_b)),
        (format!("population:{}", g.a.population), pop.clone()),
        (format!("population:{}", g.b.population), g.pop_ledger(&g.b)),
    ] {
        let cp = view.checkpoint().unwrap();
        assert_eq!(floor(&g, &key), Some((cp.seq, cp.root)), "{key}");
    }
}

#[test]
fn a_job_reserves_its_own_release_once() {
    let Some(g) = world() else { return };
    let (sa, sb) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v, prog) = g.week("2027-w01", DP);
    let (s, j) = g.job(&v, &prog, "k1");
    assert_eq!(s, 201, "{j}");
    let job = id(&j);
    // Scheduling reserved nothing (it only checks); start reserves.
    assert_eq!(G::reserves(&g.scope_ledger(&sa)), 0);
    assert_eq!(g.start(&job).0, 200);
    let (scope, pop) = (g.scope_ledger(&sa), g.pop_ledger(&g.a));
    assert_eq!((G::reserves(&scope), G::reserves(&pop)), (1, 1));
    // Exactly the job's release: the sensitivity of a patient-level sum is
    // 2 x clip x scale + the rounding, and a scoped release whose program
    // declares no sources per unit assumes every participant (two).
    let encompute_privacy::PrivacyEvent::Reserve {
        sensitivity,
        sigma2,
        scope: Some(r),
        rng,
        round_id,
        ..
    } = &scope.entries[0].event
    else {
        panic!("a reservation");
    };
    assert_eq!(*sensitivity, 2 * (2 * 4096 + 2));
    assert_eq!(*sigma2, 26_843_545_600);
    assert_eq!(r.max_sources_per_unit, 2);
    assert_eq!(r.linkage, "none");
    assert_eq!(r.job_id.as_deref(), Some(job.as_str()));
    assert_eq!(r.scope_id, sa);
    assert_eq!(rng, encompute_privacy::CSPRNG);
    assert_eq!(round_id.as_deref(), Some(job.as_str()));
    // The same release is the population's entry, chained in its own ledger.
    assert_eq!(pop.entries[0].event, scope.entries[0].event);
    pop.verify().unwrap();
    // Recorded for the job, and in the audit.
    let mut c = g.t.control.db.conn().unwrap();
    let rows: i64 = c
        .query_one(
            "SELECT count(*) FROM job_privacy_reservations WHERE job_id = $1",
            &[&job],
        )
        .unwrap()
        .get(0);
    assert_eq!(rows, 2);
    let spent: i64 = c
        .query_one("SELECT count(*) FROM audit_events WHERE action = 'privacy.spent' AND refs->>'job' = $1", &[&job])
        .unwrap()
        .get(0);
    assert_eq!(spent, 2);
    // A job is started once: starting again (a replay) is refused, and
    // charges nothing.
    assert_eq!(g.start(&job).0, 409);
    assert_eq!(G::reserves(&g.scope_ledger(&sa)), 1);
    assert_eq!(G::reserves(&g.scope_ledger(&sb)), 1);
    // The owner reads the scope's totals; the entries only its auditors.
    let t =
        g.t.ok(&g.a.owner, "GET", &format!("/v1/privacy/scopes/{sa}"), None);
    assert_eq!(t["entries"], 1);
    assert!(t["spent"]["epsilon"].as_f64().unwrap() > 0.0, "{t}");
    let (st, _) = g.t.call(
        &g.a.owner,
        "GET",
        &format!("/v1/privacy/scopes/{sa}/ledger"),
        None,
    );
    assert_eq!(st, 200);
    let (st, _) = g.t.call(
        &g.min_admin,
        "GET",
        &format!("/v1/privacy/scopes/{sa}/ledger"),
        None,
    );
    assert_eq!(st, 404);
    let p = g.t.ok(
        &g.a.owner,
        "GET",
        &format!("/v1/privacy/populations/{}", g.a.population),
        None,
    );
    assert_eq!(p["entries"], 1);
    assert!(p["rho_cap"].as_f64().unwrap() > 0.0);
    assert_eq!(p["scopes"], json!([sa]));
}

#[test]
fn a_job_with_no_scope_cannot_spend() {
    let Some(g) = world() else { return };
    let (v, prog) = g.week("2027-w01", DP);
    // No scope allocated: the job fails when it is scheduled (at
    // submission), ENC2719, and nothing exists to charge.
    let (s, j) = g.job(&v, &prog, "k1");
    assert_eq!(s, 201, "{j}");
    let job = id(&j);
    assert_eq!(g.state(&job), "failed");
    assert_eq!(g.failure(&job), "ENC2719");
    assert_eq!(G::reserves(&g.pop_ledger(&g.a)), 0);
    // Only one region allocated a scope: the other source still has none.
    let _sa = g.scope(&g.a, "1.0", None);
    let (s, j) = g.job(&v, &prog, "k2");
    assert_eq!(s, 201, "{j}");
    assert_eq!(g.state(&id(&j)), "failed");
    assert_eq!(g.failure(&id(&j)), "ENC2719");
    // And nothing was reserved in the allocated one either: the job is
    // refused whole.
    assert_eq!(G::reserves(&g.pop_ledger(&g.a)), 0);
}

// --- isolation: nothing is inherited ----------------------------------------------------

#[test]
fn an_unrelated_project_does_not_spend_or_inherit_a_budget() {
    let Some(g) = world() else { return };
    // The first project has scopes, and spends.
    let (sa, sb) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v1, p1) = g.week("2027-w01", DP);
    let job1 = id(&g.job(&v1, &p1, "k1").1);
    assert_eq!(g.start(&job1).0, 200);
    let used = G::reserves(&g.scope_ledger(&sa));
    // Another project of the same organizations, over the same series, has
    // no scope: its job (properly authorized) cannot spend, and inherits
    // nothing of the first project's.
    let other = g.new_project("another-surveillance", PURPOSE);
    let (v2, p2) = g.week_in(&other, "2027-w02", DP, [None, None]);
    let (s, j) = g.job_in(&other, &v2, &p2, "k2");
    assert_eq!(s, 201, "{j}");
    let job2 = id(&j);
    assert_eq!(g.state(&job2), "failed");
    assert_eq!(g.failure(&job2), "ENC2719");
    assert_eq!(G::reserves(&g.scope_ledger(&sa)), used);
    assert_eq!(G::reserves(&g.pop_ledger(&g.a)), used);
    // Its job cannot name the first project's scope either: a scoped
    // reservation of a job of another project is refused.
    let (v3, p3) = g.week_in(&other, "2027-w03", DP, [None, None]);
    let (_, j) = g.job_in(&other, &v3, &p3, "k3");
    let job3 = id(&j);
    let svc = g.secagg_spender(&sa);
    let ev = serde_json::json!({"kind": "reserve", "event_id": "stolen", "policy_id": null,
        "execution_spec_id": null, "round_id": job3, "output": "counts",
        "mechanism": {"kind": "discrete_gaussian", "clip_norm": "1.0", "noise_multiplier": "40.0"},
        "sensitivity": 16388, "sigma2": 26_843_545_600u64, "vector_len": 4,
        "rng": "csprng",
        "scope": {"scope_id": sa, "population_id": g.a.population, "job_id": job3,
                  "max_sources_per_unit": 2, "linkage": "none"}});
    refused(
        g.t.call(
            &svc,
            "POST",
            &format!("/v1/privacy/scopes/{sa}/events"),
            Some(ev.clone()),
        ),
        "ENC2719",
    );
    // The first project's scopes still serve it.
    assert_eq!(G::reserves(&g.scope_ledger(&sb)), used);
    // A purpose with no scope: the same refusal (a scope is for one purpose).
    let (v4, p4) = g.week("2027-w04", DP);
    let (_, j) = g.job(&v4, &p4, "k4");
    assert_eq!(g.state(&id(&j)), "queued");
}

#[test]
fn a_new_version_does_not_reset_the_population_cap() {
    let Some(g) = world() else { return };
    let _ = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    // New versions of the series, week after week, under the same scopes:
    // the population carries the spending from version to version, and the
    // cap holds: the weeks after the budget is spent are refused.
    let mut started = 0;
    let mut denied = vec![];
    for week in 1..=8 {
        let (v, prog) = g.week(&format!("2027-w{week:02}"), DP);
        let (s, j) = g.job(&v, &prog, &format!("k{week}"));
        assert_eq!(s, 201, "{j}");
        let job = id(&j);
        if g.state(&job) == "queued" {
            assert_eq!(g.start(&job).0, 200, "week {week}");
            started += 1;
        } else {
            assert_eq!(g.state(&job), "failed", "week {week}");
            denied.push((week, g.failure(&job)));
        }
    }
    assert!(started >= 2, "{started}");
    assert!(!denied.is_empty(), "the cap never bit");
    assert!(denied.iter().all(|(_, c)| c == "ENC2201"), "{denied:?}");
    // Every week after the first denial was denied: a new version is no
    // new budget.
    assert_eq!(denied.first().unwrap().0, started + 1);
    assert_eq!(denied.len(), 8 - started);
    let pop = g.pop_ledger(&g.a);
    assert_eq!(G::reserves(&pop), started);
    assert!(
        pop.cost().unwrap().epsilon <= 1.0,
        "{}",
        pop.cost().unwrap().epsilon
    );
    // The population is what ran out, and a refused job reserved nothing.
    assert_eq!(G::reserves(&g.pop_ledger(&g.b)), started);
    // The asset's own (version) ledger can never be used instead: a series
    // with a population is charged through its scopes only.
    let own = g.t.ok(
        &g.a.owner,
        "POST",
        "/v1/assets",
        Some(json!({"organization": A, "kind": "dataset", "name": format!("{SERIES}@legacy"),
                    "series": SERIES, "version": "legacy", "digest": "e".repeat(64),
                    "privacy_budget": budget(3.0), "ir_policy": registered_dp(A, "1.0")["ir_policy"],
                    "release_class": "dp-aggregate-only",
                    "key_ref": {"broker": "region-a-broker", "provider": "openbao-transit",
                                "key_ref": "counts-legacy", "key_version": 1}})),
    );
    refused(
        g.t.call(
            &g.a.owner,
            "POST",
            &format!("/v1/privacy/{}/events", id(&own)),
            Some(reserve("legacy-1", 4_000_000_000)),
        ),
        "ENC2719",
    );
}

#[test]
fn the_population_cap_is_authoritative_over_over_allocated_scopes() {
    let Some(g) = world() else { return };
    // Two programs, each with its own scope of the whole epsilon: the
    // scopes add up to twice the population.
    let (v1, p1) = g.week("2027-w01", DP);
    let (v2, p2) = g.week("2027-w02", DP2);
    let (s1a, s1b) = (
        g.scope(&g.a, "1.0", Some(&program_id(&p1))),
        g.scope(&g.b, "1.0", Some(&program_id(&p1))),
    );
    let (s2a, s2b) = (
        g.scope(&g.a, "1.0", Some(&program_id(&p2))),
        g.scope(&g.b, "1.0", Some(&program_id(&p2))),
    );
    // The first program spends until its scope (or the population) says no.
    let mut n1 = 0;
    loop {
        let (_, j) = g.job(&v1, &p1, &format!("p1-{n1}"));
        let job = id(&j);
        if g.state(&job) != "queued" {
            assert_eq!(g.failure(&job), "ENC2201");
            break;
        }
        assert_eq!(g.start(&job).0, 200);
        n1 += 1;
        assert!(n1 < 20);
    }
    assert!(n1 >= 2, "{n1}");
    // The second program's scope has never been charged, yet the
    // population (authoritative) refuses it once the first used the
    // epsilon: its jobs fail with a population denial.
    assert_eq!(G::reserves(&g.scope_ledger(&s2a)), 0);
    let mut n2 = 0;
    let denied = loop {
        let (_, j) = g.job(&v2, &p2, &format!("p2-{n2}"));
        let job = id(&j);
        if g.state(&job) != "queued" {
            break job;
        }
        assert_eq!(g.start(&job).0, 200);
        n2 += 1;
        assert!(n2 < 20);
    };
    assert_eq!(g.failure(&denied), "ENC2201");
    // Whatever the scopes allow, the series never gave up more than its cap.
    for r in [&g.a, &g.b] {
        let pop = g.pop_ledger(r);
        assert!(
            pop.cost().unwrap().epsilon <= 1.0,
            "{}",
            pop.cost().unwrap().epsilon
        );
        assert_eq!(G::reserves(&pop), n1 + n2);
    }
    assert!(n1 + n2 <= 3 + 1, "{n1} {n2}");
    let in_scopes: usize = [&s1a, &s1b, &s2a, &s2b]
        .iter()
        .map(|s| G::reserves(&g.scope_ledger(s)))
        .sum();
    assert_eq!(
        in_scopes,
        2 * (n1 + n2),
        "each release is in exactly one scope per source"
    );
}

// --- the scoped spend route -------------------------------------------------------------

/// The reservation JSON of `scope`'s ledger entry for `job`, as a
/// coordinator reports it (possibly edited).
fn reported(g: &G, scope: &str, job: &str) -> Value {
    let v = g.scope_ledger(scope);
    let e = v
        .entries
        .iter()
        .find(|e| matches!(&e.event, encompute_privacy::PrivacyEvent::Reserve { scope: Some(r), .. } if r.job_id.as_deref() == Some(job)))
        .expect("the job's reservation");
    serde_json::to_value(&e.event).unwrap()
}

#[test]
fn scoped_spend_must_be_the_jobs_own_release() {
    let Some(g) = world() else { return };
    let (sa, _sb) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v, prog) = g.week("2027-w01", DP);
    let job = id(&g.job(&v, &prog, "k1").1);
    let svc = g.secagg_spender(&sa);
    let url = format!("/v1/privacy/scopes/{sa}/events");
    // Before the job runs, nobody reserves for it (not even an authorized
    // coordinator): the release belongs to a running job.
    let mut ev = serde_json::json!({"kind": "reserve", "event_id": "x", "policy_id": null,
        "execution_spec_id": null, "round_id": job, "output": "counts",
        "mechanism": {"kind": "discrete_gaussian", "clip_norm": "1.0", "noise_multiplier": "40.0"},
        "sensitivity": 16388, "sigma2": 26_843_545_600u64, "vector_len": 4, "rng": "csprng",
        "scope": {"scope_id": sa, "population_id": g.a.population, "job_id": job,
                  "max_sources_per_unit": 2, "linkage": "none"}});
    assert!(g.t.call(&svc, "POST", &url, Some(ev.clone())).0 >= 400);
    assert_eq!(G::reserves(&g.scope_ledger(&sa)), 0);
    assert_eq!(g.start(&job).0, 200);
    let ok = reported(&g, &sa, &job);
    // The coordinator reporting the very same release: acknowledged, charged
    // once (a duplicate delivery).
    let (s, r) = g.t.call(&svc, "POST", &url, Some(ok.clone()));
    assert_eq!((s, r["duplicate"].as_bool()), (200, Some(true)), "{r}");
    assert_eq!(G::reserves(&g.scope_ledger(&sa)), 1);
    // The same event ID with other contents: refused.
    let mut other = ok.clone();
    other["sensitivity"] = json!(16389);
    refused(g.t.call(&svc, "POST", &url, Some(other)), "ENC2604");
    // A reservation under-declaring the sources per unit (one, where the
    // program, undeclared, assumes both participants), or with another
    // sensitivity, noise or linkage, is not the job's release: refused
    // (ENC2721) and charges nothing, whether or not it names the same job.
    let tamper = |f: &dyn Fn(&mut Value)| {
        let mut e = ok.clone();
        e["event_id"] = json!("other-id");
        f(&mut e);
        e
    };
    let cases: Vec<(&str, Value)> = vec![
        (
            "sources per unit",
            tamper(&|e| e["scope"]["max_sources_per_unit"] = json!(1)),
        ),
        ("sensitivity", tamper(&|e| e["sensitivity"] = json!(8194))),
        ("noise", tamper(&|e| e["sigma2"] = json!(1_000_000u64))),
        (
            "linkage",
            tamper(&|e| e["scope"]["linkage"] = json!("hmac-sha256-v1")),
        ),
        (
            "layout",
            tamper(&|e| e["scope"]["layout_id"] = json!("ab".repeat(32))),
        ),
        (
            "mechanism",
            tamper(&|e| e["mechanism"]["noise_multiplier"] = json!("30.0")),
        ),
    ];
    for (what, e) in cases {
        let (s, r) = g.t.call(&svc, "POST", &url, Some(e));
        assert!(s >= 400, "{what}: {s} {r}");
        assert!(
            ["ENC2721", "ENC2719"].contains(&code(&r)),
            "{what}: {s} {r}"
        );
    }
    assert_eq!(G::reserves(&g.scope_ledger(&sa)), 1);
    assert_eq!(G::reserves(&g.pop_ledger(&g.a)), 1);
    // The commit of the open reservation: recorded in both ledgers.
    let id1 = ok["event_id"].as_str().unwrap();
    let commit = json!({"kind": "commit", "event_id": id1, "output_commitment": "cd".repeat(32)});
    let (s, r) = g.t.call(&svc, "POST", &url, Some(commit.clone()));
    assert_eq!(s, 200, "{r}");
    let (s, r) = g.t.call(&svc, "POST", &url, Some(commit));
    assert_eq!((s, r["duplicate"].as_bool()), (200, Some(true)), "{r}");
    assert_eq!(g.scope_ledger(&sa).entries.len(), 2);
    assert_eq!(g.pop_ledger(&g.a).entries.len(), 2);
    // A commit of something never reserved: refused.
    assert!(
        g.t.call(
            &svc,
            "POST",
            &url,
            Some(
                json!({"kind": "commit", "event_id": "never", "output_commitment": "cd".repeat(32)})
            ),
        )
        .0 >= 400
    );
    // Who may report: not another service, not another member's people, not
    // an auditor; the owner's data owners may.
    ev["event_id"] = json!("nobody");
    for who in [&g.dev, &g.b.owner, &g.a.auditor, &g.min_admin] {
        let (s, r) = g.t.call(who, "POST", &url, Some(commit_for(id1)));
        assert!((400..500).contains(&s), "{s} {r}");
    }
    // The ledgers verify, and the floors are where the entries are.
    for (key, v) in [
        (format!("scope:{sa}"), g.scope_ledger(&sa)),
        (format!("population:{}", g.a.population), g.pop_ledger(&g.a)),
    ] {
        v.verify().unwrap();
        let cp = v.checkpoint().unwrap();
        assert_eq!(floor(&g, &key), Some((cp.seq, cp.root)));
    }
}

fn commit_for(event: &str) -> Value {
    json!({"kind": "commit", "event_id": event, "output_commitment": "ef".repeat(32)})
}

#[test]
fn a_release_too_noisy_to_charge_is_refused() {
    let Some(g) = world() else { return };
    let _ = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    // Noise so large the release costs less than the floor of one
    // reservation: no honest release is that noisy (ENC2204).
    let (v, prog) = g.week(
        "2027-w01",
        "dp discrete_gaussian clip_norm 1.0 noise_multiplier 5000000.0",
    );
    let (s, j) = g.job(&v, &prog, "k1");
    assert_eq!(s, 201, "{j}");
    let job = id(&j);
    assert_eq!(g.state(&job), "failed");
    assert_eq!(g.failure(&job), "ENC2204");
    assert_eq!(G::reserves(&g.pop_ledger(&g.a)), 0);
}

// --- the owner's authorization pins the scope ------------------------------------------------

#[test]
fn an_owner_pins_the_scope_in_its_authorization() {
    let Some(g) = world() else { return };
    let (any_a, any_b) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let pid = "11".repeat(32);
    let pinned_a = g.scope(&g.a, "0.5", Some(&pid));
    // Region-a's authorization names the program-pinned scope, which does
    // not serve this program: refused (ENC2719), not silently served by
    // the general one.
    let (v, prog) = g.week_in(&g.main, "2027-w01", DP, [Some(&pinned_a), None]);
    let (_, j) = g.job(&v, &prog, "k1");
    let job = id(&j);
    assert_eq!(g.state(&job), "failed");
    assert_eq!(g.failure(&job), "ENC2719");
    // Naming the general scope is honoured; an owner pinning another
    // owner's scope is refused.
    let (v, prog) = g.week_in(&g.main, "2027-w02", DP, [Some(&any_a), Some(&any_b)]);
    let job = id(&g.job(&v, &prog, "k2").1);
    assert_eq!(g.state(&job), "queued");
    assert_eq!(g.start(&job).0, 200);
    assert_eq!(G::reserves(&g.scope_ledger(&any_a)), 1);
    assert_eq!(G::reserves(&g.scope_ledger(&pinned_a)), 0);
    let (v, prog) = g.week_in(&g.main, "2027-w03", DP, [Some(&any_b), None]);
    let job = id(&g.job(&v, &prog, "k3").1);
    assert_eq!(g.state(&job), "failed");
    assert_eq!(g.failure(&job), "ENC2719");
}

// --- authorization state at start ---------------------------------------------------------------

#[test]
fn a_revoked_authorization_reserves_nothing() {
    let Some(g) = world() else { return };
    let _ = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let va = g.version(&g.a, "2027-w01");
    let vb = g.version(&g.b, "2027-w01");
    let prog = program([&va.0, &vb.0], DP);
    let row_a = g.authorize_in(&g.main, &g.a, &va, &[&prog], None);
    g.authorize_in(&g.main, &g.b, &vb, &[&prog], None);
    let (_, j) = g.job(&[va, vb], &prog, "k1");
    let job = id(&j);
    assert_eq!(g.state(&job), "queued");
    // Region-a withdraws its authorization before the job starts: the job
    // fails, and starting it reserves nothing.
    g.t.ok(
        &g.a.sec1,
        "POST",
        &format!("/v1/authorizations/{row_a}/revoke"),
        Some(json!({"reason": "withdrawn-before-the-week-ran"})),
    );
    assert_eq!(g.state(&job), "failed");
    assert!(g.start(&job).0 >= 400);
    for r in [&g.a, &g.b] {
        assert_eq!(G::reserves(&g.pop_ledger(r)), 0);
    }
    let mut c = g.t.control.db.conn().unwrap();
    let rows: i64 = c
        .query_one("SELECT count(*) FROM job_privacy_reservations", &[])
        .unwrap()
        .get(0);
    assert_eq!(rows, 0);
}

// --- concurrency: across scopes, threads and control planes ---------------------------------

#[test]
fn concurrent_starts_never_exceed_the_population() {
    let Some(g) = world() else { return };
    // Noisier than the others' programs this much costs a unit of the
    // population about two releases, so two of four jobs cannot start.
    let (v1, p1) = g.week(
        "2027-w01",
        "dp discrete_gaussian clip_norm 1.0 noise_multiplier 30.0",
    );
    let (v2, p2) = g.week(
        "2027-w02",
        "dp discrete_gaussian clip_norm 1.0 noise_multiplier 31.0",
    );
    // Two scopes per region, each with the whole epsilon.
    for p in [&p1, &p2] {
        let _ = (
            g.scope(&g.a, "1.0", Some(&program_id(p))),
            g.scope(&g.b, "1.0", Some(&program_id(p))),
        );
    }
    // Four jobs, each affordable alone (so each passes its scheduling
    // check): two of each program, hence of each scope.
    let mut jobs = vec![];
    for (i, (v, p)) in [(&v1, &p1), (&v1, &p1), (&v2, &p2), (&v2, &p2)]
        .into_iter()
        .enumerate()
    {
        let (s, j) = g.job(v, p, &format!("k{i}"));
        assert_eq!(s, 201, "{j}");
        assert_eq!(g.state(&id(&j)), "queued", "{j}");
        jobs.push(id(&j));
    }
    // They start at once: threads of this control plane, and a second one
    // (another process) on the same database.
    let other = g.t.env0.started();
    let results: Vec<(u16, Value)> = std::thread::scope(|sc| {
        let hs: Vec<_> = jobs
            .iter()
            .enumerate()
            .map(|(i, job)| {
                let (g, other) = (&g, &other);
                sc.spawn(move || {
                    let t = if i % 2 == 0 { &g.t } else { other };
                    t.call(
                        &g.evaluator.service,
                        "POST",
                        &format!("/v1/jobs/{job}/start"),
                        None,
                    )
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let started = results.iter().filter(|(s, _)| *s == 200).count();
    let refused = results.iter().filter(|(s, _)| *s >= 400).count();
    assert_eq!(started + refused, 4, "{results:?}");
    assert!((1..4).contains(&started), "{results:?}");
    // However the starts interleaved, the series never gave up more than
    // its cap: each population holds exactly the started jobs' releases,
    // verifies, and fits.
    for r in [&g.a, &g.b] {
        let pop = g.pop_ledger(r);
        pop.verify().unwrap();
        assert_eq!(G::reserves(&pop), started, "{results:?}");
        assert!(pop.cost().unwrap().epsilon <= 1.0);
    }
    // The ones refused failed on the cap (the control plane that lost the
    // race saw the winner's reservation), not by chance.
    for (job, (s, r)) in jobs.iter().zip(&results) {
        if *s >= 400 {
            assert_eq!(code(r), "ENC2201", "{r}");
            assert_eq!(g.state(job), "failed");
        } else {
            assert_eq!(g.state(job), "running");
        }
    }
    // Both control planes agree on the floors: the log holds the latest
    // checkpoint of each ledger, which the ledger extends.
    for r in [&g.a, &g.b] {
        let key = format!("population:{}", r.population);
        let cp = g.pop_ledger(r).checkpoint().unwrap();
        assert_eq!(floor(&g, &key), Some((cp.seq, cp.root)));
    }
}

// --- concurrency: a start that loses the anchor's compare-and-set --------------------------
//
// A start commits its decision in one transaction under row locks (the cap
// is enforced there, whatever happens to the anchor) and anchors it after
// the commit. Another control plane may store the anchor first: the
// anchoring is then attempted again from the stored anchor, and the caller
// gets the decision (a refusal on the cap is ENC2201, not an anchor
// conflict). The tests move the stored anchor on at the compare-and-set
// (`CasHook`), exactly where two control planes would collide.

/// The population affords one release of this program, so two jobs
/// scheduled before either starts cannot both start.
const FIT_ONE: &str = "dp discrete_gaussian clip_norm 1.0 noise_multiplier 25.0";

/// Two queued jobs of `FIT_ONE`, in the region populations' common scope.
fn two_jobs_for_one_release(g: &G) -> (String, String) {
    let jobs = queued_jobs_for_one_release(g, 2);
    (jobs[0].clone(), jobs[1].clone())
}

/// `n` queued jobs of `FIT_ONE`.
fn queued_jobs_for_one_release(g: &G, n: usize) -> Vec<String> {
    let _ = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v, prog) = g.week("2027-w01", FIT_ONE);
    (0..n)
        .map(|i| {
            let (s, j) = g.job(&v, &prog, &format!("k{i}"));
            assert_eq!(s, 201, "{j}");
            assert_eq!(g.state(&id(&j)), "queued", "{j}");
            id(&j)
        })
        .collect()
}

fn start_on(t: &T, evaluator: &As, job: &str) -> (u16, Value) {
    t.call(evaluator, "POST", &format!("/v1/jobs/{job}/start"), None)
}

/// A counter of a control plane's `/metrics` exposition.
fn counter(t: &T, name: &str) -> u64 {
    let prefix = format!("{name}{{label=\"all\"}} ");
    t.control
        .render_metrics()
        .lines()
        .find_map(|l| l.strip_prefix(&prefix).map(|v| v.parse().unwrap()))
        .unwrap_or(0)
}

const RETRIES: &str = "encompute_anchor_cas_retry_total";
const EXHAUSTED: &str = "encompute_anchor_cas_retry_exhausted_total";

/// However the starts went, exactly `running` jobs reserved, in every
/// ledger, the population verifies and fits, and no job is left half
/// reserved: a job that is running holds its reservations in both regions,
/// any other holds none.
fn cap_held(g: &G, jobs: &[String], running: usize) {
    let states: Vec<String> = jobs.iter().map(|j| g.state(j)).collect();
    assert_eq!(
        states.iter().filter(|s| *s == "running").count(),
        running,
        "{states:?}"
    );
    for r in [&g.a, &g.b] {
        let pop = g.pop_ledger(r);
        pop.verify().unwrap();
        assert_eq!(G::reserves(&pop), running, "{states:?}");
        assert!(pop.cost().unwrap().epsilon <= 1.0);
    }
    let mut c = g.t.control.db.conn().unwrap();
    for (job, state) in jobs.iter().zip(&states) {
        let rows: i64 = c
            .query_one(
                "SELECT count(*) FROM job_privacy_reservations WHERE job_id = $1",
                &[job],
            )
            .unwrap()
            .get(0);
        assert_eq!(
            rows,
            if state == "running" { 2 } else { 0 },
            "{job} {state}"
        );
    }
}

#[test]
fn a_refusal_that_loses_the_anchor_race_is_anchored_again_and_returned_as_it_is() {
    let Some(g) = world() else { return };
    let (j1, j2) = two_jobs_for_one_release(&g);
    let (h, cas) = g.t.env0.start_cas_hook();
    let ev = &g.evaluator.service;
    // The first start reserves the one release the population affords.
    assert_eq!(start_on(&g.t, ev, &j1).0, 200);
    // The second is refused on the cap, and committed as failed; while it
    // anchors that, another control plane's update lands first, so its
    // compare-and-set loses once.
    cas.arm(1);
    let r = start_on(&h, ev, &j2);
    let seen = cas.seen();
    cas.disarm();
    // The caller gets the refusal (not the anchor conflict), after the
    // anchoring was attempted again and stored.
    refused(r, "ENC2201");
    assert_eq!(seen, 2, "lost once, stored by the retry");
    assert_eq!(counter(&h, RETRIES), 1);
    assert_eq!(counter(&h, EXHAUSTED), 0);
    assert_eq!(g.state(&j2), "failed");
    assert!(
        anchored(&h, NegSet::EndedJobs, &j2),
        "the refusal is anchored"
    );
    // The retry anchored what was committed: nothing was written again.
    assert_eq!(refusal_events(&g, &j2), (1, 1));
    cap_held(&g, &[j1, j2], 1);
}

/// The governance log's head and the audit chain's, as the database holds
/// them: (gseq, hash, audit seq, audit hash).
fn heads(g: &G) -> (i64, String, i64, String) {
    let mut c = g.t.control.db.conn().unwrap();
    let l = c
        .query_one("SELECT gseq, hash FROM governance_head WHERE id", &[])
        .unwrap();
    let a = c
        .query_one("SELECT seq, hash FROM audit_head WHERE id", &[])
        .unwrap();
    (l.get(0), l.get(1), a.get(0), a.get(1))
}

/// Events a job's refusal wrote, which a retry of its anchoring must not
/// write again: its failure in the audit chain and its ending in the log.
fn refusal_events(g: &G, job: &str) -> (i64, i64) {
    let mut c = g.t.control.db.conn().unwrap();
    let failed = c
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'job.failed' AND resource_id = $1",
            &[&job],
        )
        .unwrap()
        .get(0);
    let ended = c
        .query_one(
            "SELECT count(*) FROM governance_events WHERE subject_id = $1",
            &[&job],
        )
        .unwrap()
        .get(0);
    (failed, ended)
}

/// A checkpoint another control plane stored while this one lost its
/// compare-and-set covers a refusal only if the anchor holds it: the log
/// head at or past the head right after the refusal committed, the audit
/// chain at or past the refusal's audit events, and both the database's own
/// chains. Then there is nothing to store (and nothing more is published);
/// events added later by other writers do not matter.
#[test]
fn a_refusal_another_control_plane_anchored_exactly_is_not_stored_again() {
    let Some(g) = world() else { return };
    let jobs = queued_jobs_for_one_release(&g, 3);
    let (h, cas) = g.t.env0.start_cas_hook();
    let other = std::sync::Arc::new(g.t.env0.started());
    let ev = &g.evaluator.service;
    assert_eq!(start_on(&g.t, ev, &jobs[0]).0, 200);
    let dir = g.t.env0.anchor_dir.clone();

    // 1. The rival checkpoints the log (the refusal and the audit head with
    //    it) before the loser's retry: nothing is left to store, and the
    //    loser publishes nothing more.
    let after_rival = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    cas.set_rival(std::sync::Arc::new({
        let (other, dir, after_rival) = (other.clone(), dir.clone(), after_rival.clone());
        move || {
            other.control.checkpoint_log().unwrap();
            after_rival.store(stored_counter(&dir), Ordering::SeqCst);
        }
    }));
    cas.arm(1);
    let r = start_on(&h, ev, &jobs[1]);
    let seen = cas.seen();
    cas.disarm();
    refused(r, "ENC2201");
    assert_eq!(seen, 1, "the lost compare-and-set was the only one");
    assert_eq!(
        stored_counter(&dir),
        after_rival.load(Ordering::SeqCst),
        "nothing published after the rival's checkpoint"
    );
    assert_eq!((counter(&h, RETRIES), counter(&h, EXHAUSTED)), (1, 0));
    assert!(anchored(&h, NegSet::EndedJobs, &jobs[1]));
    assert_eq!(refusal_events(&g, &jobs[1]), (1, 1), "written once");

    // 2. The rival checkpoints the log, then the audit chain grows (a
    //    denial recorded): the new audit event is not the refusal's, the
    //    anchor holds what the refusal committed, so there is still nothing
    //    to store.
    cas.set_rival(std::sync::Arc::new({
        let other = other.clone();
        move || {
            other.control.checkpoint_log().unwrap();
            other
                .control
                .audit_denied(encompute_control::audit::AuditDraft::new(
                    "a-service",
                    "req-rival",
                    "job.start",
                    "job",
                    "none",
                    encompute_control::audit::Outcome::Denied,
                ));
        }
    }));
    cas.arm(1);
    let r = start_on(&h, ev, &jobs[2]);
    let seen = cas.seen();
    cas.disarm();
    refused(r, "ENC2201");
    assert_eq!(
        seen, 1,
        "covered: the later audit event is not this refusal's"
    );
    assert!(anchored(&h, NegSet::EndedJobs, &jobs[2]));
    cap_held(&g, &jobs, 1);
}

/// A newer anchor does not cover a deny because it is newer. Two anchors
/// that do not: one a rival stored before the deny committed (older than it),
/// and one that holds the log up to the deny but not its audit events. The
/// retry anchors the deny itself. (A job's cancellation: a deny event
/// anchored by `tx_anchored` alone; a start also checks its refusal is
/// anchored, which would hide a wrong cover.)
#[test]
fn a_newer_anchor_that_does_not_hold_the_deny_covers_nothing() {
    let Some(g) = world() else { return };
    let jobs = queued_jobs_for_one_release(&g, 2);
    let (h, cas) = g.t.env0.start_cas_hook();
    let other = g.t.env0.started();
    let (dir, seed) = (g.t.env0.anchor_dir.clone(), g.t.env0.seed);
    let cancel = |job: &str| h.ok(&g.dev, "POST", &format!("/v1/jobs/{job}/cancel"), None);

    // (a) The rival's checkpoint is computed before the cancellation commits
    //     (an anchor newer than the loser's view, older than the deny): it
    //     does not cover it; the loser stores.
    other.control.checkpoint_log().unwrap();
    cas.arm(1);
    cancel(&jobs[0]);
    let seen = cas.seen();
    cas.disarm();
    assert_eq!(seen, 2, "not covered: stored by the retry");
    assert!(anchored(&h, NegSet::EndedJobs, &jobs[0]));

    // (b) The rival anchors the log's head as the cancellation left it but not
    //     the audit chain: the audit events of the deny are not held; the
    //     loser stores.
    cas.set_rival(std::sync::Arc::new({
        let (dir, db) = (dir.clone(), g.t.env0.url.clone());
        move || {
            let mut c = postgres::Client::connect(&db, postgres::NoTls).unwrap();
            let l = c
                .query_one("SELECT gseq, hash FROM governance_head WHERE id", &[])
                .unwrap();
            set_anchored_log(&dir, &seed, l.get(0), &l.get::<_, String>(1));
        }
    }));
    cas.arm(1);
    cancel(&jobs[1]);
    let seen = cas.seen();
    cas.disarm();
    assert_eq!(seen, 2, "the log is held, its audit events are not: stored");
    assert!(anchored(&h, NegSet::EndedJobs, &jobs[1]));
    let (_, _, audit_seq, _) = heads(&g);
    let stored = encompute_control::anchor::Anchor::open(
        Box::new(encompute_control::anchor::DirAnchor::new(dir.clone()).unwrap()),
        &encompute_verification::ServiceSigner::from_seed("control-plane", &seed).unwrap(),
    )
    .unwrap()
    .0
    .snapshot();
    assert!(
        stored.audit_seq >= audit_seq,
        "{} < {audit_seq}",
        stored.audit_seq
    );
}

/// An anchor at the right position that is not the database's chain (a head
/// the log does not hold, an audit root the chain does not hold) covers
/// nothing: the checkpoint finds the chain does not hold the anchored head
/// and refuses it as the rollback it is, returned at once (not retried, not
/// success), whatever position the anchor claims.
#[test]
fn an_anchor_that_is_not_the_databases_chain_covers_nothing() {
    let Some(g) = world() else { return };
    let jobs = queued_jobs_for_one_release(&g, 3);
    let (h, cas) = g.t.env0.start_cas_hook();
    let other = std::sync::Arc::new(g.t.env0.started());
    let ev = &g.evaluator.service;
    assert_eq!(start_on(&g.t, ev, &jobs[0]).0, 200);
    let (dir, seed) = (g.t.env0.anchor_dir.clone(), g.t.env0.seed);

    // The log head: the rival's checkpoint holds everything (positions
    // reached), then its head is replaced by one the log does not hold.
    cas.set_rival(std::sync::Arc::new({
        let (other, dir) = (other.clone(), dir.clone());
        move || {
            other.control.checkpoint_log().unwrap();
            update_anchor(&dir, &seed, |x| x.glog_head = "ab".repeat(32));
        }
    }));
    cas.arm(1);
    let (status, body) = start_on(&h, ev, &jobs[1]);
    let seen = cas.seen();
    cas.disarm();
    assert!(status >= 400, "{body}");
    assert_eq!(code(&body), "ENC2202", "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("GOVERNANCE LOG STATE ROLLBACK"),
        "{body}"
    );
    assert_eq!(seen, 1, "the retry never reached a store");
    assert_eq!(g.state(&jobs[1]), "failed", "the committed refusal stands");
    // (The lost compare-and-set before it was retried once; the rollback
    // refusal was not.)
    assert_eq!((counter(&h, RETRIES), counter(&h, EXHAUSTED)), (1, 0));
}

#[test]
fn an_audit_root_the_chain_does_not_hold_covers_nothing() {
    let Some(g) = world() else { return };
    let jobs = queued_jobs_for_one_release(&g, 2);
    let (h, cas) = g.t.env0.start_cas_hook();
    let other = std::sync::Arc::new(g.t.env0.started());
    let ev = &g.evaluator.service;
    assert_eq!(start_on(&g.t, ev, &jobs[0]).0, 200);
    let (dir, seed) = (g.t.env0.anchor_dir.clone(), g.t.env0.seed);
    cas.set_rival(std::sync::Arc::new({
        let (other, dir) = (other.clone(), dir.clone());
        move || {
            other.control.checkpoint_log().unwrap();
            update_anchor(&dir, &seed, |x| x.audit_root = "cd".repeat(32));
        }
    }));
    cas.arm(1);
    let (status, body) = start_on(&h, ev, &jobs[1]);
    let seen = cas.seen();
    cas.disarm();
    assert!(status >= 400, "{body}");
    assert_eq!(code(&body), "ENC2202", "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("AUDIT STATE ROLLBACK"),
        "{body}"
    );
    assert_eq!(seen, 1);
    assert_eq!(g.state(&jobs[1]), "failed");
    assert_eq!((counter(&h, RETRIES), counter(&h, EXHAUSTED)), (1, 0));
}

/// The real failure: another control plane keeps winning the anchor's
/// compare-and-set (it is busy writing events and checkpointing), and its
/// checkpoints hold this start's refusal. Anchoring the log up to its
/// current head chases a head that moves under every attempt and never
/// catches up; the refusal needs the anchor to hold its own event, which
/// it already does after the first lost compare-and-set.
#[test]
fn a_refusal_a_busy_rival_anchors_is_not_starved_by_the_rival() {
    let Some(g) = world() else { return };
    let (j1, j2) = two_jobs_for_one_release(&g);
    let (h, cas) = g.t.env0.start_cas_hook();
    let other = std::sync::Arc::new(g.t.env0.started());
    let ev = &g.evaluator.service;
    assert_eq!(start_on(&g.t, ev, &j1).0, 200);
    let (dir, seed) = (g.t.env0.anchor_dir.clone(), g.t.env0.seed);
    // Before every compare-and-set of the loser, the rival checkpoints the
    // log (the refusal in it), writes a newer event of its own and moves
    // the anchor on once more.
    let rival = {
        let other = other.clone();
        let n = std::sync::atomic::AtomicUsize::new(0);
        move || {
            other.control.checkpoint_log().unwrap();
            let (other, i) = (other.clone(), n.fetch_add(1, Ordering::SeqCst));
            // (On a thread of its own: another process's.)
            std::thread::spawn(move || {
                other
                    .control
                    .db
                    .tx(|t| {
                        encompute_control::govlog::append(
                            t,
                            encompute_control::govlog::Draft::new(
                                encompute_trust::govlog::Partition::Platform,
                                encompute_control::govlog::kind::ROLE_REMOVED,
                                &format!("rival_subject_{i}"),
                            ),
                        )
                        .map(|_| ())
                    })
                    .unwrap();
            })
            .join()
            .unwrap();
            move_anchor(&dir, &seed);
        }
    };
    let rival = std::sync::Arc::new(rival);
    cas.set_rival_always(rival);
    cas.arm(u32::MAX);
    let r = start_on(&h, ev, &j2);
    let seen = cas.seen();
    cas.disarm();
    refused(r, "ENC2201");
    assert_eq!(seen, 1, "the retry found the refusal anchored");
    assert_eq!((counter(&h, RETRIES), counter(&h, EXHAUSTED)), (1, 0));
    assert!(anchored(&h, NegSet::EndedJobs, &j2));
    cap_held(&g, &[j1, j2], 1);
}

#[test]
fn two_starts_meeting_at_the_anchor_reserve_once_and_both_get_their_answer() {
    let Some(g) = world() else { return };
    let (j1, j2) = two_jobs_for_one_release(&g);
    let (h, cas) = g.t.env0.start_cas_hook();
    let other = std::sync::Arc::new(g.t.env0.started());
    let ev = g.evaluator.service.clone();
    // The first start commits its reservation; at its compare-and-set,
    // the second start (another control plane) runs through: it finds the
    // reservation (row locks), is refused on the cap and anchors its
    // refusal, which moves the anchor under the first.
    let second: std::sync::Arc<std::sync::Mutex<Option<(u16, Value)>>> = Default::default();
    cas.set_rival(std::sync::Arc::new({
        let (other, ev, second, j2) = (other.clone(), ev.clone(), second.clone(), j2.clone());
        move || {
            *second.lock().unwrap() = Some(start_on(&other, &ev, &j2));
        }
    }));
    cas.arm(1);
    let first = start_on(&h, &ev, &j1);
    cas.disarm();
    assert_eq!(first.0, 200, "{}", first.1);
    refused(
        second.lock().unwrap().take().expect("the rival ran"),
        "ENC2201",
    );
    // The first lost the compare-and-set once and anchored again; the
    // refusal it met was not its to retry.
    assert_eq!(counter(&h, RETRIES), 1);
    assert_eq!(counter(&h, EXHAUSTED), 0);
    assert_eq!(counter(&other, RETRIES), 0);
    assert!(anchored(&other, NegSet::EndedJobs, &j2));
    // The reservation of the first is anchored too: the floors hold both
    // ledgers' latest checkpoints.
    cap_held(&g, &[j1, j2], 1);
    for r in [&g.a, &g.b] {
        let key = format!("population:{}", r.population);
        let cp = g.pop_ledger(r).checkpoint().unwrap();
        assert_eq!(floor(&g, &key), Some((cp.seq, cp.root)));
    }
}

#[test]
fn an_anchor_that_never_settles_refuses_after_the_bound_and_leaves_the_refusal_to_anchor() {
    let Some(g) = world() else { return };
    let jobs = queued_jobs_for_one_release(&g, 3);
    let (j1, j2, j3) = (jobs[0].clone(), jobs[1].clone(), jobs[2].clone());
    let (h, cas) = g.t.env0.start_cas_hook();
    let ev = &g.evaluator.service;
    assert_eq!(start_on(&g.t, ev, &j1).0, 200);
    // Every compare-and-set of the second start loses.
    cas.arm(u32::MAX);
    let (status, body) = start_on(&h, ev, &j2);
    let seen = cas.seen();
    cas.disarm();
    assert!(status >= 400, "{body}");
    // ENC2202 as before, the anchor conflict (not a rollback refusal),
    // after exactly the bound of attempts: no more, no loop.
    assert_eq!(code(&body), "ENC2202", "{body}");
    let message = body["message"].as_str().unwrap();
    assert!(message.contains("changed concurrently"), "{body}");
    assert!(!message.contains("STATE ROLLBACK"), "{body}");
    assert_eq!(seen, encompute_control::anchor::ANCHOR_CAS_ATTEMPTS);
    assert_eq!(counter(&h, RETRIES), u64::from(seen) - 1);
    assert_eq!(counter(&h, EXHAUSTED), 1);
    // What the start committed stands, as it always did (a refusal on the
    // cap: failed, nothing reserved, written once), and is not anchored yet;
    // the obligation stays on this thread, so the next anchored call
    // settles it.
    assert_eq!(g.state(&j2), "failed");
    assert!(!anchored(&h, NegSet::EndedJobs, &j2));
    assert_eq!(refusal_events(&g, &j2), (1, 1));
    assert!(encompute_control::govlog::RETRY_CHECKPOINT.with(|d| d.get()));
    cap_held(&g, &jobs, 1);
    // The next anchored call on the thread (another refused start)
    // anchors both.
    refused(start_on(&h, ev, &j3), "ENC2201");
    assert!(!encompute_control::govlog::RETRY_CHECKPOINT.with(|d| d.get()));
    assert!(anchored(&h, NegSet::EndedJobs, &j2));
    assert!(anchored(&h, NegSet::EndedJobs, &j3));
    assert_eq!(counter(&h, EXHAUSTED), 1);
}

/// A start whose retried anchoring then fails (the anchor store went away
/// after the lost compare-and-set) has committed its reservation: the
/// evaluator's retry of the start anchors it and is acknowledged, reserving
/// nothing twice (the crash window between the commit and the anchoring, on
/// the retry path).
#[test]
fn a_start_whose_retried_anchoring_failed_is_finished_by_the_evaluators_retry() {
    let Some(g) = world() else { return };
    let (j1, j2) = two_jobs_for_one_release(&g);
    let (h, cas) = g.t.env0.start_cas_hook();
    let ev = &g.evaluator.service;
    // The first attempt loses the compare-and-set, the retry finds the
    // store unavailable.
    cas.arm(1);
    cas.fail_on(2);
    let (status, body) = start_on(&h, ev, &j1);
    cas.disarm();
    assert!(status >= 400, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("unavailable"),
        "{body}"
    );
    // Committed (running, its reservations in both regions), not anchored.
    assert_eq!(g.state(&j1), "running");
    cap_held(&g, &[j1.clone(), j2], 1);
    // The evaluator's retry anchors it and is acknowledged.
    let again = start_on(&h, ev, &j1);
    assert_eq!(again.0, 200, "{}", again.1);
    for r in [&g.a, &g.b] {
        let key = format!("population:{}", r.population);
        let cp = g.pop_ledger(r).checkpoint().unwrap();
        assert_eq!(floor(&g, &key), Some((cp.seq, cp.root)));
    }
}

#[test]
fn many_concurrent_starts_across_two_control_planes_reserve_exactly_what_fits() {
    let Some(g) = world() else { return };
    let _ = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    // Eight jobs of one program, scheduled before any starts; the
    // population affords four of them (a fifth would pass its cap).
    let second = evaluator(
        &g.t,
        &g.platform,
        "evaluator-2",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    let (v, prog) = g.week("2027-w01", DP);
    let mut jobs = vec![];
    for i in 0..8 {
        let (s, j) = g.job(&v, &prog, &format!("k{i}"));
        assert_eq!(s, 201, "{j}");
        assert_eq!(g.state(&id(&j)), "queued", "{j}");
        jobs.push(id(&j));
    }
    let evaluators = [&g.evaluator, &second];
    let who: Vec<&As> = jobs
        .iter()
        .map(|job| {
            let mut c = g.t.control.db.conn().unwrap();
            let e: String = c
                .query_one("SELECT evaluator_id FROM jobs WHERE id = $1", &[job])
                .unwrap()
                .get(0);
            &evaluators.iter().find(|x| x.id == e).unwrap().service
        })
        .collect();
    let (h, _) = g.t.env0.start_cas_hook();
    let barrier = std::sync::Barrier::new(jobs.len());
    let results: Vec<(u16, Value)> = std::thread::scope(|sc| {
        let hs: Vec<_> = jobs
            .iter()
            .enumerate()
            .map(|(i, job)| {
                let (g, h, who, barrier) = (&g, &h, &who, &barrier);
                sc.spawn(move || {
                    let t = if i % 2 == 0 { &g.t } else { h };
                    barrier.wait();
                    start_on(t, who[i], job)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    // Exactly what fits reserved, whatever the callers were told.
    let exhausted = counter(&g.t, EXHAUSTED) + counter(&h, EXHAUSTED);
    let retries = counter(&g.t, RETRIES) + counter(&h, RETRIES);
    let started = results.iter().filter(|(s, _)| *s == 200).count();
    let cap = results.iter().filter(|(_, r)| code(r) == "ENC2201").count();
    let unsettled = results.iter().filter(|(_, r)| code(r) == "ENC2202").count();
    eprintln!("many starts: started {started}, refused on the cap {cap}, anchor unsettled {unsettled} (exhausted {exhausted}), anchor retries {retries}");
    assert_eq!(started + cap + unsettled, 8, "{results:?}");
    // An unsettled answer is only ever the exhausted bound, counted.
    assert!(unsettled as u64 <= exhausted, "{results:?}");
    cap_held(&g, &jobs, 4);
    // Each refused job was refused on the cap, committed as failed.
    for (job, (s, r)) in jobs.iter().zip(&results) {
        if *s >= 400 && code(r) == "ENC2201" {
            assert_eq!(g.state(job), "failed", "{r}");
        }
    }
}

// --- rollback: restored ledgers ride the governance log -------------------------------------

#[test]
fn restored_scope_is_frozen() {
    let Some(g) = world() else { return };
    let (sa, sb) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v, prog) = g.week("2027-w01", DP);
    let job1 = id(&g.job(&v, &prog, "k1").1);
    assert_eq!(g.start(&job1).0, 200);
    let (v2, prog2) = g.week("2027-w02", DP);
    let job2 = id(&g.job(&v2, &prog2, "k2").1);
    assert_eq!(g.state(&job2), "queued");
    // The database is rewound for the scope's ledger alone (its second
    // reservation, which the job below makes, is "forgotten"): first the
    // job reserves, then the entry disappears.
    assert_eq!(g.start(&job2).0, 200);
    let key = format!("scope:{sa}");
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    c.execute(
        "DELETE FROM privacy_entries WHERE asset_id = $1 AND seq > 1",
        &[&key],
    )
    .unwrap();
    drop(c);
    // A job that starts now is refused (the scope no longer extends its
    // checkpoint in the log): PRIVACY STATE ROLLBACK, ENC2202, and nothing
    // is written or anchored for it.
    let (v3, prog3) = g.week("2027-w03", DP);
    let (_, j) = g.job(&v3, &prog3, "k3");
    let job3 = id(&j);
    // Scheduling already refused it (the check reads the same floors).
    assert_eq!(g.state(&job3), "failed");
    assert_eq!(g.failure(&job3), "ENC2202");
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM privacy_entries WHERE asset_id = $1",
            &[&key],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1, "nothing was appended to the rolled-back scope");
    drop(c);
    // A coordinator's report to the rolled-back scope is refused too.
    let svc = g.secagg_spender(&sa);
    let (s, r) = g.t.call(
        &svc,
        "POST",
        &format!("/v1/privacy/scopes/{sa}/events"),
        Some(commit_for(
            reported(&g, &sa, &job1)["event_id"].as_str().unwrap(),
        )),
    );
    assert_eq!((s, code(&r)), (500, "ENC2202"), "{r}");
    // The next start refuses the database.
    let G { t, a, b, .. } = g;
    let e = t.restart().err().expect("a rolled-back scope started");
    assert!(e.message.contains("PRIVACY STATE ROLLBACK"), "{e}");
    assert!(e.message.contains(&key), "{e}");
    let _ = (a, b, sb);
}

#[test]
fn restored_population_is_refused_and_recovery_freezes_it() {
    let Some(g) = world() else { return };
    let _ = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v, prog) = g.week("2027-w01", DP);
    let job1 = id(&g.job(&v, &prog, "k1").1);
    assert_eq!(g.start(&job1).0, 200);
    let pkey = format!("population:{}", g.a.population);
    // The population's ledger is reset (its spending forgotten).
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    c.execute("DELETE FROM privacy_entries WHERE asset_id = $1", &[&pkey])
        .unwrap();
    drop(c);
    let (v2, prog2) = g.week("2027-w02", DP);
    let (_, j) = g.job(&v2, &prog2, "k2");
    assert_eq!(g.state(&id(&j)), "failed");
    assert_eq!(g.failure(&id(&j)), "ENC2202");
    let G { t, a, b, .. } = g;
    let env0 = &t.env0;
    let e = env0.start().err().expect("a reset population started");
    assert!(
        e.message.contains("PRIVACY STATE ROLLBACK") && e.message.contains(&pkey),
        "{e}"
    );
    // Explicit recovery freezes the ledger at where the database holds it: it
    // is treated as exhausted, so what was forgotten is never reused.
    let notes = run_recovery(env0);
    assert!(notes.iter().any(|n| n.contains(&pkey)), "{notes:?}");
    let t2 = env0.started();
    let mut c = postgres::Client::connect(&env0.url, postgres::NoTls).unwrap();
    let frozen: Option<String> = c
        .query_one(
            "SELECT frozen_reason FROM privacy_ledgers WHERE asset_id = $1",
            &[&pkey],
        )
        .unwrap()
        .get(0);
    assert!(frozen.is_some());
    let _ = (t2, a, b);
}

// --- views -------------------------------------------------------------------------------------

#[test]
fn scope_views_do_not_cross_organizations() {
    let Some(g) = world() else { return };
    let (sa, sb) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v, prog) = g.week("2027-w01", DP);
    let job = id(&g.job(&v, &prog, "k1").1);
    assert_eq!(g.start(&job).0, 200);
    // A stranger organization and a member's auditor.
    g.t.ok(
        &g.platform,
        "POST",
        "/v1/organizations",
        Some(json!({"id": "stranger-co", "display_name": "x",
                    "admin": {"issuer": DEV_ISSUER, "subject": "stranger-admin"}})),
    );
    let stranger = As::User("stranger-admin".into());
    // Region-a's private strings: its population, and the entries of its
    // ledgers (event IDs, hashes).
    let la = g.scope_ledger(&sa);
    let mut canaries: Vec<String> = vec![g.a.population.clone()];
    // (The ledger's root, the last hash, is what a checkpoint reveals.)
    for (i, e) in la.entries.iter().enumerate() {
        if i + 1 < la.entries.len() {
            canaries.push(e.hash.clone());
        }
        canaries.push(e.event.event_id().to_owned());
    }
    // Region-b's, from the others' side.
    let lb = g.scope_ledger(&sb);
    let mut b_canaries: Vec<String> = vec![g.b.population.clone()];
    for (i, e) in lb.entries.iter().enumerate() {
        if i + 1 < lb.entries.len() {
            b_canaries.push(e.hash.clone());
        }
        b_canaries.push(e.event.event_id().to_owned());
    }
    let urls = [
        format!("/v1/privacy/scopes/{sa}"),
        format!("/v1/privacy/scopes/{sa}/ledger"),
        format!("/v1/privacy/populations/{}", g.a.population),
        format!("/v1/projects/{}/privacy-scopes", g.main.id),
        format!("/v1/projects/{}/audit?limit=200", g.main.id),
        format!("/v1/audit?project={}", g.main.id),
    ];
    let viewers: Vec<(&str, &As)> = vec![
        ("ministry developer", &g.dev),
        ("ministry admin", &g.min_admin),
        ("region-b owner", &g.b.owner),
        ("region-b admin", &g.b.admin),
        ("stranger", &stranger),
    ];
    for url in &urls {
        for (name, who) in &viewers {
            let (s, v) = g.t.call(who, "GET", url, None);
            let text = v.to_string();
            for c in &canaries {
                // (A refusal repeats the ID the caller asked for.)
                if s != 404 {
                    assert!(
                        !text.contains(c.as_str()),
                        "GET {url} as {name} ({s}) leaks {c}: {text}"
                    );
                }
            }
            // And region-a's population and ledger entries are nobody
            // else's: 404, not 403 (it is not even visible).
            if url.contains("/populations/") || url.ends_with("/ledger") {
                assert_eq!(s, 404, "GET {url} as {name}: {v}");
            }
        }
    }
    // The project's other members see the scope's totals (a cap and what
    // it spent), never its entries; the stranger sees nothing of the project.
    let shared =
        g.t.ok(&g.dev, "GET", &format!("/v1/privacy/scopes/{sa}"), None);
    assert_eq!(shared["entries"], 1);
    assert!(shared.get("population").is_none());
    let (s, _) =
        g.t.call(&stranger, "GET", &format!("/v1/privacy/scopes/{sa}"), None);
    assert_eq!(s, 404);
    let (s, _) = g.t.call(
        &stranger,
        "GET",
        &format!("/v1/projects/{}/privacy-scopes", g.main.id),
        None,
    );
    assert_eq!(s, 404);
    // Region-b's data are region-a's secret too.
    for url in [
        format!("/v1/privacy/scopes/{sb}/ledger"),
        format!("/v1/privacy/populations/{}", g.b.population),
    ] {
        let (s, v) = g.t.call(&g.a.owner, "GET", &url, None);
        assert_eq!(s, 404, "{v}");
        // (The refusal repeats only the ID asked for: no entry.)
        for c in b_canaries.iter().skip(1) {
            assert!(!v.to_string().contains(c.as_str()));
        }
    }
    // A region's auditor reads its own ledgers; an auditor organization of
    // the project reads a scope's entries.
    let (s, v) = g.t.call(
        &g.a.auditor,
        "GET",
        &format!("/v1/privacy/scopes/{sa}/ledger"),
        None,
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    let (s, _) = g.t.call(
        &g.a.auditor,
        "GET",
        &format!("/v1/privacy/populations/{}", g.a.population),
        None,
    );
    assert_eq!(s, 200);
    // The governance log's checkpoint of a ledger holds the entry count and
    // root: no more.
    let mut c = g.t.control.db.conn().unwrap();
    let body: Value = c
        .query_one(
            "SELECT body FROM governance_events WHERE kind = 'privacy.ledger_checkpoint' AND subject_id = $1 ORDER BY gseq DESC LIMIT 1",
            &[&format!("scope:{sa}")],
        )
        .unwrap()
        .get(0);
    assert_eq!(body["partition"], "platform");
    let refs: Vec<&String> = body["refs"].as_object().unwrap().keys().collect();
    assert_eq!(refs, ["root", "seq"]);
}

// --- standard projects are unchanged ---------------------------------------------------------------

#[test]
fn standard_projects_and_unscoped_assets_are_unchanged() {
    let Some(g) = world() else { return };
    // Scopes belong to governed projects.
    let std_project = id(&g.t.ok(
        &g.a.admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": A, "name": "standard-one"})),
    ));
    let (s, v) = g.t.call(
        &g.a.sec1,
        "POST",
        "/v1/privacy/scopes",
        Some(json!({"population": g.a.population, "project": std_project, "purpose": PURPOSE, "epsilon": 0.5})),
    );
    assert_eq!((s, code(&v)), (409, "ENC2604"), "{v}");
    // An asset whose series has no population keeps its own ledger, exactly
    // as before: created with the asset, spent by its owners, anchored.
    let own = id(&g.t.ok(
        &g.a.owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": A, "kind": "dataset", "name": "plain-counts",
                    "digest": "e".repeat(64), "privacy_budget": budget(3.0)}),
        ),
    ));
    let (s, v) = g.t.call(
        &g.a.owner,
        "POST",
        &format!("/v1/privacy/{own}/events"),
        Some(reserve("r-1", 200)),
    );
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["duplicate"], false);
    let view =
        g.t.ok(&g.a.owner, "GET", &format!("/v1/privacy/{own}"), None);
    assert_eq!(view["entries"], 1);
    let cp = g.ledger(&own).checkpoint().unwrap();
    assert_eq!(floor(&g, &own), Some((cp.seq, cp.root)));
    // A scoped reservation never lands in an asset's ledger.
    let mut scoped = reserve("r-2", 200);
    scoped["scope"] = json!({"scope_id": "x", "population_id": "y", "max_sources_per_unit": 1, "linkage": "none"});
    refused(
        g.t.call(
            &g.a.owner,
            "POST",
            &format!("/v1/privacy/{own}/events"),
            Some(scoped),
        ),
        "ENC2719",
    );
    // The first schema-14 asset ledger check: the foreign key's guarantee
    // holds: a ledger for no asset is not created.
    let mut c = g.t.control.db.conn().unwrap();
    assert!(c
        .execute(
            "INSERT INTO privacy_ledgers (asset_id, organization_id, genesis) VALUES ('no-such-asset', $1, '{}')",
            &[&A],
        )
        .is_err());
}

#[test]
fn a_scope_of_another_purpose_is_not_the_jobs() {
    let Some(g) = world() else { return };
    let other = "other-surveillance-2027";
    g.add_purpose(&g.main, other);
    // The owners allocate the project scopes for the *other* purpose only.
    let mut scopes = vec![];
    for r in [&g.a, &g.b] {
        let v = g.t.ok(
            &r.sec1,
            "POST",
            "/v1/privacy/scopes",
            Some(json!({"population": r.population, "project": g.main.id,
                        "purpose": other, "epsilon": 1.0})),
        );
        let scope = id(&v);
        g.t.ok(
            &r.sec2,
            "POST",
            &format!("/v1/privacy/scopes/{scope}/approve"),
            None,
        );
        scopes.push(scope);
    }
    // A job of the project's other purpose (the program and the purpose
    // object say so) has no scope: it cannot spend what was allocated to
    // another purpose.
    let (v, prog) = g.week("2027-w01", DP);
    let (_, j) = g.job(&v, &prog, "k1");
    let job = id(&j);
    assert_eq!(g.state(&job), "failed");
    assert_eq!(g.failure(&job), "ENC2719");
    // Nor can an authorized coordinator charge that job to the other
    // purpose's scope.
    let svc = g.secagg_spender(&scopes[0]);
    let ev = json!({"kind": "reserve", "event_id": "wrong-purpose", "policy_id": null,
        "execution_spec_id": null, "round_id": job, "output": "counts",
        "mechanism": {"kind": "discrete_gaussian", "clip_norm": "1.0", "noise_multiplier": "40.0"},
        "sensitivity": 16388, "sigma2": 26_843_545_600u64, "vector_len": 4, "rng": "csprng",
        "scope": {"scope_id": scopes[0], "population_id": g.a.population, "job_id": job,
                  "max_sources_per_unit": 2, "linkage": "none"}});
    refused(
        g.t.call(
            &svc,
            "POST",
            &format!("/v1/privacy/scopes/{}/events", scopes[0]),
            Some(ev),
        ),
        "ENC2719",
    );
    for s in &scopes {
        assert_eq!(G::reserves(&g.scope_ledger(s)), 0);
    }
    assert_eq!(G::reserves(&g.pop_ledger(&g.a)), 0);
}

// --- follow-ups: populations, declarations, accounting, anchoring ------------------------------

#[test]
fn a_population_needs_four_eyes_a_known_series_and_may_be_superseded() {
    let Some(g) = world() else { return };
    let r = &g.a;
    let propose = |who: &As, series: &str, eps: &str, sup: Option<&str>| {
        g.t.call(
            who,
            "POST",
            "/v1/privacy/populations",
            Some(json!({"organization": A, "series": series, "budget": budget_json(eps), "supersedes": sup})),
        )
    };
    // A series the organization never registered: refused.
    refused(propose(&r.sec1, "no-such-series", "1.0", None), "ENC2720");
    // One population per series: another must name the active one.
    refused(propose(&r.sec1, SERIES, "2.0", None), "ENC2720");
    refused(propose(&r.sec1, SERIES, "2.0", Some("pop_nope")), "ENC2720");
    // A superseding population: proposed, never approved by its proposer.
    let (s, v) = propose(&r.sec1, SERIES, "0.8", Some(&r.population));
    assert_eq!(s, 201, "{v}");
    let new = id(&v);
    let approve = |who: &As| {
        g.t.call(
            who,
            "POST",
            &format!("/v1/privacy/populations/{new}/approve"),
            None,
        )
    };
    refused(approve(&r.sec1), "ENC2707");
    refused(approve(&r.auditor), "ENC2602");
    refused(approve(&g.b.sec1), "ENC2603");
    // Spend something under the old one first.
    let _ = (g.scope(r, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v1, p1) = g.week("2027-w01", DP);
    let job1 = id(&g.job(&v1, &p1, "k1").1);
    assert_eq!(g.start(&job1).0, 200);
    let old_spent = G::reserves(&g.pop_ledger(r));
    assert_eq!(approve(&r.sec2).0, 200);
    let old = g.t.ok(
        &r.owner,
        "GET",
        &format!("/v1/privacy/populations/{}", r.population),
        None,
    );
    assert_eq!(old["superseded_by"], new);
    // The old one keeps its history; new scopes belong to the new one.
    assert_eq!(G::reserves(&g.pop_ledger(r)), old_spent);
    refused(g.try_scope(&g.main, r, "0.5", Some("another")), "ENC2720");
    // Jobs now resolve the new population: with no scope of it yet, none runs.
    let (v2, p2) = g.week("2027-w02", DP);
    let job2 = id(&g.job(&v2, &p2, "k2").1);
    assert_eq!(g.state(&job2), "failed");
    assert_eq!(g.failure(&job2), "ENC2719");
    // The old population is superseded but still active: a version's own
    // ledger is still refused for the series (ENC2719, not a failure to
    // pick one of two populations).
    let own = g.t.ok(
        &r.owner,
        "POST",
        "/v1/assets",
        Some(json!({"organization": A, "kind": "dataset", "name": format!("{SERIES}@legacy"),
                    "series": SERIES, "version": "legacy", "digest": "e".repeat(64),
                    "privacy_budget": budget(3.0), "ir_policy": registered_dp(A, "1.0")["ir_policy"],
                    "release_class": "dp-aggregate-only",
                    "key_ref": {"broker": "region-a-broker", "provider": "openbao-transit",
                                "key_ref": "counts-legacy", "key_version": 1}})),
    );
    refused(
        g.t.call(
            &r.owner,
            "POST",
            &format!("/v1/privacy/{}/events", id(&own)),
            Some(reserve("legacy-1", 4_000_000_000)),
        ),
        "ENC2719",
    );
}

#[test]
fn a_declaration_below_the_participants_needs_every_owners_signature() {
    let Some(g) = world() else { return };
    let (sa, _sb) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let low = format!("{DP} max_sources_per_unit 1");
    // Two participants, one source per unit declared, owners did not sign it.
    let (v, prog) = g.week("2027-w01", &low);
    let job = id(&g.job(&v, &prog, "k1").1);
    assert_eq!(g.state(&job), "failed");
    assert_eq!(g.failure(&job), "ENC2721");
    // Only one owner signed it: still refused.
    let va = g.version(&g.a, "2027-w02");
    let vb = g.version(&g.b, "2027-w02");
    let prog2 = program([&va.0, &vb.0], &low);
    g.authorize_full(&g.main, &g.a, &va, &[&prog2], None, Some(1));
    g.authorize_full(&g.main, &g.b, &vb, &[&prog2], None, None);
    let job = id(&g.job(&[va, vb], &prog2, "k2").1);
    assert_eq!(g.failure(&job), "ENC2721");
    // Both signed the lower number: runs, charged for exactly one source.
    let va = g.version(&g.a, "2027-w03");
    let vb = g.version(&g.b, "2027-w03");
    let prog3 = program([&va.0, &vb.0], &low);
    g.authorize_full(&g.main, &g.a, &va, &[&prog3], None, Some(1));
    g.authorize_full(&g.main, &g.b, &vb, &[&prog3], None, Some(1));
    let job = id(&g.job(&[va, vb], &prog3, "k3").1);
    assert_eq!(g.state(&job), "queued");
    assert_eq!(g.start(&job).0, 200);
    let l = g.scope_ledger(&sa);
    let encompute_privacy::PrivacyEvent::Reserve {
        sensitivity,
        scope: Some(r),
        ..
    } = &l.entries[0].event
    else {
        panic!()
    };
    assert_eq!((*sensitivity, r.max_sources_per_unit), (2 * 4096 + 2, 1));
}

#[test]
fn two_authorizations_that_pin_different_scopes_are_refused() {
    let Some(g) = world() else { return };
    let (any_a, any_b) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let other = g.scope(&g.a, "0.5", Some(&"22".repeat(32)));
    let va = g.version(&g.a, "2027-w01");
    let vb = g.version(&g.b, "2027-w01");
    let prog = program([&va.0, &vb.0], DP);
    g.authorize_in(&g.main, &g.a, &va, &[&prog], Some(&any_a));
    g.authorize_in(&g.main, &g.a, &va, &[&prog], Some(&other));
    g.authorize_in(&g.main, &g.b, &vb, &[&prog], Some(&any_b));
    // Refused at submission, whatever the order of the authorizations' IDs.
    let (s, v) = g.job(&[va, vb], &prog, "k1");
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["code"], "ENC2719", "{v}");
    // And audited, like every other refusal of a submission.
    let mut c = g.t.control.db.conn().unwrap();
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM audit_events WHERE action = 'job.denied'
                AND refs->>'reason' = 'scope_pin_conflict'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 1);
}

#[test]
fn a_succeeded_job_needs_its_release_accounted() {
    let Some(g) = world() else { return };
    let (sa, sb) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v, prog) = g.week("2027-w01", DP);
    let job = id(&g.job(&v, &prog, "k1").1);
    assert_eq!(g.start(&job).0, 200);
    let unaccounted = |g: &G| {
        let c = &g.t.control;
        c.db.tx(|t| c.unaccounted_reservations(t, &job)).unwrap()
    };
    let m = unaccounted(&g).expect("reserved but never reported committed");
    assert!(m.contains("release not accounted"), "{m}");
    // The coordinators report each commit; then it is accounted.
    for scope in [&sa, &sb] {
        let svc = g.secagg_spender(scope);
        let e = reported(&g, scope, &job)["event_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (s, r) = g.t.call(
            &svc,
            "POST",
            &format!("/v1/privacy/scopes/{scope}/events"),
            Some(json!({"kind": "commit", "event_id": e, "output_commitment": "cd".repeat(32)})),
        );
        assert_eq!(s, 200, "{r}");
    }
    assert_eq!(unaccounted(&g), None);
    // A commit of an event no job reserved in this scope is refused.
    refused(
        g.t.call(
            &g.secagg_spender(&sa),
            "POST",
            &format!("/v1/privacy/scopes/{sa}/events"),
            Some(json!({"kind": "commit", "event_id": "ff".repeat(32), "output_commitment": "cd".repeat(32)})),
        ),
        "ENC2719",
    );
}

#[test]
fn a_start_whose_anchor_failed_is_retried_and_swept() {
    let Some(g) = world() else { return };
    let (sa, _sb) = (g.scope(&g.a, "1.0", None), g.scope(&g.b, "1.0", None));
    let (v, prog) = g.week("2027-w01", DP);
    let job = id(&g.job(&v, &prog, "k1").1);
    let (t2, fail) = g.t.env0.start_flaky();
    let call = |t: &T, j: &str| {
        t.call(
            &g.evaluator.service,
            "POST",
            &format!("/v1/jobs/{j}/start"),
            None,
        )
    };
    let arm = |on: bool| fail.store(on, std::sync::atomic::Ordering::SeqCst);
    // The reservation commits, then the anchor store fails: the call fails,
    // the budget is reserved and not yet checkpointed.
    arm(true);
    let (s, _) = call(&t2, &job);
    assert!(s >= 400, "{s}");
    assert_eq!(G::reserves(&g.scope_ledger(&sa)), 1);
    let key = format!("scope:{sa}");
    assert_eq!(
        g.t.control
            .ledger_floor(&key)
            .unwrap()
            .map(|c| c.seq)
            .unwrap_or(0),
        0
    );
    // The store is back: the same evaluator starts again, idempotently: the
    // ledgers are anchored, nothing is charged twice, and the answer is OK.
    arm(false);
    assert_eq!(call(&t2, &job).0, 200);
    assert_eq!(G::reserves(&g.scope_ledger(&sa)), 1);
    let cp = g.scope_ledger(&sa).checkpoint().unwrap();
    assert_eq!(floor(&g, &key), Some((cp.seq, cp.root)));
    // Once anchored, a start is a replay again.
    assert_eq!(call(&t2, &job).0, 409);
    // The background sweep anchors what a failed call left behind.
    let (v2, prog2) = g.week("2027-w02", DP);
    let job2 = id(&g.job(&v2, &prog2, "k2").1);
    arm(true);
    assert!(call(&t2, &job2).0 >= 400);
    arm(false);
    assert!(t2.control.anchor_pending_ledgers().unwrap() >= 2);
    let cp = g.scope_ledger(&sa).checkpoint().unwrap();
    assert_eq!(floor(&g, &key), Some((cp.seq, cp.root)));
    assert_eq!(t2.control.anchor_pending_ledgers().unwrap(), 0);
}

#[test]
fn a_project_scope_list_is_rate_limited() {
    let Some(g) = world() else { return };
    let _ = g.scope(&g.a, "1.0", None);
    g.t.control.scope_limit.set(3);
    let url = format!("/v1/projects/{}/privacy-scopes", g.main.id);
    for _ in 0..3 {
        assert_eq!(g.t.call(&g.dev, "GET", &url, None).0, 200);
    }
    assert_eq!(g.t.call(&g.dev, "GET", &url, None).0, 503);
}

// --- a governed DP job under placement, scope and authorization checks -------------------------

/// The execution transcript of `program` under `spec`.
fn transcript(program: &str, spec: &ExecutionSpec) -> Option<String> {
    let p = encompute_ir::parse(program).unwrap();
    let c = encompute_evaluator::compile_program(&p).unwrap();
    encompute_evaluator::transcript_for(&c, spec).map(|t| t.id().hex())
}

/// A governed DP job on a placement-constrained project with a scope runs
/// submit, approve, schedule, start (reserving), report, complete; and the
/// order of the checks is coherent: a job that violates the project's
/// placement, an owner's authorization or the scope's cap is refused with
/// that rule's own code, whatever else is also wrong, and reserves nothing.
/// Placement and authorization are judged before the scope, and the
/// reservation is last.
#[test]
fn a_governed_dp_job_runs_under_placement_scope_and_authorization() {
    let Some(g) = world() else { return };
    // The evaluator is the platform's, in Germany by its operator's declaration.
    let plat_sec = user(&g.t, &g.platform, "platform", "p-sec", &["security_admin"]);
    let (st, v) = g.t.call(
        &plat_sec,
        "POST",
        "/v1/evaluators/evaluator-1/location-declarations",
        Some(json!({"provider": "gcp", "region": "europe-west3"})),
    );
    assert_eq!(st, 201, "{v}");
    // The project may run only in Germany.
    let url = format!("/v1/projects/{}/placement", g.main.id);
    g.t.ok(
        &g.a.sec1,
        "POST",
        &url,
        Some(json!({"constraints": {"allowed_regions": [{"jurisdiction": "DE"}]}, "base_version": 0})),
    );
    // A scope pays for one release (about 0.43 of epsilon each) and not two.
    let (sa, sb) = (g.scope(&g.a, "0.6", None), g.scope(&g.b, "0.6", None));
    // Four weeks of the same program; each is submitted (approved and
    // scheduled where the evaluator is admitted) before any starts, so
    // every scheduling check passes while the scopes are full.
    let mut weeks = vec![];
    for w in 1..=4 {
        let (v, prog) = g.week(&format!("2027-w0{w}"), DP);
        let (s, j) = g.job(&v, &prog, &format!("k{w}"));
        assert_eq!(s, 201, "{j}");
        let job = id(&j);
        assert_eq!(g.state(&job), "queued", "{j}");
        weeks.push((job, prog, v));
    }
    let (good, bad_placement, bad_authorization, last) = (
        weeks[0].0.clone(),
        weeks[1].0.clone(),
        weeks[2].0.clone(),
        weeks[3].0.clone(),
    );

    // Start reserves, in each source's scope and population, once.
    let (s, started) = g.start(&good);
    assert_eq!(s, 200, "{started}");
    assert_eq!(started["state"], "running");
    for r in [&g.a, &g.b] {
        assert_eq!(G::reserves(&g.pop_ledger(r)), 1);
    }
    // The grant records where it was placed; the job is the one the scope pays for.
    let grant: encompute_verification::service::JobGrant =
        serde_json::from_value(started["grant"].clone()).unwrap();
    let gov = grant.governance.clone().unwrap();
    assert!(gov.placement.is_some(), "the grant records its placement");
    // Report: each source's coordinator commits the release in its scope.
    for scope in [&sa, &sb] {
        let svc = g.secagg_spender(scope);
        let e = reported(&g, scope, &good)["event_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (s, r) = g.t.call(
            &svc,
            "POST",
            &format!("/v1/privacy/scopes/{scope}/events"),
            Some(json!({"kind": "commit", "event_id": e, "output_commitment": "cd".repeat(32)})),
        );
        assert_eq!(s, 200, "{r}");
    }
    // Complete: the evaluator's receipt for the governed spec.
    let prog = &weeks[0].1;
    let spec = base_spec(prog).governed(&gov.binding);
    let receipt = encompute_verification::ExecutionReceipt::new(
        &spec,
        transcript(prog, &spec).as_deref(),
        &"5e".repeat(32),
        b"request",
        b"response",
        &g.evaluator.receipt.identity(),
    )
    .unwrap()
    .with_grant(Some(grant.digest()))
    .sign(&g.evaluator.receipt)
    .unwrap();
    let (s, done) = g.t.call(
        &g.dev,
        "POST",
        &format!("/v1/jobs/{good}/complete"),
        Some(json!({"receipt": receipt,
                    "request_commitment": encompute_verification::request_commitment(b"request"),
                    "output_commitment": encompute_verification::output_commitment(b"response"),
                    "key_id": "5e".repeat(32)})),
    );
    assert_eq!(s, 200, "{done}");
    assert_eq!(done["state"], "succeeded");

    let reserved = |g: &G| {
        (
            G::reserves(&g.pop_ledger(&g.a)),
            G::reserves(&g.pop_ledger(&g.b)),
        )
    };
    assert_eq!(reserved(&g), (1, 1));
    // The scope is spent: the next job is refused for its budget (ENC2201)
    // and reserves nothing.
    let (s, v) = g.start(&last);
    assert!(s >= 400, "{v}");
    assert_eq!(g.state(&last), "failed");
    assert_eq!(g.failure(&last), "ENC2201");
    assert_eq!(v["code"], "ENC2201", "{v}");
    assert_eq!(reserved(&g), (1, 1));

    // The budget is still spent, but a project's placement is judged first.
    // Region-a tightens the constraints so the evaluator's region is
    // prohibited: the queued job is refused for placement (ENC2710), not for
    // its budget.
    let url = format!("/v1/projects/{}/placement", g.main.id);
    g.t.ok(
        &g.a.sec1,
        "POST",
        &url,
        Some(json!({"constraints": {"allowed_regions": [{"jurisdiction": "DE"}],
                                     "prohibited_locations": [{"provider": "gcp", "region": "europe-west3"}]},
                    "base_version": 1})),
    );
    let (s, v) = g.start(&bad_placement);
    assert!(s >= 400, "{v}");
    assert_eq!(g.state(&bad_placement), "failed");
    assert_eq!(g.failure(&bad_placement), "ENC2710");
    assert_eq!(v["code"], "ENC2710", "{v}");
    assert_eq!(reserved(&g), (1, 1));

    // An owner withdraws its authorization: refused for the authorization
    // (not the budget), and reserves nothing.
    let row: String =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT id FROM authorizations WHERE asset_version_id = $1 AND status = 'active'",
                &[&weeks[2].2[0].1],
            )
            .unwrap()
            .get(0);
    g.t.ok(
        &g.a.sec1,
        "POST",
        &format!("/v1/authorizations/{row}/revoke"),
        Some(json!({"reason": "withdrawn"})),
    );
    let (s, v) = g.start(&bad_authorization);
    assert!(s >= 400, "{v}");
    assert_eq!(g.state(&bad_authorization), "failed");
    // The revocation failed the job on the spot, naming the authorization.
    let named: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM audit_events WHERE action = 'job.failed' AND resource_id = $1
               AND refs->>'revoked_authorization' IS NOT NULL",
                &[&bad_authorization],
            )
            .unwrap()
            .get(0);
    assert_eq!(named, 1);
    assert_eq!(reserved(&g), (1, 1));
}
