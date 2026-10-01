//! Auditors and cross-organization views in governed projects (public-
//! sector governance, phase 3, D9): an auditor is read-only and holds no
//! other role in an organization taking part in a governed project; an
//! auditor organization reads the project's shared records and never owns,
//! submits, receives, approves or holds keys; every organization sees one
//! shared view of a governed project's records, the same bytes for each,
//! with approvers as per-project pseudonyms and never another
//! organization's storage, keys or people. Standard organizations keep
//! their role combinations.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use common::*;
use encompute_control::api::{handle, Request, ROUTES};
use encompute_control::authn::DEV_ISSUER;
use encompute_trust::authz::{AuthorizationV2, PurposeAcceptance};
use encompute_verification::governance::{ProgramRef, ReleaseClass};
use encompute_verification::{hex, ServiceSigner};

const TAX: &str = "tax-agency";
const BEN: &str = "benefits-agency";
/// A member named by no authorization.
const OTHER: &str = "other-co";
/// The project's auditor organization.
const AUD: &str = "audit-office";
/// Takes no part in the project.
const NON: &str = "outsider";
const PURPOSE: &str = "benefits-eligibility";
/// Tax's private metadata, which no other organization may see.
const STORAGE_CANARY: &str = "tax-canary-bucket";
const KEY_REF_CANARY: &str = "income-canary-keyref";
const SUBJECT_CANARY: &str = "tax-canary-";

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
    v["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no id in {v}"))
        .to_owned()
}

struct W {
    t: T,
    platform: As,
    tax_admin: As,
    tax_sec1: As,
    tax_sec2: As,
    tax_owner: As,
    ben_admin: As,
    ben_dev: As,
    ben_auditor: As,
    other_admin: As,
    other_dev: As,
    aud_admin: As,
    aud_auditor: As,
    aud_dev: As,
    aud_sec: As,
    non_admin: As,
    non_dev: As,
    evaluator: Evaluator,
    project: String,
    tax_key: SigningKey,
    purpose: String,
    /// Tax's dataset version (its storage and key references are canaries).
    asset: String,
    version: String,
    /// Tax's active authorization of `version` (row ID).
    authorization: String,
    body: AuthorizationV2,
    program: String,
    plan: String,
    /// Benefits' governed job.
    job: String,
    /// A policy tax's security admin proposed in the project.
    policy: String,
    /// Benefits' own dataset (with a privacy ledger), governance key and
    /// automation account.
    ben_asset: String,
    ben_key: String,
    ben_user: String,
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

/// A program over `asset`, declaring the purpose, released to benefits.
fn program(asset: &str) -> String {
    format!(
        "encompute 0.1\nprogram adult precision 0.001 purpose \"{PURPOSE}\"\n\
         party \"{TAX}\" \"Tax\"\nparty \"{BEN}\" \"Benefits\"\n\
         asset \"{asset}\" dataset owners [\"{TAX}\"] readers [\"{BEN}\", \"{TAX}\"] purposes \
         [\"{PURPOSE}\"] release allowed_parties\n\
         %0 = input \"x0\" [0.0, 120.0] asset \"{asset}\" : secret u8\n\
         %1 = const [18.0] : public u8\n%2 = ge %0, %1 : secret bool\noutput \"out\" = %2 to \"{BEN}\"\n"
    )
}

fn purpose_body(org: &str, recipients: &[&str]) -> Value {
    json!({"organization": org, "name": PURPOSE, "description": "Eligibility for housing benefit",
           "modes": ["aggregate"], "allowed_release_classes": ["boolean-only"],
           "recipients": recipients, "valid_from": now() - 60, "valid_until": now() + 10_000})
}

fn request(project: &str, plan: &str, purpose: &str, asset: &str, recipients: &[&str]) -> Value {
    json!({"project": project, "plan": plan, "purpose": PURPOSE,
           "purpose_id": purpose, "source_assets": [asset], "requested_output": "out",
           "outputs": {"out": {"release_class": "boolean-only", "recipients": recipients}}})
}

fn world() -> Option<W> {
    let t = setup()?;
    t.control
        .bootstrap(DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let platform = As::User("platform-admin".into());
    for (org, admin) in [
        (TAX, "t-admin"),
        (BEN, "b-admin"),
        (OTHER, "o-admin"),
        (AUD, "a-admin"),
        (NON, "n-admin"),
    ] {
        t.ok(
            &platform,
            "POST",
            "/v1/organizations",
            Some(json!({"id": org, "display_name": org, "admin": {"issuer": DEV_ISSUER, "subject": admin}})),
        );
    }
    let tax_admin = As::User("t-admin".into());
    let ben_admin = As::User("b-admin".into());
    let other_admin = As::User("o-admin".into());
    let aud_admin = As::User("a-admin".into());
    let non_admin = As::User("n-admin".into());
    let tax_sec1 = user(&t, &tax_admin, TAX, "tax-canary-sec1", &["security_admin"]);
    let tax_sec2 = user(&t, &tax_admin, TAX, "tax-canary-sec2", &["security_admin"]);
    let tax_owner = user(&t, &tax_admin, TAX, "tax-canary-owner", &["data_owner"]);
    let ben_dev = user(&t, &ben_admin, BEN, "b-dev", &["ml_developer"]);
    let ben_auditor = user(&t, &ben_admin, BEN, "b-auditor", &["auditor"]);
    let ben_owner = user(&t, &ben_admin, BEN, "b-owner", &["data_owner"]);
    let other_dev = user(&t, &other_admin, OTHER, "o-dev", &["ml_developer"]);
    let aud_auditor = user(&t, &aud_admin, AUD, "aud-auditor", &["auditor"]);
    let aud_dev = user(&t, &aud_admin, AUD, "aud-dev", &["ml_developer"]);
    let aud_sec = user(&t, &aud_admin, AUD, "aud-sec", &["security_admin"]);
    let non_dev = user(&t, &non_admin, NON, "n-dev", &["ml_developer"]);
    let evaluator = common::evaluator(
        &t,
        &platform,
        "evaluator-1",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    broker_account(&t, &tax_admin, TAX, "tax-broker", 31);
    t.ok(
        &tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/key-brokers"),
        Some(json!({"id": "tax-broker", "grant_public_key": pk(&key(41)),
                    "provider_kind": "openbao-transit", "key_ref_namespace": "transit/tax"})),
    );
    let p = t.ok(
        &tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "benefits-eligibility",
                    "governance": "governed", "organizations": [BEN, OTHER]})),
    );
    let project = id(&p);
    for (admin, org) in [(&ben_admin, BEN), (&other_admin, OTHER)] {
        t.ok(
            admin,
            "POST",
            &format!("/v1/projects/{project}/members"),
            Some(json!({"organization": org})),
        );
    }
    // The audit office is appointed auditor, and accepts.
    let v = t.ok(
        &tax_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": AUD, "participation": "auditor"})),
    );
    assert_eq!(v["status"], "invited", "{v}");
    let v = t.ok(
        &aud_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": AUD})),
    );
    assert_eq!(v["status"], "active", "{v}");
    assert_eq!(v["participation"], "auditor", "{v}");
    // Tax's governance key and purpose.
    let tax_key = key(7);
    let k = t.ok(
        &tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        Some(json!({"public_key": pk(&tax_key), "kms_key_ref": "vault:transit/governance"})),
    );
    t.ok(
        &tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{}/approve", id(&k)),
        None,
    );
    let v = t.ok(
        &tax_sec1,
        "POST",
        &format!("/v1/projects/{project}/purposes"),
        Some(purpose_body(TAX, &[BEN, TAX])),
    );
    let purpose = id(&v);
    t.ok(
        &tax_sec2,
        "POST",
        &format!("/v1/purposes/{purpose}/approve"),
        None,
    );
    let acceptance = PurposeAcceptance {
        version: 1,
        organization: TAX.into(),
        project: project.clone(),
        purpose_id: purpose.clone(),
        accepted_at: now(),
    }
    .sign(&tax_key)
    .unwrap();
    t.ok(
        &tax_sec2,
        "POST",
        &format!("/v1/purposes/{purpose}/accept"),
        Some(json!({"acceptance": acceptance})),
    );
    // Tax's dataset version: where it is stored and which key protects it
    // are tax's own business.
    let v = t.ok(
        &tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "income@2026-q1",
                    "series": "income", "version": "2026-q1", "digest": "c".repeat(64),
                    "project": project, "storage_uri": format!("s3://{STORAGE_CANARY}/income"),
                    "ir_policy": registered(TAX)["ir_policy"], "release_class": "boolean-only",
                    "size_bytes": 4096,
                    "key_ref": {"broker": "tax-broker", "provider": "openbao-transit",
                                "key_ref": KEY_REF_CANARY, "key_version": 1}}),
        ),
    );
    let (asset, version) = (id(&v), v["version_id"].as_str().unwrap().to_owned());
    let program = program(&asset);
    let spec = {
        let p = encompute_ir::parse(&program).unwrap();
        let c = encompute_evaluator::compile_program(&p).unwrap();
        encompute_evaluator::execution_spec(
            &encompute_evaluator::Ids::of(&p, &c),
            &c,
            c.target_backend(),
        )
    };
    let body = AuthorizationV2 {
        version: 2,
        party: TAX.into(),
        project: project.clone(),
        purpose_id: purpose.clone(),
        asset_version_id: version.clone(),
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
        nonce: "ab".repeat(16),
        approvals: vec![],
    };
    let v = t.ok(
        &tax_owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": body})),
    );
    let authorization = id(&v);
    for (who, role) in [(&tax_owner, "data_owner"), (&tax_sec1, "security_admin")] {
        t.ok(
            who,
            "POST",
            &format!("/v1/authorizations/{authorization}/approve"),
            Some(json!({"role": role})),
        );
    }
    let v = t.ok(
        &tax_sec1,
        "GET",
        &format!("/v1/authorizations/{authorization}"),
        None,
    );
    let doc: AuthorizationV2 = serde_json::from_value(v["body"].clone()).unwrap();
    let s = doc.sign(&tax_key).unwrap();
    t.ok(
        &tax_sec1,
        "POST",
        &format!("/v1/authorizations/{authorization}/signature"),
        Some(json!({"public_key": s.public_key, "signature": s.signature})),
    );
    let v = t.ok(
        &ben_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": project, "program": program})),
    );
    let plan = id(&v);
    let (s, v) = t.call_with(
        &ben_dev,
        "POST",
        "/v1/jobs",
        Some(request(&project, &plan, &purpose, &asset, &[BEN])),
        &[("Idempotency-Key", "k-1")],
    );
    assert_eq!(s, 201, "{v}");
    let job = id(&v);
    let v = t.ok(
        &tax_sec1,
        "POST",
        &format!("/v1/projects/{project}/policies"),
        Some(json!({"retention_days": 30})),
    );
    let policy = id(&v);
    let v = t.ok(
        &ben_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": BEN, "kind": "dataset", "name": "claims",
                    "digest": "e".repeat(64), "privacy_budget": budget(3.0)}),
        ),
    );
    let ben_asset = id(&v);
    let v = t.ok(
        &ben_admin,
        "POST",
        &format!("/v1/organizations/{BEN}/governance-keys"),
        Some(json!({"public_key": pk(&key(8))})),
    );
    let ben_key = id(&v);
    let bot = ServiceSigner::from_seed("ben-bot", &[12; 32]).unwrap();
    t.ok(
        &ben_admin,
        "POST",
        &format!("/v1/organizations/{BEN}/service-accounts"),
        Some(json!({"id": "ben-bot", "kind": "automation", "public_key": bot.public_key_hex()})),
    );
    let ben_user = t.ok(&ben_dev, "GET", "/v1/whoami", None)["id"]
        .as_str()
        .unwrap()
        .to_owned();
    Some(W {
        t,
        platform,
        tax_admin,
        tax_sec1,
        tax_sec2,
        tax_owner,
        ben_admin,
        ben_dev,
        ben_auditor,
        other_admin,
        other_dev,
        aud_admin,
        aud_auditor,
        aud_dev,
        aud_sec,
        non_admin,
        non_dev,
        evaluator,
        project,
        tax_key,
        purpose,
        asset,
        version,
        authorization,
        body,
        program,
        plan,
        job,
        policy,
        ben_asset,
        ben_key,
        ben_user,
    })
}

impl W {
    fn principal(&self, who: &As) -> String {
        self.t.ok(who, "GET", "/v1/whoami", None)["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// Audit events that recorded a change.
    fn changes(&self) -> i64 {
        self.t
            .control
            .db
            .conn()
            .unwrap()
            .query_one(
                "SELECT count(*) FROM audit_events WHERE result = 'succeeded'",
                &[],
            )
            .unwrap()
            .get(0)
    }

    /// A request for the mutating route `pattern` that someone allowed
    /// would get accepted (or refused only for its content): benefits'
    /// organization and resources, tax's authorization and purpose, the
    /// project's job. `None` for a route this table does not know yet.
    fn mutation(&self, pattern: &str) -> Option<(String, Option<Value>)> {
        let (p, j, a, pu) = (&self.project, &self.job, &self.authorization, &self.purpose);
        let acceptance = PurposeAcceptance {
            version: 1,
            organization: BEN.into(),
            project: p.clone(),
            purpose_id: pu.clone(),
            accepted_at: now(),
        }
        .sign(&key(8))
        .unwrap();
        let s = |x: &str| x.to_owned();
        Some(match pattern {
            "/v1/organizations" => (
                s(pattern),
                Some(json!({"id": "new-org", "display_name": "New"})),
            ),
            "/v1/organizations/{}/users" => (
                format!("/v1/organizations/{BEN}/users"),
                Some(json!({"issuer": DEV_ISSUER, "subject": "b-new", "roles": ["ml_developer"]})),
            ),
            "/v1/organizations/{}/service-accounts" => (
                format!("/v1/organizations/{BEN}/service-accounts"),
                Some(json!({"id": "ben-bot-2", "kind": "automation", "public_key": pk(&key(13))})),
            ),
            "/v1/organizations/{}/service-accounts/{}/disable" => (
                format!("/v1/organizations/{BEN}/service-accounts/ben-bot/disable"),
                None,
            ),
            "/v1/organizations/{}/users/{}/disable" => (
                format!("/v1/organizations/{BEN}/users/{}/disable", self.ben_user),
                None,
            ),
            "/v1/organizations/{}/memberships/remove" => (
                format!("/v1/organizations/{BEN}/memberships/remove"),
                Some(json!({"principal": self.ben_user})),
            ),
            "/v1/organizations/{}/key-rotations" => (
                format!("/v1/organizations/{BEN}/key-rotations"),
                Some(
                    json!({"provider": "vault", "key_ref": "k", "old_version": 1, "new_version": 2}),
                ),
            ),
            "/v1/projects" => (
                s(pattern),
                Some(json!({"organization": BEN, "name": "another", "governance": "governed"})),
            ),
            "/v1/projects/{}/members" => (
                format!("/v1/projects/{p}/members"),
                Some(json!({"organization": NON})),
            ),
            "/v1/projects/{}/members/remove" => (
                format!("/v1/projects/{p}/members/remove"),
                Some(json!({"organization": OTHER})),
            ),
            "/v1/organizations/{}/governance-keys" => (
                format!("/v1/organizations/{BEN}/governance-keys"),
                Some(json!({"public_key": pk(&key(14))})),
            ),
            "/v1/organizations/{}/governance-keys/{}/approve" => (
                format!(
                    "/v1/organizations/{BEN}/governance-keys/{}/approve",
                    self.ben_key
                ),
                None,
            ),
            "/v1/organizations/{}/governance-keys/{}/revoke" => (
                format!(
                    "/v1/organizations/{BEN}/governance-keys/{}/revoke",
                    self.ben_key
                ),
                None,
            ),
            "/v1/projects/{}/purposes" => (
                format!("/v1/projects/{p}/purposes"),
                Some(purpose_body(BEN, &[BEN])),
            ),
            "/v1/purposes/{}/approve" => (format!("/v1/purposes/{pu}/approve"), None),
            "/v1/purposes/{}/accept" => (
                format!("/v1/purposes/{pu}/accept"),
                Some(json!({"acceptance": acceptance})),
            ),
            "/v1/purposes/{}/retire" => (format!("/v1/purposes/{pu}/retire"), None),
            "/v1/authorizations" => (s(pattern), Some(json!({"body": self.body}))),
            "/v1/authorizations/{}/approve" => (
                format!("/v1/authorizations/{a}/approve"),
                Some(json!({"role": "data_owner"})),
            ),
            "/v1/authorizations/{}/signature" => (
                format!("/v1/authorizations/{a}/signature"),
                Some(json!({"public_key": pk(&self.tax_key), "signature": "00".repeat(64)})),
            ),
            "/v1/authorizations/{}/revoke" => (
                format!("/v1/authorizations/{a}/revoke"),
                Some(json!({"reason": "audit"})),
            ),
            "/v1/projects/{}/checkpoints/{}/witnesses" => (
                format!("/v1/projects/{p}/checkpoints/1/witnesses"),
                Some(json!({
                    "body": {"version": 1, "organization": BEN, "partition": format!("p:{p}"),
                             "size": 1, "root": "0".repeat(64), "at": now()},
                    "public_key": "0".repeat(64), "signature": "0".repeat(128)})),
            ),
            "/v1/organizations/{}/key-brokers" => (
                format!("/v1/organizations/{BEN}/key-brokers"),
                Some(json!({"id": "ben-broker", "grant_public_key": pk(&key(42)),
                            "provider_kind": "openbao-transit", "key_ref_namespace": "transit/ben"})),
            ),
            "/v1/projects/{}/policies" => (
                format!("/v1/projects/{p}/policies"),
                Some(json!({"retention_days": 7})),
            ),
            "/v1/policies/{}/approve" => (format!("/v1/policies/{}/approve", self.policy), None),
            "/v1/assets" => (
                s(pattern),
                Some(
                    json!({"organization": BEN, "kind": "dataset", "name": "more",
                            "digest": "f".repeat(64), "project": p}),
                ),
            ),
            "/v1/assets/{}/approvals" => (
                format!("/v1/assets/{}/approvals", self.ben_asset),
                Some(json!({"project": p, "purpose": PURPOSE})),
            ),
            "/v1/assets/{}/approvals/withdraw" => (
                format!("/v1/assets/{}/approvals/withdraw", self.ben_asset),
                Some(json!({"project": p, "purpose": PURPOSE})),
            ),
            "/v1/assets/{}/revoke" => (format!("/v1/assets/{}/revoke", self.ben_asset), None),
            "/v1/plans" => (
                s(pattern),
                Some(json!({"project": p, "program": self.program})),
            ),
            "/v1/jobs" => (
                s(pattern),
                Some(request(p, &self.plan, pu, &self.asset, &[BEN])),
            ),
            "/v1/jobs/{}/cancel" => (format!("/v1/jobs/{j}/cancel"), None),
            "/v1/jobs/{}/approve" => (format!("/v1/jobs/{j}/approve"), None),
            "/v1/jobs/{}/start" => (format!("/v1/jobs/{j}/start"), None),
            "/v1/jobs/{}/release-ticket" => (
                format!("/v1/jobs/{j}/release-ticket"),
                Some(json!({"asset_version_id": self.version})),
            ),
            "/v1/jobs/{}/derived-assets" => (
                format!("/v1/jobs/{j}/derived-assets"),
                Some(
                    json!({"output": "out", "kind": "dataset", "series": "result", "version": "1",
                            "digest": "e".repeat(64),
                            "key_ref": {"broker": "ben-broker", "provider": "openbao-transit",
                                        "key_ref": "result-1", "key_version": 1},
                            "ir_policy": registered(BEN)["ir_policy"], "release_class": "boolean-only",
                            "release_record": encompute_trust::authz::ReleaseRecord {
                                version: 1, party: BEN.into(), project: p.clone(),
                                purpose_id: pu.clone(), job_id: j.clone(),
                                governance_id: "2".repeat(64), output: "out".into(),
                                output_commitment: "3".repeat(64),
                                derived_version_id: "4".repeat(64),
                                release_class: encompute_verification::governance::ReleaseClass::BooleanOnly,
                                parents: [self.version.clone()].into(),
                                authorization_ids: ["6".repeat(64)].into(),
                                onward_policy_id: "8".repeat(64),
                                recipients: [(BEN.to_string(), "7".repeat(64))].into(),
                                lineage_owners: Default::default(),
                                issued_at: now(),
                            }.sign(&key(8)).unwrap()}),
                ),
            ),
            "/v1/assets/{}/exports" => (
                format!("/v1/assets/{}/exports", self.ben_asset),
                Some(json!({"recipient": BEN})),
            ),
            "/v1/assets/{}/release-cosignature" => (
                format!("/v1/assets/{}/release-cosignature", self.ben_asset),
                None,
            ),
            "/v1/assets/{}/retention" => (
                format!("/v1/assets/{}/retention", self.ben_asset),
                Some(json!({"evidence_retention_until": now() + 1_000_000})),
            ),
            "/v1/jobs/{}/complete" => (
                format!("/v1/jobs/{j}/complete"),
                Some(json!({"receipt": {}, "request_commitment": "0".repeat(64),
                            "output_commitment": "0".repeat(64), "key_id": "0".repeat(64)})),
            ),
            "/v1/jobs/{}/receipt" => (
                format!("/v1/jobs/{j}/receipt"),
                Some(json!({"receipt": {}})),
            ),
            "/v1/evaluators" => (s(pattern), Some(json!({"id": "evaluator-9"}))),
            "/v1/evaluators/{}/status" => (
                format!("/v1/evaluators/{}/status", self.evaluator.id),
                Some(json!({"status": "draining"})),
            ),
            "/v1/privacy/{}/events" => (
                format!("/v1/privacy/{}/events", self.ben_asset),
                Some(reserve("audit-1", 1_000_000)),
            ),
            "/v1/privacy/{}/spenders" => (
                format!("/v1/privacy/{}/spenders", self.ben_asset),
                Some(json!({"service": "secagg-1"})),
            ),
            "/v1/audit/checkpoints" => (s(pattern), None),
            "/v1/messages" => (s(pattern), Some(json!({}))),
            _ => return None,
        })
    }

    /// The URLs to read for the reading route `pattern`, over the
    /// project's records and tax's (the owner's) private ones. `None` for a
    /// route this table does not know yet.
    fn reads(&self, pattern: &str) -> Option<Vec<String>> {
        let (p, j, a, pu, v) = (
            &self.project,
            &self.job,
            &self.authorization,
            &self.purpose,
            &self.asset,
        );
        Some(match pattern {
            "/v1/whoami"
            | "/v1/security/legacy-service-admins"
            | "/v1/projects"
            | "/v1/assets"
            | "/v1/evaluators" => vec![pattern.to_owned()],
            "/v1/organizations/{}" => vec![format!("/v1/organizations/{TAX}")],
            "/v1/projects/{}" => vec![format!("/v1/projects/{p}")],
            "/v1/organizations/{}/governance-keys" => {
                vec![format!("/v1/organizations/{TAX}/governance-keys")]
            }
            "/v1/organizations/{}/governance-key-attestation" => {
                vec![format!(
                    "/v1/organizations/{TAX}/governance-key-attestation"
                )]
            }
            "/v1/projects/{}/purposes" => vec![format!("/v1/projects/{p}/purposes")],
            "/v1/projects/{}/audit" => vec![
                format!("/v1/projects/{p}/audit"),
                format!("/v1/projects/{p}/audit?after=1&limit=2"),
            ],
            "/v1/projects/{}/checkpoints/latest" => vec![
                format!("/v1/projects/{p}/checkpoints/latest"),
                format!("/v1/projects/{p}/checkpoints/latest?since=1"),
            ],
            "/v1/purposes/{}" => vec![format!("/v1/purposes/{pu}")],
            "/v1/authorizations/{}" => vec![format!("/v1/authorizations/{a}")],
            "/v1/organizations/{}/key-brokers" => {
                vec![format!("/v1/organizations/{TAX}/key-brokers")]
            }
            "/v1/assets/{}" => vec![format!("/v1/assets/{v}")],
            "/v1/assets/{}/lineage" => vec![format!("/v1/assets/{v}/lineage")],
            "/v1/assets/{}/release-cosignature" => {
                vec![format!("/v1/assets/{v}/release-cosignature")]
            }
            "/v1/jobs" => vec!["/v1/jobs".into(), format!("/v1/jobs?project={p}")],
            "/v1/jobs/{}" => vec![format!("/v1/jobs/{j}")],
            "/v1/privacy/{}" => vec![format!("/v1/privacy/{v}")],
            "/v1/privacy/{}/ledger" => vec![format!("/v1/privacy/{v}/ledger")],
            "/v1/trust/{}" => vec![format!("/v1/trust/{j}")],
            "/v1/audit" => vec![
                "/v1/audit".into(),
                format!("/v1/audit?project={p}"),
                format!("/v1/audit?organization={TAX}"),
            ],
            _ => return None,
        })
    }

    /// GET `url` as `who`: the response's exact bytes.
    fn bytes(&self, who: &As, url: &str) -> (u16, Vec<u8>) {
        let r = handle(
            &self.t.control,
            &Request {
                method: "GET".into(),
                url: url.into(),
                headers: auth_headers(who, "GET", url, b""),
                body: vec![],
            },
        );
        (r.status, r.body)
    }
}

/// Mutating routes an organization's auditor is refused by a check other
/// than the auditor one (with the reason): they touch no governed project.
const NOT_PROJECT_ROUTES: &[(&str, &str)] = &[
    ("/v1/organizations", "platform admins"),
    ("/v1/organizations/{}/users", "organization admins"),
    (
        "/v1/organizations/{}/service-accounts",
        "organization admins",
    ),
    (
        "/v1/organizations/{}/service-accounts/{}/disable",
        "organization admins",
    ),
    (
        "/v1/organizations/{}/users/{}/disable",
        "organization admins",
    ),
    (
        "/v1/organizations/{}/memberships/remove",
        "organization admins",
    ),
    ("/v1/organizations/{}/key-rotations", "organization admins"),
    ("/v1/jobs/{}/start", "the scheduled evaluator"),
    ("/v1/jobs/{}/release-ticket", "the scheduled evaluator"),
    ("/v1/jobs/{}/receipt", "the scheduled evaluator"),
    ("/v1/evaluators", "platform evaluators"),
    ("/v1/evaluators/{}/status", "platform evaluators"),
    ("/v1/audit/checkpoints", "platform operators and auditors"),
    ("/v1/messages", "services"),
];

// --- auditors are read-only -------------------------------------------------------

/// Every mutating route of the router, as an auditor of a member
/// organization, as the auditor organization's people (its auditor, admin,
/// developer and security admin) and as a legacy auditor that also holds
/// security_admin: refused, and nothing changes. A member organization's
/// auditor is refused by the auditor check itself on every route that
/// touches the project (a new route without it fails here).
#[test]
fn every_mutating_route_refuses_an_auditor() {
    let Some(w) = world() else { return };
    let legacy = user(&w.t, &w.tax_admin, TAX, "t-legacy", &["auditor"]);
    legacy_role(&w.t, "t-legacy", TAX, "security_admin");
    // An automation account of the auditor organization, holding its
    // admin and owner roles.
    let bot = std::sync::Arc::new(ServiceSigner::from_seed("aud-bot", &[53; 32]).unwrap());
    w.t.ok(
        &w.aud_admin,
        "POST",
        &format!("/v1/organizations/{AUD}/service-accounts"),
        Some(
            json!({"id": "aud-bot", "kind": "automation", "public_key": bot.public_key_hex(),
                    "roles": ["organization_admin", "data_owner", "ml_developer"]}),
        ),
    );
    let aud_bot = As::Service(bot);
    let posts: Vec<&str> = ROUTES
        .iter()
        .filter(|(m, _)| *m == "POST")
        .map(|(_, p)| *p)
        .collect();
    assert!(posts.len() >= 40, "{posts:?}");
    for who in [
        &w.ben_auditor,
        &legacy,
        &w.aud_auditor,
        &w.aud_admin,
        &w.aud_dev,
        &w.aud_sec,
        &aud_bot,
    ] {
        for pattern in &posts {
            let (url, body) = w
                .mutation(pattern)
                .unwrap_or_else(|| panic!("add POST {pattern} to the auditor test's route table"));
            let before = w.changes();
            let (s, v) =
                w.t.call_with(who, "POST", &url, body, &[("Idempotency-Key", "k-auditor")]);
            assert!(
                (400..500).contains(&s) && s != 409,
                "POST {url} as an auditor: {s} {v}"
            );
            assert_eq!(w.changes(), before, "POST {url} changed something: {v}");
            let exempt = NOT_PROJECT_ROUTES.iter().any(|(p, _)| p == pattern);
            if std::ptr::eq(who, &w.ben_auditor) && !exempt {
                assert_eq!(s, 403, "POST {url}: {v}");
                assert!(
                    v["message"]
                        .as_str()
                        .unwrap_or("")
                        .contains("auditors are read-only"),
                    "POST {url} must refuse the auditor as such: {v}"
                );
            }
        }
    }
    // Every exemption names a real route.
    for (p, _) in NOT_PROJECT_ROUTES {
        assert!(posts.contains(p), "{p} is not a route");
    }
}

/// The auditor organization owns, submits, receives, approves and holds
/// keys nowhere in the project; and an auditor organization is a member of
/// no governed project, nor a member one's auditor.
#[test]
fn auditor_org_cannot_submit_or_receive() {
    let Some(w) = world() else { return };
    let p = &w.project;
    let read_only = |r: (u16, Value)| {
        assert_eq!(r.0, 403, "{}", r.1);
        assert!(
            r.1["message"].as_str().unwrap().contains("read-only"),
            "{}",
            r.1
        );
    };
    // It plans and submits nothing.
    read_only(w.t.call(
        &w.aud_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": p, "program": w.program})),
    ));
    read_only(w.t.call_with(
        &w.aud_dev,
        "POST",
        "/v1/jobs",
        Some(request(p, &w.plan, &w.purpose, &w.asset, &[BEN])),
        &[("Idempotency-Key", "k-aud")],
    ));
    // It owns nothing there: no source, no authorization.
    read_only(w.t.call(
        &w.aud_admin,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": AUD, "kind": "dataset", "name": "x", "digest": "a".repeat(64),
                    "project": p}),
        ),
    ));
    let mut body = w.body.clone();
    body.party = AUD.into();
    read_only(w.t.call(
        &w.aud_sec,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": body})),
    ));
    // It approves nothing, and proposes no purpose.
    read_only(w.t.call(
        &w.aud_sec,
        "POST",
        &format!("/v1/jobs/{}/approve", w.job),
        None,
    ));
    read_only(w.t.call(
        &w.aud_sec,
        "POST",
        &format!("/v1/projects/{p}/purposes"),
        Some(purpose_body(AUD, &[AUD])),
    ));
    // It receives nothing: no purpose names it, and no job releases to it.
    let (s, v) = w.t.call(
        &w.tax_sec1,
        "POST",
        &format!("/v1/projects/{p}/purposes"),
        Some(purpose_body(TAX, &[BEN, AUD])),
    );
    assert_eq!(s, 400, "{v}");
    let (s, v) = w.t.call_with(
        &w.ben_dev,
        "POST",
        "/v1/jobs",
        Some(request(p, &w.plan, &w.purpose, &w.asset, &[BEN, AUD])),
        &[("Idempotency-Key", "k-to-auditor")],
    );
    refused((s, v), "ENC2716");
    // It holds no keys: no key broker of its own.
    broker_account(&w.t, &w.aud_admin, AUD, "aud-broker", 51);
    refused(
        w.t.call(
            &w.aud_sec,
            "POST",
            &format!("/v1/organizations/{AUD}/key-brokers"),
            Some(json!({"id": "aud-broker", "grant_public_key": pk(&key(52)),
                        "provider_kind": "openbao-transit", "key_ref_namespace": "transit/aud"})),
        ),
        "ENC2716",
    );
    // An auditor organization is a member of no governed project, and a
    // member of one audits none.
    let q = w.t.ok(
        &w.other_admin,
        "POST",
        "/v1/projects",
        Some(
            json!({"organization": OTHER, "name": "second", "governance": "governed",
                    "organizations": [AUD]}),
        ),
    );
    let q = id(&q);
    refused(
        w.t.call(
            &w.aud_admin,
            "POST",
            &format!("/v1/projects/{q}/members"),
            Some(json!({"organization": AUD})),
        ),
        "ENC2716",
    );
    w.t.ok(
        &w.other_admin,
        "POST",
        &format!("/v1/projects/{q}/members"),
        Some(json!({"organization": BEN, "participation": "auditor"})),
    );
    refused(
        w.t.call(
            &w.ben_admin,
            "POST",
            &format!("/v1/projects/{q}/members"),
            Some(json!({"organization": BEN})),
        ),
        "ENC2716",
    );
    // Auditor organizations belong to governed projects, never their own.
    let std = w.t.ok(
        &w.other_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": OTHER, "name": "standard"})),
    );
    let (s, v) = w.t.call(
        &w.other_admin,
        "POST",
        &format!("/v1/projects/{}/members", id(&std)),
        Some(json!({"organization": AUD, "participation": "auditor"})),
    );
    assert_eq!(s, 400, "{v}");
    let (s, v) = w.t.call(
        &w.tax_admin,
        "POST",
        &format!("/v1/projects/{p}/members"),
        Some(json!({"organization": TAX, "participation": "auditor"})),
    );
    assert_eq!(s, 400, "{v}");
    // Taking part is fixed: a member is not re-invited as an auditor.
    refused(
        w.t.call(
            &w.tax_admin,
            "POST",
            &format!("/v1/projects/{p}/members"),
            Some(json!({"organization": OTHER, "participation": "auditor"})),
        ),
        "ENC2604",
    );
    // The auditor organization leaves by itself.
    let v = w.t.ok(
        &w.aud_admin,
        "POST",
        &format!("/v1/projects/{p}/members/remove"),
        Some(json!({"organization": AUD})),
    );
    assert_eq!(v["removed"], true, "{v}");
}

// --- auditor separation (D9) ------------------------------------------------------

/// In an organization taking part in a governed project an auditor holds
/// no other role: granting a combination is refused (ENC2716), an
/// organization with one neither joins nor creates a governed project
/// until it is removed, and the legacy report lists combinations.
#[test]
fn combined_roles_refused_in_governed_projects() {
    let Some(w) = world() else { return };
    let t = &w.t;
    refused(
        t.call(
            &w.tax_admin,
            "POST",
            &format!("/v1/organizations/{TAX}/users"),
            Some(json!({"issuer": DEV_ISSUER, "subject": "t-both", "roles": ["auditor", "data_owner"]})),
        ),
        "ENC2716",
    );
    refused(
        t.call(
            &w.tax_admin,
            "POST",
            &format!("/v1/organizations/{TAX}/service-accounts"),
            Some(
                json!({"id": "tax-both", "kind": "automation", "public_key": pk(&key(60)),
                        "roles": ["auditor", "operator"]}),
            ),
        ),
        "ENC2716",
    );
    // An auditor alone is fine.
    user(t, &w.tax_admin, TAX, "t-auditor", &["auditor"]);
    // An organization outside governed projects combines as before...
    let n = user(t, &w.non_admin, NON, "n-both", &["auditor", "ml_developer"]);
    let n_id = w.principal(&n);
    // ...but joins no governed project while the combination lasts.
    t.ok(
        &w.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members", w.project),
        Some(json!({"organization": NON})),
    );
    let accept = || {
        t.call(
            &w.non_admin,
            "POST",
            &format!("/v1/projects/{}/members", w.project),
            Some(json!({"organization": NON})),
        )
    };
    refused(accept(), "ENC2716");
    // Nor creates one.
    refused(
        t.call(
            &w.non_admin,
            "POST",
            "/v1/projects",
            Some(json!({"organization": NON, "name": "own", "governance": "governed"})),
        ),
        "ENC2716",
    );
    // The report lists it, with the call that removes it.
    let r = t.ok(
        &w.non_admin,
        "GET",
        "/v1/security/legacy-service-admins",
        None,
    );
    let combos = r["auditor_combinations"].as_array().unwrap();
    assert_eq!(combos.len(), 1, "{r}");
    assert_eq!(combos[0]["id"], n_id.as_str());
    assert_eq!(combos[0]["roles"], json!(["auditor", "ml_developer"]));
    assert_eq!(combos[0]["remove"]["body"]["role"], "auditor");
    // Once removed, the organization joins.
    t.ok(
        &w.non_admin,
        "POST",
        &format!("/v1/organizations/{NON}/memberships/remove"),
        Some(json!({"principal": n_id, "role": "auditor"})),
    );
    let (s, v) = accept();
    assert_eq!((s, v["status"].as_str()), (200, Some("active")), "{v}");
    // A combination from before separation stays read-only, and is listed
    // with its organization taking part in a governed project.
    let legacy = user(t, &w.tax_admin, TAX, "t-legacy", &["auditor"]);
    legacy_role(t, "t-legacy", TAX, "security_admin");
    let (s, v) = t.call(
        &legacy,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        Some(json!({"public_key": pk(&key(61))})),
    );
    assert_eq!(s, 403, "{v}");
    let r = t.ok(
        &w.tax_admin,
        "GET",
        "/v1/security/legacy-service-admins",
        None,
    );
    let combos = r["auditor_combinations"].as_array().unwrap();
    assert_eq!(combos.len(), 1, "{r}");
    assert_eq!(combos[0]["governed"], true, "{r}");
    assert_eq!(combos[0]["organization"], TAX);
}

/// Organizations outside governed projects keep rc.4's roles: a person
/// holding auditor with another role acts with that role, and bootstrap
/// admins keep admin, operator and auditor (the platform never takes part
/// in a project), reported as combinations to remove later.
#[test]
fn standard_org_role_combinations_unchanged() {
    let Some(w) = common::world() else { return };
    let t = &w.t;
    let multi = user(
        t,
        &w.b_admin,
        "modelco",
        "b-multi",
        &["ml_developer", "auditor"],
    );
    let v = t.ok(
        &multi,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project, "program": EXACT})),
    );
    let (s, j) = t.call_with(
        &multi,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": id(&v), "purpose": "medical-training",
                    "source_assets": [], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", "k-multi")],
    );
    assert_eq!(s, 201, "{j}");
    t.ok(&multi, "GET", "/v1/audit?organization=modelco", None);
    let who = t.ok(&w.platform, "GET", "/v1/whoami", None);
    let roles = who["roles"].to_string();
    for r in ["organization_admin", "operator", "auditor"] {
        assert!(roles.contains(r), "{who}");
    }
    // The platform admin still creates organizations.
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations",
        Some(json!({"id": "later-co", "display_name": "Later"})),
    );
    let r = t.ok(
        &w.platform,
        "GET",
        "/v1/security/legacy-service-admins",
        None,
    );
    let combos = r["auditor_combinations"].as_array().unwrap();
    assert!(
        combos
            .iter()
            .any(|c| c["organization"] == "platform" && c["governed"] == false),
        "{r}"
    );
    assert!(
        combos
            .iter()
            .any(|c| c["organization"] == "modelco" && c["governed"] == false),
        "{r}"
    );
}

// --- views ------------------------------------------------------------------------

/// Every reading route of the router, as benefits (member, submitter,
/// recipient), another member, the auditor organization's people, a
/// member's auditor, an outsider and the evaluator: no reply carries tax's
/// storage or key references, tax's people (IDs or identity subjects) or
/// its governance key's secret; and none but benefits' carries benefits'
/// people.
#[test]
fn governance_views_canary_scan() {
    let Some(w) = world() else { return };
    let tax_people: Vec<String> = [&w.tax_owner, &w.tax_sec1, &w.tax_sec2, &w.tax_admin]
        .iter()
        .map(|p| w.principal(p))
        .collect();
    let secret = hex(&w.tax_key.to_bytes());
    let gets: Vec<&str> = ROUTES
        .iter()
        .filter(|(m, _)| *m == "GET")
        .map(|(_, p)| *p)
        .collect();
    let viewers: Vec<(&str, &As)> = vec![
        ("benefits", &w.ben_dev),
        ("benefits admin", &w.ben_admin),
        ("benefits auditor", &w.ben_auditor),
        ("other member", &w.other_dev),
        ("other admin", &w.other_admin),
        ("auditor organization", &w.aud_auditor),
        ("auditor organization admin", &w.aud_admin),
        ("outsider", &w.non_dev),
        ("evaluator", &w.evaluator.service),
    ];
    let mut scanned = 0;
    for pattern in &gets {
        let urls = w
            .reads(pattern)
            .unwrap_or_else(|| panic!("add GET {pattern} to the canary scan's route table"));
        for url in urls {
            for (name, who) in &viewers {
                let (s, v) = w.t.call(who, "GET", &url, None);
                // A grant (the submitter's and the evaluator's only) carries
                // the binding, whose broker map is keyed by source version:
                // no key reference crosses organizations there either.
                if v.pointer("/grant/governance/binding").is_some() {
                    assert!(
                        name.starts_with("benefits") || *name == "evaluator",
                        "GET {url} as {name} carries a grant"
                    );
                }
                let text = v.to_string();
                let mut canaries: Vec<&str> =
                    vec![STORAGE_CANARY, KEY_REF_CANARY, SUBJECT_CANARY, &secret];
                canaries.extend(tax_people.iter().map(String::as_str));
                if !name.starts_with("benefits") {
                    canaries.push(&w.ben_user);
                    canaries.push("b-dev");
                }
                for c in canaries {
                    assert!(
                        !text.contains(c),
                        "GET {url} as {name} ({s}) leaks {c:?}: {text}"
                    );
                }
                scanned += 1;
            }
        }
    }
    assert!(scanned > 100, "{scanned}");
    // The scan saw real records, not only refusals.
    let a = w.t.ok(
        &w.aud_auditor,
        "GET",
        &format!("/v1/authorizations/{}", w.authorization),
        None,
    );
    assert_eq!(a["body"]["approvals"].as_array().unwrap().len(), 2, "{a}");
    let j = w.t.ok(
        &w.evaluator.service,
        "GET",
        &format!("/v1/jobs/{}", w.job),
        None,
    );
    assert_eq!(
        j.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["grant", "id"],
        "an evaluator sees a governed job's grant and nothing else: {j}"
    );
    // Tax's security admin revokes the authorization, failing benefits'
    // job: benefits' own trail records it without naming tax's person.
    w.t.ok(
        &w.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{}/revoke", w.authorization),
        Some(json!({"reason": "withdrawn"})),
    );
    let trail =
        w.t.ok(
            &w.ben_admin,
            "GET",
            &format!("/v1/audit?organization={BEN}"),
            None,
        )
        .to_string();
    assert!(trail.contains("job.failed"), "{trail}");
    assert!(trail.contains(&format!("{TAX}/user")), "{trail}");
    assert!(trail.contains(&w.ben_user), "its own people keep their IDs");
    for c in &tax_people {
        assert!(!trail.contains(c.as_str()), "{c} in {trail}");
    }
}

/// The shared view of the project, its purposes, the owner's
/// authorization, the job and the project's audit events is the same bytes
/// for every organization that does not own the record.
#[test]
fn shared_view_identical_for_members() {
    let Some(w) = world() else { return };
    let p = &w.project;
    let same = |url: &str, viewers: &[&As]| {
        let first = w.bytes(viewers[0], url);
        assert_eq!(first.0, 200, "{url}: {}", String::from_utf8_lossy(&first.1));
        for v in &viewers[1..] {
            let b = w.bytes(v, url);
            assert_eq!(
                b,
                first,
                "GET {url} differs: {} vs {}",
                String::from_utf8_lossy(&b.1),
                String::from_utf8_lossy(&first.1)
            );
        }
        first.1
    };
    let everyone = [
        &w.tax_admin,
        &w.tax_sec1,
        &w.ben_dev,
        &w.other_dev,
        &w.aud_auditor,
        &w.aud_admin,
    ];
    let project = same(&format!("/v1/projects/{p}"), &everyone);
    let project: Value = serde_json::from_slice(&project).unwrap();
    assert_eq!(project["auditors"], json!([AUD]), "{project}");
    same(&format!("/v1/projects/{p}/purposes"), &everyone);
    same(&format!("/v1/purposes/{}", w.purpose), &everyone);
    // Tax owns the authorization; benefits submitted the job.
    let a = same(
        &format!("/v1/authorizations/{}", w.authorization),
        &[&w.ben_dev, &w.ben_admin, &w.other_dev, &w.aud_auditor],
    );
    let a: Value = serde_json::from_slice(&a).unwrap();
    assert!(a.get("signed").is_none(), "{a}");
    for x in a["body"]["approvals"].as_array().unwrap() {
        assert!(x["approver"].as_str().unwrap().starts_with("psn_"), "{x}");
        assert_eq!(x["organization"], TAX);
        assert!(x.get("approver_subject").is_none(), "{x}");
    }
    let j = same(
        &format!("/v1/jobs/{}", w.job),
        &[&w.tax_sec1, &w.tax_owner, &w.other_dev, &w.aud_auditor],
    );
    let j: Value = serde_json::from_slice(&j).unwrap();
    assert!(j["grant"].is_null() && j["evaluator_url"].is_null(), "{j}");
    assert!(j["governance_id"].is_string(), "{j}");
    assert_eq!(j["initiated_by"], format!("{BEN}/user"), "{j}");
    // The submitter's own view stays full.
    let own =
        w.t.ok(&w.ben_dev, "GET", &format!("/v1/jobs/{}", w.job), None);
    assert_eq!(own["initiated_by"], w.ben_user.as_str(), "{own}");
    // The project's audit events, to every reader of a trail.
    let e = same(
        &format!("/v1/audit?project={p}"),
        &[
            &w.tax_admin,
            &w.ben_admin,
            &w.other_admin,
            &w.aud_auditor,
            &w.ben_auditor,
        ],
    );
    let e: Value = serde_json::from_slice(&e).unwrap();
    assert!(
        e.as_array()
            .unwrap()
            .iter()
            .any(|x| x["action"] == "authorization.activated"),
        "{e}"
    );
    // Pseudonyms are per project: the same approver elsewhere is another.
    let psn = &a["body"]["approvals"][0]["approver"];
    let owner = w.principal(&w.tax_owner);
    let sec = w.principal(&w.tax_sec1);
    let key = &w.t.control.pseudonyms;
    assert!(
        [&owner, &sec].iter().any(|u| *psn == key.pseudonym(p, u)),
        "{psn}"
    );
    assert!([&owner, &sec]
        .iter()
        .all(|u| *psn != key.pseudonym("prj_other", u)));
}

/// The unkeyed SHA-256 pseudonym of the first design: anyone who learns a
/// principal ID could confirm it against a shared view.
fn unkeyed(project: &str, principal: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"encompute.approver-pseudonym.v1\0");
    h.update(project.as_bytes());
    h.update([0u8]);
    h.update(principal.as_bytes());
    format!("psn_{}", hex(&h.finalize()))
}

/// Approver pseudonyms are keyed (HMAC under a key only the control plane
/// holds, derived from its signing key): someone who learns an approver's
/// principal ID cannot confirm it against a shared view, one person gets
/// unlinkable pseudonyms in two projects, and the pseudonyms survive a
/// control-plane restart.
#[test]
fn pseudonym_is_keyed() {
    let Some(w) = world() else { return };
    let url = format!("/v1/authorizations/{}", w.authorization);
    let who = w.aud_auditor.clone();
    let shown = |t: &T| -> Vec<String> {
        t.ok(&who, "GET", &url, None)["body"]["approvals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["approver"].as_str().unwrap().to_owned())
            .collect()
    };
    let before = shown(&w.t);
    assert_eq!(before.len(), 2);
    let approvers = [w.principal(&w.tax_owner), w.principal(&w.tax_sec1)];
    for u in &approvers {
        let guess = unkeyed(&w.project, u);
        assert!(
            !before.contains(&guess),
            "{u}'s pseudonym is its unkeyed hash"
        );
        // Unlinkable across projects, for the same key.
        let key = &w.t.control.pseudonyms;
        assert_ne!(key.pseudonym(&w.project, u), key.pseudonym("prj_other", u));
        assert!(before.contains(&key.pseudonym(&w.project, u)));
    }
    // Another control plane's key gives other pseudonyms.
    let other = encompute_control::views::PseudonymKey::derive(&[1; 32]);
    assert!(approvers
        .iter()
        .all(|u| !before.contains(&other.pseudonym(&w.project, u))));
    // Stable across a restart (the key comes from the stable signing key).
    let W { t, .. } = w;
    let t = t.restarted();
    assert_eq!(shown(&t), before);
}

/// Another organization's IDs answer exactly as unknown ones: not found,
/// the same message, whether guessed on a read or a write; and filters
/// never widen what a caller sees.
#[test]
fn id_guessing_is_not_found() {
    let Some(w) = world() else { return };
    let zeros = "0".repeat(64);
    let cases = [
        (
            "GET",
            "/v1/projects/{}",
            w.project.clone(),
            "prj_0000000000000000",
        ),
        ("GET", "/v1/jobs/{}", w.job.clone(), "job_0000000000000000"),
        ("GET", "/v1/trust/{}", w.job.clone(), "job_0000000000000000"),
        (
            "GET",
            "/v1/authorizations/{}",
            w.authorization.clone(),
            "atz_0000000000000000",
        ),
        ("GET", "/v1/purposes/{}", w.purpose.clone(), zeros.as_str()),
        (
            "GET",
            "/v1/assets/{}",
            w.asset.clone(),
            "ast_0000000000000000",
        ),
        (
            "POST",
            "/v1/authorizations/{}/approve",
            w.authorization.clone(),
            "atz_0000000000000000",
        ),
        (
            "POST",
            "/v1/jobs/{}/approve",
            w.job.clone(),
            "job_0000000000000000",
        ),
        (
            "POST",
            "/v1/purposes/{}/retire",
            w.purpose.clone(),
            zeros.as_str(),
        ),
    ];
    for who in [&w.non_dev, &w.non_admin] {
        for (m, pattern, real, fake) in &cases {
            let body = (pattern.contains("authorizations") && *m == "POST")
                .then(|| json!({"role": "data_owner"}));
            let (s1, v1) = w.t.call(who, m, &pattern.replace("{}", real), body.clone());
            let (s2, v2) = w.t.call(who, m, &pattern.replace("{}", fake), body);
            assert_eq!((s1, s2), (404, 404), "{m} {pattern}: {v1} / {v2}");
            assert_eq!(code(&v1), code(&v2));
            assert_eq!(
                v1["message"].as_str().unwrap().replace(real.as_str(), "ID"),
                v2["message"].as_str().unwrap().replace(fake, "ID"),
                "{m} {pattern}"
            );
        }
    }
    // Filters: another project's jobs and events are not listed.
    let v = w.t.ok(
        &w.non_dev,
        "GET",
        &format!("/v1/jobs?project={}", w.project),
        None,
    );
    assert_eq!(v, json!([]));
    let (s, _) = w.t.call(
        &w.non_admin,
        "GET",
        &format!("/v1/audit?project={}", w.project),
        None,
    );
    assert_eq!(s, 404);
    let (s, _) = w.t.call(
        &w.aud_auditor,
        "GET",
        &format!("/v1/audit?project={}&organization={TAX}", w.project),
        None,
    );
    assert_eq!(s, 400);
    let (s, _) = w.t.call(
        &w.aud_auditor,
        "GET",
        &format!("/v1/audit?organization={TAX}"),
        None,
    );
    assert_eq!(s, 404);
    // A member not named by the authorization still does not see the source.
    let (s, _) = w.t.call(
        &w.other_dev,
        "GET",
        &format!("/v1/assets/{}", w.asset),
        None,
    );
    assert_eq!(s, 404);
}

/// The auditor organization reads the project's shared records: the
/// project, purposes, the owner's signed authorization (approvers as
/// pseudonyms), the source version it names (never its storage or key),
/// its lineage, the job and its trust report, and the project's audit
/// events; its own trail records that it joined as auditor.
#[test]
fn auditor_sees_audit_view() {
    let Some(w) = world() else { return };
    let (t, a) = (&w.t, &w.aud_auditor);
    let p = t.ok(a, "GET", &format!("/v1/projects/{}", w.project), None);
    assert_eq!(p["members"], json!([BEN, OTHER, TAX]), "{p}");
    assert_eq!(p["auditors"], json!([AUD]), "{p}");
    let listed = t.ok(a, "GET", "/v1/projects", None);
    assert!(listed.to_string().contains(&w.project), "{listed}");
    let purposes = t.ok(
        a,
        "GET",
        &format!("/v1/projects/{}/purposes", w.project),
        None,
    );
    assert_eq!(purposes.as_array().unwrap().len(), 1, "{purposes}");
    let z = t.ok(
        a,
        "GET",
        &format!("/v1/authorizations/{}", w.authorization),
        None,
    );
    assert_eq!(z["status"], "active", "{z}");
    assert_eq!(z["usable"], true, "{z}");
    assert!(z["authorization_id"].is_string(), "{z}");
    let approvals = z["body"]["approvals"].as_array().unwrap();
    let roles: Vec<&str> = approvals
        .iter()
        .map(|x| x["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles.len(), 2);
    assert!(roles.contains(&"data_owner") && roles.contains(&"security_admin"));
    let s = t.ok(a, "GET", &format!("/v1/assets/{}", w.asset), None);
    assert_eq!(s["organization"], TAX, "{s}");
    assert!(
        s.get("storage_uri").is_none() && s.get("key_ref").is_none(),
        "{s}"
    );
    t.ok(a, "GET", &format!("/v1/assets/{}/lineage", w.asset), None);
    let j = t.ok(a, "GET", &format!("/v1/jobs/{}", w.job), None);
    assert_eq!(j["purpose_id"], w.purpose.as_str(), "{j}");
    let jobs = t.ok(a, "GET", &format!("/v1/jobs?project={}", w.project), None);
    assert_eq!(jobs.as_array().unwrap().len(), 1, "{jobs}");
    t.ok(a, "GET", &format!("/v1/trust/{}", w.job), None);
    let e = t.ok(a, "GET", &format!("/v1/audit?project={}", w.project), None);
    let actions: Vec<&str> = e
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["action"].as_str().unwrap())
        .collect();
    for want in [
        "project.created",
        "purpose.accepted",
        "authorization.approved",
        "authorization.activated",
        "job.created",
    ] {
        assert!(actions.contains(&want), "{want} missing: {actions:?}");
    }
    for x in e.as_array().unwrap() {
        assert!(
            x.get("request_id").is_none() && x.get("hash").is_none(),
            "{x}"
        );
    }
    let own = t.ok(a, "GET", &format!("/v1/audit?organization={AUD}"), None);
    assert!(
        own.as_array()
            .unwrap()
            .iter()
            .any(|x| x["action"] == "project.joined" && x["refs"]["participation"] == "auditor"),
        "{own}"
    );
    // Reading changes nothing, and writing is refused.
    let (s, _) = t.call(
        a,
        "POST",
        &format!("/v1/authorizations/{}/revoke", w.authorization),
        Some(json!({"reason": "audit"})),
    );
    assert_eq!(s, 403);
    let _ = (&w.platform, &w.tax_sec2);
}
