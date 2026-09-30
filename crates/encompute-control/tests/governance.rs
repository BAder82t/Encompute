//! Governed projects (public-sector governance, phase 1): the mode is
//! chosen at creation and immutable; governance keys, purposes and owner
//! authorizations take four eyes of distinct people of the organization
//! (never a service account, never the same person twice, never a role
//! held from another organization); each organization accepts a purpose
//! with its governance key; an authorization is active only with a valid
//! owner signature under the organization's active governance key; dataset
//! versions are immutable. Standard projects behave as before.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use common::*;
use encompute_control::authn::DEV_ISSUER;
use encompute_trust::authz::{AuthorizationV2, PurposeAcceptance, RevocationV2};
use encompute_verification::governance::{ProgramRef, ReleaseClass};
use encompute_verification::{hex, ServiceSigner};

const TAX: &str = "tax-agency";
const BEN: &str = "benefits-agency";

struct G {
    t: T,
    platform: As,
    tax_admin: As,
    tax_sec1: As,
    tax_sec2: As,
    tax_owner: As,
    tax_owner2: As,
    tax_auditor: As,
    tax_dev: As,
    ben_admin: As,
    ben_sec1: As,
    ben_sec2: As,
    robot: As,
    project: String,
}

fn now() -> u64 {
    encompute_verification::service::now()
}

fn gov_world() -> Option<G> {
    let t = setup()?;
    t.control
        .bootstrap(DEV_ISSUER, "platform-admin", None)
        .unwrap();
    let platform = As::User("platform-admin".into());
    for (org, admin) in [(TAX, "t-admin"), (BEN, "b-admin"), ("other-co", "c-admin")] {
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
    let tax_owner2 = user(&t, &tax_admin, TAX, "t-owner2", &["data_owner"]);
    let tax_auditor = user(
        &t,
        &tax_admin,
        TAX,
        "t-auditor",
        &["auditor", "security_admin"],
    );
    let tax_dev = user(&t, &tax_admin, TAX, "t-dev", &["ml_developer"]);
    let ben_sec1 = user(&t, &ben_admin, BEN, "b-sec1", &["security_admin"]);
    let ben_sec2 = user(&t, &ben_admin, BEN, "b-sec2", &["security_admin"]);
    // An automation key with the organization's admin and owner roles: a
    // second pair of eyes an admin could hold alone.
    let signer = Arc::new(ServiceSigner::from_seed("tax-robot", &[9; 32]).unwrap());
    t.ok(
        &tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts"),
        Some(
            json!({"id": "tax-robot", "kind": "automation", "public_key": signer.public_key_hex(),
                    "roles": ["organization_admin", "data_owner"]}),
        ),
    );
    let robot = As::Service(signer);
    let p = t.ok(
        &tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "benefits-eligibility",
                    "governance": "governed", "organizations": [BEN]})),
    );
    assert_eq!(p["governance"], "governed", "{p}");
    let project = p["id"].as_str().unwrap().to_owned();
    // The invited organization's admin accepts.
    t.ok(
        &ben_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": BEN})),
    );
    Some(G {
        t,
        platform,
        tax_admin,
        tax_sec1,
        tax_sec2,
        tax_owner,
        tax_owner2,
        tax_auditor,
        tax_dev,
        ben_admin,
        ben_sec1,
        ben_sec2,
        robot,
        project,
    })
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk(k: &SigningKey) -> String {
    hex(&k.verifying_key().to_bytes())
}

/// The server's message of a database error (a trigger's refusal).
fn db_msg(e: &postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string())
}

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

/// Asserts `(status, body)` is a refusal with `c`.
fn refused(r: (u16, Value), c: &str) {
    assert!(r.0 >= 400, "expected {c}, got {} {}", r.0, r.1);
    assert_eq!(code(&r.1), c, "{} {}", r.0, r.1);
}

impl G {
    /// Proposes and approves (by a different security admin) `k` as
    /// `org`'s governance key.
    fn register_key(&self, org: &str, proposer: &As, approver: &As, k: &SigningKey) -> String {
        let v = self.t.ok(
            proposer,
            "POST",
            &format!("/v1/organizations/{org}/governance-keys"),
            Some(json!({"public_key": pk(k), "kms_key_ref": "vault:transit/governance"})),
        );
        let id = v["id"].as_str().unwrap().to_owned();
        let v = self.t.ok(
            approver,
            "POST",
            &format!("/v1/organizations/{org}/governance-keys/{id}/approve"),
            None,
        );
        assert_eq!(v["status"], "active", "{v}");
        id
    }

    fn purpose_request(&self, name: &str) -> Value {
        json!({"organization": TAX, "name": name, "description": "Eligibility for housing benefit",
               "modes": ["aggregate"], "allowed_release_classes": ["boolean-only"],
               "recipients": [BEN], "valid_from": now() - 60, "valid_until": now() + 3600})
    }

    /// A purpose proposed by tax's first security admin and approved by the
    /// second.
    fn active_purpose(&self, name: &str) -> String {
        let v = self.t.ok(
            &self.tax_sec1,
            "POST",
            &format!("/v1/projects/{}/purposes", self.project),
            Some(self.purpose_request(name)),
        );
        let id = v["id"].as_str().unwrap().to_owned();
        let v = self.t.ok(
            &self.tax_sec2,
            "POST",
            &format!("/v1/purposes/{id}/approve"),
            None,
        );
        assert_eq!(v["status"], "active", "{v}");
        id
    }

    fn accept(&self, who: &As, org: &str, purpose: &str, k: &SigningKey) -> (u16, Value) {
        let signed = PurposeAcceptance {
            version: 1,
            organization: org.into(),
            project: self.project.clone(),
            purpose_id: purpose.into(),
            accepted_at: now(),
        }
        .sign(k)
        .unwrap();
        self.t.call(
            who,
            "POST",
            &format!("/v1/purposes/{purpose}/accept"),
            Some(json!({"acceptance": signed})),
        )
    }

    /// A version of tax's income series.
    fn version(&self, label: &str, digest: char) -> String {
        let v = self.t.ok(
            &self.tax_owner,
            "POST",
            "/v1/assets",
            Some(json!({"organization": TAX, "kind": "dataset", "name": format!("income@{label}"),
                        "series": "income", "version": label, "digest": digest.to_string().repeat(64)})),
        );
        v["version_id"].as_str().unwrap().to_owned()
    }

    fn body(&self, purpose: &str, version: &str) -> AuthorizationV2 {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        AuthorizationV2 {
            version: 2,
            party: TAX.into(),
            project: self.project.clone(),
            purpose_id: purpose.into(),
            asset_version_id: version.into(),
            asset_digest_commitment: "d".repeat(64),
            program: ProgramRef::Program {
                program_id: "a".repeat(64),
            },
            policy_id: "b".repeat(64),
            privacy_policy_id: None,
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

    fn propose(&self, who: &As, body: &AuthorizationV2) -> (u16, Value) {
        self.t.call(
            who,
            "POST",
            "/v1/authorizations",
            Some(json!({"body": body})),
        )
    }

    fn approve(&self, who: &As, id: &str, role: &str) -> (u16, Value) {
        self.t.call(
            who,
            "POST",
            &format!("/v1/authorizations/{id}/approve"),
            Some(json!({"role": role})),
        )
    }

    /// The body to sign (with its approvals), as the control plane shows it.
    fn to_sign(&self, id: &str) -> AuthorizationV2 {
        let v = self.t.ok(
            &self.tax_sec1,
            "GET",
            &format!("/v1/authorizations/{id}"),
            None,
        );
        serde_json::from_value(v["body"].clone()).unwrap()
    }

    fn upload(&self, who: &As, id: &str, body: AuthorizationV2, k: &SigningKey) -> (u16, Value) {
        let s = body.sign(k).unwrap();
        self.t.call(
            who,
            "POST",
            &format!("/v1/authorizations/{id}/signature"),
            Some(json!({"public_key": s.public_key, "signature": s.signature})),
        )
    }

    /// An authorization proposed, approved by a data owner and a security
    /// admin, and signed under `k`: (row ID, AuthorizationId).
    fn activated(&self, purpose: &str, version: &str, k: &SigningKey) -> (String, String) {
        let v = self.t.ok(
            &self.tax_owner,
            "POST",
            "/v1/authorizations",
            Some(json!({"body": self.body(purpose, version)})),
        );
        let id = v["id"].as_str().unwrap().to_owned();
        assert_eq!(self.approve(&self.tax_owner, &id, "data_owner").0, 200);
        let (_, v) = self.approve(&self.tax_sec1, &id, "security_admin");
        assert_eq!(v["status"], "approved", "{v}");
        let (s, v) = self.upload(&self.tax_sec1, &id, self.to_sign(&id), k);
        assert_eq!(s, 200, "{v}");
        (id, v["authorization_id"].as_str().unwrap().to_owned())
    }

    /// A purpose, accepted by tax under `k`, and a version: what an
    /// authorization needs.
    fn ready(&self, k: &SigningKey) -> (String, String) {
        self.register_key(TAX, &self.tax_admin, &self.tax_sec1, k);
        let purpose = self.active_purpose("benefits-eligibility");
        let (s, v) = self.accept(&self.tax_sec2, TAX, &purpose, k);
        assert_eq!(s, 200, "{v}");
        (purpose, self.version("2026-q3", 'c'))
    }
}

#[test]
fn a_governed_project_invites_its_organizations_and_its_mode_is_immutable() {
    let Some(g) = gov_world() else { return };
    let v = g.t.ok(
        &g.tax_admin,
        "GET",
        &format!("/v1/projects/{}", g.project),
        None,
    );
    assert_eq!(v["governance"], "governed");
    assert_eq!(v["members"], json!([BEN, TAX]), "{v}");
    let list = g.t.ok(&g.ben_admin, "GET", "/v1/projects", None);
    assert_eq!(list[0]["governance"], "governed", "{list}");

    // Invitations need an acceptance: other-co was invited, not added.
    let p = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(
            json!({"organization": TAX, "name": "second", "governance": "governed",
                    "organizations": ["other-co", "no-such-org"]}),
        ),
    );
    assert_eq!(p["members"], json!([TAX]));
    assert_eq!(p["invited"], json!(["no-such-org", "other-co"]), "{p}");
    let v = g.t.ok(
        &g.tax_admin,
        "GET",
        &format!("/v1/projects/{}", p["id"].as_str().unwrap()),
        None,
    );
    assert_eq!(
        v["invited"],
        json!(["other-co"]),
        "unknown organizations are not revealed: {v}"
    );

    // Only a person who administers the organization creates one.
    let governed =
        |name: &str| json!({"organization": TAX, "name": name, "governance": "governed"});
    let (s, _) =
        g.t.call(&g.tax_dev, "POST", "/v1/projects", Some(governed("by-dev")));
    assert_eq!(s, 403);
    refused(
        g.t.call(&g.robot, "POST", "/v1/projects", Some(governed("by-robot"))),
        "ENC2707",
    );
    let (s, _) = g.t.call(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "x", "governance": "sovereign"})),
    );
    assert_eq!(s, 400, "unknown modes are refused");

    // Nothing changes the mode, not even the database's owner.
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    let e = c
        .execute(
            "UPDATE projects SET governance = 'standard' WHERE id = $1",
            &[&g.project],
        )
        .unwrap_err();
    assert!(db_msg(&e).contains("immutable"), "{e}");
}

#[test]
fn standard_projects_are_unchanged() {
    let Some(g) = gov_world() else { return };
    let p = g.t.ok(
        &g.tax_dev,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "plain"})),
    );
    assert_eq!(p["governance"], "standard");
    assert_eq!(p["members"], json!([TAX]));
    let id = p["id"].as_str().unwrap();
    // v1 sharing works there as before, and not in a governed project,
    // where only owner-signed authorizations share.
    let a = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(json!({"organization": TAX, "kind": "dataset", "name": "plain-data", "digest": "e".repeat(64)})),
    );
    assert!(a.get("version_id").is_none(), "{a}");
    let asset = a["id"].as_str().unwrap();
    g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{asset}/approvals"),
        Some(json!({"project": id, "purpose": "stats"})),
    );
    refused(
        g.t.call(
            &g.tax_owner,
            "POST",
            &format!("/v1/assets/{asset}/approvals"),
            Some(json!({"project": g.project, "purpose": "stats"})),
        ),
        "ENC2701",
    );
    // Governance routes refuse standard projects.
    let (s, _) = g.t.call(
        &g.tax_sec1,
        "POST",
        &format!("/v1/projects/{id}/purposes"),
        Some(g.purpose_request("stats")),
    );
    assert_eq!(s, 409);
    // A standard asset is not a dataset version: it stays revocable and
    // its rows are not frozen.
    g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{asset}/revoke"),
        None,
    );
}

#[test]
fn a_governance_key_needs_a_second_person_who_is_a_security_admin() {
    let Some(g) = gov_world() else { return };
    let k = key(1);
    let url = format!("/v1/organizations/{TAX}/governance-keys");
    // Proposed by a person who administers the organization; never a
    // service account, even with the admin role.
    refused(
        g.t.call(&g.robot, "POST", &url, Some(json!({"public_key": pk(&k)}))),
        "ENC2707",
    );
    let (s, _) = g.t.call(
        &g.tax_dev,
        "POST",
        &url,
        Some(json!({"public_key": pk(&k)})),
    );
    assert_eq!(s, 403);
    let (s, _) = g.t.call(
        &g.ben_admin,
        "POST",
        &url,
        Some(json!({"public_key": pk(&k)})),
    );
    assert_eq!(s, 404, "another organization does not even see it");
    let (s, _) = g.t.call(
        &g.tax_admin,
        "POST",
        &url,
        Some(json!({"public_key": "zz"})),
    );
    assert_eq!(s, 400);
    let v = g.t.ok(
        &g.tax_sec1,
        "POST",
        &url,
        Some(json!({"public_key": pk(&k)})),
    );
    assert_eq!(v["status"], "proposed");
    assert_eq!(v["key_id"].as_str().unwrap().len(), 64);
    let id = v["id"].as_str().unwrap();
    let approve = format!("{url}/{id}/approve");
    // Not by the proposer, not by an auditor, not by another
    // organization's security admin, not by a service account.
    refused(g.t.call(&g.tax_sec1, "POST", &approve, None), "ENC2707");
    let (s, _) = g.t.call(&g.tax_auditor, "POST", &approve, None);
    assert_eq!(s, 403, "an auditor is read-only, whatever else it holds");
    let (s, _) = g.t.call(&g.ben_sec1, "POST", &approve, None);
    assert_eq!(s, 404);
    refused(g.t.call(&g.robot, "POST", &approve, None), "ENC2707");
    // A person with security_admin granted in this organization but homed
    // in another does not count here.
    let who = g.t.ok(&g.ben_sec2, "GET", "/v1/whoami", None);
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    c.execute(
        "INSERT INTO memberships (principal_id, organization_id, role) VALUES ($1, $2, 'security_admin')",
        &[&who["id"].as_str().unwrap(), &TAX],
    )
    .unwrap();
    let (s, v) = g.t.call(&g.ben_sec2, "POST", &approve, None);
    assert_eq!(s, 403, "{v}");
    // A different person who is a security admin here.
    let v = g.t.ok(&g.tax_sec2, "POST", &approve, None);
    assert_eq!(v["status"], "active");
    // One active key per organization.
    let v = g.t.ok(
        &g.tax_admin,
        "POST",
        &url,
        Some(json!({"public_key": pk(&key(2))})),
    );
    let (s, _) = g.t.call(
        &g.tax_sec2,
        "POST",
        &format!("{url}/{}/approve", v["id"].as_str().unwrap()),
        None,
    );
    assert_eq!(s, 409);
    // Listed to its organization only; never the private key.
    let l = g.t.ok(&g.tax_owner, "GET", &url, None);
    assert_eq!(l.as_array().unwrap().len(), 2, "{l}");
    let (s, _) = g.t.call(&g.ben_admin, "GET", &url, None);
    assert_eq!(s, 404);
    // Revoked by a person; a revoked key stays revoked.
    refused(
        g.t.call(&g.robot, "POST", &format!("{url}/{id}/revoke"), None),
        "ENC2707",
    );
    let v =
        g.t.ok(&g.tax_sec1, "POST", &format!("{url}/{id}/revoke"), None);
    assert_eq!(v["status"], "revoked");
    let (s, _) = g.t.call(&g.tax_sec2, "POST", &approve, None);
    assert_eq!(s, 409);
    let e = c
        .execute(
            "UPDATE governance_keys SET status = 'active' WHERE id = $1",
            &[&id],
        )
        .unwrap_err();
    assert!(db_msg(&e).contains("stays revoked"), "{e}");
}

#[test]
fn a_purpose_takes_two_people_and_each_organization_accepts_it_with_its_key() {
    let Some(g) = gov_world() else { return };
    let (tk, bk) = (key(1), key(2));
    let url = format!("/v1/projects/{}/purposes", g.project);
    // Proposed by a person who is a security admin of a member.
    refused(
        g.t.call(&g.robot, "POST", &url, Some(g.purpose_request("p"))),
        "ENC2707",
    );
    let (s, _) =
        g.t.call(&g.tax_owner, "POST", &url, Some(g.purpose_request("p")));
    assert_eq!(s, 403);
    let mut bad = g.purpose_request("p");
    bad["valid_until"] = bad["valid_from"].clone();
    let (s, _) = g.t.call(&g.tax_sec1, "POST", &url, Some(bad));
    assert_eq!(s, 400);
    let v = g.t.ok(
        &g.tax_sec1,
        "POST",
        &url,
        Some(g.purpose_request("benefits")),
    );
    let id = v["id"].as_str().unwrap().to_owned();
    assert_eq!(v["status"], "proposed");
    // Its ID is the content address of the document it shows.
    let doc: encompute_verification::governance::Purpose =
        serde_json::from_value(v["purpose"].clone()).unwrap();
    assert_eq!(doc.id().hex(), id);
    assert_eq!(doc.project_id, g.project);
    // The same proposal again is a conflict (a new revision is not).
    let (s, _) = g.t.call(
        &g.tax_sec1,
        "POST",
        &url,
        Some(g.purpose_request("benefits")),
    );
    assert_eq!(s, 409);

    let approve = format!("/v1/purposes/{id}/approve");
    refused(g.t.call(&g.tax_sec1, "POST", &approve, None), "ENC2707");
    refused(g.t.call(&g.robot, "POST", &approve, None), "ENC2707");
    let (s, _) = g.t.call(&g.ben_sec1, "POST", &approve, None);
    assert_eq!(
        s, 403,
        "the proposing organization's security admins approve"
    );
    // Not accepted before it is active.
    g.register_key(BEN, &g.ben_admin, &g.ben_sec1, &bk);
    refused(g.accept(&g.ben_sec2, BEN, &id, &bk), "ENC2702");
    let v = g.t.ok(&g.tax_sec2, "POST", &approve, None);
    assert_eq!(v["status"], "active");

    // Each organization accepts with its own active governance key.
    refused(g.accept(&g.tax_sec1, TAX, &id, &tk), "ENC2708"); // tax has none yet
    refused(g.accept(&g.ben_sec2, BEN, &id, &tk), "ENC2701"); // signed by another key
    let (s, _) = g.accept(&g.tax_sec1, BEN, &id, &bk);
    assert_eq!(s, 404, "for another organization");
    let (s, v) = g.accept(&g.ben_sec2, BEN, &id, &bk);
    assert_eq!(s, 200, "{v}");
    g.register_key(TAX, &g.tax_admin, &g.tax_sec1, &tk);
    let (s, v) = g.accept(&g.tax_sec2, TAX, &id, &tk);
    assert_eq!(s, 200, "{v}");
    let v =
        g.t.ok(&g.ben_sec1, "GET", &format!("/v1/purposes/{id}"), None);
    assert_eq!(v["accepted_by"], json!([BEN, TAX]), "{v}");
    let l = g.t.ok(&g.tax_owner, "GET", &url, None);
    assert_eq!(l[0]["id"], id.as_str());
    let (s, _) = g.t.call(
        &As::User("c-admin".into()),
        "GET",
        &format!("/v1/purposes/{id}"),
        None,
    );
    assert_eq!(s, 404, "a non-member does not see it");

    // Retired by a person of the proposing organization; final.
    refused(
        g.t.call(&g.robot, "POST", &format!("/v1/purposes/{id}/retire"), None),
        "ENC2707",
    );
    let v = g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{id}/retire"),
        None,
    );
    assert_eq!(v["status"], "retired");
    let (s, _) = g.t.call(&g.tax_sec2, "POST", &approve, None);
    assert_eq!(s, 409);
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    let e = c
        .execute(
            "UPDATE purposes SET status = 'active' WHERE id = $1",
            &[&id],
        )
        .unwrap_err();
    assert!(db_msg(&e).contains("stays retired"), "{e}");
}

#[test]
fn an_authorization_is_active_only_with_four_eyes_and_a_valid_owner_signature() {
    let Some(g) = gov_world() else { return };
    let k = key(1);
    let (purpose, version) = g.ready(&k);
    let body = g.body(&purpose, &version);
    // Proposed by a person of the owner.
    refused(g.propose(&g.robot, &body), "ENC2707");
    let (s, _) = g.propose(&g.ben_sec1, &body);
    assert_eq!(s, 404);
    let mut approved_body = body.clone();
    approved_body.approvals = vec![];
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": approved_body})),
    );
    let id = v["id"].as_str().unwrap().to_owned();
    assert_eq!(v["status"], "proposed");

    // Not active before four eyes.
    refused(g.upload(&g.tax_sec1, &id, g.to_sign(&id), &k), "ENC2707");
    let (s, v) = g.approve(&g.tax_owner, &id, "data_owner");
    assert_eq!(s, 200, "{v}");
    // The same person again (in another role) is one approver.
    refused(g.approve(&g.tax_owner, &id, "data_owner"), "ENC2707");
    // A service account never counts; nor a role the approver lacks.
    refused(g.approve(&g.robot, &id, "data_owner"), "ENC2707");
    let (s, _) = g.approve(&g.tax_owner2, &id, "security_admin");
    assert_eq!(s, 403);
    // Two data owners do not make the security admin the rule requires.
    let (s, v) = g.approve(&g.tax_owner2, &id, "data_owner");
    assert_eq!((s, v["status"].as_str()), (200, Some("proposed")), "{v}");
    refused(g.upload(&g.tax_sec1, &id, g.to_sign(&id), &k), "ENC2707");
    let (s, v) = g.approve(&g.tax_sec1, &id, "security_admin");
    assert_eq!((s, v["status"].as_str()), (200, Some("approved")), "{v}");

    // The approvals are statements over the proposed body.
    let doc = g.to_sign(&id);
    assert_eq!(doc.approvals.len(), 3);
    doc.check_approvals().unwrap();
    assert_eq!(doc.unapproved(), body);

    // A signature by another key, over another body, or malformed: refused.
    refused(g.upload(&g.tax_sec1, &id, doc.clone(), &key(7)), "ENC2701");
    let mut tampered = doc.clone();
    tampered.valid_until += 86_400;
    refused(g.upload(&g.tax_sec1, &id, tampered, &k), "ENC2701");
    let mut unapproved = doc.clone();
    unapproved.approvals.clear();
    refused(g.upload(&g.tax_sec1, &id, unapproved, &k), "ENC2701");
    let (s, _) = g.t.call(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{id}/signature"),
        Some(json!({"public_key": pk(&k), "signature": "zz"})),
    );
    assert!(s == 400 || s == 403, "{s}");
    // Not by another organization's person, or a service account.
    let (s, _) = g.upload(&g.ben_sec1, &id, doc.clone(), &k);
    assert_eq!(s, 404);
    refused(g.upload(&g.robot, &id, doc.clone(), &k), "ENC2707");

    // The owner's signature under its active key activates it.
    let (s, v) = g.upload(&g.tax_sec1, &id, doc.clone(), &k);
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "active");
    assert_eq!(v["authorization_id"], doc.id().as_str());
    let v = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/authorizations/{id}"),
        None,
    );
    assert_eq!(v["status"], "active");
    let signed: encompute_trust::authz::SignedAuthorizationV2 =
        serde_json::from_value(v["signed"].clone()).unwrap();
    signed.verify(&pk(&k)).unwrap();
    // Its document is frozen, even for the database's owner.
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    let e = c
        .execute(
            "UPDATE authorizations SET valid_until = valid_until + 1 WHERE id = $1",
            &[&id],
        )
        .unwrap_err();
    assert!(db_msg(&e).contains("immutable"), "{e}");

    // Revoked by a person of the owner, with its signed revocation; final.
    let revocation = RevocationV2 {
        version: 2,
        party: TAX.into(),
        authorization: doc.id(),
        reason: "superseded".into(),
        issued_at: now(),
    };
    let bad = revocation.clone().sign(&key(7)).unwrap();
    refused(
        g.t.call(
            &g.tax_sec1,
            "POST",
            &format!("/v1/authorizations/{id}/revoke"),
            Some(json!({"reason": "superseded", "revocation": bad})),
        ),
        "ENC2701",
    );
    refused(
        g.t.call(
            &g.robot,
            "POST",
            &format!("/v1/authorizations/{id}/revoke"),
            Some(json!({"reason": "superseded"})),
        ),
        "ENC2707",
    );
    let v = g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{id}/revoke"),
        Some(json!({"reason": "superseded", "revocation": revocation.sign(&k).unwrap()})),
    );
    assert_eq!(v["status"], "revoked");
    refused(g.upload(&g.tax_sec1, &id, doc, &k), "ENC2706");
    let e = c
        .execute(
            "UPDATE authorizations SET status = 'active' WHERE id = $1",
            &[&id],
        )
        .unwrap_err();
    assert!(db_msg(&e).contains("stays revoked"), "{e}");
}

#[test]
fn an_authorization_needs_a_live_key_purpose_acceptance_and_version() {
    let Some(g) = gov_world() else { return };
    let k = key(1);
    let (purpose, version) = g.ready(&k);

    // A purpose tax never accepted.
    let unaccepted = g.active_purpose("fraud-screening");
    refused(
        g.propose(&g.tax_owner, &g.body(&unaccepted, &version)),
        "ENC2702",
    );
    // A purpose that does not exist here.
    refused(
        g.propose(&g.tax_owner, &g.body(&"9".repeat(64), &version)),
        "ENC2702",
    );
    // A version tax never registered.
    refused(
        g.propose(&g.tax_owner, &g.body(&purpose, &"8".repeat(64))),
        "ENC2704",
    );
    // Already over, or reaching past the purpose's window.
    let mut late = g.body(&purpose, &version);
    late.valid_from = now() - 7200;
    late.valid_until = now() - 1;
    refused(g.propose(&g.tax_owner, &late), "ENC2705");
    let mut long = g.body(&purpose, &version);
    long.valid_until = now() + 86_400 * 365;
    refused(g.propose(&g.tax_owner, &long), "ENC2705");
    // A release class or recipient the purpose does not allow.
    let mut wider = g.body(&purpose, &version);
    wider.release_class = ReleaseClass::AuthorizedAgencyOnly;
    refused(g.propose(&g.tax_owner, &wider), "ENC2709");
    let mut more = g.body(&purpose, &version);
    more.recipients.insert("other-co".into());
    refused(g.propose(&g.tax_owner, &more), "ENC2709");
    // Another organization's authorization is proposed by its own people.
    let mut foreign = g.body(&purpose, &version);
    foreign.party = BEN.into();
    let (s, _) = g.propose(&g.tax_owner, &foreign);
    assert_eq!(s, 404);

    // A signature under a revoked key does not activate.
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": g.body(&purpose, &version)})),
    );
    let id = v["id"].as_str().unwrap().to_owned();
    g.approve(&g.tax_owner, &id, "data_owner");
    g.approve(&g.tax_sec1, &id, "security_admin");
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let key_row = keys[0]["id"].as_str().unwrap();
    g.t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{key_row}/revoke"),
        None,
    );
    refused(g.upload(&g.tax_sec1, &id, g.to_sign(&id), &k), "ENC2708");
    // A new key, approved by two people, activates it (signed anew).
    let k2 = key(2);
    g.register_key(TAX, &g.tax_admin, &g.tax_sec2, &k2);
    refused(g.upload(&g.tax_sec1, &id, g.to_sign(&id), &k), "ENC2708");
    let (s, v) = g.upload(&g.tax_sec1, &id, g.to_sign(&id), &k2);
    assert_eq!(s, 200, "{v}");
    // A retired purpose takes no new authorization.
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    refused(
        g.propose(&g.tax_owner, &g.body(&purpose, &version)),
        "ENC2706",
    );
}

#[test]
fn dataset_versions_register_once_and_never_change() {
    let Some(g) = gov_world() else { return };
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "income@2026-q3",
                    "series": "income", "version": "2026-q3", "digest": "c".repeat(64)}),
        ),
    );
    let expected = encompute_verification::governance::AssetVersion {
        version: 1,
        organization: TAX.into(),
        series: "income".into(),
        label: "2026-q3".into(),
        digest: "c".repeat(64),
    }
    .id()
    .hex();
    assert_eq!(v["version_id"], expected.as_str());
    let asset = v["id"].as_str().unwrap().to_owned();
    // The same label with another digest is refused.
    refused(
        g.t.call(
            &g.tax_owner,
            "POST",
            "/v1/assets",
            Some(
                json!({"organization": TAX, "kind": "dataset", "name": "income@2026-q3",
                        "series": "income", "version": "2026-q3", "digest": "f".repeat(64)}),
            ),
        ),
        "ENC2704",
    );
    // The name is the series and version; both or neither.
    for bad in [
        json!({"organization": TAX, "kind": "dataset", "name": "wrong",
               "series": "income", "version": "2026-q4", "digest": "f".repeat(64)}),
        json!({"organization": TAX, "kind": "dataset", "name": "income@2026-q4",
               "series": "income", "digest": "f".repeat(64)}),
        json!({"organization": TAX, "kind": "dataset", "name": "a@b@c",
               "series": "a@b", "version": "c", "digest": "f".repeat(64)}),
    ] {
        let (s, v) = g.t.call(&g.tax_owner, "POST", "/v1/assets", Some(bad));
        assert_eq!(s, 400, "{v}");
    }
    // The database refuses to change or delete a version, or to revive it.
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    for sql in [
        "UPDATE assets SET digest = 'x' WHERE id = $1",
        "UPDATE assets SET policy = '{\"release\": \"public\"}' WHERE id = $1",
        "UPDATE assets SET version = '2026-q4' WHERE id = $1",
        "DELETE FROM assets WHERE id = $1",
    ] {
        let e = c.execute(sql, &[&asset]).unwrap_err();
        assert!(db_msg(&e).contains("dataset version"), "{sql}: {e}");
    }
    g.t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{asset}/revoke"),
        None,
    );
    let e = c
        .execute(
            "UPDATE assets SET status = 'active' WHERE id = $1",
            &[&asset],
        )
        .unwrap_err();
    assert!(db_msg(&e).contains("stays revoked"), "{e}");
}

/// A job in a governed project names its purpose object and each output's
/// release, and reads registered versions under their owners'
/// authorizations: without them it is refused (the full enforcement is in
/// `tests/governed_jobs.rs`).
#[test]
fn a_governed_job_needs_its_purpose_outputs_and_an_owner_authorization() {
    let Some(g) = gov_world() else { return };
    evaluator(
        &g.t,
        &g.platform,
        "evaluator-1",
        &["openfhe", "openfhe-exact"],
        &["BINFHE_STD128_GINX_BITS_V1", "OPENFHE_CKKS_HE_STD128_V1"],
        4,
    );
    let k = key(1);
    let (purpose, _) = g.ready(&k);
    let program = "encompute 0.1
program adult precision 0.001 purpose \"benefits-eligibility\"
party \"tax-agency\" \"Tax\"
asset \"not-registered\" dataset owners [\"tax-agency\"] readers [\"tax-agency\"] purposes [\"benefits-eligibility\"] release allowed_parties
%0 = input \"age\" [0.0, 120.0] asset \"not-registered\" : secret u8
%1 = const [18.0] : public u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2 to \"tax-agency\"
";
    let plan = g.t.ok(
        &g.tax_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": g.project, "program": program})),
    );
    let submit = |body: Value, k: &str| {
        g.t.call_with(
            &g.tax_dev,
            "POST",
            "/v1/jobs",
            Some(body),
            &[("Idempotency-Key", k)],
        )
    };
    // The v1 request alone is not enough in a governed project.
    let (s, v) = submit(
        json!({"project": g.project, "plan": plan["id"], "purpose": "benefits-eligibility",
               "source_assets": [], "requested_output": "out"}),
        "k1",
    );
    assert_eq!(s, 400, "{v}");
    // With them, a program reading no authorized source is refused.
    refused(
        submit(
            json!({"project": g.project, "plan": plan["id"], "purpose": "benefits-eligibility",
                   "purpose_id": purpose, "source_assets": [], "requested_output": "out",
                   "outputs": {"out": {"release_class": "boolean-only", "recipients": [TAX]}}}),
            "k2",
        ),
        "ENC2701",
    );
}

/// Waits until the clock has passed second `t`.
fn after(t: u64) {
    while now() <= t {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn usable_code(g: &G, authorization: &str, at: u64) -> Option<&'static str> {
    g.t.control
        .authorization_usable_at(authorization, at)
        .err()
        .map(|e| e.code.as_str())
}

#[test]
fn an_approved_authorization_is_immutable_evidence() {
    let Some(g) = gov_world() else { return };
    let k = key(1);
    let (purpose, version) = g.ready(&k);
    let body = g.body(&purpose, &version);
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": body})),
    );
    let id = v["id"].as_str().unwrap().to_owned();
    assert_eq!(g.approve(&g.tax_owner, &id, "data_owner").0, 200);
    let (_, v) = g.approve(&g.tax_sec1, &id, "security_admin");
    assert_eq!(v["status"], "approved", "{v}");
    let doc = g.to_sign(&id);

    // Its quorum met, its approvals are closed: another approver, however
    // entitled, changes nothing.
    refused(g.approve(&g.tax_owner2, &id, "data_owner"), "ENC2604");
    refused(g.approve(&g.tax_sec2, &id, "security_admin"), "ENC2604");
    assert_eq!(g.to_sign(&id), doc);

    // The database refuses it too, even to its owner: no approval is
    // added, removed or edited, no recipient changes, and it is not
    // proposed again.
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    let closed = |e: postgres::Error| {
        let m = db_msg(&e);
        assert!(m.contains("immutable"), "{m}");
    };
    closed(
        c.execute(
            "INSERT INTO authorization_approvals (authorization_row, approver_id, idp_issuer,
                     approver_subject, role, statement_digest, evidence)
             VALUES ($1, 'usr_x', 'https://idp.example', 'mallory', 'data_owner', 'x', '{}')",
            &[&id],
        )
        .unwrap_err(),
    );
    closed(
        c.execute(
            "DELETE FROM authorization_approvals WHERE authorization_row = $1",
            &[&id],
        )
        .unwrap_err(),
    );
    closed(
        c.execute(
            "UPDATE authorization_approvals SET role = 'security_admin' WHERE authorization_row = $1",
            &[&id],
        )
        .unwrap_err(),
    );
    closed(
        c.execute(
            "INSERT INTO authorization_recipients (authorization_row, organization_id) VALUES ($1, 'other-co')",
            &[&id],
        )
        .unwrap_err(),
    );
    let e = c
        .execute(
            "UPDATE authorizations SET status = 'proposed' WHERE id = $1",
            &[&id],
        )
        .unwrap_err();
    assert!(db_msg(&e).contains("not proposed again"), "{e}");

    // Signed, it stays closed.
    let (s, v) = g.upload(&g.tax_sec1, &id, doc.clone(), &k);
    assert_eq!(s, 200, "{v}");
    refused(g.approve(&g.tax_sec2, &id, "security_admin"), "ENC2604");
    closed(
        c.execute(
            "DELETE FROM authorization_approvals WHERE authorization_row = $1",
            &[&id],
        )
        .unwrap_err(),
    );
    // A change of meaning is a new authorization, with its own four eyes.
    let mut narrower = body.clone();
    narrower.valid_until -= 60;
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": narrower})),
    );
    assert_ne!(v["id"], json!(id));
    assert_eq!(v["status"], "proposed");
    // Withdrawal is a state transition of its own, not an edit.
    let v = g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{id}/revoke"),
        Some(json!({"reason": "superseded"})),
    );
    assert_eq!(v["status"], "revoked");
    assert_eq!(g.to_sign(&id), doc);
    refused(g.approve(&g.tax_sec2, &id, "security_admin"), "ENC2604");
}

#[test]
fn a_revoked_governance_key_blocks_new_use_from_its_revocation_time() {
    let Some(g) = gov_world() else { return };
    let k = key(1);
    let (purpose, version) = g.ready(&k);
    let (id, authorization_id) = g.activated(&purpose, &version, &k);
    let signed_at = now();
    // Usable now, by its row or its AuthorizationId.
    assert_eq!(usable_code(&g, &id, now()), None);
    assert_eq!(usable_code(&g, &authorization_id, now()), None);
    // Not before it was active.
    assert_eq!(usable_code(&g, &id, signed_at - 3600), Some("ENC2701"));

    after(signed_at);
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    assert_eq!(keys[0]["revoked_at"], Value::Null);
    let key_row = keys[0]["id"].as_str().unwrap().to_owned();
    let revoke = || {
        g.t.ok(
            &g.tax_sec2,
            "POST",
            &format!("/v1/organizations/{TAX}/governance-keys/{key_row}/revoke"),
            None,
        )
    };
    let v = revoke();
    let revoked_at = v["revoked_at"].as_u64().expect("the revocation time");
    assert!(revoked_at > signed_at, "{v}");
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    assert_eq!(keys[0]["revoked_at"], revoked_at);
    // Revoking again changes nothing, the time included.
    assert_eq!(revoke()["revoked_at"], revoked_at);

    // From the revocation on, nothing new may use it...
    assert_eq!(usable_code(&g, &id, revoked_at), Some("ENC2708"));
    assert_eq!(usable_code(&g, &id, now() + 60), Some("ENC2708"));
    // ...while use before it stays valid, as history.
    assert_eq!(usable_code(&g, &id, revoked_at - 1), None);
    assert_eq!(usable_code(&g, &authorization_id, signed_at), None);
    // Its owner sees it: still the signed document it was, no longer
    // usable, and why.
    let v = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/authorizations/{id}"),
        None,
    );
    assert_eq!(v["status"], "active", "{v}");
    assert_eq!(v["usable"], false, "{v}");
    assert_eq!(v["governance_key_revoked_at"], revoked_at, "{v}");
    // A new key revives none of the old key's authorizations.
    g.register_key(TAX, &g.tax_admin, &g.tax_sec1, &key(2));
    assert_eq!(usable_code(&g, &id, now()), Some("ENC2708"));
    // Nor does the old key sign anything new, or a revocation.
    let revocation = RevocationV2 {
        version: 2,
        party: TAX.into(),
        authorization: authorization_id.clone(),
        reason: "key compromised".into(),
        issued_at: now(),
    };
    refused(
        g.t.call(
            &g.tax_sec1,
            "POST",
            &format!("/v1/authorizations/{id}/revoke"),
            Some(json!({"reason": "key compromised", "revocation": revocation.sign(&k).unwrap()})),
        ),
        "ENC2708",
    );

    // The revocation time is set with the revocation and never changes.
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    for sql in [
        "UPDATE governance_keys SET revoked_at = revoked_at + interval '1 day' WHERE id = $1",
        "UPDATE governance_keys SET revoked_at = revoked_at - interval '1 day' WHERE id = $1",
        "UPDATE governance_keys SET revoked_at = NULL WHERE id = $1",
    ] {
        let e = c.execute(sql, &[&key_row]).unwrap_err();
        assert!(db_msg(&e).contains("revocation time"), "{sql}: {e}");
    }
    let e = c
        .execute(
            "INSERT INTO governance_keys (id, organization_id, key_id, public_key, status, proposed_by)
             VALUES ('gky_x', $1, 'x', 'y', 'revoked', 'usr_x')",
            &[&TAX],
        )
        .unwrap_err();
    assert!(db_msg(&e).contains("check"), "{e}");
}

#[test]
fn a_revoked_authorization_is_unusable_from_its_revocation_time_only() {
    let Some(g) = gov_world() else { return };
    let k = key(1);
    let (purpose, version) = g.ready(&k);
    // Proposed or approved, it is not usable: only a signed one is.
    let v = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/authorizations",
        Some(json!({"body": g.body(&purpose, &version)})),
    );
    let pending = v["id"].as_str().unwrap().to_owned();
    assert_eq!(usable_code(&g, &pending, now()), Some("ENC2701"));
    assert_eq!(usable_code(&g, "atz_missing", now()), Some("ENC2701"));

    let (id, _) = g.activated(&purpose, &version, &k);
    let signed_at = now();
    after(signed_at);
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{id}/revoke"),
        Some(json!({"reason": "superseded"})),
    );
    let v = g.t.ok(
        &g.tax_owner,
        "GET",
        &format!("/v1/authorizations/{id}"),
        None,
    );
    let revoked_at = v["revoked_at"].as_u64().expect("the revocation time");
    assert!(revoked_at > signed_at, "{v}");
    assert_eq!(v["usable"], false, "{v}");
    // Not retroactive: blocked from its revocation on.
    assert_eq!(usable_code(&g, &id, revoked_at - 1), None);
    assert_eq!(usable_code(&g, &id, revoked_at), Some("ENC2706"));
    // The database keeps the time: set with the revocation, never changed.
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    for sql in [
        "UPDATE authorizations SET revoked_at = now() + interval '1 day' WHERE id = $1",
        "UPDATE authorizations SET revoked_at = NULL WHERE id = $1",
    ] {
        let e = c.execute(sql, &[&id]).unwrap_err();
        assert!(db_msg(&e).contains("revocation time"), "{sql}: {e}");
    }
    // A retired purpose: its authorizations are unusable from then on.
    let (other, _) = g.activated(&purpose, &version, &k);
    // Outside its window: expired.
    assert_eq!(usable_code(&g, &other, now() + 86_400), Some("ENC2705"));
    let before = now();
    after(before);
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    assert_eq!(usable_code(&g, &other, before), None);
    assert_eq!(usable_code(&g, &other, now()), Some("ENC2706"));
}

#[test]
fn version_4_databases_migrate_to_standard_projects() {
    let Some(url) = fresh_database() else { return };
    let db = encompute_control::db::Db::connect(&url).unwrap();
    assert_eq!(db.migrate_to(4).unwrap(), 4);
    db.conn()
        .unwrap()
        .batch_execute(
            "INSERT INTO organizations (id, display_name, status, policy_namespace) VALUES ('o', 'o', 'active', 'o');
             INSERT INTO projects (id, organization_id, name, status) VALUES ('p', 'o', 'p', 'active');
             INSERT INTO assets (id, organization_id, kind, name, digest, policy, lineage_root, parents, status, created_by)
                  VALUES ('a', 'o', 'dataset', 'a', 'd', '{}', 'a', '[]', 'active', 'u');",
        )
        .unwrap();
    assert_eq!(db.migrate().unwrap(), 8);
    let mut c = db.conn().unwrap();
    let r = c
        .query_one(
            "SELECT p.governance, a.series IS NULL FROM projects p, assets a WHERE p.id = 'p' AND a.id = 'a'",
            &[],
        )
        .unwrap();
    assert_eq!(r.get::<_, String>(0), "standard");
    assert!(r.get::<_, bool>(1));
    // Existing assets are not versions: they change as before.
    c.execute("UPDATE assets SET status = 'revoked' WHERE id = 'a'", &[])
        .unwrap();
    c.execute("UPDATE assets SET status = 'active' WHERE id = 'a'", &[])
        .unwrap();
}
