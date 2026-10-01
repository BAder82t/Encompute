//! A governed project of two organizations (tax and benefits agencies),
//! shared by the governance tests.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use super::*;
use encompute_control::authn::DEV_ISSUER;
use encompute_trust::authz::{AuthorizationV2, PurposeAcceptance};
use encompute_verification::governance::{ProgramRef, ReleaseClass};
use encompute_verification::{hex, ServiceSigner};

pub const TAX: &str = "tax-agency";
pub const BEN: &str = "benefits-agency";

pub struct G {
    pub t: T,
    pub platform: As,
    pub tax_admin: As,
    pub tax_sec1: As,
    pub tax_sec2: As,
    pub tax_owner: As,
    pub tax_owner2: As,
    pub tax_auditor: As,
    pub tax_dev: As,
    pub ben_admin: As,
    pub ben_sec1: As,
    pub ben_sec2: As,
    pub robot: As,
    pub project: String,
}

pub fn now() -> u64 {
    encompute_verification::service::now()
}

pub fn gov_world() -> Option<G> {
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
    let tax_auditor = user(&t, &tax_admin, TAX, "t-auditor", &["auditor"]);
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

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn pk(k: &SigningKey) -> String {
    hex(&k.verifying_key().to_bytes())
}

/// The server's message of a database error (a trigger's refusal).
pub fn db_msg(e: &postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string())
}

pub fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

/// Asserts `(status, body)` is a refusal with `c`.
pub fn refused(r: (u16, Value), c: &str) {
    assert!(r.0 >= 400, "expected {c}, got {} {}", r.0, r.1);
    assert_eq!(code(&r.1), c, "{} {}", r.0, r.1);
}

impl G {
    /// Proposes and approves (by a different security admin) `k` as
    /// `org`'s governance key.
    pub fn register_key(&self, org: &str, proposer: &As, approver: &As, k: &SigningKey) -> String {
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

    pub fn purpose_request(&self, name: &str) -> Value {
        json!({"organization": TAX, "name": name, "description": "Eligibility for housing benefit",
               "modes": ["aggregate"], "allowed_release_classes": ["boolean-only"],
               "recipients": [BEN], "valid_from": now() - 60, "valid_until": now() + 3600})
    }

    /// A purpose proposed by tax's first security admin and approved by the
    /// second.
    pub fn active_purpose(&self, name: &str) -> String {
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

    pub fn accept(&self, who: &As, org: &str, purpose: &str, k: &SigningKey) -> (u16, Value) {
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
    pub fn version(&self, label: &str, digest: char) -> String {
        let v = self.t.ok(
            &self.tax_owner,
            "POST",
            "/v1/assets",
            Some(json!({"organization": TAX, "kind": "dataset", "name": format!("income@{label}"),
                        "series": "income", "version": label, "digest": digest.to_string().repeat(64),
                        "ir_policy": registered(TAX)["ir_policy"], "release_class": "boolean-only"})),
        );
        v["version_id"].as_str().unwrap().to_owned()
    }

    pub fn body(&self, purpose: &str, version: &str) -> AuthorizationV2 {
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
            limits: probing_limits(),
            per_job_four_eyes: false,
            valid_from: now() - 30,
            valid_until: now() + 1800,
            issued_at: now(),
            nonce: hex(&nonce),
            approvals: vec![],
        }
    }

    pub fn propose(&self, who: &As, body: &AuthorizationV2) -> (u16, Value) {
        self.t.call(
            who,
            "POST",
            "/v1/authorizations",
            Some(json!({"body": body})),
        )
    }

    pub fn approve(&self, who: &As, id: &str, role: &str) -> (u16, Value) {
        self.t.call(
            who,
            "POST",
            &format!("/v1/authorizations/{id}/approve"),
            Some(json!({"role": role})),
        )
    }

    /// The body to sign (with its approvals), as the control plane shows it.
    pub fn to_sign(&self, id: &str) -> AuthorizationV2 {
        let v = self.t.ok(
            &self.tax_sec1,
            "GET",
            &format!("/v1/authorizations/{id}"),
            None,
        );
        serde_json::from_value(v["body"].clone()).unwrap()
    }

    pub fn upload(
        &self,
        who: &As,
        id: &str,
        body: AuthorizationV2,
        k: &SigningKey,
    ) -> (u16, Value) {
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
    pub fn activated(&self, purpose: &str, version: &str, k: &SigningKey) -> (String, String) {
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
    pub fn ready(&self, k: &SigningKey) -> (String, String) {
        self.register_key(TAX, &self.tax_admin, &self.tax_sec1, k);
        let purpose = self.active_purpose("benefits-eligibility");
        let (s, v) = self.accept(&self.tax_sec2, TAX, &purpose, k);
        assert_eq!(s, 200, "{v}");
        (purpose, self.version("2026-q3", 'c'))
    }
}
