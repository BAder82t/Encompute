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

use serde_json::{json, Value};

use common::gov::*;
use common::*;
use encompute_trust::authz::RevocationV2;
use encompute_verification::governance::ReleaseClass;
use encompute_verification::ServiceSigner;

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
    // An auditor that also holds security_admin: a combination from before
    // auditor separation (granting it now is refused, ENC2716), kept and
    // still read-only.
    legacy_role(&g.t, "t-auditor", TAX, "security_admin");
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
    assert_eq!(db.migrate().unwrap(), 18);
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

// --- the governance event log ------------------------------------------------

/// The governance log's events, in order: (partition, kind, subject, body).
fn glog(t: &T) -> Vec<(String, String, String, Value)> {
    t.control
        .db
        .conn()
        .unwrap()
        .query(
            "SELECT partition, kind, subject_id, body FROM governance_events ORDER BY gseq",
            &[],
        )
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect()
}

/// The events appended since `before` (a length of [`glog`]).
fn glog_since(t: &T, before: usize) -> Vec<(String, String, String, Value)> {
    glog(t).split_off(before)
}

/// Asserts one step appended exactly the one event described.
fn one_event(t: &T, before: usize, partition: &str, kind: &str, subject: &str) {
    let new = glog_since(t, before);
    assert_eq!(new.len(), 1, "{kind}: {new:?}");
    let (p, k, s, _) = &new[0];
    assert_eq!(
        (p.as_str(), k.as_str(), s.as_str()),
        (partition, kind, subject)
    );
}

/// The log is intact, and for every set the state anchor holds, the
/// database's negative rows and the log's events of that kind name the
/// same IDs: the log records every transition the anchor does.
fn log_matches_database(t: &T) {
    use encompute_control::govlog::{self, kind};
    let mut c = t.control.db.conn().unwrap();
    govlog::verify_chain(&mut *c).unwrap();
    let ids = |c: &mut postgres::Client, sql: &str| -> std::collections::BTreeSet<String> {
        c.query(sql, &[])
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect()
    };
    for (kinds, sql) in [
        (
            vec![kind::ASSET_REVOKED],
            "SELECT id FROM assets WHERE status = 'revoked'",
        ),
        (
            vec![kind::ASSET_EXPIRED],
            "SELECT id FROM assets WHERE expired_at IS NOT NULL",
        ),
        (
            vec![kind::SERVICE_ACCOUNT_DISABLED],
            "SELECT id FROM service_accounts WHERE status = 'disabled'",
        ),
        (
            vec![kind::USER_DISABLED],
            "SELECT id FROM users WHERE status = 'disabled'",
        ),
        (
            vec![kind::JOB_FAILED, kind::JOB_CANCELLED],
            "SELECT id FROM jobs WHERE state IN ('failed', 'cancelled')",
        ),
        (
            vec![kind::GRANT_WITHDRAWN],
            "SELECT id FROM withdrawn_grants",
        ),
        (
            vec![kind::MEMBERSHIP_REMOVED],
            "SELECT id FROM removed_memberships",
        ),
        (vec![kind::ROLE_REMOVED], "SELECT id FROM removed_roles"),
        (
            vec![kind::AUTHORIZATION_REVOKED],
            "SELECT id FROM authorizations WHERE status = 'revoked'",
        ),
        (
            vec![kind::PURPOSE_RETIRED],
            "SELECT id FROM purposes WHERE status = 'retired'",
        ),
        (
            vec![kind::GOVERNANCE_KEY_REVOKED],
            "SELECT id FROM governance_keys WHERE status = 'revoked'",
        ),
    ] {
        let want = ids(&mut c, sql);
        let mut got = std::collections::BTreeSet::new();
        for k in &kinds {
            got.extend(govlog::negative_ids(&mut *c, k).unwrap());
        }
        assert_eq!(got, want, "{kinds:?}");
    }
}

/// Every transition the state anchor records writes exactly one event to
/// the governance log, in the same transaction, in the governed project's
/// partition or the organization's; a governance-key revocation writes one
/// for the organization and one for each governed project it takes part
/// in. Transitions that are not security-negative (a key's or purpose's
/// approval, an acceptance, a version) write none; a member joining a
/// governed project writes `membership.added`, so the members at any size
/// of its log come from the log.
#[test]
fn every_governance_transition_writes_exactly_one_event() {
    use encompute_control::govlog::kind;
    let Some(g) = gov_world() else { return };
    let t = &g.t;
    let p = format!("p:{}", g.project);
    let o = format!("o:{TAX}");
    let k = key(1);
    let (purpose, version) = g.ready(&k);
    one_event(t, 0, &p, kind::MEMBERSHIP_ADDED, &glog(t)[0].2.clone());

    let n = glog(t).len();
    let (auth, _) = g.activated(&purpose, &version, &k);
    one_event(t, n, &p, kind::AUTHORIZATION_ISSUED, &auth);

    let n = glog(t).len();
    t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{auth}/revoke"),
        Some(json!({"reason": "superseded"})),
    );
    one_event(t, n, &p, kind::AUTHORIZATION_REVOKED, &auth);
    // Revoking it again changes nothing, and logs nothing.
    let n = glog(t).len();
    t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{auth}/revoke"),
        Some(json!({"reason": "superseded"})),
    );
    assert_eq!(glog(t).len(), n);

    let n = glog(t).len();
    t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    one_event(t, n, &p, kind::PURPOSE_RETIRED, &purpose);

    let who = t.ok(&g.tax_dev, "GET", "/v1/whoami", None);
    let dev = who["id"].as_str().unwrap().to_owned();
    let n = glog(t).len();
    t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/users/{dev}/disable"),
        None,
    );
    one_event(t, n, &o, kind::USER_DISABLED, &dev);
    let n = glog(t).len();
    t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/users/{dev}/disable"),
        None,
    );
    assert_eq!(
        glog(t).len(),
        n,
        "disabling a disabled user is no transition"
    );

    let n = glog(t).len();
    t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts/tax-robot/disable"),
        None,
    );
    one_event(t, n, &o, kind::SERVICE_ACCOUNT_DISABLED, "tax-robot");

    let who = t.ok(&g.tax_owner2, "GET", "/v1/whoami", None);
    let owner2 = who["id"].as_str().unwrap().to_owned();
    let n = glog(t).len();
    t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/memberships/remove"),
        Some(json!({"principal": owner2, "role": "data_owner"})),
    );
    let role: String = t
        .control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT id FROM removed_roles WHERE principal_id = $1",
            &[&owner2],
        )
        .unwrap()
        .get(0);
    one_event(t, n, &o, kind::ROLE_REMOVED, &role);

    let asset = |name: &str, digest: char| -> String {
        t.ok(
            &g.tax_owner,
            "POST",
            "/v1/assets",
            Some(json!({"organization": TAX, "kind": "dataset", "name": format!("income@{name}"),
                        "series": "income", "version": name, "digest": digest.to_string().repeat(64),
                        "ir_policy": registered(TAX)["ir_policy"], "release_class": "boolean-only"})),
        )["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let revoked = asset("2026-q1", 'e');
    let n = glog(t).len();
    t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{revoked}/revoke"),
        None,
    );
    one_event(t, n, &o, kind::ASSET_REVOKED, &revoked);
    let n = glog(t).len();
    t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{revoked}/revoke"),
        None,
    );
    assert_eq!(glog(t).len(), n);

    let expired = asset("2026-q2", 'f');
    let n = glog(t).len();
    assert!(t.control.expire_asset("operator-1", &expired).unwrap());
    one_event(t, n, &o, kind::ASSET_EXPIRED, &expired);
    assert!(!t.control.expire_asset("operator-1", &expired).unwrap());
    assert_eq!(glog(t).len(), n + 1);

    let n = glog(t).len();
    t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", g.project),
        Some(json!({"organization": BEN})),
    );
    let membership: String = t
        .control
        .db
        .conn()
        .unwrap()
        .query_one(
            "SELECT id FROM removed_memberships WHERE organization_id = $1",
            &[&BEN],
        )
        .unwrap()
        .get(0);
    one_event(t, n, &p, kind::MEMBERSHIP_REMOVED, &membership);
    assert_eq!(glog(t).last().unwrap().3["org"], BEN);

    let keys = t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let key_row = keys[0]["id"].as_str().unwrap().to_owned();
    let n = glog(t).len();
    t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{key_row}/revoke"),
        None,
    );
    let new = glog_since(t, n);
    let got: Vec<(&str, &str, &str)> = new
        .iter()
        .map(|(p, k, s, _)| (p.as_str(), k.as_str(), s.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            (o.as_str(), kind::GOVERNANCE_KEY_REVOKED, key_row.as_str()),
            (p.as_str(), kind::GOVERNANCE_KEY_REVOKED, key_row.as_str()),
        ]
    );
    log_matches_database(t);
}

/// Retiring a purpose is recorded in its governed project's partition,
/// once, with the purpose and its proposing organization.
#[test]
fn purpose_retirement_is_logged() {
    use encompute_control::govlog::kind;
    let Some(g) = gov_world() else { return };
    let purpose = g.active_purpose("benefits-eligibility");
    // (Benefits joining the project is the log's one event so far.)
    assert_eq!(glog(&g.t).len(), 1);
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    one_event(
        &g.t,
        1,
        &format!("p:{}", g.project),
        kind::PURPOSE_RETIRED,
        &purpose,
    );
    let body = &glog(&g.t)[1].3;
    assert_eq!(body["org"], TAX, "{body}");
    assert_eq!(body["refs"]["project"], g.project.as_str(), "{body}");
    // Retired once: retiring again records nothing.
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    assert_eq!(glog(&g.t).len(), 2);
    log_matches_database(&g.t);
}

/// A governance-key revocation reaches the log of every governed project
/// its organization takes part in (as owner or member), and its own; a
/// standard project it takes part in gets nothing.
#[test]
fn governance_key_revocation_appends_to_every_project() {
    use encompute_control::govlog::kind;
    let Some(g) = gov_world() else { return };
    let t = &g.t;
    // A second governed project tax owns, one benefits owns that tax
    // joined, and a standard project of tax's.
    let p2 = t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(
            json!({"organization": TAX, "name": "second", "governance": "governed",
                    "organizations": [BEN]}),
        ),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let p3 = t.ok(
        &g.ben_admin,
        "POST",
        "/v1/projects",
        Some(
            json!({"organization": BEN, "name": "benefits-own", "governance": "governed",
                    "organizations": [TAX]}),
        ),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{p3}/members"),
        Some(json!({"organization": TAX})),
    );
    let standard = t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "plain"})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let k = key(1);
    let key_row = g.register_key(TAX, &g.tax_admin, &g.tax_sec1, &k);
    // Only the joins so far: benefits in the world's project, tax in
    // benefits' own.
    assert!(
        glog(t).iter().all(|e| e.1 == kind::MEMBERSHIP_ADDED) && glog(t).len() == 2,
        "{:?}",
        glog(t)
    );
    t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{key_row}/revoke"),
        None,
    );
    // The whole log: the two joins, then exactly one revocation per
    // partition, and nothing else.
    let all = glog(t);
    assert_eq!(all.len(), 6, "{all:?}");
    assert!(
        all[..2].iter().all(|e| e.1 == kind::MEMBERSHIP_ADDED),
        "{all:?}"
    );
    let events: Vec<_> = all[2..].to_vec();
    let partitions: std::collections::BTreeSet<String> =
        events.iter().map(|(p, _, _, _)| p.clone()).collect();
    let want: std::collections::BTreeSet<String> = [
        format!("o:{TAX}"),
        format!("p:{}", g.project),
        format!("p:{p2}"),
        format!("p:{p3}"),
    ]
    .into();
    assert_eq!(partitions, want);
    assert_eq!(events.len(), 4, "one per partition: {events:?}");
    assert!(!partitions.contains(&format!("p:{standard}")));
    let key_id = encompute_trust::authz::governance_key_id(&pk(&k));
    for (_, kd, s, body) in &events {
        assert_eq!(kd, kind::GOVERNANCE_KEY_REVOKED);
        assert_eq!(s, &key_row);
        assert_eq!(body["org"], TAX);
        assert_eq!(body["refs"]["key_id"], key_id.as_str(), "{body}");
    }
    // Benefits' key is another organization's: none of tax's partitions
    // learn of its revocation, and tax's own partition gets nothing.
    let bk = key(2);
    let ben_row = g.register_key(BEN, &g.ben_sec1, &g.ben_sec2, &bk);
    t.ok(
        &g.ben_sec1,
        "POST",
        &format!("/v1/organizations/{BEN}/governance-keys/{ben_row}/revoke"),
        None,
    );
    let ben: Vec<String> = glog_since(t, 6).into_iter().map(|e| e.0).collect();
    assert!(ben.contains(&format!("o:{BEN}")), "{ben:?}");
    assert!(!ben.contains(&format!("o:{TAX}")), "{ben:?}");
    log_matches_database(t);
}

/// A transaction that rolls back leaves no event, no tree node and the
/// head where it was.
#[test]
fn a_rolled_back_transaction_writes_no_event() {
    use encompute_control::govlog::{self, kind, Draft};
    use encompute_trust::govlog::Partition;
    let Some(g) = gov_world() else { return };
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{}/retire", g.active_purpose("x")),
        None,
    );
    let head = |c: &mut postgres::Client| -> (i64, String, i64) {
        let r = c
            .query_one(
                "SELECT gseq, hash, (SELECT count(*) FROM governance_tree_nodes) FROM governance_head",
                &[],
            )
            .unwrap();
        (r.get(0), r.get(1), r.get(2))
    };
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    let before = head(&mut c);
    let n = glog(&g.t).len();
    {
        let mut tx = c.transaction().unwrap();
        govlog::append(
            &mut tx,
            Draft::new(Partition::Platform, kind::USER_DISABLED, "usr_rolled_back"),
        )
        .unwrap();
        tx.rollback().unwrap();
    }
    assert_eq!(head(&mut c), before);
    assert_eq!(glog(&g.t).len(), n);
    // An API call that fails part-way records nothing either: a purpose
    // retired by someone who may not.
    let purpose = g.active_purpose("y");
    let (s, _) = g.t.call(
        &g.robot,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    assert!(s >= 400);
    assert_eq!(glog(&g.t).len(), n);
    log_matches_database(&g.t);
}

/// The log is append-only in the database: no event, node, checkpoint,
/// witness or revocation head is updated, deleted or truncated, and the
/// head only moves forward one event at a time.
#[test]
fn governance_log_rows_refuse_update_and_delete() {
    let Some(g) = gov_world() else { return };
    let purpose = g.active_purpose("benefits-eligibility");
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    {
        let mut c = g.t.control.db.conn().unwrap();
        let mut tx = c.transaction().unwrap();
        encompute_control::govlog::checkpoint_partition(
            &mut tx,
            &g.t.control.signer,
            &format!("p:{}", g.project),
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    c.batch_execute(&format!(
        "INSERT INTO checkpoint_witnesses (partition, size, organization_id, signed)
              VALUES ('p:{0}', 1, '{TAX}', '{{}}');
         INSERT INTO revocation_heads (organization_id, project_id, seq, root, at, signed)
              VALUES ('{TAX}', '{0}', 1, 'r', 1, '{{}}');",
        g.project
    ))
    .unwrap();
    for sql in [
        "UPDATE governance_events SET kind = 'asset.revoked'",
        "DELETE FROM governance_events",
        "TRUNCATE governance_events",
        "UPDATE governance_tree_nodes SET hash = 'x'",
        "DELETE FROM governance_tree_nodes",
        "UPDATE governance_checkpoints SET root = 'x'",
        "DELETE FROM governance_checkpoints",
        "UPDATE checkpoint_witnesses SET signed = '{}'",
        "DELETE FROM checkpoint_witnesses",
        "UPDATE revocation_heads SET root = 'x'",
        "DELETE FROM revocation_heads",
        "DELETE FROM governance_head",
        "TRUNCATE governance_head",
        "UPDATE governance_head SET gseq = gseq - 1",
        "UPDATE governance_head SET gseq = gseq + 2",
    ] {
        let e = c.batch_execute(sql).expect_err(sql);
        let m = db_msg(&e);
        assert!(
            m.contains("append-only") || m.contains("forward"),
            "{sql}: {m}"
        );
    }
    log_matches_database(&g.t);
}

/// Leaves carry only what every member may see: no storage location, key
/// reference, asset or purpose text, revocation reason, or person's
/// identifier, whichever transitions wrote them (a canary scan).
#[test]
fn leaves_are_shared_safe() {
    let Some(g) = gov_world() else { return };
    let t = &g.t;
    let k = key(1);
    g.register_key(TAX, &g.tax_admin, &g.tax_sec1, &k);
    let v = t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/projects/{}/purposes", g.project),
        Some(json!({"organization": TAX, "name": "benefits-eligibility",
                    "description": "canary-purpose-text-5e1c",
                    "modes": ["aggregate"], "allowed_release_classes": ["boolean-only"],
                    "recipients": [BEN], "valid_from": now() - 60, "valid_until": now() + 3600})),
    );
    let purpose = v["id"].as_str().unwrap().to_owned();
    t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/purposes/{purpose}/approve"),
        None,
    );
    let (s, v) = g.accept(&g.tax_sec2, TAX, &purpose, &k);
    assert_eq!(s, 200, "{v}");
    let v = t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "canary-series-0b9d@2026-q3",
                    "series": "canary-series-0b9d", "version": "2026-q3", "digest": "c".repeat(64),
                    "storage_uri": "s3://canary-storage-7f3a/income",
                    "ir_policy": registered(TAX)["ir_policy"], "release_class": "boolean-only"}),
        ),
    );
    let (asset, version) = (
        v["id"].as_str().unwrap().to_owned(),
        v["version_id"].as_str().unwrap().to_owned(),
    );
    let (auth, _) = g.activated(&purpose, &version, &k);
    t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/authorizations/{auth}/revoke"),
        Some(json!({"reason": "canary-reason-c4d2"})),
    );
    t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    t.ok(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{asset}/revoke"),
        None,
    );
    t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", g.project),
        Some(json!({"organization": BEN})),
    );
    let keys = t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let key_row = keys[0]["id"].as_str().unwrap().to_owned();
    t.ok(
        &g.tax_sec2,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{key_row}/revoke"),
        None,
    );
    let events = glog(t);
    assert!(events.len() >= 6, "{events:?}");
    let people: Vec<String> = t
        .control
        .db
        .conn()
        .unwrap()
        .query("SELECT id FROM users UNION SELECT subject FROM users", &[])
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let fields = [
        "at",
        "kind",
        "org",
        "partition",
        "pseq",
        "refs",
        "subject",
        "v",
    ];
    let refs = [
        "asset",
        "authorization_id",
        "covered_organization",
        "governance_key",
        "key_id",
        "participation",
        "project",
        "reason",
        "revocation_id",
        "role",
        "status",
        "withdrawn",
    ];
    for (p, _, _, body) in &events {
        let text = body.to_string();
        for canary in ["canary", "s3://", "vault:", "transit", "superseded"] {
            assert!(!text.contains(canary), "{canary} in {text}");
        }
        for person in &people {
            assert!(
                !text.contains(&format!("\"{person}\"")),
                "{person} in {text}"
            );
        }
        for k in body.as_object().unwrap().keys() {
            assert!(fields.contains(&k.as_str()), "field {k} in {text}");
        }
        for k in body["refs"].as_object().into_iter().flatten().map(|x| x.0) {
            assert!(refs.contains(&k.as_str()), "reference {k} in {text}");
        }
        assert!(p.starts_with("p:") || p.starts_with("o:") || p == "platform");
        // The values of what a removal says are a closed set.
        if let Some(v) = body["refs"]["status"].as_str() {
            assert!(["active", "invited"].contains(&v), "status {v} in {text}");
        }
        if let Some(v) = body["refs"]["participation"].as_str() {
            assert!(
                ["member", "auditor"].contains(&v),
                "participation {v} in {text}"
            );
        }
    }
    log_matches_database(t);
}

/// Checkpoints and proofs come straight from the stored log: every event
/// of a project proves inclusion in its signed checkpoint, a later
/// checkpoint is consistent with an earlier one, and an event edited in
/// the database (with its triggers off) breaks the chain.
#[test]
fn checkpoints_and_proofs_from_the_database() {
    use encompute_control::govlog;
    let Some(g) = gov_world() else { return };
    let t = &g.t;
    let part = format!("p:{}", g.project);
    let ck = t.control.signer.public_key_hex();
    let checkpoint = || {
        let mut c = t.control.db.conn().unwrap();
        let mut tx = c.transaction().unwrap();
        let cp = govlog::checkpoint_partition(&mut tx, &t.control.signer, &part).unwrap();
        tx.commit().unwrap();
        cp
    };
    for name in ["a", "b", "c"] {
        let p = g.active_purpose(name);
        t.ok(
            &g.tax_sec1,
            "POST",
            &format!("/v1/purposes/{p}/retire"),
            None,
        );
    }
    let cp1 = checkpoint();
    cp1.verify(&ck).unwrap();
    // (Benefits' join is the first event.)
    assert_eq!(cp1.body.size, 4);
    assert_eq!(checkpoint(), cp1, "the same size is the same checkpoint");
    for name in ["d", "e", "f", "g"] {
        let p = g.active_purpose(name);
        t.ok(
            &g.tax_sec1,
            "POST",
            &format!("/v1/purposes/{p}/retire"),
            None,
        );
    }
    let cp2 = checkpoint();
    assert_eq!(cp2.body.size, 8);
    let mut c = t.control.db.conn().unwrap();
    for (i, e) in govlog::events(&mut *c, &part, 0, 100)
        .unwrap()
        .iter()
        .enumerate()
    {
        let proof = govlog::prove(&mut *c, &part, i as u64 + 1, 8).unwrap();
        cp2.includes(e, &proof).unwrap();
        if i < 4 {
            let proof = govlog::prove(&mut *c, &part, i as u64 + 1, 4).unwrap();
            cp1.includes(e, &proof).unwrap();
        }
    }
    let cons = govlog::prove_consistency(&mut *c, &part, 4, 8).unwrap();
    assert_eq!(cons.first_root, cp1.body.root);
    assert_eq!(cons.second_root, cp2.body.root);
    cons.verify().unwrap();
    govlog::verify_chain(&mut *c).unwrap();
    drop(c);
    attacker(
        &t.env0.url,
        &["governance_events"],
        "UPDATE governance_events SET body = jsonb_set(body, '{subject}', '\"purpose-x\"') WHERE gseq = 2",
    );
    let mut c = t.control.db.conn().unwrap();
    let e = govlog::verify_chain(&mut *c).unwrap_err();
    assert!(e.message.contains("governance event 2"), "{e}");
}

/// A standard project writes nothing to a project partition: its jobs,
/// approvals, memberships, assets and people go to their organization's
/// partition (the platform's for platform accounts), and everything it
/// answers is as before.
#[test]
fn standard_projects_log_only_to_organizations() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let project = w.project.clone();
    for (who, asset) in [(&w.a_owner, &w.dataset_a), (&w.b_owner, &w.model_b)] {
        t.ok(
            who,
            "POST",
            &format!("/v1/assets/{asset}/approvals"),
            Some(json!({"project": project, "purpose": "medical-training"})),
        );
    }
    let plan = w.plan(&exact_own(&w.model_b));
    let (_, j) = w.job(&plan, &[&w.model_b], "to-cancel");
    let job = j["id"].as_str().unwrap().to_owned();
    let v = t.ok(&w.b_dev, "POST", &format!("/v1/jobs/{job}/cancel"), None);
    assert_eq!(v["state"], "cancelled", "{v}");
    t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{}/approvals/withdraw", w.dataset_a),
        Some(json!({"project": project, "purpose": "medical-training"})),
    );
    t.ok(
        &w.b_admin,
        "POST",
        &format!("/v1/projects/{project}/members/remove"),
        Some(json!({"organization": "hospital-a"})),
    );
    let who = t.ok(&w.c_dev, "GET", "/v1/whoami", None);
    let c_dev = who["id"].as_str().unwrap().to_owned();
    t.ok(
        &w.c_admin,
        "POST",
        &format!("/v1/organizations/other-co/users/{c_dev}/disable"),
        None,
    );
    let sa = ServiceSigner::from_seed("secagg-9", &[39; 32]).unwrap();
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "secagg-9", "kind": "secagg", "public_key": sa.public_key_hex()})),
    );
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts/secagg-9/disable",
        None,
    );
    let v = t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", w.dataset_a),
        None,
    );
    assert_eq!(v["status"], "revoked", "{v}");
    let events = glog(t);
    let partitions: std::collections::BTreeSet<&str> =
        events.iter().map(|(p, _, _, _)| p.as_str()).collect();
    assert!(
        partitions.iter().all(|p| !p.starts_with("p:")),
        "{partitions:?}"
    );
    for p in ["o:modelco", "o:hospital-a", "o:other-co", "platform"] {
        assert!(partitions.contains(p), "{p}: {partitions:?}");
    }
    let kinds: std::collections::BTreeSet<&str> =
        events.iter().map(|(_, k, _, _)| k.as_str()).collect();
    for k in [
        "job.cancelled",
        "grant.withdrawn",
        "membership.removed",
        "user.disabled",
        "service_account.disabled",
        "asset.revoked",
    ] {
        assert!(kinds.contains(k), "{k}: {kinds:?}");
    }
    log_matches_database(t);
}

/// Lock order: signing an audit checkpoint takes the governance log's head
/// before the audit head, like every audit append, so it waits while
/// another transaction holds the governance head.
#[test]
fn audit_checkpoint_takes_the_governance_head_first() {
    let Some(g) = gov_world() else { return };
    let mut holder = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    let mut held = holder.transaction().unwrap();
    encompute_control::govlog::lock_head(&mut held).unwrap();
    let mut c = postgres::Client::connect(&g.t.env0.url, postgres::NoTls).unwrap();
    let mut tx = c.transaction().unwrap();
    tx.batch_execute("SET LOCAL lock_timeout = '300ms'")
        .unwrap();
    let (seq, root) = encompute_control::audit::verify_chain(&mut tx).unwrap();
    let e =
        encompute_control::audit::checkpoint_extending(&mut tx, &g.t.control.signer, seq, &root)
            .expect_err("signed while the governance head was held");
    assert!(e.message.contains("lock"), "{e}");
    drop(tx);
    held.rollback().unwrap();
    let mut tx = c.transaction().unwrap();
    encompute_control::audit::checkpoint_extending(&mut tx, &g.t.control.signer, seq, &root)
        .unwrap();
}
