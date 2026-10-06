//! Collaboration grants and their withdrawal: project membership needs the
//! invited organization's consent, an asset approval covers only the
//! members at approval time, policy four eyes are two people of the
//! project's owner, key brokers are bound to their organization, and every
//! grant has an API to take it back.

mod common;

use std::sync::Arc;

use common::*;
use serde_json::{json, Value};

fn audit_actions(t: &T, who: &As) -> Vec<Value> {
    t.ok(who, "GET", "/v1/audit?limit=1000", None)
        .as_array()
        .unwrap()
        .clone()
}

/// Invites `org` into `project` (by `owner_admin`) and accepts (by
/// `member_admin`).
fn join(t: &T, owner_admin: &As, member_admin: &As, project: &str, org: &str) {
    let v = t.ok(
        owner_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": org})),
    );
    assert_eq!(v["status"], "invited", "{v}");
    let v = t.ok(
        member_admin,
        "POST",
        &format!("/v1/projects/{project}/members"),
        Some(json!({"organization": org})),
    );
    assert_eq!(v["status"], "active", "{v}");
}

/// Review finding CP-A-1 (ENC-SF-2026-040): an organization that joins a project after an
/// owner approved its asset for it inherits nothing: it neither sees nor
/// lists the asset, and cannot submit a job over it, until the owner
/// approves again. On rc.3 the late joiner read the asset (key_ref,
/// storage) and its job was queued with a signed grant.
#[test]
fn a_late_joiner_inherits_no_asset_approval() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let d = w.dataset_a.clone();
    let approve = || {
        t.ok(
            &w.a_owner,
            "POST",
            &format!("/v1/assets/{d}/approvals"),
            Some(json!({"project": w.project, "purpose": "medical-training"})),
        )
    };
    let v = approve();
    assert_eq!(v["members"], json!(["hospital-a", "modelco"]));
    join(t, &w.b_admin, &w.c_admin, &w.project, "other-co");
    let (s, v) = t.call(&w.c_dev, "GET", &format!("/v1/assets/{d}"), None);
    assert_eq!(s, 404, "{v}");
    let list = t.ok(&w.c_dev, "GET", "/v1/assets", None);
    assert!(!list.to_string().contains(&d), "listed to the late joiner");
    let p = t.ok(
        &w.c_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project,
                    "program": exact_over(&d, "hospital-a", "dataset", "medical-training")})),
    );
    let submit = |key: &str| {
        t.call_with(
            &w.c_dev,
            "POST",
            "/v1/jobs",
            Some(
                json!({"project": w.project, "plan": p["id"], "purpose": "medical-training",
                        "source_assets": [d], "requested_output": "out"}),
            ),
            &[("Idempotency-Key", key)],
        )
    };
    let (s, v) = submit("c-1");
    assert_eq!(
        s, 404,
        "the late joiner's job over hospital-a's dataset: {v}"
    );
    // The members at approval time keep it.
    t.ok(&w.b_dev, "GET", &format!("/v1/assets/{d}"), None);
    // The owner approves again, now for the current members.
    let v = approve();
    assert_eq!(v["members"], json!(["hospital-a", "modelco", "other-co"]));
    t.ok(&w.c_dev, "GET", &format!("/v1/assets/{d}"), None);
    let (s, v) = submit("c-2");
    assert_eq!(s, 201, "{v}");
}

/// Review finding CP-A-2 (ENC-SF-2026-056): four eyes on a policy are two different people
/// with security_admin in the project owner's organization. An
/// organization admin cannot give security_admin to service accounts (on
/// rc.3 two such accounts approved a policy alone), and a collaborator's
/// security admins cannot approve a policy on the owner's project.
#[test]
fn policy_four_eyes_are_two_people_of_the_projects_owner() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let s =
        Arc::new(encompute_verification::ServiceSigner::from_seed("b-sock-1", &[71; 32]).unwrap());
    let (st, v) = t.call(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/service-accounts",
        Some(
            json!({"id": "b-sock-1", "kind": "automation", "public_key": s.public_key_hex(),
                    "roles": ["security_admin"]}),
        ),
    );
    assert_eq!(st, 400, "security_admin on an automation account: {v}");
    // An automation account without the role cannot propose either.
    t.ok(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/service-accounts",
        Some(
            json!({"id": "b-bot", "kind": "automation", "public_key": s.public_key_hex(),
                    "roles": ["operator"]}),
        ),
    );
    let (st, _) = t.call(
        &As::Service(Arc::new(
            encompute_verification::ServiceSigner::from_seed("b-bot", &[71; 32]).unwrap(),
        )),
        "POST",
        &format!("/v1/projects/{}/policies", w.project),
        Some(json!({"allow": "everything"})),
    );
    assert_eq!(st, 403);
    // A collaborator (hospital-a) proposes; its own security admins cannot
    // approve it on modelco's project; modelco's can.
    let s1 = user(t, &w.a_admin, "hospital-a", "a-sec1", &["security_admin"]);
    let s2 = user(t, &w.a_admin, "hospital-a", "a-sec2", &["security_admin"]);
    let pol = t.ok(
        &s1,
        "POST",
        &format!("/v1/projects/{}/policies", w.project),
        Some(json!({"from": "hospital-a"})),
    );
    let id = pol["id"].as_str().unwrap().to_owned();
    let (st, v) = t.call(&s2, "POST", &format!("/v1/policies/{id}/approve"), None);
    assert_eq!(
        st, 403,
        "a collaborator approved a policy on the owner's project: {v}"
    );
    let v = t.ok(
        &w.b_sec,
        "POST",
        &format!("/v1/policies/{id}/approve"),
        None,
    );
    assert_eq!(v["status"], "approved");
    // Same person twice is still refused.
    let pol = t.ok(
        &w.b_sec,
        "POST",
        &format!("/v1/projects/{}/policies", w.project),
        Some(json!({"v": 2})),
    );
    let id = pol["id"].as_str().unwrap();
    let (st, _) = t.call(
        &w.b_sec,
        "POST",
        &format!("/v1/policies/{id}/approve"),
        None,
    );
    assert_eq!(st, 403);
    t.ok(
        &w.b_sec2,
        "POST",
        &format!("/v1/policies/{id}/approve"),
        None,
    );
}

/// Review finding CP-A-3 (ENC-SF-2026-041): another tenant cannot squat the key broker an
/// asset names. Its registration under that name is refused, a broker of
/// another organization is refused at asset registration, and neither the
/// revocation nor the audit mapping of key releases ever crosses to a
/// broker of another organization. On rc.3 other-co wrote key.release
/// events into modelco's trail and received modelco's revocation.
#[test]
fn a_tenant_cannot_squat_another_organizations_key_broker() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let evil = Arc::new(
        encompute_verification::ServiceSigner::from_seed("keybroker-modelco", &[66; 32]).unwrap(),
    );
    let (s, v) = t.call(
        &w.c_admin,
        "POST",
        "/v1/organizations/other-co/service-accounts",
        Some(json!({"id": "keybroker-modelco", "kind": "keybroker",
                    "public_key": evil.public_key_hex(), "url": "http://attacker.example:1"})),
    );
    assert_eq!(
        s, 409,
        "squatting the name modelco's asset gives its broker: {v}"
    );
    // other-co's own broker, under another name: it cannot be named by
    // modelco's assets, and its messages never map to modelco's assets.
    let own = Arc::new(
        encompute_verification::ServiceSigner::from_seed("keybroker-otherco", &[67; 32]).unwrap(),
    );
    t.ok(
        &w.c_admin,
        "POST",
        "/v1/organizations/other-co/service-accounts",
        Some(json!({"id": "keybroker-otherco", "kind": "keybroker",
                    "public_key": own.public_key_hex(), "url": "http://attacker.example:1"})),
    );
    let (s, v) = t.call(
        &w.b_owner,
        "POST",
        "/v1/assets",
        Some(json!({"organization": "modelco", "kind": "model", "name": "model-8", "digest": "c".repeat(64),
                    "key_ref": {"broker": "keybroker-otherco", "provider": "openbao-transit",
                                "key_ref": "model-8", "key_version": 1}})),
    );
    assert_eq!(s, 409, "an asset naming another organization's broker: {v}");
    // Even if the database says a modelco asset names it (a write, or an
    // asset registered earlier), the broker reports nothing into modelco's
    // trail and receives none of modelco's revocations.
    t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE assets SET key_ref = jsonb_set(key_ref, '{broker}', '\"keybroker-otherco\"') WHERE id = $1",
            &[&w.model_b],
        )
        .unwrap();
    let m = encompute_verification::service::seal(
        &own,
        "key.release",
        "control-plane",
        Default::default(),
        &json!({"asset": "model-7", "allowed": true, "reason": "forged-by-other-co"}),
        300,
    )
    .unwrap();
    t.ok(
        &As::Service(own.clone()),
        "POST",
        "/v1/messages",
        Some(serde_json::to_value(&m).unwrap()),
    );
    let forged = audit_actions(t, &w.b_auditor)
        .into_iter()
        .filter(|e| e["action"] == "key.release.allowed")
        .count();
    assert_eq!(forged, 0, "other-co wrote into modelco's trail");
    t.ok(
        &w.b_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", w.model_b),
        None,
    );
    t.control.tick();
    let sent = t.transport.drain();
    assert!(
        !sent
            .iter()
            .any(|(url, _)| url == "http://attacker.example:1"),
        "revocation delivered to another organization's broker: {sent:?}"
    );
    // The platform registers the real broker under the name.
    let real =
        encompute_verification::ServiceSigner::from_seed("keybroker-modelco", &[41; 32]).unwrap();
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "keybroker-modelco", "kind": "keybroker", "public_key": real.public_key_hex()})),
    );
}

/// Review finding CP-A-4 (ENC-SF-2026-042): every grant has an API to take it back, effective
/// on the next request: disabling a user, removing a role, removing a
/// project member, withdrawing an asset approval (jobs not yet started
/// fail). Each is audited and refused to non-admins. rc.3 had none of
/// these routes.
#[test]
fn every_grant_can_be_withdrawn_through_the_api() {
    let Some(w) = world() else { return };
    let t = &w.t;
    // Disable a user: its next request is refused.
    let v = t.ok(&w.a_dev, "GET", "/v1/whoami", None);
    let a_dev = v["id"].as_str().unwrap().to_owned();
    let (s, _) = t.call(
        &w.a_owner,
        "POST",
        &format!("/v1/organizations/hospital-a/users/{a_dev}/disable"),
        None,
    );
    assert_eq!(s, 403, "a data owner disabled a user");
    let (s, _) = t.call(
        &w.b_admin,
        "POST",
        &format!("/v1/organizations/modelco/users/{a_dev}/disable"),
        None,
    );
    assert_eq!(s, 404, "another organization's user");
    t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/organizations/hospital-a/users/{a_dev}/disable"),
        None,
    );
    let (s, _) = t.call(&w.a_dev, "GET", "/v1/whoami", None);
    assert_eq!(s, 401);
    // Remove a role: effective on the next request.
    let v = t.ok(&w.b_dev, "GET", "/v1/whoami", None);
    let b_dev = v["id"].as_str().unwrap().to_owned();
    let v = t.ok(
        &w.b_admin,
        "POST",
        "/v1/organizations/modelco/memberships/remove",
        Some(json!({"principal": b_dev, "role": "ml_developer"})),
    );
    assert_eq!(v["removed"], json!(["ml_developer"]));
    let (s, _) = t.call(
        &w.b_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project, "program": EXACT})),
    );
    assert!(s == 403 || s == 404, "{s}");
    // Withdraw an approval: other members' unstarted jobs fail, and the
    // asset is no longer theirs to see.
    let d = w.dataset_a.clone();
    t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals"),
        Some(json!({"project": w.project, "purpose": "medical-training"})),
    );
    let b_dev2 = user(t, &w.b_admin, "modelco", "b-dev2", &["ml_developer"]);
    let p = t.ok(
        &b_dev2,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project,
                    "program": exact_over(&d, "hospital-a", "dataset", "medical-training")})),
    );
    let (s, j) = t.call_with(
        &b_dev2,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": p["id"], "purpose": "medical-training",
                    "source_assets": [d], "requested_output": "out"}),
        ),
        &[("Idempotency-Key", "b2-1")],
    );
    assert_eq!(s, 201, "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    let (s, _) = t.call(
        &w.b_admin,
        "POST",
        &format!("/v1/assets/{d}/approvals/withdraw"),
        Some(json!({"project": w.project, "purpose": "medical-training"})),
    );
    assert_eq!(s, 404, "only the owner withdraws its approval");
    let v = t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals/withdraw"),
        Some(json!({"project": w.project, "purpose": "medical-training"})),
    );
    assert_eq!(v["failed_jobs"], json!([job]));
    let v = t.ok(&b_dev2, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(v["state"], "failed", "{v}");
    let (s, _) = t.call(&b_dev2, "GET", &format!("/v1/assets/{d}"), None);
    assert_eq!(s, 404);
    assert!(t
        .control
        .anchored(encompute_control::govlog::NegSet::EndedJobs, &job)
        .unwrap());
    // Remove a project member: it no longer sees the project.
    let (s, _) = t.call(
        &w.c_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", w.project),
        Some(json!({"organization": "hospital-a"})),
    );
    assert_eq!(s, 404, "a non-member removed a member");
    t.ok(
        &w.b_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", w.project),
        Some(json!({"organization": "hospital-a"})),
    );
    let (s, _) = t.call(
        &w.a_owner,
        "GET",
        &format!("/v1/projects/{}", w.project),
        None,
    );
    assert_eq!(s, 404);
    let (s, _) = t.call(
        &w.b_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", w.project),
        Some(json!({"organization": "modelco"})),
    );
    assert_eq!(s, 403, "the owner cannot leave its project");
    // All of it is on the record.
    let a = audit_actions(t, &w.a_auditor);
    for action in ["user.disabled", "asset.approval_withdrawn", "project.left"] {
        assert!(a.iter().any(|e| e["action"] == action), "{action}");
    }
    let b = audit_actions(t, &w.b_auditor);
    for action in ["membership.removed", "project.member_removed", "job.failed"] {
        assert!(b.iter().any(|e| e["action"] == action), "{action}");
    }
}

/// Review finding CP-A-5 (ENC-SF-2026-057): membership needs the invited organization's
/// consent, and inviting answers the same whether the organization exists
/// (no existence oracle). On rc.3 the project owner added any organization
/// alone, and got 404 for unknown ones.
#[test]
fn membership_needs_the_invited_organizations_consent() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let p = t.ok(
        &w.c_dev,
        "POST",
        "/v1/projects",
        Some(json!({"organization": "other-co", "name": "probe"})),
    );
    let pid = p["id"].as_str().unwrap();
    let invite = |org: &str| {
        t.call(
            &w.c_admin,
            "POST",
            &format!("/v1/projects/{pid}/members"),
            Some(json!({"organization": org})),
        )
    };
    let (s1, v1) = invite("no-such-org");
    let (s2, v2) = invite("hospital-a");
    assert_eq!((s1, s2), (200, 200));
    assert_eq!(v1["status"], v2["status"]);
    assert_eq!(v2["status"], "invited");
    // Invited is not a member: hospital-a sees nothing yet, and the
    // project shows it as invited only.
    let (s, _) = t.call(&w.a_owner, "GET", &format!("/v1/projects/{pid}"), None);
    assert_eq!(s, 404);
    let v = t.ok(&w.c_dev, "GET", &format!("/v1/projects/{pid}"), None);
    assert_eq!(v["members"], json!(["other-co"]));
    assert_eq!(v["invited"], json!(["hospital-a"]));
    // hospital-a's trail tells it of the invitation; a non-admin cannot
    // accept; its admin declines.
    assert!(audit_actions(t, &w.a_admin)
        .iter()
        .any(|e| e["action"] == "project.invited" && e["project"] == pid));
    let (s, _) = t.call(
        &w.a_owner,
        "POST",
        &format!("/v1/projects/{pid}/members"),
        Some(json!({"organization": "hospital-a"})),
    );
    assert_eq!(s, 404);
    t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/projects/{pid}/members/remove"),
        Some(json!({"organization": "hospital-a"})),
    );
    let v = t.ok(&w.c_dev, "GET", &format!("/v1/projects/{pid}"), None);
    assert_eq!(v["invited"], json!([]));
    // Accepted, the membership is effective.
    invite("hospital-a");
    let v = t.ok(
        &w.a_admin,
        "POST",
        &format!("/v1/projects/{pid}/members"),
        Some(json!({"organization": "hospital-a"})),
    );
    assert_eq!(v["status"], "active");
    t.ok(&w.a_owner, "GET", &format!("/v1/projects/{pid}"), None);
}

/// Review finding CP-A-6 (ENC-SF-2026-058): a platform automation account (stored with the
/// organization `platform`) can be disabled; on rc.3 the route answered
/// 404 and the account kept working.
#[test]
fn a_platform_automation_account_can_be_disabled() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let s = Arc::new(
        encompute_verification::ServiceSigner::from_seed("platform-bot", &[77; 32]).unwrap(),
    );
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(
            json!({"id": "platform-bot", "kind": "automation", "public_key": s.public_key_hex(),
                    "roles": ["operator", "auditor"]}),
        ),
    );
    let (st, _) = t.call(
        &As::Service(s.clone()),
        "POST",
        "/v1/audit/checkpoints",
        None,
    );
    assert_eq!(st, 201);
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts/platform-bot/disable",
        None,
    );
    let (st, _) = t.call(&As::Service(s), "POST", "/v1/audit/checkpoints", None);
    assert_eq!(st, 401);
    assert!(t
        .control
        .anchored(
            encompute_control::govlog::NegSet::DisabledServices,
            "platform-bot"
        )
        .unwrap());
}

/// Submits a job over `sources` by modelco's developer, for `plan` and
/// `purpose` (idempotency key `key`).
fn submit_over(
    w: &World,
    plan: &Value,
    purpose: &str,
    sources: &[&str],
    key: &str,
) -> (u16, Value) {
    w.t.call_with(
        &w.b_dev,
        "POST",
        "/v1/jobs",
        Some(
            json!({"project": w.project, "plan": plan["id"], "purpose": purpose,
                    "source_assets": sources, "requested_output": "out"}),
        ),
        &[("Idempotency-Key", key)],
    )
}

fn plan_of(w: &World, program: &str) -> Value {
    w.t.ok(
        &w.b_dev,
        "POST",
        "/v1/plans",
        Some(json!({"project": w.project, "program": program})),
    )
}

/// Review finding rc.4 F1 (ENC-SF-2026-088): a job's purpose is the one its program declares.
/// An owner's approval for one purpose does not run a program declared for
/// another, nor a program that declares none (on rc.3 the request's free
/// text alone was compared with the approval, and both jobs were created).
#[test]
fn an_approval_covers_only_programs_declared_for_its_purpose() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let d = w.dataset_a.clone();
    t.ok(
        &w.a_owner,
        "POST",
        &format!("/v1/assets/{d}/approvals"),
        Some(json!({"project": w.project, "purpose": "medical-training"})),
    );
    // A program declared for marketing, submitted as "medical-training".
    let marketing = plan_of(&w, &exact_over(&d, "hospital-a", "dataset", "marketing"));
    let (s, v) = submit_over(&w, &marketing, "medical-training", &[&d], "p-1");
    assert_eq!(s, 403, "another purpose under the approved label: {v}");
    assert!(v["message"].as_str().unwrap().contains("marketing"), "{v}");
    // Stated honestly, it is not approved.
    let (s, v) = submit_over(&w, &marketing, "marketing", &[&d], "p-2");
    assert_eq!(s, 403, "{v}");
    // A program that declares no purpose cannot use another organization's
    // asset at all.
    let undeclared = plan_of(&w, EXACT);
    let (s, v) = submit_over(&w, &undeclared, "medical-training", &[&d], "p-3");
    assert_eq!(s, 403, "no declared purpose: {v}");
    // (Its own data needs no approval, so no purpose either; a program
    // that binds no registered asset lists none.)
    let (s, v) = submit_over(&w, &undeclared, "anything", &[], "p-4");
    assert_eq!(s, 201, "{v}");
    // The program declared for the approved purpose runs.
    let ok = plan_of(
        &w,
        &exact_over(&d, "hospital-a", "dataset", "medical-training"),
    );
    let (s, v) = submit_over(&w, &ok, "medical-training", &[&d], "p-5");
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["purpose"], "medical-training");
    let denied: Vec<Value> = audit_actions(t, &w.b_auditor)
        .into_iter()
        .filter(|e| e["action"] == "job.denied")
        .collect();
    assert!(
        denied
            .iter()
            .any(|e| e.to_string().contains("purpose_mismatch")),
        "{denied:?}"
    );
}

/// Review finding rc.4 F2 (ENC-SF-2026-089): the registered assets a program reads are its
/// job's sources, exactly. A submitter cannot leave out the asset the
/// program reads (skipping its owner's approval), nor list an approved one
/// the program does not read in its place (on rc.3 both were accepted: only
/// the listed assets were checked).
#[test]
fn a_job_lists_exactly_the_registered_assets_its_program_reads() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let d = w.dataset_a.clone();
    // Another dataset of hospital-a's, never approved.
    let secret = t.ok(
        &w.a_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": "hospital-a", "kind": "dataset", "name": "not-shared",
                    "digest": "e".repeat(64)}),
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
    let reads_secret = plan_of(
        &w,
        &exact_over(&secret, "hospital-a", "dataset", "medical-training"),
    );
    // Left out: the unapproved asset the program reads.
    let (s, v) = submit_over(&w, &reads_secret, "medical-training", &[], "s-1");
    assert_eq!(s, 403, "an unlisted source: {v}");
    assert!(v["message"].as_str().unwrap().contains(&secret), "{v}");
    // Stood in for by the approved one.
    let (s, v) = submit_over(&w, &reads_secret, "medical-training", &[&d], "s-2");
    assert_eq!(s, 403, "an approved stand-in: {v}");
    // Listing it is refused as unapproved (not visible to modelco).
    let (s, v) = submit_over(&w, &reads_secret, "medical-training", &[&secret], "s-3");
    assert_eq!(s, 404, "{v}");
    // Extra sources the program does not read are refused too.
    let reads_d = plan_of(
        &w,
        &exact_over(&d, "hospital-a", "dataset", "medical-training"),
    );
    let (s, v) = submit_over(&w, &reads_d, "medical-training", &[&d, &w.model_b], "s-4");
    assert_eq!(s, 403, "an undeclared source: {v}");
    // A program that declares its inputs under labels of its own, not the
    // registered ID, cannot use another organization's asset.
    let labelled = exact_over("patients", "hospital-a", "dataset", "medical-training");
    let labelled = plan_of(&w, &labelled);
    let (s, v) = submit_over(&w, &labelled, "medical-training", &[&d], "s-5");
    assert_eq!(s, 403, "a source the program does not read by ID: {v}");
    let (s, v) = submit_over(&w, &reads_d, "medical-training", &[&d], "s-6");
    assert_eq!(s, 201, "{v}");
}

/// Review finding rc.4 F3 (ENC-SF-2026-090): a job over an asset whose policy requires job
/// approval is approved by a person of the owning organization, never by
/// its automation account holding data_owner (on rc.3 the account's
/// approval authorized the job).
#[test]
fn a_job_is_approved_by_a_person_of_the_owner() {
    let Some(w) = world() else { return };
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
    let plan = plan_of(
        &w,
        &exact_over(&d, "hospital-a", "dataset", "medical-training"),
    );
    let (s, j) = submit_over(&w, &plan, "medical-training", &[&d], "g-1");
    assert_eq!(s, 201, "{j}");
    assert_eq!(j["state"], "waiting_for_approval", "{j}");
    let job = j["id"].as_str().unwrap().to_owned();
    let bot =
        Arc::new(encompute_verification::ServiceSigner::from_seed("a-bot", &[73; 32]).unwrap());
    t.ok(
        &w.a_admin,
        "POST",
        "/v1/organizations/hospital-a/service-accounts",
        Some(
            json!({"id": "a-bot", "kind": "automation", "public_key": bot.public_key_hex(),
                    "roles": ["data_owner"]}),
        ),
    );
    let (s, v) = t.call(
        &As::Service(bot),
        "POST",
        &format!("/v1/jobs/{job}/approve"),
        None,
    );
    assert_eq!(s, 403, "a service account approved a job: {v}");
    let v = t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{job}"), None);
    assert_eq!(v["state"], "waiting_for_approval", "{v}");
    // The submitter's own people cannot approve either.
    let (s, _) = t.call(&w.b_admin, "POST", &format!("/v1/jobs/{job}/approve"), None);
    assert_eq!(s, 403);
    let v = t.ok(&w.a_owner, "POST", &format!("/v1/jobs/{job}/approve"), None);
    assert_ne!(v["state"], "waiting_for_approval", "{v}");
}

/// Review finding rc.4 F2 residual (ENC-SF-2026-094): a job's sources are
/// exactly the registered assets its program binds, for every job, the
/// submitter's own data included. The request's list must match that set:
/// an omitted, extra, substituted (another registered version), or
/// repeated asset is refused, and a program that binds none lists none (on
/// rc.3, a program binding no asset took any list the submitter gave, and
/// that list became the job's lineage, revocation scope and trust report).
#[test]
fn a_job_lists_exactly_the_assets_its_program_binds_even_its_own() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let register = |kind: &str, name: &str, digest: char| -> String {
        t.ok(
            &w.b_admin,
            "POST",
            "/v1/assets",
            Some(
                json!({"organization": "modelco", "kind": kind, "name": name,
                        "digest": digest.to_string().repeat(64)}),
            ),
        )["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let a = w.model_b.clone();
    let b = register("dataset", "own-cohort", 'c');
    let c = register("dataset", "own-other", 'd');
    // Two versions of one dataset are two registered assets.
    let v6 = register("dataset", "cohort@v6", '6');
    let v7 = register("dataset", "cohort@v7", '7');
    let reads_ab = plan_of(
        &w,
        &format!(
            "encompute 0.1
program adult precision 0.001 purpose \"medical-training\"
party \"modelco\" \"ModelCo\"
asset \"{a}\" model owners [\"modelco\"] readers [\"modelco\"] purposes [\"medical-training\"] release allowed_parties
asset \"{b}\" dataset owners [\"modelco\"] readers [\"modelco\"] purposes [\"medical-training\"] release allowed_parties
%0 = input \"age\" [0.0, 120.0] asset \"{a}\" : secret u8
%1 = input \"min\" [0.0, 120.0] asset \"{b}\" : secret u8
%2 = ge %0, %1 : secret bool
output \"out\" = %2 to \"modelco\"
"
        ),
    );
    let reads_a = plan_of(&w, &exact_own(&a));
    let reads_v7 = plan_of(&w, &exact_own(&v7));
    let binds_none = plan_of(&w, EXACT);
    let refused = |plan: &Value, sources: &[&str], key: &str, what: &str| {
        let (s, v) = submit_over(&w, plan, "medical-training", sources, key);
        assert_eq!(s, 403, "{what}: {v}");
        v
    };
    let accepted = |plan: &Value, sources: &[&str], key: &str| {
        let (s, v) = submit_over(&w, plan, "medical-training", sources, key);
        assert_eq!(s, 201, "{v}");
        v
    };
    // Missing: the program binds A and B; the job lists A.
    let v = refused(&reads_ab, &[&a], "ab-1", "an omitted source");
    assert!(v["message"].as_str().unwrap().contains(&b), "{v}");
    let v = accepted(&reads_ab, &[&a, &b], "ab-2");
    let mut want = vec![a.clone(), b.clone()];
    want.sort();
    assert_eq!(v["source_assets"], json!(want), "{v}");
    // Extra: the program binds A; the job lists A and C.
    let v = refused(&reads_a, &[&a, &c], "a-1", "an extra source");
    assert!(v["message"].as_str().unwrap().contains(&c), "{v}");
    // Substituted: the program binds v7; the job supplies v6.
    refused(&reads_v7, &[&v6], "v-1", "another version");
    refused(&reads_v7, &[&v6, &v7], "v-2", "another version besides");
    let v = accepted(&reads_v7, &[&v7], "v-3");
    assert_eq!(v["source_assets"], json!([v7]), "{v}");
    // Repeated.
    let v = refused(&reads_a, &[&a, &a], "a-2", "a repeated source");
    assert!(
        v["message"].as_str().unwrap().contains("more than once"),
        "{v}"
    );
    // A program that binds no registered asset: the job lists none, so it
    // can neither claim nor leave out provenance.
    let v = refused(
        &binds_none,
        &[&a],
        "n-1",
        "a source the program does not bind",
    );
    assert!(
        v["message"].as_str().unwrap().contains("binds no input"),
        "{v}"
    );
    let v = accepted(&binds_none, &[], "n-2");
    assert_eq!(v["source_assets"], json!([]), "{v}");
    // An ID the caller cannot see is not found, whether or not it exists.
    let hidden = w.dataset_a.clone();
    for (id, key) in [
        (hidden.as_str(), "h-1"),
        ("ast_0000000000000000000000000000dead", "h-2"),
    ] {
        let (s, v) = submit_over(&w, &binds_none, "medical-training", &[id], key);
        assert_eq!(s, 404, "{v}");
    }
    let reasons: Vec<String> = audit_actions(t, &w.b_auditor)
        .into_iter()
        .filter(|e| e["action"] == "job.denied")
        .map(|e| e["refs"]["reason"].as_str().unwrap_or_default().to_owned())
        .collect();
    for why in ["unlisted_source", "undeclared_source", "duplicate_source"] {
        assert!(reasons.iter().any(|r| r == why), "{why}: {reasons:?}");
    }
}

/// Review finding rc.4 F2 residual (ENC-SF-2026-094): the sources the
/// control plane derives from the program are the ones revocation, the
/// job record and the trust report follow; a recorded list that is not the
/// program's set fails the trust report instead of being reported (on
/// rc.3 the report took the submitter's list, with a caveat).
#[test]
fn the_derived_sources_drive_revocation_and_the_trust_report() {
    let Some(w) = world() else { return };
    let t = &w.t;
    let kb = Arc::new(
        encompute_verification::ServiceSigner::from_seed("keybroker-modelco", &[23; 32]).unwrap(),
    );
    t.ok(
        &w.platform,
        "POST",
        "/v1/organizations/platform/service-accounts",
        Some(json!({"id": "keybroker-modelco", "kind": "keybroker",
                    "public_key": kb.public_key_hex(), "url": "http://kb.internal:8760"})),
    );
    let source_row = |job: &str| -> Value {
        let r = t.ok(&w.b_dev, "GET", &format!("/v1/trust/{job}"), None);
        r["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["check"] == "source assets")
            .cloned()
            .unwrap_or_else(|| panic!("{r}"))
    };
    let binds = plan_of(&w, &exact_own(&w.model_b));
    let (s, j) = submit_over(&w, &binds, "medical-training", &[&w.model_b], "d-1");
    assert_eq!(s, 201, "{j}");
    let binding = j["id"].as_str().unwrap().to_owned();
    let (s, j) = submit_over(&w, &plan_of(&w, EXACT), "own-research", &[], "d-2");
    assert_eq!(s, 201, "{j}");
    let unbound = j["id"].as_str().unwrap().to_owned();
    // The trust report's source row is the program's set, and says nothing
    // about the submitter's word.
    let row = source_row(&binding);
    assert_eq!(row["sources"], json!([w.model_b]), "{row}");
    assert_eq!(row["status"], "VERIFIED", "{row}");
    let row = source_row(&unbound);
    assert_eq!(row["sources"], json!([]), "{row}");
    assert!(!row.to_string().contains("submitter"), "{row}");
    // Revoking the model fails exactly the job whose program binds it, and
    // no new job over it is accepted.
    let v = t.ok(
        &w.b_owner,
        "POST",
        &format!("/v1/assets/{}/revoke", w.model_b),
        None,
    );
    assert_eq!(v["failed_jobs"], json!([binding]), "{v}");
    let v = t.ok(&w.b_dev, "GET", &format!("/v1/jobs/{binding}"), None);
    assert_eq!(v["state"], "failed", "{v}");
    let (s, v) = submit_over(&w, &binds, "medical-training", &[&w.model_b], "d-3");
    assert_eq!(s, 409, "{v}");
    // ...and leaving it out of the list does not get around that.
    let (s, v) = submit_over(&w, &binds, "medical-training", &[], "d-4");
    assert_eq!(s, 403, "{v}");
    assert_eq!(source_row(&binding)["status"], "REVOKED");
    // A recorded list that differs from the program's bindings (a row
    // written before this check, or tampered with) fails the report.
    t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE jobs SET source_assets = '[]'::jsonb WHERE id = $1",
            &[&binding],
        )
        .unwrap();
    let row = source_row(&binding);
    assert_eq!(row["status"], "FAILED", "{row}");
    assert!(
        row["detail"].as_str().unwrap().contains(&w.model_b),
        "{row}"
    );
}
