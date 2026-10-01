//! INV-247: a governed project's audit is a shared, verifiable log. Members
//! and auditors read the project's own events with inclusion proofs against
//! the control plane's latest signed checkpoint, and each member
//! organization countersigns checkpoints (witnesses) with its governance
//! key. A checkpoint every member signed is labelled `witnessed`, any other
//! `unwitnessed`; the label never blocks a job, an authorization or an
//! export. The routes read the project's own partition and nothing else:
//! never another project's or an organization's events, never private
//! metadata, and the same bytes for every member.
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use common::gov::*;
use common::*;
use encompute_control::govlog::{self, Draft};
use encompute_trust::govlog::{
    kind, CheckpointWitness, GovEvent, InclusionProof, Partition, SignedProjectCheckpoint,
};
use encompute_verification::hex;

const OTHER: &str = "other-co";
const AUD: &str = "audit-office";

struct PA {
    g: G,
    tax_key: SigningKey,
    ben_key: SigningKey,
    ben_user_ids: Vec<String>,
}

fn control_key(g: &G) -> String {
    g.t.control.signer.public_key_hex()
}

/// A governed project of tax and benefits, each with an active governance
/// key, and a checkpoint covering what happened so far.
fn pa() -> Option<PA> {
    let g = gov_world()?;
    let (tax_key, ben_key) = (key(1), key(2));
    g.register_key(TAX, &g.tax_admin, &g.tax_sec1, &tax_key);
    g.register_key(BEN, &g.ben_admin, &g.ben_sec1, &ben_key);
    g.t.control.checkpoint_log().unwrap();
    let ben_user_ids = [&g.ben_admin, &g.ben_sec1, &g.ben_sec2]
        .iter()
        .map(|w| {
            g.t.ok(w, "GET", "/v1/whoami", None)["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    Some(PA {
        g,
        tax_key,
        ben_key,
        ben_user_ids,
    })
}

impl PA {
    fn p(&self) -> &str {
        &self.g.project
    }

    /// `n` more events in the project's log (and a checkpoint of them).
    fn events(&self, project: &str, tag: &str, n: usize) {
        self.g
            .t
            .control
            .db
            .tx(|t| {
                for i in 0..n {
                    govlog::append(
                        t,
                        Draft::new(
                            Partition::Project(project.to_owned()),
                            kind::ROLE_REMOVED,
                            &format!("rol_{tag}_{i}"),
                        ),
                    )?;
                }
                Ok(())
            })
            .unwrap();
        self.g.t.control.checkpoint_log().unwrap();
    }

    fn latest(&self, who: &As) -> Value {
        self.g.t.ok(
            who,
            "GET",
            &format!("/v1/projects/{}/checkpoints/latest", self.p()),
            None,
        )
    }

    fn witness(&self, org: &str, k: &SigningKey, latest: &Value) -> Value {
        let cp: SignedProjectCheckpoint =
            serde_json::from_value(latest["checkpoint"].clone()).unwrap();
        serde_json::to_value(
            CheckpointWitness {
                version: 1,
                organization: org.into(),
                partition: cp.body.partition.clone(),
                size: cp.body.size,
                root: cp.body.root.clone(),
                at: now(),
            }
            .sign(k)
            .unwrap(),
        )
        .unwrap()
    }

    fn post(&self, who: &As, size: u64, w: Value) -> (u16, Value) {
        self.post_to(who, self.p(), size, w)
    }

    fn post_to(&self, who: &As, project: &str, size: u64, w: Value) -> (u16, Value) {
        self.g.t.call(
            who,
            "POST",
            &format!("/v1/projects/{project}/checkpoints/{size}/witnesses"),
            Some(w),
        )
    }

    fn size(latest: &Value) -> u64 {
        latest["checkpoint"]["body"]["size"].as_u64().unwrap()
    }
}

fn who_reads(g: &G) -> [(&'static str, &As); 6] {
    [
        ("tax admin", &g.tax_admin),
        ("tax security admin", &g.tax_sec1),
        ("tax auditor", &g.tax_auditor),
        ("benefits admin", &g.ben_admin),
        ("benefits security admin", &g.ben_sec1),
        ("benefits security admin 2", &g.ben_sec2),
    ]
}

/// An auditor organization appointed to the project, and its people.
fn auditor_org(g: &G) -> (As, As) {
    g.t.ok(
        &g.platform,
        "POST",
        "/v1/organizations",
        Some(json!({"id": AUD, "display_name": AUD,
                    "admin": {"issuer": encompute_control::authn::DEV_ISSUER, "subject": "aud-admin"}})),
    );
    let admin = As::User("aud-admin".into());
    let auditor = user(&g.t, &admin, AUD, "aud-auditor", &["auditor"]);
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members", g.project),
        Some(json!({"organization": AUD, "participation": "auditor"})),
    );
    g.t.ok(
        &admin,
        "POST",
        &format!("/v1/projects/{}/members", g.project),
        Some(json!({"organization": AUD, "participation": "auditor"})),
    );
    (admin, auditor)
}

fn other_org(_: &G) -> As {
    As::User("c-admin".into())
}

/// Reads every page of the project's log as `who`: (the latest checkpoint
/// as the control plane signed it, the events with their proofs).
fn read_all(
    pa: &PA,
    who: &As,
    limit: u64,
) -> (
    SignedProjectCheckpoint,
    Vec<(GovEvent, String, InclusionProof)>,
) {
    let mut after = 0u64;
    let mut out = vec![];
    let mut cp = None;
    loop {
        let v = pa.g.t.ok(
            who,
            "GET",
            &format!("/v1/projects/{}/audit?after={after}&limit={limit}", pa.p()),
            None,
        );
        let c: SignedProjectCheckpoint = serde_json::from_value(v["checkpoint"].clone()).unwrap();
        if let Some(prev) = &cp {
            assert_eq!(prev, &c, "the checkpoint stays the same across pages");
        }
        cp = Some(c);
        for e in v["events"].as_array().unwrap() {
            out.push((
                serde_json::from_value(e["event"].clone()).unwrap(),
                e["leaf_hash"].as_str().unwrap().to_owned(),
                serde_json::from_value(e["inclusion_proof"].clone()).unwrap(),
            ));
        }
        match v["next"].as_u64() {
            Some(n) => after = n,
            None => break,
        }
    }
    (cp.unwrap(), out)
}

// --- witnessing ----------------------------------------------------------------

/// Every member organization countersigns one checkpoint: it is labelled
/// `witnessed` only then, and a repeated witness answers with the stored one.
#[test]
fn every_member_witnesses_one_checkpoint() {
    let Some(pa) = pa() else { return };
    pa.events(pa.p(), "w", 3);
    let latest = pa.latest(&pa.g.tax_sec1);
    assert_eq!(latest["witness_status"], "unwitnessed", "{latest}");
    assert_eq!(latest["members"], json!([BEN, TAX]), "{latest}");
    let size = PA::size(&latest);

    let (s, v) = pa.post(&pa.g.tax_sec1, size, pa.witness(TAX, &pa.tax_key, &latest));
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["witness_status"], "unwitnessed", "{v}");
    assert_eq!(v["missing_witnesses"], json!([BEN]), "{v}");

    let (s, v) = pa.post(&pa.g.ben_sec1, size, pa.witness(BEN, &pa.ben_key, &latest));
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["witness_status"], "witnessed", "{v}");
    assert_eq!(v["missing_witnesses"], json!([]), "{v}");

    // Both see it, with both countersignatures, on both routes.
    for who in [&pa.g.tax_admin, &pa.g.ben_admin] {
        let a = pa.latest(who);
        assert_eq!(a["witness_status"], "witnessed", "{a}");
        assert_eq!(a["witnesses"].as_array().unwrap().len(), 2, "{a}");
        let l =
            pa.g.t
                .ok(who, "GET", &format!("/v1/projects/{}/audit", pa.p()), None);
        assert_eq!(l["witness_status"], "witnessed", "{l}");
    }

    // Each countersignature verifies under its organization's governance key.
    let a = pa.latest(&pa.g.tax_admin);
    for w in a["witnesses"].as_array().unwrap() {
        let sw: encompute_trust::govlog::SignedCheckpointWitness =
            serde_json::from_value(w.clone()).unwrap();
        let k = if sw.body.organization == TAX {
            pa_key(&pa.tax_key)
        } else {
            pa_key(&pa.ben_key)
        };
        sw.verify(&k).unwrap();
    }

    // Repeating a witness is idempotent.
    let (s, v) = pa.post(&pa.g.tax_sec1, size, pa.witness(TAX, &pa.tax_key, &latest));
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["witness_status"], "witnessed", "{v}");

    // A later checkpoint starts unwitnessed again.
    pa.events(pa.p(), "w2", 1);
    let newer = pa.latest(&pa.g.tax_admin);
    assert_eq!(PA::size(&newer), size + 1);
    assert_eq!(newer["witness_status"], "unwitnessed", "{newer}");
}

fn pa_key(k: &SigningKey) -> String {
    pk(k)
}

/// A member that has not signed leaves the checkpoint `unwitnessed`, and
/// nothing is blocked by it: governed work goes on.
#[test]
fn a_missing_member_gives_the_unwitnessed_label() {
    let Some(pa) = pa() else { return };
    pa.events(pa.p(), "m", 2);
    let latest = pa.latest(&pa.g.ben_admin);
    let size = PA::size(&latest);
    let (s, v) = pa.post(&pa.g.tax_sec1, size, pa.witness(TAX, &pa.tax_key, &latest));
    assert_eq!(s, 201, "{v}");
    let l = pa.latest(&pa.g.ben_admin);
    assert_eq!(l["witness_status"], "unwitnessed", "{l}");
    assert_eq!(l["witnessed_by"], json!([TAX]), "{l}");
    assert_eq!(l["missing_witnesses"], json!([BEN]), "{l}");
    // A project nobody witnessed is labelled the same way.
    pa.events(pa.p(), "m2", 1);
    let l = pa.latest(&pa.g.ben_admin);
    assert_eq!(l["witnessed_by"], json!([]), "{l}");
    // Never a gate: a purpose is proposed, approved and active, and a
    // version registered, with every checkpoint unwitnessed.
    let purpose = pa.g.active_purpose("while-unwitnessed");
    assert!(!purpose.is_empty());
    assert!(!pa.g.version("2026-q4", 'd').is_empty());
}

/// The members at a size come from the log, not from who is a member now:
/// an organization that joined later does not make an old checkpoint
/// unwitnessed, one that left is still required for it.
#[test]
fn membership_at_a_size_comes_from_the_log() {
    let Some(pa) = pa() else { return };
    let before = PA::size(&pa.latest(&pa.g.tax_admin));
    // other-co joins, then leaves.
    let other = other_org(&pa.g);
    pa.g.t.ok(
        &pa.g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members", pa.p()),
        Some(json!({"organization": OTHER})),
    );
    pa.g.t.ok(
        &other,
        "POST",
        &format!("/v1/projects/{}/members", pa.p()),
        Some(json!({"organization": OTHER})),
    );
    pa.g.t.control.checkpoint_log().unwrap();
    let joined = PA::size(&pa.latest(&pa.g.tax_admin));
    assert_eq!(joined, before + 1);
    pa.g.t.ok(
        &pa.g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", pa.p()),
        Some(json!({"organization": OTHER})),
    );
    let left = PA::size(&pa.latest(&pa.g.tax_admin));
    assert_eq!(left, joined + 1);
    let mut c = pa.g.t.control.db.conn().unwrap();
    let at = |c: &mut _, n| govlog::members_at(c, pa.p(), n).unwrap();
    assert_eq!(at(&mut *c, before), [BEN, TAX]);
    assert_eq!(at(&mut *c, joined), [BEN, OTHER, TAX]);
    assert_eq!(at(&mut *c, left), [BEN, TAX]);
    // The removal says what was removed: a member.
    let events = govlog::events(&mut *c, &format!("p:{}", pa.p()), 0, 100).unwrap();
    let removed = events
        .iter()
        .find(|e| e.kind == kind::MEMBERSHIP_REMOVED)
        .unwrap();
    assert_eq!(removed.refs["participation"], "member");
    assert_eq!(removed.refs["status"], "active");
}

/// An invitation withdrawn before it was accepted, and an auditor
/// organization, are never members of a checkpoint.
#[test]
fn invitations_and_auditors_are_not_members() {
    let Some(pa) = pa() else { return };
    let (aud_admin, _) = auditor_org(&pa.g);
    // An invitation (other-co) withdrawn by the owner.
    pa.g.t.ok(
        &pa.g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members", pa.p()),
        Some(json!({"organization": OTHER})),
    );
    pa.g.t.ok(
        &pa.g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", pa.p()),
        Some(json!({"organization": OTHER})),
    );
    pa.g.t.ok(
        &aud_admin,
        "GET",
        &format!("/v1/projects/{}/audit", pa.p()),
        None,
    );
    pa.g.t.control.checkpoint_log().unwrap();
    let latest = pa.latest(&pa.g.tax_admin);
    assert_eq!(latest["members"], json!([BEN, TAX]), "{latest}");
    // And the auditor organization cannot witness.
    let (s, v) = pa.post(
        &aud_admin,
        PA::size(&latest),
        pa.witness(AUD, &pa.tax_key, &latest),
    );
    assert_eq!(s, 403, "{v}");
    assert!(v["message"].as_str().unwrap().contains("read-only"), "{v}");
}

// --- refusals ---------------------------------------------------------------------

/// A project's log is read by the people of organizations taking part: no
/// one else, and no one reads another project's.
#[test]
fn org_a_cannot_read_project_b_audit() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    // Project B: benefits' own governed project, with other-co.
    let other = other_org(g);
    let b = g.t.ok(
        &g.ben_admin,
        "POST",
        "/v1/projects",
        Some(
            json!({"organization": BEN, "name": "claims-review", "governance": "governed",
                        "organizations": [OTHER]}),
        ),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.t.ok(
        &other,
        "POST",
        &format!("/v1/projects/{b}/members"),
        Some(json!({"organization": OTHER})),
    );
    g.t.control.checkpoint_log().unwrap();

    // Tax is no part of B: every route says 404.
    for who in [&g.tax_admin, &g.tax_sec1, &g.tax_auditor] {
        for url in [
            format!("/v1/projects/{b}/audit"),
            format!("/v1/projects/{b}/audit?after=0&limit=1"),
            format!("/v1/projects/{b}/checkpoints/latest"),
            format!("/v1/projects/{b}/checkpoints/latest?since=0"),
        ] {
            let (s, v) = g.t.call(who, "GET", &url, None);
            assert_eq!(s, 404, "GET {url}: {v}");
        }
    }
    // And other-co is no part of A.
    for url in [
        format!("/v1/projects/{}/audit", pa.p()),
        format!("/v1/projects/{}/checkpoints/latest", pa.p()),
    ] {
        let (s, v) = g.t.call(&other, "GET", &url, None);
        assert_eq!(s, 404, "GET {url}: {v}");
    }
    // Unknown projects look the same.
    let (s, _) =
        g.t.call(&g.tax_admin, "GET", "/v1/projects/prj_nothing/audit", None);
    assert_eq!(s, 404);

    // What a member reads is its project's partition only.
    let (_, mine) = read_all(&pa, &g.tax_admin, 100);
    assert!(!mine.is_empty());
    for (e, _, _) in &mine {
        assert_eq!(e.partition, format!("p:{}", pa.p()));
    }
    let theirs = g.t.ok(
        &g.ben_admin,
        "GET",
        &format!("/v1/projects/{b}/audit"),
        None,
    );
    for e in theirs["events"].as_array().unwrap() {
        assert_eq!(e["event"]["partition"], format!("p:{b}"));
    }
    // Developers and others without a reader role are refused by role (403).
    let (s, v) = g.t.call(
        &g.tax_dev,
        "GET",
        &format!("/v1/projects/{}/audit", pa.p()),
        None,
    );
    assert_eq!(s, 403, "{v}");
}

/// An event and proof of project B do not verify against project A's
/// checkpoint, whichever way they are presented.
#[test]
fn a_proof_from_project_b_fails_against_project_a_checkpoint() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    let other = other_org(g);
    let b = g.t.ok(
        &g.ben_admin,
        "POST",
        "/v1/projects",
        Some(
            json!({"organization": BEN, "name": "claims-review", "governance": "governed",
                        "organizations": [OTHER]}),
        ),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.t.ok(
        &other,
        "POST",
        &format!("/v1/projects/{b}/members"),
        Some(json!({"organization": OTHER})),
    );
    pa.events(&b, "b", 4);
    pa.events(pa.p(), "a", 4);

    let (cp_a, a_events) = read_all(&pa, &g.tax_admin, 100);
    let b_page = g.t.ok(
        &g.ben_admin,
        "GET",
        &format!("/v1/projects/{b}/audit"),
        None,
    );
    let b_cp: SignedProjectCheckpoint =
        serde_json::from_value(b_page["checkpoint"].clone()).unwrap();
    cp_a.verify(&control_key(g)).unwrap();
    b_cp.verify(&control_key(g)).unwrap();
    // Each project's own events verify.
    for (e, _, p) in &a_events {
        cp_a.includes(e, p).unwrap();
    }
    let b_events = b_page["events"].as_array().unwrap();
    assert!(b_events.len() >= 5);
    for x in b_events {
        let e: GovEvent = serde_json::from_value(x["event"].clone()).unwrap();
        let p: InclusionProof = serde_json::from_value(x["inclusion_proof"].clone()).unwrap();
        b_cp.includes(&e, &p).unwrap();
        // B's event with B's proof against A's checkpoint.
        assert!(cp_a.includes(&e, &p).is_err());
        // B's event relabelled as A's: another leaf, another root.
        let mut relabelled = e.clone();
        relabelled.partition = cp_a.body.partition.clone();
        let mut relabelled_proof = p.clone();
        relabelled_proof.partition = cp_a.body.partition.clone();
        assert!(cp_a.includes(&relabelled, &relabelled_proof).is_err());
        // B's proof against A's tree at the same position.
        if let Some((a_event, _, _)) = a_events.iter().find(|(a, _, _)| a.pseq == e.pseq) {
            let mut mixed = p.clone();
            mixed.partition = cp_a.body.partition.clone();
            mixed.tree_size = cp_a.body.size;
            assert!(cp_a.includes(a_event, &mixed).is_err());
        }
    }
}

/// An auditor changes nothing: a witness from a member's auditor, from an
/// auditor organization's people and from a service account of either is
/// refused, and nothing is stored. (`auditor.rs` runs every mutating route.)
#[test]
fn auditor_post_is_refused() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    let (aud_admin, aud_auditor) = auditor_org(g);
    pa.events(pa.p(), "aud", 1);
    let latest = pa.latest(&g.tax_admin);
    let size = PA::size(&latest);
    // The auditor organization reads.
    pa.latest(&aud_auditor);
    pa.latest(&aud_admin);
    // Tax's auditor (read-only in a member organization) and the auditor
    // organization's people write nothing.
    for (who, org, k) in [
        (&g.tax_auditor, TAX, &pa.tax_key),
        (&aud_auditor, AUD, &pa.tax_key),
        (&aud_admin, AUD, &pa.tax_key),
    ] {
        let (s, v) = pa.post(who, size, pa.witness(org, k, &latest));
        assert_eq!(s, 403, "{org}: {v}");
        assert!(v["message"].as_str().unwrap().contains("read-only"), "{v}");
    }
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM checkpoint_witnesses", &[])
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
    assert_eq!(pa.latest(&g.tax_admin)["witness_status"], "unwitnessed");
}

/// Only a member organization's human security admin witnesses, for an
/// organization that was a member at that size.
#[test]
fn witness_from_a_non_member_refused() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    pa.events(pa.p(), "nm", 2);
    let latest = pa.latest(&g.tax_admin);
    let size = PA::size(&latest);
    let other = other_org(g);
    // other-co has a governance key, but takes no part: 404.
    let other_sec = user(&g.t, &other, OTHER, "o-sec1", &["security_admin"]);
    let other_sec2 = user(&g.t, &other, OTHER, "o-sec2", &["security_admin"]);
    let other_key = key(3);
    g.register_key(OTHER, &other_sec, &other_sec2, &other_key);
    let (s, v) = pa.post(&other_sec, size, pa.witness(OTHER, &other_key, &latest));
    assert_eq!(s, 404, "{v}");
    // A member's security admin cannot witness for another organization.
    let (s, v) = pa.post(&g.tax_sec1, size, pa.witness(BEN, &pa.ben_key, &latest));
    assert_eq!(s, 404, "{v}");
    // Nor can a person without the role, an organization admin, a service
    // account.
    for who in [&g.tax_admin, &g.tax_dev, &g.tax_owner, &g.robot] {
        let (s, v) = pa.post(who, size, pa.witness(TAX, &pa.tax_key, &latest));
        assert!(s == 403, "{s} {v}");
    }
    // other-co joins after the checkpoint: it was not a member at that size.
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members", pa.p()),
        Some(json!({"organization": OTHER})),
    );
    g.t.ok(
        &other,
        "POST",
        &format!("/v1/projects/{}/members", pa.p()),
        Some(json!({"organization": OTHER})),
    );
    let (s, v) = pa.post(&other_sec, size, pa.witness(OTHER, &other_key, &latest));
    assert_eq!(s, 403, "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("not a member"),
        "{v}"
    );
    // A checkpoint that does not exist.
    let (s, v) = pa.post(
        &g.tax_sec1,
        size + 50,
        pa.witness(TAX, &pa.tax_key, &latest),
    );
    assert_eq!(s, 404, "{v}");
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM checkpoint_witnesses", &[])
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
}

/// A witness of another root, size or partition is refused (ENC2718), and
/// so is one signed by someone else.
#[test]
fn witness_with_wrong_root_refused_2718() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    pa.events(pa.p(), "wr", 3);
    let latest = pa.latest(&g.tax_admin);
    let size = PA::size(&latest);
    let cp: SignedProjectCheckpoint = serde_json::from_value(latest["checkpoint"].clone()).unwrap();
    let signed = |f: &dyn Fn(&mut CheckpointWitness)| {
        let mut w = CheckpointWitness {
            version: 1,
            organization: TAX.into(),
            partition: cp.body.partition.clone(),
            size,
            root: cp.body.root.clone(),
            at: now(),
        };
        f(&mut w);
        serde_json::to_value(w.sign(&pa.tax_key).unwrap()).unwrap()
    };
    for (what, w) in [
        ("another root", signed(&|w| w.root = "ab".repeat(32))),
        ("another size", signed(&|w| w.size = size - 1)),
        (
            "another partition",
            signed(&|w| w.partition = "p:prj_other".into()),
        ),
    ] {
        refused(pa.post(&g.tax_sec1, size, w), "ENC2718");
        let _ = what;
    }
    // The stored root is the control plane's: a root that the member holds
    // for the same size from another view does not become a witness.
    let (s, v) = pa.post(&g.tax_sec1, size, signed(&|w| w.root = hash_of(b"fork")));
    assert_eq!(s, 409, "{v}");
    assert_eq!(code(&v), "ENC2718");
    // Not signed by the key: ENC2701.
    let mut forged = signed(&|_| {});
    forged["signature"] = json!("0".repeat(128));
    refused(pa.post(&g.tax_sec1, size, forged), "ENC2701");
    // A key that is not the organization's.
    let stranger = CheckpointWitness {
        version: 1,
        organization: TAX.into(),
        partition: cp.body.partition.clone(),
        size,
        root: cp.body.root.clone(),
        at: now(),
    }
    .sign(&key(99))
    .unwrap();
    refused(
        pa.post(&g.tax_sec1, size, serde_json::to_value(stranger).unwrap()),
        "ENC2701",
    );
    // A date in the future.
    refused(
        pa.post(&g.tax_sec1, size, signed(&|w| w.at = now() + 7200)),
        "ENC1102",
    );
    // The correct witness is accepted.
    let (s, v) = pa.post(&g.tax_sec1, size, signed(&|_| {}));
    assert_eq!(s, 201, "{v}");
}

fn hash_of(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(b))
}

/// A governance key that was revoked witnesses nothing, even when a new one
/// is active: ENC2708.
#[test]
fn witness_under_revoked_key_refused() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    // Revoke tax's key (an event of the project, checkpointed before the
    // call returns), then register a fresh one.
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    let id = keys[0]["id"].as_str().unwrap().to_owned();
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/organizations/{TAX}/governance-keys/{id}/revoke"),
        None,
    );
    let latest = pa.latest(&g.tax_admin);
    let size = PA::size(&latest);
    // No active key at all.
    refused(
        pa.post(&g.tax_sec1, size, pa.witness(TAX, &pa.tax_key, &latest)),
        "ENC2708",
    );
    // A new key is active; the revoked one still witnesses nothing.
    let fresh = key(55);
    g.register_key(TAX, &g.tax_admin, &g.tax_sec1, &fresh);
    refused(
        pa.post(&g.tax_sec1, size, pa.witness(TAX, &pa.tax_key, &latest)),
        "ENC2708",
    );
    let (s, v) = pa.post(&g.tax_sec1, size, pa.witness(TAX, &fresh, &latest));
    assert_eq!(s, 201, "{v}");
}

// --- the log's contents --------------------------------------------------------------

/// What the routes return is shared-safe: the same bytes for every member
/// and auditor, only identifiers, no private metadata and no event of another
/// partition, even after events that involve private data.
#[test]
fn project_audit_leaves_are_shared_safe() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    let (aud_admin, aud_auditor) = auditor_org(g);
    // Events that involve private metadata: a key revocation (its KMS
    // reference), a retired purpose, a job.
    let keys = g.t.ok(
        &g.ben_sec1,
        "GET",
        &format!("/v1/organizations/{BEN}/governance-keys"),
        None,
    );
    g.t.ok(
        &g.ben_sec1,
        "POST",
        &format!(
            "/v1/organizations/{BEN}/governance-keys/{}/revoke",
            keys[0]["id"].as_str().unwrap()
        ),
        None,
    );
    let purpose = g.active_purpose("canary");
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    pa.events(pa.p(), "canary", 2);

    let url = format!("/v1/projects/{}/audit?limit=500", pa.p());
    let reference = serde_json::to_string(&g.t.ok(&g.tax_admin, "GET", &url, None)).unwrap();
    let mut readers: Vec<(&str, &As)> = who_reads(g).to_vec();
    readers.push(("auditor organization", &aud_auditor));
    readers.push(("auditor organization admin", &aud_admin));
    let mut canaries: Vec<String> = pa.ben_user_ids.clone();
    canaries.extend([
        "vault:transit".into(),
        hex(&pa.tax_key.to_bytes()),
        hex(&pa.ben_key.to_bytes()),
        "t-sec1".into(),
        "t-owner".into(),
        "b-sec1".into(),
        "b-admin".into(),
        "storage".into(),
        "s3://".into(),
        "kms".into(),
    ]);
    for (name, who) in readers {
        let (s, v) = g.t.call(who, "GET", &url, None);
        assert_eq!(s, 200, "{name}: {v}");
        // Byte-identical for everyone.
        assert_eq!(serde_json::to_string(&v).unwrap(), reference, "{name}");
        let text = v.to_string();
        for c in &canaries {
            assert!(!text.contains(c.as_str()), "{name} sees {c:?}: {text}");
        }
    }
    // The events themselves: identifiers only, in the project's partition.
    let v: Value = serde_json::from_str(&reference).unwrap();
    let events = v["events"].as_array().unwrap();
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["event"]["kind"].as_str().unwrap())
        .collect();
    for want in [
        "membership.added",
        "governance_key.revoked",
        "purpose.retired",
        "role.removed",
    ] {
        assert!(kinds.contains(&want), "{want} in {kinds:?}");
    }
    for e in events {
        let ev: GovEvent = serde_json::from_value(e["event"].clone()).unwrap();
        ev.check().unwrap();
        assert_eq!(ev.partition, format!("p:{}", pa.p()));
        assert_eq!(e["leaf_hash"], hash_hex_of(&ev));
    }
    // Another organization's own events (its users, its service accounts)
    // are in none of it.
    assert!(!reference.contains("user.disabled") && !reference.contains("service_account"));
}

fn hash_hex_of(e: &GovEvent) -> String {
    encompute_trust::govlog::hash_hex(&e.leaf_hash().unwrap())
}

/// Every returned proof verifies offline against the signed checkpoint with
/// the trust crate, page by page, and a changed event, proof or checkpoint
/// does not.
#[test]
fn pagination_proofs_verify_offline() {
    let Some(pa) = pa() else { return };
    pa.events(pa.p(), "pg", 12);
    let key = control_key(&pa.g);
    for limit in [1, 3, 5, 100] {
        let (cp, events) = read_all(&pa, &pa.g.ben_admin, limit);
        cp.verify(&key).unwrap();
        let size = cp.body.size;
        assert!(size >= 13, "{size}");
        assert_eq!(events.len() as u64, size, "every event, once");
        for (i, (e, leaf, proof)) in events.iter().enumerate() {
            assert_eq!(e.pseq, i as u64 + 1, "in order, without gaps");
            assert_eq!(leaf, &hash_hex_of(e));
            cp.includes(e, proof).unwrap();
            // Edited event, proof or checkpoint fail.
            let mut edited = e.clone();
            edited.subject.push('x');
            assert!(cp.includes(&edited, proof).is_err());
            let mut bad = proof.clone();
            if let Some(h) = bad.path.first_mut() {
                *h = "0".repeat(64);
                assert!(cp.includes(e, &bad).is_err());
            }
            let mut forked = cp.clone();
            forked.body.root = "1".repeat(64);
            assert!(forked.verify(&key).is_err());
        }
    }
    // A page is bounded, whatever the caller asks.
    let big = pa.g.t.ok(
        &pa.g.ben_admin,
        "GET",
        &format!("/v1/projects/{}/audit?limit=100000", pa.p()),
        None,
    );
    assert!(big["events"].as_array().unwrap().len() <= 200);
}

/// The consistency proof from an older size to the latest verifies and is
/// signed by the control plane; a size beyond the latest is refused.
#[test]
fn checkpoints_extend_with_signed_consistency_proofs() {
    let Some(pa) = pa() else { return };
    pa.events(pa.p(), "c1", 3);
    let first = pa.latest(&pa.g.tax_admin);
    let n1 = PA::size(&first);
    pa.events(pa.p(), "c2", 5);
    let url = format!("/v1/projects/{}/checkpoints/latest?since={n1}", pa.p());
    let v = pa.g.t.ok(&pa.g.tax_admin, "GET", &url, None);
    let latest: SignedProjectCheckpoint = serde_json::from_value(v["checkpoint"].clone()).unwrap();
    let old: SignedProjectCheckpoint = serde_json::from_value(first["checkpoint"].clone()).unwrap();
    let proof: encompute_trust::govlog::SignedConsistencyProof =
        serde_json::from_value(v["consistency"].clone()).unwrap();
    let key = control_key(&pa.g);
    assert_eq!(
        encompute_trust::govlog::check_extension(&key, &old, &latest, Some(&proof)).unwrap(),
        encompute_trust::govlog::Extension::Consistent
    );
    assert_eq!(proof.body.first, n1);
    assert_eq!(proof.body.second, latest.body.size);
    proof.verify_signature(&key).unwrap();
    // Without `since` there is no proof; beyond the latest size is refused.
    let v = pa.latest(&pa.g.tax_admin);
    assert!(v["consistency"].is_null());
    // A size beyond the latest: the checkpoint, and no proof.
    let v = pa.g.t.ok(
        &pa.g.tax_admin,
        "GET",
        &format!("/v1/projects/{}/checkpoints/latest?since=100000", pa.p()),
        None,
    );
    assert!(v["consistency"].is_null() && !v["checkpoint"].is_null());
    let (s, _) = pa.g.t.call(
        &pa.g.tax_admin,
        "GET",
        &format!("/v1/projects/{}/checkpoints/latest?since=abc", pa.p()),
        None,
    );
    assert_eq!(s, 400);
}

/// Cadence: a deny event is checkpointed before the call that made it
/// returns, so a member can witness it at once; other events wait for the
/// next background checkpoint.
#[test]
fn a_deny_event_is_checkpointed_before_the_call_returns() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    pa.events(pa.p(), "cad", 1);
    let before = PA::size(&pa.latest(&g.tax_admin));
    // A deny event: a governance key revoked.
    let keys = g.t.ok(
        &g.ben_sec1,
        "GET",
        &format!("/v1/organizations/{BEN}/governance-keys"),
        None,
    );
    g.t.ok(
        &g.ben_sec1,
        "POST",
        &format!(
            "/v1/organizations/{BEN}/governance-keys/{}/revoke",
            keys[0]["id"].as_str().unwrap()
        ),
        None,
    );
    assert_eq!(PA::size(&pa.latest(&g.tax_admin)), before + 1);
    // Another organization joining (not a deny event) is checkpointed by the
    // next background pass.
    let other = other_org(g);
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members", pa.p()),
        Some(json!({"organization": OTHER})),
    );
    g.t.ok(
        &other,
        "POST",
        &format!("/v1/projects/{}/members", pa.p()),
        Some(json!({"organization": OTHER})),
    );
    g.t.control.checkpoint_log().unwrap();
    assert_eq!(PA::size(&pa.latest(&g.tax_admin)), before + 2);
}

/// Standard projects are unchanged: no project partition, no new events, no
/// shared log.
#[test]
fn standard_project_unchanged() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    let p = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "plain", "organizations": [BEN]})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.t.ok(
        &g.ben_admin,
        "POST",
        &format!("/v1/projects/{p}/members"),
        Some(json!({"organization": BEN})),
    );
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{p}/members/remove"),
        Some(json!({"organization": BEN})),
    );
    let mut c = g.t.control.db.conn().unwrap();
    let in_project: i64 = c
        .query_one(
            "SELECT count(*) FROM governance_events WHERE partition = $1",
            &[&format!("p:{p}")],
        )
        .unwrap()
        .get(0);
    assert_eq!(in_project, 0, "a standard project has no partition");
    let removed = c
        .query_one(
            "SELECT body FROM governance_events WHERE kind = 'membership.removed' AND subject_id IN
               (SELECT id FROM removed_memberships WHERE project_id = $1)",
            &[&p],
        )
        .unwrap();
    let e: GovEvent = serde_json::from_value(removed.get(0)).unwrap();
    assert_eq!(e.partition, format!("o:{TAX}"));
    assert_eq!(
        e.refs.keys().map(String::as_str).collect::<Vec<_>>(),
        ["project"],
        "the event is as it always was"
    );
    // The shared log and witnessing belong to governed projects.
    for (m, url) in [
        ("GET", format!("/v1/projects/{p}/audit")),
        ("GET", format!("/v1/projects/{p}/checkpoints/latest")),
    ] {
        let (s, v) = g.t.call(&g.tax_admin, m, &url, None);
        assert_eq!(s, 400, "{url}: {v}");
    }
    let (s, v) = pa.post_to(
        &g.tax_sec1,
        &p,
        1,
        json!({
        "body": {"version": 1, "organization": TAX, "partition": format!("p:{p}"),
                 "size": 1, "root": "0".repeat(64), "at": now()},
        "public_key": "0".repeat(64), "signature": "0".repeat(128)}),
    );
    assert_eq!(s, 409, "{v}");
}

// --- former members, service accounts, older projects ---------------------------------

/// A member removed after a checkpoint can still countersign the sizes at
/// which it was a member (and only that): the project's reads stay closed
/// to it (404).
#[test]
fn member_removed_after_checkpoint_can_still_witness_older_sizes() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    pa.events(pa.p(), "fm", 2);
    let latest = pa.latest(&g.tax_admin);
    let size = PA::size(&latest);
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", pa.p()),
        Some(json!({"organization": BEN})),
    );
    // Benefits no longer reads the project.
    for url in [
        format!("/v1/projects/{}/audit", pa.p()),
        format!("/v1/projects/{}/checkpoints/latest", pa.p()),
    ] {
        let (s, v) = g.t.call(&g.ben_sec1, "GET", &url, None);
        assert_eq!(s, 404, "{url}: {v}");
    }
    // But it countersigns what it was a member of.
    let (s, v) = pa.post(&g.ben_sec1, size, pa.witness(BEN, &pa.ben_key, &latest));
    assert_eq!(s, 201, "{v}");
    let (s, v) = pa.post(&g.tax_sec1, size, pa.witness(TAX, &pa.tax_key, &latest));
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["witness_status"], "witnessed", "{v}");
    // A person without the role, or a service account, still cannot.
    let (s, v) = pa.post(&g.ben_admin, size, pa.witness(BEN, &pa.ben_key, &latest));
    assert_eq!(s, 403, "{v}");
}

#[test]
fn cannot_witness_sizes_after_removal() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    pa.events(pa.p(), "fm2", 1);
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", pa.p()),
        Some(json!({"organization": BEN})),
    );
    pa.events(pa.p(), "fm3", 1);
    let after = pa.latest(&g.tax_admin);
    let size = PA::size(&after);
    assert_eq!(after["members"], json!([TAX]), "{after}");
    // Not a member at that size, and not a reader: 404, nothing stored.
    let (s, v) = pa.post(&g.ben_sec1, size, pa.witness(BEN, &pa.ben_key, &after));
    assert_eq!(s, 404, "{v}");
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM checkpoint_witnesses", &[])
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
    // The members of the later checkpoint are tax alone: it witnesses.
    let (s, v) = pa.post(&g.tax_sec1, size, pa.witness(TAX, &pa.tax_key, &after));
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["witness_status"], "witnessed", "{v}");
}

/// A service account holding security_admin from before it was refused
/// does not witness: a person does (ENC2707).
#[test]
fn service_account_witness_refused() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    pa.events(pa.p(), "sa", 1);
    let bot = std::sync::Arc::new(
        encompute_verification::ServiceSigner::from_seed("tax-witness-bot", &[61; 32]).unwrap(),
    );
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/organizations/{TAX}/service-accounts"),
        Some(json!({"id": "tax-witness-bot", "kind": "automation",
                    "public_key": bot.public_key_hex(), "roles": ["operator"]})),
    );
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "INSERT INTO memberships (principal_id, organization_id, role)
             VALUES ('tax-witness-bot', $1, 'security_admin')",
            &[&TAX],
        )
        .unwrap();
    let latest = pa.latest(&g.tax_admin);
    let size = PA::size(&latest);
    let who = As::Service(bot);
    refused(
        pa.post(&who, size, pa.witness(TAX, &pa.tax_key, &latest)),
        "ENC2707",
    );
    // It reads nothing it should not either: the project's log is open to a
    // service account with a reader role only.
    let n: i64 =
        g.t.control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM checkpoint_witnesses", &[])
            .unwrap()
            .get(0);
    assert_eq!(n, 0);
}

/// A project whose members joined before the log recorded joins: its
/// current members count as members from the start, and witnessing works.
#[test]
fn project_predating_membership_events() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    let p2 = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(
            json!({"organization": TAX, "name": "older", "governance": "governed",
                        "organizations": [BEN]}),
        ),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Benefits' acceptance, as an older release wrote it: no event.
    g.t.control
        .db
        .conn()
        .unwrap()
        .execute(
            "UPDATE project_members SET status = 'active' WHERE project_id = $1 AND organization_id = $2",
            &[&p2, &BEN],
        )
        .unwrap();
    pa.events(&p2, "old", 2);
    let latest = g.t.ok(
        &g.tax_admin,
        "GET",
        &format!("/v1/projects/{p2}/checkpoints/latest"),
        None,
    );
    assert_eq!(latest["members"], json!([BEN, TAX]), "{latest}");
    let size = PA::size(&latest);
    let (s, v) = pa.post_to(
        &g.tax_sec1,
        &p2,
        size,
        pa.witness(TAX, &pa.tax_key, &latest),
    );
    assert_eq!(s, 201, "{v}");
    let (s, v) = pa.post_to(
        &g.ben_sec1,
        &p2,
        size,
        pa.witness(BEN, &pa.ben_key, &latest),
    );
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["witness_status"], "witnessed", "{v}");
}

// --- parameters, empty projects, cost -----------------------------------------------------

/// Malformed parameters are refused, not defaulted; a project with no
/// checkpoint yet answers both routes the same way.
#[test]
fn malformed_parameters_are_refused_and_empty_projects_answer_alike() {
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    pa.events(pa.p(), "q", 2);
    for q in [
        "audit?after=abc",
        "audit?after=-1",
        "audit?limit=abc",
        "audit?limit=0",
        "audit?limit=-5",
        "audit?after=1.5",
        "checkpoints/latest?since=abc",
        "checkpoints/latest?since=-1",
        "checkpoints/latest?since=",
    ] {
        let (s, v) = g.t.call(
            &g.tax_admin,
            "GET",
            &format!("/v1/projects/{}/{q}", pa.p()),
            None,
        );
        assert_eq!(s, 400, "{q}: {v}");
    }
    // Valid ones are as before; a since beyond the latest is the checkpoint
    // with no proof (the caller sees what that means).
    let v = g.t.ok(
        &g.tax_admin,
        "GET",
        &format!("/v1/projects/{}/checkpoints/latest?since=100000", pa.p()),
        None,
    );
    assert!(
        v["consistency"].is_null() && !v["checkpoint"].is_null(),
        "{v}"
    );
    // A project nobody has an event in.
    let fresh = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "quiet", "governance": "governed"})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let a = g.t.ok(
        &g.tax_admin,
        "GET",
        &format!("/v1/projects/{fresh}/audit"),
        None,
    );
    let b = g.t.ok(
        &g.tax_admin,
        "GET",
        &format!("/v1/projects/{fresh}/checkpoints/latest"),
        None,
    );
    assert!(a["checkpoint"].is_null() && b["checkpoint"].is_null());
    assert_eq!(a, b, "the two routes answer alike");
    assert_eq!(a["events"], json!([]));
}

/// A page of proofs costs a bounded number of statements however many
/// events it holds (one range fetch of tree nodes, none when the nodes are
/// cached), pages are capped at 200 events, and a caller is limited.
#[test]
fn a_page_costs_a_bounded_number_of_statements() {
    use std::sync::atomic::Ordering;
    let Some(pa) = pa() else { return };
    let g = &pa.g;
    pa.events(pa.p(), "big", 3000);
    let url = |after: u64, limit: u64| {
        format!("/v1/projects/{}/audit?after={after}&limit={limit}", pa.p())
    };
    let counter = || govlog::NODE_QUERIES.load(Ordering::Relaxed);
    // Other tests run in this process in sequence only (one test binary,
    // run alone here), so the counter is this test's.
    let before = counter();
    let start = std::time::Instant::now();
    let page = g.t.ok(&g.tax_admin, "GET", &url(1000, 100000), None);
    assert_eq!(page["events"].as_array().unwrap().len(), 200, "capped");
    assert!(counter() - before <= 1, "one range fetch for 200 proofs");
    assert!(start.elapsed().as_secs() < 5);
    // The same page again comes from the cache.
    let before = counter();
    g.t.ok(&g.tax_admin, "GET", &url(1000, 200), None);
    assert_eq!(counter(), before, "hot nodes are not read again");
    // Every page of the log: at most one range fetch each, and every proof
    // verifies.
    let (cp, events) = read_all(&pa, &g.tax_admin, 200);
    assert!(cp.body.size >= 3000);
    assert_eq!(events.len() as u64, cp.body.size);
    for (e, _, p) in events.iter().step_by(97) {
        cp.includes(e, p).unwrap();
    }
    let pages = cp.body.size.div_ceil(200);
    assert!(
        counter() - before <= pages,
        "{} for {pages} pages",
        counter() - before
    );

    // Per caller, a limit: past it the call is refused, and others go on.
    g.t.control.project_log_limit.set(4);
    let mut statuses = vec![];
    for _ in 0..6 {
        statuses.push(g.t.call(&g.ben_admin, "GET", &url(0, 1), None).0);
    }
    assert_eq!(statuses, [200, 200, 200, 200, 503, 503]);
    assert_eq!(g.t.call(&g.ben_sec2, "GET", &url(0, 1), None).0, 200);
    g.t.control.project_log_limit.set(120);
}
