//! INV-247 (owner revocation heads). An organization signs, with its
//! governance key, the root over every revocation it made in a governed
//! project; the control plane states that root from its log
//! (`GET /v1/projects/{id}/revocation-heads/{org}/draft`) and accepts a
//! head only when the root is its own fold, the number is the next one and
//! the key is the organization's active key (ENC2717). A governed
//! revocation sent with its head is accepted with it or not at all, and a
//! revocation without one leaves the head owed (derived from the log).
//!
//! Needs PostgreSQL (`ENCOMPUTE_TEST_DATABASE_URL`); skipped without it
//! unless `ENCOMPUTE_REQUIRE_SERVICES=1`.

mod common;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use common::gov::*;
use common::*;
use encompute_trust::govlog::{
    hash_hex, kind, revocation_root, GovEvent, RevocationHead, SignedRevocationHead,
};

const OTHER: &str = "other-co";
const AUD: &str = "audit-office";

struct RH {
    g: G,
    tax_key: SigningKey,
    ben_key: SigningKey,
}

fn rh() -> Option<RH> {
    let g = gov_world()?;
    let (tax_key, ben_key) = (key(1), key(2));
    g.register_key(TAX, &g.tax_admin, &g.tax_sec1, &tax_key);
    g.register_key(BEN, &g.ben_admin, &g.ben_sec1, &ben_key);
    g.t.control.checkpoint_log().unwrap();
    Some(RH {
        g,
        tax_key,
        ben_key,
    })
}

impl RH {
    fn p(&self) -> &str {
        &self.g.project
    }

    fn draft_url(&self, org: &str) -> String {
        format!("/v1/projects/{}/revocation-heads/{org}/draft", self.p())
    }

    fn draft(&self, who: &As, org: &str) -> Value {
        self.g.t.ok(who, "GET", &self.draft_url(org), None)
    }

    fn heads_url(&self) -> String {
        format!("/v1/projects/{}/revocation-heads", self.p())
    }

    /// A head of `org` over `root`, signed by `k`.
    fn head(
        &self,
        org: &str,
        k: &SigningKey,
        seq: u64,
        root: &str,
        at: u64,
    ) -> SignedRevocationHead {
        RevocationHead {
            version: 1,
            organization: org.into(),
            project: self.p().into(),
            seq,
            root: root.into(),
            at,
        }
        .sign(k)
        .unwrap()
    }

    /// The head the draft asks for, signed.
    fn sign_draft(&self, org: &str, k: &SigningKey, d: &Value) -> SignedRevocationHead {
        self.head(
            org,
            k,
            d["seq"].as_u64().unwrap(),
            d["root"].as_str().unwrap(),
            now(),
        )
    }

    fn post(&self, who: &As, h: &SignedRevocationHead) -> (u16, Value) {
        self.g.t.call(
            who,
            "POST",
            &self.heads_url(),
            Some(serde_json::to_value(h).unwrap()),
        )
    }

    /// An authorization tax signed: (row ID, AuthorizationId).
    fn authorization(&self, name: &str, digest: char) -> (String, String) {
        let g = &self.g;
        let purpose = g.active_purpose(name);
        let (s, v) = g.accept(&g.tax_sec2, TAX, &purpose, &self.tax_key);
        assert_eq!(s, 200, "{v}");
        let version = g.version(name, digest);
        g.activated(&purpose, &version, &self.tax_key)
    }

    fn revoke(&self, who: &As, row: &str, head: Option<&SignedRevocationHead>) -> (u16, Value) {
        let mut body = json!({"reason": "withdrawn"});
        if let Some(h) = head {
            body["revocation_head"] = serde_json::to_value(h).unwrap();
        }
        self.g.t.call(
            who,
            "POST",
            &format!("/v1/authorizations/{row}/revoke"),
            Some(body),
        )
    }

    fn events(&self, kinds: &[&str]) -> Vec<GovEvent> {
        let kinds: Vec<String> = kinds.iter().map(|k| (*k).to_owned()).collect();
        self.g
            .t
            .control
            .db
            .conn()
            .unwrap()
            .query(
                "SELECT body FROM governance_events WHERE partition = $1 AND kind = ANY($2) ORDER BY pseq",
                &[&format!("p:{}", self.p()), &kinds],
            )
            .unwrap()
            .iter()
            .map(|r| serde_json::from_value(r.get(0)).unwrap())
            .collect()
    }

    fn stored(&self) -> i64 {
        self.g
            .t
            .control
            .db
            .conn()
            .unwrap()
            .query_one("SELECT count(*) FROM revocation_heads", &[])
            .unwrap()
            .get(0)
    }
}

fn leaves(d: &Value) -> Vec<String> {
    d["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect()
}

fn root_of(l: &[String]) -> String {
    hash_hex(&revocation_root(l).unwrap())
}

/// An organization that takes no part in the project, with a governance key.
fn outsider(rh: &RH) -> (As, SigningKey) {
    let g = &rh.g;
    let admin = As::User("c-admin".into());
    let sec1 = user(&g.t, &admin, OTHER, "o-sec1", &["security_admin"]);
    let sec2 = user(&g.t, &admin, OTHER, "o-sec2", &["security_admin"]);
    let k = key(3);
    g.register_key(OTHER, &sec1, &sec2, &k);
    (sec1, k)
}

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
    for who in [&g.tax_admin, &admin] {
        g.t.ok(
            who,
            "POST",
            &format!("/v1/projects/{}/members", g.project),
            Some(json!({"organization": AUD, "participation": "auditor"})),
        );
    }
    (admin, auditor)
}

// --- the draft and the head ---------------------------------------------------

/// The root of a head must be the control plane's own fold of the
/// organization's revocations in the log: another root is refused (ENC2717),
/// and the draft names the leaves it was folded from.
#[test]
fn head_root_must_match_the_control_planes_fold() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let (row, auth) = rh.authorization("fold", 'e');
    // Nothing revoked: an empty draft with the root over no leaves.
    let d = rh.draft(&g.tax_sec1, TAX);
    assert_eq!(d["seq"], 1, "{d}");
    assert_eq!(leaves(&d), Vec::<String>::new(), "{d}");
    assert_eq!(d["root"], root_of(&[]), "{d}");
    assert_eq!(d["pending_since"], Value::Null, "{d}");
    // A first head over no revocation is a head.
    let first = rh.sign_draft(TAX, &rh.tax_key, &d);
    let (s, v) = rh.post(&g.tax_sec1, &first);
    assert_eq!(s, 201, "{v}");

    // A revocation, with no head: the draft lists it and the head is owed.
    let (s, v) = rh.revoke(&g.tax_sec1, &row, None);
    assert_eq!(s, 200, "{v}");
    let d = rh.draft(&g.tax_sec1, TAX);
    assert_eq!(d["seq"], 2, "{d}");
    assert_eq!(leaves(&d), [format!("authorization.revoked:{auth}")], "{d}");
    assert!(d["pending_since"].as_u64().is_some(), "{d}");
    assert_eq!(d["overdue"], false, "{d}");
    assert_eq!(d["root"], root_of(&leaves(&d)), "{d}");

    // The old root, an invented root and a root over a leaf of another
    // organization's: all refused, nothing stored.
    for root in [
        root_of(&[]),
        "ab".repeat(32),
        root_of(&["asset.revoked:ast_1".to_string()]),
    ] {
        let h = rh.head(TAX, &rh.tax_key, 2, &root, now());
        refused(rh.post(&g.tax_sec1, &h), "ENC2717");
    }
    assert_eq!(rh.stored(), 1);
    // The control plane's own root is accepted, and clears what was owed.
    let h = rh.sign_draft(TAX, &rh.tax_key, &d);
    let (s, v) = rh.post(&g.tax_sec1, &h);
    assert_eq!(s, 201, "{v}");
    assert_eq!(v["revocations"], 1, "{v}");
    let d = rh.draft(&g.tax_sec1, TAX);
    assert_eq!(d["seq"], 3, "{d}");
    assert_eq!(d["pending_since"], Value::Null, "{d}");
    assert_eq!(d["previous"]["seq"], 2, "{d}");
    // A project's heads are one organization's: benefits has none.
    let b = rh.draft(&g.ben_sec1, BEN);
    assert_eq!((b["seq"].as_u64(), leaves(&b).len()), (Some(1), 0), "{b}");
}

/// Numbers run 1, 2, 3 per organization and project: a skipped or repeated
/// number is refused (ENC2717), and so is a date in the future or before the
/// previous head.
#[test]
fn skipped_or_replayed_seq_refused() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let d = rh.draft(&g.tax_sec1, TAX);
    let root = d["root"].as_str().unwrap().to_owned();
    // Skipped: the first head is number 1.
    refused(
        rh.post(&g.tax_sec1, &rh.head(TAX, &rh.tax_key, 2, &root, now())),
        "ENC2717",
    );
    let t0 = now();
    let one = rh.head(TAX, &rh.tax_key, 1, &root, t0);
    assert_eq!(rh.post(&g.tax_sec1, &one).0, 201);
    // Replayed: the same head again, and the number again with another date.
    refused(rh.post(&g.tax_sec1, &one), "ENC2717");
    refused(
        rh.post(&g.tax_sec1, &rh.head(TAX, &rh.tax_key, 1, &root, t0 + 1)),
        "ENC2717",
    );
    // Skipped past the next.
    refused(
        rh.post(&g.tax_sec1, &rh.head(TAX, &rh.tax_key, 3, &root, t0 + 1)),
        "ENC2717",
    );
    // Dated in the future (beyond five minutes) or before the previous head.
    refused(
        rh.post(
            &g.tax_sec1,
            &rh.head(TAX, &rh.tax_key, 2, &root, now() + 3600),
        ),
        "ENC2717",
    );
    refused(
        rh.post(&g.tax_sec1, &rh.head(TAX, &rh.tax_key, 2, &root, t0 - 1)),
        "ENC2717",
    );
    // Numbered from 0.
    let zero = RevocationHead {
        version: 1,
        organization: TAX.into(),
        project: rh.p().into(),
        seq: 0,
        root: root.clone(),
        at: t0,
    };
    let signed = encompute_trust::authz::Signed {
        body: zero,
        public_key: pk(&rh.tax_key),
        signature: "0".repeat(128),
    };
    refused(rh.post(&g.tax_sec1, &signed), "ENC2717");
    // A head for another project.
    let mut other = rh.head(TAX, &rh.tax_key, 2, &root, now());
    other.body.project = "proj_elsewhere".into();
    refused(rh.post(&g.tax_sec1, &other), "ENC2717");
    assert_eq!(rh.stored(), 1);
    // The next number, dated a little ahead (clock skew), is accepted.
    assert_eq!(
        rh.post(
            &g.tax_sec1,
            &rh.head(TAX, &rh.tax_key, 2, &root, now() + 30)
        )
        .0,
        201
    );
    // Each organization numbers its own.
    let b = rh.draft(&g.ben_sec1, BEN);
    assert_eq!(b["seq"], 1);
    assert_eq!(
        rh.post(&g.ben_sec1, &rh.sign_draft(BEN, &rh.ben_key, &b)).0,
        201
    );
}

/// A head under a revoked governance key (or not the organization's key, or
/// with an edited body) is refused: nothing is stored.
#[test]
fn head_under_a_revoked_key_refused() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let d = rh.draft(&g.tax_sec1, TAX);
    // Signed by a key that is not tax's.
    let stranger = key(77);
    let (s, v) = rh.post(&g.tax_sec1, &rh.sign_draft(TAX, &stranger, &d));
    assert_eq!(s, 403, "{v}");
    assert_eq!(code(&v), "ENC2701", "{v}");
    // An edited body under the right key.
    let mut forged = rh.sign_draft(TAX, &rh.tax_key, &d);
    forged.body.at += 1;
    let (s, v) = rh.post(&g.tax_sec1, &forged);
    assert_eq!(s, 403, "{v}");
    assert_eq!(code(&v), "ENC2701", "{v}");
    // Signed while the key was active, posted after it is revoked.
    let h = rh.sign_draft(TAX, &rh.tax_key, &d);
    let keys = g.t.ok(
        &g.tax_sec1,
        "GET",
        &format!("/v1/organizations/{TAX}/governance-keys"),
        None,
    );
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!(
            "/v1/organizations/{TAX}/governance-keys/{}/revoke",
            keys[0]["id"].as_str().unwrap()
        ),
        None,
    );
    let (s, v) = rh.post(&g.tax_sec1, &h);
    assert_eq!(s, 403, "{v}");
    assert_eq!(code(&v), "ENC2708", "{v}");
    assert_eq!(rh.stored(), 0);
    // The revocation of the key is itself a leaf of tax's next head.
    let d = rh.draft(&g.tax_sec1, TAX);
    assert_eq!(leaves(&d).len(), 1, "{d}");
    assert!(leaves(&d)[0].starts_with("governance_key.revoked:"), "{d}");
    assert!(d["pending_since"].as_u64().is_some(), "{d}");
}

/// Only a member organization's own security admin (a person) signs for it:
/// an organization that takes no part gets 404, another member's admin
/// cannot sign for the organization, and nobody without the role can.
#[test]
fn head_from_a_non_member_refused() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let d = rh.draft(&g.tax_sec1, TAX);
    let root = d["root"].as_str().unwrap().to_owned();
    let (other_sec, other_key) = outsider(&rh);
    // Takes no part: nothing is revealed, not even that the project exists.
    let (s, v) = rh.post(&other_sec, &rh.head(OTHER, &other_key, 1, &root, now()));
    assert_eq!(s, 404, "{v}");
    let (s, v) = g.t.call(&other_sec, "GET", &rh.draft_url(OTHER), None);
    assert_eq!(s, 404, "{v}");
    let (s, v) = g.t.call(&other_sec, "GET", &rh.draft_url(TAX), None);
    assert_eq!(s, 404, "{v}");
    // A member's security admin cannot sign for another organization, nor
    // read its draft.
    let (s, v) = rh.post(&g.ben_sec1, &rh.sign_draft(TAX, &rh.tax_key, &d));
    assert_eq!(s, 404, "{v}");
    let (s, v) = g.t.call(&g.ben_sec1, "GET", &rh.draft_url(TAX), None);
    assert_eq!(s, 403, "{v}");
    // Without the role, or a service account.
    for who in [&g.tax_admin, &g.tax_dev, &g.tax_owner, &g.robot] {
        let (s, v) = rh.post(who, &rh.sign_draft(TAX, &rh.tax_key, &d));
        assert_eq!(s, 403, "{v}");
    }
    // A member that joined and left: no draft, no head for it either.
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members", rh.p()),
        Some(json!({"organization": OTHER})),
    );
    g.t.ok(
        &As::User("c-admin".into()),
        "POST",
        &format!("/v1/projects/{}/members", rh.p()),
        Some(json!({"organization": OTHER})),
    );
    g.t.ok(
        &g.tax_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", rh.p()),
        Some(json!({"organization": OTHER})),
    );
    let (s, v) = rh.post(&other_sec, &rh.head(OTHER, &other_key, 1, &root, now()));
    assert_eq!(s, 404, "{v}");
    assert_eq!(rh.stored(), 0);
}

/// Two reads of a draft agree on everything except `at`, the server's
/// read time in whole seconds (it changes with the clock, not the log).
fn same_draft(a: &Value, b: &Value) -> bool {
    let strip = |v: &Value| {
        let mut v = v.clone();
        v.as_object_mut()
            .expect("a draft is an object")
            .remove("at");
        v
    };
    strip(a) == strip(b)
}

/// Two reads of one draft that straddle a second boundary differ in `at`
/// alone: a whole-value comparison (what the auditor test did) fails on
/// them, the draft comparison does not, and a real difference is still
/// seen. Deterministic: it forces the straddle the clock only produces
/// under load.
#[test]
fn reads_of_a_draft_that_straddle_a_second_boundary_agree() {
    let first = json!({"project": "p", "organization": "tax", "seq": 1, "root": "ab", "at": 1_000});
    let second =
        json!({"project": "p", "organization": "tax", "seq": 1, "root": "ab", "at": 1_001});
    assert_ne!(first, second, "the old comparison fails on a straddle");
    assert!(same_draft(&first, &second));
    let mut other = second.clone();
    other["root"] = json!("cd");
    assert!(!same_draft(&first, &other), "a changed root is still seen");
    other = second;
    other["seq"] = json!(2);
    assert!(
        !same_draft(&first, &other),
        "a changed number is still seen"
    );
}

/// Auditors read the draft and write nothing: not from a member
/// organization's auditor role, not from an appointed auditor organization.
#[test]
fn auditor_post_refused() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let (aud_admin, aud_auditor) = auditor_org(g);
    let d = rh.draft(&g.tax_sec1, TAX);
    for who in [&g.tax_auditor, &aud_auditor] {
        let (lo, r, hi) = (now(), rh.draft(who, TAX), now());
        // The draft carries the server's read time, in whole seconds: it
        // differs between two reads whenever a second boundary falls
        // between them. Each read's time is bracketed by the clock around
        // that read, and everything else must equal the first draft.
        let at = r["at"].as_u64().unwrap();
        assert!((lo..=hi).contains(&at), "{at} outside {lo}..={hi}");
        assert!(same_draft(&r, &d), "an auditor reads the draft: {r} vs {d}");
    }
    // The auditor organization's admin is not an auditor and not tax's
    // security admin: it reads nothing here.
    assert_eq!(g.t.call(&aud_admin, "GET", &rh.draft_url(TAX), None).0, 403);
    let h = rh.sign_draft(TAX, &rh.tax_key, &d);
    for who in [&g.tax_auditor, &aud_auditor, &aud_admin] {
        let (s, v) = rh.post(who, &h);
        assert_eq!(s, 403, "{v}");
        assert!(v["message"].as_str().unwrap().contains("read-only"), "{v}");
    }
    assert_eq!(rh.stored(), 0);
    // Tax's own security admin still can.
    assert_eq!(rh.post(&g.tax_sec1, &h).0, 201);
}

/// A governed revoke may carry the owner's next head: both are recorded or
/// neither. A wrong head (or one of another organization, a standard
/// project's) leaves the authorization usable and the log unchanged.
#[test]
fn governed_revoke_with_head_is_atomic() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let (row, auth) = rh.authorization("atomic", 'f');
    let before_events = rh.events(&[kind::AUTHORIZATION_REVOKED]);
    let d = rh.draft(&g.tax_sec1, TAX);
    let expected = vec![format!("authorization.revoked:{auth}")];
    // The head for the set that includes this revocation.
    let good = rh.head(TAX, &rh.tax_key, 1, &root_of(&expected), now() + 5);

    // A root that omits it, a wrong number, and another organization's
    // head each fail the whole call.
    for bad in [
        rh.head(TAX, &rh.tax_key, 1, d["root"].as_str().unwrap(), now()),
        rh.head(TAX, &rh.tax_key, 2, &root_of(&expected), now()),
        rh.head(BEN, &rh.ben_key, 1, &root_of(&expected), now()),
    ] {
        let (s, v) = rh.revoke(&g.tax_sec1, &row, Some(&bad));
        assert!(s == 409 || s == 403, "{s} {v}");
        let status = g.t.ok(
            &g.tax_sec1,
            "GET",
            &format!("/v1/authorizations/{row}"),
            None,
        )["status"]
            .clone();
        assert_ne!(status, "revoked", "the revocation was not recorded");
        assert_eq!(rh.stored(), 0);
        assert_eq!(
            rh.events(&[kind::AUTHORIZATION_REVOKED]),
            before_events,
            "no event of it is left"
        );
    }
    let (s, v) = rh.revoke(
        &g.tax_sec1,
        &row,
        Some(&rh.head(BEN, &rh.ben_key, 1, &root_of(&expected), now())),
    );
    assert_eq!(code(&v), "ENC2717", "{s} {v}");

    // With the right head: revoked, the head stored, nothing owed.
    let (s, v) = rh.revoke(&g.tax_sec1, &row, Some(&good));
    assert_eq!(s, 200, "{v}");
    assert_eq!(rh.stored(), 1);
    let d = rh.draft(&g.tax_sec1, TAX);
    assert_eq!(leaves(&d), expected, "{d}");
    assert_eq!(d["seq"], 2, "{d}");
    assert_eq!(d["pending_since"], Value::Null, "{d}");
    // The log shows the revocation, then its head, in order.
    let log = rh.events(&[kind::AUTHORIZATION_REVOKED, kind::REVOCATION_HEAD_SIGNED]);
    let kinds: Vec<&str> = log.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        [kind::AUTHORIZATION_REVOKED, kind::REVOCATION_HEAD_SIGNED]
    );
    // Repeating the call changes nothing (already revoked).
    let (s, _) = rh.revoke(&g.tax_sec1, &row, Some(&good));
    assert_eq!(s, 200);
    assert_eq!(rh.stored(), 1);

    // A purpose retired with its head, the same way.
    let purpose = g.active_purpose("retire-with-head");
    let d = rh.draft(&g.tax_sec1, TAX);
    let mut l = leaves(&d);
    l.push(format!("purpose.retired:{purpose}"));
    let wrong = rh.head(TAX, &rh.tax_key, 2, &root_of(&leaves(&d)), now());
    let url = format!("/v1/purposes/{purpose}/retire");
    let (s, v) = g.t.call(
        &g.tax_sec1,
        "POST",
        &url,
        Some(json!({"revocation_head": wrong})),
    );
    assert_eq!(code(&v), "ENC2717", "{s} {v}");
    let (_, p) =
        g.t.call(&g.tax_sec1, "GET", &format!("/v1/purposes/{purpose}"), None);
    assert_ne!(p["status"], "retired", "{p}");
    let right = rh.head(TAX, &rh.tax_key, 2, &root_of(&l), now() + 5);
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &url,
        Some(json!({"revocation_head": right})),
    );
    assert_eq!(rh.stored(), 2);
    assert_eq!(rh.draft(&g.tax_sec1, TAX)["pending_since"], Value::Null);
}

/// Revoking without a head works, as it did: the revocation takes effect at
/// once, nothing but its own event is recorded (every transition is one
/// event), and the head is owed: the draft says since when, in the
/// organization's draft only, until it signs the next.
#[test]
fn a_governed_revoke_without_a_head_leaves_a_head_owed() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let (row, _) = rh.authorization("owed", 'a');
    let (s, v) = rh.revoke(&g.tax_sec1, &row, None);
    assert_eq!(s, 200, "{v}");
    assert_eq!(rh.events(&[kind::AUTHORIZATION_REVOKED]).len(), 1);
    assert_eq!(
        rh.events(&[kind::REVOCATION_HEAD_SIGNED]).len(),
        0,
        "no head was made up"
    );
    let d = rh.draft(&g.tax_sec1, TAX);
    let since = rh.events(&[kind::AUTHORIZATION_REVOKED])[0].at;
    assert_eq!(d["pending_since"], since, "{d}");
    // Benefits' draft is not behind: only tax owes.
    assert_eq!(rh.draft(&g.ben_sec1, BEN)["pending_since"], Value::Null);
    // Tax signs the head: nothing is owed, and a revocation after it owes
    // the next.
    assert_eq!(
        rh.post(&g.tax_sec1, &rh.sign_draft(TAX, &rh.tax_key, &d)).0,
        201
    );
    assert_eq!(rh.draft(&g.tax_sec1, TAX)["pending_since"], Value::Null);
    let purpose = g.active_purpose("owed-later");
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
    let d = rh.draft(&g.tax_sec1, TAX);
    assert!(d["pending_since"].as_u64().is_some(), "{d}");
    assert_eq!(d["seq"], 2, "{d}");
}

/// A standard project is as it was: its revocations go to the owner's own
/// partition with no head owed, the head routes belong to governed projects,
/// and a revoke that names a head there is refused.
#[test]
fn standard_project_revocation_unchanged() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let p = g.t.ok(
        &g.tax_admin,
        "POST",
        "/v1/projects",
        Some(json!({"organization": TAX, "name": "plain"})),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, v) = g.t.call(
        &g.tax_sec1,
        "GET",
        &format!("/v1/projects/{p}/revocation-heads/{TAX}/draft"),
        None,
    );
    assert_eq!(s, 400, "{v}");
    let head = rh.head(TAX, &rh.tax_key, 1, &root_of(&[]), now());
    let mut h = serde_json::to_value(&head).unwrap();
    h["body"]["project"] = json!(p);
    let (s, v) = g.t.call(
        &g.tax_sec1,
        "POST",
        &format!("/v1/projects/{p}/revocation-heads"),
        Some(h),
    );
    assert_eq!(s, 409, "{v}");
    // An asset revoked: its event is where it always was, with no marker.
    let asset = g.t.ok(
        &g.tax_owner,
        "POST",
        "/v1/assets",
        Some(
            json!({"organization": TAX, "kind": "dataset", "name": "plain@1",
                    "series": "plain", "version": "1", "digest": "b".repeat(64),
                    "ir_policy": registered(TAX)["ir_policy"], "release_class": "boolean-only"}),
        ),
    );
    let id = asset["id"].as_str().unwrap().to_owned();
    let (s, v) = g.t.call(
        &g.tax_owner,
        "POST",
        &format!("/v1/assets/{id}/revoke"),
        None,
    );
    assert_eq!(s, 200, "{v}");
    let mut c = g.t.control.db.conn().unwrap();
    let heads: i64 = c
        .query_one(
            "SELECT count(*) FROM governance_events WHERE kind LIKE 'revocation_head.%'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(heads, 0, "a standard project has no head");
    let revoked: String = c
        .query_one(
            "SELECT partition FROM governance_events WHERE kind = 'asset.revoked'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(revoked, format!("o:{TAX}"));
    // The existing body-less purpose retirement route still parses.
    let purpose = g.active_purpose("retire-plain");
    g.t.ok(
        &g.tax_sec1,
        "POST",
        &format!("/v1/purposes/{purpose}/retire"),
        None,
    );
}

/// The head's events, the draft and the audit view hold only identifiers,
/// the same bytes for every reader: no key reference, person or private
/// metadata.
#[test]
fn revocation_head_event_is_shared_safe() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let (aud_admin, aud_auditor) = auditor_org(g);
    let (row, _) = rh.authorization("canary", 'c');
    assert_eq!(rh.revoke(&g.tax_sec1, &row, None).0, 200);
    let d = rh.draft(&g.tax_sec1, TAX);
    assert_eq!(
        rh.post(&g.tax_sec1, &rh.sign_draft(TAX, &rh.tax_key, &d)).0,
        201
    );
    g.t.control.checkpoint_log().unwrap();

    let url = format!("/v1/projects/{}/audit?limit=500", rh.p());
    let reference = serde_json::to_string(&g.t.ok(&g.tax_admin, "GET", &url, None)).unwrap();
    let mut canaries: Vec<String> = vec![
        "vault:transit".into(),
        hex_key(&rh.tax_key),
        hex_key(&rh.ben_key),
        "t-sec1".into(),
        "t-sec2".into(),
        "t-owner".into(),
        "b-sec1".into(),
        "storage".into(),
        "s3://".into(),
        "kms".into(),
        "withdrawn".into(),
    ];
    canaries.push("reason".into());
    for (name, who) in [
        ("tax admin", &g.tax_admin),
        ("tax auditor", &g.tax_auditor),
        ("benefits admin", &g.ben_admin),
        ("benefits security admin", &g.ben_sec1),
        ("auditor organization", &aud_auditor),
        ("auditor organization admin", &aud_admin),
    ] {
        let (s, v) = g.t.call(who, "GET", &url, None);
        assert_eq!(s, 200, "{name}: {v}");
        assert_eq!(serde_json::to_string(&v).unwrap(), reference, "{name}");
        // The signed head is the only place a key appears: the public one.
        let text = v["events"].to_string();
        for c in &canaries {
            assert!(!text.contains(c.as_str()), "{name} sees {c:?}: {text}");
        }
    }
    let v: Value = serde_json::from_str(&reference).unwrap();
    assert_eq!(v["revocation_heads"].as_array().unwrap().len(), 1, "{v}");
    let head = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["event"]["kind"] == kind::REVOCATION_HEAD_SIGNED)
        .expect("the head is in the log");
    let e: GovEvent = serde_json::from_value(head["event"].clone()).unwrap();
    e.check().unwrap();
    assert_eq!(e.partition, format!("p:{}", rh.p()));
    assert_eq!(e.org.as_deref(), Some(TAX));
    assert_eq!(
        e.refs.keys().map(String::as_str).collect::<Vec<_>>(),
        ["root", "seq"]
    );
}

fn hex_key(k: &SigningKey) -> String {
    encompute_verification::hex(&k.to_bytes())
}

/// A head is dated no earlier than the newest revocation it covers, a
/// refused head comes back with the current draft (retryable), and a draft
/// says when its organization cannot sign.
#[test]
fn head_dating_retry_body_and_cannot_sign_reason() {
    let Some(rh) = rh() else { return };
    let g = &rh.g;
    let (row, _) = rh.authorization("dating", 'd');
    assert_eq!(rh.revoke(&g.tax_sec1, &row, None).0, 200);
    let d = rh.draft(&g.tax_sec1, TAX);
    assert!(d["log_size"].as_u64().unwrap() >= 1, "{d}");
    assert_eq!(d["cannot_sign_reason"], Value::Null, "{d}");
    // Dated before the revocation it covers: refused.
    let newest = rh.events(&[kind::AUTHORIZATION_REVOKED])[0].at;
    let early = rh.head(TAX, &rh.tax_key, 1, d["root"].as_str().unwrap(), newest - 1);
    let (s, v) = rh.post(&g.tax_sec1, &early);
    assert_eq!((s, code(&v)), (409, "ENC2717"), "{v}");
    // A stale root: 409 with the current draft, retryable in one call.
    let stale = rh.head(TAX, &rh.tax_key, 1, &root_of(&[]), now());
    let (s, v) = rh.post(&g.tax_sec1, &stale);
    assert_eq!((s, code(&v)), (409, "ENC2717"), "{v}");
    assert_eq!(v["retryable"], true, "{v}");
    assert_eq!(v["draft"]["root"], d["root"], "{v}");
    let retry = rh.sign_draft(TAX, &rh.tax_key, &v["draft"]);
    assert_eq!(rh.post(&g.tax_sec1, &retry).0, 201);
    // No active governance key: the draft says so.
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
    let b = rh.draft(&g.ben_sec1, BEN);
    assert!(
        b["cannot_sign_reason"]
            .as_str()
            .unwrap()
            .contains("no active governance key"),
        "{b}"
    );
    // A member that left still owes what it left, and its draft says it
    // cannot sign (nothing to sign for).
    let (_, _) = rh.authorization("leaves", 'e');
    g.t.ok(
        &g.ben_admin,
        "POST",
        &format!("/v1/projects/{}/members/remove", rh.p()),
        Some(json!({"organization": BEN})),
    );
    let (s, v) = g.t.call(&g.tax_auditor, "GET", &rh.draft_url(BEN), None);
    assert_eq!(s, 200, "{v}");
    assert!(
        v["cannot_sign_reason"]
            .as_str()
            .unwrap()
            .contains("no longer takes part"),
        "{v}"
    );
}
