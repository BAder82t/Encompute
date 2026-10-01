//! The governance evidence bundle (INV-243): content addressed, no
//! plaintext, shared-safe views, offline verification against pins only.
//! Any edit, omission, reordering or unknown field fails.

use serde_json::Value;

use encompute_ir::Code;
use encompute_trust::bundle::check_view;
use encompute_trust::fixture::*;
use encompute_trust::{
    check_no_plaintext, GovernanceBundle, Outcome, Pin, Pins, Provenance, ReportOptions,
    VerifyOptions,
};

fn pins(fx: &Fixture) -> Pins {
    let obtained = "the agency's official key page".to_owned();
    Pins {
        organizations: [
            (
                TAX.to_owned(),
                encompute_trust::bundle::OrganizationPin {
                    identity_key: pk(&fx.tax),
                    obtained: obtained.clone(),
                },
            ),
            (
                BEN.to_owned(),
                encompute_trust::bundle::OrganizationPin {
                    identity_key: pk(&fx.ben),
                    obtained: obtained.clone(),
                },
            ),
            (
                OTHER.to_owned(),
                encompute_trust::bundle::OrganizationPin {
                    identity_key: pk(&fx.other),
                    obtained: obtained.clone(),
                },
            ),
        ]
        .into(),
        control_plane: Some(Pin {
            key: fx.control.public_key_hex(),
            obtained: "the control plane's /v1/info, checked by phone".into(),
        }),
        evaluators: vec![Pin {
            key: fx.evaluator.identity().public_key_hex(),
            obtained: obtained.clone(),
        }],
        ..Pins::default()
    }
}

fn opts<'a>(p: &'a Pins) -> VerifyOptions<'a> {
    VerifyOptions {
        pins: p,
        base: ReportOptions::default(),
        disclosures: vec![],
        as_of: None,
        now: Some(T0 + 10),
    }
}

fn org_bundle(fx: &Fixture) -> GovernanceBundle {
    GovernanceBundle::build(
        &format!("organization:{TAX}"),
        T0 + 200,
        "encompute-control",
        fx.graph.clone(),
        owner_view(fx),
        fx.audit.clone(),
        Provenance::default(),
    )
    .unwrap()
}

/// The evidence with only `tax-agency`'s signed authorization and a card
/// for the other's.
fn owner_view(fx: &Fixture) -> encompute_trust::GovernanceEvidence {
    let mut ev = fx.shared();
    let own = fx.documents().remove(0);
    for e in &mut ev.authorizations {
        if let encompute_trust::AuthorizationEntry::Card { card } = e {
            if card.id == own.id() {
                *e = encompute_trust::AuthorizationEntry::Signed {
                    document: Box::new(own.clone()),
                };
            }
        }
    }
    ev
}

fn shared_bundle(fx: &Fixture) -> GovernanceBundle {
    GovernanceBundle::build(
        "shared",
        T0 + 200,
        "encompute-control",
        fx.graph.clone(),
        fx.shared(),
        fx.audit.clone(),
        Provenance::default(),
    )
    .unwrap()
}

fn code<T: std::fmt::Debug>(r: encompute_ir::Result<T>) -> Code {
    r.unwrap_err().code
}

#[test]
fn export_then_offline_verify() {
    let fx = Fixture::build();
    let p = pins(&fx);
    let mut b = org_bundle(&fx);
    b.sign(TAX, &fx.tax).unwrap();
    let bytes = b.to_bytes().unwrap();
    // Read back from bytes alone, verified against the verifier's own pins.
    let back = GovernanceBundle::from_bytes(&bytes).unwrap();
    assert_eq!(back, b);
    // Tax-agency's own view shows its own signed document and a card of
    // benefits-agency's: benefits discloses its document.
    let mut o = opts(&p);
    o.disclosures = fx.documents();
    let v = back.verify(&o).unwrap();
    assert_eq!(v.signatures.len(), 1);
    assert_eq!(
        v.signatures[0].status,
        encompute_trust::SignatureStatus::Verified
    );
    // Everything this release can evidence passes; the result key's holder
    // is not recorded, so the outcome is "unchecked" (exit 3), not 0.
    assert_eq!(v.outcome, Outcome::Unchecked, "{}", v.report);
    assert_eq!(v.outcome.exit_code(), 3);
    assert_eq!(
        v.report.unmet,
        vec!["Decryption control is not evidenced".to_owned()]
    );
    assert!(v.notes.iter().any(|n| n.contains("provenance")));
    // The BundleId is the manifest's, and a signature does not change it.
    let unsigned = org_bundle(&fx);
    assert_eq!(unsigned.id().unwrap(), b.id().unwrap());
}

#[test]
fn offline_verification_trusts_only_pinned_keys() {
    let fx = Fixture::build();
    let b = org_bundle(&fx);
    // No pins at all: everything is unchecked, nothing passes.
    let none = Pins::default();
    let v = b.verify(&opts(&none)).unwrap();
    assert_eq!(v.outcome, Outcome::Unchecked);
    assert!(v.notes.iter().any(|n| n.contains("no pins")));
    for r in &v.report.rows {
        assert!(
            !matches!(
                r.status,
                encompute_trust::Status::Satisfied | encompute_trust::Status::Verified
            ),
            "{} passed without any pin",
            r.name
        );
    }
    // Pins for keys other than the bundle's: contradicted, never passed.
    let mut wrong = pins(&fx);
    wrong.organizations.get_mut(TAX).unwrap().identity_key = pk(&key(99));
    let v = b.verify(&opts(&wrong)).unwrap();
    assert_eq!(v.outcome, Outcome::NotSatisfied);
    // A signature by an organization nobody pinned is attribution only.
    let mut s = b.clone();
    s.sign("somebody-else", &key(5)).unwrap();
    let p = pins(&fx);
    let v = s.verify(&opts(&p)).unwrap();
    assert_eq!(
        v.signatures[0].status,
        encompute_trust::SignatureStatus::Unpinned
    );
    assert_eq!(v.outcome, Outcome::Unchecked);
    // A signature that does not verify under a pinned key is refused.
    let mut forged = b.clone();
    forged.sign(TAX, &key(99)).unwrap();
    assert_eq!(
        code(forged.verify(&opts(&p))),
        Code::GovernanceBundleUnverified
    );
    let mut forged = b.clone();
    forged.sign(TAX, &fx.tax).unwrap();
    forged.signatures[0].signature = "00".repeat(64);
    assert_eq!(
        code(forged.verify(&opts(&p))),
        Code::GovernanceBundleUnverified
    );
}

#[test]
fn unknown_fields_and_versions_are_refused() {
    let fx = Fixture::build();
    let b = org_bundle(&fx);
    let v: Value = serde_json::from_slice(&b.to_bytes().unwrap()).unwrap();
    let canon = |v: &Value| encompute_verification::canonical::canonical_json(v).unwrap();
    // An unknown field at the top, in the manifest, in a section and
    // deep inside.
    for path in [
        "",
        "/manifest",
        "/governance",
        "/audit",
        "/provenance",
        "/governance/grant",
        "/trust",
    ] {
        let mut x = v.clone();
        x.pointer_mut(if path.is_empty() { "" } else { path })
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), Value::Bool(true));
        assert_eq!(
            code(GovernanceBundle::from_bytes(&canon(&x))),
            Code::GovernanceBundleMalformed,
            "{path}"
        );
    }
    // An unknown format, section version or legal boundary.
    for (ptr, val) in [
        (
            "/manifest/format",
            Value::from("encompute.governance-bundle.v2"),
        ),
        ("/governance/version", Value::from(2)),
        ("/audit/version", Value::from(2)),
        ("/provenance/version", Value::from(2)),
        (
            "/manifest/legal_boundary",
            Value::from("encompute.legal-boundary.v2"),
        ),
        ("/trust/version", Value::from(2)),
    ] {
        let mut x = v.clone();
        *x.pointer_mut(ptr).unwrap() = val;
        assert!(GovernanceBundle::from_bytes(&canon(&x)).is_err(), "{ptr}");
    }
    // A missing section is an omitted section.
    for section in [
        "trust",
        "governance",
        "audit",
        "provenance",
        "manifest",
        "signatures",
    ] {
        let mut x = v.clone();
        x.as_object_mut().unwrap().remove(section);
        assert!(
            GovernanceBundle::from_bytes(&canon(&x)).is_err(),
            "{section}"
        );
    }
    // Not JSON, not an object, empty.
    for junk in [&b""[..], b"[]", b"null", b"{}"] {
        assert!(GovernanceBundle::from_bytes(junk).is_err());
    }
}

/// Each leaf of the file, changed, with the file otherwise untouched: the
/// section digests (or the manifest's own checks) refuse it.
#[test]
fn every_single_field_edit_fails() {
    let fx = Fixture::build();
    let p = pins(&fx);
    let mut b = org_bundle(&fx);
    b.sign(TAX, &fx.tax).unwrap();
    let v: Value = serde_json::from_slice(&b.to_bytes().unwrap()).unwrap();
    let canon = |v: &Value| encompute_verification::canonical::canonical_json(v).unwrap();
    let baseline = b.verify(&opts(&p)).unwrap();

    let mut leaves = vec![];
    fn walk(v: &Value, path: String, out: &mut Vec<String>) {
        match v {
            Value::Object(o) => o.iter().for_each(|(k, x)| {
                walk(
                    x,
                    format!("{path}/{}", k.replace('~', "~0").replace('/', "~1")),
                    out,
                )
            }),
            Value::Array(a) => a
                .iter()
                .enumerate()
                .for_each(|(i, x)| walk(x, format!("{path}/{i}"), out)),
            _ => out.push(path),
        }
    }
    walk(&v, String::new(), &mut leaves);
    assert!(leaves.len() > 300, "{} leaves", leaves.len());
    let mut undetected = vec![];
    for ptr in &leaves {
        let mut x = v.clone();
        let leaf = x.pointer_mut(ptr).unwrap();
        let new = match &*leaf {
            Value::String(s) => Value::String(if let Some(rest) = s.strip_prefix('a') {
                format!("b{rest}")
            } else {
                format!("a{}", &s[1.min(s.len())..])
            }),
            Value::Number(n) => Value::from(n.as_u64().map_or(1, |n| n + 1)),
            Value::Bool(b) => Value::Bool(!*b),
            _ => Value::from("x"),
        };
        *leaf = new;
        // Whatever the attacker does, the result is refused, or it is not
        // the baseline's: no edit passes unnoticed.
        let verdict = GovernanceBundle::from_bytes(&canon(&x)).and_then(|e| e.verify(&opts(&p)));
        match verdict {
            Err(_) => {}
            Ok(r) => {
                let sigs = |v: &encompute_trust::Verified| {
                    v.signatures
                        .iter()
                        .map(|s| (s.organization.clone(), s.status.clone()))
                        .collect::<Vec<_>>()
                };
                if r.outcome == baseline.outcome
                    && r.report.unmet == baseline.report.unmet
                    && sigs(&r) == sigs(&baseline)
                {
                    undetected.push(ptr.clone());
                }
            }
        }
    }
    assert!(
        undetected.is_empty(),
        "edits nobody noticed: {undetected:?}"
    );
}

#[test]
fn omission_and_reordering_fail() {
    let fx = Fixture::build();
    let mut b = org_bundle(&fx);
    b.sign(BEN, &fx.ben).unwrap();
    b.sign(TAX, &fx.tax).unwrap();
    let v: Value = serde_json::from_slice(&b.to_bytes().unwrap()).unwrap();
    let canon = |v: &Value| encompute_verification::canonical::canonical_json(v).unwrap();
    // Reordering the elements of any array: authorizations, events, heads,
    // witnesses, signatures.
    for ptr in [
        "/governance/authorizations",
        "/governance/purpose_acceptances",
        "/audit/events",
        "/audit/revocation_heads",
        "/audit/witnesses",
        "/audit/members",
    ] {
        let mut x = v.clone();
        let a = x.pointer_mut(ptr).unwrap().as_array_mut().unwrap();
        assert!(a.len() >= 2, "{ptr}");
        a.swap(0, 1);
        assert!(
            GovernanceBundle::from_bytes(&canon(&x)).is_err(),
            "reordered {ptr}"
        );
        // Omitting one is as bad.
        let mut x = v.clone();
        x.pointer_mut(ptr).unwrap().as_array_mut().unwrap().pop();
        assert!(
            GovernanceBundle::from_bytes(&canon(&x)).is_err(),
            "omitted from {ptr}"
        );
    }
    // Signatures are sorted: reordering them is refused (omitting one only
    // removes someone's vouching, which is attribution, not evidence).
    let mut x = v.clone();
    x.pointer_mut("/signatures")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    assert!(
        GovernanceBundle::from_bytes(&canon(&x)).is_err(),
        "reordered signatures"
    );
    // Reordered keys, or any other encoding, are not the canonical bytes.
    let text = String::from_utf8(b.to_bytes().unwrap()).unwrap();
    let spaced = text.replacen("{\"audit\"", "{ \"audit\"", 1);
    assert_ne!(spaced, text);
    assert!(GovernanceBundle::from_bytes(spaced.as_bytes()).is_err());
    let pretty = serde_json::to_vec_pretty(&v).unwrap();
    assert!(GovernanceBundle::from_bytes(&pretty).is_err());
    // A duplicated key.
    let dup = text.replacen("{\"audit\"", "{\"audit\":{},\"audit\"", 1);
    assert!(GovernanceBundle::from_bytes(dup.as_bytes()).is_err());
    // The same bytes verify.
    GovernanceBundle::from_bytes(text.as_bytes()).unwrap();
}

/// An attacker who recomputes every digest still cannot change what the
/// signed evidence says: each row reads the signatures, the proofs and the
/// pins, not the manifest.
#[test]
fn a_rebuilt_manifest_does_not_launder_an_edit() {
    let fx = Fixture::build();
    let p = pins(&fx);
    let b = org_bundle(&fx);
    let baseline = b.verify(&opts(&p)).unwrap();
    let rebuild = |g: encompute_trust::GovernanceEvidence, a: encompute_trust::AuditEvidence| {
        GovernanceBundle::build(
            &b.manifest.view,
            b.manifest.exported_at,
            &b.manifest.exported_by,
            b.trust.clone(),
            g,
            a,
            Provenance::default(),
        )
        .unwrap()
    };
    let mut g = b.governance.clone();
    g.grant.expires_at += 1;
    let r = rebuild(g, b.audit.clone()).verify(&opts(&p)).unwrap();
    assert_eq!(r.outcome, Outcome::NotSatisfied);
    let mut a = b.audit.clone();
    a.events[0].event.at += 1;
    let r = rebuild(b.governance.clone(), a).verify(&opts(&p)).unwrap();
    assert_eq!(r.outcome, Outcome::NotSatisfied);
    // An edit that re-signs with the attacker's own key is not the pinned
    // organization's.
    let mut g = b.governance.clone();
    let doc = match &g.authorizations[0] {
        encompute_trust::AuthorizationEntry::Signed { document } => document.body.clone(),
        encompute_trust::AuthorizationEntry::Card { .. } => {
            // The first is a card; take the signed one.
            fx.documents().remove(0).body
        }
    };
    let forged = doc.sign(&key(77)).unwrap();
    for e in &mut g.authorizations {
        if matches!(e, encompute_trust::AuthorizationEntry::Signed { .. }) {
            *e = encompute_trust::AuthorizationEntry::Signed {
                document: Box::new(forged.clone()),
            };
        }
    }
    let r = rebuild(g, b.audit.clone()).verify(&opts(&p)).unwrap();
    assert_eq!(r.outcome, Outcome::NotSatisfied);
    assert_eq!(baseline.outcome, Outcome::Unchecked);
}

#[test]
fn the_plaintext_guard_refuses_what_a_bundle_must_not_carry() {
    let fx = Fixture::build();
    // A string over the cap in a field that is not a text field.
    let mut g = fx.evidence.clone();
    g.job_id = "x".repeat(300);
    let e = GovernanceBundle::build(
        "shared",
        T0,
        "encompute-control",
        fx.graph.clone(),
        g,
        fx.audit.clone(),
        Provenance::default(),
    )
    .unwrap_err();
    // An identifier is checked as one before the guard sees it.
    assert_eq!(e.code, Code::GovernanceBundleMalformed);
    // A long string in a field that is a label, in the log.
    let mut a = fx.audit.clone();
    a.members = vec!["m".repeat(300)];
    assert_eq!(
        code(GovernanceBundle::build(
            "organization:tax-agency",
            T0,
            "c",
            fx.graph.clone(),
            owner_view(&fx),
            a,
            Provenance::default()
        )),
        Code::GovernanceBundlePlaintext
    );
    // The allowed text fields are the program, the purpose's description
    // and attestation records.
    let v = serde_json::json!({"governance": {"purpose": {"description": "d".repeat(2000)}}});
    check_no_plaintext(&v).unwrap();
    let v = serde_json::json!({"governance": {"purpose": {"name": "d".repeat(300)}}});
    assert_eq!(
        check_no_plaintext(&v).unwrap_err().code,
        Code::GovernanceBundlePlaintext
    );
    let v = serde_json::json!({"a": ["b", {"c": "z".repeat(257)}]});
    assert!(check_no_plaintext(&v).is_err());
    let v = serde_json::json!({"a": "z".repeat(256)});
    check_no_plaintext(&v).unwrap();
    // A key is a label too.
    let mut o = serde_json::Map::new();
    o.insert("k".repeat(300), Value::Null);
    assert!(check_no_plaintext(&Value::Object(o)).is_err());
}

#[test]
fn views_never_leak_what_belongs_to_another_organization() {
    let fx = Fixture::build();
    // A shared view with a signed authorization (it names the approvers).
    assert_eq!(
        code(GovernanceBundle::build(
            "shared",
            T0,
            "c",
            fx.graph.clone(),
            fx.evidence.clone(),
            fx.audit.clone(),
            Provenance::default()
        )),
        Code::GovernanceBundlePlaintext
    );
    // Benefits' view carrying tax-agency's signed document.
    assert_eq!(
        code(GovernanceBundle::build(
            &format!("organization:{BEN}"),
            T0,
            "c",
            fx.graph.clone(),
            owner_view(&fx),
            fx.audit.clone(),
            Provenance::default()
        )),
        Code::GovernanceBundlePlaintext
    );
    // A raw submitter, or a card with a raw approver.
    let mut ev = fx.shared();
    ev.submitter = Some("usr_alice".into());
    assert_eq!(
        code(GovernanceBundle::build(
            "shared",
            T0,
            "c",
            fx.graph.clone(),
            ev,
            fx.audit.clone(),
            Provenance::default()
        )),
        Code::GovernanceBundlePlaintext
    );
    let mut ev = fx.shared();
    if let encompute_trust::AuthorizationEntry::Card { card } = &mut ev.authorizations[0] {
        card.approvals[0].approver = "alice@agency.example".into();
    }
    assert_eq!(
        code(GovernanceBundle::build(
            "shared",
            T0,
            "c",
            fx.graph.clone(),
            ev,
            fx.audit.clone(),
            Provenance::default()
        )),
        Code::GovernanceBundlePlaintext
    );
    // The verifier applies the same rules to a bundle someone else built:
    // swapping a shared view's cards for signed documents, with every
    // digest recomputed, is refused.
    let b = shared_bundle(&fx);
    let mut x: Value = serde_json::from_slice(&b.to_bytes().unwrap()).unwrap();
    x["manifest"]["view"] = Value::from("shared");
    let _ = x;
    assert!(check_view("organization:").is_err());
    assert!(check_view("organization:a/b").is_err());
    assert!(check_view("everyone").is_err());
    check_view("shared").unwrap();
    check_view("organization:tax-agency").unwrap();
}

#[test]
fn every_member_sees_the_same_shared_bytes() {
    let fx = Fixture::build();
    let a = shared_bundle(&fx);
    let b = shared_bundle(&fx);
    assert_eq!(a.to_bytes().unwrap(), b.to_bytes().unwrap());
    assert_eq!(a.id().unwrap(), b.id().unwrap());
    // The shared view names no approver, no raw submitter and no signed
    // authorization.
    let text = String::from_utf8(a.to_bytes().unwrap()).unwrap();
    for needle in [
        "person-0",
        "person-1",
        "idp.example",
        "approver_subject",
        "\"form\":\"signed\"",
    ] {
        assert!(!text.contains(needle), "the shared view contains {needle}");
    }
    // Members who sign it vouch for the same BundleId.
    let mut t = a.clone();
    t.sign(TAX, &fx.tax).unwrap();
    let mut n = b.clone();
    n.sign(BEN, &fx.ben).unwrap();
    assert_eq!(t.id().unwrap(), n.id().unwrap());
    let p = pins(&fx);
    for s in [&t, &n] {
        let v = s.verify(&opts(&p)).unwrap();
        assert_eq!(
            v.signatures[0].status,
            encompute_trust::SignatureStatus::Verified
        );
    }
}

#[test]
fn the_shared_view_verifies_with_disclosures_only() {
    let fx = Fixture::build();
    let p = pins(&fx);
    let b = shared_bundle(&fx);
    let v = b.verify(&opts(&p)).unwrap();
    assert_eq!(v.outcome, Outcome::Unchecked);
    assert!(v.report.unmet.len() > 1, "{:?}", v.report.unmet);
    let mut o = opts(&p);
    o.disclosures = fx.documents();
    let v = b.verify(&o).unwrap();
    assert_eq!(
        v.report.unmet,
        vec!["Decryption control is not evidenced".to_owned()]
    );
}

#[test]
fn pins_come_from_the_verifier_and_say_where() {
    let fx = Fixture::build();
    let good = pins(&fx);
    let bytes = serde_json::to_vec(&good).unwrap();
    assert_eq!(Pins::from_bytes(&bytes).unwrap(), good);
    // Unknown fields, a missing source, a malformed key, two organizations
    // on one key.
    let mut v: Value = serde_json::from_slice(&bytes).unwrap();
    v["extra"] = Value::Null;
    assert!(Pins::from_bytes(&serde_json::to_vec(&v).unwrap()).is_err());
    for edit in [
        |p: &mut Pins| p.organizations.get_mut(TAX).unwrap().obtained = " ".into(),
        |p: &mut Pins| p.organizations.get_mut(TAX).unwrap().identity_key = "zz".into(),
        |p: &mut Pins| p.control_plane.as_mut().unwrap().key = "AB".repeat(32),
        |p: &mut Pins| {
            let k = p.organizations[TAX].identity_key.clone();
            p.organizations.get_mut(BEN).unwrap().identity_key = k;
        },
    ] {
        let mut p = good.clone();
        edit(&mut p);
        assert!(Pins::from_bytes(&serde_json::to_vec(&p).unwrap()).is_err());
    }
}

#[test]
fn outcomes_have_one_table_of_exit_codes() {
    assert_eq!(Outcome::Satisfied.exit_code(), 0);
    assert_eq!(Outcome::NotSatisfied.exit_code(), 1);
    assert_eq!(Outcome::Refused.exit_code(), 2);
    assert_eq!(Outcome::Unchecked.exit_code(), 3);
    assert!(encompute_trust::EXIT_CODES.contains("3 unchecked"));
}

fn built(
    fx: &Fixture,
    edit: impl FnOnce(&mut encompute_trust::GovernanceEvidence, &mut encompute_trust::AuditEvidence),
) -> encompute_ir::Result<GovernanceBundle> {
    let (mut g, mut a) = (fx.shared(), fx.audit.clone());
    edit(&mut g, &mut a);
    GovernanceBundle::build(
        "shared",
        T0,
        "encompute-control",
        fx.graph.clone(),
        g,
        a,
        Provenance::default(),
    )
}

/// Identifiers become file names and terminal text: only `[A-Za-z0-9._-]`.
#[test]
fn identifiers_are_safe_as_file_names() {
    let fx = Fixture::build();
    for bad in [
        "../evil",
        "/etc/passwd",
        "a/b",
        "a\\b",
        "nul\0byte",
        "",
        &"x".repeat(201),
        "caf\u{e9}",
        "a b",
        "esc\u{1b}[31m",
        "a\nb",
    ] {
        let r = built(&fx, |g, a| {
            g.project = bad.to_owned();
            a.project = bad.to_owned();
        });
        assert_eq!(
            r.unwrap_err().code,
            Code::GovernanceBundleMalformed,
            "{bad:?}"
        );
        let r = built(&fx, |g, _| g.job_id = bad.to_owned());
        assert!(r.is_err(), "{bad:?}");
    }
    assert!(encompute_trust::bundle::check_ident("x", &"x".repeat(200)).is_ok());
    // A signer's organization too, and the verifier applies the same.
    let mut b = shared_bundle(&fx);
    assert!(b.sign("../evil", &fx.tax).is_err());
    let mut x = b.clone();
    x.manifest.project_id = "../evil".into();
    assert!(x.check().is_err());
}

#[test]
fn a_bundle_has_bounds() {
    let fx = Fixture::build();
    // Too many events, witnesses, heads, members or signatures.
    let many = |n: usize| {
        let mut a = fx.audit.clone();
        let e = a.events[0].clone();
        a.events = vec![e; n];
        a
    };
    let r = built(&fx, |_, a| *a = many(5001));
    assert_eq!(r.unwrap_err().code, Code::GovernanceBundleLimit);
    let r = built(&fx, |_, a| a.witnesses = vec![a.witnesses[0].clone(); 1001]);
    assert_eq!(r.unwrap_err().code, Code::GovernanceBundleLimit);
    let r = built(&fx, |_, a| {
        a.revocation_heads = vec![a.revocation_heads[0].clone(); 1001]
    });
    assert_eq!(r.unwrap_err().code, Code::GovernanceBundleLimit);
    let r = built(&fx, |_, a| a.members = vec!["m".into(); 1001]);
    assert_eq!(r.unwrap_err().code, Code::GovernanceBundleLimit);
    let r = built(&fx, |_, a| {
        a.events[0].proof.path = vec!["00".repeat(32); 65]
    });
    assert_eq!(r.unwrap_err().code, Code::GovernanceBundleLimit);
    let r = built(&fx, |g, _| g.purpose.description = "d".repeat(2001));
    assert!(r.is_err());
    // A file over the size bound is refused before it is parsed.
    let big = vec![b' '; encompute_trust::bundle::MAX_BUNDLE_BYTES + 1];
    assert_eq!(
        code(GovernanceBundle::from_bytes(&big)),
        Code::GovernanceBundleLimit
    );
}

#[test]
fn a_signature_states_what_its_signer_verified() {
    let fx = Fixture::build();
    let p = pins(&fx);
    let b = shared_bundle(&fx);
    // An unpinned signature must still verify under its own key.
    let mut s = b.clone();
    s.sign("somebody", &key(5)).unwrap();
    s.signatures[0].signature = "00".repeat(64);
    assert_eq!(code(s.verify(&opts(&p))), Code::GovernanceBundleUnverified);
    // A statement about another bundle is refused.
    let mut s = b.clone();
    s.sign("somebody", &key(5)).unwrap();
    s.signatures[0].statement.bundle_id = "0".repeat(64);
    assert!(s.verify(&opts(&p)).is_err());
    // The statement is signed: changing what it says breaks the signature.
    let mut s = b.clone();
    s.sign(TAX, &fx.tax).unwrap();
    s.signatures[0].statement.accepted_unpinned = true;
    assert_eq!(code(s.verify(&opts(&p))), Code::GovernanceBundleUnverified);
    // A verified statement is carried into the findings.
    let mut s = b.clone();
    let st = encompute_trust::SignatureStatement {
        bundle_id: s.id().unwrap(),
        verdict: encompute_trust::StatementVerdict::NotFullyEvidenced,
        pins_digest: Some(p.digest().unwrap()),
        accepted_unchecked: true,
        accepted_unpinned: false,
    };
    s.sign_statement(TAX, &fx.tax, st.clone()).unwrap();
    let v = s.verify(&opts(&p)).unwrap();
    assert_eq!(v.signatures[0].statement, st);
}

#[test]
fn one_key_has_one_role_in_the_pins() {
    let fx = Fixture::build();
    let mut p = pins(&fx);
    p.evaluators[0].key = p.control_plane.as_ref().unwrap().key.clone();
    assert!(p.check().is_err());
    let mut p = pins(&fx);
    p.control_plane.as_mut().unwrap().key = p.organizations[TAX].identity_key.clone();
    assert!(p.check().is_err());
}

#[test]
fn a_signed_claim_names_its_pins_and_nothing_else_does() {
    let fx = Fixture::build();
    let mut b = shared_bundle(&fx);
    let st = |v, pins: Option<String>, unchecked| encompute_trust::SignatureStatement {
        bundle_id: b.id().unwrap(),
        verdict: v,
        pins_digest: pins,
        accepted_unchecked: unchecked,
        accepted_unpinned: false,
    };
    use encompute_trust::StatementVerdict as V;
    // A claim without the pins it rests on, and "verified nothing" that
    // accepts something, are refused.
    assert!(b
        .clone()
        .sign_statement(TAX, &fx.tax, st(V::Satisfied, None, false))
        .is_err());
    assert!(b
        .clone()
        .sign_statement(TAX, &fx.tax, st(V::NotFullyEvidenced, None, true))
        .is_err());
    assert!(b
        .clone()
        .sign_statement(
            TAX,
            &fx.tax,
            st(V::NotVerified, Some("0".repeat(64)), false)
        )
        .is_err());
    b.sign_statement(TAX, &fx.tax, st(V::NotVerified, None, false))
        .unwrap();
}
