//! Governed-project identities (public-sector governance, phase 1): the
//! purpose, governance binding, program set and asset version IDs bind
//! every field; the execution spec binds the governance ID only when there
//! is one (standard IDs are unchanged); job grants v2 carry the binding and
//! a strict `not_after`; receipts v4 bind the grant.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use encompute_verification::canonical::canonical_json;
use encompute_verification::governance::{
    AssetVersion, GovernanceBinding, GovernanceInput, GovernanceOutput, GrantGovernance,
    ProgramRef, ProgramSetId, Purpose, PurposeMode, ReleaseClass,
};
use encompute_verification::service::{JobGrant, JOB_GRANT, JOB_GRANT_V2, JOB_GRANT_VERSION};
use encompute_verification::{
    hex, EvaluatorSigner, ExecutionReceipt, ExecutionSpec, ServiceSigner, SignedExecutionReceipt,
    GOVERNED_RECEIPT_VERSION, RECEIPT_VERSION,
};

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

fn tagged(domain: &str, bytes: &[u8]) -> String {
    let mut s = Sha256::new();
    s.update(domain.as_bytes());
    s.update([0u8]);
    s.update(bytes);
    hex(&s.finalize())
}

/// Every optional field set, so each can be changed.
fn purpose() -> Purpose {
    Purpose {
        version: 1,
        project_id: "prj_1".into(),
        name: "benefits-eligibility".into(),
        revision: 1,
        description: "Eligibility for housing benefit".into(),
        legal_basis_ref: Some("statute-12".into()),
        modes: BTreeSet::from([PurposeMode::RecordLevelExact]),
        allowed_release_classes: BTreeSet::from([ReleaseClass::BooleanOnly]),
        recipients: BTreeSet::from(["benefits-agency".into()]),
        linkage_policy_id: Some(h('1')),
        min_aggregate_parties: Some(3),
        valid_from: 1_000,
        valid_until: 2_000,
        created_by_org: "benefits-agency".into(),
    }
}

/// A named change to one field.
type Change<'a, T> = (&'a str, &'a dyn Fn(&mut T));

/// Applies each change and checks the ID moves; also checks the sweep
/// covers every serialized field, so a new field must join it.
fn sweep<T: Clone + serde::Serialize>(base: &T, id: impl Fn(&T) -> String, changes: &[Change<T>]) {
    let v = serde_json::to_value(base).unwrap();
    let keys: BTreeSet<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    let covered: BTreeSet<&str> = changes.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys, covered, "the sweep must change every field");
    let original = id(base);
    let mut seen = BTreeSet::from([original.clone()]);
    for (field, change) in changes {
        let mut x = base.clone();
        change(&mut x);
        let changed = id(&x);
        assert_ne!(changed, original, "{field} does not change the ID");
        assert!(seen.insert(changed), "{field} collides with another change");
    }
}

#[test]
fn every_purpose_field_changes_the_purpose_id() {
    let p = purpose();
    p.check().unwrap();
    sweep(
        &p,
        |p: &Purpose| p.id().hex(),
        &[
            ("version", &|p| p.version = 2),
            ("project_id", &|p| p.project_id = "prj_2".into()),
            ("name", &|p| p.name = "fraud".into()),
            ("revision", &|p| p.revision = 2),
            ("description", &|p| p.description.push('.')),
            ("legal_basis_ref", &|p| p.legal_basis_ref = None),
            ("modes", &|p| {
                p.modes.insert(PurposeMode::Aggregate);
            }),
            ("allowed_release_classes", &|p| {
                p.allowed_release_classes
                    .insert(ReleaseClass::AggregateOnly);
            }),
            ("recipients", &|p| {
                p.recipients.insert("tax-agency".into());
            }),
            ("linkage_policy_id", &|p| p.linkage_policy_id = Some(h('2'))),
            ("min_aggregate_parties", &|p| {
                p.min_aggregate_parties = Some(4)
            }),
            ("valid_from", &|p| p.valid_from = 1_001),
            ("valid_until", &|p| p.valid_until = 2_001),
            ("created_by_org", &|p| {
                p.created_by_org = "tax-agency".into()
            }),
        ],
    );
}

#[test]
fn the_purpose_id_is_the_tagged_canonical_purpose() {
    let p = purpose();
    let expected = tagged("encompute.purpose.v1", &canonical_json(&p).unwrap());
    assert_eq!(p.id().hex(), expected);
    assert_eq!(p.id().to_string(), format!("encpurpose1:{expected}"));
    // Optional fields that are absent are not serialized at all.
    let mut bare = p.clone();
    bare.legal_basis_ref = None;
    bare.min_aggregate_parties = None;
    let text = String::from_utf8(canonical_json(&bare).unwrap()).unwrap();
    assert!(!text.contains("legal_basis_ref") && !text.contains("min_aggregate_parties"));
    // The same purpose in another project is another purpose.
    let mut other = p.clone();
    other.project_id = "prj_other".into();
    assert_ne!(other.id(), p.id());
}

#[test]
fn a_purpose_is_checked_and_its_window_is_strict() {
    let p = purpose();
    assert!(!p.is_valid_at(999));
    assert!(p.is_valid_at(1_000));
    assert!(p.is_valid_at(1_999));
    assert!(!p.is_valid_at(2_000), "expiry is strict: no margin");
    let bad: [&dyn Fn(&mut Purpose); 7] = [
        &|p| p.valid_until = p.valid_from,
        &|p| p.name.clear(),
        &|p| p.project_id.clear(),
        &|p| p.modes.clear(),
        &|p| p.linkage_policy_id = None, // record-level exact needs linkage
        &|p| p.linkage_policy_id = Some("not-hex".into()),
        &|p| p.version = 9,
    ];
    for (i, b) in bad.iter().enumerate() {
        let mut x = p.clone();
        b(&mut x);
        assert!(x.check().is_err(), "change {i} was accepted");
    }
}

fn binding() -> GovernanceBinding {
    GovernanceBinding {
        version: 1,
        project: "prj_1".into(),
        purpose_id: purpose().id().hex(),
        linkage_policy_id: Some(h('1')),
        inputs: BTreeMap::from([(
            "income".into(),
            GovernanceInput {
                asset_version_id: h('3'),
                digest_commitment: h('4'),
                organization: "tax-agency".into(),
            },
        )]),
        outputs: BTreeMap::from([(
            "eligible".into(),
            GovernanceOutput {
                release_class: ReleaseClass::BooleanOnly,
                recipients: BTreeSet::from(["benefits-agency".into()]),
            },
        )]),
        placement_digest: Some(h('5')),
        project_policy_digest: Some(h('6')),
        asset_brokers: BTreeMap::new(),
    }
}

#[test]
fn every_governance_binding_field_changes_the_governance_id() {
    let b = binding();
    b.check().unwrap();
    sweep(
        &b,
        |b: &GovernanceBinding| b.id().hex(),
        &[
            ("version", &|b| b.version = 2),
            ("project", &|b| b.project = "prj_2".into()),
            ("purpose_id", &|b| b.purpose_id = h('9')),
            ("linkage_policy_id", &|b| b.linkage_policy_id = None),
            ("inputs", &|b| {
                b.inputs.get_mut("income").unwrap().organization = "benefits-agency".into()
            }),
            ("outputs", &|b| {
                b.outputs.get_mut("eligible").unwrap().release_class = ReleaseClass::Never
            }),
            ("placement_digest", &|b| b.placement_digest = None),
            ("project_policy_digest", &|b| {
                b.project_policy_digest = Some(h('7'))
            }),
        ],
    );
    // Nested fields too.
    let nested: [&dyn Fn(&mut GovernanceBinding); 6] = [
        &|b| b.inputs.get_mut("income").unwrap().asset_version_id = h('a'),
        &|b| b.inputs.get_mut("income").unwrap().digest_commitment = h('b'),
        &|b| {
            let x = b.inputs.remove("income").unwrap();
            b.inputs.insert("salary".into(), x);
        },
        &|b| {
            b.outputs
                .get_mut("eligible")
                .unwrap()
                .recipients
                .insert("tax-agency".into());
        },
        &|b| {
            let x = b.outputs.remove("eligible").unwrap();
            b.outputs.insert("ok".into(), x);
        },
        &|b| b.inputs.clear(),
    ];
    for (i, n) in nested.iter().enumerate() {
        let mut x = binding();
        n(&mut x);
        assert_ne!(x.id(), b.id(), "nested change {i}");
    }
    let expected = tagged(
        "encompute.governance-binding.v1",
        &canonical_json(&b).unwrap(),
    );
    assert_eq!(b.id().hex(), expected);
    assert_eq!(b.id().to_string(), format!("encgov1:{expected}"));
}

#[test]
fn a_governance_binding_is_checked() {
    let bad: [&dyn Fn(&mut GovernanceBinding); 6] = [
        &|b| b.purpose_id = "x".into(),
        &|b| b.project.clear(),
        &|b| b.inputs.clear(),
        &|b| b.inputs.get_mut("income").unwrap().asset_version_id = "short".into(),
        &|b| b.outputs.get_mut("eligible").unwrap().recipients.clear(),
        // Never released, yet naming a recipient.
        &|b| b.outputs.get_mut("eligible").unwrap().release_class = ReleaseClass::Never,
    ];
    for (i, f) in bad.iter().enumerate() {
        let mut b = binding();
        f(&mut b);
        assert!(b.check().is_err(), "change {i} was accepted");
    }
    // Never released and naming nobody is well formed.
    let mut b = binding();
    let o = b.outputs.get_mut("eligible").unwrap();
    o.release_class = ReleaseClass::Never;
    o.recipients.clear();
    b.check().unwrap();
}

#[test]
fn a_program_set_is_content_addressed_and_never_a_wildcard() {
    let (a, b) = (h('a'), h('b'));
    let ab = ProgramSetId::of([a.clone(), b.clone()]).unwrap();
    let ba = ProgramSetId::of([b.clone(), a.clone()]).unwrap();
    assert_eq!(ab, ba, "a set: order does not matter");
    assert_ne!(ab, ProgramSetId::of([a.clone()]).unwrap());
    assert!(ab.to_string().starts_with("encprogset1:"));
    // Empty sets, wildcards and anything but a program ID are refused.
    assert!(ProgramSetId::of(Vec::<String>::new()).is_err());
    for w in ["*", "", "ab", &"A".repeat(64), &format!("{a}*")] {
        assert!(ProgramSetId::of([w.to_string()]).is_err(), "{w:?}");
        assert!(ProgramRef::Program {
            program_id: w.to_string()
        }
        .check()
        .is_err());
    }
    assert!(
        ProgramSetId::of([a.clone(), a.clone()]).is_err(),
        "duplicates"
    );
    // A set reference is checked against its members.
    let set = ProgramRef::ProgramSet {
        program_set_id: ab.hex(),
        programs: BTreeSet::from([a.clone(), b.clone()]),
    };
    set.check().unwrap();
    assert!(set.covers(&a) && set.covers(&b) && !set.covers(&h('c')));
    let forged = ProgramRef::ProgramSet {
        program_set_id: ab.hex(),
        programs: BTreeSet::from([a.clone(), b.clone(), h('c')]),
    };
    assert!(forged.check().is_err(), "a member added under the old ID");
    let one = ProgramRef::Program {
        program_id: a.clone(),
    };
    one.check().unwrap();
    assert!(one.covers(&a) && !one.covers(&b));
}

#[test]
fn every_asset_version_field_changes_its_id() {
    let v = AssetVersion {
        version: 1,
        organization: "tax-agency".into(),
        series: "income".into(),
        label: "2026-q3".into(),
        digest: h('d'),
    };
    v.check().unwrap();
    sweep(
        &v,
        |v: &AssetVersion| v.id().hex(),
        &[
            ("version", &|v| v.version = 2),
            ("organization", &|v| {
                v.organization = "benefits-agency".into()
            }),
            ("series", &|v| v.series = "wages".into()),
            ("label", &|v| v.label = "2026-q4".into()),
            ("digest", &|v| v.digest = h('e')),
        ],
    );
    let mut bad = v.clone();
    bad.series = "a@b".into();
    assert!(bad.check().is_err(), "the separator is not part of a name");
}

fn spec() -> ExecutionSpec {
    ExecutionSpec {
        version: 1,
        program_id: h('a'),
        plan_id: h('b'),
        parameter_set_id: h('c'),
        plan_kind: "exact".into(),
        plan_version: 1,
        semantics: "exact".into(),
        scheme: "BinFHE".into(),
        backend: "openfhe-exact".into(),
        backend_version: "1.5.1".into(),
        policy_id: None,
        privacy_policy_id: None,
        governance_id: None,
    }
}

#[test]
fn the_spec_binds_a_governance_id_and_standard_specs_are_unchanged() {
    let s = spec();
    // Absent, it is not serialized: every existing spec ID is unchanged.
    let text = String::from_utf8(s.canonical_bytes().unwrap()).unwrap();
    assert!(!text.contains("governance_id"));
    assert_eq!(
        s.id().hex(),
        tagged("encompute.execution-spec.v1", text.as_bytes())
    );
    let g = s.clone().governed(&binding());
    assert_eq!(
        g.governance_id.as_deref(),
        Some(binding().id().hex().as_str())
    );
    assert_ne!(g.id(), s.id());
    let mut other = binding();
    other.purpose_id = h('9');
    assert_ne!(s.clone().governed(&other).id(), g.id());
}

fn grant(control: &ServiceSigner, governance: Option<GrantGovernance>) -> JobGrant {
    let mut g = JobGrant {
        version: if governance.is_some() {
            JOB_GRANT_V2
        } else {
            JOB_GRANT_VERSION
        },
        job_id: "job_1".into(),
        organization: "benefits-agency".into(),
        project: "prj_1".into(),
        plan_id: "pln_1".into(),
        spec_id: h('5'),
        program_id: h('a'),
        evaluator: "evaluator-1".into(),
        backend: "openfhe-exact".into(),
        profile: "BINFHE_STD128_GINX_BITS_V1".into(),
        issued_at: 1_000,
        expires_at: 1_500,
        issuer: "control-plane".into(),
        issuer_public_key: control.public_key_hex(),
        governance,
        signature: String::new(),
    };
    g.signature = control.sign(JOB_GRANT, &g.unsigned()).unwrap();
    g
}

fn grant_governance() -> GrantGovernance {
    let b = binding();
    GrantGovernance {
        plan_hash: h('8'),
        purpose_id: b.purpose_id.clone(),
        governance_id: b.id().hex(),
        binding: b,
        authorization_set_id: h('9'),
        not_after: 1_800,
        placement: None,
    }
}

#[test]
fn a_v2_grant_carries_the_binding_and_expires_strictly() {
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let pk = control.public_key_hex();
    let p = h('a');
    // v1 grants verify as before.
    let v1 = grant(&control, None);
    v1.verify(&pk, "evaluator-1", &p, 1_200).unwrap();
    // v2 grants verify, and survive the header round trip.
    let v2 = grant(&control, Some(grant_governance()));
    v2.verify(&pk, "evaluator-1", &p, 1_200).unwrap();
    assert_eq!(JobGrant::from_header(&v2.to_header()).unwrap(), v2);
    // A v1 grant's serialized form has no governance key at all.
    assert!(!serde_json::to_string(&v1).unwrap().contains("governance"));

    // Strict: at not_after the grant is dead, even inside expires_at.
    let mut gg = grant_governance();
    gg.not_after = 1_300;
    let mut short = grant(&control, Some(gg));
    short.expires_at = 1_300;
    short.signature = control.sign(JOB_GRANT, &short.unsigned()).unwrap();
    short.verify(&pk, "evaluator-1", &p, 1_299).unwrap();
    assert!(short.verify(&pk, "evaluator-1", &p, 1_300).is_err());

    // A grant outliving its authorizations is refused.
    let mut gg = grant_governance();
    gg.not_after = 1_400; // expires_at is 1_500
    let outliving = grant(&control, Some(gg));
    assert!(outliving.verify(&pk, "evaluator-1", &p, 1_200).is_err());

    // Version and governance must agree.
    let mut v1_with = grant(&control, Some(grant_governance()));
    v1_with.version = JOB_GRANT_VERSION;
    v1_with.signature = control.sign(JOB_GRANT, &v1_with.unsigned()).unwrap();
    assert!(v1_with.verify(&pk, "evaluator-1", &p, 1_200).is_err());
    let mut v2_without = grant(&control, None);
    v2_without.version = JOB_GRANT_V2;
    v2_without.signature = control.sign(JOB_GRANT, &v2_without.unsigned()).unwrap();
    assert!(v2_without.verify(&pk, "evaluator-1", &p, 1_200).is_err());

    // The carried binding must be the one the IDs name.
    let mut gg = grant_governance();
    gg.purpose_id = h('7');
    assert!(grant(&control, Some(gg))
        .verify(&pk, "evaluator-1", &p, 1_200)
        .is_err());
    let mut gg = grant_governance();
    gg.binding.project = "prj_other".into();
    assert!(grant(&control, Some(gg))
        .verify(&pk, "evaluator-1", &p, 1_200)
        .is_err());
    let mut gg = grant_governance();
    gg.governance_id = h('7');
    assert!(grant(&control, Some(gg))
        .verify(&pk, "evaluator-1", &p, 1_200)
        .is_err());
    let mut gg = grant_governance();
    gg.binding.project = "prj_2".into();
    gg.governance_id = gg.binding.id().hex();
    assert!(
        grant(&control, Some(gg))
            .verify(&pk, "evaluator-1", &p, 1_200)
            .is_err(),
        "the binding is for another project than the grant"
    );

    // Tampering with the signed governance fails the signature.
    let mut tampered = v2.clone();
    tampered.governance.as_mut().unwrap().not_after = 9_999;
    assert!(tampered.verify(&pk, "evaluator-1", &p, 1_200).is_err());

    // The grant digest binds the whole signed grant.
    assert_eq!(v2.digest().len(), 64);
    assert_ne!(v2.digest(), v1.digest());
    assert_ne!(tampered.digest(), v2.digest());
}

#[test]
fn a_v4_receipt_binds_the_grant_and_v3_receipts_are_unchanged() {
    let signer = EvaluatorSigner::from_seed(&[7; 32]);
    let s = spec();
    let base =
        ExecutionReceipt::new(&s, None, &h('1'), b"req", b"out", &signer.identity()).unwrap();
    assert_eq!(base.version, RECEIPT_VERSION);
    let v3 = base.clone().sign(&signer).unwrap();
    v3.verify_signature(&signer.identity()).unwrap();
    assert!(!String::from_utf8(v3.to_bytes().unwrap())
        .unwrap()
        .contains("grant_digest"));

    let v4 = base.clone().with_grant(Some(h('2'))).sign(&signer).unwrap();
    assert_eq!(v4.receipt.version, GOVERNED_RECEIPT_VERSION);
    v4.verify_signature(&signer.identity()).unwrap();
    let parsed = SignedExecutionReceipt::from_bytes(&v4.to_bytes().unwrap()).unwrap();
    assert_eq!(parsed, v4);

    // Version and grant digest must agree; the digest is 32 bytes of hex.
    let mut bad = base.clone().with_grant(Some(h('2')));
    bad.version = RECEIPT_VERSION;
    assert!(bad
        .sign(&signer)
        .unwrap()
        .verify_signature(&signer.identity())
        .is_err());
    let mut bad = base.clone();
    bad.version = GOVERNED_RECEIPT_VERSION;
    assert!(bad
        .sign(&signer)
        .unwrap()
        .verify_signature(&signer.identity())
        .is_err());
    let bad = base
        .clone()
        .with_grant(Some("zz".into()))
        .sign(&signer)
        .unwrap();
    assert!(bad.check_form().is_err());
    // The digest is signed.
    let mut forged = v4.clone();
    forged.receipt.grant_digest = Some(h('3'));
    assert!(forged.verify_signature(&signer.identity()).is_err());
}

/// A binding without a per-asset broker map keeps its bytes and its
/// GovernanceId (the value before the field existed).
#[test]
fn governance_ids_unchanged_without_asset_brokers() {
    let b = binding();
    let text = String::from_utf8(canonical_json(&b).unwrap()).unwrap();
    assert!(!text.contains("asset_brokers"), "{text}");
    assert_eq!(
        b.id().hex(),
        "53ceeeb22c3702d5a095aa3644e59cc973f10bbb306aa735d735a975c41a11e7"
    );
    // The map, when present, changes the ID; a broker ID or key that is not
    // a label is refused.
    let mut x = binding();
    x.asset_brokers.insert(h('3'), "tax-broker".into());
    x.check().unwrap();
    assert_ne!(x.id(), b.id());
    let mut y = x.clone();
    y.asset_brokers.insert(h('3'), "other-broker".into());
    assert_ne!(y.id(), x.id());
    let mut z = x.clone();
    z.asset_brokers.insert(h('3'), String::new());
    assert!(z.check().is_err());
    // Keyed by asset version ID, never by a key reference or asset name.
    let mut k = binding();
    k.asset_brokers.insert("income".into(), "tax-broker".into());
    assert!(k.check().is_err());
}

/// Confidentiality declarations using every asset-policy field that
/// existed before release forms (owners, readers, purposes, release,
/// derive, privacy), with an aggregation.
const DECLARED: &str = "encompute 0.1\nprogram mean precision 0.001 purpose \"eligibility\"\n\
party \"tax\" \"Tax\"\nparty \"ben\" \"Benefits\"\n\
asset \"income\" dataset owners [\"tax\"] readers [\"ben\"] purposes [\"eligibility\"] release allowed_parties derive [model aggregate_only to [\"ben\"]] privacy unit \"person\" epsilon 1.0 delta 1e-6\n\
asset \"ages\" dataset owners [\"ben\"] readers [\"ben\", \"tax\"] purposes [\"eligibility\", \"statistics\"] release owner_only\n\
%0 = input \"x\" [0.0, 120.0] asset \"income\" : secret scalar\n\
%1 = input \"y\" [0.0, 120.0] asset \"ages\" : secret scalar\n\
%2 = add %0, %1 : secret scalar\n\
output \"out\" = %2\n";

/// Release forms are skipped when absent: every existing PolicyId keeps
/// its value (the golden value was taken before the field existed), and
/// every asset-policy field, forms included, changes the PolicyId.
#[test]
fn policy_ids_unchanged_without_forms() {
    use encompute_ir::confidentiality::{AssetPolicy, ReleaseForm};
    use encompute_verification::PolicyId;
    let p = encompute_ir::parse(DECLARED).unwrap();
    let c = p.confidentiality().unwrap().clone();
    let text = String::from_utf8(canonical_json(&c).unwrap()).unwrap();
    assert!(!text.contains("forms"), "{text}");
    assert_eq!(PolicyId::of(&c).hex(), GOLDEN_POLICY_ID);
    // The field sweep, over the first asset's policy.
    let base = c.assets[0].policy.clone();
    let id = |x: &AssetPolicy| {
        let mut d = c.clone();
        d.assets[0].policy = x.clone();
        PolicyId::of(&d).hex()
    };
    let mut policy = base.clone();
    policy.forms = Some([ReleaseForm::Boolean].into());
    let changes: &[Change<AssetPolicy>] = &[
        ("owners", &|x| {
            x.owners
                .insert(encompute_ir::confidentiality::PartyId::new("ben").unwrap());
        }),
        ("readers", &|x| x.readers.clear()),
        ("purposes", &|x| {
            x.purposes.insert("statistics".into());
        }),
        ("release", &|x| {
            x.release = encompute_ir::confidentiality::Release::Never
        }),
        ("derive", &|x| x.derive.clear()),
        ("privacy", &|x| x.privacy = None),
        ("forms", &|x| {
            x.forms = Some([ReleaseForm::BoundedCategory { max: 3 }].into())
        }),
    ];
    sweep(&policy, id, changes);
    let text = String::from_utf8(canonical_json(&policy).unwrap()).unwrap();
    assert!(text.contains(r#""forms":["boolean"]"#), "{text}");
    let mut b = base.clone();
    b.forms = Some([ReleaseForm::BoundedCategory { max: 3 }].into());
    let text = String::from_utf8(canonical_json(&b).unwrap()).unwrap();
    assert!(
        text.contains(r#""forms":[{"bounded_category":{"max":3}}]"#),
        "{text}"
    );
    // Each form is a different policy, and so is the empty set.
    let ids: BTreeSet<String> = [
        None,
        Some(BTreeSet::new()),
        Some([ReleaseForm::Boolean].into()),
        Some([ReleaseForm::BoundedCategory { max: 3 }].into()),
        Some([ReleaseForm::BoundedCategory { max: 4 }].into()),
        Some([ReleaseForm::Aggregate].into()),
        Some([ReleaseForm::DpAggregate].into()),
        Some([ReleaseForm::DerivedArtifact].into()),
    ]
    .into_iter()
    .map(|f| {
        let mut x = base.clone();
        x.forms = f;
        id(&x)
    })
    .collect();
    assert_eq!(ids.len(), 8);
}

const GOLDEN_POLICY_ID: &str = "8da1eb29b218fada8b7c97652481b8dcf7884ca413c8026e0188495d11c8e88b";

/// The owners' release-class order, exhaustively: every class is within
/// itself; boolean-only and the aggregate classes are within
/// authorized-agency-only; dp-aggregate-only is within aggregate-only;
/// derived-artifact-only and never are within only themselves. A class
/// within another allows no form the other does not.
#[test]
fn class_within_order_matches_owner_decision() {
    use encompute_ir::confidentiality::ReleaseForm as F;
    use ReleaseClass::*;
    let within: &[(ReleaseClass, &[ReleaseClass])] = &[
        (Never, &[Never]),
        (BooleanOnly, &[BooleanOnly, AuthorizedAgencyOnly]),
        (AggregateOnly, &[AggregateOnly, AuthorizedAgencyOnly]),
        (
            DpAggregateOnly,
            &[DpAggregateOnly, AggregateOnly, AuthorizedAgencyOnly],
        ),
        (AuthorizedAgencyOnly, &[AuthorizedAgencyOnly]),
        (DerivedArtifactOnly, &[DerivedArtifactOnly]),
    ];
    assert_eq!(within.len(), ReleaseClass::ALL.len());
    for (a, ceilings) in within {
        for b in ReleaseClass::ALL {
            assert_eq!(
                a.within(b),
                ceilings.contains(&b),
                "{} within {}",
                a.as_str(),
                b.as_str()
            );
        }
    }
    // A partial order: reflexive, antisymmetric, transitive.
    for a in ReleaseClass::ALL {
        for b in ReleaseClass::ALL {
            if a.within(b) && b.within(a) {
                assert_eq!(a, b);
            }
            for c in ReleaseClass::ALL {
                if a.within(b) && b.within(c) {
                    assert!(a.within(c));
                }
            }
        }
    }
    // Monotone in forms.
    let forms = [
        F::Boolean,
        F::BoundedCategory { max: 3 },
        F::Aggregate,
        F::DpAggregate,
        F::DerivedArtifact,
    ];
    for a in ReleaseClass::ALL {
        for b in ReleaseClass::ALL.into_iter().filter(|b| a.within(*b)) {
            for f in forms {
                assert!(!a.allows_form(f) || b.allows_form(f), "{a:?} {b:?} {f:?}");
            }
        }
    }
    // The class → forms mapping.
    let allowed =
        |c: ReleaseClass| -> Vec<F> { forms.into_iter().filter(|f| c.allows_form(*f)).collect() };
    assert_eq!(allowed(Never), vec![]);
    assert_eq!(
        allowed(BooleanOnly),
        vec![F::Boolean, F::BoundedCategory { max: 3 }]
    );
    assert_eq!(allowed(AggregateOnly), vec![F::Aggregate, F::DpAggregate]);
    assert_eq!(allowed(DpAggregateOnly), vec![F::DpAggregate]);
    assert_eq!(allowed(AuthorizedAgencyOnly), forms.to_vec());
    assert_eq!(allowed(DerivedArtifactOnly), vec![F::DerivedArtifact]);
    // An output proven to be a plain value only fits the classes that
    // release values (or none).
    let value = BTreeSet::new();
    let admitting: Vec<ReleaseClass> = ReleaseClass::ALL
        .into_iter()
        .filter(|c| c.admits(&value))
        .collect();
    assert_eq!(admitting, vec![Never, AuthorizedAgencyOnly]);
    // Nothing released is within any ceiling; otherwise the order decides.
    for b in ReleaseClass::ALL {
        assert!(encompute_verification::governance::release_within(Never, b));
        for a in ReleaseClass::ALL.into_iter().filter(|a| *a != Never) {
            assert_eq!(
                encompute_verification::governance::release_within(a, b),
                a.within(b)
            );
        }
    }
}

#[test]
fn a_grant_records_where_the_job_was_placed() {
    use encompute_verification::placement::{GrantPlacement, Location, LocationEvidence};
    let control = ServiceSigner::from_seed("control-plane", &[5; 32]).unwrap();
    let pk = control.public_key_hex();
    let p = h('a');
    // Without it, the grant's bytes are as before.
    let plain = grant(&control, Some(grant_governance()));
    assert!(!serde_json::to_string(&plain).unwrap().contains("operator"));
    let mut gg = grant_governance();
    gg.placement = Some(GrantPlacement {
        operator: "platform".into(),
        location: Some(Location::resolve("gcp", "europe-west3", None).unwrap()),
        evidence: LocationEvidence::OperatorDeclared,
        evidence_digest: Some(h('c')),
        endpoint_digest: Some(h('e')),
    });
    let placed = grant(&control, Some(gg.clone()));
    placed.verify(&pk, "evaluator-1", &p, 1_200).unwrap();
    assert_ne!(placed.signature, plain.signature, "the record is signed");
    assert_eq!(JobGrant::from_header(&placed.to_header()).unwrap(), placed);
    // A forged jurisdiction or a malformed digest is no grant.
    let mut forged = gg.clone();
    forged
        .placement
        .as_mut()
        .unwrap()
        .location
        .as_mut()
        .unwrap()
        .jurisdiction = "US".into();
    assert!(forged.check(&forged.binding.project.clone()).is_err());
    let mut short = gg;
    short.placement.as_mut().unwrap().evidence_digest = Some("abc".into());
    assert!(short.check(&short.binding.project.clone()).is_err());
}
