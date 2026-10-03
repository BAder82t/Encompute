//! Governed projects under generated scenarios: an owner authorization is
//! usable exactly inside its window, before its key's and its own
//! revocation, and any edit or foreign key voids its signature; the release
//! classes form the documented order; and combining placement constraints
//! only narrows what is allowed, with a prohibited place always winning.
//! Each property is judged against an independent model, so a bug in the
//! shared function cannot also hide in the check.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use encompute_ir::Code;
use encompute_trust::authz::{
    ApprovalEvidence, AuthorizationLimits, AuthorizationV2, GovernanceKey, GovernanceKeyStatus,
    RevocationV2,
};
use encompute_verification::governance::{ProgramRef, ReleaseClass};
use encompute_verification::hex;
use encompute_verification::placement::{
    locations, Location, LocationEvidence, LocationPattern, Machine, PlacementConstraints, Refused,
};

use crate::{ensure, rand_u64, CheckResult, Outcome, Scale};

fn below(n: u64) -> u64 {
    rand_u64() % n.max(1)
}

fn h(c: char) -> String {
    c.to_string().repeat(64)
}

fn signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    for chunk in seed.chunks_mut(8) {
        chunk.copy_from_slice(&rand_u64().to_le_bytes());
    }
    SigningKey::from_bytes(&seed)
}

/// An authorization of `party` over a window, approved by two people.
fn authorization(from: u64, until: u64, issued_at: u64) -> AuthorizationV2 {
    let mut b = AuthorizationV2 {
        version: 2,
        party: "tax-agency".into(),
        project: "prj_1".into(),
        purpose_id: h('1'),
        asset_version_id: h('2'),
        asset_digest_commitment: h('3'),
        program: ProgramRef::Program { program_id: h('a') },
        policy_id: h('4'),
        privacy_policy_id: None,
        linkage_policy_id: None,
        release_class: ReleaseClass::BooleanOnly,
        recipients: BTreeSet::from(["benefits-agency".to_string()]),
        privacy_scope_id: None,
        execution_spec_ids: None,
        limits: AuthorizationLimits {
            max_executions: Some(10),
            max_releases: Some(10),
            ..Default::default()
        },
        per_job_four_eyes: false,
        valid_from: from,
        valid_until: until,
        issued_at,
        nonce: format!("{:016x}{:016x}", rand_u64(), rand_u64()),
        approvals: vec![],
    };
    let approvals: Vec<ApprovalEvidence> = [("alice", "data_owner"), ("bob", "security_admin")]
        .iter()
        .map(|(who, role)| ApprovalEvidence {
            statement_digest: b.approval_statement("https://idp.tax.example", who, role),
            approver_subject: (*who).into(),
            idp_issuer: "https://idp.tax.example".into(),
            auth_time: None,
            acr: None,
            amr: None,
            role: (*role).into(),
            organization: b.party.clone(),
            at: issued_at,
        })
        .collect();
    b.approvals = approvals;
    b
}

/// Times worth trying around `edges`: each edge, one either side, and a
/// few anywhere.
fn times(edges: &[u64]) -> Vec<u64> {
    let mut t = vec![0, 1, u64::MAX / 2];
    for &e in edges {
        t.extend([e.saturating_sub(1), e, e + 1]);
    }
    t.extend((0..4).map(|_| below(10_000)));
    t
}

/// An authorization is usable at `t` exactly when `t` is in its window
/// (valid_from <= t < valid_until, no margin), its governance key is not
/// revoked at `t` and did not sign after its revocation, and the owner's
/// revocation of it is not in effect at `t`; an edited body or another key
/// never verifies.
pub fn authorization_property(scale: Scale) -> CheckResult {
    let rounds = scale.pick(300, 5_000);
    let mut cases = 0;
    for _ in 0..rounds {
        let from = 100 + below(2_000);
        let until = from + 1 + below(2_000);
        let issued_at = below(from + 1);
        let sk = signing_key();
        let revoked_at = (below(3) == 0).then(|| below(5_000));
        let key = GovernanceKey {
            organization: "tax-agency".into(),
            public_key: hex(&sk.verifying_key().to_bytes()),
            status: if revoked_at.is_some() {
                GovernanceKeyStatus::Revoked
            } else {
                GovernanceKeyStatus::Active
            },
            revoked_at,
        };
        let signed = authorization(from, until, issued_at)
            .sign(&sk)
            .map_err(|e| e.to_string())?;
        let revocation = (below(3) == 0).then(|| {
            RevocationV2 {
                version: 2,
                party: "tax-agency".into(),
                authorization: signed.id(),
                reason: "withdrawn".into(),
                issued_at: below(5_000),
            }
            .sign(&sk)
            .expect("signs")
        });
        let mut edges = vec![from, until, issued_at];
        edges.extend(revoked_at);
        edges.extend(revocation.as_ref().map(|r| r.body.issued_at));
        for t in times(&edges) {
            let model = from <= t
                && t < until
                && revoked_at.is_none_or(|r| issued_at < r && t < r)
                && revocation.as_ref().is_none_or(|r| t < r.body.issued_at);
            let got = signed.usable_at(&key, revocation.as_ref().map(|r| &r.body), t);
            ensure!(
                got.is_ok() == model,
                "usable_at({t}) = {:?}, the model says {model}: window [{from}, {until}), \
                 issued {issued_at}, key revoked {revoked_at:?}, revocation {:?}",
                got.map_err(|e| e.message),
                revocation.as_ref().map(|r| r.body.issued_at)
            );
            // Without a revocation of either, the only refusal is expiry.
            if revoked_at.is_none() && revocation.is_none() && !model {
                let e = signed
                    .usable_at(&key, None, t)
                    .expect_err("outside the window");
                ensure!(
                    e.code == Code::GovernanceAuthorizationExpired,
                    "outside its window at {t}: {:?}, not an expiry",
                    e.code
                );
            }
            cases += 1;
        }
        // Any edit, and any other key, voids the signature.
        let pk = key.public_key.clone();
        ensure!(
            signed.verify(&pk).is_ok(),
            "an authorization does not verify"
        );
        let edits: [&dyn Fn(&mut AuthorizationV2); 8] = [
            &|b| b.valid_until += 1,
            &|b| b.valid_from = b.valid_from.saturating_sub(1),
            &|b| {
                b.recipients.insert("other-agency".into());
            },
            &|b| b.release_class = ReleaseClass::AuthorizedAgencyOnly,
            &|b| b.purpose_id = h('9'),
            &|b| b.program = ProgramRef::Program { program_id: h('b') },
            &|b| b.asset_version_id = h('8'),
            &|b| b.limits.max_releases = Some(11),
        ];
        for edit in edits {
            let mut forged = signed.clone();
            edit(&mut forged.body);
            ensure!(
                forged.verify(&pk).is_err(),
                "an edited authorization still verifies"
            );
            ensure!(
                forged.id() != signed.id(),
                "an edited authorization keeps its ID"
            );
            cases += 1;
        }
        let stranger = hex(&signing_key().verifying_key().to_bytes());
        ensure!(
            signed.verify(&stranger).is_err(),
            "another governance key verifies the signature"
        );
        cases += 1;
    }
    Ok(Outcome::new(cases))
}

/// The release classes form the owners' partial order: reflexive,
/// transitive and antisymmetric; `never` and `derived-artifact-only` are
/// within only themselves and nothing else is within them; every class a
/// form allows is judged by the same function (exhaustive).
pub fn release_class_order(_: Scale) -> CheckResult {
    use ReleaseClass::*;
    let all = ReleaseClass::ALL;
    let mut cases = 0;
    for a in all {
        ensure!(a.within(a), "{} is not within itself", a.as_str());
        for b in all {
            if a != b {
                ensure!(
                    !(a.within(b) && b.within(a)),
                    "{} and {} are each within the other",
                    a.as_str(),
                    b.as_str()
                );
            }
            for c in all {
                if a.within(b) && b.within(c) {
                    ensure!(
                        a.within(c),
                        "{} is within {} within {}, but not within {}",
                        a.as_str(),
                        b.as_str(),
                        c.as_str(),
                        c.as_str()
                    );
                }
                cases += 1;
            }
        }
    }
    for lone in [Never, DerivedArtifactOnly] {
        for other in all {
            if other != lone {
                ensure!(
                    !lone.within(other) && !other.within(lone),
                    "{} is related to {}",
                    lone.as_str(),
                    other.as_str()
                );
            }
        }
    }
    // The documented edges, and no others.
    let documented = [
        (BooleanOnly, AuthorizedAgencyOnly),
        (AggregateOnly, AuthorizedAgencyOnly),
        (DpAggregateOnly, AuthorizedAgencyOnly),
        (DpAggregateOnly, AggregateOnly),
    ];
    for a in all {
        for b in all {
            let want = a == b || documented.contains(&(a, b));
            ensure!(
                a.within(b) == want,
                "{} within {} is {}, the documented order says {want}",
                a.as_str(),
                b.as_str(),
                a.within(b)
            );
        }
    }
    Ok(Outcome::new(cases))
}

fn pick<T: Clone>(xs: &[T]) -> T {
    xs[below(xs.len() as u64) as usize].clone()
}

fn pattern() -> LocationPattern {
    let (p, r, j) = pick(locations::TABLE);
    match below(4) {
        0 => LocationPattern::jurisdiction(j),
        1 => LocationPattern::region(p, r),
        2 => LocationPattern::provider(p),
        _ => LocationPattern {
            jurisdiction: Some(j.into()),
            provider: Some(p.into()),
            region: None,
            zone: None,
        },
    }
}

fn names(pool: &[&str]) -> Option<BTreeSet<String>> {
    (below(3) == 0).then(|| {
        let mut s: BTreeSet<String> = (0..1 + below(2)).map(|_| pick(pool).to_string()).collect();
        if s.is_empty() {
            s.insert(pool[0].to_string());
        }
        s
    })
}

const OPERATORS: [&str; 3] = ["op-a", "op-b", "op-c"];
const EVALUATORS: [&str; 3] = ["ev-a", "ev-b", "ev-c"];

fn constraints() -> PlacementConstraints {
    PlacementConstraints {
        allowed_regions: (below(2) == 0).then(|| (0..1 + below(3)).map(|_| pattern()).collect()),
        prohibited_locations: (0..below(3)).map(|_| pattern()).collect(),
        allowed_operators: names(&OPERATORS),
        allowed_evaluators: names(&EVALUATORS),
        min_evidence: pick(&[
            LocationEvidence::SelfDeclared,
            LocationEvidence::OperatorDeclared,
            LocationEvidence::Attested,
        ]),
        ..Default::default()
    }
}

/// Combining two constraints, or adding a rule to one, only narrows: the
/// result refuses every machine either input refuses, a machine a
/// prohibited pattern of either may contain is refused as prohibited
/// whatever the other allows, and the result is at least as tight as each
/// input.
pub fn placement_property(scale: Scale) -> CheckResult {
    let rounds = scale.pick(2_000, 40_000);
    let mut cases = 0;
    for _ in 0..rounds {
        let (a, b) = (constraints(), constraints());
        let c = a.combine(&b);
        ensure!(
            c.tightens(&a) && c.tightens(&b),
            "a combination is not at least as tight as both inputs: {a:?} {b:?}"
        );
        // A rule added to `a`.
        let mut narrower = a.clone();
        narrower.prohibited_locations.insert(pattern());
        ensure!(
            narrower.tightens(&a),
            "adding a prohibited location does not tighten: {a:?}"
        );
        let location = (below(5) != 0).then(|| {
            let (p, r, _) = pick(locations::TABLE);
            Location::resolve(p, r, None).expect("a table entry resolves")
        });
        let m = Machine {
            id: EVALUATORS[below(3) as usize],
            operator: OPERATORS[below(3) as usize],
            location: location.as_ref(),
            evidence: pick(&[
                LocationEvidence::SelfDeclared,
                LocationEvidence::OperatorDeclared,
                LocationEvidence::Attested,
            ]),
        };
        let (ra, rb, rc) = (a.refusals(&m), b.refusals(&m), c.refusals(&m));
        ensure!(
            (ra.is_empty() && rb.is_empty()) || !rc.is_empty(),
            "the combination admits a machine an input refuses ({ra:?}, {rb:?}): {a:?} {b:?} {m:?}"
        );
        ensure!(
            a.refusals(&m)
                .iter()
                .all(|r| narrower.refusals(&m).contains(r)),
            "adding a rule dropped a refusal: {a:?} {m:?}"
        );
        if let Some(l) = m.location {
            for x in [&a, &b] {
                if x.prohibited_locations.iter().any(|p| p.may_contain(l)) {
                    ensure!(
                        rc.contains(&Refused::ProhibitedLocations),
                        "a prohibited place was not refused by the combination: {a:?} {b:?} {l:?}"
                    );
                }
            }
        }
        // The digest binds the rules: a different rule, a different digest.
        if narrower != a {
            ensure!(
                narrower.digest() != a.digest(),
                "two different constraints share a digest"
            );
        }
        cases += 1;
    }
    Ok(Outcome::new(cases))
}
