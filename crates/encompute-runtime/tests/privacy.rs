//! Differential privacy over secure aggregation (ADR-013): repeated rounds
//! spend each hospital's patient-level budget until a release is denied,
//! and every attempt to cheat the budget fails closed.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::PartyId;
use encompute_ir::{parse, Code};
use encompute_runtime::attestation::mock::{MockHardware, MockProvider};
use encompute_runtime::attestation::{AttestationPolicy, TeeKind, Verifier};
use encompute_runtime::dp::ledger::{self, Checkpoint};
use encompute_runtime::secagg::{
    identity_of, verify_aggregation_receipt, AggregateAsset, AggregationReceipt, AggregationSpec,
    JoinOptions, RoundCoordinator, RoundParticipant,
};
use encompute_runtime::Model;

const T0: u64 = 1_900_000_000;
const LEN: usize = 32;

/// Three hospitals, each with a patient-level budget on its gradient.
fn program(noise: f64, clip: f64, epsilon: f64) -> Model {
    let mut s = String::from(
        "encompute 0.1\nprogram fedavg precision 0.001 purpose \"disease-training\"\n\
         party \"coordinator\" \"Coordinator\"\n",
    );
    for x in ["a", "b", "c"] {
        s.push_str(&format!("party \"hospital-{x}\" \"Hospital {x}\"\n"));
    }
    for x in ["a", "b", "c"] {
        s.push_str(&format!(
            "asset \"gradient-{x}\" gradient owners [\"hospital-{x}\"] readers [\"coordinator\"] \
             purposes [\"disease-training\"] release aggregate_only \
             privacy unit \"patient\" epsilon {epsilon:?} delta 1e-6\n"
        ));
    }
    for (i, x) in ["a", "b", "c"].iter().enumerate() {
        s.push_str(&format!(
            "%{i} = input \"g{x}\" [-1.0, 1.0] asset \"gradient-{x}\" : secret vector<{LEN}>\n"
        ));
    }
    s.push_str(&format!(
        "%3 = add %0, %1 : secret vector<{LEN}>\n%4 = add %3, %2 : secret vector<{LEN}>\n\
         output \"global_gradient\" = %4 to \"coordinator\"\n\
         aggregate \"global_gradient\" sum minimum 3 colluding 2 clip [-1.0, 1.0] scale 4096 \
         modulus 40 dp discrete_gaussian clip_norm {clip:?} noise_multiplier {noise:?}\n"
    ));
    Model::compile(parse(&s).unwrap()).unwrap()
}

fn approved() -> Model {
    program(4.0, 1.0, 3.0)
}

fn party(i: usize) -> PartyId {
    PartyId::new(&format!("hospital-{}", (b'a' + i as u8) as char)).unwrap()
}

fn key(i: usize) -> SigningKey {
    SigningKey::from_bytes(&[i as u8 + 1; 32])
}

fn spec_of(m: &Model) -> AggregationSpec {
    let plan = m.aggregation_plan(None).unwrap();
    AggregationSpec::new(
        plan,
        (0..3).map(|i| identity_of(&party(i), &key(i))).collect(),
    )
    .unwrap()
}

fn gradient(i: usize) -> Vec<f64> {
    (0..LEN)
        .map(|j| (((i * 31 + j * 17) % 200) as f64 / 1000.0) - 0.1)
        .collect()
}

fn ledger_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("encompute-rt-dp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Each party's view: its approved spec and its last ledger checkpoint.
struct Party {
    spec: AggregationSpec,
    seen: Option<Checkpoint>,
}

/// One round: coordinator `coord` (already opened with its ledger), all
/// three parties checking their ledgers. Returns the aggregate and receipt,
/// updating each party's checkpoint from its privacy receipt.
fn round(
    coord: &mut RoundCoordinator,
    parties: &mut [Party],
    coordinator_check: Option<&Verifier>,
) -> encompute_ir::Result<(AggregateAsset, AggregationReceipt)> {
    let views = coord.ledger_views()?;
    let attestation = coord.coordinator_attestation().cloned();
    let mut ps = vec![];
    for (i, p) in parties.iter().enumerate() {
        let asset = format!("gradient-{}", (b'a' + i as u8) as char);
        ps.push(RoundParticipant::join_with(
            &p.spec,
            &coord.spec,
            &coord.round,
            &party(i),
            key(i),
            &gradient(i),
            JoinOptions {
                ledger: views.get(&asset),
                seen: p.seen.as_ref(),
                coordinator: match (&attestation, coordinator_check) {
                    (Some(r), Some(v)) => Some((r, v)),
                    _ => None,
                },
                ..JoinOptions::default()
            },
        )?);
    }
    for p in ps.iter_mut() {
        coord.receive_advertise(p.advertise()?)?;
    }
    let k = coord.close_advertise()?;
    for p in ps.iter_mut() {
        coord.receive_shares(p.share_keys(&k)?)?;
    }
    let inbox = coord.close_shares()?;
    for p in ps.iter_mut() {
        let who = p.party().clone();
        coord.receive_masked(p.masked_input(&inbox[&who])?)?;
    }
    let s = coord.close_masked()?;
    for p in ps.iter_mut() {
        coord.receive_consistency(p.consistency(&s)?)?;
    }
    let u = coord.close_consistency()?;
    for p in ps.iter_mut() {
        coord.receive_reveal(p.unmask(&u)?)?;
    }
    let (agg, receipt) = coord.finalize()?;
    for (i, p) in parties.iter_mut().enumerate() {
        let asset = format!("gradient-{}", (b'a' + i as u8) as char);
        let r = agg
            .privacy
            .iter()
            .find(|r| r.asset_id == asset)
            .expect("receipt per asset");
        encompute_runtime::dp::verify_privacy_receipt(
            r,
            Some(&receipt.coordinator_key),
            None,
            Some(&agg.encoded_sum),
        )?;
        p.seen = Some(Checkpoint {
            seq: r.ledger_seq,
            root: r.ledger_root.clone(),
        });
    }
    Ok((agg, receipt))
}

fn parties(m: &Model) -> Vec<Party> {
    (0..3)
        .map(|_| Party {
            spec: spec_of(m),
            seen: None,
        })
        .collect()
}

fn coordinator(
    m: &Model,
    seq: u64,
    dir: &std::path::Path,
) -> encompute_ir::Result<RoundCoordinator> {
    RoundCoordinator::open(
        spec_of(m),
        seq,
        SigningKey::from_bytes(&[200; 32]),
        None,
        T0,
    )?
    .with_ledger(dir)
}

#[test]
fn rounds_until_the_budget_is_spent() {
    let m = approved();
    let dir = ledger_dir("rounds");
    let mut ps = parties(&m);
    let spec = spec_of(&m);
    let codec = spec.plan.codec;
    let mut permitted = 0u64;
    let denied = loop {
        let mut c = match coordinator(&m, permitted + 1, &dir) {
            Ok(c) => c,
            Err(e) => break e,
        };
        let (agg, receipt) = round(&mut c, &mut ps, None).unwrap();
        permitted += 1;
        verify_aggregation_receipt(&receipt, &spec, None, Some(&agg)).unwrap();
        assert_eq!(
            receipt.manifest.privacy.len(),
            3,
            "one privacy receipt per hospital"
        );
        // Noisy, but near the clear sum: sigma = 4 * 1.0 * 4096 codes.
        let sigma = 4.0 * 4096.0 / 4096.0;
        let mut exact = true;
        for j in 0..LEN {
            let clear: f64 = (0..3).map(|i| gradient(i)[j]).sum();
            let err = (agg.values[j] - clear).abs();
            assert!(err < 7.0 * sigma + 3.0 * codec.resolution(), "{err}");
            exact &= err < 3.0 * codec.resolution();
        }
        assert!(!exact, "noise was added");
        assert!(permitted < 200);
    };
    assert!(permitted >= 2, "{permitted} rounds");
    assert_eq!(denied.code, Code::PrivacyBudgetExceeded, "{denied}");
    // Every hospital's ledger shows the spend, and survives a restart.
    for x in ["a", "b", "c"] {
        let v = ledger::read(&dir.join(format!("gradient-{x}.ledger"))).unwrap();
        assert_eq!(v.entries.len() as u64, 2 * permitted);
        assert!(v.cost().unwrap().epsilon <= 3.0);
    }
    assert_eq!(
        coordinator(&m, permitted + 1, &dir).err().unwrap().code,
        Code::PrivacyBudgetExceeded
    );
}

#[test]
fn weaker_mechanisms_are_not_the_approved_spec() {
    let m = approved();
    let dir = ledger_dir("weaker");
    // An honest coordinator's own budget check refuses the weaker noise.
    assert_eq!(
        coordinator(&program(0.5, 1.0, 3.0), 1, &dir)
            .err()
            .unwrap()
            .code,
        Code::PrivacyBudgetExceeded
    );
    // A malicious one skips that check: the hospitals still refuse, since a
    // version with less noise, a larger clip or a bigger budget is not the
    // spec they approved.
    for cheat in [
        program(0.5, 1.0, 3.0),
        program(4.0, 2.0, 3.0),
        program(4.0, 1.0, 30.0),
    ] {
        let mut c = RoundCoordinator::open(
            spec_of(&cheat),
            1,
            SigningKey::from_bytes(&[200; 32]),
            None,
            T0,
        )
        .unwrap();
        let e = round(&mut c, &mut parties(&m), None).unwrap_err();
        assert_eq!(e.code, Code::AggregationBinding, "{e}");
        assert!(e.message.contains("differ"), "{e}");
    }
    // No noise at all does not even compile.
    assert!(std::panic::catch_unwind(|| program(0.0, 1.0, 3.0)).is_err());
}

#[test]
fn ledger_rollback_deletion_reset_and_substitution_fail_closed() {
    let m = approved();
    let dir = ledger_dir("rollback");
    let mut ps = parties(&m);
    round(&mut coordinator(&m, 1, &dir).unwrap(), &mut ps, None).unwrap();
    let path = dir.join("gradient-a.ledger");
    let after_one = std::fs::read_to_string(&path).unwrap();
    round(&mut coordinator(&m, 2, &dir).unwrap(), &mut ps, None).unwrap();
    let after_two = std::fs::read_to_string(&path).unwrap();

    // Rollback: the coordinator restores the ledger to round 1.
    std::fs::write(&path, &after_one).unwrap();
    let e = round(&mut coordinator(&m, 3, &dir).unwrap(), &mut ps, None).unwrap_err();
    assert_eq!(e.code, Code::PrivacyLedger, "rollback: {e}");
    // Deletion of an event: the chain breaks.
    let lines: Vec<&str> = after_two.lines().collect();
    let mut del = lines.clone();
    del.remove(2);
    std::fs::write(&path, del.join("\n") + "\n").unwrap();
    assert_eq!(
        coordinator(&m, 3, &dir).err().unwrap().code,
        Code::PrivacyLedger
    );
    // Reset: no ledger at all (a restarted, amnesiac coordinator).
    std::fs::remove_file(&path).unwrap();
    let e = round(&mut coordinator(&m, 3, &dir).unwrap(), &mut ps, None).unwrap_err();
    assert_eq!(e.code, Code::PrivacyLedger, "reset: {e}");
    // Another dataset's ledger (with budget left) in its place.
    std::fs::copy(dir.join("gradient-b.ledger"), &path).unwrap();
    assert_eq!(
        coordinator(&m, 3, &dir).err().unwrap().code,
        Code::PrivacyLedger
    );
    // Restored honestly: rounds continue.
    std::fs::write(&path, &after_two).unwrap();
    round(&mut coordinator(&m, 3, &dir).unwrap(), &mut ps, None).unwrap();
}

#[test]
fn attested_coordinator_binds_the_privacy_configuration() {
    let m = approved();
    let dir = ledger_dir("attest");
    let hw = MockHardware::from_seed(&[6; 32]);
    let image = format!("sha256:{}", "5".repeat(64));
    let plan = m.aggregation_plan(None).unwrap();
    let mut policy = AttestationPolicy::new(&plan.id().unwrap(), plan.policy_id.as_deref());
    policy.privacy_policy_id = plan.privacy_policy_id.clone();
    policy.artifact_digest = Some(plan.program_id.clone());
    policy.allowed_tee = vec![TeeKind::Mock];
    policy.allowed_images = vec![image.clone()];
    policy.allow_development = true;
    let with_policy = |m: &Model| {
        let mut s = spec_of(m);
        s.coordinator_attestation = Some(policy.clone());
        s
    };
    let verifier = Verifier::new().with(MockProvider::new(&hw.public_key()).unwrap());
    let mut ps: Vec<Party> = (0..3)
        .map(|_| Party {
            spec: with_policy(&m),
            seen: None,
        })
        .collect();
    let open = |image: &str| {
        let mut c = RoundCoordinator::open(
            with_policy(&m),
            1,
            SigningKey::from_bytes(&[200; 32]),
            None,
            T0,
        )
        .unwrap()
        .with_ledger(&dir)
        .unwrap();
        c.attest(&hw.attester(image).issued_at(T0)).unwrap();
        c
    };
    // Unattested coordinator: refused.
    let mut bare = RoundCoordinator::open(
        with_policy(&m),
        1,
        SigningKey::from_bytes(&[200; 32]),
        None,
        T0,
    )
    .unwrap()
    .with_ledger(&dir)
    .unwrap();
    assert_eq!(
        round(&mut bare, &mut ps, Some(&verifier)).unwrap_err().code,
        Code::AggregationUnauthorized
    );
    // An unapproved coordinator image: refused.
    let e = round(&mut open("sha256:tampered"), &mut ps, Some(&verifier)).unwrap_err();
    assert_eq!(e.code, Code::WorkloadPolicy, "{e}");
    // The approved, attested coordinator: accepted.
    round(&mut open(&image), &mut ps, Some(&verifier)).unwrap();
    // A coordinator attesting another privacy configuration: its binding
    // does not satisfy the policy.
    let mut other = policy.clone();
    other.privacy_policy_id = Some("ee".repeat(32));
    let record = open(&image).coordinator_attestation().cloned().unwrap();
    assert_eq!(
        record.verify(&verifier, &other).unwrap_err().code,
        Code::WorkloadPolicy
    );
}

#[test]
fn explain_shows_budgets_and_preview() {
    let m = approved();
    let text = m.privacy_explain().unwrap().unwrap();
    for want in [
        "Differential privacy",
        "discrete_gaussian",
        "privacy unit",
        "patient",
        "epsilon 3",
        "delta 1e-6",
    ] {
        assert!(text.contains(want), "missing {want:?}\n{text}");
    }
    let dir = ledger_dir("explain");
    let mut ps = parties(&m);
    round(&mut coordinator(&m, 1, &dir).unwrap(), &mut ps, None).unwrap();
    let preview = m.privacy_preview(&dir).unwrap();
    for want in ["PROPOSED PRIVACY RELEASE", "gradient-a", "PERMITTED"] {
        assert!(preview.contains(want), "missing {want:?}\n{preview}");
    }
    let status = m.privacy_status(&dir).unwrap();
    for want in [
        "consumed",
        "remaining",
        "next release",
        "PERMITTED",
        "differential privacy",
    ] {
        assert!(status.contains(want), "missing {want:?}\n{status}");
    }
    let budget = encompute_runtime::privacy_budget_report(&dir, None).unwrap();
    for want in ["PRIVACY BUDGET", "gradient-a", "Remaining"] {
        assert!(budget.contains(want), "missing {want:?}\n{budget}");
    }
}

/// One owner's state protects every asset: hospital A has lost its state,
/// but B knows A's last checkpoint (from the signed receipt) and refuses a
/// round whose offer rolls A's ledger back.
#[test]
fn any_owner_detects_another_assets_rollback() {
    use std::collections::BTreeMap;
    let m = approved();
    let dir = ledger_dir("cross");
    let mut ps = parties(&m);
    round(&mut coordinator(&m, 1, &dir).unwrap(), &mut ps, None).unwrap();
    let path = dir.join("gradient-a.ledger");
    let after_one = std::fs::read_to_string(&path).unwrap();
    let (agg, _) = round(&mut coordinator(&m, 2, &dir).unwrap(), &mut ps, None).unwrap();
    // B records every asset's checkpoint from the round's receipts.
    let known: BTreeMap<String, Checkpoint> = agg
        .privacy
        .iter()
        .map(|r| {
            (
                r.asset_id.clone(),
                Checkpoint {
                    seq: r.ledger_seq,
                    root: r.ledger_root.clone(),
                },
            )
        })
        .collect();
    std::fs::write(&path, after_one).unwrap();
    let c = coordinator(&m, 3, &dir).unwrap();
    let views = c.ledger_views().unwrap();
    // A (no state) would not notice…
    RoundParticipant::join_with(
        &spec_of(&m),
        &c.spec,
        &c.round,
        &party(0),
        key(0),
        &gradient(0),
        JoinOptions {
            ledger: views.get("gradient-a"),
            ..JoinOptions::default()
        },
    )
    .unwrap();
    // …but B does.
    let e = RoundParticipant::join_with(
        &spec_of(&m),
        &c.spec,
        &c.round,
        &party(1),
        key(1),
        &gradient(1),
        JoinOptions {
            ledger: views.get("gradient-b"),
            seen: known.get("gradient-b"),
            all_ledgers: Some(&views),
            known: Some(&known),
            ..JoinOptions::default()
        },
    )
    .err()
    .unwrap();
    assert_eq!(e.code, Code::PrivacyLedger);
    assert!(e.message.contains("gradient-a"), "{e}");
}
