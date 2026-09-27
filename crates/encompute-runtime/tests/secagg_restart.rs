//! A SecAgg coordinator that crashes (is dropped) at a random stage of a
//! differentially private round and restarts. The parties keep their state
//! (the last round sequence joined, written before contributing, and their
//! ledger checkpoints), as the CLI's `--state` does. Then:
//!
//! - the crashed round never runs again: every party refuses its sequence
//!   (a rerun with other survivors would let a coordinator subtract two
//!   aggregates), so no output and no privacy spend happens twice;
//! - the next round (a higher sequence) runs and releases once;
//! - a round that crashed before `finalize` spent nothing, every released
//!   round is reserved and committed exactly once in every ledger, and
//!   every ledger stays valid.
//!
//! Note: a coordinator reopened on the same sequence gets a fresh round
//! nonce, hence a new round ID and new privacy event IDs: parties that do
//! not persist their last sequence would let it release that round again.
//!
//! (Crashes *inside* the release, between reservation and commit, are the
//! assurance suite's failpoint checks: `crash_injection`.)
//!
//! Bounded by default; `ENCOMPUTE_RESTART_ITERATIONS` multiplies the
//! iterations and `ENCOMPUTE_RESTART_SEED` replays a run.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::PartyId;
use encompute_ir::parse;
use encompute_runtime::dp::ledger::{self, Checkpoint};
use encompute_runtime::dp::PrivacyEvent;
use encompute_runtime::secagg::{
    identity_of, AggregateAsset, AggregationReceipt, AggregationSpec, JoinOptions,
    RoundCoordinator, RoundParticipant,
};
use encompute_runtime::Model;

const T0: u64 = 1_900_000_000;
const LEN: usize = 16;
const ASSETS: [&str; 3] = ["gradient-a", "gradient-b", "gradient-c"];

fn program() -> Model {
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
             privacy unit \"patient\" epsilon 100.0 delta 1e-6\n"
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
         modulus 40 dp discrete_gaussian clip_norm 1.0 noise_multiplier 4.0\n"
    ));
    Model::compile(parse(&s).unwrap()).unwrap()
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

fn coordinator(m: &Model, seq: u64, dir: &Path) -> encompute_ir::Result<RoundCoordinator> {
    RoundCoordinator::open(
        spec_of(m),
        seq,
        SigningKey::from_bytes(&[200; 32]),
        None,
        T0,
    )?
    .with_ledger(dir)
}

/// A party's persistent state (the CLI's `--state`).
#[derive(Clone, Default)]
struct PartyState {
    last_sequence: Option<u64>,
    seen: Option<Checkpoint>,
}

/// Runs a round's stages; stops (the coordinator "crashes") after
/// `stages` of them. 6 stages finish the round (the last is `finalize`).
fn run(
    coord: &mut RoundCoordinator,
    parties: &mut [PartyState],
    stages: usize,
) -> encompute_ir::Result<Option<(AggregateAsset, AggregationReceipt)>> {
    let views = coord.ledger_views()?;
    let mut ps = vec![];
    for (i, st) in parties.iter_mut().enumerate() {
        ps.push(RoundParticipant::join_with(
            &coord.spec,
            &coord.spec,
            &coord.round,
            &party(i),
            key(i),
            &gradient(i),
            JoinOptions {
                ledger: views.get(ASSETS[i]),
                seen: st.seen.as_ref(),
                last_sequence: st.last_sequence,
                ..JoinOptions::default()
            },
        )?);
        // Written before contributing.
        st.last_sequence = Some(coord.round.sequence);
    }
    macro_rules! stage {
        ($n:expr) => {
            if stages <= $n {
                return Ok(None);
            }
        };
    }
    for p in ps.iter_mut() {
        coord.receive_advertise(p.advertise()?)?;
    }
    let k = coord.close_advertise()?;
    stage!(1);
    for p in ps.iter_mut() {
        coord.receive_shares(p.share_keys(&k)?)?;
    }
    let inbox = coord.close_shares()?;
    stage!(2);
    for p in ps.iter_mut() {
        let who = p.party().clone();
        coord.receive_masked(p.masked_input(&inbox[&who])?)?;
    }
    let s = coord.close_masked()?;
    stage!(3);
    for p in ps.iter_mut() {
        coord.receive_consistency(p.consistency(&s)?)?;
    }
    let u = coord.close_consistency()?;
    stage!(4);
    for p in ps.iter_mut() {
        coord.receive_reveal(p.unmask(&u)?)?;
    }
    stage!(5);
    let (agg, receipt) = coord.finalize()?;
    for (i, st) in parties.iter_mut().enumerate() {
        let r = agg
            .privacy
            .iter()
            .find(|r| r.asset_id == ASSETS[i])
            .expect("receipt per asset");
        st.seen = Some(Checkpoint {
            seq: r.ledger_seq,
            root: r.ledger_root.clone(),
        });
    }
    Ok(Some((agg, receipt)))
}

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "encompute-secagg-restart-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Every ledger: valid, one reservation and one commit per released round,
/// and nothing else.
fn check_ledgers(dir: &Path, released: &BTreeSet<String>) {
    for a in ASSETS {
        let path = dir.join(format!("{a}.ledger"));
        if !path.exists() {
            assert!(
                released.is_empty(),
                "{a}: no ledger, yet rounds were released"
            );
            continue;
        }
        let v = ledger::read(&path).unwrap();
        v.verify().unwrap();
        let (mut reserved, mut committed) = (BTreeSet::new(), BTreeSet::new());
        for e in &v.entries {
            let fresh = match &e.event {
                PrivacyEvent::Reserve { round_id, .. } => {
                    reserved.insert(round_id.clone().expect("a round's event"))
                }
                PrivacyEvent::Commit { event_id, .. } => committed.insert(event_id.clone()),
            };
            assert!(fresh, "{a}: event {} recorded twice", e.event.event_id());
        }
        let rounds: BTreeSet<String> = reserved.into_iter().collect();
        assert_eq!(&rounds, released, "{a}: reserved rounds");
        assert_eq!(committed.len(), released.len(), "{a}: commits");
    }
}

#[test]
fn coordinator_restart_never_reruns_a_round_or_releases_twice() {
    let m = program();
    let dir = scratch();
    let scale: usize = std::env::var("ENCOMPUTE_RESTART_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let mut rng = std::env::var("ENCOMPUTE_RESTART_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        })
        | 1;
    eprintln!("ENCOMPUTE_RESTART_SEED={rng}");
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut parties = vec![PartyState::default(); 3];
    let mut released = BTreeSet::new();
    let mut seq = 1;
    // Crash after every stage at least once, then at random.
    let crash_points: Vec<usize> = (1..=6)
        .chain((0..6 * scale.max(1) - 6).map(|_| 1 + (next() % 6) as usize))
        .collect();
    for crash_after in crash_points {
        let mut c = coordinator(&m, seq, &dir).unwrap();
        let out = run(&mut c, &mut parties, crash_after).unwrap();
        if crash_after == 6 {
            let (_, receipt) = out.expect("a finished round");
            assert!(released.insert(receipt.manifest.round_id.clone()));
        } else {
            assert!(out.is_none());
        }
        drop(c); // the coordinator process dies here
        check_ledgers(&dir, &released);
        // Restarted on the same sequence: every party refuses it, so the
        // round is neither re-run with other survivors nor released twice.
        let again = coordinator(&m, seq, &dir).and_then(|mut c| run(&mut c, &mut parties, 6));
        let e = again.expect_err("a crashed round ran again");
        assert_eq!(e.code, encompute_ir::Code::AggregationBinding, "{e}");
        assert!(e.message.contains("replay"), "{e}");
        check_ledgers(&dir, &released);
        // The next round runs, once.
        seq += 1;
        let mut c = coordinator(&m, seq, &dir).unwrap();
        let (_, receipt) = run(&mut c, &mut parties, 6)
            .unwrap()
            .expect("the next round completes");
        assert!(released.insert(receipt.manifest.round_id.clone()));
        check_ledgers(&dir, &released);
        seq += 1;
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
