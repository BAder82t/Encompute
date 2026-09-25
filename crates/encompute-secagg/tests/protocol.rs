//! The Bonawitz protocol in memory: correctness with and without dropouts,
//! and a malicious coordinator's attempts to learn an individual input.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::PartyId;
use encompute_ir::Code;
use encompute_secagg::protocol::{Coordinator, Participant, ProtocolParams, UnmaskRequest};

const BITS: u32 = 24;

fn setup(n: usize, t: usize, len: usize) -> (ProtocolParams, Vec<(Participant, Vec<u64>)>) {
    let keys: Vec<(PartyId, SigningKey)> = (0..n)
        .map(|i| {
            (
                PartyId::new(&format!("party-{i:02}")).unwrap(),
                SigningKey::from_bytes(&[i as u8 + 1; 32]),
            )
        })
        .collect();
    let params = ProtocolParams {
        round_id: "ab".repeat(32),
        parties: keys
            .iter()
            .map(|(p, k)| (p.clone(), k.verifying_key().to_bytes()))
            .collect(),
        threshold: t,
        max_colluding: 0,
        vector_len: len,
        modulus_bits: BITS,
    };
    let parts = keys
        .into_iter()
        .enumerate()
        .map(|(i, (p, k))| {
            let x: Vec<u64> = (0..len)
                .map(|j| ((i * 1000 + j * 7) % 5000) as u64)
                .collect();
            (
                Participant::new(params.clone(), p, k, x.clone(), None).unwrap(),
                x,
            )
        })
        .collect();
    (params, parts)
}

/// Runs a round; `drop_at[i] = Some(stage)` makes party i stop responding
/// from that stage on (0 advertise … 4 unmask).
fn run(n: usize, t: usize, drop_at: &[Option<u8>]) -> encompute_ir::Result<(Vec<u64>, Vec<u64>)> {
    let (params, mut parts) = setup(n, t, 16);
    let mut c = Coordinator::new(params.clone())?;
    let alive = |i: usize, stage: u8| drop_at.get(i).copied().flatten().is_none_or(|s| s > stage);
    for (i, (p, _)) in parts.iter_mut().enumerate() {
        if alive(i, 0) {
            c.receive_advertise(p.advertise()?)?;
        }
    }
    let keys = c.close_advertise()?;
    for (i, (p, _)) in parts.iter_mut().enumerate() {
        if alive(i, 1) {
            c.receive_shares(p.share_keys(&keys)?)?;
        }
    }
    let inboxes = c.close_shares()?;
    for (i, (p, _)) in parts.iter_mut().enumerate() {
        if alive(i, 2) {
            c.receive_masked(p.masked_input(&inboxes[p.party()])?)?;
        }
    }
    let survivors = c.close_masked()?;
    for (i, (p, _)) in parts.iter_mut().enumerate() {
        if alive(i, 3) {
            c.receive_consistency(p.consistency(&survivors)?)?;
        }
    }
    let req = c.close_consistency()?;
    for (i, (p, _)) in parts.iter_mut().enumerate() {
        if alive(i, 4) {
            c.receive_reveal(p.unmask(&req)?)?;
        }
    }
    let out = c.finalize()?;
    // Expected: the sum of the survivors' inputs.
    let mut want = vec![0u64; 16];
    for (p, x) in &parts {
        if out.survivors.contains(p.party()) {
            for (w, v) in want.iter_mut().zip(x) {
                *w = (*w + v) % (1 << BITS);
            }
        }
    }
    Ok((out.sum, want))
}

#[test]
fn sums_exactly() {
    let (got, want) = run(3, 2, &[]).unwrap();
    assert_eq!(got, want);
    let (got, want) = run(3, 3, &[]).unwrap();
    assert_eq!(got, want);
}

#[test]
fn tolerates_dropouts_down_to_the_threshold() {
    // 7 parties, threshold 4: drops at each stage.
    for plan in [
        vec![Some(0), None, None, None, None, None, None],
        vec![None, Some(1), None, None, None, None, None],
        vec![None, None, Some(2), Some(2), None, None, None],
        vec![Some(0), None, Some(2), None, Some(3), None, None],
        vec![None, None, None, Some(4), None, None, Some(4)],
    ] {
        let (got, want) = run(7, 4, &plan).unwrap();
        assert_eq!(got, want, "{plan:?}");
    }
}

#[test]
fn aborts_below_the_threshold() {
    for plan in [
        vec![Some(0), Some(0), None, None, None],
        vec![None, Some(2), Some(2), None, None],
        vec![Some(3), Some(3), None, None, None],
        vec![Some(4), Some(4), None, None, None],
    ] {
        let e = run(5, 4, &plan).unwrap_err();
        assert_eq!(e.code, Code::AggregationThreshold, "{plan:?}: {e}");
    }
}

#[test]
fn thresholds_below_a_majority_are_refused() {
    let (mut params, _) = setup(5, 3, 4);
    params.threshold = 2;
    assert_eq!(
        Coordinator::new(params).err().unwrap().code,
        Code::AggregationPlan
    );
}

/// A coordinator that claims a live party dropped, to recover its mask key
/// and so its input, is caught: survivors refuse to unmask for a survivor
/// set other than the one everyone signed.
#[test]
fn equivocating_coordinator_learns_nothing() {
    let (params, mut parts) = setup(4, 3, 8);
    let mut c = Coordinator::new(params).unwrap();
    for (p, _) in parts.iter_mut() {
        c.receive_advertise(p.advertise().unwrap()).unwrap();
    }
    let keys = c.close_advertise().unwrap();
    for (p, _) in parts.iter_mut() {
        c.receive_shares(p.share_keys(&keys).unwrap()).unwrap();
    }
    let inbox = c.close_shares().unwrap();
    for (p, _) in parts.iter_mut() {
        c.receive_masked(p.masked_input(&inbox[p.party()]).unwrap())
            .unwrap();
    }
    let survivors = c.close_masked().unwrap();
    let mut sigs = vec![];
    for (p, _) in parts.iter_mut() {
        sigs.push(p.consistency(&survivors).unwrap());
    }
    // Tell party 1 that party 0 dropped: it would then reveal party 0's
    // mask key while party 0's masked input is in hand.
    let lie = UnmaskRequest {
        round_id: survivors.round_id.clone(),
        survivors: survivors.survivors[1..].to_vec(),
        signatures: sigs.clone(),
    };
    assert_eq!(
        parts[1].0.unmask(&lie).unwrap_err().code,
        Code::AggregationProtocol
    );
    // Or forge "signatures" from fewer than t parties.
    let few = UnmaskRequest {
        round_id: survivors.round_id.clone(),
        survivors: survivors.survivors.clone(),
        signatures: sigs[..2].to_vec(),
    };
    assert_eq!(
        parts[2].0.unmask(&few).unwrap_err().code,
        Code::AggregationThreshold
    );
    // A signature altered to name a different survivor set.
    let mut forged = sigs.clone();
    forged[3].body.survivors.pop();
    let bad = UnmaskRequest {
        round_id: survivors.round_id.clone(),
        survivors: survivors.survivors.clone(),
        signatures: forged,
    };
    assert_eq!(
        parts[3].0.unmask(&bad).unwrap_err().code,
        Code::AggregationUnauthorized
    );
}

#[test]
fn messages_are_authenticated_and_bound() {
    let (params, mut parts) = setup(3, 2, 4);
    let mut c = Coordinator::new(params.clone()).unwrap();
    let a0 = parts[0].0.advertise().unwrap();
    // Duplicate.
    c.receive_advertise(a0.clone()).unwrap();
    assert_eq!(
        c.receive_advertise(a0.clone()).unwrap_err().code,
        Code::AggregationBinding
    );
    // Unknown party.
    let stranger = SigningKey::from_bytes(&[99; 32]);
    let mut p = params.clone();
    p.parties.push((
        PartyId::new("zz-unknown").unwrap(),
        stranger.verifying_key().to_bytes(),
    ));
    p.threshold = 3;
    let mut intruder = Participant::new(
        p,
        PartyId::new("zz-unknown").unwrap(),
        stranger,
        vec![1; 4],
        None,
    )
    .unwrap();
    assert_eq!(
        c.receive_advertise(intruder.advertise().unwrap())
            .unwrap_err()
            .code,
        Code::AggregationUnauthorized
    );
    // Another round.
    let mut other = params.clone();
    other.round_id = "cd".repeat(32);
    let mut old = Participant::new(
        other,
        params.parties[1].0.clone(),
        SigningKey::from_bytes(&[2; 32]),
        vec![1; 4],
        None,
    )
    .unwrap();
    assert_eq!(
        c.receive_advertise(old.advertise().unwrap())
            .unwrap_err()
            .code,
        Code::AggregationBinding
    );
    // Tampered signature.
    let mut a1 = parts[1].0.advertise().unwrap();
    a1.signed.body.c_pk = a0.signed.body.c_pk.clone();
    assert_eq!(
        c.receive_advertise(a1).unwrap_err().code,
        Code::AggregationUnauthorized
    );
    // Wrong shape at construction.
    assert_eq!(
        Participant::new(
            params.clone(),
            params.parties[2].0.clone(),
            SigningKey::from_bytes(&[3; 32]),
            vec![1; 5],
            None
        )
        .unwrap_err()
        .code,
        Code::AggregationBinding
    );
    // Out of order.
    assert!(parts[2]
        .0
        .masked_input(&encompute_secagg::protocol::Inbox {
            round_id: params.round_id.clone(),
            senders: vec![],
            ciphertexts: BTreeMap::new(),
        })
        .is_err());
}

#[test]
fn tampered_masked_contribution_is_refused() {
    let (params, mut parts) = setup(3, 2, 4);
    let mut c = Coordinator::new(params).unwrap();
    for (p, _) in parts.iter_mut() {
        c.receive_advertise(p.advertise().unwrap()).unwrap();
    }
    let keys = c.close_advertise().unwrap();
    for (p, _) in parts.iter_mut() {
        c.receive_shares(p.share_keys(&keys).unwrap()).unwrap();
    }
    let inbox = c.close_shares().unwrap();
    let who = parts[0].0.party().clone();
    let mut m = parts[0].0.masked_input(&inbox[&who]).unwrap();
    m.masked[0] ^= 1;
    assert_eq!(
        c.receive_masked(m).unwrap_err().code,
        Code::AggregationProtocol
    );
}

/// The review's attack: n = 3, one party colluding with the coordinator,
/// which tells V "U3 = {V, M}" and W "U3 = {W, M}" to collect both of V's
/// secrets. With the collusion bound declared the threshold is 3: neither
/// split quorum reaches it, and a threshold of 2 is refused outright.
#[test]
fn collusion_bound_defeats_split_survivor_sets() {
    let (mut params, _) = setup(3, 3, 4);
    params.max_colluding = 1;
    params.threshold = 2;
    assert_eq!(
        Coordinator::new(params.clone()).err().unwrap().code,
        Code::AggregationPlan
    );
    params.threshold = 3;
    let mut parts: Vec<Participant> = (0..3)
        .map(|i| {
            Participant::new(
                params.clone(),
                params.parties[i].0.clone(),
                SigningKey::from_bytes(&[i as u8 + 1; 32]),
                vec![i as u64; 4],
                None,
            )
            .unwrap()
        })
        .collect();
    let mut c = Coordinator::new(params.clone()).unwrap();
    for p in parts.iter_mut() {
        c.receive_advertise(p.advertise().unwrap()).unwrap();
    }
    let k = c.close_advertise().unwrap();
    for p in parts.iter_mut() {
        c.receive_shares(p.share_keys(&k).unwrap()).unwrap();
    }
    let inbox = c.close_shares().unwrap();
    for p in parts.iter_mut() {
        let who = p.party().clone();
        c.receive_masked(p.masked_input(&inbox[&who]).unwrap())
            .unwrap();
    }
    let names: Vec<PartyId> = params.parties.iter().map(|(p, _)| p.clone()).collect();
    let split = |a: usize, b: usize| encompute_secagg::protocol::Survivors {
        round_id: params.round_id.clone(),
        survivors: vec![names[a].clone(), names[b].clone()],
    };
    let (v, w, m) = (0, 1, 2);
    assert_eq!(
        parts[v].consistency(&split(v, m)).unwrap_err().code,
        Code::AggregationThreshold
    );
    assert_eq!(
        parts[w].consistency(&split(w, m)).unwrap_err().code,
        Code::AggregationThreshold
    );
}
