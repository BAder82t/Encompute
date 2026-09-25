//! Secure aggregation: exact sums over a sweep of party counts with random
//! dropouts at every stage, and the collusion bound checked exhaustively
//! against the split-quorum attack.

use ed25519_dalek::SigningKey;
use encompute_ir::confidentiality::PartyId;
use encompute_ir::{Code, Result};
use encompute_secagg::protocol::{Coordinator, Participant, ProtocolParams};

use crate::{ensure, rand_u64, CheckResult, Outcome, Scale};

const BITS: u32 = 32;
const LEN: usize = 8;

fn params(n: usize, t: usize, colluding: usize, round: u64) -> ProtocolParams {
    ProtocolParams {
        round_id: format!("{round:064x}"),
        parties: (0..n)
            .map(|i| {
                (
                    PartyId::new(&format!("party-{i:03}")).expect("party id"),
                    identity(i).verifying_key().to_bytes(),
                )
            })
            .collect(),
        threshold: t,
        max_colluding: colluding,
        vector_len: LEN,
        modulus_bits: BITS,
    }
}

fn identity(i: usize) -> SigningKey {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
    SigningKey::from_bytes(&s)
}

/// One round with party `i` silent from stage `drop_at[i]` (0 advertise …
/// 4 unmask). Returns the output and the survivors' true sum.
fn round(p: &ProtocolParams, drop_at: &[Option<u8>]) -> Result<(Vec<u64>, Vec<u64>)> {
    let mut parts: Vec<(Participant, Vec<u64>)> = p
        .parties
        .iter()
        .enumerate()
        .map(|(i, (id, _))| {
            let x: Vec<u64> = (0..LEN).map(|_| rand_u64() % (1 << BITS)).collect();
            Participant::new(p.clone(), id.clone(), identity(i), x.clone(), None).map(|q| (q, x))
        })
        .collect::<Result<_>>()?;
    let mut c = Coordinator::new(p.clone())?;
    let alive = |i: usize, s: u8| drop_at[i].is_none_or(|d| d > s);
    for (i, (q, _)) in parts.iter_mut().enumerate() {
        if alive(i, 0) {
            c.receive_advertise(q.advertise()?)?;
        }
    }
    let keys = c.close_advertise()?;
    for (i, (q, _)) in parts.iter_mut().enumerate() {
        if alive(i, 1) {
            c.receive_shares(q.share_keys(&keys)?)?;
        }
    }
    let inboxes = c.close_shares()?;
    for (i, (q, _)) in parts.iter_mut().enumerate() {
        if alive(i, 2) {
            c.receive_masked(q.masked_input(&inboxes[q.party()])?)?;
        }
    }
    let survivors = c.close_masked()?;
    for (i, (q, _)) in parts.iter_mut().enumerate() {
        if alive(i, 3) {
            c.receive_consistency(q.consistency(&survivors)?)?;
        }
    }
    let req = c.close_consistency()?;
    for (i, (q, _)) in parts.iter_mut().enumerate() {
        if alive(i, 4) {
            c.receive_reveal(q.unmask(&req)?)?;
        }
    }
    let out = c.finalize()?;
    let mut want = vec![0u64; LEN];
    for (q, x) in &parts {
        if out.survivors.contains(q.party()) {
            for (w, v) in want.iter_mut().zip(x) {
                *w = (*w + v) % (1 << BITS);
            }
        }
    }
    Ok((out.sum, want))
}

/// INV-050/051: for every tested party count, the output is exactly the
/// survivors' sum with no dropouts and with random dropouts that leave the
/// threshold; below the threshold the round aborts and releases nothing.
pub fn sum_sweep(scale: Scale) -> CheckResult {
    let ns: Vec<usize> = match scale {
        Scale::Quick => vec![2, 3, 4, 5, 8, 13, 20],
        Scale::Nightly => (2..=100).collect(),
    };
    let mut cases = 0;
    for &n in &ns {
        let t = ProtocolParams::minimum_threshold(n, 0);
        let p = params(n, t, 0, n as u64);
        let (got, want) = round(&p, &vec![None; n]).map_err(|e| format!("n={n}: {e}"))?;
        ensure!(got == want, "n={n}: wrong sum with no dropouts");
        cases += 1;
        // Up to n - t dropouts at random stages: still exact. Dropping
        // before sending masked input (stages 0..=2) removes a party from
        // the sum; a later drop keeps it in.
        let spare = n - t;
        if spare > 0 {
            let mut drop = vec![None; n];
            for _ in 0..spare {
                drop[(rand_u64() as usize) % n] = Some((rand_u64() % 5) as u8);
            }
            let (got, want) = round(&p, &drop).map_err(|e| format!("n={n} {drop:?}: {e}"))?;
            ensure!(got == want, "n={n}: wrong sum with dropouts {drop:?}");
            cases += 1;
        }
        // One more dropout than the threshold allows, at the masked-input
        // stage: the round aborts.
        let mut drop = vec![None; n];
        for d in drop.iter_mut().take(spare + 1) {
            *d = Some(2);
        }
        match round(&p, &drop) {
            Err(e) => ensure!(
                e.code == Code::AggregationThreshold,
                "n={n}: aborted with {:?}",
                e.code
            ),
            Ok(_) => return Err(format!("n={n}: released below the threshold")),
        }
        cases += 1;
    }
    Ok(Outcome::new(cases).note(format!("party counts {:?}", (ns[0], ns[ns.len() - 1]))))
}

/// Can a coordinator colluding with `c` of `n` parties obtain both an
/// honest victim's self-mask shares and its key shares, with threshold `t`?
/// It splits the honest parties into two groups that each sign a different
/// survivor set (victim in one, absent in the other); each group, with the
/// colluders, must reach `t` signatures and `t` shares.
fn split_attack_succeeds(n: usize, c: usize, t: usize) -> bool {
    let honest = n - c;
    (0..=honest).any(|a| {
        let b = honest - a;
        a + c >= t && b + c >= t
    })
}

/// INV-053: every threshold the protocol accepts defeats the split-quorum
/// attack for its declared collusion bound, and the minimum threshold is
/// always accepted (the bound never makes a round impossible when a quorum
/// exists).
pub fn collusion_bound(scale: Scale) -> CheckResult {
    let max_n = scale.pick(64, 255);
    let mut cases = 0;
    for n in 2..=max_n {
        let mut p = params(n, n, 0, 1);
        for c in 0..n {
            p.max_colluding = c;
            for t in 1..=n {
                p.threshold = t;
                let accepted = p.validate().is_ok();
                if accepted {
                    ensure!(
                        !split_attack_succeeds(n, c, t),
                        "n={n} colluding={c}: threshold {t} accepted but the split attack \
                         recovers an honest input"
                    );
                }
                cases += 1;
            }
            let least = ProtocolParams::minimum_threshold(n, c);
            if least <= n {
                p.threshold = least;
                ensure!(
                    p.validate().is_ok(),
                    "n={n} colluding={c}: the minimum threshold {least} is refused"
                );
            }
        }
    }
    Ok(Outcome::new(cases).note(format!(
        "n in 2..={max_n}, every colluding count and threshold"
    )))
}

/// INV-080 (aggregation): no message the coordinator sees contains an
/// honest party's input in the clear.
pub fn coordinator_sees_no_input(scale: Scale) -> CheckResult {
    let reps = scale.pick(5, 50);
    for r in 0..reps {
        let n = 4;
        let p = params(n, 3, 0, 1000 + r as u64);
        // Distinctive canaries: every coordinate of party i is 0xC0FFEE00 + i.
        let canary = |i: usize| 0xC0FF_EE00u64 + i as u64;
        let mut parts: Vec<Participant> = p
            .parties
            .iter()
            .enumerate()
            .map(|(i, (id, _))| {
                Participant::new(
                    p.clone(),
                    id.clone(),
                    identity(i),
                    vec![canary(i); LEN],
                    None,
                )
            })
            .collect::<Result<_>>()
            .map_err(|e| e.to_string())?;
        let mut c = Coordinator::new(p.clone()).map_err(|e| e.to_string())?;
        let mut seen = String::new();
        let log = |s: &mut String, v: serde_json::Value| s.push_str(&v.to_string());
        for q in parts.iter_mut() {
            let a = q.advertise().map_err(|e| e.to_string())?;
            c.receive_advertise(a).map_err(|e| e.to_string())?;
        }
        let keys = c.close_advertise().map_err(|e| e.to_string())?;
        for q in parts.iter_mut() {
            let s = q.share_keys(&keys).map_err(|e| e.to_string())?;
            log(
                &mut seen,
                serde_json::to_value(&s).map_err(|e| e.to_string())?,
            );
            c.receive_shares(s).map_err(|e| e.to_string())?;
        }
        let inboxes = c.close_shares().map_err(|e| e.to_string())?;
        for q in parts.iter_mut() {
            let m = q
                .masked_input(&inboxes[q.party()])
                .map_err(|e| e.to_string())?;
            log(
                &mut seen,
                serde_json::to_value(&m).map_err(|e| e.to_string())?,
            );
            c.receive_masked(m).map_err(|e| e.to_string())?;
        }
        for i in 0..n {
            let k = canary(i);
            for needle in [k.to_string(), format!("{k:x}"), format!("{k:08X}")] {
                ensure!(
                    !seen.contains(&needle),
                    "party {i}'s input {needle} is visible to the coordinator"
                );
            }
        }
    }
    Ok(Outcome::new(reps))
}
