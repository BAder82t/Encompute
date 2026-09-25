//! Secure aggregation, Bonawitz et al., "Practical Secure Aggregation for
//! Privacy-Preserving Machine Learning" (CCS 2017), with the
//! active-adversary additions: signed keys (a PKI of party identities) and
//! the consistency-check round. Nothing here is new cryptography; the
//! choices of primitives are listed in `crypto.rs`.
//!
//! Rounds (U1 ⊇ U2 ⊇ U3 ⊇ U4 ⊇ U5 are the parties still responding):
//!
//! 0. **Advertise keys.** Each party u sends two X25519 public keys, c_u
//!    (share encryption) and s_u (masking), signed with its identity.
//! 1. **Share keys.** u checks every signature, picks a self-mask seed b_u,
//!    Shamir-shares s_u's secret and b_u (threshold t) among U1 (itself
//!    included), and sends each v its shares encrypted under
//!    KDF(DH(c_u, c_v)). It commits to b_u.
//! 2. **Masked input.** u sends
//!    `y_u = x_u + PRG(b_u) + Σ_{v∈U2, v≠u} ±PRG(KDF(DH(s_u, s_v)))  mod 2^m`,
//!    `+` when u sorts after v, `−` before. Pairwise masks cancel between
//!    survivors.
//! 3. **Consistency check.** The coordinator names the survivors U3; each u
//!    checks U3 ⊆ U2, |U3| ≥ t, and signs U3.
//! 4. **Unmask.** u checks ≥ t valid signatures on the same U3, then reveals
//!    its share of s_v's secret for each dropped v ∈ U2\U3, and its share of
//!    b_v for each survivor v ∈ U3, never both for one party.
//!
//! The coordinator reconstructs the dropped parties' mask keys (checked
//! against their advertised keys) and the survivors' self-mask seeds
//! (checked against their commitments), removes every mask, and obtains
//! `Σ_{u∈U3} x_u mod 2^m`, nothing else. Security needs `t ≥ ⌊n/2⌋ + 1`
//! against a malicious coordinator; with `c` colluding parties, `t > (n + c) / 2`.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use encompute_attestation::AttestationRecord;
use encompute_ir::confidentiality::PartyId;
use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;

use crate::crypto::{
    combine, hex, modulus_mask, open, prg, protocol_err, random32, seal, sign, split, tagged,
    unhex, unhex32, verify, DhKey, MASK_KEY, SHARE_KEY,
};

const ADVERTISE: &str = "encompute.secagg.advertise.v1";
const SHARES: &str = "encompute.secagg.shares.v1";
const MASKED: &str = "encompute.secagg.masked.v1";
const CONSISTENCY: &str = "encompute.secagg.consistency.v1";
const REVEAL: &str = "encompute.secagg.reveal.v1";
const B_COMMITMENT: &str = "encompute.secagg.self-mask-commitment.v1";
const CONTRIBUTION: &str = "encompute.secagg.contribution.v1";
const SHARE_AAD: &str = "encompute.secagg.share-ciphertext.v1";

fn binding(m: impl Into<String>) -> Error {
    Error::new(Code::AggregationBinding, m)
}

fn threshold_err(m: impl Into<String>) -> Error {
    Error::new(Code::AggregationThreshold, m)
}

/// Public parameters of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolParams {
    /// Hex round ID: every key derivation and signature binds it.
    pub round_id: String,
    /// Eligible parties and their Ed25519 identity keys, sorted by party
    /// ID. Party `i` has Shamir ID `i + 1`.
    pub parties: Vec<(PartyId, [u8; 32])>,
    /// Shamir threshold, and the fewest parties the protocol continues with.
    pub threshold: usize,
    /// Parties that may collude with the coordinator: privacy needs
    /// `threshold > (parties + max_colluding) / 2`.
    pub max_colluding: usize,
    pub vector_len: usize,
    pub modulus_bits: u32,
}

impl ProtocolParams {
    /// The smallest threshold that keeps inputs private against a malicious
    /// coordinator colluding with `colluding` of `n` parties.
    pub fn minimum_threshold(n: usize, colluding: usize) -> usize {
        (n + colluding) / 2 + 1
    }

    pub fn validate(&self) -> Result<()> {
        let n = self.parties.len();
        let bad = |m: String| Err(Error::new(Code::AggregationPlan, m));
        if !(2..=255).contains(&n) {
            return bad(format!(
                "secure aggregation needs 2 to 255 parties, got {n}"
            ));
        }
        if self.parties.windows(2).any(|w| w[0].0 >= w[1].0) {
            return bad("parties must be distinct and sorted".into());
        }
        let least = Self::minimum_threshold(n, self.max_colluding);
        if self.max_colluding >= n || self.threshold < least || self.threshold > n {
            return bad(format!(
                "threshold {} must be between {least} and {n}: with {} parties colluding with \
                 the coordinator, a smaller threshold lets it recover an honest party's input",
                self.threshold, self.max_colluding
            ));
        }
        if self.vector_len == 0 || !(8..=64).contains(&self.modulus_bits) {
            return bad("empty vector or unsupported modulus".into());
        }
        Ok(())
    }

    fn index(&self, p: &PartyId) -> Option<usize> {
        self.parties.binary_search_by(|(q, _)| q.cmp(p)).ok()
    }

    fn id(&self, p: &PartyId) -> u8 {
        (self.index(p).expect("known party") + 1) as u8
    }

    fn key(&self, p: &PartyId) -> Result<[u8; 32]> {
        self.index(p).map(|i| self.parties[i].1).ok_or_else(|| {
            Error::new(
                Code::AggregationUnauthorized,
                format!(
                    "party {p} is not authorized for aggregation round {}",
                    self.round_id
                ),
            )
        })
    }

    fn check_round(&self, round_id: &str) -> Result<()> {
        if round_id != self.round_id {
            return Err(binding(format!(
                "a message for round {round_id} was sent to round {}",
                self.round_id
            )));
        }
        Ok(())
    }
}

fn body_bytes<T: Serialize>(b: &T) -> Result<Vec<u8>> {
    canonical_json(b)
}

/// A signed protocol message body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed<T> {
    pub body: T,
    pub signature: String,
}

impl<T: Serialize> Signed<T> {
    pub(crate) fn new(key: &SigningKey, domain: &str, body: T) -> Result<Self> {
        let signature = sign(key, domain, &body_bytes(&body)?);
        Ok(Self { body, signature })
    }

    fn check(&self, params: &ProtocolParams, party: &PartyId, domain: &str) -> Result<()> {
        verify(
            &params.key(party)?,
            domain,
            &body_bytes(&self.body)?,
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvertiseBody {
    pub round_id: String,
    pub party: PartyId,
    pub c_pk: String,
    pub s_pk: String,
    /// The attestation record of the workload holding this party's key.
    #[serde(default)]
    pub attestation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advertise {
    pub signed: Signed<AdvertiseBody>,
    #[serde(default)]
    pub attestation: Option<AttestationRecord>,
}

/// Coordinator → everyone: the advertised keys of U1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBroadcast {
    pub round_id: String,
    pub advertised: Vec<Signed<AdvertiseBody>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharesBody {
    pub round_id: String,
    pub party: PartyId,
    /// Commitment to the self-mask seed b_u.
    pub self_mask_commitment: String,
    /// Recipient → encrypted shares.
    pub ciphertexts: BTreeMap<PartyId, String>,
}

/// Coordinator → one party: U2 and the shares addressed to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inbox {
    pub round_id: String,
    pub senders: Vec<PartyId>,
    pub ciphertexts: BTreeMap<PartyId, String>,
}

/// What a party signs for its masked contribution: a commitment to the
/// masked vector (which reveals nothing about its input), small enough to
/// keep in receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionStatement {
    pub round_id: String,
    pub party: PartyId,
    pub vector_len: usize,
    pub commitment: String,
}

/// Round 2's message: the masked vector and the signed statement about it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Masked {
    pub masked: Vec<u64>,
    pub statement: Signed<ContributionStatement>,
}

/// `SHA256("encompute.secagg.contribution.v1", round, party, values)`.
pub fn contribution_commitment(round_id: &str, party: &PartyId, masked: &[u64]) -> String {
    let bytes: Vec<u8> = masked.iter().flat_map(|v| v.to_le_bytes()).collect();
    hex(&tagged(
        CONTRIBUTION,
        &[round_id.as_bytes(), party.as_str().as_bytes(), &bytes],
    ))
}

/// Coordinator → everyone: the survivors U3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Survivors {
    pub round_id: String,
    pub survivors: Vec<PartyId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyBody {
    pub round_id: String,
    pub party: PartyId,
    pub survivors: Vec<PartyId>,
}

/// Coordinator → everyone: U3 and U4's signatures on it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnmaskRequest {
    pub round_id: String,
    pub survivors: Vec<PartyId>,
    pub signatures: Vec<Signed<ConsistencyBody>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevealBody {
    pub round_id: String,
    pub party: PartyId,
    /// Shares of dropped parties' mask keys.
    pub key_shares: BTreeMap<PartyId, String>,
    /// Shares of survivors' self-mask seeds.
    pub self_mask_shares: BTreeMap<PartyId, String>,
}

fn b_commitment(round_id: &str, b: &[u8]) -> String {
    hex(&tagged(B_COMMITMENT, &[round_id.as_bytes(), b]))
}

fn share_aad(round_id: &str, from: &PartyId, to: &PartyId) -> Vec<u8> {
    tagged(
        SHARE_AAD,
        &[
            round_id.as_bytes(),
            from.as_str().as_bytes(),
            to.as_str().as_bytes(),
        ],
    )
    .to_vec()
}

fn sorted_set(v: &[PartyId], what: &str) -> Result<BTreeSet<PartyId>> {
    let s: BTreeSet<PartyId> = v.iter().cloned().collect();
    if s.len() != v.len() {
        return Err(protocol_err(format!("{what} lists a party twice")));
    }
    Ok(s)
}

/// Add `sign * PRG(seed)` into `acc` mod 2^bits.
fn add_mask(acc: &mut [u64], seed: &[u8; 32], negate: bool, bits: u32) {
    let mask = modulus_mask(bits);
    let stream = prg(seed, acc.len(), bits);
    for (a, p) in acc.iter_mut().zip(stream) {
        *a = if negate {
            a.wrapping_sub(p)
        } else {
            a.wrapping_add(p)
        } & mask;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    Advertise,
    ShareKeys,
    MaskedInput,
    Consistency,
    Unmask,
    Done,
}

/// A held pair of shares of one party's secrets: (mask key, self-mask seed).
type HeldShares = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// One party's side. Its input never leaves it unmasked.
pub struct Participant {
    params: ProtocolParams,
    party: PartyId,
    identity: SigningKey,
    input: Vec<u64>,
    c: DhKey,
    s: DhKey,
    b: Zeroizing<[u8; 32]>,
    attestation: Option<AttestationRecord>,
    stage: Stage,
    /// U1's advertised keys.
    keys: BTreeMap<PartyId, ([u8; 32], [u8; 32])>,
    /// Shares received (and my own): party → (s-key share, b share).
    shares: BTreeMap<PartyId, HeldShares>,
    u2: BTreeSet<PartyId>,
    u3: Option<Vec<PartyId>>,
}

impl std::fmt::Debug for Participant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Participant({}, {:?})", self.party, self.stage)
    }
}

impl Participant {
    /// `input`: the encoded contribution, each value below 2^modulus_bits.
    pub fn new(
        params: ProtocolParams,
        party: PartyId,
        identity: SigningKey,
        input: Vec<u64>,
        attestation: Option<AttestationRecord>,
    ) -> Result<Self> {
        params.validate()?;
        if params.key(&party)? != identity.verifying_key().to_bytes() {
            return Err(Error::new(
                Code::AggregationUnauthorized,
                format!("this identity key is not party {party}'s key for the round"),
            ));
        }
        if input.len() != params.vector_len {
            return Err(binding(format!(
                "contribution has {} values; the round expects {}",
                input.len(),
                params.vector_len
            )));
        }
        if input.iter().any(|&v| v > modulus_mask(params.modulus_bits)) {
            return Err(binding("contribution values exceed the round's modulus"));
        }
        Ok(Self {
            params,
            party,
            identity,
            input,
            c: DhKey::generate()?,
            s: DhKey::generate()?,
            b: Zeroizing::new(random32()?),
            attestation,
            stage: Stage::Advertise,
            keys: BTreeMap::new(),
            shares: BTreeMap::new(),
            u2: BTreeSet::new(),
            u3: None,
        })
    }

    pub fn party(&self) -> &PartyId {
        &self.party
    }

    fn advance(&mut self, from: Stage, to: Stage) -> Result<()> {
        if self.stage != from {
            return Err(protocol_err(format!(
                "out of order: {:?} requested while at {:?}",
                to, self.stage
            )));
        }
        self.stage = to;
        Ok(())
    }

    /// Round 0.
    pub fn advertise(&mut self) -> Result<Advertise> {
        self.advance(Stage::Advertise, Stage::ShareKeys)?;
        let attestation_id = self.attestation.as_ref().map(|r| r.id()).transpose()?;
        Ok(Advertise {
            signed: Signed::new(
                &self.identity,
                ADVERTISE,
                AdvertiseBody {
                    round_id: self.params.round_id.clone(),
                    party: self.party.clone(),
                    c_pk: hex(&self.c.public()),
                    s_pk: hex(&self.s.public()),
                    attestation_id,
                },
            )?,
            attestation: self.attestation.clone(),
        })
    }

    /// Round 1.
    pub fn share_keys(&mut self, keys: &KeysBroadcast) -> Result<Signed<SharesBody>> {
        self.advance(Stage::ShareKeys, Stage::MaskedInput)?;
        let p = &self.params;
        p.check_round(&keys.round_id)?;
        let mut seen_keys = BTreeSet::new();
        for a in &keys.advertised {
            let b = &a.body;
            p.check_round(&b.round_id)?;
            a.check(p, &b.party, ADVERTISE)?;
            let (c, s) = (unhex32(&b.c_pk, "key")?, unhex32(&b.s_pk, "key")?);
            if !seen_keys.insert(c) || !seen_keys.insert(s) {
                return Err(protocol_err("two advertised keys are equal"));
            }
            if self.keys.insert(b.party.clone(), (c, s)).is_some() {
                return Err(protocol_err(format!("party {} advertised twice", b.party)));
            }
        }
        if self.keys.get(&self.party) != Some(&(self.c.public(), self.s.public())) {
            return Err(protocol_err("my advertised keys are missing or altered"));
        }
        if self.keys.len() < p.threshold {
            return Err(threshold_err(format!(
                "only {} parties advertised keys; the round needs {}",
                self.keys.len(),
                p.threshold
            )));
        }
        let members: Vec<PartyId> = self.keys.keys().cloned().collect();
        let ids: Vec<u8> = members.iter().map(|m| p.id(m)).collect();
        let s_shares = split(self.s.secret_bytes().as_ref(), p.threshold, &ids)?;
        let b_shares = split(self.b.as_ref(), p.threshold, &ids)?;
        let mut ciphertexts = BTreeMap::new();
        for (i, v) in members.iter().enumerate() {
            if v == &self.party {
                self.shares
                    .insert(v.clone(), (s_shares[i].clone(), b_shares[i].clone()));
                continue;
            }
            let k = self.c.agree(&self.keys[v].0, SHARE_KEY, &p.round_id)?;
            let mut msg = Zeroizing::new(Vec::with_capacity(68));
            msg.extend_from_slice(&s_shares[i]);
            msg.extend_from_slice(&b_shares[i]);
            let ct = seal(
                &k,
                p.id(&self.party),
                p.id(v),
                &share_aad(&p.round_id, &self.party, v),
                &msg,
            )?;
            ciphertexts.insert(v.clone(), hex(&ct));
        }
        Signed::new(
            &self.identity,
            SHARES,
            SharesBody {
                round_id: p.round_id.clone(),
                party: self.party.clone(),
                self_mask_commitment: b_commitment(&p.round_id, self.b.as_ref()),
                ciphertexts,
            },
        )
    }

    /// Round 2.
    pub fn masked_input(&mut self, inbox: &Inbox) -> Result<Masked> {
        self.advance(Stage::MaskedInput, Stage::Consistency)?;
        let p = self.params.clone();
        p.check_round(&inbox.round_id)?;
        let u2 = sorted_set(&inbox.senders, "U2")?;
        if !u2.iter().all(|v| self.keys.contains_key(v)) || !u2.contains(&self.party) {
            return Err(protocol_err("U2 is not a subset of U1 containing me"));
        }
        if u2.len() < p.threshold {
            return Err(threshold_err(format!(
                "only {} parties shared keys; the round needs {}",
                u2.len(),
                p.threshold
            )));
        }
        for v in u2.iter().filter(|v| **v != self.party) {
            let ct = inbox
                .ciphertexts
                .get(v)
                .and_then(|c| unhex(c))
                .ok_or_else(|| protocol_err(format!("no shares from {v}")))?;
            let k = self.c.agree(&self.keys[v].0, SHARE_KEY, &p.round_id)?;
            let pt = open(
                &k,
                p.id(v),
                p.id(&self.party),
                &share_aad(&p.round_id, v, &self.party),
                &ct,
            )?;
            let me = p.id(&self.party);
            if pt.len() != 66 || pt[0] != me || pt[33] != me {
                return Err(protocol_err(format!("shares from {v} are malformed")));
            }
            self.shares.insert(
                v.clone(),
                (
                    Zeroizing::new(pt[..33].to_vec()),
                    Zeroizing::new(pt[33..].to_vec()),
                ),
            );
        }
        let mut y = self.input.clone();
        add_mask(&mut y, &self.b, false, p.modulus_bits);
        let (me, _) = (p.index(&self.party).expect("known"), ());
        for v in u2.iter().filter(|v| **v != self.party) {
            let seed = self.s.agree(&self.keys[v].1, MASK_KEY, &p.round_id)?;
            // + when I sort after v, − before: the pair cancels.
            add_mask(
                &mut y,
                &seed,
                me < p.index(v).expect("known"),
                p.modulus_bits,
            );
        }
        self.u2 = u2;
        let statement = Signed::new(
            &self.identity,
            MASKED,
            ContributionStatement {
                round_id: p.round_id.clone(),
                party: self.party.clone(),
                vector_len: y.len(),
                commitment: contribution_commitment(&p.round_id, &self.party, &y),
            },
        )?;
        Ok(Masked {
            masked: y,
            statement,
        })
    }

    /// Round 3.
    pub fn consistency(&mut self, s: &Survivors) -> Result<Signed<ConsistencyBody>> {
        self.advance(Stage::Consistency, Stage::Unmask)?;
        let p = &self.params;
        p.check_round(&s.round_id)?;
        let u3 = sorted_set(&s.survivors, "U3")?;
        if !u3.is_subset(&self.u2) || !u3.contains(&self.party) {
            return Err(protocol_err("U3 is not a subset of U2 containing me"));
        }
        if u3.len() < p.threshold {
            return Err(threshold_err(format!(
                "only {} parties sent masked input; the round needs {}",
                u3.len(),
                p.threshold
            )));
        }
        let survivors: Vec<PartyId> = u3.into_iter().collect();
        self.u3 = Some(survivors.clone());
        Signed::new(
            &self.identity,
            CONSISTENCY,
            ConsistencyBody {
                round_id: p.round_id.clone(),
                party: self.party.clone(),
                survivors,
            },
        )
    }

    /// Round 4: the only round that reveals shares, and never both kinds
    /// for one party.
    pub fn unmask(&mut self, req: &UnmaskRequest) -> Result<Signed<RevealBody>> {
        self.advance(Stage::Unmask, Stage::Done)?;
        let p = &self.params;
        p.check_round(&req.round_id)?;
        let signed_u3 = self.u3.as_ref().expect("stage order");
        if &req.survivors != signed_u3 {
            return Err(protocol_err(
                "the coordinator changed the survivor set after it was signed",
            ));
        }
        let mut signers = BTreeSet::new();
        for s in &req.signatures {
            p.check_round(&s.body.round_id)?;
            s.check(p, &s.body.party, CONSISTENCY)?;
            if &s.body.survivors != signed_u3 || !signed_u3.contains(&s.body.party) {
                return Err(protocol_err(format!(
                    "{} signed a different survivor set: the coordinator is equivocating",
                    s.body.party
                )));
            }
            signers.insert(s.body.party.clone());
        }
        if signers.len() < p.threshold {
            return Err(threshold_err(format!(
                "only {} parties confirmed the survivors; the round needs {}",
                signers.len(),
                p.threshold
            )));
        }
        let u3: BTreeSet<&PartyId> = signed_u3.iter().collect();
        let mut key_shares = BTreeMap::new();
        let mut self_mask_shares = BTreeMap::new();
        for v in &self.u2 {
            let (s_share, b_share) = self
                .shares
                .get(v)
                .ok_or_else(|| protocol_err(format!("no shares held for {v}")))?;
            if u3.contains(v) {
                self_mask_shares.insert(v.clone(), hex(b_share));
            } else {
                key_shares.insert(v.clone(), hex(s_share));
            }
        }
        Signed::new(
            &self.identity,
            REVEAL,
            RevealBody {
                round_id: p.round_id.clone(),
                party: self.party.clone(),
                key_shares,
                self_mask_shares,
            },
        )
    }
}

/// The result of a run: the sum over U3, and who was in each set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aggregated {
    pub sum: Vec<u64>,
    pub advertised: Vec<PartyId>,
    pub survivors: Vec<PartyId>,
    /// Masked-contribution commitments of U3, signed by each party.
    pub contributions: Vec<Signed<ContributionStatement>>,
    /// U3 as confirmed (signed) by U4.
    pub confirmations: Vec<Signed<ConsistencyBody>>,
    pub attestations: BTreeMap<PartyId, AttestationRecord>,
}

/// The coordinator's side. It sees masked vectors only, and reconstructs
/// only what unmasking the survivors' sum needs.
pub struct Coordinator {
    params: ProtocolParams,
    stage: Stage,
    advertised: BTreeMap<PartyId, Advertise>,
    shares: BTreeMap<PartyId, Signed<SharesBody>>,
    masked: BTreeMap<PartyId, Masked>,
    consistency: BTreeMap<PartyId, Signed<ConsistencyBody>>,
    reveals: BTreeMap<PartyId, Signed<RevealBody>>,
    survivors: Vec<PartyId>,
}

impl Coordinator {
    pub fn new(params: ProtocolParams) -> Result<Self> {
        params.validate()?;
        Ok(Self {
            params,
            stage: Stage::Advertise,
            advertised: BTreeMap::new(),
            shares: BTreeMap::new(),
            masked: BTreeMap::new(),
            consistency: BTreeMap::new(),
            reveals: BTreeMap::new(),
            survivors: vec![],
        })
    }

    pub fn params(&self) -> &ProtocolParams {
        &self.params
    }

    fn expect(&self, stage: Stage) -> Result<()> {
        if self.stage != stage {
            return Err(protocol_err(format!(
                "a {stage:?} message arrived during {:?}",
                self.stage
            )));
        }
        Ok(())
    }

    /// Checks the sender and round of a message and refuses duplicates.
    fn admit<T>(
        &self,
        party: &PartyId,
        round_id: &str,
        from: Option<&BTreeMap<PartyId, T>>,
        into: &BTreeMap<PartyId, impl Sized>,
    ) -> Result<()> {
        self.params.key(party)?;
        self.params.check_round(round_id)?;
        if let Some(prev) = from {
            if !prev.contains_key(party) {
                return Err(protocol_err(format!(
                    "{party} did not take part in the previous round"
                )));
            }
        }
        if into.contains_key(party) {
            return Err(binding(format!(
                "{party} already submitted this round's message"
            )));
        }
        Ok(())
    }

    /// The parties expected to answer the current stage.
    pub fn awaiting(&self) -> BTreeSet<PartyId> {
        let all: BTreeSet<PartyId> = self.params.parties.iter().map(|(p, _)| p.clone()).collect();
        let (from, got): (BTreeSet<PartyId>, BTreeSet<PartyId>) = match self.stage {
            Stage::Advertise => (all, self.advertised.keys().cloned().collect()),
            Stage::ShareKeys => (
                self.advertised.keys().cloned().collect(),
                self.shares.keys().cloned().collect(),
            ),
            Stage::MaskedInput => (
                self.shares.keys().cloned().collect(),
                self.masked.keys().cloned().collect(),
            ),
            Stage::Consistency => (
                self.masked.keys().cloned().collect(),
                self.consistency.keys().cloned().collect(),
            ),
            Stage::Unmask => (
                self.consistency.keys().cloned().collect(),
                self.reveals.keys().cloned().collect(),
            ),
            Stage::Done => (BTreeSet::new(), BTreeSet::new()),
        };
        from.difference(&got).cloned().collect()
    }

    fn need(&self, n: usize, what: &str) -> Result<()> {
        if n < self.params.threshold {
            return Err(threshold_err(format!(
                "only {n} parties {what}; the round needs {} (aborted: no aggregate is released)",
                self.params.threshold
            )));
        }
        Ok(())
    }

    pub fn receive_advertise(&mut self, a: Advertise) -> Result<()> {
        self.expect(Stage::Advertise)?;
        let b = &a.signed.body;
        self.admit::<()>(&b.party, &b.round_id, None, &self.advertised)?;
        a.signed.check(&self.params, &b.party, ADVERTISE)?;
        unhex32(&b.c_pk, "key")?;
        unhex32(&b.s_pk, "key")?;
        let rid = a.attestation.as_ref().map(|r| r.id()).transpose()?;
        if rid != b.attestation_id {
            return Err(binding(
                "the attestation record does not match the signed advertisement",
            ));
        }
        self.advertised.insert(b.party.clone(), a);
        Ok(())
    }

    /// Ends round 0.
    pub fn close_advertise(&mut self) -> Result<KeysBroadcast> {
        self.expect(Stage::Advertise)?;
        self.need(self.advertised.len(), "advertised keys")?;
        self.stage = Stage::ShareKeys;
        Ok(KeysBroadcast {
            round_id: self.params.round_id.clone(),
            advertised: self.advertised.values().map(|a| a.signed.clone()).collect(),
        })
    }

    pub fn advertisements(&self) -> impl Iterator<Item = &Advertise> {
        self.advertised.values()
    }

    pub fn receive_shares(&mut self, s: Signed<SharesBody>) -> Result<()> {
        self.expect(Stage::ShareKeys)?;
        let b = &s.body;
        self.admit(&b.party, &b.round_id, Some(&self.advertised), &self.shares)?;
        s.check(&self.params, &b.party, SHARES)?;
        let expected: BTreeSet<&PartyId> =
            self.advertised.keys().filter(|p| **p != b.party).collect();
        if b.ciphertexts.keys().collect::<BTreeSet<_>>() != expected {
            return Err(protocol_err(format!(
                "{} did not share with exactly U1",
                b.party
            )));
        }
        unhex32(&b.self_mask_commitment, "commitment")?;
        self.shares.insert(b.party.clone(), s);
        Ok(())
    }

    /// Ends round 1: each member of U2 gets U2 and its shares.
    pub fn close_shares(&mut self) -> Result<BTreeMap<PartyId, Inbox>> {
        self.expect(Stage::ShareKeys)?;
        self.need(self.shares.len(), "shared keys")?;
        self.stage = Stage::MaskedInput;
        let senders: Vec<PartyId> = self.shares.keys().cloned().collect();
        Ok(senders
            .iter()
            .map(|to| {
                let ciphertexts = self
                    .shares
                    .iter()
                    .filter(|(from, _)| *from != to)
                    .map(|(from, s)| (from.clone(), s.body.ciphertexts[to].clone()))
                    .collect();
                (
                    to.clone(),
                    Inbox {
                        round_id: self.params.round_id.clone(),
                        senders: senders.clone(),
                        ciphertexts,
                    },
                )
            })
            .collect())
    }

    pub fn receive_masked(&mut self, m: Masked) -> Result<()> {
        self.expect(Stage::MaskedInput)?;
        let b = &m.statement.body;
        self.admit(&b.party, &b.round_id, Some(&self.shares), &self.masked)?;
        m.statement.check(&self.params, &b.party, MASKED)?;
        if m.masked.len() != self.params.vector_len || b.vector_len != self.params.vector_len {
            return Err(binding(format!(
                "{} sent {} values; the round expects {}",
                b.party,
                m.masked.len(),
                self.params.vector_len
            )));
        }
        if contribution_commitment(&b.round_id, &b.party, &m.masked) != b.commitment {
            return Err(protocol_err(format!(
                "{}'s masked contribution does not match its signed commitment (tampered)",
                b.party
            )));
        }
        if m.masked
            .iter()
            .any(|&v| v > modulus_mask(self.params.modulus_bits))
        {
            return Err(binding(format!(
                "{} sent values outside the modulus",
                b.party
            )));
        }
        self.masked.insert(b.party.clone(), m);
        Ok(())
    }

    /// Ends round 2.
    pub fn close_masked(&mut self) -> Result<Survivors> {
        self.expect(Stage::MaskedInput)?;
        self.need(self.masked.len(), "sent masked input")?;
        self.stage = Stage::Consistency;
        self.survivors = self.masked.keys().cloned().collect();
        Ok(Survivors {
            round_id: self.params.round_id.clone(),
            survivors: self.survivors.clone(),
        })
    }

    pub fn receive_consistency(&mut self, c: Signed<ConsistencyBody>) -> Result<()> {
        self.expect(Stage::Consistency)?;
        let b = &c.body;
        self.admit(&b.party, &b.round_id, Some(&self.masked), &self.consistency)?;
        c.check(&self.params, &b.party, CONSISTENCY)?;
        if b.survivors != self.survivors {
            return Err(protocol_err(format!(
                "{} confirmed another survivor set",
                b.party
            )));
        }
        self.consistency.insert(b.party.clone(), c);
        Ok(())
    }

    /// Ends round 3.
    pub fn close_consistency(&mut self) -> Result<UnmaskRequest> {
        self.expect(Stage::Consistency)?;
        self.need(self.consistency.len(), "confirmed the survivors")?;
        self.stage = Stage::Unmask;
        Ok(UnmaskRequest {
            round_id: self.params.round_id.clone(),
            survivors: self.survivors.clone(),
            signatures: self.consistency.values().cloned().collect(),
        })
    }

    pub fn receive_reveal(&mut self, r: Signed<RevealBody>) -> Result<()> {
        self.expect(Stage::Unmask)?;
        let b = &r.body;
        self.admit(
            &b.party,
            &b.round_id,
            Some(&self.consistency),
            &self.reveals,
        )?;
        r.check(&self.params, &b.party, REVEAL)?;
        let u2: BTreeSet<&PartyId> = self.shares.keys().collect();
        let u3: BTreeSet<&PartyId> = self.survivors.iter().collect();
        let dropped: BTreeSet<&PartyId> = u2.difference(&u3).copied().collect();
        if b.key_shares.keys().collect::<BTreeSet<_>>() != dropped
            || b.self_mask_shares.keys().collect::<BTreeSet<_>>() != u3
        {
            return Err(protocol_err(format!(
                "{} revealed shares for the wrong parties",
                b.party
            )));
        }
        let id = self.params.id(&b.party);
        for s in b.key_shares.values().chain(b.self_mask_shares.values()) {
            match unhex(s) {
                Some(v) if v.len() == 33 && v[0] == id => {}
                _ => {
                    return Err(protocol_err(format!(
                        "{} revealed a malformed share",
                        b.party
                    )))
                }
            }
        }
        self.reveals.insert(b.party.clone(), r);
        Ok(())
    }

    /// Ends round 4: removes every mask and returns the survivors' sum.
    pub fn finalize(&mut self) -> Result<Aggregated> {
        self.expect(Stage::Unmask)?;
        self.need(self.reveals.len(), "revealed shares")?;
        let p = self.params.clone();
        let collect = |v: &PartyId, key: bool| -> Vec<Vec<u8>> {
            self.reveals
                .values()
                .map(|r| {
                    let m = if key {
                        &r.body.key_shares
                    } else {
                        &r.body.self_mask_shares
                    };
                    unhex(&m[v]).expect("checked on receipt")
                })
                .collect()
        };
        let mut sum = vec![0u64; p.vector_len];
        let mask = modulus_mask(p.modulus_bits);
        for m in self.masked.values() {
            for (a, y) in sum.iter_mut().zip(&m.masked) {
                *a = a.wrapping_add(*y) & mask;
            }
        }
        // Survivors' self masks.
        for u in &self.survivors {
            let b = combine(&collect(u, false))?;
            if b_commitment(&p.round_id, &b) != self.shares[u].body.self_mask_commitment {
                return Err(protocol_err(format!(
                    "{u}'s self-mask seed did not reconstruct (a party revealed a bad share); \
                     aborted"
                )));
            }
            let seed: [u8; 32] = b
                .as_slice()
                .try_into()
                .map_err(|_| protocol_err("seed size"))?;
            add_mask(&mut sum, &seed, true, p.modulus_bits);
        }
        // Dropped parties' pairwise masks with the survivors.
        for v in self.shares.keys() {
            if self.survivors.contains(v) {
                continue;
            }
            let sk = combine(&collect(v, true))?;
            let sk: [u8; 32] = sk
                .as_slice()
                .try_into()
                .map_err(|_| protocol_err("key size"))?;
            let key = DhKey::from_bytes(sk);
            let adv = &self.advertised[v].signed.body;
            if hex(&key.public()) != adv.s_pk {
                return Err(protocol_err(format!(
                    "{v}'s mask key did not reconstruct (a party revealed a bad share); aborted"
                )));
            }
            let vi = p.index(v).expect("known");
            for u in &self.survivors {
                let s_u = unhex32(&self.advertised[u].signed.body.s_pk, "key")?;
                let seed = key.agree(&s_u, MASK_KEY, &p.round_id)?;
                // u added +PRG when u sorts after v: subtract what it added.
                let u_added_plus = p.index(u).expect("known") > vi;
                add_mask(&mut sum, &seed, u_added_plus, p.modulus_bits);
            }
        }
        self.stage = Stage::Done;
        Ok(Aggregated {
            sum,
            advertised: self.advertised.keys().cloned().collect(),
            survivors: self.survivors.clone(),
            contributions: self.masked.values().map(|m| m.statement.clone()).collect(),
            confirmations: self.consistency.values().cloned().collect(),
            attestations: self
                .advertised
                .iter()
                .filter_map(|(p, a)| a.attestation.clone().map(|r| (p.clone(), r)))
                .collect(),
        })
    }
}

/// Verifies a contribution statement's signature (receipt verification).
pub fn verify_contribution(
    params: &ProtocolParams,
    m: &Signed<ContributionStatement>,
) -> Result<()> {
    params.check_round(&m.body.round_id)?;
    m.check(params, &m.body.party, MASKED)
}

/// Verifies a survivor confirmation's signature (receipt verification).
pub fn verify_confirmation(params: &ProtocolParams, c: &Signed<ConsistencyBody>) -> Result<()> {
    params.check_round(&c.body.round_id)?;
    c.check(params, &c.body.party, CONSISTENCY)
}
