//! A differentially private release, as one transaction per budgeted
//! asset: check and reserve the cost in every charged ledger (all locked,
//! in a fixed order), then draw the noise, then commit the output's
//! commitment and issue signed receipts. If any budget would be exceeded,
//! nothing is reserved and no noisy output is ever produced.
//!
//! Noise is added by whoever runs the release (the aggregation
//! coordinator), which sees the aggregate before noise: this is central DP,
//! trusted as far as the coordinator's attested workload is (ADR-013).

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use encompute_ir::confidentiality::{DpMechanism, FixedPointCodec, PrivacyBudget, PrivacyUnit};
use encompute_ir::{Code, Error, Result};
use encompute_verification::canonical::canonical_json;
use encompute_verification::{hex, unhex};

use crate::accountant::gaussian_rho;
use crate::ledger::{Genesis, Ledger, LedgerView, PrivacyEvent, ScopeRef, LEDGER_VERSION};
use crate::sampler::{discrete_gaussian, Csprng, CSPRNG};
use crate::scoped::LINKAGE_NONE;
use crate::tagged;

pub const RECEIPT_VERSION: u32 = 1;
const EVENT: &str = "encompute.privacy-event.v1";
const OUTPUT: &str = "encompute.privacy-output.v1";
const RECEIPT: &str = "encompute.privacy-receipt.v1";
/// Largest noise variance (code units squared) accepted.
const MAX_SIGMA2: u64 = 1 << 60;

fn mech_err(m: impl Into<String>) -> Error {
    Error::new(Code::PrivacyMechanism, m)
}

/// A ledger a release is charged to: a budgeted source asset (version 1
/// ledger), or one of the two ledgers a scoped release is charged to, its
/// scope and its population (`scoped`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Charged {
    /// The ledger's subject: the asset, or the scope's or population's ID.
    pub asset_id: String,
    pub budget: PrivacyBudget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoped: Option<ChargedScope>,
}

impl Charged {
    /// A budgeted source asset's own ledger.
    pub fn asset(asset_id: impl Into<String>, budget: PrivacyBudget) -> Self {
        Self {
            asset_id: asset_id.into(),
            budget,
            scoped: None,
        }
    }
}

/// The ledger a scoped release is charged to is a scope's or a
/// population's: its full genesis (fixed by the owners and bound into the
/// plan the parties approved), and the scope the release is under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChargedScope {
    pub genesis: Genesis,
    pub scope_id: String,
    pub population_id: String,
}

/// Everything that identifies one release.
#[derive(Clone, Debug)]
pub struct ReleaseSpec {
    pub round_id: String,
    pub output: String,
    pub policy_id: Option<String>,
    pub privacy_policy_id: String,
    pub execution_spec_id: Option<String>,
    pub mechanism: DpMechanism,
    pub codec: FixedPointCodec,
    pub vector_len: usize,
    pub charged: Vec<Charged>,
    /// How many sources one privacy unit may appear in: the sensitivity is
    /// this many times one source's. 1 outside scopes unless declared.
    pub sources_per_unit: u32,
    /// The digest of the aggregate's stratum labels, if declared.
    pub layout_id: Option<String>,
    /// The governed job this release is for, if any: scoped reservations
    /// name it, and (as the plan's release ID, in place of the round's)
    /// it makes the reservation's identity the job's, so the control
    /// plane's and the coordinator's reservations are the same entry.
    pub job_id: Option<String>,
}

/// Noise variance in code units: `ceil((noise_multiplier * clip_norm *
/// scale)^2)`.
pub fn sigma2(m: &DpMechanism, codec: &FixedPointCodec) -> Result<u64> {
    m.validate()?;
    let sigma = m.noise_multiplier * m.clip_norm * codec.scale as f64;
    let s2 = (sigma * sigma).ceil();
    if !(s2 >= 1.0 && s2 <= MAX_SIGMA2 as f64) {
        return Err(mech_err(format!(
            "noise variance {s2:e} (code units) is outside [1, 2^60]: adjust scale or noise"
        )));
    }
    Ok(s2 as u64)
}

/// The L2 sensitivity of the encoded sum to one privacy unit, in code units.
///
/// Neighbouring datasets never change *which* parties contribute (the
/// contributor list is public and decided by the protocol, not by any one
/// unit's data):
/// - with Poisson sampling (DP-SGD), each sampled record, user, patient or
///   device's gradient is clipped to `clip_norm` by the attested workload
///   before summation, so one unit moves the sum by at most `clip_norm`;
/// - otherwise only each party's whole contribution is clipped (to
///   `clip_norm`). Nothing bounds one unit's influence inside it: one
///   organization, but also one patient, may move it anywhere in the
///   clipping ball, by at most `2 * clip_norm`. So every unit is charged
///   that (review finding DP-4; before, a patient-level budget without
///   sampling was charged half the true sensitivity).
///
/// Either way the encoding offset `-clip_min * scale` is present in both
/// sums and cancels, and rounding each coordinate to a code moves each by at
/// most 1: sensitivity `ceil(k * clip_norm * scale) + ceil(sqrt(d))`.
/// (Adding or removing a whole party is not a neighbouring dataset here: it
/// is visible in the public contributor list.)
pub fn sensitivity(unit: &PrivacyUnit, m: &DpMechanism, codec: &FixedPointCodec, d: usize) -> u64 {
    sensitivity_scaled(unit, m, codec, d, 1)
}

/// [`sensitivity`] for a privacy unit that may appear in up to
/// `sources_per_unit` of the aggregation's sources (one person registered
/// with two agencies, say). Each source's contribution moves by at most
/// the single-source sensitivity, and the unit can move all of them at
/// once, so the L2 sensitivity of the sum is that many times larger (the
/// triangle inequality, tight when the moves align), and the cost in rho
/// the square of it. A count of 0 is treated as 1, never as "free".
pub fn sensitivity_scaled(
    unit: &PrivacyUnit,
    m: &DpMechanism,
    codec: &FixedPointCodec,
    d: usize,
    sources_per_unit: u32,
) -> u64 {
    let k = encompute_ir::confidentiality::sensitivity_factor(unit, m.sampling_rate);
    let clip = (k * m.clip_norm * codec.scale as f64).ceil() as u64;
    let mut r = (d as f64).sqrt().floor() as u64;
    while r * r < d as u64 {
        r += 1;
    }
    clip.checked_add(r)
        .and_then(|b| b.checked_mul(u64::from(sources_per_unit.max(1))))
        .unwrap_or(u64::MAX)
}

impl ReleaseSpec {
    /// The ID of the reservation of this release in `asset`'s ledger (an
    /// asset, scope or population): a function of the release and the
    /// ledger, so a replayed or duplicated delivery is the same entry.
    pub fn event_id(&self, asset: &str) -> String {
        hex(&tagged(
            EVENT,
            &[
                self.round_id.as_bytes(),
                self.output.as_bytes(),
                asset.as_bytes(),
            ],
        ))
    }

    pub fn genesis(&self, c: &Charged) -> Genesis {
        match &c.scoped {
            Some(s) => s.genesis.clone(),
            None => Genesis {
                version: LEDGER_VERSION,
                asset_id: c.asset_id.clone(),
                budget: c.budget.clone(),
                privacy_policy_id: self.privacy_policy_id.clone(),
                scoping: None,
            },
        }
    }

    /// The L2 sensitivity this release charges `c`, in code units.
    pub fn sensitivity(&self, c: &Charged) -> u64 {
        sensitivity_scaled(
            &c.budget.unit,
            &self.mechanism,
            &self.codec,
            self.vector_len,
            self.sources_per_unit,
        )
    }

    /// The scope reference the reservation in `c`'s ledger carries.
    fn scope_ref(&self, c: &Charged) -> Option<Box<ScopeRef>> {
        c.scoped.as_ref().map(|s| {
            Box::new(ScopeRef {
                scope_id: s.scope_id.clone(),
                population_id: s.population_id.clone(),
                job_id: self.job_id.clone(),
                max_sources_per_unit: self.sources_per_unit.max(1),
                layout_id: self.layout_id.clone(),
                linkage: LINKAGE_NONE.to_owned(),
            })
        })
    }

    /// The reservation of this release in `c`'s ledger, as it is written
    /// before any noisy output exists; `rng` labels the randomness the
    /// noise will be drawn with.
    pub fn reserve_event(&self, c: &Charged, rng: &str) -> Result<PrivacyEvent> {
        Ok(PrivacyEvent::Reserve {
            event_id: self.event_id(&c.asset_id),
            policy_id: self.policy_id.clone(),
            execution_spec_id: self.execution_spec_id.clone(),
            round_id: Some(self.round_id.clone()),
            output: self.output.clone(),
            mechanism: self.mechanism.clone(),
            sensitivity: self.sensitivity(c),
            sigma2: sigma2(&self.mechanism, &self.codec)?,
            vector_len: self.vector_len,
            rng: rng.to_owned(),
            scope: self.scope_ref(c),
        })
    }

    /// The zCDP cost this release charges `c`.
    pub fn rho(&self, c: &Charged) -> Result<f64> {
        gaussian_rho(self.sensitivity(c), sigma2(&self.mechanism, &self.codec)?)
    }

    /// Checks that `r` is this release's receipt for one of its charged
    /// assets: signed by `signer` with production randomness, for this
    /// round, output, policies, execution, mechanism and budget, naming this
    /// release's ledger event, and (given the released values) committing
    /// exactly `noisy`.
    pub fn check_receipt(
        &self,
        r: &PrivacyReceipt,
        signer: &str,
        noisy: Option<&[i64]>,
    ) -> Result<()> {
        verify_privacy_receipt(r, Some(signer), None, noisy)?;
        let c = self
            .charged
            .iter()
            .find(|c| c.asset_id == r.asset_id)
            .ok_or_else(|| {
                mech_err(format!(
                    "asset {} is not charged by this release",
                    r.asset_id
                ))
            })?;
        let s = self.sensitivity(c);
        let bound = r.version == RECEIPT_VERSION
            && r.event_id == self.event_id(&c.asset_id)
            && r.round_id == self.round_id
            && r.output == self.output
            && r.policy_id == self.policy_id
            && r.privacy_policy_id == self.privacy_policy_id
            && r.execution_spec_id == self.execution_spec_id
            && r.unit == c.budget.unit
            && r.mechanism == self.mechanism
            && r.sensitivity == s
            && r.sigma2 == sigma2(&self.mechanism, &self.codec)?
            && r.delta == num(c.budget.delta)
            && r.budget_epsilon == num(c.budget.epsilon)
            && r.ledger_seq > 0;
        if !bound {
            return Err(mech_err(format!(
                "asset {}'s privacy receipt is not for this release (round, output, policy, \
                 mechanism, budget or ledger event differ)",
                r.asset_id
            )));
        }
        Ok(())
    }

    /// Refuses the release if `view` (the ledger of `c`) cannot afford it.
    pub fn check(&self, c: &Charged, view: &LedgerView) -> Result<()> {
        if view.genesis != self.genesis(c) {
            return Err(Error::new(
                Code::PrivacyLedger,
                format!(
                    "the ledger is not asset {}'s under this privacy policy",
                    c.asset_id
                ),
            ));
        }
        view.check(self.rho(c)?, self.mechanism.sampling_rate)
            .map(|_| ())
    }
}

fn output_commitment(round_id: &str, output: &str, values: &[i64]) -> String {
    let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
    hex(&tagged(
        OUTPUT,
        &[round_id.as_bytes(), output.as_bytes(), &bytes],
    ))
}

/// What a release cost one asset, signed by whoever ran it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyReceipt {
    pub version: u32,
    pub event_id: String,
    pub asset_id: String,
    pub round_id: String,
    pub output: String,
    pub policy_id: Option<String>,
    pub privacy_policy_id: String,
    pub execution_spec_id: Option<String>,
    pub unit: PrivacyUnit,
    pub mechanism: DpMechanism,
    pub sensitivity: u64,
    pub sigma2: u64,
    /// This release's cost, and the totals after it (epsilon at `delta`).
    pub rho_cost: String,
    pub epsilon_cost: String,
    pub cumulative_rho: String,
    pub cumulative_epsilon: String,
    pub delta: String,
    pub budget_epsilon: String,
    pub output_commitment: String,
    pub ledger_seq: u64,
    pub ledger_root: String,
    pub rng: String,
    pub signer_key: String,
    pub signature: String,
}

impl PrivacyReceipt {
    fn body_bytes(&self) -> Result<Vec<u8>> {
        let mut r = self.clone();
        r.signature = String::new();
        canonical_json(&r)
    }

    /// Signs the receipt as `signer` (setting `signer_key`).
    pub fn sign(mut self, signer: &SigningKey) -> Result<Self> {
        self.signer_key = hex(&signer.verifying_key().to_bytes());
        self.signature = hex(&signer
            .sign(&tagged(RECEIPT, &[&self.body_bytes()?]))
            .to_bytes());
        Ok(self)
    }
}

fn num(x: f64) -> String {
    format!("{x:?}")
}

/// The noisy output and its receipts.
#[derive(Clone, Debug)]
pub struct Released {
    /// `sum + noise`, in code units (decode with the codec).
    pub noisy: Vec<i64>,
    pub output_commitment: String,
    pub receipts: Vec<PrivacyReceipt>,
}

/// Runs the release transaction over the ledgers in `dir`.
pub fn release(
    spec: &ReleaseSpec,
    dir: &Path,
    sum: &[u64],
    rng: &mut Csprng,
    signer: &SigningKey,
) -> Result<Released> {
    if sum.len() != spec.vector_len {
        return Err(mech_err("the aggregate has the wrong length"));
    }
    let s2 = sigma2(&spec.mechanism, &spec.codec)?;
    let mut charged = spec.charged.clone();
    charged.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));
    // Lock every ledger (fixed order: no deadlock) and check every budget
    // before reserving anything. The checks run population first (the
    // authoritative cap, whatever the ledgers' IDs sort to), then the rest.
    let mut ledgers = vec![];
    for c in &charged {
        crate::check_asset_file_name(&c.asset_id)?;
        let path = dir.join(format!("{}.ledger", c.asset_id));
        // A population or scope exists before any release: it is allocated
        // by its owners, never created (with a fresh budget) by a release.
        let l = if c.scoped.is_some() {
            Ledger::open_existing(&path, &spec.genesis(c))?
        } else {
            Ledger::open(&path, &spec.genesis(c))?
        };
        ledgers.push(l);
        crate::failpoint("after-lock");
    }
    for populations in [true, false] {
        for (l, c) in ledgers.iter().zip(&charged) {
            let is_population = c.scoped.as_ref().is_some_and(|s| s.genesis.is_population());
            if is_population == populations {
                spec.check(c, l.view())?;
            }
        }
    }
    let mut before = vec![];
    for (l, c) in ledgers.iter_mut().zip(&charged) {
        before.push(l.view().cost()?);
        l.append(spec.reserve_event(c, rng.label())?)?;
    }
    // A crash between the reservations above (some ledgers charged, others
    // not) over-charges only: the charged ledgers keep the reservation, no
    // noisy output exists, and the round cannot be retried under its ID (the
    // event is already reserved there): a new round ID is needed. Budget is
    // never under-charged.
    crate::failpoint("after-reserve");
    // Only now does a noisy output exist.
    let noisy = sum
        .iter()
        .map(|&v| {
            let z = discrete_gaussian(s2, rng)?;
            crate::failpoint("during-noise");
            i64::try_from(v as i128 + z as i128).map_err(|_| mech_err("noisy value out of range"))
        })
        .collect::<Result<Vec<i64>>>()?;
    let commitment = output_commitment(&spec.round_id, &spec.output, &noisy);
    crate::failpoint("before-commit");
    let mut receipts = vec![];
    for ((l, c), before) in ledgers.iter_mut().zip(&charged).zip(before) {
        l.append(PrivacyEvent::Commit {
            event_id: spec.event_id(&c.asset_id),
            output_commitment: commitment.clone(),
        })?;
        crate::failpoint("after-first-commit");
        let v = l.view();
        let after = v.cost()?;
        let r = PrivacyReceipt {
            version: RECEIPT_VERSION,
            event_id: spec.event_id(&c.asset_id),
            asset_id: c.asset_id.clone(),
            round_id: spec.round_id.clone(),
            output: spec.output.clone(),
            policy_id: spec.policy_id.clone(),
            privacy_policy_id: spec.privacy_policy_id.clone(),
            execution_spec_id: spec.execution_spec_id.clone(),
            unit: c.budget.unit.clone(),
            mechanism: spec.mechanism.clone(),
            sensitivity: spec.sensitivity(c),
            sigma2: s2,
            rho_cost: num(after.rho - before.rho),
            epsilon_cost: num(after.epsilon - before.epsilon),
            cumulative_rho: num(after.rho),
            cumulative_epsilon: num(after.epsilon),
            delta: num(c.budget.delta),
            budget_epsilon: num(c.budget.epsilon),
            output_commitment: commitment.clone(),
            ledger_seq: v.entries.len() as u64,
            ledger_root: v.root()?,
            rng: rng.label().into(),
            signer_key: String::new(),
            signature: String::new(),
        };
        receipts.push(r.sign(signer)?);
    }
    Ok(Released {
        noisy,
        output_commitment: commitment,
        receipts,
    })
}

/// Checks a receipt: its signature (by `trusted`, if given), production
/// randomness, that it belongs to `spec`, and, with the asset's ledger,
/// that the ledger at `ledger_seq` has `ledger_root` and commits this
/// output.
pub fn verify_privacy_receipt(
    r: &PrivacyReceipt,
    trusted: Option<&str>,
    view: Option<&LedgerView>,
    noisy: Option<&[i64]>,
) -> Result<()> {
    let bad = |m: &str| Err(mech_err(m.to_owned()));
    if r.version != RECEIPT_VERSION {
        return bad("unknown privacy receipt version");
    }
    if trusted.is_some_and(|t| t != r.signer_key) {
        return bad("the privacy receipt was signed by an untrusted key");
    }
    let key = unhex(&r.signer_key)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| mech_err("malformed receipt key"))?;
    let sig = unhex(&r.signature)
        .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
        .ok_or_else(|| mech_err("malformed receipt signature"))?;
    key.verify_strict(&tagged(RECEIPT, &[&r.body_bytes()?]), &sig)
        .map_err(|_| mech_err("the privacy receipt's signature is invalid"))?;
    if r.rng != CSPRNG {
        return bad("the release used non-production randomness");
    }
    if let Some(v) = noisy {
        if output_commitment(&r.round_id, &r.output, v) != r.output_commitment {
            return bad("the output does not match the privacy receipt");
        }
    }
    if let Some(view) = view {
        if view.genesis.asset_id != r.asset_id
            || view.genesis.privacy_policy_id != r.privacy_policy_id
        {
            return Err(Error::new(
                Code::PrivacyLedger,
                "the ledger is for another asset or policy",
            ));
        }
        let e = view
            .entries
            .get((r.ledger_seq as usize).wrapping_sub(1))
            .ok_or_else(|| {
                Error::new(Code::PrivacyLedger, "the ledger lacks the receipt's entry")
            })?;
        if e.hash != r.ledger_root {
            return Err(Error::new(
                Code::PrivacyLedger,
                "the ledger does not contain this receipt's root",
            ));
        }
        match &e.event {
            PrivacyEvent::Commit {
                event_id,
                output_commitment,
            } if *event_id == r.event_id && *output_commitment == r.output_commitment => {}
            _ => {
                return Err(Error::new(
                    Code::PrivacyLedger,
                    "the ledger entry is not this release",
                ))
            }
        }
    }
    Ok(())
}
