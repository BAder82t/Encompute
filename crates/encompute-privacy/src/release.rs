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
use crate::ledger::{Genesis, Ledger, LedgerView, PrivacyEvent, LEDGER_VERSION};
use crate::sampler::{discrete_gaussian, Csprng, CSPRNG};
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

/// A budgeted source asset a release is charged to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Charged {
    pub asset_id: String,
    pub budget: PrivacyBudget,
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
/// - a record, user, patient or device lives inside one party's data and
///   moves that party's (clipped) vector by at most `clip_norm`;
/// - an organization's whole contribution is replaced by another (fixed
///   contributors), moving it by at most `2 * clip_norm`.
///
/// Either way the encoding offset `-clip_min * scale` is present in both
/// sums and cancels, and rounding each coordinate to a code moves each by at
/// most 1: sensitivity `ceil(k * clip_norm * scale) + ceil(sqrt(d))`.
/// (Adding or removing a whole party is not a neighbouring dataset here: it
/// is visible in the public contributor list.)
pub fn sensitivity(unit: &PrivacyUnit, m: &DpMechanism, codec: &FixedPointCodec, d: usize) -> u64 {
    let k = if *unit == PrivacyUnit::Organization {
        2.0
    } else {
        1.0
    };
    let clip = (k * m.clip_norm * codec.scale as f64).ceil() as u64;
    let mut r = (d as f64).sqrt().floor() as u64;
    while r * r < d as u64 {
        r += 1;
    }
    clip + r
}

impl ReleaseSpec {
    fn event_id(&self, asset: &str) -> String {
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
        Genesis {
            version: LEDGER_VERSION,
            asset_id: c.asset_id.clone(),
            budget: c.budget.clone(),
            privacy_policy_id: self.privacy_policy_id.clone(),
        }
    }

    /// The zCDP cost this release charges `c`.
    pub fn rho(&self, c: &Charged) -> Result<f64> {
        gaussian_rho(
            sensitivity(
                &c.budget.unit,
                &self.mechanism,
                &self.codec,
                self.vector_len,
            ),
            sigma2(&self.mechanism, &self.codec)?,
        )
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
        view.check(self.rho(c)?).map(|_| ())
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
    // before reserving anything.
    let mut ledgers = vec![];
    for c in &charged {
        crate::check_asset_file_name(&c.asset_id)?;
        let l = Ledger::open(
            &dir.join(format!("{}.ledger", c.asset_id)),
            &spec.genesis(c),
        )?;
        spec.check(c, l.view())?;
        ledgers.push(l);
        crate::failpoint("after-lock");
    }
    let mut before = vec![];
    for (l, c) in ledgers.iter_mut().zip(&charged) {
        before.push(l.view().cost()?);
        l.append(PrivacyEvent::Reserve {
            event_id: spec.event_id(&c.asset_id),
            policy_id: spec.policy_id.clone(),
            execution_spec_id: spec.execution_spec_id.clone(),
            round_id: Some(spec.round_id.clone()),
            output: spec.output.clone(),
            mechanism: spec.mechanism.clone(),
            sensitivity: sensitivity(
                &c.budget.unit,
                &spec.mechanism,
                &spec.codec,
                spec.vector_len,
            ),
            sigma2: s2,
            vector_len: spec.vector_len,
            rng: rng.label().into(),
        })?;
    }
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
            sensitivity: sensitivity(
                &c.budget.unit,
                &spec.mechanism,
                &spec.codec,
                spec.vector_len,
            ),
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
