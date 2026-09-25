//! Encompute's side of secure aggregation (ADR-012): what is aggregated
//! ([`AggregationPlan`], lowered from a checked program), who takes part
//! and how ([`AggregationSpec`], `encagg1:`), one execution
//! ([`AggregationRound`], `encround1:`), and what comes out: an
//! [`AggregateAsset`] with a derived policy, and a signed
//! [`AggregationReceipt`].

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use encompute_analysis::confidentiality::AggregationBoundary;
use encompute_attestation::{AttestationPolicy, AttestationRecord, Verifier};
use encompute_ir::confidentiality::{
    AggregationFunction, AssetKind, DpMechanism, FixedPointCodec, OutputRelease, PartyId,
    PrivacyBudget, Release,
};
use encompute_ir::{Code, Error, Result};
use encompute_privacy::ledger::{Checkpoint, Genesis, LedgerView};
use encompute_privacy::{Charged, Csprng, PrivacyReceipt, ReleaseSpec};
use encompute_verification::canonical::canonical_json;
use std::path::{Path, PathBuf};

use crate::crypto::{hex, random32, tagged, unhex, unhex32};
use crate::protocol::{
    verify_confirmation, verify_contribution, Advertise, Aggregated, ConsistencyBody,
    ContributionStatement, Coordinator, Inbox, KeysBroadcast, Masked, Participant, ProtocolParams,
    RevealBody, SharesBody, Signed, Survivors, UnmaskRequest,
};

pub const PLAN_VERSION: u32 = 1;
pub const SPEC_VERSION: u32 = 1;
pub const ROUND_VERSION: u32 = 1;
pub const RECEIPT_VERSION: u32 = 1;
/// The protocol this crate implements.
pub const PROTOCOL: &str = "secagg-bonawitz17";
pub const PROTOCOL_VERSION: u32 = 1;

const SPEC_DOMAIN: &str = "encompute.aggregation-spec.v1";
const ROUND_DOMAIN: &str = "encompute.aggregation-round.v1";
const RECEIPT_DOMAIN: &str = "encompute.aggregation-receipt.v1";
const AGGREGATE_DOMAIN: &str = "encompute.aggregate.v1";
const METADATA_DOMAIN: &str = "encompute.contribution-metadata.v1";
const CODEC_DOMAIN: &str = "encompute.aggregation-codec.v1";
const KEYS_DOMAIN: &str = "encompute.contribution-keys.v1";
const ASSET_DOMAIN: &str = "encompute.aggregate-asset.v1";
const PLAN_DOMAIN: &str = "encompute.aggregation-plan.v1";

/// `SHA256("encompute.aggregation-codec.v1", canonical codec)`, hex.
pub fn codec_id(codec: &FixedPointCodec) -> Result<String> {
    digest(CODEC_DOMAIN, codec)
}

/// What a party states about its contribution, signed with its identity
/// key before any protocol message: which round, asset, policy, training
/// execution, encoding and shape, and which protocol keys carry it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContributionMetadata {
    pub round_id: String,
    pub party: PartyId,
    pub asset_id: String,
    pub policy_id: Option<String>,
    pub execution_spec_id: Option<String>,
    pub codec_id: String,
    pub vector_len: usize,
    /// Digest of the advertised protocol keys (c_pk, s_pk).
    pub keys_digest: String,
    pub attestation_id: Option<String>,
}

/// Round 0 as a party sends it: its protocol keys and its signed metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Join {
    pub advertise: Advertise,
    pub metadata: Signed<ContributionMetadata>,
}

fn keys_digest(a: &Advertise) -> String {
    let b = &a.signed.body;
    hex(&tagged(
        KEYS_DOMAIN,
        &[b.c_pk.as_bytes(), b.s_pk.as_bytes()],
    ))
}

fn binding(m: impl Into<String>) -> Error {
    Error::new(Code::AggregationBinding, m)
}

fn digest<T: Serialize>(domain: &str, v: &T) -> Result<String> {
    Ok(hex(&tagged(domain, &[&canonical_json(v)?])))
}

/// One party's contribution slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanParticipant {
    pub party: PartyId,
    pub input: String,
    pub asset: String,
    /// The asset's privacy budget (ADR-013), charged per release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<PrivacyBudget>,
}

/// The aggregate's derived policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregatePolicy {
    pub owners: BTreeSet<PartyId>,
    /// Who may learn the aggregate (`None`: anyone).
    pub audience: Option<BTreeSet<PartyId>>,
    pub purposes: Option<BTreeSet<String>>,
    pub release: Release,
}

/// What is aggregated: scheme-independent, lowered from a program's
/// checked `aggregate` declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationPlan {
    pub version: u32,
    pub program_id: String,
    pub policy_id: Option<String>,
    pub output: String,
    pub input_asset_kind: AssetKind,
    pub output_asset_kind: AssetKind,
    pub function: AggregationFunction,
    /// Sorted by party.
    pub participants: Vec<PlanParticipant>,
    /// The fewest contributions an aggregate may be released from.
    pub minimum: usize,
    /// Parties that may collude with the coordinator (declared).
    pub colluding: usize,
    pub vector_len: usize,
    pub codec: FixedPointCodec,
    pub recipient: OutputRelease,
    pub aggregate_policy: AggregatePolicy,
    /// Differential privacy applied before release (ADR-013).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dp: Option<DpMechanism>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_policy_id: Option<String>,
}

impl AggregationPlan {
    pub fn from_boundary(
        program_id: &str,
        policy_id: Option<&str>,
        privacy_policy_id: Option<&str>,
        b: &AggregationBoundary,
    ) -> Self {
        let a = &b.aggregate_policy;
        Self {
            version: PLAN_VERSION,
            program_id: program_id.to_owned(),
            policy_id: policy_id.map(str::to_owned),
            output: b.output.clone(),
            input_asset_kind: b.contribution_policy.kind,
            output_asset_kind: a.kind,
            function: b.function,
            participants: b
                .contributions
                .iter()
                .map(|k| PlanParticipant {
                    party: k.party.clone(),
                    input: k.input.clone(),
                    asset: k.asset.clone(),
                    budget: k.budget.clone(),
                })
                .collect(),
            minimum: b.minimum,
            colluding: b.colluding,
            vector_len: b.vector_len,
            codec: b.codec,
            recipient: b.recipient.clone(),
            aggregate_policy: AggregatePolicy {
                owners: a.owners.clone(),
                audience: a.audience.clone(),
                purposes: a.purposes.clone(),
                release: a.release,
            },
            dp: b.dp.clone(),
            privacy_policy_id: privacy_policy_id.map(str::to_owned),
        }
    }

    pub fn participant(&self, party: &PartyId) -> Option<&PlanParticipant> {
        self.participants.iter().find(|p| &p.party == party)
    }

    /// `SHA256("encompute.aggregation-plan.v1", canonical plan)`: what an
    /// attested coordinator binds as its execution.
    pub fn id(&self) -> Result<String> {
        digest(PLAN_DOMAIN, self)
    }

    /// The release a round of this plan performs, charged to the budgets
    /// of `contributors`; `None` without differential privacy.
    pub fn release_spec(
        &self,
        round_id: &str,
        execution_spec_id: Option<&str>,
        contributors: &[PartyId],
    ) -> Result<Option<ReleaseSpec>> {
        let Some(dp) = &self.dp else {
            return Ok(None);
        };
        let privacy_policy_id = self.privacy_policy_id.clone().ok_or_else(|| {
            Error::new(Code::PrivacyPolicy, "a DP plan without a privacy policy ID")
        })?;
        Ok(Some(ReleaseSpec {
            round_id: round_id.to_owned(),
            output: self.output.clone(),
            policy_id: self.policy_id.clone(),
            privacy_policy_id,
            execution_spec_id: execution_spec_id.map(str::to_owned),
            mechanism: dp.clone(),
            codec: self.codec,
            vector_len: self.vector_len,
            charged: contributors
                .iter()
                .filter_map(|p| self.participant(p))
                .filter_map(|p| {
                    p.budget.clone().map(|budget| Charged {
                        asset_id: p.asset.clone(),
                        budget,
                    })
                })
                .collect(),
        }))
    }

    /// The asset's ledger as found in `dir` (a genesis-only ledger if it
    /// has none yet).
    pub fn ledger_view(&self, dir: &Path, p: &PlanParticipant) -> Result<Option<LedgerView>> {
        let (Some(budget), Some(ppid)) = (&p.budget, &self.privacy_policy_id) else {
            return Ok(None);
        };
        let path = dir.join(format!("{}.ledger", p.asset));
        if path.exists() {
            return encompute_privacy::ledger::read(&path).map(Some);
        }
        Ok(Some(LedgerView {
            genesis: Genesis {
                version: encompute_privacy::ledger::LEDGER_VERSION,
                asset_id: p.asset.clone(),
                budget: budget.clone(),
                privacy_policy_id: ppid.clone(),
            },
            entries: vec![],
        }))
    }
}

/// A party's public identity for aggregation: its Ed25519 key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartyIdentity {
    pub party: PartyId,
    pub public_key: String,
}

/// Who takes part, under what protocol and threshold: everything a party
/// approves before contributing. Its ID (`encagg1:`) is what parties
/// compare; any difference (policy, codec, shape, parties, keys) is a
/// different spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationSpec {
    pub version: u32,
    pub plan: AggregationPlan,
    pub parties: Vec<PartyIdentity>,
    pub protocol: String,
    pub protocol_version: u32,
    /// Shamir threshold: the fewest parties the protocol completes with.
    pub threshold: usize,
    /// The training program contributions come from, if fixed.
    #[serde(default)]
    pub training_execution_spec_id: Option<String>,
    /// If set, every contribution key must be held by a workload whose
    /// attestation satisfies this policy.
    #[serde(default)]
    pub attestation: Option<AttestationPolicy>,
    /// If set, the coordinator must be an attested workload satisfying this
    /// policy, bound to the plan, the round and its privacy policy: parties
    /// contribute only to a coordinator that provably adds the approved
    /// noise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_attestation: Option<AttestationPolicy>,
}

impl AggregationSpec {
    /// A spec for `plan` with these identities: the threshold is the plan's
    /// minimum, raised to what its declared collusion bound requires.
    pub fn new(plan: AggregationPlan, parties: Vec<PartyIdentity>) -> Result<Self> {
        let n = plan.participants.len();
        let spec = Self {
            version: SPEC_VERSION,
            threshold: plan
                .minimum
                .max(ProtocolParams::minimum_threshold(n, plan.colluding)),
            plan,
            parties,
            protocol: PROTOCOL.into(),
            protocol_version: PROTOCOL_VERSION,
            training_execution_spec_id: None,
            attestation: None,
            coordinator_attestation: None,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn id(&self) -> Result<String> {
        digest(SPEC_DOMAIN, self)
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::new(Code::AggregationPlan, m));
        if self.version != SPEC_VERSION || self.plan.version != PLAN_VERSION {
            return bad("unknown aggregation spec version".into());
        }
        if self.protocol != PROTOCOL || self.protocol_version != PROTOCOL_VERSION {
            return bad(format!(
                "unsupported protocol {} v{}",
                self.protocol, self.protocol_version
            ));
        }
        let planned: Vec<&PartyId> = self.plan.participants.iter().map(|p| &p.party).collect();
        let named: Vec<&PartyId> = self.parties.iter().map(|p| &p.party).collect();
        if planned != named {
            return bad(
                "the spec's party identities must match the plan's participants, in order".into(),
            );
        }
        for p in &self.parties {
            let k = unhex32(&p.public_key, "party key")?;
            VerifyingKey::from_bytes(&k).map_err(|_| {
                Error::new(
                    Code::AggregationPlan,
                    format!("{}'s key is invalid", p.party),
                )
            })?;
        }
        if self.threshold < self.plan.minimum {
            return bad(format!(
                "threshold {} is below the plan's minimum {}",
                self.threshold, self.plan.minimum
            ));
        }
        if let Some(a) = &self.attestation {
            a.validate()?;
        }
        self.plan
            .codec
            .check_overflow(self.plan.participants.len())?;
        self.params("0".repeat(64))?.validate()
    }

    fn params(&self, round_id: String) -> Result<ProtocolParams> {
        Ok(ProtocolParams {
            round_id,
            parties: self
                .parties
                .iter()
                .map(|p| Ok((p.party.clone(), unhex32(&p.public_key, "party key")?)))
                .collect::<Result<_>>()?,
            threshold: self.threshold,
            max_colluding: self.plan.colluding,
            vector_len: self.plan.vector_len,
            modulus_bits: self.plan.codec.modulus_bits,
        })
    }

    /// Why `other` is not this spec, field by field (for errors).
    pub fn difference(&self, other: &AggregationSpec) -> Option<String> {
        let (a, b) = (&self.plan, &other.plan);
        let fields: [(&str, bool); 12] = [
            ("program", a.program_id != b.program_id),
            ("PolicyID", a.policy_id != b.policy_id),
            ("output", a.output != b.output),
            ("vector shape", a.vector_len != b.vector_len),
            ("codec (clip, scale, modulus)", a.codec != b.codec),
            ("aggregation function", a.function != b.function),
            ("participants", a.participants != b.participants),
            (
                "minimum or collusion bound",
                (a.minimum, a.colluding) != (b.minimum, b.colluding),
            ),
            ("party keys", self.parties != other.parties),
            (
                "threshold or protocol",
                (self.threshold, &self.protocol) != (other.threshold, &other.protocol),
            ),
            (
                "training ExecutionSpecID",
                self.training_execution_spec_id != other.training_execution_spec_id,
            ),
            (
                "attestation policy",
                (&self.attestation, &self.coordinator_attestation)
                    != (&other.attestation, &other.coordinator_attestation),
            ),
        ];
        let diff: Vec<&str> = fields.iter().filter(|(_, d)| *d).map(|(n, _)| *n).collect();
        (!diff.is_empty() || self != other).then(|| {
            if diff.is_empty() {
                "the specs differ".into()
            } else {
                format!("they differ in: {}", diff.join(", "))
            }
        })
    }
}

/// One execution of a spec. Its ID binds every key derivation and
/// signature of the run, so nothing from one round is usable in another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationRound {
    pub version: u32,
    pub spec_id: String,
    /// Increases per round of a spec; parties refuse to go back.
    pub sequence: u64,
    pub nonce: String,
    /// The coordinator's receipt-signing key.
    pub coordinator_key: String,
    pub opened_at: u64,
}

impl AggregationRound {
    pub fn new(
        spec: &AggregationSpec,
        sequence: u64,
        coordinator: &SigningKey,
        now: u64,
    ) -> Result<Self> {
        Ok(Self {
            version: ROUND_VERSION,
            spec_id: spec.id()?,
            sequence,
            nonce: hex(&random32()?),
            coordinator_key: hex(&coordinator.verifying_key().to_bytes()),
            opened_at: now,
        })
    }

    pub fn id(&self) -> Result<String> {
        digest(ROUND_DOMAIN, self)
    }
}

/// A party's side of one round.
pub struct RoundParticipant {
    pub spec: AggregationSpec,
    pub round: AggregationRound,
    identity: SigningKey,
    protocol: Participant,
}

/// What a party checks before contributing, beyond the spec.
#[derive(Default)]
pub struct JoinOptions<'a> {
    /// The attestation of the workload holding this party's key.
    pub attestation: Option<AttestationRecord>,
    /// The last round sequence this party joined (replay protection).
    pub last_sequence: Option<u64>,
    /// This party's asset's privacy ledger, as the coordinator shows it.
    pub ledger: Option<&'a LedgerView>,
    /// The last ledger checkpoint this party saw (rollback detection).
    pub seen: Option<&'a Checkpoint>,
    /// The coordinator's attestation record and a verifier for it.
    pub coordinator: Option<(&'a AttestationRecord, &'a Verifier)>,
}

/// The coordinator is an approved attested workload bound to this plan,
/// round (its key and nonce) and privacy policy.
fn check_coordinator(
    spec: &AggregationSpec,
    round: &AggregationRound,
    policy: &AttestationPolicy,
    coordinator: Option<(&AttestationRecord, &Verifier)>,
) -> Result<()> {
    let unauthorized = |m: &str| Error::new(Code::AggregationUnauthorized, m.to_owned());
    let (record, verifier) =
        coordinator.ok_or_else(|| unauthorized("this spec requires an attested coordinator"))?;
    let b = &record.evidence.binding;
    if b.evaluator_public_key != round.coordinator_key {
        return Err(unauthorized(
            "the coordinator's attestation binds another key",
        ));
    }
    if b.challenge_nonce != round.nonce {
        return Err(unauthorized(
            "the coordinator's attestation is for another round",
        ));
    }
    if b.execution_spec_id != spec.plan.id()? {
        return Err(unauthorized(
            "the coordinator's attestation is for another plan",
        ));
    }
    record.verify(verifier, policy)?;
    Ok(())
}

impl RoundCoordinator {
    /// Attests this round's coordinator with `attester`: the binding names
    /// the plan (as execution), its policy and privacy policy, the round's
    /// coordinator key and nonce. Parties requiring an attested coordinator
    /// check it before contributing.
    pub fn attest(
        &mut self,
        attester: &dyn encompute_attestation::Attester,
    ) -> Result<AttestationRecord> {
        let plan = &self.spec.plan;
        let challenge = encompute_attestation::AttestationChallenge {
            broker_id: format!("encagg1:{}", self.spec.id()?),
            nonce: self.round.nonce.clone(),
            issued_at: self.round.opened_at,
            expires_at: self.round.opened_at.saturating_add(3600),
        };
        let evaluator = encompute_verification::EvaluatorIdentity::from_public_key(
            &self.key.verifying_key().to_bytes(),
        )?;
        let mut binding = encompute_attestation::WorkloadSession::new(&evaluator).binding(
            &challenge,
            &plan.id()?,
            plan.policy_id.as_deref(),
            &plan.program_id,
        );
        binding.privacy_policy_id = plan.privacy_policy_id.clone();
        let record = AttestationRecord::new(attester.attest(&challenge, &binding)?);
        self.coordinator_attestation = Some(record.clone());
        Ok(record)
    }

    pub fn coordinator_attestation(&self) -> Option<&AttestationRecord> {
        self.coordinator_attestation.as_ref()
    }

    /// Where the privacy ledgers live; required for DP plans. Checks now
    /// that every budgeted party can afford a round, so a round that could
    /// never be released does not start.
    pub fn with_ledger(mut self, dir: &Path) -> Result<Self> {
        let plan = &self.spec.plan;
        let all: Vec<PartyId> = plan.participants.iter().map(|p| p.party.clone()).collect();
        if let Some(r) = plan.release_spec(&self.round.id()?, None, &all)? {
            for c in &r.charged {
                let p = plan
                    .participants
                    .iter()
                    .find(|p| p.asset == c.asset_id)
                    .expect("from plan");
                let view = plan.ledger_view(dir, p)?.expect("budgeted");
                r.check(c, &view)?;
            }
        }
        self.ledger_dir = Some(dir.to_owned());
        Ok(self)
    }

    /// The budgeted assets' ledgers, for parties to check before joining.
    pub fn ledger_views(&self) -> Result<BTreeMap<String, LedgerView>> {
        let mut out = BTreeMap::new();
        if let Some(dir) = &self.ledger_dir {
            for p in &self.spec.plan.participants {
                if let Some(v) = self.spec.plan.ledger_view(dir, p)? {
                    out.insert(p.asset.clone(), v);
                }
            }
        }
        Ok(out)
    }
}

impl RoundParticipant {
    /// Joins `round` of `offered` if it is exactly the spec this party
    /// approved (`approved`), names this party, and is newer than the last
    /// round it joined. `values` are encoded with the spec's codec here.
    ///
    /// `last_sequence` is the replay protection: callers must persist the
    /// sequence of every round they join (the CLI's `--state`), or a
    /// coordinator can replay a finished round.
    #[allow(clippy::too_many_arguments)]
    pub fn join(
        approved: &AggregationSpec,
        offered: &AggregationSpec,
        round: &AggregationRound,
        party: &PartyId,
        identity: SigningKey,
        values: &[f64],
        attestation: Option<AttestationRecord>,
        last_sequence: Option<u64>,
    ) -> Result<Self> {
        Self::join_with(
            approved,
            offered,
            round,
            party,
            identity,
            values,
            JoinOptions {
                attestation,
                last_sequence,
                ..JoinOptions::default()
            },
        )
    }

    /// [`Self::join`], with privacy and coordinator checks: under a DP plan
    /// the party's contribution is L2-clipped, and it joins only if its
    /// asset's ledger (shown by the coordinator) is intact, extends the last
    /// checkpoint it saw, and can afford this round; and, if the spec
    /// requires it, only an attested coordinator bound to this plan, round
    /// and privacy policy.
    pub fn join_with(
        approved: &AggregationSpec,
        offered: &AggregationSpec,
        round: &AggregationRound,
        party: &PartyId,
        identity: SigningKey,
        values: &[f64],
        opts: JoinOptions<'_>,
    ) -> Result<Self> {
        let JoinOptions {
            attestation,
            last_sequence,
            ledger,
            seen,
            coordinator,
        } = opts;
        if let Some(why) = approved.difference(offered) {
            return Err(binding(format!(
                "the coordinator's aggregation spec is not the approved one: {why}"
            )));
        }
        let spec_id = approved.id()?;
        if round.spec_id != spec_id || round.version != ROUND_VERSION {
            return Err(binding("the round is for another aggregation spec"));
        }
        if last_sequence.is_some_and(|s| round.sequence <= s) {
            return Err(binding(format!(
                "round {} is not newer than round {} already joined (replay)",
                round.sequence,
                last_sequence.unwrap_or_default()
            )));
        }
        if approved.plan.participant(party).is_none() {
            return Err(Error::new(
                Code::AggregationUnauthorized,
                format!("party {party} is not authorized for aggregation spec {spec_id}"),
            ));
        }
        if values.len() != approved.plan.vector_len {
            return Err(binding(format!(
                "the contribution has {} values; the round expects {}",
                values.len(),
                approved.plan.vector_len
            )));
        }
        if approved.attestation.is_some() && attestation.is_none() {
            return Err(Error::new(
                Code::AggregationUnauthorized,
                "this spec requires an attested contribution workload",
            ));
        }
        if let Some(policy) = &approved.coordinator_attestation {
            check_coordinator(approved, round, policy, coordinator)?;
        }
        let plan = &approved.plan;
        let mut values = values.to_vec();
        if let Some(dp) = &plan.dp {
            let me = plan.participant(party).expect("checked above");
            if let Some(release) =
                plan.release_spec(&round.id()?, None, std::slice::from_ref(party))?
            {
                if let Some(c) = release.charged.first() {
                    let view = ledger.ok_or_else(|| {
                        Error::new(
                            Code::PrivacyLedger,
                            format!(
                                "the coordinator did not show asset {}'s privacy ledger",
                                me.asset
                            ),
                        )
                    })?;
                    view.verify()?;
                    if view.entries.iter().any(|e| matches!(&e.event,
                        encompute_privacy::PrivacyEvent::Reserve { rng, .. } if rng != encompute_privacy::CSPRNG))
                    {
                        return Err(Error::new(
                            Code::PrivacyMechanism,
                            "the ledger records releases with non-production randomness",
                        ));
                    }
                    if let Some(seen) = seen {
                        view.extends(seen)?;
                    }
                    release.check(c, view)?;
                }
            }
            // Clip the whole contribution to L2 norm clip_norm.
            let norm = values.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm > dp.clip_norm {
                let f = dp.clip_norm / norm;
                values.iter_mut().for_each(|x| *x *= f);
            }
        }
        let codec = &plan.codec;
        let encoded: Vec<u64> = values.iter().map(|&x| codec.encode(x)).collect();
        let protocol = Participant::new(
            approved.params(round.id()?)?,
            party.clone(),
            identity.clone(),
            encoded,
            attestation,
        )?;
        Ok(Self {
            spec: approved.clone(),
            round: round.clone(),
            identity,
            protocol,
        })
    }

    pub fn party(&self) -> &PartyId {
        self.protocol.party()
    }

    /// Round 0: protocol keys plus the signed contribution metadata.
    pub fn advertise(&mut self) -> Result<Join> {
        let advertise = self.protocol.advertise()?;
        let plan = &self.spec.plan;
        let party = self.protocol.party().clone();
        let metadata = ContributionMetadata {
            round_id: self.round.id()?,
            asset_id: plan
                .participant(&party)
                .expect("checked at join")
                .asset
                .clone(),
            party,
            policy_id: plan.policy_id.clone(),
            execution_spec_id: self.spec.training_execution_spec_id.clone(),
            codec_id: codec_id(&plan.codec)?,
            vector_len: plan.vector_len,
            keys_digest: keys_digest(&advertise),
            attestation_id: advertise.signed.body.attestation_id.clone(),
        };
        Ok(Join {
            metadata: Signed::new(&self.identity, METADATA_DOMAIN, metadata)?,
            advertise,
        })
    }

    pub fn share_keys(&mut self, k: &KeysBroadcast) -> Result<Signed<SharesBody>> {
        self.protocol.share_keys(k)
    }

    pub fn masked_input(&mut self, i: &Inbox) -> Result<Masked> {
        self.protocol.masked_input(i)
    }

    pub fn consistency(&mut self, s: &Survivors) -> Result<Signed<ConsistencyBody>> {
        self.protocol.consistency(s)
    }

    pub fn unmask(&mut self, u: &UnmaskRequest) -> Result<Signed<RevealBody>> {
        self.protocol.unmask(u)
    }
}

/// The aggregate: the only value a round releases.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateAsset {
    /// `SHA256("encompute.aggregate-asset.v1", receipt ID, output)`: this
    /// instance, in the asset graph.
    pub asset_id: String,
    pub output: String,
    pub kind: AssetKind,
    pub function: AggregationFunction,
    /// Decoded values (the sum, or the mean over `contributors`).
    pub values: Vec<f64>,
    /// The released integer aggregate (with privacy noise, if any), in
    /// code units.
    pub encoded_sum: Vec<i64>,
    pub contributors: Vec<PartyId>,
    /// The assets it was derived from (contributors' only).
    pub parents: Vec<String>,
    /// Owners: the contributors; audience, purposes and release from the
    /// plan's derived policy.
    pub policy: AggregatePolicy,
    /// ID of the receipt that produced it.
    pub receipt_id: String,
    /// What the release cost each budgeted source (ADR-013).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub privacy: Vec<PrivacyReceipt>,
}

/// Public metadata of a finished round: no contribution values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationManifest {
    pub version: u32,
    pub round_id: String,
    pub round: AggregationRound,
    pub spec_id: String,
    pub policy_id: Option<String>,
    pub training_execution_spec_id: Option<String>,
    pub output: String,
    pub function: AggregationFunction,
    pub protocol: String,
    pub protocol_version: u32,
    pub codec: FixedPointCodec,
    pub codec_id: String,
    pub vector_len: usize,
    pub minimum: usize,
    pub threshold: usize,
    pub max_colluding: usize,
    pub eligible: Vec<PartyId>,
    pub advertised: Vec<PartyId>,
    pub contributors: Vec<PartyId>,
    pub dropped: Vec<PartyId>,
    /// Each contributor's signed metadata (round, asset, policy, execution,
    /// codec, shape, keys, attestation).
    pub metadata: Vec<Signed<ContributionMetadata>>,
    /// Each contributor's signed commitment to its masked contribution.
    pub contributions: Vec<Signed<ContributionStatement>>,
    /// The contributor set, as signed by the parties that confirmed it.
    pub confirmations: Vec<Signed<ConsistencyBody>>,
    /// Attestation record IDs of attested contributors.
    pub attestations: BTreeMap<PartyId, String>,
    /// `SHA256("encompute.aggregate.v1", round, released sum)`.
    pub aggregate_commitment: String,
    /// Privacy receipts of the release, one per budgeted contributor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub privacy: Vec<PrivacyReceipt>,
    pub parents: Vec<String>,
}

/// The manifest, signed by the coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregationReceipt {
    pub manifest: AggregationManifest,
    pub coordinator_key: String,
    pub signature: String,
}

impl AggregationReceipt {
    pub fn id(&self) -> Result<String> {
        digest(RECEIPT_DOMAIN, self)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        serde_json::from_slice(b).map_err(|e| {
            Error::new(
                Code::AggregationProtocol,
                format!("malformed aggregation receipt: {e}"),
            )
        })
    }
}

fn aggregate_commitment(round_id: &str, sum: &[i64]) -> String {
    let bytes: Vec<u8> = sum.iter().flat_map(|v| v.to_le_bytes()).collect();
    hex(&tagged(AGGREGATE_DOMAIN, &[round_id.as_bytes(), &bytes]))
}

/// The coordinator's side of one round.
pub struct RoundCoordinator {
    pub spec: AggregationSpec,
    pub round: AggregationRound,
    key: SigningKey,
    verifier: Option<Verifier>,
    protocol: Coordinator,
    metadata: BTreeMap<PartyId, Signed<ContributionMetadata>>,
    ledger_dir: Option<PathBuf>,
    coordinator_attestation: Option<AttestationRecord>,
}

impl RoundCoordinator {
    /// `verifier` checks contributors' attestations when the spec requires
    /// them.
    pub fn open(
        spec: AggregationSpec,
        sequence: u64,
        key: SigningKey,
        verifier: Option<Verifier>,
        now: u64,
    ) -> Result<Self> {
        spec.validate()?;
        if spec.attestation.is_some() && verifier.is_none() {
            return Err(Error::new(
                Code::AggregationPlan,
                "the spec requires attested contributors: the coordinator needs a verifier",
            ));
        }
        let round = AggregationRound::new(&spec, sequence, &key, now)?;
        let protocol = Coordinator::new(spec.params(round.id()?)?)?;
        Ok(Self {
            spec,
            round,
            key,
            verifier,
            protocol,
            metadata: BTreeMap::new(),
            ledger_dir: None,
            coordinator_attestation: None,
        })
    }

    pub fn round_id(&self) -> Result<String> {
        self.round.id()
    }

    pub fn awaiting(&self) -> BTreeSet<PartyId> {
        self.protocol.awaiting()
    }

    /// Round 0: checks the party's signed metadata against the plan (round,
    /// asset, PolicyID, ExecutionSpecID, codec, shape, keys, attestation),
    /// then its attestation if the spec requires one.
    pub fn receive_advertise(&mut self, join: Join) -> Result<()> {
        let Join {
            advertise: a,
            metadata,
        } = join;
        self.check_metadata(&a, &metadata)?;
        if let Some(policy) = &self.spec.attestation {
            let party = &a.signed.body.party;
            let record = a.attestation.as_ref().ok_or_else(|| {
                Error::new(
                    Code::AggregationUnauthorized,
                    format!("{party} did not attest its contribution workload"),
                )
            })?;
            let key = self
                .spec
                .parties
                .iter()
                .find(|p| &p.party == party)
                .map(|p| p.public_key.clone())
                .ok_or_else(|| {
                    Error::new(
                        Code::AggregationUnauthorized,
                        format!("party {party} is not authorized for this round"),
                    )
                })?;
            if record.evidence.binding.evaluator_public_key != key {
                return Err(Error::new(
                    Code::AggregationUnauthorized,
                    format!("{party}'s attestation binds another key than its contribution key"),
                ));
            }
            record.verify(self.verifier.as_ref().expect("checked at open"), policy)?;
        }
        self.protocol.receive_advertise(a)?;
        self.metadata.insert(metadata.body.party.clone(), metadata);
        Ok(())
    }

    fn check_metadata(&self, a: &Advertise, m: &Signed<ContributionMetadata>) -> Result<()> {
        let party = &a.signed.body.party;
        let key = self
            .spec
            .parties
            .iter()
            .find(|p| &p.party == party)
            .map(|p| p.public_key.clone())
            .ok_or_else(|| {
                Error::new(
                    Code::AggregationUnauthorized,
                    format!("party {party} is not authorized for this round"),
                )
            })?;
        crate::crypto::verify(
            &unhex32(&key, "party key")?,
            METADATA_DOMAIN,
            &canonical_json(&m.body)?,
            &m.signature,
        )?;
        let plan = &self.spec.plan;
        let b = &m.body;
        let want_asset = &plan.participant(party).expect("authorized").asset;
        let checks: [(&str, bool); 8] = [
            ("party", &b.party == party),
            ("RoundID", b.round_id == self.round.id()?),
            ("AssetID", &b.asset_id == want_asset),
            ("PolicyID", b.policy_id == plan.policy_id),
            (
                "ExecutionSpecID",
                b.execution_spec_id == self.spec.training_execution_spec_id,
            ),
            ("codec", b.codec_id == codec_id(&plan.codec)?),
            ("vector shape", b.vector_len == plan.vector_len),
            ("protocol keys", b.keys_digest == keys_digest(a)),
        ];
        if let Some((what, _)) = checks.iter().find(|(_, ok)| !ok) {
            return Err(binding(format!(
                "{party}'s contribution names the wrong {what} for this round"
            )));
        }
        if b.attestation_id != a.signed.body.attestation_id {
            return Err(binding(format!(
                "{party}'s metadata names another attestation"
            )));
        }
        Ok(())
    }

    pub fn close_advertise(&mut self) -> Result<KeysBroadcast> {
        self.protocol.close_advertise()
    }

    pub fn receive_shares(&mut self, s: Signed<SharesBody>) -> Result<()> {
        self.protocol.receive_shares(s)
    }

    pub fn close_shares(&mut self) -> Result<BTreeMap<PartyId, Inbox>> {
        self.protocol.close_shares()
    }

    pub fn receive_masked(&mut self, m: Masked) -> Result<()> {
        self.protocol.receive_masked(m)
    }

    pub fn close_masked(&mut self) -> Result<Survivors> {
        self.protocol.close_masked()
    }

    pub fn receive_consistency(&mut self, c: Signed<ConsistencyBody>) -> Result<()> {
        self.protocol.receive_consistency(c)
    }

    pub fn close_consistency(&mut self) -> Result<UnmaskRequest> {
        self.protocol.close_consistency()
    }

    pub fn receive_reveal(&mut self, r: Signed<RevealBody>) -> Result<()> {
        self.protocol.receive_reveal(r)
    }

    /// Unmasks the sum and releases the aggregate with its receipt, only if
    /// at least the plan's minimum contributed.
    pub fn finalize(&mut self) -> Result<(AggregateAsset, AggregationReceipt)> {
        let Aggregated {
            sum,
            advertised,
            survivors,
            contributions,
            confirmations,
            attestations,
        } = self.protocol.finalize()?;
        let plan = &self.spec.plan;
        if survivors.len() < plan.minimum {
            return Err(Error::new(
                Code::AggregationThreshold,
                format!(
                    "{} contributions, below the minimum {}: no aggregate is released",
                    survivors.len(),
                    plan.minimum
                ),
            ));
        }
        let round_id = self.round.id()?;
        let n = survivors.len();
        // The released aggregate: with privacy noise under a DP plan, after
        // the cost is reserved in every contributor's ledger.
        let (released, privacy): (Vec<i64>, Vec<PrivacyReceipt>) = match plan.release_spec(
            &round_id,
            self.spec.training_execution_spec_id.as_deref(),
            &survivors,
        )? {
            None => (sum.iter().map(|&v| v as i64).collect(), vec![]),
            Some(r) => {
                let dir = self.ledger_dir.as_ref().ok_or_else(|| {
                    Error::new(
                        Code::PrivacyLedger,
                        "a DP round needs a privacy ledger directory",
                    )
                })?;
                let out =
                    encompute_privacy::release(&r, dir, &sum, &mut Csprng::from_os()?, &self.key)?;
                (out.noisy, out.receipts)
            }
        };
        let parents: Vec<String> = survivors
            .iter()
            .map(|p| plan.participant(p).expect("spec party").asset.clone())
            .collect();
        let eligible: Vec<PartyId> = plan.participants.iter().map(|p| p.party.clone()).collect();
        let manifest = AggregationManifest {
            version: RECEIPT_VERSION,
            round_id: round_id.clone(),
            round: self.round.clone(),
            spec_id: self.spec.id()?,
            policy_id: plan.policy_id.clone(),
            training_execution_spec_id: self.spec.training_execution_spec_id.clone(),
            output: plan.output.clone(),
            function: plan.function,
            protocol: self.spec.protocol.clone(),
            protocol_version: self.spec.protocol_version,
            codec: plan.codec,
            codec_id: codec_id(&plan.codec)?,
            vector_len: plan.vector_len,
            minimum: plan.minimum,
            threshold: self.spec.threshold,
            max_colluding: plan.colluding,
            dropped: eligible
                .iter()
                .filter(|p| !survivors.contains(p))
                .cloned()
                .collect(),
            eligible,
            advertised,
            contributors: survivors.clone(),
            metadata: survivors.iter().map(|p| self.metadata[p].clone()).collect(),
            contributions,
            confirmations,
            attestations: attestations
                .iter()
                .map(|(p, r)| Ok((p.clone(), r.id()?)))
                .collect::<Result<_>>()?,
            aggregate_commitment: aggregate_commitment(&round_id, &released),
            privacy: privacy.clone(),
            parents: parents.clone(),
        };
        let signature = hex(&self
            .key
            .sign(&tagged(RECEIPT_DOMAIN, &[&canonical_json(&manifest)?]))
            .to_bytes());
        let receipt = AggregationReceipt {
            manifest,
            coordinator_key: hex(&self.key.verifying_key().to_bytes()),
            signature,
        };
        let codec = &plan.codec;
        let values = released
            .iter()
            .map(|&s| {
                let total = codec.decode_sum(s, n);
                match plan.function {
                    AggregationFunction::Sum => total,
                    AggregationFunction::Mean => total / n as f64,
                }
            })
            .collect();
        let p = &plan.aggregate_policy;
        let receipt_id = receipt.id()?;
        let asset = AggregateAsset {
            asset_id: hex(&tagged(
                ASSET_DOMAIN,
                &[receipt_id.as_bytes(), plan.output.as_bytes()],
            )),
            output: plan.output.clone(),
            kind: plan.output_asset_kind,
            function: plan.function,
            values,
            encoded_sum: released,
            contributors: survivors.clone(),
            parents,
            policy: AggregatePolicy {
                owners: survivors.into_iter().collect(),
                audience: p.audience.clone(),
                purposes: p.purposes.clone(),
                release: p.release,
            },
            receipt_id,
            privacy,
        };
        Ok((asset, receipt))
    }
}

/// Checks a receipt against the spec its reader approved: the
/// coordinator's signature, the round, every contributor's signed
/// commitment and confirmation, the thresholds, attestations, and (with
/// the aggregate in hand) the aggregate commitment.
pub fn verify_aggregation_receipt(
    receipt: &AggregationReceipt,
    spec: &AggregationSpec,
    trusted_coordinator: Option<&str>,
    aggregate: Option<&AggregateAsset>,
) -> Result<()> {
    let bad = |m: String| Err(Error::new(Code::AggregationProtocol, m));
    let m = &receipt.manifest;
    if m.version != RECEIPT_VERSION {
        return bad(format!("aggregation receipt version {}", m.version));
    }
    if let Some(t) = trusted_coordinator {
        if t != receipt.coordinator_key {
            return Err(Error::new(
                Code::AggregationUnauthorized,
                "the receipt was signed by an untrusted coordinator",
            ));
        }
    }
    if receipt.coordinator_key != m.round.coordinator_key {
        return bad("the receipt's signer is not the round's coordinator".into());
    }
    let key = VerifyingKey::from_bytes(&unhex32(&receipt.coordinator_key, "coordinator key")?)
        .map_err(|_| Error::new(Code::AggregationProtocol, "coordinator key"))?;
    let sig = unhex(&receipt.signature)
        .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
        .ok_or_else(|| Error::new(Code::AggregationProtocol, "malformed receipt signature"))?;
    key.verify_strict(&tagged(RECEIPT_DOMAIN, &[&canonical_json(m)?]), &sig)
        .map_err(|_| {
            Error::new(
                Code::AggregationProtocol,
                "the aggregation receipt's signature is invalid",
            )
        })?;
    let spec_id = spec.id()?;
    if m.spec_id != spec_id || m.round.spec_id != spec_id {
        return Err(binding("the receipt is for another aggregation spec"));
    }
    if m.round_id != m.round.id()? {
        return bad("the receipt's round ID does not match its round".into());
    }
    let plan = &spec.plan;
    if m.policy_id != plan.policy_id || m.codec != plan.codec || m.vector_len != plan.vector_len {
        return Err(binding(
            "the receipt's policy, codec or shape differs from the spec",
        ));
    }
    if m.codec_id != codec_id(&plan.codec)? {
        return Err(binding("the receipt's codec ID differs from the spec"));
    }
    let params = spec.params(m.round_id.clone())?;
    let contributors: BTreeSet<&PartyId> = m.contributors.iter().collect();
    if m.contributors.len() < plan.minimum || m.contributors.len() < spec.threshold {
        return Err(Error::new(
            Code::AggregationThreshold,
            format!(
                "only {} contributors: below the minimum",
                m.contributors.len()
            ),
        ));
    }
    let stated: BTreeSet<&PartyId> = m.contributions.iter().map(|c| &c.body.party).collect();
    if stated != contributors || m.contributions.len() != contributors.len() {
        return bad("the contribution statements do not match the contributors".into());
    }
    for c in &m.contributions {
        verify_contribution(&params, c)?;
    }
    let described: BTreeSet<&PartyId> = m.metadata.iter().map(|d| &d.body.party).collect();
    if described != contributors || m.metadata.len() != contributors.len() {
        return bad("the contribution metadata does not match the contributors".into());
    }
    for d in &m.metadata {
        let b = &d.body;
        let key = spec
            .parties
            .iter()
            .find(|p| p.party == b.party)
            .map(|p| p.public_key.clone())
            .ok_or_else(|| Error::new(Code::AggregationUnauthorized, "unknown contributor"))?;
        crate::crypto::verify(
            &unhex32(&key, "key")?,
            METADATA_DOMAIN,
            &canonical_json(b)?,
            &d.signature,
        )?;
        let asset = &plan.participant(&b.party).expect("in spec").asset;
        if b.round_id != m.round_id
            || &b.asset_id != asset
            || b.policy_id != plan.policy_id
            || b.execution_spec_id != spec.training_execution_spec_id
            || b.codec_id != m.codec_id
            || b.vector_len != plan.vector_len
            || b.attestation_id.as_ref() != m.attestations.get(&b.party)
        {
            return Err(binding(format!(
                "{}'s signed metadata does not match the round",
                b.party
            )));
        }
    }
    let mut confirmed = BTreeSet::new();
    for c in &m.confirmations {
        verify_confirmation(&params, c)?;
        if c.body.survivors != m.contributors {
            return bad(format!(
                "{} confirmed a different contributor set",
                c.body.party
            ));
        }
        confirmed.insert(&c.body.party);
    }
    if confirmed.len() < spec.threshold || !confirmed.is_subset(&contributors) {
        return Err(Error::new(
            Code::AggregationThreshold,
            "too few contributors confirmed the contributor set",
        ));
    }
    if spec.attestation.is_some() && m.attestations.keys().collect::<BTreeSet<_>>() != contributors
    {
        return Err(Error::new(
            Code::AggregationUnauthorized,
            "the spec requires every contributor to be attested",
        ));
    }
    if let Some(a) = aggregate {
        if aggregate_commitment(&m.round_id, &a.encoded_sum) != m.aggregate_commitment
            || a.receipt_id != receipt.id()?
        {
            return bad("the aggregate does not match the receipt".into());
        }
    }
    Ok(())
}

/// A party's aggregation identity key.
pub fn party_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub fn identity_of(party: &PartyId, key: &SigningKey) -> PartyIdentity {
    PartyIdentity {
        party: party.clone(),
        public_key: hex(&key.verifying_key().to_bytes()),
    }
}
