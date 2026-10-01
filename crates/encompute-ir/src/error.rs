use std::fmt;

/// Stable diagnostic codes. See `docs/errors.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    /// Python control flow on a secret value.
    SecretControlFlow,
    /// Division by a secret value.
    SecretDivision,
    /// Comparison of secret values.
    SecretComparison,
    /// A secret value flows into a public sink.
    SecretToPublic,
    /// Unsupported operation on a secret value in this version.
    Unsupported,
    /// An input has no declared range.
    MissingRange,
    /// An input value is outside its declared range, or has the wrong length.
    BadInput,
    /// Depth exceeds the largest 128-bit parameter set without bootstrapping.
    DepthExceeded,
    /// Requested precision is unreachable.
    PrecisionUnreachable,
    /// The program violates an IR type rule.
    Type,
    /// The `.eir` text is malformed.
    Parse,
    /// An exact integer operation may overflow its type.
    Overflow,
    /// Compiled artifact is missing, corrupt or from another version.
    Artifact,
    /// A backend (e.g. OpenFHE) reported an error.
    Backend,
    /// An envelope is malformed, truncated or fails its checksum.
    Envelope,
    /// An envelope is of the wrong kind, format, scheme or backend version.
    Incompatible,
    /// An object was made for a different parameter set.
    WrongParameters,
    /// An object was made for a different program.
    WrongProgram,
    /// An object was made under a different or unregistered key.
    WrongKey,
    /// An execution receipt is malformed, unsigned, from an untrusted
    /// evaluator, or does not match the execution.
    Receipt,
    /// A network or protocol failure between client and evaluator.
    Remote,
    /// A semantic transcript is malformed, of an unknown version, or does
    /// not match the plan or the verification metadata.
    Transcript,
    /// An execution proof is missing, malformed or invalid, or a program
    /// requiring verified execution cannot be fully proven.
    Unverified,
    /// A confidential value flows to a public output (ENC1901).
    PublicRelease,
    /// A value is revealed to a party that may not learn it (ENC1902).
    UnauthorizedParty,
    /// An asset is used for a purpose it does not allow (ENC1903).
    PurposeViolation,
    /// A derivation weakens a policy more than its source assets allow
    /// (ENC1904).
    Declassification,
    /// An aggregate-only value is revealed without an aggregation boundary
    /// (ENC1905).
    AggregationRequired,
    /// Confidentiality declarations are malformed (ENC1906).
    PolicyDeclaration,
    /// A released value's form is not one its sources allow, or the
    /// compiler cannot prove it is (ENC1907).
    ReleaseForm,
    /// Attestation evidence is malformed, forged, tampered with, from an
    /// unknown provider, or does not bind the claimed workload (ENC2001).
    Attestation,
    /// A verified workload does not satisfy the attestation policy: wrong
    /// image, TEE, TCB, debug state, execution spec or policy (ENC2002).
    WorkloadPolicy,
    /// Attestation evidence or a challenge is stale, expired, unknown or
    /// replayed (ENC2003).
    Freshness,
    /// A key release was refused: unknown asset or session, revoked key, or
    /// a grant that does not belong to this session (ENC2004).
    KeyRelease,
    /// A party is not authorized for an aggregation round, or its
    /// contribution is not signed by its identity (ENC2101).
    AggregationUnauthorized,
    /// A contribution is bound to another round, spec, policy, shape or
    /// codec; or is a duplicate or replay (ENC2102).
    AggregationBinding,
    /// Too few participants remain to release an aggregate (ENC2103).
    AggregationThreshold,
    /// A secure-aggregation protocol message is malformed, tampered or out
    /// of order, or the aggregate cannot be reconstructed (ENC2104).
    AggregationProtocol,
    /// The aggregation encoding may overflow its modulus (ENC2105).
    AggregationOverflow,
    /// An aggregation declaration is invalid: not a sum of distinct
    /// parties' inputs, bad codec, or an impossible threshold (ENC2106).
    AggregationPlan,
    /// A release would exceed an asset's privacy budget (ENC2201).
    PrivacyBudgetExceeded,
    /// A privacy ledger is malformed, tampered, rolled back, reset or for
    /// another asset or policy (ENC2202).
    PrivacyLedger,
    /// Privacy declarations are invalid, or a budgeted asset would be
    /// released without a privacy mechanism (ENC2203).
    PrivacyPolicy,
    /// A privacy mechanism, its parameters, randomness or receipt do not
    /// match the approved configuration (ENC2204).
    PrivacyMechanism,
    /// A trust-graph evidence item is malformed or does not verify
    /// (ENC2301).
    TrustEvidence,
    /// An owner authorization is missing, invalid, expired or revoked
    /// (ENC2302).
    TrustAuthorization,
    /// The trust graph is inconsistent: a dangling edge, broken lineage,
    /// or a node that contradicts its evidence (ENC2303).
    TrustGraph,
    /// No combination of available mechanisms satisfies every trust
    /// requirement: PLANNING FAILED (ENC2401).
    PlanningFailed,
    /// A confidential execution plan does not satisfy its requirements, or
    /// claims mechanisms that are unavailable or unsupported (ENC2402).
    PlanInvalid,
    /// Execution or evidence does not match the approved plan (ENC2403).
    PlanMismatch,
    /// A training run, worker or artifact does not match the approved
    /// training specification (ENC2501).
    TrainingSpec,
    /// A checkpoint or sealed artifact is corrupted, from another project
    /// or run, or behind the authoritative privacy ledger (ENC2502).
    Checkpoint,
    /// EXPORT DENIED: a derived asset inherits a release restriction
    /// (ENC2503).
    ExportDenied,
    /// A model package is refused: a mutable revision, remote code, pickled
    /// weights, an unsupported file or architecture, or incompatible
    /// library versions (ENC2504).
    ModelPackage,
    /// No valid credentials: missing, expired, forged or development
    /// credentials in production (ENC2601).
    Unauthenticated,
    /// The identity lacks the role for this action (ENC2602).
    Forbidden,
    /// No such resource visible to this identity; resources of other
    /// organizations are reported the same way (ENC2603).
    NotFound,
    /// The request conflicts with the resource's state: an invalid job
    /// transition, a reused idempotency key, a revoked asset (ENC2604).
    Conflict,
    /// An insecure configuration was refused (production mode rejects
    /// development identities, key stores and credentials) (ENC2605).
    InsecureConfiguration,
    /// No registered evaluator can run the job's backend and parameter
    /// profile (ENC2606).
    Scheduling,
    /// A service request or message is unsigned, from an unknown service,
    /// for another recipient, expired or replayed (ENC2607).
    ServiceAuthentication,
    /// A governed project's source has no active owner-signed authorization, or an authorization's owner signature does not verify against the organization's active governance key (ENC2701).
    GovernanceAuthorizationMissing,
    /// The purpose of a governed job, program or authorization differs from the governed purpose, or the purpose is not active or not accepted (ENC2702).
    GovernancePurposeMismatch,
    /// The program (or program set) is not the one the owner authorized (ENC2703).
    GovernanceProgramNotAuthorized,
    /// A dataset version does not match the authorized version, or a registered version would change (ENC2704).
    GovernanceAssetVersionMismatch,
    /// An authorization or purpose is outside its validity window (expiry is strict) (ENC2705).
    GovernanceAuthorizationExpired,
    /// An authorization or purpose was withdrawn, revoked or retired (ENC2706).
    GovernanceAuthorizationRevoked,
    /// Four-eyes approval is incomplete: distinct humans of the approving organization are required (ENC2707).
    GovernanceFourEyesIncomplete,
    /// The organization's governance key is revoked, not approved, or absent (ENC2708).
    GovernanceKeyRevoked,
    /// A release exceeds its release class or output form (ENC2709).
    GovernanceReleaseClass,
    /// Residency or placement constraints are unsatisfied (ENC2710).
    GovernanceResidency,
    /// The linkage policy differs from the authorized one (ENC2711).
    GovernanceLinkageMismatch,
    /// A key-release ticket is invalid, expired or replayed (ENC2712).
    GovernanceReleaseTicket,
    /// A key broker's state is older than, or forked from, the generation mark kept in the organization's KMS, or the mark cannot be read or advanced (ENC2713).
    GovernanceBrokerStateRollback,
    /// An owner authorization's usage limit (releases or executions) is exhausted at the key broker (ENC2714).
    GovernanceAuthorizationLimit,
    /// Key custody refused: in a sovereign project an asset's key must be held by a key broker its own organization registered, never a platform broker or another organization's (ENC2715).
    GovernanceCustody,
    /// Auditor separation: an auditor is read-only and exclusive of every other role in an organization taking part in a governed project, and an auditor organization never owns, submits, receives, approves or holds keys there (ENC2716).
    GovernanceAuditorSeparation,
    /// A revocation head refused: it is not the next head of its organization in the project (a skipped or repeated number, a date in the future or before the previous head), its root is not the control plane's own fold of the organization's revocations in the log, or it is for another project or an organization that does not take part (ENC2717).
    GovernanceRevocationHead,
    /// A checkpoint witness refused: it does not witness the control plane's stored checkpoint of the project at that size (another size, partition or root), so it cannot count towards it (ENC2718).
    GovernanceCheckpointWitness,
    /// A location declaration or registration refused: the caller is not a person who is a security admin of the evaluator's operator organization, the location is not one the locations table knows (or its jurisdiction or zone is inconsistent), an attested location is not replaced by a declaration, or location evidence is stale or too weak for the claim (ENC2723).
    GovernanceLocationEvidence,
    /// A project's placement constraints were not changed: the constraints are invalid (an unknown region, an empty allow list), the change is not based on the current version, the project is not governed, or the change loosens them and not every member organization has proposed it yet (ENC2724).
    GovernancePlacementChange,
    /// Operator separation refused: every evaluator that could run the job is operated by a source owner or by an organization that holds a decryption key for the output, or a SecAgg coordinator is also a contributor (ENC2725).
    GovernanceOperatorSeparation,
    /// A client refused to send ciphertexts to an evaluator outside its own placement constraints: the evaluator it pinned is at a location, operated by an organization, or known by evidence the constraints do not admit, or the pin set says nothing about where it is (ENC2726).
    GovernanceClientPlacement,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::SecretControlFlow => "ENC1001",
            Code::SecretDivision => "ENC1002",
            Code::SecretComparison => "ENC1003",
            Code::SecretToPublic => "ENC1004",
            Code::Unsupported => "ENC1005",
            Code::MissingRange => "ENC1101",
            Code::BadInput => "ENC1102",
            Code::DepthExceeded => "ENC1201",
            Code::PrecisionUnreachable => "ENC1202",
            Code::Type => "ENC1301",
            Code::Parse => "ENC1302",
            Code::Overflow => "ENC1303",
            Code::Artifact => "ENC1401",
            Code::Backend => "ENC1501",
            Code::Envelope => "ENC1601",
            Code::Incompatible => "ENC1602",
            Code::WrongParameters => "ENC1603",
            Code::WrongProgram => "ENC1604",
            Code::WrongKey => "ENC1605",
            Code::Receipt => "ENC1606",
            Code::Remote => "ENC1701",
            Code::Transcript => "ENC1702",
            Code::Unverified => "ENC1801",
            Code::PublicRelease => "ENC1901",
            Code::UnauthorizedParty => "ENC1902",
            Code::PurposeViolation => "ENC1903",
            Code::Declassification => "ENC1904",
            Code::AggregationRequired => "ENC1905",
            Code::PolicyDeclaration => "ENC1906",
            Code::ReleaseForm => "ENC1907",
            Code::Attestation => "ENC2001",
            Code::WorkloadPolicy => "ENC2002",
            Code::Freshness => "ENC2003",
            Code::KeyRelease => "ENC2004",
            Code::AggregationUnauthorized => "ENC2101",
            Code::AggregationBinding => "ENC2102",
            Code::AggregationThreshold => "ENC2103",
            Code::AggregationProtocol => "ENC2104",
            Code::AggregationOverflow => "ENC2105",
            Code::AggregationPlan => "ENC2106",
            Code::PrivacyBudgetExceeded => "ENC2201",
            Code::PrivacyLedger => "ENC2202",
            Code::PrivacyPolicy => "ENC2203",
            Code::PrivacyMechanism => "ENC2204",
            Code::TrustEvidence => "ENC2301",
            Code::TrustAuthorization => "ENC2302",
            Code::TrustGraph => "ENC2303",
            Code::PlanningFailed => "ENC2401",
            Code::PlanInvalid => "ENC2402",
            Code::PlanMismatch => "ENC2403",
            Code::TrainingSpec => "ENC2501",
            Code::Checkpoint => "ENC2502",
            Code::ExportDenied => "ENC2503",
            Code::ModelPackage => "ENC2504",
            Code::Unauthenticated => "ENC2601",
            Code::Forbidden => "ENC2602",
            Code::NotFound => "ENC2603",
            Code::Conflict => "ENC2604",
            Code::InsecureConfiguration => "ENC2605",
            Code::Scheduling => "ENC2606",
            Code::ServiceAuthentication => "ENC2607",
            Code::GovernanceAuthorizationMissing => "ENC2701",
            Code::GovernancePurposeMismatch => "ENC2702",
            Code::GovernanceProgramNotAuthorized => "ENC2703",
            Code::GovernanceAssetVersionMismatch => "ENC2704",
            Code::GovernanceAuthorizationExpired => "ENC2705",
            Code::GovernanceAuthorizationRevoked => "ENC2706",
            Code::GovernanceFourEyesIncomplete => "ENC2707",
            Code::GovernanceKeyRevoked => "ENC2708",
            Code::GovernanceReleaseClass => "ENC2709",
            Code::GovernanceResidency => "ENC2710",
            Code::GovernanceLinkageMismatch => "ENC2711",
            Code::GovernanceReleaseTicket => "ENC2712",
            Code::GovernanceBrokerStateRollback => "ENC2713",
            Code::GovernanceAuthorizationLimit => "ENC2714",
            Code::GovernanceCustody => "ENC2715",
            Code::GovernanceAuditorSeparation => "ENC2716",
            Code::GovernanceRevocationHead => "ENC2717",
            Code::GovernanceCheckpointWitness => "ENC2718",
            Code::GovernanceLocationEvidence => "ENC2723",
            Code::GovernancePlacementChange => "ENC2724",
            Code::GovernanceOperatorSeparation => "ENC2725",
            Code::GovernanceClientPlacement => "ENC2726",
        }
    }
}

impl Code {
    /// Every code, for parsing codes received over the network.
    pub const ALL: [Code; 83] = [
        Code::SecretControlFlow,
        Code::SecretDivision,
        Code::SecretComparison,
        Code::SecretToPublic,
        Code::Unsupported,
        Code::MissingRange,
        Code::BadInput,
        Code::DepthExceeded,
        Code::PrecisionUnreachable,
        Code::Type,
        Code::Parse,
        Code::Overflow,
        Code::Artifact,
        Code::Backend,
        Code::Envelope,
        Code::Incompatible,
        Code::WrongParameters,
        Code::WrongProgram,
        Code::WrongKey,
        Code::Receipt,
        Code::Remote,
        Code::Transcript,
        Code::Unverified,
        Code::PublicRelease,
        Code::UnauthorizedParty,
        Code::PurposeViolation,
        Code::Declassification,
        Code::AggregationRequired,
        Code::PolicyDeclaration,
        Code::ReleaseForm,
        Code::Attestation,
        Code::WorkloadPolicy,
        Code::Freshness,
        Code::KeyRelease,
        Code::AggregationUnauthorized,
        Code::AggregationBinding,
        Code::AggregationThreshold,
        Code::AggregationProtocol,
        Code::AggregationOverflow,
        Code::AggregationPlan,
        Code::PrivacyBudgetExceeded,
        Code::PrivacyLedger,
        Code::PrivacyPolicy,
        Code::PrivacyMechanism,
        Code::TrustEvidence,
        Code::TrustAuthorization,
        Code::TrustGraph,
        Code::PlanningFailed,
        Code::PlanInvalid,
        Code::PlanMismatch,
        Code::TrainingSpec,
        Code::Checkpoint,
        Code::ExportDenied,
        Code::ModelPackage,
        Code::Unauthenticated,
        Code::Forbidden,
        Code::NotFound,
        Code::Conflict,
        Code::InsecureConfiguration,
        Code::Scheduling,
        Code::ServiceAuthentication,
        Code::GovernanceAuthorizationMissing,
        Code::GovernancePurposeMismatch,
        Code::GovernanceProgramNotAuthorized,
        Code::GovernanceAssetVersionMismatch,
        Code::GovernanceAuthorizationExpired,
        Code::GovernanceAuthorizationRevoked,
        Code::GovernanceFourEyesIncomplete,
        Code::GovernanceKeyRevoked,
        Code::GovernanceReleaseClass,
        Code::GovernanceResidency,
        Code::GovernanceLinkageMismatch,
        Code::GovernanceReleaseTicket,
        Code::GovernanceBrokerStateRollback,
        Code::GovernanceAuthorizationLimit,
        Code::GovernanceCustody,
        Code::GovernanceAuditorSeparation,
        Code::GovernanceRevocationHead,
        Code::GovernanceCheckpointWitness,
        Code::GovernanceLocationEvidence,
        Code::GovernancePlacementChange,
        Code::GovernanceOperatorSeparation,
        Code::GovernanceClientPlacement,
    ];

    pub fn parse(s: &str) -> Option<Code> {
        Code::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A diagnostic with a stable code and a human-readable explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub message: String,
}

impl Error {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn type_error(message: impl Into<String>) -> Error {
    Error::new(Code::Type, message)
}
