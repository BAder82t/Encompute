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
        }
    }
}

impl Code {
    /// Every code, for parsing codes received over the network.
    pub const ALL: [Code; 46] = [
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
