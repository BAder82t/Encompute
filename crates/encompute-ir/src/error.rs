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
        }
    }
}

impl Code {
    /// Every code, for parsing codes received over the network.
    pub const ALL: [Code; 22] = [
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
