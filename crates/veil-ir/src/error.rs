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
    /// The `.vlir` text is malformed.
    Parse,
    /// Compiled artifact is missing, corrupt or from another version.
    Artifact,
    /// A backend (e.g. OpenFHE) reported an error.
    Backend,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::SecretControlFlow => "VEIL1001",
            Code::SecretDivision => "VEIL1002",
            Code::SecretComparison => "VEIL1003",
            Code::SecretToPublic => "VEIL1004",
            Code::Unsupported => "VEIL1005",
            Code::MissingRange => "VEIL1101",
            Code::BadInput => "VEIL1102",
            Code::DepthExceeded => "VEIL1201",
            Code::PrecisionUnreachable => "VEIL1202",
            Code::Type => "VEIL1301",
            Code::Parse => "VEIL1302",
            Code::Artifact => "VEIL1401",
            Code::Backend => "VEIL1501",
        }
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
