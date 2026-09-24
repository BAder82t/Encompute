use std::fmt;

use serde::{Deserialize, Serialize};

/// Index of a node in its [`crate::Program`]; printed as `%n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValueId(pub u32);

impl ValueId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "%{}", self.0)
    }
}

/// Whether a value is encrypted (`Secret`) or known to the evaluator (`Public`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Secret,
    Public,
}

impl Visibility {
    /// Secret if either side is secret.
    pub fn join(self, other: Visibility) -> Visibility {
        if self == Visibility::Secret || other == Visibility::Secret {
            Visibility::Secret
        } else {
            Visibility::Public
        }
    }
}

/// Value shape. Matrices exist only as public constants feeding `matvec`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Shape {
    Scalar,
    Vector(usize),
    /// Rows, columns; row-major.
    Matrix(usize, usize),
}

impl Shape {
    /// Number of elements.
    pub fn len(self) -> usize {
        match self {
            Shape::Scalar => 1,
            Shape::Vector(n) => n,
            Shape::Matrix(r, c) => r * c,
        }
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Shape::Scalar => f.write_str("scalar"),
            Shape::Vector(n) => write!(f, "vector<{n}>"),
            Shape::Matrix(r, c) => write!(f, "matrix<{r}x{c}>"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Type {
    pub visibility: Visibility,
    pub shape: Shape,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = match self.visibility {
            Visibility::Secret => "secret",
            Visibility::Public => "public",
        };
        write!(f, "{v} {}", self.shape)
    }
}

/// Closed interval `[lo, hi]` declared for every element of an input.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Range {
    pub lo: f64,
    pub hi: f64,
}

impl Range {
    pub fn new(lo: f64, hi: f64) -> Self {
        Self { lo, hi }
    }

    pub fn contains(self, x: f64) -> bool {
        self.lo <= x && x <= self.hi
    }

    pub(crate) fn is_valid(self) -> bool {
        self.lo.is_finite() && self.hi.is_finite() && self.lo < self.hi
    }
}
