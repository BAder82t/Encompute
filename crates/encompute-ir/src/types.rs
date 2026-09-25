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

/// Element type. `F64` is approximate (CKKS); the others are exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Elem {
    F64,
    Bool,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
}

impl Elem {
    pub const EXACT: [Elem; 9] = [
        Elem::Bool,
        Elem::I8,
        Elem::I16,
        Elem::I32,
        Elem::I64,
        Elem::U8,
        Elem::U16,
        Elem::U32,
        Elem::U64,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Elem::F64 => "f64",
            Elem::Bool => "bool",
            Elem::I8 => "i8",
            Elem::I16 => "i16",
            Elem::I32 => "i32",
            Elem::I64 => "i64",
            Elem::U8 => "u8",
            Elem::U16 => "u16",
            Elem::U32 => "u32",
            Elem::U64 => "u64",
        }
    }

    pub fn parse(s: &str) -> Option<Elem> {
        Elem::EXACT
            .into_iter()
            .chain([Elem::F64])
            .find(|e| e.name() == s)
    }

    pub fn is_exact(self) -> bool {
        self != Elem::F64
    }

    pub fn is_int(self) -> bool {
        !matches!(self, Elem::F64 | Elem::Bool)
    }

    pub fn is_signed(self) -> bool {
        matches!(self, Elem::I8 | Elem::I16 | Elem::I32 | Elem::I64)
    }

    /// Bit width (1 for bool).
    pub fn bits(self) -> u32 {
        match self {
            Elem::Bool => 1,
            Elem::I8 | Elem::U8 => 8,
            Elem::I16 | Elem::U16 => 16,
            Elem::I32 | Elem::U32 => 32,
            Elem::I64 | Elem::U64 | Elem::F64 => 64,
        }
    }

    /// Smallest and largest representable value (exact types).
    pub fn bounds(self) -> (i128, i128) {
        match self {
            Elem::Bool => (0, 1),
            e if e.is_signed() => {
                let b = e.bits() - 1;
                (-(1i128 << b), (1i128 << b) - 1)
            }
            e => (0, (1i128 << e.bits()) - 1),
        }
    }
}

impl fmt::Display for Elem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Type {
    pub visibility: Visibility,
    pub shape: Shape,
    pub elem: Elem,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = match self.visibility {
            Visibility::Secret => "secret",
            Visibility::Public => "public",
        };
        // Approximate values print by shape (as in 0.1/0.2); exact scalars
        // print by element type.
        if self.elem == Elem::F64 {
            write!(f, "{v} {}", self.shape)
        } else {
            write!(f, "{v} {}", self.elem)
        }
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
