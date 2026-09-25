//! Encompute's assurance suite: for every documented security invariant, a
//! check that tries to break it through the public interfaces, at a quick
//! (pull request) or nightly scale. Not production code: it adds no
//! functionality, it only attacks.
//!
//! Testing cannot prove the cryptography secure. What this suite
//! establishes is narrower: the documented invariants hold under their
//! stated threat models, across the tested execution modes and integration
//! boundaries.

pub mod catalog;
pub mod checks;
pub mod mutate;
pub mod report;

use serde::Serialize;

/// How hard a check tries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scale {
    /// Pull requests: seconds per check.
    Quick,
    /// Nightly: larger populations, more processes, more samples.
    Nightly,
}

impl Scale {
    /// `quick` or `nightly` cases.
    pub fn pick(self, quick: usize, nightly: usize) -> usize {
        match self {
            Scale::Quick => quick,
            Scale::Nightly => nightly,
        }
    }
}

/// What a check did.
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    /// Attacks or cases tried.
    pub cases: usize,
    pub notes: Vec<String>,
}

impl Outcome {
    pub fn new(cases: usize) -> Self {
        Self {
            cases,
            notes: vec![],
        }
    }

    pub fn note(mut self, n: impl Into<String>) -> Self {
        self.notes.push(n.into());
        self
    }
}

/// A violated invariant: what got through.
pub type Violation = String;

pub type CheckResult = std::result::Result<Outcome, Violation>;

/// Fails the check with a message unless `cond`.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        // Bound first: a NaN comparison is false, so it fails the check.
        {
            let holds: bool = $cond;
            if !holds {
                return Err(format!($($arg)*));
            }
        }
    };
}

/// A unique scratch directory.
pub fn scratch(name: &str) -> std::path::PathBuf {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("randomness");
    let d = std::env::temp_dir().join(format!(
        "encompute-assurance-{name}-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

/// A uniform `u64` from the OS (test data, not secrets).
pub fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("randomness");
    u64::from_le_bytes(b)
}

/// Uniform in `[-1, 1)`.
pub fn rand_unit() -> f64 {
    (rand_u64() >> 11) as f64 / (1u64 << 53) as f64 * 2.0 - 1.0
}

/// Runs one check, turning a panic into a violation.
pub fn run_check(c: &checks::Check, scale: Scale) -> CheckResult {
    std::panic::catch_unwind(|| (c.run)(scale)).unwrap_or_else(|p| {
        Err(format!(
            "panicked: {}",
            p.downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| p.downcast_ref::<&str>().copied())
                .unwrap_or("(no message)")
        ))
    })
}
