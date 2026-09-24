use std::cell::RefCell;
use std::collections::BTreeSet;

use encompute_ckks::CkksParams;
use encompute_ir::{Code, Error, Result};

use crate::rng::Rng;
use crate::CkksBackend;

/// Mock backend options.
#[derive(Clone, Debug)]
pub struct MockConfig {
    pub seed: u64,
    /// Add Gaussian noise of CKKS-like size on encryption, multiplication
    /// and rotation. Off gives exact plan semantics.
    pub noise: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            seed: 0,
            noise: true,
        }
    }
}

/// Runs plans on plaintext slot vectors while enforcing what a real CKKS
/// backend would: the depth budget, available rotation keys, slot count
/// and key ownership. Level and rotation-key bugs show up without OpenFHE.
pub struct MockBackend {
    slots: usize,
    ring_dim: usize,
    mult_depth: u32,
    rotations: BTreeSet<u32>,
    sigma: f64,
    key_id: u64,
    rng: RefCell<Rng>,
}

pub struct MockSecretKey {
    key_id: u64,
}

#[derive(Clone, Debug)]
pub struct MockCiphertext {
    values: Vec<f64>,
    level: u32,
    key_id: u64,
}

impl MockCiphertext {
    /// Multiplicative depth consumed so far.
    pub fn level(&self) -> u32 {
        self.level
    }
}

impl MockBackend {
    pub fn new(
        params: &CkksParams,
        rotations: &[u32],
        config: MockConfig,
    ) -> (Self, MockSecretKey) {
        let mut rng = Rng::new(config.seed);
        let key_id = rng.next_u64();
        // CKKS loses roughly 15–20 bits below the scale to encoding and
        // rescaling noise; this is an order-of-magnitude model only.
        let sigma = if config.noise {
            2f64.powi(-(params.scale_bits as i32 - 17))
        } else {
            0.0
        };
        let backend = Self {
            slots: params.slots as usize,
            ring_dim: params.ring_dim as usize,
            mult_depth: params.mult_depth,
            rotations: rotations.iter().copied().collect(),
            sigma,
            key_id,
            rng: RefCell::new(rng),
        };
        (backend, MockSecretKey { key_id })
    }

    fn err(msg: impl Into<String>) -> Error {
        Error::new(Code::Backend, format!("mock: {}", msg.into()))
    }

    fn check_len(&self, v: &[f64]) -> Result<()> {
        if v.len() != self.slots {
            return Err(Self::err(format!(
                "expected {} slots, got {}",
                self.slots,
                v.len()
            )));
        }
        Ok(())
    }

    fn check_pair(&self, a: &MockCiphertext, b: &MockCiphertext) -> Result<()> {
        if a.key_id != self.key_id || b.key_id != self.key_id {
            return Err(Self::err("ciphertext belongs to another key"));
        }
        Ok(())
    }

    fn noisy(&self, mut values: Vec<f64>, level: u32) -> Result<MockCiphertext> {
        if level > self.mult_depth {
            return Err(Self::err(format!(
                "depth budget exhausted: level {level} > multiplicative depth {}",
                self.mult_depth
            )));
        }
        if self.sigma > 0.0 {
            let mut rng = self.rng.borrow_mut();
            for v in &mut values {
                *v += self.sigma * rng.normal();
            }
        }
        Ok(MockCiphertext {
            values,
            level,
            key_id: self.key_id,
        })
    }

    fn exact(&self, values: Vec<f64>, level: u32) -> MockCiphertext {
        MockCiphertext {
            values,
            level,
            key_id: self.key_id,
        }
    }

    fn zip(a: &MockCiphertext, b: &[f64], f: impl Fn(f64, f64) -> f64) -> Vec<f64> {
        a.values.iter().zip(b).map(|(&x, &y)| f(x, y)).collect()
    }
}

impl CkksBackend for MockBackend {
    type Ciphertext = MockCiphertext;
    type SecretKey = MockSecretKey;

    fn name(&self) -> &'static str {
        "mock"
    }

    fn slots(&self) -> usize {
        self.slots
    }

    fn encrypt(&self, values: &[f64]) -> Result<MockCiphertext> {
        self.check_len(values)?;
        self.noisy(values.to_vec(), 0)
    }

    fn decrypt(&self, sk: &MockSecretKey, ct: &MockCiphertext) -> Result<Vec<f64>> {
        if sk.key_id != ct.key_id {
            return Err(Self::err("secret key does not match ciphertext"));
        }
        Ok(ct.values.clone())
    }

    fn add(&self, a: &MockCiphertext, b: &MockCiphertext) -> Result<MockCiphertext> {
        self.check_pair(a, b)?;
        Ok(self.exact(Self::zip(a, &b.values, |x, y| x + y), a.level.max(b.level)))
    }

    fn sub(&self, a: &MockCiphertext, b: &MockCiphertext) -> Result<MockCiphertext> {
        self.check_pair(a, b)?;
        Ok(self.exact(Self::zip(a, &b.values, |x, y| x - y), a.level.max(b.level)))
    }

    fn neg(&self, a: &MockCiphertext) -> Result<MockCiphertext> {
        Ok(self.exact(a.values.iter().map(|x| -x).collect(), a.level))
    }

    fn mul(&self, a: &MockCiphertext, b: &MockCiphertext) -> Result<MockCiphertext> {
        self.check_pair(a, b)?;
        self.noisy(
            Self::zip(a, &b.values, |x, y| x * y),
            a.level.max(b.level) + 1,
        )
    }

    fn add_plain(&self, a: &MockCiphertext, p: &[f64]) -> Result<MockCiphertext> {
        self.check_len(p)?;
        Ok(self.exact(Self::zip(a, p, |x, y| x + y), a.level))
    }

    fn mul_plain(&self, a: &MockCiphertext, p: &[f64]) -> Result<MockCiphertext> {
        self.check_len(p)?;
        self.noisy(Self::zip(a, p, |x, y| x * y), a.level + 1)
    }

    fn add_const(&self, a: &MockCiphertext, c: f64) -> Result<MockCiphertext> {
        Ok(self.exact(a.values.iter().map(|x| x + c).collect(), a.level))
    }

    fn mul_const(&self, a: &MockCiphertext, c: f64) -> Result<MockCiphertext> {
        self.noisy(a.values.iter().map(|x| x * c).collect(), a.level + 1)
    }

    fn rotate(&self, a: &MockCiphertext, k: u32) -> Result<MockCiphertext> {
        if !self.rotations.contains(&k) {
            return Err(Self::err(format!("no rotation key for {k}")));
        }
        let n = self.slots;
        let values = (0..n).map(|i| a.values[(i + k as usize) % n]).collect();
        self.noisy(values, a.level)
    }

    /// What OpenFHE would serialize: two ring elements over the towers left
    /// at this level, 8 bytes per coefficient (estimate; excludes headers).
    fn ciphertext_bytes(&self, ct: &MockCiphertext) -> Result<usize> {
        let towers = (self.mult_depth + 1 - ct.level) as usize;
        Ok(2 * self.ring_dim * towers * 8)
    }
}
