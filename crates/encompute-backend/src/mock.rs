//! Mock backend: plaintext slot vectors, CKKS-like noise, real byte
//! serialization. It enforces what a real CKKS backend would: the depth
//! budget, the rotation keys the client exported, slot counts, and key
//! ownership, so key, level and rotation bugs show up without OpenFHE.

use std::cell::RefCell;

use encompute_ckks::CkksParams;
use encompute_ir::{Code, Error, Result};

use crate::rng::Rng;
use crate::{CkksClient, CkksEvaluator};

#[derive(Clone, Debug)]
pub struct MockConfig {
    pub seed: u64,
    /// Add Gaussian noise of CKKS-like size on encryption, multiplication and
    /// rotation. Off gives exact plan semantics.
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

const CT_MAGIC: &[u8; 8] = b"MOCKCT01";
const EK_MAGIC: &[u8; 8] = b"MOCKEK01";
const SK_MAGIC: &[u8; 8] = b"MOCKSK01";

fn err(msg: impl Into<String>) -> Error {
    Error::new(Code::Backend, format!("mock: {}", msg.into()))
}

/// CKKS loses roughly 15–20 bits below the scale to encoding and rescaling;
/// an order-of-magnitude model only.
fn sigma(params: &CkksParams, config: &MockConfig) -> f64 {
    if config.noise {
        2f64.powi(-(params.scale_bits as i32 - 17))
    } else {
        0.0
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.0.len() < n {
            return Err(err("truncated data"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn f64(&mut self) -> Result<f64> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn magic(&mut self, m: &[u8; 8]) -> Result<()> {
        if self.take(8)? != m {
            return Err(err("not a mock object of this kind"));
        }
        Ok(())
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(err("trailing bytes"))
        }
    }
}

fn store(values: &[f64], level: u32, key_id: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(28 + 8 * values.len());
    b.extend_from_slice(CT_MAGIC);
    b.extend_from_slice(&key_id.to_le_bytes());
    b.extend_from_slice(&level.to_le_bytes());
    b.extend_from_slice(&(values.len() as u32).to_le_bytes());
    for v in values {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b
}

fn load(bytes: &[u8], key_id: u64, slots: usize) -> Result<MockCiphertext> {
    let mut r = Reader(bytes);
    r.magic(CT_MAGIC)?;
    let id = r.u64()?;
    let level = r.u32()?;
    let n = r.u32()? as usize;
    if id != key_id {
        return Err(err("ciphertext was encrypted under another key"));
    }
    if n != slots {
        return Err(err(format!("ciphertext has {n} slots, expected {slots}")));
    }
    let values = (0..n).map(|_| r.f64()).collect::<Result<Vec<_>>>()?;
    r.end()?;
    Ok(MockCiphertext { values, level })
}

/// Client: owns the (simulated) secret key.
pub struct MockClient {
    slots: usize,
    mult_depth: u32,
    rotations: Vec<u32>,
    key_id: u64,
    sigma: f64,
    rng: RefCell<Rng>,
}

impl MockClient {
    pub fn new(params: &CkksParams, rotations: &[u32], config: MockConfig) -> Self {
        let mut rng = Rng::new(config.seed);
        let key_id = rng.next_u64();
        Self {
            slots: params.slots as usize,
            mult_depth: params.mult_depth,
            rotations: rotations.to_vec(),
            key_id,
            sigma: sigma(params, &config),
            rng: RefCell::new(rng),
        }
    }
}

impl MockClient {
    /// Serialized "secret key" (the key ID and noise seed).
    pub fn secret_key(&self) -> Vec<u8> {
        let mut b = SK_MAGIC.to_vec();
        b.extend_from_slice(&self.key_id.to_le_bytes());
        b
    }

    /// Restore from [`MockClient::secret_key`] bytes. A restored client
    /// cannot export evaluation keys.
    pub fn restore(params: &CkksParams, secret: &[u8], config: MockConfig) -> Result<Self> {
        let mut r = Reader(secret);
        r.magic(SK_MAGIC)?;
        let key_id = r.u64()?;
        r.end()?;
        Ok(Self {
            slots: params.slots as usize,
            mult_depth: params.mult_depth,
            rotations: vec![],
            key_id,
            sigma: sigma(params, &config),
            rng: RefCell::new(Rng::new(config.seed ^ key_id)),
        })
    }
}

impl CkksClient for MockClient {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn slots(&self) -> usize {
        self.slots
    }

    fn encrypt(&self, values: &[f64]) -> Result<Vec<u8>> {
        if values.len() != self.slots {
            return Err(err(format!(
                "expected {} slots, got {}",
                self.slots,
                values.len()
            )));
        }
        let mut rng = self.rng.borrow_mut();
        let noisy: Vec<f64> = values
            .iter()
            .map(|v| v + self.sigma * rng.normal())
            .collect();
        Ok(store(&noisy, 0, self.key_id))
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<f64>> {
        Ok(load(ciphertext, self.key_id, self.slots)?.values)
    }

    fn evaluation_keys(&self) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        b.extend_from_slice(EK_MAGIC);
        b.extend_from_slice(&self.key_id.to_le_bytes());
        b.extend_from_slice(&self.mult_depth.to_le_bytes());
        b.extend_from_slice(&(self.rotations.len() as u32).to_le_bytes());
        for k in &self.rotations {
            b.extend_from_slice(&k.to_le_bytes());
        }
        Ok(b)
    }
}

#[derive(Clone, Debug)]
pub struct MockCiphertext {
    values: Vec<f64>,
    level: u32,
}

impl MockCiphertext {
    /// Multiplicative depth consumed so far.
    pub fn level(&self) -> u32 {
        self.level
    }
}

/// Evaluator: knows only what the evaluation keys carry.
pub struct MockEvaluator {
    slots: usize,
    mult_depth: u32,
    rotations: Vec<u32>,
    key_id: u64,
    sigma: f64,
    rng: RefCell<Rng>,
}

impl MockEvaluator {
    /// Build an evaluator from the client's exported evaluation keys.
    pub fn new(params: &CkksParams, evaluation_keys: &[u8], config: MockConfig) -> Result<Self> {
        let mut r = Reader(evaluation_keys);
        r.magic(EK_MAGIC)?;
        let key_id = r.u64()?;
        let depth = r.u32()?;
        let n = r.u32()? as usize;
        if n > 1 << 20 {
            return Err(err("implausible rotation count"));
        }
        let rotations = (0..n).map(|_| r.u32()).collect::<Result<Vec<_>>>()?;
        r.end()?;
        if depth != params.mult_depth {
            return Err(err("evaluation keys were generated for other parameters"));
        }
        Ok(Self {
            slots: params.slots as usize,
            mult_depth: depth,
            rotations,
            key_id,
            sigma: sigma(params, &config),
            rng: RefCell::new(Rng::new(config.seed ^ 0x5EED)),
        })
    }

    fn noisy(&self, mut values: Vec<f64>, level: u32) -> Result<MockCiphertext> {
        if level > self.mult_depth {
            return Err(err(format!(
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
        Ok(MockCiphertext { values, level })
    }

    fn check_len(&self, p: &[f64]) -> Result<()> {
        if p.len() != self.slots {
            return Err(err(format!(
                "expected {} slots, got {}",
                self.slots,
                p.len()
            )));
        }
        Ok(())
    }

    fn zip(a: &MockCiphertext, b: &[f64], f: impl Fn(f64, f64) -> f64) -> Vec<f64> {
        a.values.iter().zip(b).map(|(&x, &y)| f(x, y)).collect()
    }
}

type Ct = MockCiphertext;

impl CkksEvaluator for MockEvaluator {
    type Ciphertext = MockCiphertext;

    fn name(&self) -> &'static str {
        "mock"
    }

    fn slots(&self) -> usize {
        self.slots
    }

    fn load_ciphertext(&self, bytes: &[u8]) -> Result<Ct> {
        load(bytes, self.key_id, self.slots)
    }

    fn store_ciphertext(&self, ct: &Ct) -> Result<Vec<u8>> {
        Ok(store(&ct.values, ct.level, self.key_id))
    }

    fn add(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        Ok(Ct {
            values: Self::zip(a, &b.values, |x, y| x + y),
            level: a.level.max(b.level),
        })
    }

    fn sub(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        Ok(Ct {
            values: Self::zip(a, &b.values, |x, y| x - y),
            level: a.level.max(b.level),
        })
    }

    fn neg(&self, a: &Ct) -> Result<Ct> {
        Ok(Ct {
            values: a.values.iter().map(|x| -x).collect(),
            level: a.level,
        })
    }

    fn mul(&self, a: &Ct, b: &Ct) -> Result<Ct> {
        self.noisy(
            Self::zip(a, &b.values, |x, y| x * y),
            a.level.max(b.level) + 1,
        )
    }

    fn add_plain(&self, a: &Ct, p: &[f64]) -> Result<Ct> {
        self.check_len(p)?;
        Ok(Ct {
            values: Self::zip(a, p, |x, y| x + y),
            level: a.level,
        })
    }

    fn mul_plain(&self, a: &Ct, p: &[f64]) -> Result<Ct> {
        self.check_len(p)?;
        self.noisy(Self::zip(a, p, |x, y| x * y), a.level + 1)
    }

    fn add_const(&self, a: &Ct, c: f64) -> Result<Ct> {
        Ok(Ct {
            values: a.values.iter().map(|x| x + c).collect(),
            level: a.level,
        })
    }

    fn mul_const(&self, a: &Ct, c: f64) -> Result<Ct> {
        self.noisy(a.values.iter().map(|x| x * c).collect(), a.level + 1)
    }

    fn rotate(&self, a: &Ct, k: u32) -> Result<Ct> {
        if !self.rotations.contains(&k) {
            return Err(err(format!("no rotation key for {k}")));
        }
        let n = self.slots;
        let values = (0..n).map(|i| a.values[(i + k as usize) % n]).collect();
        self.noisy(values, a.level)
    }
}
