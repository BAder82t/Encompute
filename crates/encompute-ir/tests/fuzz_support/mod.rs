//! Deterministic input generation for the fuzz smoke tests (no external
//! fuzzer: runs in `cargo test` on stable). Seeds are valid samples; each
//! round mutates one (bit flips, byte edits, splices, interesting integers
//! and tokens, truncation) or produces random bytes. A panic fails the test
//! and prints the offending input; every input must finish within a bound.
#![allow(dead_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const TOKENS: &[&[u8]] = &[
    b"\"",
    b"{",
    b"}",
    b"[",
    b"]",
    b",",
    b":",
    b"null",
    b"-1",
    b"0",
    b"1e999",
    b"-0.0",
    b"NaN",
    b"18446744073709551615",
    b"18446744073709551616",
    b"4294967295",
    b"9223372036854775807",
    b"-9223372036854775808",
    b"\\u0000",
    b"\\ud800",
    b"\xff\xfe",
    b"\xc3\x28",
    b"%",
    b"%4294967295",
    b"\n",
    b"#",
    b" ",
    b"vector<",
    b"matrix<32768x32768>",
    b"secret",
    b"public",
    b"\"version\":",
];

const INTS: &[u64] = &[
    0,
    1,
    0x7f,
    0xff,
    0xffff,
    0x7fff_ffff,
    0xffff_ffff,
    0x1_0000_0000,
    1 << 62,
    1 << 63,
    u64::MAX,
    u64::MAX - 1,
];

/// One mutation of `seed` (or random bytes), possibly splicing `others`.
pub fn mutate(rng: &mut Rng, seed: &[u8], others: &[Vec<u8>]) -> Vec<u8> {
    if rng.below(16) == 0 {
        let n = rng.below(256);
        return (0..n).map(|_| rng.next() as u8).collect();
    }
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(6) {
        let len = v.len();
        match rng.below(10) {
            0 if len > 0 => {
                let i = rng.below(len);
                v[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                v[i] = rng.next() as u8;
            }
            2 => {
                let i = rng.below(len + 1);
                v.insert(i, rng.next() as u8);
            }
            3 if len > 0 => {
                let a = rng.below(len);
                let b = (a + 1 + rng.below(16)).min(len);
                v.drain(a..b);
            }
            4 if len > 0 => {
                let a = rng.below(len);
                let b = (a + 1 + rng.below(32)).min(len);
                let chunk = v[a..b].to_vec();
                let at = rng.below(len + 1);
                v.splice(at..at, chunk);
            }
            5 => v.truncate(rng.below(len + 1)),
            6 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                let at = rng.below(len + 1);
                v.splice(at..at, t.iter().copied());
            }
            7 if len >= 8 => {
                let x = INTS[rng.below(INTS.len())];
                let at = rng.below(len - 7);
                if rng.below(2) == 0 {
                    v[at..at + 8].copy_from_slice(&x.to_le_bytes());
                } else {
                    v[at..at + 4].copy_from_slice(&(x as u32).to_le_bytes());
                }
            }
            8 if !others.is_empty() => {
                let o = &others[rng.below(others.len())];
                if !o.is_empty() {
                    let a = rng.below(o.len());
                    let b = (a + 1 + rng.below(64)).min(o.len());
                    let at = rng.below(len + 1);
                    v.splice(at..at, o[a..b].iter().copied());
                }
            }
            _ => {
                // Replace a decimal number with an interesting one.
                if let Some(i) = v.iter().position(|b| b.is_ascii_digit()) {
                    let j = v[i..]
                        .iter()
                        .position(|b| !b.is_ascii_digit())
                        .map_or(len, |k| i + k);
                    let x = INTS[rng.below(INTS.len())].to_string();
                    v.splice(i..j, x.bytes());
                }
            }
        }
    }
    v
}

/// Feeds `iters` inputs derived from `seeds` to `f`. Fails on a panic (with
/// the input) or on any input taking longer than `per_input`.
pub fn run(
    name: &str,
    seeds: &[Vec<u8>],
    iters: usize,
    per_input: Duration,
    mut f: impl FnMut(&[u8]),
) {
    assert!(!seeds.is_empty());
    let mut rng = Rng::new(
        name.bytes()
            .fold(7u64, |h, b| h.wrapping_mul(31) ^ b as u64),
    );
    for (i, s) in seeds.iter().enumerate() {
        once(name, i, s, per_input, &mut f);
    }
    once(name, 0, &[], per_input, &mut f);
    for i in 0..iters {
        let s = &seeds[rng.below(seeds.len())];
        let input = mutate(&mut rng, s, seeds);
        once(name, i, &input, per_input, &mut f);
    }
}

fn once(name: &str, i: usize, input: &[u8], per_input: Duration, f: &mut impl FnMut(&[u8])) {
    let t = Instant::now();
    let r = catch_unwind(AssertUnwindSafe(|| f(input)));
    let took = t.elapsed();
    if let Err(p) = r {
        let msg = p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        panic!(
            "{name}: input {i} panicked: {msg}\ninput ({} bytes): {:?}",
            input.len(),
            String::from_utf8_lossy(&input[..input.len().min(4096)])
        );
    }
    assert!(
        took <= per_input,
        "{name}: input {i} took {took:?} (> {per_input:?}); input: {:?}",
        String::from_utf8_lossy(&input[..input.len().min(4096)])
    );
}

/// Asserts `f` finishes within `limit`.
pub fn within<T>(limit: Duration, f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let r = f();
    assert!(t.elapsed() <= limit, "took {:?} (> {limit:?})", t.elapsed());
    r
}

/// `depth` nested JSON arrays around `inner`.
pub fn nested_json(depth: usize, inner: &str) -> String {
    format!("{}{inner}{}", "[".repeat(depth), "]".repeat(depth))
}
