//! The evaluation-key cache: keys are deserialized once (hundreds of MiB
//! for OpenFHE exact) and reused by every job, within a memory bound.
//!
//! - Bounded: `ENCOMPUTE_KEY_CACHE_BYTES` (default 4 GiB of serialized key
//!   material), least recently used keys evicted first. A job holding a key
//!   keeps it alive until it finishes; an evicted key is simply reported
//!   missing, and the client uploads it again.
//! - Key ownership: entries are keyed by the SHA-256 of the key material
//!   (the key ID ciphertexts are bound to) and, for program-specific
//!   backends, the program. A ciphertext under another client's key never
//!   runs under these keys: its own key binding is checked when it loads.
//! - OpenFHE CKKS and BGV keep relinearization and rotation keys in
//!   process-wide maps keyed by the secret key's tag, which is public (it
//!   is in every ciphertext), not by this cache's key. The shim therefore
//!   checks an upload completely before inserting anything, requires the
//!   keys inside to carry exactly the tag they are sent under, and binds
//!   each loaded tag to the SHA-256 of the bytes it came from: an upload
//!   naming a tag already loaded from other bytes is refused. So an entry
//!   for key ID K runs exactly the key material whose SHA-256 is K, and an
//!   upload, accepted or refused, never changes the keys another key ID
//!   uses. Two clients can therefore not share a tag
//!   in one process: the second is refused until the first is evicted.
//! - Metrics: hits, misses, load seconds and bytes (`GET /metrics`); no key
//!   material or identifiers in them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// What an entry is for: shared keys (`scope` empty) serve every program
/// of a backend; program-specific keys only their program.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub backend: &'static str,
    pub scope: String,
    pub key_id: String,
}

struct Entry<T> {
    value: Arc<T>,
    bytes: u64,
    last_used: u64,
}

pub struct KeyCache<T> {
    max_bytes: u64,
    inner: Mutex<Inner<T>>,
    stats: Mutex<CacheStats>,
}

struct Inner<T> {
    entries: HashMap<CacheKey, Entry<T>>,
    bytes: u64,
    clock: u64,
}

/// Counters exported as metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub loads: u64,
    pub load_seconds: f64,
    pub evictions: u64,
    pub bytes: u64,
    pub entries: u64,
}

impl std::ops::AddAssign for CacheStats {
    fn add_assign(&mut self, o: Self) {
        self.hits += o.hits;
        self.misses += o.misses;
        self.loads += o.loads;
        self.load_seconds += o.load_seconds;
        self.evictions += o.evictions;
        self.bytes += o.bytes;
        self.entries += o.entries;
    }
}

/// The configured bound (default 4 GiB).
pub fn max_bytes_from_env() -> u64 {
    std::env::var("ENCOMPUTE_KEY_CACHE_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(4 << 30)
}

impl<T> KeyCache<T> {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                bytes: 0,
                clock: 0,
            }),
            stats: Mutex::default(),
        }
    }

    /// This cache's counters.
    pub fn stats(&self) -> CacheStats {
        *self.stats.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn bump(&self, f: impl FnOnce(&mut CacheStats)) {
        f(&mut self.stats.lock().unwrap_or_else(|p| p.into_inner()));
    }

    /// Every entry, oldest use first.
    pub fn values(&self) -> Vec<Arc<T>> {
        let g = self.lock();
        let mut v: Vec<_> = g.entries.values().collect();
        v.sort_by_key(|e| e.last_used);
        v.into_iter().map(|e| e.value.clone()).collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<T>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn contains(&self, k: &CacheKey) -> bool {
        self.lock().entries.contains_key(k)
    }

    /// The entry, marked recently used.
    pub fn get(&self, k: &CacheKey) -> Option<Arc<T>> {
        let mut g = self.lock();
        g.clock += 1;
        let now = g.clock;
        let hit = g.entries.get_mut(k).map(|e| {
            e.last_used = now;
            e.value.clone()
        });
        self.bump(|s| {
            if hit.is_some() {
                s.hits += 1
            } else {
                s.misses += 1
            }
        });
        hit
    }

    /// Returns the entry for `k`, loading it with `load` (timed) if absent.
    /// Loading happens outside the lock; if two loads race, the first
    /// inserted wins.
    pub fn get_or_load(
        &self,
        k: CacheKey,
        bytes: u64,
        load: impl FnOnce() -> encompute_ir::Result<T>,
    ) -> encompute_ir::Result<Arc<T>> {
        if let Some(v) = self.get(&k) {
            return Ok(v);
        }
        let t = std::time::Instant::now();
        let value = Arc::new(load()?);
        let secs = t.elapsed().as_secs_f64();
        self.bump(|s| {
            s.loads += 1;
            s.load_seconds += secs;
        });
        let mut g = self.lock();
        g.clock += 1;
        let now = g.clock;
        if let Some(e) = g.entries.get_mut(&k) {
            e.last_used = now;
            return Ok(e.value.clone());
        }
        // Evict least recently used entries until the new one fits (an
        // entry larger than the whole bound still goes in, alone).
        while g.bytes + bytes > self.max_bytes && !g.entries.is_empty() {
            let oldest = g
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone())
                .expect("non-empty");
            if let Some(e) = g.entries.remove(&oldest) {
                g.bytes -= e.bytes;
                self.bump(|s| s.evictions += 1);
            }
        }
        g.bytes += bytes;
        g.entries.insert(
            k,
            Entry {
                value: value.clone(),
                bytes,
                last_used: now,
            },
        );
        let (b, n) = (g.bytes, g.entries.len() as u64);
        self.bump(|s| {
            s.bytes = b;
            s.entries = n;
        });
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(id: &str) -> CacheKey {
        CacheKey {
            backend: "test",
            scope: String::new(),
            key_id: id.into(),
        }
    }

    #[test]
    fn bounded_lru_and_shared_loads() {
        let c: KeyCache<String> = KeyCache::new(100);
        let loads = std::cell::Cell::new(0);
        let load = |v: &str| {
            loads.set(loads.get() + 1);
            Ok(v.to_owned())
        };
        assert_eq!(*c.get_or_load(k("a"), 40, || load("A")).unwrap(), "A");
        assert_eq!(
            *c.get_or_load(k("a"), 40, || load("A2")).unwrap(),
            "A",
            "reused, not reloaded"
        );
        assert_eq!(loads.get(), 1);
        c.get_or_load(k("b"), 40, || load("B")).unwrap();
        c.get(&k("a")); // a is now the most recently used
        let held = c.get(&k("b")).unwrap();
        c.get(&k("a"));
        c.get_or_load(k("c"), 40, || load("C")).unwrap(); // evicts b (LRU)
        assert!(c.contains(&k("a")) && c.contains(&k("c")) && !c.contains(&k("b")));
        assert_eq!(
            *held, "B",
            "a job holding an evicted key keeps it until done"
        );
        // A failed load caches nothing.
        assert!(c
            .get_or_load(k("d"), 10, || Err(encompute_ir::Error::new(
                encompute_ir::Code::WrongKey,
                "bad"
            )))
            .is_err());
        assert!(!c.contains(&k("d")));
        // Oversized entries still load, alone.
        c.get_or_load(k("big"), 500, || load("BIG")).unwrap();
        assert!(c.contains(&k("big")) && !c.contains(&k("a")));
    }
}
