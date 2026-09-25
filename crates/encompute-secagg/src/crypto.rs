//! Primitives, each a standard construction:
//! - key agreement: X25519 (contributory outputs only);
//! - key derivation: domain-separated SHA-256 over the round ID and the
//!   shared secret;
//! - pseudorandom masks: the ChaCha20 keystream (RFC 8439), as
//!   little-endian u64s reduced mod 2^m;
//! - share encryption: ChaCha20-Poly1305;
//! - secret sharing: Shamir over GF(2^8) (`vsss-rs`), byte-wise;
//! - signatures: Ed25519 (strict verification).

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use encompute_ir::{Code, Error, Result};

pub(crate) fn protocol_err(m: impl Into<String>) -> Error {
    Error::new(Code::AggregationProtocol, m)
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

pub(crate) fn unhex32(s: &str, what: &str) -> Result<[u8; 32]> {
    unhex(s)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| protocol_err(format!("{what} is not 32 bytes of hex")))
}

/// `SHA256(domain || 0x00 || parts...)`, each part length-prefixed.
pub(crate) fn tagged(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize().into()
}

pub(crate) fn random32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| protocol_err(format!("no randomness: {e}")))?;
    Ok(b)
}

/// An X25519 key pair.
pub(crate) struct DhKey {
    secret: StaticSecret,
}

impl DhKey {
    pub fn generate() -> Result<Self> {
        Ok(Self::from_bytes(random32()?))
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(b),
        }
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// `KDF(label, round, DH(self, peer))`; refuses low-order peers.
    pub fn agree(
        &self,
        peer: &[u8; 32],
        label: &str,
        round_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(protocol_err("a peer key is a low-order point"));
        }
        Ok(Zeroizing::new(tagged(
            label,
            &[round_id.as_bytes(), shared.as_bytes()],
        )))
    }
}

pub(crate) const SHARE_KEY: &str = "encompute.secagg.share-key.v1";
pub(crate) const MASK_KEY: &str = "encompute.secagg.mask-key.v1";

/// `n` pseudorandom values mod 2^bits from `seed`.
pub(crate) fn prg(seed: &[u8; 32], n: usize, bits: u32) -> Vec<u64> {
    let mut c = chacha20::ChaCha20::new(seed.into(), &[0u8; 12].into());
    let mut buf = vec![0u8; n * 8];
    c.apply_keystream(&mut buf);
    let mask = modulus_mask(bits);
    buf.as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c) & mask)
        .collect()
}

pub(crate) fn modulus_mask(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// AEAD with a per-direction nonce: the key is shared by both directions of
/// a pair, so the nonce names sender and recipient.
pub(crate) fn seal(key: &[u8; 32], from: u8, to: u8, aad: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut n = [0u8; 12];
    n[0] = from;
    n[1] = to;
    ChaCha20Poly1305::new(&(*key).into())
        .encrypt(&Nonce::from(n), Payload { msg, aad })
        .map_err(|_| protocol_err("encrypting shares failed"))
}

pub(crate) fn open(
    key: &[u8; 32],
    from: u8,
    to: u8,
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut n = [0u8; 12];
    n[0] = from;
    n[1] = to;
    ChaCha20Poly1305::new(&(*key).into())
        .decrypt(&Nonce::from(n), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| protocol_err("shares from a party do not decrypt (tampered or misrouted)"))
}

/// rand_core 0.10 adapter over the OS generator, for `vsss-rs`.
struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> std::result::Result<(), Self::Error> {
        getrandom::getrandom(d).expect("the OS random generator failed");
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsRng {}

/// Shamir shares of `secret` for the participants with Shamir IDs `ids`
/// (1..=255), any `threshold` of which reconstruct it. Share bytes start
/// with the ID.
pub(crate) fn split(
    secret: &[u8],
    threshold: usize,
    ids: &[u8],
) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let ids: Vec<vsss_rs::IdentifierGf256> = ids
        .iter()
        .map(|&i| vsss_rs::IdentifierGf256(vsss_rs::Gf256(i)))
        .collect();
    vsss_rs::Gf256::split_bytes_with_participant_ids_iter(threshold, ids.len(), secret, OsRng, ids)
        .map(|v| v.into_iter().map(Zeroizing::new).collect())
        .map_err(|e| protocol_err(format!("secret sharing failed: {e:?}")))
}

pub(crate) fn combine(shares: &[Vec<u8>]) -> Result<Zeroizing<Vec<u8>>> {
    vsss_rs::Gf256::combine_bytes(shares)
        .map(Zeroizing::new)
        .map_err(|e| protocol_err(format!("reconstruction failed: {e:?}")))
}

pub(crate) fn sign(key: &SigningKey, domain: &str, body: &[u8]) -> String {
    hex(&key.sign(&tagged(domain, &[body])).to_bytes())
}

pub(crate) fn verify(key: &[u8; 32], domain: &str, body: &[u8], signature: &str) -> Result<()> {
    let bad = || {
        Error::new(
            Code::AggregationUnauthorized,
            "a message is not signed by its party's identity",
        )
    };
    let vk = VerifyingKey::from_bytes(key).map_err(|_| bad())?;
    let sig = unhex(signature)
        .and_then(|b| Signature::from_slice(&b).ok())
        .ok_or_else(bad)?;
    vk.verify_strict(&tagged(domain, &[body]), &sig)
        .map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives() {
        let (a, b) = (DhKey::generate().unwrap(), DhKey::generate().unwrap());
        let r = "round";
        assert_eq!(
            *a.agree(&b.public(), SHARE_KEY, r).unwrap(),
            *b.agree(&a.public(), SHARE_KEY, r).unwrap()
        );
        assert_ne!(
            *a.agree(&b.public(), SHARE_KEY, r).unwrap(),
            *a.agree(&b.public(), MASK_KEY, r).unwrap()
        );
        assert_ne!(
            *a.agree(&b.public(), SHARE_KEY, r).unwrap(),
            *a.agree(&b.public(), SHARE_KEY, "other").unwrap()
        );
        assert!(a.agree(&[0u8; 32], SHARE_KEY, r).is_err(), "low order");
        assert_eq!(prg(&[1; 32], 5, 20), prg(&[1; 32], 5, 20));
        assert!(prg(&[1; 32], 100, 20).iter().all(|&v| v < 1 << 20));
        let k = [7u8; 32];
        let ct = seal(&k, 1, 2, b"aad", b"hi").unwrap();
        assert_eq!(open(&k, 1, 2, b"aad", &ct).unwrap().as_slice(), b"hi");
        assert!(open(&k, 2, 1, b"aad", &ct).is_err());
        assert!(open(&k, 1, 2, b"other", &ct).is_err());
        let secret = [9u8; 32];
        let shares = split(&secret, 3, &[1, 2, 4, 5, 9]).unwrap();
        assert_eq!(shares[2][0], 4, "share IDs as given");
        let pick: Vec<Vec<u8>> = [0, 2, 4].iter().map(|&i| shares[i].to_vec()).collect();
        assert_eq!(combine(&pick).unwrap().as_slice(), &secret);
        let two: Vec<Vec<u8>> = [0, 1].iter().map(|&i| shares[i].to_vec()).collect();
        assert_ne!(
            combine(&two).map(|s| s.to_vec()).unwrap_or_default(),
            secret.to_vec()
        );
        let sk = SigningKey::from_bytes(&[3; 32]);
        let s = sign(&sk, "d", b"body");
        assert!(verify(&sk.verifying_key().to_bytes(), "d", b"body", &s).is_ok());
        assert!(verify(&sk.verifying_key().to_bytes(), "d", b"bodY", &s).is_err());
        assert!(verify(&sk.verifying_key().to_bytes(), "e", b"body", &s).is_err());
    }
}
