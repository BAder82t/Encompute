//! Throwaway certificates and TLS servers for the tests of the TLS clients
//! (database and root-key provider). `#[path]`-included. Nothing here is
//! written outside a test's own temporary directory, and no private key is
//! ever committed: every key is generated when the test runs.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pub der: CertificateDer<'static>,
    pub pem: String,
}

pub fn ca(name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = p.self_signed(&key).unwrap();
    Ca {
        der: cert.der().clone(),
        pem: cert.pem(),
        issuer: Issuer::new(p, key),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Use {
    Server,
    Client,
}

pub struct Leaf {
    pub chain: Vec<CertificateDer<'static>>,
    pub cert_pem: String,
    pub key_pem: String,
    key_der: Vec<u8>,
}

impl Leaf {
    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::try_from(self.key_der.clone()).unwrap()
    }
}

/// A leaf certificate for `names` (subject alternative names) and common
/// name `cn`, signed by `ca`; `expired` backdates its validity to January
/// 2020.
pub fn leaf(ca: &Ca, names: &[&str], cn: &str, usage: Use, expired: bool) -> Leaf {
    let key = KeyPair::generate().unwrap();
    let mut p =
        CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![match usage {
        Use::Server => ExtendedKeyUsagePurpose::ServerAuth,
        Use::Client => ExtendedKeyUsagePurpose::ClientAuth,
    }];
    if expired {
        p.not_before = date_time_ymd(2020, 1, 1);
        p.not_after = date_time_ymd(2020, 1, 2);
    }
    let cert = p.signed_by(&key, &ca.issuer).unwrap();
    Leaf {
        chain: vec![cert.der().clone()],
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        key_der: key.serialize_der(),
    }
}

/// A server configuration; with `client_ca`, a client certificate signed by
/// it is required.
pub fn server_config(leaf: &Leaf, client_ca: Option<&Ca>) -> Arc<ServerConfig> {
    let provider = Arc::new(ring::default_provider());
    let b = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();
    let b = match client_ca {
        None => b.with_no_client_auth(),
        Some(c) => {
            let mut roots = RootCertStore::empty();
            roots.add(c.der.clone()).unwrap();
            b.with_client_cert_verifier(
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                    .build()
                    .unwrap(),
            )
        }
    };
    Arc::new(b.with_single_cert(leaf.chain.clone(), leaf.key()).unwrap())
}

/// A fresh directory under the system temporary directory, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "enc-tls-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }

    /// Writes `contents` as `name` and returns its path as a string.
    pub fn put(&self, name: &str, contents: &str) -> String {
        let p = self.0.join(name);
        std::fs::write(&p, contents).unwrap();
        p.display().to_string()
    }

    pub fn path(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn path_str(p: &Path) -> String {
    p.display().to_string()
}
