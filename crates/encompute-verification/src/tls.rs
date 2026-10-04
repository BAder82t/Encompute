//! TLS client configuration shared by the clients that need a private CA or
//! a client certificate (PostgreSQL, the root-key provider).
//!
//! rustls with the `ring` provider, the stack `ureq` already uses; no
//! OpenSSL. A configured trust bundle REPLACES the built-in public roots (it
//! never adds to them), and an unreadable or empty bundle is an error: the
//! trust store is never silently swapped for nothing.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme,
};

use encompute_ir::{Code, Error, Result};

fn err(msg: impl Into<String>) -> Error {
    Error::new(Code::InsecureConfiguration, msg)
}

/// What the client checks about the server's certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verify {
    /// Nothing: the channel is encrypted but the server is not
    /// authenticated (PostgreSQL's `sslmode=require` without a CA).
    None,
    /// The chain, not the host name (`verify-ca`).
    Chain,
    /// The chain and the host name (`verify-full`, and every HTTPS client).
    Full,
}

/// Where the trust anchors come from.
#[derive(Clone, Debug)]
pub enum Roots<'a> {
    /// The built-in public web roots.
    Public,
    /// Only the certificates in this PEM bundle.
    Bundle(&'a Path),
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// The certificates of a PEM file; an error if it cannot be read or holds
/// none.
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| err(format!("{}: {e}", path.display())))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| err(format!("{}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(err(format!(
            "{}: no certificates in the file",
            path.display()
        )));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| err(format!("{}: {e}", path.display())))
}

fn root_store(roots: &Roots<'_>) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    match roots {
        Roots::Public => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        Roots::Bundle(p) => {
            let (added, _ignored) = store.add_parsable_certificates(load_certs(p)?);
            if added == 0 {
                return Err(err(format!(
                    "{}: none of the certificates in the file could be used as a trust anchor",
                    p.display()
                )));
            }
        }
    }
    Ok(store)
}

/// Accepts a valid chain for the wrong host name (`verify-ca`).
#[derive(Debug)]
struct ChainOnly(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        match self
            .0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
        {
            // The chain is checked before the name, so this error means the
            // chain, the validity period and the key usage were all fine.
            Err(TlsError::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.0.verify_tls12_signature(m, c, d)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        self.0.verify_tls13_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// Accepts any certificate (`Verify::None`); the handshake signature is
/// still checked, so the peer must hold the key of the certificate it sends.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client configuration: the given trust anchors and verification level,
/// and a client certificate when `client` names a certificate chain file and
/// its private key file.
pub fn client_config(
    roots: &Roots<'_>,
    verify: Verify,
    client: Option<(&Path, &Path)>,
) -> Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| err(format!("tls: {e}")))?;
    let builder = match verify {
        Verify::None => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider()))),
        Verify::Chain | Verify::Full => {
            let inner = WebPkiServerVerifier::builder_with_provider(
                Arc::new(root_store(roots)?),
                provider(),
            )
            .build()
            .map_err(|e| err(format!("tls: {e}")))?;
            if verify == Verify::Chain {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(ChainOnly(inner)))
            } else {
                builder.dangerous().with_custom_certificate_verifier(inner)
            }
        }
    };
    let config = match client {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => builder
            .with_client_auth_cert(load_certs(cert)?, load_key(key)?)
            .map_err(|e| err(format!("client certificate {}: {e}", cert.display())))?,
    };
    Ok(Arc::new(config))
}

/// The OpenBao/Vault client settings from the environment, using the names
/// the `bao` and `vault` command-line tools use: `BAO_CACERT` (or
/// `VAULT_CACERT`) a PEM bundle that REPLACES the public roots, and
/// `BAO_CLIENT_CERT` + `BAO_CLIENT_KEY` (or the `VAULT_` pair) for mutual
/// TLS. `None` when none is set: the built-in public roots, no client
/// certificate (the behaviour before these were supported).
pub fn provider_config_from_env() -> Result<Option<Arc<ClientConfig>>> {
    let var = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty()))
    };
    let ca = var(&["BAO_CACERT", "VAULT_CACERT"]);
    let cert = var(&["BAO_CLIENT_CERT", "VAULT_CLIENT_CERT"]);
    let key = var(&["BAO_CLIENT_KEY", "VAULT_CLIENT_KEY"]);
    if ca.is_none() && cert.is_none() && key.is_none() {
        return Ok(None);
    }
    let client = match (&cert, &key) {
        (Some(c), Some(k)) => Some((Path::new(c.as_str()), Path::new(k.as_str()))),
        (None, None) => None,
        _ => return Err(err(
            "set both BAO_CLIENT_CERT and BAO_CLIENT_KEY (or neither) for the root key provider",
        )),
    };
    let roots = match &ca {
        Some(p) => Roots::Bundle(Path::new(p.as_str())),
        None => Roots::Public,
    };
    client_config(&roots, Verify::Full, client).map(Some)
}
