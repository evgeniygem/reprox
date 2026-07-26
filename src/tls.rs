//! Builds the `rustls::ServerConfig` for the fallback site, and the
//! machinery that lets its certificate be swapped out at runtime.
//!
//! The profile follows the spirit of Mozilla Intermediate (TLS 1.2 +
//! TLS 1.3, modern AEAD ciphers only — rustls doesn't implement
//! anything weaker anyway: no RC4, no 3DES, no non-AEAD CBC modes, no
//! static RSA key exchange) or Mozilla Modern (TLS 1.3 only), depending
//! on `tls_min_version` in the config. ALPN is configured separately:
//! `h2` first, then `http/1.1`, matching a typical modern nginx/HTTPS site.
//!
//! Unlike a plain `with_single_cert` setup, the certificate isn't baked
//! into the `ServerConfig` directly — it's served through
//! `ReloadableCertResolver` instead, so `main::hot_reload` can
//! swap in a renewed certificate/key at runtime without rebuilding the
//! `ServerConfig` (and therefore the `TlsAcceptor` that every accepted
//! connection already holds a clone of). `tls_min_version`, by
//! contrast, *is* baked into `ServerConfig` at startup and can't be
//! changed this way — see the README's notes on SIGHUP reload.

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, version};
use rustls_pki_types::pem::PemObject;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::fs;

use crate::config::ServiceConfig;

/// A `rustls::server::ResolvesServerCert` whose certificate can be
/// swapped out at runtime — the mechanism `main::hot_reload` uses
/// to pick up a renewed certificate/key on SIGHUP.
///
/// rustls calls `resolve()` once per TLS handshake (not once per
/// `ServerConfig`), so updating what it returns here takes effect for
/// every handshake that starts *after* the swap, without ever needing
/// to touch the `rustls::ServerConfig`/`TlsAcceptor` that every accepted
/// connection already holds a cheap clone of — a handshake already in
/// progress keeps whatever certificate `resolve()` already handed it,
/// so there's no tearing mid-handshake either way.
#[derive(Debug)]
pub struct ReloadableCertResolver {
    cert_key: RwLock<Arc<CertifiedKey>>,
}

impl ReloadableCertResolver {
    fn new(key: CertifiedKey) -> Self {
        Self {
            cert_key: RwLock::new(Arc::new(key)),
        }
    }

    pub fn update(&self, key: CertifiedKey) {
        *self.cert_key.write().expect("cert resolver lock poisoned") = Arc::new(key);
    }
}

impl ResolvesServerCert for ReloadableCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(
            self.cert_key
                .read()
                .expect("cert resolver lock poisoned")
                .clone(),
        )
    }
}

pub async fn build_server_config(
    config: &ServiceConfig,
) -> anyhow::Result<(ServerConfig, Arc<ReloadableCertResolver>)> {
    let certified_key = load_certified_key(&config.tls_cert_path, &config.tls_key_path).await?;
    let resolver = Arc::new(ReloadableCertResolver::new(certified_key));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let versions: &[&'static rustls::SupportedProtocolVersion] = if config.tls_min_version == "1.3"
    {
        &[&version::TLS13]
    } else {
        &[&version::TLS12, &version::TLS13]
    };

    let mut server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .context("failed to configure the requested TLS versions")?
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());

    // ALPN: HTTP/2 first, then HTTP/1.1 — like a real modern web server
    // with http2 enabled.
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok((server_config, resolver))
}

/// Loads the certificate/key at `cert_path`/`key_path` and packages
/// them into a `CertifiedKey`, verifying the two actually match. Used
/// both at startup (via `build_server_config`) and on every reload
/// (`main::hot_reload`, via `ReloadableCertResolver::update`).
pub async fn load_certified_key(cert_path: &Path, key_path: &Path) -> anyhow::Result<CertifiedKey> {
    let certs = load_certs(cert_path).await?;
    let key_der = load_key(key_path).await?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .with_context(|| format!("the key at {key_path:?} isn't valid for the TLS provider"))?;

    let certified_key = CertifiedKey::new(certs, signing_key);
    certified_key.keys_match().with_context(|| {
        format!("the private key at {key_path:?} does not match the certificate at {cert_path:?}")
    })?;

    Ok(certified_key)
}

async fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let buffer = fs::read(path)
        .await
        .with_context(|| format!("failed to open certificate file {path:?}"))?;

    let mut reader = buffer.as_slice();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse PEM certificates from {path:?}"))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {path:?}");
    }
    Ok(certs)
}

async fn load_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let buffer = fs::read(path)
        .await
        .with_context(|| format!("failed to open key file {path:?}"))?;

    let mut reader = buffer.as_slice();
    PrivateKeyDer::from_pem_reader(&mut reader)
        .with_context(|| format!("failed to parse private key from {path:?}"))
}
