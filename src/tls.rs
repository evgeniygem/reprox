//! Builds the `rustls::ServerConfig` for the fallback site.
//!
//! The profile follows the spirit of Mozilla Intermediate (TLS 1.2 +
//! TLS 1.3, modern AEAD ciphers only — rustls doesn't implement
//! anything weaker anyway: no RC4, no 3DES, no non-AEAD CBC modes, no
//! static RSA key exchange) or Mozilla Modern (TLS 1.3 only), depending
//! on `tls_min_version` in the config. ALPN is configured separately:
//! `h2` first, then `http/1.1`, matching a typical modern nginx/HTTPS site.

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, version};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;

use crate::config::ServiceConfig;

pub async fn build_server_config(config: &ServiceConfig) -> anyhow::Result<ServerConfig> {
    let certs = load_certs(&config.tls_cert_path).await?;
    let key = load_key(&config.tls_key_path).await?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let versions: &[&'static rustls::SupportedProtocolVersion] = if config.tls_min_version == "1.3"
    {
        &[&version::TLS13]
    } else {
        &[&version::TLS12, &version::TLS13]
    };

    let mut server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .context("failed to configure the requested TLS versions for the fallback site")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the fallback site certificate/key are invalid or don't match")?;

    // ALPN: HTTP/2 first, then HTTP/1.1 — like a real modern web server
    // with http2 enabled.
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(server_config)
}

async fn load_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let buffer = fs::read(path)
        .await
        .with_context(|| format!("failed to open certificate file {path:?}"))?;

    let mut reader = buffer.as_slice();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
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
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to parse private key from {path:?}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key (PKCS#8/RSA/SEC1) found in {path:?}"))
}
