use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs;

use anyhow::Context;
use serde::Deserialize;

/// Configuration for the service front.
///
/// Loaded from a TOML file (the path is taken from the `REPROX_CONFIG`
/// environment variable, defaulting to `config.toml` in the working
/// directory), after which every field can be overridden by the
/// corresponding `REPROX_*` environment variable — handy for
/// containers/systemd units where you'd rather pass secrets through
/// the environment than store them in a file.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    /// Address the front itself listens on (usually 0.0.0.0:443).
    pub listen_addr: SocketAddr,

    /// Proxy targets. If the SNI of an incoming TLS connection matches one of these,
    /// the connection is transparently proxied to upstream with no TLS termination on
    /// this side.
    pub routes: Vec<ProxyTarget>,

    /// Path to the certificate (full chain, PEM) for the fallback site.
    pub tls_cert_path: PathBuf,

    /// Path to the private key (PEM, PKCS#8/RSA/SEC1) for the fallback site.
    pub tls_key_path: PathBuf,

    /// Directory containing the static fallback site (must contain index.html).
    pub static_dir: PathBuf,

    /// Value of the Server header in fallback site responses.
    #[serde(default = "default_server_header")]
    pub server_header: String,

    /// Timeout (seconds) for reading/parsing the ClientHello and for the
    /// entire TLS handshake on the fallback path. Guards against
    /// slowloris-style connections that never complete.
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,

    /// TLS profile: "1.2" — Mozilla Intermediate (TLS 1.2 + 1.3),
    /// "1.3" — Mozilla Modern (TLS 1.3 only).
    #[serde(default = "default_tls_min_version")]
    pub tls_min_version: String,

    /// Optional address for the internal plain-text metrics endpoint.
    /// MUST be a loopback address (127.0.0.1/::1) — this is checked both
    /// at config load time and again right before the listener is bound.
    /// If unset, metrics are disabled and no extra port is opened at all.
    #[serde(default)]
    pub metrics_addr: Option<SocketAddr>,
}

/// A single `[[routes]]` entry from the config file: maps one SNI value
/// to the upstream address that "secret" traffic for it should be
/// transparently forwarded to.
///
/// `sni` is normalized (trailing dot stripped, lowercased) once, right
/// after the config is parsed — see `ServiceConfig::try_load` — so
/// every other place in the codebase can compare it as-is against the
/// (equally normalized) SNI extracted from the ClientHello.
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyTarget {
    /// The "secret" SNI/hostname this route matches on (e.g. `"domain.com"`).
    pub sni: String,
    /// Address (`host:port`) of the local service instance this route's
    /// traffic is proxied to, e.g. `"127.0.0.1:8080"`. Accepts either an
    /// IP:port pair or a resolvable hostname:port, since it is passed
    /// directly to `TcpStream::connect`.
    pub upstream: String,
}

/// Default `Server` header when `server_header` is omitted from the
/// config: mimics a plain, up-to-date nginx install so the fallback
/// site doesn't visibly announce it's actually `reprox`.
fn default_server_header() -> String {
    "nginx/1.26.2 (Ubuntu)".to_string()
}

/// Default timeout, in seconds, for both the SNI probe and the
/// fallback-path TLS handshake when `handshake_timeout_secs` is
/// omitted. 10s comfortably covers real clients (including slow mobile
/// networks) while still bounding slowloris-style stalls.
fn default_handshake_timeout() -> u64 {
    10
}

/// Default TLS profile when `tls_min_version` is omitted: Mozilla
/// Intermediate (TLS 1.2 + TLS 1.3) for maximum client compatibility.
fn default_tls_min_version() -> String {
    "1.2".to_string()
}

impl ServiceConfig {
    pub async fn try_load() -> anyhow::Result<Self> {
        let path = std::env::var("REPROX_CONFIG").unwrap_or_else(|_| "config.toml".to_string());

        let raw = fs::read_to_string(&path)
            .await
            .with_context(|| format!("failed to read config file {path}"))?;

        let mut cfg: ServiceConfig =
            toml::from_str(&raw).with_context(|| format!("failed to parse config file {path}"))?;

        // Normalize configured SNIs the same way `sni::probe_client_hello`
        // normalizes the SNI it extracts from the ClientHello (trailing
        // dot stripped, lowercased). Doing it once here — rather than on
        // every incoming connection — means `Router` can do a plain,
        // case-sensitive HashMap lookup and still match
        // "Domain.com." and "domain.com" as the same route.
        cfg.routes
            .iter_mut()
            .for_each(|r| r.sni = r.sni.trim_end_matches('.').to_ascii_lowercase());

        cfg.apply_env_overrides();
        cfg.validate()?;
        Ok(cfg)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("REPROX_LISTEN_ADDR")
            && let Ok(addr) = v.parse()
        {
            self.listen_addr = addr;
        }

        if let Ok(v) = std::env::var("REPROX_TLS_CERT_PATH") {
            self.tls_cert_path = PathBuf::from(v);
        }

        if let Ok(v) = std::env::var("REPROX_TLS_KEY_PATH") {
            self.tls_key_path = PathBuf::from(v);
        }

        if let Ok(v) = std::env::var("REPROX_STATIC_DIR") {
            self.static_dir = PathBuf::from(v);
        }

        if let Ok(v) = std::env::var("REPROX_SERVER_HEADER") {
            self.server_header = v;
        }

        if let Ok(v) = std::env::var("REPROX_HANDSHAKE_TIMEOUT_SECS")
            && let Ok(n) = v.parse()
        {
            self.handshake_timeout_secs = n;
        }

        if let Ok(v) = std::env::var("REPROX_TLS_MIN_VERSION") {
            self.tls_min_version = v;
        }

        if let Ok(v) = std::env::var("REPROX_METRICS_ADDR")
            && let Ok(addr) = v.parse()
        {
            self.metrics_addr = Some(addr);
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        // Note: an empty `routes` list is intentionally allowed — it's a
        // valid configuration for a server that only ever serves the
        // fallback site (no hidden service behind it).
        let mut seen_sni = std::collections::HashSet::with_capacity(self.routes.len());
        for target in &self.routes {
            if target.sni.trim().is_empty() || target.upstream.trim().is_empty() {
                anyhow::bail!("routes contains an empty string");
            }
            // `Router::new` builds its lookup table with a plain HashMap
            // insert, which would silently let a later duplicate
            // shadow an earlier one — fail loudly here instead, since a
            // duplicate SNI is almost certainly a copy-paste mistake in
            // the config rather than something intentional.
            if !seen_sni.insert(target.sni.as_str()) {
                anyhow::bail!("duplicate sni in routes: {:?}", target.sni);
            }
        }
        if self.handshake_timeout_secs == 0 {
            anyhow::bail!("handshake_timeout_secs must be greater than 0");
        }
        if !self.tls_cert_path.is_file() {
            anyhow::bail!("tls_cert_path not found: {:?}", self.tls_cert_path);
        }
        if !self.tls_key_path.is_file() {
            anyhow::bail!("tls_key_path not found: {:?}", self.tls_key_path);
        }
        if !self.static_dir.is_dir() {
            anyhow::bail!(
                "static_dir not found or is not a directory: {:?}",
                self.static_dir
            );
        }
        if self.tls_min_version != "1.2" && self.tls_min_version != "1.3" {
            anyhow::bail!(
                "tls_min_version must be \"1.2\" or \"1.3\", got {:?}",
                self.tls_min_version
            );
        }
        if let Some(addr) = &self.metrics_addr
            && !addr.ip().is_loopback()
        {
            anyhow::bail!("metrics_addr must be a loopback address (127.0.0.1/::1), got {addr}");
        }
        Ok(())
    }
}
