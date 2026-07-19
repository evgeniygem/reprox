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

    /// Local address of service.
    pub proxy_addr: String,

    /// Secret domain(s). If the SNI of an incoming TLS connection matches one of these,
    /// the connection is transparently proxied to service_addr with no TLS termination on
    /// this side.
    pub secret_domains: Vec<String>,

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

fn default_server_header() -> String {
    "nginx/1.26.2 (Ubuntu)".to_string()
}

fn default_handshake_timeout() -> u64 {
    10
}

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

        if let Ok(v) = std::env::var("REPROX_PROXY_ADDR") {
            self.proxy_addr = v;
        }
        if let Ok(v) = std::env::var("REPROX_SECRET_DOMAINS") {
            self.secret_domains = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
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
        if let Ok(v) = std::env::var("REPROX_METRICS_ADDR") {
            self.metrics_addr = v.parse().ok();
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.secret_domains.is_empty() {
            anyhow::bail!("secret_domains must not be empty");
        }
        for d in &self.secret_domains {
            if d.trim().is_empty() {
                anyhow::bail!("secret_domains contains an empty string");
            }
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

    /// Compares an SNI hostname against the list of service secret domains.
    /// Case-insensitive, and tolerant of a trailing FQDN dot.
    pub fn matches_secret_domain(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.secret_domains
            .iter()
            .any(|d| d.trim_end_matches('.').eq_ignore_ascii_case(&host))
    }
}
