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

    /// Hard cap on the number of connections handled at once, across
    /// both routes combined. Once this many connections are in flight,
    /// `main::accept_loop` stops pulling new ones off the kernel accept
    /// queue until a slot frees up.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Optional hard cap on concurrent connections from a single client
    /// IP, enforced in addition to `max_connections`. Unlike
    /// `max_connections`, this one *is* picked up live by SIGHUP — see
    /// `ip_limiter::PerIpLimiter::set_max_per_ip`. Unset or `0` disables it.
    #[serde(default)]
    pub max_connections_per_ip: Option<usize>,

    /// Sustained new-connections/sec allowed from a single client IP
    /// (token-bucket, complements `max_connections_per_ip`). Unset or
    /// `0` disables it. Reloadable live via SIGHUP.
    #[serde(default)]
    pub connection_rate_per_ip: Option<f64>,

    /// Burst size for `connection_rate_per_ip` — how many connections
    /// an IP may open back-to-back before throttling kicks in.
    /// Ignored if `connection_rate_per_ip` is unset. Defaults to `10`
    /// when the rate is set but burst isn't.
    #[serde(default)]
    pub connection_burst_per_ip: Option<u64>,
}

/// A single `[[routes]]` entry from the config file: maps one SNI value
/// to the upstream address that "secret" traffic for it should be
/// transparently forwarded to.
///
/// `sni` is normalized (trailing dot stripped, lowercased) once, right
/// after the config is parsed.
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

/// Default cap on simultaneous connections when `max_connections` is
/// omitted. 10,000 comfortably covers a busy single-instance deployment
/// while still bounding worst-case fd/memory usage — each proxied
/// connection uses two sockets (client + upstream), so steady-state fd
/// usage on that route is bounded to roughly 2x this value.
fn default_max_connections() -> usize {
    10_000
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
        // dot stripped, lowercased).
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

        if let Ok(v) = std::env::var("REPROX_MAX_CONNECTIONS")
            && let Ok(n) = v.parse()
        {
            self.max_connections = n;
        }

        if let Ok(v) = std::env::var("REPROX_MAX_CONNECTIONS_PER_IP")
            && let Ok(n) = v.parse()
        {
            self.max_connections_per_ip = Some(n);
        }

        if let Ok(v) = std::env::var("REPROX_CONNECTION_RATE_PER_IP")
            && let Ok(n) = v.parse()
        {
            self.connection_rate_per_ip = Some(n);
        }

        if let Ok(v) = std::env::var("REPROX_CONNECTION_BURST_PER_IP")
            && let Ok(n) = v.parse()
        {
            self.connection_burst_per_ip = Some(n);
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
            // Catch the common typos (a stray "https://" prefix, a
            // missing/garbled port, a trailing path) here, at startup,
            // rather than as a connect failure the first time a real
            // client's traffic happens to hit this route.
            validate_upstream(&target.upstream)
                .with_context(|| format!("invalid upstream for sni {:?}", target.sni))?;
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

        if self.max_connections == 0 {
            anyhow::bail!("max_connections must be greater than 0");
        }

        if let Some(rate) = self.connection_rate_per_ip {
            anyhow::ensure!(
                rate.is_finite() && rate > 0.0,
                "connection_rate_per_ip must be positive"
            );
        }

        if let Some(burst) = self.connection_burst_per_ip {
            anyhow::ensure!(burst >= 1, "connection_burst_per_ip must be at least 1");
        }

        Ok(())
    }

    /// Logs a warning for every field that a SIGHUP reload
    /// (`main::hot_reload`) cannot apply live but that changed
    /// anyway between `self` (the configuration still running) and
    /// `new` (what was just loaded from disk) — so an operator who
    /// edited one of these and sent SIGHUP finds out from the logs that
    /// nothing happened, rather than assuming the change took effect.
    pub fn warn_about_unreloadable_changes(&self, new: &ServiceConfig) {
        if self.listen_addr != new.listen_addr {
            tracing::warn!(
                old = %self.listen_addr,
                new = %new.listen_addr,
                "listen_addr changed in config.toml, but \
                SIGHUP can't rebind the listener — restart the process to apply this"
            );
        }
        if self.metrics_addr != new.metrics_addr {
            tracing::warn!(
                old = ?self.metrics_addr,
                new = ?new.metrics_addr,
                "metrics_addr changed in config.toml, but \
                SIGHUP can't rebind the metrics listener — restart the process to apply this"
            );
        }
        if self.tls_min_version != new.tls_min_version {
            tracing::warn!(
                old = %self.tls_min_version,
                new = %new.tls_min_version,
                "tls_min_version changed in config.toml, but SIGHUP only swaps the certificate,\
                 not the negotiated TLS versions — restart the process to apply this"
            );
        }
        if self.max_connections != new.max_connections {
            tracing::warn!(
                old = self.max_connections,
                new = new.max_connections,
                "max_connections changed in config.toml, but SIGHUP can't resize \
                the connection-slot limiter — restart the process to apply this"
            );
        }
    }
}

/// Verifies that `upstream` at least has the right *shape* —
/// `host:port` with a valid, non-zero port, and a host that's either a
/// literal IP address or a syntactically plausible hostname.
fn validate_upstream(upstream: &str) -> anyhow::Result<()> {
    // A bare `ip:port` — including a bracketed IPv6 literal like
    // `[::1]:8080` — parses directly; nothing further to check.
    if let Ok(addr) = upstream.parse::<SocketAddr>()
        && addr.port() != 0
    {
        return Ok(());
    }

    if upstream.contains("://") {
        anyhow::bail!("must be a host:port pair, not a URL with a scheme");
    }
    if upstream.chars().any(char::is_whitespace) {
        anyhow::bail!("must not contain whitespace");
    }

    // Otherwise this should be `hostname:port`. Split on the *last*
    // colon: an unbracketed IPv6 literal (which contains multiple
    // colons) has already been rejected by the `SocketAddr` parse
    // above and is ambiguous without brackets, so we don't try to
    // special-case it here.
    let (host, port) = upstream
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("must be a host:port pair (missing ':port')"))?;

    if host.is_empty() {
        anyhow::bail!("has an empty host before the ':'");
    }
    if host.contains('/') {
        anyhow::bail!("must not contain a path");
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        anyhow::bail!("host {host:?} contains characters not valid in a hostname");
    }

    match port.parse::<u16>() {
        Ok(0) => anyhow::bail!("port 0 is not a valid upstream port"),
        Ok(_) => Ok(()),
        Err(_) => anyhow::bail!("{port:?} is not a valid port number"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_ip_and_port() {
        assert!(validate_upstream("127.0.0.1:8080").is_ok());
        assert!(validate_upstream("0.0.0.0:443").is_ok());
    }

    #[test]
    fn accepts_bracketed_ipv6() {
        assert!(validate_upstream("[::1]:8080").is_ok());
    }

    #[test]
    fn accepts_plausible_hostname() {
        assert!(validate_upstream("backend.internal:8080").is_ok());
        assert!(validate_upstream("service-2_a.local:4443").is_ok());
    }

    #[test]
    fn rejects_missing_port() {
        assert!(validate_upstream("127.0.0.1").is_err());
        assert!(validate_upstream("backend.internal").is_err());
    }

    #[test]
    fn rejects_url_scheme() {
        assert!(validate_upstream("https://127.0.0.1:8080").is_err());
    }

    #[test]
    fn rejects_trailing_path() {
        assert!(validate_upstream("127.0.0.1:8080/").is_err());
    }

    #[test]
    fn rejects_zero_port_and_garbage_port() {
        assert!(validate_upstream("127.0.0.1:0").is_err());
        assert!(validate_upstream("127.0.0.1:notaport").is_err());
    }

    #[test]
    fn rejects_empty_host() {
        assert!(validate_upstream(":8080").is_err());
    }

    #[test]
    fn rejects_whitespace() {
        assert!(validate_upstream("127.0.0.1 :8080").is_err());
    }
}
