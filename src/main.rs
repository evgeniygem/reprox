mod config;
mod fallback;
mod metrics;
mod prefixed_stream;
mod proxy;
mod sni;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::config::ServiceConfig;
use crate::fallback::StaticSite;
use crate::metrics::Stats;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    // Required step for rustls 0.23+: install the process-wide default
    // crypto provider (we use ring — the same provider explicitly used
    // below when building the ServerConfig).
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls crypto provider"))?;

    let config = Arc::new(ServiceConfig::try_load().await?);
    tracing::info!(
        listen = %config.listen_addr,
        telemt = %config.telemt_addr,
        secret_domains = ?config.secret_domains,
        tls_profile = %config.tls_min_version,
        "configuration loaded"
    );

    let server_config = tls::build_server_config(&config).await?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let site = Arc::new(StaticSite::try_load(&config.static_dir).await?);
    let stats = Arc::new(Stats::default());

    if let Some(metrics_addr) = config.metrics_addr {
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(metrics_addr, stats).await {
                tracing::error!(error = %e, "internal metrics endpoint stopped with an error");
            }
        });
    }

    let listener = TcpListener::bind(config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "reprox is listening");

    tokio::select! {
        res = accept_loop(listener, config, acceptor, site, stats) => res?,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received Ctrl+C, shutting down");
        }
    }

    Ok(())
}

async fn accept_loop(
    listener: TcpListener,
    config: Arc<ServiceConfig>,
    acceptor: TlsAcceptor,
    site: Arc<StaticSite>,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let _ = stream.set_nodelay(true);

        let config = config.clone();
        let acceptor = acceptor.clone();
        let site = site.clone();
        let stats = stats.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, config, acceptor, site, stats).await {
                tracing::debug!(%peer, error = %e, "connection ended with an error");
            }
        });
    }
}

/// Routing for a single incoming TCP connection:
/// 1. Sniff the SNI out of the ClientHello without establishing our own
///    TLS session.
/// 2. If the SNI matches telemt's secret domain, transparently proxy the
///    TCP stream (together with the already-read buffer) to telemt.
/// 3. Otherwise, terminate TLS ourselves using the real certificate and
///    serve the fallback site. This also covers: no SNI present, and an
///    outright invalid ClientHello — in both cases we still attempt a
///    full TLS handshake, just like an ordinary HTTPS server would.
async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ServiceConfig>,
    acceptor: TlsAcceptor,
    site: Arc<StaticSite>,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    let probe_timeout = Duration::from_secs(config.handshake_timeout_secs);

    let (prefix, sni_host) =
        match timeout(probe_timeout, sni::probe_client_hello(&mut stream)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::debug!(%peer, error = %e, "read error while sniffing SNI");
                let _ = stream.shutdown().await;
                return Ok(());
            }
            Err(_) => {
                tracing::debug!(%peer, "timed out waiting for the ClientHello");
                let _ = stream.shutdown().await;
                return Ok(());
            }
        };

    let is_secret = sni_host
        .as_deref()
        .map(|h| config.matches_secret_domain(h))
        .unwrap_or(false);

    if is_secret {
        tracing::debug!(%peer, sni = ?sni_host, "SNI matched the secret domain — proxying to telemt");
        stats.inc_proxied();
        proxy::route(stream, prefix, &config.telemt_addr).await
    } else {
        tracing::debug!(%peer, sni = ?sni_host, "SNI did not match — serving the fallback site");
        stats.inc_fallback();
        fallback::serve_tls(stream, prefix, acceptor, site, config).await
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}
