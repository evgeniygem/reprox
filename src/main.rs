mod config;
mod http_util;
mod metrics;
mod prefixed_stream;
mod route;
mod sni;
mod tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::config::ServiceConfig;
use crate::metrics::Stats;
use crate::route::fallback::StaticSite;
use crate::sni::ProbeResult;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    // Required step for rustls 0.23+: install the process-wide default
    // crypto provider (we use aws_lc_rs — the same provider explicitly
    // used below when building the ServerConfig).
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls crypto provider"))?;

    let config = Arc::new(ServiceConfig::try_load().await?);
    tracing::info!(
        listen = %config.listen_addr,
        proxy = %config.proxy_addr,
        secret_domains = ?config.secret_domains,
        tls_profile = %config.tls_min_version,
        "configuration loaded"
    );

    let server_config = tls::build_server_config(&config).await?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let site = Arc::new(StaticSite::try_load(&config.static_dir).await?);
    let stats = Arc::new(Stats::new());

    if let Some(metrics_addr) = config.metrics_addr {
        let stats = stats.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::serve(metrics_addr, stats, config).await {
                tracing::error!(error = %e, "internal metrics API stopped with an error");
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
///    TLS session, classifying the result for both routing and metrics
///    (see `sni::ProbeResult`).
/// 2. If the SNI matches service's secret domain, transparently proxy the
///    TCP stream (together with the already-read buffer) to service.
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

    let (prefix, probe_result) =
        match timeout(probe_timeout, sni::probe_client_hello(&mut stream)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                tracing::debug!(%peer, error = %e, "read error while sniffing SNI");
                stats
                    .connections_probe_io_error_total
                    .fetch_add(1, Ordering::Relaxed);
                let _ = stream.shutdown().await;
                return Ok(());
            }
            Err(_) => {
                tracing::debug!(%peer, "timed out waiting for the ClientHello");
                stats
                    .connections_probe_timeout_total
                    .fetch_add(1, Ordering::Relaxed);
                let _ = stream.shutdown().await;
                return Ok(());
            }
        };

    let sni_host = match &probe_result {
        ProbeResult::Sni(host) => {
            stats.sni_present_total.fetch_add(1, Ordering::Relaxed);
            Some(host.clone())
        }
        ProbeResult::NoSni => {
            stats.sni_absent_total.fetch_add(1, Ordering::Relaxed);
            None
        }
        ProbeResult::NotTls => {
            stats
                .clienthello_not_tls_total
                .fetch_add(1, Ordering::Relaxed);
            None
        }
        ProbeResult::ConnectionClosed => {
            stats
                .connections_closed_early_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
    };

    let is_secret = sni_host
        .as_deref()
        .map(|h| config.matches_secret_domain(h))
        .unwrap_or(false);

    if is_secret {
        tracing::debug!(%peer, sni = ?sni_host, "SNI matched the secret domain — proxying to service");
        let _active = stats.begin_proxied();
        route::proxy(stream, prefix, &config.proxy_addr, stats.clone()).await
    } else {
        tracing::debug!(%peer, sni = ?sni_host, "SNI did not match — serving the fallback site");
        let _active = stats.begin_fallback();
        route::serve(stream, prefix, acceptor, site, config, stats.clone()).await
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
