mod config;
mod http_util;
mod metrics;
mod prefixed_stream;
mod route;
mod sni;
mod tls;

use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::ServiceConfig;
use crate::metrics::Stats;
use crate::route::fallback::StaticSite;
use crate::route::Router;

/// How long to wait, after a shutdown signal (SIGINT/Ctrl+C or SIGTERM),
/// for already-accepted connections (in-flight proxy sessions and
/// fallback HTTP responses) to finish on their own before the process
/// exits and the Tokio runtime aborts whatever tasks are still running.
/// Chosen to comfortably cover a large static-file download or a
/// short-lived proxy session without making an operator wait too long
/// for a routine restart.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// How long to sleep after a transient `accept()` error before trying
/// again. Without this, an error that keeps recurring on every call
/// (e.g. the process running out of file descriptors) would otherwise
/// spin the accept loop at 100% CPU instead of accepting connections.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

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
        routes = ?config.routes,
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

    // Router::new takes ownership of one Arc<Stats>; keep our own clone
    // so we can still read the active-connection gauges after it (and
    // accept_loop, and the listener) are dropped below.
    let router = Router::new(acceptor, stats.clone(), site, config);

    tokio::select! {
        res = accept_loop(listener, router) => res?,
        _ = shutdown_signal() => {}
    }

    // The listener (owned by accept_loop's future, now dropped) is
    // closed, so no new connections can arrive. Give connections that
    // were already accepted — an in-progress proxy session, a large
    // static file mid-download — a chance to finish on their own
    // instead of being aborted mid-stream the instant this function
    // returns and the Tokio runtime shuts down.
    wait_for_drain(&stats, SHUTDOWN_GRACE).await;

    Ok(())
}

/// Waits for whichever shutdown signal arrives first.
///
/// `tokio::signal::ctrl_c()` only ever fires on SIGINT — which covers
/// Ctrl+C in an interactive terminal, but *not* `systemctl stop`, whose
/// default `KillSignal` is SIGTERM. Without also handling SIGTERM here,
/// the graceful drain in `main` would never run under the systemd unit
/// this project's README documents: SIGTERM's default disposition is to
/// terminate the process immediately, abruptly cutting off whatever
/// connections were in flight.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "failed to install the Ctrl+C (SIGINT) handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => tracing::warn!(error = %e, "failed to install the SIGTERM handler"),
        }
    };
    // Non-Unix targets (e.g. a Windows dev machine) have no SIGTERM;
    // fall back to a future that never completes so `select!` below
    // relies on Ctrl+C alone there.
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl+C (SIGINT), shutting down"),
        _ = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}

/// Polls the active-connection gauges until both routes have drained to
/// zero or `grace_period` elapses, whichever comes first — see the
/// call site in `main` for why this matters.
async fn wait_for_drain(stats: &Stats, grace_period: Duration) {
    const POLL_INTERVAL: Duration = Duration::from_millis(200);
    let deadline = tokio::time::Instant::now() + grace_period;

    loop {
        let active = stats.active_connections();
        if active <= 0 {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                active,
                "shutdown grace period elapsed with connections still active; exiting anyway"
            );
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn accept_loop(listener: TcpListener, router: Router) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // A transient accept() failure (e.g. the process
                // temporarily out of file descriptors) previously
                // propagated via `?` and brought the entire listener —
                // and every other in-flight connection along with it —
                // down. Log it and keep going instead; the short sleep
                // avoids spinning at 100% CPU if the underlying
                // condition doesn't clear up immediately.
                tracing::warn!(error = %e, "accept() failed; retrying");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        let router = router.clone();

        tokio::spawn(async move {
            if let Err(e) = router.route(stream, peer).await {
                tracing::debug!(%peer, error = %e, "connection ended with an error");
            }
        });
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
