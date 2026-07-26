mod config;
mod http_util;
mod limiter;
mod metrics;
mod prefixed_stream;
mod route;
mod sni;
mod tls;

use anyhow::Context;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::ServiceConfig;
use crate::limiter::ConnectionLimiter;
use crate::metrics::Stats;
use crate::route::Router;
use crate::route::fallback::StaticSite;

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
        max_connections = config.max_connections,
        "configuration loaded"
    );

    let (server_config, cert_resolver) = tls::build_server_config(&config).await?;
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

    // Router::new takes ownership of one Arc<Stats>; keep our own clones
    // so we can still read the active-connection gauges after it (and
    // accept_loop, and the listener) are dropped below, and so
    // accept_loop can gate admission on the connection-slot semaphore
    // that also lives on `Stats` (see metrics::Stats::acquire_connection_slot).
    let router = Router::new(acceptor, stats.clone(), site, config.clone());

    // Watch for SIGHUP and reload config/routes/static site/TLS
    // certificate on each one — see `hot_reload` for exactly what
    // is and isn't picked up live. Unix-only (SIGHUP has no Windows
    // equivalent), matching this project's systemd/Linux deployment
    // target; on other platforms this simply isn't spawned, and the
    // process only supports a full restart to pick up config changes.
    #[cfg(unix)]
    {
        let router = router.clone();
        let cert_resolver = cert_resolver.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = hot_reload(router, cert_resolver, config).await {
                tracing::error!(
                    error = %e,
                    "SIGHUP reload watcher stopped;\
                     config/cert reload via SIGHUP is no longer available \
                     (a full restart still works)"
                );
            }
        });
    }

    let conn_limiter = ConnectionLimiter::new(config.max_connections, stats.clone());

    tokio::select! {
        res = accept_loop(listener, router, conn_limiter) => res?,
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
            tracing::warn!(error = %e, "failed to install the SIGINT handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
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
        _ = ctrl_c => tracing::info!("received SIGINT, shutting down"),
        _ = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}

/// Watches for SIGHUP and, on each one, reloads `config.toml`, the
/// `routes` table, the in-memory static site, and the TLS certificate/
/// key — all without dropping a single in-flight connection: an
/// existing connection keeps running against whatever state it already
/// snapshotted (`route::Router::route` takes its own snapshot at the
/// very start of each connection), so a reload only affects connections
/// accepted afterwards.
///
/// What does **not** take effect from a SIGHUP reload: `listen_addr`,
/// `metrics_addr`, `tls_min_version`, and `max_connections`. Each of
/// those is baked into something created once at startup — a bound
/// listener, a `rustls::ServerConfig`'s negotiated cipher/version set,
/// or a fixed-size semaphore — and none of those get rebuilt here.
/// Changing one of these in `config.toml` and sending SIGHUP logs a
/// warning (`ServiceConfig::warn_about_unreloadable_changes`) instead of
/// silently doing nothing, but a full restart is still required to
/// actually apply it.
///
/// A reload that fails partway through (bad TOML, a missing, invalid,
/// or mismatched cert/key, an unloadable static site) is logged and
/// otherwise ignored: the process keeps running on whatever
/// configuration it already had, rather than crashing or ending up in a
/// half-applied mix of old and new state.
#[cfg(unix)]
async fn hot_reload(
    router: Router,
    cert_resolver: Arc<tls::ReloadableCertResolver>,
    mut current_config: Arc<ServiceConfig>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sighup =
        signal(SignalKind::hangup()).context("failed to install the SIGHUP signal handler")?;

    loop {
        if sighup.recv().await.is_none() {
            tracing::error!(
                "SIGHUP signal stream ended unexpectedly; no longer watching for reloads"
            );
            return Ok(());
        }

        tracing::info!(
            "SIGHUP received — reloading config, routes, static site, and TLS certificate"
        );

        let new_config = match ServiceConfig::try_load().await {
            Ok(c) => Arc::new(c),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "reload failed: could not load/validate config.toml — \
                    keeping the previous configuration"
                );
                continue;
            }
        };
        current_config.warn_about_unreloadable_changes(&new_config);

        let certified_key = match tls::load_certified_key(
            &new_config.tls_cert_path,
            &new_config.tls_key_path,
        )
        .await
        {
            Ok(k) => k,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "reload failed: could not load the TLS certificate/key — keeping the previous certificate and configuration"
                );
                continue;
            }
        };

        cert_resolver.update(certified_key);
        router.reload(new_config.clone());
        current_config = new_config;

        tracing::info!("reload complete");
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

/// Accepts connections and hands each one to `router`, bounded by
/// `stats`'s connection-slot semaphore (`max_connections` in the
/// config).
///
/// The slot is acquired *before* `accept()` is even called, not after —
/// so once `max_connections` connections are in flight, this loop stops
/// pulling new sockets off the kernel's accept queue entirely instead of
/// accepting an unbounded number of them (each holding a file descriptor
/// and a spawned task) and only then discovering the process is out of
/// descriptors or memory. Excess connections simply queue in the
/// kernel's own accept backlog (and get refused once *that* fills up),
/// which is exactly how nginx's `worker_connections` limit behaves.
async fn accept_loop(
    listener: TcpListener,
    router: Router,
    connection_limiter: ConnectionLimiter,
) -> anyhow::Result<()> {
    loop {
        let slot = connection_limiter.acquire_slot().await;

        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // A transient accept() failure (e.g. the process
                // temporarily out of file descriptors) previously
                // propagated via `?` and brought the entire listener —
                // and every other in-flight connection along with it —
                // down. Log it and keep going instead; the short sleep
                // avoids spinning at 100% CPU if the underlying
                // condition doesn't clear up immediately. Give back the
                // slot we reserved for the connection that didn't
                // actually materialize, so it doesn't sit wasted until
                // the next successful accept happens to release one.
                drop(slot);
                tracing::warn!(error = %e, "accept() failed; retrying");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        let router = router.clone();

        tokio::spawn(async move {
            // Held for as long as the spawned task runs; dropped (and
            // the slot released back to the pool) whenever it ends, via
            // any path — normal completion, early return, or panic.
            let _slot = slot;
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
