mod config;
mod http_util;
mod ip_limiter;
mod limiter;
mod metrics;
mod prefixed_stream;
mod rate_limiter;
mod route;
mod sni;
mod tls;

use anyhow::Context;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::ServiceConfig;
use crate::ip_limiter::IpLimiter;
use crate::limiter::ConnectionLimiter;
use crate::metrics::Stats;
use crate::rate_limiter::RateLimiter;
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
    let rate_limiter = RateLimiter::new(
        config.connection_rate_per_ip.unwrap_or(0.0),
        config.connection_burst_per_ip.unwrap_or(10),
    );
    let ip_limiter = IpLimiter::new(config.max_connections_per_ip.unwrap_or(0));

    // Watch for SIGHUP and reload config/routes/TLS certificate on
    // each one — see `hot_reload` for exactly what
    // is and isn't picked up live. Unix-only (SIGHUP has no Windows
    // equivalent), matching this project's systemd/Linux deployment
    // target; on other platforms this simply isn't spawned, and the
    // process only supports a full restart to pick up config changes.
    #[cfg(unix)]
    {
        let router = router.clone();
        let cert_resolver = cert_resolver.clone();
        let config = config.clone();
        let ip_limiter = ip_limiter.clone();
        let rate_limiter = rate_limiter.clone();

        tokio::spawn(async move {
            if let Err(e) =
                hot_reload(router, cert_resolver, ip_limiter, rate_limiter, config).await
            {
                tracing::error!(
                    error = %e,
                    "SIGHUP reload watcher stopped;\
                     config/cert reload via SIGHUP is no longer available \
                     (a full restart still works)"
                );
            }
        });
    }

    // Background task: periodically sweeps stale buckets
    {
        let rate_limiter = rate_limiter.clone();
        tokio::spawn(async move {
            run_janitor(rate_limiter, Duration::from_secs(300)).await;
        });
    }

    let conn_limiter = ConnectionLimiter::new(config.max_connections, stats.clone());

    tokio::select! {
        res = accept_loop(listener,
                          router,
                          conn_limiter,
                          ip_limiter,
                          rate_limiter,
                          stats.clone()) => res?,
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
/// `routes` table, and the TLS certificate/key — all without dropping a
/// single in-flight connection: an existing connection keeps running
/// against whatever state it already snapshotted (`route::Router::route`
/// takes its own snapshot at the very start of each connection), so a
/// reload only affects connections accepted afterwards.
///
/// What does **not** take effect from a SIGHUP reload: `listen_addr`,
/// `metrics_addr`, `tls_min_version`, `max_connections`, and
/// `static_dir`. Each of those is baked into something created once at
/// startup — a bound listener, a `rustls::ServerConfig`'s negotiated
/// cipher/version set, a fixed-size semaphore, or (for `static_dir`)
/// the in-memory static site built once in `main` and handed to
/// `Router::new` — and none of those get rebuilt here. Changing one of
/// these in `config.toml` and sending SIGHUP logs a warning
/// (`ServiceConfig::warn_about_unreloadable_changes`) instead of
/// silently doing nothing, but a full restart is still required to
/// actually apply it.
///
/// A reload that fails partway through (bad TOML, or a missing,
/// invalid, or mismatched cert/key) is logged and otherwise ignored:
/// the process keeps running on whatever configuration it already had,
/// rather than crashing or ending up in a half-applied mix of old and
/// new state.
#[cfg(unix)]
async fn hot_reload(
    router: Router,
    cert_resolver: Arc<tls::ReloadableCertResolver>,
    ip_limiter: IpLimiter,
    rate_limiter: RateLimiter,
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

        tracing::info!("SIGHUP received — reloading config, routes, and TLS certificate");

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

        // Update states
        cert_resolver.update(certified_key);
        router.reload(new_config.clone());

        ip_limiter.set_limit(new_config.max_connections_per_ip.unwrap_or(0));

        rate_limiter.set_limit(
            new_config.connection_rate_per_ip.unwrap_or(0.0),
            new_config.connection_burst_per_ip.unwrap_or(10),
        );

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

/// Run the janitor to clear the rate limiter's memory. A full buffer is
/// indistinguishable from an IP address that has never been encountered,
/// so deleting it does not result in any loss of state.
async fn run_janitor(rate_limiter: RateLimiter, duration: Duration) {
    let mut timer = tokio::time::interval(duration);

    loop {
        timer.tick().await;
        rate_limiter.sweep();
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
    ip_limiter: IpLimiter,
    rate_limiter: RateLimiter,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    loop {
        let conn_slot = connection_limiter.acquire_slot().await;

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
                drop(conn_slot);
                tracing::warn!(error = %e, "accept() failed; retrying");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        if !rate_limiter.allow(peer.ip()) {
            drop(conn_slot); // give the global slot back too
            tracing::debug!(%peer, "rejected: per-IP connection rate exceeded");
            stats
                .connections_rejected_rate_limit_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }

        // Per-IP check happens after accept() (we only learn the peer's
        // address once the socket exists), but before the connection
        // task is spawned — a flooding IP gets its socket closed
        // immediately instead of ever reaching the SNI-probe stage.
        let ip_slot = match ip_limiter.try_acquire_slot(peer.ip()) {
            Some(s) => s,
            None => {
                drop(conn_slot); // give the global slot back too
                tracing::debug!(%peer, "rejected: per-IP connection limit reached");
                stats
                    .connections_rejected_ip_limit_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                continue; // `stream` drops here, closing the socket
            }
        };

        let router = router.clone();

        tokio::spawn(async move {
            // Held for as long as the spawned task runs; dropped (and
            // the slot released back to the pool) whenever it ends, via
            // any path — normal completion, early return, or panic.
            let _conn_slot = conn_slot;
            let _ip_slot = ip_slot;
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
