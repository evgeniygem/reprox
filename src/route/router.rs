//! Ties `sni::probe_client_hello`, the proxy path (`route::proxy`), and
//! the fallback HTTPS site (`route::serve`) together into a single
//! per-connection routing decision, and owns the shared, cheaply
//! cloneable state (the SNI→upstream table, TLS acceptor, stats,
//! static site, config) that every accepted connection needs.
//!
//! The SNI table, and config are grouped into a single `RouterState`,
//! swapped as one atomic unit behind a `RwLock<Arc<_>>` so
//! `main::hot_reload` can apply reload without ever letting
//! one connection see routes from one config version alongside
//! static content from another. `route()` takes a single snapshot (one
//! cheap `Arc` clone) at the very start of each connection and uses
//! that snapshot for the connection's whole lifetime — a reload never
//! changes behavior mid-connection, only for connections accepted
//! afterwards.
//!
//! The TLS acceptor is *not* part of this swappable state: its
//! certificate reloads through a different mechanism (see
//! `tls::ReloadableCertResolver`) that doesn't require rebuilding the
//! `rustls::ServerConfig`/`TlsAcceptor` itself, so the acceptor held
//! here never needs to change after startup.

use hashbrown::HashMap;
use rustc_hash::FxBuildHasher;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use super::proxy::proxy;
use super::serve::serve;
use crate::config::{ProxyTarget, ServiceConfig};
use crate::metrics::Stats;
use crate::route::fallback::StaticSite;
use crate::sni::{self, ProbeResult};

/// One immutable snapshot of everything a routing decision needs that
/// can change on a SIGHUP reload: the SNI→upstream lookup table (built
/// once here from `config.routes` rather than scanned linearly per
/// connection) and the config it was built from. Wrapped in an `Arc` and
/// swapped as a single unit by `Router::reload`, so a connection that
/// took its snapshot via `Router::route` never sees routes from one
/// config version mixed with, say, `handshake_timeout_secs` from another.
struct RouterState {
    /// SNI → route lookup, keyed by the same normalized (lowercased,
    /// trailing-dot-stripped) form `sni::parse_server_name_extension`
    /// produces, so `route()` can look up the probed SNI directly.
    routes: HashMap<String, ProxyTarget, FxBuildHasher>,
    /// The config this snapshot was built from; handed to `route::serve`
    /// for the fallback path (headers, handshake timeout, etc.) so it
    /// too stays consistent with whichever `routes` table was matched.
    config: Arc<ServiceConfig>,
}

impl RouterState {
    fn new(config: Arc<ServiceConfig>) -> Self {
        let mut routes = HashMap::with_capacity_and_hasher(config.routes.len(), FxBuildHasher);

        for route in config.routes.iter() {
            routes.insert(route.sni.clone(), route.clone());
        }

        Self { routes, config }
    }
}

/// Shared state behind every clone of `Router`. Kept in its own struct
/// (rather than fields directly on `Router`) so `Router::clone()` is
/// just an `Arc` bump, not a deep copy — cheap enough to clone once per
/// accepted connection (see `main::accept_loop`).
struct Inner {
    state: RwLock<Arc<RouterState>>,
    acceptor: TlsAcceptor,
    stats: Arc<Stats>,
    site: Arc<StaticSite>,
}

/// Cheaply cloneable handle used to route each accepted TCP connection.
/// One `Router` is constructed at startup and cloned per connection in
/// `main::accept_loop`.
#[derive(Clone)]
pub struct Router {
    inner: Arc<Inner>,
}

impl Router {
    /// Builds the SNI→upstream lookup table from `config.routes` and
    /// bundles it with the other pieces every connection needs to be
    /// routed: the TLS acceptor for the fallback path, shared metrics,
    /// the in-memory static site, and the config itself.
    pub fn new(
        acceptor: TlsAcceptor,
        stats: Arc<Stats>,
        site: Arc<StaticSite>,
        config: Arc<ServiceConfig>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(Arc::new(RouterState::new(config))),
                acceptor,
                stats,
                site,
            }),
        }
    }

    /// Atomically swaps in a freshly loaded routing table (rebuilt from
    /// `config.routes`). Connections already inside `route()` keep using
    /// whatever snapshot they already took (see `route()` below); only
    /// connections accepted after this call see the new state.
    pub fn reload(&self, config: Arc<ServiceConfig>) {
        let new_state = Arc::new(RouterState::new(config));
        *self
            .inner
            .state
            .write()
            .expect("router state lock poisoned") = new_state;
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
    pub async fn route(&self, mut stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
        // One snapshot of routes/config for this connection's
        // whole lifetime — a single cheap `Arc` clone, held only long
        // enough to read it out of the lock.
        let state = self
            .inner
            .state
            .read()
            .expect("router state lock poisoned")
            .clone();

        // Bound how long we'll wait for a complete ClientHello before
        // giving up — protects against slowloris-style connections that
        // open a socket and then trickle bytes in (or send nothing at
        // all) forever.
        let probe_timeout = Duration::from_secs(state.config.handshake_timeout_secs);

        let stats = self.inner.stats.clone();

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

        // `sni_host` (from `sni::parse_server_name_extension`) and the
        // keys of `state.routes` (from `ServiceConfig::try_load`) are
        // both already lowercased with any trailing dot stripped, so a
        // plain lookup is all that's needed here.
        let target = sni_host.as_deref().and_then(|h| state.routes.get(h));

        match target {
            Some(target) => {
                tracing::debug!(%peer, sni = ?sni_host, "SNI matched the secret domain — proxying to service");
                let _active = self.inner.stats.begin_proxied();
                proxy(stream, prefix, &target.upstream, stats).await
            }
            None => {
                tracing::debug!(%peer, sni = ?sni_host, "SNI did not match — serving the fallback site");
                let _active = self.inner.stats.begin_fallback();
                serve(
                    stream,
                    prefix,
                    self.inner.acceptor.clone(),
                    self.inner.site.clone(),
                    state.config.clone(),
                    stats,
                )
                .await
            }
        }
    }
}
