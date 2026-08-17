//! TCP proxying to the local service instance.
//!
//! Two variants live here, selected per-route by `ProxyTarget::tls_passthrough`
//! (see `route::router`):
//!
//! - `proxy` — the default, and there is nothing TLS-specific about it:
//!   service implements the handshake itself and is responsible for TLS
//!   record sizing — we only forward bytes in both directions, starting
//!   with the prefix already read during SNI sniffing (otherwise service
//!   would see a ClientHello missing its first few bytes and couldn't
//!   carry out its own handshake).
//! - `proxy_with_tls_termination` — for routes that opt out of passthrough:
//!   `reprox` terminates TLS itself (same certificate/`TlsAcceptor` as the
//!   fallback site) and relays the decrypted plaintext to `upstream` over a
//!   new, unencrypted TCP connection.
//!
//! Byte counters and connect-failure counts are recorded into `Stats` along
//! the way; connection count, active-connection gauge, and duration are
//! handled by the `ActiveGuard` the caller holds for the lifetime of the
//! connection.
//!
//! Connecting to the upstream service goes through `connect_with_backoff`:
//! a bounded number of attempts, each with its own timeout, with an
//! exponentially growing delay between them. This absorbs the two most
//! common *transient* failure modes without any operator intervention —
//! a service that's mid-restart (a moment of ECONNREFUSED) and a route
//! that's briefly slow to accept — while still giving up in bounded time
//! against a route that's genuinely down, rather than leaving the
//! client's connection (and the connection slot it holds — see
//! `main::accept_loop`) stuck for however long the OS's own, much
//! longer and platform-dependent connect timeout happens to be.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::config::ServiceConfig;
use crate::metrics::Stats;
use crate::prefixed_stream::PrefixedStream;
use anyhow::Context;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

/// How `connect_with_backoff` retries a failed or stalled connect to the
/// upstream service.
#[derive(Debug, Clone, Copy)]
struct ConnectRetryPolicy {
    /// Timeout for a single `TcpStream::connect` attempt. Bounds the
    /// case a plain connect error doesn't cover: a route that's
    /// firewalled (the SYN is silently dropped) rather than actively
    /// refusing, which the OS would otherwise only give up on after its
    /// own, much longer and platform-dependent default.
    attempt_timeout: Duration,
    /// Maximum number of attempts before giving up, including the
    /// first — e.g. `4` means "1 initial try + up to 3 retries".
    max_attempts: u32,
    /// Delay before the *first* retry (i.e. before attempt 2). Doubles
    /// after every subsequently failed attempt.
    base_delay: Duration,
    /// Upper bound on the delay between attempts, no matter how many
    /// have already failed — keeps the backoff from growing unboundedly
    /// against a route that's been down for a while.
    max_delay: Duration,
}

impl ConnectRetryPolicy {
    /// The policy `proxy()` uses in production. Worst case (every
    /// attempt times out) this bounds the time a client's connection —
    /// and the connection slot it holds, see `main::accept_loop` — can
    /// be stuck waiting on a dead upstream to `4 * 3s + (200+400+800)ms`
    /// ≈ 13.4s, versus the previous unbounded, platform-dependent wait
    /// on a single un-timed-out `TcpStream::connect`.
    const DEFAULT: Self = Self {
        attempt_timeout: Duration::from_secs(3),
        max_attempts: 4,
        base_delay: Duration::from_millis(200),
        max_delay: Duration::from_secs(2),
    };

    /// Delay to wait *before* making attempt number `attempt`.
    /// Grows exponentially with each attempt after the first,
    /// capped at `max_delay`.
    fn get_delay(&self, attempt: u32) -> Duration {
        if attempt <= 1 {
            return Duration::ZERO;
        }
        // attempt 2 waits base_delay, attempt 3 waits base_delay*2,
        // attempt 4 waits base_delay*4, and so on.
        let exponent = attempt - 2;
        let multiplier = 1u32.checked_shl(exponent).unwrap_or(u32::MAX);
        self.base_delay
            .checked_mul(multiplier)
            .unwrap_or(self.max_delay)
            .min(self.max_delay)
    }
}

/// Generic exponential-backoff retry driver: calls `attempt` up to
/// `policy.max_attempts` times (attempt numbers are 1-indexed), sleeping
/// `policy.get_delay(n)` before each attempt after the first, and
/// returning as soon as one succeeds. Returns the last error if every
/// attempt fails.
///
/// Kept generic over what an "attempt" actually does — rather than
/// hardcoding a `TcpStream::connect` call — so the backoff/retry
/// mechanism itself can be unit-tested (see `tests` below) without any
/// real network I/O. `connect_with_backoff` is the only caller, and
/// wires it up to a real connect.
async fn retry_with_backoff<T, E, F, Fut>(policy: &ConnectRetryPolicy, mut func: F) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut last_err = None;
    for n in 1..=policy.max_attempts.max(1) {
        let delay = policy.get_delay(n);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        match func(n).await {
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("the loop runs at least once, so this is always set on the Err path"))
}

/// Connects to `endpoint`, retrying with exponential backoff (per
/// `policy`) on a connect error or a per-attempt timeout.
///
/// Every failed attempt except the last one (i.e. every attempt that
/// will actually be retried) bumps `proxy_service_connect_retries_total`;
/// the final give-up is counted separately by the caller, as
/// `proxy_service_connect_failures_total` — so the two metrics together
/// distinguish "service was just briefly slow to accept" from "service
/// is actually down".
async fn connect_with_backoff(
    endpoint: &str,
    policy: &ConnectRetryPolicy,
    stats: &Stats,
) -> std::io::Result<TcpStream> {
    let max_attempts = policy.max_attempts.max(1);

    retry_with_backoff(policy, |attempt| async move {
        let err = match timeout(policy.attempt_timeout, TcpStream::connect(endpoint)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => e,
            Err(_) => std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "connect to {endpoint} timed out after {:?}",
                    policy.attempt_timeout
                ),
            ),
        };

        if attempt < max_attempts {
            stats
                .proxy_service_connect_retries_total
                .fetch_add(1, Ordering::Relaxed);
        }
        tracing::debug!(
            endpoint,
            attempt,
            max_attempts,
            error = %err,
            "connect to service failed"
        );
        Err(err)
    })
    .await
}

async fn relay_to_service<S>(
    stream: &mut S,
    prefix: Option<Bytes>,
    endpoint: &str,
    stats: Arc<Stats>,
) -> anyhow::Result<()>
where
    S: AsyncWrite + AsyncRead + Unpin,
{
    let mut upstream =
        match connect_with_backoff(endpoint, &ConnectRetryPolicy::DEFAULT, &stats).await {
            Ok(s) => s,
            Err(e) => {
                stats
                    .proxy_service_connect_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e).with_context(|| {
                    format!(
                        "failed to connect to service at {endpoint} after {} attempt(s)",
                        ConnectRetryPolicy::DEFAULT.max_attempts
                    )
                });
            }
        };
    let _ = upstream.set_nodelay(true);

    if let Some(prefix) = prefix.as_ref()
        && !prefix.is_empty()
    {
        upstream
            .write_all(prefix)
            .await
            .context("failed to forward the buffered ClientHello to service")?;
        stats
            .proxy_bytes_client_to_service_total
            .fetch_add(prefix.len() as u64, Ordering::Relaxed);
    }

    match tokio::io::copy_bidirectional(stream, &mut upstream).await {
        Ok((from_client, from_upstream)) => {
            stats
                .proxy_bytes_client_to_service_total
                .fetch_add(from_client, Ordering::Relaxed);
            stats
                .proxy_bytes_service_to_client_total
                .fetch_add(from_upstream, Ordering::Relaxed);
            tracing::debug!(from_client, from_upstream, "service session closed");
        }
        Err(e) => {
            // One side dropping the connection is normal for long-lived
            // proxied sessions, not an application error.
            tracing::debug!(error = %e, "service session ended with an I/O error");
        }
    }

    Ok(())
}

pub async fn proxy(
    mut client: TcpStream,
    prefix: Bytes,
    endpoint: &str,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    relay_to_service(&mut client, Some(prefix), endpoint, stats).await
}

/// Like `proxy`, but for a route with `tls_passthrough = false`: instead of
/// forwarding the raw TLS bytes untouched, `reprox` terminates the TLS
/// connection itself — reusing the same certificate/`TlsAcceptor` as the
/// fallback site (`route::serve::serve`) — and relays the *decrypted*
/// plaintext to `endpoint` over a new, unencrypted TCP connection.
///
/// `prefix` is the ClientHello bytes already read during SNI sniffing;
/// it's replayed into the TLS handshake via `PrefixedStream`, exactly as
/// `serve` does for the fallback path, so no byte of the handshake is
/// lost. The handshake itself, ALPN bookkeeping, and connect-with-backoff
/// to `endpoint` all mirror `serve`/`proxy` respectively — see those for
/// the reasoning behind each step.
pub async fn proxy_with_tls_termination(
    stream: TcpStream,
    prefix: Bytes,
    acceptor: TlsAcceptor,
    endpoint: &str,
    config: Arc<ServiceConfig>,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    let io = PrefixedStream::new(prefix, stream);
    let handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);

    let mut tls_stream = match timeout(handshake_timeout, acceptor.accept(io)).await {
        Ok(Ok(s)) => {
            stats
                .proxy_tls_handshake_success_total
                .fetch_add(1, Ordering::Relaxed);
            s
        }
        Ok(Err(e)) => {
            // Invalid ClientHello, unsupported TLS version, etc. rustls
            // itself sends a proper TLS alert wherever the protocol calls
            // for one; after the error we just close the connection —
            // with no forced RST (there is no SO_LINGER(0) anywhere in
            // this project).
            stats
                .proxy_tls_handshake_failure_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(error = %e, "proxy-path TLS handshake failed");
            return Ok(());
        }
        Err(_) => {
            // Slowloris-style stall: the client never finished the TLS
            // handshake within handshake_timeout_secs.
            stats
                .proxy_tls_handshake_failure_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!("proxy-path TLS handshake timed out");
            return Ok(());
        }
    };

    relay_to_service(&mut tls_stream, None, endpoint, stats).await
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;

    use tokio::net::TcpListener;

    use super::*;

    /// A policy fast enough that even the "give up after every attempt
    /// fails" tests below finish in well under a second of real time —
    /// no `tokio::time::pause`/mocked clock needed.
    fn test_policy() -> ConnectRetryPolicy {
        ConnectRetryPolicy {
            attempt_timeout: Duration::from_millis(200),
            max_attempts: 4,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
        }
    }

    #[test]
    fn get_delay_first_attempt_is_zero() {
        assert_eq!(ConnectRetryPolicy::DEFAULT.get_delay(1), Duration::ZERO);
    }

    #[test]
    fn get_delay_doubles_each_attempt() {
        let policy = ConnectRetryPolicy {
            attempt_timeout: Duration::from_secs(1),
            max_attempts: 6,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
        };
        assert_eq!(policy.get_delay(2), Duration::from_millis(100));
        assert_eq!(policy.get_delay(3), Duration::from_millis(200));
        assert_eq!(policy.get_delay(4), Duration::from_millis(400));
        assert_eq!(policy.get_delay(5), Duration::from_millis(800));
    }

    #[test]
    fn get_delay_is_capped_at_max_delay() {
        let policy = ConnectRetryPolicy {
            attempt_timeout: Duration::from_secs(1),
            max_attempts: 20,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(2),
        };
        // Uncapped this would be 100ms * 2^12 ≈ 409.6s.
        assert_eq!(policy.get_delay(14), Duration::from_secs(2));
        assert_eq!(policy.get_delay(20), Duration::from_secs(2));
    }

    #[test]
    fn get_delay_never_panics_on_extreme_attempt_numbers() {
        let policy = ConnectRetryPolicy {
            attempt_timeout: Duration::from_millis(1),
            max_attempts: u32::MAX,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
        };
        // Would overflow a naive `1 << (attempt - 2)` computation well
        // before this; must saturate at max_delay instead of panicking.
        assert_eq!(policy.get_delay(u32::MAX), Duration::from_millis(5));
    }

    #[tokio::test]
    async fn retry_with_backoff_returns_first_success_without_retrying() {
        let policy = test_policy();
        let calls = AtomicU32::new(0);

        let result: Result<u32, &str> = retry_with_backoff(&policy, |_attempt| {
            calls.fetch_add(1, Ordering::Relaxed);
            async { Ok(42) }
        })
        .await;

        assert_eq!(result, Ok(42));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn retry_with_backoff_retries_until_success() {
        let policy = test_policy();
        let calls = AtomicU32::new(0);

        let result: Result<u32, &str> = retry_with_backoff(&policy, |attempt| {
            calls.fetch_add(1, Ordering::Relaxed);
            async move {
                if attempt < 3 {
                    Err("not yet")
                } else {
                    Ok(attempt)
                }
            }
        })
        .await;

        assert_eq!(result, Ok(3));
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn retry_with_backoff_gives_up_after_max_attempts() {
        let policy = test_policy(); // max_attempts == 4
        let calls = AtomicU32::new(0);

        let result: Result<u32, &str> = retry_with_backoff(&policy, |_attempt| {
            calls.fetch_add(1, Ordering::Relaxed);
            async { Err("still down") }
        })
        .await;

        assert_eq!(result, Err("still down"));
        assert_eq!(calls.load(Ordering::Relaxed), 4);
    }

    // --- connect_with_backoff (real loopback sockets, no timing tricks) ---

    #[tokio::test]
    async fn connect_with_backoff_succeeds_on_the_first_attempt() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let stats = Stats::new();
        let result = connect_with_backoff(&addr.to_string(), &test_policy(), &stats).await;

        assert!(result.is_ok());
        assert_eq!(
            stats
                .proxy_service_connect_retries_total
                .load(Ordering::Relaxed),
            0,
            "a first-try success must not be counted as a retry"
        );
    }

    #[tokio::test]
    async fn connect_with_backoff_gives_up_and_counts_retries_on_a_dead_port() {
        // Bind to grab a free port, then drop the listener immediately —
        // nothing is listening there afterwards, so the OS answers new
        // connection attempts with an immediate refusal (no waiting on
        // attempt_timeout), keeping this test fast.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let policy = test_policy(); // max_attempts == 4
        let stats = Stats::new();
        let result = connect_with_backoff(&addr.to_string(), &policy, &stats).await;

        assert!(result.is_err());
        // 4 attempts total: the first 3 are each followed by another
        // attempt (so they count as retries); the 4th, final one does
        // not — it's what the caller counts as
        // proxy_service_connect_failures_total instead.
        assert_eq!(
            stats
                .proxy_service_connect_retries_total
                .load(Ordering::Relaxed),
            3
        );
    }
}
