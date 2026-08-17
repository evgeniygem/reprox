//! Internal metrics/API endpoint.
//!
//! Only ever listens on a loopback address (checked twice: once when
//! the config is validated, and again right before binding), so it is
//! unreachable from outside the VPS by construction — there are no
//! "technical" paths exposed on the main 443 port under the domain
//! either.
//!
//! Exposes three GET-only routes over plain HTTP:
//!   - `/metrics`       Prometheus text exposition format.
//!   - `/metrics.json`  the same data as structured JSON.
//!   - `/healthz`       trivial liveness check ("ok").
//!
//! Anything else returns 404; non-GET requests return 405.

use std::convert::Infallible;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use crate::config::ServiceConfig;
use crate::http_util::{ResponseBody, full_body};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpListener;

/// Which code path a connection took. Used to pick which "active
/// connections" gauge and duration accumulator an `ActiveGuard`
/// updates, and to label the corresponding metrics.
#[derive(Debug, Clone, Copy)]
enum Route {
    Proxied,
    Fallback,
}

/// RAII guard for the "active connections" gauge and per-route
/// duration/­completion counters: everything is recorded once, when the
/// guard is dropped — including when the connection handler returns
/// early via `?` or panics — so these numbers can never drift from
/// reality the way a manual "decrement at the end" call might if a code
/// path forgot to call it.
pub struct ActiveGuard {
    stats: Arc<Stats>,
    route: Route,
    started: Instant,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let elapsed_ms = self.started.elapsed().as_millis() as u64;
        match self.route {
            Route::Proxied => {
                self.stats.active_proxied.fetch_sub(1, Ordering::Relaxed);
                self.stats
                    .connections_proxied_completed_total
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .proxy_connection_duration_ms_total
                    .fetch_add(elapsed_ms, Ordering::Relaxed);
            }
            Route::Fallback => {
                self.stats.active_fallback.fetch_sub(1, Ordering::Relaxed);
                self.stats
                    .connections_fallback_completed_total
                    .fetch_add(1, Ordering::Relaxed);
                self.stats
                    .fallback_connection_duration_ms_total
                    .fetch_add(elapsed_ms, Ordering::Relaxed);
            }
        }
    }
}

/// All counters/gauges tracked by the process. Every field that other
/// modules (proxy.rs, serve) need to update directly is `pub`;
/// the rest (active-connection gauges, start time) is only ever touched
/// through `Stats`'s own methods so invariants (e.g. gauges never going
/// negative in practice) stay in one place.
pub struct Stats {
    start: Instant,

    // --- connections ---
    pub connections: AtomicU64,
    pub connections_rejected_ip_limit_total: AtomicU64,
    pub connections_rejected_rate_limit_total: AtomicU64,
    pub connections_proxied_total: AtomicU64,
    pub connections_fallback_total: AtomicU64,
    connections_proxied_completed_total: AtomicU64,
    connections_fallback_completed_total: AtomicU64,
    proxy_connection_duration_ms_total: AtomicU64,
    fallback_connection_duration_ms_total: AtomicU64,
    pub connections_probe_timeout_total: AtomicU64,
    pub connections_probe_io_error_total: AtomicU64,
    pub connections_closed_early_total: AtomicU64,
    active_proxied: AtomicI64,
    active_fallback: AtomicI64,

    // --- ClientHello classification (see sni::ProbeResult) ---
    pub sni_present_total: AtomicU64,
    pub sni_absent_total: AtomicU64,
    pub clienthello_not_tls_total: AtomicU64,

    // --- service proxy path ---
    pub proxy_bytes_client_to_service_total: AtomicU64,
    pub proxy_bytes_service_to_client_total: AtomicU64,
    pub proxy_service_connect_failures_total: AtomicU64,
    pub proxy_service_connect_retries_total: AtomicU64,

    // --- fallback TLS ---
    pub fallback_tls_handshake_success_total: AtomicU64,
    pub fallback_tls_handshake_failure_total: AtomicU64,
    pub fallback_alpn_h2_total: AtomicU64,
    pub fallback_alpn_http1_total: AtomicU64,
    pub fallback_alpn_none_total: AtomicU64,

    // --- proxy TLS ---
    pub proxy_tls_handshake_success_total: AtomicU64,
    pub proxy_tls_handshake_failure_total: AtomicU64,

    // --- fallback HTTP ---
    pub http_method_get_total: AtomicU64,
    pub http_method_head_total: AtomicU64,
    pub http_method_options_total: AtomicU64,
    pub http_method_other_total: AtomicU64,
    pub http_status_200_total: AtomicU64,
    pub http_status_204_total: AtomicU64,
    pub http_status_304_total: AtomicU64,
    pub http_status_404_total: AtomicU64,
    pub http_status_405_total: AtomicU64,
    pub http_status_other_total: AtomicU64,
    pub http_bytes_sent_total: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            connections: AtomicU64::new(0),
            connections_rejected_ip_limit_total: AtomicU64::new(0),
            connections_rejected_rate_limit_total: AtomicU64::new(0),
            connections_proxied_total: AtomicU64::new(0),
            connections_fallback_total: AtomicU64::new(0),
            connections_proxied_completed_total: AtomicU64::new(0),
            connections_fallback_completed_total: AtomicU64::new(0),
            proxy_connection_duration_ms_total: AtomicU64::new(0),
            fallback_connection_duration_ms_total: AtomicU64::new(0),
            connections_probe_timeout_total: AtomicU64::new(0),
            connections_probe_io_error_total: AtomicU64::new(0),
            connections_closed_early_total: AtomicU64::new(0),
            active_proxied: AtomicI64::new(0),
            active_fallback: AtomicI64::new(0),
            sni_present_total: AtomicU64::new(0),
            sni_absent_total: AtomicU64::new(0),
            clienthello_not_tls_total: AtomicU64::new(0),
            proxy_bytes_client_to_service_total: AtomicU64::new(0),
            proxy_bytes_service_to_client_total: AtomicU64::new(0),
            proxy_service_connect_failures_total: AtomicU64::new(0),
            proxy_service_connect_retries_total: AtomicU64::new(0),
            fallback_tls_handshake_success_total: AtomicU64::new(0),
            fallback_tls_handshake_failure_total: AtomicU64::new(0),
            fallback_alpn_h2_total: AtomicU64::new(0),
            fallback_alpn_http1_total: AtomicU64::new(0),
            fallback_alpn_none_total: AtomicU64::new(0),
            proxy_tls_handshake_success_total: AtomicU64::new(0),
            proxy_tls_handshake_failure_total: AtomicU64::new(0),
            http_method_get_total: AtomicU64::new(0),
            http_method_head_total: AtomicU64::new(0),
            http_method_options_total: AtomicU64::new(0),
            http_method_other_total: AtomicU64::new(0),
            http_status_200_total: AtomicU64::new(0),
            http_status_204_total: AtomicU64::new(0),
            http_status_304_total: AtomicU64::new(0),
            http_status_404_total: AtomicU64::new(0),
            http_status_405_total: AtomicU64::new(0),
            http_status_other_total: AtomicU64::new(0),
            http_bytes_sent_total: AtomicU64::new(0),
        }
    }

    /// Call when a connection starts being routed to service. Returns a
    /// guard that must be kept alive for as long as the connection is
    /// being served; dropping it (including via early return) records
    /// completion and duration automatically.
    pub fn begin_proxied(self: &Arc<Self>) -> ActiveGuard {
        self.connections_proxied_total
            .fetch_add(1, Ordering::Relaxed);
        self.active_proxied.fetch_add(1, Ordering::Relaxed);
        ActiveGuard {
            stats: self.clone(),
            route: Route::Proxied,
            started: Instant::now(),
        }
    }

    /// Same as `begin_proxied`, for connections served by the fallback
    /// HTTPS site.
    pub fn begin_fallback(self: &Arc<Self>) -> ActiveGuard {
        self.connections_fallback_total
            .fetch_add(1, Ordering::Relaxed);
        self.active_fallback.fetch_add(1, Ordering::Relaxed);
        ActiveGuard {
            stats: self.clone(),
            route: Route::Fallback,
            started: Instant::now(),
        }
    }

    pub fn uptime_seconds(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    /// Total number of connections currently being served, across both
    /// routes. Used by `main`'s graceful-shutdown drain to know when it's
    /// safe to exit; also handy as a quick "is anything still happening"
    /// check outside of Prometheus/JSON scraping.
    pub fn active_connections(&self) -> i64 {
        self.connections.load(Ordering::Relaxed) as i64
    }

    fn snapshot(&self, config: &ServiceConfig) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_seconds: self.uptime_seconds(),
            connections: ConnectionsSnapshot {
                proxied_total: self.connections_proxied_total.load(Ordering::Relaxed),
                fallback_total: self.connections_fallback_total.load(Ordering::Relaxed),
                proxied_completed_total: self
                    .connections_proxied_completed_total
                    .load(Ordering::Relaxed),
                fallback_completed_total: self
                    .connections_fallback_completed_total
                    .load(Ordering::Relaxed),
                active_proxied: self.active_proxied.load(Ordering::Relaxed),
                active_fallback: self.active_fallback.load(Ordering::Relaxed),
                proxied_duration_ms_sum: self
                    .proxy_connection_duration_ms_total
                    .load(Ordering::Relaxed),
                fallback_duration_ms_sum: self
                    .fallback_connection_duration_ms_total
                    .load(Ordering::Relaxed),
                probe_timeout_total: self.connections_probe_timeout_total.load(Ordering::Relaxed),
                probe_io_error_total: self
                    .connections_probe_io_error_total
                    .load(Ordering::Relaxed),
                closed_early_total: self.connections_closed_early_total.load(Ordering::Relaxed),
                connections_limit: config.max_connections as u64,
                connections_available: (config.max_connections as u64)
                    .saturating_sub(self.connections.load(Ordering::Relaxed)),
                ip_limit_total: self
                    .connections_rejected_ip_limit_total
                    .load(Ordering::Relaxed),
                rate_limit_total: self
                    .connections_rejected_rate_limit_total
                    .load(Ordering::Relaxed),
            },
            clienthello: ClientHelloSnapshot {
                sni_present_total: self.sni_present_total.load(Ordering::Relaxed),
                sni_absent_total: self.sni_absent_total.load(Ordering::Relaxed),
                not_tls_total: self.clienthello_not_tls_total.load(Ordering::Relaxed),
            },
            proxy: ProxySnapshot {
                bytes_client_to_service_total: self
                    .proxy_bytes_client_to_service_total
                    .load(Ordering::Relaxed),
                bytes_service_to_client_total: self
                    .proxy_bytes_service_to_client_total
                    .load(Ordering::Relaxed),
                service_connect_failures_total: self
                    .proxy_service_connect_failures_total
                    .load(Ordering::Relaxed),
                service_connect_retries_total: self
                    .proxy_service_connect_retries_total
                    .load(Ordering::Relaxed),
            },
            tls: TlsSnapshot {
                fallback_handshake_success_total: self
                    .fallback_tls_handshake_success_total
                    .load(Ordering::Relaxed),
                fallback_handshake_failure_total: self
                    .fallback_tls_handshake_failure_total
                    .load(Ordering::Relaxed),
                fallback_alpn_h2_total: self.fallback_alpn_h2_total.load(Ordering::Relaxed),
                fallback_alpn_http1_total: self.fallback_alpn_http1_total.load(Ordering::Relaxed),
                fallback_alpn_none_total: self.fallback_alpn_none_total.load(Ordering::Relaxed),

                proxy_handshake_success_total: self
                    .proxy_tls_handshake_success_total
                    .load(Ordering::Relaxed),
                proxy_handshake_failure_total: self
                    .proxy_tls_handshake_failure_total
                    .load(Ordering::Relaxed),
            },
            http: HttpSnapshot {
                method_get_total: self.http_method_get_total.load(Ordering::Relaxed),
                method_head_total: self.http_method_head_total.load(Ordering::Relaxed),
                method_options_total: self.http_method_options_total.load(Ordering::Relaxed),
                method_other_total: self.http_method_other_total.load(Ordering::Relaxed),
                status_200_total: self.http_status_200_total.load(Ordering::Relaxed),
                status_204_total: self.http_status_204_total.load(Ordering::Relaxed),
                status_304_total: self.http_status_304_total.load(Ordering::Relaxed),
                status_404_total: self.http_status_404_total.load(Ordering::Relaxed),
                status_405_total: self.http_status_405_total.load(Ordering::Relaxed),
                status_other_total: self.http_status_other_total.load(Ordering::Relaxed),
                bytes_sent_total: self.http_bytes_sent_total.load(Ordering::Relaxed),
            },
            config: ConfigSnapshot {
                routes_count: config.routes.len(),
                tls_profile: config.tls_min_version.clone(),
            },
        }
    }

    fn render_prometheus(&self, config: &ServiceConfig) -> String {
        let s = self.snapshot(config);
        let mut out = String::with_capacity(6 * 1024);

        push_metric(
            &mut out,
            "reprox_uptime_seconds",
            "gauge",
            "Time in seconds since the process started.",
            &[(&[], Value::F(s.uptime_seconds))],
        );

        push_metric(
            &mut out,
            "reprox_connections_total",
            "counter",
            "Total TCP connections accepted, by route.",
            &[
                (
                    &[("route", "proxied")],
                    Value::U(s.connections.proxied_total),
                ),
                (
                    &[("route", "fallback")],
                    Value::U(s.connections.fallback_total),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_connections_active",
            "gauge",
            "Connections currently being served, by route.",
            &[
                (
                    &[("route", "proxied")],
                    Value::I(s.connections.active_proxied),
                ),
                (
                    &[("route", "fallback")],
                    Value::I(s.connections.active_fallback),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_connection_duration_ms_sum",
            "counter",
            "Total time spent serving completed connections, by route, in milliseconds.",
            &[
                (
                    &[("route", "proxied")],
                    Value::U(s.connections.proxied_duration_ms_sum),
                ),
                (
                    &[("route", "fallback")],
                    Value::U(s.connections.fallback_duration_ms_sum),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_connection_duration_ms_count",
            "counter",
            "Number of completed connections included in connection_duration_ms_sum, by route.",
            &[
                (
                    &[("route", "proxied")],
                    Value::U(s.connections.proxied_completed_total),
                ),
                (
                    &[("route", "fallback")],
                    Value::U(s.connections.fallback_completed_total),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_connections_rejected_total",
            "counter",
            "Connections that never produced a usable ClientHello.",
            &[
                (
                    &[("reason", "probe_timeout")],
                    Value::U(s.connections.probe_timeout_total),
                ),
                (
                    &[("reason", "probe_io_error")],
                    Value::U(s.connections.probe_io_error_total),
                ),
                (
                    &[("reason", "closed_early")],
                    Value::U(s.connections.closed_early_total),
                ),
                (
                    &[("reason", "ip_limit")],
                    Value::U(s.connections.ip_limit_total),
                ),
                (
                    &[("reason", "rate_limit")],
                    Value::U(s.connections.rate_limit_total),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_connections_limit",
            "gauge",
            "Configured cap on connections handled at once, across both routes (max_connections).",
            &[(&[], Value::U(s.connections.connections_limit))],
        );

        push_metric(
            &mut out,
            "reprox_connections_available",
            "gauge",
            "Connections currently free out of reprox_connections_limit. A sustained 0 means max_connections is the current bottleneck.",
            &[(&[], Value::U(s.connections.connections_available))],
        );

        push_metric(
            &mut out,
            "reprox_clienthello_total",
            "counter",
            "ClientHello classification results (see sni::ProbeResult).",
            &[
                (
                    &[("result", "sni_present")],
                    Value::U(s.clienthello.sni_present_total),
                ),
                (
                    &[("result", "sni_absent")],
                    Value::U(s.clienthello.sni_absent_total),
                ),
                (
                    &[("result", "not_tls")],
                    Value::U(s.clienthello.not_tls_total),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_proxy_bytes_total",
            "counter",
            "Bytes relayed between clients and service.",
            &[
                (
                    &[("direction", "client_to_service")],
                    Value::U(s.proxy.bytes_client_to_service_total),
                ),
                (
                    &[("direction", "service_to_client")],
                    Value::U(s.proxy.bytes_service_to_client_total),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_proxy_service_connect_failures_total",
            "counter",
            "Connections that could not reach the local service instance after exhausting connect retries (see reprox_proxy_service_connect_retries_total). A non-zero rate usually means the service is down or misconfigured.",
            &[(&[], Value::U(s.proxy.service_connect_failures_total))],
        );

        push_metric(
            &mut out,
            "reprox_proxy_service_connect_retries_total",
            "counter",
            "Individual failed connect attempts to the local service that were retried with backoff (excludes each route's final, giving-up attempt, which is counted in reprox_proxy_service_connect_failures_total instead). A high rate here relative to the failures counter means the service is usually just briefly slow to accept, not actually down.",
            &[(&[], Value::U(s.proxy.service_connect_retries_total))],
        );

        push_metric(
            &mut out,
            "reprox_fallback_tls_handshakes_total",
            "counter",
            "Fallback-path TLS handshake outcomes.",
            &[
                (
                    &[("result", "success")],
                    Value::U(s.tls.fallback_handshake_success_total),
                ),
                (
                    &[("result", "failure")],
                    Value::U(s.tls.fallback_handshake_failure_total),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_fallback_alpn_selected_total",
            "counter",
            "Negotiated ALPN protocol on the fallback path.",
            &[
                (
                    &[("protocol", "h2")],
                    Value::U(s.tls.fallback_alpn_h2_total),
                ),
                (
                    &[("protocol", "http1")],
                    Value::U(s.tls.fallback_alpn_http1_total),
                ),
                (
                    &[("protocol", "none")],
                    Value::U(s.tls.fallback_alpn_none_total),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_proxy_tls_handshakes_total",
            "counter",
            "Proxy-path TLS handshake outcomes.",
            &[
                (
                    &[("result", "success")],
                    Value::U(s.tls.proxy_handshake_success_total),
                ),
                (
                    &[("result", "failure")],
                    Value::U(s.tls.proxy_handshake_failure_total),
                ),
            ],
        );

        push_metric(
            &mut out,
            "reprox_http_requests_total",
            "counter",
            "Fallback-site HTTP requests, by method.",
            &[
                (&[("method", "GET")], Value::U(s.http.method_get_total)),
                (&[("method", "HEAD")], Value::U(s.http.method_head_total)),
                (
                    &[("method", "OPTIONS")],
                    Value::U(s.http.method_options_total),
                ),
                (&[("method", "other")], Value::U(s.http.method_other_total)),
            ],
        );

        push_metric(
            &mut out,
            "reprox_http_responses_total",
            "counter",
            "Fallback-site HTTP responses, by status code.",
            &[
                (&[("status", "200")], Value::U(s.http.status_200_total)),
                (&[("status", "204")], Value::U(s.http.status_204_total)),
                (&[("status", "304")], Value::U(s.http.status_304_total)),
                (&[("status", "404")], Value::U(s.http.status_404_total)),
                (&[("status", "405")], Value::U(s.http.status_405_total)),
                (&[("status", "other")], Value::U(s.http.status_other_total)),
            ],
        );

        push_metric(
            &mut out,
            "reprox_http_response_bytes_total",
            "counter",
            "Approximate response body bytes sent by the fallback site (read from Content-Length).",
            &[(&[], Value::U(s.http.bytes_sent_total))],
        );

        // Name kept as `reprox_config_secret_domains` for backward
        // compatibility with existing dashboards/alerts from when the
        // config only supported a single service behind a flat list of
        // secret domains; it now reflects `routes.len()` (each entry a
        // distinct sni -> upstream mapping), which is what the HELP text
        // and the JSON field (`config.routes_count`) both describe.
        push_metric(
            &mut out,
            "reprox_config_secret_domains",
            "gauge",
            "Number of service routes currently configured.",
            &[(&[], Value::U(s.config.routes_count as u64))],
        );

        out
    }
}

/// A metric sample value. Kept as a small enum (rather than always
/// casting to f64) so integer counters/gauges are always rendered
/// without a spurious decimal point, while genuinely fractional values
/// (uptime) still get sensible precision.
enum Value {
    U(u64),
    I(i64),
    F(f64),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::U(v) => write!(f, "{v}"),
            Value::I(v) => write!(f, "{v}"),
            Value::F(v) => write!(f, "{v:.3}"),
        }
    }
}

/// Appends one metric's `# HELP`/`# TYPE` lines followed by each of its
/// samples to `out`, in Prometheus text exposition format.
fn push_metric(
    out: &mut String,
    name: &str,
    metric_type: &str,
    help: &str,
    samples: &[(&[(&str, &str)], Value)],
) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
    for (labels, value) in samples {
        if labels.is_empty() {
            let _ = writeln!(out, "{name} {value}");
        } else {
            let mut label_str = String::new();
            for (i, (k, v)) in labels.iter().enumerate() {
                if i > 0 {
                    label_str.push(',');
                }
                let _ = write!(label_str, "{k}=\"{v}\"");
            }
            let _ = writeln!(out, "{name}{{{label_str}}} {value}");
        }
    }
    out.push('\n');
}

// JSON snapshot — served at /metrics.json for consumers that would
// rather not parse the Prometheus text format.

#[derive(Serialize)]
struct MetricsSnapshot {
    uptime_seconds: f64,
    connections: ConnectionsSnapshot,
    clienthello: ClientHelloSnapshot,
    proxy: ProxySnapshot,
    tls: TlsSnapshot,
    http: HttpSnapshot,
    config: ConfigSnapshot,
}

#[derive(Serialize)]
struct ConnectionsSnapshot {
    proxied_total: u64,
    fallback_total: u64,
    proxied_completed_total: u64,
    fallback_completed_total: u64,
    active_proxied: i64,
    active_fallback: i64,
    proxied_duration_ms_sum: u64,
    fallback_duration_ms_sum: u64,
    probe_timeout_total: u64,
    probe_io_error_total: u64,
    closed_early_total: u64,
    connections_limit: u64,
    connections_available: u64,
    ip_limit_total: u64,
    rate_limit_total: u64,
}

#[derive(Serialize)]
struct ClientHelloSnapshot {
    sni_present_total: u64,
    sni_absent_total: u64,
    not_tls_total: u64,
}

#[derive(Serialize)]
struct ProxySnapshot {
    bytes_client_to_service_total: u64,
    bytes_service_to_client_total: u64,
    service_connect_failures_total: u64,
    service_connect_retries_total: u64,
}

#[derive(Serialize)]
struct TlsSnapshot {
    fallback_handshake_success_total: u64,
    fallback_handshake_failure_total: u64,
    fallback_alpn_h2_total: u64,
    fallback_alpn_http1_total: u64,
    fallback_alpn_none_total: u64,
    proxy_handshake_success_total: u64,
    proxy_handshake_failure_total: u64,
}

#[derive(Serialize)]
struct HttpSnapshot {
    method_get_total: u64,
    method_head_total: u64,
    method_options_total: u64,
    method_other_total: u64,
    status_200_total: u64,
    status_204_total: u64,
    status_304_total: u64,
    status_404_total: u64,
    status_405_total: u64,
    status_other_total: u64,
    bytes_sent_total: u64,
}

#[derive(Serialize)]
struct ConfigSnapshot {
    routes_count: usize,
    tls_profile: String,
}

// The API itself: a tiny plain-HTTP server, loopback-only
pub async fn serve(
    addr: SocketAddr,
    stats: Arc<Stats>,
    config: Arc<ServiceConfig>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "metrics_addr must be a loopback address, got {addr}"
    );

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "internal metrics API listening (loopback only)");

    loop {
        let (stream, _) = listener.accept().await?;
        let stats = stats.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req: Request<Incoming>| {
                let stats = stats.clone();
                let config = config.clone();
                async move { handle_request(req, stats, config).await }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(error = %e, "metrics API connection ended with an error");
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
    stats: Arc<Stats>,
    config: Arc<ServiceConfig>,
) -> Result<Response<ResponseBody>, Infallible> {
    if req.method() != Method::GET {
        return Ok(plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed\n",
        ));
    }

    let response = match req.uri().path() {
        "/metrics" => {
            let body = stats.render_prometheus(&config);
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )
                .body(full_body(Bytes::from(body)))
                .expect("well-formed response")
        }
        "/metrics.json" => {
            let snapshot = stats.snapshot(&config);
            let body = serde_json::to_string_pretty(&snapshot).unwrap_or_else(|_| "{}".to_string());
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                .body(full_body(Bytes::from(body)))
                .expect("well-formed response")
        }
        "/healthz" => plain_response(StatusCode::OK, "ok\n"),
        _ => plain_response(StatusCode::NOT_FOUND, "not found\n"),
    };

    Ok(response)
}

fn plain_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from_static(body.as_bytes())))
        .expect("well-formed response")
}
