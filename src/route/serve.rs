//! Fallback path: when the SNI didn't match service's secret domain (it
//! didn't match, was absent, or the handshake didn't even look like
//! TLS), the server performs a full TLS handshake itself using the
//! provided real certificate and serves a static site — an ordinary
//! HTTPS host, indistinguishable from the outside from a classic nginx.
//!
//! Along the way it records TLS handshake outcomes, the negotiated ALPN
//! protocol, and per-request method/status/byte counters into `Stats`
//! (see metrics.rs) — connection count, the active-connection gauge,
//! and duration are handled by the `ActiveGuard` the caller holds for
//! the lifetime of the connection.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};

use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::fallback::{FileEntry, StaticSite};
use crate::config::ServiceConfig;
use crate::http_util::{ResponseBody, empty_body, full_body};
use crate::metrics::Stats;
use crate::prefixed_stream::PrefixedStream;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};
use tokio::time::timeout;

// TLS termination + choosing HTTP/1.1 or HTTP/2 based on the ALPN result
pub async fn serve(
    stream: TcpStream,
    prefix: Bytes,
    acceptor: TlsAcceptor,
    site: Arc<StaticSite>,
    config: Arc<ServiceConfig>,
    stats: Arc<Stats>,
) -> anyhow::Result<()> {
    let io = PrefixedStream::new(prefix, stream);
    let handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);

    let tls_stream = match timeout(handshake_timeout, acceptor.accept(io)).await {
        Ok(Ok(s)) => {
            stats
                .fallback_tls_handshake_success_total
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
                .fallback_tls_handshake_failure_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(error = %e, "fallback-path TLS handshake failed");
            return Ok(());
        }
        Err(_) => {
            // Slowloris-style stall: the client never finished the TLS
            // handshake within handshake_timeout_secs.
            stats
                .fallback_tls_handshake_failure_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!("fallback-path TLS handshake timed out");
            return Ok(());
        }
    };

    let alpn = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
    if alpn.as_deref() == Some(b"h2") {
        stats.fallback_alpn_h2_total.fetch_add(1, Ordering::Relaxed);
    } else if alpn.as_deref() == Some(b"http/1.1") {
        stats
            .fallback_alpn_http1_total
            .fetch_add(1, Ordering::Relaxed);
    } else {
        stats
            .fallback_alpn_none_total
            .fetch_add(1, Ordering::Relaxed);
    }

    let io = TokioIo::new(tls_stream);

    let service = service_fn(move |req: Request<Incoming>| {
        let site = site.clone();
        let config = config.clone();
        let stats = stats.clone();
        async move { handle_http(req, site, config, stats).await }
    });

    let result = if alpn.as_deref() == Some(b"h2") {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, service)
            .await
    } else {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .with_upgrades()
            .await
    };

    if let Err(e) = result {
        tracing::debug!(error = %e, "fallback site HTTP connection ended with an error");
    }

    Ok(())
}
// HTTP handler: GET/HEAD serve files, OPTIONS gets a response, other
// methods get a 405 — just like a configured static location in nginx.

async fn handle_http(
    req: Request<Incoming>,
    site: Arc<StaticSite>,
    config: Arc<ServiceConfig>,
    stats: Arc<Stats>,
) -> Result<Response<ResponseBody>, std::convert::Infallible> {
    let method = req.method().clone();

    if method == Method::GET {
        stats.http_method_get_total.fetch_add(1, Ordering::Relaxed);
    } else if method == Method::HEAD {
        stats.http_method_head_total.fetch_add(1, Ordering::Relaxed);
    } else if method == Method::OPTIONS {
        stats
            .http_method_options_total
            .fetch_add(1, Ordering::Relaxed);
    } else {
        stats
            .http_method_other_total
            .fetch_add(1, Ordering::Relaxed);
    }

    let response = if method == Method::OPTIONS {
        options_response(&config)
    } else if method != Method::GET && method != Method::HEAD {
        method_not_allowed_response(&config)
    } else {
        let decoded = percent_encoding::percent_decode_str(req.uri().path())
            .decode_utf8_lossy()
            .into_owned();

        match site.resolve(&decoded) {
            Some(entry) => file_response(&req, entry, &method, &config),
            None => not_found_response(&method, &site, &config),
        }
    };

    record_response_metrics(&stats, &response);
    Ok(response)
}

/// Records the status-code counter and (when a Content-Length header is
/// present) the response-body byte counter for a fallback-site response.
fn record_response_metrics(stats: &Stats, resp: &Response<ResponseBody>) {
    let counter = match resp.status().as_u16() {
        200 => &stats.http_status_200_total,
        204 => &stats.http_status_204_total,
        304 => &stats.http_status_304_total,
        404 => &stats.http_status_404_total,
        405 => &stats.http_status_405_total,
        _ => &stats.http_status_other_total,
    };
    counter.fetch_add(1, Ordering::Relaxed);

    if let Some(len) = resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        stats
            .http_bytes_sent_total
            .fetch_add(len, Ordering::Relaxed);
    }
}

fn file_response(
    req: &Request<Incoming>,
    entry: &FileEntry,
    method: &Method,
    config: &ServiceConfig,
) -> Response<ResponseBody> {
    if let Some(inm) = req.headers().get(header::IF_NONE_MATCH)
        && inm.to_str().map(|v| v == entry.etag).unwrap_or(false)
    {
        return not_modified_response(entry, config);
    }

    let body: ResponseBody = if *method == Method::HEAD {
        empty_body()
    } else {
        full_body(entry.bytes.clone())
    };

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, entry.content_type)
        .header(header::CONTENT_LENGTH, entry.bytes.len().to_string())
        .header(header::ETAG, entry.etag.clone())
        .header(header::LAST_MODIFIED, entry.last_modified.clone())
        .header(header::CACHE_CONTROL, cache_control_for(entry.content_type))
        .body(body)
        .expect("well-formed response");

    apply_common_headers(resp.headers_mut(), config);
    resp
}

fn not_found_response(
    method: &Method,
    site: &StaticSite,
    config: &ServiceConfig,
) -> Response<ResponseBody> {
    let entry = site.not_found();
    let body: ResponseBody = if *method == Method::HEAD {
        empty_body()
    } else {
        full_body(entry.bytes.clone())
    };

    let mut resp = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, entry.content_type)
        .header(header::CONTENT_LENGTH, entry.bytes.len().to_string())
        .header(header::CACHE_CONTROL, "no-cache")
        .body(body)
        .expect("well-formed response");

    apply_common_headers(resp.headers_mut(), config);
    resp
}

fn not_modified_response(entry: &FileEntry, config: &ServiceConfig) -> Response<ResponseBody> {
    let mut resp = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(header::ETAG, entry.etag.clone())
        .header(header::LAST_MODIFIED, entry.last_modified.clone())
        .body(empty_body())
        .expect("well-formed response");
    apply_common_headers(resp.headers_mut(), config);
    resp
}

fn options_response(config: &ServiceConfig) -> Response<ResponseBody> {
    let mut resp = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::ALLOW, "GET, HEAD, OPTIONS")
        .header(header::CONTENT_LENGTH, "0")
        .body(empty_body())
        .expect("well-formed response");
    apply_common_headers(resp.headers_mut(), config);
    resp
}

fn method_not_allowed_response(config: &ServiceConfig) -> Response<ResponseBody> {
    let html = b"<!doctype html><html><head><title>405 Not Allowed</title></head>\
<body><center><h1>405 Not Allowed</h1></center></body></html>"
        .to_vec();
    let len = html.len();
    let mut resp = Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::ALLOW, "GET, HEAD, OPTIONS")
        .header(header::CONTENT_LENGTH, len.to_string())
        .body(full_body(Bytes::from(html)))
        .expect("well-formed response");
    apply_common_headers(resp.headers_mut(), config);
    resp
}

fn apply_common_headers(headers: &mut HeaderMap, config: &ServiceConfig) {
    if let Ok(v) = HeaderValue::from_str(&config.server_header) {
        headers.insert(header::SERVER, v);
    }
    if let Ok(v) = HeaderValue::from_str(&httpdate::fmt_http_date(SystemTime::now())) {
        headers.insert(header::DATE, v);
    }
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
}

fn cache_control_for(content_type: &str) -> &'static str {
    if content_type.starts_with("text/html") {
        // HTML — let the browser revalidate against the ETag every time.
        "no-cache"
    } else {
        // Static assets — safe to cache for a long time.
        "public, max-age=2592000, immutable"
    }
}
