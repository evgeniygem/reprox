//! Fallback path: when the SNI didn't match telemt's secret domain (it
//! didn't match, was absent, or the handshake didn't even look like
//! TLS), the server performs a full TLS handshake itself using the
//! provided real certificate and serves a static site — an ordinary
//! HTTPS host, indistinguishable from the outside from a classic nginx.

use anyhow::Context;
use async_recursion::async_recursion;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::config::ServiceConfig;
use crate::prefixed_stream::PrefixedStream;

type ResponseBody = BoxBody<Bytes, std::convert::Infallible>;

const DEFAULT_404_HTML: &str = "<!doctype html>\
    <html lang=\"en\">\
    <head><meta charset=\"utf-8\"><title>404 Not Found</title></head>\
    <body><h1>404 Not Found</h1><p>The page you requested does not exist.</p></body>\
    </html>";

/// Static site: all content is read once at startup and lives in memory
/// (the site is small — tens/hundreds of KB), so serving is fast and
/// there is no path for directory traversal by construction: the
/// HashMap keys are built purely by walking the directory on disk, not
/// from a user-supplied Path, so "../../etc/passwd" simply never
/// matches any known key.

#[derive(Clone)]
pub struct FileEntry {
    pub bytes: Bytes,
    pub content_type: &'static str,
    pub etag: String,
    pub last_modified: String,
}

pub struct StaticSite {
    files: HashMap<String, FileEntry>,
    not_found: FileEntry,
}

impl StaticSite {
    pub async fn try_load(root: &Path) -> anyhow::Result<Self> {
        let mut files = HashMap::new();
        walk_dir(root, root, &mut files).await?;

        if !files.contains_key("/index.html") {
            anyhow::bail!("static_dir ({root:?}) must contain an index.html at its root");
        }

        let not_found = files.get("/404.html").cloned().unwrap_or_else(|| {
            let bytes = Bytes::from_static(DEFAULT_404_HTML.as_bytes());
            FileEntry {
                etag: make_etag(bytes.len() as u64, 0),
                last_modified: httpdate::fmt_http_date(SystemTime::now()),
                content_type: "text/html; charset=utf-8",
                bytes,
            }
        });

        tracing::info!(files = files.len(), root = ?root, "static site loaded into memory");
        Ok(Self { files, not_found })
    }

    pub fn resolve(&self, raw_path: &str) -> Option<&FileEntry> {
        let path = raw_path.split('?').next().unwrap_or("/");
        let key = if path == "/" || path.is_empty() {
            "/index.html"
        } else {
            path
        };
        self.files.get(key)
    }

    pub fn not_found(&self) -> &FileEntry {
        &self.not_found
    }
}

#[async_recursion]
async fn walk_dir(
    root: &Path,
    dir: &Path,
    out: &mut HashMap<String, FileEntry>,
) -> anyhow::Result<()> {
    let mut entries = fs::read_dir(dir)
        .await
        .with_context(|| format!("reading directory {dir:?}"))?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_type = entry.file_type().await?;

        if file_type.is_dir() {
            walk_dir(root, &path, out).await?;
        } else if file_type.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let url_path = format!("/{}", rel.to_string_lossy().replace('\\', "/"));

            let bytes = fs::read(&path)
                .await
                .with_context(|| format!("reading file {path:?}"))?;

            let meta = fs::metadata(&path).await?;

            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);

            let mtime_secs = mtime
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            out.insert(
                url_path,
                FileEntry {
                    content_type: content_type_for(ext),
                    etag: make_etag(bytes.len() as u64, mtime_secs),
                    last_modified: httpdate::fmt_http_date(mtime),
                    bytes: Bytes::from(bytes),
                },
            );
        }
    }
    Ok(())
}

fn content_type_for(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

/// Formatted like a standard nginx ETag: "<hex mtime>-<hex size>".
fn make_etag(size: u64, mtime_secs: u64) -> String {
    format!("\"{mtime_secs:x}-{size:x}\"")
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

// ---------------------------------------------------------------------
// TLS termination + choosing HTTP/1.1 or HTTP/2 based on the ALPN result
// ---------------------------------------------------------------------

pub async fn serve_tls(
    stream: TcpStream,
    prefix: Bytes,
    acceptor: TlsAcceptor,
    site: Arc<StaticSite>,
    config: Arc<ServiceConfig>,
) -> anyhow::Result<()> {
    let io = PrefixedStream::new(prefix, stream);

    let tls_stream = match acceptor.accept(io).await {
        Ok(s) => s,
        Err(e) => {
            // Invalid ClientHello, unsupported TLS version, etc. rustls
            // itself sends a proper TLS alert wherever the protocol calls
            // for one; after the error we just close the connection —
            // with no forced RST (there is no SO_LINGER(0) anywhere in
            // this project).
            tracing::debug!(error = %e, "fallback-path TLS handshake failed");
            return Ok(());
        }
    };

    let alpn = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
    let io = TokioIo::new(tls_stream);

    let service = service_fn(move |req: Request<Incoming>| {
        let site = site.clone();
        let config = config.clone();
        async move { handle_http(req, site, config).await }
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

/// HTTP handler: GET/HEAD serve files, OPTIONS gets a response, other
/// methods get a 405 — just like a configured static location in nginx.
async fn handle_http(
    req: Request<Incoming>,
    site: Arc<StaticSite>,
    config: Arc<ServiceConfig>,
) -> Result<Response<ResponseBody>, std::convert::Infallible> {
    let method = req.method().clone();

    if method == Method::OPTIONS {
        return Ok(options_response(&config));
    }
    if method != Method::GET && method != Method::HEAD {
        return Ok(method_not_allowed_response(&config));
    }

    let decoded = percent_encoding::percent_decode_str(req.uri().path())
        .decode_utf8_lossy()
        .into_owned();

    match site.resolve(&decoded) {
        Some(entry) => Ok(file_response(&req, entry, &method, &config)),
        None => Ok(not_found_response(&method, &site, &config)),
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

fn empty_body() -> ResponseBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(bytes: Bytes) -> ResponseBody {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}
