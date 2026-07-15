//! Optional internal metrics endpoint. Only listens on a loopback
//! address (checked twice: once when the config is validated, and again
//! right before binding), so it's unreachable from outside the VPS at
//! all — there are no "technical" paths on the main 443 port under the
//! domain either; the counters live exclusively on this separate port
//! on 127.0.0.1/::1.

use http::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
pub struct Stats {
    pub proxied_total: AtomicU64,
    pub fallback_total: AtomicU64,
}

impl Stats {
    pub fn inc_proxied(&self) {
        self.proxied_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_fallback(&self) {
        self.fallback_total.fetch_add(1, Ordering::Relaxed);
    }
}

pub async fn serve(addr: SocketAddr, stats: Arc<Stats>) -> anyhow::Result<()> {
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "metrics_addr must be a loopback address, got {addr}"
    );

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "internal metrics endpoint listening (loopback only)");

    loop {
        let (mut stream, _) = listener.accept().await?;
        let stats = stats.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            // We don't fully parse the request — this isn't a public
            // HTTP API, just a minimal text response to any incoming byte.
            let _ = stream.read(&mut buf).await;

            let body = format!(
                "telemt_frontend_proxied_total {}\ntelemt_frontend_fallback_total {}\n",
                stats.proxied_total.load(Ordering::Relaxed),
                stats.fallback_total.load(Ordering::Relaxed),
            );

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .header(CONTENT_LENGTH, body.len())
                .header(CONNECTION, "close")
                .body(body)
                .unwrap()
                .collect()
                .await
                .unwrap()
                .to_bytes();

            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        });
    }
}
